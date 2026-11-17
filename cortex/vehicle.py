"""CAS OBD Scanner integration: turn the scanner's exports into ranked vehicle risks.

Reads, by content (file names don't matter):
  * Test report CSV   - "Save as spreadsheet" on the Tests page
                        header: group,command,test,result,value,explanation,expected
  * Car health JSON   - "Export history" on the Health page: {"vin": ..., "checks": [...]}
  * Data log CSV      - "Download CSV" on the Data log page
                        header: timestamp,pid,sensor,value,unit
  * Fault codes       - any text containing codes such as P0300, C0035, B0012, U0121

Each finding is ranked like every other Cortex alert (likelihood x impact x criticality,
plus harm), so a fault that affects safety on the road (airbags, brakes, overheating)
outranks one that only risks an MOT failure. docs/engine.js holds an identical JS port
for the iPhone app; tests/test_vehicle.py checks both give the same results.
"""
from __future__ import annotations

import csv
import io
import json
import math
import re

from .realtime import hng_time

DTC_RE = re.compile(r"\b([PCBU][0-3][0-9A-F]{3})\b")

# Descriptions from CAS OBD Scanner's own table (DTC_TXT).
DTC_TXT = {
    "P0087": "Fuel rail/system pressure too low", "P0088": "Fuel rail/system pressure too high",
    "P0100": "MAF sensor circuit", "P0101": "MAF sensor range/performance", "P0102": "MAF sensor circuit low",
    "P0103": "MAF sensor circuit high", "P0106": "MAP sensor range/performance", "P0110": "Intake air temp sensor circuit",
    "P0115": "Coolant temp sensor circuit", "P0116": "Coolant temp sensor range/performance",
    "P0120": "Throttle position sensor circuit", "P0128": "Coolant below thermostat regulating temperature",
    "P0130": "O2 sensor circuit (B1S1)", "P0133": "O2 sensor slow response (B1S1)", "P0135": "O2 sensor heater circuit (B1S1)",
    "P0141": "O2 sensor heater circuit (B1S2)", "P0171": "System too lean (bank 1)", "P0172": "System too rich (bank 1)",
    "P0174": "System too lean (bank 2)", "P0175": "System too rich (bank 2)", "P0234": "Turbo/supercharger overboost",
    "P0299": "Turbo/supercharger underboost", "P0300": "Random/multiple cylinder misfire", "P0301": "Cylinder 1 misfire",
    "P0302": "Cylinder 2 misfire", "P0303": "Cylinder 3 misfire", "P0304": "Cylinder 4 misfire", "P0305": "Cylinder 5 misfire",
    "P0306": "Cylinder 6 misfire", "P0325": "Knock sensor 1 circuit (bank 1)", "P0335": "Crankshaft position sensor A circuit",
    "P0340": "Camshaft position sensor A circuit (bank 1)", "P0380": "Glow plug/heater circuit A", "P0400": "EGR flow",
    "P0401": "EGR insufficient flow", "P0402": "EGR excessive flow", "P0420": "Catalyst efficiency below threshold (bank 1)",
    "P0430": "Catalyst efficiency below threshold (bank 2)", "P0440": "EVAP system", "P0442": "EVAP system small leak",
    "P0455": "EVAP system large leak", "P0456": "EVAP system very small leak", "P0500": "Vehicle speed sensor",
    "P0505": "Idle air control system", "P0507": "Idle speed higher than expected", "P0562": "System voltage low",
    "P0563": "System voltage high", "P0600": "Serial communication link", "P0700": "Transmission control system (see TCM codes)",
    "P2002": "Diesel particulate filter efficiency below threshold", "P2463": "Diesel particulate filter soot accumulation",
}
DTC_TXT.update({  # standard SAE network codes that matter for safety
    "U0100": "Lost communication with engine control module",
    "U0121": "Lost communication with ABS control module",
    "U0151": "Lost communication with airbag (restraints) control module",
})
DTC_SYS = {"P": "Powertrain", "C": "Chassis", "B": "Body", "U": "Network"}
KIND_LABEL = {"airbag": "Airbag (SRS) system fault", "brakes": "ABS, brakes, stability or steering fault",
              "misfire": "Engine misfire", "overheating": "Over-temperature fault", "transmission": "Gearbox fault",
              "charging": "System voltage fault", "emissions": "Emissions system fault", "network": "Module communication fault"}

# (letter, from, to, kind, likelihood, impact, harm, advice) - first match wins.
DTC_RULES = [
    ("B", "0001", "0099", "airbag", 4, 5, "severe",
     "The airbag (SRS) system has a fault and may not deploy in a crash. Get it checked before carrying passengers."),
    ("U", "0151", "0151", "airbag", 3, 5, "severe",
     "The car has lost contact with the airbag module - the airbags may not deploy. Get it checked promptly."),
    ("U", "0121", "0129", "brakes", 3, 5, "severe",
     "The car has lost contact with the ABS/stability module - ABS and stability control may be off. Drive gently and get it checked."),
    ("C", "0000", "3FFF", "brakes", 4, 5, "severe",
     "Chassis fault (ABS, brakes, stability control or steering). These systems may be disabled - drive gently and get it checked promptly."),
    ("P", "0217", "0218", "overheating", 5, 5, "severe",
     "Engine or gearbox over-temperature. Stop safely and let it cool - driving on can wreck the engine."),
    ("P", "0300", "0312", "misfire", 5, 4, "moderate",
     "Engine misfire. Avoid hard acceleration. If the check-engine light flashes, stop - unburnt fuel can overheat the catalytic converter."),
    ("P", "0335", "0349", "stall_risk", 4, 4, "moderate",
     "Crankshaft/camshaft sensor fault - the engine may cut out or fail to restart. Fix it before a long journey."),
    ("P", "0087", "0088", "fuel_pressure", 4, 4, "moderate", "Fuel pressure fault - possible loss of power or stalling."),
    ("P", "0234", "0234", "boost", 4, 4, "moderate", "Turbo overboost - can damage the engine. Avoid full throttle until checked."),
    ("P", "0560", "0563", "charging", 4, 4, "moderate",
     "System voltage fault - the battery or alternator may be failing and could leave you stranded."),
    ("P", "0700", "0799", "transmission", 4, 4, "moderate", "Gearbox fault - gear changes may be affected or the car may go into limp mode."),
    ("P", "0500", "0503", "speed_sensor", 3, 4, "moderate",
     "Vehicle speed sensor fault - the speedometer, ABS or gearbox may behave oddly."),
    ("P", "2463", "2463", "dpf", 4, 3, "moderate",
     "Diesel particulate filter is overloaded with soot - it needs a regeneration drive soon or the car may go into limp mode."),
    ("P", "0171", "0175", "fuel_trim", 4, 3, "minor", "Fuel mixture lean or rich - check for air leaks, the MAF sensor or fuel delivery."),
    ("P", "0299", "0299", "boost", 4, 3, "minor", "Turbo underboost - reduced power. Check the boost hoses and wastegate."),
    ("P", "0115", "0128", "cooling", 3, 3, "minor", "Cooling sensor or thermostat fault - keep an eye on the temperature gauge."),
    ("P", "2002", "2002", "emissions", 4, 3, "minor", "Diesel particulate filter efficiency low - an MOT failure risk."),
    ("P", "0400", "0499", "emissions", 4, 2, "minor",
     "Emissions system fault (catalyst, EGR or EVAP) - likely an MOT failure rather than a safety issue."),
    ("U", "0000", "3FFF", "network", 3, 4, "moderate", "Module communication fault - some systems may not work correctly."),
    ("P", "0000", "3FFF", "engine", 3, 3, "minor", "Engine or powertrain fault - get the code diagnosed."),
    ("B", "0000", "3FFF", "body", 3, 2, "none", "Body electronics fault (lights, locks or comfort systems) - usually not urgent."),
]


def r1(x: float) -> str:
    """One-decimal formatting that is identical in Python and JavaScript."""
    return f"{math.floor(x * 10 + 0.5) / 10:.1f}"


def dtc_text(code: str) -> str:
    if code in DTC_TXT:
        return DTC_TXT[code]
    generic = code[1] in "02"
    kind = classify_dtc(code)[0]
    base = KIND_LABEL.get(kind, DTC_SYS[code[0]] + " fault")
    return base + (" (generic code)" if generic else " (manufacturer-specific code - look up for your make)")


def classify_dtc(code: str):
    for letter, lo, hi, kind, L, I, harm, advice in DTC_RULES:
        if code[0] == letter and lo <= code[1:] <= hi:
            return kind, L, I, harm, advice
    return "engine", 3, 3, "minor", "Get the code diagnosed."


def find_codes(text: str) -> list[str]:
    seen, out = set(), []
    for c in DTC_RE.findall(text or ""):
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out


def _finding(kind, entity, ts, detail, L, I, harm, advice):
    return {"kind": kind, "entity": entity, "ts": ts, "detail": detail,
            "profile": (max(1, min(5, L)), I, harm), "advice": advice}


def dtc_findings(codes: list[str], entity: str, ts: float, status: str = "") -> list[dict]:
    out = []
    for c in codes:
        kind, L, I, harm, advice = classify_dtc(c)
        label = f"{c} {dtc_text(c)}"
        if status == "pending":
            L -= 1
            label += " (pending - seen recently, not yet confirmed)"
        elif status == "permanent":
            label += " (permanent - clears itself once the repair is confirmed)"
        out.append(_finding(kind, entity, ts, label, L, I, harm, advice))
    return out


# ------------------------------------------------------------------ detection
TEST_HEADER = "group,command,test,result,value,explanation,expected"
LOG_HEADER = "timestamp,pid,sensor,value,unit"


def detect(text: str) -> str | None:
    """Which CAS OBD Scanner export (if any) is this?"""
    head = (text or "").lstrip("﻿").lstrip()
    first = head.split("\n", 1)[0].strip().lower()
    if first.startswith(TEST_HEADER):
        return "test_report"
    if first.startswith(LOG_HEADER):
        return "data_log"
    if head.startswith("{"):
        try:
            d = json.loads(head)
        except json.JSONDecodeError:
            return None
        if isinstance(d, dict) and isinstance(d.get("checks"), list):
            return "health"
        return None
    return None


def _rows(text: str) -> list[list[str]]:
    return list(csv.reader(io.StringIO(text.lstrip("﻿").strip())))


_NUM = re.compile(r"^[+-]?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?$")


def _num(x):
    """Strict number parsing that behaves identically in the JavaScript port."""
    if isinstance(x, bool) or x is None:
        return None
    if isinstance(x, (int, float)):
        return float(x) if math.isfinite(x) else None
    x = str(x).strip()
    return float(x) if _NUM.match(x) else None


# ---------------------------------------------------------------- test report
TEST_IMPACT = {"Engine": 4, "Electrical": 4, "Fuel and air": 3, "Emissions": 2, "Communication": 2,
               "Adapter": 1, "Vehicle identity": 1}


def test_report_findings(text: str, now: float) -> list[dict]:
    rows = _rows(text)[1:]
    entity = "vehicle"
    for r in rows:
        if len(r) >= 5 and r[2] == "VIN" and len(r[4].strip()) == 17:
            entity = r[4].strip()
    out = []
    for r in rows:
        if len(r) < 6:
            continue
        group, _cmd, test, result, value, note = r[:6]
        if group == "Fault codes":
            codes = find_codes(value)
            status = "pending" if "Pending" in test else "permanent" if "Permanent" in test else ""
            out += dtc_findings(codes, entity, now, status)
            continue
        if result not in ("Fail", "Check"):
            continue
        I = TEST_IMPACT.get(group, 2)
        detail = f"{test}: {value} - {note}" if value else f"{test} - {note}"
        if test == "Coolant temperature" and result == "Fail":
            out.append(_finding("overheating", entity, now, detail, 5, 5, "severe",
                                "The engine is overheating. Stop safely and let it cool - driving on can wreck the engine."))
        elif result == "Fail":
            harm = "moderate" if group in ("Engine", "Electrical") else "minor"
            out.append(_finding("vehicle_test_fail", entity, now, detail, 4, I, harm,
                                "Failed check - see the explanation and get it looked at."))
        else:
            out.append(_finding("vehicle_test_check", entity, now, detail, 3, I, "none",
                                "Worth checking - not urgent on its own."))
    return out


# --------------------------------------------------------------------- health
def _slope(ys):
    n = len(ys)
    mx, my = (n - 1) / 2, sum(ys) / n
    num = sum((i - mx) * (y - my) for i, y in enumerate(ys))
    den = sum((i - mx) * (i - mx) for i in range(n))
    return num / den if den else 0.0


def health_findings(text: str, now: float) -> list[dict]:
    d = json.loads(text.lstrip("﻿"))
    entity = (d.get("vin") or "vehicle").strip() or "vehicle"
    h = [c for c in d.get("checks", []) if isinstance(c, dict)]
    if not h:
        return []
    L = h[-1]
    ts = hng_time(L.get("t")) or now
    rpm, v, cool, lt, run = (_num(L.get(k)) for k in ("rpm", "vRun", "coolant", "ltft", "runtime"))
    out = []
    running = rpm is not None and rpm > 500
    if running and v is not None and v < 13.2:
        out.append(_finding("charging", entity, ts, f"Charging voltage low ({r1(v)} V with the engine running)", 4, 4,
                            "moderate", "The alternator may be failing - the battery will run down and the car could stop."))
    if running and v is not None and v > 15:
        out.append(_finding("charging", entity, ts, f"Overcharging ({r1(v)} V)", 4, 4, "moderate",
                            "Suspect the voltage regulator - overcharging damages the battery and electronics."))
    if rpm is not None and rpm < 300 and v is not None and v < 12.2:
        out.append(_finding("battery", entity, ts, f"Battery low with the engine off ({r1(v)} V)", 3, 3, "minor",
                            "Charge or test the battery - it may not start the car on a cold morning."))
    if running and cool is not None and cool >= 112:
        out.append(_finding("overheating", entity, ts, f"Coolant at {r1(cool)} °C", 5, 5, "severe",
                            "The engine is overheating. Stop safely and let it cool - driving on can wreck the engine."))
    if lt is not None and abs(lt) > 10:
        out.append(_finding("fuel_trim", entity, ts, f"Long-term fuel trim {r1(lt)}% "
                            f"({'lean - air leak or fuel delivery' if lt > 0 else 'rich'})", 3, 3, "minor",
                            "The engine is compensating for a mixture problem - check before it sets a P0171/P0172."))
    if run is not None and run > 900 and cool is not None and cool < 75:
        out.append(_finding("cooling", entity, ts, f"Coolant only {r1(cool)} °C after {int(math.floor(run / 60 + 0.5))} min", 3, 2, "minor",
                            "The thermostat may be sticking open - poor heating and higher fuel use."))
    runs = [c for c in h if (_num(c.get("rpm")) or 0) > 500 and _num(c.get("vRun")) is not None][-10:]
    if len(runs) >= 3:
        drop = _slope([_num(c["vRun"]) for c in runs]) * (len(runs) - 1)
        if drop < -0.3:
            out.append(_finding("charging_trend", entity, ts, f"Charging voltage drifted down {r1(-drop)} V over "
                                f"{len(runs)} checks", 3, 4, "minor", "The alternator or battery may be weakening."))
    lts = [c for c in h if _num(c.get("ltft")) is not None][-10:]
    if len(lts) >= 3:
        dr = _slope([_num(c["ltft"]) for c in lts]) * (len(lts) - 1)
        if abs(dr) > 5:
            out.append(_finding("fuel_trim_trend", entity, ts, f"Fuel trim drifting {'lean' if dr > 0 else 'rich'} "
                                f"({r1(dr)}% over {len(lts)} checks)", 3, 3, "minor",
                                "Catch it early - before a P0171/P0172 fault code is set."))
    return out


# ------------------------------------------------------------------- data log
JUMP = {"Coolant temperature": 8.0, "Control module voltage": 1.0, "Long term fuel trim B1": 8.0,
        "Long term fuel trim B2": 8.0, "Engine oil temperature": 8.0}


def data_log_findings(text: str, now: float) -> list[dict]:
    series: dict[str, list[tuple[float, float]]] = {}
    for r in _rows(text)[1:]:
        if len(r) < 4:
            continue
        v = _num(r[3])
        if v is None:
            continue
        series.setdefault(r[2], []).append((hng_time(r[0]) or now, v))
    out, ent = [], "vehicle"

    def first_over(name, lim):
        return next(((t, v) for t, v in series.get(name, []) if v >= lim), None)

    hit = first_over("Coolant temperature", 112)
    if hit:
        out.append(_finding("overheating", ent, hit[0], f"Coolant reached {r1(max(v for _, v in series['Coolant temperature']))} °C",
                            5, 5, "severe", "The engine overheated. Stop safely and let it cool - check coolant level and fan."))
    hit = first_over("Engine oil temperature", 130)
    if hit:
        out.append(_finding("oil_overheat", ent, hit[0], f"Oil temperature reached {r1(hit[1])} °C", 4, 4, "moderate",
                            "Oil this hot loses protection - ease off and check oil level and cooling."))
    volts = series.get("Control module voltage", [])
    if volts:
        lo = min(volts, key=lambda p: p[1])
        hi = max(volts, key=lambda p: p[1])
        if lo[1] < 11.0:
            out.append(_finding("charging", ent, lo[0], f"Supply voltage dropped to {r1(lo[1])} V", 4, 4, "moderate",
                                "A weak battery, poor earth or failing alternator - the car could cut out."))
        if hi[1] > 15.2:
            out.append(_finding("charging", ent, hi[0], f"Supply voltage rose to {r1(hi[1])} V", 4, 4, "moderate",
                                "Suspect the voltage regulator - overcharging damages the battery and electronics."))
    for name in ("Long term fuel trim B1", "Long term fuel trim B2"):
        s = series.get(name, [])
        if len(s) >= 5:
            m = sum(v for _, v in s) / len(s)
            if abs(m) > 10:
                out.append(_finding("fuel_trim", ent, s[-1][0], f"{name} averaged {r1(m)}%", 3, 3, "minor",
                                    "The engine is compensating for a mixture problem - check for air leaks or the MAF sensor."))
    for name, jump in JUMP.items():               # sudden jumps in values that should change slowly
        s = series.get(name, [])
        n, w = 0, 20
        first = None
        for i in range(w, len(s)):
            win = [v for _, v in s[i - w:i]]
            m = sum(win) / w
            sd = math.sqrt(sum((x - m) * (x - m) for x in win) / w)
            x = s[i][1]
            if abs(x - m) >= jump and (sd == 0 or abs(x - m) / sd > 4):
                n += 1
                first = first or s[i]
        if n:
            out.append(_finding("sensor_jump", ent, first[0], f"{n} sudden jump(s) in {name} (first to {r1(first[1])})",
                                2, 2, "none", "Could be a loose connector or failing sensor - watch for it again."))
    return out


def findings_for(text: str, now: float) -> list[dict] | None:
    """Findings for a CAS OBD Scanner export, or None if the text isn't one."""
    kind = detect(text)
    if kind == "test_report":
        return test_report_findings(text, now)
    if kind == "health":
        return health_findings(text, now)
    if kind == "data_log":
        return data_log_findings(text, now)
    return None


def apply(monitor, findings: list[dict]) -> list[dict]:
    """Rank findings through a ThreatMonitor so they are scored, shown and saved like any alert.
    Duplicate codes (e.g. confirmed and permanent) keep only the highest-ranked copy."""
    best: dict[tuple, dict] = {}
    order = []
    for f in findings:
        key = (f["kind"], f["entity"], f["detail"][:5] if DTC_RE.match(f["detail"]) else f["detail"])
        if key not in best:
            order.append(key)
            best[key] = f
        else:
            a, b = best[key]["profile"], f["profile"]
            if b[0] * b[1] > a[0] * a[1]:
                best[key] = f
    return [monitor._alert(f["kind"], f["entity"], f["ts"], f["detail"], profile=f["profile"], advice=f["advice"])
            for f in (best[k] for k in order)]


def analyse_text(monitor, text: str, now: float) -> str | None:
    """Feed a whole file to `monitor`: OBD exports are analysed as vehicle data, anything else
    line by line, and a plain list of fault codes is recognised if nothing else matched.
    Returns what was detected ("obd_test_report", "obd_health", "obd_data_log", "obd_codes")
    or None for ordinary logs. Mirrors Monitor.feedText in docs/engine.js."""
    try:
        found = findings_for(text, now)
    except (ValueError, json.JSONDecodeError):
        found = None
    if found is not None:
        monitor.events += 1
        apply(monitor, found)
        return "obd_" + detect(text)
    for line in text.splitlines():
        monitor.feed(line)
    if monitor.events == 0:
        codes = find_codes(text)
        if codes:
            monitor.events += 1
            apply(monitor, dtc_findings(codes, "vehicle", now))
            return "obd_codes"
    return None
