"""CAS OBD Scanner integration: correct ranking of real-world vehicle risks, and identical
results from the PC (Python) and iPhone (JavaScript) engines."""
import json
import random
import shutil
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from cortex import vehicle
from cortex.realtime import ThreatMonitor

ROOT = Path(__file__).resolve().parent.parent
OBD = ROOT / "examples" / "obd"
NODE = shutil.which("node")
NOW = 1763402400.0
quiet = lambda *a, **k: None


def py_run(text, crit=None):
    m = ThreatMonitor(out=quiet, criticality=crit or {})
    what = vehicle.analyse_text(m, text, NOW)
    return what, m.events, [(a["kind"], a["entity"], a["priority"], a["score"], a["detail"], round(a["ts"], 3))
                            for a in m.alerts]


def js_run(text, crit, tmp_path):
    src = tmp_path / "in.txt"
    src.write_text(text, encoding="utf-8")
    script = f"""
const E = require({json.dumps(str(ROOT / 'docs' / 'engine.js'))});
const m = new E.Monitor({{criticality: {json.dumps(crit or {})}}});
m.feedText(require('fs').readFileSync({json.dumps(str(src))}, 'utf8'), {NOW});
console.log(JSON.stringify([m.source, m.events, m.alerts.map(a => [a.kind, a.entity, a.priority, a.score, a.detail, Math.round(a.ts * 1000) / 1000])]));
"""
    out = json.loads(subprocess.run([NODE, "-e", script], capture_output=True, text=True, check=True).stdout)
    return out[0], out[1], [tuple(a) for a in out[2]]


# ------------------------------------------------------------------ behaviour
def test_safety_faults_outrank_mot_faults():
    _, _, a = py_run((OBD / "fault-codes.txt").read_text())
    pri = {d.split()[0]: p for _, _, p, _, d, _ in a}
    assert pri["B0012"] == pri["C0035"] == pri["U0121"] == "P1"   # airbag, brakes, lost ABS
    assert pri["P0300"] == "P2" and pri["P0442"] == "P3"          # misfire > EVAP leak


def test_test_report():
    what, _, a = py_run((OBD / "cas-obd-test-report.csv").read_text())
    assert what == "obd_test_report"
    assert all(e == "WVWZZZAWZHY123456" for _, e, *_ in a)            # VIN picked up
    codes = [d.split()[0] for _, _, _, _, d, _ in a if vehicle.DTC_RE.match(d)]
    assert codes.count("P0420") == 1                                  # confirmed + permanent merged
    assert any("pending" in d and d.startswith("P0171") for *_, d, _ in a)
    assert not any("Coolant" in d for *_, d, _ in a)                  # Pass rows ignored


def test_health_and_data_log():
    what, _, a = py_run((OBD / "health-WVWZZZAWZHY123456.json").read_text())
    kinds = {k for k, *_ in a}
    assert what == "obd_health" and {"charging", "charging_trend", "fuel_trim", "fuel_trim_trend"} <= kinds
    what, _, a = py_run((OBD / "obd-log-2026-11-17-07-40-00.csv").read_text())
    assert what == "obd_data_log"
    assert ("overheating", "P1") in {(k, p) for k, _, p, *_ in a}
    assert any(k == "charging" and "10.8" in d for k, _, _, _, d, _ in a)


def test_clean_exports_and_ordinary_logs():
    clean = 'group,command,test,result,value,explanation,expected\n"Engine","0105","Coolant temperature","Pass","90 °C","ok","x"'
    assert py_run(clean)[0] == "obd_test_report" and py_run(clean)[2] == []
    assert py_run((ROOT / "examples" / "sample_auth.log").read_text())[0] is None
    assert py_run("hello world")[2] == []


def test_dtc_text_and_classification():
    assert vehicle.dtc_text("P0301") == "Cylinder 1 misfire"
    assert vehicle.dtc_text("B0012").startswith("Airbag")
    assert "manufacturer-specific" in vehicle.dtc_text("P1234")
    assert vehicle.classify_dtc("C1234")[0] == "brakes"
    assert vehicle.classify_dtc("P0217")[3] == "severe"
    assert vehicle.find_codes("P0300 p0301 XP0302 P0300 U0100") == ["P0300", "U0100"]


# --------------------------------------------------------------------- parity
def rand_test_report(rng):
    groups = ["Engine", "Electrical", "Fuel and air", "Emissions", "Communication", "Adapter", "Vehicle identity", "Odd"]
    codes = ["P0300", "P0301", "P0420", "P0171", "B0012", "C0035", "U0121", "U0100", "P0217", "P1234", "B1234", "P2463", "P0562"]
    lines = ["group,command,test,result,value,explanation,expected"]
    if rng.random() < 0.7:
        lines.append('"Vehicle identity","0902","VIN","Info","%s","v","e"' % rng.choice(["WVWZZZAWZHY123456", "SHORT"]))
    for _ in range(rng.randint(0, 12)):
        if rng.random() < 0.3:
            test = rng.choice(["Confirmed fault codes", "Pending fault codes", "Permanent fault codes"])
            val = ", ".join(rng.sample(codes, rng.randint(0, 3))) or "None"
            lines.append('"Fault codes","03","%s","%s","%s","x, ""quoted"" note","None."' % (test, "Fail" if val != "None" else "Pass", val))
        else:
            test = rng.choice(["Coolant temperature", "Engine speed", "Battery voltage", "O2 sensor"])
            lines.append('"%s","01%02X","%s","%s","%s","note, with comma","exp"' % (
                rng.choice(groups), rng.randint(0, 255), test, rng.choice(["Pass", "Check", "Fail", "Info", "No reply"]),
                rng.choice(["", "12.9 V", "+11.7 %"])))
    if rng.random() < 0.3:
        lines.append('"short","row"')
    return "\n".join(lines)


def rand_health(rng):
    t0 = datetime(2026, 9, 1, tzinfo=timezone.utc)
    checks = []
    for i in range(rng.randint(0, 9)):
        pick = lambda lo, hi: rng.choice([None, round(rng.uniform(lo, hi), rng.choice([0, 1, 3])), "12.5", "x"])
        checks.append({"t": (t0 + timedelta(days=i)).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
                       "rpm": rng.choice([0, 250, 800.25, None]), "vRun": pick(11.5, 15.5), "ltft": pick(-15, 15),
                       "coolant": pick(60, 118), "runtime": rng.choice([None, 100, 1200, 2000])})
    return json.dumps({"vin": rng.choice(["", "WVWZZZAWZHY123456", None]), "checks": checks}, indent=rng.choice([None, 2]))


def rand_data_log(rng):
    base = datetime(2026, 11, 1, tzinfo=timezone.utc)
    lines = ["timestamp,pid,sensor,value,unit"]
    names = ["Coolant temperature", "Control module voltage", "Long term fuel trim B1", "Engine oil temperature", "Engine RPM"]
    level = {"Coolant temperature": 90, "Control module voltage": 14, "Long term fuel trim B1": rng.choice([2, 12]),
             "Engine oil temperature": 100, "Engine RPM": 800}
    for i in range(rng.randint(0, 120)):
        ts = (base + timedelta(seconds=i)).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        n = rng.choice(names)
        v = level[n] + rng.gauss(0, 0.3) + (rng.choice([0] * 30 + [15, -4, 25]) if n != "Engine RPM" else 0)
        lines.append('"%s","05","%s","%s","u"' % (ts, n, rng.choice([round(v, 3), round(v, 3), "", "abc", "1e1"])))
    return "\n".join(lines)


@pytest.mark.skipif(NODE is None, reason="node not installed")
def test_js_vehicle_engine_matches_python(tmp_path):
    rng = random.Random(2026)
    texts = [p.read_text() for p in sorted(OBD.iterdir())]
    texts += [rand_test_report(rng) for _ in range(40)] + [rand_health(rng) for _ in range(40)]
    texts += [rand_data_log(rng) for _ in range(40)]
    texts += ["Codes: " + " ".join(rng.sample(["P0300", "C0035", "U0151", "B0001", "P0420", "P0700"], 3)) for _ in range(10)]
    crit = {"WVWZZZAWZHY123456": 3}
    blob = "\n␞\n".join(texts)                      # one node process for speed
    src = tmp_path / "all.txt"
    src.write_text(blob, encoding="utf-8")
    script = f"""
const E = require({json.dumps(str(ROOT / 'docs' / 'engine.js'))});
const parts = require('fs').readFileSync({json.dumps(str(src))}, 'utf8').split('\\n\\u241e\\n');
console.log(JSON.stringify(parts.map(t => {{ const m = new E.Monitor({{criticality: {json.dumps(crit)}}}); m.feedText(t, {NOW});
  return [m.source, m.events, m.alerts.map(a => [a.kind, a.entity, a.priority, a.score, a.detail, Math.round(a.ts * 1000) / 1000])]; }})));
"""
    js = json.loads(subprocess.run([NODE, "-e", script], capture_output=True, text=True, check=True).stdout)
    hits = 0
    for text, (src_js, ev_js, al_js) in zip(texts, js):
        what, ev, al = py_run(text, crit)
        assert (what, ev, al) == (src_js, ev_js, [tuple(a) for a in al_js]), text[:300]
        hits += len(al)
    assert hits > 100
