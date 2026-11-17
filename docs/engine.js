/* CAS Cortex threat engine (browser + Node). A faithful port of cortex/realtime.py so
   the iPhone app gives the same alerts as the desktop app. Runs fully on the device. */
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.CortexEngine = factory();
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  const FAIL = /Failed password for (?:invalid user )?\S+ from (\d{1,3}(?:\.\d{1,3}){3})/;
  const OK = /Accepted \w+ for (\S+) from (\d{1,3}(?:\.\d{1,3}){3})/;
  const SYSLOG_TS = /^([A-Z][a-z]{2})\s+(\d{1,2}) (\d{2}):(\d{2}):(\d{2})/;
  const MONTHS = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };

  const CMD_RULES = {
    encoded_command: [/(?:^|\s)[-/]e(?:n|nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}/i],
    download_cradle: [/downloadstring/i, /downloadfile/i, /invoke-webrequest/i, /iwr /i,
                      /start-bitstransfer/i, /(curl|wget)\b[^|]*\|\s*(ba)?sh\b/i],
    hidden_window: [/[-/]w(?:indowstyle)?\s+hidden/i],
    execution_policy_bypass: [/[-/](?:ep|exec|executionpolicy)\s+bypass/i],
    lolbin: [/certutil(?:\.exe)?\b.*[-/]urlcache/i, /mshta(?:\.exe)?\s+https?:/i,
             /regsvr32(?:\.exe)?\b.*[-/]i:https?:/i, /rundll32(?:\.exe)?\b.*javascript:/i],
  };

  const RISK_PROFILE = {
    bruteforce: [4, 3, "moderate"],
    bruteforce_then_success: [5, 5, "severe"],
    beaconing: [4, 4, "moderate"],
    impossible_travel: [3, 4, "moderate"],
    suspicious_process: [4, 4, "moderate"],
    multi_signal_device: [5, 5, "severe"],
  };

  /* ---- CAS HomeNet Guard alerts (alerts.jsonl written by the Windows app) ---- */
  const HNG_SEVERITY = { Info: 0, Low: 1, Medium: 2, High: 3, Critical: 4 };
  const HNG_HARM = { 4: "severe", 3: "moderate", 2: "minor", 1: "none", 0: "none" };
  const HNG_IMPACT = { malicious_server: 5, exploit_attempt: 4, c2_beaconing: 4, port_scan: 3, worm_scanning: 5,
    data_exfiltration: 5, suspicious_program: 4, new_device: 2, exposed_service: 4, device_risk: 3,
    network_anomaly: 3, system: 2 };
  const MULTI_WINDOW = 24 * 3600, MULTI_KINDS = 3;
  const HNG_TS = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})?$/;

  function hngTime(s) {
    const m = HNG_TS.exec(String(s || ""));
    if (!m) return null;
    let t = Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]) / 1000;
    if (m[8] && m[8] !== "Z") {
      const sign = m[8][0] === "+" ? 1 : -1;
      t -= sign * (parseInt(m[8].slice(1, 3), 10) * 3600 + parseInt(m[8].slice(4, 6), 10) * 60);
    }
    if (m[7]) t += parseInt((m[7].slice(0, 3) + "000").slice(0, 3), 10) / 1000;
    return t;
  }

  function hngKind(e) {
    const src = String(e.Source || ""), title = String(e.Title || "").toLowerCase();
    if (src === "ThreatIntel" || title.includes("malicious server")) return "malicious_server";
    if (src === "Signature") return "exploit_attempt";
    if (src === "DeviceAudit") return title.includes("new device") ? "new_device" : title.includes("service") ? "exposed_service" : "device_risk";
    if (src === "Anomaly") {
      for (const [k, kind] of [["beacon", "c2_beaconing"], ["port scan", "port_scan"], ["worm", "worm_scanning"],
                               ["upload", "data_exfiltration"], ["program", "suspicious_program"]])
        if (title.includes(k)) return kind;
      return "network_anomaly";
    }
    return "system";
  }
  const ADVICE = { P1: "Act now.", P2: "Investigate today.", P3: "Review when convenient.", P4: "Log and monitor." };
  const TITLES = {
    bruteforce: "Brute-force login attempts",
    bruteforce_then_success: "Possible account compromise",
    beaconing: "Possible malware beaconing",
    impossible_travel: "Impossible travel",
    suspicious_process: "Suspicious command line",
    multi_signal_device: "Device showing multiple compromise signs",
    airbag: "Airbag (SRS) fault", brakes: "ABS / brakes / stability fault", overheating: "Engine overheating",
    misfire: "Engine misfire", stall_risk: "Risk of stalling", fuel_pressure: "Fuel pressure fault", boost: "Turbo boost fault",
    charging: "Charging / voltage problem", transmission: "Gearbox fault", speed_sensor: "Speed sensor fault",
    dpf: "Particulate filter overloaded", fuel_trim: "Fuel mixture problem", cooling: "Cooling system fault",
    emissions: "Emissions fault (MOT risk)", network: "Module communication fault", engine: "Engine fault",
    body: "Body electronics fault", battery: "Battery low", oil_overheat: "Oil overheating",
    charging_trend: "Charging voltage falling", fuel_trim_trend: "Fuel mixture drifting", sensor_jump: "Sensor glitch",
    vehicle_test_fail: "Failed vehicle check", vehicle_test_check: "Vehicle check to review",
  };

  // Format numbers like Python's repr(float) so phone and PC alerts read identically.
  function pyFloat(x) { return Number.isInteger(x) ? x.toFixed(1) : String(x); }
  function round(x, dp) { const f = Math.pow(10, dp); return Math.round(x * f) / f; }
  function mean(a) { return a.reduce((s, v) => s + v, 0) / a.length; }
  function pstdev(a) { const m = mean(a); return Math.sqrt(a.reduce((s, v) => s + (v - m) * (v - m), 0) / a.length); }


  /* ======================= CAS OBD Scanner (vehicle) =======================
     Port of cortex/vehicle.py - keep the two identical (tests/test_vehicle.py). */
  const DTC_RE_G = /\b([PCBU][0-3][0-9A-F]{3})\b/g, DTC_START = /^([PCBU][0-3][0-9A-F]{3})\b/;
  const DTC_TXT = {"P0087": "Fuel rail/system pressure too low", "P0088": "Fuel rail/system pressure too high", "P0100": "MAF sensor circuit", "P0101": "MAF sensor range/performance", "P0102": "MAF sensor circuit low", "P0103": "MAF sensor circuit high", "P0106": "MAP sensor range/performance", "P0110": "Intake air temp sensor circuit", "P0115": "Coolant temp sensor circuit", "P0116": "Coolant temp sensor range/performance", "P0120": "Throttle position sensor circuit", "P0128": "Coolant below thermostat regulating temperature", "P0130": "O2 sensor circuit (B1S1)", "P0133": "O2 sensor slow response (B1S1)", "P0135": "O2 sensor heater circuit (B1S1)", "P0141": "O2 sensor heater circuit (B1S2)", "P0171": "System too lean (bank 1)", "P0172": "System too rich (bank 1)", "P0174": "System too lean (bank 2)", "P0175": "System too rich (bank 2)", "P0234": "Turbo/supercharger overboost", "P0299": "Turbo/supercharger underboost", "P0300": "Random/multiple cylinder misfire", "P0301": "Cylinder 1 misfire", "P0302": "Cylinder 2 misfire", "P0303": "Cylinder 3 misfire", "P0304": "Cylinder 4 misfire", "P0305": "Cylinder 5 misfire", "P0306": "Cylinder 6 misfire", "P0325": "Knock sensor 1 circuit (bank 1)", "P0335": "Crankshaft position sensor A circuit", "P0340": "Camshaft position sensor A circuit (bank 1)", "P0380": "Glow plug/heater circuit A", "P0400": "EGR flow", "P0401": "EGR insufficient flow", "P0402": "EGR excessive flow", "P0420": "Catalyst efficiency below threshold (bank 1)", "P0430": "Catalyst efficiency below threshold (bank 2)", "P0440": "EVAP system", "P0442": "EVAP system small leak", "P0455": "EVAP system large leak", "P0456": "EVAP system very small leak", "P0500": "Vehicle speed sensor", "P0505": "Idle air control system", "P0507": "Idle speed higher than expected", "P0562": "System voltage low", "P0563": "System voltage high", "P0600": "Serial communication link", "P0700": "Transmission control system (see TCM codes)", "P2002": "Diesel particulate filter efficiency below threshold", "P2463": "Diesel particulate filter soot accumulation", "U0100": "Lost communication with engine control module", "U0121": "Lost communication with ABS control module", "U0151": "Lost communication with airbag (restraints) control module"};
  const DTC_SYS = { P: "Powertrain", C: "Chassis", B: "Body", U: "Network" };
  const KIND_LABEL = {"airbag": "Airbag (SRS) system fault", "brakes": "ABS, brakes, stability or steering fault", "misfire": "Engine misfire", "overheating": "Over-temperature fault", "transmission": "Gearbox fault", "charging": "System voltage fault", "emissions": "Emissions system fault", "network": "Module communication fault"};
  const DTC_RULES = [["B", "0001", "0099", "airbag", 4, 5, "severe", "The airbag (SRS) system has a fault and may not deploy in a crash. Get it checked before carrying passengers."], ["U", "0151", "0151", "airbag", 3, 5, "severe", "The car has lost contact with the airbag module - the airbags may not deploy. Get it checked promptly."], ["U", "0121", "0129", "brakes", 3, 5, "severe", "The car has lost contact with the ABS/stability module - ABS and stability control may be off. Drive gently and get it checked."], ["C", "0000", "3FFF", "brakes", 4, 5, "severe", "Chassis fault (ABS, brakes, stability control or steering). These systems may be disabled - drive gently and get it checked promptly."], ["P", "0217", "0218", "overheating", 5, 5, "severe", "Engine or gearbox over-temperature. Stop safely and let it cool - driving on can wreck the engine."], ["P", "0300", "0312", "misfire", 5, 4, "moderate", "Engine misfire. Avoid hard acceleration. If the check-engine light flashes, stop - unburnt fuel can overheat the catalytic converter."], ["P", "0335", "0349", "stall_risk", 4, 4, "moderate", "Crankshaft/camshaft sensor fault - the engine may cut out or fail to restart. Fix it before a long journey."], ["P", "0087", "0088", "fuel_pressure", 4, 4, "moderate", "Fuel pressure fault - possible loss of power or stalling."], ["P", "0234", "0234", "boost", 4, 4, "moderate", "Turbo overboost - can damage the engine. Avoid full throttle until checked."], ["P", "0560", "0563", "charging", 4, 4, "moderate", "System voltage fault - the battery or alternator may be failing and could leave you stranded."], ["P", "0700", "0799", "transmission", 4, 4, "moderate", "Gearbox fault - gear changes may be affected or the car may go into limp mode."], ["P", "0500", "0503", "speed_sensor", 3, 4, "moderate", "Vehicle speed sensor fault - the speedometer, ABS or gearbox may behave oddly."], ["P", "2463", "2463", "dpf", 4, 3, "moderate", "Diesel particulate filter is overloaded with soot - it needs a regeneration drive soon or the car may go into limp mode."], ["P", "0171", "0175", "fuel_trim", 4, 3, "minor", "Fuel mixture lean or rich - check for air leaks, the MAF sensor or fuel delivery."], ["P", "0299", "0299", "boost", 4, 3, "minor", "Turbo underboost - reduced power. Check the boost hoses and wastegate."], ["P", "0115", "0128", "cooling", 3, 3, "minor", "Cooling sensor or thermostat fault - keep an eye on the temperature gauge."], ["P", "2002", "2002", "emissions", 4, 3, "minor", "Diesel particulate filter efficiency low - an MOT failure risk."], ["P", "0400", "0499", "emissions", 4, 2, "minor", "Emissions system fault (catalyst, EGR or EVAP) - likely an MOT failure rather than a safety issue."], ["U", "0000", "3FFF", "network", 3, 4, "moderate", "Module communication fault - some systems may not work correctly."], ["P", "0000", "3FFF", "engine", 3, 3, "minor", "Engine or powertrain fault - get the code diagnosed."], ["B", "0000", "3FFF", "body", 3, 2, "none", "Body electronics fault (lights, locks or comfort systems) - usually not urgent."]];
  const TEST_IMPACT = {"Engine": 4, "Electrical": 4, "Fuel and air": 3, "Emissions": 2, "Communication": 2, "Adapter": 1, "Vehicle identity": 1};
  const JUMP = {"Coolant temperature": 8.0, "Control module voltage": 1.0, "Long term fuel trim B1": 8.0, "Long term fuel trim B2": 8.0, "Engine oil temperature": 8.0};
  const NUM_RE = /^[+-]?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?$/;

  function r1(x) { return (Math.floor(x * 10 + 0.5) / 10).toFixed(1); }
  function num(x) {
    if (x === null || x === undefined || typeof x === "boolean") return null;
    if (typeof x === "number") return isFinite(x) ? x : null;
    const t = String(x).trim();
    return NUM_RE.test(t) ? parseFloat(t) : null;
  }
  function classifyDtc(code) {
    for (const [letter, lo, hi, kind, L, I, harm, advice] of DTC_RULES)
      if (code[0] === letter && lo <= code.slice(1) && code.slice(1) <= hi) return [kind, L, I, harm, advice];
    return ["engine", 3, 3, "minor", "Get the code diagnosed."];
  }
  function dtcText(code) {
    if (DTC_TXT[code]) return DTC_TXT[code];
    const generic = "02".includes(code[1]);
    const base = KIND_LABEL[classifyDtc(code)[0]] || (DTC_SYS[code[0]] + " fault");
    return base + (generic ? " (generic code)" : " (manufacturer-specific code - look up for your make)");
  }
  function findCodes(text) {
    const seen = new Set(), out = [];
    for (const m of String(text || "").matchAll(DTC_RE_G)) if (!seen.has(m[1])) { seen.add(m[1]); out.push(m[1]); }
    return out;
  }
  function finding(kind, entity, ts, detail, L, I, harm, advice) {
    return { kind, entity, ts, detail, profile: [Math.max(1, Math.min(5, L)), I, harm], advice };
  }
  function dtcFindings(codes, entity, ts, status) {
    return codes.map(c => {
      let [kind, L, I, harm, advice] = classifyDtc(c);
      let label = `${c} ${dtcText(c)}`;
      if (status === "pending") { L -= 1; label += " (pending - seen recently, not yet confirmed)"; }
      else if (status === "permanent") label += " (permanent - clears itself once the repair is confirmed)";
      return finding(kind, entity, ts, label, L, I, harm, advice);
    });
  }
  function stripBom(t) { return String(t || "").replace(/^﻿/, ""); }
  function vehicleDetect(text) {
    const head = stripBom(text).trimStart();
    const first = head.split("\n", 1)[0].trim().toLowerCase();
    if (first.startsWith("group,command,test,result,value,explanation,expected")) return "test_report";
    if (first.startsWith("timestamp,pid,sensor,value,unit")) return "data_log";
    if (head.startsWith("{")) {
      try { const d = JSON.parse(head); if (d && typeof d === "object" && !Array.isArray(d) && Array.isArray(d.checks)) return "health"; }
      catch (_) {}
    }
    return null;
  }
  function parseCsv(text) {                       // RFC 4180, like Python's csv module
    const t = stripBom(text).trim(), rows = []; let row = [], f = "", q = false;
    for (let i = 0; i < t.length; i++) {
      const c = t[i];
      if (q) { if (c === '"') { if (t[i + 1] === '"') { f += '"'; i++; } else q = false; } else f += c; }
      else if (c === '"') q = true;
      else if (c === ",") { row.push(f); f = ""; }
      else if (c === "\n" || c === "\r") { if (c === "\r" && t[i + 1] === "\n") i++; row.push(f); rows.push(row); row = []; f = ""; }
      else f += c;
    }
    if (f !== "" || row.length) { row.push(f); rows.push(row); }
    return rows;
  }
  function testReportFindings(text, now) {
    const rows = parseCsv(text).slice(1);
    let entity = "vehicle";
    for (const r of rows) if (r.length >= 5 && r[2] === "VIN" && r[4].trim().length === 17) entity = r[4].trim();
    const out = [];
    for (const r of rows) {
      if (r.length < 6) continue;
      const [group, , test, result, value, note] = r;
      if (group === "Fault codes") {
        const status = test.includes("Pending") ? "pending" : test.includes("Permanent") ? "permanent" : "";
        out.push(...dtcFindings(findCodes(value), entity, now, status));
        continue;
      }
      if (result !== "Fail" && result !== "Check") continue;
      const I = TEST_IMPACT[group] ?? 2;
      const detail = value ? `${test}: ${value} - ${note}` : `${test} - ${note}`;
      if (test === "Coolant temperature" && result === "Fail")
        out.push(finding("overheating", entity, now, detail, 5, 5, "severe", "The engine is overheating. Stop safely and let it cool - driving on can wreck the engine."));
      else if (result === "Fail")
        out.push(finding("vehicle_test_fail", entity, now, detail, 4, I, (group === "Engine" || group === "Electrical") ? "moderate" : "minor", "Failed check - see the explanation and get it looked at."));
      else
        out.push(finding("vehicle_test_check", entity, now, detail, 3, I, "none", "Worth checking - not urgent on its own."));
    }
    return out;
  }
  function slope(ys) {
    const n = ys.length, mx = (n - 1) / 2; let my = 0; for (const y of ys) my += y; my /= n;
    let a = 0, b = 0;
    ys.forEach((y, i) => { a += (i - mx) * (y - my); });
    for (let i = 0; i < n; i++) b += (i - mx) * (i - mx);
    return b ? a / b : 0;
  }
  function healthFindings(text, now) {
    const d = JSON.parse(stripBom(text));
    const entity = (typeof d.vin === "string" && d.vin.trim()) ? d.vin.trim() : "vehicle";
    const h = (d.checks || []).filter(c => c && typeof c === "object" && !Array.isArray(c));
    if (!h.length) return [];
    const L = h[h.length - 1], ts = hngTime(L.t) || now;
    const rpm = num(L.rpm), v = num(L.vRun), cool = num(L.coolant), lt = num(L.ltft), run = num(L.runtime);
    const out = [], running = rpm !== null && rpm > 500;
    if (running && v !== null && v < 13.2) out.push(finding("charging", entity, ts, `Charging voltage low (${r1(v)} V with the engine running)`, 4, 4, "moderate", "The alternator may be failing - the battery will run down and the car could stop."));
    if (running && v !== null && v > 15) out.push(finding("charging", entity, ts, `Overcharging (${r1(v)} V)`, 4, 4, "moderate", "Suspect the voltage regulator - overcharging damages the battery and electronics."));
    if (rpm !== null && rpm < 300 && v !== null && v < 12.2) out.push(finding("battery", entity, ts, `Battery low with the engine off (${r1(v)} V)`, 3, 3, "minor", "Charge or test the battery - it may not start the car on a cold morning."));
    if (running && cool !== null && cool >= 112) out.push(finding("overheating", entity, ts, `Coolant at ${r1(cool)} °C`, 5, 5, "severe", "The engine is overheating. Stop safely and let it cool - driving on can wreck the engine."));
    if (lt !== null && Math.abs(lt) > 10) out.push(finding("fuel_trim", entity, ts, `Long-term fuel trim ${r1(lt)}% (${lt > 0 ? "lean - air leak or fuel delivery" : "rich"})`, 3, 3, "minor", "The engine is compensating for a mixture problem - check before it sets a P0171/P0172."));
    if (run !== null && run > 900 && cool !== null && cool < 75) out.push(finding("cooling", entity, ts, `Coolant only ${r1(cool)} °C after ${Math.floor(run / 60 + 0.5)} min`, 3, 2, "minor", "The thermostat may be sticking open - poor heating and higher fuel use."));
    const runs = h.filter(c => (num(c.rpm) || 0) > 500 && num(c.vRun) !== null).slice(-10);
    if (runs.length >= 3) {
      const drop = slope(runs.map(c => num(c.vRun))) * (runs.length - 1);
      if (drop < -0.3) out.push(finding("charging_trend", entity, ts, `Charging voltage drifted down ${r1(-drop)} V over ${runs.length} checks`, 3, 4, "minor", "The alternator or battery may be weakening."));
    }
    const lts = h.filter(c => num(c.ltft) !== null).slice(-10);
    if (lts.length >= 3) {
      const dr = slope(lts.map(c => num(c.ltft))) * (lts.length - 1);
      if (Math.abs(dr) > 5) out.push(finding("fuel_trim_trend", entity, ts, `Fuel trim drifting ${dr > 0 ? "lean" : "rich"} (${r1(dr)}% over ${lts.length} checks)`, 3, 3, "minor", "Catch it early - before a P0171/P0172 fault code is set."));
    }
    return out;
  }
  function dataLogFindings(text, now) {
    const series = new Map();
    for (const r of parseCsv(text).slice(1)) {
      if (r.length < 4) continue;
      const v = num(r[3]); if (v === null) continue;
      if (!series.has(r[2])) series.set(r[2], []);
      series.get(r[2]).push([hngTime(r[0]) || now, v]);
    }
    const out = [], ent = "vehicle";
    const firstOver = (name, lim) => (series.get(name) || []).find(p => p[1] >= lim) || null;
    let hit = firstOver("Coolant temperature", 112);
    if (hit) out.push(finding("overheating", ent, hit[0], `Coolant reached ${r1(Math.max(...series.get("Coolant temperature").map(p => p[1])))} °C`, 5, 5, "severe", "The engine overheated. Stop safely and let it cool - check coolant level and fan."));
    hit = firstOver("Engine oil temperature", 130);
    if (hit) out.push(finding("oil_overheat", ent, hit[0], `Oil temperature reached ${r1(hit[1])} °C`, 4, 4, "moderate", "Oil this hot loses protection - ease off and check oil level and cooling."));
    const volts = series.get("Control module voltage") || [];
    if (volts.length) {
      let lo = volts[0], hi = volts[0];
      for (const p of volts) { if (p[1] < lo[1]) lo = p; if (p[1] > hi[1]) hi = p; }
      if (lo[1] < 11.0) out.push(finding("charging", ent, lo[0], `Supply voltage dropped to ${r1(lo[1])} V`, 4, 4, "moderate", "A weak battery, poor earth or failing alternator - the car could cut out."));
      if (hi[1] > 15.2) out.push(finding("charging", ent, hi[0], `Supply voltage rose to ${r1(hi[1])} V`, 4, 4, "moderate", "Suspect the voltage regulator - overcharging damages the battery and electronics."));
    }
    for (const name of ["Long term fuel trim B1", "Long term fuel trim B2"]) {
      const s = series.get(name) || [];
      if (s.length >= 5) {
        let m = 0; for (const p of s) m += p[1]; m /= s.length;
        if (Math.abs(m) > 10) out.push(finding("fuel_trim", ent, s[s.length - 1][0], `${name} averaged ${r1(m)}%`, 3, 3, "minor", "The engine is compensating for a mixture problem - check for air leaks or the MAF sensor."));
      }
    }
    for (const [name, jump] of Object.entries(JUMP)) {
      const s = series.get(name) || []; const w = 20; let n = 0, first = null;
      for (let i = w; i < s.length; i++) {
        let m = 0; for (let k = i - w; k < i; k++) m += s[k][1]; m /= w;
        let ss = 0; for (let k = i - w; k < i; k++) ss += (s[k][1] - m) * (s[k][1] - m);
        const sd = Math.sqrt(ss / w), x = s[i][1];
        if (Math.abs(x - m) >= jump && (sd === 0 || Math.abs(x - m) / sd > 4)) { n++; first = first || s[i]; }
      }
      if (n) out.push(finding("sensor_jump", ent, first[0], `${n} sudden jump(s) in ${name} (first to ${r1(first[1])})`, 2, 2, "none", "Could be a loose connector or failing sensor - watch for it again."));
    }
    return out;
  }
  function vehicleFindings(text, now) {
    const k = vehicleDetect(text);
    if (k === "test_report") return testReportFindings(text, now);
    if (k === "health") return healthFindings(text, now);
    if (k === "data_log") return dataLogFindings(text, now);
    return null;
  }

  function beaconAnalysis(timestamps) {
    const ts = [...timestamps].sort((a, b) => a - b);
    const iv = ts.slice(1).map((t, i) => t - ts[i]);
    if (iv.length < 3) return { beacon: false, mean_interval: null, jitter: null };
    const m = mean(iv);
    if (m === 0) return { beacon: false, mean_interval: 0, jitter: null };
    const j = pstdev(iv) / m;
    return { beacon: j < 0.1 && m >= 1, mean_interval: round(m, 3), jitter: round(j, 4) };
  }

  function haversineKm(lat1, lon1, lat2, lon2) {
    const r = Math.PI / 180, p1 = lat1 * r, p2 = lat2 * r, dp = p2 - p1, dl = (lon2 - lon1) * r;
    const h = Math.sin(dp / 2) ** 2 + Math.cos(p1) * Math.cos(p2) * Math.sin(dl / 2) ** 2;
    return 2 * 6371.0 * Math.asin(Math.sqrt(h));
  }

  function travelCheck(a, b, maxKmh = 900) {
    if (b.ts < a.ts) [a, b] = [b, a];
    const km = haversineKm(a.lat, a.lon, b.lat, b.lon);
    const dt = b.ts - a.ts;
    let speed;
    if (dt === 0) { if (km === 0) return null; speed = Infinity; } else speed = km / (dt / 3600);
    return speed > maxKmh ? (isFinite(speed) ? round(speed, 1) : Infinity) : null;
  }

  function cmdIndicators(cmd) {
    return Object.keys(CMD_RULES).filter(n => CMD_RULES[n].some(re => re.test(cmd))).sort();
  }

  function prioritise(L, I, C, harm) {
    const s = L * I * C;
    const p = (harm === "severe" || harm === "catastrophic" || s >= 45) ? "P1" : s >= 20 ? "P2" : s >= 8 ? "P3" : "P4";
    return { score: s, priority: p };
  }

  function parseLine(line, nowYear) {
    line = (line || "").trim();
    if (!line) return null;
    if (line[0] === "{") {
      let e;
      try { e = JSON.parse(line); } catch (_) { return null; }
      if (!e || typeof e !== "object" || Array.isArray(e)) return null;
      if ("TimeUtc" in e && "Title" in e && "Severity" in e) {        // CAS HomeNet Guard alert
        const ts = hngTime(e.TimeUtc);
        return Object.assign({}, e, { type: "hng_alert", ts: ts === null ? Date.now() / 1000 : ts });
      }
      if (!("type" in e)) return null;
      if (e.ts === undefined) e.ts = Date.now() / 1000;
      return e;
    }
    let ts = Date.now() / 1000;
    const m = SYSLOG_TS.exec(line);
    if (m && m[1] in MONTHS) {
      ts = new Date(nowYear || new Date().getFullYear(), MONTHS[m[1]], +m[2], +m[3], +m[4], +m[5]).getTime() / 1000;
    }
    let f = FAIL.exec(line);
    if (f) return { ts, type: "auth_fail", source: f[1] };
    f = OK.exec(line);
    if (f) return { ts, type: "auth_ok", source: f[2], user: f[1] };
    return null;
  }

  class Monitor {
    constructor(opts = {}) {
      this.failCount = opts.failCount || 5;
      this.failWindow = opts.failWindow || 60;
      this.criticality = opts.criticality || {};
      this.fails = new Map(); this.recentBurst = new Map(); this.conns = new Map();
      this.beaconAlerted = new Set(); this.lastLogin = new Map();
      this.alerts = []; this.events = 0; this.seq = 0;
      this.hngSeen = new Map(); this.hngEscalated = new Map(); this.hngIds = new Set();
    }
    feed(line) {
      const e = parseLine(line);
      if (!e) return [];
      this.events++;
      const out = [];
      const t = e.type;
      if (t === "auth_fail") {
        const q = this.fails.get(e.source) || [];
        q.push(e.ts);
        while (q.length && e.ts - q[0] > this.failWindow) q.shift();
        this.fails.set(e.source, q);
        if (q.length >= this.failCount) {
          out.push(this.alert("bruteforce", e.source, e.ts, `${q.length} failed logins in ${Math.trunc(e.ts - q[0])}s`));
          this.recentBurst.set(e.source, e.ts);
          this.fails.set(e.source, []);
        }
      } else if (t === "auth_ok") {
        const b = this.recentBurst.get(e.source);
        if (b !== undefined && e.ts - b <= 600) {
          out.push(this.alert("bruteforce_then_success", e.source, e.ts,
            `successful login as ${e.user} shortly after a brute-force burst - possible account compromise`));
        }
      } else if (t === "conn" && e.dest) {
        const src = e.source || "?", key = src + "\u0000" + e.dest;
        const q = this.conns.get(key) || [];
        q.push(e.ts); if (q.length > 20) q.shift();
        this.conns.set(key, q);
        if (q.length >= 6 && !this.beaconAlerted.has(key)) {
          const r = beaconAnalysis(q);
          if (r.beacon) {
            this.beaconAlerted.add(key);
            out.push(this.alert("beaconing", src, e.ts,
              `regular connections to ${e.dest} every ${pyFloat(r.mean_interval)}s (jitter ${pyFloat(r.jitter)})`));
          }
        }
      } else if (t === "login" && e.user !== undefined) {
        const prev = this.lastLogin.get(e.user);
        const cur = { user: e.user, ts: e.ts, lat: e.lat, lon: e.lon };
        if (prev) {
          const sp = travelCheck(prev, cur);
          if (sp !== null) out.push(this.alert("impossible_travel", e.user, e.ts,
            `travel speed ${isFinite(sp) ? pyFloat(sp) : "inf"} km/h between logins`));
        }
        this.lastLogin.set(e.user, cur);
      } else if (t === "process" && e.cmdline) {
        const ind = cmdIndicators(e.cmdline);
        if (ind.length) out.push(this.alert("suspicious_process", e.source || "?", e.ts, "indicators: " + ind.join(", ")));
      } else if (t === "hng_alert") {
        if (e.Id && this.hngIds.has(e.Id)) { this.events--; return []; }
        if (e.Id) this.hngIds.add(e.Id);
        out.push(...this.homenet(e));
      }
      return out;
    }
    homenet(e) {
      const status = String(e.Status ?? "Open");
      let sev = e.Severity;
      sev = Number.isInteger(sev) ? sev : (HNG_SEVERITY[String(sev)] ?? 2);
      if (status === "Ignored" || status === "Resolved" || sev <= 0) return [];
      const kind = hngKind(e);
      const local = e.LocalIp || "", remote = e.RemoteIp || "";
      const entity = local || remote || "?";
      const L = Math.min(5, sev + 1 + (e.HighConfidence ? 1 : 0));
      let detail = String(e.Title ?? "");
      if (e.Detail) detail += " - " + e.Detail;
      if (remote && remote !== entity) detail += ` (remote ${remote}` + (e.RemotePort ? `:${e.RemotePort}` : "") + ")";
      if (status === "Blocked") detail += " [already blocked by HomeNet Guard]";
      const out = [this.alert(kind, entity, e.ts, detail, [L, HNG_IMPACT[kind], HNG_HARM[sev]], e.Recommendation || null, e.Title)];
      if (local) {
        const hist = this.hngSeen.get(local) || [];
        hist.push([e.ts, kind]);
        while (hist.length && e.ts - hist[0][0] > MULTI_WINDOW) hist.shift();
        this.hngSeen.set(local, hist);
        const kinds = [...new Set(hist.map(h => h[1]))].sort();
        const last = this.hngEscalated.get(local);
        if (kinds.length >= MULTI_KINDS && (last === undefined || e.ts - last > MULTI_WINDOW)) {
          this.hngEscalated.set(local, e.ts);
          out.push(this.alert("multi_signal_device", local, e.ts,
            `${kinds.length} different warning signs within 24h: ` + kinds.join(", "), null,
            "Treat this device as compromised: disconnect it from the network, then factory-reset it or run a full malware scan before reconnecting."));
        }
      }
      return out;
    }
    alert(kind, entity, ts, detail, profile, advice, title) {
      this.seq++;
      const [L, I, harm] = profile || RISK_PROFILE[kind];
      const crit = Math.max(1, Math.min(3, parseInt(this.criticality[entity] || 2, 10)));
      const pr = prioritise(L, I, crit, harm);
      const a = { id: "A" + this.seq, ts, kind, title: title || TITLES[kind], entity, detail,
                  score: pr.score, priority: pr.priority, advice: advice || ADVICE[pr.priority] };
      this.alerts.push(a);
      return a;
    }
    applyFindings(findings) {
      const best = new Map();
      for (const f of findings) {
        const m = DTC_START.exec(f.detail);
        const key = JSON.stringify([f.kind, f.entity, m ? f.detail.slice(0, 5) : f.detail]);
        const cur = best.get(key);
        if (!cur) best.set(key, f);
        else if (f.profile[0] * f.profile[1] > cur.profile[0] * cur.profile[1]) best.set(key, f);
      }
      return [...best.values()].map(f => this.alert(f.kind, f.entity, f.ts, f.detail, f.profile, f.advice,
        f.kind.startsWith("vehicle_test") ? f.detail.split(/: | - /)[0] : null));
    }
    feedText(text, now) {
      now = now ?? Date.now() / 1000;
      this.source = null;
      let found = null;
      try { found = vehicleFindings(text, now); } catch (_) { found = null; }
      if (found !== null) {                       // a CAS OBD Scanner export
        this.source = "obd_" + vehicleDetect(text);
        this.events += 1;
        this.applyFindings(found);
        return this.alerts;
      }
      for (const line of text.split(/\r?\n/)) this.feed(line);
      if (this.events === 0) {
        const codes = findCodes(text);
        if (codes.length) { this.source = "obd_codes"; this.events += 1; this.applyFindings(dtcFindings(codes, "vehicle", now, "")); }
      }
      return this.alerts;
    }
  }

  function parseCriticality(text) {
    const out = {};
    for (const part of (text || "").split(/[\s,]+/)) {
      if (!part) continue;
      const [k, v] = part.split("=");
      out[k] = parseInt(v || "3", 10);
    }
    return out;
  }

  return { Monitor, vehicleDetect, vehicleFindings, findCodes, dtcText, beaconAnalysis, travelCheck, cmdIndicators, prioritise, parseLine, parseCriticality,
           haversineKm, ADVICE, TITLES };
});
