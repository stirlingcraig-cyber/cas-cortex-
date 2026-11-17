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
  };

  // Format numbers like Python's repr(float) so phone and PC alerts read identically.
  function pyFloat(x) { return Number.isInteger(x) ? x.toFixed(1) : String(x); }
  function round(x, dp) { const f = Math.pow(10, dp); return Math.round(x * f) / f; }
  function mean(a) { return a.reduce((s, v) => s + v, 0) / a.length; }
  function pstdev(a) { const m = mean(a); return Math.sqrt(a.reduce((s, v) => s + (v - m) * (v - m), 0) / a.length); }

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
    feedText(text) {
      for (const line of text.split(/\r?\n/)) this.feed(line);
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

  return { Monitor, beaconAnalysis, travelCheck, cmdIndicators, prioritise, parseLine, parseCriticality,
           haversineKm, ADVICE, TITLES };
});
