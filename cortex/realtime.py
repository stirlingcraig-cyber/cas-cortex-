"""Real-time threat, risk and harm monitor.

Reads a log stream (a file, optionally followed like `tail -f`, or stdin) and raises
prioritised alerts. Accepts:
  - sshd auth lines ("Failed password for ... from <ip>", "Accepted password ...")
  - JSON lines events:
      {"ts": 1700000000, "type": "auth_fail", "source": "10.0.0.5"}
      {"ts": ..., "type": "conn", "source": "host1", "dest": "203.0.113.9"}
      {"ts": ..., "type": "login", "user": "craig", "lat": 55.86, "lon": -4.25}
      {"ts": ..., "type": "process", "source": "host1", "cmdline": "powershell -enc ..."}

Detectors have built-in implementations. With `use_learned=True` the monitor swaps in
skills the agent has learned and verified (same contract as the training tasks), so
what Cortex learns becomes live capability. Learned code is policy-checked again first.
"""
from __future__ import annotations

import json
import math
import re
import statistics
import time
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path

from .sandbox import check_policy

_FAIL = re.compile(r"Failed password for (?:invalid user )?\S+ from (\d{1,3}(?:\.\d{1,3}){3})")
_OK = re.compile(r"Accepted \w+ for (\S+) from (\d{1,3}(?:\.\d{1,3}){3})")
_SYSLOG_TS = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2}) (\d{2}):(\d{2}):(\d{2})")


# --------------------------------------------------------------- built-ins
def builtin_beacon(timestamps):
    ts = sorted(timestamps)
    iv = [b - a for a, b in zip(ts, ts[1:])]
    if len(iv) < 3:
        return {"beacon": False, "mean_interval": None, "jitter": None}
    m = statistics.mean(iv)
    if m == 0:
        return {"beacon": False, "mean_interval": 0.0, "jitter": None}
    j = statistics.pstdev(iv) / m
    return {"beacon": j < 0.1 and m >= 1, "mean_interval": round(float(m), 3), "jitter": round(j, 4)}


def builtin_travel(logins, max_kmh=900):
    a, b = sorted(logins, key=lambda l: l["ts"])[:2]
    p1, p2 = math.radians(a["lat"]), math.radians(b["lat"])
    dp, dl = p2 - p1, math.radians(b["lon"] - a["lon"])
    h = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    km = 2 * 6371.0 * math.asin(math.sqrt(h))
    dt = b["ts"] - a["ts"]
    if dt == 0:
        if km == 0:
            return []
        speed = float("inf")
    else:
        speed = km / (dt / 3600)
    if speed > max_kmh:
        return [{"user": a["user"], "from_ts": a["ts"], "to_ts": b["ts"],
                 "speed_kmh": speed if math.isinf(speed) else round(speed, 1)}]
    return []


_CMD_RULES = {
    "encoded_command": [r"(?:^|\s)[-/]e(?:n|nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}"],
    "download_cradle": [r"downloadstring", r"downloadfile", r"invoke-webrequest", r"iwr ",
                        r"start-bitstransfer", r"(curl|wget)\b[^|]*\|\s*(ba)?sh\b"],
    "hidden_window": [r"[-/]w(?:indowstyle)?\s+hidden"],
    "execution_policy_bypass": [r"[-/](?:ep|exec|executionpolicy)\s+bypass"],
    "lolbin": [r"certutil(?:\.exe)?\b.*[-/]urlcache", r"mshta(?:\.exe)?\s+https?:",
               r"regsvr32(?:\.exe)?\b.*[-/]i:https?:", r"rundll32(?:\.exe)?\b.*javascript:"],
}


def builtin_cmdline(cmd):
    return sorted(n for n, ps in _CMD_RULES.items() if any(re.search(p, cmd, re.I) for p in ps))


_HARMS = {"none", "minor", "moderate", "severe", "catastrophic"}


def builtin_prioritise(risks):
    out = []
    for r in risks:
        s = r["likelihood"] * r["impact"] * r["criticality"]
        p = ("P1" if r["harm"] in ("severe", "catastrophic") or s >= 45 else
             "P2" if s >= 20 else "P3" if s >= 8 else "P4")
        out.append({"id": r["id"], "score": s, "priority": p})
    return sorted(out, key=lambda x: (x["priority"], -x["score"], x["id"]))


LEARNABLE = {
    "beacon_analysis": builtin_beacon,
    "impossible_travel": builtin_travel,
    "suspicious_commandline": builtin_cmdline,
    "prioritise_risks": builtin_prioritise,
}

# How each alert kind maps to likelihood / impact / harm before asset criticality.
RISK_PROFILE = {
    "bruteforce": (4, 3, "moderate"),
    "bruteforce_then_success": (5, 5, "severe"),
    "beaconing": (4, 4, "moderate"),
    "impossible_travel": (3, 4, "moderate"),
    "suspicious_process": (4, 4, "moderate"),
    "multi_signal_device": (5, 5, "severe"),
}


# ------------------------------------------------------- CAS HomeNet Guard
# HomeNet Guard (C#) writes one JSON alert per line to
# C:\ProgramData\CAS Solutions\HomeNetGuard\alerts.jsonl, e.g.
# {"Id": "...", "TimeUtc": "2026-11-17T18:00:00.1234567Z", "Severity": "High", "Source": "Anomaly",
#  "Title": "Port scan detected", "Detail": "...", "LocalIp": "192.168.1.20", "RemoteIp": "...",
#  "RemotePort": 23, "Recommendation": "...", "Status": "Open", "HighConfidence": false}
HNG_DEFAULT_PATH = r"C:\ProgramData\CAS Solutions\HomeNetGuard\alerts.jsonl"
HNG_SEVERITY = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
HNG_HARM = {4: "severe", 3: "moderate", 2: "minor", 1: "none", 0: "none"}
HNG_IMPACT = {"malicious_server": 5, "exploit_attempt": 4, "c2_beaconing": 4, "port_scan": 3,
              "worm_scanning": 5, "data_exfiltration": 5, "suspicious_program": 4, "new_device": 2,
              "exposed_service": 4, "device_risk": 3, "network_anomaly": 3, "system": 2}
MULTI_SIGNAL_WINDOW = 24 * 3600
MULTI_SIGNAL_KINDS = 3
_HNG_TS = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})?$")


def hng_time(s) -> float | None:
    """Parse .NET's ISO time (up to 7 fractional digits, usually ending in Z) as UTC seconds."""
    m = _HNG_TS.match(str(s or ""))
    if not m:
        return None
    y, mo, d, h, mi, se, frac, tz = m.groups()
    from datetime import timezone, timedelta
    tzinfo = timezone.utc
    if tz and tz != "Z":
        sign = 1 if tz[0] == "+" else -1
        tzinfo = timezone(sign * timedelta(hours=int(tz[1:3]), minutes=int(tz[4:6])))
    dt = datetime(int(y), int(mo), int(d), int(h), int(mi), int(se), tzinfo=tzinfo)
    return dt.timestamp() + (int(frac[:3].ljust(3, "0")) / 1000 if frac else 0.0)


def hng_kind(e: dict) -> str:
    src, title = str(e.get("Source", "")), str(e.get("Title", "")).lower()
    if src == "ThreatIntel" or "malicious server" in title:
        return "malicious_server"
    if src == "Signature":
        return "exploit_attempt"
    if src == "DeviceAudit":
        return ("new_device" if "new device" in title else
                "exposed_service" if "service" in title else "device_risk")
    if src == "Anomaly":
        for key, kind in (("beacon", "c2_beaconing"), ("port scan", "port_scan"), ("worm", "worm_scanning"),
                          ("upload", "data_exfiltration"), ("program", "suspicious_program")):
            if key in title:
                return kind
        return "network_anomaly"
    return "system"


def load_learned(skill_code: dict[str, str]) -> dict:
    """Return {name: callable} for learned detector skills that pass policy."""
    fns = {}
    for name in LEARNABLE:
        code = skill_code.get(name)
        if not code or check_policy(code) or "from skills" in code:
            continue
        ns: dict = {"__name__": f"learned_{name}"}
        try:
            exec(compile(code, f"<skill {name}>", "exec"), ns)  # policy-checked, verified skill
            if callable(ns.get(name)):
                fns[name] = ns[name]
        except Exception:
            continue
    return fns


class ThreatMonitor:
    def __init__(self, fail_count: int = 5, fail_window: int = 60, criticality: dict | None = None,
                 learned: dict | None = None, triage=None, alerts_path: Path | None = None,
                 out=print):
        self.fail_count, self.fail_window = fail_count, fail_window
        self.criticality = criticality or {}
        self.fn = dict(LEARNABLE)
        self.fn.update(learned or {})
        self.learned_names = sorted((learned or {}).keys())
        self.triage = triage
        self.alerts_path = alerts_path
        self.out = out
        self.fails = defaultdict(deque)
        self.recent_burst = {}
        self.conns = defaultdict(lambda: deque(maxlen=20))
        self.beacon_alerted = set()
        self.last_login = {}
        self.alerts: list[dict] = []
        self.events = 0
        self._seq = 0
        self.hng_seen = defaultdict(deque)
        self.hng_escalated = {}
        self.hng_ids = set()

    # ---------------------------------------------------------------- parsing
    @staticmethod
    def parse(line: str) -> dict | None:
        line = line.strip()
        if not line:
            return None
        if line.startswith("{"):
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                return None
            if not isinstance(e, dict):
                return None
            if "TimeUtc" in e and "Title" in e and "Severity" in e:   # CAS HomeNet Guard alert
                ts = hng_time(e["TimeUtc"])
                return dict(e, type="hng_alert", ts=ts if ts is not None else time.time())
            e.setdefault("ts", time.time())
            return e if "type" in e else None
        ts = time.time()
        m = _SYSLOG_TS.match(line)
        if m:
            try:
                ts = datetime.strptime(f"{datetime.now().year} {m.group(1)} {m.group(2)} "
                                       f"{m.group(3)}:{m.group(4)}:{m.group(5)}",
                                       "%Y %b %d %H:%M:%S").timestamp()
            except ValueError:
                pass
        m = _FAIL.search(line)
        if m:
            return {"ts": ts, "type": "auth_fail", "source": m.group(1)}
        m = _OK.search(line)
        if m:
            return {"ts": ts, "type": "auth_ok", "source": m.group(2), "user": m.group(1)}
        return None

    # -------------------------------------------------------------- detection
    def feed(self, line: str) -> list[dict]:
        e = self.parse(line)
        if e is None:
            return []
        self.events += 1
        t = e.get("type")
        raised = []
        if t == "auth_fail":
            q = self.fails[e["source"]]
            q.append(e["ts"])
            while q and e["ts"] - q[0] > self.fail_window:
                q.popleft()
            if len(q) >= self.fail_count:
                raised.append(self._alert("bruteforce", e["source"], e["ts"],
                                          f"{len(q)} failed logins in {int(e['ts'] - q[0])}s"))
                self.recent_burst[e["source"]] = e["ts"]
                q.clear()
        elif t == "auth_ok":
            b = self.recent_burst.get(e["source"])
            if b is not None and e["ts"] - b <= 600:
                raised.append(self._alert("bruteforce_then_success", e["source"], e["ts"],
                                          f"successful login as {e.get('user')} shortly after a "
                                          f"brute-force burst - possible account compromise"))
        elif t == "conn" and e.get("dest"):
            key = (e.get("source", "?"), e["dest"])
            self.conns[key].append(e["ts"])
            if len(self.conns[key]) >= 6 and key not in self.beacon_alerted:
                r = self.fn["beacon_analysis"](list(self.conns[key]))
                if r.get("beacon"):
                    self.beacon_alerted.add(key)
                    raised.append(self._alert("beaconing", key[0], e["ts"],
                                              f"regular connections to {key[1]} every "
                                              f"{r['mean_interval']}s (jitter {r['jitter']})"))
        elif t == "login" and "user" in e:
            prev = self.last_login.get(e["user"])
            cur = {"user": e["user"], "ts": e["ts"], "lat": e["lat"], "lon": e["lon"]}
            if prev:
                hits = self.fn["impossible_travel"]([prev, cur])
                for h in hits:
                    raised.append(self._alert("impossible_travel", e["user"], e["ts"],
                                              f"travel speed {h['speed_kmh']} km/h between logins"))
            self.last_login[e["user"]] = cur
        elif t == "process" and e.get("cmdline"):
            ind = self.fn["suspicious_commandline"](e["cmdline"])
            if ind:
                raised.append(self._alert("suspicious_process", e.get("source", "?"), e["ts"],
                                          "indicators: " + ", ".join(ind)))
        elif t == "hng_alert":
            hid = e.get("Id")
            if hid and hid in self.hng_ids:      # same alert again after HomeNet Guard rewrote its file
                self.events -= 1
                return []
            if hid:
                self.hng_ids.add(hid)
            raised += self._homenet(e)
        return raised

    def _homenet(self, e: dict) -> list[dict]:
        """Turn a HomeNet Guard alert into a ranked Cortex alert, and escalate any home device
        that shows several different kinds of compromise sign within 24 hours."""
        status = str(e.get("Status", "Open"))
        sev = e.get("Severity")
        sev = sev if isinstance(sev, int) else HNG_SEVERITY.get(str(sev), 2)
        if status in ("Ignored", "Resolved") or sev <= 0:
            return []
        kind = hng_kind(e)
        local, remote = e.get("LocalIp") or "", e.get("RemoteIp") or ""
        entity = local or remote or "?"
        L = min(5, sev + 1 + (1 if e.get("HighConfidence") else 0))
        detail = str(e.get("Title", ""))
        if e.get("Detail"):
            detail += " - " + str(e["Detail"])
        if remote and remote != entity:
            detail += f" (remote {remote}" + (f":{e['RemotePort']}" if e.get("RemotePort") else "") + ")"
        if status == "Blocked":
            detail += " [already blocked by HomeNet Guard]"
        out = [self._alert(kind, entity, e["ts"], detail,
                           profile=(L, HNG_IMPACT[kind], HNG_HARM[sev]),
                           advice=e.get("Recommendation") or None)]
        if local:
            hist = self.hng_seen[local]
            hist.append((e["ts"], kind))
            while hist and e["ts"] - hist[0][0] > MULTI_SIGNAL_WINDOW:
                hist.popleft()
            kinds = sorted({k for _, k in hist})
            last = self.hng_escalated.get(local)
            if len(kinds) >= MULTI_SIGNAL_KINDS and (last is None or e["ts"] - last > MULTI_SIGNAL_WINDOW):
                self.hng_escalated[local] = e["ts"]
                out.append(self._alert("multi_signal_device", local, e["ts"],
                                       f"{len(kinds)} different warning signs within 24h: " + ", ".join(kinds),
                                       advice="Treat this device as compromised: disconnect it from the network, "
                                              "then factory-reset it or run a full malware scan before reconnecting."))
        return out

    def _alert(self, kind: str, entity: str, ts: float, detail: str, profile=None, advice=None) -> dict:
        self._seq += 1
        L, I, harm = profile or RISK_PROFILE[kind]
        crit = int(self.criticality.get(entity, 2))
        risk = {"id": f"A{self._seq}", "likelihood": L, "impact": I,
                "criticality": max(1, min(3, crit)), "harm": harm if harm in _HARMS else "moderate"}
        pr = self.fn["prioritise_risks"]([risk])[0]
        a = {"id": risk["id"], "ts": ts, "kind": kind, "entity": entity, "detail": detail,
             "score": pr["score"], "priority": pr["priority"]}
        if advice:
            a["advice"] = advice
        if self.triage and a["priority"] in ("P1", "P2"):
            try:
                a["assessment"] = self.triage(a)
            except Exception as ex:  # triage is advisory only
                if ex.__class__.__name__ in ("Halted", "BudgetExceeded"):
                    raise
                a["assessment"] = f"(triage unavailable: {ex.__class__.__name__})"
        self.alerts.append(a)
        if self.alerts_path:
            with Path(self.alerts_path).open("a", encoding="utf-8") as f:
                f.write(json.dumps(a) + "\n")
        when = datetime.fromtimestamp(ts).strftime("%H:%M:%S")
        self.out(f"[{a['priority']}] {when} {kind:<24} {entity:<18} score={a['score']:<3} {detail}")
        if "assessment" in a:
            for line in a["assessment"].strip().splitlines():
                self.out(f"       {line}")
        return a


TRIAGE_SYSTEM = """You are a SOC analyst assistant performing defensive triage. Given one alert,
reply in at most 3 short lines:
Threat: what is most likely happening.
Harm: who/what could be harmed and how badly if it is real.
Action: the single most useful next defensive step."""


def make_triage(llm):
    def triage(alert: dict) -> str:
        msg = json.dumps({k: alert[k] for k in ("kind", "entity", "detail", "priority", "score")})
        return llm.complete(TRIAGE_SYSTEM, [{"role": "user", "content": msg}], max_tokens=200).text
    return triage


def follow(path: Path, monitor: ThreatMonitor, from_start: bool, kill_check, poll: float = 1.0):
    """Watch a log like `tail -f` WITHOUT keeping it open between checks.

    CAS HomeNet Guard rewrites its alerts.jsonl by replacing the file; on Windows that fails
    if another program holds it open. So each check opens, reads only the new bytes, and
    closes. A file that shrinks (replaced or rotated) is read again from the start; HomeNet
    Guard alerts already seen are skipped by their Id."""
    path = Path(path)
    offset = 0 if from_start or not path.exists() else path.stat().st_size
    pending, sig, ident = b"", b"", None
    while True:
        kill_check()
        try:
            st = path.stat()
        except FileNotFoundError:
            time.sleep(poll)
            continue
        new_ident = (st.st_dev, st.st_ino)
        if (ident is not None and new_ident != ident) or st.st_size < offset:
            offset, pending, sig = 0, b"", b""          # replaced, rewritten or rotated
        ident = new_ident
        try:
            with path.open("rb") as f:
                if sig:                                  # same bytes still before our position?
                    f.seek(offset - len(sig))
                    if f.read(len(sig)) != sig:
                        offset, pending, sig = 0, b"", b""
                if st.st_size > offset:
                    f.seek(offset)
                    data = f.read(st.st_size - offset)
                else:
                    data = b""
        except OSError:
            time.sleep(poll)
            continue
        if data:
            offset += len(data)
            sig = (sig + data)[-64:]
            chunk = pending + data
            lines = chunk.split(b"\n")
            pending = lines.pop()
            for line in lines:
                monitor.feed(line.decode("utf-8", errors="replace"))
        time.sleep(poll)
