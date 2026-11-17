"""iPhone app: the JavaScript threat engine must match the Python one exactly, and
publishing must push only learning data (never alerts or logs)."""
import json
import random
import shutil
import subprocess
from pathlib import Path

import pytest
from conftest import oracle_llm

from cortex.agent import CortexAgent
from cortex.config import load_config
from cortex.evaluator.taskbank import BUILTIN_TASKS
from cortex.governance import AuditLog
from cortex.memory.store import Memory
from cortex.publish import build_status, publish
from cortex.realtime import ThreatMonitor
from cortex.trainer import run_eval, train

ROOT = Path(__file__).resolve().parent.parent
quiet = lambda *a, **k: None
NODE = shutil.which("node")


def random_events(seed=7, n=600):
    rng = random.Random(seed)
    base, lines = 1763233200, []
    ips = [f"10.0.0.{i}" for i in range(1, 6)] + ["203.0.113.7"]
    for i in range(n):
        t = base + i * rng.choice([1, 2, 3, 30])
        k = rng.random()
        if k < 0.45:
            lines.append(json.dumps({"ts": t, "type": "auth_fail", "source": rng.choice(ips)}))
        elif k < 0.55:
            lines.append(json.dumps({"ts": t, "type": "auth_ok", "source": rng.choice(ips), "user": "u1"}))
        elif k < 0.75:
            lines.append(json.dumps({"ts": base + i * 60 + rng.choice([0, 0, 1]), "type": "conn",
                                     "source": rng.choice(["PC1", "PC2"]), "dest": rng.choice(["1.2.3.4", "5.6.7.8"])}))
        elif k < 0.88:
            lines.append(json.dumps({"ts": t, "type": "login", "user": rng.choice(["a", "b"]),
                                     "lat": rng.uniform(-60, 60), "lon": rng.uniform(-120, 120)}))
        else:
            lines.append(json.dumps({"ts": t, "type": "process", "source": "PC3", "cmdline": rng.choice([
                "notepad.exe a.txt", "powershell -w hidden -ep bypass", "certutil -urlcache -f http://x/a",
                "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAA="])}))
    lines.append("Mar 10 12:00:01 host sshd[1]: Failed password for root from 198.51.100.9 port 22 ssh2")
    lines.append("garbage line")
    return "\n".join(lines)


def random_hng(seed=11, n=400):
    rng = random.Random(seed)
    srcs = [("ThreatIntel", "Device contacted a known malicious server"), ("Signature", "Log4Shell probe [SIG-010]"),
            ("Anomaly", "Possible command-and-control beaconing"), ("Anomaly", "Port scan detected"),
            ("Anomaly", "Worm-like scanning from a home device"), ("Anomaly", "Unusual upload volume"),
            ("Anomaly", "Suspicious program connection"), ("Anomaly", "Odd thing"),
            ("DeviceAudit", "New device joined your network"), ("DeviceAudit", "High-risk service exposed on a device"),
            ("System", "Feeds updated")]
    lines, t = [], 1763380000
    for i in range(n):
        t += rng.choice([5, 60, 900, 3600, 20000])
        src, title = rng.choice(srcs)
        frac = rng.choice(["", ".1", ".1234567", ".500"])
        tz = rng.choice(["Z", "Z", "+01:00", "-05:30", ""])
        from datetime import datetime, timezone
        stamp = datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S") + frac + tz
        sev = rng.choice(["Info", "Low", "Medium", "High", "Critical", 2, 4])
        lines.append(json.dumps({"Id": str(i), "TimeUtc": stamp, "Severity": sev, "Source": src, "Title": title,
                                 "Detail": rng.choice(["", "detail text"]),
                                 "LocalIp": rng.choice(["192.168.1.5", "192.168.1.6", None]),
                                 "RemoteIp": rng.choice(["8.8.4.4", None]), "RemotePort": rng.choice([None, 23, 443]),
                                 "Recommendation": rng.choice([None, "Do this."]),
                                 "Status": rng.choice(["Open", "Open", "Blocked", "Ignored", "Resolved"]),
                                 "HighConfidence": rng.random() < 0.3}))
    lines += ["[1, 2]", "{\"TimeUtc\": \"bad\", \"Title\": \"x\", \"Severity\": \"High\", \"Source\": \"Anomaly\"}"]
    return "\n".join(lines)


def py_alerts(text, crit):
    m = ThreatMonitor(out=quiet, criticality=crit)
    for line in text.splitlines():
        m.feed(line)
    return [(a["kind"], a["entity"], a["priority"], a["score"], a["detail"]) for a in m.alerts], m.events


@pytest.mark.skipif(NODE is None, reason="node not installed")
@pytest.mark.parametrize("name", ["sample_auth.log", "events.jsonl", "homenet_guard_alerts.jsonl", "random", "random_hng"])
def test_js_engine_matches_python(tmp_path, name):
    text = (random_events() if name == "random" else random_hng() if name == "random_hng"
            else (ROOT / "examples" / name).read_text())
    crit = {"203.0.113.7": 3, "PC3": 1, "192.168.1.12": 3, "192.168.1.6": 1}
    src = tmp_path / "in.txt"
    src.write_text(text)
    script = f"""
const E = require({json.dumps(str(ROOT / 'docs' / 'engine.js'))});
const fs = require('fs');
const m = new E.Monitor({{criticality: {json.dumps(crit)}}});
m.feedText(fs.readFileSync({json.dumps(str(src))}, 'utf8'));
console.log(JSON.stringify({{events: m.events, alerts: m.alerts.map(a => [a.kind, a.entity, a.priority, a.score, a.detail])}}));
"""
    out = json.loads(subprocess.run([NODE, "-e", script], capture_output=True, text=True, check=True).stdout)
    want, events = py_alerts(text, crit)
    if name == "random_hng":  # one malformed-time line gets "now" as its time on each side; compare the rest
        want, out["alerts"] = [w for w in want if "bad" not in w[4]], [a for a in out["alerts"] if "bad" not in a[4]]
    assert out["events"] == events
    assert [tuple(a) for a in out["alerts"]] == want
    assert len(want) > 0


@pytest.fixture
def trained_home(tmp_path):
    cfg = load_config(tmp_path / "home")
    audit = AuditLog(cfg.audit_path)
    mem = Memory(cfg.db_path)
    train(CortexAgent(oracle_llm(), mem, audit, log=quiet), mem, BUILTIN_TASKS, 1, log=quiet)
    ro = Memory(cfg.db_path, read_only=True)
    run_eval(CortexAgent(oracle_llm(), ro, audit, learn=False, log=quiet), ro, BUILTIN_TASKS, "all", log=quiet)
    (cfg.home / "alerts.jsonl").write_text(json.dumps({"entity": "10.9.9.9", "detail": "secret"}) + "\n")
    return cfg.home


def test_status_has_learning_data_but_no_alerts(trained_home):
    s = build_status(trained_home)
    assert s["stats"]["skills"] == 12 and len(s["skills"]) == 12 and s["runs"][-1]["overall"] == 1.0
    assert all(k["code"] and k["tests"] for k in s["skills"])
    blob = json.dumps(s)
    assert "10.9.9.9" not in blob and "secret" not in blob and "alerts" not in s


def test_publish_pushes_to_github_remote(tmp_path, trained_home):
    if not shutil.which("git"):
        pytest.skip("git not installed")
    g = lambda *a, cwd: subprocess.run(["git", *a], cwd=cwd, check=True, capture_output=True, text=True)
    remote = tmp_path / "remote.git"
    g("init", "--bare", "-b", "main", str(remote), cwd=tmp_path)
    work = tmp_path / "work"
    (work / "docs" / "data").mkdir(parents=True)
    (work / "docs" / "index.html").write_text("app")
    g("init", "-b", "main", cwd=work)
    g("-c", "user.name=t", "-c", "user.email=t@t", "add", ".", cwd=work)
    g("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-m", "init", cwd=work)
    g("remote", "add", "origin", f"file://{remote}", cwd=work)
    g("push", "origin", "main", cwd=work)
    msgs = []
    assert publish(trained_home, out=msgs.append, cwd=work)
    shown = subprocess.run(["git", "show", "main:docs/data/status.json"], cwd=remote, capture_output=True, text=True).stdout
    assert json.loads(shown)["stats"]["skills"] == 12
    assert any("Published" in m for m in msgs)


def test_publish_explains_when_not_connected(tmp_path, trained_home):
    work = tmp_path / "plain"
    (work / "docs" / "data").mkdir(parents=True)
    msgs = []
    assert not publish(trained_home, out=msgs.append, cwd=work)
    assert any("connect_github.bat" in m for m in msgs)
    assert (work / "docs" / "data" / "status.json").exists()


def test_homenet_guard_alerts():
    from cortex.realtime import hng_time
    from datetime import datetime, timezone
    base = datetime(2026, 11, 17, 18, 0, tzinfo=timezone.utc).timestamp()
    assert hng_time("2026-11-17T18:00:00.1234567Z") == pytest.approx(base + 0.123)
    assert hng_time("2026-11-17T19:00:00+01:00") == base
    assert hng_time("2026-11-17T18:00:00") == base
    assert hng_time("nope") is None
    m = ThreatMonitor(out=quiet, criticality={"192.168.1.12": 3})
    for line in (ROOT / "examples" / "homenet_guard_alerts.jsonl").read_text().splitlines():
        m.feed(line)
    got = [(a["kind"], a["entity"], a["priority"]) for a in m.alerts]
    assert ("multi_signal_device", "192.168.1.47", "P1") in got
    assert ("malicious_server", "192.168.1.12", "P1") in got
    assert not any(k == "data_exfiltration" for k, _, _ in got)      # Ignored in HomeNet Guard
    assert not any(k == "system" for k, _, _ in got)                 # Info-level
    assert all(a.get("advice") for a in m.alerts)
    assert len([a for a in m.alerts if a["kind"] == "multi_signal_device"]) == 1


def test_live_watch_survives_homenet_rewrites(tmp_path):
    """HomeNet Guard appends, then sometimes replaces the whole file. Cortex must not hold the
    file open (Windows would block the replace) and must not double-count rewritten alerts."""
    import threading, time as _t
    from cortex.realtime import follow
    src = (ROOT / "examples" / "homenet_guard_alerts.jsonl").read_text().splitlines()
    f = tmp_path / "alerts.jsonl"
    f.write_text("\n".join(src[:3]) + "\n")
    m = ThreatMonitor(out=quiet)
    stop = {"now": False}

    def kill():
        if stop["now"]:
            raise SystemExit
    th = threading.Thread(target=lambda: _swallow(follow, f, m, True, kill, 0.05), daemon=True)
    th.start()
    _t.sleep(0.4)
    with f.open("a") as fh:                      # HomeNet Guard appends two alerts...
        fh.write("\n".join(src[3:5]) + "\n")
    _t.sleep(0.4)
    tmp = tmp_path / "alerts.tmp"                # ...then rewrites the file (status change)
    tmp.write_text("\n".join(src[1:]) + "\n")
    tmp.replace(f)                               # would fail on Windows if the file were held open
    _t.sleep(0.5)
    stop["now"] = True
    th.join(2)
    kinds = [a["kind"] for a in m.alerts]
    assert kinds.count("new_device") == 1 and kinds.count("worm_scanning") == 1
    assert "exploit_attempt" in kinds and kinds.count("multi_signal_device") == 1


def _swallow(fn, *a):
    try:
        fn(*a)
    except SystemExit:
        pass
