import json

from cortex.realtime import ThreatMonitor, load_learned
from reference_solutions import REFERENCE

quiet = lambda *a, **k: None


def j(**e):
    return json.dumps(e)


def test_bruteforce_then_success_escalates(tmp_path):
    m = ThreatMonitor(out=quiet, alerts_path=tmp_path / "alerts.jsonl", criticality={"10.0.0.5": 3})
    for s in range(5):
        m.feed(f"Mar 10 12:00:0{s} host sshd[1]: Failed password for root from 10.0.0.5 port 22 ssh2")
    m.feed("Mar 10 12:00:30 host sshd[1]: Accepted password for root from 10.0.0.5 port 22 ssh2")
    kinds = [(a["kind"], a["priority"]) for a in m.alerts]
    assert kinds == [("bruteforce", "P2"), ("bruteforce_then_success", "P1")]
    assert len((tmp_path / "alerts.jsonl").read_text().splitlines()) == 2


def test_beacon_travel_process():
    m = ThreatMonitor(out=quiet)
    for t in range(0, 600, 60):
        m.feed(j(ts=1000 + t, type="conn", source="pc1", dest="203.0.113.9"))
    m.feed(j(ts=0, type="login", user="craig", lat=55.86, lon=-4.25))
    m.feed(j(ts=1800, type="login", user="craig", lat=40.71, lon=-74.0))
    m.feed(j(ts=5, type="process", source="pc2", cmdline="powershell -w hidden -ep bypass -c x"))
    m.feed("not json and not a log line")
    kinds = sorted(a["kind"] for a in m.alerts)
    assert kinds == ["beaconing", "impossible_travel", "suspicious_process"]
    assert m.events == 13


def test_learned_detectors_are_swapped_in():
    code = {"beacon_analysis": REFERENCE["threat.beaconing"],
            "suspicious_commandline": "import os\ndef suspicious_commandline(c):\n    return []\n"}
    learned = load_learned(code)
    assert list(learned) == ["beacon_analysis"]  # policy-violating skill rejected
    m = ThreatMonitor(out=quiet, learned=learned)
    assert m.learned_names == ["beacon_analysis"]
    for t in range(0, 600, 60):
        m.feed(j(ts=t, type="conn", source="a", dest="b"))
    assert m.alerts and m.alerts[0]["kind"] == "beaconing"
