"""Continuous learning from the user: alert feedback (PC + iPhone parity), Claude-history
proposals checked against the user's own code, focus profile and the nightly autopilot."""
import json
import random
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

from cortex import autopilot, claude_history as ch, feedback as fb
from cortex.agent import REFLECT_SYSTEM, TESTGEN_SYSTEM, CortexAgent
from cortex.llm import FakeLLM
from cortex.publish import build_status
from cortex.realtime import ThreatMonitor
from cortex import vehicle

ROOT = Path(__file__).resolve().parent.parent
NODE = shutil.which("node")
quiet = lambda *a, **k: None


# ------------------------------------------------------------------- feedback
def recs(kind, entity, verdict, n):
    return [{"id": f"{kind}{entity}{verdict}{i}", "kind": kind, "entity": entity, "verdict": verdict} for i in range(n)]


def test_false_alarms_lower_and_actions_raise_with_safety_floor():
    s = fb.summarise(recs("misfire", "car", "false_alarm", 3) + recs("airbag", "car", "false_alarm", 9)
                     + recs("emissions", "a", "acted", 1) + recs("emissions", "b", "acted", 1))
    assert fb.adjust("P2", "misfire", "car", s)[0] == "P3"
    assert fb.adjust("P2", "misfire", "other-car", s) == ("P2", "")     # learning is per device/vehicle
    assert fb.adjust("P1", "airbag", "car", s)[0] == "P2"              # safety: never below P2
    assert fb.adjust("P2", "airbag", "car", s) == ("P2", "")
    assert fb.adjust("P3", "emissions", "z", s)[0] == "P2"             # acted twice -> raised everywhere
    assert fb.adjust("P1", "emissions", "z", s) == ("P1", "")
    assert fb.adjust("P2", "misfire", "car", fb.summarise(recs("misfire", "car", "false_alarm", 3)
                                                          + recs("misfire", "car", "useful", 3)))[0] == "P2"


def test_monitor_applies_feedback_and_explains():
    s = fb.summarise(recs("misfire", "vehicle", "false_alarm", 4))
    m = ThreatMonitor(out=quiet, feedback=s)
    vehicle.analyse_text(m, "P0300 B0012", 1.0)
    mis = next(a for a in m.alerts if a["kind"] == "misfire")
    assert mis["priority"] == "P3" and "false alarm" in mis["learned"]


def test_feedback_storage_import_and_reset(tmp_path):
    fb.add(tmp_path, "beaconing", "PC1", "useful")
    f = tmp_path / "cortex-feedback-2026-11-17.json"
    f.write_text(json.dumps({"type": "cas-cortex-feedback", "feedback": recs("misfire", "vehicle", "acted", 2)
                             + [{"id": "bad", "kind": "x", "verdict": "nonsense"}], "usage": {"monitor": 5}}))
    assert fb.import_file(tmp_path, f)[0] == 2
    assert fb.import_file(tmp_path, f)[0] == 0                          # no duplicates
    assert len(fb.load(tmp_path)) == 3
    (tmp_path / "x.json").write_text("{}")
    with pytest.raises(ValueError):
        fb.import_file(tmp_path, tmp_path / "x.json")
    fb.reset(tmp_path)
    assert fb.load(tmp_path) == [] and (tmp_path / "feedback.jsonl.bak").exists()


@pytest.mark.skipif(NODE is None, reason="node not installed")
def test_feedback_adjustment_matches_iphone(tmp_path):
    rng = random.Random(5)
    kinds = ["misfire", "airbag", "emissions", "beaconing", "brakes", "bruteforce"]
    cases = []
    for _ in range(300):
        records = [{"id": str(i), "kind": rng.choice(kinds), "entity": rng.choice(["a", "b", ""]),
                    "verdict": rng.choice(fb.VERDICTS + ("junk",))} for i in range(rng.randint(0, 25))]
        cases.append((records, rng.choice(["P1", "P2", "P3", "P4"]), rng.choice(kinds), rng.choice(["a", "b", ""])))
    src = tmp_path / "c.json"
    src.write_text(json.dumps(cases))
    script = f"""const E = require({json.dumps(str(ROOT / 'docs' / 'engine.js'))});
const cases = JSON.parse(require('fs').readFileSync({json.dumps(str(src))}, 'utf8'));
console.log(JSON.stringify(cases.map(([r, p, k, e]) => E.adjustPriority(p, k, e, E.summariseFeedback(r)))));"""
    js = json.loads(subprocess.run([NODE, "-e", script], capture_output=True, text=True, check=True).stdout)
    py = [list(fb.adjust(p, k, e, fb.summarise(r))) for r, p, k, e in cases]
    assert py == js and sum(1 for x in py if x[1]) > 20


# ------------------------------------------------------------- Claude history
GOOD = '''Here you go:
```python
import re

def count_vowels(text):
    """Return how many vowels (a, e, i, o, u - any case) are in text."""
    return len(re.findall(r"[aeiou]", text, re.I))

def _helper(x):
    return x

print(count_vowels("Hello"))
```'''
FILEY = "```python\nimport os\ndef list_dir(p):\n    return os.listdir(p)\n```"


def make_export(tmp_path):
    convs = [
        {"uuid": "c1", "name": "Vowel counter", "created_at": "2026-10-01T10:00:00Z", "chat_messages": [
            {"sender": "human", "text": "Write a python function to count vowels in a string for my app"},
            {"sender": "assistant", "text": GOOD}]},
        {"uuid": "c2", "name": "Folder lister", "chat_messages": [
            {"sender": "human", "content": [{"type": "text", "text": "python script to list files"}]},
            {"sender": "assistant", "content": [{"type": "text", "text": FILEY}]}]},
        {"uuid": "c3", "name": "Firewall advice", "chat_messages": [
            {"sender": "human", "text": "How do I harden my firewall against port scan and malware? security vpn"}]},
        {"uuid": "c4", "name": "Cooking", "chat_messages": [{"sender": "human", "text": "Best roast potatoes?"}]},
    ]
    z = tmp_path / "data-export.zip"
    with zipfile.ZipFile(z, "w") as f:
        f.writestr("data-2026/conversations.json", json.dumps(convs))
        f.writestr("data-2026/users.json", "[]")
    return z


def test_import_claude_export(tmp_path):
    home = tmp_path / "home"; home.mkdir()
    r = ch.import_export(home, make_export(tmp_path))
    assert r["conversations"] == 4 and r["new_proposals"] == 1          # file-using code skipped
    assert r["by_domain"]["cyber"] == 1 and r["by_domain"]["coding"] >= 1
    p = ch.load_proposals(home)[0]
    assert p["name"] == "count_vowels" and "vowels" in p["spec"] and p["status"] == "new"
    assert ch.import_export(home, make_export(tmp_path))["new_proposals"] == 0   # no duplicates
    assert ch.set_status(home, "all-new", "approved") == 1
    profile = json.loads((home / "claude_profile.json").read_text())
    assert "roast" not in json.dumps(profile)                           # only counts are kept


def test_learning_a_proposal_keeps_only_tests_the_original_passes(tmp_path):
    from cortex.memory.store import Memory
    from cortex.governance import AuditLog
    home = tmp_path / "h"; home.mkdir()
    ch.import_export(home, make_export(tmp_path))
    p = ch.load_proposals(home)[0]
    tests = ["assert count_vowels('Hello') == 2", "assert count_vowels('') == 0", "assert count_vowels('AEIOU') == 5",
             "assert count_vowels('xyz') == 1", "assert count_vowels('aa') == 3"]          # last two are wrong
    sol = "```python\ndef count_vowels(text):\n    return sum(c in 'aeiouAEIOU' for c in text)\n```"

    def model(system, messages):
        if system == TESTGEN_SYSTEM:
            return json.dumps({"tests": tests})
        if system == REFLECT_SYSTEM:
            return '{"lesson": "Count characters case-insensitively.", "knowledge": []}'
        return sol
    mem = Memory(home / "c.db")
    o = CortexAgent(FakeLLM(model), mem, AuditLog(home / "a"), log=quiet).solve_freeform(
        p["spec"], p["name"], p["domain"], p["title"], reference_code=p["reference_code"])
    assert o.solved and mem.get_skill("count_vowels").trust == "reference-checked"
    assert len(mem.get_skill("count_vowels").tests) == 3


# ------------------------------------------------------------ focus/autopilot
def test_focus_profile(tmp_path):
    (tmp_path / "usage.json").write_text(json.dumps({"monitor:obd": 6, "train:coding": 2, "iphone:obd_codes": 3}))
    fb.add(tmp_path, "misfire", "car", "useful")
    f = autopilot.focus(tmp_path)
    assert f["next_training"][0] == "threat" and abs(sum(f["weights"].values()) - 1) < 0.01


def test_autopilot_pass(tmp_path, monkeypatch):
    home = tmp_path / "home"; home.mkdir()
    inbox = tmp_path / "inbox"; inbox.mkdir()
    (inbox / "cortex-feedback-1.json").write_text(json.dumps({"type": "cas-cortex-feedback",
                                                              "feedback": recs("misfire", "v", "acted", 2)}))
    monkeypatch.setattr(autopilot, "inbox_folders", lambda: [inbox])
    ch.import_export(home, make_export(tmp_path)); ch.set_status(home, "all-new", "approved")
    calls = []
    runner = lambda args: calls.append(args) or 0
    rep = autopilot.run(home, lambda: True, [], log=quiet, runner=runner, now=1_000_000)
    assert rep["feedback_imported"] == 2 and rep["learned"] == [("count_vowels", True)]
    train = [c for c in calls if c[0] == "train"]
    assert len(train) == 1 and train[0][-4:] == ["coding", "cyber", "bigdata", "threat"]          # weekly: all areas
    assert "--hours" in train[0] and ["eval", "--split", "holdout"] in calls
    assert ch.load_proposals(home)[0]["status"] == "learned"
    calls.clear()
    autopilot.run(home, lambda: True, [], log=quiet, runner=runner, now=1_000_000 + 86400)
    train = [c for c in calls if c[0] == "train"]
    assert len(train) == 1 and len(train[0][train[0].index("--domain") + 1:]) == 2                # focus areas only
    assert not any(c[0] == "eval" for c in calls)
    calls.clear()
    rep = autopilot.run(home, lambda: False, [], log=quiet, runner=runner, now=1_000_000 + 2 * 86400)
    assert not any(c[0] in ("train", "learn-proposal") for c in calls)                         # model offline


def test_published_status_never_contains_entities(tmp_path):
    fb.add(tmp_path, "malicious_server", "192.168.1.12", "acted")
    fb.add(tmp_path, "airbag", "WVWZZZAWZHY123456", "useful")
    s = json.dumps(build_status(tmp_path))
    assert "192.168.1.12" not in s and "WVWZZZ" not in s
    st = build_status(tmp_path)
    assert st["feedback"]["kinds"]["airbag"]["useful"] == 1 and len(st["feedback"]["ids"]) == 2
    assert "weights" in st["focus"]


def test_describe_learning():
    s = fb.summarise(recs("misfire", "car", "false_alarm", 3) + recs("beaconing", "PC1", "acted", 2))
    assert fb.describe(s) == ["all beaconing alerts: raised one level (you acted on 2)",
                              "misfire on car: lowered one level (3 false alarms)"]
