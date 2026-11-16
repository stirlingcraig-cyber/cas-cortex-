import json

import pytest

from cortex import governance
from cortex.governance import (AuditLog, Budget, BudgetExceeded, GovernedLLM, Halted,
                               IntegrityError, KillSwitch, lock_integrity, verify_integrity)
from cortex.llm import FakeLLM
from cortex.memory.store import Memory


def test_skill_lifecycle(mem):
    kw = dict(name="f", domain="coding", description="d", code="def f(): return 1", tests=["t"])
    assert mem.upsert_skill(trust="self-tested", **kw) == "added"
    assert mem.upsert_skill(trust="self-tested", **kw) == "reinforced"
    kw["code"] = "def f():\n    return 1\n"
    assert mem.upsert_skill(trust="verified-visible", **kw) == "upgraded"
    s = mem.get_skill("f")
    assert s.trust == "verified-visible" and s.version == 2 and s.successes == 3


def test_retrieval(mem):
    mem.upsert_skill(name="detect_bruteforce", domain="cyber", description="SSH brute force failed password logs",
                     code="x", tests=[], trust="verified-visible")
    mem.upsert_skill(name="merge_intervals", domain="coding", description="merge overlapping intervals",
                     code="y", tests=[], trust="verified-visible")
    assert mem.search_skills("failed ssh password attempts", k=1)[0].name == "detect_bruteforce"
    mem.add_lesson("Use a sliding window deque so memory stays bounded on streams.", "bigdata", "t1")
    assert "deque" in mem.search_lessons("streaming window memory")[0]
    mem.add_triple("Population stdev", "divides by", "n", "t1")
    assert mem.related_knowledge("stdev")[0] == ("population stdev", "divides by", "n")


def test_read_only_never_writes(tmp_path):
    m = Memory(tmp_path / "x.db", read_only=True)
    m.upsert_skill(name="f", domain="coding", description="", code="", tests=[], trust="t")
    m.add_lesson("a long enough lesson text here", "coding", "t")
    m.set_meta("generation", 5)
    assert m.stats()["skills"] == 0 and m.stats()["lessons"] == 0 and m.get_meta("generation", 0) == 0


def test_audit_chain_detects_tampering(tmp_path):
    p = tmp_path / "a.jsonl"
    log = AuditLog(p)
    for i in range(5):
        log.write("e", i=i)
    assert log.verify()[0]
    assert AuditLog(p)._last == log._last  # chain resumes after restart
    lines = p.read_text().splitlines()
    rec = json.loads(lines[2]); rec["data"]["i"] = 99
    lines[2] = json.dumps(rec, sort_keys=True)
    p.write_text("\n".join(lines) + "\n")
    ok, n, msg = AuditLog(p).verify()
    assert not ok and "3" in msg


def test_kill_switch_and_budget(tmp_path):
    kill = KillSwitch(tmp_path / "STOP")
    llm = GovernedLLM(FakeLLM(["a", "b", "c"]), Budget(2, 10**6), AuditLog(tmp_path / "a"), kill)
    llm.complete("s", [{"role": "user", "content": "x"}])
    llm.complete("s", [{"role": "user", "content": "x"}])
    with pytest.raises(BudgetExceeded):
        llm.complete("s", [{"role": "user", "content": "x"}])
    (tmp_path / "STOP").write_text("1")
    with pytest.raises(Halted):
        llm.complete("s", [])


def test_integrity_lock(tmp_path, monkeypatch):
    p = tmp_path / "i.json"
    with pytest.raises(IntegrityError):
        verify_integrity(p, required=True)
    lock_integrity(p)
    assert verify_integrity(p, required=True) == []
    real = governance._file_hashes
    monkeypatch.setattr(governance, "_file_hashes", lambda: {**real(), "sandbox.py": "tampered"})
    with pytest.raises(IntegrityError):
        verify_integrity(p, required=True)
