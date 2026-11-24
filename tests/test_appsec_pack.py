"""The appsec (defensive security) task pack: valid, discriminating hidden tests, each proven
correct by a reference solution. These tasks teach Cortex to RECOGNISE web attacks and insecure
code (the blue-team / scanner side), not to produce exploits."""
import json
from pathlib import Path

import pytest

from cortex.evaluator.evaluate import evaluate
from cortex.evaluator.taskbank import all_tasks, load_custom_tasks
from cortex.gui_backend import validate_task
from cortex.sandbox import check_policy, run_tests

PACK = Path(__file__).resolve().parent.parent / "examples" / "task_packs" / "appsec.json"

REF = {
"cyber.detect_sqli": r'''
import re
_PATS = [r"'\s*or\s+'?\d+'?\s*=\s*'?\d+", r"\bunion\s+select\b", r"\bdrop\s+table\b",
         r";\s*(drop|delete|insert|update)\b", r"'\s*(--|#)", r"/\*.*?\*/", r"\bxp_cmdshell\b",
         r"\b(sleep|benchmark|pg_sleep)\s*\(", r"\bwaitfor\s+delay\b"]
def detect_sqli(value):
    return any(re.search(p, value, re.I | re.S) for p in _PATS)
''',
"cyber.detect_xss": r'''
import re
_PATS = [r"<\s*script", r"</\s*script\s*>", r"javascript\s*:", r"\bon(error|load|click|mouseover|focus)\s*=",
         r"<\s*svg", r"<\s*iframe", r"document\.cookie"]
def detect_xss(value):
    return any(re.search(p, value, re.I) for p in _PATS)
''',
"cyber.detect_path_traversal": r'''
import re
_PATS = [r"\.\./", r"\.\.\\", r"%2e%2e(%2f|%5c)?", r"\.\.%2f", r"/etc/passwd", r"/etc/shadow",
         r"boot\.ini", r"win\.ini"]
def detect_path_traversal(value):
    return any(re.search(p, value, re.I) for p in _PATS)
''',
"cyber.scan_code_vulns": r'''
import re
_RULES = {
    "code_execution": [r"\beval\s*\(", r"\bexec\s*\("],
    "command_injection": [r"\bos\.system\s*\(", r"subprocess\.\w+\([^)]*shell\s*=\s*True"],
    "hardcoded_secret": [r"(?i)\b(password|passwd|api_key|apikey|secret|token)\s*=\s*['\"][^'\"]{3,}['\"]",
                         r"AKIA[0-9A-Z]{16}"],
    "weak_hash": [r"(?i)\b(hashlib\.)?(md5|sha1)\s*\("],
    "insecure_deserialization": [r"\bpickle\.loads?\s*\(", r"\bmarshal\.loads\s*\(",
                                 r"\byaml\.load\s*\((?![^)]*Loader\s*=)"],
    "disabled_tls_verification": [r"\bverify\s*=\s*False\b", r"ssl\._create_unverified_context"],
}
def scan_code_vulns(code):
    return sorted(name for name, pats in _RULES.items() if any(re.search(p, code) for p in pats))
''',
"cyber.check_security_headers": r'''
_RECOMMENDED = ["Content-Security-Policy", "Referrer-Policy", "Strict-Transport-Security",
                "X-Content-Type-Options", "X-Frame-Options"]
def missing_security_headers(headers):
    present = {k.lower() for k in headers}
    return [h for h in _RECOMMENDED if h.lower() not in present]
''',
"cyber.classify_web_attack": r'''
import re
def classify_web_attack(value):
    v = value
    if (re.search(r"'\s*or\s+'?\d+'?\s*=\s*'?\d+", v, re.I) or re.search(r"\bunion\s+select\b", v, re.I)
            or re.search(r"'\s*--", v)):
        return "sqli"
    if re.search(r"<\s*script", v, re.I) or re.search(r"javascript\s*:", v, re.I) or re.search(r"\bon\w+\s*=", v, re.I):
        return "xss"
    if re.search(r"\.\./|\.\.\\|%2e%2e", v, re.I):
        return "path_traversal"
    if re.search(r"(;|\|\||&&|\||`|\$\()\s*`?\s*(cat|ls|id|whoami|nc|curl|wget|bash|sh)\b", v, re.I):
        return "command_injection"
    if (re.search(r"https?://(127\.0\.0\.1|localhost|169\.254\.169\.254|0\.0\.0\.0|\[::1\])", v, re.I)
            or re.search(r"\b(file|gopher)://", v, re.I)):
        return "ssrf"
    return "none"
''',
}


def pack():
    return json.loads(PACK.read_text())


@pytest.mark.parametrize("task", pack(), ids=lambda t: t["id"])
def test_reference_passes_every_test(task):
    assert check_policy(REF[task["id"]]) == []          # the detectors themselves use only safe stdlib (re)
    r = run_tests(REF[task["id"]], task["visible_tests"] + task["hidden_tests"])
    assert r.all_passed, r.failure_report()


@pytest.mark.parametrize("task", pack(), ids=lambda t: t["id"])
def test_stub_fails(task, tmp_path):
    (tmp_path / "p.json").write_text(json.dumps([task]))
    t = load_custom_tasks(tmp_path)[0]
    stub = f"def {t.entry_point}(*a, **k):\n    return None\n"
    assert evaluate(t, stub, {}).score < 0.5


def test_pack_valid_and_installs(tmp_path):
    for t in pack():
        assert validate_task(t, []) == []
    assert sum(t["split"] == "holdout" for t in pack()) == 1
    (tmp_path / "appsec.json").write_text(PACK.read_text())
    ids = [t.id for t in all_tasks(tmp_path)]
    assert "cyber.detect_sqli" in ids and "cyber.classify_web_attack" in ids


def test_detectors_are_defensive_not_exploit_tools():
    """Guard rail: these tasks ask only for boolean/label detection, never to emit a working payload."""
    for t in pack():
        text = (t["prompt"] + " " + t["entry_point"]).lower()
        assert any(w in text for w in ("detect", "classify", "flag", "missing", "recognise", "scan"))
        assert "-> bool" in t["prompt"] or "-> list" in t["prompt"] or "-> str" in t["prompt"]
