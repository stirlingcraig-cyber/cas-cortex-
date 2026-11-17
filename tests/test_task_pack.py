"""The automotive task pack: valid, discriminating hidden tests, proven by reference answers."""
import json
from pathlib import Path

import pytest

from cortex.evaluator.evaluate import evaluate
from cortex.evaluator.taskbank import all_tasks, load_custom_tasks
from cortex.gui_backend import validate_task
from cortex.sandbox import run_tests

PACK = Path(__file__).resolve().parent.parent / "examples" / "task_packs" / "automotive.json"

REF = {
"coding.obd_decode_dtc": '''
import re
def decode_dtc(raw):
    if not isinstance(raw, str) or not re.fullmatch(r"[0-9A-Fa-f]{4}", raw):
        raise ValueError("need 4 hex characters")
    v = int(raw[0], 16)
    return "PCBU"[v >> 2] + str(v & 3) + raw[1:].upper()
''',
"coding.obd_pid_value": '''
F = {0x04: (1, lambda a, b: a * 100 / 255), 0x05: (1, lambda a, b: a - 40), 0x0C: (2, lambda a, b: (256 * a + b) / 4),
     0x0D: (1, lambda a, b: a), 0x0F: (1, lambda a, b: a - 40), 0x11: (1, lambda a, b: a * 100 / 255),
     0x42: (2, lambda a, b: (256 * a + b) / 1000)}
for p in (6, 7, 8, 9):
    F[p] = (1, lambda a, b: (a - 128) * 100 / 128)
def pid_value(pid, data):
    if pid not in F:
        raise ValueError("unknown pid")
    n, f = F[pid]
    if len(data) < n or any(not 0 <= x <= 255 for x in data):
        raise ValueError("bad data")
    return round(f(data[0], data[1] if n > 1 else 0), 2)
''',
"threat.dtc_triage": '''
import re
P1 = [("B", "0001", "0099"), ("C", "0000", "3FFF"), ("U", "0121", "0129"), ("U", "0151", "0151"), ("P", "0217", "0218")]
P2 = [("P", "0300", "0312"), ("P", "0335", "0349"), ("P", "0087", "0088"), ("P", "0234", "0234"), ("P", "0560", "0563"),
      ("P", "0700", "0799"), ("U", "0000", "3FFF")]
P4 = [("P", "0400", "0499"), ("B", "0000", "3FFF")]
def _in(c, rules):
    return any(c[0] == l and lo <= c[1:] <= hi for l, lo, hi in rules)
def triage_dtcs(codes):
    out, seen = [], set()
    for c in codes:
        if not isinstance(c, str) or not re.fullmatch(r"[PCBU][0-3][0-9A-F]{3}", c):
            raise ValueError(c)
        if c in seen:
            continue
        seen.add(c)
        p = "P1" if _in(c, P1) else "P2" if _in(c, P2) else "P4" if _in(c, P4) else "P3"
        out.append({"code": c, "priority": p})
    return sorted(out, key=lambda x: (x["priority"], x["code"]))
''',
"bigdata.sensor_summary": '''
def summarise_sensors(rows):
    acc = {}
    for ts, name, value in rows:
        if value is None:
            continue
        try:
            v = float(value)
        except (TypeError, ValueError):
            continue
        a = acc.get(name)
        if a is None:
            acc[name] = [1, v, v, v, ts, ts]
        else:
            a[0] += 1; a[1] += v; a[2] = min(a[2], v); a[3] = max(a[3], v); a[5] = ts
    return {k: {"count": n, "min": mn, "max": mx, "mean": round(s / n, 3), "first": f, "last": l}
            for k, (n, s, mn, mx, f, l) in acc.items()}
''',
}


def pack():
    return json.loads(PACK.read_text())


@pytest.mark.parametrize("task", pack(), ids=lambda t: t["id"])
def test_reference_passes(task):
    r = run_tests(REF[task["id"]], task["visible_tests"] + task["hidden_tests"])
    assert r.all_passed, r.failure_report()


@pytest.mark.parametrize("task", pack(), ids=lambda t: t["id"])
def test_stub_fails(task, tmp_path):
    (tmp_path / "p.json").write_text(json.dumps([task]))
    t = load_custom_tasks(tmp_path)[0]
    assert evaluate(t, f"def {t.entry_point}(*a, **k):\n    return None\n", {}).score < 0.35


def test_pack_is_valid_and_installs(tmp_path):
    for t in pack():
        assert validate_task(t, []) == []
    (tmp_path / "automotive.json").write_text(PACK.read_text())
    ids = [t.id for t in all_tasks(tmp_path)]
    assert "threat.dtc_triage" in ids and len(ids) == 20
