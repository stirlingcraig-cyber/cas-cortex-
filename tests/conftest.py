import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from cortex.agent import REFLECT_SYSTEM, TESTGEN_SYSTEM  # noqa: E402
from cortex.evaluator.taskbank import BUILTIN_TASKS  # noqa: E402
from cortex.governance import AuditLog  # noqa: E402
from cortex.llm import FakeLLM  # noqa: E402
from cortex.memory.store import Memory  # noqa: E402
from reference_solutions import REFERENCE  # noqa: E402

BY_ENTRY = {t.entry_point: REFERENCE[t.id] for t in BUILTIN_TASKS}


def oracle_llm(wrong_first: bool = False):
    """A fake model that knows the reference answers - lets us test the whole
    pipeline deterministically without an API key."""
    seen = set()

    def respond(system, messages):
        if system == REFLECT_SYSTEM:
            return ('{"lesson": "Read the specification edge cases carefully before coding.",'
                    ' "knowledge": [["sliding window", "bounds", "memory use"]]}')
        if system == TESTGEN_SYSTEM:
            return '{"tests": ["assert double(2) == 4", "assert double(0) == 0", "assert double(-3) == -6"]}'
        first = messages[0]["content"]
        m = re.search(r"defining `(\w+)`", first)
        name = m.group(1) if m else ""
        if name == "double":
            return "```python\ndef double(x):\n    return x * 2\n```"
        if wrong_first and name not in seen:
            seen.add(name)
            return f"```python\ndef {name}(*a, **k):\n    return None\n```"
        return "```python\n" + BY_ENTRY[name] + "\n```"
    return FakeLLM(respond)


@pytest.fixture
def mem(tmp_path):
    m = Memory(tmp_path / "c.db")
    yield m
    m.close()


@pytest.fixture
def audit(tmp_path):
    return AuditLog(tmp_path / "audit.jsonl")
