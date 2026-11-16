"""Independent scorer. Runs HIDDEN tests the agent never sees. PROTECTED FILE."""
from __future__ import annotations

from dataclasses import dataclass

from ..sandbox import run_tests
from .taskbank import Task


@dataclass
class EvalResult:
    task_id: str
    score: float
    passed: int
    total: int
    note: str = ""


def evaluate(task: Task, code: str, skills: dict[str, str], timeout: float = 20.0,
             memory_mb: int = 768) -> EvalResult:
    if not code.strip():
        return EvalResult(task.id, 0.0, 0, len(task.hidden_tests), "no code")
    r = run_tests(code, task.hidden_tests, skills=skills, timeout=timeout, memory_mb=memory_mb)
    note = ""
    if r.policy:
        note = "policy violation"
    elif r.timed_out:
        note = "timeout"
    elif r.load_error:
        note = "load error"
    return EvalResult(task.id, r.pass_rate if not note else 0.0, r.passed, r.total, note)
