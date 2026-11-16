"""Governance layer - the part the agent can never change.

- AuditLog:   append-only, hash-chained JSONL; tampering is detectable.
- Budget:     hard caps on model calls and tokens per run.
- KillSwitch: create a file called STOP in CORTEX_HOME and every loop halts at the
              next model call.
- Integrity:  SHA-256 manifest of the evaluator, sandbox and governance code. Evals
              refuse to run if anything changed since `cortex lock`.
- GovernedLLM wraps every model call with all of the above.
"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

from .llm import LLM, LLMResponse

PKG = Path(__file__).resolve().parent
PROTECTED = ["evaluator/taskbank.py", "evaluator/evaluate.py", "sandbox.py", "governance.py"]


class Halted(Exception):
    pass


class BudgetExceeded(Exception):
    pass


class IntegrityError(Exception):
    pass


class AuditLog:
    def __init__(self, path: Path):
        self.path = Path(path)
        self._last = self._tail_hash()

    def _tail_hash(self) -> str:
        if not self.path.exists():
            return "GENESIS"
        last = "GENESIS"
        with self.path.open(encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    last = json.loads(line)["hash"]
        return last

    def write(self, event: str, **data) -> None:
        rec = {"ts": round(time.time(), 3), "event": event, "data": data, "prev": self._last}
        rec["hash"] = hashlib.sha256(json.dumps(rec, sort_keys=True).encode()).hexdigest()
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, sort_keys=True) + "\n")
        self._last = rec["hash"]

    def verify(self) -> tuple[bool, int, str]:
        """Return (ok, entries_checked, message)."""
        if not self.path.exists():
            return True, 0, "no audit log yet"
        prev, n = "GENESIS", 0
        with self.path.open(encoding="utf-8") as f:
            for n, line in enumerate((l for l in f if l.strip()), 1):
                rec = json.loads(line)
                h = rec.pop("hash")
                if rec["prev"] != prev:
                    return False, n, f"chain broken at entry {n}"
                if hashlib.sha256(json.dumps(rec, sort_keys=True).encode()).hexdigest() != h:
                    return False, n, f"entry {n} was modified"
                prev = h
        return True, n, "audit chain intact"


class Budget:
    def __init__(self, max_calls: int, max_tokens: int):
        self.max_calls, self.max_tokens = max_calls, max_tokens
        self.calls = self.tokens = 0

    def check(self) -> None:
        if self.calls >= self.max_calls:
            raise BudgetExceeded(f"model call budget reached ({self.max_calls})")
        if self.tokens >= self.max_tokens:
            raise BudgetExceeded(f"token budget reached ({self.max_tokens})")

    def charge(self, tokens: int) -> None:
        self.calls += 1
        self.tokens += tokens


class KillSwitch:
    def __init__(self, path: Path):
        self.path = Path(path)

    def check(self) -> None:
        if self.path.exists():
            raise Halted(f"kill switch engaged ({self.path}). Delete the file to resume.")


class GovernedLLM(LLM):
    def __init__(self, inner: LLM, budget: Budget, audit: AuditLog, kill: KillSwitch):
        self.inner, self.budget, self.audit, self.kill = inner, budget, audit, kill
        self.name = f"governed:{inner.name}"

    def complete(self, system, messages, max_tokens=4000) -> LLMResponse:
        self.kill.check()
        self.budget.check()
        prompt_hash = hashlib.sha256((system + json.dumps(messages)).encode()).hexdigest()[:16]
        r = self.inner.complete(system, messages, max_tokens)
        self.budget.charge(r.tokens)
        self.audit.write("llm_call", provider=self.inner.name, prompt_sha=prompt_hash,
                         in_tokens=r.input_tokens, out_tokens=r.output_tokens,
                         response_sha=hashlib.sha256(r.text.encode()).hexdigest()[:16])
        return r


def _file_hashes() -> dict[str, str]:
    return {rel: hashlib.sha256((PKG / rel).read_bytes()).hexdigest() for rel in PROTECTED}


def lock_integrity(path: Path) -> dict[str, str]:
    h = _file_hashes()
    Path(path).write_text(json.dumps(h, indent=2), encoding="utf-8")
    return h


def verify_integrity(path: Path, required: bool = False) -> list[str]:
    """Return list of changed files. Raises if `required` and anything changed or no lock."""
    path = Path(path)
    if not path.exists():
        if required:
            raise IntegrityError("no integrity lock - run `cortex lock` first")
        return []
    saved = json.loads(path.read_text(encoding="utf-8"))
    now = _file_hashes()
    changed = [f for f in PROTECTED if saved.get(f) != now.get(f)]
    if changed and required:
        raise IntegrityError("protected files changed since lock: " + ", ".join(changed))
    return changed
