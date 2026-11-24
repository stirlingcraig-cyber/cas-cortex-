"""Cortex's tunable 'method' - the settings and prompt guidance it uses to solve tasks.

This is the ONLY part of Cortex that self-improvement (step 3) may change. It lives in a plain
file in your data folder (tuning.json), never in the program code. The protected files - the
evaluator, the task bank, the sandbox and the governance layer - are integrity-locked and can
never be changed this way.

Every value has a safe range, and the fixed system prompt (with its safety rules) is always kept;
self-improvement may only append a short addendum to it, never remove or edit it.
"""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path

# Phrases an addendum must not contain - it must be constructive coding guidance, not an attempt
# to relax the rules. (The sandbox and evaluator enforce safety regardless; this is defence in depth.)
_ADDENDUM_BANNED = re.compile(
    r"\b(ignore|disable|bypass|override|forget)\b|import\s+os|subprocess|os\.system|\beval\s*\(|"
    r"\bexec\s*\(|open\s*\(|socket|network|__\w+__|verify\s*=\s*false|without\s+import",
    re.I)
BOUNDS = {"max_skills": (1, 6), "max_attempts": (2, 8), "stuck_after": (1, 4)}
REFLECT_CHOICES = ("always", "smart", "never")
ADDENDUM_MAX = 400


@dataclass
class Tuning:
    max_skills: int = 3
    max_attempts: int = 4
    stuck_after: int = 2
    reflect: str = "smart"
    system_addendum: str = ""       # appended to the fixed solving prompt

    def clamped(self) -> "Tuning":
        d = asdict(self)
        for k, (lo, hi) in BOUNDS.items():
            try:
                d[k] = max(lo, min(hi, int(d[k])))
            except (TypeError, ValueError):
                d[k] = getattr(Tuning(), k)
        if d["reflect"] not in REFLECT_CHOICES:
            d["reflect"] = "smart"
        d["system_addendum"] = sanitise_addendum(d.get("system_addendum", ""))
        return Tuning(**d)

    def agent_kwargs(self) -> dict:
        t = self.clamped()
        return {"max_skills": t.max_skills, "max_attempts": t.max_attempts, "stuck_after": t.stuck_after,
                "reflect": t.reflect, "system_addendum": t.system_addendum}

    def describe(self) -> dict:
        return asdict(self.clamped())


def sanitise_addendum(text: str) -> str:
    """Return a safe addendum, or '' if it looks unsafe. Keeps it short and single-purpose."""
    text = (text or "").strip().strip("`").strip()
    if not text:
        return ""
    if len(text) > ADDENDUM_MAX or _ADDENDUM_BANNED.search(text) or "```" in text:
        return ""
    # one or two sentences of plain guidance only
    return " ".join(text.split())[:ADDENDUM_MAX]


def addendum_ok(text: str) -> bool:
    return bool((text or "").strip()) and sanitise_addendum(text) == " ".join((text or "").strip().split())[:ADDENDUM_MAX]


def path(home: Path) -> Path:
    return Path(home) / "tuning.json"


def load(home: Path) -> Tuning:
    p = path(home)
    if not p.exists():
        return Tuning()
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
        known = {k: d[k] for k in Tuning().__dataclass_fields__ if k in d}
        return Tuning(**known).clamped()
    except (json.JSONDecodeError, TypeError, OSError):
        return Tuning()


def save(home: Path, tuning: Tuning) -> None:
    path(home).write_text(json.dumps(tuning.clamped().describe(), indent=1), encoding="utf-8")


def reset(home: Path) -> None:
    p = path(home)
    if p.exists():
        p.unlink()


def diff(before: Tuning, after: Tuning) -> dict:
    """What changed between two tunings: {field: [old, new]}."""
    a, b = before.clamped().describe(), after.clamped().describe()
    return {k: [a[k], b[k]] for k in a if a[k] != b[k]}
