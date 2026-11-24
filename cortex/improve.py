"""Step 3: gated self-improvement.

Cortex proposes changes to its own METHOD (the tunable settings and a short prompt addendum in
tuning.py - never the protected evaluator, sandbox or governance code). Each candidate is scored
against the HIDDEN evaluator on a held-out set, in isolation and with memory read-only, so a change
is only ever proposed if it genuinely scores better. You approve or reject each proposal; nothing
is applied on its own.

Hard safety invariants:
  * This engine writes only tuning.json and improvements.json in your data folder. It never edits
    any file in the cortex package.
  * Candidate scoring refuses to run unless the integrity lock verifies (evaluator/sandbox/
    governance unchanged).
  * The fixed system prompt (with its safety rules) is always kept; a candidate may only add a
    short, checked addendum to it.
  * A candidate is gated out if it does not beat the current method by a clear margin.
"""
from __future__ import annotations

import json
import time
import uuid
from dataclasses import replace
from pathlib import Path

from .agent import SYSTEM, CortexAgent
from .evaluator.evaluate import evaluate
from .evaluator.taskbank import Task
from .governance import AuditLog, verify_integrity
from .memory.store import Memory
from .tuning import Tuning, diff, load as load_tuning, sanitise_addendum, save as save_tuning

MARGIN = 0.05            # a candidate must beat the current method by at least this on the hidden set
IMPROVE_SYSTEM = (
    "You improve the system prompt of a Python-coding agent. You are given mistakes the agent keeps "
    "making. Reply with ONE short extra instruction (a single sentence, under 300 characters) to add "
    "to its prompt so it avoids those mistakes. Output only the instruction - no code, no quotes, no "
    "preamble. It must be general coding guidance, not a change to any safety rule.")


# ------------------------------------------------------------------ proposing
def _recent_lessons(mem: Memory, n: int = 8) -> list[str]:
    rows = mem.db.execute("SELECT text FROM lessons ORDER BY uses DESC, id DESC LIMIT ?", (n,)).fetchall()
    return [r["text"] for r in rows]


def parameter_candidates(base: Tuning) -> list[tuple[Tuning, str]]:
    """Safe, bounded tweaks to the numeric settings."""
    out = []
    b = base.clamped()
    for field, delta, why in [("max_skills", 1, "offer more learned skills as examples"),
                              ("max_attempts", 2, "allow more attempts before giving up"),
                              ("stuck_after", 1, "let it try a bit longer before calling itself stuck")]:
        cand = replace(b, **{field: getattr(b, field) + delta}).clamped()
        if diff(b, cand):
            out.append((cand, f"{field} {getattr(b, field)} -> {getattr(cand, field)} ({why})"))
    if b.reflect != "always":
        out.append((replace(b, reflect="always").clamped(), "reflect after every task (more lessons, slower)"))
    return out


def prompt_candidate(base: Tuning, llm, mem: Memory, log=print) -> tuple[Tuning, str] | None:
    lessons = _recent_lessons(mem)
    if len(lessons) < 3:
        return None
    msg = "Mistakes the agent keeps making:\n" + "\n".join(f"- {l}" for l in lessons)
    try:
        text = llm.complete(IMPROVE_SYSTEM, [{"role": "user", "content": msg}], max_tokens=200, temperature=0.4).text
    except Exception as e:
        if e.__class__.__name__ in ("Halted", "BudgetExceeded"):
            raise
        return None
    add = sanitise_addendum(text)
    if not add or add == base.clamped().system_addendum:
        log("  (the model's prompt suggestion was empty or unsafe - skipped)")
        return None
    return replace(base.clamped(), system_addendum=add), f'add to prompt: "{add[:80]}..."'


# ----------------------------------------------------------------- evaluating
def score(cfg, tuning: Tuning, tasks: list[Task], llm, split: str = "holdout", log=print,
          sample: int | None = None) -> float:
    """Mean hidden-test score for a tuning, memory read-only, integrity verified. No writes to the
    real memory or audit log (a throwaway audit path is used)."""
    verify_integrity(cfg.integrity_path, required=True)
    chosen = [t for t in tasks if split == "all" or t.split == split]
    if sample:
        chosen = chosen[:sample]
    mem = Memory(cfg.db_path, read_only=True)
    try:
        skills = mem.skill_code_map()
        agent = CortexAgent(llm, mem, AuditLog(cfg.home / "improve_trials.jsonl"), learn=False, log=lambda *a: None,
                            sandbox_timeout=cfg.sandbox_timeout, memory_mb=cfg.sandbox_memory_mb,
                            **tuning.agent_kwargs())
        total = 0.0
        for t in chosen:
            o = agent.solve(t.public_view(), mode="improve")
            total += evaluate(t, o.code, skills, timeout=cfg.sandbox_timeout).score
        return total / len(chosen) if chosen else 0.0
    finally:
        mem.close()


# -------------------------------------------------------------- orchestration
def propose(cfg, llm, tasks: list[Task], log=print, max_candidates: int = 3,
            split: str = "holdout", sample: int | None = None) -> dict:
    """Score the current method, try candidates, and queue the best genuine improvement (if any)."""
    base = load_tuning(cfg.home)
    log("Measuring the current method on the hidden tests...")
    base_score = score(cfg, base, tasks, llm, split=split, log=log, sample=sample)
    log(f"  current: {base_score:.0%}")

    candidates = parameter_candidates(base)
    pc = prompt_candidate(base, llm, Memory(cfg.db_path, read_only=True), log=log)
    if pc:
        candidates.insert(0, pc)
    candidates = candidates[:max_candidates]

    results = []
    for cand, desc in candidates:
        log(f"Trying: {desc}")
        sc = score(cfg, cand, tasks, llm, split=split, log=log, sample=sample)
        log(f"  -> {sc:.0%} ({'+' if sc >= base_score else ''}{(sc - base_score) * 100:.0f} pts)")
        results.append((cand, desc, sc))

    results.sort(key=lambda r: -r[2])
    best = results[0] if results else None
    queued = None
    if best and best[2] >= base_score + MARGIN:
        cand, desc, sc = best
        queued = {"id": uuid.uuid4().hex[:12], "ts": time.time(), "rationale": desc,
                  "change": diff(base, cand), "addendum": cand.clamped().system_addendum,
                  "tuning": cand.clamped().describe(), "baseline_score": round(base_score, 4),
                  "candidate_score": round(sc, 4), "split": split, "status": "proposed"}
        _add_proposal(cfg.home, queued)
        log(f"\nProposed: {desc}  ({base_score:.0%} -> {sc:.0%}). Review and approve it to apply.")
    else:
        log("\nNo change beat the current method by enough - keeping things as they are.")
    return {"baseline": round(base_score, 4), "tried": len(results), "queued": queued}


# ------------------------------------------------------------------ proposals
def _file(home: Path) -> Path:
    return Path(home) / "improvements.json"


def load_proposals(home: Path) -> list[dict]:
    p = _file(home)
    try:
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else []
    except json.JSONDecodeError:
        return []


def _save(home: Path, props: list[dict]) -> None:
    _file(home).write_text(json.dumps(props[-100:], indent=1), encoding="utf-8")


def _add_proposal(home: Path, prop: dict) -> None:
    props = load_proposals(home)
    props.append(prop)
    _save(home, props)


def apply(home: Path, prop_id: str, audit: AuditLog | None = None) -> dict:
    """Approve and apply a proposal: it becomes Cortex's active method."""
    props = load_proposals(home)
    p = next((x for x in props if x["id"] == prop_id), None)
    if not p:
        raise KeyError(prop_id)
    if p["status"] != "proposed":
        raise ValueError(f"proposal is already {p['status']}")
    save_tuning(home, Tuning(**p["tuning"]))
    p["status"] = "applied"
    p["applied_at"] = time.time()
    _save(home, props)
    if audit:
        audit.write("self_improvement_applied", id=prop_id, change=p["change"],
                    gain=round(p["candidate_score"] - p["baseline_score"], 4))
    return p


def reject(home: Path, prop_id: str, audit: AuditLog | None = None) -> dict:
    props = load_proposals(home)
    p = next((x for x in props if x["id"] == prop_id), None)
    if not p:
        raise KeyError(prop_id)
    p["status"] = "rejected"
    _save(home, props)
    if audit:
        audit.write("self_improvement_rejected", id=prop_id)
    return p
