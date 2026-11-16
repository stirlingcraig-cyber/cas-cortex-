"""Training curriculum and evaluation.

train: practise train-split tasks, unsolved first, re-practising one mastered task per
       round so skills stay reinforced. Each round is one 'generation'.
eval:  run tasks with memory READ-ONLY, score each with the hidden tests.
       train split  -> retention (can it still do what it learned?)
       holdout split -> transfer (does what it learned help on unseen problems?)
"""
from __future__ import annotations

import random
import time
import uuid

from .agent import CortexAgent
from .evaluator.evaluate import evaluate
from .evaluator.taskbank import Task
from .memory.store import Memory


def select_curriculum(tasks: list[Task], mem: Memory, rng: random.Random) -> list[Task]:
    have = {s.name for s in mem.all_skills()}
    unsolved = [t for t in tasks if t.entry_point not in have]
    mastered = [t for t in tasks if t.entry_point in have]
    plan = list(unsolved)
    if mastered:
        plan.append(rng.choice(mastered))
    return plan


def train(agent: CortexAgent, mem: Memory, tasks: list[Task], rounds: int, log=print,
          seed: int | None = None) -> list[dict]:
    rng = random.Random(seed)
    train_tasks = [t for t in tasks if t.split == "train"]
    summary = []
    for _ in range(rounds):
        gen = mem.get_meta("generation", 0) + 1
        plan = select_curriculum(train_tasks, mem, rng)
        log(f"\n=== generation {gen}: {len(plan)} task(s) ===")
        for t in plan:
            log(f"  [{t.domain}] {t.id}")
            o = agent.solve(t.public_view(), mode="train")
            log(f"    -> {'SOLVED' if o.solved else 'not solved'}"
                + (f", skill {o.skill_action}" if o.skill_action else "")
                + (f", reused {', '.join(o.skills_used)}" if o.skills_used else ""))
            if o.lesson:
                log(f"    lesson: {o.lesson[:160]}")
            summary.append({"generation": gen, "task": t.id, "solved": o.solved,
                            "attempts": o.attempts, "tokens": o.tokens})
        mem.set_meta("generation", gen)
    return summary


def run_eval(agent: CortexAgent, mem: Memory, tasks: list[Task], split: str = "all",
             timeout: float = 20.0, log=print) -> dict:
    """`agent` must be built with a read-only memory (learn=False) so evaluation is clean."""
    assert not agent.learn, "evaluation must run with learning disabled"
    chosen = [t for t in tasks if split == "all" or t.split == split]
    run_id = time.strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]
    gen = mem.get_meta("generation", 0)
    skills = mem.skill_code_map()
    rows = []
    for t in chosen:
        log(f"  [{t.split}/{t.domain}] {t.id}")
        o = agent.solve(t.public_view(), mode="eval")
        er = evaluate(t, o.code, skills, timeout=timeout)
        log(f"    hidden score {er.score:.0%} ({er.passed}/{er.total}){' ' + er.note if er.note else ''}")
        mem.record_eval(run_id, gen, t.id, t.domain, t.split, er.score, o.attempts, o.tokens)
        rows.append({"task": t.id, "domain": t.domain, "split": t.split, "score": er.score})
    by = {}
    for r in rows:
        by.setdefault((r["split"], r["domain"]), []).append(r["score"])
    return {"run_id": run_id, "generation": gen, "rows": rows,
            "summary": {f"{s}/{d}": sum(v) / len(v) for (s, d), v in sorted(by.items())}}


def report(mem: Memory) -> str:
    hist = mem.eval_history()
    if not hist:
        return "No evaluations yet. Run: cortex eval"
    runs: dict[str, dict] = {}
    for r in hist:
        d = runs.setdefault(r["run_id"], {"gen": r["generation"], "ts": r["ts"], "cells": {}, "tokens": 0})
        d["cells"][f"{r['split']}/{r['domain']}"] = r["score"]
        d["tokens"] += r["tokens"] or 0
    cols = sorted({c for d in runs.values() for c in d["cells"]})
    head = f"{'run':<22}{'gen':>4}  " + "  ".join(f"{c:>16}" for c in cols) + f"  {'overall':>8}"
    lines = ["Learning curve (hidden-test score; train = retention, holdout = transfer)", head,
             "-" * len(head)]
    for rid, d in runs.items():
        vals = [d["cells"].get(c) for c in cols]
        present = [v for v in vals if v is not None]
        overall = sum(present) / len(present) if present else 0
        lines.append(f"{rid:<22}{d['gen']:>4}  " +
                     "  ".join(f"{(f'{v:.0%}' if v is not None else '-'):>16}" for v in vals) +
                     f"  {overall:>8.0%}")
    return "\n".join(lines)
