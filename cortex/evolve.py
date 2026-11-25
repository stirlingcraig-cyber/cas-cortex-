"""Step 4: evolutionary search over Cortex's own method.

Instead of improving one setting at a time (step 3), this breeds a whole POPULATION of
differently-tuned copies of Cortex, scores each against the HIDDEN evaluator, keeps the best,
and breeds the next generation from them (mutation + crossover). The best copy found - the
'champion' - is queued as a proposal that you approve or reject, exactly like step 3.

Same safety invariants as step 3:
  * only the tunable method evolves (settings + a bounded, checked prompt addendum); the
    evaluator, task bank, sandbox, governance and the fixed safety prompt are never touched;
  * fitness scoring runs with memory read-only and refuses unless the integrity lock verifies;
  * every field stays inside its safe range; nothing is applied without your approval.
"""
from __future__ import annotations

import random
import time
import uuid
from dataclasses import replace
from pathlib import Path

from . import improve
from .evaluator.taskbank import Task
from .governance import BudgetExceeded, Halted
from .tuning import BOUNDS, Tuning, diff, load as load_tuning, sanitise_addendum

# Evolution never selects "never" (it would stop the agent learning) - only these.
REFLECT_GENES = ("smart", "always")


def genome_sig(t: Tuning) -> tuple:
    t = t.clamped()
    return (t.max_skills, t.max_attempts, t.stuck_after, t.reflect, t.system_addendum)


def mutate(base: Tuning, rng: random.Random) -> Tuning:
    """Change one or two genes of a tuning, staying inside the safe bounds."""
    t = base.clamped()
    fields = ["max_skills", "max_attempts", "stuck_after", "reflect", "addendum"]
    for field in rng.sample(fields, rng.randint(1, 2)):
        if field == "reflect":
            t = replace(t, reflect=rng.choice(REFLECT_GENES))
        elif field == "addendum":
            t = replace(t, system_addendum="" if t.system_addendum and rng.random() < 0.5 else t.system_addendum)
        else:
            lo, hi = BOUNDS[field]
            step = rng.choice([-1, 1]) * (2 if field == "max_attempts" and rng.random() < 0.4 else 1)
            t = replace(t, **{field: max(lo, min(hi, getattr(t, field) + step))})
    return t.clamped()


def crossover(a: Tuning, b: Tuning, rng: random.Random) -> Tuning:
    a, b = a.clamped(), b.clamped()
    pick = lambda f: getattr(a if rng.random() < 0.5 else b, f)
    return Tuning(max_skills=pick("max_skills"), max_attempts=pick("max_attempts"),
                  stuck_after=pick("stuck_after"), reflect=pick("reflect"),
                  system_addendum=pick("system_addendum")).clamped()


def neighbours(base: Tuning) -> list[Tuning]:
    """Single-gene steps around a tuning, ordered round-robin by gene so a small population still
    explores every setting's first step before any second step. gen 0 thus covers each direction."""
    b = base.clamped()
    per_field: dict[str, list[Tuning]] = {}
    for field in ("max_skills", "max_attempts", "stuck_after"):
        lo, hi = BOUNDS[field]
        per_field[field] = [replace(b, **{field: v}).clamped()
                            for step in (1, -1, 2, -2) for v in [getattr(b, field) + step] if lo <= v <= hi]
    per_field["reflect"] = [replace(b, reflect=r).clamped() for r in REFLECT_GENES if r != b.reflect]
    if b.system_addendum:
        per_field["addendum"] = [replace(b, system_addendum="").clamped()]
    out, i = [], 0
    while any(i < len(v) for v in per_field.values()):
        for v in per_field.values():
            if i < len(v):
                out.append(v[i])
        i += 1
    return out


def seed_population(base: Tuning, size: int, rng: random.Random, extra_addenda=()) -> list[Tuning]:
    pop, seen = [base.clamped()], {genome_sig(base)}

    def add(cand):
        if genome_sig(cand) not in seen and len(pop) < size:
            seen.add(genome_sig(cand)); pop.append(cand)

    for a in extra_addenda:                        # optional LLM-proposed prompt variants
        cand = replace(base.clamped(), system_addendum=sanitise_addendum(a)).clamped()
        if cand.system_addendum:
            add(cand)
    for cand in neighbours(base):                  # systematic single-gene neighbours (round-robin)
        add(cand)
    guard = 0
    while len(pop) < size and guard < size * 20:   # then random multi-gene mutations
        guard += 1
        add(mutate(base, rng))
    return pop[:size]


def evolve(cfg, llm, tasks: list[Task], population: int = 5, generations: int = 3, split: str = "holdout",
           sample: int | None = None, log=print, fitness=None, clock=time.time, hours: float | None = None,
           seed: int | None = None) -> dict:
    """Run the search. `fitness(tuning) -> float` defaults to scoring on the hidden evaluator."""
    rng = random.Random(seed)
    base = load_tuning(cfg.home)
    if fitness is None:
        def fitness(t):
            return improve.score(cfg, t, tasks, llm, split=split, sample=sample, log=lambda *a: None)
    cache: dict[tuple, float] = {}
    deadline = clock() + hours * 3600 if hours else None

    def evaluate(t: Tuning) -> float:
        sig = genome_sig(t)
        if sig not in cache:
            cache[sig] = fitness(t)
        return cache[sig]

    # propose a couple of prompt variants from the model's own recent lessons (best-effort)
    extra = []
    try:
        from .memory.store import Memory
        pc = improve.prompt_candidate(base, llm, Memory(cfg.db_path, read_only=True), log=lambda *a: None)
        if pc:
            extra.append(pc[0].system_addendum)
    except Exception as e:
        if e.__class__.__name__ in ("Halted", "BudgetExceeded"):
            raise

    pop = seed_population(base, population, rng, extra)
    base_score = evaluate(base)
    log(f"Baseline (current method): {base_score:.0%}")
    history = []
    stopped = ""
    try:
        for gen in range(1, generations + 1):
            if deadline and clock() >= deadline:
                stopped = "time budget reached"
                break
            for t in pop:
                evaluate(t)
            pop.sort(key=lambda t: -cache[genome_sig(t)])
            best = cache[genome_sig(pop[0])]
            log(f"Generation {gen}: best {best:.0%} over {len(pop)} variants")
            history.append({"generation": gen, "best": round(best, 4),
                            "scores": sorted((round(cache[genome_sig(t)], 4) for t in pop), reverse=True)})
            if gen == generations:
                break
            elites = pop[:max(2, population // 2)]
            nxt, seen = list(elites), {genome_sig(t) for t in elites}
            guard = 0
            while len(nxt) < population and guard < population * 30:
                guard += 1
                child = mutate(crossover(rng.choice(elites), rng.choice(elites), rng), rng)
                if genome_sig(child) not in seen:
                    seen.add(genome_sig(child)); nxt.append(child)
            pop = nxt
    except (Halted, BudgetExceeded) as e:
        # the kill switch or the spending cap stopped us - keep the best found so far
        stopped = "kill switch" if isinstance(e, Halted) else "budget reached"
        log(f"Stopped early: {stopped}.")

    if not cache:
        return {"baseline": 0.0, "variants_tested": 0, "champion_score": 0.0, "generations": 0,
                "queued": None, "history": [], "stopped": stopped or "no variants scored"}
    champ_sig = max(cache, key=lambda s: cache[s])
    # the champion tuning is rebuilt from its signature, so it never depends on object identity
    champion = Tuning(max_skills=champ_sig[0], max_attempts=champ_sig[1], stuck_after=champ_sig[2],
                      reflect=champ_sig[3], system_addendum=champ_sig[4])
    champ_score = cache[champ_sig]
    queued = None
    if champ_score >= base_score + improve.MARGIN and diff(base, champion):
        queued = {"id": uuid.uuid4().hex[:12], "ts": time.time(),
                  "rationale": f"evolved over {len(history)} generations ({len(cache)} variants tested): "
                               + ", ".join(f"{k} {v[0]}->{v[1]}" for k, v in diff(base, champion).items()),
                  "change": diff(base, champion), "addendum": champion.clamped().system_addendum,
                  "tuning": champion.clamped().describe(), "baseline_score": round(base_score, 4),
                  "candidate_score": round(champ_score, 4), "split": split, "status": "proposed",
                  "method": "evolution", "history": history}
        improve._add_proposal(cfg.home, queued)
        log(f"\nChampion found: {base_score:.0%} -> {champ_score:.0%}. Review and approve it to apply.")
    else:
        log(f"\nNo evolved variant beat the current method by enough ({stopped or 'done'}).")
    return {"baseline": round(base_score, 4), "variants_tested": len(cache),
            "champion_score": round(champ_score, 4), "generations": len(history), "queued": queued,
            "history": history, "stopped": stopped}

