"""Step 4: evolutionary search. Breeds a population of tunings, scores each against the hidden
evaluator, keeps the best, and queues the champion for approval - never applying it on its own,
never changing anything but the safe tunable method."""
import random

import pytest
from conftest import oracle_llm

from cortex import evolve, improve, tuning
from cortex.config import load_config
from cortex.evaluator.taskbank import BUILTIN_TASKS
from cortex.governance import lock_integrity
from cortex.llm import FakeLLM
from cortex.memory.store import Memory
from cortex.tuning import Tuning, BOUNDS

quiet = lambda *a, **k: None


@pytest.fixture
def home(tmp_path):
    cfg = load_config(tmp_path)
    lock_integrity(cfg.integrity_path)
    Memory(cfg.db_path).add_lesson("Handle empty input first.", "coding", "x")
    return cfg


def test_mutation_and_crossover_stay_in_bounds():
    rng = random.Random(0)
    base = Tuning()
    for _ in range(500):
        m = evolve.mutate(base, rng)
        assert BOUNDS["max_skills"][0] <= m.max_skills <= BOUNDS["max_skills"][1]
        assert BOUNDS["max_attempts"][0] <= m.max_attempts <= BOUNDS["max_attempts"][1]
        assert m.reflect in evolve.REFLECT_GENES          # never evolves to "never"
        c = evolve.crossover(base, m, rng)
        assert c.max_attempts in (base.max_attempts, m.max_attempts)


def test_seed_population_is_unique_and_sized():
    pop = evolve.seed_population(Tuning(), 6, random.Random(1))
    assert len(pop) == 6 and len({evolve.genome_sig(t) for t in pop}) == 6
    assert evolve.genome_sig(pop[0]) == evolve.genome_sig(Tuning())    # base is included


def test_evolution_finds_and_queues_a_better_variant(home):
    # fitness we control: reward more attempts (climbs toward max_attempts=8)
    def fitness(t):
        return 0.4 + 0.05 * (t.max_attempts - 2)
    res = evolve.evolve(home, FakeLLM([]), BUILTIN_TASKS, population=5, generations=4, log=quiet,
                        fitness=fitness, seed=3)
    assert res["queued"] and res["champion_score"] > res["baseline"]
    props = improve.load_proposals(home.home)
    assert len(props) == 1 and props[0]["method"] == "evolution" and props[0]["status"] == "proposed"
    assert props[0]["tuning"]["max_attempts"] >= Tuning().max_attempts
    # the champion improves over generations
    bests = [g["best"] for g in res["history"]]
    assert bests == sorted(bests)


def test_no_proposal_when_nothing_beats_baseline(home):
    res = evolve.evolve(home, FakeLLM([]), BUILTIN_TASKS, population=4, generations=2, log=quiet,
                        fitness=lambda t: 0.5, seed=1)
    assert res["queued"] is None and improve.load_proposals(home.home) == []


def test_champion_can_be_approved_through_step3_flow(home):
    evolve.evolve(home, FakeLLM([]), BUILTIN_TASKS, population=4, generations=3, log=quiet,
                  fitness=lambda t: 0.4 + 0.1 * t.max_skills, seed=2)
    pid = improve.load_proposals(home.home)[0]["id"]
    improve.apply(home.home, pid)
    assert tuning.load(home.home).max_skills == improve.load_proposals(home.home)[0]["tuning"]["max_skills"]


def test_fitness_cached_so_each_genome_scored_once(home):
    calls = []
    def fitness(t):
        calls.append(evolve.genome_sig(t))
        return 0.5 + 0.01 * t.max_skills
    evolve.evolve(home, FakeLLM([]), BUILTIN_TASKS, population=5, generations=3, log=quiet,
                  fitness=fitness, seed=5)
    assert len(calls) == len(set(calls))              # no genome scored twice


def test_real_fitness_is_read_only_and_bounded(home):
    Memory(home.db_path).close()
    res = evolve.evolve(home, oracle_llm(), BUILTIN_TASKS, population=3, generations=1, split="holdout",
                        sample=2, log=quiet, seed=1)
    assert 0.0 <= res["champion_score"] <= 1.0 and res["variants_tested"] >= 1
    assert Memory(home.db_path).stats()["eval_runs"] == 0    # scoring never wrote to memory


def test_evolution_never_writes_into_the_package(home):
    import cortex
    from pathlib import Path
    pkg = Path(cortex.__file__).resolve().parent
    before = {p: p.stat().st_mtime for p in pkg.rglob("*.py")}
    evolve.evolve(home, FakeLLM([]), BUILTIN_TASKS, population=4, generations=2, log=quiet,
                  fitness=lambda t: 0.4 + 0.1 * t.max_attempts, seed=1)
    improve.apply(home.home, improve.load_proposals(home.home)[0]["id"])
    assert {p: p.stat().st_mtime for p in pkg.rglob("*.py")} == before
