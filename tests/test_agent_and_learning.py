from conftest import oracle_llm

from cortex.agent import CortexAgent
from cortex.evaluator.taskbank import BUILTIN_TASKS
from cortex.memory.store import Memory
from cortex.trainer import report, run_eval, train

T = {t.id: t for t in BUILTIN_TASKS}
quiet = lambda *a, **k: None


def test_self_correction_then_skill_and_lesson(mem, audit):
    agent = CortexAgent(oracle_llm(wrong_first=True), mem, audit, log=quiet)
    o = agent.solve(T["cyber.ssh_bruteforce"].public_view())
    assert o.solved and o.attempts == 2 and o.skill_action == "added"
    assert mem.get_skill("detect_bruteforce").trust == "verified-visible"
    assert mem.stats()["lessons"] == 1 and mem.stats()["knowledge_triples"] == 1
    assert mem.episodes()[0]["solved"] == 1
    # the retry prompt carried the failing test output back to the model
    retry = agent.llm.calls[1][1][-1]["content"]
    assert "did not pass" in retry and "got None" in retry


def test_learned_skills_and_lessons_appear_in_later_prompts(mem, audit):
    llm = oracle_llm()
    agent = CortexAgent(llm, mem, audit, log=quiet)
    agent.solve(T["threat.beaconing"].public_view())
    agent.solve(T["threat.correlate"].public_view())
    first_prompt = llm.calls[-2][1][0]["content"]  # prompt for second task (before reflection)
    assert "Lessons from your past experience" in first_prompt
    assert "Available skills" in first_prompt


def test_recall_by_import_reinforces_not_overwrites(mem, audit):
    agent = CortexAgent(oracle_llm(), mem, audit, log=quiet)
    agent.solve(T["bigdata.top_k"].public_view())
    from cortex.llm import FakeLLM
    wrapper = "```python\nfrom skills import top_k_frequent\n```"
    reflect = '{"lesson": "Reuse verified skills when the contract matches.", "knowledge": []}'
    agent2 = CortexAgent(FakeLLM([wrapper, reflect]), mem, audit, log=quiet)
    o = agent2.solve(T["bigdata.top_k"].public_view())
    s = mem.get_skill("top_k_frequent")
    assert o.solved and o.skill_action == "reinforced" and "from skills" not in s.code
    assert s.uses == 1 and s.successes == 2


def test_train_then_eval_is_read_only(tmp_path, audit):
    mem = Memory(tmp_path / "c.db")
    agent = CortexAgent(oracle_llm(), mem, audit, log=quiet)
    res = train(agent, mem, BUILTIN_TASKS, rounds=2, log=quiet, seed=1)
    assert len(mem.all_skills()) == 12  # all train-split tasks, no holdout leakage
    assert mem.get_meta("generation") == 2 and all(r["solved"] for r in res)
    before = mem.stats()
    ro = Memory(tmp_path / "c.db", read_only=True)
    ev = run_eval(CortexAgent(oracle_llm(), ro, audit, learn=False, log=quiet), ro,
                  BUILTIN_TASKS, split="all", log=quiet)
    after = Memory(tmp_path / "c.db").stats()
    assert after["episodes"] == before["episodes"] and after["skills"] == before["skills"]
    assert ev["summary"]["holdout/cyber"] == 1.0 and len(ev["rows"]) == 16
    assert "holdout/threat" in report(ro)


def test_failed_task_records_episode_without_skill(mem, audit):
    from cortex.llm import FakeLLM
    bad = "```python\ndef merge_intervals(x):\n    return x\n```"
    llm = FakeLLM([bad, bad, '{"lesson": "Sort intervals by start before merging them.", "knowledge": []}'])
    o = CortexAgent(llm, mem, audit, max_attempts=2, log=quiet).solve(T["coding.merge_intervals"].public_view())
    assert not o.solved and mem.get_skill("merge_intervals") is None
    assert mem.past_reflections("coding.merge_intervals") == ["Sort intervals by start before merging them."]


def test_freeform_learning_self_tests(mem, audit):
    agent = CortexAgent(oracle_llm(), mem, audit, log=quiet)
    o = agent.solve_freeform("Return x doubled.", "double", "coding")
    assert o.solved and mem.get_skill("double").trust == "self-tested"


def test_demo_code_from_small_models_is_removed(mem, audit):
    """Local models often append examples that crash on import (e.g. calling the function
    with the invalid input the spec says must raise). That must not hide a correct answer."""
    from conftest import BY_ENTRY
    from cortex.agent import clean_solution
    from cortex.llm import FakeLLM
    noisy = ("```python\n" + BY_ENTRY["version_compare"] +
             "\n# Example usage\nprint(version_compare('1.a', '1.0'))\nassert version_compare('1', '2') == 1\n"
             "if __name__ == '__main__':\n    print('demo')\n```")
    logs = []
    agent = CortexAgent(FakeLLM([noisy, '{"lesson": "Keep modules free of demo code.", "knowledge": []}']),
                        mem, audit, log=logs.append)
    o = agent.solve(T["coding.version_compare"].public_view())
    assert o.solved and o.attempts == 1 and "print(" not in o.code
    assert clean_solution("x = 1\n") == "x = 1\n"


def test_failure_reason_is_shown(mem, audit):
    from cortex.llm import FakeLLM
    bad = "```python\nimport math\nraise RuntimeError('boom on import')\n```"
    logs = []
    CortexAgent(FakeLLM([bad, bad, "{}"]), mem, audit, max_attempts=2, log=logs.append).solve(
        T["coding.merge_intervals"].public_view())
    assert any("reason: RuntimeError: boom on import" in l for l in logs)


def test_forgotten_import_is_fixed_without_another_model_call(mem, audit):
    """Seen on a real PC: a local model used math.radians(...) without `import math` and
    repeated it on every retry. Cortex now adds the import itself."""
    from conftest import BY_ENTRY
    from cortex.llm import FakeLLM
    ref = BY_ENTRY["impossible_travel"].replace("import math\n", "").replace("from collections import defaultdict\n", "")
    llm = FakeLLM(["```python\n" + ref + "\n```", '{"lesson": "Always import modules you use.", "knowledge": []}'])
    logs = []
    o = CortexAgent(llm, mem, audit, log=logs.append).solve(T["threat.impossible_travel"].public_view())
    assert o.solved and o.attempts == 1 and len(llm.calls) == 2           # 1 attempt + 1 reflection
    assert "import math" in o.code and "from collections import defaultdict" in o.code
    assert any("auto-fixed missing import" in l for l in logs)


def test_testgen_parsing_tolerates_messy_model_output(mem, audit):
    """Small models rarely return clean JSON. _parse_tests must harvest asserts from JSON,
    bare arrays, code fences, <think> blocks and loose lines - this is what caused
    'could not generate a usable test suite'."""
    from cortex.llm import FakeLLM
    agent = CortexAgent(FakeLLM([]), mem, audit, log=quiet)
    ep = "login_storm"
    json_ok = '{"tests": ["assert login_storm([0]*10) is True", "assert login_storm([]) is False"]}'
    assert len(agent._parse_tests(json_ok, ep)) == 2
    fenced = "Here are tests:\n```python\nassert login_storm([1,2]) is False\nassert login_storm(list(range(10))) is True\n```"
    assert len(agent._parse_tests(fenced, ep)) == 2
    thinky = '<think>let me think</think>\n{"tests": ["assert login_storm([5]) is False"]}'
    assert agent._parse_tests(thinky, ep) == ["assert login_storm([5]) is False"]
    loose = 'assert login_storm([0,30,59]) is False\nassert login_storm([0]*10) is True\nnot a test line'
    assert len(agent._parse_tests(loose, ep)) == 2
    assert agent._parse_tests('assert something_else(1) == 1', ep) == []      # wrong function ignored
    assert agent._parse_tests('assert login_storm(', ep) == []               # unparseable ignored


def test_freeform_retries_then_gives_clear_error(mem, audit):
    from cortex.llm import FakeLLM
    # first two tries unusable, third gives 3 good tests
    good = '{"tests": ["assert login_storm([0]*10) is True", "assert login_storm([]) is False", "assert login_storm([1,2,3]) is False"]}'
    llm = FakeLLM(["sorry, no idea", "{}", good, "```python\ndef login_storm(x):\n    return len(x) >= 10\n```", "{}"])
    o = CortexAgent(llm, mem, audit, log=quiet).solve_freeform(
        "Return True if 10+ timestamps fall in any 60s window", "login_storm", "cyber")
    assert o.solved and mem.get_skill("login_storm").trust == "self-tested"
    # never usable -> a helpful error, not a crash
    import pytest
    with pytest.raises(RuntimeError, match="Add a practice task"):
        CortexAgent(FakeLLM(["nope", "still nope", "nope again"]), mem, audit, log=quiet).solve_freeform(
            "do a thing", "mystery_fn", "coding")
