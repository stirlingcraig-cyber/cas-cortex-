import pytest

from cortex.evaluator.evaluate import evaluate
from cortex.evaluator.taskbank import BUILTIN_TASKS, DOMAINS, all_tasks
from cortex.sandbox import run_tests
from reference_solutions import REFERENCE


@pytest.mark.parametrize("task", BUILTIN_TASKS, ids=lambda t: t.id)
def test_reference_passes_every_test(task):
    r = run_tests(REFERENCE[task.id], list(task.visible_tests) + list(task.hidden_tests))
    assert r.all_passed, r.failure_report()


@pytest.mark.parametrize("task", BUILTIN_TASKS, ids=lambda t: t.id)
def test_stub_scores_zero(task):
    stub = f"def {task.entry_point}(*a, **k):\n    return None\n"
    if task.entry_point[0].isupper():
        stub = f"class {task.entry_point}:\n    def __init__(self, *a, **k):\n        pass\n"
    assert evaluate(task, stub, {}).score < 0.35


def test_hidden_tests_discriminate_plausible_wrong_answer():
    t = next(t for t in BUILTIN_TASKS if t.id == "coding.version_compare")
    naive = "def version_compare(a, b):\n    return (a > b) - (a < b)\n"
    assert evaluate(t, naive, {}).score < 0.6


def test_public_view_hides_hidden_tests():
    for t in BUILTIN_TASKS:
        v = t.public_view()
        assert not hasattr(v, "hidden_tests")
        assert not set(t.hidden_tests) & set(v.visible_tests) or t.id == "bigdata.rolling_z"


def test_curriculum_shape():
    assert {t.domain for t in BUILTIN_TASKS} == set(DOMAINS)
    for d in DOMAINS:
        splits = [t.split for t in BUILTIN_TASKS if t.domain == d]
        assert splits.count("holdout") == 1 and splits.count("train") == 3


def test_custom_tasks_load(tmp_path):
    (tmp_path / "mine.json").write_text("""{"id": "coding.add", "domain": "coding",
      "title": "Add", "entry_point": "add", "prompt": "add(a,b)",
      "visible_tests": ["assert add(1, 2) == 3"], "hidden_tests": ["assert add(2, 2) == 4"]}""")
    ts = all_tasks(tmp_path)
    assert ts[-1].id == "coding.add" and len(ts) == len(BUILTIN_TASKS) + 1
