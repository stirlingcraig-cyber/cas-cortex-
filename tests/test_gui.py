"""Desktop app tests. Backend logic always runs; the window smoke test runs only when
tkinter and a display are available (it is skipped on headless machines)."""
import os
import queue
import time

import pytest
from conftest import oracle_llm

from cortex import gui_backend as be
from cortex.agent import CortexAgent
from cortex.config import load_config
from cortex.evaluator.taskbank import BUILTIN_TASKS
from cortex.governance import AuditLog
from cortex.memory.store import Memory
from cortex.trainer import run_eval, train

quiet = lambda *a, **k: None


@pytest.fixture
def trained_home(tmp_path):
    cfg = load_config(tmp_path)
    audit = AuditLog(cfg.audit_path)
    ro = Memory(cfg.db_path, read_only=True)
    run_eval(CortexAgent(oracle_llm(), ro, audit, learn=False, log=quiet), ro, BUILTIN_TASKS, "holdout", log=quiet)
    mem = Memory(cfg.db_path)
    train(CortexAgent(oracle_llm(), mem, audit, log=quiet), mem, BUILTIN_TASKS, 1, log=quiet)
    ro = Memory(cfg.db_path, read_only=True)
    run_eval(CortexAgent(oracle_llm(), ro, audit, learn=False, log=quiet), ro, BUILTIN_TASKS, "all", log=quiet)
    return tmp_path


def run_job(args, home, timeout=60):
    q = queue.Queue()
    be.Job("t", args, home, q)
    out, deadline = [], time.time() + timeout
    while time.time() < deadline:
        kind, _, payload = q.get(timeout=timeout)
        if kind == "done":
            return out, payload
        out.append((kind, payload))
    raise TimeoutError


def test_job_streams_cli_output(tmp_path):
    out, rc = run_job(["tasks", "--domain", "cyber"], tmp_path)
    lines = [p for k, p in out if k == "line"]
    assert rc == 0 and any("cyber.ssh_bruteforce" in l for l in lines) and len(lines) == 4


def test_job_reports_failure_code(tmp_path):
    _, rc = run_job(["solve", "no.such.task"], tmp_path)
    assert rc != 0


def test_snapshot_and_journey(tmp_path, trained_home):
    fresh = be.journey(be.snapshot(tmp_path / "empty"), setup_ok=False)
    assert len(fresh) == 8 and not any(s["done"] for s in fresh)
    s = be.snapshot(trained_home)
    assert s["skills"] == 12 and s["generation"] == 1 and s["latest_score"] == 1.0
    steps = be.journey(s, setup_ok=True)
    done = {x["title"]: x["done"] for x in steps}
    assert done["Take a baseline score"] and done["Train it"] and done["Measure progress"]
    assert not done["Teach it something new"] and not done["Monitor threats live"]
    assert {x["tab"] for x in steps} <= {"Setup", "Train", "Progress", "Skills & Memory", "Teach", "Threat Monitor"}


def test_progress_and_memory_rows(trained_home):
    cols, runs = be.progress_rows(trained_home)
    assert len(runs) == 2 and "holdout/cyber" in cols and runs[0]["train"] is None
    assert runs[1]["overall"] == 1.0
    m = be.memory_rows(trained_home)
    assert m["episodes"] and m["lessons"]
    assert be.audit_rows(trained_home)[0][1] in ("episode", "llm_call", "eval_end")
    assert len(be.skills_rows(trained_home)) == 12


def test_task_form_validation_and_save(tmp_path):
    d = {"id": "cyber.jwt_expiry", "domain": "cyber", "split": "train", "title": "JWT expiry",
         "entry_point": "jwt_expired", "prompt": "Return True when exp is at or before now.",
         "visible_tests": be.split_tests("assert jwt_expired(1, 2) is True\n"),
         "hidden_tests": be.split_tests("assert jwt_expired(3, 2) is False\n\nx = jwt_expired(2, 2)\nassert x is True")}
    assert d["hidden_tests"][1].count("\n") == 1
    path = be.save_task(tmp_path, d)
    assert path.exists() and be.custom_tasks(tmp_path)[0][0] == "cyber.jwt_expiry"
    assert "cyber.jwt_expiry" in be.task_ids(tmp_path)
    with pytest.raises(ValueError, match="already exists"):
        be.save_task(tmp_path, d)
    bad = dict(d, id="x y", entry_point="1bad", visible_tests=["assert (("], hidden_tests=[])
    errs = be.validate_task(bad, [])
    assert len(errs) >= 4


def test_window_smoke(trained_home):
    tk = pytest.importorskip("tkinter")
    if os.name != "nt" and not os.environ.get("DISPLAY"):
        pytest.skip("no display")
    from cortex.gui import TABS, CortexApp
    app = CortexApp(trained_home)
    try:
        app.withdraw()
        for i in range(len(TABS)):
            app.nb.select(i)
            app.update()
        assert app.cards["skills"].cget("text") == "12"
        assert len(app.skill_tree.get_children()) == 12
        assert len(app.prog_tree.get_children()) == 2
        app._kill(True)
        assert app.chip_ks.cget("text") == "KILL SWITCH ON"
        app._kill(False)
    finally:
        app.destroy()


def test_stop_ends_a_running_job_and_its_children(tmp_path):
    log = tmp_path / "live.log"
    log.write_text("")
    q = queue.Queue()
    job = be.Job("m", ["watch", str(log), "--follow"], tmp_path, q)
    time.sleep(1.5)
    assert job.running()
    t0 = time.time()
    job.stop()
    assert not job.running() and time.time() - t0 < 10 and job.stopped
    kinds = []
    deadline = time.time() + 10
    while time.time() < deadline:
        kind, _, _ = q.get(timeout=10)
        kinds.append(kind)
        if kind == "done":
            break
    assert kinds[-1] == "done"


def test_shared_stop_button_enabled_while_training(trained_home, tmp_path):
    pytest.importorskip("tkinter")
    if os.name != "nt" and not os.environ.get("DISPLAY"):
        pytest.skip("no display")
    from cortex.gui import CortexApp
    app = CortexApp(trained_home)
    try:
        app.withdraw()
        log = tmp_path / "x.log"; log.write_text("")
        app.run("train", ["watch", str(log), "--follow"], app.train_con)  # stand-in long job
        app.update()
        stop_btn = app._stop_buttons["train"]
        assert app._stop_buttons["solve"] is stop_btn
        assert str(stop_btn.cget("state")) == "normal"
        stop_btn.invoke()
        assert not app.jobs["train"].running()
    finally:
        for j in app.jobs.values():
            j.stop()
        app.destroy()
