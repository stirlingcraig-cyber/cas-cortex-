"""Faster, more automated training: stop sequences and output caps, short retry prompts,
stuck detection, smart reflection, task parking, hands-off training and the speed test."""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from conftest import BY_ENTRY, oracle_llm
from test_local_providers import FakeServer

from cortex import cli
from cortex.agent import REFLECT_SYSTEM, CortexAgent
from cortex.config import load_config
from cortex.doctor import speed_test
from cortex.evaluator.taskbank import BUILTIN_TASKS
from cortex.llm import CODE_STOP, FakeLLM, extract_code, make_llm
from cortex.memory.store import Memory
from cortex.trainer import parked, select_curriculum, train

T = {t.id: t for t in BUILTIN_TASKS}
quiet = lambda *a, **k: None


@pytest.fixture
def clean_env(monkeypatch):
    for k in ("ANTHROPIC_API_KEY", "CORTEX_PROVIDER", "CORTEX_MODEL", "CORTEX_HOME", "OLLAMA_URL"):
        monkeypatch.delenv(k, raising=False)
    return monkeypatch


def test_model_calls_stop_after_the_code_and_are_capped(tmp_path, clean_env):
    s = FakeServer()
    try:
        clean_env.setenv("OLLAMA_URL", s.url)
        llm = make_llm(load_config(tmp_path))
        llm.complete("s", [{"role": "user", "content": "Write the complete module defining `double`."}], max_tokens=4000)
        opts = s.requests[-1][1]["options"]
        assert opts["stop"] == CODE_STOP and opts["num_predict"] == 1800 and opts["num_ctx"] == 8192
    finally:
        s.close()


def test_code_is_extracted_when_the_stop_sequence_cut_the_closing_fence():
    assert extract_code("Sure:\n```python\ndef f():\n    return 1\n") == "def f():\n    return 1\n"


def test_stops_early_when_the_model_repeats_itself(mem, audit):
    bad = "```python\ndef merge_intervals(x):\n    return x\n```"
    llm = FakeLLM([bad] * 8 + ['{"lesson": "Sort by start first.", "knowledge": []}'])
    logs = []
    o = CortexAgent(llm, mem, audit, max_attempts=8, log=logs.append).solve(T["coding.merge_intervals"].public_view())
    assert o.attempts == 2 and not o.solved                   # not 8
    assert any("stopping early" in l for l in logs)


def test_stops_early_on_the_same_mistake_in_different_code(mem, audit):
    codes = [f"```python\ndef merge_intervals(x):\n    y = {i}\n    raise KeyError('k')\n```" for i in range(8)]
    llm = FakeLLM(codes + ["{}"])
    o = CortexAgent(llm, mem, audit, max_attempts=8, stuck_after=2, log=quiet).solve(
        T["coding.merge_intervals"].public_view())
    assert o.attempts == 3


def test_retry_prompt_carries_only_the_latest_attempt(mem, audit):
    codes = [f"```python\ndef merge_intervals(x):\n    return {i}\n```" for i in range(3)]
    llm = FakeLLM(codes + ["```python\n" + BY_ENTRY["merge_intervals"] + "\n```", "{}"])
    CortexAgent(llm, mem, audit, max_attempts=5, stuck_after=0, log=quiet).solve(T["coding.merge_intervals"].public_view())
    assert [len(m) for _, m in llm.calls[:4]] == [1, 3, 3, 3]
    assert "Attempt 3 did not pass" in llm.calls[3][1][-1]["content"]


def test_smart_reflection_skips_easy_repeats(mem, audit):
    llm = oracle_llm()
    agent = CortexAgent(llm, mem, audit, log=quiet)
    agent.solve(T["bigdata.top_k"].public_view())                       # first success: reflects
    n = len([c for c in llm.calls if c[0] == REFLECT_SYSTEM])
    agent.solve(T["bigdata.top_k"].public_view())                       # mastered, 1 attempt: no reflection
    assert n == 1 and len([c for c in llm.calls if c[0] == REFLECT_SYSTEM]) == 1
    CortexAgent(llm, mem, audit, reflect="always", log=quiet).solve(T["bigdata.top_k"].public_view())
    assert len([c for c in llm.calls if c[0] == REFLECT_SYSTEM]) == 2


def test_failing_tasks_are_parked_then_return(mem):
    t = T["coding.lru_cache"]
    for i in range(3):
        mem.log_episode(task_id=t.id, domain="coding", mode="train", attempts=4, solved=False, visible_pass=0,
                        code="", reflection="", skills_used=[], tokens=0, duration=1)
    import random
    assert parked(t, mem)
    logs = []
    plan = select_curriculum([t, T["coding.topo_sort"]], mem, random.Random(1), log=logs.append)
    assert t not in plan and any("parked" in l for l in logs)
    assert not parked(t, mem, now=__import__("time").time() + 4 * 86400)


def test_hands_off_training_stops_when_mastered_or_out_of_time(tmp_path, audit):
    mem = Memory(tmp_path / "a.db")
    tasks = [t for t in BUILTIN_TASKS if t.domain == "cyber"]
    res = train(CortexAgent(oracle_llm(), mem, audit, log=quiet), mem, tasks, 1, log=quiet, until_mastered=True)
    assert {r["task"] for r in res} == {"cyber.ssh_bruteforce", "cyber.extract_iocs", "cyber.suspicious_cmdline"}
    assert mem.get_meta("generation") == 1                              # stopped once mastered

    mem2 = Memory(tmp_path / "b.db")
    now = [0.0]

    def clock():
        now[0] += 600                                                   # every check = 10 minutes later
        return now[0]
    logs = []
    res = train(CortexAgent(oracle_llm(), mem2, audit, log=quiet), mem2, BUILTIN_TASKS, 1, log=logs.append,
                hours=1.5, clock=clock)
    assert 0 < len(res) < 12 and any("Time budget reached" in l for l in logs)


def test_hands_off_training_gives_up_when_stuck(tmp_path, audit):
    mem = Memory(tmp_path / "c.db")
    llm = FakeLLM(lambda s, m: "{}" if s == REFLECT_SYSTEM else "```python\ndef nope():\n    pass\n```")
    logs = []
    train(CortexAgent(llm, mem, audit, max_attempts=2, log=quiet), mem,
          [T["coding.merge_intervals"]], 1, log=logs.append, until_mastered=True)
    assert mem.get_meta("generation") <= 3
    assert any("parked" in l or "No new skills" in l for l in logs)


def test_cli_hands_off_then_eval(tmp_path, clean_env, capsys):
    s = FakeServer()
    try:
        clean_env.setenv("OLLAMA_URL", s.url)
        cli.main(["--home", str(tmp_path / "h"), "train", "--until-mastered", "--then-eval",
                  "--domain", "cyber", "threat"])
        out = capsys.readouterr().out
        assert "6/6 practice episodes solved" in out and "evaluation (holdout)" in out
        assert "Every practice task is mastered" in out
    finally:
        s.close()


class SpeedServer:
    def __init__(self, vram):
        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, obj):
                d = json.dumps(obj).encode()
                self.send_response(200); self.send_header("Content-Length", str(len(d))); self.end_headers()
                self.wfile.write(d)

            def do_GET(self):
                self._send({"models": [{"name": "qwen2.5-coder:7b", "size": 5_000, "size_vram": vram}]})

            def do_POST(self):
                self.rfile.read(int(self.headers["Content-Length"]))
                self._send({"response": "def r(s): return s[::-1]", "eval_count": 40, "eval_duration": 10_000_000_000,
                            "prompt_eval_count": 30, "prompt_eval_duration": 1_000_000_000})
        self.httpd = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.httpd.server_port}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()


def test_speed_test_reports_cpu_and_suggests_faster_model(tmp_path, clean_env):
    srv = SpeedServer(vram=0)
    clean_env.setenv("OLLAMA_URL", srv.url)
    clean_env.setenv("CORTEX_MODEL", "qwen2.5-coder:7b")
    lines = []
    r = speed_test(load_config(tmp_path), out=lines.append)
    srv.httpd.shutdown()
    assert r["gen_tps"] == 4.0 and r["gpu_share"] == 0.0
    text = "\n".join(lines)
    assert "CPU only" in text and "qwen2.5-coder:3b" in text and "graphics card" in text
