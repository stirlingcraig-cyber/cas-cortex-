"""The local, no-API-key path: Ollama and OpenAI-compatible servers, config defaults,
the doctor, and a full CLI train/eval run against a stand-in Ollama server."""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from conftest import oracle_llm

from cortex import cli
from cortex.config import load_config
from cortex.doctor import has_model, recommend_model, run_doctor
from cortex.llm import OllamaLLM, OpenAICompatLLM, extract_code, extract_json


class FakeServer:
    """Speaks enough of the Ollama and OpenAI APIs; answers using the oracle model."""

    def __init__(self, models=("qwen2.5-coder:7b",), think=False):
        oracle = oracle_llm()
        self.requests = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, obj):
                data = json.dumps(obj).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                if self.path == "/api/tags":
                    self._send({"models": [{"name": m} for m in models]})
                elif self.path == "/v1/models":
                    self._send({"data": [{"id": m} for m in models]})

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                outer.requests.append((self.path, body))
                system = body["messages"][0]["content"]
                text = oracle.complete(system, body["messages"][1:]).text
                if think:
                    text = "<think>let me reason about ```python\nbad()\n``` first</think>\n" + text
                if self.path == "/api/chat":
                    self._send({"message": {"content": text}, "prompt_eval_count": 120, "eval_count": 80})
                elif self.path == "/v1/chat/completions":
                    self._send({"choices": [{"message": {"content": text}}],
                                "usage": {"prompt_tokens": 120, "completion_tokens": 80}})

        self.httpd = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.httpd.server_port}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()


@pytest.fixture
def server():
    s = FakeServer()
    yield s
    s.close()


@pytest.fixture
def clean_env(monkeypatch):
    for k in ("ANTHROPIC_API_KEY", "CORTEX_PROVIDER", "CORTEX_MODEL", "CORTEX_HOME",
              "OLLAMA_URL", "OPENAI_BASE_URL", "OPENAI_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    return monkeypatch


def test_default_is_local_without_api_key(tmp_path, clean_env):
    cfg = load_config(tmp_path)
    assert cfg.provider == "ollama" and cfg.local
    clean_env.setenv("ANTHROPIC_API_KEY", "x")
    assert load_config(tmp_path).provider == "anthropic"
    cfg.save_settings(provider="ollama", model="qwen2.5-coder:3b")
    c2 = load_config(tmp_path)  # saved choice beats auto-detect
    assert (c2.provider, c2.model) == ("ollama", "qwen2.5-coder:3b")


def test_ollama_request_sets_context_window(server):
    r = OllamaLLM("qwen2.5-coder:7b", server.url).complete(
        "s", [{"role": "user", "content": "Write the complete module defining `double`."}])
    path, body = server.requests[-1]
    assert path == "/api/chat" and body["options"]["num_ctx"] >= 8192 and not body["stream"]
    assert "def double" in r.text and r.tokens == 200


def test_openai_compatible(server):
    r = OpenAICompatLLM("any", server.url + "/v1").complete(
        "s", [{"role": "user", "content": "Write the complete module defining `double`."}])
    assert "def double" in r.text and server.requests[-1][0] == "/v1/chat/completions"


def test_friendly_error_when_ollama_not_running():
    with pytest.raises(RuntimeError, match="Start the Ollama app"):
        OllamaLLM("m", "http://127.0.0.1:9").complete("s", [{"role": "user", "content": "x"}])


def test_thinking_models_are_handled():
    t = "<think>maybe ```python\nwrong()\n```</think>\nHere:\n```Python\ndef f():\n    return 1\n```"
    assert extract_code(t) == "def f():\n    return 1\n"
    assert extract_json('<think>{"no": 1}</think>{"lesson": "x"}') == {"lesson": "x"}


def test_model_recommendation():
    assert recommend_model(8)[0] == "qwen2.5-coder:3b"
    assert recommend_model(16)[0] == "qwen2.5-coder:7b"
    assert recommend_model(64)[0] == "qwen2.5-coder:14b"
    assert recommend_model(4)[0] == "qwen2.5-coder:1.5b"
    assert has_model(["qwen2.5-coder:7b"], "qwen2.5-coder:7b")
    assert not has_model(["llama3:latest"], "qwen2.5-coder:7b")


def test_doctor(tmp_path, clean_env, server):
    clean_env.setenv("OLLAMA_URL", server.url)
    clean_env.setenv("CORTEX_MODEL", "qwen2.5-coder:7b")
    out = []
    assert run_doctor(load_config(tmp_path), out=out.append)
    assert any("ready" in l for l in out)
    clean_env.setenv("OLLAMA_URL", "http://127.0.0.1:9")
    out = []
    assert not run_doctor(load_config(tmp_path), out=out.append)
    assert any("NOT reachable" in l for l in out)


def test_full_cli_run_against_local_server(tmp_path, clean_env, capsys):
    s = FakeServer(think=True)  # also proves <think> output doesn't break the loop
    try:
        clean_env.setenv("OLLAMA_URL", s.url)
        home = str(tmp_path / "data")
        cli.main(["--home", home, "train", "--rounds", "1", "--domain", "cyber"])
        cli.main(["--home", home, "eval", "--split", "holdout", "--domain", "cyber"])
        cli.main(["--home", home, "skills"])
        cli.main(["--home", home, "verify"])
        out = capsys.readouterr().out
        assert "3/3 practice episodes solved" in out
        assert "holdout/cyber" in out and "100%" in out
        assert "detect_bruteforce" in out and "audit chain intact" in out
        assert all(p == "/api/chat" for p, _ in s.requests)
    finally:
        s.close()


def test_check_sandbox_command(tmp_path, capsys):
    cli.main(["--home", str(tmp_path), "check-sandbox"])
    out = capsys.readouterr().out
    assert out.count("PASS") == 3 and "Sandbox works" in out
