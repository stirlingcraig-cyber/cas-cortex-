"""Model providers. The foundation model is swappable: Claude via API for strong
reasoning, or a local open model via Ollama (no data leaves your machine)."""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable


@dataclass
class LLMResponse:
    text: str
    input_tokens: int = 0
    output_tokens: int = 0
    seconds: float = 0.0          # generation time reported by the model server, if known

    @property
    def tokens(self) -> int:
        return self.input_tokens + self.output_tokens


class LLM:
    name = "base"
    # Speed settings applied to every call (set by make_llm). Stopping at the closing code
    # fence skips the explanation small models like to add after the code; the output cap
    # stops runaway answers. Neither affects answers that are already shorter.
    default_stop: list[str] | None = None
    max_tokens_cap: int | None = None

    def _limits(self, stop, max_tokens):
        stop = stop or self.default_stop
        if self.max_tokens_cap:
            max_tokens = min(max_tokens, self.max_tokens_cap)
        return stop, max_tokens

    def complete(self, system: str, messages: list[dict], max_tokens: int = 4000,
                 stop: list[str] | None = None, temperature: float | None = None) -> LLMResponse:
        raise NotImplementedError


class AnthropicLLM(LLM):
    name = "anthropic"

    def __init__(self, model: str):
        try:
            import anthropic
        except ImportError as e:
            raise RuntimeError("pip install anthropic  (needed for the anthropic provider)") from e
        self.client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY
        self.model = model

    def complete(self, system, messages, max_tokens=4000, stop=None, temperature=None):
        stop, max_tokens = self._limits(stop, max_tokens)
        kw = {"stop_sequences": stop} if stop else {}
        if temperature is not None:
            kw["temperature"] = temperature
        r = self.client.messages.create(model=self.model, max_tokens=max_tokens,
                                        system=system, messages=messages, **kw)
        text = "".join(getattr(b, "text", "") for b in r.content)
        return LLMResponse(text, r.usage.input_tokens, r.usage.output_tokens)


class OllamaLLM(LLM):
    name = "ollama"

    def __init__(self, model: str, url: str = "http://localhost:11434", num_ctx: int = 16384):
        self.model, self.url, self.num_ctx = model, url.rstrip("/"), num_ctx

    def complete(self, system, messages, max_tokens=4000, stop=None, temperature=None):
        stop, max_tokens = self._limits(stop, max_tokens)
        # Ollama's default context window is small and silently truncates long prompts,
        # which would cut off the skills and lessons Cortex relies on - so set it explicitly.
        body = {"model": self.model, "stream": False, "keep_alive": "30m",
                "options": {"num_predict": max_tokens, "num_ctx": self.num_ctx,
                            "temperature": 0.2 if temperature is None else temperature,
                            **({"stop": stop} if stop else {})},
                "messages": [{"role": "system", "content": system}] + messages}
        d = _post_json(self.url + "/api/chat", body, None, "Ollama",
                       "Start the Ollama app (or run `ollama serve`), then try again. "
                       "Run `python -m cortex doctor` to check your setup.")
        if "error" in d:
            raise RuntimeError(f"Ollama: {d['error']} - try `ollama pull {self.model}`")
        return LLMResponse(d["message"]["content"], d.get("prompt_eval_count", 0),
                           d.get("eval_count", 0), d.get("total_duration", 0) / 1e9)


class OpenAICompatLLM(LLM):
    """Any OpenAI-compatible chat server: LM Studio (default http://localhost:1234/v1),
    llama.cpp server, vLLM, Jan, or Ollama's /v1 endpoint. An API key is optional."""
    name = "openai"

    def __init__(self, model: str, base_url: str = "http://localhost:1234/v1", api_key: str | None = None):
        self.model, self.base_url, self.api_key = model, base_url.rstrip("/"), api_key

    def complete(self, system, messages, max_tokens=4000, stop=None, temperature=None):
        stop, max_tokens = self._limits(stop, max_tokens)
        body = {"model": self.model, "max_tokens": max_tokens,
                "temperature": 0.2 if temperature is None else temperature,
                "messages": [{"role": "system", "content": system}] + messages}
        if stop:
            body["stop"] = stop
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else None
        d = _post_json(self.base_url + "/chat/completions", body, headers, "the local model server",
                       f"Cortex is set to use LM Studio (provider 'openai'). Either start LM Studio's local server with a "
                       "model loaded, or if you use Ollama (the default): Setup tab > Provider 'ollama' > Use this model.")
        u = d.get("usage") or {}
        return LLMResponse(d["choices"][0]["message"]["content"] or "",
                           u.get("prompt_tokens", 0), u.get("completion_tokens", 0))


def _post_json(url: str, body: dict, headers: dict | None, who: str, hint: str) -> dict:
    h = {"Content-Type": "application/json", **(headers or {})}
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers=h)
    try:
        with urllib.request.urlopen(req, timeout=900) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")[:300]
        raise RuntimeError(f"{who} returned HTTP {e.code}: {detail}") from e
    except (urllib.error.URLError, ConnectionError, TimeoutError) as e:
        raise RuntimeError(f"Could not reach {who} at {url}. {hint}") from e


class FakeLLM(LLM):
    """Scripted model for tests. `script` is a list of strings or a callable
    (system, messages) -> str."""
    name = "fake"

    def __init__(self, script: list[str] | Callable[[str, list[dict]], str]):
        self.script = script
        self.calls: list[tuple[str, list[dict]]] = []

    def complete(self, system, messages, max_tokens=4000, stop=None, temperature=None):
        self.calls.append((system, messages))
        self.stops = getattr(self, "stops", []) + [stop]
        self.temps = getattr(self, "temps", []) + [temperature]
        if callable(self.script):
            text = self.script(system, messages)
        else:
            text = self.script.pop(0) if self.script else ""
        return LLMResponse(text, 100, 50)


CODE_STOP = ["\n```\n", "\n```\r\n"]


def make_llm(cfg) -> LLM:
    if cfg.provider == "anthropic":
        llm = AnthropicLLM(cfg.model)
    elif cfg.provider == "ollama":
        llm = OllamaLLM(cfg.model, cfg.ollama_url, cfg.num_ctx)
    elif cfg.provider == "openai":
        llm = OpenAICompatLLM(cfg.model, cfg.openai_base_url, cfg.openai_api_key)
    else:
        raise ValueError(cfg.provider)
    if getattr(cfg, "fast", True):
        llm.default_stop = CODE_STOP
        llm.max_tokens_cap = getattr(cfg, "max_output_tokens", 1800)
    return llm


_CODE = re.compile(r"```[ \t]*(?:python3?|py)?[ \t]*\r?\n(.*?)```", re.S | re.I)
_THINK = re.compile(r"<think>.*?</think>", re.S | re.I)


def strip_thinking(text: str) -> str:
    """Remove <think>...</think> reasoning that some local models (Qwen3, DeepSeek-R1) emit."""
    return _THINK.sub("", text or "")


def extract_code(text: str) -> str:
    text = strip_thinking(text)
    blocks = _CODE.findall(text or "")
    if blocks:
        return max(blocks, key=len).strip() + "\n"
    m = re.search(r"```[ \t]*(?:python3?|py)?[ \t]*\r?\n(.*)$", text or "", re.S | re.I)
    if m:                                   # opening fence but no closing one
        return m.group(1).strip().rstrip("`").strip() + "\n"
    return (text or "").strip() + "\n"


def extract_json(text: str):
    text = strip_thinking(text)
    m = re.search(r"```(?:json)?\s*\n(.*?)```", text or "", re.S)
    raw = m.group(1) if m else text
    start, end = raw.find("{"), raw.rfind("}")
    if start == -1 or end == -1:
        return None
    try:
        return json.loads(raw[start:end + 1])
    except json.JSONDecodeError:
        return None
