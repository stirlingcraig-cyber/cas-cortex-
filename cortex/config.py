"""Configuration. Everything can be set with environment variables or CLI flags.

CORTEX_HOME        data folder (default: ./cortex_data)
CORTEX_PROVIDER    ollama | openai | anthropic
                   default: ollama (free, local, no API key). anthropic is chosen
                   automatically only if ANTHROPIC_API_KEY is set.
CORTEX_MODEL       model name (default per provider; for ollama, picked to suit your RAM
                   by `cortex doctor`, which saves it to <home>/settings.json)
OLLAMA_URL         default http://localhost:11434
OPENAI_BASE_URL    for the openai-compatible provider (default LM Studio: http://localhost:1234/v1)
OPENAI_API_KEY     optional, only if your local server requires one
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

DEFAULT_MODELS = {"ollama": "qwen2.5-coder:7b", "openai": "local-model",
                  "anthropic": "claude-sonnet-5-5"}
PROVIDERS = tuple(DEFAULT_MODELS)


@dataclass
class Config:
    home: Path
    provider: str = "ollama"
    model: str = DEFAULT_MODELS["ollama"]
    ollama_url: str = "http://localhost:11434"
    openai_base_url: str = "http://localhost:1234/v1"
    openai_api_key: str | None = None
    num_ctx: int = 8192               # 8k fits every Cortex prompt; bigger only costs RAM and speed
    fast: bool = True                 # stop at the end of the code, cap answer length
    max_output_tokens: int = 1800
    reflect: str = "smart"            # smart = only reflect when there's something to learn
    stuck_after: int = 2              # stop retrying when the same mistake repeats this often
    max_attempts: int = 4              # code attempts per task
    max_llm_calls: int = 300           # per command run
    max_tokens_per_run: int = 5_000_000
    sandbox_timeout: float = 15.0
    sandbox_memory_mb: int = 768

    @property
    def local(self) -> bool: return self.provider != "anthropic"
    @property
    def db_path(self) -> Path: return self.home / "cortex.db"
    @property
    def audit_path(self) -> Path: return self.home / "audit.jsonl"
    @property
    def stop_path(self) -> Path: return self.home / "STOP"
    @property
    def integrity_path(self) -> Path: return self.home / "integrity.json"
    @property
    def tasks_dir(self) -> Path: return self.home / "tasks"
    @property
    def settings_path(self) -> Path: return self.home / "settings.json"

    def save_settings(self, **values) -> None:
        cur = read_settings(self.home)
        cur.update(values)
        self.settings_path.write_text(json.dumps(cur, indent=2), encoding="utf-8")


def read_settings(home: Path) -> dict:
    p = Path(home) / "settings.json"
    try:
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}
    except json.JSONDecodeError:
        return {}


def load_config(home: str | Path | None = None, provider: str | None = None,
                model: str | None = None) -> Config:
    """Precedence: CLI flag > environment variable > settings.json > default."""
    home = Path(home or os.environ.get("CORTEX_HOME") or Path.cwd() / "cortex_data").resolve()
    home.mkdir(parents=True, exist_ok=True)
    (home / "tasks").mkdir(exist_ok=True)
    saved = read_settings(home)
    provider = (provider or os.environ.get("CORTEX_PROVIDER") or saved.get("provider")
                or ("anthropic" if os.environ.get("ANTHROPIC_API_KEY") else "ollama")).lower()
    if provider not in PROVIDERS:
        raise ValueError(f"unknown provider {provider!r}; use one of {', '.join(PROVIDERS)}")
    saved_model = saved.get("model") if saved.get("provider", provider) == provider else None
    model = model or os.environ.get("CORTEX_MODEL") or saved_model or DEFAULT_MODELS[provider]
    return Config(home=home, provider=provider, model=model,
                  ollama_url=os.environ.get("OLLAMA_URL", saved.get("ollama_url", "http://localhost:11434")),
                  openai_base_url=os.environ.get("OPENAI_BASE_URL",
                                                 saved.get("openai_base_url", "http://localhost:1234/v1")),
                  openai_api_key=os.environ.get("OPENAI_API_KEY") or None,
                  num_ctx=int(saved.get("num_ctx", 8192)),
                  fast=bool(saved.get("fast", True)),
                  max_output_tokens=int(saved.get("max_output_tokens", 1800)),
                  reflect=str(saved.get("reflect", "smart")))
