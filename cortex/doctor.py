"""`cortex doctor`: checks your PC, picks a local model that fits, and can download it."""
from __future__ import annotations

import json
import os
import platform
import shutil
import sys
import urllib.error
import urllib.request

# (minimum RAM in GB, model, approx download) - best first. Qwen2.5-Coder is strong at
# Python for its size and runs on CPU; a GPU just makes it faster.
MODEL_LADDER = [
    (30, "qwen2.5-coder:14b", "9 GB"),
    (14, "qwen2.5-coder:7b", "4.7 GB"),
    (7, "qwen2.5-coder:3b", "1.9 GB"),
    (0, "qwen2.5-coder:1.5b", "1 GB"),
]


def total_ram_gb() -> float | None:
    try:
        if os.name == "nt":
            import ctypes

            class MEM(ctypes.Structure):
                _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                            ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                            ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                            ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                            ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]
            m = MEM()
            m.dwLength = ctypes.sizeof(MEM)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m))
            return m.ullTotalPhys / 1024 ** 3
        return os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") / 1024 ** 3
    except Exception:
        return None


def recommend_model(ram_gb: float | None) -> tuple[str, str]:
    if ram_gb is None:
        return MODEL_LADDER[1][1], MODEL_LADDER[1][2]
    for need, model, size in MODEL_LADDER:
        if ram_gb >= need:
            return model, size
    return MODEL_LADDER[-1][1], MODEL_LADDER[-1][2]


def ollama_models(url: str) -> list[str] | None:
    """Installed model names, or None if Ollama isn't reachable."""
    try:
        with urllib.request.urlopen(url.rstrip("/") + "/api/tags", timeout=5) as r:
            return [m["name"] for m in json.loads(r.read()).get("models", [])]
    except (urllib.error.URLError, ConnectionError, TimeoutError, ValueError):
        return None


def has_model(installed: list[str], model: str) -> bool:
    want = model if ":" in model else model + ":latest"
    return any(m == want or m == model for m in installed)


def pull_model(url: str, model: str, out=print) -> bool:
    req = urllib.request.Request(url.rstrip("/") + "/api/pull",
                                 data=json.dumps({"model": model, "stream": True}).encode(),
                                 headers={"Content-Type": "application/json"})
    last = ""
    try:
        with urllib.request.urlopen(req, timeout=7200) as r:
            for line in r:
                d = json.loads(line or b"{}")
                if "error" in d:
                    out(f"  error: {d['error']}")
                    return False
                status = d.get("status", "")
                if d.get("total"):
                    pct = 100 * d.get("completed", 0) / d["total"]
                    msg = f"  {status} {pct:5.1f}%"
                else:
                    msg = f"  {status}"
                if msg != last:
                    sys.stdout.write("\r" + msg.ljust(60))
                    sys.stdout.flush()
                    last = msg
        out("")
        return True
    except (urllib.error.URLError, ConnectionError) as e:
        out(f"  could not reach Ollama: {e}")
        return False


def run_doctor(cfg, pull: bool = False, out=print) -> bool:
    ok = True
    ram = total_ram_gb()
    rec, size = recommend_model(ram)
    out(f"Python      {platform.python_version()} ({'ok' if sys.version_info >= (3, 10) else 'need 3.10+'})")
    out(f"System      {platform.system()} {platform.release()}, RAM "
        f"{f'{ram:.0f} GB' if ram else 'unknown'}")
    out(f"Provider    {cfg.provider}   model: {cfg.model}")
    if cfg.provider == "anthropic":
        out("            (cloud API - needs ANTHROPIC_API_KEY)")
        return bool(os.environ.get("ANTHROPIC_API_KEY"))
    if cfg.provider == "openai":
        try:
            with urllib.request.urlopen(cfg.openai_base_url.rstrip("/") + "/models", timeout=5) as r:
                names = [m.get("id") for m in json.loads(r.read()).get("data", [])]
            out(f"Server      reachable at {cfg.openai_base_url}; models: {', '.join(names) or 'none loaded'}")
            return bool(names)
        except Exception:
            out(f"Server      NOT reachable at {cfg.openai_base_url} - start LM Studio's local server")
            return False

    # ollama
    exe = shutil.which("ollama")
    out(f"Ollama app  {'installed' if exe else 'not found on PATH'}")
    installed = ollama_models(cfg.ollama_url)
    if installed is None:
        out(f"Ollama API  NOT reachable at {cfg.ollama_url}")
        out("")
        if not exe:
            out("Install it (free) in PowerShell:   winget install --id Ollama.Ollama -e")
            out("or download from https://ollama.com/download, then open the Ollama app.")
        else:
            out("Start the Ollama app from the Start menu (or run `ollama serve`).")
        return False
    out(f"Ollama API  running; models installed: {', '.join(installed) or 'none'}")

    if cfg.model == "qwen2.5-coder:7b" and rec != cfg.model and not os.environ.get("CORTEX_MODEL"):
        out(f"Suggested   {rec} suits {f'{ram:.0f} GB' if ram else 'your'} RAM better - using it")
        cfg.model = rec
        cfg.save_settings(provider="ollama", model=rec)
    if not has_model(installed, cfg.model):
        if pull:
            out(f"Downloading {cfg.model} (~{size if cfg.model == rec else 'several GB'}) - one-off...")
            if not pull_model(cfg.ollama_url, cfg.model, out):
                return False
        else:
            out(f"Model       {cfg.model} not downloaded yet. Run:  python -m cortex doctor --pull")
            ok = False
    else:
        out(f"Model       {cfg.model} ready")
    if ok:
        cfg.save_settings(provider="ollama", model=cfg.model)
        out("\nAll set - no API key needed. Try:  python -m cortex solve coding.merge_intervals --show")
    return ok
