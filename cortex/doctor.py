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


def speed_test(cfg, out=print) -> dict | None:
    """Measure how fast the local model really is on this PC, and whether it uses the GPU."""
    if cfg.provider != "ollama":
        out("Speed test is for Ollama models.")
        return None
    base = cfg.ollama_url.rstrip("/")
    body = {"model": cfg.model, "stream": False, "keep_alive": "30m",
            "prompt": "Write a short Python function that returns the reverse of a string. Code only.",
            "options": {"num_predict": 120, "temperature": 0, "num_ctx": cfg.num_ctx}}
    req = urllib.request.Request(base + "/api/generate", data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    out(f"Testing {cfg.model} (first run also loads it into memory)...")
    try:
        with urllib.request.urlopen(req, timeout=600) as r:
            d = json.loads(r.read())
        with urllib.request.urlopen(base + "/api/ps", timeout=10) as r:
            ps = json.loads(r.read()).get("models", [])
    except (urllib.error.URLError, ConnectionError, TimeoutError) as e:
        out(f"Couldn't reach Ollama: {e}")
        return None
    gen_tps = d.get("eval_count", 0) / max(d.get("eval_duration", 1) / 1e9, 1e-6)
    prm_tps = d.get("prompt_eval_count", 0) / max(d.get("prompt_eval_duration", 1) / 1e9, 1e-6)
    m = next((x for x in ps if x.get("name", "").startswith(cfg.model.split(":")[0])), ps[0] if ps else {})
    gpu = (m.get("size_vram", 0) / m["size"]) if m.get("size") else 0.0
    per_attempt = 350 / max(gen_tps, 0.1) + 2000 / max(prm_tps, 0.1)
    res = {"gen_tps": round(gen_tps, 1), "prompt_tps": round(prm_tps, 1), "gpu_share": round(gpu, 2),
           "seconds_per_attempt": round(per_attempt)}
    out(f"Writing speed : {gen_tps:.1f} tokens/s")
    out(f"Reading speed : {prm_tps:.0f} tokens/s")
    out(f"Runs on       : {'GPU' if gpu > 0.9 else 'partly GPU (%d%%)' % (gpu * 100) if gpu > 0 else 'CPU only'}")
    out(f"Estimate      : about {per_attempt:.0f} s per attempt")
    if gpu == 0:
        out("Tip: no GPU is being used. If this PC has an NVIDIA or AMD graphics card, update its driver "
            "and restart Ollama - it can be 5-10x faster.")
    if gen_tps < 6:
        smaller = "qwen2.5-coder:3b" if "7b" in cfg.model or "14b" in cfg.model else "qwen2.5-coder:1.5b"
        out(f"Tip: this is slow for training. {smaller} is roughly 2x faster (Setup > Model choice), "
            "at some cost in accuracy.")
    return res
