"""Non-visual logic for the desktop app: running Cortex commands in the background,
reading memory for display, and validating custom tasks. Kept separate from the
window code so it can be tested without a screen."""
from __future__ import annotations

import ast
import json
import os
import queue
import subprocess
import sys
import threading
import urllib.request
from pathlib import Path

from .config import load_config
from .evaluator.taskbank import DOMAINS, all_tasks
from .memory.store import Memory

APP_DIR = Path(__file__).resolve().parent.parent


def console_python() -> str:
    """Use python.exe (not pythonw.exe) for child processes so output can be captured."""
    exe = Path(sys.executable)
    if exe.name.lower() == "pythonw.exe":
        alt = exe.with_name("python.exe")
        if alt.exists():
            return str(alt)
    return str(exe)


class Job:
    """Runs `python -m cortex ...` in the background and streams its output.

    Events put on `events`: ("line", key, text), ("cr", key, text) for progress lines
    that should overwrite the previous one, and ("done", key, returncode)."""

    def __init__(self, key: str, args: list[str], home: Path, events: queue.Queue,
                 extra_env: dict | None = None):
        self.key, self.events = key, events
        cmd = [console_python(), "-u", "-m", "cortex", "--home", str(home)] + args
        env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUNBUFFERED="1", **(extra_env or {}))
        kw = dict(cwd=str(APP_DIR), env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                  stdin=subprocess.DEVNULL, bufsize=0)
        if os.name == "nt":
            kw["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        else:
            kw["start_new_session"] = True  # own process group, so stop() can end the whole tree
        self.proc = subprocess.Popen(cmd, **kw)
        self.stopped = False
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self):
        buf = ""
        dec = __import__("codecs").getincrementaldecoder("utf-8")("replace")
        while True:
            chunk = self.proc.stdout.read(1024)
            if not chunk:
                break
            buf += dec.decode(chunk)
            while True:
                i_n, i_r = buf.find("\n"), buf.find("\r")
                idx = min(i for i in (i_n, i_r) if i != -1) if (i_n != -1 or i_r != -1) else -1
                if idx == -1:
                    break
                seg, sep = buf[:idx], buf[idx]
                if sep == "\r" and buf[idx + 1:idx + 2] == "\n":
                    buf = buf[idx + 2:]
                    sep = "\n"
                else:
                    buf = buf[idx + 1:]
                self.events.put(("line" if sep == "\n" else "cr", self.key, seg))
        tail = buf + dec.decode(b"", final=True)
        if tail:
            self.events.put(("line", self.key, tail))
        rc = self.proc.wait()
        self.events.put(("done", self.key, rc))

    def running(self) -> bool:
        return self.proc.poll() is None

    def stop(self):
        """End the job AND everything it started. On Windows a venv's python.exe is a
        launcher that runs the real interpreter as a child process, and training also
        starts sandbox processes - terminating only the top process leaves them running."""
        if not self.running():
            return
        self.stopped = True
        pid = self.proc.pid
        try:
            if os.name == "nt":
                subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True,
                               creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0), timeout=15)
            else:
                import signal
                os.killpg(os.getpgid(pid), signal.SIGTERM)
        except Exception:
            pass
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()


# --------------------------------------------------------------------- data
def ollama_state(url: str, model: str) -> tuple[bool, bool]:
    """(ollama reachable, model installed)."""
    try:
        with urllib.request.urlopen(url.rstrip("/") + "/api/tags", timeout=3) as r:
            names = [m["name"] for m in json.loads(r.read()).get("models", [])]
        want = model if ":" in model else model + ":latest"
        return True, any(n in (model, want) for n in names)
    except Exception:
        return False, False


def snapshot(home: Path) -> dict:
    """Everything the Home tab needs, in one read."""
    cfg = load_config(home)
    mem = Memory(cfg.db_path, read_only=True)
    try:
        s = mem.stats()
        hist = mem.eval_history()
        latest = None
        if hist:
            last_run = hist[-1]["run_id"]
            vals = [r["score"] for r in hist if r["run_id"] == last_run]
            latest = sum(vals) / len(vals)
        s.update({
            "provider": cfg.provider, "model": cfg.model,
            "kill_switch": cfg.stop_path.exists(),
            "latest_score": latest,
            "trained_eval": any(r["generation"] >= 1 for r in hist),
            "custom_tasks": len(list(cfg.tasks_dir.glob("*.json"))),
            "self_tested": sum(1 for k in mem.all_skills() if k.trust == "self-tested"),
            "alerts_file": (cfg.home / "alerts.jsonl").exists(),
        })
        return s
    finally:
        mem.close()


def journey(s: dict, setup_ok: bool) -> list[dict]:
    """The 8 steps of the user guide, with done/not-done state and target tab."""
    steps = [
        ("Set up your local AI model", "Install Ollama and download a model (one-off).", "Setup", setup_ok),
        ("Try a first task", "Watch Cortex attempt, test and fix a solution.", "Train", s["episodes"] > 0),
        ("Take a baseline score", "Measure Cortex before it has learned anything.", "Progress", s["eval_runs"] > 0),
        ("Train it", "Let it practise and build skills and lessons.", "Train", s["generation"] >= 1),
        ("Measure progress", "Score again and compare on the learning curve.", "Progress", s["trained_eval"]),
        ("Explore what it knows", "Browse skills, lessons and its knowledge graph.", "Skills & Memory", s["skills"] > 0),
        ("Teach it something new", "Describe a new ability or add your own tasks.", "Teach",
         s["custom_tasks"] > 0 or s["self_tested"] > 0),
        ("Monitor threats live", "Watch logs for attacks and prioritised risks.", "Threat Monitor", s["alerts_file"]),
    ]
    return [{"title": t, "detail": d, "tab": tab, "done": bool(done)} for t, d, tab, done in steps]


def skills_rows(home: Path):
    cfg = load_config(home)
    mem = Memory(cfg.db_path, read_only=True)
    try:
        return mem.all_skills()
    finally:
        mem.close()


def memory_rows(home: Path, n: int = 200) -> dict:
    cfg = load_config(home)
    mem = Memory(cfg.db_path, read_only=True)
    try:
        q = lambda sql: [tuple(r) for r in mem.db.execute(sql, (n,)).fetchall()]
        return {
            "lessons": q("SELECT domain, uses, text FROM lessons ORDER BY id DESC LIMIT ?"),
            "knowledge": q("SELECT subject, relation, object, source FROM triples ORDER BY ts DESC LIMIT ?"),
            "episodes": q("""SELECT datetime(ts, 'unixepoch', 'localtime'), task_id, mode,
                             CASE solved WHEN 1 THEN 'solved' ELSE 'failed' END, attempts, tokens
                             FROM episodes ORDER BY id DESC LIMIT ?"""),
        }
    finally:
        mem.close()


def progress_rows(home: Path) -> tuple[list[str], list[dict]]:
    """Columns and one row per evaluation run (for the table and chart)."""
    cfg = load_config(home)
    mem = Memory(cfg.db_path, read_only=True)
    try:
        hist = mem.eval_history()
    finally:
        mem.close()
    runs: dict[str, dict] = {}
    for r in hist:
        d = runs.setdefault(r["run_id"], {"run": r["run_id"], "gen": r["generation"], "ts": r["ts"],
                                          "cells": {}, "n": {}})
        key = f"{r['split']}/{r['domain']}"
        d["cells"][key] = r["score"]
        d["n"][key] = r["n"]
    cols = sorted({c for d in runs.values() for c in d["cells"]})
    out = []
    for d in runs.values():
        def avg(prefix):
            pairs = [(v, d["n"][k]) for k, v in d["cells"].items() if k.startswith(prefix)]
            tot = sum(n for _, n in pairs)
            return sum(v * n for v, n in pairs) / tot if tot else None
        d["train"], d["holdout"], d["overall"] = avg("train/"), avg("holdout/"), avg("")
        out.append(d)
    return cols, out


def task_ids(home: Path) -> list[str]:
    cfg = load_config(home)
    return [t.id for t in all_tasks(cfg.tasks_dir)]


def audit_rows(home: Path, n: int = 300) -> list[tuple]:
    cfg = load_config(home)
    if not cfg.audit_path.exists():
        return []
    lines = cfg.audit_path.read_text(encoding="utf-8").splitlines()[-n:]
    from datetime import datetime
    rows = []
    for line in reversed(lines):
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        detail = ", ".join(f"{k}={v}" for k, v in r.get("data", {}).items())
        rows.append((datetime.fromtimestamp(r["ts"]).strftime("%Y-%m-%d %H:%M:%S"), r["event"], detail[:200]))
    return rows


# --------------------------------------------------------------- teach/tasks
def split_tests(text: str) -> list[str]:
    """Tests are separated by blank lines; a single test may span several lines."""
    blocks, cur = [], []
    for line in text.replace("\r\n", "\n").split("\n"):
        if line.strip():
            cur.append(line.rstrip())
        elif cur:
            blocks.append("\n".join(cur)); cur = []
    if cur:
        blocks.append("\n".join(cur))
    return blocks


def validate_task(d: dict, existing_ids: list[str]) -> list[str]:
    errs = []
    tid = d.get("id", "").strip()
    if not tid or " " in tid:
        errs.append("Task ID is required and must not contain spaces (e.g. cyber.jwt_expiry).")
    elif tid in existing_ids:
        errs.append(f"Task ID '{tid}' already exists.")
    if d.get("domain") not in DOMAINS:
        errs.append("Choose a domain.")
    if d.get("split") not in ("train", "holdout"):
        errs.append("Choose train or holdout.")
    if not d.get("title", "").strip():
        errs.append("Title is required.")
    ep = d.get("entry_point", "").strip()
    if not ep.isidentifier():
        errs.append("Function/class name must be a valid Python name (e.g. jwt_expired).")
    if len(d.get("prompt", "").strip()) < 15:
        errs.append("Write a fuller specification (what goes in, what comes out, edge cases).")
    for label, key in (("Example", "visible_tests"), ("Hidden", "hidden_tests")):
        tests = d.get(key) or []
        if not tests:
            errs.append(f"Add at least one {label.lower()} test.")
        for i, t in enumerate(tests, 1):
            try:
                ast.parse(t)
            except SyntaxError as e:
                errs.append(f"{label} test {i} is not valid Python: {e.msg} (line {e.lineno}).")
            if ep and ep not in t:
                errs.append(f"{label} test {i} doesn't use {ep}.")
    return errs


def save_task(home: Path, d: dict) -> Path:
    cfg = load_config(home)
    errs = validate_task(d, [t.id for t in all_tasks(cfg.tasks_dir)])
    if errs:
        raise ValueError("\n".join(errs))
    p = cfg.tasks_dir / (d["id"].replace(".", "_") + ".json")
    p.write_text(json.dumps(d, indent=2), encoding="utf-8")
    return p


def custom_tasks(home: Path) -> list[tuple[str, str, str, str]]:
    cfg = load_config(home)
    out = []
    for p in sorted(cfg.tasks_dir.glob("*.json")):
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
            for t in (d if isinstance(d, list) else [d]):
                out.append((t.get("id", "?"), t.get("domain", "?"), t.get("split", "train"), p.name))
        except Exception:
            out.append(("(unreadable)", "", "", p.name))
    return out


def open_path(path: Path):
    path = Path(path)
    if os.name == "nt":
        os.startfile(str(path))  # noqa: S606 - opening the user's own files
    elif sys.platform == "darwin":
        subprocess.Popen(["open", str(path)])
    else:
        subprocess.Popen(["xdg-open", str(path)])
