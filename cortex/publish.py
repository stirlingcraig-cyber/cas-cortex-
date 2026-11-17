"""Publish a snapshot of Cortex's progress to GitHub so the iPhone app can show it.

Only learning data is published: scores, skills (code), lessons, knowledge and a short
practice history. Alerts and log contents are NEVER published - they can contain IP
addresses and user names, and the repository is public.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path

from . import __version__
from .config import load_config
from .memory.store import Memory

APP_DIR = Path(__file__).resolve().parent.parent
STATUS_PATH = APP_DIR / "docs" / "data" / "status.json"


def build_status(home: Path) -> dict:
    cfg = load_config(home)
    mem = Memory(cfg.db_path, read_only=True)
    try:
        hist = mem.eval_history()
        runs: dict[str, dict] = {}
        for r in hist:
            d = runs.setdefault(r["run_id"], {"run": r["run_id"], "ts": r["ts"], "gen": r["generation"],
                                              "cells": {}, "_n": {}})
            k = f"{r['split']}/{r['domain']}"
            d["cells"][k] = round(r["score"], 4)
            d["_n"][k] = r["n"]
        out_runs = []
        for d in runs.values():
            def avg(prefix):
                pairs = [(v, d["_n"][k]) for k, v in d["cells"].items() if k.startswith(prefix)]
                tot = sum(n for _, n in pairs)
                return round(sum(v * n for v, n in pairs) / tot, 4) if tot else None
            d["train"], d["holdout"], d["overall"] = avg("train/"), avg("holdout/"), avg("")
            del d["_n"]
            out_runs.append(d)
        q = lambda sql, n=100: mem.db.execute(sql, (n,)).fetchall()
        return {
            "version": __version__,
            "published_at": int(time.time()),
            "provider": cfg.provider,
            "model": cfg.model,
            "stats": mem.stats(),
            "runs": out_runs,
            "skills": [{"name": s.name, "domain": s.domain, "trust": s.trust, "version": s.version,
                        "successes": s.successes, "uses": s.uses, "description": s.description,
                        "code": s.code, "tests": s.tests} for s in mem.all_skills()],
            "lessons": [{"domain": r["domain"], "text": r["text"], "uses": r["uses"]}
                        for r in q("SELECT domain, text, uses FROM lessons ORDER BY uses DESC, id DESC LIMIT ?")],
            "knowledge": [[r["subject"], r["relation"], r["object"]]
                          for r in q("SELECT subject, relation, object FROM triples ORDER BY ts DESC LIMIT ?")],
            "focus": _focus(home),
            "feedback": _feedback(home),
            "recent_episodes": [{"ts": r["ts"], "task": r["task_id"], "mode": r["mode"], "solved": bool(r["solved"]),
                                 "attempts": r["attempts"]}
                                for r in q("SELECT ts, task_id, mode, solved, attempts FROM episodes ORDER BY id DESC LIMIT ?", 30)],
        }
    finally:
        mem.close()


def _focus(home):
    from .autopilot import focus
    return focus(home)


def _feedback(home):
    """Kind-level counts and record ids only - never IPs, device names or VINs."""
    from . import feedback
    recs = feedback.load(home)
    return {"kinds": feedback.kind_summary(recs), "ids": [r["id"] for r in recs if r.get("id")][-2000:]}


def write_status(home: Path, path: Path = STATUS_PATH) -> Path:
    data = build_status(home)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=1), encoding="utf-8")
    return path


def _git(*args, cwd=APP_DIR, check=True) -> subprocess.CompletedProcess:
    kw = {}
    if os.name == "nt":
        kw["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    p = subprocess.run(["git", *args], cwd=str(cwd), capture_output=True, text=True,
                       encoding="utf-8", errors="replace", **kw)
    if check and p.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed:\n{(p.stderr or p.stdout).strip()[-800:]}")
    return p


def git_ready(cwd: Path = APP_DIR) -> str | None:
    """Return None if publishing can work, else a plain-English reason."""
    if not shutil.which("git"):
        return "Git isn't installed. Run connect_github.bat in the cas-cortex folder (one-off)."
    if _git("rev-parse", "--is-inside-work-tree", cwd=cwd, check=False).returncode != 0:
        return "This folder isn't connected to GitHub yet. Run connect_github.bat in the cas-cortex folder (one-off)."
    if not _git("remote", "get-url", "origin", cwd=cwd, check=False).stdout.strip():
        return "No GitHub repository is set. Run connect_github.bat in the cas-cortex folder (one-off)."
    return None


def publish(home: Path, push: bool = True, out=print, cwd: Path = APP_DIR) -> bool:
    path = write_status(home, cwd / "docs" / "data" / "status.json")
    data = json.loads(path.read_text(encoding="utf-8"))
    out(f"Snapshot written: generation {data['stats']['generation']}, {len(data['skills'])} skills, "
        f"{len(data['runs'])} evaluation(s). No alerts or logs included.")
    if not push:
        return True
    why = git_ready(cwd)
    if why:
        out(why)
        return False
    rel = str(path.relative_to(cwd)).replace("\\", "/")
    _git("add", rel, cwd=cwd)
    if not _git("diff", "--cached", "--quiet", cwd=cwd, check=False).returncode:
        out("Nothing new to publish - the iPhone already has the latest.")
        return True
    _git("-c", "user.name=CAS Cortex", "-c", "user.email=cortex@users.noreply.github.com",
         "commit", "-m", f"Publish Cortex progress (generation {data['stats']['generation']})", "--", rel, cwd=cwd)
    out("Uploading to GitHub...")
    p = _git("push", "origin", "HEAD:main", cwd=cwd, check=False)
    if p.returncode != 0:
        out("GitHub has newer changes - syncing first...")
        _git("pull", "--rebase", "--autostash", "origin", "main", cwd=cwd)
        _git("push", "origin", "HEAD:main", cwd=cwd)
    url = _git("remote", "get-url", "origin", cwd=cwd).stdout.strip()
    owner_repo = url.rstrip("/").removesuffix(".git").split("github.com")[-1].strip(":/")
    if "/" in owner_repo:
        owner, repo = owner_repo.split("/", 1)
        out(f"Published. On your iPhone open https://{owner.lower()}.github.io/{repo}/ and tap Refresh from PC "
            "(GitHub can take about a minute to update).")
    else:
        out("Published.")
    return True
