"""Continuous learning: what you focus on, and a nightly autopilot that acts on it.

Focus profile - where your attention goes, from:
  * what you use Cortex for on the PC and iPhone (usage counters, no content),
  * the alerts you give feedback on,
  * the topics of your Claude conversations (counts only, if you imported an export).

Autopilot (run by a Windows scheduled task, or "Run now"):
  1. import iPhone feedback files from iCloud Drive / OneDrive / Downloads
  2. learn up to 3 Claude-history proposals you approved
  3. train the 2 areas you focus on most for up to N hours (all areas once a week),
     stopping early once everything is mastered or no progress is being made
  4. evaluate weekly (holdout = honest measure)
  5. publish to the iPhone app, if connected to GitHub
Every step respects the kill switch and budgets; everything is logged to autopilot.log.
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

from . import claude_history, feedback
from .evaluator.taskbank import DOMAINS

SOURCE_DOMAINS = {
    "monitor:obd": {"threat": 1.0}, "monitor:homenet": {"cyber": 0.6, "threat": 0.4},
    "monitor:logs": {"cyber": 0.5, "threat": 0.5}, "monitor:other": {"threat": 0.5},
    "obd_test_report": {"threat": 1.0}, "obd_health": {"threat": 1.0}, "obd_data_log": {"threat": 0.5, "bigdata": 0.5},
    "obd_codes": {"threat": 1.0}, "monitor": {"threat": 0.5, "cyber": 0.5},
}
VEHICLE_KINDS = {"airbag", "brakes", "overheating", "misfire", "stall_risk", "fuel_pressure", "boost", "charging",
                 "transmission", "speed_sensor", "dpf", "fuel_trim", "cooling", "emissions", "network", "engine",
                 "body", "battery", "oil_overheat", "charging_trend", "fuel_trim_trend", "sensor_jump",
                 "vehicle_test_fail", "vehicle_test_check"}


def _usage(home: Path) -> dict:
    p = Path(home) / "usage.json"
    try:
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}
    except json.JSONDecodeError:
        return {}


def add_phone_usage(home: Path, usage: dict) -> None:
    """Merge iPhone usage counters (keeps the latest totals per key)."""
    p = Path(home) / "usage.json"
    d = _usage(home)
    for k, v in (usage or {}).items():
        if isinstance(v, (int, float)):
            d[f"iphone:{k}"] = max(d.get(f"iphone:{k}", 0), int(v))
    p.write_text(json.dumps(d, indent=1), encoding="utf-8")


def focus(home: Path) -> dict:
    w = {d: 0.0 for d in DOMAINS}
    for key, n in _usage(home).items():
        k = key.split(":", 1)[1] if key.startswith("iphone:") else key
        if k.startswith(("train:", "learn:")):
            d = k.split(":", 1)[1]
            if d in w:
                w[d] += n * (1.0 if k.startswith("learn:") else 0.5)
        for d, share in SOURCE_DOMAINS.get(k, {}).items():
            w[d] += n * share
    for r in feedback.load(home):
        w["threat"] += 0.5
        w["threat" if r.get("kind") in VEHICLE_KINDS else "cyber"] += 0.5
    for d, n in claude_history.load_profile(home).get("by_domain", {}).items():
        if d in w:
            w[d] += n
    total = sum(w.values())
    weights = {d: round(v / total, 3) for d, v in w.items()} if total else {}
    ranked = [d for d, v in sorted(w.items(), key=lambda kv: -kv[1]) if v > 0]
    return {"weights": weights, "next_training": ranked[:2] or list(DOMAINS)}


# ------------------------------------------------------------------- autopilot
def inbox_folders() -> list[Path]:
    h = Path.home()
    return [p for p in (h / "iCloudDrive" / "CAS Cortex", h / "iCloudDrive", h / "OneDrive" / "CAS Cortex",
                        h / "OneDrive", h / "Downloads") if p.exists()]


def import_inbox(home: Path, folders: list[Path] | None = None, log=print) -> int:
    total = 0
    for folder in folders if folders is not None else inbox_folders():
        for f in sorted(Path(folder).glob("cortex-feedback-*.json")):
            try:
                n, usage = feedback.import_file(home, f)
                add_phone_usage(home, usage)
                total += n
                if n:
                    log(f"  imported {n} feedback item(s) from {f.name}")
            except (ValueError, json.JSONDecodeError, OSError) as e:
                log(f"  skipped {f.name}: {e}")
    return total


def _state(home: Path) -> dict:
    p = Path(home) / "autopilot_state.json"
    try:
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}
    except json.JSONDecodeError:
        return {}


def _save_state(home: Path, st: dict) -> None:
    (Path(home) / "autopilot_state.json").write_text(json.dumps(st, indent=1), encoding="utf-8")


def run(home: Path, model_ready, cli_args: list[str], log=print, max_proposals: int = 3,
        rounds: int = 1, now: float | None = None, runner=None, hours: float = 2.0) -> dict:
    """One autopilot pass. `runner(args) -> returncode` runs a cortex command (default: subprocess)."""
    now = now or time.time()
    home = Path(home)
    st = _state(home)
    runner = runner or (lambda args: subprocess.run([sys.executable, "-m", "cortex", *cli_args, *args]).returncode)
    report = {"started": now, "feedback_imported": 0, "learned": [], "trained": [], "evaluated": False,
              "published": False}
    log("== CAS Cortex autopilot ==")
    report["feedback_imported"] = import_inbox(home, log=log)
    ready = model_ready()
    if not ready:
        log("  AI model not available (is Ollama running?) - skipping learning and training tonight.")
    else:
        approved = [p for p in claude_history.load_proposals(home) if p["status"] == "approved"][:max_proposals]
        for p in approved:
            log(f"  learning '{p['name']}' from your Claude history")
            rc = runner(["learn-proposal", p["id"]])
            claude_history.set_status(home, [p["id"]], "learned" if rc == 0 else "failed")
            report["learned"].append((p["name"], rc == 0))
        weekly = now - st.get("last_full_train", 0) > 6.5 * 86400
        areas = list(DOMAINS) if weekly else focus(home)["next_training"]
        log(f"  training for up to {hours:g} h: {', '.join(areas)} (stops early when mastered or stuck)")
        if runner(["train", "--hours", f"{hours:g}", "--max-calls", str(int(150 * hours) + 50),
                   "--domain", *areas]) == 0:
            report["trained"] = list(areas)
        if weekly:
            st["last_full_train"] = now
        if now - st.get("last_eval", 0) > 6.5 * 86400:
            log("  weekly evaluation (holdout)")
            report["evaluated"] = runner(["eval", "--split", "holdout"]) == 0
            if report["evaluated"]:
                st["last_eval"] = now
    from .publish import git_ready
    if git_ready() is None:
        report["published"] = runner(["publish"]) == 0
    st["last_run"] = now
    st["last_report"] = report
    _save_state(home, st)
    log(f"== done: {len(report['trained'])} area(s) trained, {len(report['learned'])} proposal(s) learned, "
        f"{report['feedback_imported']} feedback item(s) imported ==")
    return report
