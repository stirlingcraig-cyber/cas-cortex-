"""Learning from how you respond to alerts.

Every alert can be marked "useful", "false_alarm" or "acted" (you did something about it),
on the PC or the iPhone. Cortex turns that into small, explainable priority adjustments:

* An alert type for one device/vehicle that you have called a false alarm 3+ times (and more
  often than useful) is lowered one level. Safety-critical types never go below P2.
* An alert type you have acted on 2+ times (at least as often as false alarms) is raised one level.

Adjustments are visible (each alert says why it moved), reversible (reset the feedback) and
never touch the risk score itself. docs/engine.js holds the identical JavaScript port.
"""
from __future__ import annotations

import json
import time
import uuid
from pathlib import Path

VERDICTS = ("useful", "false_alarm", "acted")
SAFETY_KINDS = {"airbag", "brakes", "overheating", "malicious_server", "multi_signal_device", "worm_scanning",
                "bruteforce_then_success", "data_exfiltration"}
LOWER_AFTER, RAISE_AFTER = 3, 2


def summarise(records: list[dict]) -> dict:
    """{"kind|entity": counts, "kind": counts} with counts {"useful", "false_alarm", "acted"}."""
    out: dict[str, dict] = {}
    for r in records:
        v = r.get("verdict")
        if v not in VERDICTS or not r.get("kind"):
            continue
        for key in (f"{r['kind']}|{r.get('entity', '')}", r["kind"]):
            c = out.setdefault(key, {"useful": 0, "false_alarm": 0, "acted": 0})
            c[v] += 1
    return out


def adjust(priority: str, kind: str, entity: str, summary: dict) -> tuple[str, str]:
    """Return (new_priority, explanation or "")."""
    if not summary:
        return priority, ""
    z = {"useful": 0, "false_alarm": 0, "acted": 0}
    ke = summary.get(f"{kind}|{entity}", z)
    k = summary.get(kind, z)
    level = int(priority[1])
    if ke["false_alarm"] >= LOWER_AFTER and ke["false_alarm"] > ke["useful"] + ke["acted"]:
        floor = 2 if kind in SAFETY_KINDS else 4
        new = level if level >= floor else min(level + 1, floor)
        if new != level:
            return f"P{new}", f"lowered from P{level}: you marked {ke['false_alarm']} similar alerts as false alarms"
        return priority, ""
    if k["acted"] >= RAISE_AFTER and k["acted"] >= k["false_alarm"] and level > 1:
        return f"P{level - 1}", f"raised from P{level}: you acted on {k['acted']} alerts like this"
    return priority, ""


# ------------------------------------------------------------------- storage
def path(home: Path) -> Path:
    return Path(home) / "feedback.jsonl"


def load(home: Path) -> list[dict]:
    p = path(home)
    if not p.exists():
        return []
    out = []
    for line in p.read_text(encoding="utf-8").splitlines():
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(r, dict) and r.get("verdict") in VERDICTS:
            out.append(r)
    return out


def add(home: Path, kind: str, entity: str, verdict: str, source: str = "pc") -> dict:
    if verdict not in VERDICTS:
        raise ValueError(verdict)
    r = {"id": uuid.uuid4().hex, "ts": round(time.time(), 3), "kind": kind, "entity": entity,
         "verdict": verdict, "source": source}
    with path(home).open("a", encoding="utf-8") as f:
        f.write(json.dumps(r) + "\n")
    return r


def import_file(home: Path, file: Path) -> tuple[int, dict]:
    """Import an iPhone feedback export. Returns (new records, phone usage counters)."""
    d = json.loads(Path(file).read_text(encoding="utf-8"))
    if not isinstance(d, dict) or d.get("type") != "cas-cortex-feedback":
        raise ValueError("That isn't a CAS Cortex feedback file (export it from the iPhone app's Monitor tab).")
    have = {r.get("id") for r in load(home)}
    new = [r for r in d.get("feedback", []) if isinstance(r, dict) and r.get("id") not in have
           and r.get("verdict") in VERDICTS and r.get("kind")]
    with path(home).open("a", encoding="utf-8") as f:
        for r in new:
            r = {k: r[k] for k in ("id", "ts", "kind", "entity", "verdict") if k in r}
            r["source"] = "iphone"
            f.write(json.dumps(r) + "\n")
    return len(new), d.get("usage", {}) if isinstance(d.get("usage"), dict) else {}


def reset(home: Path) -> None:
    p = path(home)
    if p.exists():
        p.replace(p.with_suffix(".jsonl.bak"))


def kind_summary(records: list[dict]) -> dict:
    """Kind-level counts only (safe to publish: no IPs, device names or VINs)."""
    return {k: v for k, v in summarise(records).items() if "|" not in k}


def describe(summary: dict) -> list[str]:
    """Plain-English list of what has been learned (for the desktop app and command line)."""
    lines = []
    for key in sorted(summary):
        if "|" in key:
            kind, ent = key.split("|", 1)
            if adjust("P1", kind, ent, {key: summary[key]})[1] or adjust("P3", kind, ent, {key: summary[key]})[1]:
                n = summary[key]["false_alarm"]
                lines.append(f"{kind} on {ent or '(unnamed)'}: lowered one level ({n} false alarms)")
        else:
            c = summary[key]
            if c["acted"] >= RAISE_AFTER and c["acted"] >= c["false_alarm"]:
                lines.append(f"all {key} alerts: raised one level (you acted on {c['acted']})")
    return lines
