"""Learn from your Claude conversations - locally, with your approval.

Input: the export from claude.ai (Settings > Privacy > Export data), either the .zip or the
conversations.json inside it. Nothing is uploaded or published. Cortex keeps only:

* a topic profile: how many conversations touched each of its four areas (counts only), and
* task proposals: self-contained Python functions Claude wrote for you, each with a short
  description of what you asked for. You approve or dismiss each one before Cortex learns it.

When Cortex learns an approved proposal it writes its own tests, keeps only the tests your
original function passes (so wrong tests are thrown away), then solves the task itself. The
skill is stored as "reference-checked".
"""
from __future__ import annotations

import ast
import hashlib
import json
import re
import time
import zipfile
from pathlib import Path

from .sandbox import check_policy

KEYWORDS = {
    "cyber": ["security", "vulnerab", "firewall", "malware", "phishing", "exploit", "cve", "hack", "intrusion",
              "ioc", "encrypt", "vpn", "port scan", "threat intel", "brute force", "ransomware", "osint", "network"],
    "bigdata": ["csv", "dataset", "pandas", "aggregate", "rows", "big data", "excel", "spreadsheet", "sql",
                "dataframe", "etl", "export", "records", "switching", "analysis", "bills"],
    "threat": ["risk", "harm", "threat", "incident", "alert", "anomaly", "safety", "prioriti", "fault code",
               "dtc", "obd", "warning", "witness", "cctv"],
    "coding": ["python", "function", "script", "code", "bug", "error", "class ", "def ", "api", "app",
               "javascript", "html", "github"],
}
CODE_BLOCK = re.compile(r"```(?:python3?|py)[ \t]*\r?\n(.*?)```", re.S | re.I)


# --------------------------------------------------------------------- reading
def load_conversations(path: Path) -> list[dict]:
    path = Path(path)
    if path.suffix.lower() == ".zip":
        with zipfile.ZipFile(path) as z:
            names = [n for n in z.namelist() if n.lower().endswith("conversations.json")]
            if not names:
                raise ValueError("No conversations.json found in that export zip.")
            data = json.loads(z.read(names[0]).decode("utf-8"))
    else:
        data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        data = data.get("conversations", [])
    if not isinstance(data, list):
        raise ValueError("Unrecognised export format.")
    return [c for c in data if isinstance(c, dict)]


def message_text(m: dict) -> str:
    parts = []
    if isinstance(m.get("text"), str) and m["text"].strip():
        parts.append(m["text"])
    elif isinstance(m.get("content"), list):
        for c in m["content"]:
            if isinstance(c, dict) and isinstance(c.get("text"), str):
                parts.append(c["text"])
    return "\n".join(parts)


def messages(conv: dict) -> list[tuple[str, str]]:
    out = []
    for m in conv.get("chat_messages") or conv.get("messages") or []:
        if not isinstance(m, dict):
            continue
        sender = str(m.get("sender") or m.get("role") or "").lower()
        sender = "human" if sender in ("human", "user") else "assistant" if sender in ("assistant", "claude") else sender
        out.append((sender, message_text(m)))
    return out


def classify(text: str) -> str | None:
    t = text.lower()
    scores = {d: sum(t.count(k) for k in ks) for d, ks in KEYWORDS.items()}
    best = max(scores, key=lambda d: scores[d])
    return best if scores[best] >= 2 else None


# ------------------------------------------------------------------ proposals
def _functions(block: str):
    try:
        tree = ast.parse(block)
    except SyntaxError:
        return []
    out = []
    for node in tree.body:
        if (isinstance(node, ast.FunctionDef) and not node.name.startswith("_") and node.name != "main"
                and node.args.args):
            out.append(node)
    return out


def proposals_from(conv: dict, known: set[str]) -> list[dict]:
    msgs = messages(conv)
    human = "\n".join(t for s, t in msgs if s == "human")
    request = next((t for s, t in msgs if s == "human" and t.strip()), "").strip()
    out = []
    for sender, text in msgs:
        if sender != "assistant":
            continue
        for block in CODE_BLOCK.findall(text):
            if check_policy(block):          # uses files/network/OS - can't be learned in the sandbox
                continue
            for fn in _functions(block)[:3]:
                if fn.name in known:
                    continue
                known.add(fn.name)
                src = ast.get_source_segment(block, fn) or ""
                doc = ast.get_docstring(fn) or ""
                args = ", ".join(a.arg for a in fn.args.args)
                spec = (f"Write `{fn.name}({args})`. " + (doc.strip() + " " if doc else "")
                        + "Context - what was asked for: " + re.sub(r"\s+", " ", request)[:350])
                pid = hashlib.sha1(f"{conv.get('uuid', conv.get('name', ''))}:{fn.name}".encode()).hexdigest()[:12]
                out.append({"id": pid, "name": fn.name, "domain": classify(human + "\n" + src) or "coding",
                            "title": (conv.get("name") or "Claude conversation")[:80],
                            "date": str(conv.get("created_at") or "")[:10], "spec": spec[:900],
                            "reference_code": block, "status": "new"})
    return out


# ------------------------------------------------------------------- storage
def _paths(home: Path):
    home = Path(home)
    return home / "claude_profile.json", home / "proposals.json"


def load_proposals(home: Path) -> list[dict]:
    p = _paths(home)[1]
    try:
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else []
    except json.JSONDecodeError:
        return []


def save_proposals(home: Path, props: list[dict]) -> None:
    _paths(home)[1].write_text(json.dumps(props, indent=1), encoding="utf-8")


def load_profile(home: Path) -> dict:
    p = _paths(home)[0]
    try:
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}
    except json.JSONDecodeError:
        return {}


def import_export(home: Path, export_path: Path, skill_names: set[str] | None = None) -> dict:
    convs = load_conversations(export_path)
    by_domain = {d: 0 for d in KEYWORDS}
    for c in convs:
        d = classify("\n".join(t for s, t in messages(c) if s == "human"))
        if d:
            by_domain[d] += 1
    props = load_proposals(home)
    known = {p["name"] for p in props} | set(skill_names or ())
    new = []
    for c in convs:
        new += proposals_from(c, known)
    props = (props + new)[-300:]
    save_proposals(home, props)
    profile = {"imported_at": time.time(), "conversations": len(convs), "by_domain": by_domain}
    _paths(home)[0].write_text(json.dumps(profile, indent=1), encoding="utf-8")
    return {"conversations": len(convs), "by_domain": by_domain, "new_proposals": len(new),
            "total_proposals": len(props)}


def set_status(home: Path, ids: list[str] | str, status: str) -> int:
    props = load_proposals(home)
    n = 0
    for p in props:
        if ids == "all-new" and p["status"] == "new" or (isinstance(ids, list) and p["id"] in ids):
            p["status"] = status
            n += 1
    save_proposals(home, props)
    return n


def filter_tests_with_reference(tests: list[str], reference_code: str, timeout: float = 15.0) -> list[str]:
    """Keep only generated tests that the user's original function passes."""
    from .sandbox import run_tests
    r = run_tests(reference_code, tests, timeout=timeout)
    if r.load_error or r.policy or r.timed_out:
        return []
    return [x["test"] for x in r.results if x["passed"]]
