"""Persistent memory: episodic (experiences), semantic (lessons + knowledge graph),
procedural (verified skill library). One SQLite file, safe to copy/back up.

`read_only=True` turns every write into a no-op - used for holdout evaluation so
measuring the agent never changes it.
"""
from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

from .retrieval import bm25_rank, tokenize

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS episodes(
    id INTEGER PRIMARY KEY, ts REAL, task_id TEXT, domain TEXT, mode TEXT,
    attempts INTEGER, solved INTEGER, visible_pass REAL, code TEXT, reflection TEXT,
    skills_used TEXT, tokens INTEGER, duration REAL);
CREATE TABLE IF NOT EXISTS skills(
    name TEXT PRIMARY KEY, domain TEXT, description TEXT, code TEXT, tests TEXT,
    trust TEXT, version INTEGER, successes INTEGER, uses INTEGER, created REAL, updated REAL);
CREATE TABLE IF NOT EXISTS lessons(
    id INTEGER PRIMARY KEY, ts REAL, domain TEXT, task_id TEXT, text TEXT UNIQUE,
    uses INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS triples(
    subject TEXT, relation TEXT, object TEXT, source TEXT, ts REAL,
    PRIMARY KEY(subject, relation, object));
CREATE TABLE IF NOT EXISTS eval_runs(
    run_id TEXT, ts REAL, generation INTEGER, task_id TEXT, domain TEXT, split TEXT,
    score REAL, attempts INTEGER, tokens INTEGER);
CREATE INDEX IF NOT EXISTS ep_task ON episodes(task_id);
"""


@dataclass
class Skill:
    name: str
    domain: str
    description: str
    code: str
    tests: list[str]
    trust: str
    version: int
    successes: int
    uses: int


class Memory:
    def __init__(self, db_path: Path | str, read_only: bool = False):
        self.path = str(db_path)
        self.read_only = read_only
        self.db = sqlite3.connect(self.path)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        self.db.commit()

    def close(self):
        self.db.close()

    def _write(self, sql: str, args=()):
        if self.read_only:
            return None
        cur = self.db.execute(sql, args)
        self.db.commit()
        return cur

    # ------------------------------------------------------------------ meta
    def get_meta(self, key: str, default=None):
        r = self.db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return json.loads(r["value"]) if r else default

    def set_meta(self, key: str, value) -> None:
        self._write("INSERT OR REPLACE INTO meta(key, value) VALUES(?, ?)",
                    (key, json.dumps(value)))

    # -------------------------------------------------------------- episodic
    def log_episode(self, *, task_id, domain, mode, attempts, solved, visible_pass,
                    code, reflection, skills_used, tokens, duration) -> None:
        self._write("""INSERT INTO episodes(ts, task_id, domain, mode, attempts, solved,
                       visible_pass, code, reflection, skills_used, tokens, duration)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (time.time(), task_id, domain, mode, attempts, int(solved), visible_pass,
                     code, reflection, json.dumps(skills_used), tokens, duration))

    def episodes(self, task_id: str | None = None, limit: int = 50) -> list[sqlite3.Row]:
        if task_id:
            return self.db.execute("SELECT * FROM episodes WHERE task_id=? ORDER BY id DESC LIMIT ?",
                                   (task_id, limit)).fetchall()
        return self.db.execute("SELECT * FROM episodes ORDER BY id DESC LIMIT ?", (limit,)).fetchall()

    def past_reflections(self, task_id: str, n: int = 2) -> list[str]:
        rows = self.db.execute("""SELECT reflection FROM episodes WHERE task_id=? AND reflection != ''
                                  ORDER BY id DESC LIMIT ?""", (task_id, n)).fetchall()
        return [r["reflection"] for r in rows]

    # ------------------------------------------------------------ procedural
    def upsert_skill(self, *, name, domain, description, code, tests, trust) -> str:
        """Add a verified skill. Existing skills are kept (stable) and gain a success;
        a skill is only replaced when the newcomer has stronger verification."""
        now = time.time()
        old = self.get_skill(name)
        rank = {"self-tested": 0, "verified-visible": 1}
        if old is None:
            self._write("""INSERT INTO skills VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                        (name, domain, description, code, json.dumps(list(tests)), trust,
                         1, 1, 0, now, now))
            return "added"
        if rank.get(trust, 0) > rank.get(old.trust, 0) and code != old.code:
            self._write("""UPDATE skills SET code=?, tests=?, trust=?, version=version+1,
                           successes=successes+1, description=?, updated=? WHERE name=?""",
                        (code, json.dumps(list(tests)), trust, description, now, name))
            return "upgraded"
        self._write("UPDATE skills SET successes=successes+1, updated=? WHERE name=?", (now, name))
        return "reinforced"

    def note_skill_use(self, names: list[str]) -> None:
        for n in names:
            self._write("UPDATE skills SET uses=uses+1 WHERE name=?", (n,))

    def get_skill(self, name: str) -> Skill | None:
        r = self.db.execute("SELECT * FROM skills WHERE name=?", (name,)).fetchone()
        return self._skill(r) if r else None

    def all_skills(self) -> list[Skill]:
        return [self._skill(r) for r in self.db.execute("SELECT * FROM skills ORDER BY domain, name")]

    def skill_code_map(self) -> dict[str, str]:
        return {s.name: s.code for s in self.all_skills()}

    def search_skills(self, query: str, k: int = 4) -> list[Skill]:
        skills = self.all_skills()
        docs = [(s.name, f"{s.name} {s.name} {s.domain} {s.description}") for s in skills]
        by = {s.name: s for s in skills}
        return [by[i] for i, _ in bm25_rank(query, docs, k)]

    @staticmethod
    def _skill(r) -> Skill:
        return Skill(r["name"], r["domain"], r["description"], r["code"],
                     json.loads(r["tests"]), r["trust"], r["version"], r["successes"], r["uses"])

    # -------------------------------------------------------------- semantic
    def add_lesson(self, text: str, domain: str, task_id: str) -> None:
        text = (text or "").strip()
        if len(text) < 12:
            return
        self._write("INSERT OR IGNORE INTO lessons(ts, domain, task_id, text) VALUES(?,?,?,?)",
                    (time.time(), domain, task_id, text[:600]))

    def search_lessons(self, query: str, k: int = 5, exclude_task: str | None = None) -> list[str]:
        rows = self.db.execute("SELECT id, domain, task_id, text FROM lessons").fetchall()
        docs = [(r["id"], f"{r['domain']} {r['text']}") for r in rows
                if exclude_task is None or r["task_id"] != exclude_task]
        hits = bm25_rank(query, docs, k)
        by = {r["id"]: r["text"] for r in rows}
        for i, _ in hits:
            self._write("UPDATE lessons SET uses=uses+1 WHERE id=?", (i,))
        return [by[i] for i, _ in hits]

    def add_triple(self, s: str, r: str, o: str, source: str) -> None:
        s, r, o = (str(x).strip().lower()[:120] for x in (s, r, o))
        if s and r and o:
            self._write("INSERT OR IGNORE INTO triples VALUES(?,?,?,?,?)", (s, r, o, source, time.time()))

    def related_knowledge(self, query: str, k: int = 8) -> list[tuple[str, str, str]]:
        rows = self.db.execute("SELECT subject, relation, object FROM triples").fetchall()
        docs = [(idx, f"{r['subject']} {r['relation']} {r['object']}") for idx, r in enumerate(rows)]
        return [tuple(rows[i]) for i, _ in bm25_rank(query, docs, k)]

    # ----------------------------------------------------------------- evals
    def record_eval(self, run_id, generation, task_id, domain, split, score, attempts, tokens):
        # evaluation results are always recorded, even when learning is disabled
        self.db.execute("INSERT INTO eval_runs VALUES(?,?,?,?,?,?,?,?,?)",
                        (run_id, time.time(), generation, task_id, domain, split, score,
                         attempts, tokens))
        self.db.commit()

    def eval_history(self) -> list[sqlite3.Row]:
        return self.db.execute("""SELECT run_id, MIN(ts) ts, generation, domain, split,
                                  AVG(score) score, COUNT(*) n, SUM(tokens) tokens
                                  FROM eval_runs GROUP BY run_id, domain, split
                                  ORDER BY ts, domain, split""").fetchall()

    # ----------------------------------------------------------------- stats
    def stats(self) -> dict:
        q = lambda sql: self.db.execute(sql).fetchone()[0]
        return {
            "episodes": q("SELECT COUNT(*) FROM episodes"),
            "solved_episodes": q("SELECT COUNT(*) FROM episodes WHERE solved=1"),
            "skills": q("SELECT COUNT(*) FROM skills"),
            "lessons": q("SELECT COUNT(*) FROM lessons"),
            "knowledge_triples": q("SELECT COUNT(*) FROM triples"),
            "eval_runs": q("SELECT COUNT(DISTINCT run_id) FROM eval_runs"),
            "generation": self.get_meta("generation", 0),
            "tokens_used": q("SELECT COALESCE(SUM(tokens),0) FROM episodes"),
        }


__all__ = ["Memory", "Skill", "tokenize"]
