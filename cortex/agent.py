"""The learning agent: retrieve -> attempt -> test -> self-correct -> reflect -> remember.

Learns from visible tests and its own self-generated tests only. It never sees the
evaluator's hidden tests.
"""
from __future__ import annotations

import ast
import json
import re
import time
from dataclasses import dataclass, field

from .evaluator.taskbank import TaskView
from .llm import LLM, extract_code, extract_json
from .memory.store import Memory
from .governance import AuditLog
from .sandbox import ALLOWED_MODULES, run_tests, skills_used

DOMAIN_FOCUS = {
    "coding": "general software engineering: correctness, edge cases, clean algorithms",
    "cyber": "defensive cyber security: log analysis, detection engineering, indicator "
             "extraction, vulnerability scoring",
    "bigdata": "big-data processing: streaming, bounded memory, single-pass algorithms, "
               "numerical stability at scale",
    "threat": "real-time threat, risk and harm interpretation: event correlation, "
              "anomaly detection, prioritisation",
}

SYSTEM = f"""You are the engineering core of CAS Cortex, a learning agent that specialises in
software engineering, defensive cyber security, big-data processing and real-time threat,
risk and harm analysis. You write correct, efficient, standard-library Python 3.10+.

Rules:
- Reply with exactly one ```python code block containing the complete module, and nothing
  else: no explanation before or after it.
- The module must only define things: no example usage, print() calls, asserts, tests or
  `if __name__ == "__main__":` block.
- Allowed imports only: {", ".join(sorted(m for m in ALLOWED_MODULES if m not in ("skills", "__future__")))}.
- You may also `from skills import <name>` for any skill listed as available; those are
  verified functions from your own past work. Reuse them when they genuinely fit.
- No file, network, subprocess or OS access. No eval/exec/getattr. Do not define __eq__.
- Follow the specification exactly; it is the contract. Handle edge cases it mentions.
- Do not special-case the example tests; solve the general problem."""

REFLECT_SYSTEM = """You are the reflection module of a learning agent. Given a task and how the
attempts went, extract durable, reusable knowledge. Reply with JSON only:
{"lesson": "<one or two sentences: a general, reusable insight or pitfall - not specific to
this exact task's values>",
 "knowledge": [["subject", "relation", "object"], ...]}
Give 0-4 knowledge triples of general facts (e.g. ["population stdev", "divides by", "n"])."""

TESTGEN_SYSTEM = """You write rigorous Python test snippets for a specification. Reply with JSON
ONLY, in exactly this shape:
{"tests": ["assert fn(1) == 2", "assert fn(0) == 0"]}
Give 6-10 independent snippets. Each must be a single line starting with `assert`, call the target
function by its exact name, use only the standard library, cover normal and edge cases from the
spec, and use expected values you are certain of. No prose, no code fences, no comments."""


def _is_main_guard(node) -> bool:
    t = getattr(node, "test", None)
    return (isinstance(node, ast.If) and isinstance(t, ast.Compare)
            and isinstance(t.left, ast.Name) and t.left.id == "__name__")


def _has_demo_code(node) -> bool:
    for n in ast.walk(node):
        if isinstance(n, ast.Assert):
            return True
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in ("print", "input"):
            return True
    return False


def clean_solution(code: str) -> str:
    """Remove demo/test code that models (especially small local ones) often append at
    module level - example asserts, print() calls, `if __name__ == "__main__":` blocks and
    loops that print. Such lines crash the module on import and hide a correct solution."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return code
    keep = []
    for node in tree.body:
        if isinstance(node, ast.Assert) or _is_main_guard(node):
            continue
        if isinstance(node, ast.Expr) and not (isinstance(node.value, ast.Constant)
                                               and isinstance(node.value.value, str)):
            continue  # bare calls such as print(...) or f(...); docstrings are kept
        if isinstance(node, (ast.For, ast.While, ast.With, ast.Try)) and _has_demo_code(node):
            continue
        keep.append(node)
    if len(keep) == len(tree.body):
        return code
    return ast.unparse(ast.Module(body=keep, type_ignores=[])) + "\n"


# Names small models often use without importing them -> the import that fixes it.
AUTO_IMPORTS = {m: f"import {m}" for m in ("math", "re", "statistics", "heapq", "bisect", "itertools", "functools",
                                             "collections", "json", "random", "string", "datetime", "ipaddress",
                                             "hashlib", "base64", "operator", "time", "csv", "io", "copy", "decimal")}
AUTO_IMPORTS.update({
    "defaultdict": "from collections import defaultdict", "Counter": "from collections import Counter",
    "deque": "from collections import deque", "OrderedDict": "from collections import OrderedDict",
    "namedtuple": "from collections import namedtuple", "dataclass": "from dataclasses import dataclass",
    "field": "from dataclasses import field", "reduce": "from functools import reduce",
    "lru_cache": "from functools import lru_cache", "heappush": "from heapq import heappush",
    "heappop": "from heapq import heappop", "sqrt": "from math import sqrt", "radians": "from math import radians",
    "sin": "from math import sin", "cos": "from math import cos", "asin": "from math import asin",
    "atan2": "from math import atan2", "floor": "from math import floor", "ceil": "from math import ceil",
    "inf": "from math import inf", "isclose": "from math import isclose", "mean": "from statistics import mean",
    "pstdev": "from statistics import pstdev", "median": "from statistics import median",
    **{t: f"from typing import {t}" for t in ("List", "Dict", "Tuple", "Optional", "Any", "Iterable", "Iterator",
                                              "Set", "Union", "Callable", "Sequence")},
})
_MISSING = re.compile(r"NameError: name '(\w+)' is not defined")


def missing_imports(result) -> list[str]:
    """Import lines that would fix NameErrors such as "name 'math' is not defined"."""
    texts = [result.load_error or ""] + [r.get("error") or "" for r in result.results]
    names = {m for t in texts for m in _MISSING.findall(t)}
    return sorted({AUTO_IMPORTS[n] for n in names if n in AUTO_IMPORTS})


def short_reason(result) -> str:
    """One-line explanation of a failed attempt, for the live console."""
    if result is None or result.all_passed:
        return ""
    if result.policy:
        return result.policy[0]
    if result.timed_out:
        return "took too long (timeout)"
    if result.load_error:
        lines = [l.strip() for l in result.load_error.strip().splitlines() if l.strip()]
        return (lines[-1] if lines else "module failed to load")[:200]
    for r in result.results:
        if not r["passed"] and r.get("error"):
            return r["error"].splitlines()[-1][:200]
    return ""


@dataclass
class Outcome:
    task_id: str
    solved: bool
    attempts: int
    visible_pass: float
    code: str
    tokens: int
    duration: float
    skills_used: list[str] = field(default_factory=list)
    skill_action: str = ""
    lesson: str = ""
    history: list[str] = field(default_factory=list)


class CortexAgent:
    def __init__(self, llm: LLM, memory: Memory, audit: AuditLog, max_attempts: int = 4,
                 sandbox_timeout: float = 15.0, memory_mb: int = 768, learn: bool = True,
                 log=print, max_skills: int = 4, reflect: str = "smart", stuck_after: int = 2,
                 system_addendum: str = ""):
        self.llm, self.mem, self.audit = llm, memory, audit
        self.max_attempts = max_attempts
        self.timeout, self.memory_mb = sandbox_timeout, memory_mb
        self.learn = learn and not memory.read_only
        self.log = log
        self.max_skills = max_skills
        self.reflect_mode = reflect          # "always" | "smart" | "never"
        self.stuck_after = stuck_after
        # The fixed SYSTEM (with the safety rules) is ALWAYS the base; self-improvement may only
        # append a short addendum, never remove or edit the core instructions.
        self.system = SYSTEM + (("\n\n" + system_addendum.strip()) if system_addendum.strip() else "")

    # ------------------------------------------------------------ prompting
    def _context(self, task: TaskView) -> tuple[str, list[str], dict[str, str]]:
        query = f"{task.title} {task.domain} {task.prompt}"
        skills = self.mem.search_skills(query, k=self.max_skills)
        lessons = self.mem.search_lessons(query, k=5)
        facts = self.mem.related_knowledge(query, k=8)
        past = self.mem.past_reflections(task.id, n=2)
        struggles = self.mem.past_struggles(task.id, n=3)
        parts = [f"## Domain focus\n{DOMAIN_FOCUS.get(task.domain, task.domain)}",
                 f"## Task: {task.title}\n{task.prompt}",
                 "## Example tests (your code must pass these; hidden tests also apply)\n"
                 + "\n\n".join(task.visible_tests)]
        if skills:
            parts.append("## Available skills (import with `from skills import <name>`)\n" +
                         "\n\n".join(f"### {s.name} [{s.domain}, used {s.uses}x]\n{s.description}\n"
                                     f"```python\n{s.code.strip()}\n```" for s in skills))
        if lessons:
            parts.append("## Lessons from your past experience\n" + "\n".join(f"- {l}" for l in lessons))
        if facts:
            parts.append("## Related knowledge\n" + "\n".join(f"- {s} {r} {o}" for s, r, o in facts))
        if past:
            parts.append("## Your notes from previous attempts at this exact task\n" +
                         "\n".join(f"- {p}" for p in past))
        if struggles:
            # Show the approaches that already failed (closest first) so it builds on them
            # instead of repeating them. This is how it eventually solves a hard task.
            lines = ["## Approaches you ALREADY TRIED that did NOT work - do not repeat these; "
                     "fix the specific error or try a different approach"]
            best_code, best_reason, best_rate = struggles[0]
            for _, reason, rate in struggles:
                lines.append(f"- failed ({rate:.0%} of visible tests passed): {reason or 'did not pass'}")
            if best_rate > 0:
                trimmed = "\n".join(best_code.splitlines()[:25])
                lines.append("Your closest attempt (still wrong - fix the error above, keep what worked):\n"
                             f"```python\n{trimmed}\n```")
            parts.append("\n".join(lines))
        parts.append(f"Write the complete module defining `{task.entry_point}`.")
        return "\n\n".join(parts), lessons, {s.name: s.code for s in skills}

    def _auto_import(self, code, result, task, skill_code):
        """Fix forgotten standard-library imports without spending another model call.
        Local models often write math.sqrt(...) but forget `import math`, then repeat the
        same mistake on every retry."""
        for _ in range(3):
            if result.all_passed or result.policy or result.timed_out:
                break
            fixes = [f for f in missing_imports(result) if f not in code]
            if not fixes:
                break
            fixed = "\n".join(fixes) + "\n" + code
            again = run_tests(fixed, task.visible_tests, skills=skill_code, timeout=self.timeout,
                              memory_mb=self.memory_mb)
            if again.passed < result.passed:
                break
            self.log(f"      auto-fixed missing import: {', '.join(fixes)}")
            code, result = fixed, again
        return code, result

    # ---------------------------------------------------------------- solve
    def solve(self, task: TaskView, mode: str = "train", trust: str = "verified-visible") -> Outcome:
        t0 = time.time()
        prompt, _, _ = self._context(task)
        skill_code = self.mem.skill_code_map()
        first = {"role": "user", "content": prompt}
        messages = [first]
        tokens, code, best_code, best_rate = 0, "", "", -1.0
        history: list[str] = []
        attempts = 0
        result = None
        seen_code: set[str] = set()
        same_reason, last_reason = 0, None
        stopped_early = ""
        diversified = False
        for attempts in range(1, self.max_attempts + 1):
            # Raise temperature once it has stalled, so it explores a genuinely different idea
            # instead of nudging the same wrong one. On the final attempt, force a fresh approach.
            if diversified and same_reason == 0:
                temperature = 0.85       # the just-triggered "different approach" attempt
            elif same_reason <= 1 and not seen_code:
                temperature = 0.2
            elif attempts < self.max_attempts:
                temperature = 0.5
            else:
                temperature = 0.85
            sys_prompt = self.system
            if temperature >= 0.85 and (seen_code or same_reason > 1 or diversified):
                sys_prompt = self.system + ("\n\nIMPORTANT: your previous approach is not working. Start over with a "
                                            "fundamentally different algorithm or structure - do not tweak the last attempt.")
            r = self.llm.complete(sys_prompt, messages, max_tokens=1800, temperature=temperature)
            tokens += r.tokens
            code = clean_solution(extract_code(r.text))
            result = run_tests(code, task.visible_tests, skills=skill_code,
                               timeout=self.timeout, memory_mb=self.memory_mb)
            code, result = self._auto_import(code, result, task, skill_code)
            history.append(f"attempt {attempts}: {result.passed}/{result.total} visible tests"
                           + (" (policy)" if result.policy else "")
                           + (" (timeout)" if result.timed_out else "")
                           + (" (load error)" if result.load_error else ""))
            self.log(f"    {history[-1]}")
            why = short_reason(result)
            if why:
                self.log(f"      reason: {why}")
            if result.pass_rate > best_rate:
                best_rate, best_code = result.pass_rate, code
            if result.all_passed:
                break
            if self.learn and not result.policy:
                self.mem.record_struggle(task.id, code, why or result.failure_report(1)[:200], result.pass_rate)
            # Stuck detection: a small model that repeats itself won't succeed on attempt 8 -
            # stop and let the next generation try again with the lesson from this one.
            norm = "\n".join(l.rstrip() for l in code.strip().splitlines())
            same_reason = same_reason + 1 if why and why == last_reason else 1
            last_reason = why
            if norm in seen_code:
                stopped_early = "it wrote the same code again"
            elif self.stuck_after and same_reason > self.stuck_after:
                stopped_early = f"the same mistake {same_reason} times in a row"
            # Before giving up on a stuck task, spend one attempt on a genuinely different
            # approach (high temperature, explicit "start over"). That's often what breaks through.
            if stopped_early and not diversified and attempts < self.max_attempts:
                diversified = True
                stopped_early = ""
                self.log("    stuck - trying a fundamentally different approach")
                messages = [first, {"role": "user", "content":
                            "Your previous approaches all failed the same way:\n\n" + result.failure_report(2) +
                            "\n\nThat whole approach is wrong. Start over with a completely different algorithm "
                            f"or data structure and write the full module defining `{task.entry_point}`."}]
                seen_code.add(norm)
                same_reason = 0
                continue
            if stopped_early:
                self.log(f"    stopping early: {stopped_early} (saves time - it will retry next round)")
                break
            seen_code.add(norm)
            # Keep only the latest attempt in the conversation: shorter prompts are much faster
            # on a local model, and stop the context window overflowing on long retries.
            messages = [first,
                        {"role": "assistant", "content": f"```python\n{code.strip()}\n```"},
                        {"role": "user", "content":
                         f"Attempt {attempts} did not pass:\n\n" + result.failure_report() +
                         "\n\nDiagnose the root cause, then return the complete corrected module."}]
        solved = bool(result and result.all_passed)
        final = code if solved else best_code
        if self.learn and solved:
            self.mem.clear_struggles(task.id)      # cracked it - the failed-approach history is spent
        used = skills_used(final)
        out = Outcome(task.id, solved, attempts, max(best_rate, 0.0), final, tokens,
                      0.0, used, history=history)

        if self.learn:
            self.mem.note_skill_use(used)
            existing = self.mem.get_skill(task.entry_point)
            if solved and existing is not None and task.entry_point in used:
                # solved by recalling its own skill: reinforce, never store a self-import
                out.skill_action = self.mem.upsert_skill(
                    name=existing.name, domain=existing.domain, description=existing.description,
                    code=existing.code, tests=existing.tests, trust=existing.trust)
            elif solved:
                out.skill_action = self.mem.upsert_skill(
                    name=task.entry_point, domain=task.domain,
                    description=f"{task.title}. " + task.prompt.split("\n")[0][:300],
                    code=final, tests=list(task.visible_tests), trust=trust)
            if self._should_reflect(task, out):
                out.lesson, rtoks = self._reflect(task, out, result)
                out.tokens += rtoks
        out.duration = time.time() - t0
        if self.learn:
            self.mem.log_episode(task_id=task.id, domain=task.domain, mode=mode,
                                 attempts=out.attempts, solved=solved,
                                 visible_pass=out.visible_pass, code=final,
                                 reflection=out.lesson, skills_used=used, tokens=out.tokens,
                                 duration=out.duration)
        self.audit.write("episode", task=task.id, mode=mode, solved=solved,
                         attempts=out.attempts, skill_action=out.skill_action, learn=self.learn)
        return out

    def _should_reflect(self, task: TaskView, out: Outcome) -> bool:
        """Reflection costs a whole model call. In 'smart' mode Cortex only reflects when there
        is something to learn: it struggled or failed, or it solved this task for the first time."""
        if self.reflect_mode == "never":
            return False
        if self.reflect_mode == "always" or not out.solved or out.attempts > 1:
            return True
        return out.skill_action == "added"

    def _reflect(self, task: TaskView, out: Outcome, last) -> tuple[str, int]:
        summary = (f"Task: {task.title} ({task.domain})\n{task.prompt}\n\n"
                   f"Attempts: {'; '.join(out.history)}\nSolved: {out.solved}\n")
        if last is not None and not last.all_passed:
            summary += "\nLast failure:\n" + last.failure_report(max_items=3)[:2500]
        summary += f"\n\nFinal code:\n```python\n{out.code[:4000]}\n```"
        try:
            r = self.llm.complete(REFLECT_SYSTEM, [{"role": "user", "content": summary}], max_tokens=600)
        except Exception as e:  # reflection is best-effort, but budget/kill must propagate
            if e.__class__.__name__ in ("Halted", "BudgetExceeded"):
                raise
            return "", 0
        data = extract_json(r.text) or {}
        lesson = str(data.get("lesson", "")).strip()
        if lesson:
            self.mem.add_lesson(lesson, task.domain, task.id)
        for trip in (data.get("knowledge") or [])[:4]:
            if isinstance(trip, (list, tuple)) and len(trip) == 3:
                self.mem.add_triple(*trip, source=task.id)
        return lesson, r.tokens

    # ---------------------------------------------------- self-generated work
    def _parse_tests(self, text: str, entry_point: str) -> list[str]:
        """Pull usable `assert` snippets out of a model's reply, however it formatted them -
        proper JSON, a bare array, a code block, or just lines of asserts. Small local models
        rarely return clean JSON, so this harvests tests from all of those."""
        from .llm import strip_thinking
        candidates: list[str] = []
        data = extract_json(text)
        if isinstance(data, dict) and isinstance(data.get("tests"), list):
            candidates += [t for t in data["tests"] if isinstance(t, str)]
        clean = strip_thinking(text)
        if not candidates:                       # maybe a bare JSON array of strings
            start, end = clean.find("["), clean.rfind("]")
            if start != -1 and end > start:
                try:
                    arr = json.loads(clean[start:end + 1])
                    candidates += [t for t in arr if isinstance(t, str)]
                except (json.JSONDecodeError, ValueError):
                    pass
        for raw in clean.replace("```python", "").replace("```", "").splitlines():
            line = raw.strip().strip(",").strip()
            if (line.startswith("assert ") or line.startswith('"assert ')) and entry_point in line:
                candidates.append(line.strip('"'))
        valid, seen = [], set()
        for t in candidates:
            t = t.strip().strip('"').strip()
            key = " ".join(t.split())
            if entry_point not in t or key in seen:
                continue
            try:
                ast.parse(t)
            except SyntaxError:
                continue
            seen.add(key)
            valid.append(t)
        return valid

    def _generate_tests(self, spec: str, entry_point: str) -> tuple[list[str], int]:
        prompt = (f"Specification for a Python function `{entry_point}`:\n{spec}\n\n"
                  f"Write independent test snippets, each a single line starting with `assert "
                  f"{entry_point}(` and a value you are sure of. Reply with JSON only, like:\n"
                  f'{{"tests": ["assert {entry_point}(1) == 2", "assert {entry_point}(0) == 0"]}}')
        tests, toks, seen = [], 0, set()
        for i in range(3):                       # retry: small models often need a couple of goes
            r = self.llm.complete(TESTGEN_SYSTEM, [{"role": "user", "content": prompt}],
                                  max_tokens=1600, temperature=0.2 + 0.3 * i)
            toks += r.tokens
            for t in self._parse_tests(r.text, entry_point):
                key = " ".join(t.split())
                if key not in seen:
                    seen.add(key)
                    tests.append(t)
            if len(tests) >= 5:
                break
        return tests, toks

    def solve_freeform(self, spec: str, entry_point: str, domain: str, title: str = "",
                       reference_code: str | None = None) -> Outcome:
        """Learn a brand-new capability from a plain-English spec: write tests first,
        then the code. Resulting skills are marked 'self-tested' (lower trust). With
        reference_code (e.g. a function from your Claude history) only tests the reference
        passes are kept, and the skill is marked 'reference-checked'."""
        tests, toks = self._generate_tests(spec, entry_point)
        trust = "self-tested"
        if reference_code:
            from .claude_history import filter_tests_with_reference
            before = len(tests)
            tests = filter_tests_with_reference(tests, reference_code, self.timeout)
            self.log(f"  kept {len(tests)} of {before} self-tests that your original function passes")
            trust = "reference-checked"
        if len(tests) < 3:
            raise RuntimeError(
                f"the model couldn't write a usable test suite for `{entry_point}` after 3 tries. "
                "Try rewording the description with a concrete example or two (e.g. 'f([1,2,3]) returns 6'), "
                "use a larger model, or add it on the 'Add a practice task' tab where you write the tests yourself.")
        self.log(f"  generated {len(tests)} self-tests")
        view = TaskView(id=f"adhoc.{entry_point}", domain=domain, title=title or entry_point,
                        entry_point=entry_point, prompt=spec, visible_tests=tuple(tests))
        out = self.solve(view, mode="adhoc", trust=trust)
        out.tokens += toks
        return out
