"""The learning agent: retrieve -> attempt -> test -> self-correct -> reflect -> remember.

Learns from visible tests and its own self-generated tests only. It never sees the
evaluator's hidden tests.
"""
from __future__ import annotations

import ast
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
- Reply with exactly one ```python code block containing the complete module.
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
only: {"tests": ["assert ...", ...]}. Give 6-10 independent snippets. Each must be valid
Python using only the target function/class and the standard library, cover normal cases and
edge cases stated in the spec, and have expected values you are certain of."""


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
                 log=print, max_skills: int = 4):
        self.llm, self.mem, self.audit = llm, memory, audit
        self.max_attempts = max_attempts
        self.timeout, self.memory_mb = sandbox_timeout, memory_mb
        self.learn = learn and not memory.read_only
        self.log = log
        self.max_skills = max_skills

    # ------------------------------------------------------------ prompting
    def _context(self, task: TaskView) -> tuple[str, list[str], dict[str, str]]:
        query = f"{task.title} {task.domain} {task.prompt}"
        skills = self.mem.search_skills(query, k=self.max_skills)
        lessons = self.mem.search_lessons(query, k=5)
        facts = self.mem.related_knowledge(query, k=8)
        past = self.mem.past_reflections(task.id, n=2)
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
        parts.append(f"Write the complete module defining `{task.entry_point}`.")
        return "\n\n".join(parts), lessons, {s.name: s.code for s in skills}

    # ---------------------------------------------------------------- solve
    def solve(self, task: TaskView, mode: str = "train", trust: str = "verified-visible") -> Outcome:
        t0 = time.time()
        prompt, _, _ = self._context(task)
        skill_code = self.mem.skill_code_map()
        messages = [{"role": "user", "content": prompt}]
        tokens, code, best_code, best_rate = 0, "", "", -1.0
        history: list[str] = []
        attempts = 0
        result = None
        for attempts in range(1, self.max_attempts + 1):
            r = self.llm.complete(SYSTEM, messages, max_tokens=4000)
            tokens += r.tokens
            code = clean_solution(extract_code(r.text))
            result = run_tests(code, task.visible_tests, skills=skill_code,
                               timeout=self.timeout, memory_mb=self.memory_mb)
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
            messages += [{"role": "assistant", "content": r.text},
                         {"role": "user", "content":
                          "Your solution did not pass:\n\n" + result.failure_report() +
                          "\n\nDiagnose the root cause, then return the complete corrected module."}]
        solved = bool(result and result.all_passed)
        final = code if solved else best_code
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
    def solve_freeform(self, spec: str, entry_point: str, domain: str, title: str = "",
                       reference_code: str | None = None) -> Outcome:
        """Learn a brand-new capability from a plain-English spec: write tests first,
        then the code. Resulting skills are marked 'self-tested' (lower trust). With
        reference_code (e.g. a function from your Claude history) only tests the reference
        passes are kept, and the skill is marked 'reference-checked'."""
        r = self.llm.complete(TESTGEN_SYSTEM, [{"role": "user", "content":
                              f"Specification for `{entry_point}`:\n{spec}"}], max_tokens=2500)
        data = extract_json(r.text) or {}
        tests = [t for t in data.get("tests", []) if isinstance(t, str) and entry_point in t]
        trust = "self-tested"
        if reference_code:
            from .claude_history import filter_tests_with_reference
            before = len(tests)
            tests = filter_tests_with_reference(tests, reference_code, self.timeout)
            self.log(f"  kept {len(tests)} of {before} self-tests that your original function passes")
            trust = "reference-checked"
        if len(tests) < 3:
            raise RuntimeError("could not generate a usable test suite for this spec")
        self.log(f"  generated {len(tests)} self-tests")
        view = TaskView(id=f"adhoc.{entry_point}", domain=domain, title=title or entry_point,
                        entry_point=entry_point, prompt=spec, visible_tests=tuple(tests))
        out = self.solve(view, mode="adhoc", trust=trust)
        out.tokens += r.tokens
        return out
