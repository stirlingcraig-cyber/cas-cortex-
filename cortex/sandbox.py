"""Policy check + isolated execution of agent-written code.

Two layers:
1. Static policy (AST): import allowlist, banned builtins, no dunder escapes, no
   equality overrides (a classic way to game `==` tests).
2. Separate process: `python -I`, temp dir, timeout, secrets stripped from the
   environment, memory/CPU limits on Linux/macOS.

This is defence in depth for a single-user machine, NOT a security boundary against
a determined adversary. Step 3 (self-modification) moves execution into Docker.

PROTECTED FILE (covered by `cortex lock`).
"""
from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

ALLOWED_MODULES = {
    "array", "base64", "bisect", "collections", "copy", "csv", "dataclasses", "datetime",
    "decimal", "enum", "fractions", "functools", "hashlib", "heapq", "io", "ipaddress",
    "itertools", "json", "math", "operator", "random", "re", "statistics", "string",
    "struct", "textwrap", "time", "typing", "zlib", "urllib.parse", "skills",
    "__future__", "abc", "numbers", "unicodedata", "difflib", "html", "uuid",
}
BANNED_NAMES = {
    "eval", "exec", "compile", "open", "__import__", "input", "breakpoint", "globals",
    "locals", "vars", "getattr", "setattr", "delattr", "memoryview", "exit", "quit",
    "__builtins__", "help",
}
ALLOWED_DUNDER_ATTRS = {"__init__", "__name__", "__len__", "__iter__", "__next__",
                        "__repr__", "__str__", "__lt__", "__le__", "__gt__", "__ge__",
                        "__contains__", "__getitem__", "__setitem__", "__call__"}
BANNED_METHOD_DEFS = {"__eq__", "__ne__", "__bool__", "__hash__", "__del__",
                      "__getattr__", "__getattribute__", "__class_getitem__"}
SECRET_HINTS = ("KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "CREDENTIAL")


class PolicyViolation(Exception):
    pass


def _module_allowed(name: str) -> bool:
    if name in ALLOWED_MODULES:
        return True
    root = name.split(".")[0]
    # allow "collections.abc" etc. when the root is allowed, except urllib (only .parse)
    return root in ALLOWED_MODULES and root != "urllib"


def check_policy(code: str) -> list[str]:
    """Return a list of human-readable policy violations (empty = OK)."""
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        return [f"SyntaxError: {e.msg} (line {e.lineno})"]
    problems = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if not _module_allowed(a.name):
                    problems.append(f"import of '{a.name}' is not allowed")
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if node.level and node.level > 0:
                problems.append("relative imports are not allowed")
            elif not _module_allowed(mod):
                problems.append(f"import from '{mod}' is not allowed")
        elif isinstance(node, ast.Name) and node.id in BANNED_NAMES:
            problems.append(f"use of '{node.id}' is not allowed")
        elif isinstance(node, ast.Attribute):
            a = node.attr
            if a.startswith("__") and a.endswith("__") and a not in ALLOWED_DUNDER_ATTRS:
                problems.append(f"access to '{a}' is not allowed")
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name in BANNED_METHOD_DEFS:
                problems.append(f"defining '{node.name}' is blocked (prevents gaming equality tests)")
    # de-duplicate, keep order
    seen, out = set(), []
    for p in problems:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


def skills_used(code: str) -> list[str]:
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return []
    names = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "skills":
            names += [a.name for a in node.names]
    return sorted(set(names))


HARNESS = r'''
import json, sys, ast, traceback
_open = open
_dumps = json.dumps
workdir, spec_path, sol_path, out_path = sys.argv[1:5]
sys.path.insert(0, workdir)
with _open(spec_path, encoding="utf-8") as f:
    spec = json.load(f)
out = {"load_error": None, "results": []}
ns = {"__name__": "solution"}
try:
    with _open(sol_path, encoding="utf-8") as f:
        src = f.read()
    exec(compile(src, "solution.py", "exec"), ns)
except BaseException:
    out["load_error"] = traceback.format_exc(limit=3)[-2000:]
if out["load_error"] is None:
    for test in spec["tests"]:
        env = dict(ns)
        rec = {"test": test, "passed": False, "error": None}
        try:
            exec(compile(test, "<test>", "exec"), env)
            rec["passed"] = True
        except AssertionError as e:
            detail = str(e)
            try:
                tree = ast.parse(test)
                node = tree.body[-1]
                if (len(tree.body) == 1 and isinstance(node, ast.Assert)
                        and isinstance(node.test, ast.Compare) and len(node.test.ops) == 1):
                    lhs = eval(compile(ast.Expression(node.test.left), "<lhs>", "eval"), dict(ns))
                    detail = "got " + repr(lhs)[:600]
            except BaseException as e2:
                detail = detail or repr(e2)[:300]
            rec["error"] = ("AssertionError: " + detail) if detail else "AssertionError"
        except BaseException as e:
            rec["error"] = "".join(traceback.format_exception_only(type(e), e)).strip()[-1000:]
        out["results"].append(rec)
with _open(out_path, "w", encoding="utf-8") as f:
    f.write(_dumps(out))
'''


@dataclass
class RunResult:
    passed: int = 0
    total: int = 0
    load_error: str | None = None
    policy: list[str] = field(default_factory=list)
    timed_out: bool = False
    results: list[dict] = field(default_factory=list)
    duration: float = 0.0
    stderr: str = ""

    @property
    def pass_rate(self) -> float:
        return self.passed / self.total if self.total else 0.0

    @property
    def all_passed(self) -> bool:
        return self.total > 0 and self.passed == self.total

    def failure_report(self, max_items: int = 6) -> str:
        if self.policy:
            return "Policy violations:\n" + "\n".join(f"- {p}" for p in self.policy)
        if self.timed_out:
            return "Timed out: the code took too long (infinite loop or inefficient algorithm)."
        if self.load_error:
            return "The module failed to load:\n" + self.load_error
        lines = []
        for r in self.results:
            if not r["passed"]:
                lines.append(f"Test:\n{r['test']}\nResult: {r['error']}")
            if len(lines) >= max_items:
                break
        return "\n\n".join(lines) if lines else "All tests passed."


def _safe_env() -> dict:
    env = {k: v for k, v in os.environ.items()
           if not any(h in k.upper() for h in SECRET_HINTS)}
    env["PYTHONIOENCODING"] = "utf-8"
    env.pop("PYTHONPATH", None)
    env.pop("PYTHONSTARTUP", None)
    return env


def _limits(memory_mb: int, cpu_seconds: int):
    def apply():
        try:
            import resource
            mem = memory_mb * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (mem, mem))
            resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds + 1))
        except Exception:
            pass
    return apply


def write_skills_package(root: Path, skills: dict[str, str]) -> None:
    pkg = root / "skills"
    pkg.mkdir(exist_ok=True)
    init = ["# auto-generated: verified skills from CAS Cortex procedural memory"]
    for name, code in skills.items():
        if not name.isidentifier():
            continue
        (pkg / f"{name}.py").write_text(code, encoding="utf-8")
        init.append(f"try:\n    from .{name} import {name}\nexcept Exception:\n    pass")
    (pkg / "__init__.py").write_text("\n".join(init) + "\n", encoding="utf-8")


def run_tests(code: str, tests: list[str] | tuple[str, ...], skills: dict[str, str] | None = None,
              timeout: float = 10.0, memory_mb: int = 768) -> RunResult:
    """Policy-check `code`, then run each test snippet against it in a subprocess."""
    res = RunResult(total=len(tests))
    res.policy = check_policy(code)
    if res.policy:
        return res
    for name, scode in (skills or {}).items():
        if check_policy(scode):
            skills = {k: v for k, v in skills.items() if k != name}
    start = time.time()
    with tempfile.TemporaryDirectory(prefix="cortex_sbx_") as td:
        root = Path(td)
        write_skills_package(root, skills or {})
        (root / "solution.py").write_text(code, encoding="utf-8")
        (root / "spec.json").write_text(json.dumps({"tests": list(tests)}), encoding="utf-8")
        harness = root / "_harness.py"
        harness.write_text(HARNESS, encoding="utf-8")
        out_path = root / "_result.json"
        kwargs = dict(cwd=td, env=_safe_env(), capture_output=True, text=True,
                      timeout=timeout, stdin=subprocess.DEVNULL)
        if os.name == "posix":
            kwargs["preexec_fn"] = _limits(memory_mb, int(timeout) + 2)
        elif os.name == "nt":
            kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        try:
            proc = subprocess.run([sys.executable, "-I", str(harness), td,
                                   str(root / "spec.json"), str(root / "solution.py"),
                                   str(out_path)], **kwargs)
            res.stderr = (proc.stderr or "")[-2000:]
        except subprocess.TimeoutExpired:
            res.timed_out = True
            res.duration = time.time() - start
            return res
        res.duration = time.time() - start
        if not out_path.exists():
            res.load_error = "Process crashed before reporting.\n" + res.stderr
            return res
        data = json.loads(out_path.read_text(encoding="utf-8"))
    res.load_error = data["load_error"]
    res.results = data["results"]
    res.passed = sum(1 for r in res.results if r["passed"])
    return res
