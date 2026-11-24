"""CAS Cortex command line.  Run `python -m cortex --help`."""
from __future__ import annotations

import argparse
import json
import sys
import textwrap
import time
from pathlib import Path

from . import __version__
from .config import load_config
from .evaluator.taskbank import DOMAINS, all_tasks
from .governance import (AuditLog, Budget, BudgetExceeded, GovernedLLM, Halted, IntegrityError,
                         KillSwitch, lock_integrity, verify_integrity)
from .memory.store import Memory


class Runtime:
    def __init__(self, args):
        self.cfg = load_config(args.home, args.provider, args.model)
        if getattr(args, "attempts", None):
            self.cfg.max_attempts = args.attempts
        if getattr(args, "max_calls", None):
            self.cfg.max_llm_calls = args.max_calls
        self.audit = AuditLog(self.cfg.audit_path)
        self.kill = KillSwitch(self.cfg.stop_path)
        self.budget = Budget(self.cfg.max_llm_calls, self.cfg.max_tokens_per_run)
        self._llm = None

    @property
    def llm(self):
        if self._llm is None:
            from .llm import make_llm
            self._llm = GovernedLLM(make_llm(self.cfg), self.budget, self.audit, self.kill)
        return self._llm

    def memory(self, read_only=False) -> Memory:
        return Memory(self.cfg.db_path, read_only=read_only)

    def agent(self, mem: Memory, learn=True):
        from .agent import CortexAgent
        from .tuning import load as load_tuning
        # Self-improvement's approved settings, if any, override the defaults. Falls back to the
        # built-in defaults when nothing has been tuned.
        kw = {"max_skills": 3 if self.cfg.local else 4, "max_attempts": self.cfg.max_attempts,
              "reflect": self.cfg.reflect, "stuck_after": self.cfg.stuck_after, "system_addendum": ""}
        kw.update(load_tuning(self.cfg.home).agent_kwargs())
        return CortexAgent(self.llm, mem, self.audit, sandbox_timeout=self.cfg.sandbox_timeout,
                           memory_mb=self.cfg.sandbox_memory_mb, learn=learn, **kw)

    def tasks(self, domain=None):
        ts = all_tasks(self.cfg.tasks_dir)
        return [t for t in ts if domain in (None, "all") or t.domain == domain]

    def ensure_integrity(self):
        if not self.cfg.integrity_path.exists():
            lock_integrity(self.cfg.integrity_path)
            self.audit.write("integrity_locked", auto=True)
        verify_integrity(self.cfg.integrity_path, required=True)


# ------------------------------------------------------------------ commands
def cmd_status(rt, a):
    mem = rt.memory(read_only=True)
    s = mem.stats()
    changed = verify_integrity(rt.cfg.integrity_path)
    ok, n, msg = rt.audit.verify()
    print(f"CAS Cortex {__version__}   home: {rt.cfg.home}")
    print(f"model: {rt.cfg.provider}/{rt.cfg.model}")
    print(f"generation {s['generation']} | episodes {s['episodes']} ({s['solved_episodes']} solved) | "
          f"skills {s['skills']} | lessons {s['lessons']} | knowledge {s['knowledge_triples']} | "
          f"evals {s['eval_runs']} | tokens {s['tokens_used']:,}")
    print(f"kill switch: {'ENGAGED' if rt.cfg.stop_path.exists() else 'off'} | "
          f"integrity: {'lock missing' if not rt.cfg.integrity_path.exists() else ('CHANGED: ' + ', '.join(changed) if changed else 'ok')} | "
          f"audit: {msg} ({n} entries)")


def cmd_doctor(rt, a):
    from .doctor import run_doctor, speed_test
    if a.speed:
        if speed_test(rt.cfg) is None:
            sys.exit(1)
        return
    if not run_doctor(rt.cfg, pull=a.pull):
        sys.exit(1)


def cmd_check_sandbox(rt, a):
    """Prove the code sandbox works on this PC, independent of the AI model."""
    import platform
    import tempfile
    from .sandbox import run_tests
    print(f"Python      {sys.executable}")
    print(f"Version     {platform.python_version()} on {platform.system()} {platform.release()}")
    print(f"Temp folder {tempfile.gettempdir()}")
    checks = [
        ("Run a correct solution", "from collections import Counter\ndef add(a, b):\n    return a + b\n",
         ["assert add(2, 3) == 5", "assert add(-1, 1) == 0"], {}, 2),
        ("Reuse a stored skill", "from skills import double\ndef quad(x):\n    return double(double(x))\n",
         ["assert quad(3) == 12"], {"double": "def double(x):\n    return 2 * x\n"}, 1),
        ("Report a broken solution", "def f(:\n    pass\n", ["assert f() == 1"], {}, 0),
    ]
    ok = True
    for name, code, tests, skills, want in checks:
        r = run_tests(code, tests, skills=skills, timeout=rt.cfg.sandbox_timeout)
        good = r.passed == want and (want > 0 or r.policy or r.load_error)
        ok &= bool(good)
        print(f"{'PASS' if good else 'FAIL'}  {name}: {r.passed}/{r.total} passed in {r.duration:.1f}s")
        if not good:
            print("      " + r.failure_report().replace("\n", "\n      ")[:1500])
            if r.stderr:
                print("      stderr: " + r.stderr[-800:])
    print("\nSandbox works on this PC." if ok else
          "\nSandbox problem on this PC - please send this output (screenshot) for a fix.")
    if not ok:
        sys.exit(1)


def cmd_publish(rt, a):
    from .publish import publish
    if not publish(rt.cfg.home, push=not a.no_push):
        sys.exit(1)


def cmd_add_pack(rt, a):
    """Install a task pack (e.g. automotive) into the curriculum."""
    import shutil
    from .gui_backend import APP_DIR
    src = Path(a.pack)
    if not src.exists():
        src = APP_DIR / "examples" / "task_packs" / f"{a.pack}.json"
    if not src.exists():
        packs = sorted(p.stem for p in (APP_DIR / "examples" / "task_packs").glob("*.json"))
        sys.exit(f"No task pack '{a.pack}'. Available: {', '.join(packs)}")
    dest = rt.cfg.tasks_dir / f"pack_{src.stem}.json"
    shutil.copyfile(src, dest)
    try:
        tasks = all_tasks(rt.cfg.tasks_dir)
    except Exception as e:
        dest.unlink()
        sys.exit(f"Couldn't add the pack: {e}")
    new = [t for t in json.loads(src.read_text(encoding="utf-8"))]
    print(f"Added {len(new)} task(s) from '{src.stem}': " + ", ".join(t["id"] for t in new))
    print(f"Curriculum now has {len(tasks)} tasks. Train with:  cortex train" +
          (f" --domain {new[0]['domain']}" if len({t['domain'] for t in new}) == 1 else ""))
    rt.audit.write("task_pack_added", pack=src.stem, tasks=[t["id"] for t in new])


def cmd_import_claude(rt, a):
    from . import claude_history as ch
    mem = rt.memory(read_only=True)
    r = ch.import_export(rt.cfg.home, Path(a.export), {s.name for s in mem.all_skills()})
    rt.audit.write("claude_history_imported", conversations=r["conversations"], new_proposals=r["new_proposals"])
    print(f"Read {r['conversations']} conversations (processed on this PC only).")
    print("Topics: " + ", ".join(f"{d} {n}" for d, n in sorted(r["by_domain"].items(), key=lambda kv: -kv[1])))
    print(f"{r['new_proposals']} new skill proposal(s) from code Claude wrote for you "
          f"({r['total_proposals']} in total). Review them: cortex proposals")


def cmd_proposals(rt, a):
    from . import claude_history as ch
    if a.approve:
        n = ch.set_status(rt.cfg.home, "all-new" if a.approve == ["all"] else a.approve, "approved")
        print(f"Approved {n} proposal(s). Learn them now with: cortex learn-proposal <id>  (or let autopilot do it)")
        return
    if a.dismiss:
        print(f"Dismissed {ch.set_status(rt.cfg.home, a.dismiss, 'dismissed')} proposal(s).")
        return
    props = ch.load_proposals(rt.cfg.home)
    if not props:
        print("No proposals yet. Import your Claude export first: cortex import-claude <export.zip>")
    for p in props:
        if p["status"] != "dismissed" or a.all:
            print(f"{p['id']}  {p['status']:<9} {p['domain']:<8} {p['name']:<28} from '{p['title'][:40]}' {p['date']}")


def cmd_learn_proposal(rt, a):
    from . import claude_history as ch
    props = {p["id"]: p for p in ch.load_proposals(rt.cfg.home)}
    p = props.get(a.id)
    if not p:
        sys.exit(f"No proposal {a.id}. See: cortex proposals")
    mem = rt.memory()
    try:
        o = rt.agent(mem).solve_freeform(p["spec"], p["name"], p["domain"], p["title"], reference_code=p["reference_code"])
    except RuntimeError as e:
        ch.set_status(rt.cfg.home, [p["id"]], "failed")
        sys.exit(f"Couldn't learn '{p['name']}': {e}")
    ch.set_status(rt.cfg.home, [p["id"]], "learned" if o.solved else "failed")
    print(f"\n{'LEARNED' if o.solved else 'not learned'} `{p['name']}` (reference-checked); skill: {o.skill_action or '-'}")
    if not o.solved:
        sys.exit(1)


def cmd_feedback(rt, a):
    from . import feedback as fb
    from .autopilot import add_phone_usage
    if a.import_file:
        n, usage = fb.import_file(rt.cfg.home, Path(a.import_file))
        add_phone_usage(rt.cfg.home, usage)
        rt.audit.write("feedback_imported", items=n)
        print(f"Imported {n} new feedback item(s) from the iPhone.")
        return
    if a.reset:
        fb.reset(rt.cfg.home)
        rt.audit.write("feedback_reset")
        print("Feedback reset (a backup was kept as feedback.jsonl.bak).")
        return
    recs = fb.load(rt.cfg.home)
    print(f"{len(recs)} piece(s) of feedback.")
    for line in fb.describe(fb.summarise(recs)) or ["No adjustments learned yet."]:
        print("  " + line)


def cmd_focus(rt, a):
    from .autopilot import focus
    f = focus(rt.cfg.home)
    if not f["weights"]:
        print("No usage yet - Cortex learns your focus as you use it.")
    for d, w in sorted(f["weights"].items(), key=lambda kv: -kv[1]):
        print(f"  {d:<8} {'#' * int(w * 40):<40} {w:.0%}")
    print("Next autopilot training: " + ", ".join(f["next_training"]))


def cmd_autopilot(rt, a):
    from . import autopilot
    from .gui_backend import ollama_state
    log_path = rt.cfg.home / "autopilot.log"

    def log(msg):
        line = time.strftime("%Y-%m-%d %H:%M:%S ") + msg
        print(line)
        with log_path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")

    def ready():
        if rt.cfg.provider != "ollama":
            return True
        online, has = ollama_state(rt.cfg.ollama_url, rt.cfg.model)
        return online and has
    rt.kill.check()
    rt.audit.write("autopilot_start")
    rep = autopilot.run(rt.cfg.home, ready, ["--home", str(rt.cfg.home)], log=log, rounds=a.rounds, hours=a.hours)
    rt.audit.write("autopilot_end", trained=rep["trained"], learned=len(rep["learned"]),
                   feedback=rep["feedback_imported"], published=rep["published"])


def cmd_improve(rt, a):
    from . import improve
    rt.ensure_integrity()
    tasks = rt.tasks()
    rt.audit.write("self_improvement_start", split=a.split)
    res = improve.propose(rt.cfg, rt.llm, tasks, max_candidates=a.candidates, split=a.split,
                          sample=a.sample)
    rt.audit.write("self_improvement_end", baseline=res["baseline"], queued=bool(res["queued"]))


def cmd_improvements(rt, a):
    from . import improve
    if a.approve:
        for pid in a.approve:
            try:
                p = improve.apply(rt.cfg.home, pid, rt.audit)
                print(f"Applied {pid}: {p['rationale']} (now Cortex's active method).")
            except (KeyError, ValueError) as e:
                print(f"{pid}: {e}")
        return
    if a.reject:
        for pid in a.reject:
            try:
                improve.reject(rt.cfg.home, pid, rt.audit)
                print(f"Rejected {pid}.")
            except KeyError as e:
                print(f"{pid}: no such proposal")
        return
    props = improve.load_proposals(rt.cfg.home)
    if not props:
        print("No self-improvement proposals yet. Run: cortex improve")
    for p in props:
        if p["status"] != "rejected" or a.all:
            print(f"{p['id']}  {p['status']:<9} {p['baseline_score']:.0%} -> {p['candidate_score']:.0%}  {p['rationale']}")


def cmd_tuning(rt, a):
    from . import tuning
    if a.reset:
        tuning.reset(rt.cfg.home)
        rt.audit.write("tuning_reset")
        print("Method reset to the built-in defaults.")
        return
    t = tuning.load(rt.cfg.home).describe()
    print("Cortex's current method (what self-improvement can change):")
    for k, v in t.items():
        print(f"  {k}: {v!r}" if k != "system_addendum" else f"  {k}: {v or '(none)'}")


def cmd_gui(rt, a):
    from .gui import main as gui_main
    gui_main(str(rt.cfg.home))


def cmd_tasks(rt, a):
    for t in rt.tasks(a.domain):
        print(f"{t.id:32} {t.split:8} {t.title}")


def cmd_train(rt, a):
    from .trainer import report, run_eval, train
    mem = rt.memory()
    domains = a.domain or []
    rt.audit.write("train_start", rounds=a.rounds, domain=domains, hours=a.hours, until_mastered=a.until_mastered)
    tasks = [t for t in rt.tasks() if not domains or t.domain in domains]
    t0 = time.time()
    try:
        res = train(rt.agent(mem), mem, tasks, a.rounds, seed=a.seed, hours=a.hours,
                    until_mastered=a.until_mastered)
    finally:
        rt.audit.write("train_end", calls=rt.budget.calls, tokens=rt.budget.tokens)
    solved = sum(r["solved"] for r in res)
    mins = (time.time() - t0) / 60
    print(f"\n{solved}/{len(res)} practice episodes solved in {mins:.0f} min. "
          f"Model calls {rt.budget.calls}, tokens {rt.budget.tokens:,}.")
    if res:
        print(f"Average {sum(r['seconds'] for r in res) / len(res):.0f} s per task.")
    print("Skills in library: " + (", ".join(s.name for s in mem.all_skills()) or "none"))
    if a.then_eval:
        print("\n=== evaluation (holdout) ===")
        rt.ensure_integrity()
        ro = rt.memory(read_only=True)
        run_eval(rt.agent(ro, learn=False), ro, rt.tasks(), split="holdout")
        print(report(ro))
    if a.then_publish:
        from .publish import publish
        print("\n=== publish ===")
        publish(rt.cfg.home)


def cmd_eval(rt, a):
    from .trainer import report, run_eval
    rt.ensure_integrity()
    mem = rt.memory(read_only=True)
    rt.audit.write("eval_start", split=a.split, domain=a.domain)
    res = run_eval(rt.agent(mem, learn=False), mem, rt.tasks(a.domain), split=a.split)
    rt.audit.write("eval_end", run=res["run_id"], summary=res["summary"])
    print("\nSummary (hidden tests):")
    for k, v in res["summary"].items():
        print(f"  {k:<20} {v:.0%}")
    print()
    print(report(mem))


def cmd_solve(rt, a):
    tasks = {t.id: t for t in rt.tasks()}
    if a.task_id not in tasks:
        sys.exit(f"unknown task {a.task_id}; see `cortex tasks`")
    t = tasks[a.task_id]
    mem = rt.memory()
    o = rt.agent(mem).solve(t.public_view(), mode="manual")
    print(f"\n{'SOLVED' if o.solved else 'not solved'} in {o.attempts} attempt(s); "
          f"skill: {o.skill_action or '-'}; lesson: {o.lesson or '-'}")
    if a.show:
        print("\n" + o.code)


def cmd_learn(rt, a):
    spec = Path(a.spec[1:]).read_text(encoding="utf-8") if a.spec.startswith("@") else a.spec
    if a.domain not in DOMAINS:
        sys.exit(f"--domain must be one of {DOMAINS}")
    mem = rt.memory()
    o = rt.agent(mem).solve_freeform(spec, a.name, a.domain, a.title or a.name)
    print(f"\n{'LEARNED' if o.solved else 'not learned'} `{a.name}` "
          f"({o.attempts} attempt(s), self-tested); skill: {o.skill_action or '-'}")
    if a.show or o.solved:
        print("\n" + o.code)


def cmd_skills(rt, a):
    mem = rt.memory(read_only=True)
    if a.name:
        s = mem.get_skill(a.name)
        if not s:
            sys.exit("no such skill")
        print(f"# {s.name}  [{s.domain}] trust={s.trust} v{s.version} successes={s.successes} uses={s.uses}")
        print(f"# {s.description}\n")
        print(s.code)
        return
    skills = mem.all_skills()
    if not skills:
        print("No skills yet. Run: cortex train")
    for s in skills:
        print(f"{s.name:28} {s.domain:8} {s.trust:17} v{s.version} successes={s.successes} uses={s.uses}")


def cmd_memory(rt, a):
    mem = rt.memory(read_only=True)
    print("Lessons:")
    for r in mem.db.execute("SELECT domain, text, uses FROM lessons ORDER BY id DESC LIMIT ?", (a.n,)):
        print(f"  [{r['domain']}] (used {r['uses']}x) " + textwrap.shorten(r["text"], 160))
    print("\nKnowledge graph (latest):")
    for r in mem.db.execute("SELECT subject, relation, object FROM triples ORDER BY ts DESC LIMIT ?", (a.n,)):
        print(f"  {r['subject']} --{r['relation']}--> {r['object']}")
    print("\nRecent episodes:")
    for r in mem.episodes(limit=a.n):
        print(f"  {r['task_id']:30} {r['mode']:7} {'solved' if r['solved'] else 'failed':7} "
              f"attempts={r['attempts']} tokens={r['tokens']}")


def cmd_report(rt, a):
    from .trainer import report
    print(report(rt.memory(read_only=True)))


def cmd_watch(rt, a):
    from .realtime import ThreatMonitor, follow, load_learned, make_triage
    crit = {}
    for c in a.critical or []:
        k, _, v = c.partition("=")
        crit[k] = int(v or 3)
    if a.homenet:
        from .realtime import HNG_DEFAULT_PATH
        a.file, a.follow, a.from_start = a.file if a.file not in (None, "") else HNG_DEFAULT_PATH, True, True
        if not Path(a.file).exists():
            sys.exit(f"HomeNet Guard alerts not found at {a.file}. Is CAS HomeNet Guard installed and running?")
    elif not a.file:
        sys.exit("Give a log file (or - for stdin), or use --homenet")
    learned = load_learned(rt.memory(read_only=True).skill_code_map()) if a.use_learned else {}
    from . import feedback as fb
    mon = ThreatMonitor(fail_count=a.fail_count, fail_window=a.fail_window, criticality=crit,
                        feedback=fb.summarise(fb.load(rt.cfg.home)),
                        learned=learned, triage=make_triage(rt.llm) if a.triage else None,
                        alerts_path=rt.cfg.home / "alerts.jsonl")
    if learned:
        print("Using learned detectors: " + ", ".join(sorted(learned)))
    rt.audit.write("watch_start", source=a.file, learned=sorted(learned), triage=a.triage)
    try:
        if a.file == "-":
            for line in sys.stdin:
                rt.kill.check()
                mon.feed(line)
        elif a.follow and not _is_vehicle_export(a.file):
            print(f"Watching {a.file} (Ctrl+C or `cortex stop` to end)")
            follow(Path(a.file), mon, a.from_start, rt.kill.check)
        else:
            from . import vehicle
            text = Path(a.file).read_text(encoding="utf-8", errors="replace")
            what = vehicle.analyse_text(mon, text, time.time())
            if what:
                print("CAS OBD Scanner: " + {"obd_test_report": "test report", "obd_health": "car health history",
                                             "obd_data_log": "data log", "obd_codes": "fault codes"}[what]
                      + (" - no problems found." if not mon.alerts else " analysed."))
    except KeyboardInterrupt:
        pass
    finally:
        counts = {}
        for al in mon.alerts:
            counts[al["priority"]] = counts.get(al["priority"], 0) + 1
        print(f"\n{mon.events} events, {len(mon.alerts)} alerts "
              + json.dumps(dict(sorted(counts.items()))))
        rt.audit.write("watch_end", events=mon.events, alerts=len(mon.alerts))


def _is_vehicle_export(path) -> bool:
    from . import vehicle
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return vehicle.detect(f.read(4096) + "\n") is not None or path.lower().endswith(".json")
    except OSError:
        return False


def cmd_lock(rt, a):
    if rt.cfg.integrity_path.exists() and not a.force:
        changed = verify_integrity(rt.cfg.integrity_path)
        if changed:
            sys.exit("Protected files changed: " + ", ".join(changed) +
                     "\nReview the changes, then run `cortex lock --force` to accept them.")
        print("Integrity lock already in place and valid.")
        return
    lock_integrity(rt.cfg.integrity_path)
    rt.audit.write("integrity_locked", forced=a.force)
    print("Protected files locked.")


def cmd_verify(rt, a):
    changed = verify_integrity(rt.cfg.integrity_path)
    ok, n, msg = rt.audit.verify()
    print(f"integrity: {'ok' if not changed else 'CHANGED: ' + ', '.join(changed)}"
          f"{' (no lock yet)' if not rt.cfg.integrity_path.exists() else ''}")
    print(f"audit: {msg} ({n} entries)")
    if changed or not ok:
        sys.exit(1)


def cmd_stop(rt, a):
    rt.cfg.stop_path.write_text("stop requested\n", encoding="utf-8")
    rt.audit.write("kill_switch", engaged=True)
    print(f"Kill switch engaged ({rt.cfg.stop_path}). Running loops halt at their next step.")


def cmd_resume(rt, a):
    if rt.cfg.stop_path.exists():
        rt.cfg.stop_path.unlink()
    rt.audit.write("kill_switch", engaged=False)
    print("Kill switch released.")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cortex", description="CAS Cortex - a self-learning engineering agent")
    p.add_argument("--home", help="data folder (default ./cortex_data or $CORTEX_HOME)")
    p.add_argument("--provider", choices=["ollama", "openai", "anthropic"],
                   help="ollama (default, free, local), openai (LM Studio etc.), anthropic")
    p.add_argument("--model")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("status", help="memory, governance and model status")
    sub.add_parser("gui", help="open the desktop app")
    s = sub.add_parser("publish", help="publish progress to GitHub for the iPhone app")
    s.add_argument("--no-push", action="store_true", help="only write docs/data/status.json")
    s = sub.add_parser("improve", help="step 3: propose and test improvements to Cortex's own method")
    s.add_argument("--candidates", type=int, default=3, help="how many changes to try")
    s.add_argument("--split", choices=["holdout", "train", "all"], default="holdout")
    s.add_argument("--sample", type=int, help="only score this many tasks (faster)")
    s.add_argument("--max-calls", type=int)
    s = sub.add_parser("improvements", help="review self-improvement proposals")
    s.add_argument("--approve", nargs="+", metavar="ID"); s.add_argument("--reject", nargs="+", metavar="ID")
    s.add_argument("--all", action="store_true")
    s = sub.add_parser("tuning", help="show Cortex's current method, or reset it")
    s.add_argument("--reset", action="store_true")
    s = sub.add_parser("add-pack", help="add a ready-made task pack, e.g. automotive")
    s.add_argument("pack", help="pack name (automotive) or path to a pack .json")
    s = sub.add_parser("import-claude", help="learn from your Claude data export (processed locally)")
    s.add_argument("export", help="the export .zip (or conversations.json)")
    s = sub.add_parser("proposals", help="skill proposals from your Claude history")
    s.add_argument("--approve", nargs="+", metavar="ID", help="approve proposal IDs, or 'all'")
    s.add_argument("--dismiss", nargs="+", metavar="ID")
    s.add_argument("--all", action="store_true", help="include dismissed")
    s = sub.add_parser("learn-proposal", help="learn one approved proposal now")
    s.add_argument("id"); s.add_argument("--attempts", type=int)
    s = sub.add_parser("feedback", help="what Cortex has learned from your alert feedback")
    s.add_argument("--import", dest="import_file", metavar="FILE", help="import an iPhone feedback file")
    s.add_argument("--reset", action="store_true")
    sub.add_parser("focus", help="what Cortex has learned about your focus")
    s = sub.add_parser("autopilot", help="one pass of continuous learning (used by the nightly task)")
    s.add_argument("--rounds", type=int, default=1)
    s.add_argument("--hours", type=float, default=2.0, help="training time budget per night (default 2)")
    s.add_argument("--max-calls", type=int)
    sub.add_parser("check-sandbox", help="test that agent code can run on this PC (no AI needed)")
    s = sub.add_parser("doctor", help="check setup, choose a local model for your PC, download it")
    s.add_argument("--pull", action="store_true", help="download the model if missing")
    s.add_argument("--speed", action="store_true", help="measure how fast the model runs on this PC")
    s = sub.add_parser("tasks", help="list curriculum tasks"); s.add_argument("--domain", choices=DOMAINS)
    s = sub.add_parser("train", help="practise and learn")
    s.add_argument("--rounds", type=int, default=1)
    s.add_argument("--domain", choices=DOMAINS, nargs="+", help="one or more areas (default: all)")
    s.add_argument("--hours", type=float, help="hands-off: keep training for up to this long")
    s.add_argument("--until-mastered", action="store_true",
                   help="hands-off: keep going until every practice task is mastered (stops if stuck)")
    s.add_argument("--then-eval", action="store_true", help="run the holdout evaluation when finished")
    s.add_argument("--then-publish", action="store_true", help="publish to the iPhone app when finished")
    s.add_argument("--attempts", type=int); s.add_argument("--max-calls", type=int)
    s.add_argument("--seed", type=int)
    s = sub.add_parser("eval", help="score with hidden tests (memory read-only)")
    s.add_argument("--split", choices=["all", "train", "holdout"], default="all")
    s.add_argument("--domain", choices=DOMAINS); s.add_argument("--attempts", type=int)
    s.add_argument("--max-calls", type=int)
    s = sub.add_parser("solve", help="attempt one task and learn from it")
    s.add_argument("task_id"); s.add_argument("--show", action="store_true")
    s.add_argument("--attempts", type=int)
    s = sub.add_parser("learn", help="learn a new capability from a plain-English spec")
    s.add_argument("spec", help="spec text, or @file.txt"); s.add_argument("--name", required=True)
    s.add_argument("--domain", required=True); s.add_argument("--title")
    s.add_argument("--show", action="store_true"); s.add_argument("--attempts", type=int)
    s = sub.add_parser("skills", help="list skills, or show one"); s.add_argument("name", nargs="?")
    s = sub.add_parser("memory", help="lessons, knowledge graph, episodes"); s.add_argument("-n", type=int, default=10)
    sub.add_parser("report", help="learning curve across evaluations")
    s = sub.add_parser("watch", help="real-time threat, risk and harm monitor")
    s.add_argument("file", nargs="?", help="log file, or - for stdin (optional with --homenet)")
    s.add_argument("--homenet", action="store_true",
                   help="watch CAS HomeNet Guard's alerts live (C:\\ProgramData\\CAS Solutions\\HomeNetGuard\\alerts.jsonl)")
    s.add_argument("--follow", action="store_true", help="keep watching like tail -f")
    s.add_argument("--from-start", action="store_true", help="with --follow, read existing lines first")
    s.add_argument("--use-learned", action="store_true", help="use detectors Cortex has learned")
    s.add_argument("--triage", action="store_true", help="LLM triage of P1/P2 alerts")
    s.add_argument("--critical", nargs="*", help="asset criticality, e.g. 10.0.0.5=3 db01=3")
    s.add_argument("--fail-count", type=int, default=5); s.add_argument("--fail-window", type=int, default=60)
    s.add_argument("--max-calls", type=int)
    s = sub.add_parser("lock", help="lock evaluator/sandbox/governance integrity")
    s.add_argument("--force", action="store_true")
    sub.add_parser("verify", help="verify integrity lock and audit chain")
    sub.add_parser("stop", help="engage the kill switch")
    sub.add_parser("resume", help="release the kill switch")
    return p


COMMANDS = {"status": cmd_status, "doctor": cmd_doctor, "gui": cmd_gui, "check-sandbox": cmd_check_sandbox, "publish": cmd_publish,
            "improve": cmd_improve, "improvements": cmd_improvements, "tuning": cmd_tuning, "add-pack": cmd_add_pack, "import-claude": cmd_import_claude,
            "proposals": cmd_proposals, "learn-proposal": cmd_learn_proposal, "feedback": cmd_feedback,
            "focus": cmd_focus, "autopilot": cmd_autopilot, "tasks": cmd_tasks, "train": cmd_train, "eval": cmd_eval,
            "solve": cmd_solve, "learn": cmd_learn, "skills": cmd_skills, "memory": cmd_memory,
            "report": cmd_report, "watch": cmd_watch, "lock": cmd_lock, "verify": cmd_verify,
            "stop": cmd_stop, "resume": cmd_resume}


def main(argv=None):
    args = build_parser().parse_args(argv)
    rt = Runtime(args)
    try:
        COMMANDS[args.cmd](rt, args)
    except Halted as e:
        sys.exit(f"HALTED: {e}")
    except BudgetExceeded as e:
        sys.exit(f"BUDGET: {e}. Progress so far is saved; raise --max-calls to continue.")
    except IntegrityError as e:
        sys.exit(f"INTEGRITY: {e}")
    except RuntimeError as e:
        sys.exit(f"ERROR: {e}")


if __name__ == "__main__":
    main()
