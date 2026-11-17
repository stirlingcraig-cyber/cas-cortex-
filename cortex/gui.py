"""CAS Cortex desktop app. Launch with the desktop shortcut, `Start CAS Cortex.bat`,
or `python -m cortex gui`. Each tab follows a stage of the user guide."""
from __future__ import annotations

import json
import os
import queue
import sys
import threading
import tkinter as tk
import webbrowser
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from . import __version__
from . import gui_backend as be
from .config import DEFAULT_MODELS, load_config
from .doctor import MODEL_LADDER, recommend_model, total_ram_gb
from .evaluator.taskbank import DOMAINS
from .governance import AuditLog, lock_integrity, verify_integrity

NAVY, TEAL, TEAL_D, BG, CARD = "#14213D", "#0F7C7A", "#0B5E5C", "#F4F7F8", "#FFFFFF"
GREEN, RED, AMBER, GREY, INK = "#1E8E3E", "#C62828", "#E08A00", "#6B7280", "#1F2328"
PRIO = {"P1": ("#FDE2E1", RED), "P2": ("#FFEFD5", AMBER), "P3": ("#FFF9DB", "#8A6D00"), "P4": ("#EEF1F4", GREY)}
DOMAIN_LABELS = {"All areas": None, "Coding": "coding", "Cyber security": "cyber",
                 "Big data": "bigdata", "Threat, risk & harm": "threat"}
IPHONE_URL = "https://stirlingcraig-cyber.github.io/cas-cortex-/"
TABS = ["Home", "Setup", "Train", "Progress", "Skills & Memory", "Teach", "Threat Monitor", "Learn from You",
        "Safety", "Help"]


def ui_font(size=10, weight="normal"):
    fam = "Segoe UI" if os.name == "nt" else "DejaVu Sans"
    return (fam, size, weight)


MONO = ("Consolas" if os.name == "nt" else "DejaVu Sans Mono", 9)


class Console(ttk.Frame):
    """Scrolling output panel with colour highlighting and progress-line support."""

    def __init__(self, master, height=14):
        super().__init__(master)
        self.text = tk.Text(self, height=height, wrap="word", font=MONO, bg="#0E1726", fg="#D7E3EA",
                            insertbackground="white", relief="flat", padx=8, pady=6)
        sb = ttk.Scrollbar(self, command=self.text.yview)
        self.text.configure(yscrollcommand=sb.set, state="disabled")
        self.text.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        for tag, col in (("good", "#7EE2A8"), ("bad", "#FF8A80"), ("head", "#5EEAD4"),
                         ("warn", "#FFD180"), ("dim", "#8FA3B5")):
            self.text.tag_configure(tag, foreground=col)
        self.text.tag_configure("head", font=(MONO[0], MONO[1], "bold"))
        self._cr_active = False

    def _tag(self, line):
        l = line.lower()
        if line.startswith("===") or line.startswith("$ "):
            return "head"
        if "[p1]" in l or "error" in l or "halted" in l or "not solved" in l or "not reachable" in l or "budget" in l:
            return "bad"
        if "solved" in l or " ready" in l or "all set" in l or "intact" in l or "learned" in l or "100%" in l:
            return "good"
        if "[p2]" in l or "lesson:" in l or "suggested" in l or "not downloaded" in l:
            return "warn"
        if line.startswith("    attempt"):
            return "dim"
        return None

    def write(self, line, cr=False):
        t = self.text
        t.configure(state="normal")
        if self._cr_active:
            t.delete("end-2l linestart", "end-1c")
        t.insert("end", line + "\n", self._tag(line) or ())
        self._cr_active = cr
        if int(t.index("end-1c").split(".")[0]) > 4000:
            t.delete("1.0", "500.0")
        t.see("end")
        t.configure(state="disabled")

    def clear(self):
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        self.text.configure(state="disabled")
        self._cr_active = False


def make_tree(master, columns, widths, height=10, stretch_last=True):
    frame = ttk.Frame(master)
    tree = ttk.Treeview(frame, columns=columns, show="headings", height=height)
    for i, (c, w) in enumerate(zip(columns, widths)):
        tree.heading(c, text=c)
        tree.column(c, width=w, anchor="w", stretch=(stretch_last and i == len(columns) - 1))
    sb = ttk.Scrollbar(frame, command=tree.yview)
    tree.configure(yscrollcommand=sb.set)
    tree.pack(side="left", fill="both", expand=True)
    sb.pack(side="right", fill="y")
    tree.tag_configure("odd", background="#F1F6F7")
    return frame, tree


def fill_tree(tree, rows, tags_fn=None):
    tree.delete(*tree.get_children())
    for i, r in enumerate(rows):
        tags = ["odd"] if i % 2 else []
        if tags_fn:
            tags += tags_fn(r)
        tree.insert("", "end", values=r, tags=tags)


class CortexApp(tk.Tk):
    def __init__(self, home: Path | None = None):
        super().__init__()
        self.home = Path(home or os.environ.get("CORTEX_HOME") or be.APP_DIR / "cortex_data").resolve()
        self.cfg = load_config(self.home)
        self.events: queue.Queue = queue.Queue()
        self.jobs: dict[str, be.Job] = {}
        self.consoles: dict[str, Console] = {}
        self.on_done: dict[str, callable] = {}
        self.setup_ok = False
        self.ollama_online = None
        self._monitor_offset = 0

        self.title("CAS Cortex")
        self.geometry("1180x780")
        self.minsize(1000, 680)
        self.configure(bg=BG)
        self._icon()
        self._style()
        self._header()
        self._statusbar()
        self.nb = ttk.Notebook(self, style="Main.TNotebook")
        self.nb.pack(fill="both", expand=True, padx=10, pady=(6, 0))
        self.pages = {}
        for name in TABS:
            f = ttk.Frame(self.nb, style="Page.TFrame", padding=14)
            self.nb.add(f, text=f"  {name}  ")
            self.pages[name] = f
        self.build_home(); self.build_setup(); self.build_train(); self.build_progress()
        self.build_memory(); self.build_teach(); self.build_monitor(); self.build_learn(); self.build_safety()
        self.build_help()
        self.nb.bind("<<NotebookTabChanged>>", self._on_tab)
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(100, self._poll)
        self.after(300, self.refresh_all)
        self._check_ollama()

    # ------------------------------------------------------------------ chrome
    def _icon(self):
        ico, png = be.APP_DIR / "assets" / "cortex.ico", be.APP_DIR / "assets" / "cortex.png"
        try:
            if os.name == "nt" and ico.exists():
                self.iconbitmap(default=str(ico))
            elif png.exists():
                self.iconphoto(True, tk.PhotoImage(file=str(png)))
        except tk.TclError:
            pass

    def _style(self):
        st = ttk.Style(self)
        st.theme_use("clam")
        st.configure(".", font=ui_font(10), background=BG, foreground=INK)
        st.configure("Page.TFrame", background=BG)
        st.configure("Card.TFrame", background=CARD, relief="solid", borderwidth=1)
        st.configure("TLabel", background=BG)
        st.configure("Card.TLabel", background=CARD)
        st.configure("H1.TLabel", font=ui_font(16, "bold"), foreground=NAVY, background=BG)
        st.configure("H2.TLabel", font=ui_font(11, "bold"), foreground=TEAL, background=BG)
        st.configure("Muted.TLabel", foreground=GREY, background=BG)
        st.configure("CardMuted.TLabel", foreground=GREY, background=CARD, font=ui_font(9))
        st.configure("CardBig.TLabel", foreground=NAVY, background=CARD, font=ui_font(15, "bold"))
        st.configure("Main.TNotebook", background=BG, borderwidth=0)
        st.configure("Main.TNotebook.Tab", padding=(6, 7), font=ui_font(10, "bold"), background="#DCE6E8",
                     foreground=NAVY)
        st.map("Main.TNotebook.Tab", background=[("selected", CARD)], foreground=[("selected", TEAL)])
        st.configure("Accent.TButton", font=ui_font(10, "bold"), foreground="white", background=TEAL,
                     padding=(14, 7), borderwidth=0)
        st.map("Accent.TButton", background=[("disabled", "#9BB8B7"), ("active", TEAL_D)])
        st.configure("Danger.TButton", font=ui_font(10, "bold"), foreground="white", background=RED,
                     padding=(14, 7), borderwidth=0)
        st.map("Danger.TButton", background=[("disabled", "#D9A3A3"), ("active", "#9E1F1F")])
        st.configure("TButton", padding=(10, 6))
        st.configure("Go.TButton", font=ui_font(9, "bold"), foreground=TEAL, padding=(10, 3))
        st.configure("TLabelframe", background=BG)
        st.configure("TLabelframe.Label", font=ui_font(10, "bold"), foreground=NAVY, background=BG)
        st.configure("Treeview", rowheight=24, font=ui_font(9))
        st.configure("Treeview.Heading", font=ui_font(9, "bold"), background="#DCE6E8")
        st.configure("TCheckbutton", background=BG)
        st.configure("TRadiobutton", background=BG)

    def _header(self):
        h = tk.Frame(self, bg=NAVY, height=58)
        h.pack(fill="x")
        tk.Label(h, text="CAS Cortex", bg=NAVY, fg="white", font=ui_font(18, "bold")).pack(side="left", padx=(16, 8), pady=10)
        tk.Label(h, text="self-learning engineering agent", bg=NAVY, fg="#9CC7C5",
                 font=ui_font(10)).pack(side="left", pady=(16, 10))
        self.chip_ks = tk.Label(h, text="", bg=NAVY, fg="white", font=ui_font(9, "bold"), padx=10, pady=4)
        self.chip_ks.pack(side="right", padx=(6, 16))
        self.chip_ollama = tk.Label(h, text="AI model: checking...", bg="#2B3A5A", fg="white",
                                    font=ui_font(9, "bold"), padx=10, pady=4)
        self.chip_ollama.pack(side="right", padx=6)

    def _statusbar(self):
        bar = tk.Frame(self, bg="#E3EBED", height=26)
        bar.pack(fill="x", side="bottom")
        self.status = tk.Label(bar, text="Ready", bg="#E3EBED", fg=INK, font=ui_font(9), anchor="w")
        self.status.pack(side="left", padx=10, fill="x", expand=True)
        tk.Label(bar, text=f"v{__version__}  |  data: {self.home}", bg="#E3EBED", fg=GREY,
                 font=ui_font(9)).pack(side="right", padx=10)

    def go(self, tab: str):
        self.nb.select(TABS.index(tab))

    def _on_tab(self, _=None):
        name = TABS[self.nb.index(self.nb.select())]
        refresh = {"Home": self.refresh_home, "Progress": self.refresh_progress,
                   "Skills & Memory": self.refresh_memory, "Teach": self.refresh_teach,
                   "Safety": self.refresh_safety, "Train": self.refresh_train,
                   "Learn from You": self.refresh_learn}.get(name)
        if refresh:
            refresh()

    def refresh_all(self):
        for f in (self.refresh_home, self.refresh_train, self.refresh_progress, self.refresh_memory,
                  self.refresh_teach, self.refresh_safety, self.refresh_learn):
            try:
                f()
            except Exception as e:  # never let one panel break the app
                self.set_status(f"Could not refresh: {e}")

    def set_status(self, text):
        self.status.configure(text=text)

    # --------------------------------------------------------------- jobs
    def busy(self) -> str | None:
        for k, j in self.jobs.items():
            if k != "monitor" and j.running():
                return k
        return None

    def run(self, key: str, args: list[str], console: Console, done=None, exclusive=True, label=None):
        if exclusive and (b := self.busy()):
            messagebox.showinfo("CAS Cortex", f"Please wait - '{b}' is still running.\n"
                                              "Stop it first, or wait for it to finish.")
            return False
        console.write(f"$ cortex {' '.join(args)}")
        try:
            self.jobs[key] = be.Job(key, args, self.home, self.events)
        except Exception as e:
            console.write(f"ERROR: could not start: {e}")
            return False
        self.consoles[key] = console
        self.on_done[key] = done
        self.set_status(label or f"Running: {key}...")
        self._update_buttons()
        return True

    def stop(self, key: str):
        j = self.jobs.get(key)
        if j and j.running():
            self.consoles[key].write("Stopping...")
            self.set_status(f"Stopping {key}...")
            j.stop()
            self.consoles[key].write("Stopped. Everything learned so far is saved.")

    def _poll(self):
        try:
            while True:
                kind, key, payload = self.events.get_nowait()
                con = self.consoles.get(key)
                if kind in ("line", "cr") and con:
                    con.write(payload, cr=(kind == "cr"))
                    if key == "train":
                        self._train_progress(payload)
                elif kind == "done":
                    j = self.jobs.get(key)
                    if con:
                        msg = ("Stopped." if j and j.stopped else
                               "Finished." if payload == 0 else f"Finished with problems (code {payload}).")
                        con.write(msg)
                    self.set_status("Ready")
                    cb = self.on_done.get(key)
                    if cb:
                        try:
                            cb(payload)
                        except Exception as e:
                            self.set_status(f"Refresh error: {e}")
                    self._update_buttons()
                    self.refresh_home()
        except queue.Empty:
            pass
        if self.jobs.get("monitor") and self.jobs["monitor"].running():
            self._read_alerts()
        self.after(120, self._poll)

    def _update_buttons(self):
        b = self.busy()
        for btn in getattr(self, "_run_buttons", []):
            btn.configure(state="disabled" if b else "normal")
        live: dict = {}
        for key, btn in getattr(self, "_stop_buttons", {}).items():
            j = self.jobs.get(key)
            live[btn] = live.get(btn, False) or bool(j and j.running())
        for btn, on in live.items():
            btn.configure(state="normal" if on else "disabled")
        mon = self.jobs.get("monitor")
        if hasattr(self, "mon_start"):
            running = bool(mon and mon.running())
            self.mon_start.configure(state="disabled" if running else "normal")
            self.mon_stop.configure(state="normal" if running else "disabled")

    def _reg(self, run_buttons=(), stop=None):
        self._run_buttons = getattr(self, "_run_buttons", []) + list(run_buttons)
        if stop:
            self._stop_buttons = getattr(self, "_stop_buttons", {})
            self._stop_buttons[stop[0]] = stop[1]

    def _check_ollama(self):
        def work():
            cfg = load_config(self.home)
            if cfg.provider != "ollama":
                res = ("other", cfg)
            else:
                res = (be.ollama_state(cfg.ollama_url, cfg.model), cfg)
            self.after(0, lambda: self._ollama_result(*res))
        threading.Thread(target=work, daemon=True).start()
        self.after(20000, self._check_ollama)

    def _ollama_result(self, state, cfg):
        self.cfg = cfg
        if state == "other":
            self.setup_ok = True
            self.chip_ollama.configure(text=f"AI model: {cfg.provider} / {cfg.model}", bg=TEAL)
        else:
            online, has = state
            self.setup_ok = online and has
            if not online:
                self.chip_ollama.configure(text="AI model: Ollama offline", bg=RED)
            elif not has:
                self.chip_ollama.configure(text=f"AI model: {cfg.model} not downloaded", bg=AMBER)
            else:
                self.chip_ollama.configure(text=f"AI model: {cfg.model} ready", bg=GREEN)
        if hasattr(self, "setup_state"):
            self.setup_state.configure(
                text=("Ready - your local AI model is installed and running." if self.setup_ok else
                      "Not ready yet - run 'Check my setup' below for what to do next."),
                foreground=GREEN if self.setup_ok else RED)
        self.refresh_home()

    # ================================================================ HOME
    def build_home(self):
        p = self.pages["Home"]
        ttk.Label(p, text="Welcome to CAS Cortex", style="H1.TLabel").pack(anchor="w")
        ttk.Label(p, text="Cortex learns coding, cyber security, big data and threat analysis by practising, "
                          "testing its own work and remembering what works. Follow the steps below.",
                  style="Muted.TLabel", wraplength=1050).pack(anchor="w", pady=(2, 10))
        self.next_banner = tk.Frame(p, bg=TEAL)
        self.next_banner.pack(fill="x", pady=(0, 12))
        self.next_label = tk.Label(self.next_banner, text="", bg=TEAL, fg="white", font=ui_font(11, "bold"),
                                   anchor="w", padx=14, pady=10)
        self.next_label.pack(side="left", fill="x", expand=True)
        self.next_btn = tk.Button(self.next_banner, text="Go  >", bg="white", fg=TEAL, relief="flat",
                                  font=ui_font(10, "bold"), padx=14, cursor="hand2")
        self.next_btn.pack(side="right", padx=12, pady=8)

        cards = ttk.Frame(p, style="Page.TFrame")
        cards.pack(fill="x", pady=(0, 12))
        self.cards = {}
        for i, (key, label) in enumerate([("model", "AI model"), ("generation", "Generation"),
                                          ("skills", "Skills learned"), ("lessons", "Lessons"),
                                          ("evals", "Evaluations"), ("score", "Latest score")]):
            c = ttk.Frame(cards, style="Card.TFrame", padding=(12, 8))
            c.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 8, 0))
            cards.columnconfigure(i, weight=1)
            ttk.Label(c, text=label, style="CardMuted.TLabel").pack(anchor="w")
            v = ttk.Label(c, text="-", style="CardBig.TLabel")
            v.pack(anchor="w")
            self.cards[key] = v

        ttk.Label(p, text="Your journey", style="H2.TLabel").pack(anchor="w", pady=(4, 6))
        self.journey_frame = ttk.Frame(p, style="Page.TFrame")
        self.journey_frame.pack(fill="both", expand=True)

    def refresh_home(self):
        try:
            s = be.snapshot(self.home)
        except Exception as e:
            self.set_status(f"Could not read memory: {e}")
            return
        model = s["model"]
        self.cards["model"].configure(text=(model[:18] + "...") if len(model) > 20 else model,
                                      font=ui_font(11 if len(model) > 14 else 15, "bold"))
        self.cards["generation"].configure(text=str(s["generation"]))
        self.cards["skills"].configure(text=str(s["skills"]))
        self.cards["lessons"].configure(text=str(s["lessons"]))
        self.cards["evals"].configure(text=str(s["eval_runs"]))
        self.cards["score"].configure(text="-" if s["latest_score"] is None else f"{s['latest_score']:.0%}")
        ks = s["kill_switch"]
        self.chip_ks.configure(text="KILL SWITCH ON" if ks else "Kill switch off", bg=RED if ks else "#2B3A5A")

        steps = be.journey(s, self.setup_ok)
        for w in self.journey_frame.winfo_children():
            w.destroy()
        nxt = next((x for x in steps if not x["done"]), None)
        for i, st in enumerate(steps):
            r, c = divmod(i, 2)
            card = tk.Frame(self.journey_frame, bg=CARD, highlightthickness=2 if st is nxt else 1,
                            highlightbackground=TEAL if st is nxt else "#D5DFE2")
            card.grid(row=r, column=c, sticky="nsew", padx=(0 if c == 0 else 10, 0), pady=(0, 10))
            self.journey_frame.columnconfigure(c, weight=1)
            mark, col = ("✔", GREEN) if st["done"] else (str(i + 1), TEAL if st is nxt else GREY)
            tk.Label(card, text=mark, bg=col, fg="white", font=ui_font(11, "bold"), width=3,
                     height=2).pack(side="left", padx=(10, 10), pady=10)
            txt = tk.Frame(card, bg=CARD)
            txt.pack(side="left", fill="x", expand=True, pady=8)
            tk.Label(txt, text=st["title"], bg=CARD, fg=NAVY, font=ui_font(10, "bold"), anchor="w").pack(fill="x")
            tk.Label(txt, text=st["detail"], bg=CARD, fg=GREY, font=ui_font(9), anchor="w").pack(fill="x")
            ttk.Button(card, text=f"{st['tab']}  >", style="Go.TButton",
                       command=lambda t=st["tab"]: self.go(t)).pack(side="right", padx=10)
        if nxt:
            self.next_label.configure(text=f"Next step:  {nxt['title']}  -  {nxt['detail']}")
            self.next_btn.configure(command=lambda: self.go(nxt["tab"]), state="normal")
        else:
            self.next_label.configure(text="All steps complete - keep training and measuring to grow Cortex.")
            self.next_btn.configure(command=lambda: self.go("Train"))

    # =============================================================== SETUP
    def build_setup(self):
        p = self.pages["Setup"]
        ttk.Label(p, text="Step 1 - Set up your local AI model", style="H1.TLabel").pack(anchor="w")
        self.setup_state = ttk.Label(p, text="Checking...", font=ui_font(11, "bold"))
        self.setup_state.pack(anchor="w", pady=(2, 10))

        row = ttk.Frame(p, style="Page.TFrame"); row.pack(fill="x")
        b1 = ttk.Button(row, text="Check my setup", style="Accent.TButton",
                        command=lambda: self.run("doctor", ["doctor"], self.setup_con, done=lambda rc: self._check_ollama()))
        b2 = ttk.Button(row, text="Download / update model",
                        command=lambda: self.run("doctor", ["doctor", "--pull"], self.setup_con,
                                                 done=lambda rc: self._check_ollama(), label="Downloading model..."))
        b3 = ttk.Button(row, text="Install Ollama", command=self._install_ollama)
        b4 = ttk.Button(row, text="Ollama website", command=lambda: webbrowser.open("https://ollama.com/download"))
        b5 = ttk.Button(row, text="Test the sandbox",
                        command=lambda: self.run("sandbox", ["check-sandbox"], self.setup_con, label="Testing sandbox..."))
        for b in (b1, b2, b5, b3, b4):
            b.pack(side="left", padx=(0, 8))
        self._reg([b1, b2, b3, b5])

        lf = ttk.LabelFrame(p, text="Model choice", padding=10)
        lf.pack(fill="x", pady=12)
        ram = total_ram_gb()
        rec, size = recommend_model(ram)
        ttk.Label(lf, text=f"This PC has {f'{ram:.0f} GB' if ram else 'unknown'} RAM - recommended: {rec} ({size}). "
                           "Bigger models are smarter but slower.", style="Muted.TLabel").grid(row=0, column=0, columnspan=6, sticky="w")
        ttk.Label(lf, text="Provider").grid(row=1, column=0, sticky="w", pady=(8, 0))
        self.prov_var = tk.StringVar(value=self.cfg.provider)
        ttk.Combobox(lf, textvariable=self.prov_var, values=["ollama", "openai", "anthropic"], width=12,
                     state="readonly").grid(row=1, column=1, sticky="w", padx=6, pady=(8, 0))
        ttk.Label(lf, text="Model").grid(row=1, column=2, sticky="w", pady=(8, 0))
        self.model_var = tk.StringVar(value=self.cfg.model)
        ttk.Combobox(lf, textvariable=self.model_var, width=28,
                     values=[m for _, m, _ in MODEL_LADDER] + ["qwen2.5-coder:32b", "qwen3-coder"]
                     ).grid(row=1, column=3, sticky="w", padx=6, pady=(8, 0))
        bs = ttk.Button(lf, text="Use this model", command=self._save_model)
        bs.grid(row=1, column=4, padx=6, pady=(8, 0))
        ttk.Label(lf, text="ollama = free & local (default)   openai = LM Studio or similar local server   "
                           "anthropic = Claude API (needs a key)", style="Muted.TLabel").grid(row=2, column=0, columnspan=6, sticky="w", pady=(6, 0))

        ttk.Label(p, text="Output", style="H2.TLabel").pack(anchor="w")
        self.setup_con = Console(p, height=16)
        self.setup_con.pack(fill="both", expand=True)

    def _save_model(self):
        prov, model = self.prov_var.get(), self.model_var.get().strip()
        if not model:
            return
        if prov != self.cfg.provider and model == self.cfg.model:
            model = DEFAULT_MODELS[prov]
            self.model_var.set(model)
        self.cfg.provider, self.cfg.model = prov, model
        self.cfg.save_settings(provider=prov, model=model)
        self.setup_con.write(f"Saved: provider={prov}, model={model}")
        if prov == "ollama":
            self.run("doctor", ["doctor", "--pull"], self.setup_con, done=lambda rc: self._check_ollama(),
                     label="Downloading model...")
        else:
            self._check_ollama()

    def _install_ollama(self):
        if os.name != "nt":
            webbrowser.open("https://ollama.com/download")
            return
        if not messagebox.askyesno("Install Ollama", "Install Ollama (free, about 1.5 GB) using Windows winget?\n\n"
                                                     "Windows may ask for permission."):
            return
        self.setup_con.write("$ winget install --id Ollama.Ollama -e")

        def work():
            import subprocess
            try:
                p = subprocess.run(["winget", "install", "--id", "Ollama.Ollama", "-e",
                                    "--accept-package-agreements", "--accept-source-agreements"],
                                   capture_output=True, text=True, errors="replace",
                                   creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                out = (p.stdout or "") + (p.stderr or "")
            except FileNotFoundError:
                out = "winget not found. Use the 'Ollama website' button to download the installer."
            self.after(0, lambda: [self.setup_con.write(l) for l in out.splitlines()[-15:] if l.strip()])
            self.after(0, lambda: self.setup_con.write("Now open Ollama from the Start menu, then click 'Download / update model'."))
        threading.Thread(target=work, daemon=True).start()

    # =============================================================== TRAIN
    def build_train(self):
        p = self.pages["Train"]
        ttk.Label(p, text="Steps 2 & 4 - Practise and learn", style="H1.TLabel").pack(anchor="w")
        ttk.Label(p, text="Each round (generation) works through tasks it hasn't mastered yet, plus one revision task. "
                          "Everything it learns is saved as it goes, so stopping is always safe.",
                  style="Muted.TLabel", wraplength=1050).pack(anchor="w", pady=(2, 10))
        top = ttk.Frame(p, style="Page.TFrame"); top.pack(fill="x")

        lf = ttk.LabelFrame(top, text="Train", padding=10)
        lf.pack(side="left", fill="y")
        ttk.Label(lf, text="Rounds").grid(row=0, column=0, sticky="w")
        self.rounds = tk.IntVar(value=1)
        ttk.Spinbox(lf, from_=1, to=50, textvariable=self.rounds, width=5).grid(row=0, column=1, sticky="w", padx=6)
        ttk.Label(lf, text="Area").grid(row=0, column=2, sticky="w", padx=(10, 0))
        self.train_dom = tk.StringVar(value="All areas")
        ttk.Combobox(lf, textvariable=self.train_dom, values=list(DOMAIN_LABELS), width=18,
                     state="readonly").grid(row=0, column=3, sticky="w", padx=6)
        ttk.Label(lf, text="Attempts per task").grid(row=1, column=0, sticky="w", pady=(8, 0))
        self.attempts = tk.IntVar(value=4)
        ttk.Spinbox(lf, from_=1, to=8, textvariable=self.attempts, width=5).grid(row=1, column=1, sticky="w", padx=6, pady=(8, 0))
        ttk.Label(lf, text="Max model calls").grid(row=1, column=2, sticky="w", padx=(10, 0), pady=(8, 0))
        self.max_calls = tk.IntVar(value=300)
        ttk.Spinbox(lf, from_=10, to=5000, increment=50, textvariable=self.max_calls, width=8).grid(row=1, column=3, sticky="w", padx=6, pady=(8, 0))
        bt = ttk.Frame(lf, style="Page.TFrame"); bt.grid(row=2, column=0, columnspan=4, sticky="w", pady=(10, 0))
        start = ttk.Button(bt, text="Start training", style="Accent.TButton", command=self._start_train)
        stop = ttk.Button(bt, text="Stop", style="Danger.TButton", command=lambda: (self.stop("train"), self.stop("solve")), state="disabled")
        start.pack(side="left"); stop.pack(side="left", padx=8)

        lf2 = ttk.LabelFrame(top, text="Try a single task (step 2)", padding=10)
        lf2.pack(side="left", fill="both", expand=True, padx=(12, 0))
        self.task_var = tk.StringVar(value="coding.merge_intervals")
        self.task_box = ttk.Combobox(lf2, textvariable=self.task_var, width=34, state="readonly")
        self.task_box.grid(row=0, column=0, sticky="w")
        self.show_code = tk.BooleanVar(value=True)
        ttk.Checkbutton(lf2, text="Show the final code", variable=self.show_code).grid(row=0, column=1, padx=10)
        solve = ttk.Button(lf2, text="Solve this task", style="Accent.TButton", command=self._solve)
        solve.grid(row=1, column=0, sticky="w", pady=(10, 0))
        ttk.Label(lf2, text="Time guide: a local 7B model takes ~20-90 s per attempt.",
                  style="Muted.TLabel").grid(row=2, column=0, columnspan=2, sticky="w", pady=(8, 0))
        self._reg([start, solve], stop=("train", stop))
        self._stop_buttons["solve"] = stop

        self.train_info = ttk.Label(p, text="", style="H2.TLabel")
        self.train_info.pack(anchor="w", pady=(10, 4))
        self.train_con = Console(p, height=18)
        self.train_con.pack(fill="both", expand=True)

    def refresh_train(self):
        try:
            ids = be.task_ids(self.home)
            self.task_box.configure(values=ids)
        except Exception:
            pass

    def _start_train(self):
        args = ["train", "--rounds", str(self.rounds.get()), "--attempts", str(self.attempts.get()),
                "--max-calls", str(self.max_calls.get())]
        d = DOMAIN_LABELS[self.train_dom.get()]
        if d:
            args += ["--domain", d]
        be.bump_usage(self.home, f"train:{d or 'all'}")
        self._train_stats = {"done": 0, "solved": 0}
        self.train_info.configure(text="Starting...")
        self.run("train", args, self.train_con, label="Training...", done=lambda rc: self.refresh_all())

    def _train_progress(self, line):
        st = getattr(self, "_train_stats", None)
        if st is None:
            return
        if line.startswith("=== generation"):
            st["gen"] = line.strip("= ")
        if line.strip().startswith("-> "):
            st["done"] += 1
            st["solved"] += "SOLVED" in line
        self.train_info.configure(text=f"{st.get('gen', '')}   |   tasks finished: {st['done']}   solved: {st['solved']}")

    def _solve(self):
        args = ["solve", self.task_var.get(), "--attempts", str(self.attempts.get())]
        if self.show_code.get():
            args.append("--show")
        self._train_stats = None
        self.train_info.configure(text=f"Solving {self.task_var.get()}...")
        self.run("solve", args, self.train_con, label="Solving task...", done=lambda rc: self.refresh_all())

    # ============================================================ PROGRESS
    def build_progress(self):
        p = self.pages["Progress"]
        ttk.Label(p, text="Steps 3 & 5 - Measure progress", style="H1.TLabel").pack(anchor="w")
        ttk.Label(p, text="Evaluations score Cortex with hidden tests while its memory is read-only. "
                          "Train = retention of practised skills; Holdout = transfer to problems it has never practised.",
                  style="Muted.TLabel", wraplength=1050).pack(anchor="w", pady=(2, 8))
        row = ttk.Frame(p, style="Page.TFrame"); row.pack(fill="x")
        ttk.Label(row, text="Tasks").pack(side="left")
        self.ev_split = tk.StringVar(value="all")
        for v, t in (("all", "All 16"), ("holdout", "Holdout only (quick)"), ("train", "Train only")):
            ttk.Radiobutton(row, text=t, value=v, variable=self.ev_split).pack(side="left", padx=6)
        ttk.Label(row, text="Area").pack(side="left", padx=(12, 4))
        self.ev_dom = tk.StringVar(value="All areas")
        ttk.Combobox(row, textvariable=self.ev_dom, values=list(DOMAIN_LABELS), width=18, state="readonly").pack(side="left")
        start = ttk.Button(row, text="Run evaluation", style="Accent.TButton", command=self._start_eval)
        stop = ttk.Button(row, text="Stop", style="Danger.TButton", command=lambda: self.stop("eval"), state="disabled")
        start.pack(side="left", padx=(14, 6)); stop.pack(side="left")
        pub = ttk.Button(row, text="Publish to iPhone", command=lambda: self.run(
            "publish", ["publish"], self.eval_con, label="Publishing to GitHub..."))
        pub.pack(side="right")
        self._reg([start, pub], stop=("eval", stop))

        mid = ttk.Frame(p, style="Page.TFrame"); mid.pack(fill="both", expand=True, pady=(10, 0))
        left = ttk.Frame(mid, style="Page.TFrame"); left.pack(side="left", fill="both", expand=True)
        ttk.Label(left, text="Learning curve", style="H2.TLabel").pack(anchor="w")
        self.chart = tk.Canvas(left, bg="white", height=250, highlightthickness=1, highlightbackground="#D5DFE2")
        self.chart.pack(fill="both", expand=True)
        self.chart.bind("<Configure>", lambda e: self._draw_chart())
        right = ttk.Frame(mid, style="Page.TFrame"); right.pack(side="left", fill="both", padx=(12, 0))
        ttk.Label(right, text="What the numbers mean", style="H2.TLabel").pack(anchor="w")
        for t in ("Train rising: it keeps what it practises.",
                  "Holdout rising: learning transfers to new problems - the best sign.",
                  "Train high, holdout flat: it memorises. Add varied tasks (Teach tab).",
                  "Scores wobble between runs: normal - watch the trend."):
            ttk.Label(right, text="• " + t, wraplength=300, style="Muted.TLabel").pack(anchor="w", pady=2)

        ttk.Label(p, text="All evaluations", style="H2.TLabel").pack(anchor="w", pady=(10, 2))
        self.prog_frame = ttk.Frame(p, style="Page.TFrame")
        self.prog_frame.pack(fill="x")
        self.prog_tree_frame, self.prog_tree = make_tree(self.prog_frame, ["Run"], [160], height=5)
        self.prog_tree_frame.pack(fill="x")
        self.eval_con = Console(p, height=7)
        self.eval_con.pack(fill="both", pady=(8, 0))
        self._prog_runs = []

    def _start_eval(self):
        args = ["eval", "--split", self.ev_split.get(), "--attempts", str(self.attempts.get()),
                "--max-calls", str(self.max_calls.get())]
        d = DOMAIN_LABELS[self.ev_dom.get()]
        if d:
            args += ["--domain", d]
        self.run("eval", args, self.eval_con, label="Evaluating...", done=lambda rc: self.refresh_all())

    def refresh_progress(self):
        cols, runs = be.progress_rows(self.home)
        self._prog_runs = runs
        self.prog_tree_frame.destroy()
        nice = {"coding": "Coding", "cyber": "Cyber", "bigdata": "Big data", "threat": "Threat"}
        names = ["When", "Gen"] + [f"{c.split('/')[0].title()}: {nice.get(c.split('/')[1], c.split('/')[1])}"
                                   for c in cols] + ["Overall"]
        widths = [95, 40] + [126] * len(cols) + [70]
        self.prog_tree_frame, self.prog_tree = make_tree(self.prog_frame, names, widths, height=5)
        self.prog_tree_frame.pack(fill="x")
        rows = []
        for d in reversed(runs):
            when = datetime.fromtimestamp(d["ts"]).strftime("%d %b %H:%M")
            rows.append([when, d["gen"]] + [("-" if d["cells"].get(c) is None else f"{d['cells'][c]:.0%}") for c in cols]
                        + [f"{d['overall']:.0%}"])
        fill_tree(self.prog_tree, rows)
        self._draw_chart()

    def _draw_chart(self):
        c = self.chart
        c.delete("all")
        w, h = max(c.winfo_width(), 300), max(c.winfo_height(), 200)
        L, R, T, B = 48, 20, 20, 42
        runs = self._prog_runs
        for i in range(0, 101, 25):
            y = T + (h - T - B) * (1 - i / 100)
            c.create_line(L, y, w - R, y, fill="#E5ECEE")
            c.create_text(L - 8, y, text=f"{i}%", anchor="e", fill=GREY, font=ui_font(8))
        if not runs:
            c.create_text(w / 2, h / 2, text="No evaluations yet - click 'Run evaluation' to take a baseline.",
                          fill=GREY, font=ui_font(10))
            return
        n = len(runs)
        xs = [L + (w - L - R) * (i / max(n - 1, 1)) if n > 1 else (L + w - R) / 2 for i in range(n)]
        series = [("overall", NAVY, "Overall"), ("train", TEAL, "Train (retention)"), ("holdout", AMBER, "Holdout (transfer)")]
        for key, col, label in series:
            pts = [(x, T + (h - T - B) * (1 - d[key])) for x, d in zip(xs, runs) if d.get(key) is not None]
            if len(pts) > 1:
                c.create_line(*[v for pt in pts for v in pt], fill=col, width=2.5, smooth=False)
            for x, y in pts:
                c.create_oval(x - 4, y - 4, x + 4, y + 4, fill=col, outline="white")
        for x, d in zip(xs, runs):
            c.create_text(x, h - B + 12, text=f"gen {d['gen']}", fill=GREY, font=ui_font(8))
        lx = L
        for _, col, label in series:
            c.create_rectangle(lx, h - 14, lx + 10, h - 4, fill=col, outline=col)
            c.create_text(lx + 14, h - 9, text=label, anchor="w", fill=INK, font=ui_font(8))
            lx += 150

    # ====================================================== SKILLS & MEMORY
    def build_memory(self):
        p = self.pages["Skills & Memory"]
        top = ttk.Frame(p, style="Page.TFrame"); top.pack(fill="x")
        ttk.Label(top, text="Step 6 - Explore what Cortex knows", style="H1.TLabel").pack(side="left")
        ttk.Button(top, text="Refresh", command=self.refresh_memory).pack(side="right")
        pw = ttk.PanedWindow(p, orient="horizontal"); pw.pack(fill="both", expand=True, pady=(8, 0))
        left = ttk.Frame(pw, style="Page.TFrame")
        ttk.Label(left, text="Skills (verified code it can reuse)", style="H2.TLabel").pack(anchor="w")
        f, self.skill_tree = make_tree(left, ["Skill", "Area", "Trust", "Successes", "Used"], [170, 70, 110, 82, 50], height=12)
        f.pack(fill="both", expand=True)
        self.skill_tree.bind("<<TreeviewSelect>>", self._show_skill)
        right = ttk.Frame(pw, style="Page.TFrame")
        hdr = ttk.Frame(right, style="Page.TFrame"); hdr.pack(fill="x")
        self.skill_title = ttk.Label(hdr, text="Select a skill to see its code", style="H2.TLabel")
        self.skill_title.pack(side="left")
        ttk.Button(hdr, text="Copy code", command=self._copy_skill).pack(side="right")
        self.skill_code = tk.Text(right, font=MONO, wrap="none", height=12, bg="#FBFCFD", relief="solid", borderwidth=1)
        self.skill_code.pack(fill="both", expand=True)
        pw.add(left, weight=1); pw.add(right, weight=1)

        inner = ttk.Notebook(p); inner.pack(fill="both", expand=True, pady=(10, 0))
        specs = {"Lessons": (["Area", "Used", "Lesson"], [80, 50, 900]),
                 "Knowledge graph": (["Subject", "Relation", "Object", "From task"], [220, 160, 300, 200]),
                 "Episodes (history)": (["When", "Task", "Mode", "Result", "Attempts", "Tokens"], [140, 230, 70, 70, 70, 80])}
        self.mem_trees = {}
        for name, (cols, widths) in specs.items():
            fr = ttk.Frame(inner, padding=4)
            tf, tree = make_tree(fr, cols, widths, height=7)
            tf.pack(fill="both", expand=True)
            inner.add(fr, text=f"  {name}  ")
            self.mem_trees[name] = tree

    def refresh_memory(self):
        self._skills = {s.name: s for s in be.skills_rows(self.home)}
        fill_tree(self.skill_tree, [(s.name, s.domain, s.trust, s.successes, s.uses) for s in self._skills.values()],
                  tags_fn=lambda r: ["self"] if r[2] == "self-tested" else [])
        self.skill_tree.tag_configure("self", foreground=AMBER)
        m = be.memory_rows(self.home)
        fill_tree(self.mem_trees["Lessons"], m["lessons"])
        fill_tree(self.mem_trees["Knowledge graph"], m["knowledge"])
        fill_tree(self.mem_trees["Episodes (history)"], m["episodes"],
                  tags_fn=lambda r: ["fail"] if r[3] == "failed" else [])
        self.mem_trees["Episodes (history)"].tag_configure("fail", foreground=RED)

    def _show_skill(self, _=None):
        sel = self.skill_tree.selection()
        if not sel:
            return
        name = self.skill_tree.item(sel[0])["values"][0]
        s = self._skills.get(name)
        if not s:
            return
        self.skill_title.configure(text=f"{s.name}  (v{s.version}, {s.trust})")
        self.skill_code.delete("1.0", "end")
        self.skill_code.insert("1.0", f"# {s.description}\n\n{s.code}")

    def _copy_skill(self):
        self.clipboard_clear()
        self.clipboard_append(self.skill_code.get("1.0", "end-1c"))
        self.set_status("Code copied to clipboard")

    # =============================================================== TEACH
    def build_teach(self):
        p = self.pages["Teach"]
        ttk.Label(p, text="Step 7 - Teach Cortex something new", style="H1.TLabel").pack(anchor="w")
        nb = ttk.Notebook(p); nb.pack(fill="both", expand=True, pady=(8, 0))

        # --- learn from description
        a = ttk.Frame(nb, padding=12); nb.add(a, text="  Learn from a description  ")
        ttk.Label(a, text="Describe the ability in plain English. Cortex writes its own tests, then the code, and saves it "
                          "as a 'self-tested' skill (check it before relying on it).", style="Muted.TLabel",
                  wraplength=1000).grid(row=0, column=0, columnspan=4, sticky="w")
        ttk.Label(a, text="Function name").grid(row=1, column=0, sticky="w", pady=(10, 0))
        self.learn_name = tk.StringVar(value="login_storm")
        ttk.Entry(a, textvariable=self.learn_name, width=28).grid(row=1, column=1, sticky="w", padx=6, pady=(10, 0))
        ttk.Label(a, text="Area").grid(row=1, column=2, sticky="w", pady=(10, 0))
        self.learn_dom = tk.StringVar(value="Cyber security")
        ttk.Combobox(a, textvariable=self.learn_dom, values=list(DOMAIN_LABELS)[1:], width=18,
                     state="readonly").grid(row=1, column=3, sticky="w", padx=6, pady=(10, 0))
        ttk.Label(a, text="Description").grid(row=2, column=0, sticky="nw", pady=(10, 0))
        self.learn_spec = tk.Text(a, height=6, wrap="word", font=ui_font(10), relief="solid", borderwidth=1)
        self.learn_spec.grid(row=2, column=1, columnspan=3, sticky="nsew", padx=6, pady=(10, 0))
        self.learn_spec.insert("1.0", "Given a list of failed-login timestamps in seconds, return True if 10 or more "
                                      "fall within any 60-second window, otherwise False.")
        lb = ttk.Button(a, text="Learn it", style="Accent.TButton", command=self._learn)
        lb.grid(row=3, column=1, sticky="w", padx=6, pady=10)
        pk = ttk.Button(a, text="Add automotive task pack (CAS OBD)", command=lambda: self.run(
            "pack", ["add-pack", "automotive"], self.teach_con, label="Adding task pack...",
            done=lambda rc: (self.refresh_teach(), self.refresh_train(), self.refresh_home())))
        pk.grid(row=3, column=2, columnspan=2, sticky="w", padx=6, pady=10)
        self._reg([lb, pk])
        a.columnconfigure(3, weight=1); a.rowconfigure(4, weight=1)
        self.teach_con = Console(a, height=10)
        self.teach_con.grid(row=4, column=0, columnspan=4, sticky="nsew")

        # --- add a practice task
        b = ttk.Frame(nb, padding=12); nb.add(b, text="  Add a practice task  ")
        ttk.Label(b, text="Permanently grow the curriculum. Example tests are shown to Cortex; hidden tests are used only "
                          "for scoring. Separate tests with a blank line.", style="Muted.TLabel",
                  wraplength=1000).grid(row=0, column=0, columnspan=6, sticky="w")
        self.t_vars = {k: tk.StringVar() for k in ("id", "title", "entry_point")}
        self.t_vars["id"].set("cyber.jwt_expiry")
        self.t_vars["title"].set("JWT expiry check")
        self.t_vars["entry_point"].set("jwt_expired")
        for i, (k, lab) in enumerate((("id", "Task ID"), ("title", "Title"), ("entry_point", "Function name"))):
            ttk.Label(b, text=lab).grid(row=1, column=i * 2, sticky="w", pady=(10, 0))
            ttk.Entry(b, textvariable=self.t_vars[k], width=24).grid(row=1, column=i * 2 + 1, sticky="w", padx=6, pady=(10, 0))
        ttk.Label(b, text="Area").grid(row=2, column=0, sticky="w", pady=(8, 0))
        self.t_dom = tk.StringVar(value="Cyber security")
        ttk.Combobox(b, textvariable=self.t_dom, values=list(DOMAIN_LABELS)[1:], width=20, state="readonly").grid(row=2, column=1, sticky="w", padx=6, pady=(8, 0))
        ttk.Label(b, text="Use for").grid(row=2, column=2, sticky="w", pady=(8, 0))
        self.t_split = tk.StringVar(value="train")
        ttk.Combobox(b, textvariable=self.t_split, values=["train", "holdout"], width=10, state="readonly").grid(row=2, column=3, sticky="w", padx=6, pady=(8, 0))

        def box(r, label, h, text):
            ttk.Label(b, text=label).grid(row=r, column=0, sticky="nw", pady=(8, 0))
            t = tk.Text(b, height=h, wrap="word", font=MONO, relief="solid", borderwidth=1)
            t.grid(row=r, column=1, columnspan=5, sticky="nsew", padx=6, pady=(8, 0))
            t.insert("1.0", text)
            return t
        self.t_prompt = box(3, "Specification", 3, "Write jwt_expired(exp: int, now: int) -> bool. Return True when the "
                                                  "token's exp (Unix seconds) is at or before now.")
        self.t_visible = box(4, "Example tests", 2, "assert jwt_expired(100, 200) is True")
        self.t_hidden = box(5, "Hidden tests", 3, "assert jwt_expired(300, 200) is False\n\nassert jwt_expired(200, 200) is True")
        ttk.Button(b, text="Save task", style="Accent.TButton", command=self._save_task).grid(row=6, column=1, sticky="w", padx=6, pady=10)
        b.columnconfigure(5, weight=1); b.rowconfigure(7, weight=1)
        lf = ttk.LabelFrame(b, text="Your tasks", padding=6)
        lf.grid(row=7, column=0, columnspan=6, sticky="nsew")
        tf, self.custom_tree = make_tree(lf, ["Task ID", "Area", "Use for", "File"], [240, 100, 90, 300], height=4)
        tf.pack(fill="both", expand=True)
        ttk.Button(lf, text="Delete selected", command=self._delete_task).pack(anchor="e", pady=(6, 0))

    def refresh_teach(self):
        fill_tree(self.custom_tree, be.custom_tasks(self.home))

    def _learn(self):
        name = self.learn_name.get().strip()
        spec = self.learn_spec.get("1.0", "end").strip()
        if not name.isidentifier():
            messagebox.showwarning("Learn", "Function name must be a valid Python name, e.g. login_storm")
            return
        if len(spec) < 15:
            messagebox.showwarning("Learn", "Please write a fuller description.")
            return
        spec_file = self.home / "last_spec.txt"
        spec_file.write_text(spec, encoding="utf-8")
        be.bump_usage(self.home, f"learn:{DOMAIN_LABELS[self.learn_dom.get()]}")
        self.run("learn", ["learn", f"@{spec_file}", "--name", name, "--domain",
                           DOMAIN_LABELS[self.learn_dom.get()], "--attempts", str(self.attempts.get())],
                 self.teach_con, label="Learning...", done=lambda rc: self.refresh_all())

    def _save_task(self):
        d = {"id": self.t_vars["id"].get().strip(), "domain": DOMAIN_LABELS[self.t_dom.get()],
             "split": self.t_split.get(), "title": self.t_vars["title"].get().strip(),
             "entry_point": self.t_vars["entry_point"].get().strip(),
             "prompt": self.t_prompt.get("1.0", "end").strip(),
             "visible_tests": be.split_tests(self.t_visible.get("1.0", "end")),
             "hidden_tests": be.split_tests(self.t_hidden.get("1.0", "end"))}
        try:
            path = be.save_task(self.home, d)
        except ValueError as e:
            messagebox.showwarning("Please fix", str(e))
            return
        messagebox.showinfo("Saved", f"Task saved to {path.name}.\nIt will be used next time you train or evaluate.")
        self.refresh_teach(); self.refresh_train(); self.refresh_home()

    def _delete_task(self):
        sel = self.custom_tree.selection()
        if not sel:
            return
        fname = self.custom_tree.item(sel[0])["values"][3]
        if messagebox.askyesno("Delete task", f"Delete {fname}? Skills already learned from it are kept."):
            (load_config(self.home).tasks_dir / fname).unlink(missing_ok=True)
            self.refresh_teach(); self.refresh_train()

    # ============================================================= MONITOR
    def build_monitor(self):
        p = self.pages["Threat Monitor"]
        ttk.Label(p, text="Step 8 - Real-time threat, risk and harm monitor", style="H1.TLabel").pack(anchor="w")
        lf = ttk.LabelFrame(p, text="Source and options", padding=10)
        lf.pack(fill="x", pady=(8, 0))
        ttk.Label(lf, text="Log file").grid(row=0, column=0, sticky="w")
        self.mon_file = tk.StringVar(value=str(be.APP_DIR / "examples" / "sample_auth.log"))
        ttk.Entry(lf, textvariable=self.mon_file, width=70).grid(row=0, column=1, columnspan=3, sticky="we", padx=6)
        ttk.Button(lf, text="Browse...", command=self._browse_log).grid(row=0, column=4)
        ttk.Button(lf, text="Sample: SSH log", command=lambda: self.mon_file.set(str(be.APP_DIR / "examples" / "sample_auth.log"))).grid(row=0, column=5, padx=4)
        ttk.Button(lf, text="Sample: events", command=lambda: self.mon_file.set(str(be.APP_DIR / "examples" / "events.jsonl"))).grid(row=0, column=6)
        hng = ttk.Frame(lf, style="Page.TFrame")
        hng.grid(row=4, column=0, columnspan=7, sticky="w", pady=(10, 0))
        ttk.Label(hng, text="CAS HomeNet Guard:", font=ui_font(10, "bold")).pack(side="left", padx=(0, 8))
        ttk.Button(hng, text="Watch its alerts live", style="Accent.TButton", command=self._use_homenet).pack(side="left")
        ttk.Button(hng, text="Sample: HomeNet Guard", command=lambda: self.mon_file.set(
            str(be.APP_DIR / "examples" / "homenet_guard_alerts.jsonl"))).pack(side="left", padx=8)
        ttk.Button(hng, text="Copy log for iPhone...", command=self._copy_for_iphone).pack(side="left")
        obd = ttk.Frame(lf, style="Page.TFrame")
        obd.grid(row=5, column=0, columnspan=7, sticky="w", pady=(8, 0))
        ttk.Label(obd, text="CAS OBD Scanner:", font=ui_font(10, "bold")).pack(side="left", padx=(0, 8))
        ttk.Button(obd, text="Open OBD export...", style="Accent.TButton", command=self._open_obd).pack(side="left")
        for label, fname in (("Sample: test report", "cas-obd-test-report.csv"), ("Sample: car health", "health-WVWZZZAWZHY123456.json"),
                             ("Sample: data log", "obd-log-2026-11-17-07-40-00.csv"), ("Sample: fault codes", "fault-codes.txt")):
            ttk.Button(obd, text=label, command=lambda f=fname: self._obd_sample(f)).pack(side="left", padx=(8, 0))
        self.mon_opts = {k: tk.BooleanVar(value=v) for k, v in (("follow", False), ("from_start", True),
                                                                ("use_learned", False), ("triage", False))}
        labels = {"follow": "Keep watching (live)", "from_start": "Include existing lines",
                  "use_learned": "Use learned detectors", "triage": "AI triage of P1/P2 (slower)"}
        opts = ttk.Frame(lf, style="Page.TFrame")
        opts.grid(row=1, column=0, columnspan=7, sticky="w", pady=(8, 0))
        for k in self.mon_opts:
            ttk.Checkbutton(opts, text=labels[k], variable=self.mon_opts[k]).pack(side="left", padx=(0, 18))
        ttk.Label(lf, text="Critical assets").grid(row=2, column=0, sticky="w", pady=(8, 0))
        self.mon_crit = tk.StringVar(value="203.0.113.7=3")
        ttk.Entry(lf, textvariable=self.mon_crit, width=40).grid(row=2, column=1, sticky="w", padx=6, pady=(8, 0))
        ttk.Label(lf, text="e.g. 10.0.0.5=3 FILESERVER01=3 (1 low - 3 critical)", style="Muted.TLabel").grid(row=2, column=2, columnspan=4, sticky="w", pady=(8, 0))
        ttk.Label(lf, text="Brute force: fails").grid(row=3, column=0, sticky="w", pady=(8, 0))
        self.mon_fc, self.mon_fw = tk.IntVar(value=5), tk.IntVar(value=60)
        ttk.Spinbox(lf, from_=2, to=100, textvariable=self.mon_fc, width=5).grid(row=3, column=1, sticky="w", padx=6, pady=(8, 0))
        ttk.Label(lf, text="within seconds").grid(row=3, column=2, sticky="w", pady=(8, 0))
        ttk.Spinbox(lf, from_=5, to=3600, textvariable=self.mon_fw, width=6).grid(row=3, column=3, sticky="w", pady=(8, 0))
        lf.columnconfigure(3, weight=1)

        row = ttk.Frame(p, style="Page.TFrame"); row.pack(fill="x", pady=8)
        self.mon_start = ttk.Button(row, text="Start monitoring", style="Accent.TButton", command=self._start_monitor)
        self.mon_stop = ttk.Button(row, text="Stop", style="Danger.TButton", command=lambda: self.stop("monitor"), state="disabled")
        self.mon_start.pack(side="left"); self.mon_stop.pack(side="left", padx=8)
        ttk.Button(row, text="Clear alerts", command=self._clear_alerts).pack(side="left")
        self.prio_chips = {}
        for pr in ("P4", "P3", "P2", "P1"):
            bg, fg = PRIO[pr]
            l = tk.Label(row, text=f"{pr}: 0", bg=bg, fg=fg, font=ui_font(10, "bold"), padx=12, pady=4)
            l.pack(side="right", padx=3)
            self.prio_chips[pr] = l

        pw = ttk.PanedWindow(p, orient="vertical"); pw.pack(fill="both", expand=True)
        tf = ttk.Frame(pw, style="Page.TFrame")
        f, self.alert_tree = make_tree(tf, ["Priority", "Time", "Alert", "Entity", "Score", "Detail"],
                                       [65, 75, 180, 140, 55, 600], height=9)
        f.pack(fill="both", expand=True)
        for pr, (bg, fg) in PRIO.items():
            self.alert_tree.tag_configure(pr, background=bg, foreground=fg)
        self.alert_tree.bind("<<TreeviewSelect>>", self._alert_detail)
        bottom = ttk.Frame(pw, style="Page.TFrame")
        self.alert_text = tk.Text(bottom, height=5, wrap="word", font=ui_font(10), relief="solid", borderwidth=1, bg="#FBFCFD")
        self.alert_text.pack(fill="both", expand=True, pady=(6, 0))
        self.alert_text.insert("1.0", "Select an alert to see details and the AI assessment (if triage is on).\n\n"
                                      "P1 act now  |  P2 investigate today  |  P3 review when convenient  |  P4 log and monitor")
        fbrow = ttk.Frame(bottom, style="Page.TFrame"); fbrow.pack(fill="x", pady=(4, 0))
        ttk.Label(fbrow, text="Teach Cortex about the selected alert:").pack(side="left")
        for label, verdict in (("Useful", "useful"), ("False alarm", "false_alarm"), ("I acted on it", "acted")):
            ttk.Button(fbrow, text=label, command=lambda v=verdict: self._feedback(v)).pack(side="left", padx=(6, 0))
        self.fb_note = ttk.Label(fbrow, text="", style="Muted.TLabel"); self.fb_note.pack(side="left", padx=10)
        self.mon_con = Console(bottom, height=4)
        self.mon_con.pack(fill="x", pady=(6, 0))
        pw.add(tf, weight=3); pw.add(bottom, weight=1)
        self._alerts = []

    def _obd_sample(self, fname):
        self.mon_file.set(str(be.APP_DIR / "examples" / "obd" / fname))
        self.mon_opts["follow"].set(False)
        self._start_monitor()

    def _open_obd(self):
        f = filedialog.askopenfilename(title="Open a CAS OBD Scanner export (test report, health history, data log or fault codes)",
                                       initialdir=str(Path.home() / "Downloads"),
                                       filetypes=[("OBD exports", "*.csv *.json *.txt"), ("All files", "*.*")])
        if f:
            self.mon_file.set(f)
            self.mon_opts["follow"].set(False)
            self._start_monitor()

    def _use_homenet(self):
        from .realtime import HNG_DEFAULT_PATH
        if not Path(HNG_DEFAULT_PATH).exists():
            messagebox.showwarning("HomeNet Guard", "HomeNet Guard's alert file wasn't found:\n"
                                   f"{HNG_DEFAULT_PATH}\n\nStart CAS HomeNet Guard (it creates the file "
                                   "when it raises its first alert), or use 'Sample: HomeNet Guard' to try it.")
            return
        self.mon_file.set(HNG_DEFAULT_PATH)
        self.mon_opts["follow"].set(True)
        self.mon_opts["from_start"].set(True)
        self._start_monitor()

    def _copy_for_iphone(self):
        import shutil
        src = Path(self.mon_file.get().strip())
        if not src.exists():
            messagebox.showwarning("Copy for iPhone", "Choose a log file first.")
            return
        home = Path.home()
        start = next((d for d in (home / "iCloudDrive", home / "OneDrive", home / "Documents") if d.exists()), home)
        dest = filedialog.asksaveasfilename(title="Save a copy where your iPhone can see it (iCloud Drive or OneDrive)",
                                            initialdir=str(start), initialfile=src.name,
                                            filetypes=[("Log files", "*.jsonl *.log *.txt"), ("All files", "*.*")])
        if dest:
            shutil.copyfile(src, dest)
            messagebox.showinfo("Copied", f"Saved to {dest}.\n\nOn your iPhone: CAS Cortex > Monitor > Open file... "
                                          "and pick it from the Files app.")

    def _browse_log(self):
        f = filedialog.askopenfilename(title="Choose a log file",
                                       filetypes=[("Logs", "*.log *.jsonl *.txt *.json"), ("All files", "*.*")])
        if f:
            self.mon_file.set(f)

    def _start_monitor(self):
        f = self.mon_file.get().strip()
        if not Path(f).exists():
            messagebox.showwarning("Monitor", "That log file doesn't exist.")
            return
        args = ["watch", f, "--fail-count", str(self.mon_fc.get()), "--fail-window", str(self.mon_fw.get())]
        o = {k: v.get() for k, v in self.mon_opts.items()}
        if o["follow"]:
            args.append("--follow")
            if o["from_start"]:
                args.append("--from-start")
        if o["use_learned"]:
            args.append("--use-learned")
        if o["triage"]:
            args.append("--triage")
        crit = self.mon_crit.get().split()
        if crit:
            args += ["--critical"] + crit
        be.bump_usage(self.home, be.monitor_source_key(f))
        apath = self.home / "alerts.jsonl"
        self._monitor_offset = apath.stat().st_size if apath.exists() else 0
        self.run("monitor", args, self.mon_con, exclusive=False, label="Monitoring...",
                 done=lambda rc: (self._read_alerts(), self.refresh_home()))

    def _read_alerts(self):
        apath = self.home / "alerts.jsonl"
        if not apath.exists():
            return
        with apath.open(encoding="utf-8") as fh:
            fh.seek(self._monitor_offset)
            data = fh.read()
            if not data.endswith("\n"):
                data = data[: data.rfind("\n") + 1]
            self._monitor_offset += len(data.encode("utf-8"))
        for line in data.splitlines():
            try:
                a = json.loads(line)
            except json.JSONDecodeError:
                continue
            self._alerts.append(a)
            when = datetime.fromtimestamp(a["ts"]).strftime("%H:%M:%S")
            self.alert_tree.insert("", 0, iid=f"a{len(self._alerts)}",
                                   values=(a["priority"], when, a["kind"], a["entity"], a["score"], a["detail"]),
                                   tags=[a["priority"]])
        counts = {p: 0 for p in PRIO}
        for a in self._alerts:
            counts[a["priority"]] = counts.get(a["priority"], 0) + 1
        for p, l in self.prio_chips.items():
            l.configure(text=f"{p}: {counts[p]}")

    def _feedback(self, verdict):
        from . import feedback as fb
        sel = self.alert_tree.selection()
        if not sel:
            self.fb_note.configure(text="Select an alert first.")
            return
        a = self._alerts[int(sel[0][1:]) - 1]
        fb.add(self.home, a["kind"], a["entity"], verdict)
        n = len(fb.load(self.home))
        self.fb_note.configure(text=f"Saved ({verdict.replace('_', ' ')}). Cortex has {n} piece(s) of feedback.")
        self.set_status("Feedback saved - future alerts like this will be ranked accordingly")

    def _alert_detail(self, _=None):
        sel = self.alert_tree.selection()
        if not sel:
            return
        a = self._alerts[int(sel[0][1:]) - 1]
        advice = {"P1": "Act now.", "P2": "Investigate today.", "P3": "Review when convenient.", "P4": "Log and monitor."}
        txt = (f"{a['priority']}  {a['kind']}  -  {a['entity']}   (risk score {a['score']})\n"
               f"{a['detail']}\nSuggested response: {a.get('advice') or advice[a['priority']]}")
        if a.get("learned"):
            txt += f"\nLearned: {a['learned']}"
        if a.get("assessment"):
            txt += "\n\nAI assessment:\n" + a["assessment"]
        self.alert_text.delete("1.0", "end")
        self.alert_text.insert("1.0", txt)

    def _clear_alerts(self):
        self._alerts = []
        self.alert_tree.delete(*self.alert_tree.get_children())
        for p, l in self.prio_chips.items():
            l.configure(text=f"{p}: 0")

    # ======================================================= LEARN FROM YOU
    def build_learn(self):
        p = self.pages["Learn from You"]
        ttk.Label(p, text="Step 9 - Let Cortex learn from how you use it", style="H1.TLabel").pack(anchor="w")
        ttk.Label(p, text="Everything here is processed on this PC. Your Claude history and alert details are never "
                          "published; the iPhone only receives counts.", style="Muted.TLabel").pack(anchor="w", pady=(2, 8))
        top = ttk.Frame(p, style="Page.TFrame"); top.pack(fill="both", expand=True)

        cl = ttk.LabelFrame(top, text="Your Claude history", padding=10)
        cl.pack(side="left", fill="both", expand=True)
        ttk.Label(cl, text="claude.ai > Settings > Privacy > Export data. When the email arrives, download the "
                           "zip and import it here. Cortex proposes skills from code Claude wrote for you; you "
                           "approve which ones it learns.", wraplength=520, style="Muted.TLabel").pack(anchor="w")
        r = ttk.Frame(cl, style="Page.TFrame"); r.pack(fill="x", pady=6)
        b1 = ttk.Button(r, text="Import Claude export...", style="Accent.TButton", command=self._import_claude)
        b1.pack(side="left")
        self.claude_summary = ttk.Label(r, text="", style="Muted.TLabel"); self.claude_summary.pack(side="left", padx=10)
        tf, self.prop_tree = make_tree(cl, ["ID", "Status", "Area", "Skill", "From conversation"], [95, 75, 70, 150, 260], height=8)
        tf.pack(fill="both", expand=True)
        for st, col in (("approved", GREEN), ("learned", TEAL), ("failed", RED), ("dismissed", GREY)):
            self.prop_tree.tag_configure(st, foreground=col)
        self.prop_tree.bind("<<TreeviewSelect>>", self._show_proposal)
        r2 = ttk.Frame(cl, style="Page.TFrame"); r2.pack(fill="x", pady=(6, 0))
        ttk.Button(r2, text="Approve", command=lambda: self._proposal_status("approve")).pack(side="left")
        ttk.Button(r2, text="Approve all new", command=lambda: self._proposal_status("approve-all")).pack(side="left", padx=6)
        ttk.Button(r2, text="Dismiss", command=lambda: self._proposal_status("dismiss")).pack(side="left")
        b2 = ttk.Button(r2, text="Learn selected now", command=self._learn_proposal)
        b2.pack(side="left", padx=6)
        self.prop_detail = tk.Text(cl, height=4, wrap="word", font=ui_font(9), relief="solid", borderwidth=1, bg="#FBFCFD")
        self.prop_detail.pack(fill="x", pady=(6, 0))

        right = ttk.Frame(top, style="Page.TFrame"); right.pack(side="left", fill="both", padx=(12, 0))
        fbf = ttk.LabelFrame(right, text="Your alert feedback", padding=10); fbf.pack(fill="x")
        self.fb_summary = ttk.Label(fbf, text="", wraplength=420); self.fb_summary.pack(anchor="w")
        rr = ttk.Frame(fbf, style="Page.TFrame"); rr.pack(fill="x", pady=6)
        ttk.Button(rr, text="Import iPhone feedback...", command=self._import_feedback).pack(side="left")
        ttk.Button(rr, text="Reset", command=self._reset_feedback).pack(side="left", padx=6)
        self.fb_learned = tk.Text(fbf, height=5, wrap="word", font=ui_font(9), relief="flat", bg=BG)
        self.fb_learned.pack(fill="x")

        ff = ttk.LabelFrame(right, text="Your focus (learned)", padding=10); ff.pack(fill="x", pady=(10, 0))
        self.focus_canvas = tk.Canvas(ff, width=420, height=110, bg=BG, highlightthickness=0)
        self.focus_canvas.pack(anchor="w")
        self.focus_next = ttk.Label(ff, text="", style="Muted.TLabel"); self.focus_next.pack(anchor="w")

        ap = ttk.LabelFrame(right, text="Nightly autopilot", padding=10); ap.pack(fill="x", pady=(10, 0))
        self.ap_state = ttk.Label(ap, text="", wraplength=420); self.ap_state.pack(anchor="w")
        ra = ttk.Frame(ap, style="Page.TFrame"); ra.pack(fill="x", pady=6)
        b3 = ttk.Button(ra, text="Run autopilot now", style="Accent.TButton",
                        command=lambda: self.run("autopilot", ["autopilot"], self.learn_con, label="Autopilot running...",
                                                 done=lambda rc: self.refresh_all()))
        b3.pack(side="left")
        ttk.Button(ra, text="Turn nightly on", command=lambda: self._autopilot_schedule(True)).pack(side="left", padx=6)
        ttk.Button(ra, text="Turn off", command=lambda: self._autopilot_schedule(False)).pack(side="left")
        self._reg([b1, b2, b3])
        self.learn_con = Console(p, height=6)
        self.learn_con.pack(fill="x", pady=(8, 0))

    def refresh_learn(self):
        from . import autopilot, claude_history as ch, feedback as fb
        props = ch.load_proposals(self.home)
        fill_tree(self.prop_tree, [(x["id"], x["status"], x["domain"], x["name"], x["title"]) for x in props
                                   if x["status"] != "dismissed"], tags_fn=lambda r: [r[1]])
        prof = ch.load_profile(self.home)
        self.claude_summary.configure(text=(f"{prof['conversations']} conversations read" if prof else "Not imported yet"))
        recs = fb.load(self.home)
        cnt = {v: sum(1 for r in recs if r["verdict"] == v) for v in fb.VERDICTS}
        self.fb_summary.configure(text=f"{len(recs)} piece(s): {cnt['useful']} useful, {cnt['false_alarm']} false alarms, "
                                       f"{cnt['acted']} acted on. Mark alerts on the Threat Monitor tab or the iPhone.")
        lines = fb.describe(fb.summarise(recs))
        self.fb_learned.configure(state="normal"); self.fb_learned.delete("1.0", "end")
        self.fb_learned.insert("1.0", "\n".join(lines) or "No adjustments learned yet.")
        self.fb_learned.configure(state="disabled")
        f = autopilot.focus(self.home)
        c = self.focus_canvas; c.delete("all")
        labels = {"coding": "Coding", "cyber": "Cyber", "bigdata": "Big data", "threat": "Threat"}
        for i, d in enumerate(("coding", "cyber", "bigdata", "threat")):
            w = f["weights"].get(d, 0)
            y = 8 + i * 25
            c.create_text(0, y + 7, text=labels[d], anchor="w", font=ui_font(9))
            c.create_rectangle(70, y, 370, y + 14, fill="#DCE6E8", outline="")
            c.create_rectangle(70, y, 70 + 300 * w, y + 14, fill=TEAL, outline="")
            c.create_text(378, y + 7, text=f"{w:.0%}", anchor="w", font=ui_font(9))
        self.focus_next.configure(text="Next autopilot training: " + ", ".join(labels[d] for d in f["next_training"]))
        st = autopilot._state(self.home)
        last = st.get("last_run")
        sched = self._autopilot_installed()
        self.ap_state.configure(text=("Nightly: ON" if sched else "Nightly: off" if sched is False else "Nightly: Windows only")
                                + (f" | last run {datetime.fromtimestamp(last).strftime('%d %b %H:%M')}" if last else " | never run"))

    def _import_claude(self):
        f = filedialog.askopenfilename(title="Choose your Claude data export (.zip)", initialdir=str(Path.home() / "Downloads"),
                                       filetypes=[("Claude export", "*.zip *.json"), ("All files", "*.*")])
        if f:
            self.run("claude", ["import-claude", f], self.learn_con, label="Reading your Claude history...",
                     done=lambda rc: self.refresh_learn())

    def _selected_proposals(self):
        return [self.prop_tree.item(i)["values"][0] for i in self.prop_tree.selection()]

    def _proposal_status(self, action):
        from . import claude_history as ch
        ids = [str(x) for x in self._selected_proposals()]
        if action == "approve-all":
            ch.set_status(self.home, "all-new", "approved")
        elif ids:
            ch.set_status(self.home, ids, "approved" if action == "approve" else "dismissed")
        self.refresh_learn()

    def _show_proposal(self, _=None):
        from . import claude_history as ch
        ids = [str(x) for x in self._selected_proposals()]
        p = next((x for x in ch.load_proposals(self.home) if ids and x["id"] == ids[0]), None)
        self.prop_detail.delete("1.0", "end")
        if p:
            self.prop_detail.insert("1.0", p["spec"] + "\n\nOriginal code:\n" + p["reference_code"][:1500])

    def _learn_proposal(self):
        ids = [str(x) for x in self._selected_proposals()]
        if not ids:
            messagebox.showinfo("Learn", "Select a proposal first.")
            return
        self.run("proposal", ["learn-proposal", ids[0], "--attempts", str(self.attempts.get())], self.learn_con,
                 label="Learning from your Claude history...", done=lambda rc: self.refresh_all())

    def _import_feedback(self):
        start = next((d for d in (Path.home() / "iCloudDrive", Path.home() / "OneDrive", Path.home() / "Downloads")
                      if d.exists()), Path.home())
        f = filedialog.askopenfilename(title="Choose the feedback file sent from your iPhone", initialdir=str(start),
                                       filetypes=[("Cortex feedback", "cortex-feedback-*.json *.json")])
        if f:
            self.run("fbimport", ["feedback", "--import", f], self.learn_con, label="Importing feedback...",
                     done=lambda rc: self.refresh_learn())

    def _reset_feedback(self):
        if messagebox.askyesno("Reset feedback", "Forget everything Cortex learned from your alert feedback?\n"
                                                 "(A backup copy is kept.)"):
            self.run("fbreset", ["feedback", "--reset"], self.learn_con, done=lambda rc: self.refresh_learn())

    def _autopilot_installed(self):
        if os.name != "nt":
            return None
        import subprocess
        r = subprocess.run(["schtasks", "/query", "/tn", "CAS Cortex Autopilot"], capture_output=True,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        return r.returncode == 0

    def _autopilot_schedule(self, on: bool):
        if os.name != "nt":
            messagebox.showinfo("Autopilot", "The nightly schedule uses Windows Task Scheduler.")
            return
        import subprocess
        args = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                str(be.APP_DIR / "install_autopilot.ps1")] + ([] if on else ["-Remove"])
        r = subprocess.run(args, capture_output=True, text=True, errors="replace",
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        self.learn_con.write((r.stdout or r.stderr or "").strip() or ("Done." if r.returncode == 0 else "Failed."))
        self.refresh_learn()

    # ============================================================== SAFETY
    def build_safety(self):
        p = self.pages["Safety"]
        ttk.Label(p, text="Safety controls", style="H1.TLabel").pack(anchor="w")
        ttk.Label(p, text="These sit outside Cortex's reach: it cannot edit, switch off or work around them.",
                  style="Muted.TLabel").pack(anchor="w", pady=(2, 10))
        row = ttk.Frame(p, style="Page.TFrame"); row.pack(fill="x")

        ks = ttk.LabelFrame(row, text="Kill switch", padding=12)
        ks.pack(side="left", fill="both", expand=True)
        self.ks_light = tk.Label(ks, text="", font=ui_font(12, "bold"), fg="white", padx=14, pady=8)
        self.ks_light.pack(anchor="w")
        ttk.Label(ks, text="Engaging it halts training, evaluation and monitoring at their next step.",
                  wraplength=330, style="Muted.TLabel").pack(anchor="w", pady=6)
        b = ttk.Frame(ks, style="Page.TFrame"); b.pack(anchor="w")
        ttk.Button(b, text="Engage", style="Danger.TButton", command=lambda: self._kill(True)).pack(side="left")
        ttk.Button(b, text="Release", command=lambda: self._kill(False)).pack(side="left", padx=8)

        ig = ttk.LabelFrame(row, text="Integrity and audit", padding=12)
        ig.pack(side="left", fill="both", expand=True, padx=12)
        self.ig_label = ttk.Label(ig, text="", wraplength=360, font=ui_font(10, "bold"))
        self.ig_label.pack(anchor="w")
        ttk.Label(ig, text="The scorer, task bank, sandbox and safety code are fingerprinted. Evaluations "
                           "refuse to run if they change. The audit log is a tamper-evident chain.",
                  wraplength=360, style="Muted.TLabel").pack(anchor="w", pady=6)
        b2 = ttk.Frame(ig, style="Page.TFrame"); b2.pack(anchor="w")
        ttk.Button(b2, text="Verify now", style="Accent.TButton", command=self.refresh_safety).pack(side="left")
        ttk.Button(b2, text="Accept file changes...", command=self._relock).pack(side="left", padx=8)

        sb = ttk.LabelFrame(row, text="Always on", padding=12)
        sb.pack(side="left", fill="both", expand=True)
        for t in ("Sandbox: separate, time-limited process; no files, network or system access; secrets removed.",
                  "Budgets: cap on model calls per run (Train tab).",
                  "Read-only evaluation: memory can't change while being measured.",
                  "Equality-faking and result-faking tricks blocked."):
            ttk.Label(sb, text="• " + t, wraplength=330, style="Muted.TLabel").pack(anchor="w", pady=2)

        ttk.Label(p, text="Audit log (newest first)", style="H2.TLabel").pack(anchor="w", pady=(12, 4))
        f, self.audit_tree = make_tree(p, ["Time", "Event", "Details"], [150, 140, 800], height=12)
        f.pack(fill="both", expand=True)

    def refresh_safety(self):
        cfg = load_config(self.home)
        on = cfg.stop_path.exists()
        self.ks_light.configure(text="ENGAGED - Cortex is halted" if on else "Off - Cortex can run",
                                bg=RED if on else GREEN)
        changed = verify_integrity(cfg.integrity_path)
        ok, n, msg = AuditLog(cfg.audit_path).verify()
        if not cfg.integrity_path.exists():
            ig = "Integrity lock: not created yet (made automatically at first evaluation)."
        elif changed:
            ig = "Integrity: CHANGED - " + ", ".join(changed)
        else:
            ig = "Integrity: all protected files unchanged."
        self.ig_label.configure(text=f"{ig}\nAudit: {msg} ({n} entries).",
                                foreground=RED if (changed or not ok) else GREEN)
        fill_tree(self.audit_tree, be.audit_rows(self.home))

    def _kill(self, engage: bool):
        cfg = load_config(self.home)
        audit = AuditLog(cfg.audit_path)
        if engage:
            cfg.stop_path.write_text("stop requested from desktop app\n", encoding="utf-8")
        elif cfg.stop_path.exists():
            cfg.stop_path.unlink()
        audit.write("kill_switch", engaged=engage, via="gui")
        self.refresh_safety(); self.refresh_home()

    def _relock(self):
        cfg = load_config(self.home)
        changed = verify_integrity(cfg.integrity_path)
        if not changed and cfg.integrity_path.exists():
            messagebox.showinfo("Integrity", "Nothing has changed - no action needed.")
            return
        if messagebox.askyesno("Accept changes", "Only do this if YOU changed or updated the protected files "
                                                 "(for example installing a new version of Cortex).\n\n"
                                                 f"Changed: {', '.join(changed) or 'no lock yet'}\n\nAccept them?"):
            lock_integrity(cfg.integrity_path)
            AuditLog(cfg.audit_path).write("integrity_locked", forced=True, via="gui")
            self.refresh_safety()

    # ================================================================ HELP
    def build_help(self):
        p = self.pages["Help"]
        ttk.Label(p, text="Help", style="H1.TLabel").pack(anchor="w")
        row = ttk.Frame(p, style="Page.TFrame"); row.pack(fill="x", pady=(6, 12))
        guide = be.APP_DIR / "docs" / "CAS_Cortex_User_Guide.pdf"
        ttk.Button(row, text="Open the User Guide (PDF)", style="Accent.TButton",
                   command=lambda: be.open_path(guide)).pack(side="left")
        ttk.Button(row, text="Open data folder", command=lambda: be.open_path(self.home)).pack(side="left", padx=8)
        ttk.Button(row, text="Open program folder", command=lambda: be.open_path(be.APP_DIR)).pack(side="left")
        ttk.Button(row, text="iPhone app", command=lambda: webbrowser.open(IPHONE_URL)).pack(side="left", padx=8)
        text = tk.Text(p, wrap="word", font=ui_font(10), relief="flat", bg=BG, padx=4)
        text.pack(fill="both", expand=True)
        text.tag_configure("h", font=ui_font(11, "bold"), foreground=TEAL, spacing1=8)
        text.tag_configure("b", font=ui_font(10, "bold"))
        sections = [
            ("The 8 steps", None),
            ("1  Setup", "Install Ollama and download a model. The header shows green when ready."),
            ("2  Train > Try a single task", "Watch one attempt-test-fix cycle and see the final code."),
            ("3  Progress > Run evaluation", "Take a baseline before training."),
            ("4  Train > Start training", "Practise for one or more rounds. Stop any time - progress is saved."),
            ("5  Progress", "Evaluate again and compare on the learning curve."),
            ("6  Skills & Memory", "Browse skills (and their code), lessons, knowledge and history."),
            ("7  Teach", "Describe a new ability, or add your own practice tasks."),
            ("8  Threat Monitor", "Analyse logs for brute force, compromise, beaconing, impossible travel and "
                                  "malicious commands, ranked P1-P4."),
            ("iPhone", "Progress > Publish to iPhone sends scores, skills and lessons (never alerts or logs) to GitHub. "
                       "On the iPhone open " + IPHONE_URL + " in Safari > Share > Add to Home Screen. "
                       "One-off: run connect_github.bat first."),
            ("Common fixes", None),
            ("Header says 'Ollama offline'", "Open Ollama from the Start menu, then Setup > Check my setup."),
            ("'Model not downloaded'", "Setup > Download / update model."),
            ("Training is slow", "Train one area at a time, or choose a smaller model on the Setup tab."),
            ("'HALTED'", "Safety > Release the kill switch."),
            ("'INTEGRITY' error", "Safety > Accept file changes, only if you updated Cortex yourself."),
            ("PC runs out of memory", "Setup > choose qwen2.5-coder:3b > Use this model."),
            ("Every attempt says '(load error)'", "Read the 'reason:' line under it. Then Setup > Test the sandbox - "
                                                  "if that passes, the model's code is at fault and Cortex will learn; "
                                                  "if it fails, the sandbox needs fixing on this PC."),
        ]
        for title, body in sections:
            if body is None:
                text.insert("end", title + "\n", "h")
            else:
                text.insert("end", title + ":  ", "b")
                text.insert("end", body + "\n")
        text.configure(state="disabled")

    # ============================================================== close
    def _on_close(self):
        running = [k for k, j in self.jobs.items() if j.running()]
        if running and not messagebox.askyesno("Quit", f"Still running: {', '.join(running)}.\n"
                                                       "Stop and quit? (Progress so far is saved.)"):
            return
        for j in self.jobs.values():
            j.stop()
        self.destroy()


def main(home: str | None = None):
    app = CortexApp(Path(home) if home else None)

    def report(exc, val, tb):
        messagebox.showerror("CAS Cortex", f"Something went wrong:\n{val}")
    app.report_callback_exception = report
    app.mainloop()


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else None)
