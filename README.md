# CAS Cortex — self-learning engineering agent (Steps 1 & 2)

CAS Cortex learns four specialisms and gets measurably better at them over time:

| Domain | What it practises |
|---|---|
| `coding` | algorithms, data structures, edge-case-heavy specs |
| `cyber` | defensive security: auth-log brute force, IOC extraction, malicious command lines, CVSS scoring |
| `bigdata` | streaming top-k, reservoir sampling, bounded-memory group-by, rolling anomaly detection |
| `threat` | real-time event correlation, impossible travel, C2 beaconing, risk & harm prioritisation |

It runs on a **free local model on your own PC** (via Ollama — no API key), or optionally Claude via API,
and adds what the model lacks: **persistent memory, a growing skill library, self-correction,
reflection, and honest measurement**.

## How it learns

```
retrieve memory ─► write code ─► run tests in sandbox ─► fix from failures (up to 4x)
       ▲                                                            │
       └──── skills (verified code) ◄── reflect: lessons + knowledge ◄┘
```

* **Episodic memory** – every attempt: task, outcome, attempts, tokens, reflection.
* **Procedural memory** – a *skill library*: code that passed its tests becomes a skill. Later
  solutions can `from skills import detect_bruteforce` and build on it.
* **Semantic memory** – lessons ("sort intervals before merging") and a knowledge graph of
  triples, retrieved by relevance (BM25) into future prompts.
* **Self-correction** – failing test output (including the actual wrong value) goes back to the
  model for a diagnosed retry.
* **Self-generated training data** – `cortex learn` takes a plain-English spec, writes its own
  tests first, then learns the capability (stored as lower-trust `self-tested`).

## How it's measured (and why you can trust the numbers)

Each task has **visible tests** (the agent learns from these) and **hidden tests** (only the
evaluator sees them). `cortex eval` runs with memory **read-only**, so measuring never changes
the agent. Results split into:

* **train** – *retention*: can it still do what it practised?
* **holdout** – *transfer*: does what it learned help on problems it has never practised?

`cortex report` shows the learning curve across generations.

## Governance (the part the agent cannot change)

* **Sandbox** – agent code runs in a separate `python -I` process with a timeout, secrets stripped
  from the environment, an import allowlist, and no file/network/OS access. Memory/CPU limits on
  Linux/macOS. Defining `__eq__` is blocked (a known way to fake `==` tests).
* **Integrity lock** – evaluator, task bank, sandbox and governance code are SHA-256 locked;
  `eval` refuses to run if they change. `cortex lock --force` after *you* review a change.
* **Hash-chained audit log** – `audit.jsonl`; `cortex verify` detects any edit.
* **Budgets** – caps on model calls and tokens per command (`--max-calls`).
* **Kill switch** – `cortex stop` (or create a file named `STOP` in the data folder) halts every
  loop at its next step. `cortex resume` releases it.

The sandbox is defence in depth for your own machine, not a hardened security boundary. Step 3
(self-modification) moves execution into Docker.

## Desktop app

After setup, open **CAS Cortex** from the desktop icon (or Start menu > CAS Solutions, or
double-click `Start CAS Cortex.bat`). One tab per step of the user guide:

| Tab | Step | |
|---|---|---|
| Home | overview | progress cards, your 8-step journey, and a **Next step** button |
| Setup | 1 | check setup, install Ollama, choose/download a model |
| Train | 2, 4 | try a single task; training rounds by area; Stop is always safe |
| Progress | 3, 5 | run evaluations; learning-curve chart and score table |
| Skills & Memory | 6 | skills and their code, lessons, knowledge graph, history |
| Teach | 7 | learn from a description; add practice tasks with a validated form |
| Threat Monitor | 8 | analyse or live-watch logs; colour-coded P1–P4 alerts |
| Safety | – | kill switch, integrity/audit checks, audit log |
| Help | – | open the PDF guide, folders, common fixes |

The app runs the same engine as the command line (`.\cortex gui` also opens it). Full guide:
`docs\CAS_Cortex_User_Guide.pdf`.

## iPhone app

**https://stirlingcraig-cyber.github.io/cas-cortex-/**: open it in Safari, then **Share → Add to Home Screen**.

* **Threat Monitor**: paste or open a log and get P1–P4 alerts. Runs entirely on the phone (a JavaScript
  port of the desktop engine, tested to give identical alerts). Nothing is uploaded.
* **Progress / Skills**: learning curve, scores, skills (with code), lessons and knowledge from your PC.
* **Tools**: run learned skills on the phone (uses Pyodide, downloaded on first use).

Training stays on the PC because it needs the local AI model. To send results to the phone:
1. One-off: double-click **`connect_github.bat`** (installs Git and the GitHub CLI if needed, signs you in,
   links this folder to the repo and turns on GitHub Pages).
2. After training: **Progress tab → Publish to iPhone** (or `.\cortex publish`).

Only learning data is published. **Alerts and log contents are never published**, because the repo is public.

## CAS HomeNet Guard integration

Cortex reads HomeNet Guard's alert file (`C:\ProgramData\CAS Solutions\HomeNetGuard\alerts.jsonl`) directly:

* **Desktop app:** Threat Monitor tab → **Watch its alerts live**. The command-line equivalent is `.\cortex watch --homenet`.
* **iPhone:** Threat Monitor tab → **Copy log for iPhone...**, save it to iCloud Drive or OneDrive, then in the
  iPhone app go to Monitor → **Open file…**.

What Cortex adds:
* Every HomeNet Guard alert gets a P1–P4 rank from its severity, confidence, the type of threat and how important
  the device is (*Critical assets*). Ignored, resolved and info-only alerts are skipped; blocked ones are marked.
* **Multi-signal escalation:** a home device with 3 or more different warning signs within 24 hours (e.g. new
  device + exposed Telnet + beaconing) raises a P1 *Device showing multiple compromise signs*.
* HomeNet Guard's own recommendation is shown as the suggested response.
* Live watching never holds the file open, so HomeNet Guard can keep updating it; rewritten alerts aren't counted twice.

## CAS OBD Scanner integration

Cortex reads the scanner's exports, on the PC or the iPhone, and ranks every problem P1–P4 by the harm it could
cause on the road: airbags, brakes and overheating come above an MOT-only emissions fault.

| Scanner export | Where in CAS OBD Scanner |
|---|---|
| Test report CSV | Tests → *Save as spreadsheet* |
| Car health history JSON | Health → *Export history* (voltage and fuel-trim trends across checks) |
| Data log CSV | Data log → *Download CSV* (overheating, voltage drops, sensor glitches) |
| Fault codes | Type or paste codes such as `P0300 C0035 B0012` |

* **Desktop:** Threat Monitor tab → **Open OBD export...** (or a Sample button). Command line: `.\cortex watch <file>`.
* **iPhone:** Monitor → **Open file…**, or type fault codes into the box → **Analyse**.
* **Teach Cortex car skills:** Teach tab → **Add automotive task pack** (`.\cortex add-pack automotive`). This adds 4
  tasks (decode fault-code bytes, convert live-data bytes, triage codes by harm, summarise a data log); then train.

## Install (Windows) — free, local, no API key

**Easiest:** unzip, open the `cas-cortex` folder, double-click **`setup.bat`**.

The setup script:
1. installs Python 3.12 with winget if needed and creates a `.venv`
2. installs **Ollama** (free local model runner) with winget if needed and starts it
3. checks your RAM, picks a coding model that fits, and downloads it (one-off):

| RAM | Model | Download |
|---|---|---|
| 30 GB+ | qwen2.5-coder:14b | ~9 GB |
| 14 GB+ | qwen2.5-coder:7b | ~4.7 GB |
| 7 GB+ | qwen2.5-coder:3b | ~1.9 GB |
| less | qwen2.5-coder:1.5b | ~1 GB |

4. runs the self-tests
5. creates **CAS Cortex** shortcuts on your desktop and Start menu, and offers to open the app.

Everything then runs on your PC: no account, no API key, no per-use cost, and no code or logs
leave your machine. A GPU makes it faster but isn't required.

Manual equivalent:
```powershell
winget install --id Ollama.Ollama -e
py -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m cortex doctor --pull
```

`.\cortex <command>` (the `cortex.cmd` launcher) is the same as `python -m cortex <command>` using the venv.

**Other model options** (all optional):
* **LM Studio** or any OpenAI-compatible local server: `.\cortex --provider openai --model <name> doctor`
  (default address `http://localhost:1234/v1`; change with `$env:OPENAI_BASE_URL`).
* **Different Ollama model:** `$env:CORTEX_MODEL = "qwen2.5-coder:14b"` then `.\cortex doctor --pull`.
* **Claude API** if you ever get a key: `pip install anthropic`, set `$env:ANTHROPIC_API_KEY`.
  Cortex switches to it automatically.

**What to expect from a local model:** a 7B model on CPU takes roughly 20–90 seconds per attempt,
so `train --rounds 1` over 12 tasks can take 15–40 minutes. It will solve fewer tasks first time
than a large cloud model, so you have more room to improve, and the skill library and lessons make
the biggest difference for smaller models. Use `--domain cyber` (etc.) for shorter sessions.

Data lives in `.\cortex_data` (override with `--home` or `$env:CORTEX_HOME`).

## Quick start

```powershell
python -m cortex doctor                   # check model + setup
python -m cortex eval                     # baseline: generation 0, empty memory
python -m cortex train --rounds 3         # practise; builds skills + lessons
python -m cortex eval                     # measure again
python -m cortex report                   # learning curve
python -m cortex skills                   # what it has learned
python -m cortex skills detect_bruteforce # show one skill's code
python -m cortex memory                   # lessons, knowledge graph, episodes
```

Teach it something new:
```powershell
python -m cortex learn "Return True if a JWT's exp claim (unix seconds) is in the past given now" `
  --name jwt_expired --domain cyber
```

## Real-time threat, risk & harm monitor

```powershell
python -m cortex watch examples\sample_auth.log --critical 203.0.113.7=3
python -m cortex watch examples\events.jsonl
python -m cortex watch C:\logs\auth.log --follow           # live, like tail -f
python -m cortex watch examples\events.jsonl --use-learned --triage
```

* Detects brute force, **brute force followed by a successful login** (escalated to P1), C2
  beaconing, impossible travel and malicious process command lines.
* Every alert is scored likelihood × impact × asset criticality, with harm severity, into P1–P4.
* `--use-learned` swaps in detectors **Cortex has learned and verified** — what it learns becomes
  live capability. `--triage` adds a 3-line LLM assessment (threat / harm / action) to P1–P2 alerts.
* Alerts are also written to `cortex_data\alerts.jsonl`.

Input: sshd auth lines, or JSON lines (`auth_fail`, `auth_ok`, `conn`, `login`, `process`
events — see `cortex/realtime.py`).

## Grow the curriculum

Drop JSON files into `cortex_data\tasks\`:
```json
{"id": "cyber.jwt_exp", "domain": "cyber", "split": "train", "title": "JWT expiry",
 "entry_point": "jwt_expired", "prompt": "…spec…",
 "visible_tests": ["assert jwt_expired(...) is True"],
 "hidden_tests": ["assert ...", "assert ..."]}
```
Use `"split": "holdout"` for tasks reserved for measuring transfer.

## Tests

```powershell
pip install pytest
python -m pytest -q
```
81 tests cover the task bank (every hidden test is proven against a reference solution and
shown to reject stubs), sandbox policy, memory, governance, the learning loop, the monitor and the desktop app.
They use a scripted model and a stand-in Ollama server (including a full CLI train → eval run),
so they need no model download, network or API key.

## Next: Step 3 (gated self-modification)

The agent proposes changes to its own prompts, retrieval settings and tools on a git branch.
Changes are tested in Docker against the locked evaluator, and you approve the merge. The
evaluator, governance and permissions stay outside its reach.
