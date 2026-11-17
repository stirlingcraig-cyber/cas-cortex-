/* CAS Cortex iPhone app */
"use strict";
const $ = id => document.getElementById(id);
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const pct = v => (v === null || v === undefined) ? "–" : Math.round(v * 100) + "%";
const AREA = { coding: "Coding", cyber: "Cyber", bigdata: "Big data", threat: "Threat" };
let STATUS = null;

/* ---------- navigation ---------- */
function show(id) {
  document.querySelectorAll("section").forEach(s => s.classList.toggle("on", s.id === id));
  document.querySelectorAll("nav button").forEach(b => b.classList.toggle("on", b.dataset.s === id));
  window.scrollTo(0, 0);
  try { localStorage.setItem("cortex-tab", id); } catch (_) {}
}
document.querySelectorAll("nav button").forEach(b => b.addEventListener("click", () => show(b.dataset.s)));

/* ---------- data from the PC ---------- */
async function loadStatus(userAsked) {
  try {
    const r = await fetch("data/status.json?t=" + Date.now(), { cache: "no-store" });
    if (!r.ok) throw new Error("HTTP " + r.status);
    STATUS = await r.json();
    try { localStorage.setItem("cortex-status", JSON.stringify(STATUS)); } catch (_) {}
  } catch (e) {
    try { STATUS = JSON.parse(localStorage.getItem("cortex-status")); } catch (_) { STATUS = null; }
    if (userAsked) alert("Couldn't reach GitHub - showing the last saved copy.");
  }
  render();
}

function render() {
  const s = STATUS;
  if (!s || !s.published_at) {
    $("home-banner").innerHTML = "<b>Not published yet</b>On your PC: train Cortex, then Progress tab → <i>Publish to iPhone</i>. The Threat Monitor works now.";
    renderTools();
    return;
  }
  const st = s.stats || {};
  const when = new Date(s.published_at * 1000);
  $("s-gen").textContent = st.generation ?? "–";
  $("s-skills").textContent = st.skills ?? "–";
  $("s-lessons").textContent = st.lessons ?? "–";
  const last = (s.runs || []).slice(-1)[0];
  $("s-score").textContent = last ? pct(last.overall) : "–";
  $("s-model").textContent = `AI model: ${s.model} (${s.provider}) · version ${s.version}`;
  $("s-pub").textContent = "Last published: " + when.toLocaleString("en-GB", { dateStyle: "medium", timeStyle: "short" });
  $("hdr-sub").textContent = `generation ${st.generation ?? 0} · ${st.skills ?? 0} skills · updated ${when.toLocaleDateString("en-GB")}`;
  const ages = (Date.now() / 1000 - s.published_at) / 86400;
  $("home-banner").innerHTML = last
    ? `<b>Latest score ${pct(last.overall)}</b>Train ${pct(last.train)} · Holdout ${pct(last.holdout)} · generation ${last.gen}${ages > 3 ? "<br>Published " + Math.round(ages) + " days ago - publish again from your PC for fresh results." : ""}`
    : "<b>Published</b>No evaluations yet - run one on your PC's Progress tab.";
  renderProgress(); renderSkills(); renderTools();
}

/* ---------- progress ---------- */
function renderProgress() {
  const runs = (STATUS && STATUS.runs) || [];
  $("chart").innerHTML = chartSVG(runs);
  if (!runs.length) return;
  const last = runs[runs.length - 1];
  const keys = Object.keys(last.cells).sort();
  const areas = [...new Set(keys.map(k => k.split("/")[1]))];
  let h = "<table><tr><th>Area</th><th>Train</th><th>Holdout</th></tr>";
  for (const a of areas) h += `<tr><td>${esc(AREA[a] || a)}</td><td>${pct(last.cells["train/" + a])}</td><td>${pct(last.cells["holdout/" + a])}</td></tr>`;
  $("latest-table").innerHTML = h + "</table>";
  let t = "<table><tr><th>When</th><th>Gen</th><th>Train</th><th>Holdout</th><th>All</th></tr>";
  for (const r of [...runs].reverse()) {
    const d = new Date(r.ts * 1000).toLocaleDateString("en-GB", { day: "numeric", month: "short" });
    t += `<tr><td>${d}</td><td>${r.gen}</td><td>${pct(r.train)}</td><td>${pct(r.holdout)}</td><td><b>${pct(r.overall)}</b></td></tr>`;
  }
  $("runs-table").innerHTML = t + "</table>";
}

function chartSVG(runs) {
  const W = 340, H = 190, L = 34, R = 10, T = 10, B = 26;
  let g = `<svg viewBox="0 0 ${W} ${H}" width="100%" role="img" aria-label="Learning curve">`;
  for (let i = 0; i <= 100; i += 25) {
    const y = T + (H - T - B) * (1 - i / 100);
    g += `<line x1="${L}" x2="${W - R}" y1="${y}" y2="${y}" stroke="currentColor" stroke-opacity=".12"/>`;
    g += `<text x="${L - 6}" y="${y + 4}" font-size="10" text-anchor="end" fill="currentColor" fill-opacity=".6">${i}%</text>`;
  }
  if (!runs.length) return g + `<text x="${W / 2}" y="${H / 2}" font-size="12" text-anchor="middle" fill="currentColor" fill-opacity=".6">No evaluations published yet</text></svg>`;
  const n = runs.length, xs = runs.map((_, i) => n > 1 ? L + (W - L - R) * i / (n - 1) : (L + W - R) / 2);
  for (const [k, col] of [["overall", "#14213D"], ["train", "#0F7C7A"], ["holdout", "#E08A00"]]) {
    const pts = runs.map((r, i) => r[k] == null ? null : [xs[i], T + (H - T - B) * (1 - r[k])]).filter(Boolean);
    if (pts.length > 1) g += `<polyline points="${pts.map(p => p.join(",")).join(" ")}" fill="none" stroke="${col}" stroke-width="2.5"/>`;
    for (const [x, y] of pts) g += `<circle cx="${x}" cy="${y}" r="3.5" fill="${col}" stroke="#fff" stroke-width="1"/>`;
  }
  runs.forEach((r, i) => { if (n <= 8 || i % Math.ceil(n / 8) === 0) g += `<text x="${xs[i]}" y="${H - 8}" font-size="10" text-anchor="middle" fill="currentColor" fill-opacity=".6">g${r.gen}</text>`; });
  return g + "</svg>";
}

/* ---------- skills & memory ---------- */
function renderSkills() {
  const s = STATUS || {};
  const skills = s.skills || [];
  $("skills-list").innerHTML = skills.length ? skills.map(k => `
    <details class="item"><summary>${esc(k.name)}<span class="pill${k.trust === "self-tested" ? " amber" : ""}">${esc(k.trust)}</span>
    <div class="muted" style="font-weight:400">${esc(AREA[k.domain] || k.domain)} · v${k.version} · solved ${k.successes}× · reused ${k.uses}×</div></summary>
    <div class="muted" style="margin-top:6px">${esc(k.description)}</div><pre>${esc(k.code)}</pre></details>`).join("")
    : '<span class="muted">No skills published yet.</span>';
  const ls = s.lessons || [];
  $("lessons-list").innerHTML = ls.length ? ls.map(l => `<div class="item"><span class="pill">${esc(AREA[l.domain] || l.domain)}</span> ${esc(l.text)}</div>`).join("") : '<span class="muted">–</span>';
  const kg = s.knowledge || [];
  $("knowledge-list").innerHTML = kg.length ? kg.map(([a, r, b]) => `<div class="item">${esc(a)} <span class="muted">— ${esc(r)} →</span> ${esc(b)}</div>`).join("") : '<span class="muted">–</span>';
  const ep = s.recent_episodes || [];
  $("episodes-list").innerHTML = ep.length ? "<table>" + ep.map(e => `<tr><td>${esc(e.task)}</td><td class="${e.solved ? "ok" : "bad"}">${e.solved ? "solved" : "failed"}</td><td>${e.attempts}×</td></tr>`).join("") + "</table>" : '<span class="muted">–</span>';
}

/* ---------- threat monitor (on-device) ---------- */
function useSample(which) { $("log").value = window.CORTEX_SAMPLES[which]; }
function openFile(inp) {
  const f = inp.files && inp.files[0];
  if (!f) return;
  if (f.size > 20 * 1024 * 1024) { alert("That file is over 20 MB - please trim it."); return; }
  const rd = new FileReader();
  rd.onload = () => { $("log").value = rd.result; analyse(); };
  rd.readAsText(f);
}
function analyse() {
  const m = new CortexEngine.Monitor({
    failCount: parseInt($("fc").value, 10) || 5, failWindow: parseInt($("fw").value, 10) || 60,
    criticality: CortexEngine.parseCriticality($("crit").value),
  });
  const alerts = m.feedText($("log").value).slice()
    .sort((a, b) => a.priority.localeCompare(b.priority) || b.ts - a.ts);   // most urgent first, then newest
  const counts = { P1: 0, P2: 0, P3: 0, P4: 0 };
  alerts.forEach(a => counts[a.priority]++);
  $("chips").innerHTML = ["P1", "P2", "P3", "P4"].map(p => `<div class="chip ${p}">${p}: ${counts[p]}</div>`).join("");
  $("alerts").innerHTML = alerts.map(a => {
    const t = new Date(a.ts * 1000).toLocaleTimeString("en-GB");
    return `<details class="alert"><summary class="top"><span class="badge ${a.priority}">${a.priority}</span>
      <span class="t">${esc(a.title)}</span></summary>
      <div class="d">${esc(a.entity)} · ${t} · risk score ${a.score}</div>
      <div class="d">${esc(a.detail)}</div><div class="d"><b>Suggested response:</b> ${esc(a.advice)}</div></details>`;
  }).join("") || '<div class="card muted">No alerts - nothing found that needs attention.</div>';
  const what = { obd_test_report: "CAS OBD Scanner test report", obd_health: "CAS OBD Scanner health history",
                 obd_data_log: "CAS OBD Scanner data log", obd_codes: "car fault codes" }[m.source];
  $("mon-summary").textContent = (what ? `Read as ${what}. ` : `${m.events} events analysed. `) +
    `${alerts.length} alert(s). Analysed on this iPhone - nothing was uploaded.`;
}

/* ---------- tools: run learned skills with Pyodide ---------- */
const PYODIDE_VERSIONS = ["v314.0.8", "v0.27.2"];
let pyodide = null;
function exampleCall(skill) {
  for (const t of skill.tests || []) {
    const line = t.split("\n").find(l => l.trim().startsWith("assert ") && l.includes(skill.name));
    if (!line) continue;
    let e = line.trim().slice(7);
    const i = e.search(/\s(==|is|in)\s/);
    if (i > 0) e = e.slice(0, i);
    if (e.startsWith(skill.name + "(")) return e;
  }
  return skill.name + "()";
}
function renderTools() {
  const skills = ((STATUS && STATUS.skills) || []).filter(k => /^[a-z_]/.test(k.name));
  const sel = $("tool-skill");
  const prev = sel.value;
  sel.innerHTML = skills.length ? skills.map(k => `<option value="${esc(k.name)}">${esc(k.name)} (${esc(AREA[k.domain] || k.domain)})</option>`).join("")
    : "<option>No skills published yet</option>";
  $("tool-run").disabled = !skills.length;
  if (prev && skills.some(k => k.name === prev)) sel.value = prev;
  pickSkill();
}
function pickSkill() {
  const k = ((STATUS && STATUS.skills) || []).find(x => x.name === $("tool-skill").value);
  $("tool-desc").textContent = k ? k.description : "";
  $("tool-expr").value = k ? exampleCall(k) : "";
  $("tool-out").style.display = "none";
}
async function getPyodide() {
  if (pyodide) return pyodide;
  let lastErr;
  for (const v of PYODIDE_VERSIONS) {
    const base = `https://cdn.jsdelivr.net/pyodide/${v}/full/`;
    try {
      const mod = await import(base + "pyodide.mjs");
      pyodide = await mod.loadPyodide({ indexURL: base });
      return pyodide;
    } catch (e) { lastErr = e; }
  }
  throw lastErr;
}
async function runSkill() {
  const out = $("tool-out"), btn = $("tool-run");
  out.style.display = "block";
  btn.disabled = true;
  out.textContent = pyodide ? "Running…" : "Loading the Python engine (first time only)…";
  try {
    const py = await getPyodide();
    const skills = STATUS.skills || [];
    py.FS.mkdirTree("/home/pyodide/skills");
    let init = "";
    for (const k of skills) {
      py.FS.writeFile(`/home/pyodide/skills/${k.name}.py`, k.code);
      init += `try:\n    from .${k.name} import ${k.name}\nexcept Exception:\n    pass\n`;
    }
    py.FS.writeFile("/home/pyodide/skills/__init__.py", init);
    py.globals.set("_expr", $("tool-expr").value);
    const res = await py.runPythonAsync(`
import sys, importlib, json
sys.path.insert(0, "/home/pyodide")
for m in [m for m in sys.modules if m == "skills" or m.startswith("skills.")]:
    del sys.modules[m]
import skills
_ns = {n: getattr(skills, n) for n in dir(skills) if not n.startswith("_")}
try:
    _r = eval(_expr, _ns)
    _out = json.dumps(_r, indent=2, default=repr) if isinstance(_r, (dict, list, tuple)) else repr(_r)
except Exception as _e:
    _out = "Error: " + type(_e).__name__ + ": " + str(_e)
_out`);
    out.textContent = res;
  } catch (e) {
    out.textContent = "Couldn't load the Python engine. Check your internet connection and try again.\n" + e;
  } finally { btn.disabled = false; }
}

/* ---------- start ---------- */
if ("serviceWorker" in navigator) navigator.serviceWorker.register("sw.js").catch(() => {});
try { const t = localStorage.getItem("cortex-tab"); if (t && $(t)) show(t); } catch (_) {}
loadStatus(false);
