"""Known-good solutions used ONLY to prove the task bank's hidden tests are correct.
Never shown to the agent."""

REFERENCE = {}

REFERENCE["coding.version_compare"] = '''
def version_compare(a, b):
    def parse(s):
        if not isinstance(s, str) or not s.strip():
            raise ValueError("empty version")
        s = s.strip()
        if s[0] in "vV":
            s = s[1:]
        out = []
        for p in s.split("."):
            if not p.isdigit():
                raise ValueError("bad component: %r" % p)
            out.append(int(p))
        return out
    x, y = parse(a), parse(b)
    n = max(len(x), len(y))
    x += [0] * (n - len(x)); y += [0] * (n - len(y))
    return (x > y) - (x < y)
'''

REFERENCE["coding.merge_intervals"] = '''
def merge_intervals(intervals):
    out = []
    for s, e in sorted((list(i) for i in intervals), key=lambda p: p[0]):
        if out and s <= out[-1][1]:
            out[-1][1] = max(out[-1][1], e)
        else:
            out.append([s, e])
    return out
'''

REFERENCE["coding.lru_cache"] = '''
from collections import OrderedDict
class LRUCache:
    def __init__(self, capacity):
        self.cap = capacity
        self.d = OrderedDict()
    def get(self, key):
        if key not in self.d:
            return -1
        self.d.move_to_end(key)
        return self.d[key]
    def put(self, key, value):
        self.d[key] = value
        self.d.move_to_end(key)
        if len(self.d) > self.cap:
            self.d.popitem(last=False)
'''

REFERENCE["coding.topo_sort"] = '''
import heapq
def topo_sort(deps):
    nodes = set(deps)
    for v in deps.values():
        nodes.update(v)
    indeg = {n: 0 for n in nodes}
    children = {n: [] for n in nodes}
    for n, pre in deps.items():
        for p in set(pre):
            indeg[n] += 1
            children[p].append(n)
    heap = [n for n in nodes if indeg[n] == 0]
    heapq.heapify(heap)
    out = []
    while heap:
        n = heapq.heappop(heap)
        out.append(n)
        for c in children[n]:
            indeg[c] -= 1
            if indeg[c] == 0:
                heapq.heappush(heap, c)
    if len(out) != len(nodes):
        raise ValueError("cycle")
    return out
'''

REFERENCE["cyber.ssh_bruteforce"] = '''
import re
from collections import Counter
PAT = re.compile(r"Failed password for (?:invalid user )?\\S+ from (\\d{1,3}(?:\\.\\d{1,3}){3})")
def detect_bruteforce(lines, threshold=5):
    c = Counter()
    for line in lines:
        m = PAT.search(line)
        if m:
            c[m.group(1)] += 1
    return {ip: n for ip, n in c.items() if n >= threshold}
'''

REFERENCE["cyber.extract_iocs"] = '''
import re
IP = re.compile(r"(?<![\\d.])(\\d{1,3}(?:\\.\\d{1,3}){3})(?![\\d.])")
DOM = re.compile(r"\\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,24}\\b", re.I)
SHA = re.compile(r"\\b[a-fA-F0-9]{64}\\b")
def extract_iocs(text):
    for a in ("[.]", "(.)", "{.}"):
        text = text.replace(a, ".")
    text = re.sub("hxxp", "http", text, flags=re.I)
    ips = {m for m in IP.findall(text) if all(0 <= int(o) <= 255 for o in m.split("."))}
    doms = {m.lower() for m in DOM.findall(text)}
    shas = {m.lower() for m in SHA.findall(text)}
    return {"ipv4": sorted(ips), "domains": sorted(doms), "sha256": sorted(shas)}
'''

REFERENCE["cyber.suspicious_cmdline"] = '''
import re
RULES = {
    "encoded_command": [r"(?:^|\\s)[-/]e(?:n|nc|ncodedcommand)?\\s+[A-Za-z0-9+/=]{20,}"],
    "download_cradle": [r"downloadstring", r"downloadfile", r"invoke-webrequest", r"iwr ",
                        r"start-bitstransfer", r"(curl|wget)\\b[^|]*\\|\\s*(ba)?sh\\b"],
    "hidden_window": [r"[-/]w(?:indowstyle)?\\s+hidden"],
    "execution_policy_bypass": [r"[-/](?:ep|exec|executionpolicy)\\s+bypass"],
    "lolbin": [r"certutil(?:\\.exe)?\\b.*[-/]urlcache", r"mshta(?:\\.exe)?\\s+https?:",
               r"regsvr32(?:\\.exe)?\\b.*[-/]i:https?:", r"rundll32(?:\\.exe)?\\b.*javascript:"],
}
def suspicious_commandline(cmd):
    return sorted(n for n, pats in RULES.items() if any(re.search(p, cmd, re.I) for p in pats))
'''

REFERENCE["cyber.cvss31"] = '''
import math
W = {"AV": {"N": .85, "A": .62, "L": .55, "P": .2}, "AC": {"L": .77, "H": .44},
     "UI": {"N": .85, "R": .62}, "CIA": {"H": .56, "L": .22, "N": 0.0}}
def roundup(x):
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0
def cvss31_base_score(vector):
    if not isinstance(vector, str) or not (vector.startswith("CVSS:3.1/") or vector.startswith("CVSS:3.0/")):
        raise ValueError("bad prefix")
    m = {}
    for part in vector.split("/")[1:]:
        k, _, v = part.partition(":")
        m[k] = v
    need = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
    if any(k not in m for k in need):
        raise ValueError("missing metric")
    try:
        s = m["S"]
        if s not in ("U", "C"):
            raise KeyError
        pr = {"N": .85, "L": .68 if s == "C" else .62, "H": .5 if s == "C" else .27}[m["PR"]]
        av, ac, ui = W["AV"][m["AV"]], W["AC"][m["AC"]], W["UI"][m["UI"]]
        c, i, a = (W["CIA"][m[k]] for k in "CIA")
    except KeyError:
        raise ValueError("bad metric value")
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    impact = 6.42 * iss if s == "U" else 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    expl = 8.22 * av * ac * pr * ui
    if impact <= 0:
        score = 0.0
    elif s == "U":
        score = roundup(min(impact + expl, 10))
    else:
        score = roundup(min(1.08 * (impact + expl), 10))
    sev = ("None" if score == 0 else "Low" if score < 4 else "Medium" if score < 7
           else "High" if score < 9 else "Critical")
    return (score, sev)
'''

REFERENCE["bigdata.top_k"] = '''
import heapq
from collections import Counter
def top_k_frequent(stream, k):
    if k <= 0:
        return []
    c = Counter(stream)
    return heapq.nsmallest(k, c.items(), key=lambda kv: (-kv[1], kv[0]))
'''

REFERENCE["bigdata.reservoir"] = '''
import random
def reservoir_sample(stream, k, seed):
    if k <= 0:
        return []
    rng = random.Random(seed)
    res = []
    for i, x in enumerate(stream):
        if i < k:
            res.append(x)
        else:
            j = rng.randint(0, i)
            if j < k:
                res[j] = x
    return res
'''

REFERENCE["bigdata.group_aggregate"] = '''
def group_aggregate(rows, key, value):
    acc = {}
    for r in rows:
        if key not in r or value not in r or r[value] is None:
            continue
        try:
            v = float(r[value])
        except (TypeError, ValueError):
            continue
        g = acc.get(r[key])
        if g is None:
            acc[r[key]] = [1, v, v, v]
        else:
            g[0] += 1; g[1] += v
            if v < g[2]: g[2] = v
            if v > g[3]: g[3] = v
    return {k: {"count": n, "sum": s, "min": mn, "max": mx, "mean": s / n}
            for k, (n, s, mn, mx) in acc.items()}
'''

REFERENCE["bigdata.rolling_z"] = '''
import math
def rolling_zscore_anomalies(values, window, threshold):
    if window < 1:
        raise ValueError("window must be >= 1")
    v = list(values)
    out = []
    if len(v) <= window:
        return out
    s = sum(v[:window]); sq = sum(x * x for x in v[:window])
    for i in range(window, len(v)):
        m = s / window
        var = max(sq / window - m * m, 0.0)
        sd = math.sqrt(var)
        if sd < 1e-12 * max(1.0, abs(m)):
            win = v[i - window:i]
            m2 = sum(win) / window
            sd = math.sqrt(sum((x - m2) ** 2 for x in win) / window)
            m = m2
        x = v[i]
        if (sd > 0 and abs(x - m) / sd > threshold) or (sd == 0 and x != m):
            out.append(i)
        s += x - v[i - window]; sq += x * x - v[i - window] ** 2
    return out
'''

REFERENCE["threat.correlate"] = '''
from collections import defaultdict
def correlate_events(events, event_type, count, window_seconds):
    evs = sorted((e for e in events if e.get("type") == event_type), key=lambda e: e["ts"])
    buf = defaultdict(list)
    alerts = []
    for e in evs:
        b = buf[e["source"]]
        b.append(e["ts"])
        while b and e["ts"] - b[0] > window_seconds:
            b.pop(0)
        if len(b) >= count:
            alerts.append({"source": e["source"], "start": b[0], "end": e["ts"]})
            b.clear()
    return sorted(alerts, key=lambda a: (a["end"], a["source"]))
'''

REFERENCE["threat.impossible_travel"] = '''
import math
from collections import defaultdict
def _hav(a, b, c, d):
    p1, p2 = math.radians(a), math.radians(c)
    dp, dl = math.radians(c - a), math.radians(d - b)
    h = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * 6371.0 * math.asin(math.sqrt(h))
def impossible_travel(logins, max_kmh=900):
    by = defaultdict(list)
    for l in logins:
        by[l["user"]].append(l)
    out = []
    for u, ls in by.items():
        ls.sort(key=lambda l: l["ts"])
        for a, b in zip(ls, ls[1:]):
            km = _hav(a["lat"], a["lon"], b["lat"], b["lon"])
            dt = b["ts"] - a["ts"]
            if dt == 0:
                if km == 0:
                    continue
                speed = float("inf")
            else:
                speed = km / (dt / 3600)
            if speed > max_kmh:
                out.append({"user": u, "from_ts": a["ts"], "to_ts": b["ts"],
                            "speed_kmh": speed if speed == float("inf") else round(speed, 1)})
    return sorted(out, key=lambda r: (r["user"], r["to_ts"]))
'''

REFERENCE["threat.beaconing"] = '''
import statistics
def beacon_analysis(timestamps):
    ts = sorted(timestamps)
    iv = [b - a for a, b in zip(ts, ts[1:])]
    if len(iv) < 3:
        return {"beacon": False, "mean_interval": None, "jitter": None}
    m = statistics.mean(iv)
    if m == 0:
        return {"beacon": False, "mean_interval": 0.0, "jitter": None}
    j = statistics.pstdev(iv) / m
    return {"beacon": j < 0.1 and m >= 1, "mean_interval": round(float(m), 3), "jitter": round(j, 4)}
'''

REFERENCE["threat.prioritise"] = '''
HARMS = {"none", "minor", "moderate", "severe", "catastrophic"}
def prioritise_risks(risks):
    out = []
    for r in risks:
        L, I, C, h = r["likelihood"], r["impact"], r["criticality"], r["harm"]
        if not (isinstance(L, int) and 1 <= L <= 5 and isinstance(I, int) and 1 <= I <= 5
                and isinstance(C, int) and 1 <= C <= 3 and h in HARMS):
            raise ValueError("invalid risk %r" % r.get("id"))
        s = L * I * C
        p = ("P1" if h in ("severe", "catastrophic") or s >= 45 else
             "P2" if s >= 20 else "P3" if s >= 8 else "P4")
        out.append({"id": r["id"], "score": s, "priority": p})
    return sorted(out, key=lambda x: (x["priority"], -x["score"], x["id"]))
'''
