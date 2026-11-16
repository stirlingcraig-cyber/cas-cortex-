"""Dependency-free BM25 ranking used by all three memory stores."""
from __future__ import annotations

import math
import re
from collections import Counter

_TOKEN = re.compile(r"[a-z0-9]+")
_STOP = set("""a an the and or of to in on for with is are be by as at it its this that from
into if else then than return returns list dict str int float none true false each
must should write any all not use using only""".split())


def tokenize(text: str) -> list[str]:
    words = []
    for t in _TOKEN.findall((text or "").lower().replace("_", " ")):
        if len(t) > 1 and t not in _STOP:
            words.append(t)
    return words


def bm25_rank(query: str, docs: list[tuple[object, str]], top_k: int = 5,
              k1: float = 1.5, b: float = 0.75) -> list[tuple[object, float]]:
    """Return [(doc_id, score)] best first, score > 0 only."""
    q = tokenize(query)
    if not q or not docs:
        return []
    toks = [(i, tokenize(t)) for i, t in docs]
    n = len(toks)
    avg = sum(len(t) for _, t in toks) / n or 1.0
    df = Counter()
    for _, t in toks:
        df.update(set(t))
    scored = []
    qset = set(q)
    for i, t in toks:
        tf = Counter(t)
        s = 0.0
        for w in qset:
            if w not in tf:
                continue
            idf = math.log(1 + (n - df[w] + 0.5) / (df[w] + 0.5))
            f = tf[w]
            s += idf * f * (k1 + 1) / (f + k1 * (1 - b + b * len(t) / avg))
        if s > 0:
            scored.append((i, s))
    scored.sort(key=lambda x: -x[1])
    return scored[:top_k]
