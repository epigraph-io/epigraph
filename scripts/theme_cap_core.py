#!/usr/bin/env python3
"""The pure half of the theme-cap split (Atlas W1, backlog 8c4aefda).

`split_to_cap(ids, embeddings, cap, seed)` partitions one theme's members into
parts of at most `cap` claims, by UMAP over the embeddings and then k-means,
recursively. It is a pure function of its four inputs: no database, no claim
text, no clock. That is what lets the heavy step run off the prod box (design
2026-11-12 §2: the maths may leave the box on claim ids and embeddings only),
and what makes a rerun over the same input give the same parts.

This module deliberately imports nothing but numpy, scikit-learn and umap-learn
(lazily), and in particular not `theme_lib`, which pulls in psycopg2: the
`compute` step of `theme_cap_split.py` runs on a host with no DB driver, and
tests/theme/test_theme_cap_core.py::test_compute_runs_without_db_driver blocks
those imports to keep it that way.

It also owns the two files that cross the box boundary:
  * an export: one `<theme_id>.npz` per theme holding `claim_ids` (fixed-width
    unicode) and `embeddings` (float32), plus an `export.json` index. Both load
    with `allow_pickle=False`, so a file that comes back from another host
    cannot run code when it is read;
  * a result: JSON naming each theme's parts as lists of claim ids.
"""
import json
import math
import pathlib

import numpy as np
from sklearn.cluster import KMeans
from sklearn.preprocessing import normalize

EXPORT_FORMAT = "theme-cap-export/1"
RESULT_FORMAT = "theme-cap-result/1"

DEFAULT_CAP = 2000
DEFAULT_SEED = 42

# refine_clusters.auto_refine's reducer: the same space the theme-v2 grow loop
# splits clusters in. min_dist=0 packs each cluster tightly, which is what the
# k-means after it wants.
UMAP_COMPONENTS = 16
UMAP_NEIGHBORS = 15
# At or below this many points UMAP's neighbour graph is too thin to be worth
# its cost (and its spectral init can fail); k-means on the normalised vectors
# is used directly.
UMAP_MIN_POINTS = 100


def _distinct(x):
    """How many distinct rows `x` has (to 1e-6)."""
    return len(np.unique(np.round(x, 6), axis=0))


def _reduce(x, seed):
    """L2-normalised low-dimensional coordinates for clustering.

    UMAP is skipped when there are too few DISTINCT points for its neighbour
    graph: on a set of identical vectors its layout is not reproducible even
    with a fixed seed (measured), and there is nothing for it to separate."""
    x = normalize(np.asarray(x, dtype=np.float32))
    if _distinct(x) <= UMAP_MIN_POINTS:
        return x
    import umap  # lazy: heavy import, and only this path needs it

    reducer = umap.UMAP(n_components=UMAP_COMPONENTS, metric="cosine",
                        n_neighbors=UMAP_NEIGHBORS, min_dist=0.0, random_state=seed)
    return normalize(reducer.fit_transform(x).astype(np.float32))


def _merge_small(labels, coords, min_part):
    """Fold every cluster under `min_part` into the cluster with the nearest
    centroid, smallest first, so the split does not leave crumbs. Returns the
    surviving clusters as index arrays, in label order."""
    groups = {int(c): np.flatnonzero(labels == c) for c in np.unique(labels)}
    while len(groups) > 1:
        small = sorted((len(v), c) for c, v in groups.items() if len(v) < min_part)
        if not small:
            break
        _, c = small[0]
        centre = coords[groups[c]].mean(axis=0)
        others = sorted(groups)
        others.remove(c)
        dists = [float(np.linalg.norm(coords[groups[o]].mean(axis=0) - centre)) for o in others]
        target = others[int(np.argmin(dists))]
        groups[target] = np.sort(np.concatenate([groups[target], groups.pop(c)]))
    return [groups[c] for c in sorted(groups)]


def _chunks(n, cap):
    """Equal consecutive chunks of range(n), each at most `cap`."""
    k = math.ceil(n / cap)
    bounds = [round(i * n / k) for i in range(k + 1)]
    return [np.arange(bounds[i], bounds[i + 1]) for i in range(k)]


def _split(x, cap, seed, min_part):
    """Index arrays (into x) of parts each at most `cap`. Every recursive call
    is on a strictly smaller set, so this terminates."""
    n = len(x)
    if n <= cap:
        return [np.arange(n)]
    k = max(2, math.ceil(n / cap))
    if _distinct(normalize(x)) < 2:
        groups = []  # nothing to separate: every member is the same vector
    else:
        coords = _reduce(x, seed)
        labels = KMeans(n_clusters=k, n_init=10, random_state=seed).fit_predict(coords)
        groups = _merge_small(labels, coords, min_part)
    if len(groups) < 2:
        # Nothing to separate (e.g. identical embeddings): cut by position,
        # which is claim-id order because split_to_cap sorted the input.
        groups = _chunks(n, cap)
    parts = []
    for g in groups:
        parts.extend(g[sub] for sub in _split(x[g], cap, seed, min_part))
    return parts


def order_parts(parts):
    """Each part sorted; parts by size descending, then by smallest claim id.

    Part 0 is the one that keeps the theme's id."""
    parts = [sorted(p) for p in parts if p]
    return sorted(parts, key=lambda p: (-len(p), p[0]))


def split_to_cap(ids, embeddings, cap=DEFAULT_CAP, seed=DEFAULT_SEED, min_part=None):
    """Partition `ids` (with their `embeddings` rows) into parts of at most `cap`.

    Pure and deterministic: the input is first sorted by claim id, so the
    result does not depend on the order rows arrive in. `min_part` (default
    cap // 20) is the size under which a cluster is merged into its nearest
    neighbour rather than kept as its own part.

    Returns a list of lists of claim ids, ordered by `order_parts`.
    """
    if cap < 1:
        raise ValueError("cap must be at least 1")
    ids = [str(i) for i in ids]
    x = np.asarray(embeddings, dtype=np.float32)
    if x.ndim != 2 or len(x) != len(ids):
        raise ValueError(f"need one embedding row per id ({len(ids)} ids, shape {x.shape})")
    if len(set(ids)) != len(ids):
        raise ValueError("claim ids must be unique")
    if not ids:
        return []
    order = sorted(range(len(ids)), key=ids.__getitem__)
    ids = [ids[i] for i in order]
    x = x[order]
    if min_part is None:
        min_part = max(1, cap // 20)
    parts = _split(x, cap, seed, min_part)
    return order_parts([[ids[i] for i in p] for p in parts])


def validate_parts(members, parts, cap):
    """Raise ValueError unless `parts` cover `members` exactly once, each <= cap."""
    seen = set()
    for p in parts:
        for cid in p:
            if cid in seen:
                raise ValueError(f"claim {cid} appears in more than one part")
            seen.add(cid)
        if len(p) > cap:
            raise ValueError(f"a part of {len(p)} claims is over the cap of {cap}")
    if seen != set(members):
        missing = len(set(members) - seen)
        extra = len(seen - set(members))
        raise ValueError(f"parts do not cover the members: {missing} missing, {extra} extra")


def write_theme_npz(path, claim_ids, embeddings):
    """One theme's export: ids as fixed-width unicode, embeddings as float32."""
    ids = np.asarray([str(c) for c in claim_ids], dtype="U36")
    np.savez(path, claim_ids=ids, embeddings=np.asarray(embeddings, dtype=np.float32))


def read_theme_npz(path):
    """Inverse of write_theme_npz; never unpickles."""
    with np.load(path, allow_pickle=False) as z:
        return [str(c) for c in z["claim_ids"]], np.asarray(z["embeddings"], dtype=np.float32)


def compute_export_dir(export_dir, cap=None, seed=None):
    """Run split_to_cap over every theme of an export directory.

    Returns the result document (RESULT_FORMAT). `cap` and `seed` default to
    the values the export recorded."""
    export_dir = pathlib.Path(export_dir)
    index = json.loads((export_dir / "export.json").read_text())
    if index.get("format") != EXPORT_FORMAT:
        raise ValueError(f"not a {EXPORT_FORMAT} export: {index.get('format')!r}")
    cap = int(cap if cap is not None else index["cap"])
    seed = int(seed if seed is not None else index["seed"])
    themes = []
    for entry in index["themes"]:
        theme_id = str(entry["theme_id"])
        ids, x = read_theme_npz(export_dir / f"{theme_id}.npz")
        themes.append({"theme_id": theme_id, "parts": split_to_cap(ids, x, cap=cap, seed=seed)})
    return {"format": RESULT_FORMAT, "cap": cap, "seed": seed, "themes": themes}
