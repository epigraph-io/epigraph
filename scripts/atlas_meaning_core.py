#!/usr/bin/env python3
"""The "by meaning" hierarchy's pure core (Atlas W4, backlog f9fc052c).

Under each theme of one Atlas map, the claims the map draws are clustered
recursively by embedding until every leaf group fits the leaf cap (W3: at most
100 nodes, claims + agents + evidence counted together). A group that already
fits is a leaf, so no level ever has a single child.

`build_tree(ids, embeddings, attachments, map_key=..., theme_id=...)` is a pure
function of its inputs: no database, no claim text, no clock. That is what lets
it run off the prod box (design 2026-11-12 §2: the maths may leave the box on
claim ids, embeddings and structure only).

**Weight.** A group's weight is its claim count plus the number of DISTINCT
attachment nodes over its claims. `attachments[i]` lists claim i's agents and
evidence as small integers, numbered per theme by the box-side export
(`atlas_meaning export`, crates/epigraph-cli/src/atlas_meaning), so an agent
shared by many claims is one node per group and no agent or evidence id leaves
the box. Each claim's list is already cut by W3's per-claim cap, so every
claim alone fits and every split terminates; a claim over the cap on its own is
refused.

**Split.** W1's (theme_cap_core): L2-normalise, UMAP (skipped at 100 distinct
points or fewer), k-means with k = clamp(ceil(weight / cap), 2, MAX_FANOUT),
small clusters merged into their nearest, larger k tried when that leaves one
group. Only identical vectors fall back to equal cuts in claim-id order,
counted in `id_chunk_cuts`.

**Ids.** UUIDv5 in NAMESPACE, deterministic, so a group whose members are
unchanged keeps its id across runs with no matching against an earlier run:
  * the root (depth 0, the theme root): "{map}|{hierarchy}|{theme}|root";
  * any other group: "{map}|{hierarchy}|{theme}|members|" + its claim ids
    (every claim under it), lowercase, sorted, comma-joined.
`map` is "public" or "team:<group uuid>". The box-side apply mints the same
strings in Rust and refuses any id that differs (golden vectors pinned in
both test suites).

Files that cross the box boundary (both directions are plain JSON plus raw
little-endian float32, so nothing read here can run code):
  * an export directory: `export.json` (EXPORT_FORMAT: map, hierarchy, cap,
    seed, dim, and per theme its claim and attachment-node counts), and per
    theme `<theme_id>.json` ({"claim_ids", "attachments"}) and
    `<theme_id>.f32` (claims x dim embeddings, in claim_ids order);
  * a result (RESULT_FORMAT): per theme its groups in pre-order, each
    {"id", "parent", "depth", "kind", "claim_count", "weight", and "members"
    for a leaf or "children" for a group}, plus the library versions, since
    ids persist only while the clustering reproduces.

Usage (off the box; needs numpy, scikit-learn, umap-learn, no DB driver):
    python3 scripts/atlas_meaning_core.py compute --from export-dir/ --out result.json
"""
import argparse
import json
import math
import pathlib
import platform
import sys
import uuid

import numpy as np
from sklearn.preprocessing import normalize

try:  # imported as scripts.atlas_meaning_core (tests) or run from scripts/
    from scripts import theme_cap_core as cap_core
except ImportError:  # pragma: no cover - the off-box CLI path
    import theme_cap_core as cap_core

EXPORT_FORMAT = "atlas-meaning-export/1"
RESULT_FORMAT = "atlas-meaning-result/1"
HIERARCHY = "meaning"

# uuid5(NAMESPACE_URL, "urn:epigraph:atlas-group:v1"); pinned as a literal in
# crates/epigraph-cli/src/atlas_meaning/tree.rs.
NAMESPACE = uuid.UUID("fe2624a2-be4f-595a-be4c-2e14830d2a5b")

DEFAULT_CAP = 100
DEFAULT_SEED = 42
# The most children one split makes. The W10a contract allows 128 children
# and 16 levels below the theme root; k-means may add K_RETRIES to k.
MAX_FANOUT = 16
MAX_CHILDREN = 128
MAX_DEPTH = 16


# ── ids ─────────────────────────────────────────────────────────────────────

def _check_map_key(map_key):
    if map_key == "public":
        return map_key
    if map_key.startswith("team:"):
        g = map_key[len("team:"):]
        if str(uuid.UUID(g)) == g:
            return map_key
    raise ValueError(f"map key must be 'public' or 'team:<lowercase uuid>', not {map_key!r}")


def _canon(u):
    s = str(u)
    if str(uuid.UUID(s)) != s:
        raise ValueError(f"not a lowercase hyphenated uuid: {s!r}")
    return s


def root_id(map_key, hierarchy, theme_id):
    """The id of a theme's root in one hierarchy of one map."""
    name = f"{_check_map_key(map_key)}|{hierarchy}|{_canon(theme_id)}|root"
    return str(uuid.uuid5(NAMESPACE, name))


def group_id(map_key, hierarchy, theme_id, members):
    """The id of a non-root group: a function of its member claim set only."""
    ids = sorted(_canon(m) for m in members)
    if not ids:
        raise ValueError("a group has at least one claim")
    name = f"{_check_map_key(map_key)}|{hierarchy}|{_canon(theme_id)}|members|" + ",".join(ids)
    return str(uuid.uuid5(NAMESPACE, name))


# ── the tree ────────────────────────────────────────────────────────────────

def _weight(idx, att):
    nodes = set()
    for i in idx:
        nodes.update(att[i])
    return len(idx) + len(nodes)


def _split(idx, x, att, cap, seed, stats):
    """Two to MAX_FANOUT + K_RETRIES groups of `idx` (index arrays into x)."""
    n = len(idx)
    k = min(MAX_FANOUT, max(2, math.ceil(_weight(idx, att) / cap)), n)
    sub = x[idx]
    groups = []
    if cap_core._distinct(normalize(sub)) >= 2:
        min_part = max(1, n // (4 * k))
        groups = cap_core._cluster(cap_core._reduce(sub, seed), k, seed, min_part)
    if len(groups) < 2:
        # Nothing to separate (identical vectors): k equal cuts by position,
        # which is claim-id order because build_tree sorted the input.
        stats["id_chunk_cuts"] += 1
        groups = cap_core._chunks(n, math.ceil(n / k))
    return [idx[np.asarray(g)] for g in groups]


def _order(parts, ids):
    """Children by claim count descending, then by smallest claim id."""
    return sorted(parts, key=lambda p: (-len(p), ids[int(p.min())]))


def build_tree(ids, embeddings, attachments, *, map_key, theme_id, cap=DEFAULT_CAP,
               seed=DEFAULT_SEED, hierarchy=HIERARCHY):
    """The hierarchy of one theme on one map: its groups in pre-order (the
    root first) and a stats dict ({"id_chunk_cuts"}).

    Pure and deterministic: the input is sorted by claim id first, so the
    result does not depend on the order rows arrive in."""
    if cap < 1:
        raise ValueError("cap must be at least 1")
    _check_map_key(map_key)
    ids = [_canon(i) for i in ids]
    x = np.asarray(embeddings, dtype=np.float32)
    if x.ndim != 2 or len(x) != len(ids) or len(attachments) != len(ids):
        raise ValueError(f"need one embedding row and one attachment list per id "
                         f"({len(ids)} ids, embeddings {x.shape}, {len(attachments)} lists)")
    if len(set(ids)) != len(ids):
        raise ValueError("claim ids must be unique")
    if not ids:
        return [], {"id_chunk_cuts": 0}
    order = sorted(range(len(ids)), key=ids.__getitem__)
    ids = [ids[i] for i in order]
    x = x[order]
    att = [sorted({int(a) for a in attachments[i]}) for i in order]
    for c, a in zip(ids, att):
        if 1 + len(a) > cap:
            raise ValueError(f"claim {c} is over the cap on its own ({1 + len(a)} > {cap} "
                             "nodes); the export must apply W3's per-claim cap")

    stats = {"id_chunk_cuts": 0}
    groups = []

    def node(idx, depth, parent):
        members = [ids[i] for i in idx]
        gid = root_id(map_key, hierarchy, theme_id) if parent is None else \
            group_id(map_key, hierarchy, theme_id, members)
        w = _weight(idx, att)
        g = {"id": gid, "parent": parent, "depth": depth, "claim_count": len(idx), "weight": w}
        groups.append(g)
        if w <= cap:
            g["kind"] = "leaf"
            g["members"] = members
            return gid
        if depth >= MAX_DEPTH:
            raise ValueError(f"theme {theme_id} needs more than {MAX_DEPTH} levels")
        parts = _order(_split(idx, x, att, cap, seed, stats), ids)
        if not 2 <= len(parts) <= MAX_CHILDREN:
            raise ValueError(f"a split made {len(parts)} children")
        g["kind"] = "group"
        g["children"] = [node(np.sort(p), depth + 1, gid) for p in parts]
        return gid

    node(np.arange(len(ids)), 0, None)
    return groups, stats


def validate_tree(groups, ids, attachments, *, map_key, theme_id, cap, hierarchy=HIERARCHY):
    """Raise ValueError unless `groups` is a well-formed tree over `ids`: one
    root, ids as minted, parents and depths that chain, at least two children
    per group, every claim in exactly one leaf, every leaf within the cap."""
    pos = {_canon(c): i for i, c in enumerate(ids)}
    att = [set(a) for a in attachments]
    by_id = {}
    for g in groups:
        if g["id"] in by_id:
            raise ValueError(f"group {g['id']} appears twice")
        by_id[g["id"]] = g
    roots = [g for g in groups if g["parent"] is None]
    if len(roots) != 1 or roots[0]["depth"] != 0:
        raise ValueError("a tree has exactly one root, at depth 0")
    if roots[0]["id"] != root_id(map_key, hierarchy, theme_id):
        raise ValueError("the root id is not the minted one")
    seen = set()
    reached = set()

    def claims_under(g, depth):
        if g["depth"] != depth or depth > MAX_DEPTH:
            raise ValueError(f"group {g['id']} has depth {g['depth']}, expected {depth}")
        reached.add(g["id"])
        if g["kind"] == "leaf":
            members = g["members"]
            if not members:
                raise ValueError(f"leaf {g['id']} is empty")
            for c in members:
                if c not in pos:
                    raise ValueError(f"leaf {g['id']} holds a claim that is not a member")
                if c in seen:
                    raise ValueError(f"claim {c} is in more than one leaf")
                seen.add(c)
            nodes = set().union(*(att[pos[c]] for c in members))
            if len(members) + len(nodes) > cap:
                raise ValueError(f"leaf {g['id']} is over the cap")
            under = set(members)
        elif g["kind"] == "group":
            kids = g["children"]
            if not 2 <= len(kids) <= MAX_CHILDREN:
                raise ValueError(f"group {g['id']} has {len(kids)} children")
            under = set()
            for k in kids:
                child = by_id.get(k)
                if child is None or child["parent"] != g["id"]:
                    raise ValueError(f"child {k} of {g['id']} does not point back to it")
                under |= claims_under(child, depth + 1)
        else:
            raise ValueError(f"group {g['id']} has kind {g['kind']!r}")
        if g["parent"] is not None and g["id"] != group_id(map_key, hierarchy, theme_id, under):
            raise ValueError(f"group {g['id']} is not the id minted from its members")
        return under

    claims_under(roots[0], 0)
    if reached != set(by_id):
        raise ValueError("a group is not reachable from the root")
    if seen != set(pos):
        raise ValueError(f"leaves cover {len(seen)} of {len(pos)} members")


# ── files ───────────────────────────────────────────────────────────────────

def _dumps(obj):
    """Compact JSON, as serde_json writes it."""
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


def write_export(export_dir, map_key, *, cap, seed, dim, themes):
    """Write an export directory. `themes` maps theme id to (ids, X, attachments),
    ids sorted. The Rust export writer produces the same bytes (tests)."""
    export_dir = pathlib.Path(export_dir)
    export_dir.mkdir(parents=True, exist_ok=True)
    entries = []
    for theme_id in sorted(themes):
        ids, x, att = themes[theme_id]
        x = np.asarray(x, dtype="<f4")
        if x.shape != (len(ids), dim):
            raise ValueError(f"theme {theme_id}: embeddings {x.shape}, want ({len(ids)}, {dim})")
        (export_dir / f"{theme_id}.json").write_text(
            _dumps({"claim_ids": list(ids), "attachments": [list(a) for a in att]}))
        (export_dir / f"{theme_id}.f32").write_bytes(x.tobytes())
        nodes = set().union(*(set(a) for a in att)) if att else set()
        entries.append({"theme_id": theme_id, "claims": len(ids), "attachment_nodes": len(nodes)})
    index = {"format": EXPORT_FORMAT, "map": map_key, "hierarchy": HIERARCHY, "cap": cap,
             "seed": seed, "dim": dim, "themes": entries}
    (export_dir / "export.json").write_text(_dumps(index))


def read_export_theme(export_dir, theme_id, dim):
    """One theme of an export: (ids, X, attachments)."""
    export_dir = pathlib.Path(export_dir)
    doc = json.loads((export_dir / f"{_canon(theme_id)}.json").read_text())
    ids = [_canon(c) for c in doc["claim_ids"]]
    att = [[int(a) for a in lst] for lst in doc["attachments"]]
    raw = np.fromfile(export_dir / f"{theme_id}.f32", dtype="<f4")
    if raw.size != len(ids) * dim:
        raise ValueError(f"theme {theme_id}: the embedding file holds {raw.size} floats, "
                         f"want {len(ids)} x {dim}")
    if len(att) != len(ids):
        raise ValueError(f"theme {theme_id}: {len(att)} attachment lists for {len(ids)} ids")
    return ids, raw.reshape(len(ids), dim).astype(np.float32), att


def _versions():
    import sklearn
    try:
        import importlib.metadata as md
        umap_version = md.version("umap-learn")
    except Exception:  # noqa: BLE001 - recorded, never fatal
        umap_version = None
    return {"numpy": np.__version__, "scikit-learn": sklearn.__version__,
            "umap-learn": umap_version, "python": platform.python_version()}


def compute_export_dir(export_dir, cap=None, seed=None):
    """Build and validate every theme's tree of an export. Returns the result
    document (RESULT_FORMAT). `cap` and `seed` default to the export's."""
    export_dir = pathlib.Path(export_dir)
    index = json.loads((export_dir / "export.json").read_text())
    if index.get("format") != EXPORT_FORMAT:
        raise ValueError(f"not a {EXPORT_FORMAT} export: {index.get('format')!r}")
    if index.get("hierarchy") != HIERARCHY:
        raise ValueError(f"not a {HIERARCHY} export: {index.get('hierarchy')!r}")
    map_key = _check_map_key(index["map"])
    cap = int(cap if cap is not None else index["cap"])
    seed = int(seed if seed is not None else index["seed"])
    dim = int(index["dim"])
    themes = []
    for entry in index["themes"]:
        theme_id = _canon(entry["theme_id"])
        ids, x, att = read_export_theme(export_dir, theme_id, dim)
        groups, stats = build_tree(ids, x, att, map_key=map_key, theme_id=theme_id,
                                   cap=cap, seed=seed)
        validate_tree(groups, ids, att, map_key=map_key, theme_id=theme_id, cap=cap)
        themes.append({"theme_id": theme_id, "id_chunk_cuts": stats["id_chunk_cuts"],
                       "groups": groups})
    return {"format": RESULT_FORMAT, "map": map_key, "hierarchy": HIERARCHY, "cap": cap,
            "seed": seed, "versions": _versions(), "themes": themes}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("compute", help="build every theme's tree of an export (no DB)")
    c.add_argument("--from", dest="src", required=True, help="the export directory")
    c.add_argument("--out", required=True, help="the result file to write")
    args = ap.parse_args(argv)
    result = compute_export_dir(args.src)
    pathlib.Path(args.out).write_text(json.dumps(result, indent=1) + "\n")
    leaves = sum(g["kind"] == "leaf" for t in result["themes"] for g in t["groups"])
    print(f"{len(result['themes'])} themes, {leaves} leaves -> {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
