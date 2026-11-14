#!/usr/bin/env python3
"""The "by links" hierarchy's pure core (Atlas W5, backlog 4e02c23f, with
W5b febb2a77).

Under each theme of one Atlas map, the claims the map draws are grouped by the
communities of the claim graph until every leaf group fits the leaf cap (W3:
at most 100 nodes, claims + agents + evidence counted together). A group that
already fits is a leaf, so no level ever has a single child.

`build_tree(ids, attachments, links, meaning_leaf, embeddings, map_key=...,
theme_id=...)` is a pure function of its inputs: no database, no claim text,
no clock. That is what lets it run off the prod box (design 2026-11-12 §2: the
maths may leave the box on claim ids, embeddings and structure only).

**Counted links.** The box-side export (`atlas_links export`,
crates/epigraph-cli/src/atlas_links) passes the theme's links as index pairs:
claim-to-claim edges the map may draw (public, or the team's own with no
co-owner), both ends members of the theme, whose relationship is one of
supports, refutes, contradicts, cites, elaborates, corroborates or
decomposes_to (either spelling). This core treats them as an undirected,
unweighted graph.

**Weight.** W4's (atlas_meaning_core): a group's claims plus the DISTINCT
attachment integers over them, so a shared agent is one node per group.

**The tree.**
  1. L = the claims with a link to another member, U = the rest.
  2. A theme whose weight fits is one root leaf.
  3. L is decomposed bottom-up into UNITS that each fit, and a unit is never
     split again: a set that fits is a unit; a disconnected set over the cap
     is cut into its connected components (so a component that fits stays
     whole); a connected one into its Louvain communities (networkx, seeded,
     nodes and edges added in id order); one Louvain will not split (a single
     dense community) by W4's embedding split. Each part is cut again the
     same way.
  4. Units are packed top-down: a set of units whose union fits is a leaf;
     otherwise they are packed into bins of target weight
     T = max(cap, ceil(w / k)), k = clamp(ceil(w / cap), 2, MAX_FANOUT):
     linked units are merged first, most links first, while the merge stays
     within T (so the parts Louvain cut out of one component sit together);
     the merged groups are then packed first-fit decreasing. Over MAX_FANOUT
     bins, T doubles (staying below w) and the packing repeats. Every bin is
     a child, and since T < w there are always two or more.
  5. W5b: for each meaning leaf with unlinked claims, ONE leaf holding exactly
     those claims (a MIRROR of the meaning leaf), directly under the root.
     It fits because the meaning leaves come resolved (each fits) and a
     mirror is a subset of one.

**Ids.** W4's mint with hierarchy "links": the root "{map}|links|{theme}|root",
every other group from its sorted member claims. The box-side apply mints
the same strings in Rust and refuses any id that differs.

Files that cross the box boundary (plain JSON plus raw little-endian float32):
  * an export directory: `export.json` (EXPORT_FORMAT: map, hierarchy, cap,
    seed, dim, and per theme its claim, linked, link, attachment-node and
    meaning-leaf counts), and per theme `<theme_id>.json` ({"claim_ids",
    "attachments", "links", "meaning_leaf"}: links as sorted [i, j] pairs
    with i < j, meaning_leaf one integer per claim) and `<theme_id>.f32` (the
    embeddings of the LINKED claims only, in claim_ids order: an unlinked
    claim's embedding never leaves the box, since only linked claims are ever
    cut by embedding);
  * a result (RESULT_FORMAT): per theme its groups in pre-order (W4's group
    shape), plus the library versions, since ids persist only while the
    clustering reproduces.

Usage (off the box; needs numpy, scikit-learn, umap-learn, networkx, no DB
driver):
    python3 scripts/atlas_links_core.py compute --from export-dir/ --out result.json
"""
import argparse
import json
import math
import pathlib
import sys
from collections import defaultdict

import networkx as nx
import numpy as np

try:  # imported as scripts.atlas_links_core (tests) or run from scripts/
    from scripts import atlas_meaning_core as meaning
except ImportError:  # pragma: no cover - the off-box CLI path
    import atlas_meaning_core as meaning

EXPORT_FORMAT = "atlas-links-export/1"
RESULT_FORMAT = "atlas-links-result/1"
HIERARCHY = "links"

DEFAULT_CAP = meaning.DEFAULT_CAP
DEFAULT_SEED = meaning.DEFAULT_SEED
MAX_FANOUT = meaning.MAX_FANOUT
MAX_CHILDREN = meaning.MAX_CHILDREN
MAX_DEPTH = meaning.MAX_DEPTH

root_id = meaning.root_id
group_id = meaning.group_id


# ── input ───────────────────────────────────────────────────────────────────

def _prepare(ids, attachments, links, meaning_leaf, embeddings, map_key, cap):
    """Sort everything by claim id. Returns (ids, att, pairs, ml, x)."""
    if cap < 1:
        raise ValueError("cap must be at least 1")
    meaning._check_map_key(map_key)
    ids = [meaning._canon(i) for i in ids]
    n = len(ids)
    if len(set(ids)) != n:
        raise ValueError("claim ids must be unique")
    if len(attachments) != n or len(meaning_leaf) != n:
        raise ValueError(f"need one attachment list and one meaning leaf per id ({n} ids, "
                         f"{len(attachments)} lists, {len(meaning_leaf)} meaning leaves)")
    x = np.asarray(embeddings, dtype=np.float32)
    if n and (x.ndim != 2 or len(x) != n):
        raise ValueError(f"need one embedding row per id ({n} ids, embeddings {x.shape})")
    order = sorted(range(n), key=ids.__getitem__)
    new = {old: k for k, old in enumerate(order)}
    pairs = set()
    for a, b in links:
        a, b = int(a), int(b)
        if not (0 <= a < n and 0 <= b < n):
            raise ValueError(f"link ({a}, {b}) names no claim")
        if a != b:
            a, b = new[a], new[b]
            pairs.add((min(a, b), max(a, b)))
    ids = [ids[i] for i in order]
    att = [sorted({int(v) for v in attachments[i]}) for i in order]
    ml = [int(meaning_leaf[i]) for i in order]
    x = x[order] if n else x
    for c, a in zip(ids, att):
        if 1 + len(a) > cap:
            raise ValueError(f"claim {c} is over the cap on its own ({1 + len(a)} > {cap} "
                             "nodes); the export must apply W3's per-claim cap")
    return ids, att, sorted(pairs), ml, x


def _weight(idx, att):
    return meaning._weight(idx, att)


# ── units: L decomposed bottom-up ───────────────────────────────────────────

def _subgraph(idx, adj):
    """The subgraph on `idx` (sorted index array), nodes and edges added in
    index order, so everything that walks it is deterministic."""
    members = set(int(i) for i in idx)
    g = nx.Graph()
    g.add_nodes_from(int(i) for i in idx)
    g.add_edges_from((int(a), b) for a in idx for b in sorted(adj[int(a)])
                     if b > a and b in members)
    return g


def _sorted_sets(sets):
    return [np.asarray(sorted(c)) for c in sorted(sets, key=min)]


def _units(idx, adj, x, att, cap, seed, stats):
    """`idx` cut into units that each fit the cap. A set that fits is a unit.
    Otherwise a disconnected set is cut into its connected components (a
    component that fits is never cut); a connected one into its Louvain
    communities; a community Louvain will not split (one dense community) by
    W4's embedding split. Each part is cut again the same way."""
    if _weight(idx, att) <= cap:
        return [idx]
    g = _subgraph(idx, adj)
    parts = _sorted_sets(nx.connected_components(g))
    if len(parts) < 2:
        parts = _sorted_sets(nx.community.louvain_communities(g, seed=seed))
    if len(parts) < 2:
        stats["embedding_splits"] += 1
        parts = meaning._split(idx, x, att, cap, seed, stats)
        if len(parts) < 2:  # pragma: no cover - _split always cuts in two or more
            raise ValueError("the embedding split did not cut a community over the cap")
    out = []
    for p in sorted(parts, key=lambda p: int(np.min(p))):
        out.extend(_units(np.sort(np.asarray(p)), adj, x, att, cap, seed, stats))
    return out


# ── packing: units top-down ─────────────────────────────────────────────────

def _pack(units, unit_nbrs, att, cap):
    """Bins (lists of unit indices) of `units`, each a child of one level.
    Two or more bins, at most MAX_FANOUT unless the units cannot be packed so
    (then at most MAX_CHILDREN).

    Two passes against a target weight T: first the linked units are merged,
    most links first (ties: smaller unit indices), while the merged bin still
    weighs at most T, so units that Louvain cut out of one component sit
    together; then the bins are packed first-fit decreasing (by weight, then
    smallest claim) into bins of at most T. Over MAX_FANOUT bins, T doubles
    (staying below the total weight, so there are always two or more bins)."""
    all_idx = np.concatenate(list(units))
    w = _weight(all_idx, att)
    k = min(MAX_FANOUT, max(2, math.ceil(w / cap)))
    target = max(cap, math.ceil(w / k))
    unit_nodes = [set().union(*(att[i] for i in units[u])) for u in range(len(units))]
    pairs = sorted((-cnt, u, v) for u in range(len(units))
                   for v, cnt in unit_nbrs[u].items() if u < v)

    def weight(members, nodes):
        return members + len(nodes)

    while True:
        # Pass 1: merge linked units, most links first.
        root = list(range(len(units)))
        size = [len(units[u]) for u in range(len(units))]
        nodes = [set(unit_nodes[u]) for u in range(len(units))]
        merged = [[u] for u in range(len(units))]

        def find(u):
            while root[u] != u:
                root[u] = root[root[u]]
                u = root[u]
            return u

        for _, u, v in pairs:
            a, b = find(u), find(v)
            if a == b or weight(size[a] + size[b], nodes[a] | nodes[b]) > target:
                continue
            a, b = min(a, b), max(a, b)
            root[b] = a
            size[a] += size[b]
            nodes[a] |= nodes[b]
            merged[a].extend(merged[b])
        groups = [merged[u] for u in range(len(units)) if find(u) == u]
        # Pass 2: first-fit decreasing of the merged groups.
        gw = {id(gr): (weight(sum(len(units[u]) for u in gr),
                              set().union(*(unit_nodes[u] for u in gr))),
                       min(int(np.min(units[u])) for u in gr)) for gr in groups}
        groups.sort(key=lambda gr: (-gw[id(gr)][0], gw[id(gr)][1]))
        bins, bin_size, bin_nodes = [], [], []
        for gr in groups:
            g_size = sum(len(units[u]) for u in gr)
            g_nodes = set().union(*(unit_nodes[u] for u in gr))
            for b in range(len(bins)):
                if weight(bin_size[b] + g_size, bin_nodes[b] | g_nodes) <= target:
                    bins[b].extend(gr)
                    bin_size[b] += g_size
                    bin_nodes[b] |= g_nodes
                    break
            else:
                bins.append(list(gr))
                bin_size.append(g_size)
                bin_nodes.append(set(g_nodes))
        grown = min(target * 2, w - 1)
        if len(bins) <= MAX_FANOUT or grown <= target:
            break
        target = grown
    if not 2 <= len(bins) <= MAX_CHILDREN:
        raise ValueError(f"the links packing made {len(bins)} children")
    return [sorted(b) for b in bins]


def _unit_neighbours(units, adj):
    unit_of = {}
    for u, idx in enumerate(units):
        for i in idx:
            unit_of[int(i)] = u
    nbrs = [defaultdict(int) for _ in units]
    for u, idx in enumerate(units):
        for i in idx:
            for j in adj[int(i)]:
                v = unit_of.get(j)
                if v is not None and v != u:
                    nbrs[u][v] += 1
    return [dict(n) for n in nbrs]


# ── the tree ────────────────────────────────────────────────────────────────

def _order(parts):
    """Children by claim count descending, then by smallest claim (ids are
    sorted, so the smallest index is the smallest id)."""
    return sorted(parts, key=lambda p: (-len(p[1]), int(np.min(p[1]))))


def build_tree(ids, attachments, links, meaning_leaf, embeddings, *, map_key, theme_id,
               cap=DEFAULT_CAP, seed=DEFAULT_SEED):
    """The "by links" hierarchy of one theme on one map: its groups in
    pre-order (the root first) and a stats dict.

    `links` are (i, j) index pairs into `ids`; `meaning_leaf[i]` is claim i's
    "by meaning" leaf as any integer (claims sharing one share a leaf);
    `embeddings` has one row per claim (the rows of unlinked claims are never
    read). Pure and deterministic: the input is sorted by claim id first, so
    the result does not depend on the order rows arrive in."""
    ids, att, pairs, ml, x = _prepare(ids, attachments, links, meaning_leaf, embeddings,
                                      map_key, cap)
    stats = {"id_chunk_cuts": 0, "embedding_splits": 0, "linked": 0, "unlinked": 0,
             "mirrors": 0}
    if not ids:
        return [], stats
    n = len(ids)
    adj = [set() for _ in range(n)]
    for a, b in pairs:
        adj[a].add(b)
        adj[b].add(a)
    linked = np.asarray([i for i in range(n) if adj[i]], dtype=int)
    unlinked = [i for i in range(n) if not adj[i]]
    stats["linked"], stats["unlinked"] = len(linked), len(unlinked)
    groups = []

    def leaf(idx, depth, parent):
        idx = np.sort(np.asarray(idx))
        members = [ids[i] for i in idx]
        gid = root_id(map_key, HIERARCHY, theme_id) if parent is None else \
            group_id(map_key, HIERARCHY, theme_id, members)
        groups.append({"id": gid, "parent": parent, "depth": depth, "claim_count": len(idx),
                       "weight": _weight(idx, att), "kind": "leaf", "members": members})
        return gid

    def group(idx, depth, parent, children):
        """`children`: (kind, claims, payload) with kind "leaf" (payload
        None) or "units" (payload: the unit arrays of a bin)."""
        if depth >= MAX_DEPTH:
            raise ValueError(f"theme {theme_id} needs more than {MAX_DEPTH} levels")
        if not 2 <= len(children) <= MAX_CHILDREN:
            raise ValueError(f"a links level would have {len(children)} children")
        members = [ids[i] for i in np.sort(idx)]
        gid = root_id(map_key, HIERARCHY, theme_id) if parent is None else \
            group_id(map_key, HIERARCHY, theme_id, members)
        g = {"id": gid, "parent": parent, "depth": depth, "claim_count": len(idx),
             "weight": _weight(idx, att), "kind": "group"}
        groups.append(g)
        g["children"] = [node(c, depth + 1, gid) for c in _order(children)]
        return gid

    def bins_of(units):
        nbrs = _unit_neighbours(units, adj)
        out = []
        for b in _pack(units, nbrs, att, cap):
            parts = [units[u] for u in b]
            out.append(("units", np.sort(np.concatenate(parts)), parts))
        return out

    def node(child, depth, parent):
        kind, idx, parts = child
        if kind == "leaf" or len(parts) == 1 or _weight(idx, att) <= cap:
            return leaf(idx, depth, parent)
        return group(idx, depth, parent, bins_of(parts))

    everything = np.arange(n)
    if _weight(everything, att) <= cap:
        leaf(everything, 0, None)
        return groups, stats

    children = []
    if len(linked):
        if _weight(linked, att) <= cap:
            children.append(("leaf", linked, None))
        else:
            children.extend(bins_of(_units(linked, adj, x, att, cap, seed, stats)))
    by_leaf = defaultdict(list)
    for i in unlinked:
        by_leaf[ml[i]].append(i)
    for m in sorted(by_leaf):
        idx = np.asarray(by_leaf[m])
        if _weight(idx, att) > cap:
            raise ValueError(f"theme {theme_id}: the unlinked claims of one meaning leaf weigh "
                             f"{_weight(idx, att)} > {cap}; the meaning leaves must come "
                             "resolved (every one within the cap)")
        children.append(("leaf", idx, None))
    stats["mirrors"] = len(by_leaf)
    group(everything, 0, None, children)
    return groups, stats


def validate_tree(groups, ids, attachments, links, meaning_leaf, *, map_key, theme_id, cap):
    """Raise ValueError unless `groups` is a well-formed links tree over `ids`:
    W4's structural check (one root, ids as minted, parents and depths that
    chain, two or more children per group, every claim in exactly one leaf,
    every leaf within the cap), and the W5b mirror rule: unless the whole
    theme is one root leaf, every leaf holding an unlinked claim holds exactly
    the unlinked claims of that claim's meaning leaf."""
    meaning.validate_tree(groups, ids, attachments, map_key=map_key, theme_id=theme_id,
                          cap=cap, hierarchy=HIERARCHY)
    ids = [meaning._canon(i) for i in ids]
    has_link = [False] * len(ids)
    for a, b in links:
        if int(a) != int(b):
            has_link[int(a)] = has_link[int(b)] = True
    mirror = defaultdict(set)
    for i, c in enumerate(ids):
        if not has_link[i]:
            mirror[int(meaning_leaf[i])].add(c)
    leaf_of_meaning = {c: int(meaning_leaf[i]) for i, c in enumerate(ids) if not has_link[i]}
    leaves = [g for g in groups if g["kind"] == "leaf"]
    if len(groups) == 1:
        return
    for g in leaves:
        members = set(g["members"])
        for c in members:
            if c in leaf_of_meaning and members != mirror[leaf_of_meaning[c]]:
                raise ValueError(f"leaf {g['id']} holds unlinked claim {c} but is not the "
                                 "mirror of its meaning leaf")


# ── files ───────────────────────────────────────────────────────────────────

def write_export(export_dir, map_key, *, cap, seed, dim, themes):
    """Write an export directory. `themes` maps theme id to (ids, attachments,
    links, meaning_leaf, X), ids sorted, X one row per claim (only the linked
    claims' rows are written). The Rust export writer produces the same bytes
    (tests)."""
    export_dir = pathlib.Path(export_dir)
    export_dir.mkdir(parents=True, exist_ok=True)
    entries = []
    for theme_id in sorted(themes):
        ids, att, links, ml, x = themes[theme_id]
        if list(ids) != sorted(ids):
            raise ValueError(f"theme {theme_id}: ids must be sorted")
        pairs = sorted({(min(int(a), int(b)), max(int(a), int(b))) for a, b in links
                        if int(a) != int(b)})
        has_link = sorted({i for p in pairs for i in p})
        x = np.asarray(x, dtype="<f4")
        if x.shape != (len(ids), dim):
            raise ValueError(f"theme {theme_id}: embeddings {x.shape}, want ({len(ids)}, {dim})")
        (export_dir / f"{theme_id}.json").write_text(meaning._dumps({
            "claim_ids": list(ids), "attachments": [list(a) for a in att],
            "links": [list(p) for p in pairs], "meaning_leaf": [int(m) for m in ml]}))
        (export_dir / f"{theme_id}.f32").write_bytes(x[has_link].tobytes())
        nodes = set().union(*(set(a) for a in att)) if att else set()
        entries.append({"theme_id": theme_id, "claims": len(ids), "linked": len(has_link),
                        "links": len(pairs), "attachment_nodes": len(nodes),
                        "meaning_leaves": len(set(int(m) for m in ml))})
    index = {"format": EXPORT_FORMAT, "map": map_key, "hierarchy": HIERARCHY, "cap": cap,
             "seed": seed, "dim": dim, "themes": entries}
    (export_dir / "export.json").write_text(meaning._dumps(index))


def read_export_theme(export_dir, theme_id, dim):
    """One theme of an export: (ids, attachments, links, meaning_leaf, X), X
    one row per claim, zero for the unlinked claims (not exported)."""
    export_dir = pathlib.Path(export_dir)
    doc = json.loads((export_dir / f"{meaning._canon(theme_id)}.json").read_text())
    ids = [meaning._canon(c) for c in doc["claim_ids"]]
    att = [[int(a) for a in lst] for lst in doc["attachments"]]
    links = [(int(a), int(b)) for a, b in doc["links"]]
    ml = [int(m) for m in doc["meaning_leaf"]]
    n = len(ids)
    if len(att) != n or len(ml) != n:
        raise ValueError(f"theme {theme_id}: {len(att)} attachment lists and {len(ml)} meaning "
                         f"leaves for {n} ids")
    for a, b in links:
        if not (0 <= a < b < n):
            raise ValueError(f"theme {theme_id}: link ({a}, {b}) is not an ordered pair of claims")
    has_link = sorted({i for p in links for i in p})
    raw = np.fromfile(export_dir / f"{theme_id}.f32", dtype="<f4")
    if raw.size != len(has_link) * dim:
        raise ValueError(f"theme {theme_id}: the embedding file holds {raw.size} floats, "
                         f"want {len(has_link)} linked claims x {dim}")
    x = np.zeros((n, dim), dtype=np.float32)
    if has_link:
        x[has_link] = raw.reshape(len(has_link), dim)
    return ids, att, links, ml, x


def _versions():
    v = meaning._versions()
    v["networkx"] = nx.__version__
    return {k: v[k] for k in ("numpy", "scikit-learn", "umap-learn", "networkx", "python")}


def compute_export_dir(export_dir, cap=None, seed=None):
    """Build and validate every theme's tree of an export. Returns the result
    document (RESULT_FORMAT). `cap` and `seed` default to the export's."""
    export_dir = pathlib.Path(export_dir)
    index = json.loads((export_dir / "export.json").read_text())
    if index.get("format") != EXPORT_FORMAT:
        raise ValueError(f"not a {EXPORT_FORMAT} export: {index.get('format')!r}")
    if index.get("hierarchy") != HIERARCHY:
        raise ValueError(f"not a {HIERARCHY} export: {index.get('hierarchy')!r}")
    map_key = meaning._check_map_key(index["map"])
    cap = int(cap if cap is not None else index["cap"])
    seed = int(seed if seed is not None else index["seed"])
    dim = int(index["dim"])
    themes = []
    for entry in index["themes"]:
        theme_id = meaning._canon(entry["theme_id"])
        ids, att, links, ml, x = read_export_theme(export_dir, theme_id, dim)
        groups, stats = build_tree(ids, att, links, ml, x, map_key=map_key, theme_id=theme_id,
                                   cap=cap, seed=seed)
        validate_tree(groups, ids, att, links, ml, map_key=map_key, theme_id=theme_id, cap=cap)
        themes.append({"theme_id": theme_id, "id_chunk_cuts": stats["id_chunk_cuts"],
                       "embedding_splits": stats["embedding_splits"], "groups": groups})
    return {"format": RESULT_FORMAT, "map": map_key, "hierarchy": HIERARCHY, "cap": cap,
            "seed": seed, "versions": _versions(), "themes": themes}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("compute", help="build every theme's links tree of an export (no DB)")
    c.add_argument("--from", dest="src", required=True, help="the export directory")
    c.add_argument("--out", required=True, help="the result file to write")
    args = ap.parse_args(argv)
    result = compute_export_dir(args.src)
    pathlib.Path(args.out).write_text(json.dumps(result, indent=1) + "\n")
    leaves = sum(g["kind"] == "leaf" for t in result["themes"] for g in t["groups"])
    print(f"{len(result['themes'])} themes, {leaves} leaves -> {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
