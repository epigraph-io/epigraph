"""The "by links" hierarchy's pure core and its file formats (no DB).

Atlas W5 (backlog 4e02c23f) with W5b (febb2a77): under each theme of one map,
the claims are grouped by the communities of the claim graph (the counted
epistemic links plus decomposes_to) until every leaf fits the 100-node cap,
weighted as W4 weighs a leaf (claims + DISTINCT attachment nodes). A claim
with no counted link to another member of its theme goes into a links leaf
that mirrors its "by meaning" leaf: exactly the unlinked claims of that leaf.

The core is a pure function of claim ids, per-claim attachment integers, link
index pairs, per-claim meaning-leaf integers and the linked claims'
embeddings, so it can run off the prod box. The box halves (export, apply)
are Rust: crates/epigraph-cli/src/atlas_links. The committed fixture under
crates/epigraph-cli/tests/fixtures/atlas_links is read by both suites.
"""
import json
import os
import pathlib
import subprocess
import sys
import uuid

import numpy as np
import pytest

from scripts import atlas_links_core as core
from scripts import atlas_meaning_core as meaning

REPO = pathlib.Path(__file__).resolve().parents[2]
FIXTURE = REPO / "crates" / "epigraph-cli" / "tests" / "fixtures" / "atlas_links"
TEAM = "5e5e0000-0000-4000-8000-000000007ea0"
THEME = "3c886e23-925e-4966-b135-a7ef81df30a4"
MAP = f"team:{TEAM}"
DIM = 8


def _ids(n, seed):
    rng = np.random.RandomState(seed)
    out = set()
    while len(out) < n:
        out.add(str(uuid.UUID(int=int(rng.randint(0, 2**62)) << 64 | int(rng.randint(0, 2**62)))))
    return sorted(out)


class Theme:
    """A synthetic theme built claim by claim: ids are drawn up front, then
    each claim gets attachments, a meaning leaf and an embedding row."""

    def __init__(self, n, seed=7):
        self.ids = _ids(n, seed)
        self.att = [[] for _ in range(n)]
        self.links = []
        self.meaning_leaf = [0] * n
        self.rng = np.random.RandomState(seed)
        self.x = self.rng.normal(size=(n, DIM)).astype(np.float32)

    def clique(self, idx):
        idx = list(idx)
        for a in range(len(idx)):
            for b in range(a + 1, len(idx)):
                self.links.append((idx[a], idx[b]))

    def path(self, idx):
        idx = list(idx)
        self.links.extend(zip(idx, idx[1:]))

    def build(self, cap=100, seed=42, order=None):
        ids, att, ml, x = self.ids, self.att, self.meaning_leaf, self.x
        links = self.links
        if order is not None:
            pos = {old: new for new, old in enumerate(order)}
            ids = [ids[i] for i in order]
            att = [att[i] for i in order]
            ml = [ml[i] for i in order]
            x = x[order]
            links = [(pos[a], pos[b]) for a, b in links]
        return core.build_tree(ids, att, links, ml, x, map_key=MAP, theme_id=THEME,
                               cap=cap, seed=seed)

    def validate(self, groups, cap=100):
        core.validate_tree(groups, self.ids, self.att, self.links, self.meaning_leaf,
                           map_key=MAP, theme_id=THEME, cap=cap)


def _leaves(groups):
    return [g for g in groups if g["kind"] == "leaf"]


def _leaf_of(groups):
    return {c: g["id"] for g in _leaves(groups) for c in g["members"]}


def _weight(members, t):
    pos = {c: i for i, c in enumerate(t.ids)}
    nodes = set()
    for c in members:
        nodes.update(t.att[pos[c]])
    return len(members) + len(nodes)


@pytest.fixture(scope="module")
def realistic():
    """600 claims: 12 dense clusters of 30 (a few cross links), 60 claims in
    chains of 3 (paper reasoning via decomposes_to), 180 unlinked claims in
    six meaning leaves. Four shared agents and one to three evidence rows per
    claim, as measured (evidence per claim p50 1, p99 3)."""
    t = Theme(600, seed=11)
    rng = np.random.RandomState(3)
    for i in range(600):
        t.att[i] = [int(rng.randint(0, 4))] + [1000 + 3 * i + k for k in range(1 + (i % 7 == 0) * 2)]
    for c in range(12):
        members = range(30 * c, 30 * c + 30)
        for a in members:
            for b in members:
                if a < b and rng.rand() < 0.4:
                    t.links.append((a, b))
        t.links.append((30 * c, (30 * c + 45) % 360))
    for p in range(20):
        t.path(range(360 + 3 * p, 363 + 3 * p))
    for i in range(420, 600):
        t.meaning_leaf[i] = 1 + (i - 420) // 30
    for i in range(420):
        t.meaning_leaf[i] = 7 + i // 60
    return t, t.build()


def test_every_leaf_weight_is_within_the_cap(realistic):
    t, (groups, _) = realistic
    leaves = _leaves(groups)
    assert len(leaves) >= 8
    for g in leaves:
        assert _weight(g["members"], t) <= 100, g["id"]
        assert g["weight"] == _weight(g["members"], t)
    t.validate(groups)


def test_a_densely_linked_cluster_stays_in_one_leaf(realistic):
    t, (groups, _) = realistic
    leaf_of = _leaf_of(groups)
    for c in range(12):
        cluster = {leaf_of[t.ids[i]] for i in range(30 * c, 30 * c + 30)}
        assert len(cluster) == 1, f"cluster {c} is spread over {len(cluster)} leaves"
    for p in range(20):
        chain = {leaf_of[t.ids[i]] for i in range(360 + 3 * p, 363 + 3 * p)}
        assert len(chain) == 1, f"chain {p} was cut"


def test_louvain_finds_dense_clusters_whatever_their_ids():
    """ONE connected component of four dense clusters of 45 claims (each 45
    + 45 evidence = 90 nodes) joined by single bridges, the clusters' claims
    interleaved in id order: only the community detection can separate them
    (no cut by position or by component would), and each lands whole in one
    leaf."""
    t = Theme(180, seed=19)
    rng = np.random.RandomState(4)
    for i in range(180):
        t.att[i] = [500 + i]
    cluster = [list(range(k, 180, 4)) for k in range(4)]
    for members in cluster:
        for a in members:
            for b in members:
                if a < b and rng.rand() < 0.5:
                    t.links.append((a, b))
    for k in range(3):
        t.links.append((cluster[k][0], cluster[k + 1][0]))
    groups, _ = t.build()
    leaf_of = _leaf_of(groups)
    for k, members in enumerate(cluster):
        assert len({leaf_of[t.ids[i]] for i in members}) == 1, f"cluster {k} was cut"
    t.validate(groups)


def test_a_fitting_component_is_never_split_across_leaves():
    """Four separate components of 30 claims (each 30 + 30 evidence = 60
    nodes, fits) in a theme of 240 nodes: each component lands whole in one
    leaf; packing never cuts a unit."""
    t = Theme(120, seed=5)
    for i in range(120):
        t.att[i] = [500 + i]
    for c in range(4):
        t.path(range(30 * c, 30 * c + 30))
    groups, _ = t.build()
    leaf_of = _leaf_of(groups)
    for c in range(4):
        assert len({leaf_of[t.ids[i]] for i in range(30 * c, 30 * c + 30)}) == 1
    t.validate(groups)


def test_parts_of_one_component_are_packed_together():
    """16 components, each two 60-claim cliques joined by one link (120
    nodes, over the cap, so Louvain cuts it in two units). The halves are
    numbered apart (every first half before every second half), so packing
    by position alone would pair two first halves; packing by links keeps
    each component's halves under one parent."""
    t = Theme(1920, seed=17)
    first = lambda p: range(60 * p, 60 * p + 60)  # noqa: E731
    second = lambda p: range(960 + 60 * p, 960 + 60 * p + 60)  # noqa: E731
    for p in range(16):
        t.clique(first(p))
        t.clique(second(p))
        t.links.append((60 * p, 960 + 60 * p))
    groups, _ = t.build()
    parent = {c: g["parent"] for g in _leaves(groups) for c in g["members"]}
    for p in range(16):
        a, b = t.ids[60 * p], t.ids[960 + 60 * p]
        assert parent[a] == parent[b], f"component {p}'s halves were packed apart"
        assert parent[a] != groups[0]["id"], "each component is a group of its two halves"
    t.validate(groups)


def test_a_clique_over_the_cap_is_split_by_embedding():
    """One clique of 120 claims will not split by modularity, so W4's
    embedding split cuts it: two tight blobs in the clique's embeddings end
    up in different leaves, each leaf one blob."""
    t = Theme(120, seed=9)
    t.clique(range(120))
    centres = np.eye(DIM, dtype=np.float32)
    for i in range(120):
        t.x[i] = centres[i % 2] + 0.01 * t.rng.normal(size=DIM)
    groups, stats = t.build()
    assert stats["embedding_splits"] >= 1
    for g in _leaves(groups):
        blobs = {t.ids.index(c) % 2 for c in g["members"]}
        assert len(blobs) == 1, "a leaf mixes the two blobs"
    t.validate(groups)


def test_an_unlinked_claim_lands_in_its_meaning_leafs_mirror(realistic):
    t, (groups, stats) = realistic
    assert stats["unlinked"] == 180 and stats["mirrors"] == 6
    leaves = {g["id"]: set(g["members"]) for g in _leaves(groups)}
    leaf_of = _leaf_of(groups)
    for i in range(420, 600):
        want = {t.ids[j] for j in range(420, 600) if t.meaning_leaf[j] == t.meaning_leaf[i]}
        assert leaves[leaf_of[t.ids[i]]] == want
    # And the mirror's id is the links mint of exactly those claims.
    some = {t.ids[j] for j in range(420, 450)}
    assert core.group_id(MAP, "links", THEME, some) in leaves


def test_a_linked_claim_is_never_in_a_mirror(realistic):
    t, (groups, _) = realistic
    unlinked = set(t.ids[420:600])
    for g in _leaves(groups):
        m = set(g["members"])
        assert m <= unlinked or not (m & unlinked), g["id"]


def test_no_level_has_a_single_child(realistic):
    _, (groups, _) = realistic
    for g in groups:
        if g["kind"] == "group":
            assert len(g["children"]) >= 2, g["id"]


def test_rerun_reproduces_every_group_id(realistic):
    t, (groups, _) = realistic
    again, _ = t.build()
    assert again == groups
    order = list(np.random.RandomState(1).permutation(len(t.ids)))
    shuffled, _ = t.build(order=order)
    assert {g["id"] for g in shuffled} == {g["id"] for g in groups}
    assert sorted(map(json.dumps, shuffled)) == sorted(map(json.dumps, groups))


def test_many_small_components_keep_the_root_fanout_bounded():
    """2,000 claims in 1,000 linked pairs: 1,000 units, packed into at most
    16 children per level (so the tree nests), every pair whole, and no
    leaf left as a crumb of one or two pairs."""
    t = Theme(2000, seed=13)
    for p in range(1000):
        t.links.append((2 * p, 2 * p + 1))
    groups, _ = t.build()
    for g in groups:
        if g["kind"] == "group":
            assert 2 <= len(g["children"]) <= core.MAX_FANOUT, (g["depth"], len(g["children"]))
    assert any(g["depth"] == 2 for g in groups), "2,000 nodes need a second level"
    leaf_of = _leaf_of(groups)
    for p in range(1000):
        assert leaf_of[t.ids[2 * p]] == leaf_of[t.ids[2 * p + 1]]
    for g in _leaves(groups):
        assert len(g["members"]) >= 20, "packing fills leaves instead of leaving crumbs"
    t.validate(groups)


def test_a_theme_under_the_cap_is_one_root_leaf():
    t = Theme(40, seed=2)
    t.path(range(10))
    for i in range(10, 40):
        t.meaning_leaf[i] = i % 3
    groups, _ = t.build()
    assert len(groups) == 1
    assert groups[0]["kind"] == "leaf" and groups[0]["parent"] is None
    assert groups[0]["id"] == core.root_id(MAP, "links", THEME)
    assert sorted(groups[0]["members"]) == t.ids


def test_a_theme_with_no_links_mirrors_every_meaning_leaf():
    t = Theme(150, seed=4)
    for i in range(150):
        t.meaning_leaf[i] = i // 50
    groups, stats = t.build()
    assert stats["linked"] == 0
    root = groups[0]
    assert root["kind"] == "group" and len(root["children"]) == 3
    want = {core.group_id(MAP, "links", THEME, t.ids[50 * k: 50 * k + 50]) for k in range(3)}
    assert set(root["children"]) == want
    t.validate(groups)


def _many_mirrors(n_leaves, per_leaf, seed, shared_agents=4):
    """A theme of two linked clusters (one bin each) and `n_leaves` meaning
    leaves of `per_leaf` unlinked claims, each claim with one of a few shared
    agents and an evidence row of its own. The meaning-leaf integers are
    shuffled against the claim ids, so meaning-leaf order and claim-id order
    differ."""
    n = 60 + n_leaves * per_leaf
    t = Theme(n, seed=seed)
    for i in range(n):
        t.att[i] = [i % shared_agents, 1000 + i]
    t.clique(range(0, 30))
    t.clique(range(30, 60))
    perm = np.random.RandomState(seed).permutation(n_leaves)
    for i in range(60, n):
        t.meaning_leaf[i] = 10 + int(perm[(i - 60) // per_leaf])
    for i in range(60):
        t.meaning_leaf[i] = i // 30
    return t


def _check_nested_mirrors(t, groups, cap=100):
    """Every leaf holding an unlinked claim is its exact mirror; every group
    of mirrors holds two or more children, weighs over the cap (so it could
    not have been a leaf) and holds no linked claim; the root holds at most
    MAX_FANOUT children and every level at most MAX_CHILDREN. (A group of
    mirrors can be wider than MAX_FANOUT: cutting it further would make
    groups that fit, which must be leaves, and a leaf of two mirrors breaks
    the mirror rule.)"""
    t.validate(groups, cap=cap)
    by_id = {g["id"]: g for g in groups}
    linked = {t.ids[i] for p in t.links for i in p}

    def claims(g):
        if g["kind"] == "leaf":
            return set(g["members"])
        return set().union(*(claims(by_id[k]) for k in g["children"]))

    mirror_groups = 0
    for g in groups:
        if g["kind"] != "group":
            continue
        limit = core.MAX_FANOUT if g["parent"] is None else core.MAX_CHILDREN
        assert 2 <= len(g["children"]) <= limit, (g["depth"], len(g["children"]))
        if g["parent"] is not None and not (claims(g) & linked):
            mirror_groups += 1
            assert _weight(claims(g), t) > cap, "a group of mirrors that fits must not exist"
    return mirror_groups


def test_many_mirror_leaves_nest_under_the_root():
    """390 unlinked claims in 130 meaning leaves plus two linked bins: flat,
    the root would hold 132 children, over the contract's 128 (the whole map
    refused). Nested, every level holds at most MAX_FANOUT children, every
    mirror is still exact, and the mirrors are grouped in meaning-leaf order."""
    t = _many_mirrors(130, 3, seed=21)
    groups, stats = t.build()
    assert stats["mirrors"] == 130
    assert _check_nested_mirrors(t, groups) >= 2
    by_id = {g["id"]: g for g in groups}
    # A mirror group holds a contiguous run of meaning leaves.
    for g in groups:
        if g["kind"] == "group" and g["parent"] is not None:
            kids = [by_id[k] for k in g["children"]]
            if all(k["kind"] == "leaf" for k in kids):
                ml = sorted({t.meaning_leaf[t.ids.index(k["members"][0])] for k in kids})
                if ml[0] >= 10:
                    assert ml == list(range(ml[0], ml[-1] + 1))
    again, _ = t.build(order=list(np.random.RandomState(5).permutation(len(t.ids))))
    assert sorted(map(json.dumps, again)) == sorted(map(json.dumps, groups))


def test_a_few_dozen_mirrors_keep_the_root_fanout_bounded():
    """40 mirrors under the 128-child limit still nest: the root fanout stays
    within the MAX_FANOUT the packing aims for."""
    t = _many_mirrors(40, 3, seed=22)
    groups, _ = t.build()
    assert _check_nested_mirrors(t, groups) >= 2
    assert len(groups[0]["children"]) <= core.MAX_FANOUT


def test_mirrors_too_light_to_nest_beyond_the_child_limit_are_refused():
    """130 one-claim mirrors with no attachments weigh 130 together: they
    cannot make two groups over the cap of 100, and flat they are over the
    128-child limit, so the theme is refused (fail closed), naming the
    counts."""
    t = Theme(190, seed=23)
    t.clique(range(0, 30))
    t.clique(range(30, 60))
    for i in range(190):
        t.meaning_leaf[i] = i if i >= 60 else i // 30
    with pytest.raises(ValueError, match="130 mirror leaves weighing 130"):
        t.build()


def test_ids_match_the_golden_vector():
    # The same vectors are pinned in crates/epigraph-cli/src/atlas_links/graph.rs.
    assert core.root_id(MAP, "links", THEME) == "a3f580a9-6493-540c-a047-19edb935e318"
    assert core.root_id("public", "links", THEME) == "ea9a52a2-1e97-58f5-b155-74a2713eb4a4"
    c1 = "00000000-0000-4000-8000-000000000001"
    c2 = "00000000-0000-4000-8000-000000000002"
    assert core.group_id(MAP, "links", THEME, [c2, c1]) == "3d72648d-1698-5960-8c99-42f5afd56350"
    assert core.group_id(MAP, "links", THEME, [c1, c2]) != \
        meaning.group_id(MAP, "meaning", THEME, [c1, c2])


def test_a_mirror_over_the_cap_is_refused():
    """The meaning leaves come resolved (every one fits), so an unlinked set
    of one meaning leaf over the cap means the input is not a resolved tree."""
    t = Theme(120, seed=6)
    with pytest.raises(ValueError, match="meaning leaf"):
        t.build()


def test_a_claim_over_the_cap_alone_is_refused():
    t = Theme(3, seed=1)
    t.att[0] = list(range(100))
    with pytest.raises(ValueError, match="over the cap on its own"):
        t.build()


def _remint(gs):
    """Re-mint every id of a hand-edited tree from its members, so a breakage
    reaches the check it targets instead of failing the id check first."""
    by_id = {g["id"]: g for g in gs}
    root = next(g for g in gs if g["parent"] is None)
    new = {}

    def under(g):
        if g["kind"] == "leaf":
            claims = set(g["members"])
        else:
            claims = set().union(*(under(by_id[k]) for k in g["children"]))
        new[g["id"]] = core.root_id(MAP, "links", THEME) if g is root else \
            core.group_id(MAP, "links", THEME, claims)
        return claims

    under(root)
    for g in gs:
        g["id"] = new[g["id"]]
        if g["parent"] is not None:
            g["parent"] = new[g["parent"]]
        if g["kind"] == "group":
            g["children"] = [new[k] for k in g["children"]]


def _breakages(t, groups):
    unlinked = set(t.ids[420:600])
    leaves = _leaves(groups)
    mirrors = [g for g in leaves if set(g["members"]) <= unlinked]
    linked_leaf = next(g for g in leaves if not set(g["members"]) & unlinked)

    def edit(gs, gid, fn):
        for g in gs:
            if g["id"] == gid:
                g["members"] = fn(g["members"])

    def forged(gs):
        gs[1]["id"] = str(uuid.uuid4())

    def single_child(gs):
        root_ = gs[0]
        kid = root_["children"][0]
        rest = root_["children"][1:]
        for g in gs:
            if g["id"] in rest:
                g["parent"] = kid
        root_["children"] = [kid]

    def mirror_with_linked_claim(gs):
        moved = linked_leaf["members"][0]
        edit(gs, mirrors[0]["id"], lambda m: m + [moved])
        edit(gs, linked_leaf["id"], lambda m: m[1:])
        _remint(gs)

    def mirror_split(gs):
        # One unlinked claim moved into another mirror: still covered and
        # minted, no longer its meaning leaf's mirror.
        moved = mirrors[0]["members"][0]
        edit(gs, mirrors[0]["id"], lambda m: m[1:])
        edit(gs, mirrors[1]["id"], lambda m: m + [moved])
        _remint(gs)

    def unlinked_in_linked_leaf(gs):
        moved = mirrors[0]["members"][0]
        edit(gs, mirrors[0]["id"], lambda m: m[1:])
        edit(gs, linked_leaf["id"], lambda m: m + [moved])
        _remint(gs)

    def member_twice(gs):
        edit(gs, mirrors[0]["id"], lambda m: m + [linked_leaf["members"][0]])

    return {"forged_id": forged, "single_child": single_child,
            "mirror_with_linked_claim": mirror_with_linked_claim,
            "mirror_split": mirror_split, "unlinked_in_linked_leaf": unlinked_in_linked_leaf,
            "member_twice": member_twice}


@pytest.mark.parametrize("breakage", ["forged_id", "single_child", "mirror_with_linked_claim",
                                      "mirror_split", "unlinked_in_linked_leaf",
                                      "member_twice"])
def test_validate_tree_refuses_a_malformed_tree(realistic, breakage):
    t, (groups, _) = realistic
    t.validate(groups)
    broken = json.loads(json.dumps(groups))
    _breakages(t, broken)[breakage](broken)
    with pytest.raises(ValueError):
        t.validate(broken)


# ── the committed fixture, read by both suites ────────────────────────────────

FIXTURE_CAP = 6


def fixture_inputs():
    """The committed export's content, regenerated: 100 claims in 25 linked
    paths of 4, a 9-claim clique (over the cap of 6 alone, so the embedding
    split cuts it, two blobs), and 12 unlinked claims in three meaning leaves.
    No attachments except a shared agent (index 0) on the clique."""
    t = Theme(121, seed=21)
    for p in range(25):
        t.path(range(4 * p, 4 * p + 4))
    t.clique(range(100, 109))
    for i in range(100, 109):
        t.att[i] = [0]
        t.x[i] = np.eye(DIM, dtype=np.float32)[i % 2] + 0.01 * t.rng.normal(size=DIM)
    for i in range(109, 121):
        t.meaning_leaf[i] = 1 + (i - 109) // 4
    for i in range(109):
        t.meaning_leaf[i] = 4 + i // 4
    return t


def test_committed_export_is_the_fixture_inputs():
    t = fixture_inputs()
    index = json.loads((FIXTURE / "export" / "export.json").read_text())
    assert index == {
        "format": core.EXPORT_FORMAT, "map": MAP, "hierarchy": "links",
        "cap": FIXTURE_CAP, "seed": 42, "dim": DIM,
        "themes": [{"theme_id": THEME, "claims": 121, "linked": 109, "links": 111,
                    "attachment_nodes": 1, "meaning_leaves": 31}],
    }
    got = core.read_export_theme(FIXTURE / "export", THEME, DIM)
    ids, att, links, ml, x = got
    assert ids == t.ids and att == t.att and ml == t.meaning_leaf
    assert links == sorted({(min(a, b), max(a, b)) for a, b in t.links})
    assert np.array_equal(x[:109], t.x[:109])
    assert not x[109:].any(), "unlinked claims' embeddings never leave the box"


def test_committed_fixture_reproduces_the_committed_result():
    want = json.loads((FIXTURE / "result.json").read_text())
    got = core.compute_export_dir(FIXTURE / "export")
    want.pop("versions")
    got.pop("versions")
    assert got == want
    (theme,) = got["themes"]
    assert any(g["depth"] == 2 for g in theme["groups"]), "the fixture must nest"
    assert theme["embedding_splits"] >= 1


def test_compute_runs_without_db_driver(tmp_path):
    """`compute` is the off-box step: it must run where no DB driver exists."""
    out = tmp_path / "result.json"
    runner = (
        "import sys, runpy\n"
        "for m in ('psycopg2', 'theme_lib', 'maintenance_dsn', 'sqlalchemy'):\n"
        "    sys.modules[m] = None\n"
        f"sys.argv = ['atlas_links_core.py', 'compute', '--from', "
        f"{str(FIXTURE / 'export')!r}, '--out', {str(out)!r}]\n"
        f"sys.path.insert(0, {str(REPO / 'scripts')!r})\n"
        f"runpy.run_path({str(REPO / 'scripts' / 'atlas_links_core.py')!r}, "
        "run_name='__main__')\n"
    )
    proc = subprocess.run([sys.executable, "-c", runner], capture_output=True, text=True,
                          env={**os.environ, "PYTHONPATH": ""})
    assert proc.returncode == 0, proc.stderr
    result = json.loads(out.read_text())
    assert result["format"] == core.RESULT_FORMAT
    assert set(result["versions"]) == {"numpy", "scikit-learn", "umap-learn", "networkx",
                                       "python"}
    want = json.loads((FIXTURE / "result.json").read_text())
    assert result["themes"] == want["themes"]


def test_export_reader_refuses_a_truncated_embedding_file(tmp_path):
    t = fixture_inputs()
    core.write_export(tmp_path, MAP, cap=FIXTURE_CAP, seed=42, dim=DIM,
                      themes={THEME: (t.ids, t.att, t.links, t.meaning_leaf, t.x)})
    f32 = tmp_path / f"{THEME}.f32"
    f32.write_bytes(f32.read_bytes()[:-4])
    with pytest.raises(ValueError, match="embedding file"):
        core.read_export_theme(tmp_path, THEME, DIM)
