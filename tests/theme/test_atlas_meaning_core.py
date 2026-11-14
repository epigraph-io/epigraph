"""The "by meaning" hierarchy's pure core and its file formats (no DB).

Atlas W4 (backlog f9fc052c): under each theme of one map, the claims are
clustered recursively by embedding until every leaf fits the 100-node cap,
where a leaf's weight is its claims plus its DISTINCT attachment nodes (agents
and evidence, a shared one counted once). The core is a pure function of claim
ids, embeddings and per-claim attachment indices (integers numbered per theme,
never agent or evidence ids), so it can run off the prod box.

The box halves (export, apply) are Rust: crates/epigraph-cli/src/atlas_meaning.
The committed fixture under crates/epigraph-cli/tests/fixtures/atlas_meaning is
read by both suites, so the export and result formats and the group-id mint
cannot drift apart between the two languages.
"""
import json
import os
import pathlib
import subprocess
import sys
import uuid

import numpy as np
import pytest

from scripts import atlas_meaning_core as core

REPO = pathlib.Path(__file__).resolve().parents[2]
FIXTURE = REPO / "crates" / "epigraph-cli" / "tests" / "fixtures" / "atlas_meaning"
TEAM = "5e5e0000-0000-4000-8000-000000007ea0"
THEME = "3c886e23-925e-4966-b135-a7ef81df30a4"
MAP = f"team:{TEAM}"


def _id(rng):
    return str(uuid.UUID(int=int(rng.randint(0, 2**62)) << 64 | int(rng.randint(0, 2**62))))


def _blobs(n_blobs, per_blob, dim, seed, attach=None):
    """Tight, well-separated blobs. `attach(i, rng)` gives claim i's attachment
    indices (default: none). Returns (ids, X, attachments, blob_of_id)."""
    rng = np.random.RandomState(seed)
    ids, rows, att, blob_of = [], [], [], {}
    for b in range(n_blobs):
        centre = rng.normal(size=dim)
        for _ in range(per_blob):
            cid = _id(rng)
            ids.append(cid)
            rows.append(centre + 0.05 * rng.normal(size=dim))
            att.append(attach(len(ids) - 1, rng) if attach else [])
            blob_of[cid] = b
    return ids, np.asarray(rows, dtype=np.float32), att, blob_of


def _build(ids, x, att, cap=100, seed=42):
    return core.build_tree(ids, x, att, map_key=MAP, theme_id=THEME, cap=cap, seed=seed)


def _leaves(groups):
    return [g for g in groups if g["kind"] == "leaf"]


def _weight(members, ids, att):
    pos = {c: i for i, c in enumerate(ids)}
    nodes = set()
    for c in members:
        nodes.update(att[pos[c]])
    return len(members) + len(nodes)


# Agents shared by many claims (most claims come from a few high-degree agents)
# and about one evidence row per claim, sometimes three: the orchestrator's
# measured shape (evidence per claim p50 1, p99 3).
def _realistic(i, rng):
    agent = int(rng.randint(0, 4))  # indices 0..3: four shared agents
    evidence = [1000 + 3 * i + k for k in range(1 + (i % 7 == 0) * 2)]
    return [agent] + evidence


@pytest.fixture(scope="module")
def realistic():
    ids, x, att, blob_of = _blobs(n_blobs=6, per_blob=120, dim=32, seed=11, attach=_realistic)
    groups, stats = _build(ids, x, att)
    return ids, x, att, blob_of, groups, stats


def test_every_leaf_weight_is_within_the_cap(realistic):
    ids, _, att, _, groups, _ = realistic
    leaves = _leaves(groups)
    assert len(leaves) > 1, "720 claims with attachments cannot fit one 100-node leaf"
    for leaf in leaves:
        assert _weight(leaf["members"], ids, att) <= 100, leaf["id"]
        assert leaf["weight"] == _weight(leaf["members"], ids, att)
    covered = sorted(c for leaf in leaves for c in leaf["members"])
    assert covered == sorted(ids), "every claim in exactly one leaf"


def test_the_tree_follows_the_embeddings(realistic):
    """Chunking by id would also meet the cap; only a split that follows the
    embeddings keeps each blob under one level-1 group."""
    ids, _, _, blob_of, groups, stats = realistic
    assert stats["id_chunk_cuts"] == 0
    by_id = {g["id"]: g for g in groups}

    def claims_under(g):
        if g["kind"] == "leaf":
            return set(g["members"])
        return set().union(*(claims_under(by_id[c]) for c in g["children"]))

    root = groups[0]
    for child in root["children"]:
        blobs = {blob_of[c] for c in claims_under(by_id[child])}
        assert len(blobs) == 1, f"a level-1 group mixes blobs {blobs}"


def test_tree_structure_is_well_formed(realistic):
    ids, _, att, _, groups, _ = realistic
    core.validate_tree(groups, ids, att, map_key=MAP, theme_id=THEME, cap=100)
    root = groups[0]
    assert root["parent"] is None and root["depth"] == 0
    assert root["id"] == core.root_id(MAP, "meaning", THEME)
    for g in groups:
        if g["kind"] == "group":
            assert len(g["children"]) >= 2, "a group never has a single child"
            assert len(g["children"]) <= core.MAX_CHILDREN


def test_rerun_reproduces_every_group_id(realistic):
    ids, x, att, _, groups, _ = realistic
    again, _ = _build(ids, x, att)
    assert again == groups
    # Input order does not matter: the core sorts by claim id first.
    order = np.random.RandomState(3).permutation(len(ids))
    shuffled, _ = _build([ids[i] for i in order], x[order], [att[i] for i in order])
    assert shuffled == groups


def test_a_group_id_depends_only_on_its_members():
    """Unchanged groups keep their ids across runs: the id is minted from
    (map, hierarchy, theme, sorted member claim ids), never from the run."""
    a = ["00000000-0000-4000-8000-000000000002", "00000000-0000-4000-8000-000000000001"]
    assert core.group_id(MAP, "meaning", THEME, a) == core.group_id(
        MAP, "meaning", THEME, sorted(a))
    assert core.group_id(MAP, "meaning", THEME, a) != core.group_id(
        MAP, "meaning", THEME, a[:1])
    assert core.group_id(MAP, "meaning", THEME, a) != core.group_id(
        "public", "meaning", THEME, a)
    assert core.group_id(MAP, "meaning", THEME, a) != core.group_id(MAP, "links", THEME, a)


def test_ids_match_the_golden_vector():
    """The same vector is pinned in crates/epigraph-cli/src/atlas_meaning/tree.rs."""
    assert str(core.NAMESPACE) == "fe2624a2-be4f-595a-be4c-2e14830d2a5b"
    assert core.root_id(MAP, "meaning", THEME) == "c21ff8e0-db41-5755-8a4f-4324dacdf211"
    assert core.root_id("public", "links", THEME) == "ea9a52a2-1e97-58f5-b155-74a2713eb4a4"
    members = ["00000000-0000-4000-8000-000000000002", "00000000-0000-4000-8000-000000000001"]
    assert core.group_id(MAP, "meaning", THEME, members) == "e0e7d398-32de-5302-8400-0d33ba7b254a"


def test_a_theme_under_the_cap_is_one_root_leaf():
    ids, x, att, _ = _blobs(n_blobs=3, per_blob=10, dim=16, seed=5,
                            attach=lambda i, rng: [i])
    groups, _ = _build(ids, x, att)  # 30 claims + 30 evidence = 60
    assert len(groups) == 1
    (root,) = groups
    assert root["kind"] == "leaf" and root["depth"] == 0 and root["parent"] is None
    assert root["id"] == core.root_id(MAP, "meaning", THEME)
    assert root["members"] == sorted(ids)


def test_a_child_that_fits_is_a_leaf_with_no_empty_level():
    """Two blobs of 40 claims, each with one evidence row: 160 in all, 80 a
    blob. The root splits once and each blob is a leaf directly under it."""
    ids, x, att, blob_of = _blobs(n_blobs=2, per_blob=40, dim=16, seed=9,
                                  attach=lambda i, rng: [i])
    groups, _ = _build(ids, x, att)
    root = groups[0]
    assert root["kind"] == "group" and len(root["children"]) == 2
    children = groups[1:]
    assert [g["kind"] for g in children] == ["leaf", "leaf"]
    assert all(g["depth"] == 1 and g["parent"] == root["id"] for g in children)
    for g in children:
        assert len({blob_of[c] for c in g["members"]}) == 1
        assert g["id"] == core.group_id(MAP, "meaning", THEME, g["members"])


def test_a_shared_agent_counts_once_per_group():
    """60 claims all asserted by one agent weigh 61 nodes: one leaf. Counting
    the agent once per claim would make it 120 and split the theme."""
    ids, x, att, _ = _blobs(n_blobs=3, per_blob=20, dim=16, seed=13,
                            attach=lambda i, rng: [0])
    groups, _ = _build(ids, x, att)
    assert len(groups) == 1 and groups[0]["kind"] == "leaf"
    assert groups[0]["weight"] == 61


def test_shared_evidence_counts_once_and_unshared_evidence_splits():
    """The same 60 claims, each with its own two evidence rows, weigh 180."""
    ids, x, att, _ = _blobs(n_blobs=3, per_blob=20, dim=16, seed=13,
                            attach=lambda i, rng: [2 * i, 2 * i + 1])
    groups, _ = _build(ids, x, att)
    assert groups[0]["kind"] == "group"
    assert all(g["weight"] <= 100 for g in _leaves(groups))


def test_a_claim_over_the_cap_alone_is_refused():
    """W3's per-claim cap keeps every exported claim within the cap; a claim
    over it would make the recursion unable to terminate."""
    ids, x, _, _ = _blobs(n_blobs=1, per_blob=3, dim=8, seed=1)
    att = [list(range(100)), [], []]  # 1 + 100 = 101 nodes alone
    with pytest.raises(ValueError, match="over the cap on its own"):
        _build(ids, x, att)


def test_identical_vectors_terminate_within_the_cap():
    rng = np.random.RandomState(2)
    ids = sorted(_id(rng) for _ in range(250))
    x = np.ones((250, 8), dtype=np.float32)
    att = [[i] for i in range(250)]  # 500 nodes
    groups, stats = _build(ids, x, att)
    assert stats["id_chunk_cuts"] >= 1
    assert all(g["weight"] <= 100 for g in _leaves(groups))
    core.validate_tree(groups, ids, att, map_key=MAP, theme_id=THEME, cap=100)


@pytest.mark.parametrize("breakage", ["forged_id", "single_child", "member_twice", "over_cap"])
def test_validate_tree_refuses_a_malformed_tree(breakage):
    ids, x, att, _ = _blobs(n_blobs=2, per_blob=40, dim=16, seed=9,
                            attach=lambda i, rng: [i])
    groups, _ = _build(ids, x, att)
    groups = json.loads(json.dumps(groups))
    if breakage == "forged_id":
        groups[1]["id"] = str(uuid.uuid4())
        groups[0]["children"][0] = groups[1]["id"]
    elif breakage == "single_child":
        # The empty level: a theme that fits, wrapped in a root whose only
        # child is the whole theme as a leaf. Its ids are otherwise valid.
        members = sorted(ids)
        leaf_id = core.group_id(MAP, "meaning", THEME, members)
        root = core.root_id(MAP, "meaning", THEME)
        groups = [{"id": root, "parent": None, "depth": 0, "kind": "group",
                   "claim_count": 80, "weight": 160, "children": [leaf_id]},
                  {"id": leaf_id, "parent": root, "depth": 1, "kind": "leaf",
                   "claim_count": 80, "weight": 160, "members": members}]
        att = [[] for _ in ids]  # 80 nodes: the whole theme fits one leaf
    elif breakage == "member_twice":
        groups[2]["members"].append(groups[1]["members"][0])
    elif breakage == "over_cap":
        merged = sorted(groups[1]["members"] + groups[2]["members"])
        groups = [{"id": core.root_id(MAP, "meaning", THEME), "parent": None, "depth": 0,
                   "kind": "leaf", "claim_count": len(merged), "weight": 160,
                   "members": merged}]
    with pytest.raises(ValueError):
        core.validate_tree(groups, ids, att, map_key=MAP, theme_id=THEME, cap=100)


# ── the committed fixture, read by both suites ────────────────────────────────

FIXTURE_CAP = 12
FIXTURE_DIM = 8


def fixture_inputs():
    """The committed export's content, regenerated: 30 claims in three blobs,
    a shared agent (index 0) on every claim of the first blob, one evidence row
    on every claim."""
    ids, x, _, blob_of = _blobs(n_blobs=3, per_blob=10, dim=FIXTURE_DIM, seed=21)
    order = sorted(range(len(ids)), key=ids.__getitem__)
    ids = [ids[i] for i in order]
    x = x[order]
    att = []
    for n, cid in enumerate(ids):
        a = [1 + n]
        if blob_of[cid] == 0:
            a = [0] + a
        att.append(a)
    return ids, x, att


def test_committed_export_is_the_fixture_inputs():
    ids, x, att = fixture_inputs()
    index = json.loads((FIXTURE / "export" / "export.json").read_text())
    assert index == {
        "format": core.EXPORT_FORMAT, "map": MAP, "hierarchy": "meaning",
        "cap": FIXTURE_CAP, "seed": 42, "dim": FIXTURE_DIM,
        "themes": [{"theme_id": THEME, "claims": len(ids), "attachment_nodes": 31}],
    }
    got_ids, got_x, got_att = core.read_export_theme(FIXTURE / "export", THEME, FIXTURE_DIM)
    assert got_ids == ids and got_att == att
    assert np.array_equal(got_x, x)


def test_committed_fixture_reproduces_the_committed_result():
    want = json.loads((FIXTURE / "result.json").read_text())
    got = core.compute_export_dir(FIXTURE / "export")
    want.pop("versions")
    got.pop("versions")
    assert got == want
    (theme,) = got["themes"]
    assert any(g["kind"] == "group" for g in theme["groups"]), "the fixture must nest"


def test_compute_runs_without_db_driver(tmp_path):
    """`compute` is the off-box step: it must run where no DB driver exists."""
    out = tmp_path / "result.json"
    runner = (
        "import sys, runpy\n"
        "for m in ('psycopg2', 'theme_lib', 'maintenance_dsn', 'sqlalchemy'):\n"
        "    sys.modules[m] = None\n"
        f"sys.argv = ['atlas_meaning_core.py', 'compute', '--from', "
        f"{str(FIXTURE / 'export')!r}, '--out', {str(out)!r}]\n"
        f"sys.path.insert(0, {str(REPO / 'scripts')!r})\n"
        f"runpy.run_path({str(REPO / 'scripts' / 'atlas_meaning_core.py')!r}, "
        "run_name='__main__')\n"
    )
    proc = subprocess.run([sys.executable, "-c", runner], capture_output=True, text=True,
                          env={**os.environ, "PYTHONPATH": ""})
    assert proc.returncode == 0, proc.stderr
    result = json.loads(out.read_text())
    assert result["format"] == core.RESULT_FORMAT
    assert set(result["versions"]) == {"numpy", "scikit-learn", "umap-learn", "python"}
    want = json.loads((FIXTURE / "result.json").read_text())
    assert result["themes"] == want["themes"]


def test_export_reader_refuses_a_truncated_embedding_file(tmp_path):
    ids, x, att = fixture_inputs()
    core.write_export(tmp_path, MAP, cap=FIXTURE_CAP, seed=42, dim=FIXTURE_DIM,
                      themes={THEME: (ids, x, att)})
    f32 = tmp_path / f"{THEME}.f32"
    f32.write_bytes(f32.read_bytes()[:-4])
    with pytest.raises(ValueError, match="embedding file"):
        core.read_export_theme(tmp_path, THEME, FIXTURE_DIM)
