"""The theme-cap split's CLI and DB arm (Atlas W1, backlog 8c4aefda).

Runs scripts/theme_cap_split.py's plan / export / compute / apply / reverse
against the tests/theme fixture database (a fresh database migrated to head;
CI's `python` job provisions it and sets EPIGRAPH_PYTEST_REQUIRE_DB=1).

The cap is scaled down to 40 so a fixture of a few dozen claims exercises the
same paths a 2,000 cap does on a real corpus. Each seeded group sits on its own
dominant embedding axis (conftest.make_embedding), so the split can only
recover the groups as seeded.
"""
import contextlib
import io
import json
import os
import pathlib
import subprocess
import sys
import uuid

import pytest

from scripts import label_themes_llm as L
from scripts import theme_cap_core as core
from scripts import theme_cap_split as S
from tests.theme.conftest import TEST_DSN, make_embedding
from tests.theme.test_theme_cap_core import _blobs

REPO = pathlib.Path(__file__).resolve().parents[2]

CAP = 40
RUN_ID = "33333333-3333-3333-3333-333333333333"
PARENT_LABEL = "Parent Theme Name"
TEXT_MARK = "capsplit-member-text-"


def _claim(cur, agent_id, theme_id, seed, embedded=True, owner=None, current=True):
    content = f"{TEXT_MARK}{uuid.uuid4()}"
    emb = make_embedding(seed) if embedded and current else None
    if owner is None:
        cur.execute(
            "INSERT INTO claims (content, content_hash, truth_value, agent_id, embedding, theme_id, "
            "                    is_current) "
            "VALUES (%s, sha256(%s::bytea), 0.5, %s, %s::vector, %s, %s) RETURNING id::text",
            (content, content, agent_id, emb, theme_id, current),
        )
    else:
        cur.execute(
            "INSERT INTO claims (content, content_hash, truth_value, agent_id, embedding, "
            "                    theme_id, visibility, owner_group_id) "
            "VALUES (%s, sha256(%s::bytea), 0.5, %s, %s::vector, %s, 'group', %s) "
            "RETURNING id::text",
            (content, content, agent_id, emb, theme_id, owner),
        )
    return cur.fetchone()[0]


def _theme(db, agent_id, sizes, label=PARENT_LABEL, props=None, unembedded=0, seed0=1,
           with_3072=True, retired=0):
    """A theme whose members form len(sizes) separated groups, plus `unembedded`
    current members with no embedding and `retired` non-current members (which
    carry none, as chk_deprecated_no_embedding requires).
    Returns (theme_id, [ids of group 0, ...], [unembedded and retired ids])."""
    props = props if props is not None else {"source": "cluster_run",
                                             "cluster_run_id": RUN_ID, "cluster_id": 7}
    with db.cursor() as cur:
        cur.execute(
            "INSERT INTO claim_themes (label, description, claim_count, centroid, centroid_3072, "
            "                          properties) "
            "VALUES (%s, 'whole-theme description', %s, %s::vector, %s::vector, %s::jsonb) "
            "RETURNING id::text",
            (label, sum(sizes), make_embedding(seed0),
             make_embedding(seed0, dim=3072) if with_3072 else None, json.dumps(props)),
        )
        theme_id = cur.fetchone()[0]
        groups = [[_claim(cur, agent_id, theme_id, seed0 + g) for _ in range(n)]
                  for g, n in enumerate(sizes)]
        loose = [_claim(cur, agent_id, theme_id, seed0, embedded=False)
                 for _ in range(unembedded)]
        loose += [_claim(cur, agent_id, theme_id, seed0, current=False) for _ in range(retired)]
    db.commit()
    return theme_id, groups, loose


def _snapshot(db):
    """Every claim_themes row in full, and the claims membership projection."""
    with db.cursor() as cur:
        cur.execute("SELECT ct::text FROM claim_themes ct ORDER BY id")
        themes = [r[0] for r in cur.fetchall()]
        cur.execute("SELECT md5(coalesce(string_agg(id::text || ':' || "
                    "coalesce(theme_id::text, '-'), '|' ORDER BY id), '')) FROM claims")
        members = cur.fetchone()[0]
    db.rollback()
    return themes, members


def _sizes(db):
    with db.cursor() as cur:
        cur.execute("SELECT theme_id::text, count(*) FROM claims WHERE theme_id IS NOT NULL "
                    "GROUP BY theme_id")
        out = dict(cur.fetchall())
    db.rollback()
    return out


def _theme_of(db, ids):
    with db.cursor() as cur:
        cur.execute("SELECT DISTINCT theme_id::text FROM claims WHERE id = ANY(%s::uuid[])", (ids,))
        out = sorted(r[0] for r in cur.fetchall())
    db.rollback()
    return out


def _run(argv):
    """main(argv) with stdout/stderr captured; returns (stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        assert S.main(argv) == 0
    return out.getvalue(), err.getvalue()


def test_plan_lists_every_over_cap_theme_with_part_sizes(db, seed_agent, tmp_path):
    big, _, _ = _theme(db, seed_agent, (30, 25, 20))
    pair, _, _ = _theme(db, seed_agent, (25, 25), label="Second Theme", seed0=10)
    small, _, _ = _theme(db, seed_agent, (12,), label="Small Theme", seed0=20)
    before = _snapshot(db)

    out, _ = _run(["plan", "--database-url", TEST_DSN, "--cap", str(CAP),
                   "--out", str(tmp_path / "plan.json")])

    report = {r["theme_id"]: r for r in json.loads(out)["themes"]}
    assert set(report) == {big, pair}, "plan must list every theme over the cap, and only those"
    assert report[big]["part_sizes"] == [30, 25, 20]
    assert report[pair]["part_sizes"] == [25, 25]
    assert all(r["reaches_cap"] for r in report.values())
    assert small not in report
    assert _snapshot(db) == before, "plan is a dry run and must write nothing"
    result = json.loads((tmp_path / "plan.json").read_text())
    assert {t["theme_id"] for t in result["themes"]} == {big, pair}


def test_apply_leaves_no_theme_over_cap_and_largest_keeps_id(db, seed_agent, tmp_path):
    theme, (g0, g1, g2), _ = _theme(db, seed_agent, (30, 25, 20))

    result, _ = S.plan(db, cap=CAP)
    manifest = S.apply_result(db, result, tmp_path / "m.json")

    sizes = _sizes(db)
    assert max(sizes.values()) <= CAP
    assert _theme_of(db, g0) == [theme], "the largest part keeps the theme id"
    (t1,), (t2,) = _theme_of(db, g1), _theme_of(db, g2)
    assert len({theme, t1, t2}) == 3
    assert [p["theme_id"] for p in manifest["themes"][0]["new_parts"]] == [t1, t2]
    with db.cursor() as cur:
        cur.execute("SELECT id::text, label, description, claim_count, centroid IS NULL, "
                    "centroid_3072 IS NULL, properties FROM claim_themes ORDER BY claim_count DESC")
        rows = cur.fetchall()
    db.rollback()
    assert [(r[0], r[3]) for r in rows] == [(theme, 30), (t1, 25), (t2, 20)]
    for part, (_, label, desc, _, centroid_null, c3072_null, props) in enumerate(rows):
        assert label == f"{PARENT_LABEL} · part {part + 1}"
        assert not L.is_placeholder_label(label)
        assert desc == ""
        assert not centroid_null
        # no member has a 3072 embedding, so the recomputed 3072 centroid is NULL
        # rather than the parent's stale whole-theme one
        assert c3072_null
        assert props["needs_naming"] is True
        assert (props["split_of"], props["split_part"], props["split_path"]) == (theme, part, [part])
        assert (props["cluster_run_id"], props["cluster_id"]) == (RUN_ID, 7)
        assert props["split_run"] == manifest["split_run"]
        assert props["split_id_chunk_cuts"] == 0


def test_resplit_keeps_earlier_lineage_and_a_unique_path(db, seed_agent, tmp_path):
    earlier = str(uuid.uuid4())
    theme, _, _ = _theme(db, seed_agent, (30, 25), label="Older Part · part 2", props={
        "cluster_run_id": RUN_ID, "cluster_id": 7, "split_of": earlier, "split_part": 1})

    result, _ = S.plan(db, cap=CAP)
    S.apply_result(db, result, tmp_path / "m.json")

    with db.cursor() as cur:
        cur.execute("SELECT label, properties FROM claim_themes ORDER BY claim_count DESC")
        rows = cur.fetchall()
    db.rollback()
    assert [p["split_path"] for _, p in rows] == [[1, 0], [1, 1]]
    assert [label for label, _ in rows] == ["Older Part · part 2.1", "Older Part · part 2.2"]
    for _, p in rows:
        assert p["split_of"] == theme
        assert p["split_history"] == [{"split_of": earlier, "split_part": 1}]


def test_apply_then_reverse_is_byte_identical(db, seed_agent, tmp_path):
    _theme(db, seed_agent, (30, 25, 20))
    _theme(db, seed_agent, (25, 25), label="Second Theme", seed0=10, with_3072=False)
    before = _snapshot(db)
    export, result, manifest = tmp_path / "export", tmp_path / "r.json", tmp_path / "m.json"

    old_umask = os.umask(0o022)  # a typical umask: the export must not rely on a strict one
    try:
        _run(["export", "--database-url", TEST_DSN, "--cap", str(CAP), "--out", str(export)])
    finally:
        os.umask(old_umask)
    npz = sorted(export.glob("*.npz"))
    assert len(npz) == 2
    # embeddings approximate claim content: everything the export creates is owner-only
    for f in [export, export / "export.json", *npz]:
        assert f.stat().st_mode & 0o077 == 0, (f.name, oct(f.stat().st_mode))
    _run(["compute", "--from", str(export), "--out", str(result)])
    _run(["apply", "--database-url", TEST_DSN, "--from", str(result),
          "--manifest", str(manifest)])
    assert _snapshot(db) != before
    assert max(_sizes(db).values()) <= CAP
    _run(["reverse", "--database-url", TEST_DSN, "--manifest", str(manifest)])

    assert _snapshot(db) == before, "reverse must restore claim_themes and membership exactly"


def _intake_group(cur, agent_id):
    gid = str(uuid.uuid4())
    cur.execute(
        "INSERT INTO groups (id, display_name, did_key, public_key, kind, created_by_agent_id) "
        "VALUES (%s, 'intake', 'did:test:team:' || %s, sha256(%s::bytea), 'team', %s)",
        (gid, gid, gid, agent_id),
    )
    cur.execute("INSERT INTO bug_report_intake_settings (intake_group_id) VALUES (%s)", (gid,))
    return gid


def test_no_claim_text_reaches_any_output(db, seed_agent, tmp_path):
    theme, groups, _ = _theme(db, seed_agent, (30, 25, 20))
    with db.cursor() as cur:
        group = _intake_group(cur, seed_agent)
        report_claim = _claim(cur, seed_agent, theme, 3, owner=group)  # sits with group 2
    db.commit()
    try:
        export, result, manifest = tmp_path / "e", tmp_path / "r.json", tmp_path / "m.json"
        outputs = [
            _run(["plan", "--database-url", TEST_DSN, "--cap", str(CAP),
                  "--out", str(tmp_path / "p.json")]),
            _run(["export", "--database-url", TEST_DSN, "--cap", str(CAP), "--out", str(export)]),
            _run(["compute", "--from", str(export), "--out", str(result)]),
            _run(["apply", "--database-url", TEST_DSN, "--from", str(result),
                  "--manifest", str(manifest)]),
        ]
        blobs = [s.encode() for pair in outputs for s in pair]
        blobs += [f.read_bytes() for f in tmp_path.rglob("*") if f.is_file()]
        with db.cursor() as cur:
            cur.execute("SELECT string_agg(label || description || properties::text, '|') "
                        "FROM claim_themes")
            blobs.append(cur.fetchone()[0].encode())
        db.rollback()
        assert not [b for b in blobs if TEXT_MARK.encode() in b], "claim text leaked"
        # The intake rule covers labels only; an intake member moves with its part.
        assert _theme_of(db, [report_claim]) == _theme_of(db, groups[2])
    finally:
        db.rollback()
        with db.cursor() as cur:
            cur.execute("DELETE FROM bug_report_intake_settings")
            cur.execute("UPDATE claims SET theme_id = NULL WHERE id = %s", (report_claim,))
            cur.execute("DELETE FROM claims WHERE id = %s", (report_claim,))
            cur.execute("SET LOCAL epigraph.allow_group_delete = 'yes'")
            cur.execute("DELETE FROM groups WHERE id = %s", (group,))
        db.commit()


def test_apply_refuses_a_stale_result_and_writes_nothing(db, seed_agent, tmp_path):
    theme, _, _ = _theme(db, seed_agent, (30, 25, 20))
    result, _ = S.plan(db, cap=CAP)
    with db.cursor() as cur:
        _claim(cur, seed_agent, theme, 1)  # assigned after the plan
    db.commit()
    before = _snapshot(db)

    with pytest.raises(ValueError, match="no longer matches"):
        S.apply_result(db, result, tmp_path / "m.json")

    assert _snapshot(db) == before
    assert not (tmp_path / "m.json").exists()


def test_apply_refuses_when_unembedded_members_push_kept_part_over_cap(db, seed_agent, tmp_path):
    _theme(db, seed_agent, (30, 25, 20), unembedded=15)
    result, report = S.plan(db, cap=CAP)
    assert report[0]["reaches_cap"] is False
    before = _snapshot(db)

    with pytest.raises(ValueError, match="over the cap"):
        S.apply_result(db, result, tmp_path / "m.json")

    assert _snapshot(db) == before
    assert not (tmp_path / "m.json").exists()


@pytest.mark.parametrize("embedded, unembedded", [
    ((35,), 10),  # embedded members fit in ONE part; the theme is still over the cap
    ((), 45),     # no embedded member at all: the result has no parts for it
], ids=["one-part", "no-embeddings"])
def test_apply_refuses_an_over_cap_theme_it_cannot_split(db, seed_agent, tmp_path,
                                                         embedded, unembedded):
    """A theme the split leaves whole must not pass as applied: the apply would
    report success and the theme would stay over the cap."""
    stuck, _, _ = _theme(db, seed_agent, embedded, label="Unembedded Theme", seed0=40,
                         unembedded=unembedded)
    _theme(db, seed_agent, (30, 25, 20))  # a splittable theme in the same result
    result, report = S.plan(db, cap=CAP)
    by_id = {r["theme_id"]: r for r in report}
    assert by_id[stuck]["current"] == 45 and by_id[stuck]["reaches_cap"] is False
    before = _snapshot(db)

    with pytest.raises(ValueError, match=f"over the cap.*{stuck}"):
        S.apply_result(db, result, tmp_path / "m.json")

    assert _snapshot(db) == before, "the whole apply is refused, the splittable theme too"
    assert not (tmp_path / "m.json").exists()


def test_plan_and_parts_record_an_id_order_cut(db, seed_agent, tmp_path):
    """Members with identical vectors can only be cut by claim id. The dry run
    and the written parts both say so, so it is countable on a real corpus."""
    theme, _, _ = _theme(db, seed_agent, (45,))  # one seeded group: identical embeddings

    result, report = S.plan(db, cap=CAP)
    assert report[0]["id_chunk_cuts"] >= 1 and report[0]["part_sizes"] == [23, 22]
    S.apply_result(db, result, tmp_path / "m.json")

    with db.cursor() as cur:
        cur.execute("SELECT properties FROM claim_themes")
        props = [r[0] for r in cur.fetchall()]
    db.rollback()
    assert len(props) == 2
    assert all(p["split_id_chunk_cuts"] == report[0]["id_chunk_cuts"] for p in props)


class _NoDB:
    def __getattr__(self, name):
        raise AssertionError(f"apply touched the database ({name}) before checking the cap")


def test_apply_refuses_a_result_whose_cap_is_over_its_own():
    """The result file may come back from off the box; its cap must not be what
    decides how large a part may be."""
    result = {"format": core.RESULT_FORMAT, "cap": 8000, "seed": 42, "themes": []}

    with pytest.raises(ValueError, match="over apply's cap of 2000"):
        S.apply_result(_NoDB(), result, "unused.json")


def test_reverse_keeps_a_column_added_after_the_apply(db, seed_agent, tmp_path):
    """A claim_themes column added between apply and reverse (a later Atlas item
    may add one) is not in the snapshot. Reverse leaves it as it is, rather
    than writing NULL into it or failing on its NOT NULL."""
    theme, _, _ = _theme(db, seed_agent, (30, 25, 20))
    before = _snapshot(db)
    result, _ = S.plan(db, cap=CAP)
    manifest = S.apply_result(db, result, tmp_path / "m.json")
    try:
        with db.cursor() as cur:
            cur.execute("ALTER TABLE claim_themes ADD COLUMN w1_added text NOT NULL "
                        "DEFAULT 'kept'")
            cur.execute("UPDATE claim_themes SET w1_added = 'changed' WHERE id = %s", (theme,))
        db.commit()

        S.reverse_manifest(db, manifest)

        with db.cursor() as cur:
            cur.execute("SELECT w1_added FROM claim_themes")
            assert [r[0] for r in cur.fetchall()] == ["changed"]
        db.rollback()
    finally:
        db.rollback()
        with db.cursor() as cur:
            cur.execute("ALTER TABLE claim_themes DROP COLUMN IF EXISTS w1_added")
        db.commit()
    assert _snapshot(db) == before


def test_the_cap_counts_current_members_only(db, seed_agent, tmp_path):
    """Superseded and duplicate-marked members keep their theme_id but are not
    drawn and cannot be clustered: they neither trigger a split nor overflow the
    kept part. (Current members without an embedding do; see the test above.)"""
    under, _, _ = _theme(db, seed_agent, (35,), label="Mostly Retired", seed0=30, retired=20)
    over, groups, retired = _theme(db, seed_agent, (30, 25, 20), retired=15)

    result, report = S.plan(db, cap=CAP)
    assert [r["theme_id"] for r in report] == [over], "a theme of 35 current members is not over"
    assert report[0]["retired"] == 15 and report[0]["reaches_cap"]
    S.apply_result(db, result, tmp_path / "m.json")

    assert _theme_of(db, retired) == [over], "retired members stay with the kept part"
    assert _theme_of(db, groups[0]) == [over]
    with db.cursor() as cur:
        cur.execute("SELECT theme_id::text, count(*) FROM claims WHERE theme_id IS NOT NULL "
                    "AND is_current GROUP BY theme_id")
        current = dict(cur.fetchall())
    db.rollback()
    assert max(current.values()) <= CAP
    assert current[over] == 30 and current[under] == 35


def test_reverse_refuses_drift_unless_allowed(db, seed_agent, tmp_path):
    theme, _, _ = _theme(db, seed_agent, (30, 25, 20))
    before = _snapshot(db)
    result, _ = S.plan(db, cap=CAP)
    manifest = S.apply_result(db, result, tmp_path / "m.json")
    new_part = manifest["themes"][0]["new_parts"][0]["theme_id"]
    with db.cursor() as cur:
        late = _claim(cur, seed_agent, new_part, 2)  # assigned to a part after the apply
    db.commit()
    applied = _snapshot(db)

    with pytest.raises(ValueError, match="membership changed"):
        S.reverse_manifest(db, manifest)
    assert _snapshot(db) == applied, "a refused reverse must write nothing"

    S.reverse_manifest(db, manifest, allow_drift=True)
    sizes = _sizes(db)
    assert set(sizes) == {theme} and sizes[theme] == 76
    assert _theme_of(db, [late]) == [theme]
    assert _snapshot(db)[0] != before[0]  # count and centroid recomputed, not restored
    with db.cursor() as cur:
        cur.execute("SELECT claim_count, label FROM claim_themes WHERE id = %s", (theme,))
        assert cur.fetchone() == (76, PARENT_LABEL)
    db.rollback()


def test_manifest_of_an_uncommitted_apply_reverses_as_a_no_op(db, seed_agent, tmp_path,
                                                             monkeypatch):
    _theme(db, seed_agent, (30, 25, 20))
    before = _snapshot(db)
    result, _ = S.plan(db, cap=CAP)

    def crash(conn):
        raise RuntimeError("connection lost at commit")

    monkeypatch.setattr(S, "_commit", crash)
    with pytest.raises(RuntimeError):
        S.apply_result(db, result, tmp_path / "m.json")
    monkeypatch.undo()

    assert _snapshot(db) == before
    manifest = json.loads((tmp_path / "m.json").read_text())  # written before the commit
    assert S.reverse_manifest(db, manifest) == [
        {"parent_id": manifest["themes"][0]["parent_id"], "status": "nothing to reverse"}]
    assert _snapshot(db) == before


def test_a_session_under_row_security_is_refused(db):
    """The application role sees a subset of claims under forced RLS; the guard
    asks the database (epigraph_bypass) and refuses it."""
    with db.cursor() as cur:
        cur.execute("SET SESSION AUTHORIZATION epigraph_app")
    db.commit()
    try:
        with pytest.raises(SystemExit, match="does not bypass row-level security"):
            S.require_maintenance_session(db)
    finally:
        db.rollback()
        with db.cursor() as cur:
            cur.execute("RESET SESSION AUTHORIZATION")
        db.commit()
    S.require_maintenance_session(db)  # the fixture's own session passes


# ── DB-free: the off-box compute step, names, the role guard ──


def _write_export(dirpath, themes, cap):
    """An export directory as `theme_cap_split.py export` writes it."""
    index = {"format": core.EXPORT_FORMAT, "cap": cap, "seed": 42, "themes": []}
    for theme_id, (ids, x) in themes.items():
        core.write_theme_npz(pathlib.Path(dirpath) / f"{theme_id}.npz", ids, x)
        index["themes"].append({"theme_id": theme_id, "embedded": len(ids)})
    (pathlib.Path(dirpath) / "export.json").write_text(json.dumps(index))


def test_compute_runs_without_db_driver(tmp_path):
    """`compute` is the off-box step: it must run where no DB driver exists."""
    ids, x, _ = _blobs(n_blobs=3, per_blob=40, dim=16)
    theme = str(uuid.uuid4())
    _write_export(tmp_path, {theme: (ids, x)}, cap=50)
    out = tmp_path / "result.json"
    # Blocking the modules makes any import of them raise ImportError.
    runner = (
        "import sys, runpy\n"
        "for m in ('psycopg2', 'theme_lib', 'maintenance_dsn'):\n"
        "    sys.modules[m] = None\n"
        f"sys.argv = ['theme_cap_split.py', 'compute', '--from', {str(tmp_path)!r}, "
        f"'--out', {str(out)!r}]\n"
        f"sys.path.insert(0, {str(REPO / 'scripts')!r})\n"
        f"runpy.run_path({str(REPO / 'scripts' / 'theme_cap_split.py')!r}, run_name='__main__')\n"
    )
    proc = subprocess.run([sys.executable, "-c", runner], capture_output=True, text=True,
                          env={**os.environ, "PYTHONPATH": ""})
    assert proc.returncode == 0, proc.stderr

    result = json.loads(out.read_text())
    assert result["format"] == core.RESULT_FORMAT
    (entry,) = result["themes"]
    assert entry["theme_id"] == theme
    assert all(len(p) <= 50 for p in entry["parts"])
    assert entry["parts"] == core.split_to_cap(ids, x, cap=50, seed=42)


@pytest.mark.parametrize("parent", [
    "Surface Science",
    "A very long theme name that already runs well past the sixty character limit",
    "cluster-split-1234abcd-0",
    "auto-17",
    "Surface Science · part 2",
])
def test_part_labels_are_neutral_and_not_placeholders(parent):
    for path in ([0], [1], [1, 0], [3, 11]):
        label = S.part_label(parent, path)
        assert len(label) < 60
        # A placeholder is renamed by label_themes_llm's default run from member
        # text, which is the D-PR16 leak; W8 names these parts instead.
        assert not L.is_placeholder_label(label), label
        assert label.endswith(" · part " + ".".join(str(p + 1) for p in path))


def test_part_label_keeps_a_named_parent_and_drops_its_old_suffix():
    assert S.part_label("Surface Science", [1]) == "Surface Science · part 2"
    assert S.part_label("Surface Science · part 2", [1, 0]) == "Surface Science · part 2.1"


@pytest.mark.parametrize("dsn", [
    "postgres://epigraph_app:pw@db/epigraph",
    "postgresql://epigraph_app@localhost:5432/epigraph",
    "host=db user=epigraph_app dbname=epigraph",
])
def test_application_role_dsn_is_refused(dsn):
    with pytest.raises(SystemExit, match="maintenance"):
        S.refuse_application_role(dsn)


@pytest.mark.parametrize("dsn", [
    "postgres://maintenance:pw@db/epigraph",
    "postgres://epigraph:epigraph@localhost/epigraph_py_test",
    "host=db user=someone dbname=epigraph",
])
def test_other_dsns_pass_the_role_guard(dsn):
    S.refuse_application_role(dsn)
