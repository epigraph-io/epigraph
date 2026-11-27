"""Unit + integration tests for cluster → theme projection."""
import json
import sys
import uuid

import pytest
from psycopg2 import sql

from scripts import project_to_themes as P
from tests.theme.conftest import make_embedding


def test_theme_properties_records_lineage():
    props = P.theme_properties("run-123", 7)
    assert props["source"] == "cluster_run"
    assert props["cluster_run_id"] == "run-123"
    assert props["cluster_id"] == 7


def _seed_run(db, agent_id):
    """Two clusters, 3 claims each, with cluster_labels + claim_clusters."""
    run_id = "11111111-1111-1111-1111-111111111111"
    claim_ids = []
    with db.cursor() as cur:
        for cl in range(2):
            for i in range(3):
                content = f"c{cl}-{i}"
                cur.execute(
                    "INSERT INTO claims (content, content_hash, truth_value, agent_id, embedding) "
                    "VALUES (%s, sha256(%s::bytea), 0.5, %s, %s::vector) RETURNING id::text",
                    (content, content, agent_id, make_embedding(cl)),
                )
                cid = cur.fetchone()[0]
                claim_ids.append(cid)
                cur.execute(
                    "INSERT INTO claim_clusters (claim_id, cluster_id, centroid_distance, "
                    "second_centroid_dist, boundary_ratio, silhouette_score, cluster_run_id, "
                    "centroid_distances) VALUES (%s,%s,0.1,0.5,0.2,0.8,%s,%s)",
                    (cid, cl, run_id, [0.1, 0.5]),
                )
            cur.execute(
                "INSERT INTO cluster_labels (cluster_run_id, cluster_id, label, sample_count) "
                "VALUES (%s,%s,%s,3)",
                (run_id, cl, f"cluster-{cl}"),
            )
    db.commit()
    return run_id, claim_ids


def test_project_run_materialises_themes(db, script_db, seed_agent):
    run_id, claim_ids = _seed_run(db, seed_agent)

    P.project_run(script_db, run_id)

    with db.cursor() as cur:
        cur.execute("SELECT count(*) FROM claim_themes")
        assert cur.fetchone()[0] == 2  # one theme per cluster
        cur.execute("SELECT count(*) FROM claims WHERE theme_id IS NULL AND id::text = ANY(%s)",
                    (claim_ids,))
        assert cur.fetchone()[0] == 0  # every seeded claim now themed
        cur.execute("SELECT count(*) FROM claim_themes WHERE centroid IS NULL")
        assert cur.fetchone()[0] == 0  # real 1536-d centroid set
        cur.execute("SELECT properties->>'cluster_run_id' FROM claim_themes LIMIT 1")
        assert cur.fetchone()[0] == run_id


# --- the full-rebuild guard (backlog 18ae37e7) ---------------------------------
#
# A projection deletes every claim_themes row and mints new ids. The per-run
# views built on those ids reference claim_themes ON DELETE CASCADE, so the
# wipe silently took the graph neighbourhoods and every Atlas layout and map
# with it. It now refuses unless the caller says it means it, and says what
# goes.

CASCADE_TABLES = ("graph_neighborhoods", "atlas_layout_themes", "atlas_map_levels")


@pytest.fixture
def derived_runs(db):
    """The graph-clustering and Atlas-layout runs a test seeds; deleted at
    teardown (the db fixture wipes only the clustering tables)."""
    made = {"graph": [], "layout": []}
    yield made
    db.rollback()
    with db.cursor() as cur:
        cur.execute("DELETE FROM graph_cluster_runs WHERE run_id = ANY(%s::uuid[])",
                    (made["graph"],))
        cur.execute("DELETE FROM atlas_layout_runs WHERE id = ANY(%s::uuid[])",
                    (made["layout"],))
    db.commit()


def _seed_earlier_projection(db, claim_id, derived_runs):
    """A theme from an earlier projection with one claim filed under it, plus
    one graph neighbourhood and one Atlas layout position built on it."""
    graph_run, layout_run, region = (str(uuid.uuid4()) for _ in range(3))
    derived_runs["graph"].append(graph_run)
    derived_runs["layout"].append(layout_run)
    with db.cursor() as cur:
        cur.execute(
            "INSERT INTO claim_themes (label, description, claim_count, centroid, properties) "
            "VALUES ('earlier', '', 1, %s::vector, '{}'::jsonb) RETURNING id::text",
            (make_embedding(5),),
        )
        theme_id = cur.fetchone()[0]
        cur.execute("UPDATE claims SET theme_id = %s WHERE id = %s", (theme_id, claim_id))
        cur.execute("INSERT INTO graph_cluster_runs (run_id, cluster_count) VALUES (%s, 1)",
                    (graph_run,))
        cur.execute(
            "INSERT INTO graph_neighborhoods (run_id, theme_id, label, size) "
            "VALUES (%s, %s, 'earlier neighbourhood', 1) RETURNING id",
            (graph_run, theme_id),
        )
        # One level down: the claim's membership in that neighbourhood
        # cascades from graph_neighborhoods, not from claim_themes.
        cur.execute(
            "INSERT INTO claim_neighborhood_membership (run_id, claim_id, neighborhood_id) "
            "VALUES (%s, %s, %s)",
            (graph_run, claim_id, cur.fetchone()[0]),
        )
        cur.execute(
            "INSERT INTO atlas_layout_runs (id, algo, visibility_epoch, theme_count, "
            "region_count, public_claim_count, public_link_count, theme_set_digest) "
            "VALUES (%s, 'test', 0, 1, 1, 1, 0, %s)",
            (layout_run, "0" * 64),
        )
        cur.execute(
            "INSERT INTO atlas_layout_regions (id, run_id, ordinal, label, x, y, r, centroid) "
            "VALUES (%s, %s, 0, 'region', 0, 0, 1, %s::vector)",
            (region, layout_run, make_embedding(5)),
        )
        cur.execute(
            "INSERT INTO atlas_layout_themes (run_id, theme_id, region_id, rank_in_region, "
            "x, y, public_member_count) VALUES (%s, %s, %s, 0, 0, 0, 1)",
            (layout_run, theme_id, region),
        )
    db.commit()
    return theme_id, graph_run, layout_run


def _derived_state(db, theme_id, graph_run, layout_run):
    with db.cursor() as cur:
        cur.execute("SELECT count(*) FROM claim_themes WHERE id = %s", (theme_id,))
        themes = cur.fetchone()[0]
        cur.execute("SELECT count(*) FROM claims WHERE theme_id = %s", (theme_id,))
        claims = cur.fetchone()[0]
        cur.execute("SELECT count(*) FROM graph_neighborhoods WHERE run_id = %s", (graph_run,))
        neighbourhoods = cur.fetchone()[0]
        cur.execute("SELECT count(*) FROM atlas_layout_themes WHERE run_id = %s", (layout_run,))
        positions = cur.fetchone()[0]
    db.commit()
    return {"themes": themes, "claims": claims,
            "neighbourhoods": neighbourhoods, "positions": positions}


def test_project_run_refuses_to_wipe_existing_themes_without_the_flag(
        db, script_db, seed_agent, derived_runs):
    run_id, claim_ids = _seed_run(db, seed_agent)
    theme_id, graph_run, layout_run = _seed_earlier_projection(db, claim_ids[0], derived_runs)

    refusal = None
    try:
        P.project_run(script_db, run_id)
    except P.FullRebuildRefused as e:
        refusal = str(e)
    script_db.rollback()

    # Nothing went: the earlier theme, the claim filed under it, and the
    # neighbourhood and layout position built on it are all still there.
    assert _derived_state(db, theme_id, graph_run, layout_run) == {
        "themes": 1, "claims": 1, "neighbourhoods": 1, "positions": 1}
    assert refusal is not None, "an unconfirmed full rebuild must be refused"
    assert P.FULL_REBUILD_FLAG == "--i-understand-full-rebuild"
    assert P.FULL_REBUILD_FLAG in refusal
    for table in CASCADE_TABLES:  # it names everything the cascade drops
        assert table in refusal, refusal
    assert "public.graph_neighborhoods: 1 row" in refusal, refusal
    assert "public.atlas_layout_themes: 1 row" in refusal, refusal
    # A cascade of a cascade is counted too, exactly: every graph_neighborhoods
    # row goes, so every membership row pointing at one does.
    assert "public.claim_neighborhood_membership: 1 row" in refusal, refusal
    assert "claim_themes: 1 theme" in refusal, refusal


def test_project_run_with_the_flag_reports_what_it_dropped_and_the_rebuild(
        db, script_db, seed_agent, derived_runs, capsys):
    run_id, claim_ids = _seed_run(db, seed_agent)
    theme_id, graph_run, layout_run = _seed_earlier_projection(db, claim_ids[0], derived_runs)

    created = P.project_run(script_db, run_id, confirm_full_rebuild=True)

    assert created == 2
    assert _derived_state(db, theme_id, graph_run, layout_run) == {
        "themes": 0, "claims": 0, "neighbourhoods": 0, "positions": 0}
    err = capsys.readouterr().err
    assert "public.graph_neighborhoods: 1 row" in err, err
    assert "public.atlas_layout_themes: 1 row" in err, err
    assert "public.atlas_map_levels: 0 rows" in err, err
    for step in P.REBUILD_STEPS:
        assert step in err, err


def test_project_run_on_an_empty_theme_table_needs_no_flag(db, script_db, seed_agent):
    """A first projection (or a restore after a wipe) drops nothing."""
    run_id, _ = _seed_run(db, seed_agent)
    assert P.project_run(script_db, run_id) == 2


def test_cascading_tables_include_the_cascades_of_cascades(db, script_db):
    tables = P.cascading_tables(script_db)
    script_db.rollback()
    names = [t for _, t in tables]
    assert set(CASCADE_TABLES) <= set(names), tables
    for child, parent in (("claim_neighborhood_membership", "graph_neighborhoods"),
                          ("neighborhood_edges", "graph_neighborhoods"),
                          ("atlas_layout_theme_links", "atlas_layout_themes")):
        assert child in names, tables
        assert names.index(parent) < names.index(child), tables  # parents first
    assert ("public", "claims") not in tables  # claims.theme_id does not cascade


@pytest.fixture
def scratch_cascade(db, script_db):
    """A table created by the test with an ON DELETE CASCADE foreign key to
    claim_themes (nullable, so a row can reference nothing), and a table that
    cascades from it. No list in the script can name them: only the catalog."""
    suffix = uuid.uuid4().hex[:8]
    child, grandchild = f"zz_theme_child_{suffix}", f"zz_theme_grandchild_{suffix}"
    with script_db.cursor() as cur:
        cur.execute("SELECT current_user")
        script_role = cur.fetchone()[0]
    script_db.rollback()
    with db.cursor() as cur:
        cur.execute(sql.SQL(
            "CREATE TABLE public.{} (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), "
            "theme_id uuid REFERENCES public.claim_themes(id) ON DELETE CASCADE)"
        ).format(sql.Identifier(child)))
        cur.execute(sql.SQL(
            "CREATE TABLE public.{} (child_id uuid NOT NULL "
            "REFERENCES public.{}(id) ON DELETE CASCADE)"
        ).format(sql.Identifier(grandchild), sql.Identifier(child)))
        cur.execute(sql.SQL("GRANT SELECT ON public.{}, public.{} TO {}").format(
            sql.Identifier(child), sql.Identifier(grandchild), sql.Identifier(script_role)))
    db.commit()
    try:
        yield child, grandchild
    finally:
        script_db.rollback()  # its read locks would block the DROP
        db.rollback()
        with db.cursor() as cur:
            cur.execute(sql.SQL("DROP TABLE IF EXISTS public.{}, public.{}").format(
                sql.Identifier(grandchild), sql.Identifier(child)))
        db.commit()


def test_a_cascading_table_is_found_and_counted_from_the_catalog(db, script_db, scratch_cascade):
    child, grandchild = scratch_cascade
    with db.cursor() as cur:
        cur.execute(
            "INSERT INTO claim_themes (label, description, claim_count, centroid, properties) "
            "VALUES ('earlier', '', 0, %s::vector, '{}'::jsonb) RETURNING id",
            (make_embedding(5),),
        )
        theme_id = cur.fetchone()[0]
        ids = []
        for ref in (theme_id, theme_id, None):  # the NULL row references no theme
            cur.execute(sql.SQL("INSERT INTO public.{} (theme_id) VALUES (%s) RETURNING id")
                        .format(sql.Identifier(child)), (ref,))
            ids.append(cur.fetchone()[0])
        for cid in (ids[0], ids[2]):
            cur.execute(sql.SQL("INSERT INTO public.{} (child_id) VALUES (%s)")
                        .format(sql.Identifier(grandchild)), (cid,))
    db.commit()

    tables = P.cascading_tables(script_db)
    impact = P.rebuild_impact(script_db)
    script_db.rollback()

    names = [t for _, t in tables]
    assert names.index(child) < names.index(grandchild), tables
    # Exact where it can be: the row whose key is NULL survives the wipe.
    assert impact["cascade"][f"public.{child}"] == 2, impact
    assert f"public.{child}" not in impact["approximate"], impact
    # Its parent is only partly emptied, so the grandchild gets an upper
    # bound (its rows that reference any child row), marked as one.
    assert impact["cascade"][f"public.{grandchild}"] == 2, impact
    assert impact["approximate"] == [f"public.{grandchild}"], impact
    described = P.describe_impact(impact)
    assert f"public.{child}: 2 rows" in described, described
    assert f"public.{grandchild}: up to 2 rows" in described, described


@pytest.fixture
def team_map(db, seed_agent):
    """A team group whose Atlas map has one finished run with one level."""
    gid = str(uuid.uuid4())
    made = {"group": gid, "runs": []}
    with db.cursor() as cur:
        cur.execute(
            "INSERT INTO groups (id, display_name, did_key, public_key, kind, created_by_agent_id) "
            "VALUES (%s, 'map team', 'did:test:team:' || %s, sha256(%s::bytea), 'team', %s)",
            (gid, gid, gid, seed_agent),
        )
    db.commit()
    yield made
    db.rollback()
    with db.cursor() as cur:
        cur.execute("DELETE FROM atlas_map_runs WHERE id = ANY(%s::uuid[])", (made["runs"],))
        cur.execute("DELETE FROM atlas_map_epochs WHERE owner_group_id = %s", (gid,))
        cur.execute("SET LOCAL epigraph.allow_group_delete = 'yes'")
        cur.execute("DELETE FROM groups WHERE id = %s", (gid,))
    db.commit()


def _seed_team_map_level(db, team_map, theme_id):
    gid = team_map["group"]
    with db.cursor() as cur:
        cur.execute(
            "INSERT INTO atlas_map_runs (owner_group_id, visibility, finished_at, algo, "
            "map_epoch, public_epoch, map_left_epoch, public_left_epoch, level_count) "
            "VALUES (%s, 'group', now(), 'test', 0, 0, 0, 0, 1) RETURNING id::text",
            (gid,),
        )
        run = cur.fetchone()[0]
        team_map["runs"].append(run)
        cur.execute(
            "INSERT INTO atlas_map_levels (run_id, owner_group_id, visibility, hierarchy, "
            "group_id, parent_group_id, theme_id, level, schema_version, payload) "
            "VALUES (%s, %s, 'group', 'meaning', gen_random_uuid(), NULL, %s, 0, 1, '{}'::jsonb)",
            (run, gid, theme_id),
        )
    db.commit()
    return run


def test_a_team_maps_levels_are_counted_named_and_dropped(
        db, script_db, seed_agent, derived_runs, team_map, capsys):
    run_id, claim_ids = _seed_run(db, seed_agent)
    theme_id, _graph_run, _layout_run = _seed_earlier_projection(db, claim_ids[0], derived_runs)
    map_run = _seed_team_map_level(db, team_map, theme_id)

    with pytest.raises(P.FullRebuildRefused) as refused:
        P.project_run(script_db, run_id)
    script_db.rollback()
    refusal = str(refused.value)
    assert "public.atlas_map_levels: 1 row" in refusal, refusal
    assert f"maps losing their levels: team:{team_map['group']}" in refusal, refusal

    P.project_run(script_db, run_id, confirm_full_rebuild=True)
    with db.cursor() as cur:
        cur.execute("SELECT count(*) FROM atlas_map_levels WHERE run_id = %s", (map_run,))
        assert cur.fetchone()[0] == 0  # the team map's level went with its theme
    db.commit()
    assert f"team:{team_map['group']}" in capsys.readouterr().err


def test_rebuild_steps_start_with_the_theme_cap_split_sequence():
    """The per-run views are rebuilt the way a theme-cap split rebuilds them,
    then every Atlas map (public and team) gets its operator build."""
    from scripts import theme_cap_split as S
    assert P.REBUILD_STEPS[:len(S.REBUILD_STEPS)] == S.REBUILD_STEPS
    rest = " ".join(P.REBUILD_STEPS[len(S.REBUILD_STEPS):])
    for builder in ("atlas_meaning", "atlas_links", "atlas_nightly --apply"):
        assert builder in rest, rest


def test_main_accepts_the_flag_and_reports_the_rebuild(monkeypatch, capsys):
    seen = {}

    class Conn:
        def rollback(self):
            seen["rolled_back"] = True

        def close(self):
            seen["closed"] = True

    monkeypatch.setattr(P.theme_lib, "connect", lambda url: Conn())
    monkeypatch.setattr(P.theme_lib, "set_statement_timeout", lambda conn, ms: None)

    def fake_project_run(conn, run_id, *, confirm_full_rebuild=False):
        seen["confirm"] = confirm_full_rebuild
        return 3

    monkeypatch.setattr(P, "project_run", fake_project_run)
    monkeypatch.setattr(sys, "argv", ["project_to_themes.py", "--run-id", "r1",
                                      "--i-understand-full-rebuild"])
    P.main()
    out = json.loads(capsys.readouterr().out)
    assert seen["confirm"] is True
    assert out["themes"] == 3
    assert out["rebuild_next"] == P.REBUILD_STEPS


def test_main_exits_nonzero_on_a_refusal_without_a_traceback(monkeypatch, capsys):
    seen = {}

    class Conn:
        def rollback(self):
            seen["rolled_back"] = True

        def close(self):
            seen["closed"] = True

    monkeypatch.setattr(P.theme_lib, "connect", lambda url: Conn())
    monkeypatch.setattr(P.theme_lib, "set_statement_timeout", lambda conn, ms: None)

    def refuse(conn, run_id, *, confirm_full_rebuild=False):
        raise P.FullRebuildRefused("refusing: claim_themes: 4 themes")

    monkeypatch.setattr(P, "project_run", refuse)
    monkeypatch.setattr(sys, "argv", ["project_to_themes.py", "--run-id", "r1"])
    with pytest.raises(SystemExit) as exc:
        P.main()
    assert exc.value.code == 1
    assert seen == {"rolled_back": True, "closed": True}
    assert "claim_themes: 4 themes" in capsys.readouterr().err
