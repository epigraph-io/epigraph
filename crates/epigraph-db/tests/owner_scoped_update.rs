//! Migration 117: UPDATE of an edge, or of an instance-wide registry row, is
//! owner-scoped.
//!
//! 077's `edges_tenancy` and the four registries' `<table>_tenancy` policies
//! admit a WORLD-owned public row in their WITH CHECK, and a world-owned row is
//! nobody's (the world group is memberless). So any application session could
//! retract, relabel or re-point an edge between two public claims, or rewrite a
//! shared frame's properties. On `edges` the re-point was also a RE-OWN: 070's
//! `edges_tenancy` trigger restamps the owner from the new endpoints, and 115's
//! owner guard watches only the owner columns. 117 adds one RESTRICTIVE,
//! FOR UPDATE policy per table, `<table>_update_owner`: the old row (USING) and
//! the new row (WITH CHECK) must both be the session's -- owner, or on `edges`
//! co-owner, in its writable set.
//!
//! # Why every arm runs as `epigraph_app`
//!
//! `#[sqlx::test]` connects as the superuser `epigraph`, for whom every policy
//! is bypassed. Every arm that asserts a refusal or an admission switches to
//! `epigraph_app` with `SET SESSION AUTHORIZATION` and stamps the session GUCs
//! as `ScopedPool::begin_as` does (see `owner_scoped_delete.rs`).

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::visibility::Viewer;
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

const WORLD: Uuid = Uuid::nil();

async fn assert_app_role_does_not_bypass(pool: &PgPool) {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app's rolbypassrls");
    assert!(
        !bypassrls,
        "epigraph_app holds BYPASSRLS, so every arm in this file is vacuous"
    );
}

fn csv(ids: &[Uuid]) -> String {
    ids.iter()
        .map(Uuid::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

/// Stamp `conn` for `agent` exactly as `ScopedPool::begin_as` would.
async fn stamp(conn: &mut PgConnection, pool: &PgPool, agent: Uuid) {
    let v = Viewer::resolve(pool, agent).await.expect("resolve viewer");
    let groups = csv(v.group_bind().expect("scoped viewer"));
    let writable = csv(v.writable_groups());
    assert!(!writable.is_empty(), "a writer with no writable group");
    sqlx::query(
        "SELECT set_config('epigraph.group_ids', $1, false), \
                set_config('epigraph.writable_group_ids', $2, false), \
                set_config('epigraph.principal_id', $3, false)",
    )
    .bind(groups)
    .bind(writable)
    .bind(agent.to_string())
    .execute(&mut *conn)
    .await
    .expect("stamp session gucs");
}

/// A public claim owned by `group` (not the world).
async fn seed_public_claim_owned_by(pool: &PgPool, agent: Uuid, group: Uuid, tag: &str) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, $2, $3, 0.5, $4, true, 'public', $5)",
    )
    .bind(id)
    .bind(format!("owner-scoped update fixture claim {tag}"))
    .bind(&hash)
    .bind(agent)
    .bind(group)
    .execute(pool)
    .await
    .expect("seed a public claim owned by a group");
    id
}

/// Make `agent` a READER (not a writer) of `group`.
async fn add_reader(pool: &PgPool, group: Uuid, agent: Uuid) {
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'reader')",
    )
    .bind(group)
    .bind(agent)
    .execute(pool)
    .await
    .expect("seed reader membership");
}

/// `(source_id, target_id, owner_group_id, co_owner_group_id, valid_to IS NULL)`.
async fn edge_row(pool: &PgPool, id: Uuid) -> (Uuid, Uuid, Uuid, Option<Uuid>, bool) {
    sqlx::query_as(
        "SELECT source_id, target_id, owner_group_id, co_owner_group_id, valid_to IS NULL \
           FROM edges WHERE id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .expect("edge row")
}

/// An UPDATE's outcome: rows affected, or the SQLSTATE it raised.
async fn update(conn: &mut PgConnection, sql: &str, id: Uuid, arg: Uuid) -> Result<u64, String> {
    sqlx::query(sql)
        .bind(id)
        .bind(arg)
        .execute(&mut *conn)
        .await
        .map(|r| r.rows_affected())
        .map_err(|e| {
            e.as_database_error()
                .and_then(|d| d.code())
                .map(|c| c.to_string())
                .unwrap_or_else(|| e.to_string())
        })
}

/// The W9 review-2 attack, and every other UPDATE of a world edge, from a
/// BYSTANDER. Z can read the public-public world edge A -> B. It tries to
/// re-point the edge's source at its own public claim (which 070's trigger
/// would restamp, re-owning the edge), its target, to retract it and to
/// relabel it; each matches 0 rows, and the follow-up DELETE -- which 115's
/// source-writer arm would have admitted after a re-point -- removes nothing.
/// The edge is exactly as it was. The superuser (a privileged session, as the
/// administrative cascade is) still re-points it.
#[sqlx::test(migrations = "../../migrations")]
async fn a_bystander_cannot_repoint_a_world_edge_and_so_cannot_reown_or_delete_it(pool: PgPool) {
    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let (z, z_group) = fixture::seed_agent_with_group(&pool, "bystander-z").await;
    let a = fixture::seed_public_claim(&pool, author, "world claim A").await;
    let b = fixture::seed_public_claim(&pool, author, "world claim B").await;
    let zc = seed_public_claim_owned_by(&pool, z, z_group, "Z's own public claim").await;
    let edge = fixture::seed_edge(&pool, a, b).await;
    let before = edge_row(&pool, edge).await;
    assert_eq!(
        (before.2, before.3),
        (WORLD, None),
        "fixture shape: an edge between two public claims is nobody's"
    );
    assert_app_role_does_not_bypass(&pool).await;

    let p = pool.clone();
    let (seen, outcomes, deleted) =
        fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
            stamp(&mut conn, &p, z).await;
            let seen: i64 = sqlx::query_scalar("SELECT count(*) FROM edges WHERE id = $1")
                .bind(edge)
                .fetch_one(&mut *conn)
                .await
                .expect("read as Z");
            let mut outcomes = Vec::new();
            for (what, sql) in [
            ("re-point source", "UPDATE edges SET source_id = $2 WHERE id = $1"),
            ("re-point target", "UPDATE edges SET target_id = $2 WHERE id = $1"),
            (
                "retract",
                "UPDATE edges SET valid_to = now() WHERE id = $1 AND $2 IS NOT NULL",
            ),
            (
                "relabel",
                "UPDATE edges SET properties = properties || jsonb_build_object('by', $2::text) \
                 WHERE id = $1",
            ),
        ] {
            outcomes.push((what, update(&mut conn, sql, edge, zc).await));
        }
            let deleted = sqlx::query("DELETE FROM edges WHERE id = $1")
                .bind(edge)
                .execute(&mut *conn)
                .await
                .expect("delete")
                .rows_affected();
            (conn, (seen, outcomes, deleted))
        })
        .await;
    assert_eq!(seen, 1, "calibration: Z reads the world edge");
    for (what, r) in &outcomes {
        assert_eq!(
            r,
            &Ok(0),
            "{what}: a bystander's UPDATE of a world edge matches nothing"
        );
    }
    assert_eq!(
        deleted, 0,
        "and the re-point-then-delete attack removes nothing"
    );
    assert_eq!(edge_row(&pool, edge).await, before, "the edge is untouched");

    // Privileged: the administrative cascade's shape still lands.
    let n = sqlx::query("UPDATE edges SET source_id = $2 WHERE id = $1")
        .bind(edge)
        .bind(zc)
        .execute(&pool)
        .await
        .expect("superuser re-point")
        .rows_affected();
    assert_eq!(n, 1);
}

/// The edge's OWNER and CO-OWNER still update it. W owns an edge between two of
/// its group's private claims: it retracts, relabels and re-points it. C
/// co-owns an edge G1 -> G2 (and reads it as a reader of G1). 077's permissive
/// WITH CHECK names only the OWNER, so a co-owner's in-place relabel was
/// refused before 117 and still is (42501); what the co-owner may do is
/// re-point the edge off the owner's endpoint, after which the restamp leaves
/// it in C's group -- 117's USING admits the co-owner, and its WITH CHECK the
/// restamped row. A bystander Z updates nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn the_owner_and_the_co_owner_still_update_their_edges(pool: PgPool) {
    let (w, g1) = fixture::seed_agent_with_group(&pool, "owner-w").await;
    let (c, g2) = fixture::seed_agent_with_group(&pool, "co-owner-c").await;
    let (z, _) = fixture::seed_agent_with_group(&pool, "bystander-z").await;
    add_reader(&pool, g1, c).await;
    let w1 = fixture::seed_group_claim(&pool, w, g1, "W's private claim 1").await;
    let w2 = fixture::seed_group_claim(&pool, w, g1, "W's private claim 2").await;
    let w3 = fixture::seed_group_claim(&pool, w, g1, "W's private claim 3").await;
    let cc = fixture::seed_group_claim(&pool, c, g2, "C's private claim").await;
    let public = fixture::seed_public_claim(&pool, w, "a public claim").await;
    let owned = fixture::seed_edge(&pool, w1, w2).await;
    let co_owned = fixture::seed_edge(&pool, w1, cc).await;
    assert_eq!(
        {
            let r = edge_row(&pool, owned).await;
            (r.2, r.3)
        },
        (g1, None)
    );
    assert_eq!(
        {
            let r = edge_row(&pool, co_owned).await;
            (r.2, r.3)
        },
        (g1, Some(g2)),
        "fixture shape: owned by G1, co-owned by G2"
    );
    assert_app_role_does_not_bypass(&pool).await;

    let p = pool.clone();
    let (by_w, by_c, by_z) = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, w).await;
        let by_w =
            vec![
            update(
                &mut conn,
                "UPDATE edges SET properties = properties || jsonb_build_object('by', $2::text) \
                 WHERE id = $1",
                owned,
                w,
            )
            .await,
            update(&mut conn, "UPDATE edges SET target_id = $2 WHERE id = $1", owned, w3).await,
            update(
                &mut conn,
                "UPDATE edges SET valid_to = now() WHERE id = $1 AND $2 IS NOT NULL",
                owned,
                w,
            )
            .await,
        ];
        stamp(&mut conn, &p, z).await;
        let by_z_repoint = update(
            &mut conn,
            "UPDATE edges SET source_id = $2 WHERE id = $1",
            co_owned,
            public,
        )
        .await;
        stamp(&mut conn, &p, c).await;
        let by_c = vec![
            update(
                &mut conn,
                "UPDATE edges SET properties = properties || jsonb_build_object('by', $2::text) \
                 WHERE id = $1",
                co_owned,
                c,
            )
            .await,
            update(
                &mut conn,
                "UPDATE edges SET source_id = $2 WHERE id = $1",
                co_owned,
                public,
            )
            .await,
        ];
        stamp(&mut conn, &p, z).await;
        let by_z = update(
            &mut conn,
            "UPDATE edges SET properties = properties || jsonb_build_object('by', $2::text) \
             WHERE id = $1",
            co_owned,
            z,
        )
        .await;
        (conn, (by_w, by_c, (by_z, by_z_repoint)))
    })
    .await;
    assert_eq!(
        by_w,
        vec![Ok(1), Ok(1), Ok(1)],
        "the owner relabels, re-points, retracts"
    );
    assert_eq!(
        by_c,
        vec![Err("42501".to_string()), Ok(1)],
        "the co-owner: in-place relabel refused by 077's owner-only WITH CHECK; re-point admitted"
    );
    assert_eq!(by_z, (Ok(0), Ok(0)), "a bystander does neither");
    let r = edge_row(&pool, co_owned).await;
    assert_eq!(
        (r.0, r.2, r.3),
        (public, g2, None),
        "re-pointed, now C's group alone"
    );
    let r = edge_row(&pool, owned).await;
    assert_eq!((r.1, r.4), (w3, false), "re-pointed and retracted");
}

/// The WITH CHECK half: `edges_tenancy`'s restamp cannot be driven to a row the
/// session would not own. C co-owns W's edge G1 -> G2; W re-points its SOURCE
/// at a public claim, which the trigger restamps to `('group', G2)` alone --
/// C's group, not W's. The row W would leave behind is not W's, so the UPDATE
/// is refused (42501) and nothing changes.
#[sqlx::test(migrations = "../../migrations")]
async fn a_repoint_whose_restamp_the_session_would_not_own_is_refused(pool: PgPool) {
    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let (w, g1) = fixture::seed_agent_with_group(&pool, "owner-w").await;
    let (c, g2) = fixture::seed_agent_with_group(&pool, "co-owner-c").await;
    add_reader(&pool, g2, w).await;
    let w1 = fixture::seed_group_claim(&pool, w, g1, "W's private claim").await;
    let cc = fixture::seed_group_claim(&pool, c, g2, "C's private claim").await;
    let public = fixture::seed_public_claim(&pool, author, "a world claim").await;
    let edge = fixture::seed_edge(&pool, w1, cc).await;
    let before = edge_row(&pool, edge).await;
    assert_eq!((before.2, before.3), (g1, Some(g2)), "fixture shape");
    assert_app_role_does_not_bypass(&pool).await;

    let p = pool.clone();
    let r = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, w).await;
        let r = update(
            &mut conn,
            "UPDATE edges SET source_id = $2 WHERE id = $1",
            edge,
            public,
        )
        .await;
        (conn, r)
    })
    .await;
    assert_eq!(r, Err("42501".to_string()), "the restamped row is not W's");
    assert_eq!(edge_row(&pool, edge).await, before, "nothing changed");
}

/// The four registries. A WORLD frame and a WORLD perspective -- shared by
/// every group -- are not updatable by any application session; a frame owned
/// by W's group is W's to update. The superuser still updates a world row.
#[sqlx::test(migrations = "../../migrations")]
async fn a_registry_row_nobody_owns_is_not_updatable_by_the_app_role(pool: PgPool) {
    let (w, g) = fixture::seed_agent_with_group(&pool, "writer-w").await;
    let world_frame = epigraph_db::FrameRepository::create(
        &pool,
        "w10-world-frame",
        Some("world registry row"),
        &["TRUE".to_string(), "FALSE".to_string()],
    )
    .await
    .expect("world frame")
    .id;
    let world_perspective = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO perspectives (id, name, visibility, owner_group_id) \
         VALUES ($1, 'w10 world perspective', 'public', '00000000-0000-0000-0000-000000000000')",
    )
    .bind(world_perspective)
    .execute(&pool)
    .await
    .expect("world perspective");
    let owned_frame = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO frames (id, name, hypotheses, visibility, owner_group_id) \
         VALUES ($1, 'w10-owned-frame', ARRAY['A','B'], 'group', $2)",
    )
    .bind(owned_frame)
    .bind(g)
    .execute(&pool)
    .await
    .expect("group-owned frame");
    for (t, id) in [("frames", world_frame), ("perspectives", world_perspective)] {
        let owner: Uuid =
            sqlx::query_scalar(&format!("SELECT owner_group_id FROM {t} WHERE id = $1"))
                .bind(id)
                .fetch_one(&pool)
                .await
                .expect("owner");
        assert_eq!(owner, WORLD, "fixture shape: {t} row is the world's");
    }
    assert_app_role_does_not_bypass(&pool).await;

    let p = pool.clone();
    let outcomes = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, w).await;
        let sql = |t: &str| {
            format!(
                "UPDATE {t} SET properties = COALESCE(properties, '{{}}'::jsonb) \
                   || jsonb_build_object('by', $2::text) WHERE id = $1"
            )
        };
        let out = vec![
            update(&mut conn, &sql("frames"), world_frame, w).await,
            update(&mut conn, &sql("perspectives"), world_perspective, w).await,
            update(&mut conn, &sql("frames"), owned_frame, w).await,
        ];
        (conn, out)
    })
    .await;
    assert_eq!(
        outcomes,
        vec![Ok(0), Ok(0), Ok(1)],
        "world frame, world perspective: nobody's; W's own frame: W's"
    );
    let n = sqlx::query(
        "UPDATE frames SET properties = COALESCE(properties, '{}'::jsonb) || '{\"su\":1}' \
         WHERE id = $1",
    )
    .bind(world_frame)
    .execute(&pool)
    .await
    .expect("superuser")
    .rows_affected();
    assert_eq!(n, 1, "a privileged session updates a world registry row");
}

/// Every relation with both tenancy columns whose UPDATE-covering permissive
/// policy admits a WORLD-owned row in its WITH CHECK carries a restrictive,
/// FOR UPDATE policy whose USING and WITH CHECK both name the writable set. The
/// set is exactly 117's five; a sixth fails here until it gets one.
#[sqlx::test(migrations = "../../migrations")]
async fn every_world_admitting_table_has_a_restrictive_update_policy(pool: PgPool) {
    let rows: Vec<(String, bool)> = sqlx::query_as(
        "WITH t AS ( \
           SELECT c.oid, c.relname FROM pg_class c \
             JOIN pg_namespace n ON n.oid = c.relnamespace \
            WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p') \
              AND EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = c.oid \
                            AND a.attname = 'owner_group_id' AND NOT a.attisdropped) \
              AND EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = c.oid \
                            AND a.attname = 'visibility' AND NOT a.attisdropped)) \
         SELECT t.relname::text, EXISTS ( \
                  SELECT 1 FROM pg_policy r WHERE r.polrelid = t.oid \
                     AND NOT r.polpermissive AND r.polcmd = 'w' \
                     AND pg_get_expr(r.polqual, r.polrelid) LIKE '%epigraph_writable_groups%' \
                     AND pg_get_expr(r.polwithcheck, r.polrelid) \
                         LIKE '%epigraph_writable_groups%' \
                     AND pg_get_expr(r.polqual, r.polrelid) \
                         NOT LIKE '%00000000-0000-0000-0000-000000000000%' \
                     AND pg_get_expr(r.polwithcheck, r.polrelid) \
                         NOT LIKE '%00000000-0000-0000-0000-000000000000%') \
           FROM t \
          WHERE EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid = t.oid \
                           AND p.polpermissive AND p.polcmd IN ('*', 'w') \
                           AND pg_get_expr(p.polwithcheck, p.polrelid) \
                               LIKE '%00000000-0000-0000-0000-000000000000%') \
          ORDER BY 1",
    )
    .fetch_all(&pool)
    .await
    .expect("catalog");
    let names: Vec<&str> = rows.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(
        names,
        vec!["communities", "contexts", "edges", "frames", "perspectives"],
        "the world-admitting set changed; give a new member 117's policy"
    );
    for (t, ok) in &rows {
        assert!(
            ok,
            "{t} admits a world row on UPDATE and has no owner-scoped UPDATE policy"
        );
    }
}

/// Only `edges` restamps its owner on UPDATE (070/072's `edges_tenancy`, which
/// assigns `NEW.owner_group_id` from the endpoints). A second table that did
/// would re-own a row without naming the owner column, which 115's guard does
/// not see; it must get 117's policy first.
#[sqlx::test(migrations = "../../migrations")]
async fn no_other_table_restamps_its_owner_on_update(pool: PgPool) {
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT c.relname::text, tg.tgname::text \
           FROM pg_trigger tg \
           JOIN pg_class c ON c.oid = tg.tgrelid \
           JOIN pg_namespace n ON n.oid = c.relnamespace \
           JOIN pg_proc p ON p.oid = tg.tgfoid \
          WHERE n.nspname = 'public' AND NOT tg.tgisinternal \
            AND (tg.tgtype & 16) <> 0 AND (tg.tgtype & 2) <> 0 \
            AND p.prosrc ~* 'NEW\\.owner_group_id\\s*:=' \
          ORDER BY 1, 2",
    )
    .fetch_all(&pool)
    .await
    .expect("catalog");
    assert_eq!(
        rows,
        vec![("edges".to_string(), "edges_tenancy".to_string())],
        "a BEFORE UPDATE trigger that restamps an owner appeared or moved"
    );
}
