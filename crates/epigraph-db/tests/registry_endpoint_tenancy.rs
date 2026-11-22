//! Migration 258: a `frame`, `context`, `perspective` or `community` endpoint
//! contributes its OWN tenancy (the registry row's `owner_group_id`,
//! `visibility`, migration 062) to an edge's meet (backlog a07c25c0).
//!
//! Before 258, `epigraph_node_tenancy` (070, 219) answered `('public',
//! world)` for all four types, and 219's propagation read only claims,
//! evidence and workflows. So an edge from a PUBLIC claim to a group-private
//! registry row was `('public', world)`: a non-member listing the claim's
//! edges read the private row's id and its link to the claim.
//!
//! What is pinned:
//!
//! * on the APPLICATION ROLE (`epigraph_app`, row security on), per type: a
//!   non-member does not read the edge from a public claim to a group-private
//!   registry row, and does read the control edge onto a public one; a member
//!   reads both;
//! * the oracle answers each registry row's own tuple;
//! * the claim-side cascade (`epigraph_propagate_tenancy`) meets each type,
//!   on either side of the edge, with its own row when the claim narrows into
//!   another group (co-owned, never handed to the claim's group alone);
//! * the one-time re-meet (258 section 4) narrows an edge stamped before 258,
//!   keeps the group a legacy declaration required (co-owned), holds an edge
//!   that would need three groups, leaves public registry rows' edges alone,
//!   and is idempotent;
//! * the one-time re-meet skips an edge whose other endpoint no longer exists
//!   (instead of aborting on `edges_validate_refs`) and still narrows the rest.
//!
//! Verified to fail (mutations of 258, each applied alone):
//! * the `perspective` arm removed from `epigraph_node_tenancy` -> the
//!   perspective app-role test, the oracle test, the narrowing test and the
//!   re-meet test fail;
//! * the target-side `communities` LEFT JOIN of `epigraph_propagate_tenancy`
//!   disabled -> only the narrowing test fails (community, node is target);
//! * the `refs_ok` guard removed from section 4 -> the dangling-endpoint test
//!   fails (the re-run aborts on the reference check).
//!
//! With 258 replaced by an empty stub (the tree before 258) every test here
//! fails: the edges are public, and section 4 is absent. Emptying section 4
//! alone is NOT enough to fail the app-role tests: the function arms still
//! stamp new edges correctly.

mod viewer_fixture;

use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture as fixture;

const WORLD: Uuid = Uuid::nil();

/// The migration file itself, so the re-run below cannot drift from it.
const MIGRATION_258: &str = include_str!("../../../migrations/258_registry_endpoint_tenancy.sql");

/// The four registry endpoint types and their tables.
const TYPES: [(&str, &str); 4] = [
    ("frame", "frames"),
    ("context", "contexts"),
    ("perspective", "perspectives"),
    ("community", "communities"),
];

/// A registry row of entity type `ty` with the given tenancy (harness
/// superuser, standing in for a legacy re-stamp or a group writer's direct
/// write; no first-party writer produces a group-private one).
async fn registry_row(pool: &PgPool, ty: &str, owner: Uuid, visibility: &str) -> Uuid {
    let id = Uuid::new_v4();
    let name = format!("{ty}-{id}");
    let sql = match ty {
        "frame" => {
            "INSERT INTO frames (id, name, hypotheses, owner_group_id, visibility) \
             VALUES ($1, $2, ARRAY['a','b'], $3, $4)"
        }
        "context" => {
            "INSERT INTO contexts (id, name, context_type, owner_group_id, visibility) \
             VALUES ($1, $2, 'domain', $3, $4)"
        }
        "perspective" => {
            "INSERT INTO perspectives (id, name, owner_group_id, visibility) \
             VALUES ($1, $2, $3, $4)"
        }
        "community" => {
            "INSERT INTO communities (id, name, owner_group_id, visibility) \
             VALUES ($1, $2, $3, $4)"
        }
        other => panic!("no seeder for {other}"),
    };
    sqlx::query(sql)
        .bind(id)
        .bind(&name)
        .bind(owner)
        .bind(visibility)
        .execute(pool)
        .await
        .unwrap_or_else(|e| panic!("seed {ty}: {e}"));
    id
}

/// An UNDECLARED edge (062's defaults): the trigger derives its tenancy.
async fn edge(pool: &PgPool, source: (Uuid, &str), target: (Uuid, &str)) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, $2, $3, $4, 'relates_to') RETURNING id",
    )
    .bind(source.0)
    .bind(source.1)
    .bind(target.0)
    .bind(target.1)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("insert {} -> {} edge: {e}", source.1, target.1))
}

async fn edge_tenancy(pool: &PgPool, id: Uuid) -> (String, Uuid, Option<Uuid>) {
    sqlx::query_as(
        "SELECT visibility::text, owner_group_id, co_owner_group_id FROM edges WHERE id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .expect("read edge tenancy")
}

fn group(g: Uuid) -> (String, Uuid, Option<Uuid>) {
    ("group".to_string(), g, None)
}

fn public_world() -> (String, Uuid, Option<Uuid>) {
    ("public".to_string(), WORLD, None)
}

/// The edges among `ids` that a session of the application role reads, with
/// `groups` stamped as its read set (none: a non-member of every group).
async fn app_reads(app: &PgPool, groups: &[Uuid], ids: &[Uuid]) -> Vec<Uuid> {
    let mut conn = app.acquire().await.expect("acquire app-role connection");
    let set = groups
        .iter()
        .map(Uuid::to_string)
        .collect::<Vec<_>>()
        .join(",");
    sqlx::query("SELECT set_config('epigraph.group_ids', $1, false)")
        .bind(&set)
        .execute(&mut *conn)
        .await
        .expect("stamp the read set");
    let who: String = sqlx::query_scalar("SELECT current_user::text")
        .fetch_one(&mut *conn)
        .await
        .expect("current_user");
    assert_eq!(
        who, "epigraph_app",
        "CALIBRATION: the read runs as the application role"
    );
    let mut out: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM edges WHERE id = ANY($1)")
        .bind(ids)
        .fetch_all(&mut *conn)
        .await
        .expect("read edges as the application role");
    out.sort();
    out
}

/// For registry type `ty`: an edge from a PUBLIC claim to a group-private row
/// is the row's group's, and the application role reads it only as a member;
/// the control edge onto a public row of the same type is read by anyone.
async fn a_non_member_cannot_read_an_edge_onto_a_private(pool: PgPool, ty: &str) {
    let (agent, g) = fixture::seed_agent_with_group(&pool, &format!("{ty}-owner")).await;
    let (_, stranger) = fixture::seed_agent_with_group(&pool, &format!("{ty}-stranger")).await;
    let claim =
        fixture::seed_public_claim(&pool, agent, &format!("a public claim near a {ty}")).await;
    let private = registry_row(&pool, ty, g, "group").await;
    let public = registry_row(&pool, ty, WORLD, "public").await;

    let e_private = edge(&pool, (claim, "claim"), (private, ty)).await;
    let e_private_rev = edge(&pool, (private, ty), (claim, "claim")).await;
    let e_public = edge(&pool, (claim, "claim"), (public, ty)).await;

    assert_eq!(
        edge_tenancy(&pool, e_private).await,
        group(g),
        "an edge from a public claim onto a group-private {ty} is the {ty}'s group's"
    );
    assert_eq!(
        edge_tenancy(&pool, e_private_rev).await,
        group(g),
        "the same with the {ty} as the SOURCE end"
    );
    assert_eq!(
        edge_tenancy(&pool, e_public).await,
        public_world(),
        "CALIBRATION: an edge between a public claim and a public {ty} stays structural"
    );

    let app = fixture::downgraded_pool(&pool, "epigraph_app").await;
    let all = [e_private, e_private_rev, e_public];
    let mut members = all.to_vec();
    members.sort();
    assert_eq!(
        app_reads(&app, &[], &all).await,
        vec![e_public],
        "a session in no group reads the public {ty}'s edge and not the private one's"
    );
    assert_eq!(
        app_reads(&app, &[stranger], &all).await,
        vec![e_public],
        "a member of another group does not read the private {ty}'s edges either"
    );
    assert_eq!(
        app_reads(&app, &[g], &all).await,
        members,
        "CALIBRATION: a member of the {ty}'s group reads all three edges"
    );
    app.close().await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_non_member_cannot_read_an_edge_onto_a_private_frame(pool: PgPool) {
    a_non_member_cannot_read_an_edge_onto_a_private(pool, "frame").await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_non_member_cannot_read_an_edge_onto_a_private_context(pool: PgPool) {
    a_non_member_cannot_read_an_edge_onto_a_private(pool, "context").await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_non_member_cannot_read_an_edge_onto_a_private_perspective(pool: PgPool) {
    a_non_member_cannot_read_an_edge_onto_a_private(pool, "perspective").await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_non_member_cannot_read_an_edge_onto_a_private_community(pool: PgPool) {
    a_non_member_cannot_read_an_edge_onto_a_private(pool, "community").await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_oracle_answers_each_registry_rows_own_tuple(pool: PgPool) {
    let (_, g) = fixture::seed_agent_with_group(&pool, "registry-oracle").await;
    for (ty, _) in TYPES {
        let private = registry_row(&pool, ty, g, "group").await;
        let public = registry_row(&pool, ty, g, "public").await;
        let answer = |id: Uuid| {
            let pool = pool.clone();
            async move {
                sqlx::query_as::<_, (Uuid, String)>(
                    "SELECT g, v::text FROM public.epigraph_node_tenancy($1, $2)",
                )
                .bind(id)
                .bind(ty)
                .fetch_all(&pool)
                .await
                .expect("call the oracle")
            }
        };
        assert_eq!(
            answer(private).await,
            vec![(g, "group".to_string())],
            "{ty}"
        );
        assert_eq!(
            answer(public).await,
            vec![(g, "public".to_string())],
            "{ty}"
        );
        assert_eq!(
            answer(Uuid::new_v4()).await,
            vec![(WORLD, "public".to_string())],
            "an unknown {ty} id keeps 070's ('public', world) fallback"
        );
    }

    // CREATE OR REPLACE kept 070's frame: maintenance-owned, not executable by
    // the application role.
    let (owner, app_exec): (String, bool) = sqlx::query_as(
        "SELECT pg_get_userbyid(p.proowner)::text, \
                has_function_privilege('epigraph_app', p.oid, 'EXECUTE') \
           FROM pg_proc p WHERE p.oid = 'public.epigraph_node_tenancy(uuid, text)'::regprocedure",
    )
    .fetch_one(&pool)
    .await
    .expect("read the oracle's catalog row");
    assert_eq!(owner, "epigraph_maintenance");
    assert!(
        !app_exec,
        "the oracle stays revoked from the application role"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn narrowing_a_claim_co_owns_its_edges_onto_private_registry_rows(pool: PgPool) {
    let (agent, node_group) = fixture::seed_agent_with_group(&pool, "registry-node-group").await;
    let (_, other) = fixture::seed_agent_with_group(&pool, "registry-claim-group").await;
    let claim = fixture::seed_public_claim(&pool, agent, "a public claim about to narrow").await;

    // Per type and side: an edge onto a private row of the type, and one onto
    // a public row (calibration).
    let mut private_edges = Vec::new();
    let mut public_edges = Vec::new();
    for (ty, _) in TYPES {
        let private = registry_row(&pool, ty, node_group, "group").await;
        let public = registry_row(&pool, ty, WORLD, "public").await;
        for node_is_source in [false, true] {
            let (p, q) = if node_is_source {
                (
                    edge(&pool, (private, ty), (claim, "claim")).await,
                    edge(&pool, (public, ty), (claim, "claim")).await,
                )
            } else {
                (
                    edge(&pool, (claim, "claim"), (private, ty)).await,
                    edge(&pool, (claim, "claim"), (public, ty)).await,
                )
            };
            assert_eq!(
                edge_tenancy(&pool, p).await,
                group(node_group),
                "CALIBRATION: the write-time stamp ({ty}, node is source: {node_is_source})"
            );
            private_edges.push((ty, node_is_source, p));
            public_edges.push((ty, node_is_source, q));
        }
    }

    // The claim narrows into ANOTHER group (a privatization or restrict act).
    sqlx::query("UPDATE claims SET visibility = 'group', owner_group_id = $2 WHERE id = $1")
        .bind(claim)
        .bind(other)
        .execute(&pool)
        .await
        .expect("narrow the claim");

    for (ty, node_is_source, e) in private_edges {
        // 072's co-owner rule: the SOURCE's group owns, the TARGET's co-owns.
        let want = if node_is_source {
            ("group".to_string(), node_group, Some(other))
        } else {
            ("group".to_string(), other, Some(node_group))
        };
        assert_eq!(
            edge_tenancy(&pool, e).await,
            want,
            "the cascade meets the edge with the {ty}'s row as well as the claim's (node is \
             source: {node_is_source}): co-owned, so the claim's group alone never reads an \
             edge naming a {ty} it cannot read"
        );
    }
    for (ty, node_is_source, e) in public_edges {
        assert_eq!(
            edge_tenancy(&pool, e).await,
            group(other),
            "CALIBRATION: a public {ty}'s edge takes the claim's group alone (node is source: \
             {node_is_source})"
        );
    }
}

/// The text of 258 from its section 4 on (the bypass guard and the re-meet,
/// both idempotent), to re-run on a database that already carries 258.
fn section_4() -> &'static str {
    let at = MIGRATION_258
        .find("-- 4. THE ONE-TIME RE-MEET")
        .expect("258 has its section 4");
    let start = MIGRATION_258[..at]
        .rfind("-- ====")
        .expect("section 4's rule line");
    &MIGRATION_258[start..]
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_one_time_re_meet_narrows_stale_edges_onto_private_registry_rows(pool: PgPool) {
    let (agent, g) = fixture::seed_agent_with_group(&pool, "registry-backfill").await;
    let (other_agent, other) =
        fixture::seed_agent_with_group(&pool, "registry-backfill-other").await;
    let claim = fixture::seed_public_claim(&pool, agent, "a public claim").await;
    let theirs = fixture::seed_group_claim(&pool, other_agent, other, "their private claim").await;

    let (_, third) = fixture::seed_agent_with_group(&pool, "registry-backfill-third").await;

    let mut stale_public = Vec::new();
    let mut stale_cross = Vec::new();
    let mut declared = Vec::new();
    let mut held = Vec::new();
    let mut untouched = Vec::new();
    for (ty, _) in TYPES {
        let private = registry_row(&pool, ty, g, "group").await;
        let public = registry_row(&pool, ty, WORLD, "public").await;
        stale_public.push((ty, edge(&pool, (claim, "claim"), (private, ty)).await));
        stale_public.push((ty, edge(&pool, (private, ty), (claim, "claim")).await));
        stale_cross.push((ty, edge(&pool, (private, ty), (theirs, "claim")).await));
        declared.push((ty, edge(&pool, (claim, "claim"), (private, ty)).await));
        held.push((ty, edge(&pool, (claim, "claim"), (private, ty)).await));
        untouched.push((ty, edge(&pool, (claim, "claim"), (public, ty)).await));
    }

    // The rows as a pre-258 database stamped them: the registry row counted
    // as public.
    let ids: Vec<Uuid> = stale_public.iter().map(|(_, e)| *e).collect();
    sqlx::query(
        "UPDATE edges SET visibility = 'public', owner_group_id = $2, co_owner_group_id = NULL \
          WHERE id = ANY($1)",
    )
    .bind(&ids)
    .bind(WORLD)
    .execute(&pool)
    .await
    .expect("restore the pre-258 public edges");
    let cross: Vec<Uuid> = stale_cross.iter().map(|(_, e)| *e).collect();
    sqlx::query(
        "UPDATE edges SET visibility = 'group', owner_group_id = $2, co_owner_group_id = NULL \
          WHERE id = ANY($1)",
    )
    .bind(&cross)
    .bind(other)
    .execute(&pool)
    .await
    .expect("restore the pre-258 claim-only meet");
    // A legacy edge DECLARED private to another group, between a public claim
    // and the registry row (the old oracle counted the row public, so 120's
    // no-widening arm kept the declaration).
    let ids: Vec<Uuid> = declared.iter().map(|(_, e)| *e).collect();
    sqlx::query(
        "UPDATE edges SET visibility = 'group', owner_group_id = $2, co_owner_group_id = NULL \
          WHERE id = ANY($1)",
    )
    .bind(&ids)
    .bind(other)
    .execute(&pool)
    .await
    .expect("restore the pre-258 declaration");
    // The same, declared co-owned by two OTHER groups: with the row's group
    // that is three, more than an edge carries.
    let ids: Vec<Uuid> = held.iter().map(|(_, e)| *e).collect();
    sqlx::query(
        "UPDATE edges SET visibility = 'group', owner_group_id = $2, co_owner_group_id = $3 \
          WHERE id = ANY($1)",
    )
    .bind(&ids)
    .bind(other)
    .bind(third)
    .execute(&pool)
    .await
    .expect("restore the pre-258 co-owned declaration");

    sqlx::raw_sql(section_4())
        .execute(&pool)
        .await
        .expect("re-run 258's section 4");

    for (ty, e) in &stale_public {
        assert_eq!(
            edge_tenancy(&pool, *e).await,
            group(g),
            "{ty} edge narrowed"
        );
    }
    for (ty, e) in &stale_cross {
        assert_eq!(
            edge_tenancy(&pool, *e).await,
            ("group".to_string(), g, Some(other)),
            "an edge from a group-private {ty} onto another group's claim becomes co-owned"
        );
    }
    for (ty, e) in &declared {
        assert_eq!(
            edge_tenancy(&pool, *e).await,
            ("group".to_string(), g, Some(other)),
            "a {ty} edge declared private to another group keeps that group: co-owned, never \
             handed to the {ty}'s group alone"
        );
    }
    for (ty, e) in &held {
        assert_eq!(
            edge_tenancy(&pool, *e).await,
            ("group".to_string(), other, Some(third)),
            "a {ty} edge that would need three groups is held as it is"
        );
    }
    for (ty, e) in &untouched {
        assert_eq!(
            edge_tenancy(&pool, *e).await,
            public_world(),
            "a public {ty}'s edge is not touched"
        );
    }

    let snapshot = || {
        let pool = pool.clone();
        async move {
            sqlx::query_as::<_, (Uuid, String, Uuid, Option<Uuid>)>(
                "SELECT id, visibility::text, owner_group_id, co_owner_group_id FROM edges \
                 ORDER BY id",
            )
            .fetch_all(&pool)
            .await
            .expect("snapshot")
        }
    };
    let before = snapshot().await;
    sqlx::raw_sql(section_4())
        .execute(&pool)
        .await
        .expect("re-run 258's section 4 again");
    assert_eq!(before, snapshot().await, "the re-meet is idempotent");
}

/// An edge between a group-private registry row and an endpoint that no
/// longer exists, written with `edges_validate_refs` disabled (harness
/// superuser), standing in for a row whose other endpoint was deleted after
/// the edge was written.
async fn dangling_edge(pool: &PgPool, registry: (Uuid, &str)) -> Uuid {
    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("ALTER TABLE edges DISABLE TRIGGER edges_validate_refs")
        .execute(&mut *tx)
        .await
        .expect("disable edges_validate_refs");
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, $2, $3, 'agent', 'relates_to') RETURNING id",
    )
    .bind(registry.0)
    .bind(registry.1)
    .bind(Uuid::new_v4())
    .fetch_one(&mut *tx)
    .await
    .expect("insert a dangling edge");
    sqlx::query("ALTER TABLE edges ENABLE TRIGGER edges_validate_refs")
        .execute(&mut *tx)
        .await
        .expect("re-enable edges_validate_refs");
    tx.commit().await.expect("commit");
    id
}

/// Section 4 skips (and counts) an edge whose other endpoint no longer
/// exists instead of aborting: an UPDATE of `edges` fires
/// `edges_validate_refs` on every row it writes, so one dangling row would
/// fail the migration and the api's boot with it. The re-meet of every other
/// stale edge in the same run still lands.
///
/// Verified to fail without the `refs_ok` guard in section 4: the re-run
/// raises the reference error and this test panics at "re-run 258's section 4".
#[sqlx::test(migrations = "../../migrations")]
async fn the_one_time_re_meet_skips_an_edge_with_a_dangling_endpoint(pool: PgPool) {
    let (agent, g) = fixture::seed_agent_with_group(&pool, "registry-dangling").await;
    let claim = fixture::seed_public_claim(&pool, agent, "a public claim").await;

    let mut dangling = Vec::new();
    let mut stale = Vec::new();
    for (ty, _) in TYPES {
        let private = registry_row(&pool, ty, g, "group").await;
        dangling.push((ty, dangling_edge(&pool, (private, ty)).await));
        stale.push((ty, edge(&pool, (claim, "claim"), (private, ty)).await));
    }
    let ids: Vec<Uuid> = dangling
        .iter()
        .chain(stale.iter())
        .map(|(_, e)| *e)
        .collect();
    // The pre-258 stamp (the registry row counted as public). Written with
    // edges_validate_refs off too: the dangling rows would trip it.
    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("ALTER TABLE edges DISABLE TRIGGER edges_validate_refs")
        .execute(&mut *tx)
        .await
        .expect("disable edges_validate_refs");
    sqlx::query(
        "UPDATE edges SET visibility = 'public', owner_group_id = $2, co_owner_group_id = NULL \
          WHERE id = ANY($1)",
    )
    .bind(&ids)
    .bind(WORLD)
    .execute(&mut *tx)
    .await
    .expect("restore the pre-258 public edges");
    sqlx::query("ALTER TABLE edges ENABLE TRIGGER edges_validate_refs")
        .execute(&mut *tx)
        .await
        .expect("re-enable edges_validate_refs");
    tx.commit().await.expect("commit");

    sqlx::raw_sql(section_4())
        .execute(&pool)
        .await
        .expect("re-run 258's section 4");

    for (ty, e) in &dangling {
        assert_eq!(
            edge_tenancy(&pool, *e).await,
            public_world(),
            "a {ty} edge with a dangling endpoint is skipped, not written"
        );
    }
    for (ty, e) in &stale {
        assert_eq!(
            edge_tenancy(&pool, *e).await,
            group(g),
            "the other stale {ty} edge in the same run is still narrowed"
        );
    }
}
