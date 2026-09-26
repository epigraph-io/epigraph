//! Migration 114: a row a writer ATTACHES to a public claim it cannot write is
//! owned by the WRITER's group and stays public; the claim's per-claim
//! aggregates stay the claim's and are reached by a non-owner only through the
//! audited definers; the claim ROW stays the owner's.
//!
//! # Why every arm runs as `epigraph_app`
//!
//! `#[sqlx::test]` connects as the superuser `epigraph`, which bypasses RLS and
//! which 114 deliberately leaves on the old path — so an arm shaped "the insert
//! now lands" passes identically on a tree without 114 when run on the harness
//! connection. Every arm below switches the session to the non-bypassing
//! `epigraph_app` (`SET SESSION AUTHORIZATION`, so `session_user` is the app
//! role, as it is for the production app DSN), asserts it does not bypass,
//! and stamps the three session GUCs from `Viewer::resolve` exactly as
//! `ScopedPool::begin_as` does.
//!
//! # The claims are world-owned, like production's
//!
//! 473,114 of 480,115 production claims are `('public', world)` and authored by
//! somebody else; `fixture::seed_public_claim` produces exactly that shape.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::visibility::Viewer;
use epigraph_db::{AgentRepository, CachedBelief, FrameRepository, MassFunctionRepository};
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

/// Stamp `conn` for `agent` exactly as `ScopedPool::begin_as` would: the
/// groups and writable groups `Viewer::resolve` computes, and the principal.
async fn stamp(conn: &mut PgConnection, pool: &PgPool, agent: Uuid) {
    let v = Viewer::resolve(pool, agent).await.expect("resolve viewer");
    let groups = csv(v.group_bind().expect("scoped viewer"));
    let writable = csv(v.writable_groups());
    assert!(
        !writable.is_empty(),
        "a writer with no writable group makes every arm vacuous"
    );
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

/// The three GUCs cleared: the unstamped steady state of an app session.
async fn unstamp(conn: &mut PgConnection) {
    sqlx::query(
        "SELECT set_config('epigraph.group_ids', '', false), \
                set_config('epigraph.writable_group_ids', '', false), \
                set_config('epigraph.principal_id', '', false)",
    )
    .execute(&mut *conn)
    .await
    .expect("clear session gucs");
}

async fn seed_frame(pool: &PgPool, name: &str) -> Uuid {
    FrameRepository::create(
        pool,
        name,
        Some("writer-owned fixture"),
        &["TRUE".to_string(), "FALSE".to_string()],
    )
    .await
    .expect("seed frame")
    .id
}

/// Seed a public claim owned by `group` (NOT the world): the shape the MCP write
/// path gives a claim its own author submits.
async fn seed_public_claim_owned_by(pool: &PgPool, agent: Uuid, group: Uuid, tag: &str) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, $2, $3, 0.5, $4, true, 'public', $5)",
    )
    .bind(id)
    .bind(format!("writer-owned fixture claim {tag}"))
    .bind(&hash)
    .bind(agent)
    .bind(group)
    .execute(pool)
    .await
    .expect("seed a public claim owned by a group");
    id
}

fn evidence_sql() -> &'static str {
    "INSERT INTO evidence (claim_id, evidence_type, content_hash, raw_content) \
     VALUES ($1, 'observation', $2, $3) RETURNING id"
}

async fn insert_evidence(
    conn: &mut PgConnection,
    claim: Uuid,
    tag: &str,
) -> Result<Uuid, sqlx::Error> {
    let hash: Vec<u8> = blake3::hash(format!("{claim}:{tag}").as_bytes())
        .as_bytes()
        .to_vec();
    sqlx::query_scalar(evidence_sql())
        .bind(claim)
        .bind(&hash)
        .bind(format!("writer-owned evidence {tag}"))
        .fetch_one(&mut *conn)
        .await
}

async fn tenancy(pool: &PgPool, table: &str, id: Uuid) -> (Uuid, String, bool) {
    sqlx::query_as(&format!(
        "SELECT owner_group_id, visibility::text, writer_owned FROM {table} WHERE id = $1"
    ))
    .bind(id)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("read {table} {id}: {e}"))
}

async fn audit_events(pool: &PgPool, claim: Uuid) -> Vec<(Option<Uuid>, String)> {
    sqlx::query_as(
        "SELECT agent_id, details->>'action' FROM security_events \
          WHERE event_type = 'claims.foreign_aggregate_write' \
            AND details->>'claim_id' = $1::text ORDER BY created_at",
    )
    .bind(claim)
    .fetch_all(pool)
    .await
    .expect("read audit events")
}

// ===========================================================================
// 1. The three per-writer tables, plain writer.
// ===========================================================================

/// A writer attaches evidence, a mass function and a reasoning trace to a
/// WORLD-owned public claim another agent authored. All three land, owned by the
/// writer's personal group, public, and marked `writer_owned`. The same three
/// statements on an UNSTAMPED session are still refused, so what admitted them
/// is the writer's identity, not a loosened policy.
#[sqlx::test(migrations = "../../migrations")]
async fn a_writer_attaches_evidence_mass_and_trace_to_a_world_claim_it_cannot_write(pool: PgPool) {
    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let (writer, writer_group) = fixture::seed_agent_with_group(&pool, "writer").await;
    let claim = fixture::seed_public_claim(&pool, author, "world claim W").await;
    let frame = seed_frame(&pool, "wo-frame-1").await;
    assert_app_role_does_not_bypass(&pool).await;

    let p = pool.clone();
    let (ev, mf, tr, refused) = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        // Unstamped first: the pre-114 answer, still.
        unstamp(&mut conn).await;
        let refused = insert_evidence(&mut conn, claim, "unstamped").await;

        stamp(&mut conn, &p, writer).await;
        let ev = insert_evidence(&mut conn, claim, "stamped").await;
        let mf = MassFunctionRepository::store_with_perspective(
            &mut *conn,
            claim,
            frame,
            Some(writer),
            None,
            &serde_json::json!({"0": 0.6, "0,1": 0.4}),
            None,
            Some("test"),
            None,
            None,
            "unknown",
            None,
        )
        .await;
        let tr: Result<Uuid, sqlx::Error> = sqlx::query_scalar(
            "INSERT INTO reasoning_traces (claim_id, reasoning_type, explanation) \
             VALUES ($1, 'deductive', 'writer-owned trace') RETURNING id",
        )
        .bind(claim)
        .fetch_one(&mut *conn)
        .await;
        (conn, (ev, mf, tr, refused))
    })
    .await;

    let refused = refused.expect_err("an UNSTAMPED app session has no writer to own the row");
    assert!(
        refused.to_string().contains("row-level security"),
        "the unstamped refusal must be 077's WITH CHECK, as before 114: {refused}"
    );
    for (table, id) in [
        ("evidence", ev.expect("stamped evidence onto a world claim")),
        (
            "mass_functions",
            mf.expect("stamped mass function onto a world claim"),
        ),
        (
            "reasoning_traces",
            tr.expect("stamped trace onto a world claim"),
        ),
    ] {
        let (owner, vis, writer_owned) = tenancy(&pool, table, id).await;
        assert_eq!(
            owner, writer_group,
            "{table}: owned by the WRITER's personal group"
        );
        assert_ne!(owner, WORLD, "{table}: never the claim's world owner");
        assert_eq!(vis, "public", "{table}: evidence is never sequestered");
        assert!(writer_owned, "{table}: marked writer-owned");
    }
    let (claim_owner, claim_labels): (Uuid, Vec<String>) =
        sqlx::query_as("SELECT owner_group_id, labels FROM claims WHERE id = $1")
            .bind(claim)
            .fetch_one(&pool)
            .await
            .expect("read claim");
    assert_eq!(claim_owner, WORLD, "attaching never re-owns the claim");
    assert!(claim_labels.is_empty());
}

// ===========================================================================
// 2. An operated agent attaches under its operator's group (#503's rule).
// ===========================================================================

#[sqlx::test(migrations = "../../migrations")]
async fn an_operated_agent_attaches_under_its_operators_group(pool: PgPool) {
    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let (operator, operator_group) = fixture::seed_agent_with_group(&pool, "operator").await;
    let (agent, agent_group) = fixture::seed_agent_with_group(&pool, "operated").await;
    {
        let mut conn = pool.acquire().await.expect("acquire");
        let out = AgentRepository::link_operator(&mut conn, agent, operator)
            .await
            .expect("link the agent to its operator on the harness connection");
        assert_eq!(out.operator_group_id, operator_group);
    }
    let claim =
        fixture::seed_public_claim(&pool, author, "world claim for an operated agent").await;
    assert_app_role_does_not_bypass(&pool).await;

    let p = pool.clone();
    let ev = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, agent).await;
        let ev = insert_evidence(&mut conn, claim, "operated").await;
        (conn, ev)
    })
    .await
    .expect("an operated agent attaches to a world claim");

    let (owner, vis, writer_owned) = tenancy(&pool, "evidence", ev).await;
    assert_eq!(
        owner, operator_group,
        "an operated agent's row is owned by its OPERATOR's group, as its claims are \
         (ClaimRepository::default_decl_for_author)"
    );
    assert_ne!(
        owner, agent_group,
        "not the operated agent's own personal group"
    );
    assert_eq!(vis, "public");
    assert!(writer_owned);
}

// ===========================================================================
// 3. The claim's own writer: unchanged.
// ===========================================================================

/// The owner's path is 074/070's: the row inherits the claim's owner, a
/// caller-declared `writer_owned = true` is forced false, and a declared owner
/// that differs from the claim's is re-synced to the claim's by arm (c).
#[sqlx::test(migrations = "../../migrations")]
async fn the_claims_own_writer_still_inherits_the_claims_owner(pool: PgPool) {
    let (owner, owner_group) = fixture::seed_agent_with_group(&pool, "owner").await;
    let claim = seed_public_claim_owned_by(&pool, owner, owner_group, "owned").await;
    // A second writable group of the owner, to declare instead of the claim's:
    // another agent's personal group the owner is a writer of.
    let (_, other_group) = fixture::seed_agent_with_group(&pool, "other").await;
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'writer')",
    )
    .bind(other_group)
    .bind(owner)
    .execute(&pool)
    .await
    .expect("second writable group");
    assert_app_role_does_not_bypass(&pool).await;

    let p = pool.clone();
    let (plain, forged, declared) = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, owner).await;
        let plain = insert_evidence(&mut conn, claim, "owner-plain").await;
        let hash: Vec<u8> = blake3::hash(b"owner-forged").as_bytes().to_vec();
        let forged: Result<Uuid, sqlx::Error> = sqlx::query_scalar(
            "INSERT INTO evidence (claim_id, evidence_type, content_hash, writer_owned) \
             VALUES ($1, 'observation', $2, true) RETURNING id",
        )
        .bind(claim)
        .bind(&hash)
        .fetch_one(&mut *conn)
        .await;
        let hash: Vec<u8> = blake3::hash(b"owner-declared").as_bytes().to_vec();
        let declared: Result<Uuid, sqlx::Error> = sqlx::query_scalar(
            "INSERT INTO evidence (claim_id, evidence_type, content_hash, visibility, owner_group_id) \
             VALUES ($1, 'observation', $2, 'public', $3) RETURNING id",
        )
        .bind(claim)
        .bind(&hash)
        .bind(other_group)
        .fetch_one(&mut *conn)
        .await;
        (conn, (plain, forged, declared))
    })
    .await;

    for (what, id) in [
        ("plain", plain.expect("owner evidence")),
        (
            "forged writer_owned",
            forged.expect("owner evidence declaring writer_owned"),
        ),
        (
            "declared other owner",
            declared.expect("owner evidence declaring another group"),
        ),
    ] {
        let (g, vis, writer_owned) = tenancy(&pool, "evidence", id).await;
        assert_eq!(
            g, owner_group,
            "{what}: inherits the CLAIM's owner, as before 114"
        );
        assert_eq!(vis, "public");
        assert!(
            !writer_owned,
            "{what}: writer_owned is never caller-declared"
        );
    }
}

// ===========================================================================
// 4 + 5. The two propagation arms.
// ===========================================================================

/// Arm (c): a LATER insert on the same claim, by the claim's owner and by a
/// maintenance-class session, re-syncs the claim's rows and must not re-stamp
/// the writer's row to the claim's owner. Arm (d): privatizing the claim
/// narrows the writer's row to 'group' and keeps its owner; the owner's own
/// rows follow the claim; a re-own leaves the writer's owner alone.
#[sqlx::test(migrations = "../../migrations")]
async fn writer_rows_survive_both_propagation_arms_and_narrow_with_the_claim(pool: PgPool) {
    let (owner, owner_group) = fixture::seed_agent_with_group(&pool, "owner").await;
    let (writer, writer_group) = fixture::seed_agent_with_group(&pool, "writer").await;
    let claim = seed_public_claim_owned_by(&pool, owner, owner_group, "propagation").await;
    assert_app_role_does_not_bypass(&pool).await;

    let p = pool.clone();
    let (w_ev, o_ev) = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, writer).await;
        let w = insert_evidence(&mut conn, claim, "writer").await;
        // Arm (c) fires on this insert and re-syncs every row of the claim.
        stamp(&mut conn, &p, owner).await;
        let o = insert_evidence(&mut conn, claim, "owner-later").await;
        (conn, (w, o))
    })
    .await;
    let w_ev = w_ev.expect("writer evidence on another group's public claim");
    let o_ev = o_ev.expect("owner evidence");
    // And once more on the harness (privileged) connection.
    fixture::seed_evidence(&pool, claim, "reference").await;

    assert_eq!(
        tenancy(&pool, "evidence", w_ev).await,
        (writer_group, "public".to_string(), true),
        "arm (c) must not re-stamp a writer-owned row to the claim's owner"
    );
    assert_eq!(
        tenancy(&pool, "evidence", o_ev).await,
        (owner_group, "public".to_string(), false)
    );

    // Arm (d): privatize (a narrowing; the harness is the maintenance-class writer).
    sqlx::query("UPDATE claims SET visibility = 'group' WHERE id = $1")
        .bind(claim)
        .execute(&pool)
        .await
        .expect("privatize the claim");
    assert_eq!(
        tenancy(&pool, "evidence", w_ev).await,
        (writer_group, "group".to_string(), true),
        "privatizing the claim narrows the writer's row and never moves its owner"
    );
    assert_eq!(
        tenancy(&pool, "evidence", o_ev).await,
        (owner_group, "group".to_string(), false)
    );

    // Re-own to another group: the owner's rows follow, the writer's owner stays.
    let (_, new_group) = fixture::seed_agent_with_group(&pool, "new-owner").await;
    sqlx::query("UPDATE claims SET owner_group_id = $2 WHERE id = $1")
        .bind(claim)
        .bind(new_group)
        .execute(&pool)
        .await
        .expect("re-own the claim");
    assert_eq!(
        tenancy(&pool, "evidence", w_ev).await,
        (writer_group, "group".to_string(), true)
    );
    assert_eq!(
        tenancy(&pool, "evidence", o_ev).await,
        (new_group, "group".to_string(), false)
    );
}

// ===========================================================================
// 6 + 7. The owner guard, and the claim row.
// ===========================================================================

/// Nobody takes a row by UPDATE: moving a world-owned public row into one's own
/// group (which 077 alone admits: USING sees a public row, WITH CHECK sees a
/// writable owner) and clearing one's own `writer_owned` flag are both refused.
/// The claim ROW (labels) stays refused to a non-owner.
#[sqlx::test(migrations = "../../migrations")]
async fn no_app_session_re_owns_a_derived_row_or_writes_the_claim_row(pool: PgPool) {
    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let (writer, writer_group) = fixture::seed_agent_with_group(&pool, "writer").await;
    let claim = fixture::seed_public_claim(&pool, author, "guarded world claim").await;
    let world_ev = fixture::seed_evidence(&pool, claim, "document").await;
    assert_eq!(tenancy(&pool, "evidence", world_ev).await.0, WORLD);
    assert_app_role_does_not_bypass(&pool).await;

    let p = pool.clone();
    let (steal, unflag, relabel, mine) =
        fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
            stamp(&mut conn, &p, writer).await;
            let mine = insert_evidence(&mut conn, claim, "mine")
                .await
                .expect("attach");
            let steal = sqlx::query("UPDATE evidence SET owner_group_id = $2 WHERE id = $1")
                .bind(world_ev)
                .bind(writer_group)
                .execute(&mut *conn)
                .await;
            let unflag = sqlx::query("UPDATE evidence SET writer_owned = false WHERE id = $1")
                .bind(mine)
                .execute(&mut *conn)
                .await;
            let relabel = sqlx::query(
                "UPDATE claims SET labels = array_append(labels, 'stolen') WHERE id = $1",
            )
            .bind(claim)
            .execute(&mut *conn)
            .await;
            (conn, (steal, unflag, relabel, mine))
        })
        .await;

    let e = steal.expect_err("a world-owned row cannot be moved into the writer's group");
    assert!(
        e.to_string().contains("only a maintenance session re-owns"),
        "{e}"
    );
    let e = unflag.expect_err("the writer cannot clear its own writer_owned flag");
    assert!(
        e.to_string().contains("only a maintenance session re-owns"),
        "{e}"
    );
    let e = relabel.expect_err("the claim row stays its owner's");
    assert!(e.to_string().contains("row-level security"), "{e}");
    assert_eq!(tenancy(&pool, "evidence", world_ev).await.0, WORLD);
    assert!(tenancy(&pool, "evidence", mine).await.2);
    let labels: Vec<String> = sqlx::query_scalar("SELECT labels FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(&pool)
        .await
        .expect("labels");
    assert!(!labels.contains(&"stolen".to_string()));
}

// ===========================================================================
// 8. The per-claim aggregates through the audited definers.
// ===========================================================================

/// A non-owner's frame assignment and DS cache writes land CLAIM-owned, are
/// audited under the writer's principal, never change an existing assignment,
/// and never touch `truth_value`. The same call on an UNSTAMPED session keeps
/// the pre-114 answer (077's refusal): the path is attributable or it is not
/// taken.
#[sqlx::test(migrations = "../../migrations")]
async fn a_non_owners_aggregate_writes_are_claim_owned_audited_and_leave_truth_alone(pool: PgPool) {
    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let (writer, _) = fixture::seed_agent_with_group(&pool, "writer").await;
    let fresh = fixture::seed_public_claim(&pool, author, "no frame yet").await;
    let assigned = fixture::seed_public_claim(&pool, author, "already assigned").await;
    let frame = seed_frame(&pool, "wo-frame-8").await;
    // Production's shape: a world-owned assignment already exists (125k rows).
    FrameRepository::assign_claim(&pool, assigned, frame, Some(0))
        .await
        .expect("harness assignment");
    let truth_before: f64 = sqlx::query_scalar("SELECT truth_value FROM claims WHERE id = $1")
        .bind(fresh)
        .fetch_one(&pool)
        .await
        .expect("truth");
    assert_app_role_does_not_bypass(&pool).await;

    let p = pool.clone();
    let (unstamped, a_fresh, a_assigned, belief, class, clear) =
        fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
            unstamp(&mut conn).await;
            let unstamped = FrameRepository::assign_claim(&mut *conn, fresh, frame, Some(0)).await;
            stamp(&mut conn, &p, writer).await;
            let a_fresh = FrameRepository::assign_claim(&mut *conn, fresh, frame, Some(0)).await;
            // A DIFFERENT index onto an existing assignment: kept as the owner set it.
            let a_assigned =
                FrameRepository::assign_claim(&mut *conn, assigned, frame, Some(1)).await;
            let belief = MassFunctionRepository::update_claim_belief(
                &mut *conn,
                fresh,
                CachedBelief {
                    belief: 0.6,
                    plausibility: 0.9,
                    mass_on_empty: 0.0,
                    pignistic_prob: Some(0.75),
                    mass_on_missing: 0.0,
                    belief_frame_id: Some(frame),
                },
            )
            .await;
            let class = MassFunctionRepository::update_claim_classification(
                &mut *conn,
                fresh,
                "supported",
                frame,
            )
            .await;
            let clear = MassFunctionRepository::clear_claim_belief(&mut *conn, assigned).await;
            (conn, (unstamped, a_fresh, a_assigned, belief, class, clear))
        })
        .await;

    let e = unstamped.expect_err("no principal, no non-owner aggregate write");
    assert!(e.to_string().contains("row-level security"), "{e}");
    a_fresh.expect("non-owner frame assignment");
    a_assigned.expect("non-owner assignment onto an existing one");
    assert!(
        belief.expect("non-owner DS cache write"),
        "a claim with no cached frame is SEEDED by a non-owner's combination"
    );
    class.expect("non-owner classification write");
    assert_eq!(
        clear.expect("non-owner clear"),
        0,
        "nothing cached on `assigned` to clear"
    );

    let rows: Vec<(Uuid, Uuid, Option<i32>, String)> = sqlx::query_as(
        "SELECT claim_id, owner_group_id, hypothesis_index, visibility::text FROM claim_frames \
          WHERE frame_id = $1 ORDER BY claim_id",
    )
    .bind(frame)
    .fetch_all(&pool)
    .await
    .expect("claim_frames");
    assert_eq!(rows.len(), 2);
    for (c, owner, idx, vis) in &rows {
        assert_eq!(
            *owner, WORLD,
            "{c}: the assignment is the CLAIM's, not the writer's"
        );
        assert_eq!(vis, "public");
        assert_eq!(
            *idx,
            Some(0),
            "{c}: an existing index is never changed by a non-owner"
        );
    }

    let (bel, pl, betp, class, truth): (
        Option<f64>,
        Option<f64>,
        Option<f64>,
        Option<String>,
        f64,
    ) = sqlx::query_as(
        "SELECT belief, plausibility, pignistic_prob, classification, truth_value \
               FROM claims WHERE id = $1",
    )
    .bind(fresh)
    .fetch_one(&pool)
    .await
    .expect("claim cache");
    assert_eq!((bel, pl, betp), (Some(0.6), Some(0.9), Some(0.75)));
    assert_eq!(class.as_deref(), Some("supported"));
    assert_eq!(
        truth, truth_before,
        "the owner's truth_value is never written by this path"
    );

    let fresh_events = audit_events(&pool, fresh).await;
    assert_eq!(
        fresh_events,
        vec![
            (Some(writer), "claim_frame_attach".to_string()),
            (Some(writer), "belief_cache".to_string()),
            (Some(writer), "classification".to_string()),
        ],
        "one audit row per effective non-owner write, attributed to the writer"
    );
    assert!(
        audit_events(&pool, assigned).await.is_empty(),
        "a no-op (existing assignment, nothing to clear) writes no audit row"
    );
}

/// The owner's aggregate writes are the ordinary statements: claim-owned rows,
/// the index CAN be changed, and no audit row is written.
#[sqlx::test(migrations = "../../migrations")]
async fn the_owners_aggregate_writes_take_the_ordinary_path(pool: PgPool) {
    let (owner, owner_group) = fixture::seed_agent_with_group(&pool, "owner").await;
    let claim = seed_public_claim_owned_by(&pool, owner, owner_group, "owner aggregates").await;
    let frame = seed_frame(&pool, "wo-frame-9").await;
    assert_app_role_does_not_bypass(&pool).await;

    let p = pool.clone();
    let (first, second, belief) = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, owner).await;
        let first = FrameRepository::assign_claim(&mut *conn, claim, frame, Some(0)).await;
        let second = FrameRepository::assign_claim(&mut *conn, claim, frame, Some(1)).await;
        let belief = MassFunctionRepository::update_claim_belief(
            &mut *conn,
            claim,
            CachedBelief {
                belief: 0.2,
                plausibility: 0.7,
                mass_on_empty: 0.0,
                pignistic_prob: Some(0.45),
                mass_on_missing: 0.0,
                belief_frame_id: Some(frame),
            },
        )
        .await;
        (conn, (first, second, belief))
    })
    .await;
    first.expect("owner assignment");
    second.expect("owner re-assignment");
    belief.expect("owner cache write");

    let (g, idx): (Uuid, Option<i32>) = sqlx::query_as(
        "SELECT owner_group_id, hypothesis_index FROM claim_frames WHERE claim_id = $1",
    )
    .bind(claim)
    .fetch_one(&pool)
    .await
    .expect("assignment");
    assert_eq!(g, owner_group);
    assert_eq!(
        idx,
        Some(1),
        "the owner can still change its own claim's index"
    );
    assert!(audit_events(&pool, claim).await.is_empty());
}

/// A group-private claim the writer cannot read: the non-owner definer answers
/// with the SAME text a nonexistent id gets, modulo the id. (The tools read the
/// claim through the caller's viewer first and answer "not found" for both; this
/// pins the definer's own answer, which a raw app DSN can reach.)
#[sqlx::test(migrations = "../../migrations")]
async fn a_private_claim_the_writer_cannot_read_answers_like_a_missing_one(pool: PgPool) {
    let (author, author_group) = fixture::seed_agent_with_group(&pool, "author").await;
    let (writer, _) = fixture::seed_agent_with_group(&pool, "writer").await;
    let private = fixture::seed_group_claim(&pool, author, author_group, "private").await;
    let missing = Uuid::new_v4();
    assert_app_role_does_not_bypass(&pool).await;

    let p = pool.clone();
    let (a, b, ev) = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, writer).await;
        let a = sqlx::query_scalar::<_, i32>("SELECT public.epigraph_foreign_belief_clear($1)")
            .bind(private)
            .fetch_one(&mut *conn)
            .await;
        let b = sqlx::query_scalar::<_, i32>("SELECT public.epigraph_foreign_belief_clear($1)")
            .bind(missing)
            .fetch_one(&mut *conn)
            .await;
        let ev = insert_evidence(&mut conn, private, "private").await;
        (conn, (a, b, ev))
    })
    .await;
    let a = a
        .expect_err("private")
        .to_string()
        .replace(&private.to_string(), "<id>");
    let b = b
        .expect_err("missing")
        .to_string()
        .replace(&missing.to_string(), "<id>");
    assert_eq!(
        a, b,
        "an unreadable private claim must answer exactly as a missing one"
    );
    assert!(a.contains("FA02"), "{a}");
    ev.expect_err("evidence onto an unreadable private claim is still refused");
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM evidence WHERE claim_id = $1")
        .bind(private)
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(n, 0);
}

/// The claim's cache carries ONE frame's combination. A non-owner may refresh it
/// on that frame but may NOT re-point it to another frame -- here one the writer
/// just created, holding only its own BBA -- which would replace the claim's
/// cross-writer combination on the writer's own authority. The writer's BBA on
/// the other frame is still stored (writer-owned); the cache, its frame and its
/// classification are untouched and no audit row is written for the refused
/// re-point. (Found in the MCP rehearsal: `submit_ds_evidence` on a writer-made
/// frame moved a world claim's pignistic from its binary_truth combination.)
#[sqlx::test(migrations = "../../migrations")]
async fn a_non_owner_refreshes_the_claims_belief_frame_but_never_re_points_it(pool: PgPool) {
    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let (writer, writer_group) = fixture::seed_agent_with_group(&pool, "writer").await;
    let claim = fixture::seed_public_claim(&pool, author, "cache on frame A").await;
    let frame_a = seed_frame(&pool, "wo-frame-A").await;
    let frame_b = seed_frame(&pool, "wo-frame-B-writer-made").await;
    // The owner-side state: the cache carries frame A's combination.
    sqlx::query(
        "UPDATE claims SET belief = 0.5, plausibility = 0.9, pignistic_prob = 0.7, \
                           mass_on_empty = 0, mass_on_missing = 0, belief_frame_id = $2, \
                           classification = 'supported' WHERE id = $1",
    )
    .bind(claim)
    .bind(frame_a)
    .execute(&pool)
    .await
    .expect("owner-side cache on frame A");
    assert_app_role_does_not_bypass(&pool).await;

    let p = pool.clone();
    let (mf_b, on_b, class_b, on_a) =
        fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
            stamp(&mut conn, &p, writer).await;
            let mf_b = MassFunctionRepository::store_with_perspective(
                &mut *conn,
                claim,
                frame_b,
                Some(writer),
                None,
                &serde_json::json!({"1": 0.95, "0,1": 0.05}),
                None,
                Some("test"),
                None,
                None,
                "unknown",
                None,
            )
            .await;
            let on_b = MassFunctionRepository::update_claim_belief(
                &mut *conn,
                claim,
                CachedBelief {
                    belief: 0.0,
                    plausibility: 0.05,
                    mass_on_empty: 0.0,
                    pignistic_prob: Some(0.025),
                    mass_on_missing: 0.0,
                    belief_frame_id: Some(frame_b),
                },
            )
            .await;
            let class_b = MassFunctionRepository::update_claim_classification(
                &mut *conn,
                claim,
                "contradicted",
                frame_b,
            )
            .await;
            let on_a = MassFunctionRepository::update_claim_belief(
                &mut *conn,
                claim,
                CachedBelief {
                    belief: 0.55,
                    plausibility: 0.92,
                    mass_on_empty: 0.0,
                    pignistic_prob: Some(0.735),
                    mass_on_missing: 0.0,
                    belief_frame_id: Some(frame_a),
                },
            )
            .await;
            (conn, (mf_b, on_b, class_b, on_a))
        })
        .await;

    let mf_b = mf_b.expect("the writer's BBA on its own frame is stored");
    assert_eq!(
        tenancy(&pool, "mass_functions", mf_b).await,
        (writer_group, "public".to_string(), true)
    );
    assert!(
        !on_b.expect("a refused re-point is a no-op, not an error"),
        "the cache must NOT be re-pointed to the writer's frame"
    );
    class_b.expect("a refused classification is a no-op, not an error");
    assert!(
        on_a.expect("refresh on the cache's own frame"),
        "a non-owner DOES refresh the combination on the frame the cache carries"
    );

    let (frame, betp, class): (Option<Uuid>, Option<f64>, Option<String>) = sqlx::query_as(
        "SELECT belief_frame_id, pignistic_prob, classification FROM claims WHERE id = $1",
    )
    .bind(claim)
    .fetch_one(&pool)
    .await
    .expect("claim cache");
    assert_eq!(frame, Some(frame_a), "the cache still carries frame A");
    assert_eq!(
        betp,
        Some(0.735),
        "refreshed on A, never replaced by B's 0.025"
    );
    assert_eq!(
        class.as_deref(),
        Some("supported"),
        "B's verdict never lands"
    );
    let events = audit_events(&pool, claim).await;
    assert_eq!(
        events,
        vec![(Some(writer), "belief_cache".to_string())],
        "one audit row, for the refresh on A; none for the refused re-point"
    );
}
