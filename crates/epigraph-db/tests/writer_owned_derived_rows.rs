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
//! Most public claims are `('public', world)` and authored by somebody else;
//! `fixture::seed_public_claim` produces exactly that shape.

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
/// the writer's row to the claim's owner. Arm (d): re-owning the still-PUBLIC
/// claim leaves the writer's owner alone; privatizing it hands the writer's row
/// to the claim (owner and visibility follow, flag cleared: review finding W5),
/// after which it follows the claim like any claim-owned row.
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

    // Arm (d), claim still PUBLIC: re-own it. The owner's rows follow, the
    // writer's owner stays (the harness is the maintenance-class writer).
    let (_, new_group) = fixture::seed_agent_with_group(&pool, "new-owner").await;
    sqlx::query("UPDATE claims SET owner_group_id = $2 WHERE id = $1")
        .bind(claim)
        .bind(new_group)
        .execute(&pool)
        .await
        .expect("re-own the claim");
    assert_eq!(
        tenancy(&pool, "evidence", w_ev).await,
        (writer_group, "public".to_string(), true),
        "re-owning a public claim never moves the writer's row"
    );
    assert_eq!(
        tenancy(&pool, "evidence", o_ev).await,
        (new_group, "public".to_string(), false)
    );

    // Arm (d), claim NARROWED: the writer's row becomes the claim's.
    sqlx::query("UPDATE claims SET visibility = 'group' WHERE id = $1")
        .bind(claim)
        .execute(&pool)
        .await
        .expect("privatize the claim");
    assert_eq!(
        tenancy(&pool, "evidence", w_ev).await,
        (new_group, "group".to_string(), false),
        "privatizing hands the writer's row to the claim's owner, narrowed and un-flagged"
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
    // `binary_truth`: the only frame a non-owner may SEED a claim's cache on.
    let frame = seed_frame(&pool, "binary_truth").await;
    // The common shape: a world-owned assignment already exists.
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
        "a claim with no cache at all is SEEDED by a non-owner's binary_truth combination"
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

// ===========================================================================
// Review round 2 (PR #514): the prod-shaped and adversarial arms.
// ===========================================================================

async fn store_bba(
    conn: &mut PgConnection,
    claim: Uuid,
    frame: Uuid,
    agent: Uuid,
    perspective: Option<Uuid>,
    masses: serde_json::Value,
) -> Result<Uuid, epigraph_db::DbError> {
    MassFunctionRepository::store_with_perspective(
        &mut *conn,
        claim,
        frame,
        Some(agent),
        perspective,
        &masses,
        None,
        Some("test"),
        None,
        None,
        "unknown",
        None,
    )
    .await
}

fn cache(belief: f64, plausibility: f64, betp: f64, frame: Uuid) -> CachedBelief {
    CachedBelief {
        belief,
        plausibility,
        mass_on_empty: 0.0,
        pignistic_prob: Some(betp),
        mass_on_missing: 0.0,
        belief_frame_id: Some(frame),
    }
}

async fn cached(pool: &PgPool, claim: Uuid) -> (Option<Uuid>, Option<f64>, Option<String>) {
    sqlx::query_as(
        "SELECT belief_frame_id, pignistic_prob, classification FROM claims WHERE id = $1",
    )
    .bind(claim)
    .fetch_one(pool)
    .await
    .expect("claim cache")
}

/// W1. The common older shape: a cache (belief / pignistic / classification)
/// with NO `belief_frame_id`. A non-owner must not treat it as "no cache" and
/// seed over it -- that would replace the claim's belief with one BBA's
/// measures and then hand the frame to the writer. Seeding needs every cache
/// column NULL and lands on `binary_truth` only, and the clear definer touches
/// neither a frameless cache nor one still backed by a mass function.
#[sqlx::test(migrations = "../../migrations")]
async fn a_frameless_legacy_cache_is_never_seeded_over_and_only_binary_truth_seeds(pool: PgPool) {
    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let (writer, _) = fixture::seed_agent_with_group(&pool, "writer").await;
    let legacy = fixture::seed_public_claim(&pool, author, "legacy frameless cache").await;
    let fresh_own = fixture::seed_public_claim(&pool, author, "no cache, writer frame").await;
    let fresh_bt = fixture::seed_public_claim(&pool, author, "no cache, binary_truth").await;
    let backed = fixture::seed_public_claim(&pool, author, "framed cache, backed").await;
    let bt = seed_frame(&pool, "binary_truth").await;
    let own = seed_frame(&pool, "wo-writer-made-frame").await;
    sqlx::query(
        "UPDATE claims SET belief = 0.8, plausibility = 0.9, pignistic_prob = 0.85, \
                           classification = 'supported', belief_frame_id = NULL WHERE id = $1",
    )
    .bind(legacy)
    .execute(&pool)
    .await
    .expect("legacy frameless cache");
    sqlx::query(
        "UPDATE claims SET belief = 0.7, plausibility = 0.8, pignistic_prob = 0.75, \
                           belief_frame_id = $2 WHERE id = $1",
    )
    .bind(backed)
    .bind(bt)
    .execute(&pool)
    .await
    .expect("framed cache");
    {
        let mut h = pool.acquire().await.expect("acquire");
        store_bba(
            &mut h,
            backed,
            bt,
            author,
            None,
            serde_json::json!({"0": 0.7, "0,1": 0.3}),
        )
        .await
        .expect("harness BBA backing the framed cache");
    }
    assert_app_role_does_not_bypass(&pool).await;

    let p = pool.clone();
    let (on_legacy, class_legacy, clear_legacy, on_own, on_bt, clear_backed) =
        fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
            stamp(&mut conn, &p, writer).await;
            let a = MassFunctionRepository::update_claim_belief(
                &mut *conn,
                legacy,
                cache(0.0, 0.05, 0.025, bt),
            )
            .await;
            let b = MassFunctionRepository::update_claim_classification(
                &mut *conn,
                legacy,
                "contradicted",
                bt,
            )
            .await;
            let c = MassFunctionRepository::clear_claim_belief(&mut *conn, legacy).await;
            let d = MassFunctionRepository::update_claim_belief(
                &mut *conn,
                fresh_own,
                cache(0.1, 0.2, 0.15, own),
            )
            .await;
            let e = MassFunctionRepository::update_claim_belief(
                &mut *conn,
                fresh_bt,
                cache(0.6, 0.9, 0.75, bt),
            )
            .await;
            let f = MassFunctionRepository::clear_claim_belief(&mut *conn, backed).await;
            (conn, (a, b, c, d, e, f))
        })
        .await;

    assert!(
        !on_legacy.expect("a refused seed is a no-op, not an error"),
        "a frameless older cache must NOT be overwritten by one non-owner BBA"
    );
    class_legacy.expect("a refused classification is a no-op");
    assert_eq!(
        clear_legacy.expect("clear"),
        0,
        "a frameless cache is not cleared"
    );
    assert!(
        !on_own.expect("no-op"),
        "a non-owner cannot make a frame of its own the one carrying a claim's belief"
    );
    assert!(
        on_bt.expect("seed"),
        "an uncached claim IS seeded on binary_truth"
    );
    assert_eq!(
        clear_backed.expect("clear"),
        0,
        "a cache still backed by a mass function is not cleared"
    );

    assert_eq!(
        cached(&pool, legacy).await,
        (None, Some(0.85), Some("supported".to_string())),
        "the older cache is untouched"
    );
    assert_eq!(cached(&pool, fresh_own).await, (None, None, None));
    assert_eq!(cached(&pool, fresh_bt).await, (Some(bt), Some(0.75), None));
    assert_eq!(cached(&pool, backed).await.1, Some(0.75));
    for (c, want) in [(legacy, 0), (fresh_own, 0), (fresh_bt, 1), (backed, 0)] {
        assert_eq!(
            audit_events(&pool, c).await.len(),
            want,
            "{c}: an audit row only for an effective write"
        );
    }
}

/// W2. The `binary_truth` index is what every reader takes as the claim's own
/// truth. A non-owner may not CREATE that assignment at index 1 (FALSE): on a
/// world claim nobody could correct it. Index 0 is created; a second writer
/// asking for 1 afterwards keeps 0; another frame's index is not constrained.
#[sqlx::test(migrations = "../../migrations")]
async fn a_non_owner_cannot_bind_a_world_claim_to_false_on_binary_truth(pool: PgPool) {
    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let (w, _) = fixture::seed_agent_with_group(&pool, "writer-w").await;
    let (x, _) = fixture::seed_agent_with_group(&pool, "writer-x").await;
    let c1 = fixture::seed_public_claim(&pool, author, "binary claim").await;
    let c2 = fixture::seed_public_claim(&pool, author, "axis claim").await;
    let bt = seed_frame(&pool, "binary_truth").await;
    let axis = seed_frame(&pool, "wo-axis").await;
    assert_app_role_does_not_bypass(&pool).await;

    let p = pool.clone();
    let (false_first, true_first, x_false, axis_one) =
        fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
            stamp(&mut conn, &p, w).await;
            let a = FrameRepository::assign_claim(&mut *conn, c1, bt, Some(1)).await;
            let b = FrameRepository::assign_claim(&mut *conn, c1, bt, Some(0)).await;
            stamp(&mut conn, &p, x).await;
            let c = FrameRepository::assign_claim(&mut *conn, c1, bt, Some(1)).await;
            let d = FrameRepository::assign_claim(&mut *conn, c2, axis, Some(1)).await;
            (conn, (a, b, c, d))
        })
        .await;

    let e = false_first.expect_err("a non-owner's FALSE binding on binary_truth is refused");
    assert!(e.to_string().contains("FA07"), "{e}");
    true_first.expect("index 0 is created");
    x_false.expect("an existing assignment is kept, not an error");
    axis_one.expect("another frame's index is not constrained");

    let idx = |c: Uuid, f: Uuid| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, Option<i32>>(
                "SELECT hypothesis_index FROM claim_frames WHERE claim_id = $1 AND frame_id = $2",
            )
            .bind(c)
            .bind(f)
            .fetch_all(&pool)
            .await
            .expect("claim_frames")
        }
    };
    assert_eq!(idx(c1, bt).await, vec![Some(0)], "c1 stays bound to TRUE");
    assert_eq!(idx(c2, axis).await, vec![Some(1)]);
    assert_eq!(
        audit_events(&pool, c1).await,
        vec![(Some(w), "claim_frame_attach".to_string())],
        "the refused binding wrote no audit row"
    );
}

/// W3. A BBA a privileged server stored before 114 on a world claim is owned by
/// the world group, so its own source agent cannot replace it on the
/// application role (the upsert lands on that row and 077 refuses its owner).
/// The maintenance re-own hands it to the agent (its operator's group for an
/// operated agent), after which the replacement lands. A row whose agent can
/// write the claim's own group is left claim-owned. Batched and idempotent.
#[sqlx::test(migrations = "../../migrations")]
async fn a_legacy_claim_owned_bba_is_replaceable_after_the_maintenance_reown(pool: PgPool) {
    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let (w, w_group) = fixture::seed_agent_with_group(&pool, "writer").await;
    let (operator, operator_group) = fixture::seed_agent_with_group(&pool, "operator").await;
    let (operated, _) = fixture::seed_agent_with_group(&pool, "operated").await;
    let (member, member_group) = fixture::seed_agent_with_group(&pool, "member").await;
    {
        let mut conn = pool.acquire().await.expect("acquire");
        AgentRepository::link_operator(&mut conn, operated, operator)
            .await
            .expect("link");
    }
    let cw = fixture::seed_public_claim(&pool, author, "world claim with legacy BBAs").await;
    let cm = seed_public_claim_owned_by(&pool, member, member_group, "member's claim").await;
    let frame = seed_frame(&pool, "wo-legacy").await;
    let (w_row, p_row, m_row) = {
        let mut h = pool.acquire().await.expect("acquire");
        let m = serde_json::json!({"0": 0.6, "0,1": 0.4});
        (
            store_bba(&mut h, cw, frame, w, None, m.clone())
                .await
                .expect("legacy W"),
            store_bba(&mut h, cw, frame, operated, None, m.clone())
                .await
                .expect("legacy operated"),
            store_bba(&mut h, cm, frame, member, None, m)
                .await
                .expect("legacy member"),
        )
    };
    assert_eq!(
        tenancy(&pool, "mass_functions", w_row).await,
        (WORLD, "public".into(), false)
    );
    assert_app_role_does_not_bypass(&pool).await;

    let replace = |pool: PgPool| async move {
        let p = pool.clone();
        fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
            stamp(&mut conn, &p, w).await;
            let r = store_bba(
                &mut conn,
                cw,
                frame,
                w,
                None,
                serde_json::json!({"1": 0.3, "0,1": 0.7}),
            )
            .await;
            (conn, r)
        })
        .await
    };
    let before = replace(pool.clone()).await;
    let e = before.expect_err("the legacy row blocks its own agent's replacement");
    assert!(e.to_string().contains("row-level security"), "{e}");

    let calls: Vec<i64> = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let mut out = Vec::new();
        for limit in [Some(1_i32), None, None] {
            out.push(
                sqlx::query_scalar::<_, i64>("SELECT public.epigraph_reown_legacy_writer_bbas($1)")
                    .bind(limit)
                    .fetch_one(&mut *conn)
                    .await
                    .expect("maintenance re-own"),
            );
        }
        (conn, out)
    })
    .await;
    assert_eq!(
        calls,
        vec![1, 1, 0],
        "batched by the limit, then idempotent"
    );

    assert_eq!(
        tenancy(&pool, "mass_functions", w_row).await,
        (w_group, "public".into(), true)
    );
    assert_eq!(
        tenancy(&pool, "mass_functions", p_row).await,
        (operator_group, "public".into(), true),
        "an operated agent's legacy row goes to its OPERATOR's group"
    );
    assert_eq!(
        tenancy(&pool, "mass_functions", m_row).await,
        (member_group, "public".into(), false),
        "a row whose agent can write the claim's group stays the claim's"
    );
    let after = replace(pool.clone())
        .await
        .expect("the agent now replaces its own BBA");
    assert_eq!(after, w_row, "an upsert of the same key, not a new row");
    let events: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM security_events WHERE event_type = 'derived.legacy_writer_reown'",
    )
    .fetch_one(&pool)
    .await
    .expect("events");
    assert_eq!(events, 2, "one audit row per call that re-owned anything");
}

async fn seed_perspective(pool: &PgPool, id: Uuid) {
    sqlx::query("INSERT INTO perspectives (id, name) VALUES ($1, $2)")
        .bind(id)
        .bind(format!("edge {id}"))
        .execute(pool)
        .await
        .expect("seed edge perspective");
}

/// W4(b). A writer marks its own claim a duplicate of a WORLD-owned canonical.
/// The edge-keyed BBAs on the duplicate -- its own and ANOTHER writer's -- move
/// with their edges and come out writer-owned (so neither is re-stamped to the
/// world by a later insert), the canonical gets its binary_truth assignment
/// through the audited definer, and a duplicate bound to FALSE cannot pass
/// that binding to a canonical it does not own.
#[sqlx::test(migrations = "../../migrations")]
async fn mark_duplicate_onto_a_world_canonical_moves_every_writers_bba(pool: PgPool) {
    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let (w, w_group) = fixture::seed_agent_with_group(&pool, "dedup-writer").await;
    let (x, x_group) = fixture::seed_agent_with_group(&pool, "other-writer").await;
    let dup = seed_public_claim_owned_by(&pool, w, w_group, "the duplicate").await;
    let dup_false = seed_public_claim_owned_by(&pool, w, w_group, "a FALSE-bound dup").await;
    let sw = seed_public_claim_owned_by(&pool, w, w_group, "W's source").await;
    let sx = seed_public_claim_owned_by(&pool, x, x_group, "X's source").await;
    let canonical = fixture::seed_public_claim(&pool, author, "world canonical").await;
    let canonical2 = fixture::seed_public_claim(&pool, author, "world canonical 2").await;
    let bt = seed_frame(&pool, "binary_truth").await;
    let ex = fixture::seed_edge(&pool, sx, dup).await;
    let ew = fixture::seed_edge(&pool, sw, dup).await;
    let ef = fixture::seed_edge(&pool, sw, dup_false).await;
    for e in [ex, ew, ef] {
        seed_perspective(&pool, e).await;
    }
    assert_app_role_does_not_bypass(&pool).await;

    let p = pool.clone();
    let (x_bba, w_bba, repair, refused) =
        fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
            let m = serde_json::json!({"0": 0.6, "0,1": 0.4});
            stamp(&mut conn, &p, x).await;
            let x_bba = store_bba(&mut conn, dup, bt, x, Some(ex), m.clone()).await;
            stamp(&mut conn, &p, w).await;
            FrameRepository::assign_claim(&mut *conn, dup, bt, Some(0))
                .await
                .expect("W binds its own dup");
            FrameRepository::assign_claim(&mut *conn, dup_false, bt, Some(1))
                .await
                .expect("W may bind its OWN claim to FALSE");
            let w_bba = store_bba(&mut conn, dup, bt, w, Some(ew), m.clone()).await;
            store_bba(&mut conn, dup_false, bt, w, Some(ef), m)
                .await
                .expect("W's BBA on the FALSE-bound dup");
            let repair = epigraph_db::ClaimRepository::mark_duplicate_with_repair_conn(
                &mut conn,
                epigraph_core::ClaimId::from_uuid(dup),
                epigraph_core::ClaimId::from_uuid(canonical),
            )
            .await;
            let refused = epigraph_db::ClaimRepository::mark_duplicate_with_repair_conn(
                &mut conn,
                epigraph_core::ClaimId::from_uuid(dup_false),
                epigraph_core::ClaimId::from_uuid(canonical2),
            )
            .await;
            (conn, (x_bba, w_bba, repair, refused))
        })
        .await;
    let x_bba = x_bba.expect("X attaches to W's public claim");
    let w_bba = w_bba.expect("W's own BBA");
    assert_eq!(
        tenancy(&pool, "mass_functions", x_bba).await,
        (x_group, "public".into(), true)
    );
    let repair = repair.expect("the dedup onto a world canonical lands on the app role");
    assert_eq!(repair.moved_bbas, 2);

    for (id, group, what) in [(x_bba, x_group, "X's"), (w_bba, w_group, "W's")] {
        let on: Uuid = sqlx::query_scalar("SELECT claim_id FROM mass_functions WHERE id = $1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .expect("moved row");
        assert_eq!(on, canonical, "{what} BBA moved with its edge");
        assert_eq!(
            tenancy(&pool, "mass_functions", id).await,
            (group, "public".into(), true),
            "{what} BBA is writer-owned on the world canonical"
        );
    }
    // A later insert on the canonical (arm (c)) must not re-stamp them.
    fixture::seed_evidence(&pool, canonical, "reference").await;
    assert_eq!(tenancy(&pool, "mass_functions", w_bba).await.0, w_group);

    let (owner, idx): (Uuid, Option<i32>) = sqlx::query_as(
        "SELECT owner_group_id, hypothesis_index FROM claim_frames \
          WHERE claim_id = $1 AND frame_id = $2",
    )
    .bind(canonical)
    .bind(bt)
    .fetch_one(&pool)
    .await
    .expect("canonical assignment");
    assert_eq!(
        (owner, idx),
        (WORLD, Some(0)),
        "claim-owned, created via the definer"
    );
    let actions: Vec<String> = audit_events(&pool, canonical)
        .await
        .into_iter()
        .map(|(_, a)| a)
        .collect();
    assert!(
        actions.contains(&"claim_frame_attach".to_string()),
        "{actions:?}"
    );
    assert!(
        actions.contains(&"dedup_bba_move".to_string()),
        "{actions:?}"
    );

    let e = refused.expect_err("a FALSE binding cannot pass to a world canonical");
    assert!(e.to_string().contains("FA07"), "{e}");
    let still_current: bool = sqlx::query_scalar("SELECT is_current FROM claims WHERE id = $1")
        .bind(dup_false)
        .fetch_one(&pool)
        .await
        .expect("dup_false");
    assert!(still_current, "the refused dedup wrote nothing");
}

/// W5. After the claim's owner privatizes it, what a writer had attached is
/// the OWNER's: the owner sees it and can remove it, and the writer's group no
/// longer sees rows about a claim it cannot read.
#[sqlx::test(migrations = "../../migrations")]
async fn privatizing_a_claim_hands_its_writer_owned_rows_to_the_claims_owner(pool: PgPool) {
    let (owner, owner_group) = fixture::seed_agent_with_group(&pool, "owner").await;
    let (writer, _) = fixture::seed_agent_with_group(&pool, "writer").await;
    let claim = seed_public_claim_owned_by(&pool, owner, owner_group, "to be privatized").await;
    let frame = seed_frame(&pool, "wo-priv").await;
    assert_app_role_does_not_bypass(&pool).await;

    let p = pool.clone();
    let (ev, mf) = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, writer).await;
        let ev = insert_evidence(&mut conn, claim, "before-privatize")
            .await
            .expect("attach");
        let mf = store_bba(
            &mut conn,
            claim,
            frame,
            writer,
            None,
            serde_json::json!({"0": 0.9, "0,1": 0.1}),
        )
        .await
        .expect("attach BBA");
        (conn, (ev, mf))
    })
    .await;

    sqlx::query("UPDATE claims SET visibility = 'group' WHERE id = $1")
        .bind(claim)
        .execute(&pool)
        .await
        .expect("the owner privatizes (harness)");

    let p = pool.clone();
    let (w_sees, o_sees, o_deletes) =
        fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
            let q = "SELECT (SELECT count(*) FROM evidence WHERE id = $1) \
                      + (SELECT count(*) FROM mass_functions WHERE id = $2)";
            stamp(&mut conn, &p, writer).await;
            let w_sees: i64 = sqlx::query_scalar(q)
                .bind(ev)
                .bind(mf)
                .fetch_one(&mut *conn)
                .await
                .expect("w");
            stamp(&mut conn, &p, owner).await;
            let o_sees: i64 = sqlx::query_scalar(q)
                .bind(ev)
                .bind(mf)
                .fetch_one(&mut *conn)
                .await
                .expect("o");
            let o_deletes = sqlx::query("DELETE FROM evidence WHERE id = $1")
                .bind(ev)
                .execute(&mut *conn)
                .await
                .expect("owner deletes")
                .rows_affected();
            (conn, (w_sees, o_sees, o_deletes))
        })
        .await;
    assert_eq!(
        o_sees, 2,
        "the claim's owner sees what was attached to its claim"
    );
    assert_eq!(o_deletes, 1, "and can remove it");
    assert_eq!(
        w_sees, 0,
        "the writer's group no longer sees rows about a private claim"
    );
    assert_eq!(
        tenancy(&pool, "mass_functions", mf).await,
        (owner_group, "group".into(), false)
    );
}

/// W6. An attach and a privatization of the same claim serialise on the claim
/// row, in both orders, so no PUBLIC writer-owned row survives on a private
/// claim. Attach first: the privatization waits for it and then hands the row
/// to the owner. Privatization first: the attach waits, sees a private claim,
/// and is refused as before 114.
#[sqlx::test(migrations = "../../migrations")]
async fn an_attach_and_a_privatization_of_the_same_claim_serialise(pool: PgPool) {
    use std::time::Duration;
    let (owner, owner_group) = fixture::seed_agent_with_group(&pool, "owner").await;
    let (writer, _) = fixture::seed_agent_with_group(&pool, "writer").await;
    let c1 = seed_public_claim_owned_by(&pool, owner, owner_group, "attach first").await;
    let c2 = seed_public_claim_owned_by(&pool, owner, owner_group, "privatize first").await;
    assert_app_role_does_not_bypass(&pool).await;

    // Order 1: the attach holds its transaction open while the privatization runs.
    let p = pool.clone();
    let ev = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        use sqlx::Executor;
        stamp(&mut conn, &p, writer).await;
        conn.execute("BEGIN").await.expect("begin");
        let ev = insert_evidence(&mut conn, c1, "racing")
            .await
            .expect("attach");
        let pp = p.clone();
        let privatize = tokio::spawn(async move {
            sqlx::query("UPDATE claims SET visibility = 'group' WHERE id = $1")
                .bind(c1)
                .execute(&pp)
                .await
                .expect("privatize")
        });
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(
            !privatize.is_finished(),
            "the privatization must wait for the attach's claim lock"
        );
        conn.execute("COMMIT").await.expect("commit the attach");
        tokio::time::timeout(Duration::from_secs(10), privatize)
            .await
            .expect("the privatization proceeds once the attach commits")
            .expect("join");
        (conn, ev)
    })
    .await;
    assert_eq!(
        tenancy(&pool, "evidence", ev).await,
        (owner_group, "group".into(), false),
        "the privatization saw the committed attach and handed it to the owner"
    );

    // Order 2: the privatization holds the claim row while the attach runs.
    let mut btx = pool.begin().await.expect("begin privatization");
    sqlx::query("UPDATE claims SET visibility = 'group' WHERE id = $1")
        .bind(c2)
        .execute(&mut *btx)
        .await
        .expect("privatize, uncommitted");
    let committer = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(500)).await;
        btx.commit().await.expect("commit privatization");
    });
    let p = pool.clone();
    let late = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, writer).await;
        let r = tokio::time::timeout(
            Duration::from_secs(10),
            insert_evidence(&mut conn, c2, "late"),
        )
        .await
        .expect("the attach proceeds once the privatization commits");
        (conn, r)
    })
    .await;
    committer.await.expect("join");
    let e = late.expect_err("an attach that waited on a privatization is refused");
    assert!(e.to_string().contains("row-level security"), "{e}");
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM evidence WHERE claim_id = $1")
        .bind(c2)
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(n, 0);
}

/// W7. A writer owns its row, but the row's parent and visibility track a
/// claim that is not the writer's: re-pointing it at another claim (a private
/// one, or an id that does not exist) and changing its visibility are refused
/// with ONE message, before any foreign-key check (no existence oracle).
#[sqlx::test(migrations = "../../migrations")]
async fn a_writer_cannot_repoint_or_rescope_its_own_writer_owned_row(pool: PgPool) {
    let (author, author_group) = fixture::seed_agent_with_group(&pool, "author").await;
    let (writer, writer_group) = fixture::seed_agent_with_group(&pool, "writer").await;
    let world = fixture::seed_public_claim(&pool, author, "world").await;
    let private = fixture::seed_group_claim(&pool, author, author_group, "private").await;
    let frame = seed_frame(&pool, "wo-repoint").await;
    assert_app_role_does_not_bypass(&pool).await;

    let p = pool.clone();
    let (ev, mf, to_private, to_missing, rescope, mf_to_private) =
        fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
            stamp(&mut conn, &p, writer).await;
            let ev = insert_evidence(&mut conn, world, "mine")
                .await
                .expect("attach");
            let mf = store_bba(
                &mut conn,
                world,
                frame,
                writer,
                None,
                serde_json::json!({"0": 0.5, "0,1": 0.5}),
            )
            .await
            .expect("attach BBA");
            let upd = |sql: &'static str, id: Uuid, v: Uuid| (sql, id, v);
            let mut out = Vec::new();
            for (sql, id, v) in [
                upd(
                    "UPDATE evidence SET claim_id = $2 WHERE id = $1",
                    ev,
                    private,
                ),
                upd(
                    "UPDATE evidence SET claim_id = $2 WHERE id = $1",
                    ev,
                    Uuid::new_v4(),
                ),
                upd(
                    "UPDATE mass_functions SET claim_id = $2 WHERE id = $1",
                    mf,
                    private,
                ),
            ] {
                out.push(
                    sqlx::query(sql)
                        .bind(id)
                        .bind(v)
                        .execute(&mut *conn)
                        .await
                        .map(|r| r.rows_affected()),
                );
            }
            let rescope = sqlx::query("UPDATE evidence SET visibility = 'group' WHERE id = $1")
                .bind(ev)
                .execute(&mut *conn)
                .await
                .map(|r| r.rows_affected());
            let mut out = out.into_iter();
            let (a, b, c) = (
                out.next().unwrap(),
                out.next().unwrap(),
                out.next().unwrap(),
            );
            (conn, (ev, mf, a, b, rescope, c))
        })
        .await;

    let msg = |r: Result<u64, sqlx::Error>, what: &str| {
        r.expect_err(what)
            .to_string()
            .replace(&ev.to_string(), "<row>")
            .replace(&mf.to_string(), "<row>")
    };
    let a = msg(to_private, "re-pointing at a private claim is refused");
    let b = msg(to_missing, "re-pointing at a missing claim is refused");
    assert!(a.contains("moves a writer-owned one"), "{a}");
    assert_eq!(a, b, "a private target and a missing one answer alike");
    assert!(msg(rescope, "rescoping is refused").contains("moves a writer-owned one"));
    assert!(msg(mf_to_private, "BBA re-point refused").contains("moves a writer-owned one"));
    assert_eq!(
        tenancy(&pool, "evidence", ev).await,
        (writer_group, "public".into(), true)
    );
    let on: Uuid = sqlx::query_scalar("SELECT claim_id FROM evidence WHERE id = $1")
        .bind(ev)
        .fetch_one(&pool)
        .await
        .expect("row");
    assert_eq!(on, world);
}

/// W13. A principal with no writable group of its own attaches nothing (the
/// trigger leaves its row to 077), so it writes no aggregate through the
/// definers either, even called directly.
#[sqlx::test(migrations = "../../migrations")]
async fn a_principal_with_no_writable_group_writes_no_aggregate(pool: PgPool) {
    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let (reader, reader_group) = fixture::seed_agent_with_group(&pool, "reader").await;
    sqlx::query("UPDATE group_memberships SET role = 'reader' WHERE agent_id = $1")
        .bind(reader)
        .execute(&pool)
        .await
        .expect("downgrade to reader");
    let claim = fixture::seed_public_claim(&pool, author, "world").await;
    let bt = seed_frame(&pool, "binary_truth").await;
    assert_app_role_does_not_bypass(&pool).await;

    let (direct, via_repo) = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        sqlx::query(
            "SELECT set_config('epigraph.group_ids', $1, false), \
                    set_config('epigraph.writable_group_ids', '', false), \
                    set_config('epigraph.principal_id', $2, false)",
        )
        .bind(reader_group.to_string())
        .bind(reader.to_string())
        .execute(&mut *conn)
        .await
        .expect("stamp a read-only principal");
        let direct = sqlx::query_scalar::<_, i32>(
            "SELECT public.epigraph_foreign_belief_cache($1, 0.6, 0.9, 0, 0.75, 0, $2)",
        )
        .bind(claim)
        .bind(bt)
        .fetch_one(&mut *conn)
        .await;
        let via_repo = FrameRepository::assign_claim(&mut *conn, claim, bt, Some(0)).await;
        (conn, (direct, via_repo))
    })
    .await;
    let e = direct.expect_err("a read-only principal seeds no cache");
    assert!(e.to_string().contains("row-level security"), "{e}");
    via_repo.expect_err("nor a frame assignment");
    assert_eq!(cached(&pool, claim).await, (None, None, None));
    assert!(audit_events(&pool, claim).await.is_empty());
}
