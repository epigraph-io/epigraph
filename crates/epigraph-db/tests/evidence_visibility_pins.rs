//! Migration 110: a PINNED evidence row is never widened by tenancy
//! propagation, and an unpinned one behaves exactly as it did before 110.
//!
//! # The shape
//!
//! One claim carries two evidence rows: PINNED (hidden by an operator:
//! `('group', operator group)` plus a row in `evidence_visibility_pins`) and
//! FREE (an ordinary unpinned sibling). The claim is then driven through every
//! transition the two trigger arms react to:
//!
//! * arm (d), a claims UPDATE of `(owner_group_id, visibility)`: a re-own onto
//!   another group, a privatization (`public -> group`), a declassification
//!   onto the world group, and a move onto 074's seed group;
//! * arm (c), a new evidence INSERT for the same claim.
//!
//! FREE must equal its claim after every step (070/072's invariant, unchanged).
//! PINNED must stay `group` at every step; its owner follows the claim, except
//! onto world or seed, where it keeps the owner it had.
//!
//! `#[sqlx::test]` connects as a BYPASSRLS superuser, so the privilege arms
//! reach `epigraph_app` and `epigraph_maintenance` through `SET SESSION
//! AUTHORIZATION` ([`fixture::as_role`]).

#[path = "viewer_fixture.rs"]
mod fixture;

use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

const WORLD: Uuid = Uuid::nil();
const SEED: Uuid = Uuid::from_u128(0xdead);

async fn tenancy(pool: &PgPool, table: &str, id: Uuid) -> (Uuid, String) {
    sqlx::query_as(&format!(
        "SELECT owner_group_id, visibility::text FROM {table} WHERE id = $1"
    ))
    .bind(id)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("{table} {id}: {e}"))
}

async fn insert_evidence(pool: &PgPool, claim: Uuid, label: &str) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO evidence (id, claim_id, evidence_type, content_hash, raw_content) \
         VALUES ($1, $2, 'testimony', $3, $4)",
    )
    .bind(id)
    .bind(claim)
    .bind(hash)
    .bind(format!("evidence {label}"))
    .execute(pool)
    .await
    .expect("insert evidence");
    id
}

/// Hide `evidence` the way `epigraph-operator hide-evidence --apply` leaves
/// it: pinned, then `('group', group)`.
async fn hide(pool: &PgPool, evidence: Uuid, group: Uuid, operator: Uuid) {
    sqlx::query(
        "INSERT INTO evidence_visibility_pins (evidence_id, pinned_by, reason) \
         VALUES ($1, $2, 'test: hidden by the operator')",
    )
    .bind(evidence)
    .bind(operator)
    .execute(pool)
    .await
    .expect("pin");
    sqlx::query("UPDATE evidence SET owner_group_id = $2, visibility = 'group' WHERE id = $1")
        .bind(evidence)
        .bind(group)
        .execute(pool)
        .await
        .expect("hide");
}

/// Move a claim, as the admin declassification surface would: 074 refuses a
/// `group -> public` claim UPDATE unless `epigraph.allow_declassify = 'yes'`
/// is set for the transaction.
async fn move_claim(pool: &PgPool, claim: Uuid, owner: Uuid, visibility: &str) {
    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("SELECT set_config('epigraph.allow_declassify', 'yes', true)")
        .execute(&mut *tx)
        .await
        .expect("allow declassify");
    sqlx::query("UPDATE claims SET owner_group_id = $2, visibility = $3 WHERE id = $1")
        .bind(claim)
        .bind(owner)
        .bind(visibility)
        .execute(&mut *tx)
        .await
        .unwrap_or_else(|e| panic!("move claim to ({owner}, {visibility}): {e}"));
    tx.commit().await.expect("commit");
}

struct Fx {
    operator: Uuid,
    op_group: Uuid,
    other_group: Uuid,
    claim: Uuid,
    pinned: Uuid,
    free: Uuid,
}

async fn seed(pool: &PgPool) -> Fx {
    let (operator, op_group) = fixture::seed_agent_with_group(pool, "pin-operator").await;
    let (_, other_group) = fixture::seed_agent_with_group(pool, "pin-other").await;
    let claim =
        fixture::seed_public_claim(pool, operator, "a public claim with hidden evidence").await;
    let pinned = insert_evidence(pool, claim, "pinned").await;
    let free = insert_evidence(pool, claim, "free").await;
    hide(pool, pinned, op_group, operator).await;
    Fx {
        operator,
        op_group,
        other_group,
        claim,
        pinned,
        free,
    }
}

/// Every step asserts both rows; the message names the step.
async fn assert_rows(pool: &PgPool, fx: &Fx, step: &str, pinned_owner: Uuid) {
    let claim = tenancy(pool, "claims", fx.claim).await;
    assert_eq!(
        tenancy(pool, "evidence", fx.free).await,
        claim,
        "{step}: an UNPINNED evidence row must equal its claim (070/072, unchanged by 110)"
    );
    assert_eq!(
        tenancy(pool, "evidence", fx.pinned).await,
        (pinned_owner, "group".to_string()),
        "{step}: a PINNED evidence row must stay 'group' (never widened) and own {pinned_owner}"
    );
}

/// B-H2 end to end. Revert either arm's pin clause and the row is re-published:
/// arm (d) at the first `move_claim`, arm (c) at the evidence INSERT.
#[sqlx::test(migrations = "../../migrations")]
async fn a_pinned_row_is_never_widened_and_follows_its_claim_except_onto_world_or_seed(
    pool: PgPool,
) {
    let fx = seed(&pool).await;
    assert_rows(&pool, &fx, "after the hide", fx.op_group).await;

    // Arm (c): a NEW evidence row for the same public claim re-syncs every row
    // of the claim to the claim — except the pinned one.
    let late = insert_evidence(&pool, fx.claim, "late").await;
    assert_eq!(
        tenancy(&pool, "evidence", late).await,
        tenancy(&pool, "claims", fx.claim).await,
        "the inserted row inherits its claim"
    );
    assert_rows(&pool, &fx, "after an evidence INSERT (arm c)", fx.op_group).await;

    // Arm (d): a re-own onto another group. The pinned row follows the owner
    // and stays group.
    move_claim(&pool, fx.claim, fx.other_group, "public").await;
    assert_rows(&pool, &fx, "after a re-own (arm d)", fx.other_group).await;

    // Privatization, then declassification onto the world group.
    move_claim(&pool, fx.claim, fx.other_group, "group").await;
    assert_rows(&pool, &fx, "after privatization (arm d)", fx.other_group).await;
    move_claim(&pool, fx.claim, WORLD, "public").await;
    assert_rows(
        &pool,
        &fx,
        "after declassification onto world (arm d)",
        fx.other_group,
    )
    .await;

    // Back to a real group, then onto 074's seed group.
    move_claim(&pool, fx.claim, fx.op_group, "public").await;
    assert_rows(&pool, &fx, "after a re-own back (arm d)", fx.op_group).await;
    move_claim(&pool, fx.claim, SEED, "public").await;
    assert_rows(&pool, &fx, "after a move onto seed (arm d)", fx.op_group).await;

    // And arm (c) once more, on the seed-owned claim.
    insert_evidence(&pool, fx.claim, "later").await;
    assert_rows(
        &pool,
        &fx,
        "after a second evidence INSERT (arm c)",
        fx.op_group,
    )
    .await;
}

/// Unpinned rows keep 070/072 semantics: with NO pin anywhere, every evidence
/// row of the claim equals the claim after every transition, and a row made
/// STRICTER than its claim by hand is overwritten by the next evidence INSERT
/// (070's "no widening gate" is intact for everything that is not pinned).
#[sqlx::test(migrations = "../../migrations")]
async fn unpinned_rows_keep_the_070_072_semantics(pool: PgPool) {
    let (operator, op_group) = fixture::seed_agent_with_group(&pool, "nopin-operator").await;
    let (_, other_group) = fixture::seed_agent_with_group(&pool, "nopin-other").await;
    let claim = fixture::seed_public_claim(&pool, operator, "no pins here").await;
    let a = insert_evidence(&pool, claim, "a").await;
    let b = insert_evidence(&pool, claim, "b").await;

    for (owner, vis) in [
        (other_group, "public"),
        (other_group, "group"),
        (WORLD, "public"),
        (op_group, "group"),
        (SEED, "public"),
    ] {
        move_claim(&pool, claim, owner, vis).await;
        for e in [a, b] {
            assert_eq!(
                tenancy(&pool, "evidence", e).await,
                (owner, vis.to_string()),
                "unpinned evidence {e} must follow its claim to ({owner}, {vis})"
            );
        }
    }

    // A stricter-than-parent UNPINNED row is re-synced by the next INSERT.
    move_claim(&pool, claim, op_group, "public").await;
    sqlx::query("UPDATE evidence SET visibility = 'group' WHERE id = $1")
        .bind(a)
        .execute(&pool)
        .await
        .expect("make a stricter by hand");
    insert_evidence(&pool, claim, "c").await;
    assert_eq!(
        tenancy(&pool, "evidence", a).await,
        (op_group, "public".to_string()),
        "an unpinned row stricter than its claim is re-published by the next evidence \
         INSERT, exactly as before 110: only a PIN exempts a row"
    );
}

/// The `derived text[]` literal the operator CLI parses is still present and
/// names the same seventeen tables in the same order, and both bodies consult
/// the pin table (what `hide::guard_status` reads).
#[sqlx::test(migrations = "../../migrations")]
async fn the_bodies_keep_the_derived_literal_and_name_the_pin_table(pool: PgPool) {
    let (prop, inherit): (String, String) = sqlx::query_as(
        "SELECT (SELECT prosrc FROM pg_proc \
                  WHERE oid = 'public.epigraph_propagate_tenancy()'::regprocedure), \
                (SELECT prosrc FROM pg_proc \
                  WHERE oid = 'public.epigraph_inherit_tenancy_stmt()'::regprocedure)",
    )
    .fetch_one(&pool)
    .await
    .expect("bodies");
    let literal = "derived text[] := ARRAY[
          'triples','entity_mentions','claim_versions','mass_functions',
          'ds_combined_beliefs','ds_bayesian_divergence','claim_frames',
          'harvester_claim_provenance','evidence',
          'challenges','reasoning_traces','experiment_triples',
          'experiment_entity_mentions','claim_clusters','claim_cluster_membership',
          'claim_neighborhood_membership','claim_signature_revocations'];";
    assert!(
        prop.contains(literal),
        "072's derived[] literal must survive 110 byte for byte"
    );
    assert!(prop.contains("evidence_visibility_pins"));
    assert!(inherit.contains("evidence_visibility_pins"));
    let owners: Vec<(String, String, bool)> = sqlx::query_as(
        "SELECT p.proname::text, r.rolname::text, p.prosecdef FROM pg_proc p \
           JOIN pg_roles r ON r.oid = p.proowner \
          WHERE p.oid IN ('public.epigraph_propagate_tenancy()'::regprocedure, \
                          'public.epigraph_inherit_tenancy_stmt()'::regprocedure) \
          ORDER BY 1",
    )
    .fetch_all(&pool)
    .await
    .expect("owners");
    for (name, owner, definer) in owners {
        assert!(definer, "{name} must stay SECURITY DEFINER");
        assert_eq!(
            owner, "epigraph_maintenance",
            "{name} must be owned by maintenance"
        );
    }
}

async fn try_exec(conn: &mut PgConnection, sql: &str, id: Uuid) -> Result<u64, String> {
    sqlx::query(sql)
        .bind(id)
        .execute(&mut *conn)
        .await
        .map(|r| r.rows_affected())
        .map_err(|e| e.to_string())
}

/// Only a maintenance session can set or clear a pin. `epigraph_app` can
/// neither insert nor delete one, cannot update one, and reads none.
#[sqlx::test(migrations = "../../migrations")]
async fn only_a_maintenance_session_can_pin_or_unpin(pool: PgPool) {
    let fx = seed(&pool).await;
    let other = insert_evidence(&pool, fx.claim, "unpinned").await;
    fixture::grant_app_privileges(&pool, "epigraph_app").await;
    // `grant_app_privileges` is a blanket GRANT on every table; take the pin
    // table back to what 110 gives the app role, so the arm measures 110.
    sqlx::query("REVOKE ALL ON evidence_visibility_pins FROM epigraph_app")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("GRANT SELECT ON evidence_visibility_pins TO epigraph_app")
        .execute(&pool)
        .await
        .unwrap();

    let (ins, del, upd, seen) = fixture::as_role(&pool, "epigraph_app", |mut c| async move {
        let ins = try_exec(
            &mut c,
            "INSERT INTO evidence_visibility_pins (evidence_id, pinned_by, reason) \
             VALUES ($1, gen_random_uuid(), 'app')",
            other,
        )
        .await;
        let del = try_exec(
            &mut c,
            "DELETE FROM evidence_visibility_pins WHERE evidence_id = $1",
            fx.pinned,
        )
        .await;
        let upd = try_exec(
            &mut c,
            "UPDATE evidence_visibility_pins SET reason = 'app' WHERE evidence_id = $1",
            fx.pinned,
        )
        .await;
        let seen: i64 = sqlx::query_scalar("SELECT count(*) FROM evidence_visibility_pins")
            .fetch_one(&mut *c)
            .await
            .expect("app SELECT is granted and filtered, not refused");
        (c, (ins, del, upd, seen))
    })
    .await;
    assert!(ins.is_err(), "epigraph_app must not pin: {ins:?}");
    assert!(del.is_err(), "epigraph_app must not unpin: {del:?}");
    assert!(upd.is_err(), "epigraph_app must not edit a pin: {upd:?}");
    assert_eq!(seen, 0, "the SELECT policy admits no app session");
    let still: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM evidence_visibility_pins WHERE evidence_id = ANY($1)",
    )
    .bind(vec![fx.pinned, other])
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(still, 1, "the app attempts changed nothing");

    // A maintenance session (session_user a member of epigraph_maintenance,
    // which is what `epigraph_bypass()` reads) can pin and unpin.
    let (ins, del) = fixture::as_role(&pool, "epigraph_maintenance", |mut c| async move {
        let ins = try_exec(
            &mut c,
            "INSERT INTO evidence_visibility_pins (evidence_id, pinned_by, reason) \
             VALUES ($1, gen_random_uuid(), 'maintenance')",
            other,
        )
        .await;
        let del = try_exec(
            &mut c,
            "DELETE FROM evidence_visibility_pins WHERE evidence_id = $1",
            other,
        )
        .await;
        (c, (ins, del))
    })
    .await;
    assert_eq!(ins, Ok(1), "maintenance pins");
    assert_eq!(del, Ok(1), "maintenance unpins");
    let _ = fx.operator;
}

/// Deleting the claim deletes its evidence and, through the FK, the pin: no
/// orphan pin can outlive its row.
#[sqlx::test(migrations = "../../migrations")]
async fn a_pin_goes_with_its_evidence_row(pool: PgPool) {
    let fx = seed(&pool).await;
    sqlx::query("DELETE FROM evidence WHERE id = $1")
        .bind(fx.pinned)
        .execute(&pool)
        .await
        .expect("delete the hidden row");
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM evidence_visibility_pins")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(n, 0, "the pin cascades with its evidence row");
}
