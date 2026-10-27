//! Migration 184 (operator ruling R-79, backlog f8ec73b7): retract ONE mass
//! function (BBA). A retracted row is excluded from every fold and belief
//! read and kept for audit; only the BBA's owner (a writer of its owning
//! group) or a live `claims:admin` holder retracts it, through
//! `epigraph_retract_mass_function`, which writes one `security_events` row.
//!
//! # Why every arm runs as `epigraph_app`
//!
//! `#[sqlx::test]` connects as the superuser `epigraph`, which bypasses row
//! security, so "the owner may retract and a stranger may not" would hold
//! vacuously on the harness connection. Every retraction and every read below
//! runs as the non-bypassing `epigraph_app`, stamped exactly as
//! `ScopedPool::begin_as` stamps a request. Fixture rows that need no policy
//! (claims, frames, perspectives, an `oauth_clients` row) are written on the
//! harness connection.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::repos::mass_function::{
    BbaRetractArm, BbaRetractError, BbaRetractStatus, MassFunctionRepository,
};
use epigraph_db::visibility::Viewer;
use epigraph_db::AdminToken;
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

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

/// Stamp `conn` for `agent` exactly as `ScopedPool::begin_as` would, and
/// return the viewer the stamp came from.
async fn stamp(conn: &mut PgConnection, pool: &PgPool, agent: Uuid) -> Viewer {
    let v = Viewer::resolve(pool, agent).await.expect("resolve viewer");
    let groups = csv(v.group_bind().expect("scoped viewer"));
    let writable = csv(v.writable_groups());
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
    v
}

async fn seed_frame(pool: &PgPool, tag: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses) VALUES ($1, ARRAY['h0','h1']::text[]) RETURNING id",
    )
    .bind(format!("r79-{tag}-{}", Uuid::new_v4()))
    .fetch_one(pool)
    .await
    .expect("seed frame")
}

async fn seed_perspective(pool: &PgPool, owner: Uuid) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO perspectives (name, owner_agent_id) VALUES ($1, $2) RETURNING id",
    )
    .bind(format!("r79-perspective-{}", Uuid::new_v4()))
    .bind(owner)
    .fetch_one(pool)
    .await
    .expect("seed perspective")
}

/// A public claim owned by `group`.
async fn public_claim_owned_by(pool: &PgPool, agent: Uuid, group: Uuid, tag: &str) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, $2, $3, 0.5, $4, true, 'public', $5)",
    )
    .bind(id)
    .bind(format!("bba retract fixture {tag}"))
    .bind(&hash)
    .bind(agent)
    .bind(group)
    .execute(pool)
    .await
    .expect("seed a public claim owned by a group");
    id
}

/// Store `agent`'s BBA `{0: support, Θ: 1 - support}` on (claim, frame) on a
/// connection stamped for `agent`, through the repository upsert every BBA
/// writer goes through.
async fn store_bba(
    conn: &mut PgConnection,
    pool: &PgPool,
    agent: Uuid,
    claim: Uuid,
    frame: Uuid,
    perspective: Option<Uuid>,
    support: f64,
) -> Uuid {
    stamp(conn, pool, agent).await;
    let masses = serde_json::json!({"0": support, "0,1": 1.0 - support});
    MassFunctionRepository::store_with_perspective(
        &mut *conn,
        claim,
        frame,
        Some(agent),
        perspective,
        &masses,
        None,
        None,
        Some(1.0),
        None,
        "unknown",
        None,
    )
    .await
    .unwrap_or_else(|e| panic!("store {agent}'s BBA: {e}"))
}

/// `(retracted_at IS NOT NULL, retracted_by, retract_reason)` of one row, read
/// on the harness connection (the row is KEPT whatever its state).
async fn retract_columns(pool: &PgPool, id: Uuid) -> (bool, Option<Uuid>, Option<String>) {
    sqlx::query_as(
        "SELECT retracted_at IS NOT NULL, retracted_by, retract_reason \
           FROM mass_functions WHERE id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("read mass function {id}: {e}"))
}

/// The `mass_functions.retract` audit rows naming `id`.
async fn audit_rows(pool: &PgPool, id: Uuid) -> Vec<(Option<Uuid>, serde_json::Value)> {
    sqlx::query_as(
        "SELECT agent_id, details FROM security_events \
          WHERE event_type = 'mass_functions.retract' \
            AND details->>'mass_function_id' = $1::text \
          ORDER BY created_at",
    )
    .bind(id)
    .fetch_all(pool)
    .await
    .expect("read retract audit rows")
}

struct World {
    owner: Uuid,
    other: Uuid,
    other_group: Uuid,
    stranger: Uuid,
    claim: Uuid,
    /// The owner's BBA sits alone on `frame_a` under `perspective`.
    frame_a: Uuid,
    /// The other writer's (writer-owned, migration 114) BBA sits on `frame_b`.
    frame_b: Uuid,
    #[allow(dead_code)] // read by the reader arm added with the fold exclusion
    perspective: Uuid,
    owner_bba: Uuid,
    other_bba: Uuid,
}

async fn world(pool: &PgPool) -> World {
    assert_app_role_does_not_bypass(pool).await;
    let (owner, owner_group) = fixture::seed_agent_with_group(pool, "r79-owner").await;
    let (other, other_group) = fixture::seed_agent_with_group(pool, "r79-other").await;
    let (stranger, _) = fixture::seed_agent_with_group(pool, "r79-stranger").await;
    let claim = public_claim_owned_by(pool, owner, owner_group, "two writers").await;
    let frame_a = seed_frame(pool, "a").await;
    let frame_b = seed_frame(pool, "b").await;
    let perspective = seed_perspective(pool, owner).await;
    let p = pool.clone();
    let (owner_bba, other_bba) = fixture::as_role(pool, "epigraph_app", |mut conn| async move {
        let a = store_bba(&mut conn, &p, owner, claim, frame_a, Some(perspective), 0.9).await;
        let b = store_bba(&mut conn, &p, other, claim, frame_b, None, 0.3).await;
        (conn, (a, b))
    })
    .await;
    World {
        owner,
        other,
        other_group,
        stranger,
        claim,
        frame_a,
        frame_b,
        perspective,
        owner_bba,
        other_bba,
    }
}

/// The owner retracts its own BBA: the columns name the owner, ONE audit row
/// carries the row as it was, and a second retraction changes nothing and
/// writes no second audit row.
#[sqlx::test(migrations = "../../migrations")]
async fn the_owner_retracts_once_with_one_audit_row_and_a_re_retract_is_idempotent(pool: PgPool) {
    let w = world(&pool).await;
    // A stored scoped belief on each frame, as the evidence routes write them.
    for frame in [w.frame_a, w.frame_b] {
        sqlx::query(
            "INSERT INTO ds_combined_beliefs (frame_id, claim_id, scope_type, belief, plausibility) \
             VALUES ($1, $2, 'global', 0.9, 1.0)",
        )
        .bind(frame)
        .bind(w.claim)
        .execute(&pool)
        .await
        .expect("seed a stored scoped belief");
    }
    let p = pool.clone();
    let (owner, id) = (w.owner, w.owner_bba);
    let (first, second) = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, owner).await;
        let a = MassFunctionRepository::retract_conn(
            &mut conn,
            id,
            "  duplicate re-observation ",
            None,
        )
        .await;
        let b = MassFunctionRepository::retract_conn(&mut conn, id, "a second reason", None).await;
        (conn, (a, b))
    })
    .await;
    let first = first.expect("the owner retracts its own BBA");
    assert_eq!(first.status, BbaRetractStatus::Retracted);
    assert_eq!(first.arm, BbaRetractArm::Owner);
    assert_eq!(first.mass_function_id, w.owner_bba);
    assert_eq!(first.claim_id, w.claim);
    assert_eq!(first.frame_id, w.frame_a);
    assert_eq!(first.retracted_by, w.owner);
    assert_eq!(
        first.retract_reason, "duplicate re-observation",
        "the reason is trimmed"
    );
    assert_eq!(
        first.scoped_beliefs_cleared, 1,
        "the retracted row's frame loses its stale stored scoped belief"
    );
    let stored: Vec<Uuid> = sqlx::query_scalar(
        "SELECT frame_id FROM ds_combined_beliefs WHERE claim_id = $1 ORDER BY frame_id",
    )
    .bind(w.claim)
    .fetch_all(&pool)
    .await
    .expect("read stored scoped beliefs");
    assert_eq!(
        stored,
        vec![w.frame_b],
        "only the retracted row's (claim, frame) is cleared"
    );

    let second = second.expect("a re-retraction is not an error");
    assert_eq!(second.status, BbaRetractStatus::AlreadyRetracted);
    assert_eq!(
        (second.retracted_at, second.retract_reason.as_str()),
        (first.retracted_at, "duplicate re-observation"),
        "a re-retraction keeps the first retraction's columns"
    );

    assert_eq!(
        retract_columns(&pool, w.owner_bba).await,
        (
            true,
            Some(w.owner),
            Some("duplicate re-observation".to_string())
        )
    );
    let audit = audit_rows(&pool, w.owner_bba).await;
    assert_eq!(audit.len(), 1, "exactly one audit row: {audit:#?}");
    let (agent, details) = &audit[0];
    assert_eq!(*agent, Some(w.owner), "the audit row names the retractor");
    assert_eq!(details["arm"], "owner");
    assert_eq!(details["reason"], "duplicate re-observation");
    assert_eq!(details["claim_id"], w.claim.to_string());
    assert_eq!(
        details["before"]["id"],
        w.owner_bba.to_string(),
        "the audit row snapshots the row as it was"
    );
    assert!(
        details["before"]["retracted_at"].is_null(),
        "the snapshot is the LIVE row, before the retraction"
    );
    assert_eq!(details["before"]["masses"]["0"], 0.9);
}

/// Who may NOT retract, and how they are told:
/// * a stranger that can READ a public BBA but not write its group: refused
///   (Forbidden, the 403 class), nothing written;
/// * the claim's owner on another writer's writer-owned BBA: refused the same
///   way (the BBA's owner is the writer's group, not the claim's);
/// * a stranger on a group-PRIVATE BBA it cannot read: NotFound, the SAME
///   answer a random id gets (no existence oracle).
#[sqlx::test(migrations = "../../migrations")]
async fn a_non_owner_is_refused_and_an_unreadable_bba_is_not_found(pool: PgPool) {
    let w = world(&pool).await;
    // A group-private claim of the OTHER writer, with its own BBA.
    let private_claim =
        fixture::seed_group_claim(&pool, w.other, w.other_group, "r79 private").await;
    let p = pool.clone();
    let (other, stranger, owner, claim, frame_b) =
        (w.other, w.stranger, w.owner, w.claim, w.frame_b);
    let (owner_bba, other_bba) = (w.owner_bba, w.other_bba);
    let (private_bba, by_stranger, owner_on_other, hidden, random) =
        fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
            let private_bba =
                store_bba(&mut conn, &p, other, private_claim, frame_b, None, 0.7).await;
            stamp(&mut conn, &p, stranger).await;
            let a =
                MassFunctionRepository::retract_conn(&mut conn, owner_bba, "not mine", None).await;
            let c =
                MassFunctionRepository::retract_conn(&mut conn, private_bba, "hidden", None).await;
            let d = MassFunctionRepository::retract_conn(&mut conn, Uuid::new_v4(), "random", None)
                .await;
            stamp(&mut conn, &p, owner).await;
            let b = MassFunctionRepository::retract_conn(&mut conn, other_bba, "on my claim", None)
                .await;
            let _ = claim;
            (conn, (private_bba, a, b, c, d))
        })
        .await;
    assert!(
        matches!(by_stranger, Err(BbaRetractError::Forbidden(_))),
        "a reader that does not write the BBA's group is refused: {by_stranger:?}"
    );
    assert!(
        matches!(owner_on_other, Err(BbaRetractError::Forbidden(_))),
        "the claim's owner does not own another writer's BBA: {owner_on_other:?}"
    );
    assert!(
        matches!(hidden, Err(BbaRetractError::NotFound(id)) if id == private_bba),
        "an unreadable BBA is not found: {hidden:?}"
    );
    assert!(
        matches!(random, Err(BbaRetractError::NotFound(_))),
        "a random id is not found: {random:?}"
    );
    for id in [w.owner_bba, w.other_bba, private_bba] {
        assert_eq!(
            retract_columns(&pool, id).await,
            (false, None, None),
            "nothing written on {id}"
        );
        assert!(
            audit_rows(&pool, id).await.is_empty(),
            "no audit row for {id}"
        );
    }
}

/// The admin arm: a stranger whose token's client holds a LIVE `claims:admin`
/// grant retracts another writer's BBA, and the audit row records the admin
/// arm and its client; the same stranger presenting a SUSPENDED client is
/// refused.
#[sqlx::test(migrations = "../../migrations")]
async fn a_live_claims_admin_retracts_and_a_suspended_one_is_refused(pool: PgPool) {
    let w = world(&pool).await;
    let mut clients = Vec::new();
    for status in ["active", "suspended"] {
        let client = Uuid::new_v4();
        let scopes = vec!["claims:write".to_string(), "claims:admin".to_string()];
        sqlx::query(
            "INSERT INTO oauth_clients (id, client_id, client_name, client_type, allowed_scopes, \
                                        granted_scopes, status, agent_id) \
             VALUES ($1, $2, 'r79 admin client', 'human', $3, $3, $4, $5)",
        )
        .bind(client)
        .bind(format!("r79-admin-{client}"))
        .bind(&scopes)
        .bind(status)
        .bind(w.stranger)
        .execute(&pool)
        .await
        .expect("seed the admin's oauth client");
        clients.push(client);
    }
    let (live, suspended) = (clients[0], clients[1]);
    let jti = Uuid::new_v4();
    let p = pool.clone();
    let (stranger, owner_bba, other_bba) = (w.stranger, w.owner_bba, w.other_bba);
    let (refused, admitted) = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, stranger).await;
        let r = MassFunctionRepository::retract_conn(
            &mut conn,
            owner_bba,
            "suspended admin",
            Some(AdminToken {
                client_id: suspended,
                jti,
            }),
        )
        .await;
        let a = MassFunctionRepository::retract_conn(
            &mut conn,
            other_bba,
            "promotion duplicate",
            Some(AdminToken {
                client_id: live,
                jti,
            }),
        )
        .await;
        (conn, (r, a))
    })
    .await;
    assert!(
        matches!(refused, Err(BbaRetractError::Forbidden(_))),
        "a suspended admin client is refused: {refused:?}"
    );
    assert_eq!(
        retract_columns(&pool, w.owner_bba).await,
        (false, None, None)
    );
    let admitted = admitted.expect("a live claims:admin grant retracts another writer's BBA");
    assert_eq!(admitted.arm, BbaRetractArm::Admin);
    assert_eq!(
        admitted.retracted_by, w.stranger,
        "the ADMIN is the retractor"
    );
    let audit = audit_rows(&pool, w.other_bba).await;
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].0, Some(w.stranger));
    assert_eq!(audit[0].1["arm"], "admin");
    assert_eq!(audit[0].1["admin_client_id"], live.to_string());
    assert_eq!(audit[0].1["admin_token_jti"], jti.to_string());
}

/// The reason is required (blank after trimming is refused, nothing written),
/// and an application session cannot mark a row retracted by a direct UPDATE,
/// even its own: only the definer records a retraction, with its audit row.
#[sqlx::test(migrations = "../../migrations")]
async fn a_blank_reason_and_a_direct_update_are_refused(pool: PgPool) {
    let w = world(&pool).await;
    let p = pool.clone();
    let (owner, id) = (w.owner, w.owner_bba);
    let (blank, direct) = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, owner).await;
        let b = MassFunctionRepository::retract_conn(&mut conn, id, "   ", None).await;
        let d = sqlx::query(
            "UPDATE mass_functions SET retracted_at = now(), retracted_by = $2, \
                    retract_reason = 'no audit' WHERE id = $1",
        )
        .bind(id)
        .bind(owner)
        .execute(&mut *conn)
        .await;
        (conn, (b, d))
    })
    .await;
    assert!(
        matches!(blank, Err(BbaRetractError::InvalidReason(_))),
        "a blank reason is refused: {blank:?}"
    );
    let direct = direct.expect_err("a direct UPDATE of the retract columns is refused");
    assert_eq!(
        direct.as_database_error().and_then(|e| e.code()).as_deref(),
        Some("42501"),
        "refused as a privilege error: {direct}"
    );
    assert_eq!(
        retract_columns(&pool, w.owner_bba).await,
        (false, None, None)
    );
    assert!(audit_rows(&pool, w.owner_bba).await.is_empty());
}
