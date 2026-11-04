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

use epigraph_db::repos::atom_axiom::atom_input_rows;
use epigraph_db::repos::compound_valuation::compound_own_rows;
use epigraph_db::repos::mass_function::{
    BbaRetractArm, BbaRetractError, BbaRetractStatus, BbaUnretractStatus, MassFunctionRepository,
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

/// Mark `id` retracted on the harness (superuser) connection, independently
/// of the definer, so the reader arm tests the readers alone.
async fn mark_retracted_directly(pool: &PgPool, id: Uuid, by: Uuid) {
    sqlx::query(
        "UPDATE mass_functions \
            SET retracted_at = now(), retracted_by = $2, retract_reason = 'fixture' \
          WHERE id = $1",
    )
    .bind(id)
    .bind(by)
    .execute(pool)
    .await
    .expect("mark retracted on the harness connection");
}

/// A community whose members are `perspectives`, on the harness connection.
async fn seed_community(pool: &PgPool, perspectives: &[Uuid]) -> Uuid {
    let id: Uuid = sqlx::query_scalar("INSERT INTO communities (name) VALUES ($1) RETURNING id")
        .bind(format!("r79-community-{}", Uuid::new_v4()))
        .fetch_one(pool)
        .await
        .expect("seed community");
    for p in perspectives {
        sqlx::query("INSERT INTO community_members (community_id, perspective_id) VALUES ($1, $2)")
            .bind(id)
            .bind(p)
            .execute(pool)
            .await
            .expect("seed community member");
    }
    id
}

/// One stored scoped belief of (claim, frame), as the evidence routes write
/// them, on the harness connection.
async fn seed_scoped_belief(
    pool: &PgPool,
    claim: Uuid,
    frame: Uuid,
    scope_type: &str,
    scope_id: Option<Uuid>,
    strategy: Option<&str>,
) {
    sqlx::query(
        "INSERT INTO ds_combined_beliefs \
                (frame_id, claim_id, scope_type, scope_id, belief, plausibility, strategy_used) \
         VALUES ($1, $2, $3, $4, 0.9, 1.0, $5)",
    )
    .bind(frame)
    .bind(claim)
    .bind(scope_type)
    .bind(scope_id)
    .bind(strategy)
    .execute(pool)
    .await
    .expect("seed a stored scoped belief");
}

/// `(frame, scope_type, scope_id)` of every stored scoped belief of `claim`,
/// sorted.
async fn stored_scopes(pool: &PgPool, claim: Uuid) -> Vec<(Uuid, String, Option<Uuid>)> {
    let mut rows: Vec<(Uuid, String, Option<Uuid>)> = sqlx::query_as(
        "SELECT frame_id, scope_type, scope_id FROM ds_combined_beliefs WHERE claim_id = $1",
    )
    .bind(claim)
    .fetch_all(pool)
    .await
    .expect("read stored scoped beliefs");
    rows.sort();
    rows
}

/// The `mass_functions.unretract` audit rows naming `id`.
async fn unretract_rows(pool: &PgPool, id: Uuid) -> Vec<(Option<Uuid>, serde_json::Value)> {
    sqlx::query_as(
        "SELECT agent_id, details FROM security_events \
          WHERE event_type = 'mass_functions.unretract' \
            AND details->>'mass_function_id' = $1::text \
          ORDER BY created_at",
    )
    .bind(id)
    .fetch_all(pool)
    .await
    .expect("read unretract audit rows")
}

/// The message of a refused statement, or a panic naming what was expected.
fn db_message<T: std::fmt::Debug>(r: Result<T, sqlx::Error>, what: &str) -> (String, String) {
    let e = r.expect_err(what);
    let d = e
        .as_database_error()
        .unwrap_or_else(|| panic!("{what}: not a database error: {e}"));
    (
        d.code().map(|c| c.to_string()).unwrap_or_default(),
        d.message().to_string(),
    )
}

/// An `oauth_clients` row bound to `agent` with `scopes` granted and `status`.
async fn seed_client(pool: &PgPool, agent: Uuid, scopes: &[&str], status: &str) -> Uuid {
    let client = Uuid::new_v4();
    let scopes: Vec<String> = scopes.iter().map(|s| (*s).to_string()).collect();
    sqlx::query(
        "INSERT INTO oauth_clients (id, client_id, client_name, client_type, allowed_scopes, \
                                    granted_scopes, status, agent_id) \
         VALUES ($1, $2, 'r79 admin client', 'human', $3, $3, $4, $5)",
    )
    .bind(client)
    .bind(format!("r79-admin-{client}"))
    .bind(&scopes)
    .bind(status)
    .bind(agent)
    .execute(pool)
    .await
    .expect("seed an oauth client");
    client
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

/// Every repository reader that folds or counts a claim's BBAs, as the
/// owner's stamped app session sees them: the ids each returns for the
/// world's claim.
#[derive(Debug, PartialEq)]
struct ReaderView {
    for_claim_frame_a: Vec<Uuid>,
    for_claim: Vec<Uuid>,
    for_claims: Vec<Uuid>,
    binary_frames: Vec<Uuid>,
    frame_perspective: Vec<Uuid>,
    frame_perspectives: Vec<Uuid>,
    all_for_frame_a: Vec<Uuid>,
    count_for_claim: i64,
    count_for_claim_frame_a: i64,
    derived_count: i64,
    frames: Vec<Uuid>,
    cache_owner: Option<Uuid>,
    atom_inputs: Vec<Uuid>,
    compound_own: Vec<Uuid>,
}

async fn readers(pool: &PgPool, w: &World) -> ReaderView {
    let p = pool.clone();
    let (owner, claim, frame_a, perspective) = (w.owner, w.claim, w.frame_a, w.perspective);
    fixture::as_role(pool, "epigraph_app", |mut conn| async move {
        let v = stamp(&mut conn, &p, owner).await;
        let ids = |rows: Vec<epigraph_db::MassFunctionRow>| {
            let mut v: Vec<Uuid> = rows.into_iter().map(|r| r.id).collect();
            v.sort();
            v
        };
        let r = MassFunctionRepository::get_for_claim_frame(&mut *conn, &v, claim, frame_a)
            .await
            .expect("get_for_claim_frame");
        let for_claim_frame_a = ids(r);
        let for_claim = ids(MassFunctionRepository::get_for_claim(&mut *conn, &v, claim)
            .await
            .expect("get_for_claim"));
        let for_claims = ids(
            MassFunctionRepository::get_for_claims(&mut *conn, &v, &[claim])
                .await
                .expect("get_for_claims"),
        );
        let binary_frames = ids(MassFunctionRepository::get_for_claim_binary_frames(
            &mut *conn, &v, claim,
        )
        .await
        .expect("get_for_claim_binary_frames"));
        let frame_perspective = ids(MassFunctionRepository::get_for_claim_frame_perspective(
            &mut *conn,
            &v,
            claim,
            frame_a,
            perspective,
        )
        .await
        .expect("get_for_claim_frame_perspective"));
        let frame_perspectives = ids(MassFunctionRepository::get_for_claim_frame_perspectives(
            &mut *conn,
            &v,
            claim,
            frame_a,
            &[perspective],
        )
        .await
        .expect("get_for_claim_frame_perspectives"));
        let all_for_frame_a = ids(MassFunctionRepository::get_all_for_frame(
            &mut *conn, &v, frame_a,
        )
        .await
        .expect("get_all_for_frame"));
        let count_for_claim = MassFunctionRepository::count_for_claim(&mut *conn, &v, claim)
            .await
            .expect("count_for_claim");
        let count_for_claim_frame_a =
            MassFunctionRepository::count_for_claim_frame(&mut *conn, &v, claim, frame_a)
                .await
                .expect("count_for_claim_frame");
        let derived_count =
            epigraph_db::repos::derivation_scope::DerivationScopeRepository::count_viewer_derived_for_claim(
                &mut *conn, &v, claim,
            )
            .await
            .expect("count_viewer_derived_for_claim");
        let mut frames: Vec<Uuid> =
            MassFunctionRepository::list_frames_for_claim(&mut *conn, &v, claim)
                .await
                .expect("list_frames_for_claim")
                .into_iter()
                .map(|(f, _)| f)
                .collect();
        frames.sort();
        let cache_owner =
            MassFunctionRepository::cache_owner_frame_for_claim(&mut *conn, &v, claim)
                .await
                .expect("cache_owner_frame_for_claim");
        let mut atom_inputs: Vec<Uuid> = atom_input_rows(&mut *conn, &v, &[claim], Uuid::nil())
            .await
            .expect("atom_input_rows")
            .into_iter()
            .map(|r| r.row.id)
            .collect();
        atom_inputs.sort();
        let mut compound_own: Vec<Uuid> = compound_own_rows(&mut *conn, &v, &[claim], Uuid::nil())
            .await
            .expect("compound_own_rows")
            .into_iter()
            .map(|r| r.input.row.id)
            .collect();
        compound_own.sort();
        (
            conn,
            ReaderView {
                for_claim_frame_a,
                for_claim,
                for_claims,
                binary_frames,
                frame_perspective,
                frame_perspectives,
                all_for_frame_a,
                count_for_claim,
                count_for_claim_frame_a,
                derived_count,
                frames,
                cache_owner,
                atom_inputs,
                compound_own,
            },
        )
    })
    .await
}

fn sorted(mut v: Vec<Uuid>) -> Vec<Uuid> {
    v.sort();
    v
}

/// R-79's core: a retracted BBA leaves EVERY fold and belief reader, and the
/// row itself stays. Measured against the same readers before the
/// retraction, so the "after" assertions cannot pass on a reader that never
/// returned the row.
#[sqlx::test(migrations = "../../migrations")]
async fn a_retracted_bba_leaves_every_fold_reader_and_stays_stored(pool: PgPool) {
    let w = world(&pool).await;
    let before = readers(&pool, &w).await;
    let both = sorted(vec![w.owner_bba, w.other_bba]);
    assert_eq!(before.for_claim_frame_a, vec![w.owner_bba], "calibration");
    assert_eq!(before.for_claim, both, "calibration");
    assert_eq!(before.count_for_claim, 2, "calibration");
    assert_eq!(before.derived_count, 2, "calibration");
    assert_eq!(
        before.cache_owner,
        Some(w.frame_a),
        "calibration: the earliest input's frame owns the cache before the retraction"
    );
    assert_eq!(
        before.atom_inputs, both,
        "calibration: the atom fold reads both rows"
    );

    mark_retracted_directly(&pool, w.owner_bba, w.owner).await;
    let after = readers(&pool, &w).await;
    assert_eq!(
        after,
        ReaderView {
            for_claim_frame_a: vec![],
            for_claim: vec![w.other_bba],
            for_claims: vec![w.other_bba],
            binary_frames: vec![w.other_bba],
            frame_perspective: vec![],
            frame_perspectives: vec![],
            all_for_frame_a: vec![],
            count_for_claim: 1,
            count_for_claim_frame_a: 0,
            derived_count: 1,
            frames: vec![w.frame_b],
            cache_owner: Some(w.frame_b),
            atom_inputs: vec![w.other_bba],
            compound_own: vec![w.other_bba],
        },
        "a retracted BBA must leave every fold, count and cache-owner read"
    );
    assert_eq!(
        retract_columns(&pool, w.owner_bba).await,
        (true, Some(w.owner), Some("fixture".to_string())),
        "the retracted row is kept, with its retract columns, for audit"
    );
}

/// The owner retracts its own BBA: the columns name the owner, ONE audit row
/// carries the row as it was, and a second retraction changes nothing and
/// writes no second audit row.
#[sqlx::test(migrations = "../../migrations")]
async fn the_owner_retracts_once_with_one_audit_row_and_a_re_retract_is_idempotent(pool: PgPool) {
    let w = world(&pool).await;
    // Stored scoped beliefs, as the evidence routes write them. The retracted
    // row (frame_a, under `w.perspective`) was folded by exactly three of
    // them: frame_a's global scope, its own perspective scope, and a
    // community that counts its perspective. The others never included it.
    let other_perspective = seed_perspective(&pool, w.owner).await;
    let community_in = seed_community(&pool, &[w.perspective]).await;
    let community_out = seed_community(&pool, &[other_perspective]).await;
    let community_override = seed_community(&pool, &[w.perspective]).await;
    let folded_it = [
        (w.frame_a, "global", None),
        (w.frame_a, "perspective", Some(w.perspective)),
        (w.frame_a, "community", Some(community_in)),
    ];
    let never_folded_it = [
        (w.frame_b, "global", None),
        (w.frame_a, "perspective", Some(other_perspective)),
        (w.frame_a, "community", Some(community_out)),
    ];
    for (frame, scope, scope_id) in folded_it.iter().chain(never_folded_it.iter()) {
        seed_scoped_belief(&pool, w.claim, *frame, scope, *scope_id, None).await;
    }
    // A community's mass override is the community's own assessment, not a
    // fold of its members' BBAs: it stays.
    seed_scoped_belief(
        &pool,
        w.claim,
        w.frame_a,
        "community",
        Some(community_override),
        Some("override"),
    )
    .await;
    let p = pool.clone();
    let (owner, id, claim, frame_a) = (w.owner, w.owner_bba, w.claim, w.frame_a);
    let (first, second) = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, owner).await;
        let a = MassFunctionRepository::retract_conn(
            &mut conn,
            id,
            "  duplicate re-observation ",
            None,
        )
        .await;
        // A fresh stored fold written after the retraction (the next
        // evidence write stores one): a repeat must not touch it.
        seed_scoped_belief(&p, claim, frame_a, "global", None, None).await;
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
        first.scoped_beliefs_cleared, 3,
        "exactly the three stored folds that included the retracted row are cleared"
    );
    let mut expected: Vec<(Uuid, String, Option<Uuid>)> = never_folded_it
        .iter()
        .map(|(f, s, id)| (*f, (*s).to_string(), *id))
        .collect();
    expected.push((w.frame_a, "community".to_string(), Some(community_override)));
    expected.push((w.frame_a, "global".to_string(), None));
    expected.sort();
    assert_eq!(
        stored_scopes(&pool, w.claim).await,
        expected,
        "the scopes that never folded the row, the override, and the fold written after \
         the retraction all survive"
    );

    let second = second.expect("a re-retraction is not an error");
    assert_eq!(second.status, BbaRetractStatus::AlreadyRetracted);
    assert_eq!(
        second.scoped_beliefs_cleared, 0,
        "a repeat deletes no stored belief"
    );
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
/// arm and its client. Each conjunct of the grant re-check refuses on its
/// own, with nothing written: a SUSPENDED client, an active admin client
/// bound to ANOTHER agent (a session may not present someone else's grant),
/// and the caller's own active client whose granted scopes lack
/// `claims:admin` (a token scope the client record no longer backs).
#[sqlx::test(migrations = "../../migrations")]
async fn a_live_claims_admin_retracts_and_each_failed_grant_check_is_refused(pool: PgPool) {
    let w = world(&pool).await;
    let admin_scopes = ["claims:write", "claims:admin"];
    let live = seed_client(&pool, w.stranger, &admin_scopes, "active").await;
    let suspended = seed_client(&pool, w.stranger, &admin_scopes, "suspended").await;
    let foreign = seed_client(&pool, w.other, &admin_scopes, "active").await;
    let ungranted = seed_client(&pool, w.stranger, &["claims:write"], "active").await;
    let jti = Uuid::new_v4();
    let p = pool.clone();
    let (stranger, owner_bba, other_bba) = (w.stranger, w.owner_bba, w.other_bba);
    let (refused, admitted) = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, stranger).await;
        let mut refused = Vec::new();
        for (label, client) in [
            ("suspended", suspended),
            ("bound to another agent", foreign),
            ("without the claims:admin grant", ungranted),
        ] {
            let r = MassFunctionRepository::retract_conn(
                &mut conn,
                owner_bba,
                label,
                Some(AdminToken {
                    client_id: client,
                    jti,
                }),
            )
            .await;
            refused.push((label, r));
        }
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
        (conn, (refused, a))
    })
    .await;
    for (label, r) in &refused {
        assert!(
            matches!(r, Err(BbaRetractError::Forbidden(_))),
            "an admin client {label} is refused: {r:?}"
        );
    }
    assert_eq!(
        retract_columns(&pool, w.owner_bba).await,
        (false, None, None),
        "no refused admin call wrote anything"
    );
    assert!(audit_rows(&pool, w.owner_bba).await.is_empty());
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

/// The reason is required: blank after trimming, or longer than 2000
/// characters, is refused with nothing written. An application session cannot
/// mark a row retracted by a direct UPDATE either, even its own: only the
/// definer records a retraction, with its audit row, and the guard says so
/// (RT06, not a row-security failure).
#[sqlx::test(migrations = "../../migrations")]
async fn a_bad_reason_and_a_direct_update_are_refused(pool: PgPool) {
    let w = world(&pool).await;
    let p = pool.clone();
    let (owner, id) = (w.owner, w.owner_bba);
    let long = "x".repeat(2001);
    let longest = "y".repeat(2000);
    let (blank, too_long, direct, at_limit) =
        fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
            stamp(&mut conn, &p, owner).await;
            let b = MassFunctionRepository::retract_conn(&mut conn, id, "   ", None).await;
            let l = MassFunctionRepository::retract_conn(&mut conn, id, &long, None).await;
            let d = sqlx::query(
                "UPDATE mass_functions SET retracted_at = now(), retracted_by = $2, \
                        retract_reason = 'no audit' WHERE id = $1",
            )
            .bind(id)
            .bind(owner)
            .execute(&mut *conn)
            .await;
            // Calibration last: a 2000-character reason is admitted, so the
            // 2001 refusal is the bound and not the call's shape.
            let ok = MassFunctionRepository::retract_conn(&mut conn, id, &longest, None).await;
            (conn, (b, l, d, ok))
        })
        .await;
    assert!(
        matches!(blank, Err(BbaRetractError::InvalidReason(_))),
        "a blank reason is refused: {blank:?}"
    );
    assert!(
        matches!(too_long, Err(BbaRetractError::InvalidReason(_))),
        "a 2001-character reason is refused: {too_long:?}"
    );
    let (code, message) = db_message(direct, "a direct UPDATE of the retract columns is refused");
    assert_eq!(code, "42501", "refused as a privilege error: {message}");
    assert!(
        message.contains("RT06"),
        "refused by the retract guard, not by row security: {message}"
    );
    let at_limit = at_limit.expect("CALIBRATION: a 2000-character reason is admitted");
    assert_eq!(at_limit.status, BbaRetractStatus::Retracted);
    let audit = audit_rows(&pool, w.owner_bba).await;
    assert_eq!(
        audit.len(),
        1,
        "only the admitted call wrote an audit row: {audit:#?}"
    );
    assert_eq!(audit[0].1["reason"], "y".repeat(2000));
}

/// The refusals that come before any row is read. A session with no
/// principal has nobody to record as the retractor (RT01). And authority is
/// decided before state: a stranger retracting a public row the owner has
/// ALREADY retracted is refused, not told `already_retracted`, so a caller
/// that may not retract a row learns nothing of its state. Nothing is written
/// by either.
#[sqlx::test(migrations = "../../migrations")]
async fn no_principal_is_refused_and_a_stranger_learns_nothing_of_a_retracted_row(pool: PgPool) {
    let w = world(&pool).await;
    let p = pool.clone();
    let (owner, stranger, id) = (w.owner, w.stranger, w.owner_bba);
    let (unstamped, owners, strangers) =
        fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
            sqlx::query(
                "SELECT set_config('epigraph.group_ids', '', false), \
                        set_config('epigraph.writable_group_ids', '', false), \
                        set_config('epigraph.principal_id', '', false)",
            )
            .execute(&mut *conn)
            .await
            .expect("unstamp");
            let u = sqlx::query_scalar::<_, serde_json::Value>(
                "SELECT public.epigraph_retract_mass_function($1, 'no principal', NULL, NULL)",
            )
            .bind(id)
            .fetch_one(&mut *conn)
            .await;
            stamp(&mut conn, &p, owner).await;
            let o = MassFunctionRepository::retract_conn(&mut conn, id, "owner first", None).await;
            stamp(&mut conn, &p, stranger).await;
            let s =
                MassFunctionRepository::retract_conn(&mut conn, id, "stranger second", None).await;
            (conn, (u, o, s))
        })
        .await;
    let (code, message) = db_message(unstamped, "an unstamped session retracts nothing");
    assert_eq!(code, "42501", "{message}");
    assert!(message.contains("RT01"), "no principal: {message}");
    let owners = owners.expect("the owner retracts its BBA");
    assert!(
        matches!(strangers, Err(BbaRetractError::Forbidden(_))),
        "a stranger on an already-retracted row is refused, not answered \
         already_retracted: {strangers:?}"
    );
    assert_eq!(
        retract_columns(&pool, w.owner_bba).await,
        (true, Some(w.owner), Some("owner first".to_string())),
        "the owner's retraction stands as it was"
    );
    let audit = audit_rows(&pool, w.owner_bba).await;
    assert_eq!(audit.len(), 1, "only the owner's call wrote: {audit:#?}");
    assert_eq!(audit[0].0, Some(owners.retracted_by));
}

/// `(masses, created_at)` of one row, read on the harness connection.
async fn assessment_of(
    pool: &PgPool,
    id: Uuid,
) -> (serde_json::Value, chrono::DateTime<chrono::Utc>) {
    sqlx::query_as("SELECT masses, created_at FROM mass_functions WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap_or_else(|e| panic!("read mass function {id}: {e}"))
}

/// Operator ruling R-103: a retracted row HOLDS its upsert key. A later write
/// to that key, here the owner resubmitting through the repository upsert
/// every BBA writer goes through, is REFUSED (RT07, a state refusal the
/// transports answer 409 / a tool error) and changes nothing: the row stays
/// retracted with the retracted masses and `created_at`, no fold reads it,
/// and no un-retraction is recorded. The same write on the harness
/// connection, which passes every session bypass (`epigraph_bypass()`, as a
/// backfill on the maintenance connection does), is refused the same way:
/// the refusal has no bypass.
#[sqlx::test(migrations = "../../migrations")]
async fn a_write_to_a_retracted_key_is_refused_and_changes_nothing(pool: PgPool) {
    let w = world(&pool).await;
    let p = pool.clone();
    let (owner, claim, frame_a, perspective, id) =
        (w.owner, w.claim, w.frame_a, w.perspective, w.owner_bba);
    let resubmit = |support: f64| serde_json::json!({"0": support, "0,1": 1.0 - support});
    let r1 = resubmit(0.4);
    let (retracted, rewrite, live) =
        fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
            stamp(&mut conn, &p, owner).await;
            let r = MassFunctionRepository::retract_conn(&mut conn, id, "superseded", None).await;
            stamp(&mut conn, &p, owner).await;
            let again = MassFunctionRepository::store_with_perspective(
                &mut *conn,
                claim,
                frame_a,
                Some(owner),
                Some(perspective),
                &r1,
                None,
                None,
                Some(1.0),
                None,
                "unknown",
                None,
            )
            .await;
            let v = stamp(&mut conn, &p, owner).await;
            let live: Vec<Uuid> =
                MassFunctionRepository::get_for_claim_frame(&mut *conn, &v, claim, frame_a)
                    .await
                    .expect("get_for_claim_frame")
                    .into_iter()
                    .map(|r| r.id)
                    .collect();
            (conn, (r, again, live))
        })
        .await;
    retracted.expect("the owner retracts its BBA");
    let before = assessment_of(&pool, id).await;
    match rewrite {
        Err(epigraph_db::DbError::Refused {
            kind: epigraph_db::RefusalKind::State,
            message,
        }) => {
            assert!(message.starts_with("RT07: "), "coded RT07: {message}");
            assert!(
                message.contains(&id.to_string()),
                "names the retracted row: {message}"
            );
        }
        other => panic!("a write to a retracted key must be refused RT07 (state): {other:?}"),
    }
    assert_eq!(
        retract_columns(&pool, id).await,
        (true, Some(owner), Some("superseded".to_string())),
        "the retraction stands"
    );
    assert_eq!(before.0["0"], 0.9, "the retracted masses are untouched");
    assert!(live.is_empty(), "no fold reads the row: {live:?}");
    assert!(
        unretract_rows(&pool, id).await.is_empty(),
        "nothing un-retracted"
    );

    // The harness connection passes every session bypass; the refusal holds.
    let privileged = MassFunctionRepository::store_with_perspective(
        &pool,
        claim,
        frame_a,
        Some(owner),
        Some(perspective),
        &resubmit(0.2),
        None,
        Some("backfill"),
        Some(1.0),
        None,
        "unknown",
        None,
    )
    .await;
    assert!(
        matches!(
            &privileged,
            Err(epigraph_db::DbError::Refused { message, .. }) if message.starts_with("RT07: ")
        ),
        "a privileged write to a retracted key is refused too: {privileged:?}"
    );
    assert_eq!(
        assessment_of(&pool, id).await,
        before,
        "neither write changed the masses or created_at"
    );
    assert_eq!(
        retract_columns(&pool, id).await,
        (true, Some(owner), Some("superseded".to_string()))
    );
    let rows_at_key: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM mass_functions \
          WHERE claim_id = $1 AND frame_id = $2 AND source_agent_id = $3 AND perspective_id = $4",
    )
    .bind(claim)
    .bind(frame_a)
    .bind(owner)
    .bind(perspective)
    .fetch_one(&pool)
    .await
    .expect("count rows at the key");
    assert_eq!(rows_at_key, 1, "no second row beside the retracted one");
}

/// R-79's motivating case is an ADMIN retracting somebody else's BBA, so the
/// row's owner (which 077 lets UPDATE its own row) must not be able to undo
/// or overwrite that. A bare clear (the three columns NULLed, nothing else
/// changed) is refused (RT06). A clear that comes with a new assessment (here
/// a new `created_at`, as the upsert stamps one) is refused too (ruling R-103:
/// RT07, which fires first). The admin's retraction stands, untouched, and
/// no un-retraction is recorded.
#[sqlx::test(migrations = "../../migrations")]
async fn an_owner_can_neither_clear_nor_overwrite_an_admin_retraction(pool: PgPool) {
    let w = world(&pool).await;
    let live = seed_client(
        &pool,
        w.stranger,
        &["claims:write", "claims:admin"],
        "active",
    )
    .await;
    let p = pool.clone();
    let (owner, stranger, id) = (w.owner, w.stranger, w.owner_bba);
    let (admin, bare, reassessed) =
        fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
            stamp(&mut conn, &p, stranger).await;
            let a = MassFunctionRepository::retract_conn(
                &mut conn,
                id,
                "duplicate re-observation",
                Some(AdminToken {
                    client_id: live,
                    jti: Uuid::new_v4(),
                }),
            )
            .await;
            stamp(&mut conn, &p, owner).await;
            let b = sqlx::query(
                "UPDATE mass_functions \
                    SET retracted_at = NULL, retracted_by = NULL, retract_reason = NULL \
                  WHERE id = $1",
            )
            .bind(id)
            .execute(&mut *conn)
            .await;
            let r = sqlx::query(
                "UPDATE mass_functions \
                    SET retracted_at = NULL, retracted_by = NULL, retract_reason = NULL, \
                        created_at = clock_timestamp() \
                  WHERE id = $1",
            )
            .bind(id)
            .execute(&mut *conn)
            .await;
            (conn, (a, b, r))
        })
        .await;
    let admin = admin.expect("the admin retracts the owner's BBA");
    assert_eq!(admin.arm, BbaRetractArm::Admin);
    let (code, message) = db_message(bare, "a bare clear of an admin retraction is refused");
    assert_eq!(code, "42501", "{message}");
    assert!(message.contains("RT06"), "refused by the guard: {message}");
    let (code, message) = db_message(
        reassessed,
        "a clear that comes with a new assessment is refused (R-103)",
    );
    assert_eq!(code, "42501", "{message}");
    assert!(
        message.starts_with("RT07: "),
        "refused as a re-write: {message}"
    );
    assert!(
        unretract_rows(&pool, w.owner_bba).await.is_empty(),
        "nothing was un-retracted"
    );
    assert_eq!(
        retract_columns(&pool, w.owner_bba).await,
        (
            true,
            Some(w.stranger),
            Some("duplicate re-observation".to_string())
        ),
        "the admin's retraction stands as it was"
    );
}

/// The guard covers INSERT too: an application session cannot write a new
/// row that is already retracted (with a `retracted_by` of its choosing and
/// no audit row). The same INSERT without the retract columns lands, so the
/// refusal is the guard's and not row security's.
#[sqlx::test(migrations = "../../migrations")]
async fn an_insert_that_arrives_retracted_is_refused(pool: PgPool) {
    let w = world(&pool).await;
    let frame = seed_frame(&pool, "insert").await;
    let p = pool.clone();
    let (owner, stranger, claim) = (w.owner, w.stranger, w.claim);
    let (forged, plain) = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, owner).await;
        let f = sqlx::query(
            "INSERT INTO mass_functions (claim_id, frame_id, source_agent_id, masses, \
                                         retracted_at, retracted_by, retract_reason) \
             VALUES ($1, $2, $3, '{\"0\": 0.5, \"0,1\": 0.5}'::jsonb, now(), $4, 'forged')",
        )
        .bind(claim)
        .bind(frame)
        .bind(owner)
        .bind(stranger)
        .execute(&mut *conn)
        .await;
        let ok = sqlx::query(
            "INSERT INTO mass_functions (claim_id, frame_id, source_agent_id, masses) \
             VALUES ($1, $2, $3, '{\"0\": 0.5, \"0,1\": 0.5}'::jsonb)",
        )
        .bind(claim)
        .bind(frame)
        .bind(owner)
        .execute(&mut *conn)
        .await;
        (conn, (f, ok))
    })
    .await;
    let (code, message) = db_message(forged, "an INSERT that arrives retracted is refused");
    assert_eq!(code, "42501", "{message}");
    assert!(message.contains("RT06"), "refused by the guard: {message}");
    plain.expect("CALIBRATION: the same INSERT without retract columns lands");
    let retracted_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM mass_functions \
          WHERE claim_id = $1 AND frame_id = $2 AND retracted_at IS NOT NULL",
    )
    .bind(w.claim)
    .bind(frame)
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(retracted_rows, 0, "no forged retracted row exists");
}

/// The edge wake-up gate counts a retracted row as present (its register
/// entry in `bba_retract_read_lint.rs`): a re-asserted edge must not silently
/// re-derive a BBA somebody retracted. Pinned with the perspective's ONLY row
/// retracted.
#[sqlx::test(migrations = "../../migrations")]
async fn a_perspective_whose_only_bba_is_retracted_still_exists(pool: PgPool) {
    let w = world(&pool).await;
    let before = exists_for(&pool, w.owner, w.perspective).await;
    assert!(before, "CALIBRATION: the perspective holds the owner's row");
    mark_retracted_directly(&pool, w.owner_bba, w.owner).await;
    assert!(
        exists_for(&pool, w.owner, w.perspective).await,
        "a retracted row still counts as wired"
    );
}

async fn exists_for(pool: &PgPool, agent: Uuid, perspective: Uuid) -> bool {
    let p = pool.clone();
    fixture::as_role(pool, "epigraph_app", |mut conn| async move {
        let v = stamp(&mut conn, &p, agent).await;
        let e = MassFunctionRepository::exists_for_perspective(&mut *conn, &v, perspective)
            .await
            .expect("exists_for_perspective");
        (conn, e)
    })
    .await
}

/// `compound_own_rows` reads each own row's refuting citers in a subquery
/// over `mass_functions` beside the outer read; the retracted-row filter must
/// sit on the CITER (`ar`), not only on the outer row. A retracted
/// `attributed_v1` row that refutes the owner's row stops counting as a
/// citer, while the cited row itself stays.
#[sqlx::test(migrations = "../../migrations")]
async fn a_retracted_refuting_citer_drops_out_of_compound_own_rows(pool: PgPool) {
    let w = world(&pool).await;
    let owner_group: Uuid = sqlx::query_scalar("SELECT owner_group_id FROM claims WHERE id = $1")
        .bind(w.claim)
        .fetch_one(&pool)
        .await
        .expect("the claim's group");
    let citer_claim = public_claim_owned_by(&pool, w.owner, owner_group, "citer").await;
    let citer = MassFunctionRepository::store_with_perspective(
        &pool,
        citer_claim,
        w.frame_a,
        Some(w.owner),
        Some(w.perspective),
        &serde_json::json!({"1": 0.6, "0,1": 0.4}),
        None,
        Some("attributed_v1"),
        Some(1.0),
        None,
        "unknown",
        None,
    )
    .await
    .expect("store the attributed citer");
    let citers = |pool: PgPool, owner: Uuid, claim: Uuid| async move {
        let p = pool.clone();
        fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
            let v = stamp(&mut conn, &p, owner).await;
            let rows = compound_own_rows(&mut *conn, &v, &[claim], Uuid::nil())
                .await
                .expect("compound_own_rows");
            let out: Vec<(Uuid, Vec<Uuid>)> = rows
                .into_iter()
                .map(|r| (r.input.row.id, r.refuting_citers))
                .collect();
            (conn, out)
        })
        .await
    };
    let before = citers(pool.clone(), w.owner, w.claim).await;
    let own = before
        .iter()
        .find(|(id, _)| *id == w.owner_bba)
        .unwrap_or_else(|| panic!("CALIBRATION: the owner's row is read: {before:?}"));
    assert_eq!(own.1, vec![citer_claim], "CALIBRATION: the citer counts");

    mark_retracted_directly(&pool, citer, w.owner).await;
    let after = citers(pool.clone(), w.owner, w.claim).await;
    let own = after
        .iter()
        .find(|(id, _)| *id == w.owner_bba)
        .unwrap_or_else(|| panic!("the cited row itself stays: {after:?}"));
    assert!(
        own.1.is_empty(),
        "a retracted citer no longer refutes: {after:?}"
    );
}

/// Known limit, pinned so a change is deliberate: in a dedup repair a
/// canonical's RETRACTED row still holds its upsert key (migration 034's
/// unique key covers it), so the duplicate's LIVE row at the same key is kept
/// on the duplicate and the merged claim folds neither. The retracted row is
/// not displaced by the repair; the source re-submits on the canonical to
/// count again.
#[sqlx::test(migrations = "../../migrations")]
async fn a_dedup_keeps_a_live_row_whose_key_a_retracted_canonical_row_holds(pool: PgPool) {
    let w = world(&pool).await;
    let owner_group: Uuid = sqlx::query_scalar("SELECT owner_group_id FROM claims WHERE id = $1")
        .bind(w.claim)
        .fetch_one(&pool)
        .await
        .expect("the claim's group");
    let canonical = w.claim;
    let dup = public_claim_owned_by(&pool, w.owner, owner_group, "duplicate").await;
    let on_dup = MassFunctionRepository::store_with_perspective(
        &pool,
        dup,
        w.frame_a,
        Some(w.owner),
        Some(w.perspective),
        &serde_json::json!({"0": 0.7, "0,1": 0.3}),
        None,
        None,
        Some(1.0),
        None,
        "unknown",
        None,
    )
    .await
    .expect("the duplicate's live row at the canonical's key");
    mark_retracted_directly(&pool, w.owner_bba, w.owner).await;

    let repair = epigraph_db::ClaimRepository::mark_duplicate_with_repair(
        &pool,
        epigraph_core::ClaimId::from_uuid(dup),
        epigraph_core::ClaimId::from_uuid(canonical),
    )
    .await
    .expect("dedup");
    assert_eq!(
        repair.kept_on_duplicate,
        vec![on_dup],
        "the live row stays on the duplicate"
    );
    let on_dup_claim: Uuid =
        sqlx::query_scalar("SELECT claim_id FROM mass_functions WHERE id = $1")
            .bind(on_dup)
            .fetch_one(&pool)
            .await
            .expect("read");
    assert_eq!(on_dup_claim, dup);
    let canonical_frame_a: Vec<Uuid> = readers(&pool, &w).await.for_claim_frame_a;
    assert!(
        canonical_frame_a.is_empty(),
        "the canonical folds neither row at that key: {canonical_frame_a:?}"
    );
}

/// Operator ruling R-103's way back: the owner un-retracts its retracted BBA
/// through `epigraph_unretract_mass_function`, with a reason. The row is live
/// again with the masses and `created_at` it was retracted with, every fold
/// reader returns it, one `mass_functions.unretract` audit row records the
/// caller, the arm, the reason and the retraction it undid, and the stored
/// scoped beliefs of its (claim, frame) that will fold it again (global and
/// its own perspective; not another perspective's) are deleted as stale. A
/// repeat answers `not_retracted` and writes nothing. Afterwards the key
/// takes writes again.
#[sqlx::test(migrations = "../../migrations")]
async fn the_owner_unretracts_once_audited_and_the_key_takes_writes_again(pool: PgPool) {
    let w = world(&pool).await;
    let p = pool.clone();
    let (owner, claim, frame_a, perspective, id) =
        (w.owner, w.claim, w.frame_a, w.perspective, w.owner_bba);
    let other_perspective = seed_perspective(&pool, w.other).await;
    let p2 = pool.clone();
    fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p2, owner).await;
        MassFunctionRepository::retract_conn(&mut conn, id, "superseded", None)
            .await
            .expect("the owner retracts its BBA");
        (conn, ())
    })
    .await;
    let retracted_state = assessment_of(&pool, id).await;
    // The folds an evidence write stored while the row was retracted.
    seed_scoped_belief(&pool, claim, frame_a, "global", None, None).await;
    seed_scoped_belief(
        &pool,
        claim,
        frame_a,
        "perspective",
        Some(perspective),
        None,
    )
    .await;
    seed_scoped_belief(
        &pool,
        claim,
        frame_a,
        "perspective",
        Some(other_perspective),
        None,
    )
    .await;

    let (first, again, live, rewrite) =
        fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
            stamp(&mut conn, &p, owner).await;
            let first =
                MassFunctionRepository::unretract_conn(&mut conn, id, "retracted in error", None)
                    .await;
            let again =
                MassFunctionRepository::unretract_conn(&mut conn, id, "once more", None).await;
            let v = stamp(&mut conn, &p, owner).await;
            let live: Vec<Uuid> =
                MassFunctionRepository::get_for_claim_frame(&mut *conn, &v, claim, frame_a)
                    .await
                    .expect("get_for_claim_frame")
                    .into_iter()
                    .map(|r| r.id)
                    .collect();
            let rewrite =
                store_bba(&mut conn, &p, owner, claim, frame_a, Some(perspective), 0.4).await;
            (conn, (first, again, live, rewrite))
        })
        .await;
    let first = first.expect("the owner un-retracts its BBA");
    assert_eq!(first.status, BbaUnretractStatus::Unretracted);
    assert_eq!(first.arm, BbaRetractArm::Owner);
    assert_eq!(first.unretracted_by, w.owner);
    assert_eq!(first.reason, "retracted in error");
    assert_eq!(first.previous_retract_reason.as_deref(), Some("superseded"));
    assert_eq!(first.previously_retracted_by, Some(w.owner));
    assert_eq!(
        first.scoped_beliefs_cleared, 2,
        "the global and own-perspective folds go; another perspective's stays"
    );
    assert_eq!(
        stored_scopes(&pool, claim).await,
        vec![(frame_a, "perspective".to_string(), Some(other_perspective))]
    );
    assert_eq!(live, vec![id], "every fold reads the row again");

    let again = again.expect("a repeat is answered");
    assert_eq!(again.status, BbaUnretractStatus::NotRetracted);
    assert_eq!(again.scoped_beliefs_cleared, 0);
    assert_eq!(again.previously_retracted_at, None);

    let audit = unretract_rows(&pool, id).await;
    assert_eq!(audit.len(), 1, "audited once: {audit:#?}");
    let (agent, details) = &audit[0];
    assert_eq!(*agent, Some(w.owner));
    assert_eq!(details["reason"], "retracted in error");
    assert_eq!(details["arm"], "owner");
    assert_eq!(details["before"]["retract_reason"], "superseded");
    assert_eq!(details["before"]["masses"]["0"], 0.9);
    assert_eq!(details["scoped_beliefs_cleared"], 2);
    assert_eq!(
        audit_rows(&pool, id).await.len(),
        1,
        "the retraction's own row stays"
    );

    assert_eq!(
        rewrite, id,
        "after the un-retraction the key takes writes again"
    );
    let (masses, _) = assessment_of(&pool, id).await;
    assert_eq!(masses["0"], 0.4);
    assert_ne!(retracted_state.1, assessment_of(&pool, id).await.1);
}

/// Who may un-retract, and the order of the checks. A stranger is refused on
/// a retracted row AND on a live one (authority before state: it is not told
/// `not_retracted`); a random id is "not found"; a blank reason is refused.
/// None of them writes. An owner may un-retract a retraction a live
/// `claims:admin` holder made (arm `owner`), and a live `claims:admin` holder
/// may un-retract the owner's (arm `admin`, with its client in the audit).
#[sqlx::test(migrations = "../../migrations")]
async fn unretract_authority_is_checked_before_state_and_admits_owner_and_admin(pool: PgPool) {
    let w = world(&pool).await;
    let admin_client = seed_client(
        &pool,
        w.stranger,
        &["claims:write", "claims:admin"],
        "active",
    )
    .await;
    let other_client = seed_client(&pool, w.other, &["claims:write"], "active").await;
    let p = pool.clone();
    let (owner, other, stranger, id, other_id) =
        (w.owner, w.other, w.stranger, w.owner_bba, w.other_bba);
    let admin = || AdminToken {
        client_id: admin_client,
        jti: Uuid::new_v4(),
    };
    let (refusals, by_owner, by_admin) =
        fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
            // `other` (no write on the owner's group, no admin grant) on the
            // owner's LIVE row, then on it retracted.
            stamp(&mut conn, &p, other).await;
            let on_live = MassFunctionRepository::unretract_conn(
                &mut conn,
                id,
                "not mine",
                Some(AdminToken {
                    client_id: other_client,
                    jti: Uuid::new_v4(),
                }),
            )
            .await;
            stamp(&mut conn, &p, stranger).await;
            MassFunctionRepository::retract_conn(&mut conn, id, "admin retraction", Some(admin()))
                .await
                .expect("the admin retracts the owner's BBA");
            stamp(&mut conn, &p, other).await;
            let on_retracted =
                MassFunctionRepository::unretract_conn(&mut conn, id, "not mine", None).await;
            let random =
                MassFunctionRepository::unretract_conn(&mut conn, Uuid::new_v4(), "random", None)
                    .await;
            stamp(&mut conn, &p, owner).await;
            let blank = MassFunctionRepository::unretract_conn(&mut conn, id, "  ", None).await;
            let by_owner =
                MassFunctionRepository::unretract_conn(&mut conn, id, "owner disagrees", None)
                    .await;
            // The admin un-retracts the other writer's row the other retracted.
            stamp(&mut conn, &p, other).await;
            MassFunctionRepository::retract_conn(&mut conn, other_id, "own retraction", None)
                .await
                .expect("the other writer retracts its own BBA");
            stamp(&mut conn, &p, stranger).await;
            let by_admin = MassFunctionRepository::unretract_conn(
                &mut conn,
                other_id,
                "admin restores",
                Some(admin()),
            )
            .await;
            (
                conn,
                ((on_live, on_retracted, random, blank), by_owner, by_admin),
            )
        })
        .await;
    let (on_live, on_retracted, random, blank) = refusals;
    assert!(
        matches!(on_live, Err(BbaRetractError::Forbidden(_))),
        "a stranger on a live row is refused, not told not_retracted: {on_live:?}"
    );
    assert!(
        matches!(on_retracted, Err(BbaRetractError::Forbidden(_))),
        "{on_retracted:?}"
    );
    assert!(
        matches!(random, Err(BbaRetractError::NotFound(_))),
        "{random:?}"
    );
    assert!(
        matches!(blank, Err(BbaRetractError::InvalidReason(_))),
        "{blank:?}"
    );
    let by_owner = by_owner.expect("the owner un-retracts the admin's retraction");
    assert_eq!(
        (by_owner.status, by_owner.arm),
        (BbaUnretractStatus::Unretracted, BbaRetractArm::Owner)
    );
    assert_eq!(by_owner.previously_retracted_by, Some(w.stranger));
    let by_admin = by_admin.expect("a live claims:admin holder un-retracts");
    assert_eq!(
        (by_admin.status, by_admin.arm),
        (BbaUnretractStatus::Unretracted, BbaRetractArm::Admin)
    );
    let owner_audit = unretract_rows(&pool, w.owner_bba).await;
    assert_eq!(
        owner_audit.len(),
        1,
        "only the owner's call wrote: {owner_audit:#?}"
    );
    assert_eq!(owner_audit[0].1["reason"], "owner disagrees");
    let admin_audit = unretract_rows(&pool, w.other_bba).await;
    assert_eq!(admin_audit.len(), 1, "{admin_audit:#?}");
    assert_eq!(admin_audit[0].0, Some(w.stranger));
    assert_eq!(admin_audit[0].1["arm"], "admin");
    assert_eq!(
        admin_audit[0].1["admin_client_id"],
        admin_client.to_string()
    );
    assert_eq!(
        retract_columns(&pool, w.other_bba).await,
        (false, None, None)
    );
}

/// Ruling R-103's "ONLY through the explicit un-retract": a clear of the
/// retract columns outside the definer is refused (RT06) on EVERY session. On
/// the application session even when it sets the definer's transaction
/// marker itself (it is not the maintenance role), and on the harness
/// connection, which passes every session bypass and so passed the old bare
/// clear guard.
#[sqlx::test(migrations = "../../migrations")]
async fn no_session_clears_a_retraction_outside_the_unretract_definer(pool: PgPool) {
    let w = world(&pool).await;
    let p = pool.clone();
    let (owner, id) = (w.owner, w.owner_bba);
    let forged = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, owner).await;
        MassFunctionRepository::retract_conn(&mut conn, id, "superseded", None)
            .await
            .expect("the owner retracts its BBA");
        let mut tx = sqlx::Connection::begin(&mut *conn).await.expect("begin");
        sqlx::query("SELECT set_config('epigraph.mf_unretract_id', $1, true)")
            .bind(id.to_string())
            .execute(&mut *tx)
            .await
            .expect("set the marker");
        let f = sqlx::query(
            "UPDATE mass_functions \
                SET retracted_at = NULL, retracted_by = NULL, retract_reason = NULL \
              WHERE id = $1",
        )
        .bind(id)
        .execute(&mut *tx)
        .await;
        drop(tx);
        (conn, f)
    })
    .await;
    let (code, message) = db_message(forged, "an application session cannot forge the clear");
    assert_eq!(code, "42501", "{message}");
    assert!(message.contains("RT06"), "{message}");

    let privileged = sqlx::query(
        "UPDATE mass_functions \
            SET retracted_at = NULL, retracted_by = NULL, retract_reason = NULL \
          WHERE id = $1",
    )
    .bind(id)
    .execute(&pool)
    .await;
    let (code, message) = db_message(privileged, "a privileged session cannot clear either");
    assert_eq!(code, "42501", "{message}");
    assert!(message.contains("RT06"), "{message}");
    assert_eq!(
        retract_columns(&pool, id).await,
        (true, Some(w.owner), Some("superseded".to_string()))
    );
    assert!(unretract_rows(&pool, id).await.is_empty());
}
