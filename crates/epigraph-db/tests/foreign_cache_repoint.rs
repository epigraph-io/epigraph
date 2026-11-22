//! Migration 243: a NON-OWNER's recompute on the application role may re-point
//! a public claim's belief cache off a frame whose every input is
//! inadmissible, to the frame the cache-owner rule elects (backlog 0296077b).
//!
//! # The defect
//!
//! A public claim's cache records `binary_truth`, holding a fold that includes
//! a BBA citing evidence later NARROWED (hidden from the public). Its only
//! input that may still enter the cache is on `claim_validity`, so the owner
//! rule (`MassFunctionRepository::cache_owner_frame_for_claim`) names
//! `claim_validity`. Before 243, migration 114's
//! `epigraph_foreign_belief_cache` refreshed a non-owner's write only on the
//! frame the cache records, so that write was declined and every reader of the
//! public claim kept being served a fold of evidence it can no longer read,
//! until a privileged recompute ran.
//!
//! # What is pinned
//!
//! Every arm runs `MassFunctionRepository::update_claim_belief` (the statement
//! every recompute writes through) on an `epigraph_app` session stamped as a
//! writer that does NOT own the claim, so the write reaches the definer:
//!
//! * the re-point is accepted in the 0296077b shape, audited as
//!   `belief_cache_repoint`, and the classification follows it;
//! * a cached combination row on the recorded frame does not keep it (the
//!   owner rule does not count one as an input either);
//! * refusals, each a no-op that leaves the cache and the audit log as they
//!   were: the recorded frame still holds an admissible input (114's guard of
//!   the cross-writer combination); a frame of the writer's own choosing; a
//!   re-point to `claim_validity` while `binary_truth` has an admissible input;
//!   a compound;
//! * the function body carries the owner rule's three Rust-generated
//!   predicates verbatim (drift ratchet);
//! * `docs/runbooks/243-undo.sql` restores 114's body on 190's path.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::visibility::Viewer;
use epigraph_db::{
    CachedBelief, FrameRepository, MassFunctionRepository, ScopedPool, SessionGucMode,
};
use sqlx::PgPool;
use uuid::Uuid;

const SIGNATURE: &str = "public.epigraph_foreign_belief_cache(uuid, double precision, \
                         double precision, double precision, double precision, \
                         double precision, uuid)";

/// 114's body of the definer (md5 of `prosrc`), which 243 re-states.
const MD5_114: &str = "fadd978562eecfd45e5e3c3d7a2462f4";

/// The frame called `name`, created when absent (`frames.name` is UNIQUE).
async fn frame_named(pool: &PgPool, name: &str) -> Uuid {
    if let Some(id) = sqlx::query_scalar::<_, Uuid>("SELECT id FROM frames WHERE name = $1")
        .bind(name)
        .fetch_optional(pool)
        .await
        .expect("look the frame up")
    {
        return id;
    }
    FrameRepository::create(
        pool,
        name,
        Some("foreign cache re-point fixture"),
        &["TRUE".to_string(), "FALSE".to_string()],
    )
    .await
    .expect("create the frame")
    .id
}

/// A BBA on (`claim`, `frame`) by `agent` citing `evidence`, stored on the
/// harness connection (so it is the claim's, public).
async fn input(pool: &PgPool, claim: Uuid, frame: Uuid, agent: Uuid, evidence: Uuid) -> Uuid {
    MassFunctionRepository::store_with_perspective(
        pool,
        claim,
        frame,
        Some(agent),
        None,
        &serde_json::json!({"0": 0.8, "0,1": 0.2}),
        None,
        Some("test"),
        None,
        None,
        "unknown",
        Some(evidence),
    )
    .await
    .expect("store an input BBA")
}

/// Narrow `evidence` to `group`, pinned as `hide-evidence` pins it (110). The
/// BBA row citing it stays public.
async fn hide(pool: &PgPool, evidence: Uuid, group: Uuid, by: Uuid) {
    sqlx::query(
        "INSERT INTO evidence_visibility_pins (evidence_id, pinned_by, reason) \
         VALUES ($1, $2, 'test: hidden')",
    )
    .bind(evidence)
    .bind(by)
    .execute(pool)
    .await
    .expect("pin the hidden evidence");
    sqlx::query("UPDATE evidence SET visibility = 'group', owner_group_id = $2 WHERE id = $1")
        .bind(evidence)
        .bind(group)
        .execute(pool)
        .await
        .expect("narrow the evidence");
}

/// Put a cache on `claim` recorded on `frame` (the stale fold a recompute
/// meets), as the owner side wrote it.
async fn stale_cache_on(pool: &PgPool, claim: Uuid, frame: Uuid) {
    sqlx::query(
        "UPDATE claims SET belief = 0.8, plausibility = 1.0, pignistic_prob = 0.9, \
                           mass_on_empty = 0, mass_on_missing = 0, belief_frame_id = $2, \
                           classification = 'supported' WHERE id = $1",
    )
    .bind(claim)
    .bind(frame)
    .execute(pool)
    .await
    .expect("stale cache");
}

type Cache = (Option<Uuid>, Option<f64>, Option<String>);

async fn cache(pool: &PgPool, claim: Uuid) -> Cache {
    sqlx::query_as(
        "SELECT belief_frame_id, pignistic_prob, classification FROM claims WHERE id = $1",
    )
    .bind(claim)
    .fetch_one(pool)
    .await
    .expect("read the cache")
}

async fn audit(pool: &PgPool, claim: Uuid) -> Vec<(Option<Uuid>, String)> {
    sqlx::query_as(
        "SELECT agent_id, details->>'action' FROM security_events \
          WHERE event_type = 'claims.foreign_aggregate_write' \
            AND details->>'claim_id' = $1::text ORDER BY created_at",
    )
    .bind(claim)
    .fetch_all(pool)
    .await
    .expect("read the audit rows")
}

/// The fold a non-owner offers on `frame`: BetP 0.7, `contradicted` after.
fn offered(frame: Uuid) -> CachedBelief {
    CachedBelief {
        belief: 0.6,
        plausibility: 0.8,
        mass_on_empty: 0.0,
        pignistic_prob: Some(0.7),
        mass_on_missing: 0.0,
        belief_frame_id: Some(frame),
    }
}

/// The two writes of a recompute (cache, then its verdict) by `writer` on an
/// `epigraph_app` session stamped as `writer`, committed. Returns whether the
/// cache was written.
async fn write_as(pool: &PgPool, writer: Uuid, claim: Uuid, frame: Uuid) -> bool {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app's rolbypassrls");
    assert!(!bypassrls, "CALIBRATION: epigraph_app must not bypass RLS");
    let url = fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let viewer = Viewer::resolve(pool, writer).await.expect("writer viewer");
    let mut tx = scoped.begin_as(&viewer).await.expect("stamped app session");
    let foreign = epigraph_db::repos::foreign_attach::is_foreign_public_claim(&mut tx, claim)
        .await
        .expect("read the foreign-public test");
    assert!(
        foreign,
        "CALIBRATION: the writer is a non-owner on a public claim, so the write reaches the \
         migration-114 definer"
    );
    let written = MassFunctionRepository::update_claim_belief(&mut *tx, claim, offered(frame))
        .await
        .expect("a declined write is a no-op, not an error");
    MassFunctionRepository::update_claim_classification(&mut *tx, claim, "contradicted", frame)
        .await
        .expect("a declined verdict is a no-op, not an error");
    tx.commit().await.expect("commit");
    written
}

struct World {
    author: Uuid,
    writer: Uuid,
    member: Uuid,
    group: Uuid,
    binary: Uuid,
    validity: Uuid,
}

async fn world(pool: &PgPool, label: &str) -> World {
    let (author, _) = fixture::seed_agent_with_group(pool, &format!("{label}-author")).await;
    let (writer, _) = fixture::seed_agent_with_group(pool, &format!("{label}-writer")).await;
    let (member, group) = fixture::seed_agent_with_group(pool, &format!("{label}-member")).await;
    World {
        author,
        writer,
        member,
        group,
        binary: frame_named(pool, "binary_truth").await,
        validity: frame_named(pool, "claim_validity").await,
    }
}

/// A world-owned public claim whose `binary_truth` input cites evidence now
/// hidden, and whose `claim_validity` input cites public evidence; its cache
/// records `binary_truth` (the fold taken while the evidence was public).
async fn narrowed_claim(pool: &PgPool, w: &World, label: &str) -> Uuid {
    let claim = fixture::seed_public_claim(pool, w.author, label).await;
    let hidden = fixture::seed_evidence(pool, claim, "document").await;
    input(pool, claim, w.binary, w.member, hidden).await;
    let open = fixture::seed_evidence(pool, claim, "observation").await;
    input(pool, claim, w.validity, w.author, open).await;
    stale_cache_on(pool, claim, w.binary).await;
    hide(pool, hidden, w.group, w.member).await;
    claim
}

fn stale(frame: Uuid) -> Cache {
    (Some(frame), Some(0.9), Some("supported".to_string()))
}

/// The 0296077b shape: the non-owner's recompute moves the cache to
/// `claim_validity`, the frame the owner rule elects, and its verdict follows.
#[sqlx::test(migrations = "../../migrations")]
async fn a_non_owner_re_points_the_cache_off_a_frame_whose_every_input_is_hidden(pool: PgPool) {
    let w = world(&pool, "fcr-accept").await;
    let claim = narrowed_claim(&pool, &w, "fcr accepted re-point").await;
    assert_eq!(cache(&pool, claim).await, stale(w.binary), "PREMISE");

    assert!(
        write_as(&pool, w.writer, claim, w.validity).await,
        "the non-owner's write onto the owner-rule frame must be accepted: the recorded \
         binary_truth fold is a fold of hidden evidence only"
    );
    assert_eq!(
        cache(&pool, claim).await,
        (
            Some(w.validity),
            Some(0.7),
            Some("contradicted".to_string())
        ),
        "the cache, and the verdict on it, now carry claim_validity's fold"
    );
    assert_eq!(
        audit(&pool, claim).await,
        vec![
            (Some(w.writer), "belief_cache_repoint".to_string()),
            (Some(w.writer), "classification".to_string()),
        ],
        "the re-point is audited under its own action, then the verdict"
    );
}

/// A cached combination row (agent-less, perspective-less, a fold label) on
/// the recorded frame is not an input to the owner rule, so it does not keep
/// the cache on that frame either.
#[sqlx::test(migrations = "../../migrations")]
async fn a_cached_combination_row_does_not_hold_the_recorded_frame(pool: PgPool) {
    let w = world(&pool, "fcr-cached").await;
    let claim = narrowed_claim(&pool, &w, "fcr cached combination").await;
    MassFunctionRepository::store_with_perspective(
        &pool,
        claim,
        w.binary,
        None,
        None,
        &serde_json::json!({"0": 0.9, "0,1": 0.1}),
        None,
        Some("Dempster"),
        None,
        None,
        "unknown",
        None,
    )
    .await
    .expect("store the cached combination row");

    assert!(
        write_as(&pool, w.writer, claim, w.validity).await,
        "a cached combination row on binary_truth must not block the re-point"
    );
    assert_eq!(cache(&pool, claim).await.0, Some(w.validity));
}

/// 114's guard of the cross-writer combination: while the recorded frame
/// still holds an input any reader of the claim may read, it stays the
/// cache's frame, whatever a non-owner offers.
#[sqlx::test(migrations = "../../migrations")]
async fn a_recorded_frame_with_an_admissible_input_is_never_re_pointed(pool: PgPool) {
    let w = world(&pool, "fcr-held").await;
    let claim = narrowed_claim(&pool, &w, "fcr recorded still admissible").await;
    let open_bt = fixture::seed_evidence(&pool, claim, "testimony").await;
    input(&pool, claim, w.binary, w.author, open_bt).await;

    assert!(
        !write_as(&pool, w.writer, claim, w.validity).await,
        "binary_truth still holds an admissible input: the re-point must be declined"
    );
    assert_eq!(cache(&pool, claim).await, stale(w.binary));
    assert!(
        audit(&pool, claim).await.is_empty(),
        "a declined write is not audited"
    );
}

/// The same guard where it is the ONLY one: the recorded frame is a third
/// frame that still holds an admissible input, and the offer is
/// `binary_truth`, which also holds one. The owner rule would rank
/// `binary_truth` first here, but the recorded fold leaks nothing, so this is
/// not the 0296077b shape: 243 leaves it to the owner or a privileged
/// recompute, exactly as 114 did.
#[sqlx::test(migrations = "../../migrations")]
async fn an_admissible_recorded_third_frame_is_not_re_pointed_to_binary_truth(pool: PgPool) {
    let w = world(&pool, "fcr-third-held").await;
    let third = frame_named(&pool, "fcr-paper-validity-held").await;
    let claim = fixture::seed_public_claim(&pool, w.author, "fcr third frame held").await;
    let open_third = fixture::seed_evidence(&pool, claim, "document").await;
    input(&pool, claim, third, w.member, open_third).await;
    let open_bt = fixture::seed_evidence(&pool, claim, "testimony").await;
    input(&pool, claim, w.binary, w.author, open_bt).await;
    stale_cache_on(&pool, claim, third).await;

    assert!(
        !write_as(&pool, w.writer, claim, w.binary).await,
        "the recorded third frame holds an admissible input: no re-point"
    );
    assert_eq!(cache(&pool, claim).await, stale(third));
    assert!(audit(&pool, claim).await.is_empty());
}

/// A frame of the writer's own choosing never carries the claim's belief,
/// even off a recorded frame whose inputs are all hidden.
#[sqlx::test(migrations = "../../migrations")]
async fn a_frame_of_the_writers_choosing_never_takes_the_cache(pool: PgPool) {
    let w = world(&pool, "fcr-own-frame").await;
    let claim = narrowed_claim(&pool, &w, "fcr writer frame").await;
    let own = frame_named(&pool, "fcr-writer-made-frame").await;
    let ev = fixture::seed_evidence(&pool, claim, "testimony").await;
    input(&pool, claim, own, w.writer, ev).await;

    assert!(
        !write_as(&pool, w.writer, claim, own).await,
        "a non-canonical frame must not take the cache"
    );
    assert_eq!(cache(&pool, claim).await, stale(w.binary));
    assert!(audit(&pool, claim).await.is_empty());
}

/// Off a recorded third frame whose inputs are all hidden, the owner rule
/// elects `binary_truth` over `claim_validity` when both have an admissible
/// input: the re-point to `claim_validity` is declined, to `binary_truth`
/// accepted.
#[sqlx::test(migrations = "../../migrations")]
async fn claim_validity_takes_the_cache_only_when_binary_truth_has_no_admissible_input(
    pool: PgPool,
) {
    let w = world(&pool, "fcr-rank").await;
    let third = frame_named(&pool, "fcr-paper-validity").await;
    let claim = fixture::seed_public_claim(&pool, w.author, "fcr ranks").await;
    let hidden = fixture::seed_evidence(&pool, claim, "document").await;
    input(&pool, claim, third, w.member, hidden).await;
    let open_cv = fixture::seed_evidence(&pool, claim, "observation").await;
    input(&pool, claim, w.validity, w.author, open_cv).await;
    let open_bt = fixture::seed_evidence(&pool, claim, "testimony").await;
    input(&pool, claim, w.binary, w.author, open_bt).await;
    stale_cache_on(&pool, claim, third).await;
    hide(&pool, hidden, w.group, w.member).await;

    assert!(
        !write_as(&pool, w.writer, claim, w.validity).await,
        "binary_truth has an admissible input, so claim_validity is not the owner-rule frame"
    );
    assert_eq!(cache(&pool, claim).await, stale(third));
    assert!(
        write_as(&pool, w.writer, claim, w.binary).await,
        "binary_truth, the owner-rule frame, takes the cache"
    );
    assert_eq!(cache(&pool, claim).await.0, Some(w.binary));
}

/// A compound has no owner frame (its belief is a query over its leaves), so
/// its cache is never re-pointed.
#[sqlx::test(migrations = "../../migrations")]
async fn a_compound_is_never_re_pointed(pool: PgPool) {
    let w = world(&pool, "fcr-compound").await;
    let claim = narrowed_claim(&pool, &w, "fcr compound").await;
    let leaf = fixture::seed_public_claim(&pool, w.author, "fcr compound leaf").await;
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', 'decomposes_to')",
    )
    .bind(claim)
    .bind(leaf)
    .execute(&pool)
    .await
    .expect("decompose the claim");
    let compound: bool = sqlx::query_scalar("SELECT public.epigraph_claim_is_compound($1)")
        .bind(claim)
        .fetch_one(&pool)
        .await
        .expect("compound test");
    assert!(compound, "CALIBRATION: the claim is a compound");

    assert!(
        !write_as(&pool, w.writer, claim, w.validity).await,
        "a compound's cache must not be re-pointed"
    );
    assert_eq!(cache(&pool, claim).await, stale(w.binary));
}

fn squash(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The definer inlines the owner rule's three predicates. Each must be the
/// Rust-generated text verbatim (whitespace aside), so a change on the Rust
/// side fails here until a migration re-states the body.
#[sqlx::test(migrations = "../../migrations")]
async fn the_definer_carries_the_owner_rules_predicates_verbatim(pool: PgPool) {
    let body: String =
        sqlx::query_scalar("SELECT p.prosrc FROM pg_proc p WHERE p.oid = to_regprocedure($1)")
            .bind(SIGNATURE)
            .fetch_one(&pool)
            .await
            .expect("read the definer body");
    let body = squash(&body);
    for (name, predicate) in [
        (
            "cached_combination_predicate",
            epigraph_db::repos::mass_function::cached_combination_predicate("mf."),
        ),
        (
            "ingest_template_predicate",
            epigraph_db::repos::mass_function::ingest_template_predicate("mf.", "f."),
        ),
        (
            "cache_admissible_predicate",
            epigraph_db::repos::derivation_scope::cache_admissible_predicate("mf", "c"),
        ),
    ] {
        let predicate = squash(&predicate);
        let n = body.matches(&predicate).count();
        assert_eq!(
            n, 3,
            "the definer must carry {name} verbatim in each of its three input reads; \
             found {n} copies of:\n{predicate}"
        );
    }
}

/// The undo runbook puts 114's body back on 190's path, keeps the owner, and
/// the 0296077b write is declined again.
#[sqlx::test(migrations = "../../migrations")]
async fn the_243_undo_restores_114s_body_on_190s_path(pool: PgPool) {
    let undo = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/runbooks/243-undo.sql"
    ))
    .expect("read the undo");
    sqlx::raw_sql(&undo)
        .execute(&pool)
        .await
        .expect("apply the undo");
    let (md5, path, owner): (String, Option<Vec<String>>, String) = sqlx::query_as(
        "SELECT md5(p.prosrc), p.proconfig, pg_get_userbyid(p.proowner)::text \
           FROM pg_proc p WHERE p.oid = to_regprocedure($1)",
    )
    .bind(SIGNATURE)
    .fetch_one(&pool)
    .await
    .expect("read the definer");
    assert_eq!(md5, MD5_114, "the undo restores 114's body");
    assert_eq!(
        path,
        Some(vec!["search_path=pg_catalog, public, pg_temp".to_string()]),
        "on 190's path"
    );
    let maint: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance')",
    )
    .fetch_one(&pool)
    .await
    .expect("role probe");
    if maint {
        assert_eq!(owner, "epigraph_maintenance", "owner kept");
    }

    let w = world(&pool, "fcr-undo").await;
    let claim = narrowed_claim(&pool, &w, "fcr after undo").await;
    assert!(
        !write_as(&pool, w.writer, claim, w.validity).await,
        "after the undo the re-point is declined again (114's rule)"
    );
    assert_eq!(cache(&pool, claim).await, stale(w.binary));

    let again = sqlx::raw_sql(&undo).execute(&pool).await;
    assert!(
        again.is_err_and(|e| e.to_string().contains("243-undo")),
        "a second undo refuses: the body is no longer 243's"
    );
}
