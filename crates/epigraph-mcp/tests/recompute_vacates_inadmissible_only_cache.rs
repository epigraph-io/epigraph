//! Ruling R-80 (on R-22 / R-71): a claim whose EVERY BBA is inadmissible
//! for its cache (some source is narrower than the claim) gets a VACUOUS
//! cache on recompute (full ignorance: Bel 0, Pl 1, BetP 0.5 on the binary
//! frame, classification `not_enough_info`), instead of keeping its old
//! cached value.
//!
//! # What was wrong, measured at origin/main before this file
//!
//! The recompute fold drops every inadmissible BBA
//! (`epigraph_engine::derivation_scope::retain_for_cache`). When that left
//! nothing, `recompute_combined_belief` returned without writing, so the claim
//! kept the value folded BEFORE its source was narrowed (evidence hidden after
//! the fact, or a cache written before R-22). That stale value is what every
//! reader of the claim is served, and it still carries the narrowed evidence's
//! direction and weight. `recompute_beliefs` reported the claim as recomputed.
//!
//! # What is pinned
//!
//! * the vacate, on an `epigraph_app` session stamped as a member of the
//!   evidence's group and as the claim's author (row security applies), and
//!   through the MCP `recompute_beliefs` tool on the maintenance session;
//! * the claim-wide gate: an admissible input on ANOTHER frame of the claim
//!   means not every BBA is inadmissible, so nothing is vacated;
//! * a claim with no cache stays without one (writing a vacuous value there
//!   would announce that an unseen BBA exists).

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_crypto::AgentSigner;
use epigraph_db::visibility::Viewer;
use epigraph_db::{MassFunctionRepository, PerspectiveRepository, ScopedPool, SessionGucMode};
use epigraph_engine::edge_factor::{
    ensure_binary_frame, recompute_claim_cached_belief, resolve_claim_validity_frame,
};
use epigraph_mcp::types::RecomputeBeliefsParams;
use epigraph_mcp::{embed::McpEmbedder, tools, EpiGraphMcpFull};
use rmcp::model::ContentBlock;
use sqlx::PgPool;
use uuid::Uuid;

/// The claim's whole cache: (BetP, Bel, Pl, mass_on_empty, mass_on_missing,
/// belief_frame_id, classification).
type Cache = (
    Option<f64>,
    Option<f64>,
    Option<f64>,
    Option<f64>,
    Option<f64>,
    Option<Uuid>,
    Option<String>,
);

async fn cache(pool: &PgPool, claim: Uuid) -> Cache {
    sqlx::query_as(
        "SELECT pignistic_prob, belief, plausibility, mass_on_empty, mass_on_missing, \
                belief_frame_id, classification \
           FROM claims WHERE id = $1",
    )
    .bind(claim)
    .fetch_one(pool)
    .await
    .expect("read the cache")
}

/// Put `value` back as the claim's cache (the stale value a recompute meets).
async fn restore(pool: &PgPool, claim: Uuid, value: &Cache) {
    sqlx::query(
        "UPDATE claims SET pignistic_prob = $2, belief = $3, plausibility = $4, \
                mass_on_empty = $5, mass_on_missing = $6, belief_frame_id = $7, \
                classification = $8 \
          WHERE id = $1",
    )
    .bind(claim)
    .bind(value.0)
    .bind(value.1)
    .bind(value.2)
    .bind(value.3)
    .bind(value.4)
    .bind(value.5)
    .bind(value.6.as_deref())
    .execute(pool)
    .await
    .expect("restore the cache");
}

fn near(x: Option<f64>, y: f64) -> bool {
    x.is_some_and(|x| (x - y).abs() < 1e-9)
}

/// Full ignorance on `frame`: BetP 0.5, Bel 0, Pl 1, no conflict, no missing
/// mass, `not_enough_info`.
fn is_vacuous(c: &Cache, frame: Uuid) -> bool {
    near(c.0, 0.5)
        && near(c.1, 0.0)
        && near(c.2, 1.0)
        && near(c.3, 0.0)
        && near(c.4, 0.0)
        && c.5 == Some(frame)
        && c.6.as_deref() == Some("not_enough_info")
}

/// A BBA on (`claim`, `frame`) by `agent` citing `evidence`, with `t` on TRUE.
async fn store(pool: &PgPool, claim: Uuid, frame: Uuid, agent: Uuid, evidence: Uuid, t: f64) {
    PerspectiveRepository::ensure_evidence_perspective(pool, evidence, Some(agent))
        .await
        .expect("evidence perspective");
    MassFunctionRepository::store_with_perspective(
        pool,
        claim,
        frame,
        Some(agent),
        Some(evidence),
        &serde_json::json!({"0": t, "0,1": 1.0 - t}),
        None,
        Some("auto_wire"),
        Some(1.0),
        None,
        "unknown",
        Some(evidence),
    )
    .await
    .expect("store a BBA");
}

/// Narrow `evidence` to `group`, pinned as `epigraph-operator hide-evidence`
/// pins it (migration 110). The BBA row citing it stays public.
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
        .expect("narrow the evidence to the group");
}

async fn app_role(pool: &PgPool) -> ScopedPool {
    let url = fixture::database_url_for(pool).await;
    ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
        .await
        .expect("app-role ScopedPool")
}

/// `recompute_claim_cached_belief` on an `epigraph_app` session stamped as
/// `viewer`, committed.
async fn recompute_as(scoped: &ScopedPool, viewer: &Viewer, claim: Uuid) {
    let mut tx = scoped.begin_as(viewer).await.expect("stamped app session");
    recompute_claim_cached_belief(&mut tx, viewer, claim)
        .await
        .expect("recompute on the application role");
    tx.commit().await.expect("commit");
}

struct World {
    public: Viewer,
    member: Uuid,
    member_viewer: Viewer,
    author: Uuid,
    author_viewer: Viewer,
    group: Uuid,
    binary: Uuid,
}

async fn world(pool: &PgPool, label: &str) -> World {
    let public = fixture::public_viewer(pool).await;
    let (member, group) = fixture::seed_agent_with_group(pool, &format!("{label}-member")).await;
    let (author, _) = fixture::seed_agent_with_group(pool, &format!("{label}-author")).await;
    let member_viewer = Viewer::resolve(pool, member).await.expect("member viewer");
    let author_viewer = Viewer::resolve(pool, author).await.expect("author viewer");
    let binary = ensure_binary_frame(&mut pool.acquire().await.expect("acquire"), &public)
        .await
        .expect("binary_truth");
    World {
        public,
        member,
        member_viewer,
        author,
        author_viewer,
        group,
        binary,
    }
}

/// A public claim with one BBA citing public evidence, its cache recomputed,
/// then that evidence hidden: every BBA of the claim is now inadmissible and
/// the cache still holds the value folded from it. Returns (claim, that cache).
async fn stale_claim(pool: &PgPool, w: &World, label: &str) -> (Uuid, Cache) {
    let claim = fixture::seed_public_claim(pool, w.author, label).await;
    let ev = fixture::seed_evidence(pool, claim, "observation").await;
    store(pool, claim, w.binary, w.author, ev, 0.8).await;
    recompute_claim_cached_belief(
        &mut pool.acquire().await.expect("acquire"),
        &w.public,
        claim,
    )
    .await
    .expect("recompute while the evidence is public");
    let stale = cache(pool, claim).await;
    assert!(
        stale.0.is_some_and(|b| b > 0.55) && stale.6.is_some(),
        "PREMISE: the public evidence's fold is cached ({stale:?})"
    );
    hide(pool, ev, w.group, w.member).await;
    (claim, stale)
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_claim_whose_every_bba_is_inadmissible_gets_a_vacuous_cache_on_recompute(pool: PgPool) {
    let w = world(&pool, "r80-vacate").await;
    let (claim, stale) = stale_claim(&pool, &w, "r80 every bba inadmissible").await;
    let scoped = app_role(&pool).await;

    // The member can read the hidden evidence; the author cannot. Neither may
    // leave the claim's readers a belief folded from it.
    for (who, viewer) in [("member", &w.member_viewer), ("author", &w.author_viewer)] {
        restore(&pool, claim, &stale).await;
        recompute_as(&scoped, viewer, claim).await;
        let after = cache(&pool, claim).await;
        assert!(
            is_vacuous(&after, w.binary),
            "recompute as the {who} on the application role must vacate the cache of a claim \
             whose every BBA is inadmissible; it left {after:?} (stale value {stale:?})"
        );
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn recompute_beliefs_vacates_a_claim_whose_every_bba_is_inadmissible(pool: PgPool) {
    let w = world(&pool, "r80-tool").await;
    let (claim, stale) = stale_claim(&pool, &w, "r80 recompute_beliefs").await;
    let signer = AgentSigner::from_bytes(&[0x80u8; 32]).expect("signer");
    let server = EpiGraphMcpFull::new(
        pool.clone(),
        signer,
        McpEmbedder::new(pool.clone(), None),
        false,
    )
    .with_scoped_pool(fixture::scoped_pool(&pool).await);

    let out = tools::cdst_maintenance::recompute_beliefs(
        &server,
        &mut fixture::scoped_pool(&pool)
            .await
            .maintenance_session(epigraph_db::visibility::SystemReason::BeliefRecomputation)
            .await
            .expect("maintenance session"),
        RecomputeBeliefsParams {
            claim_ids: Some(vec![claim.to_string()]),
            labels: None,
            limit: None,
            offset: None,
        },
    )
    .await
    .expect("recompute_beliefs");
    let text = match out.content.first().cloned().expect("content") {
        ContentBlock::Text(t) => t.text,
        other => panic!("expected text, got {other:?}"),
    };
    let report: serde_json::Value = serde_json::from_str(&text).expect("JSON report");

    let after = cache(&pool, claim).await;
    assert!(
        is_vacuous(&after, w.binary),
        "recompute_beliefs must vacate the cache of a claim whose every BBA is inadmissible; \
         it left {after:?} (stale value {stale:?}) and reported {report}"
    );
    assert_eq!(report["claims_recomputed"], 1, "{report}");
    assert_eq!(report["frame_writes"], 1, "{report}");
    assert_eq!(report["errors"], serde_json::json!([]), "{report}");
}

/// Not every BBA is inadmissible: the claim keeps an admissible input on
/// `claim_validity` while its `binary_truth` (the cache-owner frame) holds only
/// a hidden-evidence BBA. R-80 does not vacate it.
#[sqlx::test(migrations = "../../migrations")]
async fn an_admissible_input_on_another_frame_is_not_vacated(pool: PgPool) {
    let w = world(&pool, "r80-other-frame").await;
    let validity =
        resolve_claim_validity_frame(&mut pool.acquire().await.expect("acquire"), &w.public)
            .await
            .expect("claim_validity");
    let claim = fixture::seed_public_claim(&pool, w.author, "r80 admissible elsewhere").await;
    let open_ev = fixture::seed_evidence(&pool, claim, "observation").await;
    store(&pool, claim, validity, w.author, open_ev, 0.7).await;
    let hidden_ev = fixture::seed_evidence(&pool, claim, "document").await;
    store(&pool, claim, w.binary, w.member, hidden_ev, 0.9).await;
    recompute_claim_cached_belief(
        &mut pool.acquire().await.expect("acquire"),
        &w.public,
        claim,
    )
    .await
    .expect("recompute while every source is public");
    let before = cache(&pool, claim).await;
    assert!(
        before.0.is_some() && before.5 == Some(w.binary),
        "PREMISE: binary_truth owns a filled cache ({before:?})"
    );
    hide(&pool, hidden_ev, w.group, w.member).await;

    recompute_as(&app_role(&pool).await, &w.member_viewer, claim).await;
    let after = cache(&pool, claim).await;
    assert!(
        !is_vacuous(&after, w.binary) && after.0.is_some(),
        "a claim with an admissible BBA on another frame was vacated: {after:?}"
    );
}

/// A claim with no cache whose every BBA is inadmissible keeps no cache: a
/// vacuous value there would tell its readers that an unseen BBA exists.
#[sqlx::test(migrations = "../../migrations")]
async fn a_claim_without_a_cache_is_not_given_one(pool: PgPool) {
    let w = world(&pool, "r80-null").await;
    let claim = fixture::seed_public_claim(&pool, w.author, "r80 never cached").await;
    let ev = fixture::seed_evidence(&pool, claim, "observation").await;
    hide(&pool, ev, w.group, w.member).await;
    store(&pool, claim, w.binary, w.member, ev, 0.8).await;
    let before = cache(&pool, claim).await;
    assert!(
        before.0.is_none() && before.1.is_none() && before.2.is_none(),
        "PREMISE: the claim has no cache ({before:?})"
    );

    recompute_as(&app_role(&pool).await, &w.member_viewer, claim).await;
    let after = cache(&pool, claim).await;
    assert!(
        after.0.is_none() && after.1.is_none() && after.2.is_none(),
        "a claim whose only BBA is inadmissible was given a cache it never had: {after:?}"
    );
}
