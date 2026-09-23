//! Authorization of `POST /api/v1/hypothesis/:id/promote` (`F-SBC-A2`).
//!
//! The handler used to take only a `ViewerExtractor`. It checked no scope and
//! no owner, and after the read-only readiness re-check it ran every write on
//! the raw pool, constrained by id alone. Any authenticated principal that
//! could read a promotion-ready hypothesis could therefore promote it. The
//! tests below pin each layer of the replacement gate, in the order the
//! handler applies them:
//!
//! 1. `claims:write` (403 without it);
//! 2. the hypothesis must be READABLE by the caller (404 when it is not:
//!    absent, not forbidden);
//! 3. the caller must own it or hold `claims:admin` (403), even when it can
//!    write the owning group;
//! 4. the status `UPDATE` carries `{WRITABLE:c}`, so the caller must be able
//!    to write the group that owns the row (403 when it cannot).
//!
//! Every refusal asserts the ROWS as well as the status: the claim's
//! `hypothesis_status`, its `research_validity` frame membership, the
//! `research_validity` mass function. A 4xx that still
//! wrote would pass a status-only test.
//!
//! # Fixture shape
//!
//! Every hypothesis here is PROMOTION-READY, so a refusal is the gate's doing
//! and not `evaluate_promotion`'s: a `hypothesis_assessment` mass function with
//! `m({supported}) = 0.8`, one `complete` experiment whose result an analysis
//! `analyzes`, and that analysis `provides_evidence` to the hypothesis with a
//! non-empty `scope_limitations`. Claims are declared
//! `(visibility, <author's personal group>)` explicitly, as
//! `workflow_deprecate_test.rs` does and for the same reason: a claim inserted
//! without a declaration lands in the seed group through 074's escape hatch,
//! which nobody can write.
//!
//! # Side effect, stated rather than hidden
//!
//! These tests run against the shared `DATABASE_URL` database, and
//! `ensure_frames` inserts permanent `hypothesis_assessment` and
//! `research_validity` frame rows that no migration seeds. The handler looks
//! both up by those literal names, so a per-run name is not available. The
//! inserts are `ON CONFLICT (name) DO NOTHING`, the same as
//! `hypothesis_ownership_from_principal.rs`.

#![cfg(feature = "db")]

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;

mod common;

/// The world group: the owner a public registry row carries.
const WORLD: &str = "00000000-0000-0000-0000-000000000000";

async fn test_pool() -> (String, PgPool) {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("connect to test DB");
    (url, pool)
}

/// `(hypothesis_assessment, research_validity)` frame ids, creating either
/// frame if it does not exist.
async fn ensure_frames(pool: &PgPool) -> (Uuid, Uuid) {
    let mut ids = Vec::new();
    for name in ["hypothesis_assessment", "research_validity"] {
        sqlx::query(
            "INSERT INTO frames (name, hypotheses, visibility, owner_group_id) \
             VALUES ($1, ARRAY['true','false'], 'public', $2::uuid) \
             ON CONFLICT (name) DO NOTHING",
        )
        .bind(name)
        .bind(WORLD)
        .execute(pool)
        .await
        .expect("seed frame");
        let id: Uuid = sqlx::query_scalar("SELECT id FROM frames WHERE name = $1")
            .bind(name)
            .fetch_one(pool)
            .await
            .expect("read frame id");
        ids.push(id);
    }
    (ids[0], ids[1])
}

/// Seed a claim authored by `author`, declared `(visibility, <author's personal
/// group>)`.
async fn seed_claim(pool: &PgPool, author: Uuid, visibility: &str, content: &str) -> Uuid {
    let group = common::personal_group_of(pool, author).await;
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, is_current, \
                             labels, properties, visibility, owner_group_id) \
         VALUES ($1, $2, $3, $4, 0.5, true, ARRAY['hypothesis'], \
                 '{\"hypothesis_status\": \"active\"}'::jsonb, $5, $6)",
    )
    .bind(id)
    .bind(format!("{content} {id}"))
    .bind(&hash)
    .bind(author)
    .bind(visibility)
    .bind(group)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}

/// Insert `source --relationship--> target` and force the edge PUBLIC.
///
/// Forced for the reason `workflow_deprecate_test.rs` gives: an edge inherits
/// its endpoints' tenancy, and the readiness re-check's experiment count reads
/// its `analyzes` edge under the EDGE predicate. Left private, the edge would
/// make the hypothesis NOT READY for a caller outside the author's group, and
/// the tests below would then be testing `evaluate_promotion`, not the gate.
async fn seed_public_edge(
    pool: &PgPool,
    source: Uuid,
    target: Uuid,
    source_type: &str,
    target_type: &str,
    relationship: &str,
) {
    let edge =
        common::insert_edge(pool, source, target, source_type, target_type, relationship).await;
    sqlx::query(
        "UPDATE edges SET visibility = 'public', owner_group_id = $2::uuid, \
                          co_owner_group_id = NULL \
         WHERE id = $1",
    )
    .bind(edge)
    .bind(WORLD)
    .execute(pool)
    .await
    .expect("force the edge public");
}

/// Seed a PROMOTION-READY hypothesis authored by `author`. See the module doc
/// for what "ready" takes.
async fn seed_ready_hypothesis(pool: &PgPool, author: Uuid, visibility: &str) -> Uuid {
    let (hyp_frame, _) = ensure_frames(pool).await;
    let h = seed_claim(pool, author, visibility, "promotion-authority hypothesis").await;

    sqlx::query(
        "INSERT INTO claim_frames (claim_id, frame_id, hypothesis_index) VALUES ($1, $2, 0)",
    )
    .bind(h)
    .bind(hyp_frame)
    .execute(pool)
    .await
    .expect("bind the hypothesis to hypothesis_assessment");

    sqlx::query(
        "INSERT INTO mass_functions (claim_id, frame_id, source_agent_id, masses) \
         VALUES ($1, $2, $3, '{\"0\": 0.8, \"0,1\": 0.2}'::jsonb)",
    )
    .bind(h)
    .bind(hyp_frame)
    .bind(author)
    .execute(pool)
    .await
    .expect("seed a supporting hypothesis_assessment mass function");

    let experiment: Uuid = sqlx::query_scalar(
        "INSERT INTO experiments (hypothesis_id, created_by, status) \
         VALUES ($1, $2, 'complete') RETURNING id",
    )
    .bind(h)
    .bind(author)
    .fetch_one(pool)
    .await
    .expect("seed a complete experiment");
    let result: Uuid = sqlx::query_scalar(
        "INSERT INTO experiment_results (experiment_id, data_source) \
         VALUES ($1, 'manual') RETURNING id",
    )
    .bind(experiment)
    .fetch_one(pool)
    .await
    .expect("seed an experiment result");
    let analysis: Uuid = sqlx::query_scalar(
        "INSERT INTO analyses (analysis_type, method_description, agent_id, properties) \
         VALUES ('promotion-authority', 'fixture', $1, \
                 '{\"scope_limitations\": [\"fixture conditions only\"]}'::jsonb) \
         RETURNING id",
    )
    .bind(author)
    .fetch_one(pool)
    .await
    .expect("seed an analysis");

    seed_public_edge(
        pool,
        analysis,
        result,
        "analysis",
        "experiment_result",
        "analyzes",
    )
    .await;
    seed_public_edge(pool, analysis, h, "analysis", "claim", "provides_evidence").await;
    h
}

/// Seed a factor in `frame` over `variables`.
async fn seed_factor(pool: &PgPool, variables: &[Uuid], frame: Uuid) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO factors (factor_type, variable_ids, potential, frame_id) \
         VALUES ('evidential_support', $1, '{}'::jsonb, $2) RETURNING id",
    )
    .bind(variables)
    .bind(frame)
    .fetch_one(pool)
    .await
    .expect("seed factor")
}

async fn factor_frame(pool: &PgPool, factor: Uuid) -> Uuid {
    sqlx::query_scalar("SELECT frame_id FROM factors WHERE id = $1")
        .bind(factor)
        .fetch_one(pool)
        .await
        .expect("read factor frame")
}

/// Everything a promotion writes, read back on the raw pool.
#[derive(Debug, PartialEq)]
struct PromotionState {
    status: Option<String>,
    in_research_validity: bool,
    research_validity_masses: i64,
}

async fn promotion_state(pool: &PgPool, h: Uuid) -> PromotionState {
    let (_, rv) = ensure_frames(pool).await;
    let status: Option<String> =
        sqlx::query_scalar("SELECT properties->>'hypothesis_status' FROM claims WHERE id = $1")
            .bind(h)
            .fetch_one(pool)
            .await
            .expect("read hypothesis status");
    let in_research_validity: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM claim_frames WHERE claim_id = $1 AND frame_id = $2)",
    )
    .bind(h)
    .bind(rv)
    .fetch_one(pool)
    .await
    .expect("read frame membership");
    let research_validity_masses: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM mass_functions WHERE claim_id = $1 AND frame_id = $2",
    )
    .bind(h)
    .bind(rv)
    .fetch_one(pool)
    .await
    .expect("count research_validity mass functions");
    PromotionState {
        status,
        in_research_validity,
        research_validity_masses,
    }
}

fn assert_untouched(state: &PromotionState, what: &str) {
    assert_eq!(
        *state,
        PromotionState {
            status: Some("active".to_string()),
            in_research_validity: false,
            research_validity_masses: 0,
        },
        "{what} must be untouched: still active, not in research_validity, no \
         research_validity mass function"
    );
}

fn assert_promoted(state: &PromotionState, what: &str) {
    assert_eq!(
        *state,
        PromotionState {
            status: Some("promoted".to_string()),
            in_research_validity: true,
            research_validity_masses: 1,
        },
        "{what} must be promoted: status promoted, in research_validity, one \
         research_validity mass function copied from hypothesis_assessment"
    );
}

async fn promote(addr: std::net::SocketAddr, token: &str, h: Uuid) -> (u16, String) {
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/hypothesis/{h}/promote"))
        .bearer_auth(token)
        .send()
        .await
        .expect("HTTP POST succeeds");
    let status = resp.status().as_u16();
    (status, resp.text().await.unwrap_or_default())
}

/// The positive control, on the same fixture every refusal below uses: the
/// author, holding `claims:write`, promotes their own ready hypothesis, and
/// every promotion write lands. Without this leg, a gate that refused everyone
/// would pass the whole file.
#[tokio::test(flavor = "multi_thread")]
async fn the_owner_promotes_their_ready_hypothesis() {
    let (url, pool) = test_pool().await;
    let owner = common::seed_system_agent(&pool).await;
    let h = seed_ready_hypothesis(&pool, owner, "group").await;
    let (hyp_frame, rv_frame) = ensure_frames(&pool).await;
    let own = seed_claim(&pool, owner, "group", "the owner's own evidence").await;
    let own_factor = seed_factor(&pool, &[h, own], hyp_frame).await;

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let token = common::test_bearer_token_for_principal(owner, &["claims:write"]);
    let (status, body) = promote(addr, &token, h).await;
    assert_eq!(
        status, 200,
        "the owner's promotion must succeed; body={body}"
    );

    assert_promoted(&promotion_state(&pool, h).await, "the owner's hypothesis");
    assert_eq!(
        factor_frame(&pool, own_factor).await,
        rv_frame,
        "a factor whose every variable the owner may write must move to research_validity"
    );
}

/// `claims:write` is required. The route used to check no scope at all, so a
/// read-only token could promote.
#[tokio::test(flavor = "multi_thread")]
async fn promote_without_claims_write_is_403_and_writes_nothing() {
    let (url, pool) = test_pool().await;
    let owner = common::seed_system_agent(&pool).await;
    let h = seed_ready_hypothesis(&pool, owner, "public").await;

    let (addr, _shutdown) = common::spawn_app(&url).await;
    // The OWNER, so the only thing missing is the scope.
    let token = common::test_bearer_token_for_principal(owner, &["claims:read"]);
    let (status, body) = promote(addr, &token, h).await;
    assert_eq!(status, 403, "claims:write is required; body={body}");

    assert_untouched(&promotion_state(&pool, h).await, "the hypothesis");
}

/// A readable hypothesis authored by someone else is 403 for a non-admin.
#[tokio::test(flavor = "multi_thread")]
async fn promoting_another_principals_hypothesis_is_403_and_writes_nothing() {
    let (url, pool) = test_pool().await;
    let owner = common::seed_system_agent(&pool).await;
    let other = common::seed_system_agent(&pool).await;
    let h = seed_ready_hypothesis(&pool, owner, "public").await;

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let token = common::test_bearer_token_for_principal(other, &["claims:write"]);
    let (status, body) = promote(addr, &token, h).await;
    assert_eq!(
        status, 403,
        "a non-owner without claims:admin must be refused; body={body}"
    );

    assert_untouched(&promotion_state(&pool, h).await, "the hypothesis");
}

/// Make `member` a live `writer` in `owner`'s personal group, so `member`'s
/// viewer can WRITE the rows that group owns.
async fn add_writer_to_personal_group_of(pool: &PgPool, owner: Uuid, member: Uuid) {
    let group = common::personal_group_of(pool, owner).await;
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'writer')",
    )
    .bind(group)
    .bind(member)
    .execute(pool)
    .await
    .expect("add a writer to the owner's group");
}

/// The owner gate is real, and not subsumed by the write predicate.
///
/// The caller is a `writer` in the group that owns the hypothesis, so
/// `{WRITABLE:c}` alone would let it through. It is not the author and holds
/// no `claims:admin`, so `require_owner_or_admin` refuses it. This is the same
/// line `update_claim`, `supersede_claim` and `deprecate_workflow` draw. Remove
/// the owner gate and this test goes 200.
#[tokio::test(flavor = "multi_thread")]
async fn a_group_writer_who_is_not_the_author_is_403_and_writes_nothing() {
    let (url, pool) = test_pool().await;
    let owner = common::seed_system_agent(&pool).await;
    let colleague = common::seed_system_agent(&pool).await;
    let h = seed_ready_hypothesis(&pool, owner, "group").await;
    add_writer_to_personal_group_of(&pool, owner, colleague).await;

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let token = common::test_bearer_token_for_principal(colleague, &["claims:write"]);
    let (status, body) = promote(addr, &token, h).await;
    assert_eq!(
        status, 403,
        "a writer in the owning group who is not the author, without claims:admin, must be \
         refused; body={body}"
    );

    assert_untouched(&promotion_state(&pool, h).await, "the hypothesis");
}

/// `claims:admin` overrides authorship, but only inside the caller's write
/// authority: an admin that can write the owning group promotes. This is the
/// admin leg of the positive control, and the counterpart of
/// `claims_admin_outside_the_owning_group_cannot_promote` below.
#[tokio::test(flavor = "multi_thread")]
async fn claims_admin_who_can_write_the_owning_group_promotes() {
    let (url, pool) = test_pool().await;
    let owner = common::seed_system_agent(&pool).await;
    let admin = common::seed_system_agent(&pool).await;
    let h = seed_ready_hypothesis(&pool, owner, "group").await;
    add_writer_to_personal_group_of(&pool, owner, admin).await;

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let token = common::test_bearer_token_for_principal(admin, &["claims:write", "claims:admin"]);
    let (status, body) = promote(addr, &token, h).await;
    assert_eq!(
        status, 200,
        "claims:admin with write authority over the owning group must promote; body={body}"
    );

    assert_promoted(&promotion_state(&pool, h).await, "the hypothesis");
}

/// The write predicate is real, not decorative.
///
/// A `claims:admin` token PASSES the owner gate, so on a public hypothesis
/// owned by another principal's personal group the only thing that can refuse
/// the write is the `{WRITABLE:c}` marker on the status `UPDATE`: the admin is
/// in no group that owns the row. Remove the marker and this test goes 200.
#[tokio::test(flavor = "multi_thread")]
async fn claims_admin_outside_the_owning_group_cannot_promote() {
    let (url, pool) = test_pool().await;
    let owner = common::seed_system_agent(&pool).await;
    let admin = common::seed_system_agent(&pool).await;
    let h = seed_ready_hypothesis(&pool, owner, "public").await;

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let token = common::test_bearer_token_for_principal(admin, &["claims:write", "claims:admin"]);
    let (status, body) = promote(addr, &token, h).await;
    assert_eq!(
        status, 403,
        "the write predicate must refuse a principal that cannot write the owning group; \
         body={body}"
    );

    assert_untouched(&promotion_state(&pool, h).await, "the hypothesis");
}

/// A hypothesis private to a group the caller is not in is ABSENT: 404, and
/// nothing is written, even for `claims:admin`.
///
/// NOT DISCRIMINATING AGAINST THE PRE-FIX HANDLER, and stated so it is not
/// over-read: the readiness re-check already read through the caller's viewer
/// and 404'd here. It pins that the new gate keeps "unreadable" as 404 rather
/// than turning it into a 403, which would confirm the row exists.
#[tokio::test(flavor = "multi_thread")]
async fn promoting_a_hypothesis_the_caller_cannot_read_is_404_and_writes_nothing() {
    let (url, pool) = test_pool().await;
    let owner = common::seed_system_agent(&pool).await;
    let stranger = common::seed_system_agent(&pool).await;
    let h = seed_ready_hypothesis(&pool, owner, "group").await;

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let token =
        common::test_bearer_token_for_principal(stranger, &["claims:write", "claims:admin"]);
    let (status, body) = promote(addr, &token, h).await;
    assert_eq!(
        status, 404,
        "a hypothesis the caller cannot read must be absent (404); body={body}"
    );

    assert_untouched(
        &promotion_state(&pool, h).await,
        "the unreadable hypothesis",
    );
}
