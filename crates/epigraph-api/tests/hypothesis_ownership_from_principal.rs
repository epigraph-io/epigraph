#![cfg(feature = "db")]
//! `POST /api/v1/hypothesis` derives `claims.owner_group_id` from the
//! AUTHENTICATED PRINCIPAL, not from the `agent_id` in the request body.
//!
//! `routes/claims.rs::create_claim` made this move already; this handler could
//! not, because it held no principal at all. It does now, so the divergence
//! closes and the two write paths agree on where ownership comes from.
//!
//! # What this does NOT assert, deliberately
//!
//! `claims.agent_id` still comes from the body, and a mismatch is still
//! accepted rather than refused. That is a separate, still-open question with
//! its own entry (`D-PR16-claim-authorship-is-not-a-credential`) and a live
//! in-repo consumer that constrains any answer; `routes/claims.rs::create_claim`
//! carries the standing determination. The test below pins the authorship field
//! as UNCHANGED so that a future PR which does decide it cannot do so silently
//! here.
//!
//! # Side effect, stated rather than hidden
//!
//! These tests run against the shared `DATABASE_URL` database rather than
//! `#[sqlx::test]`, and `ensure_hypothesis_frame` inserts a permanent
//! `hypothesis_assessment` frame row that no migration seeds. It is
//! `ON CONFLICT (name) DO NOTHING`, so it is idempotent, but it does survive the
//! run: a future assertion over `frames` contents or counts would be
//! order-dependent on whether this binary ran first. The handler looks the frame
//! up by that literal name, so a per-run unique name is not available.

mod common;

use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

/// A frame named `hypothesis_assessment` must exist — the handler binds the new
/// claim to it. Declared `('public', <world>)`, which is what an instance-wide
/// registry row carries.
async fn ensure_hypothesis_frame(pool: &sqlx::PgPool) {
    sqlx::query(
        "INSERT INTO frames (name, hypotheses, visibility, owner_group_id) \
         VALUES ('hypothesis_assessment', ARRAY['true','false'], 'public', \
                 '00000000-0000-0000-0000-000000000000'::uuid) \
         ON CONFLICT (name) DO NOTHING",
    )
    .execute(pool)
    .await
    .expect("seed hypothesis_assessment frame");
}

async fn seed_agent(pool: &sqlx::PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let pk: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'system') \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(id)
    .bind(&pk)
    .execute(pool)
    .await
    .expect("seed agent");
    id
}

/// The control, asserted as an EFFECT on the stored row rather than as a status
/// code: a caller authenticated as A, naming B as the author, produces a claim
/// owned by A's group.
///
/// Both directions in one row, because the failure modes are opposite: owning
/// it from the BODY lets a caller place rows in a group it is not a member of,
/// and owning it from nowhere at all would break the write outright.
#[tokio::test(flavor = "multi_thread")]
async fn hypothesis_ownership_comes_from_the_token_not_the_body() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    ensure_hypothesis_frame(&pool).await;

    let caller = seed_agent(&pool).await;
    let claimed_author = seed_agent(&pool).await;
    let caller_group = common::personal_group_of(&pool, caller).await;
    let author_group = common::personal_group_of(&pool, claimed_author).await;
    assert_ne!(
        caller_group, author_group,
        "the fixture must give the two principals different groups, or this test \
         cannot distinguish the two derivations"
    );

    let (addr, _shutdown) = common::spawn_app_with_mock_embedding(&url).await;

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/hypothesis"))
        .bearer_auth(common::mint_token_with_agent(&["claims:write"], caller))
        .json(&serde_json::json!({
            "statement": format!("HYP ownership probe {}", Uuid::new_v4()),
            "research_question": "does ownership follow the token?",
            "agent_id": claimed_author.to_string(),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "the write itself must still succeed");
    let body: serde_json::Value = resp.json().await.unwrap();
    let hypothesis_id: Uuid = body
        .get("hypothesis_id")
        .and_then(|v| v.as_str())
        .expect("hypothesis_id in the response")
        .parse()
        .unwrap();

    let (agent_id, owner_group_id, visibility): (Uuid, Uuid, String) =
        sqlx::query_as("SELECT agent_id, owner_group_id, visibility FROM claims WHERE id = $1")
            .bind(hypothesis_id)
            .fetch_one(&pool)
            .await
            .expect("the hypothesis claim was written");

    assert_eq!(
        owner_group_id, caller_group,
        "the row must be owned by the AUTHENTICATED caller's group"
    );
    assert_ne!(
        owner_group_id, author_group,
        "an unauthenticated body field must not decide which group owns the row"
    );
    assert_eq!(
        visibility, "public",
        "the visibility half is unchanged — this is about ownership, not disclosure"
    );
    assert_eq!(
        agent_id, claimed_author,
        "authorship still comes from the body and is deliberately NOT decided here; \
         see the module header"
    );
}

/// A tokenless request never reaches the derivation at all.
///
/// The route is on the protected router, so this is belt-and-braces — but the
/// extractor is what makes the handler's principal non-optional, and an
/// `Option<..>` regression would show up here rather than in the test above,
/// which is authenticated throughout.
#[tokio::test(flavor = "multi_thread")]
async fn hypothesis_without_a_token_is_refused() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app_with_mock_embedding(&url).await;

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/hypothesis"))
        .json(&serde_json::json!({
            "statement": "HYP anonymous probe",
            "agent_id": Uuid::new_v4().to_string(),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

/// A token that AUTHENTICATES but carries no `agent_id` is refused too — the
/// extractor's SECOND rejection branch, which the tokenless test above cannot
/// reach.
///
/// This is a real population, not a hypothetical: `middleware/bearer.rs` names
/// it — "An OAuth client registered before PR-02 populated
/// `oauth_clients.agent_id` mints exactly this token." Such a caller used to get
/// a 200 from this route, because the handler read its author from the body and
/// needed no principal. It now gets a 401, and the remedy is re-minting the
/// token. Both branches are pinned so that making the principal optional again
/// — the regression that would silently restore body-derived ownership — fails
/// here rather than in production.
#[tokio::test(flavor = "multi_thread")]
async fn hypothesis_with_a_principal_less_token_is_refused() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app_with_mock_embedding(&url).await;

    let secret = std::env::var("EPIGRAPH_JWT_SECRET")
        .unwrap_or_else(|_| "epigraph-dev-secret-change-in-production!!".to_string());
    let cfg = epigraph_api::oauth::JwtConfig::from_secret(secret.as_bytes());
    let (token, _jti) = cfg
        .issue_access_token(
            Uuid::new_v4(),
            vec!["claims:write".to_string()],
            "service",
            None,
            // The whole point of the fixture: a structurally valid token with
            // no principal bound to it.
            None,
            chrono::Duration::minutes(60),
        )
        .expect("test JWT issued");

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/hypothesis"))
        .bearer_auth(token)
        .json(&serde_json::json!({
            "statement": "HYP principal-less probe",
            "agent_id": Uuid::new_v4().to_string(),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        401,
        "a token with no agent_id has no principal to own the row, and the \
         handler must refuse rather than fall back to the body"
    );
}

// ── The VOI neighborhood is read through the viewer ───────────────────────

/// Seed a GROUNDED claim: one with a `paper -> claim` provenance edge, which is
/// the only kind `create_hypothesis`'s neighborhood scan counts.
async fn seed_grounded_claim(
    pool: &sqlx::PgPool,
    author: Uuid,
    content: &str,
    pgvec: &str,
    owner: Option<Uuid>,
) -> Uuid {
    let (visibility, group): (&str, Uuid) = match owner {
        Some(g) => ("group", g),
        None => ("public", Uuid::nil()),
    };
    let claim: Uuid = sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current, \
                             embedding, visibility, owner_group_id) \
         VALUES ($1, sha256($1::bytea), 0.8, $2, true, $3::vector, $4, $5) RETURNING id",
    )
    .bind(content)
    .bind(author)
    .bind(pgvec)
    .bind(visibility)
    .bind(group)
    .fetch_one(pool)
    .await
    .expect("seed grounded claim");

    let paper: Uuid = sqlx::query_scalar(
        "INSERT INTO papers (id, doi, title) \
         VALUES (gen_random_uuid(), '10.voi/' || gen_random_uuid()::text, 'voi fixture') \
         RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("seed paper");
    let edge: Uuid = sqlx::query_scalar(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         VALUES (gen_random_uuid(), $1, 'paper', $2, 'claim', 'asserts') RETURNING id",
    )
    .bind(paper)
    .bind(claim)
    .fetch_one(pool)
    .await
    .expect("seed grounding edge");

    // THE GROUNDING EDGE IS FORCED PUBLIC, AND THAT IS WHAT MAKES THE PLANT
    // DISCRIMINATING. Migration 070 makes an edge inherit its endpoints'
    // tenancy, so a private claim's edge is private too — and the edge
    // predicate alone would then exclude the neighbour, whatever the `claims`
    // predicate did. Left that way, the test would pass with the `claims`
    // filter removed, which is the "assertion that cannot fail on its subject"
    // this suite keeps rejecting. With the edge public, the only thing that can
    // exclude the private claim is the predicate on `claims`.
    sqlx::query(
        "UPDATE edges SET visibility = 'public', \
         owner_group_id = '00000000-0000-0000-0000-000000000000'::uuid WHERE id = $1",
    )
    .bind(edge)
    .execute(pool)
    .await
    .expect("force the grounding edge public");
    claim
}

/// `neighborhood_size` and the `voi` object are aggregates over a scan of
/// `claims`, and the caller controls both the statement and the radius. The scan
/// is now viewer-filtered, so a claim private to a group the caller is not in
/// does not move those numbers.
///
/// Asserted as an EFFECT on the returned aggregate, not as a status code, and
/// with the positive leg on the SAME request: a public grounded neighbour with
/// the identical vector IS counted. Over-suppression here would be invisible —
/// a VOI score computed over nothing still returns 200.
#[tokio::test(flavor = "multi_thread")]
async fn hypothesis_voi_neighborhood_excludes_claims_the_caller_cannot_read() {
    use epigraph_embeddings::{EmbeddingConfig, EmbeddingService, MockProvider};

    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    ensure_hypothesis_frame(&pool).await;

    let caller = seed_agent(&pool).await;
    let stranger = seed_agent(&pool).await;
    let stranger_group = common::personal_group_of(&pool, stranger).await;
    let caller_group = common::personal_group_of(&pool, caller).await;
    assert_ne!(
        caller_group, stranger_group,
        "precondition: the caller must not be a member of the group that owns the \
         private neighbour"
    );

    // The statement is unique per run, so its vector collides with nothing this
    // test (or any earlier run of it) left in the shared database. The two
    // neighbours are seeded with the EXACT vector the handler will embed, so
    // both sit at similarity 1.0 and a radius of 0.99 admits them and nothing
    // else.
    let statement = format!("VOI viewer-scope probe {}", Uuid::new_v4());
    let embedder = MockProvider::new(EmbeddingConfig::openai(1536));
    let vector = embedder.generate(&statement).await.expect("mock embed");
    let pgvec = format!(
        "[{}]",
        vector
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join(",")
    );

    let visible = seed_grounded_claim(
        &pool,
        caller,
        &format!("{statement} :: public neighbour"),
        &pgvec,
        None,
    )
    .await;
    let hidden = seed_grounded_claim(
        &pool,
        stranger,
        &format!("{statement} :: private neighbour"),
        &pgvec,
        Some(stranger_group),
    )
    .await;

    let (addr, _shutdown) = common::spawn_app_with_mock_embedding(&url).await;
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/hypothesis"))
        .bearer_auth(common::mint_token_with_agent(&["claims:write"], caller))
        .json(&serde_json::json!({
            "statement": statement,
            "search_radius": 0.99,
            "agent_id": caller.to_string(),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();

    assert_eq!(
        body["neighborhood_size"].as_u64(),
        Some(1),
        "the private neighbour must not be counted, and the public one must be: \
         got {body}"
    );
    assert_eq!(
        body["voi"]["neighbor_count"].as_u64(),
        Some(1),
        "the VOI aggregate is derived from the same rows and must agree"
    );

    // Named so a reader can find them in the fixture; the assertion above is the
    // property, and these keep the seeds from being optimised out of the story.
    let _ = (visible, hidden);
}
