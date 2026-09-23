#![cfg(feature = "db")]
//! **`PUT /api/v1/claims/:id/embedding` and `PUT /api/v1/evidence/:id/embedding`
//! are write-gated, seal-aware and refuse mock vectors** — observed over HTTP.
//!
//! # What these routes did before (deferred-commitment key `embed-on-write-helper`)
//!
//! Both handlers took only `State`, `Path` and `Json`. Each ran its own
//! `UPDATE <table> SET embedding = $1::vector WHERE id = $2` against the raw
//! pool and answered `stored: true` whatever the row count was. So any holder
//! of any bearer token could:
//!
//! * overwrite the vector on another tenant's claim or evidence and poison
//!   semantic recall for it;
//! * put a vector on a SEALED claim, which CLAUDE.md's audit calls a
//!   page-the-on-call condition (`sealed_with_embedding > 0`);
//! * with no provider configured, store `generate_mock_embedding`'s
//!   byte-histogram in the live ANN column.
//!
//! # The discriminating pairs
//!
//! Same construction as `write_gate_evidence_http.rs`, which this file mirrors:
//! ONE principal holding `admin` in its own group and `reader` in another, ONE
//! token, one route, and rows in both groups. A negative with no positive
//! beside it would also pass over a handler that 404s everything, so every
//! refusal below sits next to a success that differs in exactly one variable.
//! Every assertion reads the row back rather than trusting the status alone.

mod common;

#[path = "viewer_fixture.rs"]
mod fixture;

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;

/// A `visibility='group'` claim owned by `group`, with one evidence row also
/// owned by `group`. Tenancy is explicit on both inserts for the reason
/// `write_gate_evidence_http.rs::seed_group_evidence` gives.
async fn seed_group_claim_and_evidence(pool: &PgPool, author: Uuid, group: Uuid) -> (Uuid, Uuid) {
    let claim_id = Uuid::new_v4();
    let claim_hash: Vec<u8> = claim_id
        .as_bytes()
        .iter()
        .copied()
        .cycle()
        .take(32)
        .collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, owner_group_id, visibility) \
         VALUES ($1, $2, $3, $4, $5, 'group')",
    )
    .bind(claim_id)
    .bind(format!("embedding write-gate claim {claim_id}"))
    .bind(&claim_hash)
    .bind(author)
    .bind(group)
    .execute(pool)
    .await
    .expect("seed claim");

    let evidence_id = Uuid::new_v4();
    let ev_hash: Vec<u8> = evidence_id
        .as_bytes()
        .iter()
        .copied()
        .cycle()
        .take(32)
        .collect();
    sqlx::query(
        "INSERT INTO evidence \
             (id, content_hash, evidence_type, raw_content, claim_id, owner_group_id, visibility) \
         VALUES ($1, $2, 'document', 'embedding write-gate evidence', $3, $4, 'group')",
    )
    .bind(evidence_id)
    .bind(&ev_hash)
    .bind(claim_id)
    .bind(group)
    .execute(pool)
    .await
    .expect("seed evidence");

    (claim_id, evidence_id)
}

/// Seal `claim` the way the ceremony leaves it, reduced to the one row the
/// write's predicate reads: a `claim_encryption` row. The claim is
/// `visibility='group'`, so migration 081's no-public-sealed trigger admits it.
async fn seal(pool: &PgPool, claim: Uuid, group: Uuid) {
    sqlx::query(
        "INSERT INTO group_key_epochs (group_id, epoch, status) VALUES ($1, 0, 'active') \
         ON CONFLICT (group_id, epoch) DO NOTHING",
    )
    .bind(group)
    .execute(pool)
    .await
    .expect("seed key epoch");
    sqlx::query(
        "INSERT INTO claim_encryption (claim_id, group_id, epoch, privacy_tier, encrypted_content) \
         VALUES ($1, $2, 0, 'fully_private', $3)",
    )
    .bind(claim)
    .bind(group)
    .bind(vec![0xcdu8; 64])
    .execute(pool)
    .await
    .expect("seal the claim");
}

async fn claim_vector_is_null(pool: &PgPool, id: Uuid) -> bool {
    sqlx::query_scalar("SELECT embedding IS NULL FROM claims WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("read claim vector")
}

async fn evidence_vector_is_null(pool: &PgPool, id: Uuid) -> bool {
    sqlx::query_scalar("SELECT embedding IS NULL FROM evidence WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("read evidence vector")
}

struct Http {
    pool: PgPool,
    addr: std::net::SocketAddr,
    _shutdown: tokio::sync::oneshot::Sender<()>,
    principal: Uuid,
    /// Owned by a group the principal holds `reader` in.
    claim_readable: Uuid,
    ev_readable: Uuid,
    /// Owned by the principal's own group, where it holds `admin`.
    claim_writable: Uuid,
    ev_writable: Uuid,
    /// Also in the principal's own group, and sealed.
    claim_sealed: Uuid,
}

/// `with_embedding` picks the server: a configured (mock-provider) embedding
/// service, or none at all.
async fn setup(with_embedding: bool) -> Http {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .expect("connect");

    let (principal, own_group) = fixture::seed_agent_with_group(&pool, "embed-put-principal").await;
    let (author, other_group) = fixture::seed_agent_with_group(&pool, "embed-put-author").await;

    // The read-only half of the asymmetry. See write_gate_evidence_http.rs for
    // why this plain INSERT cannot conflict.
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'reader')",
    )
    .bind(other_group)
    .bind(principal)
    .execute(&pool)
    .await
    .expect("seed reader membership");

    let (claim_readable, ev_readable) =
        seed_group_claim_and_evidence(&pool, author, other_group).await;
    let (claim_writable, ev_writable) =
        seed_group_claim_and_evidence(&pool, principal, own_group).await;
    let (claim_sealed, _) = seed_group_claim_and_evidence(&pool, principal, own_group).await;
    seal(&pool, claim_sealed, own_group).await;

    let (addr, shutdown) = if with_embedding {
        common::spawn_app_with_mock_embedding(&url).await
    } else {
        common::spawn_app(&url).await
    };

    Http {
        pool,
        addr,
        _shutdown: shutdown,
        principal,
        claim_readable,
        ev_readable,
        claim_writable,
        ev_writable,
        claim_sealed,
    }
}

impl Http {
    fn token(&self, scopes: &[&str]) -> String {
        common::mint_token_with_agent(scopes, self.principal)
    }

    /// The scopes the gate is NOT under test for: both write scopes granted,
    /// so a refusal below is the row predicate and not the scope check.
    fn writer_token(&self) -> String {
        self.token(&["claims:read", "claims:write", "evidence:write"])
    }

    async fn put(&self, kind: &str, id: Uuid, token: &str) -> reqwest::Response {
        reqwest::Client::new()
            .put(format!("http://{}/api/v1/{kind}/{id}/embedding", self.addr))
            .bearer_auth(token)
            .json(&serde_json::json!({ "text": "an embeddable sentence" }))
            .send()
            .await
            .expect("PUT embedding")
    }
}

/// **Claims, the tenancy pair.** Read authority is not write authority.
#[tokio::test(flavor = "multi_thread")]
async fn a_claim_vector_is_written_only_where_the_caller_may_write() {
    let h = setup(true).await;
    let token = h.writer_token();

    let resp = h.put("claims", h.claim_readable, &token).await;
    let status = resp.status();
    assert_ne!(
        status, 200,
        "a principal holding only `reader` in the owning group wrote a claim \
         vector over HTTP"
    );
    assert_eq!(
        status, 404,
        "the refusal must be indistinguishable from `no such claim` (403 would \
         confirm the id exists in a group the caller cannot write)"
    );
    assert!(
        claim_vector_is_null(&h.pool, h.claim_readable).await,
        "the read-only group's claim must still carry no vector"
    );

    let resp = h.put("claims", h.claim_writable, &token).await;
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(
        status, 200,
        "the owner could not embed its own claim: {body}"
    );
    assert_eq!(body["stored"], true);
    assert_eq!(body["dimension"], 1536);
    assert!(
        !claim_vector_is_null(&h.pool, h.claim_writable).await,
        "a 200 that left the column NULL is not a successful write"
    );
    assert!(
        claim_vector_is_null(&h.pool, h.claim_readable).await,
        "the authorized write must touch ONE row"
    );
}

/// **Claims, the seal.** Same principal, same group, same role as the positive
/// arm above; the only difference is a `claim_encryption` row.
#[tokio::test(flavor = "multi_thread")]
async fn a_sealed_claim_gets_no_vector_and_the_same_404() {
    let h = setup(true).await;
    let token = h.writer_token();

    let resp = h.put("claims", h.claim_sealed, &token).await;
    assert_eq!(
        resp.status(),
        404,
        "a sealed claim must answer exactly what an absent one does, or the \
         route is a seal oracle"
    );
    assert!(
        claim_vector_is_null(&h.pool, h.claim_sealed).await,
        "a sealed claim carrying a vector is CLAUDE.md's sealed_with_embedding \
         violation"
    );

    // Positive control on the same server, same group, same token.
    let resp = h.put("claims", h.claim_writable, &token).await;
    assert_eq!(resp.status(), 200);
}

/// **Evidence, the tenancy pair.**
#[tokio::test(flavor = "multi_thread")]
async fn an_evidence_vector_is_written_only_where_the_caller_may_write() {
    let h = setup(true).await;
    let token = h.writer_token();

    let resp = h.put("evidence", h.ev_readable, &token).await;
    assert_eq!(
        resp.status(),
        404,
        "a `reader` in the owning group must get the absent-row answer"
    );
    assert!(evidence_vector_is_null(&h.pool, h.ev_readable).await);

    let resp = h.put("evidence", h.ev_writable, &token).await;
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(
        status, 200,
        "the owner could not embed its own evidence: {body}"
    );
    assert_eq!(body["stored"], true);
    assert!(!evidence_vector_is_null(&h.pool, h.ev_writable).await);
    assert!(evidence_vector_is_null(&h.pool, h.ev_readable).await);
}

/// **No provider, no write.** The handlers used to fall back to a mock vector
/// and store it; they now refuse with 503 and leave the column alone.
#[tokio::test(flavor = "multi_thread")]
async fn without_a_configured_provider_nothing_is_stored() {
    let h = setup(false).await;
    let token = h.writer_token();

    for (kind, id) in [("claims", h.claim_writable), ("evidence", h.ev_writable)] {
        let resp = h.put(kind, id, &token).await;
        assert_eq!(
            resp.status(),
            503,
            "PUT /{kind}/:id/embedding with no embedding service must refuse, \
             not store a mock vector"
        );
    }
    assert!(claim_vector_is_null(&h.pool, h.claim_writable).await);
    assert!(evidence_vector_is_null(&h.pool, h.ev_writable).await);
}

/// **The scope check is unconditional.** A read-only token is refused before
/// any row is touched, even on a row the principal could otherwise write.
#[tokio::test(flavor = "multi_thread")]
async fn a_token_without_a_write_scope_is_refused() {
    let h = setup(true).await;
    let token = h.token(&["claims:read"]);

    for (kind, id) in [("claims", h.claim_writable), ("evidence", h.ev_writable)] {
        let resp = h.put(kind, id, &token).await;
        assert_eq!(
            resp.status(),
            403,
            "PUT /{kind}/:id/embedding accepted a token with no write scope"
        );
    }
    assert!(claim_vector_is_null(&h.pool, h.claim_writable).await);
    assert!(evidence_vector_is_null(&h.pool, h.ev_writable).await);
}
