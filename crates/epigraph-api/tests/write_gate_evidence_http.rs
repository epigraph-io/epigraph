#![cfg(feature = "db")]
//! **The route→repo hop of the write gate, observed instead of grepped**
//! (PR-16, delivered as 16b).
//!
//! # Why this file exists when `write_gate_evidence_update.rs` already passes
//!
//! That file proves the mechanism: it applies a real single-token mutation to
//! `EvidenceRepository::update_raw_content`, runs real SQL, and fails in the
//! exfiltration direction. What it cannot prove is that the viewer reaching that
//! function over HTTP is the **caller's** viewer. Between the request and the
//! repo call sit the extractor, the router chain and the handler, and until this
//! file the only thing asserting that hop was
//! `viewer_route_table_lint.rs::update_evidence_routes_through_the_gated_repo_fn`
//! — a **source-text** check that the handler names the gated function. A
//! name-grep cannot distinguish `update_raw_content(&state.db_pool, &viewer, ..)`
//! from the same call passing some other viewer, and it is the difference
//! between a well-tested library function and a production control.
//!
//! # The 404-not-403 mapping had NO behavioral witness at all
//!
//! `update_raw_content` returns `Ok(false)` for both "no such evidence" and "you
//! may not write this evidence", deliberately, and the handler maps that to 404
//! because a 403 would confirm that evidence with this id exists inside a group
//! the caller cannot write to. That is a **disclosure control**, and it was
//! asserted in a doc comment and nowhere else — which is precisely the shape
//! this PR exists to reject. A doc comment claiming a security property is the
//! same defect class as `PolicyGate::authorize`, one level down.
//!
//! # The discriminating pair
//!
//! A negative alone would pass over a route that is simply broken — a 404 is
//! also what a handler returns when it 404s everything. So:
//!
//! * **Negative:** a principal holding `reader` in the owning group PUTs and
//!   gets **404** — not 403, not 200 — and the row is byte-unchanged.
//! * **Positive:** the SAME principal, the SAME request shape, against a row in
//!   a group where it holds `admin`, gets **200** and the row DID change.
//!
//! One principal, one token, one route, two rows. The only variable is the role
//! the principal holds in the owning group, which is exactly the variable the
//! write predicate reads.

mod common;

#[path = "viewer_fixture.rs"]
mod fixture;

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;

/// Evidence owned by `group`, with the tenancy columns set explicitly.
///
/// `visibility` is `'group'` on both the claim and the evidence: this file is
/// about the role the principal holds, and a `public` row would introduce a
/// second variable. The public-disjunct fail-open has its own row-level witness
/// in `epigraph-db/tests/write_gate_evidence_update.rs`.
async fn seed_group_evidence(pool: &PgPool, author: Uuid, group: Uuid, body: &str) -> Uuid {
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
    .bind(format!("write-gate http claim {claim_id}"))
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
         VALUES ($1, $2, 'document', $3, $4, $5, 'group')",
    )
    .bind(evidence_id)
    .bind(&ev_hash)
    .bind(body)
    .bind(claim_id)
    .bind(group)
    .execute(pool)
    .await
    .expect("seed evidence");

    evidence_id
}

async fn raw_content_of(pool: &PgPool, id: Uuid) -> Option<String> {
    sqlx::query_scalar("SELECT raw_content FROM evidence WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("read back raw_content")
}

/// The asymmetric world, built over HTTP-visible primitives.
struct Http {
    pool: PgPool,
    addr: std::net::SocketAddr,
    _shutdown: tokio::sync::oneshot::Sender<()>,
    token: String,
    /// The one principal every case below authenticates as.
    principal: Uuid,
    /// Owned by a group the principal holds `reader` in.
    ev_readable: Uuid,
    /// Owned by a group the principal holds `admin` in.
    ev_writable: Uuid,
}

const SEEDED_R: &str = "http seed, read-only group";
const SEEDED_W: &str = "http seed, writable group";

async fn setup() -> Http {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .expect("connect");

    // `seed_agent_with_group` mirrors production's `ensure_personal_group` and
    // gives the principal an `admin` membership — the writable half.
    let (principal, own_group) = fixture::seed_agent_with_group(&pool, "wg-http-principal").await;
    let (author, other_group) = fixture::seed_agent_with_group(&pool, "wg-http-author").await;

    // The read-only half: a SECOND membership, role `reader`. This is the whole
    // fixture. Without it the principal's readable and writable sets are equal
    // and the negative case below cannot distinguish a write gate from a read
    // gate — the same asymmetry `write_gate_evidence_update.rs` documents at
    // length, re-established here at the HTTP layer.
    // A plain INSERT, no `ON CONFLICT`: both the agent and the group were minted
    // by the calls above, so this pairing cannot already exist. (The live-row
    // uniqueness here is on `(group_id, agent_id)` filtered to unrevoked rows,
    // with the full constraint on `(group_id, agent_id, epoch)` — an `ON
    // CONFLICT (group_id, agent_id)` does not name either and errors 42P10.)
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'reader')",
    )
    .bind(other_group)
    .bind(principal)
    .execute(&pool)
    .await
    .expect("seed reader membership");

    let ev_readable = seed_group_evidence(&pool, author, other_group, SEEDED_R).await;
    let ev_writable = seed_group_evidence(&pool, principal, own_group, SEEDED_W).await;

    let (addr, shutdown) = common::spawn_app(&url).await;

    Http {
        pool,
        addr,
        _shutdown: shutdown,
        // `evidence:write` is granted. The scope check is NOT the control under
        // test here — a scope-refused request would 403 before the predicate ran
        // and would prove nothing about tenancy.
        token: common::mint_token_with_agent(&["evidence:write", "claims:read"], principal),
        principal,
        ev_readable,
        ev_writable,
    }
}

async fn put_raw_content(h: &Http, id: Uuid, body: &str) -> reqwest::Response {
    reqwest::Client::new()
        .put(format!("http://{}/api/v1/evidence/{id}", h.addr))
        .bearer_auth(&h.token)
        .json(&serde_json::json!({ "raw_content": body }))
        .send()
        .await
        .expect("PUT /api/v1/evidence/:id")
}

/// **The fixture's premise.** Run this first when the pair below starts failing.
///
/// If the principal's two memberships stopped differing in role, both cases
/// below would exercise the same authority and the pair would agree for a
/// reason that has nothing to do with the gate.
#[tokio::test(flavor = "multi_thread")]
async fn the_http_principal_holds_two_roles_in_two_groups() {
    let h = setup().await;
    let roles: Vec<String> = sqlx::query_scalar(
        "SELECT role::text FROM group_memberships \
         WHERE agent_id = $1 AND revoked_at IS NULL ORDER BY role",
    )
    .bind(h.principal)
    .fetch_all(&h.pool)
    .await
    .expect("roles");

    assert_eq!(
        roles,
        vec!["admin".to_string(), "reader".to_string()],
        "the principal must hold exactly one `admin` and one `reader` \
         membership. If both are writable roles the negative case below passes \
         for no reason; if neither is, the positive case does."
    );
}

/// **The disclosure control, given a witness.** A row the caller may READ but
/// not WRITE answers 404 — not 403.
///
/// A 403 here would be a working authorization decision AND an information
/// leak: it confirms that evidence with this id exists in a group the caller
/// cannot write to. The repo function returns the same `Ok(false)` for "absent"
/// and "forbidden" precisely so the handler cannot accidentally tell them apart,
/// and this is the only assertion in the tree that observes the result.
#[tokio::test(flavor = "multi_thread")]
async fn a_reader_putting_evidence_in_a_read_only_group_gets_404_not_403() {
    let h = setup().await;

    let resp = put_raw_content(&h, h.ev_readable, "TAMPERED VIA HTTP").await;
    let status = resp.status();

    assert_ne!(
        status, 200,
        "a principal holding only `reader` in the owning group updated evidence \
         over HTTP. Either the handler is not passing the CALLER's viewer to \
         `EvidenceRepository::update_raw_content`, or the write predicate is \
         binding the read group set."
    );
    assert_ne!(
        status, 403,
        "403 confirms that evidence with this id exists inside a group the \
         caller cannot write to — the disclosure the 404 mapping exists to \
         prevent. See `update_evidence`'s doc comment."
    );
    assert_eq!(
        status, 404,
        "the refusal must be indistinguishable from `no such evidence`"
    );
    assert_eq!(
        raw_content_of(&h.pool, h.ev_readable).await.as_deref(),
        Some(SEEDED_R),
        "the row must be byte-unchanged. Asserting only on the status would \
         also pass if the handler 404'd after a successful write."
    );
}

/// **The positive direction**, without which the 404 above proves nothing.
///
/// Same principal, same token, same route, same body shape — the only
/// difference is that this row's owning group is one where the principal holds
/// `admin`. If this fails, the gate is over-suppressing, which is silent and
/// permanent in a way a leak is not: nobody files a bug saying their write
/// mysteriously succeeded.
#[tokio::test(flavor = "multi_thread")]
async fn a_writer_putting_evidence_in_its_own_group_succeeds_over_http() {
    let h = setup().await;

    let resp = put_raw_content(&h, h.ev_writable, "BACKFILLED VIA HTTP").await;
    let status = resp.status();

    assert_eq!(
        status,
        200,
        "the write gate refused a principal holding `admin` in the owning \
         group. body: {}",
        resp.text().await.unwrap_or_default()
    );
    assert_eq!(
        raw_content_of(&h.pool, h.ev_writable).await.as_deref(),
        Some("BACKFILLED VIA HTTP"),
        "a 200 that did not change the row is not a successful write"
    );
    assert_eq!(
        raw_content_of(&h.pool, h.ev_readable).await.as_deref(),
        Some(SEEDED_R),
        "the authorized write must touch ONE row. A predicate that matched the \
         whole table would still return 200 here."
    );
}
