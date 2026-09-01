//! Transport-parity tests for `require_owner_or_admin`'s no-`AuthContext` arm.
//!
//! These call the ownership-gated tools themselves (`supersede_claim`,
//! `mark_duplicate`) so the REAL gate runs. `tools::supersede`'s in-module
//! `mod tests` deliberately does not: it reimplements the policy as a local
//! `check_ownership` helper because it has no pool, so those tests would keep
//! passing if the gate were deleted. Anything asserting the gate's actual
//! behavior belongs here.
//!
//! ## What is under test
//!
//! Over a transport with no `AuthContext` (stdio), the gate falls back to
//! comparing the claim's author against the server's own signer agent. That is
//! a real ownership policy when the operator DECLARED the signer
//! (`--agent-key` / `--agent-model`, `select_signer` rungs 1-3) and an
//! undecidable comparison when they did not (rung 4: a fresh random keypair
//! per process, registered as an `agents` row that has authored nothing).
//!
//! Observed in production before the fix — a stdio `supersede_claim` against a
//! claim owned by another agent:
//!
//! ```text
//! MCP error -32602: claim is owned by agent bfe4de51-…; caller agent
//! b314df09-… cannot retire it (no AuthContext on this transport —
//! claims:admin scope only honored over HTTP)
//! ```
//!
//! `b314df09` was created at that process's start and authored nothing, so no
//! claim could ever have satisfied the comparison, and the remedy the message
//! named was unreachable from stdio.
//!
//! The two arms must stay distinguishable, which is why the declared-signer
//! denial is asserted alongside the undeclared-signer grant: without it, this
//! file could not tell a narrow fix from a blanket "stdio may do anything".

use epigraph_core::ClaimId;
use epigraph_db::ClaimRepository;
use epigraph_mcp::tools::claims::resolve_backlog_item;
use epigraph_mcp::tools::supersede::{mark_duplicate, supersede_claim};
use epigraph_mcp::types::{MarkDuplicateParams, ResolveBacklogItemParams, SupersedeClaimParams};
use sqlx::PgPool;
use uuid::Uuid;

mod common;
use common::{build_test_server, build_test_server_generated_signer};

/// The reported defect. Rung-4 signer + no `AuthContext` + a claim owned by
/// another agent: the supersede must go through, and must actually land
/// (`is_current` flipped, `supersedes` populated) rather than merely returning
/// Ok.
#[sqlx::test(migrations = "../../migrations")]
async fn generated_signer_permits_cross_agent_supersede_without_auth(pool: PgPool) {
    let server = build_test_server_generated_signer(pool.clone());

    let foreign_agent = seed_agent_row(&pool).await;
    let foreign_claim = seed_claim(&pool, foreign_agent).await;

    supersede_claim(
        &server,
        SupersedeClaimParams {
            claim_id: foreign_claim.as_uuid().to_string(),
            content: "replacement authored on an unauthenticated transport".to_string(),
            truth_value: 0.7,
            reason: "stale cross-agent claim retired by a stdio agent".to_string(),
        },
        None,
    )
    .await
    .expect("rung-4 signer must not be refused: its owner-equality check is undecidable");

    let (is_current,): (bool,) = sqlx::query_as("SELECT is_current FROM claims WHERE id = $1")
        .bind(foreign_claim.as_uuid())
        .fetch_one(&pool)
        .await
        .expect("re-read superseded claim");
    assert!(
        !is_current,
        "the supersede must have committed, not just passed the gate"
    );
}

/// `mark_duplicate` shares the gate, so it must move in lockstep. Asserted
/// separately because the two tools call `require_owner_or_admin` from
/// different call sites and a fix applied to only one would leave cross-agent
/// dedup blocked while supersede worked.
#[sqlx::test(migrations = "../../migrations")]
async fn generated_signer_permits_cross_agent_mark_duplicate_without_auth(pool: PgPool) {
    let server = build_test_server_generated_signer(pool.clone());

    let foreign_agent = seed_agent_row(&pool).await;
    let duplicate = seed_claim(&pool, foreign_agent).await;
    let canonical = seed_claim(&pool, foreign_agent).await;

    mark_duplicate(
        &server,
        MarkDuplicateParams {
            claim_id: duplicate.as_uuid().to_string(),
            canonical_id: canonical.as_uuid().to_string(),
            reason: Some("cross-agent dedup from a stdio agent".to_string()),
        },
        None,
    )
    .await
    .expect("rung-4 signer must not be refused for mark_duplicate either");

    let (is_current,): (bool,) = sqlx::query_as("SELECT is_current FROM claims WHERE id = $1")
        .bind(duplicate.as_uuid())
        .fetch_one(&pool)
        .await
        .expect("re-read duplicate");
    assert!(!is_current, "the dedup must have committed");
}

/// The third caller of the gate, and the one agents hit most: the repo's
/// backlog convention mandates `resolve_backlog_item` for retiring a backlog
/// claim. Enumerated explicitly rather than assumed to follow from the other
/// two — it reaches `require_owner_or_admin` from its own call site in
/// `tools::claims`, and a fix applied at only two of three sites would leave
/// the mandated verb blocked.
#[sqlx::test(migrations = "../../migrations")]
async fn generated_signer_permits_cross_agent_backlog_retirement_without_auth(pool: PgPool) {
    let server = build_test_server_generated_signer(pool.clone());

    let foreign_agent = seed_agent_row(&pool).await;
    let foreign_claim = seed_backlog_claim(&pool, foreign_agent).await;

    resolve_backlog_item(
        &server,
        ResolveBacklogItemParams {
            original_id: foreign_claim.as_uuid().to_string(),
            resolution_content: "retired by a stdio agent with no declared signer".to_string(),
            methodology: None,
        },
        None,
    )
    .await
    .expect("rung-4 signer must not be refused for resolve_backlog_item either");

    // Assert against the DB, not the response body: retirement is label-side,
    // and the point is that the ORIGINAL row was actually patched.
    let labels = ClaimRepository::get_labels(&pool, foreign_claim)
        .await
        .expect("get_labels");
    assert!(
        labels.contains(&"resolved".to_string()),
        "the original backlog claim must carry 'resolved' after retirement: {labels:?}"
    );
}

/// The blast-radius bound. A server whose signer WAS declared keeps enforcing
/// owner-equality on the same no-`AuthContext` transport — this is the
/// behavior prod's `--agent-key`-carrying processes rely on, and its absence
/// would make the change a blanket grant rather than a narrow one.
#[sqlx::test(migrations = "../../migrations")]
async fn declared_signer_still_denies_cross_agent_supersede_without_auth(pool: PgPool) {
    let server = build_test_server(pool.clone());

    let foreign_agent = seed_agent_row(&pool).await;
    let foreign_claim = seed_claim(&pool, foreign_agent).await;

    let err = supersede_claim(
        &server,
        SupersedeClaimParams {
            claim_id: foreign_claim.as_uuid().to_string(),
            content: "must not be written".to_string(),
            truth_value: 0.7,
            reason: "should be refused".to_string(),
        },
        None,
    )
    .await
    .expect_err("a declared signer must still enforce owner-equality");

    let msg = err.message.to_string();
    assert!(
        msg.contains("declared signer identity"),
        "the denial must name the condition that produced it, so an operator can act on it \
         (the old text pointed at claims:admin-over-HTTP, unreachable from stdio): {msg:?}"
    );

    let (is_current,): (bool,) = sqlx::query_as("SELECT is_current FROM claims WHERE id = $1")
        .bind(foreign_claim.as_uuid())
        .fetch_one(&pool)
        .await
        .expect("re-read refused claim");
    assert!(
        is_current,
        "a refused supersede must not have written anything"
    );
}

/// A rung-4 server must still not become a general free-for-all elsewhere:
/// when an `AuthContext` IS present, the admin/principal policy governs and
/// the undeclared-signer arm is never reached. Without this, the grant could
/// leak into the authenticated HTTP path, where a real principal exists and
/// owner-equality is enforceable.
#[sqlx::test(migrations = "../../migrations")]
async fn generated_signer_does_not_relax_the_authenticated_path(pool: PgPool) {
    use epigraph_auth::{AuthContext, ClientType};

    let server = build_test_server_generated_signer(pool.clone());

    let foreign_agent = seed_agent_row(&pool).await;
    let foreign_claim = seed_claim(&pool, foreign_agent).await;

    // Authenticated, but neither admin nor the owner.
    let auth = AuthContext {
        client_id: Uuid::new_v4(),
        agent_id: None,
        owner_id: Some(Uuid::new_v4()),
        client_type: ClientType::Service,
        scopes: vec!["claims:write".to_string()],
        jti: Uuid::new_v4(),
    };

    let err = supersede_claim(
        &server,
        SupersedeClaimParams {
            claim_id: foreign_claim.as_uuid().to_string(),
            content: "must not be written".to_string(),
            truth_value: 0.7,
            reason: "should be refused".to_string(),
        },
        Some(&auth),
    )
    .await
    .expect_err("an authenticated non-owner without claims:admin must still be denied");

    assert!(
        err.message.to_string().contains("claims:admin"),
        "the authenticated denial must keep citing the scope it needs: {:?}",
        err.message
    );
}

async fn seed_agent_row(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    // Unique-per-id public key so it cannot collide with the server signer's.
    let pk: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING")
        .bind(id)
        .bind(&pk)
        .execute(pool)
        .await
        .expect("seed foreign agent");
    id
}

async fn seed_claim(pool: &PgPool, agent_id: Uuid) -> ClaimId {
    seed_claim_with_labels(pool, agent_id, &[]).await
}

async fn seed_backlog_claim(pool: &PgPool, agent_id: Uuid) -> ClaimId {
    seed_claim_with_labels(pool, agent_id, &["backlog"]).await
}

async fn seed_claim_with_labels(pool: &PgPool, agent_id: Uuid, labels: &[&str]) -> ClaimId {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id
        .as_bytes()
        .iter()
        .copied()
        .chain(std::iter::repeat(0).take(16))
        .take(32)
        .collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, \
                             labels, is_current, supersedes) \
         VALUES ($1, $2, $3, 0.5, $4, $5, true, NULL)",
    )
    .bind(id)
    .bind(format!("foreign claim {id}"))
    .bind(hash)
    .bind(agent_id)
    .bind(labels.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    .execute(pool)
    .await
    .expect("seed foreign claim");
    ClaimId::from_uuid(id)
}
