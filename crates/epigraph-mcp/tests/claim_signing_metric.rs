//! Backlog 953d5707: the unsigned-claim count is a queryable metric.
//! `system_stats(detailed: true)` reports `claims_signed` / `claims_unsigned`
//! next to `edges_signed` / `edges_unsigned`, over the claims the caller may
//! read, so the share of claims no server attested is visible rather than
//! tacit (HTTP claims written with no API key, packet and import writers).

mod common;

#[path = "viewer_fixture.rs"]
mod fixture;

use common::{build_test_server, first_text};
use epigraph_core::{AgentId, Claim, TenancyDecl, TruthValue};
use epigraph_crypto::{AgentSigner, ContentHasher, SignedEntity};
use epigraph_db::visibility::Viewer;
use epigraph_db::ClaimRepository;
use epigraph_mcp::types::SystemStatsParams;
use epigraph_mcp::{tools, EpiGraphMcpFull};
use sqlx::PgPool;
use uuid::Uuid;

async fn stats(server: &EpiGraphMcpFull, viewer: &Viewer) -> (i64, i64, i64) {
    let v = first_text(
        &tools::batch::system_stats(
            server,
            viewer,
            SystemStatsParams {
                detailed: Some(true),
            },
        )
        .await
        .expect("detailed stats"),
    );
    let n = |k: &str| {
        v.get(k)
            .and_then(serde_json::Value::as_i64)
            .unwrap_or_else(|| panic!("system_stats detailed must report `{k}`: {v}"))
    };
    (n("claims"), n("claims_signed"), n("claims_unsigned"))
}

/// A claim by `author`, signed by `signer` (agent `signer_id`) through the
/// repository's store gate, so the row carries a real v1 claim signature.
async fn seed_signed_claim(
    pool: &PgPool,
    author: Uuid,
    signer: &AgentSigner,
    signer_id: Uuid,
    decl: TenancyDecl,
    content: &str,
) -> Uuid {
    let mut claim = Claim::new(
        content.to_string(),
        AgentId::from_uuid(author),
        signer.public_key(),
        TruthValue::clamped(0.5),
    );
    let digest = ContentHasher::hash(content.as_bytes());
    claim.content_hash = digest;
    claim.signature = Some(signer.sign_entity(SignedEntity::Claim, &digest));
    let mut conn = pool.acquire().await.expect("acquire");
    let row = ClaimRepository::create_strict_signed(&mut conn, &claim, decl, Some(signer_id))
        .await
        .expect("signed claim");
    let id: Uuid = row.id.into();
    let stored: Option<Uuid> = sqlx::query_scalar("SELECT signer_id FROM claims WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("signer_id");
    assert_eq!(stored, Some(signer_id), "CALIBRATION: the row is signed");
    id
}

#[sqlx::test(migrations = "../../migrations")]
async fn detailed_stats_count_signed_and_unsigned_claims_for_the_caller(pool: PgPool) {
    let signer = AgentSigner::from_bytes(&[0x95; 32]).expect("signer");
    let (s, _) = fixture::seed_agent_with_group(&pool, "claim-metric-signer").await;
    sqlx::query("UPDATE agents SET public_key = $2 WHERE id = $1")
        .bind(s)
        .bind(signer.public_key().as_slice())
        .execute(&pool)
        .await
        .expect("register the signer's key");
    let (w, w_group) = fixture::seed_agent_with_group(&pool, "claim-metric-writer").await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "claim-metric-stranger").await;
    let w_viewer = Viewer::resolve(&pool, w).await.expect("viewer");
    let s_viewer = Viewer::resolve(&pool, stranger).await.expect("viewer");
    let server = build_test_server(pool.clone());

    let (w_all0, w_signed0, w_unsigned0) = stats(&server, &w_viewer).await;
    let (s_all0, s_signed0, s_unsigned0) = stats(&server, &s_viewer).await;

    // Public: one signed, one unsigned. Group-private to `w`: one signed, two
    // unsigned.
    seed_signed_claim(
        &pool,
        w,
        &signer,
        s,
        TenancyDecl::public(w_group),
        "claim metric: signed public",
    )
    .await;
    fixture::seed_public_claim(&pool, w, "claim metric: unsigned public").await;
    seed_signed_claim(
        &pool,
        w,
        &signer,
        s,
        TenancyDecl::group(w_group),
        "claim metric: signed private",
    )
    .await;
    fixture::seed_group_claim(&pool, w, w_group, "claim metric: unsigned private 1").await;
    fixture::seed_group_claim(&pool, w, w_group, "claim metric: unsigned private 2").await;

    assert_eq!(
        stats(&server, &w_viewer).await,
        (w_all0 + 5, w_signed0 + 2, w_unsigned0 + 3),
        "the writer counts its public and its group-private claims"
    );
    assert_eq!(
        stats(&server, &s_viewer).await,
        (s_all0 + 2, s_signed0 + 1, s_unsigned0 + 1),
        "a stranger counts the public claims and not the private ones"
    );
}
