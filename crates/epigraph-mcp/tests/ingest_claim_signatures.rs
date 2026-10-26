//! Backlog `4ff87716`: `ingest_document` and `ingest_document_spine` sign every
//! claim they write (v1, ruling R-34) and STORE that signature, so
//! `verify_claim` reports an ingested claim signed and valid.
//!
//! Before the fix both walks computed the claim signature and dropped it: the
//! document-scoped nodes (thesis, sections, paragraphs) are written by
//! `ClaimRepository::create_with_id_if_absent_conn` and the content-addressed
//! atoms by `ClaimRepository::create_conn`, and neither INSERT carried
//! `signature` / `signer_id`. Both classes are checked, per tool.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;

use common::{build_scoped_test_server, build_test_server};
use epigraph_crypto::{AgentSigner, SignatureScheme, SignatureVerifier, SignedEntity};
use epigraph_mcp::tools::claims::verify_claim;
use epigraph_mcp::types::VerifyClaimParams;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

/// The key every `build_scoped_test_server` signs with.
fn server_key() -> [u8; 32] {
    AgentSigner::from_bytes(&[0xA7u8; 32])
        .expect("signer")
        .public_key()
}

fn extraction(tag: &str) -> epigraph_ingest::schema::DocumentExtraction {
    serde_json::from_value(serde_json::json!({
        "source": {
            "title": format!("4ff87716 {tag}: Stored Claim Signatures"),
            "doi": format!("10.9999/4ff87716-{tag}"),
            "source_type": "Paper",
            "authors": [{"name": "Alice Author", "affiliations": [], "roles": ["author"]}]
        },
        "thesis": format!("4ff87716 {tag}: an ingested claim carries its stored signature."),
        "thesis_derivation": "TopDown",
        "sections": [{
            "title": "Methods",
            "paragraphs": [{
                "text": format!("4ff87716 {tag}: the walk stores what it signs."),
                "atoms": [format!("4ff87716 {tag}: an atom is signed and stored.")],
                "generality": [1],
                "confidence": 0.9
            }]
        }],
        "relationships": []
    }))
    .expect("fixture parses")
}

async fn verify(pool: &PgPool, claim: Uuid) -> Value {
    let author: Uuid = sqlx::query_scalar("SELECT agent_id FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("claim");
    let viewer = epigraph_db::visibility::Viewer::resolve(pool, author)
        .await
        .expect("viewer");
    let out = verify_claim(
        &build_test_server(pool.clone()),
        &viewer,
        VerifyClaimParams {
            claim_id: claim.to_string(),
        },
    )
    .await
    .expect("verify_claim");
    common::first_text(&out)
}

/// Every claim the walk wrote at `levels` is stored with a v1 claim signature
/// by the server key over its stored digest, recorded against the server's
/// signer agent, and `verify_claim` reports it signed, valid, `v1`. At least
/// one row per class, so the check cannot pass vacuously.
async fn assert_stored_and_verifying(pool: &PgPool, tool: &str, levels: &[i32]) {
    let rows: Vec<(Uuid, i32, Vec<u8>, Option<Vec<u8>>, Option<Uuid>)> = sqlx::query_as(
        "SELECT id, (properties->>'level')::int, content_hash, signature, signer_id \
           FROM claims WHERE properties ? 'level' ORDER BY 2",
    )
    .fetch_all(pool)
    .await
    .expect("claims");
    let signer_agent: Uuid = sqlx::query_scalar("SELECT id FROM agents WHERE public_key = $1")
        .bind(server_key().as_slice())
        .fetch_one(pool)
        .await
        .expect("the server's signer agent");
    for level in levels {
        assert!(
            rows.iter().any(|r| r.1 == *level),
            "{tool}: no claim at level {level} to check: {rows:?}"
        );
    }
    for (id, level, hash, signature, signer_id) in rows {
        let Some(signature) = signature else {
            panic!("{tool}: level-{level} claim {id} was stored without its signature");
        };
        let hash: [u8; 32] = hash.try_into().expect("32-byte digest");
        let signature: [u8; 64] = signature.try_into().expect("64-byte signature");
        assert_eq!(
            SignatureVerifier::verify_entity(&server_key(), SignedEntity::Claim, &hash, &signature)
                .unwrap(),
            Some(SignatureScheme::V1),
            "{tool}: level-{level} claim {id} does not carry a v1 claim signature"
        );
        assert_eq!(
            signer_id,
            Some(signer_agent),
            "{tool}: level-{level} claim {id}"
        );
        let resp = verify(pool, id).await;
        assert_eq!(
            (
                resp["signed"].clone(),
                resp["signature_valid"].clone(),
                resp["signature_scheme"].clone(),
            ),
            (Value::Bool(true), Value::Bool(true), Value::from("v1")),
            "{tool}: verify_claim on level-{level} claim {id}: {resp}"
        );
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn ingest_document_stores_a_verifying_v1_signature_on_every_claim(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    epigraph_mcp::tools::ingestion::do_ingest_document(
        &server,
        &viewer,
        &extraction("document"),
        None,
    )
    .await
    .expect("document ingests");
    assert_stored_and_verifying(&pool, "ingest_document", &[0, 1, 2, 3]).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn ingest_document_spine_stores_a_verifying_v1_signature_on_every_claim(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    epigraph_mcp::tools::ingestion::do_ingest_document_spine(
        &server,
        &viewer,
        &extraction("spine"),
        None,
    )
    .await
    .expect("spine ingests");
    // The spine writes levels 0-2 only; its atoms come later, through
    // `ingest_document_inline`.
    assert_stored_and_verifying(&pool, "ingest_document_spine", &[0, 1, 2]).await;
}

/// A dedup hit writes nothing onto the existing row: an atom that converges
/// onto a claim already in the graph (another writer's, unsigned) leaves that
/// row's `signature` / `signer_id` as they were. Regression guard for the fix,
/// which must sign only rows the walk INSERTS.
#[sqlx::test(migrations = "../../migrations")]
async fn a_converged_atom_is_not_signed_over(pool: PgPool) {
    let other = common::seed_agent(&pool).await;
    let atom = "4ff87716 converge: an atom is signed and stored.";
    let existing = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, labels, \
                             is_current, properties) \
         VALUES ($1, $2, $3, 0.5, $4, ARRAY[]::text[], true, '{}'::jsonb)",
    )
    .bind(existing)
    .bind(atom)
    .bind(epigraph_crypto::ContentHasher::hash(atom.as_bytes()).as_slice())
    .bind(other)
    .execute(&pool)
    .await
    .expect("seed the existing atom");

    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    epigraph_mcp::tools::ingestion::do_ingest_document(
        &server,
        &viewer,
        &extraction("converge"),
        None,
    )
    .await
    .expect("document ingests");

    let (signature, signer_id): (Option<Vec<u8>>, Option<Uuid>) =
        sqlx::query_as("SELECT signature, signer_id FROM claims WHERE id = $1")
            .bind(existing)
            .fetch_one(&pool)
            .await
            .expect("existing atom");
    assert_eq!(
        (signature, signer_id),
        (None, None),
        "the walk signed a row it did not write"
    );
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM claims WHERE content = $1")
        .bind(atom)
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(
        n, 1,
        "calibration: the atom converged onto the existing row"
    );
}
