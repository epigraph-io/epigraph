//! End-to-end: `verify_claim` over rows written by the REAL document ingest
//! writer, not by hand-seeded SQL.
//!
//! `verify_claim`'s three-valued integrity answer classifies a row by
//! `claims.properties` (`level` + `source_type`), via
//! `epigraph_ingest::document::stored_content_hash_is_seed_scoped`. Every other
//! test of that classifier — in `verify_claim_crypto.rs` — writes those
//! properties itself, and the drift guard in `epigraph-ingest` checks
//! `PlannedClaim::properties`, i.e. the PLAN. Neither proves the plan's
//! properties reach the ROW.
//!
//! That link is not free: `persist_planned_claim` writes no properties at all,
//! and `epigraph-ingest-executor`'s workflow path demonstrates the failure mode
//! by reducing them to `json!({"level": planned.level})` — a shape with no
//! `source_type`, which would send every structural row down the tampering
//! branch. So this drives `do_ingest_document` / `do_ingest_document_spine`
//! (the cores behind MCP `ingest_document`, `ingest_document_inline` and
//! `ingest_document_spine`) and then asks `verify_claim` about what landed.
//!
//! Deliberately does NOT use `tests/common`: that helper DROPs
//! `uq_claims_content_hash_agent`, and the seed-scoped digest exists precisely
//! to satisfy that constraint — keeping it in force is part of what makes these
//! fixtures realistic.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_crypto::AgentSigner;
use epigraph_ingest::schema::DocumentExtraction;
use epigraph_mcp::embed::McpEmbedder;
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools::claims::verify_claim;
use epigraph_mcp::tools::ingestion::{do_ingest_document, do_ingest_document_spine};
use epigraph_mcp::types::VerifyClaimParams;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

const TITLE: &str = "Cryogenic Positional Assembly of Diamondoid Cages";
const THESIS: &str =
    "Cryogenic Positional Assembly of Diamondoid Cages advances the state of the art.";
const SECTION: &str = "Methods";
const PARAGRAPH: &str = "Tips were functionalized under ultra-high vacuum before each run.";
const ATOM: &str = "Tip functionalization occurred under ultra-high vacuum.";

fn make_server(pool: PgPool) -> EpiGraphMcpFull {
    let signer = AgentSigner::generate();
    let embedder = McpEmbedder::new(pool.clone(), None);
    EpiGraphMcpFull::new(pool, signer, embedder, false)
}

fn extraction() -> DocumentExtraction {
    let json = serde_json::json!({
        "source": {
            "title": TITLE,
            "doi": "10.9999/verify-claim-after-ingest",
            "source_type": "Paper",
            "authors": [{"name": "Alice Author", "affiliations": [], "roles": ["author"]}]
        },
        "thesis": THESIS,
        "thesis_derivation": "TopDown",
        "sections": [{
            "title": SECTION,
            "paragraphs": [{
                "text": PARAGRAPH,
                "atoms": [ATOM],
                "generality": [1],
                "confidence": 0.9
            }]
        }],
        "relationships": []
    });
    serde_json::from_value(json).expect("fixture parses")
}

/// Every structural row the document writer produced must report
/// `not_applicable`, and the atom must report `match`.
///
/// This is the whole chain in one assertion set: builder binds a seed-scoped
/// digest → writer persists it AND the properties that identify it →
/// `verify_claim` classifies from those properties → the verdict is "undecided",
/// not "tampered". Break any link and a real, untampered, freshly ingested
/// thesis reports a mismatch — which is exactly what it did before this fix.
#[sqlx::test(migrations = "../../migrations")]
async fn freshly_ingested_spine_rows_are_not_accused_of_tampering(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = make_server(pool.clone());
    do_ingest_document(&server, &viewer, &extraction())
        .await
        .expect("document ingests");

    for (label, content) in [
        ("thesis (level 0)", THESIS),
        ("section (level 1)", SECTION),
        ("paragraph (level 2)", PARAGRAPH),
    ] {
        let id = only_claim_with_content(&pool, content).await;
        let resp = run_verify(&server, &viewer, id).await;
        assert_eq!(
            resp["hash_check"],
            Value::String("not_applicable".to_string()),
            "{label} was just written by the real ingest writer and nothing has \
             touched it since, so `mismatch` here is a false tampering alarm: {resp}"
        );
        assert_eq!(
            resp["hash_matches"],
            Value::Null,
            "{label}: hash_matches must be null, never false: {resp}"
        );
    }

    // The converse over the SAME document: atoms bind the plain content hash, so
    // the writer's output must verify positively. Without this the test would be
    // satisfied by a classifier that answers not_applicable for everything.
    let atom_id = only_claim_with_content(&pool, ATOM).await;
    let resp = run_verify(&server, &viewer, atom_id).await;
    assert_eq!(
        resp["hash_check"],
        Value::String("match".to_string()),
        "an atom stores blake3(content), so a freshly ingested atom must verify: {resp}"
    );
    assert_eq!(resp["hash_matches"], Value::Bool(true), "{resp}");
}

/// Same guarantee through `ingest_document_spine`, which is a different core
/// function (`do_ingest_document_spine`) with its own `set_properties` call.
///
/// The review named all three ingest tools; a fix verified through only one core
/// would leave the other's rows accused. Spine writes levels 0-2 and no atoms.
#[sqlx::test(migrations = "../../migrations")]
async fn spine_ingest_rows_are_not_accused_of_tampering(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = make_server(pool.clone());
    do_ingest_document_spine(&server, &extraction())
        .await
        .expect("spine ingests");

    for (label, content) in [
        ("thesis (level 0)", THESIS),
        ("section (level 1)", SECTION),
        ("paragraph (level 2)", PARAGRAPH),
    ] {
        let id = only_claim_with_content(&pool, content).await;
        let resp = run_verify(&server, &viewer, id).await;
        assert_eq!(
            resp["hash_check"],
            Value::String("not_applicable".to_string()),
            "{label} from do_ingest_document_spine: {resp}"
        );
    }
}

/// A tampered spine row is honestly reported as UNDECIDED, not as clean and not
/// as tampered — and this test says so out loud rather than leaving it implied.
///
/// This is the cost of the fix, recorded as a test so nobody later reads
/// `not_applicable` as an all-clear: mutating a structural body is invisible to
/// the content-hash check, because the seed that produced the stored digest is
/// not on the row and guessing it would be the false confidence this whole item
/// is about. Detection for this class has to come from the signature half or
/// from the document's own provenance.
#[sqlx::test(migrations = "../../migrations")]
async fn a_tampered_spine_row_is_reported_undecided_not_clean(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = make_server(pool.clone());
    do_ingest_document_spine(&server, &extraction())
        .await
        .expect("spine ingests");

    let id = only_claim_with_content(&pool, PARAGRAPH).await;
    sqlx::query("UPDATE claims SET content = $2 WHERE id = $1")
        .bind(id)
        .bind("Tips were NOT functionalized before any run.")
        .execute(&pool)
        .await
        .expect("tamper");

    let resp = run_verify(&server, &viewer, id).await;
    assert_eq!(
        resp["hash_check"],
        Value::String("not_applicable".to_string()),
        "content-hash verification cannot see this mutation, and must not claim \
         to: {resp}"
    );
    assert_ne!(
        resp["hash_matches"],
        Value::Bool(true),
        "and it must never report the tampered row as a positive match: {resp}"
    );
}

async fn only_claim_with_content(pool: &PgPool, content: &str) -> Uuid {
    let ids: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM claims WHERE content = $1 ORDER BY id")
        .bind(content)
        .fetch_all(pool)
        .await
        .expect("claim lookup");
    assert_eq!(
        ids.len(),
        1,
        "expected exactly one persisted claim with content {content:?}, got {ids:?} — \
         the ingest fixture did not land as expected, so the verdict below would be \
         meaningless"
    );
    ids[0]
}

async fn run_verify(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    claim_id: Uuid,
) -> Value {
    let result = verify_claim(
        server,
        viewer,
        VerifyClaimParams {
            claim_id: claim_id.to_string(),
        },
    )
    .await
    .expect("verify_claim");
    let text = result
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.clone())
        .expect("text content block");
    serde_json::from_str(&text).expect("response is JSON")
}
