//! Structured dataset evidence through the MCP write and read tools (backlog
//! c8beb101).
//!
//! A claim filed with a `dataset` must carry evidence `{type: dataset,
//! root_uri, manifest_hash: blake3:..., file_count, total_bytes}` that a reader
//! gets back from `get_claim` and `get_provenance` without parsing
//! `evidence_data`, on a row signed exactly as every other MCP evidence row is,
//! with the dataset fields themselves covered by a server attestation that a
//! reader verifies (review finding 1).
//!
//! Params are built from JSON, not struct literals, on purpose: serde ignores
//! unknown fields here, so against the pre-dataset types the same payload
//! deserialises, runs, and fails on the assertions (no `datasets`, a bad
//! dataset accepted) rather than failing to compile.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_crypto::{AgentSigner, SignatureScheme, SignatureVerifier, SignedEntity};
use epigraph_mcp::types::{BatchSubmitClaimsParams, SubmitClaimParams};
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

const B3_HEX: &str = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";
const ROOT: &str = "s3://lab-runs/c8beb101/campaign-7/run-0042";

fn dataset_json() -> Value {
    json!({
        "root_uri": ROOT,
        "manifest_uri": format!("{ROOT}/MANIFEST.b3"),
        // Upper case on input: stored lower case, so readers compare one form.
        "manifest_hash": format!("BLAKE3:{}", B3_HEX.to_ascii_uppercase()),
        "file_count": 1204,
        "total_bytes": 73_014_444_032_u64,
        "sample_id": "sample-17"
    })
}

/// The stored `properties` of the dataset row: the serialised
/// `EvidenceType::Dataset`, normalised. Compared as JSON so this file builds
/// against the pre-dataset code and fails there on the assertion.
fn expected_dataset() -> Value {
    json!({
        "type": "dataset",
        "root_uri": ROOT,
        "manifest_uri": format!("{ROOT}/MANIFEST.b3"),
        "manifest_blob_id": null,
        "manifest_hash": format!("blake3:{B3_HEX}"),
        "hash_algorithm": "blake3",
        "file_count": 1204,
        "total_bytes": 73_014_444_032_u64,
        "sample_id": "sample-17",
        "blob_ids": []
    })
}

fn submission(content: &str, dataset: Value) -> SubmitClaimParams {
    serde_json::from_value(json!({
        "content": content,
        "methodology": "direct_observation",
        "evidence_data": "campaign 7 run 42: gate passed",
        "evidence_type": "empirical",
        "confidence": 0.8,
        "visibility": "public",
        "novelty_threshold": 0.0,
        "dataset": dataset,
    }))
    .expect("submit_claim params")
}

/// `(id, evidence_type, source_url, properties, content_hash, signature)`.
type EvidenceRow = (
    Uuid,
    String,
    Option<String>,
    Value,
    Vec<u8>,
    Option<Vec<u8>>,
);

/// The key every `build_scoped_test_server` signs with.
fn test_server_key() -> [u8; 32] {
    AgentSigner::from_bytes(&[0xA7u8; 32])
        .expect("signer")
        .public_key()
}

/// `properties` without its `attestation`, and whether there was one.
fn without_attestation(mut v: Value) -> (Value, bool) {
    let had = v
        .as_object_mut()
        .and_then(|o| o.remove("attestation"))
        .is_some();
    (v, had)
}

/// Whether a dataset as a reader receives it (stored `properties`, or a
/// `get_claim` `datasets` entry, whose extra `evidence_id` serde ignores)
/// carries an attestation that verifies under the test server key for these
/// ids. `None` when it carries none.
fn attestation_verifies(dataset: &Value, evidence_id: Uuid, claim_id: Uuid) -> Option<bool> {
    let parsed: epigraph_core::EvidenceType =
        serde_json::from_value(dataset.clone()).expect("a dataset value");
    parsed.verify_dataset_attestation(
        epigraph_core::EvidenceId::from_uuid(evidence_id),
        epigraph_core::ClaimId::from_uuid(claim_id),
        &test_server_key(),
    )
}

fn get_claim_params(claim_id: Uuid) -> epigraph_mcp::types::GetClaimParams {
    epigraph_mcp::types::GetClaimParams {
        claim_id: claim_id.to_string(),
        frame_id: None,
        perspective_id: None,
    }
}

async fn claims_with_content(pool: &PgPool, content: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM claims WHERE content = $1")
        .bind(content)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// The DONE criterion, end to end on one claim: the stored row is a SIGNED
/// `dataset` row (v1 evidence signature by the server key over its content
/// hash, unchanged by this feature) whose properties are the normalised
/// dataset; `get_claim` returns it under `datasets`; `get_provenance` carries
/// it on the evidence entity.
#[sqlx::test(migrations = "../../migrations")]
async fn a_dataset_submission_round_trips_through_a_signed_write(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let content = "c8beb101: campaign 7 run 42 passed its gate";

    let body = first_text(
        &epigraph_mcp::tools::claims::submit_claim(
            &server,
            &viewer,
            submission(content, dataset_json()),
            None,
        )
        .await
        .expect("submit_claim with a dataset"),
    );
    let claim_id = parse_uuid_field(&body, "claim_id");

    // The stored row.
    let (evidence_id, stored_type, source_url, properties, hash, sig): EvidenceRow =
        sqlx::query_as(
            "SELECT id, evidence_type, source_url, properties, content_hash, signature \
               FROM evidence WHERE claim_id = $1",
        )
        .bind(claim_id)
        .fetch_one(&pool)
        .await
        .expect("one evidence row");
    assert_eq!(stored_type, "dataset");
    assert_eq!(
        source_url.as_deref(),
        Some(ROOT),
        "root_uri is the source_url"
    );
    let (fields, attested) = without_attestation(properties.clone());
    assert_eq!(fields, expected_dataset());
    assert!(
        attested,
        "the server must attest the dataset fields: {properties}"
    );
    assert_eq!(
        attestation_verifies(&properties, evidence_id, claim_id),
        Some(true),
        "the stored attestation must verify under the server key: {properties}"
    );
    let hash: [u8; 32] = hash.try_into().unwrap();
    assert_eq!(
        hash,
        epigraph_crypto::ContentHasher::hash(b"campaign 7 run 42: gate passed"),
        "content_hash stays BLAKE3(evidence_data)"
    );
    let sig: [u8; 64] = sig.expect("signed").try_into().unwrap();
    assert_eq!(
        SignatureVerifier::verify_entity(&test_server_key(), SignedEntity::Evidence, &hash, &sig)
            .unwrap(),
        Some(SignatureScheme::V1),
        "the dataset row is signed as v1 evidence by the server key"
    );

    // get_claim.
    let got = first_text(
        &epigraph_mcp::tools::claims::get_claim(
            &server,
            &viewer,
            epigraph_mcp::types::GetClaimParams {
                claim_id: claim_id.to_string(),
                frame_id: None,
                perspective_id: None,
            },
        )
        .await
        .expect("get_claim"),
    );
    let datasets = got["datasets"]
        .as_array()
        .unwrap_or_else(|| panic!("{got}"));
    assert_eq!(datasets.len(), 1, "{got}");
    let d = &datasets[0];
    assert_eq!(d["evidence_id"], evidence_id.to_string());
    assert_eq!(d["type"], "dataset");
    assert_eq!(d["root_uri"], ROOT);
    assert_eq!(d["manifest_hash"], format!("blake3:{B3_HEX}"));
    assert_eq!(d["hash_algorithm"], "blake3");
    assert_eq!(d["file_count"], 1204);
    assert_eq!(d["total_bytes"], 73_014_444_032_u64);
    assert_eq!(
        attestation_verifies(d, evidence_id, claim_id),
        Some(true),
        "get_claim must hand the reader an attestation that verifies: {got}"
    );

    // get_provenance.
    let prov = first_text(
        &epigraph_mcp::tools::provenance::get_provenance(
            &server,
            &viewer,
            serde_json::from_value(json!({ "claim_id": claim_id.to_string() })).unwrap(),
        )
        .await
        .expect("get_provenance"),
    );
    let text = prov.to_string();
    let graph = prov["entities"]
        .as_array()
        .unwrap_or_else(|| panic!("no entities: {text}"));
    let entity = graph
        .iter()
        .find(|e| e["@id"] == format!("evidence:{evidence_id}"))
        .unwrap_or_else(|| panic!("no evidence entity: {text}"));
    assert_eq!(
        entity["dataset"]["manifest_hash"],
        format!("blake3:{B3_HEX}")
    );
    assert_eq!(entity["dataset"]["root_uri"], ROOT);
    assert_eq!(entity["dataset"]["file_count"], 1204);
    assert_eq!(
        attestation_verifies(&entity["dataset"], evidence_id, claim_id),
        Some(true),
        "get_provenance must carry the verifying attestation: {text}"
    );
}

/// Review finding 1: the evidence row's signature covers only
/// `content_hash`, so an edit to the stored dataset fields, or a dataset
/// copied onto another claim's row, used to leave every stored signature
/// verifying while `get_claim` served the edited digest. With the attestation
/// a reader of `get_claim` detects both, and the row signature still verifies
/// (so this is the attestation's doing, not a broken row).
#[sqlx::test(migrations = "../../migrations")]
async fn an_edited_or_transplanted_dataset_fails_its_attestation(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let submit = |content: &'static str, dataset: Value| {
        let server = &server;
        let viewer = &viewer;
        async move {
            let body = first_text(
                &epigraph_mcp::tools::claims::submit_claim(
                    server,
                    viewer,
                    submission(content, dataset),
                    None,
                )
                .await
                .expect("submit_claim"),
            );
            parse_uuid_field(&body, "claim_id")
        }
    };
    let first = submit("c8beb101: tamper target run 1", dataset_json()).await;
    let mut other_dataset = dataset_json();
    other_dataset["root_uri"] = json!(format!("{ROOT}-other"));
    other_dataset["file_count"] = json!(7);
    let second = submit("c8beb101: transplant target run 2", other_dataset).await;

    let evidence_of = |claim: Uuid| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, Uuid>(
                "SELECT id FROM evidence WHERE claim_id = $1 AND evidence_type = 'dataset'",
            )
            .bind(claim)
            .fetch_one(&pool)
            .await
            .expect("a dataset row")
        }
    };
    let first_ev = evidence_of(first).await;
    let second_ev = evidence_of(second).await;
    let dataset_from_get_claim = |claim: Uuid| {
        let server = &server;
        let viewer = &viewer;
        async move {
            let got = first_text(
                &epigraph_mcp::tools::claims::get_claim(server, viewer, get_claim_params(claim))
                    .await
                    .expect("get_claim"),
            );
            got["datasets"][0].clone()
        }
    };
    // Both verify before anything is touched.
    assert_eq!(
        attestation_verifies(&dataset_from_get_claim(first).await, first_ev, first),
        Some(true)
    );
    assert_eq!(
        attestation_verifies(&dataset_from_get_claim(second).await, second_ev, second),
        Some(true)
    );

    // Edit: the review's exact UPDATE on the manifest digest.
    sqlx::query(
        "UPDATE evidence SET properties = jsonb_set(properties, '{manifest_hash}', $2) \
          WHERE id = $1",
    )
    .bind(first_ev)
    .bind(json!(format!("blake3:{}", "0".repeat(64))))
    .execute(&pool)
    .await
    .unwrap();
    let edited = dataset_from_get_claim(first).await;
    assert_eq!(
        edited["manifest_hash"],
        format!("blake3:{}", "0".repeat(64))
    );
    assert_eq!(
        attestation_verifies(&edited, first_ev, first),
        Some(false),
        "an edited manifest digest must fail its attestation: {edited}"
    );

    // Transplant: the second row's whole properties, attestation included,
    // copied onto the first claim's row.
    sqlx::query(
        "UPDATE evidence SET properties = (SELECT properties FROM evidence WHERE id = $2) \
          WHERE id = $1",
    )
    .bind(first_ev)
    .bind(second_ev)
    .execute(&pool)
    .await
    .unwrap();
    let transplanted = dataset_from_get_claim(first).await;
    assert_eq!(transplanted["file_count"], 7, "{transplanted}");
    assert_eq!(
        attestation_verifies(&transplanted, first_ev, first),
        Some(false),
        "a dataset copied from another row must fail its attestation: {transplanted}"
    );

    // The row signature is untouched by either edit and still verifies: it
    // never covered these fields, which is the gap the attestation closes.
    let (hash, sig): (Vec<u8>, Vec<u8>) =
        sqlx::query_as("SELECT content_hash, signature FROM evidence WHERE id = $1")
            .bind(first_ev)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        SignatureVerifier::verify_entity(
            &test_server_key(),
            SignedEntity::Evidence,
            &hash.try_into().unwrap(),
            &sig.try_into().unwrap()
        )
        .unwrap(),
        Some(SignatureScheme::V1)
    );
}

/// A claim filed without a dataset still answers `datasets: []`, so a reader
/// never has to tell "absent" from "none".
#[sqlx::test(migrations = "../../migrations")]
async fn get_claim_answers_an_empty_datasets_list_without_one(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let p = submission("c8beb101: a plain claim", Value::Null);
    let body = first_text(
        &epigraph_mcp::tools::claims::submit_claim(&server, &viewer, p, None)
            .await
            .unwrap(),
    );
    let claim_id = parse_uuid_field(&body, "claim_id");
    let got = first_text(
        &epigraph_mcp::tools::claims::get_claim(
            &server,
            &viewer,
            epigraph_mcp::types::GetClaimParams {
                claim_id: claim_id.to_string(),
                frame_id: None,
                perspective_id: None,
            },
        )
        .await
        .unwrap(),
    );
    assert_eq!(got["datasets"], json!([]), "{got}");
}

/// A dataset no reader could verify (an algorithm outside the list) refuses the
/// call before anything is written.
#[sqlx::test(migrations = "../../migrations")]
async fn a_bad_dataset_refuses_submit_claim_and_writes_nothing(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let content = "c8beb101: a claim with an md5 manifest";
    let mut bad = dataset_json();
    bad["manifest_hash"] = json!(format!("md5:{}", &B3_HEX[..32]));

    let err =
        epigraph_mcp::tools::claims::submit_claim(&server, &viewer, submission(content, bad), None)
            .await
            .expect_err("an md5 manifest digest must be refused");
    assert!(err.message.contains("hash_algorithm"), "{err:?}");
    assert_eq!(claims_with_content(&pool, content).await, 0);
}

/// `batch_submit_claims` carries a dataset per entry, and a bad dataset refuses
/// only its own entry.
#[sqlx::test(migrations = "../../migrations")]
async fn batch_entries_carry_their_own_dataset(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let good = "c8beb101: batch run 1 passed";
    let bad_content = "c8beb101: batch run 2 with a short digest";
    let mut bad = dataset_json();
    bad["manifest_hash"] = json!("blake3:abcd");
    let entry = |content: &str, dataset: Value| {
        json!({
            "content": content,
            "methodology": "direct_observation",
            "evidence_data": format!("evidence for {content}"),
            "evidence_type": "empirical",
            "visibility": "public",
            "novelty_threshold": 0.0,
            "dataset": dataset,
        })
    };
    let params: BatchSubmitClaimsParams = serde_json::from_value(json!({
        "claims": [entry(good, dataset_json()), entry(bad_content, bad)]
    }))
    .unwrap();

    let summary = first_text(
        &epigraph_mcp::tools::batch::batch_submit_claims(&server, &viewer, params, None)
            .await
            .expect("batch_submit_claims"),
    );
    assert_eq!(summary["results"][0]["status"], "ok", "{summary}");
    assert_eq!(summary["errors"], 1, "{summary}");
    assert_eq!(claims_with_content(&pool, bad_content).await, 0);

    let claim_id: Uuid = summary["results"][0]["claim_id"]
        .as_str()
        .unwrap_or_else(|| panic!("{summary}"))
        .parse()
        .unwrap();
    let props: Value = sqlx::query_scalar(
        "SELECT properties FROM evidence WHERE claim_id = $1 AND evidence_type = 'dataset'",
    )
    .bind(claim_id)
    .fetch_one(&pool)
    .await
    .expect("the good entry's dataset row");
    let (fields, attested) = without_attestation(props);
    assert_eq!(fields, expected_dataset());
    assert!(attested, "a batch entry's dataset is attested too");
}
