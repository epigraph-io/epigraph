#![cfg(feature = "db")]
//! GET /api/v1/claims/:id/provenance truncates the claim-step label on a char
//! boundary. It used to byte-slice at 57 (`&content[..57]`), which panics when
//! a multi-byte character straddles byte 57; with no `CatchPanicLayer` the
//! client just saw the connection drop.
mod common;

use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

/// Seed a public claim (no ownership row) with one claim→evidence edge, so the
/// response carries a claim step whose label can be asserted.
async fn seed_claim_with_evidence(pool: &sqlx::PgPool, content: &str) -> Uuid {
    let claim_id = common::seed_claim(pool, content).await;
    let evidence_id = Uuid::new_v4();
    let ev_hash: Vec<u8> = evidence_id
        .as_bytes()
        .iter()
        .copied()
        .cycle()
        .take(32)
        .collect();
    sqlx::query(
        "INSERT INTO evidence (id, raw_content, content_hash, evidence_type, claim_id, properties) \
         VALUES ($1, 'ev', $2, 'document', $3, '{\"evidence_type\":\"document\",\"doi\":\"10.1/x\"}'::jsonb)",
    )
    .bind(evidence_id)
    .bind(&ev_hash)
    .bind(claim_id)
    .execute(pool)
    .await
    .unwrap();
    common::insert_edge(
        pool,
        claim_id,
        evidence_id,
        "claim",
        "evidence",
        "DERIVED_FROM",
    )
    .await;
    claim_id
}

/// The label of the (single) claim-typed step in a provenance response.
fn claim_step_label(body: &serde_json::Value) -> String {
    let labels: Vec<&str> = body["chains"]
        .as_array()
        .expect("chains array")
        .iter()
        .flat_map(|chain| chain["path"].as_array().expect("path array").iter())
        .filter(|step| step["entity_type"] == "claim")
        .map(|step| step["label"].as_str().expect("label string"))
        .collect();
    assert!(
        !labels.is_empty(),
        "expected a claim-typed provenance step (chain seeding failed); test would be vacuous without it"
    );
    labels[0].to_string()
}

#[tokio::test(flavor = "multi_thread")]
async fn provenance_label_cuts_multibyte_content_on_a_char_boundary() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    let (addr, _shutdown) = common::spawn_app(&url).await;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap();

    // 'μ' is two bytes and occupies bytes 56..58, so byte 57 is inside it.
    let straddling = format!("{}μ and then the rest of a long claim", "a".repeat(56));
    assert!(!straddling.is_char_boundary(57));
    // 40 two-byte chars: 80 bytes (over the old byte threshold) but 40 chars.
    let short_multibyte = "é".repeat(40);
    assert!(!short_multibyte.is_char_boundary(57));

    for (content, expected) in [
        (
            straddling.clone(),
            format!("{}...", straddling.chars().take(57).collect::<String>()),
        ),
        (short_multibyte.clone(), short_multibyte.clone()),
    ] {
        let claim_id = seed_claim_with_evidence(&pool, &content).await;
        let resp = client
            .get(format!("http://{addr}/api/v1/claims/{claim_id}/provenance"))
            .send()
            .await
            .unwrap_or_else(|e| panic!("request for {content:?} failed (handler panic?): {e}"));
        assert_eq!(resp.status(), 200, "content {content:?}");
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(claim_step_label(&body), expected);
    }
}
