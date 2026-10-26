//! An evidence URL must survive the write and come back on a claim read
//! (backlog 43ab8c73, drain unit U036).
//!
//! Before this, every evidence INSERT bound `NULL` to `evidence.source_url`,
//! so the URL lived only inside `evidence.properties` — and for `empirical`
//! evidence (stored as `EvidenceType::Observation`, which has no URL slot) it
//! lived nowhere at all. The norcal-rfp monitor submits `empirical` evidence,
//! so its "Discovery URLs" were unrecoverable by any read.
//!
//! Every test here measures the stored row (or the tool's own JSON) rather than
//! a fixture's echo: the evidence row read back is the one `submit_claim`
//! wrote.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_mcp::types::SubmitClaimParams;
use sqlx::PgPool;
use uuid::Uuid;

const RFP_URL: &str = "https://example.org/u036/rfp-1";

fn rfp_submission(content: &str, evidence_type: &str, url: Option<&str>) -> SubmitClaimParams {
    SubmitClaimParams {
        content: content.into(),
        methodology: "direct_observation".into(),
        evidence_data: "listing seen".into(),
        evidence_type: evidence_type.into(),
        confidence: 0.8,
        source_url: url.map(String::from),
        reasoning: None,
        labels: vec!["u036-rfp".into()],
        novelty_threshold: None,
    }
}

async fn submit(
    server: &epigraph_mcp::EpiGraphMcpFull,
    viewer: &epigraph_db::Viewer,
    params: SubmitClaimParams,
) -> Uuid {
    let body = first_text(
        &epigraph_mcp::tools::claims::submit_claim(server, viewer, params, None)
            .await
            .expect("submit_claim"),
    );
    parse_uuid_field(&body, "claim_id")
}

async fn stored_source_urls(pool: &PgPool, claim_id: Uuid) -> Vec<Option<String>> {
    sqlx::query_scalar("SELECT source_url FROM evidence WHERE claim_id = $1")
        .bind(claim_id)
        .fetch_all(pool)
        .await
        .expect("read evidence.source_url")
}

/// The norcal-rfp path: `empirical` evidence with a `source_url`. The URL must
/// land in `evidence.source_url`, since the evidence type has nowhere else to
/// keep it.
#[sqlx::test(migrations = "../../migrations")]
async fn an_empirical_submission_stores_its_source_url(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);

    let claim_id = submit(
        &server,
        &viewer,
        rfp_submission("u036: rfp discovered", "empirical", Some(RFP_URL)),
    )
    .await;

    let stored = stored_source_urls(&pool, claim_id).await;
    assert!(
        stored.contains(&Some(RFP_URL.to_string())),
        "evidence.source_url for claim {claim_id} = {stored:?}; expected it to hold {RFP_URL}"
    );
}

async fn get_claim_json(
    server: &epigraph_mcp::EpiGraphMcpFull,
    viewer: &epigraph_db::Viewer,
    claim_id: Uuid,
) -> serde_json::Value {
    first_text(
        &epigraph_mcp::tools::claims::get_claim(
            server,
            viewer,
            epigraph_mcp::types::GetClaimParams {
                claim_id: claim_id.to_string(),
                frame_id: None,
                perspective_id: None,
            },
        )
        .await
        .expect("get_claim"),
    )
}

/// Insert an evidence row the way a writer from BEFORE the write-path fix left
/// it: `source_url` column NULL, the link only inside `properties`.
async fn seed_legacy_evidence(
    pool: &PgPool,
    claim_id: Uuid,
    db_type: &str,
    properties: serde_json::Value,
    created_at: chrono::DateTime<chrono::Utc>,
) {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO evidence (id, content_hash, evidence_type, source_url, claim_id, \
                               properties, created_at) \
         VALUES ($1, $2, $3, NULL, $4, $5, $6)",
    )
    .bind(id)
    .bind(id.as_bytes().repeat(2))
    .bind(db_type)
    .bind(claim_id)
    .bind(properties)
    .bind(created_at)
    .execute(pool)
    .await
    .expect("seed legacy evidence");
}

/// Rows written before the write-path fix keep their link only in
/// `properties`: a Document's `source_url`, a Literature row's `doi`. `get_claim`
/// must surface both, in evidence order, from those rows — the column is NULL.
#[sqlx::test(migrations = "../../migrations")]
async fn get_claim_surfaces_the_evidence_url_of_a_pre_existing_document_row(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let claim_id = seed_claim(&pool, "u036: a claim with legacy evidence", 0.6).await;
    let t0 = chrono::Utc::now() - chrono::Duration::hours(2);
    seed_legacy_evidence(
        &pool,
        claim_id,
        "document",
        serde_json::json!({
            "type": "document",
            "source_url": "https://example.org/u036/doc",
            "mime_type": "text/plain",
            "checksum": null
        }),
        t0,
    )
    .await;
    seed_legacy_evidence(
        &pool,
        claim_id,
        "reference",
        serde_json::json!({
            "type": "literature",
            "doi": "10.1234/u036",
            "extraction_target": "abstract",
            "page_range": null
        }),
        t0 + chrono::Duration::minutes(1),
    )
    .await;

    let body = get_claim_json(&server, &viewer, claim_id).await;
    assert_eq!(
        body["source_urls"],
        serde_json::json!([
            "https://example.org/u036/doc",
            "https://doi.org/10.1234/u036"
        ]),
        "{body}"
    );
}

/// The digest consumer's bulk read: one opt-in flag, and without it the
/// response is unchanged (no `source_urls` key at all). A URL submitted twice to
/// the same claim (the second call a content-hash dedup hit) is listed once.
#[sqlx::test(migrations = "../../migrations")]
async fn query_claims_by_label_returns_urls_only_when_asked(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let claim_id = submit(
        &server,
        &viewer,
        rfp_submission("u036: rfp listed", "empirical", Some(RFP_URL)),
    )
    .await;
    // Different evidence text: the same text on the same claim is the same
    // evidence row (unique on content_hash, claim_id).
    let mut resubmit = rfp_submission("u036: rfp listed", "empirical", Some(RFP_URL));
    resubmit.evidence_data = "listing seen again".into();
    let again = submit(&server, &viewer, resubmit).await;
    assert_eq!(again, claim_id, "the resubmit must be a content-hash hit");

    // Built from JSON so the flag is an input the tool's schema accepts.
    let query = |include: bool| {
        let params: epigraph_mcp::types::QueryClaimsByLabelParams =
            serde_json::from_value(serde_json::json!({
                "labels": ["u036-rfp"],
                "include_source_urls": include,
            }))
            .expect("params");
        params
    };
    let find = |body: &serde_json::Value| -> serde_json::Value {
        body.as_array()
            .unwrap_or_else(|| panic!("expected an array, got {body}"))
            .iter()
            .find(|c| c["id"] == claim_id.to_string())
            .unwrap_or_else(|| panic!("claim {claim_id} not listed: {body}"))
            .clone()
    };

    let with = first_text(
        &epigraph_mcp::tools::paper_queries::query_claims_by_label(&server, &viewer, query(true))
            .await
            .expect("query with urls"),
    );
    let claim = find(&with);
    assert_eq!(
        claim["source_urls"],
        serde_json::json!([RFP_URL]),
        "{claim}"
    );

    let without = first_text(
        &epigraph_mcp::tools::paper_queries::query_claims_by_label(&server, &viewer, query(false))
            .await
            .expect("query without urls"),
    );
    let claim = find(&without);
    assert!(
        claim.get("source_urls").is_none(),
        "the default response must not carry source_urls: {claim}"
    );
}

/// A testimony with no URL is stored with `source = "unknown"`. That is free
/// text, not a link, so `get_claim` reports an EMPTY list — present, not absent,
/// so a consumer can tell "no URL on file" from "this server does not say".
#[sqlx::test(migrations = "../../migrations")]
async fn a_testimony_with_no_url_surfaces_none(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let claim_id = submit(
        &server,
        &viewer,
        rfp_submission("u036: an unsourced testimony", "testimonial", None),
    )
    .await;

    let body = get_claim_json(&server, &viewer, claim_id).await;
    assert!(
        body.get("source_urls").is_some(),
        "get_claim must always carry source_urls: {body}"
    );
    assert_eq!(body["source_urls"], serde_json::json!([]), "{body}");
}

/// `update_with_evidence` is the norcal-rfp reviewer's second write path (it
/// re-asserts evidence on a claim a prior cycle created), and it wrote its
/// evidence row through the same NULL-binding `create` `submit_claim` did. An
/// `empirical` URL passed to it must land in the column too.
#[sqlx::test(migrations = "../../migrations")]
async fn update_with_evidence_stores_an_empirical_source_url(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let claim_id = seed_claim(&pool, "u036: an rfp re-seen this cycle", 0.6).await;
    let url = "https://example.org/u036/rfp-update";

    epigraph_mcp::tools::claims::update_with_evidence(
        &server,
        &viewer,
        epigraph_mcp::types::UpdateWithEvidenceParams {
            canonical_name: None,
            step_index: None,
            claim_id: claim_id.to_string(),
            evidence_type: "empirical".into(),
            evidence_data: "listing seen again this cycle".into(),
            source_url: Some(url.into()),
            supports: true,
            strength: 0.7,
            labels: vec![],
        },
        None,
    )
    .await
    .expect("update_with_evidence");

    let stored = stored_source_urls(&pool, claim_id).await;
    assert_eq!(
        stored,
        vec![Some(url.to_string())],
        "evidence.source_url for claim {claim_id}; the empirical arm must not drop the URL"
    );
}

/// A testimonial's `source_url` parameter is the only way to set
/// `Testimony.source`, so callers pass free text (a person's name) there, and
/// the writer stores it in the column verbatim. `get_claim` promises "the URLs
/// of the evidence", so a column value that is not an `http(s)` URL must not be
/// surfaced — the same rule the `properties` fallback applies to testimony.
#[sqlx::test(migrations = "../../migrations")]
async fn a_testimonial_whose_source_is_a_name_surfaces_no_url(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let claim_id = submit(
        &server,
        &viewer,
        rfp_submission(
            "u036: a testimony from a named witness",
            "testimonial",
            Some("Dr. Jane Witness"),
        ),
    )
    .await;

    // CALIBRATION: the free text really is in the column, so the empty list
    // below is the read's filter and not an empty column.
    assert_eq!(
        stored_source_urls(&pool, claim_id).await,
        vec![Some("Dr. Jane Witness".to_string())]
    );
    let body = get_claim_json(&server, &viewer, claim_id).await;
    assert_eq!(body["source_urls"], serde_json::json!([]), "{body}");
}

/// The rest of the legacy `properties` fallback, one row per arm, in evidence
/// order:
///
/// * a testimony whose `source` IS an `http(s)` URL — surfaced;
/// * a figure's DOI — surfaced as `https://doi.org/<doi>`;
/// * a literature row whose `doi` is not a DOI (ingestion spells such an
///   identifier `doi:<id>`, `ingestion.rs`) — NOT surfaced as a bogus doi.org
///   link;
/// * a row whose column and `properties.source_url` disagree — the column
///   wins, and the properties URL is not listed at all.
#[sqlx::test(migrations = "../../migrations")]
async fn the_legacy_fallback_covers_testimony_and_figure_and_the_column_wins(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let claim_id = seed_claim(&pool, "u036: a claim with every legacy shape", 0.6).await;
    let t0 = chrono::Utc::now() - chrono::Duration::hours(2);
    let minute = |n: i64| t0 + chrono::Duration::minutes(n);

    seed_legacy_evidence(
        &pool,
        claim_id,
        "testimony",
        serde_json::json!({
            "type": "testimony",
            "source": "https://example.org/u036/witness",
            "testified_at": "2026-01-01T00:00:00Z",
            "verification": null
        }),
        minute(0),
    )
    .await;
    seed_legacy_evidence(
        &pool,
        claim_id,
        "figure",
        serde_json::json!({
            "type": "figure",
            "doi": "10.5555/u036.fig",
            "figure_id": "Fig. 2a",
            "caption": null,
            "mime_type": "image/png",
            "page": null
        }),
        minute(1),
    )
    .await;
    seed_legacy_evidence(
        &pool,
        claim_id,
        "reference",
        serde_json::json!({
            "type": "literature",
            "doi": "arXiv:2401.00001",
            "extraction_target": "abstract",
            "page_range": null
        }),
        minute(2),
    )
    .await;
    seed_legacy_evidence(
        &pool,
        claim_id,
        "document",
        serde_json::json!({
            "type": "document",
            "source_url": "https://example.org/u036/stale-properties-url",
            "mime_type": "text/plain",
            "checksum": null
        }),
        minute(3),
    )
    .await;
    sqlx::query(
        "UPDATE evidence SET source_url = 'https://example.org/u036/column-url' \
          WHERE claim_id = $1 AND properties->>'source_url' LIKE '%stale-properties-url'",
    )
    .bind(claim_id)
    .execute(&pool)
    .await
    .expect("give the document row a column URL that disagrees with its properties");

    let body = get_claim_json(&server, &viewer, claim_id).await;
    assert_eq!(
        body["source_urls"],
        serde_json::json!([
            "https://example.org/u036/witness",
            "https://doi.org/10.5555/u036.fig",
            "https://example.org/u036/column-url"
        ]),
        "{body}"
    );
}
