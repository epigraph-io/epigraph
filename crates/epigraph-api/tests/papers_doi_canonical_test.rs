#![cfg(feature = "db")]
//! The REST paper routes key `papers.doi` on the ONE canonical document key
//! the MCP ingestion and paper-query tools use (backlog 90756d26).
//!
//! `https://doi.org/10.x/y`, `doi:10.x/y` and the bare `10.x/y` name one
//! paper. Before this, `POST /api/v1/papers` stored whatever spelling it was
//! given and `GET /api/v1/papers?doi=` matched it exactly, so the three
//! spellings were three document keys, and a bare-DOI lookup missed a row an
//! older writer had keyed on the resolver URL.
//!
//! What each test pins:
//!
//! * every spelling resolves to one row, stored under the bare DOI, and the
//!   list filter finds it under every spelling;
//! * a row keyed on a legacy resolver-URL spelling is FOUND by the bare DOI on
//!   both routes, and the writer does not mint a bare twin beside it;
//! * the normalizer is not a blanket prefix strip: a resolver URL with no DOI
//!   behind it, and a short registrant that is not a DOI, are stored verbatim,
//!   and two different DOIs stay two papers.

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;
mod common;

async fn connect() -> (String, PgPool) {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    (url, pool)
}

async fn post_paper(
    addr: std::net::SocketAddr,
    token: &str,
    doi: &str,
) -> (reqwest::StatusCode, serde_json::Value) {
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/papers"))
        .bearer_auth(token)
        .json(&serde_json::json!({ "doi": doi, "title": "canonical doi test" }))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    (
        status,
        serde_json::from_str(&text).unwrap_or(serde_json::json!({ "raw": text })),
    )
}

async fn list_by_doi(
    addr: std::net::SocketAddr,
    token: &str,
    doi: &str,
) -> (reqwest::StatusCode, serde_json::Value) {
    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/api/v1/papers"))
        .query(&[("doi", doi)])
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    (
        status,
        serde_json::from_str(&text).unwrap_or(serde_json::json!({ "raw": text })),
    )
}

/// Every `papers` row whose key ends in this DOI's unique suffix, whatever its
/// prefix: the twin detector.
async fn rows_ending_in(pool: &PgPool, suffix: &str) -> Vec<(Uuid, String)> {
    sqlx::query_as("SELECT id, doi FROM papers WHERE doi LIKE '%' || $1 ORDER BY doi")
        .bind(suffix)
        .fetch_all(pool)
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn every_doi_spelling_is_one_paper_keyed_on_the_bare_doi() {
    let (url, pool) = connect().await;
    let (addr, _shutdown) = common::spawn_app(&url).await;
    let (token, _) =
        common::test_bearer_token_with_seeded_client(&pool, &["claims:write", "claims:read"]).await;

    let suffix = format!("e2int.{}", Uuid::new_v4());
    let bare = format!("10.5555/{suffix}");

    let (s1, url_form) = post_paper(addr, &token, &format!("https://doi.org/{bare}")).await;
    assert_eq!(s1, 200, "{url_form}");
    let (s2, doi_form) = post_paper(addr, &token, &format!("doi:{bare}")).await;
    assert_eq!(s2, 200, "{doi_form}");
    let (s3, bare_form) = post_paper(addr, &token, &bare).await;
    assert_eq!(s3, 200, "{bare_form}");

    let rows = rows_ending_in(&pool, &suffix).await;
    assert_eq!(
        rows.len(),
        1,
        "three spellings of one DOI must be one paper, got {rows:?}"
    );
    assert_eq!(rows[0].1, bare, "the stored key must be the bare DOI");
    assert_eq!(url_form["doi"], bare.as_str(), "{url_form}");
    assert_eq!(url_form["id"], doi_form["id"]);
    assert_eq!(url_form["id"], bare_form["id"]);

    for spelling in [
        format!("https://doi.org/{bare}"),
        format!("https://dx.doi.org/{bare}"),
        format!("doi:{bare}"),
        bare.clone(),
    ] {
        let (status, body) = list_by_doi(addr, &token, &spelling).await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(
            body["total"], 1,
            "GET ?doi={spelling} must find the paper: {body}"
        );
        assert_eq!(
            body["items"][0]["id"], bare_form["id"],
            "{spelling}: {body}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_legacy_url_keyed_paper_is_found_by_the_bare_doi_and_not_twinned() {
    let (url, pool) = connect().await;
    let (addr, _shutdown) = common::spawn_app(&url).await;
    let (token, _) =
        common::test_bearer_token_with_seeded_client(&pool, &["claims:write", "claims:read"]).await;

    let suffix = format!("e2legacy.{}", Uuid::new_v4());
    let bare = format!("10.5555/{suffix}");
    let legacy_key = format!("https://doi.org/{bare}");
    // A row written before keys were canonicalized, as the MCP path's legacy
    // lookup assumes such rows exist.
    let legacy_id: Uuid =
        sqlx::query_scalar("INSERT INTO papers (doi, title) VALUES ($1, 'legacy') RETURNING id")
            .bind(&legacy_key)
            .fetch_one(&pool)
            .await
            .unwrap();

    let (status, body) = list_by_doi(addr, &token, &bare).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body["total"], 1,
        "a bare-DOI lookup must find the URL-keyed row: {body}"
    );
    assert_eq!(body["items"][0]["id"], legacy_id.to_string(), "{body}");

    let (status, body) = post_paper(addr, &token, &bare).await;
    assert_eq!(status, 200, "{body}");
    let rows = rows_ending_in(&pool, &suffix).await;
    assert_eq!(
        rows,
        vec![(legacy_id, legacy_key.clone())],
        "POST with the bare DOI must reuse the legacy row, not mint a bare twin"
    );
    assert_eq!(body["id"], legacy_id.to_string(), "{body}");
    assert_eq!(
        body["title"], "canonical doi test",
        "the upsert must have updated the row it found: {body}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn non_doi_keys_stay_verbatim_and_distinct_dois_stay_distinct() {
    let (url, pool) = connect().await;
    let (addr, _shutdown) = common::spawn_app(&url).await;
    let (token, _) =
        common::test_bearer_token_with_seeded_client(&pool, &["claims:write", "claims:read"]).await;

    let tag = Uuid::new_v4();
    // A resolver URL with no DOI behind it, and a 2-digit registrant (not a
    // DOI): neither may lose its prefix.
    for key in [
        format!("https://doi.org/about-{tag}"),
        format!("https://doi.org/10.12/short-{tag}"),
    ] {
        let (status, body) = post_paper(addr, &token, &key).await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["doi"], key.as_str(), "stored verbatim: {body}");
    }

    let a = format!("10.5555/e2a.{tag}");
    let b = format!("10.5555/e2b.{tag}");
    let (_, pa) = post_paper(addr, &token, &format!("https://doi.org/{a}")).await;
    let (_, pb) = post_paper(addr, &token, &b).await;
    assert_ne!(pa["id"], pb["id"], "two DOIs are two papers: {pa} {pb}");
    assert_eq!(pa["doi"], a.as_str());
    assert_eq!(pb["doi"], b.as_str());
}
