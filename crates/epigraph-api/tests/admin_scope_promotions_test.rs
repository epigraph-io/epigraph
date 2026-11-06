#![cfg(feature = "db")]

//! Scope-gate regression tests for Bundle F (issues #117 and #120).
//!
//! Every handler that was promoted from `claims:write` (or had no gate) to
//! `claims:admin` gets one test here: mint a `claims:write`-only token and
//! verify the endpoint returns 403. This locks the gates against accidental
//! scope downgrade.
//!
//! For `forget_convention` (Bundle I.2) an additional test verifies that the
//! refuting evidence row is attributed to the calling principal rather than a
//! zero-byte system agent.

mod common;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn spawn() -> (std::net::SocketAddr, tokio::sync::oneshot::Sender<()>) {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    common::spawn_app(&url).await
}

fn write_token() -> String {
    common::test_bearer_token_with_scopes(&["claims:write"])
}

fn admin_token() -> String {
    common::test_bearer_token_with_scopes(&["claims:admin"])
}

// ---------------------------------------------------------------------------
// crud.rs — 7 handlers (build_themes_from_corpus retired with the k-means
// prototype, backlog a0ed0180: tests/theme_kmeans_retired.rs)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn reassign_claim_with_claims_write_returns_403() {
    let (addr, _shutdown) = spawn().await;
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/themes/reassign"))
        .bearer_auth(write_token())
        .json(&serde_json::json!({"claim_id": uuid::Uuid::new_v4()}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "expected 403, got {}", resp.status());
}

#[tokio::test(flavor = "multi_thread")]
async fn assign_unthemed_with_claims_write_returns_403() {
    let (addr, _shutdown) = spawn().await;
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/themes/assign-unthemed"))
        .bearer_auth(write_token())
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "expected 403, got {}", resp.status());
}

#[tokio::test(flavor = "multi_thread")]
async fn recompute_centroids_with_claims_write_returns_403() {
    let (addr, _shutdown) = spawn().await;
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/themes/recompute-centroids"))
        .bearer_auth(write_token())
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "expected 403, got {}", resp.status());
}

#[tokio::test(flavor = "multi_thread")]
async fn create_theme_with_centroid_with_claims_write_returns_403() {
    let (addr, _shutdown) = spawn().await;
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/themes/create-with-centroid"))
        .bearer_auth(write_token())
        .json(&serde_json::json!({"label":"x","description":"y","centroid":[0.1],"claim_ids":[]}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "expected 403, got {}", resp.status());
}

#[tokio::test(flavor = "multi_thread")]
async fn upsert_cluster_with_claims_write_returns_403() {
    let (addr, _shutdown) = spawn().await;
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/clusters"))
        .bearer_auth(write_token())
        .json(&serde_json::json!({"claim_id": uuid::Uuid::new_v4(), "cluster_label": "test"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "expected 403, got {}", resp.status());
}

#[tokio::test(flavor = "multi_thread")]
async fn assign_claim_to_frame_with_claims_write_returns_403() {
    let (addr, _shutdown) = spawn().await;
    let frame_id = uuid::Uuid::new_v4();
    let resp = reqwest::Client::new()
        .post(format!(
            "http://{addr}/api/v1/frames/{frame_id}/assign-claim"
        ))
        .bearer_auth(write_token())
        .json(&serde_json::json!({"claim_id": uuid::Uuid::new_v4()}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "expected 403, got {}", resp.status());
}

#[tokio::test(flavor = "multi_thread")]
async fn promote_staged_edges_with_claims_write_returns_403() {
    let (addr, _shutdown) = spawn().await;
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/edges-staging/promote"))
        .bearer_auth(write_token())
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "expected 403, got {}", resp.status());
}

/// Stage one approved edge between two fresh claims, as a direct database
/// writer does (no application code inserts into `edges_staging`). Returns
/// `(staging_id, source_id, target_id)`.
async fn stage_approved_edge(
    pool: &sqlx::PgPool,
    relationship: &str,
    properties: serde_json::Value,
) -> (uuid::Uuid, uuid::Uuid, uuid::Uuid) {
    let src = common::seed_claim(pool, &format!("staged src {}", uuid::Uuid::new_v4())).await;
    let tgt = common::seed_claim(pool, &format!("staged tgt {}", uuid::Uuid::new_v4())).await;
    let id: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO edges_staging (source_id, target_id, relationship, properties, review_status) \
         VALUES ($1, $2, $3, $4, 'approved') RETURNING id",
    )
    .bind(src)
    .bind(tgt)
    .bind(relationship)
    .bind(properties)
    .fetch_one(pool)
    .await
    .expect("stage edge");
    (id, src, tgt)
}

async fn edges_between(pool: &sqlx::PgPool, src: uuid::Uuid, tgt: uuid::Uuid) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM edges WHERE source_id = $1 AND target_id = $2")
        .bind(src)
        .bind(tgt)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// The stored relationship of the one edge `src -> tgt`.
async fn relationship_between(pool: &sqlx::PgPool, src: uuid::Uuid, tgt: uuid::Uuid) -> String {
    sqlx::query_scalar("SELECT relationship FROM edges WHERE source_id = $1 AND target_id = $2")
        .bind(src)
        .bind(tgt)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn staging_status(pool: &sqlx::PgPool, id: uuid::Uuid) -> String {
    sqlx::query_scalar("SELECT review_status::text FROM edges_staging WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// Serializes the two reserved-key promote tests. Both stage rows into the
/// shared `edges_staging` table, and a promote-all request refuses while ANY
/// approved row carries the key, so the promote-all positive control would
/// otherwise race the other test's forged row.
static PROMOTE_SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// `properties.dedup` marks a dedup act's identity edge, which the un-mark,
/// the index view and the revert planning trust; create and patch (HTTP and
/// MCP) refuse it, and the promote route must too. A request naming a staged
/// row that carries the key is refused WHOLE: neither that row nor a clean row
/// named alongside it is written, and both stay `approved`. The same clean row
/// on its own promotes, so the refusal is the key's, not a broken route.
#[tokio::test(flavor = "multi_thread")]
async fn promote_staged_edges_refuses_a_reserved_dedup_key() {
    let _serial = PROMOTE_SERIAL.lock().await;
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let (forged, f_src, f_tgt) = stage_approved_edge(
        &pool,
        "same_as",
        serde_json::json!({"dedup": {"tool": "forged", "rule": "none"}}),
    )
    .await;
    let (clean, c_src, c_tgt) =
        stage_approved_edge(&pool, "CORROBORATES", serde_json::json!({"note": "ok"})).await;

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/edges-staging/promote"))
        .bearer_auth(admin_token())
        .json(&serde_json::json!({"edge_ids": [forged, clean]}))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body = resp.text().await.unwrap();
    assert_eq!(status, 400, "expected 400, got {status}: {body}");
    assert!(
        body.contains(epigraph_db::DEDUP_IDENTITY_KEY_RESERVED)
            && body.contains(&forged.to_string()),
        "the refusal must carry the reserved-key text and name the staged row: {body}"
    );
    assert!(
        !body.contains(&clean.to_string()),
        "only the offending row is named: {body}"
    );
    assert_eq!(
        edges_between(&pool, f_src, f_tgt).await,
        0,
        "no forged edge"
    );
    assert_eq!(
        edges_between(&pool, c_src, c_tgt).await,
        0,
        "the refusal writes nothing, not even the clean row"
    );
    assert_eq!(staging_status(&pool, forged).await, "approved");
    assert_eq!(staging_status(&pool, clean).await, "approved");

    // Positive control: the clean row alone promotes.
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/edges-staging/promote"))
        .bearer_auth(admin_token())
        .json(&serde_json::json!({"edge_ids": [clean]}))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body = resp.text().await.unwrap();
    assert_eq!(status, 200, "clean promote: {status}: {body}");
    assert_eq!(edges_between(&pool, c_src, c_tgt).await, 1);
    // A staged `CORROBORATES` is promoted in the canonical lower-case
    // spelling every edge writer stores (backlog 3ce5e00c).
    assert_eq!(
        relationship_between(&pool, c_src, c_tgt).await,
        "corroborates"
    );
    assert_eq!(staging_status(&pool, clean).await, "promoted");

    sqlx::query("DELETE FROM edges_staging WHERE id = $1")
        .bind(forged)
        .execute(&pool)
        .await
        .unwrap();
}

/// The promote-all branch (no `edge_ids`) copies every approved row; a staged
/// row carrying `properties.dedup` must refuse it the same way. Once that row
/// is gone, a clean approved row promotes through the same branch (positive
/// control: the refusal is the key's, not a broken promote-all statement).
#[tokio::test(flavor = "multi_thread")]
async fn promote_all_staged_edges_refuses_a_reserved_dedup_key() {
    let _serial = PROMOTE_SERIAL.lock().await;
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let (forged, f_src, f_tgt) = stage_approved_edge(
        &pool,
        "same_as",
        serde_json::json!({"dedup": {"tool": "forged", "rule": "none"}}),
    )
    .await;

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/edges-staging/promote"))
        .bearer_auth(admin_token())
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body = resp.text().await.unwrap();
    assert_eq!(status, 400, "expected 400, got {status}: {body}");
    assert!(
        body.contains(epigraph_db::DEDUP_IDENTITY_KEY_RESERVED)
            && body.contains(&forged.to_string()),
        "the refusal must carry the reserved-key text and name the staged row: {body}"
    );
    assert_eq!(
        edges_between(&pool, f_src, f_tgt).await,
        0,
        "no forged edge"
    );
    assert_eq!(staging_status(&pool, forged).await, "approved");

    sqlx::query("DELETE FROM edges_staging WHERE id = $1")
        .bind(forged)
        .execute(&pool)
        .await
        .unwrap();

    // Positive control on the promote-all branch: with the forged row gone, a
    // clean approved row promotes. Asserted on this row only, since other
    // approved rows in the shared table may promote alongside it.
    let (clean, c_src, c_tgt) =
        stage_approved_edge(&pool, "CORROBORATES", serde_json::json!({"note": "ok"})).await;
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/edges-staging/promote"))
        .bearer_auth(admin_token())
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body = resp.text().await.unwrap();
    assert_eq!(status, 200, "clean promote-all: {status}: {body}");
    assert_eq!(edges_between(&pool, c_src, c_tgt).await, 1);
    assert_eq!(
        relationship_between(&pool, c_src, c_tgt).await,
        "corroborates",
        "the promote-all branch stores the canonical spelling too"
    );
    assert_eq!(staging_status(&pool, clean).await, "promoted");
}

/// A paper's `asserts` onto a claim and an agent-sourced `asserts` are the
/// document ingest's (or the agent's own) to write: a staged row has no author
/// who could speak for the agent. The promote refuses either, on BOTH
/// branches, naming the rows; nothing is written, not even a clean row named
/// alongside, and every row stays `approved`. The clean row alone promotes
/// (positive control: the refusal is the relationship's).
#[tokio::test(flavor = "multi_thread")]
async fn promote_staged_edges_refuses_the_ingests_provenance_and_agent_attributions() {
    let _serial = PROMOTE_SERIAL.lock().await;
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let claim = common::seed_claim(
        &pool,
        &format!("staged provenance {}", uuid::Uuid::new_v4()),
    )
    .await;
    let paper: uuid::Uuid =
        sqlx::query_scalar("INSERT INTO papers (doi, title) VALUES ($1, $1) RETURNING id")
            .bind(format!(
                "10.9999/staged-provenance-{}",
                uuid::Uuid::new_v4()
            ))
            .fetch_one(&pool)
            .await
            .unwrap();
    let agent = common::seed_system_agent(&pool).await;
    let stage = |source: uuid::Uuid, source_type: &'static str| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, uuid::Uuid>(
                "INSERT INTO edges_staging (source_id, source_type, target_id, target_type, \
                                            relationship, properties, review_status) \
                 VALUES ($1, $2, $3, 'claim', 'asserts', '{}'::jsonb, 'approved') RETURNING id",
            )
            .bind(source)
            .bind(source_type)
            .bind(claim)
            .fetch_one(&pool)
            .await
            .unwrap()
        }
    };
    let from_paper = stage(paper, "paper").await;
    let from_agent = stage(agent, "agent").await;
    let (clean, c_src, c_tgt) =
        stage_approved_edge(&pool, "CORROBORATES", serde_json::json!({"note": "ok"})).await;
    let into_claim = || async {
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM edges WHERE target_id = $1 AND relationship = 'asserts'",
        )
        .bind(claim)
        .fetch_one(&pool)
        .await
        .unwrap()
    };

    for body in [
        serde_json::json!({"edge_ids": [from_paper, from_agent, clean]}),
        serde_json::json!({}),
    ] {
        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/api/v1/edges-staging/promote"))
            .bearer_auth(admin_token())
            .json(&body)
            .send()
            .await
            .unwrap();
        let status = resp.status();
        let text = resp.text().await.unwrap();
        assert_eq!(status, 400, "{body}: expected 400, got {status}: {text}");
        assert!(
            text.contains("document ingest")
                && text.contains(&from_paper.to_string())
                && text.contains(&from_agent.to_string()),
            "{body}: the refusal names the rule and both staged rows: {text}"
        );
        assert_eq!(into_claim().await, 0, "{body}: nothing written");
        assert_eq!(edges_between(&pool, c_src, c_tgt).await, 0, "{body}");
        for id in [from_paper, from_agent, clean] {
            assert_eq!(staging_status(&pool, id).await, "approved", "{body}");
        }
    }

    // Positive control: the clean row alone promotes.
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/edges-staging/promote"))
        .bearer_auth(admin_token())
        .json(&serde_json::json!({"edge_ids": [clean]}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "clean promote");
    assert_eq!(edges_between(&pool, c_src, c_tgt).await, 1);

    sqlx::query("DELETE FROM edges_staging WHERE id = ANY($1)")
        .bind(vec![from_paper, from_agent])
        .execute(&pool)
        .await
        .unwrap();
}

/// `properties.supersede_act` marks a supersession's own `AUTHORED` edge,
/// which the arming census and the edge migration key on; create and patch
/// (HTTP and MCP) refuse it, and so does the promote route, on BOTH branches
/// (named rows and promote-all): nothing is written and the row stays
/// `approved`. The clean-row positive controls of the dedup tests above run
/// the same statements.
#[tokio::test(flavor = "multi_thread")]
async fn promote_staged_edges_refuses_the_supersede_act_marker() {
    let _serial = PROMOTE_SERIAL.lock().await;
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let (forged, f_src, f_tgt) = stage_approved_edge(
        &pool,
        "CORROBORATES",
        serde_json::json!({"supersede_act": "supersede_claim"}),
    )
    .await;
    for body in [
        serde_json::json!({"edge_ids": [forged]}),
        serde_json::json!({}),
    ] {
        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/api/v1/edges-staging/promote"))
            .bearer_auth(admin_token())
            .json(&body)
            .send()
            .await
            .unwrap();
        let status = resp.status();
        let text = resp.text().await.unwrap();
        assert_eq!(status, 400, "{body}: expected 400, got {status}: {text}");
        assert!(
            text.contains("supersede_act") && text.contains(&forged.to_string()),
            "{body}: the refusal names the reserved key and the staged row: {text}"
        );
        assert_eq!(
            edges_between(&pool, f_src, f_tgt).await,
            0,
            "{body}: no forged edge"
        );
        assert_eq!(staging_status(&pool, forged).await, "approved");
    }

    sqlx::query("DELETE FROM edges_staging WHERE id = $1")
        .bind(forged)
        .execute(&pool)
        .await
        .unwrap();
}

/// X-2 (supersede SPEC section 11 phase 1, SF-27; backlog 69c78f9a): a
/// REGRESSION PIN, not a red test. Both statement arms of the promote (named
/// `edge_ids`, promote-all) already refuse a staged row whose `properties`
/// carry a reserved act key; this pins each arm against each key with the
/// exact text `epigraph_db::reserved_edge_property_refusal` gives for that
/// row (the dedup tests above pin only the dedup text, the supersede-act test
/// only the key's name): 400, the staged row named, no edge between its
/// endpoints, and the row still `approved`.
#[tokio::test(flavor = "multi_thread")]
async fn promote_staged_edges_refuses_each_reserved_key_on_each_arm() {
    let _serial = PROMOTE_SERIAL.lock().await;
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    let (addr, _shutdown) = common::spawn_app(&url).await;

    for (relationship, properties) in [
        (
            "same_as",
            serde_json::json!({"dedup": {"tool": "forged", "rule": "none"}}),
        ),
        (
            "AUTHORED",
            serde_json::json!({"supersede_act": "supersede_claim"}),
        ),
    ] {
        let expected = epigraph_db::reserved_edge_property_refusal(&properties)
            .expect("calibration: the key is reserved");
        let (staged, s_src, s_tgt) =
            stage_approved_edge(&pool, relationship, properties.clone()).await;
        for body in [
            serde_json::json!({"edge_ids": [staged]}),
            serde_json::json!({}),
        ] {
            let resp = reqwest::Client::new()
                .post(format!("http://{addr}/api/v1/edges-staging/promote"))
                .bearer_auth(admin_token())
                .json(&body)
                .send()
                .await
                .unwrap();
            let status = resp.status();
            let text = resp.text().await.unwrap();
            assert_eq!(status, 400, "{properties} {body}: got {status}: {text}");
            assert!(
                text.contains(expected) && text.contains(&staged.to_string()),
                "{properties} {body}: the refusal carries the reserved-key text and names \
                 the row: {text}"
            );
            assert_eq!(
                edges_between(&pool, s_src, s_tgt).await,
                0,
                "{properties} {body}: nothing promoted"
            );
            assert_eq!(staging_status(&pool, staged).await, "approved");
        }
        sqlx::query("DELETE FROM edges_staging WHERE id = $1")
            .bind(staged)
            .execute(&pool)
            .await
            .unwrap();
    }
}

/// K12a (supersede SPEC section 11; ruling R-132 "supersedes = revision
/// only"): a staged `supersedes` edge, in any spelling, is not promoted on
/// either branch. The promote copies a staged row's relationship verbatim
/// (only the case-folded four are lower-cased), so before K12a it published a
/// lineage edge that retires nothing. The request is refused whole (400 on
/// `relationship`, naming the act and the staged row), nothing is written and
/// the row stays `approved`; the clean-row positive controls above run the
/// same statements.
#[tokio::test(flavor = "multi_thread")]
async fn promote_staged_edges_refuses_a_staged_supersedes_edge() {
    let _serial = PROMOTE_SERIAL.lock().await;
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    let (addr, _shutdown) = common::spawn_app(&url).await;

    for rel in ["supersedes", "SUPERSEDES", "Supersedes"] {
        let (staged, s_src, s_tgt) =
            stage_approved_edge(&pool, rel, serde_json::json!({"note": "k12a"})).await;
        for body in [
            serde_json::json!({"edge_ids": [staged]}),
            serde_json::json!({}),
        ] {
            let resp = reqwest::Client::new()
                .post(format!("http://{addr}/api/v1/edges-staging/promote"))
                .bearer_auth(admin_token())
                .json(&body)
                .send()
                .await
                .unwrap();
            let status = resp.status();
            let text = resp.text().await.unwrap();
            assert_eq!(
                status, 400,
                "{rel} {body}: expected 400, got {status}: {text}"
            );
            assert!(
                text.contains("written only by the supersession act")
                    && text.contains(&staged.to_string()),
                "{rel} {body}: the refusal names the act and the staged row: {text}"
            );
            assert_eq!(
                edges_between(&pool, s_src, s_tgt).await,
                0,
                "{rel} {body}: no lineage edge"
            );
            assert_eq!(staging_status(&pool, staged).await, "approved");
        }
        sqlx::query("DELETE FROM edges_staging WHERE id = $1")
            .bind(staged)
            .execute(&pool)
            .await
            .unwrap();
    }
}

/// POST the staged-edge promote with `body`; `(status, text)`.
async fn promote(addr: std::net::SocketAddr, body: serde_json::Value) -> (u16, String) {
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/edges-staging/promote"))
        .bearer_auth(admin_token())
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    (status, resp.text().await.unwrap())
}

/// K12a (supersede SPEC section 11 phase 1 K12 (a)): a staged `supersedes` row
/// refuses the WHOLE promote request on each arm, not just its own row. Each
/// arm runs as one auto-commit statement that returns the 400 after the
/// statement has run, so only the statement's own "no lineage row in the
/// request" condition keeps the clean rows beside it unpromoted: a per-row
/// exclusion would promote them and still answer 400.
///
/// (a) `edge_ids` arm: `[supersedes_row, clean_row]` is 400 naming only the
/// lineage row, no edge for either pair, both rows still `approved`; then
/// `[clean_row]` alone promotes (an in-test positive control).
/// (b) promote-all arm: a clean approved row beside an approved supersedes row
/// is 400 and the clean row is not promoted; once the supersedes row is gone,
/// promote-all promotes the clean row.
#[tokio::test(flavor = "multi_thread")]
async fn promote_staged_edges_refuses_a_request_holding_a_staged_supersedes_row_whole() {
    let _serial = PROMOTE_SERIAL.lock().await;
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    let (addr, _shutdown) = common::spawn_app(&url).await;

    // (a) the named edge_ids arm.
    let (lineage, l_src, l_tgt) =
        stage_approved_edge(&pool, "supersedes", serde_json::json!({"note": "k12a"})).await;
    let (clean, c_src, c_tgt) =
        stage_approved_edge(&pool, "CORROBORATES", serde_json::json!({"note": "ok"})).await;
    let (status, text) = promote(addr, serde_json::json!({"edge_ids": [lineage, clean]})).await;
    assert_eq!(status, 400, "edge_ids: {text}");
    assert!(
        text.contains("written only by the supersession act")
            && text.contains(&lineage.to_string()),
        "edge_ids: the refusal names the act and the lineage row: {text}"
    );
    assert!(
        !text.contains(&clean.to_string()),
        "edge_ids: only the lineage row is named: {text}"
    );
    assert_eq!(
        edges_between(&pool, l_src, l_tgt).await,
        0,
        "edge_ids: no lineage edge"
    );
    assert_eq!(
        edges_between(&pool, c_src, c_tgt).await,
        0,
        "edge_ids: the refusal writes nothing, not even the clean row"
    );
    assert_eq!(staging_status(&pool, lineage).await, "approved");
    assert_eq!(staging_status(&pool, clean).await, "approved");

    let (status, text) = promote(addr, serde_json::json!({"edge_ids": [clean]})).await;
    assert_eq!(
        status, 200,
        "edge_ids CONTROL: the clean row alone promotes: {text}"
    );
    assert_eq!(
        edges_between(&pool, c_src, c_tgt).await,
        1,
        "edge_ids CONTROL"
    );
    assert_eq!(
        staging_status(&pool, clean).await,
        "promoted",
        "edge_ids CONTROL"
    );

    // (b) the promote-all arm; the lineage row from (a) is still approved.
    let (clean_all, a_src, a_tgt) =
        stage_approved_edge(&pool, "CORROBORATES", serde_json::json!({"note": "ok"})).await;
    let (status, text) = promote(addr, serde_json::json!({})).await;
    assert_eq!(status, 400, "promote-all: {text}");
    assert!(
        text.contains("written only by the supersession act")
            && text.contains(&lineage.to_string()),
        "promote-all: the refusal names the act and the lineage row: {text}"
    );
    assert_eq!(
        edges_between(&pool, l_src, l_tgt).await,
        0,
        "promote-all: no lineage edge"
    );
    assert_eq!(
        edges_between(&pool, a_src, a_tgt).await,
        0,
        "promote-all: the refusal writes nothing, not even the clean row"
    );
    assert_eq!(staging_status(&pool, lineage).await, "approved");
    assert_eq!(staging_status(&pool, clean_all).await, "approved");

    sqlx::query("DELETE FROM edges_staging WHERE id = $1")
        .bind(lineage)
        .execute(&pool)
        .await
        .unwrap();
    let (status, text) = promote(addr, serde_json::json!({})).await;
    assert_eq!(
        status, 200,
        "promote-all CONTROL: without the lineage row it promotes: {text}"
    );
    assert_eq!(
        edges_between(&pool, a_src, a_tgt).await,
        1,
        "promote-all CONTROL"
    );
    assert_eq!(
        staging_status(&pool, clean_all).await,
        "promoted",
        "promote-all CONTROL"
    );
}

// ---------------------------------------------------------------------------
// clusters.rs — 1 handler
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn build_from_bridges_with_claims_write_returns_403() {
    let (addr, _shutdown) = spawn().await;
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/clusters/build-from-bridges"))
        .bearer_auth(write_token())
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "expected 403, got {}", resp.status());
}

// ---------------------------------------------------------------------------
// conflicts.rs — 1 handler
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn resolve_conflict_with_claims_write_returns_403() {
    let (addr, _shutdown) = spawn().await;
    let a = uuid::Uuid::new_v4();
    let b = uuid::Uuid::new_v4();
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/conflicts/{a}/{b}/resolve"))
        .bearer_auth(write_token())
        .json(&serde_json::json!({"winner_id": a, "resolution": "test"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "expected 403, got {}", resp.status());
}

// ---------------------------------------------------------------------------
// conventions.rs — 2 handlers
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn learn_convention_with_claims_write_returns_403() {
    let (addr, _shutdown) = spawn().await;
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/conventions"))
        .bearer_auth(write_token())
        .json(&serde_json::json!({"content": "Always test", "evidence": "tests pass"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "expected 403, got {}", resp.status());
}

#[tokio::test(flavor = "multi_thread")]
async fn forget_convention_with_claims_write_returns_403() {
    let (addr, _shutdown) = spawn().await;
    let convention_id = uuid::Uuid::new_v4();
    let resp = reqwest::Client::new()
        .delete(format!("http://{addr}/api/v1/conventions/{convention_id}"))
        .bearer_auth(write_token())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "expected 403, got {}", resp.status());
}

/// Bundle I.2 — verify forget_convention attributes evidence to the calling
/// principal, not a zero-byte system agent.
#[tokio::test(flavor = "multi_thread")]
async fn forget_convention_attributes_evidence_to_caller() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();

    let (addr, _shutdown) = common::spawn_app(&url).await;

    // 1. Create a convention via the API (requires claims:admin).
    // Use a UUID-suffixed content to avoid content_hash collisions across test runs.
    let unique_suffix = uuid::Uuid::new_v4();
    let learn_resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/conventions"))
        .bearer_auth(admin_token())
        .json(&serde_json::json!({
            "content": format!("attribution-test convention {unique_suffix}"),
            "evidence": "seeded for attribution test"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        learn_resp.status(),
        201,
        "learn_convention should succeed: {}",
        learn_resp.status()
    );
    let learn_body: serde_json::Value = learn_resp.json().await.unwrap();
    let convention_id = learn_body["claim_id"]
        .as_str()
        .expect("claim_id in response");

    // 2. Mint a token with a known client_id so we can assert on agent identity.
    let (forget_token, caller_client_id) =
        common::test_bearer_token_with_seeded_client(&pool, &["claims:admin"]).await;

    // 3. Forget the convention using the seeded-client token.
    let forget_resp = reqwest::Client::new()
        .delete(format!("http://{addr}/api/v1/conventions/{convention_id}"))
        .bearer_auth(&forget_token)
        .send()
        .await
        .unwrap();
    assert_eq!(
        forget_resp.status(),
        200,
        "forget_convention should succeed: {}",
        forget_resp.status()
    );

    // 4. Derive the expected principal public key (16-byte UUID repeated to 32 bytes).
    let principal_bytes = caller_client_id.as_bytes();
    let mut expected_pub_key = vec![0u8; 32];
    expected_pub_key[..16].copy_from_slice(principal_bytes);
    expected_pub_key[16..].copy_from_slice(principal_bytes);

    // 5. Find the agents row for this principal.
    let agent_id: Option<uuid::Uuid> =
        sqlx::query_scalar("SELECT id FROM agents WHERE public_key = $1 LIMIT 1")
            .bind(&expected_pub_key)
            .fetch_optional(&pool)
            .await
            .unwrap();
    assert!(
        agent_id.is_some(),
        "Expected an agents row keyed by caller's principal public_key to exist"
    );

    let agent_id = agent_id.unwrap();
    let convention_uuid: uuid::Uuid = convention_id.parse().unwrap();

    // 6. Verify the refuting evidence row exists for this convention.
    // (Unsigned evidence has signer_id = NULL by DB constraint; we verify existence.)
    let evidence_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM evidence \
         WHERE claim_id = $1 \
         AND raw_content = 'Convention explicitly forgotten/deprecated'",
    )
    .bind(convention_uuid)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        evidence_count >= 1,
        "Expected at least one refute evidence row for convention (claim_id={convention_uuid}), got {evidence_count}"
    );

    // 7. Verify the principal-keyed agents row was created (not the zero-byte identity).
    // This is the core of the attribution fix: get-or-create an agent per principal,
    // rather than always using the zero-byte system agent.
    assert!(
        agent_id != uuid::Uuid::nil(),
        "Principal agent should have a non-nil UUID"
    );

    // 8. Confirm the principal agent's display_name encodes the principal identity.
    let display_name: Option<String> =
        sqlx::query_scalar("SELECT display_name FROM agents WHERE id = $1")
            .bind(agent_id)
            .fetch_optional(&pool)
            .await
            .unwrap();
    let display_name = display_name.unwrap_or_default();
    assert!(
        display_name.contains("principal:"),
        "Principal agent display_name should encode the principal UUID; got: {display_name:?}"
    );
}

// ---------------------------------------------------------------------------
// ownership.rs — 2 handlers, BOTH DELETED BY PR-14
// ---------------------------------------------------------------------------
//
// `assign_ownership_with_claims_write_returns_403` and
// `update_partition_with_claims_write_returns_403` lived here. They minted a
// `claims:write`-only token, called `POST /api/v1/ownership` and
// `PUT /api/v1/ownership/:node_id`, and required 403 — locking those two gates
// against an accidental downgrade to `claims:write`.
//
// PR-14 deleted both routes (and their MCP twins), so the requests now return
// 404 and the assertions fail for a reason that has nothing to do with scopes.
// There is no way to retarget them: the property is "THIS endpoint demands
// claims:admin", and the endpoint is gone.
//
// The concern they encoded is not dropped, it is resolved more strongly than a
// 403 ever expressed it. PR-12 recorded a live asymmetry — MCP gated
// `assign_ownership` at `claims:write` while the HTTP route with the identical
// declassification power demanded `claims:admin`, so the cheaper transport
// reached the same capability. Deleting both surfaces closes that asymmetry at
// the source rather than by levelling two scope entries, and
// `epigraph-mcp/src/scope_map.rs` lost all three ownership entries in the same
// commit. A capability that does not exist cannot be reached with the wrong
// scope.
//
// Every other handler promoted by Bundle F still has its case below/above.
