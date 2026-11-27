//! MCP `recall`'s `route` parameter (backlog a47df8ed): `similarity` (the
//! default), `auto` and `hierarchical`, served by the engine's own sparse-page
//! test, viewer-scoped theme leg and RRF merge
//! (`epigraph_engine::recall::{ann_page_is_sparse, theme_leg_on, rrf_merge}`).
//!
//! Every params struct is built with `serde_json::from_value`, so this file
//! compiles on the code before the change: `RecallParams` has no
//! `deny_unknown_fields`, so a `route` key is simply ignored there and each
//! route test fails on an assertion, not on a compile error.
//!
//! ## Geometry (the engine's `recall_theme_leg.rs` fixture, on MCP's page)
//!
//! 1536-d vectors in 16 buckets of 96. The query is pure bucket 0, and so is
//! the theme's centroid. A vector "bucket `b` with share `s`" is `s` in bucket
//! 0 plus 1.0 in bucket `b`, so its cosine to the query is set by `s`:
//!
//! - `ann_a` (0.36, cos ~0.339) and `ann_b` (0.35, cos ~0.330): the two
//!   claims nearest the query, outside any theme, and below the engine's 0.4
//!   sparse threshold, so `auto` traverses;
//! - `member` (0.2, cos ~0.196): a public theme member FARTHER from the query
//!   than both, so a similarity page of 2 never holds it;
//! - `private_member` (0.3, cos ~0.287): a group-private member of the same
//!   theme, closer than `member`, so a theme leg that forgot the viewer would
//!   rank it first.
//!
//! The query text matches no claim's content, so the hybrid page's lexical
//! leg is empty and the page is the dense leg alone.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_mcp::tools::memory::__test_only::recall_with_pgvec;
use epigraph_mcp::types::RecallParams;
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

const DIM: usize = 1536;
const STRIDE: usize = DIM / 16;
/// Matches no seeded content, so the lexical leg contributes nothing.
const QUERY: &str = "zyxwvroutequery";

fn vec_to_pgvec(v: &[f32]) -> String {
    format!(
        "[{}]",
        v.iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>()
            .join(",")
    )
}

/// Bucket 0 at `query_share` plus `far_bucket` at 1.0.
fn mixed(far_bucket: usize, query_share: f32) -> String {
    let mut v = vec![0.0f32; DIM];
    for slot in v.iter_mut().take(STRIDE) {
        *slot = query_share;
    }
    for slot in v.iter_mut().skip(far_bucket * STRIDE).take(STRIDE) {
        *slot = 1.0;
    }
    vec_to_pgvec(&v)
}

/// Pure bucket 0: the query, and the theme centroid.
fn query_bucket() -> String {
    let mut v = vec![0.0f32; DIM];
    for slot in v.iter_mut().take(STRIDE) {
        *slot = 1.0;
    }
    vec_to_pgvec(&v)
}

async fn seed_theme(pool: &PgPool, label: &str, centroid: &str) -> Uuid {
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO claim_themes (label, description) VALUES ($1, 'mcp recall route test') \
         RETURNING id",
    )
    .bind(label)
    .fetch_one(pool)
    .await
    .expect("insert theme");
    sqlx::query("UPDATE claim_themes SET centroid = $2::vector WHERE id = $1")
        .bind(id)
        .bind(centroid)
        .execute(pool)
        .await
        .expect("set centroid");
    id
}

async fn embed_and_theme(pool: &PgPool, claim: Uuid, vec: &str, theme: Option<Uuid>) {
    fixture::set_claim_embedding(pool, claim, vec).await;
    sqlx::query("UPDATE claims SET truth_value = 0.8, theme_id = $2 WHERE id = $1")
        .bind(claim)
        .bind(theme)
        .execute(pool)
        .await
        .expect("set theme");
}

struct Corpus {
    ann_a: Uuid,
    ann_b: Uuid,
    member: Uuid,
    private_member: Uuid,
    theme: Uuid,
    author: Uuid,
    outsider: Uuid,
}

async fn seed(pool: &PgPool) -> Corpus {
    let (author, group) = fixture::seed_agent_with_group(pool, "a47df8ed-mcp-author").await;
    let (outsider, _) = fixture::seed_agent_with_group(pool, "a47df8ed-mcp-outsider").await;
    let theme = seed_theme(pool, "a47df8ed-mcp-theme", &query_bucket()).await;

    let ann_a = fixture::seed_public_claim(pool, author, "near claim a").await;
    embed_and_theme(pool, ann_a, &mixed(3, 0.36), None).await;
    let ann_b = fixture::seed_public_claim(pool, author, "near claim b").await;
    embed_and_theme(pool, ann_b, &mixed(4, 0.35), None).await;

    let member = fixture::seed_public_claim(pool, author, "theme member").await;
    embed_and_theme(pool, member, &mixed(5, 0.2), Some(theme)).await;

    let private_member =
        fixture::seed_group_claim(pool, author, group, "private theme member").await;
    embed_and_theme(pool, private_member, &mixed(6, 0.3), Some(theme)).await;

    Corpus {
        ann_a,
        ann_b,
        member,
        private_member,
        theme,
        author,
        outsider,
    }
}

fn build_server(pool: PgPool, scoped: epigraph_db::ScopedPool) -> epigraph_mcp::EpiGraphMcpFull {
    use epigraph_crypto::AgentSigner;
    use epigraph_mcp::embed::McpEmbedder;
    use epigraph_mcp::EpiGraphMcpFull;
    let signer = AgentSigner::from_bytes(&[0u8; 32]).expect("signer");
    let embedder = McpEmbedder::new(pool.clone(), None);
    EpiGraphMcpFull::new(pool, signer, embedder, /*read_only=*/ false).with_scoped_pool(scoped)
}

fn params(extra: Value) -> RecallParams {
    let mut p = json!({ "query": QUERY, "min_truth": 0.0 });
    for (k, v) in extra.as_object().expect("object").clone() {
        p[k] = v;
    }
    serde_json::from_value(p).expect("params")
}

/// The response text exactly as the tool returns it.
async fn recall_text(
    server: &epigraph_mcp::EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    p: RecallParams,
) -> String {
    let out = recall_with_pgvec(server, viewer, p, Some(query_bucket()))
        .await
        .expect("recall ok");
    out.content
        .iter()
        .find_map(|c| c.as_text().map(|t| t.text.clone()))
        .expect("text content")
}

async fn recall_body(
    server: &epigraph_mcp::EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    p: RecallParams,
) -> Value {
    serde_json::from_str(&recall_text(server, viewer, p).await).expect("recall envelope")
}

fn ids(body: &Value) -> Vec<String> {
    body["results"]
        .as_array()
        .unwrap_or_else(|| panic!("results array: {body}"))
        .iter()
        .map(|r| r["claim_id"].as_str().expect("claim_id").to_string())
        .collect()
}

fn row(body: &Value, id: Uuid) -> &Value {
    body["results"]
        .as_array()
        .expect("results")
        .iter()
        .find(|r| r["claim_id"] == id.to_string())
        .unwrap_or_else(|| panic!("{id} missing: {body}"))
}

/// The default route is the hybrid page as it was before `route` existed,
/// byte for byte. The snapshot below was captured on the code before this
/// change (the same test, run there): only the run-specific values, the two
/// claim ids, their `created_at` and the minted `recall_event_id`, are
/// replaced by placeholders. Passing `route: "similarity"` serves the same
/// page plus `route_used`, and nothing else.
#[sqlx::test(migrations = "../../migrations")]
async fn default_route_output_is_byte_identical(pool: PgPool) {
    let c = seed(&pool).await;
    let scoped = fixture::scoped_pool(&pool).await;
    let server = build_server(pool.clone(), scoped);
    let viewer = epigraph_db::Viewer::resolve(&pool, c.outsider)
        .await
        .expect("viewer");

    let text = recall_text(&server, &viewer, params(json!({ "limit": 2 }))).await;
    let body: Value = serde_json::from_str(&text).expect("envelope");
    let mut normalized = text.clone();
    for (id, name) in [(c.ann_a, "<ann_a>"), (c.ann_b, "<ann_b>")] {
        normalized = normalized.replace(&id.to_string(), name);
    }
    for r in body["results"].as_array().expect("results") {
        let ts = r["created_at"].as_str().expect("created_at");
        normalized = normalized.replace(ts, "<ts>");
    }
    let event = body["recall_event_id"].as_str().expect("event id");
    normalized = normalized.replace(event, "<event>");

    let expected = r#"{
  "results": [
    {
      "claim_id": "<ann_a>",
      "content": "near claim a",
      "truth_value": 0.8,
      "belief_score": 0.8,
      "similarity": 0.33871951191338734,
      "rrf_score": 0.01639344262295082,
      "matched_via": [
        "dense"
      ],
      "created_at": "<ts>"
    },
    {
      "claim_id": "<ann_b>",
      "content": "near claim b",
      "truth_value": 0.8,
      "belief_score": 0.8,
      "similarity": 0.3303503806402759,
      "rrf_score": 0.016129032258064516,
      "matched_via": [
        "dense"
      ],
      "created_at": "<ts>"
    }
  ],
  "recall_event_id": "<event>",
  "n_total_candidates": 0,
  "coverage_rate": 1.0,
  "candidate_pool_saturated": false
}"#;
    assert_eq!(
        normalized, expected,
        "the default recall output moved; raw response: {text}"
    );
}

/// `route: "similarity"` is the default page with `route_used` added, and no
/// `theme_leg`.
#[sqlx::test(migrations = "../../migrations")]
async fn explicit_similarity_serves_the_default_page(pool: PgPool) {
    let c = seed(&pool).await;
    let scoped = fixture::scoped_pool(&pool).await;
    let server = build_server(pool.clone(), scoped);
    let viewer = epigraph_db::Viewer::resolve(&pool, c.outsider)
        .await
        .expect("viewer");

    let default = recall_body(&server, &viewer, params(json!({ "limit": 2 }))).await;
    let similarity = recall_body(
        &server,
        &viewer,
        params(json!({ "limit": 2, "route": "similarity" })),
    )
    .await;
    assert_eq!(ids(&default), ids(&similarity));
    assert_eq!(default["results"], similarity["results"]);
    assert_eq!(similarity["route_used"], "similarity", "{similarity}");
    assert!(similarity.get("theme_leg").is_none(), "{similarity}");
    assert!(default.get("route_used").is_none(), "{default}");
}

/// `auto` on a sparse page (best cosine ~0.34 < 0.4): the theme leg runs, its
/// member is RRF-merged onto the limit-2 page that similarity fills with the
/// two ANN-nearest claims, and the response says so.
#[sqlx::test(migrations = "../../migrations")]
async fn auto_on_a_sparse_page_adds_theme_hits(pool: PgPool) {
    let c = seed(&pool).await;
    let scoped = fixture::scoped_pool(&pool).await;
    let server = build_server(pool.clone(), scoped);
    let viewer = epigraph_db::Viewer::resolve(&pool, c.outsider)
        .await
        .expect("viewer");

    // Control: the similarity page holds the two ANN hits and not the member.
    let similarity = recall_body(&server, &viewer, params(json!({ "limit": 2 }))).await;
    let got = ids(&similarity);
    assert_eq!(got.len(), 2, "{similarity}");
    assert!(!got.contains(&c.member.to_string()), "{similarity}");

    let auto = recall_body(
        &server,
        &viewer,
        params(json!({ "limit": 2, "route": "auto" })),
    )
    .await;
    let got = ids(&auto);
    assert_eq!(got.len(), 2, "limit holds after the merge: {auto}");
    assert_eq!(
        got[0],
        c.ann_a.to_string(),
        "the top ANN hit keeps rank 1: {auto}"
    );
    let member = row(&auto, c.member);
    assert_eq!(member["matched_via"], json!(["theme"]), "{auto}");
    let sim = member["similarity"].as_f64().expect("similarity");
    assert!(
        (sim - 0.196).abs() < 0.02,
        "a theme hit reports its real cosine, got {sim}: {auto}"
    );
    assert_eq!(auto["route_used"], "auto", "{auto}");
    assert_eq!(auto["theme_leg"]["added"], 1, "{auto}");
    assert_eq!(
        auto["theme_leg"]["themes"][0]["theme_id"],
        c.theme.to_string(),
        "{auto}"
    );
}

/// `auto` on a page that is NOT sparse runs no theme leg: the page is the
/// similarity page and `route_used` reports `similarity`.
#[sqlx::test(migrations = "../../migrations")]
async fn auto_on_a_full_strong_page_does_not_traverse(pool: PgPool) {
    let c = seed(&pool).await;
    // Five claims at cosine 1.0 to the query: a full (limit 5), strong page.
    let mut strong = Vec::new();
    for i in 0..5 {
        let id = fixture::seed_public_claim(&pool, c.author, &format!("strong claim {i}")).await;
        embed_and_theme(&pool, id, &query_bucket(), None).await;
        strong.push(id.to_string());
    }
    let scoped = fixture::scoped_pool(&pool).await;
    let server = build_server(pool.clone(), scoped);
    let viewer = epigraph_db::Viewer::resolve(&pool, c.outsider)
        .await
        .expect("viewer");

    let similarity = recall_body(&server, &viewer, params(json!({ "limit": 5 }))).await;
    let auto = recall_body(
        &server,
        &viewer,
        params(json!({ "limit": 5, "route": "auto" })),
    )
    .await;
    assert_eq!(similarity["results"], auto["results"], "{auto}");
    assert_eq!(auto["route_used"], "similarity", "{auto}");
    assert!(auto.get("theme_leg").is_none(), "{auto}");
    let mut got = ids(&auto);
    got.sort();
    strong.sort();
    assert_eq!(got, strong, "{auto}");
}

/// `hierarchical` is the theme leg alone: the ANN-nearest claims carry no
/// theme, so they cannot appear, and every row is a theme member.
#[sqlx::test(migrations = "../../migrations")]
async fn hierarchical_returns_theme_members_only(pool: PgPool) {
    let c = seed(&pool).await;
    let scoped = fixture::scoped_pool(&pool).await;
    let server = build_server(pool.clone(), scoped);
    let viewer = epigraph_db::Viewer::resolve(&pool, c.author)
        .await
        .expect("viewer");

    let body = recall_body(
        &server,
        &viewer,
        params(json!({ "limit": 10, "route": "hierarchical" })),
    )
    .await;
    let got = ids(&body);
    assert_eq!(
        got,
        vec![c.private_member.to_string(), c.member.to_string()],
        "the author's two theme members, nearest first, and nothing else: {body}"
    );
    for r in body["results"].as_array().expect("results") {
        assert_eq!(r["matched_via"], json!(["theme"]), "{body}");
    }
    assert_eq!(body["route_used"], "hierarchical", "{body}");
    assert_eq!(body["theme_leg"]["added"], 2, "{body}");
    assert!(
        body.get("n_total_candidates").is_none(),
        "no hybrid pool ran, so no coverage is reported: {body}"
    );
}

/// A group-private theme member never reaches an outsider, on either theme
/// route, AS THE APPLICATION ROLE in both GUC modes, where row security is
/// decided by the connection's stamp and not only by the in-query predicate.
/// The author's own page carrying it is the control: an unstamped theme read
/// would hide it from the author too.
///
/// The private member is nearer the query than the public one, so a theme leg
/// that ignored the viewer would spend the one slot of a limit-1 page on it,
/// and the per-claim read would then drop it and serve an empty page.
#[sqlx::test(migrations = "../../migrations")]
async fn a_private_theme_member_is_invisible_to_an_outsider(pool: PgPool) {
    let c = seed(&pool).await;
    let url = fixture::database_url_for(&pool).await;
    for mode in [
        epigraph_db::SessionGucMode::Session,
        epigraph_db::SessionGucMode::Transaction,
    ] {
        let scoped =
            epigraph_db::ScopedPool::connect_downgraded_for_tests(&url, mode, "epigraph_app")
                .await
                .expect("app-role ScopedPool");
        let app = scoped.inner().clone();
        let role: String = sqlx::query_scalar("SELECT session_user::text")
            .fetch_one(&app)
            .await
            .unwrap();
        assert_eq!(role, "epigraph_app", "precondition: the app role");
        let outsider = epigraph_db::Viewer::resolve(&app, c.outsider)
            .await
            .expect("outsider viewer");
        let author = epigraph_db::Viewer::resolve(&app, c.author)
            .await
            .expect("author viewer");
        let server = build_server(app, scoped);

        for route in ["auto", "hierarchical"] {
            let body = recall_body(
                &server,
                &outsider,
                params(json!({ "limit": 10, "route": route })),
            )
            .await;
            let got = ids(&body);
            assert!(
                !got.contains(&c.private_member.to_string()),
                "{mode:?}/{route} leaked a group-private theme member to an outsider: {body}"
            );
            assert!(
                got.contains(&c.member.to_string()),
                "{mode:?}/{route} must still serve the public member: {body}"
            );
        }
        let one = recall_body(
            &server,
            &outsider,
            params(json!({ "limit": 1, "route": "hierarchical" })),
        )
        .await;
        assert_eq!(
            ids(&one),
            vec![c.member.to_string()],
            "{mode:?}: the one theme slot goes to the visible member: {one}"
        );

        let mine = recall_body(
            &server,
            &author,
            params(json!({ "limit": 10, "route": "hierarchical" })),
        )
        .await;
        assert!(
            ids(&mine).contains(&c.private_member.to_string()),
            "{mode:?}: the author's own private member is missing, so the theme leg did not \
             read on the author's stamp: {mine}"
        );
    }
}

/// The route is part of what was asked, so the audit row records it, and
/// whether the theme leg ran.
#[sqlx::test(migrations = "../../migrations")]
async fn the_route_is_recorded_in_the_audit_params(pool: PgPool) {
    let c = seed(&pool).await;
    let scoped = fixture::scoped_pool(&pool).await;
    let server = build_server(pool.clone(), scoped);
    let viewer = epigraph_db::Viewer::resolve(&pool, c.outsider)
        .await
        .expect("viewer");

    for (route, theme_leg) in [
        (None, false),
        (Some("auto"), true),
        (Some("hierarchical"), true),
    ] {
        sqlx::query("DELETE FROM recall_events")
            .execute(&pool)
            .await
            .unwrap();
        let extra = match route {
            Some(r) => json!({ "limit": 2, "route": r }),
            None => json!({ "limit": 2 }),
        };
        let body = recall_body(&server, &viewer, params(extra)).await;
        assert!(
            server
                .background_tasks()
                .wait_idle(std::time::Duration::from_secs(10))
                .await,
            "audit write did not finish"
        );
        let logged: Value = sqlx::query_scalar(
            "SELECT params FROM recall_events WHERE tool = 'recall' AND id = $1::uuid",
        )
        .bind(body["recall_event_id"].as_str().expect("event id"))
        .fetch_one(&pool)
        .await
        .expect("audit row");
        assert_eq!(
            logged["route"],
            route.unwrap_or("similarity"),
            "{route:?}: {logged}"
        );
        assert_eq!(logged["theme_leg"], theme_leg, "{route:?}: {logged}");
    }
}

/// A theme route cannot honour a scope the theme leg does not filter on, so
/// the combination is refused rather than silently widened; an unknown route
/// is refused rather than served as the default.
#[sqlx::test(migrations = "../../migrations")]
async fn unsupported_route_combinations_are_refused(pool: PgPool) {
    let c = seed(&pool).await;
    let scoped = fixture::scoped_pool(&pool).await;
    let server = build_server(pool.clone(), scoped);
    let viewer = epigraph_db::Viewer::resolve(&pool, c.outsider)
        .await
        .expect("viewer");

    for (extra, what) in [
        (json!({ "route": "auto", "tags": ["x"] }), "tags"),
        (
            json!({ "route": "hierarchical", "agent_id": c.author.to_string() }),
            "agent_id",
        ),
        (json!({ "route": "auto", "offset": 5 }), "offset"),
        (
            json!({ "route": "hierarchical", "theme_id": c.theme.to_string() }),
            "theme_id",
        ),
    ] {
        let got = recall_with_pgvec(&server, &viewer, params(extra), Some(query_bucket())).await;
        assert!(
            got.is_err(),
            "a theme route with {what} must be refused, got {got:?}"
        );
    }
    let bad: Result<RecallParams, _> =
        serde_json::from_value(json!({ "query": QUERY, "route": "semantic" }));
    assert!(bad.is_err(), "an unknown route must not deserialize");
}
