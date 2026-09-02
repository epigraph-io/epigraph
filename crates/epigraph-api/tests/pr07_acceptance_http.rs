#![cfg(feature = "db")]
//! HTTP-level coverage for PR-07 acceptance criteria #2 and #3.
//!
//! # Why these are HTTP tests and not repo tests
//!
//! Both criteria are statements about a **response body**, not about a query:
//!
//! * #2 — "`/themes/:id/embeddings` returns zero raw 1536-d vectors at any
//!   `limit`" — is a shape property of the serialised JSON. The repo function
//!   `ClaimThemeRepository::get_theme_embeddings` still returns full pgvector
//!   text and always will; the whole fix lives in the handler, between the repo
//!   call and the response. A repo-level test cannot see it, and the sibling
//!   file `tenant_isolation_http.rs` — which is DB-level despite its name —
//!   therefore could not have caught this criterion being unimplemented. It
//!   was, for the whole of PR-07's first pass.
//!
//! * #3 — "`GET /api/v1/challenges` returns no `explanation` for a claim the
//!   caller cannot read" — is likewise about what is absent from a payload.
//!
//! These go through `spawn_app` → `build_app_for_tests` → `create_router`, so
//! they exercise the production middleware layering (scope gate, bearer auth,
//! `ViewerExtractor`) rather than hand-passing an `AuthContext` to a handler.

mod common;

use serde_json::Value;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

async fn pool_and_app() -> (
    sqlx::PgPool,
    std::net::SocketAddr,
    tokio::sync::oneshot::Sender<()>,
) {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .expect("connect test pool");
    let (addr, shutdown) = common::spawn_app(&url).await;
    (pool, addr, shutdown)
}

/// Seed a theme holding `n` claims with real 1536-d embeddings.
async fn seed_theme_with_embedded_claims(pool: &sqlx::PgPool, n: usize) -> Uuid {
    let theme_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claim_themes (id, label, description) VALUES ($1, $2, $3) \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(theme_id)
    .bind(format!("pr07-test-theme-{theme_id}"))
    .bind("PR-07 acceptance fixture")
    .execute(pool)
    .await
    .expect("seed theme");

    for i in 0..n {
        let claim_id = common::seed_claim(pool, &format!("pr07 embedding fixture {i}")).await;
        // Two separated lobes so the projection has a real axis to find.
        let base = if i % 2 == 0 { 1.0_f32 } else { -1.0_f32 };
        let vals: Vec<String> = (0..1536)
            .map(|j| {
                let v = if j == 0 {
                    base
                } else {
                    (i as f32) * 0.0001 + (j as f32) * 1e-6
                };
                v.to_string()
            })
            .collect();
        let vec_literal = format!("[{}]", vals.join(","));
        sqlx::query("UPDATE claims SET theme_id = $1, embedding = $2::vector WHERE id = $3")
            .bind(theme_id)
            .bind(&vec_literal)
            .bind(claim_id)
            .execute(pool)
            .await
            .expect("attach claim to theme with embedding");
    }
    theme_id
}

/// Deep-scan a JSON value for any array of numbers longer than 2.
///
/// This is the actual acceptance assertion for #2 and it is written
/// structurally rather than as "the key `embedding` is absent", so renaming the
/// field cannot make the test pass while the vectors still ship.
fn longest_numeric_array(v: &Value) -> usize {
    match v {
        Value::Array(items) => {
            let own = if !items.is_empty() && items.iter().all(Value::is_number) {
                items.len()
            } else {
                0
            };
            own.max(items.iter().map(longest_numeric_array).max().unwrap_or(0))
        }
        Value::Object(map) => map.values().map(longest_numeric_array).max().unwrap_or(0),
        _ => 0,
    }
}

#[tokio::test]
async fn theme_embeddings_returns_a_2d_projection_and_no_raw_vectors() {
    let (pool, addr, shutdown) = pool_and_app().await;
    let theme_id = seed_theme_with_embedded_claims(&pool, 6).await;

    let token = common::test_bearer_token_with_scopes(&["claims:admin"]);
    let client = reqwest::Client::new();

    // "at any limit" is part of the criterion, so probe the default, an
    // explicit small limit, and a limit above the 5000 cap.
    for limit in ["", "?limit=3", "?limit=100000"] {
        let resp = client
            .get(format!(
                "http://{addr}/api/v1/themes/{theme_id}/embeddings{limit}"
            ))
            .bearer_auth(&token)
            .send()
            .await
            .expect("request themes embeddings");
        assert_eq!(
            resp.status(),
            200,
            "expected 200 at claims:admin for limit {limit:?}"
        );
        let body: Value = resp.json().await.expect("json body");

        let longest = longest_numeric_array(&body);
        assert!(
            longest <= 2,
            "acceptance #2 violated at limit {limit:?}: response contains a numeric \
             array of length {longest}. The endpoint must return a 2-D projection, \
             never raw embedding vectors.\nbody: {body}"
        );

        let claims = body["claims"].as_array().expect("claims array");
        assert!(!claims.is_empty(), "fixture should return rows");
        for c in claims {
            assert!(
                c.get("embedding").is_none(),
                "raw `embedding` field is back in the payload: {c}"
            );
            let proj = c["projection"].as_array().expect("projection array");
            assert_eq!(proj.len(), 2, "projection must be exactly 2-D: {c}");
            assert!(
                proj.iter().all(|x| x.as_f64().is_some_and(f64::is_finite)),
                "projection must be finite numbers: {c}"
            );
        }
    }

    // The projection must actually separate the two seeded lobes, otherwise
    // "we return two numbers" would be satisfiable by returning zeros and the
    // endpoint would be useless to `maintain_themes.py`.
    let resp = client
        .get(format!("http://{addr}/api/v1/themes/{theme_id}/embeddings"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("request themes embeddings");
    let body: Value = resp.json().await.expect("json body");
    let xs: Vec<f64> = body["claims"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["projection"][0].as_f64().unwrap())
        .collect();
    let spread =
        xs.iter().cloned().fold(f64::MIN, f64::max) - xs.iter().cloned().fold(f64::MAX, f64::min);
    assert!(
        spread > 0.5,
        "the projection collapsed to a point (spread {spread}); k-means over it \
         could not split the theme, which is the endpoint's only purpose"
    );

    let _ = shutdown.send(());
}

#[tokio::test]
async fn theme_embeddings_requires_claims_admin_not_claims_read() {
    // Acceptance #2's other half. `PENDING_SERVICE_SCOPES` grants `claims:read`,
    // so leaving the gate there meant any registrant could pull the theme's
    // embedding corpus.
    let (pool, addr, shutdown) = pool_and_app().await;
    let theme_id = seed_theme_with_embedded_claims(&pool, 2).await;
    let client = reqwest::Client::new();

    let read_only = common::test_bearer_token_with_scopes(&["claims:read"]);
    let resp = client
        .get(format!("http://{addr}/api/v1/themes/{theme_id}/embeddings"))
        .bearer_auth(&read_only)
        .send()
        .await
        .expect("request with claims:read");
    assert_eq!(
        resp.status(),
        403,
        "claims:read must no longer be sufficient for theme embeddings"
    );

    let anon = client
        .get(format!("http://{addr}/api/v1/themes/{theme_id}/embeddings"))
        .send()
        .await
        .expect("anonymous request");
    assert_eq!(anon.status(), 401, "anonymous access must be refused");

    let _ = shutdown.send(());
}

#[tokio::test]
async fn create_theme_with_centroid_averages_the_claims_when_no_centroid_is_sent() {
    // The other half of acceptance #2's fix. Stopping `/themes/:id/embeddings`
    // from returning raw vectors also removed the only way a theme-splitting
    // client could compute a sub-theme centroid, so
    // `CreateThemeWithCentroidRequest::centroid` became optional and the server
    // averages the claims' real embeddings instead
    // (`ClaimThemeRepository::set_centroid_from_claims`).
    //
    // Without this test that repo function is new, unexercised SQL on a write
    // path: `UPDATE ... FROM (SELECT AVG(c.embedding) ...) agg ... RETURNING
    // agg.n`, with a spliced visibility predicate and a bind order that has to
    // line up with `splice(.., 3)`. A binding or arity mistake would surface
    // only in production.
    let (pool, addr, shutdown) = pool_and_app().await;
    let source_theme = seed_theme_with_embedded_claims(&pool, 4).await;
    let client = reqwest::Client::new();
    let token = common::test_bearer_token_with_scopes(&["claims:admin"]);

    let claim_ids: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM claims WHERE theme_id = $1")
        .bind(source_theme)
        .fetch_all(&pool)
        .await
        .expect("fetch fixture claim ids");
    assert_eq!(claim_ids.len(), 4, "fixture should have seeded 4 claims");

    let resp = client
        .post(format!("http://{addr}/api/v1/themes/create-with-centroid"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "label": format!("pr07-derived-{}", Uuid::new_v4()),
            "description": "centroid omitted on purpose",
            "claim_ids": claim_ids,
        }))
        .send()
        .await
        .expect("create theme without a centroid");
    assert_eq!(
        resp.status(),
        201,
        "omitting `centroid` must be accepted, not rejected as a missing field"
    );
    let body: Value = resp.json().await.expect("json body");
    let new_theme: Uuid = body["theme_id"]
        .as_str()
        .expect("theme_id in response")
        .parse()
        .expect("theme_id parses");

    // The centroid must actually be populated, and at the real dimension —
    // asserting merely "not null" would pass if we had written the 2-D
    // projection into it, which is the specific mistake this path exists to
    // prevent.
    let dims: Option<i32> =
        sqlx::query_scalar("SELECT vector_dims(centroid) FROM claim_themes WHERE id = $1")
            .bind(new_theme)
            .fetch_one(&pool)
            .await
            .expect("read back the derived centroid");
    assert_eq!(
        dims,
        Some(1536),
        "the server-derived centroid must be a full 1536-d vector averaged from \
         the claims, not the 2-D projection the client now receives"
    );

    let _ = shutdown.send(());
}

#[tokio::test]
async fn challenges_list_is_reachable_and_carries_no_foreign_explanation() {
    // Acceptance #3. `list_challenges` takes a `ViewerExtractor` and calls
    // `ChallengeRepository::list_for_claim`, whose SQL carries
    // `/* {VISIBILITY:challenges} */` — row-level filtering subsumes hiding the
    // `explanation` field. That was inherited from PR-06 and had ZERO test
    // coverage; the eight cases in `tenant_isolation_http.rs` never touch
    // challenges. This closes the gap at the HTTP boundary.
    //
    // Today every fixture row is `visibility = 'public'` (migration 062's
    // default; nothing transcribes ownership until PR-12), so this asserts the
    // reachable half — the endpoint authenticates, the handler resolves a
    // viewer, and a challenge for an unrelated claim never appears in another
    // claim's listing. The cross-tenant half arms when PR-12 populates the
    // tenancy columns.
    let (pool, addr, shutdown) = pool_and_app().await;
    let client = reqwest::Client::new();

    let subject = common::seed_claim(&pool, "pr07 challenge subject").await;
    let unrelated = common::seed_claim(&pool, "pr07 unrelated claim").await;
    let challenger = common::seed_system_agent(&pool).await;

    let secret_explanation = format!("pr07-secret-explanation-{}", Uuid::new_v4());
    sqlx::query(
        "INSERT INTO challenges (id, claim_id, challenger_id, challenge_type, explanation) \
         VALUES ($1, $2, $3, 'methodology', $4)",
    )
    .bind(Uuid::new_v4())
    .bind(unrelated)
    .bind(challenger)
    .bind(&secret_explanation)
    .execute(&pool)
    .await
    .expect("seed challenge on the unrelated claim");

    let token = common::test_bearer_token_with_scopes(&["claims:read"]);
    let resp = client
        .get(format!("http://{addr}/api/v1/claims/{subject}/challenges"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("request challenges");
    assert_eq!(resp.status(), 200, "challenge listing must authenticate");
    let body = resp.text().await.expect("body text");
    assert!(
        !body.contains(&secret_explanation),
        "a challenge belonging to a DIFFERENT claim leaked its explanation into \
         this claim's listing.\nbody: {body}"
    );

    let anon = client
        .get(format!("http://{addr}/api/v1/claims/{subject}/challenges"))
        .send()
        .await
        .expect("anonymous challenges request");
    assert_eq!(
        anon.status(),
        401,
        "challenge listing must not be anonymously readable"
    );

    let _ = shutdown.send(());
}
