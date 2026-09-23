#![cfg(feature = "db")]
//! Regression test: `POST /api/v1/claims` with `if_not_exists=true` overwrote the
//! labels of an ALREADY-EXISTING claim owned by someone else.
//!
//! `create_claim` guards its `content_hash`/`properties` write on `was_created`,
//! but guarded the `UPDATE claims SET labels` write only on
//! `!request.labels.is_empty()`. So a dedup hit — which is explicitly not a
//! creation — still rewrote the stored label array.
//!
//! This is not cosmetic. `crates/epigraph-api/src/routes/policies.rs` uses
//! `'policy:active' = ANY(labels)` and `'policy:challenge' = ANY(labels)` as
//! UPDATE predicates, so stripping a policy claim's labels permanently detaches
//! it from its outcome and challenge endpoints. Any `claims:write` holder who
//! can guess the content could do it.
//!
//! `crates/epigraph-api/src/routes/submit.rs` already had the correct shape
//! (`if was_created && !packet.claim.labels.is_empty()`); this brings
//! `create_claim` into line with it.

use sqlx::postgres::PgPoolOptions;
mod common;

#[tokio::test(flavor = "multi_thread")]
async fn dedup_hit_must_not_overwrite_existing_labels() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();

    let agent = common::seed_system_agent(&pool).await;
    let (addr, _shutdown) = common::spawn_app(&url).await;
    let (token, _) = common::test_bearer_token_with_seeded_client(&pool, &["claims:write"]).await;

    let client = reqwest::Client::new();
    let endpoint = format!("http://{addr}/api/v1/claims");
    // Unique content per run so the test does not depend on prior DB state.
    let content = format!("label-overwrite regression {}", uuid::Uuid::new_v4());

    // Victim claim: carries the label its state machine is keyed on.
    let created = client
        .post(&endpoint)
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "content": content,
            "agent_id": agent,
            "labels": ["policy:active", "keep-me"],
        }))
        .send()
        .await
        .unwrap();
    assert!(
        created.status().is_success(),
        "seeding the victim claim should succeed; got {}",
        created.status()
    );

    // Attacker path: same (content, agent) so create dedups — `was_created=false`
    // — but a label array is supplied anyway.
    let second = client
        .post(&endpoint)
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "content": content,
            "agent_id": agent,
            "if_not_exists": true,
            "labels": ["attacker-controlled"],
        }))
        .send()
        .await
        .unwrap();
    let status = second.status();
    let body: serde_json::Value = second.json().await.unwrap_or(serde_json::Value::Null);
    assert!(
        status.is_success(),
        "if_not_exists dedup hit should succeed, not error; got {status}"
    );
    // `was_created` carries `skip_serializing_if = "std::ops::Not::not"`, so a
    // dedup hit OMITS the field entirely — absent and `false` mean the same thing.
    let was_created = body
        .get("was_created")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    assert!(
        !was_created,
        "second POST must be a dedup hit, not a creation — otherwise this test is \
         not exercising the guarded path at all. body={body}"
    );

    // The stored labels must be untouched by a request that created nothing.
    let labels: Vec<String> =
        sqlx::query_scalar("SELECT labels FROM claims WHERE content = $1 AND agent_id = $2")
            .bind(&content)
            .bind(agent)
            .fetch_one(&pool)
            .await
            .expect("victim claim row");

    assert!(
        labels.iter().any(|l| l == "policy:active"),
        "policy:active was stripped by a non-creating request — the claim is now \
         invisible to every policies.rs UPDATE keyed on it. labels={labels:?}"
    );
    assert!(
        labels.iter().any(|l| l == "keep-me"),
        "pre-existing labels were replaced wholesale, not merged. labels={labels:?}"
    );
    assert!(
        !labels.iter().any(|l| l == "attacker-controlled"),
        "a request that created nothing injected a label. labels={labels:?}"
    );
}
