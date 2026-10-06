#![cfg(feature = "db")]
//! `POST /api/v1/claims` with `derived_from` records ONE derivation evidence
//! row on the created (or deduplicated) claim, and nothing else.
//!
//! Backlog 3590a2d8 (5th recurrence): `decompose_claims` atoms were born with
//! `evidence_ids: []`, because `submit_atom` posts here and this handler wrote
//! no evidence row for them. `get_provenance` / `GET /lineage/:id` therefore
//! could not say where an atom came from, and every tier2-enrichment pass
//! re-filed the population as a "bulk ingestion skips evidence" bug.
//!
//! Policy (U041, option A): an atom carries derivation PROVENANCE at birth —
//! a `document` evidence row whose `raw_content` is the parent's text and whose
//! `properties.derived_from_claim` names the parent — and NO belief mass. The
//! truth value stays where the request put it.
//!
//! What this file pins, and why each assertion is not decorative:
//!
//! * exactly one row, type `document`, naming the parent, carrying the
//!   parent's text — the observable defect;
//! * the row is reachable through the lineage read (`GET /lineage/:id`), the
//!   same `LineageRepository` path `get_provenance` serves `evidence_ids`
//!   from, so the fix is visible where the report looked;
//! * a repeated identical POST (an `if_not_exists` dedup hit, as a re-applied
//!   plan line produces) adds no second row;
//! * an atom POSTed WITHOUT `derived_from` gets zero rows — the field, not the
//!   route, creates the row;
//! * truth is untouched (provenance, not belief);
//! * a parent that is invisible, non-public or nonexistent is refused BEFORE
//!   anything is committed (the atom row is rolled back), with one response
//!   for all three so the refusal is not an existence oracle. A public atom's
//!   evidence is public, so copying a group-private parent's text into it
//!   would republish that text.

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;
mod common;

async fn evidence_rows(
    pool: &PgPool,
    claim_id: Uuid,
) -> Vec<(Uuid, String, serde_json::Value, Option<String>)> {
    sqlx::query_as(
        "SELECT id, evidence_type, properties, raw_content FROM evidence WHERE claim_id = $1",
    )
    .bind(claim_id)
    .fetch_all(pool)
    .await
    .expect("read evidence rows")
}

async fn post_claim(
    client: &reqwest::Client,
    endpoint: &str,
    token: &str,
    body: serde_json::Value,
) -> (reqwest::StatusCode, serde_json::Value) {
    let resp = client
        .post(endpoint)
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .expect("POST /api/v1/claims");
    let status = resp.status();
    let json = resp.json().await.unwrap_or(serde_json::Value::Null);
    (status, json)
}

fn id_of(body: &serde_json::Value) -> Uuid {
    body.get("id")
        .and_then(serde_json::Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok())
        .unwrap_or_else(|| panic!("response carries a claim id; body={body}"))
}

#[tokio::test(flavor = "multi_thread")]
async fn create_claim_with_derived_from_records_derivation_evidence() {
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
    let run = Uuid::new_v4();

    // Parent: a compound claim, as decompose_claims selects.
    let parent_text = format!(
        "U041 parent {run}: the Atwood machine has two masses on one string. \
         The heavier mass accelerates downward."
    );
    let (st, body) = post_claim(
        &client,
        &endpoint,
        &token,
        serde_json::json!({ "content": parent_text, "agent_id": agent }),
    )
    .await;
    assert!(st.is_success(), "seeding the parent failed: {st} {body}");
    let parent = id_of(&body);

    // Atom, exactly the shape decompose_claims::submit_atom posts.
    let atom_req = serde_json::json!({
        "content": format!("U041 atom {run}: the heavier mass accelerates downward."),
        "agent_id": agent,
        "initial_truth": 0.5,
        "if_not_exists": true,
        "properties": {"methodology": "inductive_generalization"},
        "labels": ["atom", "generality:0"],
        "derived_from": {"claim_id": parent, "method": "decompose_claims"},
    });
    let (st, body) = post_claim(&client, &endpoint, &token, atom_req.clone()).await;
    assert!(st.is_success(), "atom POST failed: {st} {body}");
    let atom = id_of(&body);

    let rows = evidence_rows(&pool, atom).await;
    assert_eq!(
        rows.len(),
        1,
        "an atom POSTed with derived_from must carry exactly one derivation \
         evidence row; got {rows:?}"
    );
    let (evidence_id, ev_type, props, raw) = &rows[0];
    assert_eq!(
        ev_type, "document",
        "derivation evidence is stored as `document`"
    );
    assert_eq!(
        props
            .get("derived_from_claim")
            .and_then(serde_json::Value::as_str),
        Some(parent.to_string().as_str()),
        "properties.derived_from_claim must name the parent; props={props}"
    );
    assert_eq!(
        props.get("method").and_then(serde_json::Value::as_str),
        Some("decompose_claims"),
        "properties.method records the writer; props={props}"
    );
    assert_eq!(
        raw.as_deref(),
        Some(parent_text.as_str()),
        "raw_content is the parent's text — the passage the atom was derived from"
    );

    // Provenance, not belief: the truth value is what the request asked for.
    let truth: f64 = sqlx::query_scalar("SELECT truth_value FROM claims WHERE id = $1")
        .bind(atom)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(
        (truth - 0.5).abs() < 1e-9,
        "derivation evidence must not move belief; truth={truth}"
    );

    // The row is visible where the report looked: the lineage read that
    // get_provenance's evidence_ids come from.
    let lineage: serde_json::Value = client
        .get(format!("http://{addr}/lineage/{atom}?max_depth=1"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("GET /lineage")
        .json()
        .await
        .expect("lineage json");
    let node_evidence: Vec<String> = lineage["nodes"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|n| n["claim_id"].as_str() == Some(atom.to_string().as_str()))
        .flat_map(|n| n["evidence"].as_array().cloned().unwrap_or_default())
        .filter_map(|e| e["id"].as_str().map(str::to_string))
        .collect();
    assert_eq!(
        node_evidence,
        vec![evidence_id.to_string()],
        "the lineage read must list the derivation evidence on the atom; lineage={lineage}"
    );

    // Idempotent: the identical request (a re-applied plan line) dedups and
    // adds nothing.
    let (st, body) = post_claim(&client, &endpoint, &token, atom_req).await;
    assert!(st.is_success(), "repeat atom POST failed: {st} {body}");
    assert_eq!(
        id_of(&body),
        atom,
        "the repeat must dedup onto the same atom"
    );
    assert!(
        !body
            .get("was_created")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
        "the repeat must be a dedup hit; body={body}"
    );
    assert_eq!(
        evidence_rows(&pool, atom).await.len(),
        1,
        "a dedup hit with the same derived_from must not add a second row"
    );

    // Control: no derived_from, no row.
    let (st, body) = post_claim(
        &client,
        &endpoint,
        &token,
        serde_json::json!({
            "content": format!("U041 control atom {run}: the string is massless."),
            "agent_id": agent,
            "if_not_exists": true,
            "labels": ["atom", "generality:0"],
        }),
    )
    .await;
    assert!(st.is_success(), "control POST failed: {st} {body}");
    assert!(
        evidence_rows(&pool, id_of(&body)).await.is_empty(),
        "an atom POSTed without derived_from must get no evidence row"
    );
}

/// The atom's content was never committed: the refusal rolled the tx back.
async fn atom_absent(pool: &PgPool, content: &str) -> bool {
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM claims WHERE content = $1")
        .bind(content)
        .fetch_one(pool)
        .await
        .unwrap();
    n == 0
}

#[tokio::test(flavor = "multi_thread")]
async fn derived_from_an_unavailable_parent_is_refused_without_writing_the_atom() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();

    let agent = common::seed_system_agent(&pool).await;
    let (addr, _shutdown) = common::spawn_app(&url).await;
    let (token, client_row) =
        common::test_bearer_token_with_seeded_client(&pool, &["claims:write"]).await;
    let client = reqwest::Client::new();
    let endpoint = format!("http://{addr}/api/v1/claims");
    let run = Uuid::new_v4();

    // (a) Group-private to a stranger: invisible to the caller.
    let stranger = Uuid::new_v4();
    let invisible = common::seed_claim_with_agent(
        &pool,
        &format!("U041 stranger-private parent {run}. Second sentence."),
        stranger,
    )
    .await;
    common::seed_private_ownership(&pool, invisible, stranger).await;

    // (b) Group-private to the CALLER: visible, but not public. Its text must
    // not be copied into a public atom's evidence.
    let own_private = common::seed_claim_writable_by_client(
        &pool,
        &format!("U041 caller-private parent {run}. Second sentence."),
        client_row,
    )
    .await;
    sqlx::query("UPDATE claims SET visibility = 'group' WHERE id = $1")
        .bind(own_private)
        .execute(&pool)
        .await
        .unwrap();
    let vis: String = sqlx::query_scalar("SELECT visibility FROM claims WHERE id = $1")
        .bind(own_private)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        vis, "group",
        "fixture must leave the caller's parent group-private"
    );

    // (c) Nonexistent.
    let missing = Uuid::new_v4();

    let mut answers = Vec::new();
    for (label, parent) in [
        ("invisible", invisible),
        ("caller-private", own_private),
        ("nonexistent", missing),
    ] {
        let content = format!("U041 refused atom {run} {label}.");
        let (st, body) = post_claim(
            &client,
            &endpoint,
            &token,
            serde_json::json!({
                "content": content,
                "agent_id": agent,
                "if_not_exists": true,
                "labels": ["atom", "generality:0"],
                "derived_from": {"claim_id": parent, "method": "decompose_claims"},
            }),
        )
        .await;
        assert_eq!(
            st,
            reqwest::StatusCode::BAD_REQUEST,
            "derived_from a {label} parent must be refused; got {st} {body}"
        );
        assert!(
            atom_absent(&pool, &content).await,
            "the refused {label} request must not leave its atom committed"
        );
        // The parent id is the only thing that differs; strip it before
        // comparing so the bodies prove there is one answer.
        answers.push(body.to_string().replace(&parent.to_string(), "<parent>"));
    }
    assert!(
        answers.windows(2).all(|w| w[0] == w[1]),
        "invisible, non-public and nonexistent parents must get one identical \
         answer (no existence oracle); got {answers:?}"
    );
}
