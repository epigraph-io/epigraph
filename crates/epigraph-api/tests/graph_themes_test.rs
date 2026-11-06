#![cfg(feature = "db")]
//! # Why both arms take an injected `pool`
//!
//! MEASURED, not inferred. Built at `c4d3f304` and run four times against the
//! shared database with this binary and `build_from_bridges_test` as
//! CONCURRENT processes, each at `--test-threads=4`:
//! `themes_expand_returns_neighborhoods_for_seeded_theme` failed 2 of 3 runs
//! with `23503 neighborhood_edges_neighborhood_a_fkey ... Key
//! (neighborhood_a)=(...) is not present in table "graph_neighborhoods"` — the
//! other binary's unfiltered `DELETE FROM graph_neighborhoods` landing between
//! this arm's own INSERT and the edge INSERT that references it. Run alone at
//! four threads the same binary passed 4 of 4. The failure is therefore in the
//! shared corpus, not in this arm.
//!
//! The finding (`F-tests-depend-on-accumulated-shared-db-fixtures`) required
//! exactly that characterisation before conversion, because the previous
//! inventories in this series were built from grep evidence alone.
//!
//! # Both files convert together
//!
//! This binary and `build_from_bridges_test.rs` truncate the SAME three tables
//! (`neighborhood_edges`, `claim_neighborhood_membership`,
//! `graph_neighborhoods`) — and they are the same three the already-isolated
//! `graph_neighborhoods_test.rs` used to truncate. Converting one and leaving
//! the other keeps the surviving truncation alive against two isolated
//! siblings, which is the half-state that re-breaks them.
//!
//! `#[sqlx::test]` supplies the empty database the DELETEs were faking, so
//! that conversion changed no assertion and lost no test name. (Backlog
//! 57917c13 later replaced `themes_overview_returns_seeded_themes` with
//! `themes_overview_reports_live_member_counts` and the tenancy arms below:
//! the route now counts live, viewer-readable members, so a theme seeded with
//! a stored count and no members is absent.) `spawn_app`
//! builds its own pool from a URL, so each arm hands it
//! `fixture::database_url_for(&pool)` — the per-test database — rather than the
//! ambient `DATABASE_URL`, which would seed one database and assert against
//! another.
//!
//! These arms lost their `flavor = "multi_thread"` runtime, for the reason
//! `graph_neighborhoods_test.rs`'s header sets out at length: `#[sqlx::test]`
//! drives the future on a current-thread runtime, and nothing in this request
//! path blocks.

use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

mod common;

#[path = "viewer_fixture.rs"]
mod fixture;

// ---- GET /api/v1/graph/themes/overview (backlog 57917c13) ---------------------
//
// The route reports, per theme, the live count of CURRENT members the CALLER
// can read; a theme with no readable member is absent; the stored
// `claim_themes.claim_count` is never returned. Every theme below is seeded
// with a deliberately WRONG stored count so a route that read the column
// fails.

/// A theme with an explicit, deliberately wrong stored `claim_count`.
async fn seed_theme(pool: &PgPool, label: &str, stored_count: i32) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO claim_themes (label, description, claim_count) \
         VALUES ($1, '', $2) RETURNING id",
    )
    .bind(label)
    .bind(stored_count)
    .fetch_one(pool)
    .await
    .expect("insert theme")
}

/// A public, current claim by `agent`, assigned to `theme`.
async fn seed_member(pool: &PgPool, theme: Uuid, agent: Uuid, content: &str) -> Uuid {
    let claim = common::seed_claim_with_agent(pool, content, agent).await;
    sqlx::query("UPDATE claims SET theme_id = $2 WHERE id = $1")
        .bind(claim)
        .bind(theme)
        .execute(pool)
        .await
        .expect("assign claim to theme");
    claim
}

/// `GET path` with an optional bearer; `(status, body text)`.
async fn get(addr: std::net::SocketAddr, path: &str, token: Option<&str>) -> (u16, String) {
    let mut req = reqwest::Client::new().get(format!("http://{addr}{path}"));
    if let Some(t) = token {
        req = req.header("Authorization", format!("Bearer {t}"));
    }
    let resp = req.send().await.expect("request");
    let status = resp.status().as_u16();
    (status, resp.text().await.expect("body"))
}

fn json(body: &str) -> Value {
    serde_json::from_str(body).unwrap_or_else(|e| panic!("not JSON ({e}): {body}"))
}

/// `(id, claim_count)` of every theme in a parsed body, in body order.
fn id_counts(body: &Value) -> Vec<(Uuid, i64)> {
    body["themes"]
        .as_array()
        .expect("themes array")
        .iter()
        .map(|t| {
            (
                t["id"]
                    .as_str()
                    .and_then(|s| Uuid::parse_str(s).ok())
                    .expect("id"),
                t["claim_count"]
                    .as_i64()
                    .expect("claim_count is an integer"),
            )
        })
        .collect()
}

#[sqlx::test(migrations = "../../migrations")]
async fn themes_overview_reports_live_member_counts(pool: PgPool) {
    let url = fixture::database_url_for(&pool).await;
    // Live members A(3), C(2), B(1), D(1); stored counts 12, 9, 7, 7, the
    // numbers this arm used to assert. A route that read the stored column
    // returns the old numbers; one that dropped the `id ASC` tiebreak makes the
    // B/D order nondeterministic.
    let agent = Uuid::new_v4();
    let a = seed_theme(&pool, "A", 12).await;
    let b = seed_theme(&pool, "B", 7).await;
    let c = seed_theme(&pool, "C", 9).await;
    let d = seed_theme(&pool, "D", 7).await;
    for (theme, n) in [(a, 3), (c, 2), (b, 1), (d, 1)] {
        for i in 0..n {
            seed_member(&pool, theme, agent, &format!("live member {theme} {i}")).await;
        }
    }
    // A retired member is not counted.
    let retired = seed_member(&pool, a, agent, "retired member of A").await;
    sqlx::query("UPDATE claims SET is_current = false WHERE id = $1")
        .bind(retired)
        .execute(&pool)
        .await
        .expect("retire");

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let (status, text) = get(
        addr,
        "/api/v1/graph/themes/overview",
        Some(&common::test_bearer_token()),
    )
    .await;
    assert_eq!(status, 200, "{text}");
    let body = json(&text);

    let (first_tie, second_tie) = if b < d { (b, d) } else { (d, b) };
    assert_eq!(
        id_counts(&body),
        vec![(a, 3), (c, 2), (first_tie, 1), (second_tie, 1)],
        "claim_count DESC then id ASC, with LIVE counts; got {body}"
    );
    let labels: Vec<&str> = body["themes"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|t| t["label"].as_str())
        .collect();
    assert_eq!(labels[..2], ["A", "C"], "labels travel with their rows");
    assert_eq!(body["total"], 4);
    assert!(body["next_cursor"].is_null(), "{body}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn themes_overview_requires_a_bearer(pool: PgPool) {
    let url = fixture::database_url_for(&pool).await;
    let (addr, _shutdown) = common::spawn_app(&url).await;
    let (status, text) = get(addr, "/api/v1/graph/themes/overview", None).await;
    assert_eq!(status, 401, "{text}");
}

/// THE TENANCY TEST. A stranger in a different group from the owner sees no
/// count, id, label or existence signal of the owner's private members or of
/// the theme whose only member is private.
#[sqlx::test(migrations = "../../migrations")]
async fn themes_overview_hides_a_private_theme_and_its_count_from_a_non_member(pool: PgPool) {
    let url = fixture::database_url_for(&pool).await;
    let owner = Uuid::new_v4();
    let stranger = Uuid::new_v4();

    // P: one member, private to the owner. Its label is a unique marker, so a
    // leak of it anywhere in the body is detectable by substring.
    let marker = format!("U1-PRIVATE-THEME-{}", Uuid::new_v4().simple());
    let p = seed_theme(&pool, &marker, 50).await;
    let p_claim = seed_member(&pool, p, owner, "owner's private member of P").await;
    common::seed_private_ownership(&pool, p_claim, owner).await;

    // Q: one public member and one owner-private member.
    let q = seed_theme(&pool, "U1 public theme", 50).await;
    seed_member(&pool, q, owner, "public member of Q").await;
    let q_private = seed_member(&pool, q, owner, "owner's private member of Q").await;
    common::seed_private_ownership(&pool, q_private, owner).await;

    // The stranger has a group of its own, different from the owner's.
    common::seed_claim_with_agent(&pool, "stranger's own unthemed claim", stranger).await;
    let stranger_group = common::personal_group_of(&pool, stranger).await;
    let owner_group = common::personal_group_of(&pool, owner).await;
    assert_ne!(
        stranger_group, owner_group,
        "two viewers in DIFFERENT groups"
    );

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let stranger_token = common::mint_token_with_agent(&["claims:read"], stranger);
    let owner_token = common::mint_token_with_agent(&["claims:read"], owner);

    // Owner first: the calibration arm. It proves the stranger assertions do
    // not pass against an empty handler, and that the marker WOULD be found
    // had it leaked.
    let (status, owner_text) = get(addr, "/api/v1/graph/themes/overview", Some(&owner_token)).await;
    assert_eq!(status, 200, "{owner_text}");
    let owner_body = json(&owner_text);
    assert_eq!(id_counts(&owner_body), vec![(q, 2), (p, 1)], "{owner_body}");
    assert_eq!(owner_body["total"], 2);
    assert!(
        owner_text.contains(&marker),
        "CALIBRATION: the owner's body carries P's marker label"
    );

    let (status, text) = get(addr, "/api/v1/graph/themes/overview", Some(&stranger_token)).await;
    assert_eq!(status, 200, "{text}");
    let body = json(&text);

    // Parsed body. Counts are JSON numbers, so they are asserted on the parsed
    // value and never by substring (a bare `50` can occur in a UUID's hex).
    assert_eq!(
        id_counts(&body),
        vec![(q, 1)],
        "the stranger sees Q with its ONE readable member, and no P; got {body}"
    );
    assert_eq!(body["themes"][0]["label"], "U1 public theme");
    let total = body["total"].as_i64().expect("total");
    assert_eq!(total, 1, "the stranger's total does not count P");
    assert!(total != 50 && total != 2);
    for (_, count) in id_counts(&body) {
        assert_eq!(count, 1, "no stored (50) or owner-scoped (2) count");
    }
    assert!(body["next_cursor"].is_null(), "{body}");

    // Raw text, fixed seeded values only.
    for needle in [
        p.to_string(),
        p.simple().to_string(),
        marker.clone(),
        p_claim.to_string(),
        p_claim.simple().to_string(),
        q_private.to_string(),
        q_private.simple().to_string(),
    ] {
        assert!(
            !text.contains(&needle),
            "the stranger's body leaks {needle}: {text}"
        );
    }

    // With limit=1 the walk is one page and the cursor does not hint at a
    // hidden row.
    let (status, text1) = get(
        addr,
        "/api/v1/graph/themes/overview?limit=1",
        Some(&stranger_token),
    )
    .await;
    assert_eq!(status, 200, "{text1}");
    let body1 = json(&text1);
    assert_eq!(id_counts(&body1), vec![(q, 1)]);
    assert_eq!(body1["total"], 1);
    assert!(body1["next_cursor"].is_null(), "{body1}");

    // A spoofed agent_id in the query string changes nothing: the viewer comes
    // from the token.
    let (status, spoofed) = get(
        addr,
        &format!("/api/v1/graph/themes/overview?agent_id={owner}"),
        Some(&stranger_token),
    )
    .await;
    assert_eq!(status, 200, "{spoofed}");
    assert_eq!(json(&spoofed), body, "agent_id in the query is ignored");
}

#[sqlx::test(migrations = "../../migrations")]
async fn themes_overview_rejects_a_malformed_cursor(pool: PgPool) {
    let url = fixture::database_url_for(&pool).await;
    let theme = seed_theme(&pool, "cursor theme", 0).await;
    seed_member(&pool, theme, Uuid::new_v4(), "cursor theme member").await;
    let (addr, _shutdown) = common::spawn_app(&url).await;
    let token = common::test_bearer_token();

    for bad in [
        "garbage".to_string(),
        format!("k1.1.{}", Uuid::new_v4().simple()),
        format!("t1.0.{}", Uuid::new_v4().simple()),
    ] {
        let (status, text) = get(
            addr,
            &format!("/api/v1/graph/themes/overview?after={bad}"),
            Some(&token),
        )
        .await;
        assert_eq!(status, 400, "after={bad}: {text}");
        assert!(text.contains("malformed `after` cursor"), "{text}");
    }

    // Empty `after` is a first page.
    let (status, text) = get(addr, "/api/v1/graph/themes/overview?after=", Some(&token)).await;
    assert_eq!(status, 200, "{text}");
    assert_eq!(id_counts(&json(&text)), vec![(theme, 1)]);

    // A typed `limit`: not a number is the extractor's 400.
    let (status, _) = get(
        addr,
        "/api/v1/graph/themes/overview?limit=abc",
        Some(&token),
    )
    .await;
    assert_eq!(status, 400);
}

#[sqlx::test(migrations = "../../migrations")]
async fn themes_overview_clamps_limit(pool: PgPool) {
    let url = fixture::database_url_for(&pool).await;
    let agent = Uuid::new_v4();
    let mut expected = Vec::new();
    for (i, n) in [3i64, 2, 1].into_iter().enumerate() {
        let theme = seed_theme(&pool, &format!("clamp {i}"), 0).await;
        for k in 0..n {
            seed_member(&pool, theme, agent, &format!("clamp {i} {k}")).await;
        }
        expected.push((theme, n));
    }
    let (addr, _shutdown) = common::spawn_app(&url).await;
    let token = common::test_bearer_token();

    // limit=0 behaves as 1: one row and a cursor.
    let (status, text) = get(addr, "/api/v1/graph/themes/overview?limit=0", Some(&token)).await;
    assert_eq!(status, 200, "{text}");
    let body = json(&text);
    assert_eq!(id_counts(&body), expected[..1]);
    assert_eq!(body["total"], 3);
    let cursor = body["next_cursor"]
        .as_str()
        .expect("a cut page carries a cursor")
        .to_string();
    assert!(cursor.starts_with("t1."), "{cursor}");

    // Following the cursors at limit=1 walks every theme once.
    let mut walked = id_counts(&body);
    let mut after = Some(cursor);
    while let Some(c) = after.take() {
        let (status, text) = get(
            addr,
            &format!("/api/v1/graph/themes/overview?limit=1&after={c}"),
            Some(&token),
        )
        .await;
        assert_eq!(status, 200, "{text}");
        let page = json(&text);
        walked.extend(id_counts(&page));
        after = page["next_cursor"].as_str().map(str::to_string);
        assert!(walked.len() <= 3, "the walk must terminate: {walked:?}");
    }
    assert_eq!(walked, expected);

    // limit=100000 behaves as 200: everything, no cursor.
    let (status, text) = get(
        addr,
        "/api/v1/graph/themes/overview?limit=100000",
        Some(&token),
    )
    .await;
    assert_eq!(status, 200, "{text}");
    let body = json(&text);
    assert_eq!(id_counts(&body), expected);
    assert!(body["next_cursor"].is_null());
}

#[sqlx::test(migrations = "../../migrations")]
async fn themes_expand_returns_neighborhoods_for_seeded_theme(pool: PgPool) {
    let url = fixture::database_url_for(&pool).await;

    // Inline minimal seed: agent + run + theme + 2 atoms + 1 edge.
    let agent_id = uuid::Uuid::parse_str("00000000-0000-0000-0000-0000000000bb").unwrap();
    sqlx::query(
        "INSERT INTO agents (id, public_key, display_name, agent_type) \
         VALUES ($1, decode(repeat('BB', 32), 'hex'), 'themes-expand-test', 'system') \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(agent_id)
    .execute(&pool)
    .await
    .unwrap();

    let run_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO graph_cluster_runs (run_id, cluster_count, degraded) VALUES ($1, 0, FALSE)",
    )
    .bind(run_id)
    .execute(&pool)
    .await
    .unwrap();

    let theme_id = Uuid::new_v4();
    sqlx::query("INSERT INTO claim_themes (id, label, description, claim_count) VALUES ($1, 'Expand', '', 2)")
        .bind(theme_id).execute(&pool).await.unwrap();

    let claim_a = Uuid::new_v4();
    let claim_b = Uuid::new_v4();
    for (id, content) in [(claim_a, "atom-a"), (claim_b, "atom-b")] {
        let hash: Vec<u8> = id
            .as_bytes()
            .iter()
            .chain(id.as_bytes().iter())
            .copied()
            .collect();
        sqlx::query(
            "INSERT INTO claims (id, content, content_hash, agent_id, pignistic_prob, theme_id) \
             VALUES ($1, $2, $3, $4, 0.5, $5)",
        )
        .bind(id)
        .bind(content)
        .bind(hash)
        .bind(agent_id)
        .bind(theme_id)
        .execute(&pool)
        .await
        .unwrap();
    }

    // Seed two neighborhoods directly (skip Louvain for fast unit-test scope).
    let nbr_a = Uuid::new_v4();
    let nbr_b = Uuid::new_v4();
    for (id, label, size) in [(nbr_a, "nbr-a", 1_i32), (nbr_b, "nbr-b", 1_i32)] {
        sqlx::query(
            "INSERT INTO graph_neighborhoods (id, run_id, theme_id, label, size, mean_betp, dominant_frame_id) \
             VALUES ($1, $2, $3, $4, $5, NULL, NULL)"
        )
        .bind(id).bind(run_id).bind(theme_id).bind(label).bind(size)
        .execute(&pool).await.unwrap();
    }
    sqlx::query("INSERT INTO claim_neighborhood_membership (run_id, claim_id, neighborhood_id) VALUES ($1, $2, $3)")
        .bind(run_id).bind(claim_a).bind(nbr_a).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO claim_neighborhood_membership (run_id, claim_id, neighborhood_id) VALUES ($1, $2, $3)")
        .bind(run_id).bind(claim_b).bind(nbr_b).execute(&pool).await.unwrap();

    // Inter-neighborhood edge — store canonical (a < b).
    let (lo, hi) = if nbr_a < nbr_b {
        (nbr_a, nbr_b)
    } else {
        (nbr_b, nbr_a)
    };
    sqlx::query(
        "INSERT INTO neighborhood_edges (run_id, neighborhood_a, neighborhood_b, weight) \
         VALUES ($1, $2, $3, 0.7)",
    )
    .bind(run_id)
    .bind(lo)
    .bind(hi)
    .execute(&pool)
    .await
    .unwrap();

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let resp = reqwest::Client::new()
        .get(format!(
            "http://{addr}/api/v1/graph/themes/{theme_id}/expand"
        ))
        .header(
            "Authorization",
            format!("Bearer {}", common::test_bearer_token()),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        200,
        "themes/expand should return 200"
    );
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["theme_id"].as_str().unwrap(), theme_id.to_string());
    let nbrs = body["neighborhoods"].as_array().unwrap();
    assert_eq!(
        nbrs.len(),
        2,
        "expected exactly 2 neighborhoods for the seeded theme"
    );
    let edges = body["neighborhood_edges"].as_array().unwrap();
    assert_eq!(edges.len(), 1, "expected one inter-neighborhood edge");
    assert!((edges[0]["weight"].as_f64().unwrap() - 0.7).abs() < 1e-9);
}
