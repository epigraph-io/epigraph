#![cfg(feature = "db")]
//! The human-identity disclosure rule (migration 272) on the REST surfaces,
//! through the full router (spec
//! `docs/superpowers/specs/2026-11-24-human-identity-visibility-design.md`,
//! section 7 and T1).
//!
//! For each surface, an outsider's view of an UNNAMED human H equals its view
//! of N, a production-shaped nameless non-human agent, once ids, keys and
//! timestamps are replaced; and a teammate of H sees H's name (CALIBRATION),
//! so no test passes by redacting everyone.
//!
//! Both pools run on the APPLICATION ROLE, as in
//! `agents_profile_visibility_http.rs`: on the superuser pool
//! `epigraph_bypass()` is true and every human would be named.
//!
//! All names are invented.

mod common;
mod viewer_fixture;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use epigraph_api::create_router;
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::{ScopedPool, SessionGucMode};
use http_body_util::BodyExt;
use serde_json::Value;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;
use viewer_fixture::{database_url_for, downgraded_pool};

async fn app_role_state(pool: &PgPool) -> AppState {
    let url = database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let bypass: bool = sqlx::query_scalar("SELECT public.epigraph_bypass()")
        .fetch_one(scoped.inner())
        .await
        .expect("epigraph_bypass on the scoped pool");
    assert!(
        !bypass,
        "CALIBRATION: the scoped pool must not be privileged"
    );
    let raw = downgraded_pool(pool, "epigraph_app").await;
    let mut state = AppState::with_db(raw, ApiConfig::default());
    state.scoped = Some(scoped);
    state
}

async fn call(
    state: &AppState,
    caller: Uuid,
    method: Method,
    uri: &str,
    scopes: &[&str],
    body: Option<Value>,
) -> (StatusCode, Value) {
    let token = common::mint_token_with_agent(scopes, caller);
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"));
    let body = match body {
        Some(b) => {
            req = req.header(header::CONTENT_TYPE, "application/json");
            Body::from(b.to_string())
        }
        None => Body::empty(),
    };
    let resp = create_router(state.clone())
        .oneshot(req.body(body).expect("request"))
        .await
        .expect("response");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn get(state: &AppState, caller: Uuid, uri: &str) -> (StatusCode, Value) {
    call(state, caller, Method::GET, uri, &["claims:read"], None).await
}

/// An `oauth_clients` row of `client_type`, linked through the real
/// provisioning path (`ensure_for_client`), as a token mint does. A human
/// client gets a provider-form id so the asserted name is adopted.
async fn provisioned(pool: &PgPool, client_type: &str, name: &str) -> Uuid {
    let client_id = if client_type == "human" {
        format!("fixtureprovider:{}", Uuid::new_v4().simple())
    } else {
        format!("epigraph_{}", Uuid::new_v4().simple())
    };
    let row: Uuid = sqlx::query_scalar(
        "INSERT INTO oauth_clients (client_id, client_name, client_type, allowed_scopes, \
                                    status, legal_entity_name, legal_contact_email) \
         VALUES ($1, $2, $3, ARRAY['claims:write'], 'active', 'Fixture Org', \
                 'fixture@example.invalid') RETURNING id",
    )
    .bind(&client_id)
    .bind(name)
    .bind(client_type)
    .fetch_one(pool)
    .await
    .expect("client row");
    let mut tx = pool.begin().await.expect("begin");
    let agent = epigraph_db::AgentRepository::ensure_for_client(&mut tx, row)
        .await
        .expect("ensure_for_client");
    tx.commit().await.expect("commit");
    agent.into()
}

/// H (a provider-provisioned person under its real name, profile `group` as
/// migration 274 provisions it) and N (a service principal provisioned the
/// same way, then nameless with a `group` profile: C7 option (b)).
async fn h_and_n(pool: &PgPool, name: &str) -> (Uuid, Uuid) {
    let h = provisioned(pool, "human", name).await;
    let n = provisioned(pool, "service", "fixture service").await;
    sqlx::query(
        "UPDATE agents SET display_name = NULL, profile_visibility = 'group' WHERE id = $1",
    )
    .bind(n)
    .execute(pool)
    .await
    .expect("nameless N");
    (h, n)
}

async fn team_of(pool: &PgPool, members: &[Uuid]) -> Uuid {
    let id = Uuid::new_v4();
    let pk: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO groups (id, did_key, public_key, kind, display_name) \
         VALUES ($1, $2, $3, 'team', $4)",
    )
    .bind(id)
    .bind(format!("did:key:human-identity-{id}"))
    .bind(&pk)
    .bind(format!("team {id}"))
    .execute(pool)
    .await
    .expect("team");
    for m in members {
        sqlx::query(
            "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
             VALUES ($1, $2, ''::bytea, 0, 'writer')",
        )
        .bind(id)
        .bind(m)
        .execute(pool)
        .await
        .expect("membership");
    }
    id
}

async fn public_key_hex(pool: &PgPool, agent: Uuid) -> String {
    let k: Vec<u8> = sqlx::query_scalar("SELECT public_key FROM agents WHERE id = $1")
        .bind(agent)
        .fetch_one(pool)
        .await
        .expect("key");
    hex::encode(k)
}

/// Replace every occurrence of each `(value, placeholder)` in a JSON value's
/// strings, so H's and N's bodies compare modulo identity.
fn masked(v: &Value, subs: &[(String, &str)]) -> Value {
    match v {
        Value::String(s) => {
            let mut s = s.clone();
            for (from, to) in subs {
                s = s.replace(from.as_str(), to);
            }
            Value::String(s)
        }
        Value::Array(a) => Value::Array(a.iter().map(|x| masked(x, subs)).collect()),
        Value::Object(o) => Value::Object(
            o.iter()
                .map(|(k, x)| {
                    let x = if k == "created_at" {
                        Value::String("<t>".into())
                    } else {
                        masked(x, subs)
                    };
                    (k.clone(), x)
                })
                .collect(),
        ),
        other => other.clone(),
    }
}

async fn subs_for(pool: &PgPool, agent: Uuid) -> Vec<(String, &'static str)> {
    vec![
        (agent.to_string(), "<id>"),
        (public_key_hex(pool, agent).await, "<key>"),
    ]
}

/// C1, C2, C3: `GET /api/v1/agents/:id`, `GET /agents/:id`,
/// `GET /api/v1/agents?public_key=` and `GET /agents/:id/reputation` answer
/// an outsider about an unnamed human exactly as about N (200, no name, no
/// marker); a teammate gets the name (CALIBRATION).
#[sqlx::test(migrations = "../../migrations")]
async fn the_agent_routes_show_an_unnamed_human_as_a_nameless_agent(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let (h, n) = h_and_n(&pool, "Marisol Unheard").await;
    let (outsider, _) = viewer_fixture::seed_agent_with_group(&pool, "outsider").await;
    let (mate, _) = viewer_fixture::seed_agent_with_group(&pool, "teammate").await;
    team_of(&pool, &[h, mate]).await;
    let (sh, sn) = (subs_for(&pool, h).await, subs_for(&pool, n).await);

    for route in [
        "/api/v1/agents/{id}",
        "/agents/{id}",
        "/agents/{id}/reputation",
    ] {
        let (st_h, body_h) = get(&state, outsider, &route.replace("{id}", &h.to_string())).await;
        let (st_n, body_n) = get(&state, outsider, &route.replace("{id}", &n.to_string())).await;
        assert_eq!(st_h, StatusCode::OK, "{route}: {body_h}");
        assert_eq!(st_n, StatusCode::OK, "{route}: {body_n}");
        assert_eq!(
            masked(&body_h, &sh),
            masked(&body_n, &sn),
            "{route}: H must read as N to an outsider"
        );
        let (_, mine) = get(&state, mate, &route.replace("{id}", &h.to_string())).await;
        assert_eq!(
            mine["display_name"], "Marisol Unheard",
            "{route}: CALIBRATION, a teammate sees the name"
        );
    }

    let by_key = |agent: Uuid| {
        let state = state.clone();
        let pool = pool.clone();
        async move {
            let k = public_key_hex(&pool, agent).await;
            get(&state, outsider, &format!("/api/v1/agents?public_key={k}")).await
        }
    };
    let (_, list_h) = by_key(h).await;
    let (_, list_n) = by_key(n).await;
    assert_eq!(list_h["total"], 1, "{list_h}");
    assert_eq!(masked(&list_h, &sh), masked(&list_n, &sn), "?public_key=");

    // The unfiltered page: H's item carries no name, N's neither.
    let (_, page) = get(&state, outsider, "/api/v1/agents?limit=100").await;
    let item = |id: Uuid| {
        page["items"]
            .as_array()
            .expect("items")
            .iter()
            .find(|i| i["id"] == id.to_string())
            .cloned()
            .unwrap_or_else(|| panic!("{id} listed"))
    };
    assert_eq!(masked(&item(h), &sh), masked(&item(n), &sn), "page item");
}

/// C4: posting an existing human principal's public key (which
/// `GET /api/v1/agents` serves) is a find-hit that returns that row; its
/// name follows the rule, as `GET /api/v1/agents/:id` does.
#[sqlx::test(migrations = "../../migrations")]
async fn a_create_find_hit_reads_back_no_name_it_may_not_see(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let (h, _n) = h_and_n(&pool, "Marisol Unheard").await;
    let (outsider, _) = viewer_fixture::seed_agent_with_group(&pool, "outsider").await;
    let (mate, _) = viewer_fixture::seed_agent_with_group(&pool, "teammate").await;
    team_of(&pool, &[h, mate]).await;
    let key = public_key_hex(&pool, h).await;
    let post = |who: Uuid| {
        let state = state.clone();
        let key = key.clone();
        async move {
            call(
                &state,
                who,
                Method::POST,
                "/api/v1/agents",
                &["agents:write"],
                Some(serde_json::json!({"public_key": key})),
            )
            .await
        }
    };
    let (st, body) = post(outsider).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(body["id"], h.to_string(), "the find-hit is H: {body}");
    assert_eq!(body["display_name"], Value::Null, "{body}");
    let (_, body) = post(mate).await;
    assert_eq!(
        body["display_name"], "Marisol Unheard",
        "CALIBRATION: {body}"
    );
}

/// An explicit `authored` edge from `author` to a new paper, as `ingester`'s
/// document ingest writes it when it attaches an existing agent: the
/// extraction's spelling (`author_name`) and the name-derived node it
/// replaced (`replaces_author`). Returns the paper.
async fn explicit_authorship(pool: &PgPool, ingester: Uuid, author: Uuid, name: &str) -> Uuid {
    let paper: Uuid =
        sqlx::query_scalar("INSERT INTO papers (doi, title) VALUES ($1, 'T') RETURNING id")
            .bind(format!(
                "10.0000/human-identity.{}",
                Uuid::new_v4().simple()
            ))
            .fetch_one(pool)
            .await
            .expect("paper");
    let mut conn = pool.acquire().await.expect("conn");
    epigraph_db::create_ingest_written_edge_if_absent_conn(
        &mut conn,
        None,
        "ingest_document",
        ingester,
        author,
        "agent",
        paper,
        "paper",
        "authored",
        Some(serde_json::json!({
            "position": 0,
            "role": "author",
            "explicit_agent_id": true,
            "author_name": name,
            "replaces_author": Uuid::new_v4().to_string(),
        })),
    )
    .await
    .expect("authored edge");
    paper
}

/// Rows E2 / E3: `GET /api/v1/edges` serves an unnamed human's explicit
/// `authored` edge without `author_name` or `replaces_author` to an
/// outsider; position and role stay. A teammate gets both keys
/// (CALIBRATION), and a non-human agent's same edge keeps them (the rule
/// redacts humans only).
#[sqlx::test(migrations = "../../migrations")]
async fn an_unnamed_humans_authorship_edge_carries_no_spelling_of_its_name(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let (h, n) = h_and_n(&pool, "Leocadia Spelled").await;
    let (outsider, _) = viewer_fixture::seed_agent_with_group(&pool, "outsider").await;
    let (mate, _) = viewer_fixture::seed_agent_with_group(&pool, "teammate").await;
    let (ingester, _) = viewer_fixture::seed_agent_with_group(&pool, "ingester").await;
    team_of(&pool, &[h, mate]).await;
    explicit_authorship(&pool, ingester, h, "Leocadia Spelled").await;
    explicit_authorship(&pool, ingester, n, "A Service Spelling").await;

    let edge_of = |who: Uuid, agent: Uuid| {
        let state = state.clone();
        async move {
            let (st, body) = get(
                &state,
                who,
                &format!("/api/v1/edges?source_id={agent}&relationship=authored"),
            )
            .await;
            assert_eq!(st, StatusCode::OK, "{body}");
            let edges = body.as_array().expect("edges").clone();
            assert_eq!(edges.len(), 1, "{body}");
            edges[0]["properties"].clone()
        }
    };
    let p = edge_of(outsider, h).await;
    assert!(p.get("author_name").is_none(), "{p}");
    assert!(p.get("replaces_author").is_none(), "{p}");
    assert_eq!(p["position"], 0, "the edge's other data stays: {p}");
    assert_eq!(p["role"], "author");
    let p = edge_of(mate, h).await;
    assert_eq!(p["author_name"], "Leocadia Spelled", "CALIBRATION: {p}");
    assert!(p.get("replaces_author").is_some(), "CALIBRATION: {p}");
    let p = edge_of(outsider, n).await;
    assert_eq!(
        p["author_name"], "A Service Spelling",
        "a non-human keeps it: {p}"
    );
}

/// Row H6 (finding L5): a graph-query predicate on an agent's `properties`
/// (`full_name`, `email`) is a matcher on a profile detail; it never returns
/// an unnamed human to an outsider, and returns it to a teammate
/// (CALIBRATION).
#[sqlx::test(migrations = "../../migrations")]
async fn a_graph_query_cannot_match_an_unnamed_humans_profile(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let (h, _n) = h_and_n(&pool, "Seraphine Queried").await;
    sqlx::query(
        "UPDATE agents SET properties = '{\"full_name\": \"Seraphine Queried\", \
                                          \"email\": \"seraphine@example.invalid\"}'::jsonb \
          WHERE id = $1",
    )
    .bind(h)
    .execute(&pool)
    .await
    .expect("properties");
    let (outsider, _) = viewer_fixture::seed_agent_with_group(&pool, "outsider").await;
    let (mate, _) = viewer_fixture::seed_agent_with_group(&pool, "teammate").await;
    team_of(&pool, &[h, mate]).await;
    let hits = |who: Uuid, q: &'static str| {
        let state = state.clone();
        async move {
            let (st, body) = call(
                &state,
                who,
                Method::POST,
                "/api/v1/graph/query",
                &["claims:read"],
                Some(serde_json::json!({ "query": q })),
            )
            .await;
            assert_eq!(st, StatusCode::OK, "{q}: {body}");
            body["nodes"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|n| n["id"].as_str().map(str::to_string))
                .collect::<Vec<_>>()
        }
    };
    for q in [
        "MATCH (a:agent) WHERE a.full_name = 'Seraphine Queried' RETURN *",
        "MATCH (a:agent) WHERE a.email = 'seraphine@example.invalid' RETURN *",
    ] {
        assert!(
            !hits(outsider, q).await.contains(&h.to_string()),
            "{q}: an outsider matched the unnamed human"
        );
        assert!(
            hits(mate, q).await.contains(&h.to_string()),
            "{q}: CALIBRATION, a teammate matches"
        );
    }
}

/// Row H2: the graph builder (`load_subgraph_conn`, behind
/// `POST /api/v1/graph/query` and `graph_full`) gives an unnamed human's
/// node no `display_name` and the `id[..8]` label a nameless agent gets; a
/// teammate sees the name (CALIBRATION).
#[sqlx::test(migrations = "../../migrations")]
async fn the_graph_view_labels_an_unnamed_human_as_a_nameless_agent(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let (h, n) = h_and_n(&pool, "Ottilie Graphed").await;
    let (outsider, _) = viewer_fixture::seed_agent_with_group(&pool, "outsider").await;
    let (mate, _) = viewer_fixture::seed_agent_with_group(&pool, "teammate").await;
    team_of(&pool, &[h, mate]).await;
    let node = |who: Uuid, id: Uuid| {
        let state = state.clone();
        async move {
            let (st, body) = call(
                &state,
                who,
                Method::POST,
                "/api/v1/graph/query",
                &["claims:read"],
                Some(serde_json::json!({ "query": "MATCH (a:agent) RETURN * LIMIT 200" })),
            )
            .await;
            assert_eq!(st, StatusCode::OK, "{body}");
            let n = body["nodes"]
                .as_array()
                .expect("nodes")
                .iter()
                .find(|x| x["id"] == id.to_string())
                .cloned()
                .unwrap_or_else(|| panic!("{id} in the graph: {body}"));
            (
                n["display_name"].clone(),
                n["label"]
                    .as_str()
                    .unwrap_or_default()
                    .replace(&id.to_string()[..8], "<id>"),
            )
        }
    };
    assert_eq!(
        node(outsider, h).await,
        node(outsider, n).await,
        "H's node reads as N's"
    );
    assert_eq!(
        node(mate, h).await.0,
        serde_json::json!("Ottilie Graphed"),
        "CALIBRATION"
    );
}

/// Rows F1, F2, F3: the political surfaces answer an outsider about an
/// unnamed human exactly as about N: `GET /api/v1/agents/:id/epistemic-profile`
/// and `GET /api/v1/agents/compare` (no name), and a claim's genealogy names
/// an `AMPLIFIED_BY` human with no name; a teammate gets the name
/// (CALIBRATION).
#[sqlx::test(migrations = "../../migrations")]
async fn the_political_surfaces_show_an_unnamed_human_as_a_nameless_agent(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let (h, n) = h_and_n(&pool, "Cosima Amplified").await;
    let (outsider, _) = viewer_fixture::seed_agent_with_group(&pool, "outsider").await;
    let (mate, _) = viewer_fixture::seed_agent_with_group(&pool, "teammate").await;
    team_of(&pool, &[h, mate]).await;
    let (sh, sn) = (subs_for(&pool, h).await, subs_for(&pool, n).await);

    let route = |id: Uuid| format!("/api/v1/agents/{id}/epistemic-profile");
    let (st, body_h) = get(&state, outsider, &route(h)).await;
    assert_eq!(st, StatusCode::OK, "{body_h}");
    let (_, body_n) = get(&state, outsider, &route(n)).await;
    assert_eq!(
        masked(&body_h, &sh),
        masked(&body_n, &sn),
        "epistemic profile"
    );
    let (_, mine) = get(&state, mate, &route(h)).await;
    assert_eq!(mine["display_name"], "Cosima Amplified", "CALIBRATION");

    // Compare (review finding tests#3): H reads as N to the outsider, while a
    // NAMED non-human keeps its name in the same response and the teammate
    // gets H's name, so a mutant nulling every name fails.
    let (svc, _) = viewer_fixture::seed_agent_with_group(&pool, "named service").await;
    sqlx::query("UPDATE agents SET display_name = 'Plain Named Service' WHERE id = $1")
        .bind(svc)
        .execute(&pool)
        .await
        .expect("name the service");
    let compare_names = |who: Uuid| {
        let state = state.clone();
        async move {
            let (st, cmp) = get(
                &state,
                who,
                &format!("/api/v1/agents/compare?ids={h},{n},{svc}"),
            )
            .await;
            assert_eq!(st, StatusCode::OK, "{cmp}");
            let list = cmp
                .as_array()
                .or_else(|| cmp["agents"].as_array())
                .or_else(|| cmp["profiles"].as_array())
                .unwrap_or_else(|| panic!("compare body: {cmp}"))
                .clone();
            let name_of = |id: Uuid| {
                list.iter()
                    .find(|p| p["agent_id"] == id.to_string() || p["id"] == id.to_string())
                    .unwrap_or_else(|| panic!("{id} in compare: {list:?}"))["display_name"]
                    .clone()
            };
            (name_of(h), name_of(n), name_of(svc))
        }
    };
    assert_eq!(
        compare_names(outsider).await,
        (Value::Null, Value::Null, Value::from("Plain Named Service")),
        "compare, outsider"
    );
    assert_eq!(
        compare_names(mate).await.0,
        Value::from("Cosima Amplified"),
        "CALIBRATION: compare, teammate"
    );

    // Genealogy: a public claim amplified by H (an edge a stranger may write
    // names nobody; the edge is world-readable as agent-endpoint edges are).
    let (filer, _) = viewer_fixture::seed_agent_with_group(&pool, "filer").await;
    let claim = viewer_fixture::seed_public_claim(&pool, filer, "an amplified claim").await;
    let mut conn = pool.acquire().await.expect("conn");
    epigraph_db::EdgeRepository::create_if_not_exists_conn(
        &mut conn,
        claim,
        "claim",
        h,
        "agent",
        "AMPLIFIED_BY",
        Some(serde_json::json!({})),
        None,
        None,
    )
    .await
    .expect("amplified-by edge");
    drop(conn);
    let gen = |who: Uuid| {
        let state = state.clone();
        async move {
            let (st, body) = get(&state, who, &format!("/api/v1/claims/{claim}/genealogy")).await;
            assert_eq!(st, StatusCode::OK, "{body}");
            body.to_string()
        }
    };
    assert!(
        !gen(outsider).await.contains("Cosima Amplified"),
        "the genealogy named an unnamed human"
    );
    assert!(
        gen(mate).await.contains("Cosima Amplified"),
        "CALIBRATION: a teammate sees the name"
    );
}

/// Review finding tests#3: the inflation leaderboard
/// (`PoliticalRepository::get_inflation_leaderboard`) lists only agents with
/// claims the caller reads, and names each through the rule. H filed two
/// group claims in its team: the teammate sees H listed BY NAME; the outsider
/// does not see H at all (it reads none of H's claims), while a public filer
/// is listed by name to the outsider (so the projection is not nulled for
/// everyone).
#[sqlx::test(migrations = "../../migrations")]
async fn the_leaderboard_names_exactly_the_filers_the_caller_reads(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let (h, _) = h_and_n(&pool, "Leander Inflated").await;
    let (outsider, _) = viewer_fixture::seed_agent_with_group(&pool, "lb outsider").await;
    let (mate, _) = viewer_fixture::seed_agent_with_group(&pool, "lb teammate").await;
    let team = team_of(&pool, &[h, mate]).await;
    let (filer, _) = viewer_fixture::seed_agent_with_group(&pool, "lb public filer").await;
    sqlx::query("UPDATE agents SET display_name = 'Public Inflator' WHERE id = $1")
        .bind(filer)
        .execute(&pool)
        .await
        .expect("name the filer");
    for i in 0..2 {
        let c = viewer_fixture::seed_group_claim(&pool, h, team, &format!("h inflated {i}")).await;
        let p = viewer_fixture::seed_public_claim(&pool, filer, &format!("p inflated {i}")).await;
        sqlx::query(
            "UPDATE claims SET properties = jsonb_build_object('inflation_factor', 1.5) \
              WHERE id = ANY($1)",
        )
        .bind(vec![c, p])
        .execute(&pool)
        .await
        .expect("inflation factor");
    }
    let board = |who: Uuid| {
        let state = state.clone();
        async move {
            let (st, body) = get(&state, who, "/api/v1/inflation-index/leaderboard").await;
            assert_eq!(st, StatusCode::OK, "{body}");
            body.as_array().cloned().unwrap_or_else(|| panic!("{body}"))
        }
    };
    let entry = |rows: &[Value], id: Uuid| {
        rows.iter()
            .find(|r| r["agent_id"] == id.to_string())
            .cloned()
    };
    let out = board(outsider).await;
    assert!(
        entry(&out, h).is_none(),
        "the outsider reads none of H's claims: {out:?}"
    );
    assert!(
        !Value::Array(out.clone()).to_string().contains("Leander"),
        "the leaderboard named an unnamed human: {out:?}"
    );
    assert_eq!(
        entry(&out, filer).expect("the public filer is listed")["display_name"],
        "Public Inflator",
        "CALIBRATION: a public filer is named to the outsider"
    );
    let mine = board(mate).await;
    assert_eq!(
        entry(&mine, h).expect("the teammate reads H's claims")["display_name"],
        "Leander Inflated",
        "the teammate sees H named"
    );
}

/// Review finding tests#5: REST `GET /api/v1/agents/search` (named by the
/// brief) does not find an unnamed human by name, and `GET /api/v1/agents?label=`
/// serves H's item exactly as N's (both provisioned principals carry
/// `oauth-principal`); a teammate finds and sees the name (CALIBRATION).
#[sqlx::test(migrations = "../../migrations")]
async fn search_and_label_listing_show_an_unnamed_human_as_a_nameless_agent(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let (h, n) = h_and_n(&pool, "Philippa Searchless").await;
    let (outsider, _) = viewer_fixture::seed_agent_with_group(&pool, "search outsider").await;
    let (mate, _) = viewer_fixture::seed_agent_with_group(&pool, "search teammate").await;
    team_of(&pool, &[h, mate]).await;

    let search = "/api/v1/agents/search?name=Philippa%20Searchless";
    let (st, body) = get(&state, outsider, search).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert!(
        !body.to_string().contains(&h.to_string()) && !body.to_string().contains("Philippa"),
        "search found an unnamed human by name: {body}"
    );
    let (st, body) = get(&state, mate, search).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert!(
        body.to_string().contains(&h.to_string()),
        "CALIBRATION: {body}"
    );

    let (sh, sn) = (subs_for(&pool, h).await, subs_for(&pool, n).await);
    let (st, page) = get(
        &state,
        outsider,
        "/api/v1/agents?label=oauth-principal&limit=100",
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{page}");
    let item = |page: &Value, id: Uuid| {
        page["items"]
            .as_array()
            .unwrap_or_else(|| panic!("items: {page}"))
            .iter()
            .find(|i| i["id"] == id.to_string())
            .cloned()
            .unwrap_or_else(|| panic!("{id} listed: {page}"))
    };
    assert_eq!(
        masked(&item(&page, h), &sh),
        masked(&item(&page, n), &sn),
        "?label=: H's item reads as N's"
    );
    let (_, page) = get(
        &state,
        mate,
        "/api/v1/agents?label=oauth-principal&limit=100",
    )
    .await;
    assert_eq!(
        item(&page, h)["display_name"],
        "Philippa Searchless",
        "CALIBRATION"
    );
}
