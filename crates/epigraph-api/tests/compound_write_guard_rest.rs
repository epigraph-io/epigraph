//! The REST textless BBA writers honour `EPIGRAPH_COMPOUND_WRITE_GUARD`
//! (backlog 7435772c, SPEC §4.1 W3): `POST /api/v1/frames/:id/evidence` and
//! `POST /api/v1/claims/:id/assess`. Their masses carry no evidence text, so
//! on a COMPOUND (a claim with an in-force `decomposes_to` out-edge) they
//! could never be attributed to the compound's atoms.
//!
//! - `refuse`: 422 with the machine-keyed `compound_target` body listing the
//!   atoms the caller can see, and NOTHING written: no BBA, frame
//!   assignment, divergence or scoped-belief row, no edge, no assessment
//!   event, the claims row untouched;
//! - `warn`: the write goes ahead, the response carries
//!   `deprecated_compound_target` with the visible atoms, and the
//!   compound's cached belief is not moved;
//! - an atom target is written as before, with no field.
//!
//! The app's mode is set with `AppState::with_compound_write_guard`, so both
//! modes run in one process. The MCP twin is
//! `epigraph-mcp/tests/ds_evidence_compound_write_guard.rs`; the role decision
//! on an application session is pinned in
//! `epigraph-engine/tests/compound_write_guard_app_role.rs`.
#![cfg(feature = "db")]

mod common;

use epigraph_engine::belief_modes::CompoundWriteGuard;
use serde_json::Value;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::PgPool;
use std::net::SocketAddr;
use tokio::sync::oneshot;
use uuid::Uuid;

async fn spawn_app(
    conn_opts: &PgConnectOptions,
    guard: CompoundWriteGuard,
) -> (SocketAddr, oneshot::Sender<()>) {
    let base = std::env::var("DATABASE_URL").expect("DATABASE_URL");
    let db = conn_opts.get_database().expect("test database name");
    let prefix = base
        .split_once('?')
        .map_or(base.as_str(), |(a, _)| a)
        .trim_end_matches('/')
        .rsplit_once('/')
        .expect("DATABASE_URL must carry a database path")
        .0
        .to_string();
    let scoped = epigraph_db::ScopedPool::connect(
        &format!("{prefix}/{db}"),
        epigraph_db::SessionGucMode::Session,
    )
    .await
    .expect("ScopedPool::connect");
    let state =
        epigraph_api::AppState::with_scoped_pool(scoped, epigraph_api::ApiConfig::default())
            .with_compound_write_guard(guard);
    let app = epigraph_api::routes::create_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .with_graceful_shutdown(async {
                let _ = rx.await;
            })
            .await
            .unwrap();
    });
    (addr, tx)
}

async fn seed_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let pk: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, $2)")
        .bind(id)
        .bind(&pk)
        .execute(pool)
        .await
        .expect("seed agent");
    id
}

async fn seed_claim(pool: &PgPool, agent: Uuid, what: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id) \
         VALUES ($1, sha256($1::bytea), 0.5, $2) RETURNING id",
    )
    .bind(format!("7435772c rest {what} {}", Uuid::new_v4()))
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("seed claim")
}

/// A compound with two atoms: `(compound, atoms sorted by id)`.
async fn compound_with_atoms(pool: &PgPool, agent: Uuid) -> (Uuid, Vec<Uuid>) {
    let compound = seed_claim(pool, agent, "compound").await;
    let mut atoms = vec![
        seed_claim(pool, agent, "atom a").await,
        seed_claim(pool, agent, "atom b").await,
    ];
    for a in &atoms {
        sqlx::query(
            "INSERT INTO edges (id, source_id, source_type, target_id, target_type, \
                                relationship, valid_from) \
             VALUES (gen_random_uuid(), $1, 'claim', $2, 'claim', 'decomposes_to', \
                     now() - interval '1 day')",
        )
        .bind(compound)
        .bind(*a)
        .execute(pool)
        .await
        .expect("seed decomposes_to");
    }
    atoms.sort();
    (compound, atoms)
}

async fn seed_frame(pool: &PgPool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses) VALUES ($1, ARRAY['TRUE','FALSE']::text[]) \
         RETURNING id",
    )
    .bind(format!("7435772c-{}", Uuid::new_v4()))
    .fetch_one(pool)
    .await
    .expect("seed frame")
}

/// Everything either route can write for `claim`.
#[derive(Debug, PartialEq)]
struct Footprint {
    bbas: i64,
    frame_assignments: i64,
    divergence_rows: i64,
    scoped_beliefs: i64,
    edges: i64,
    assessment_events: i64,
    claim_row: Value,
}

async fn footprint(pool: &PgPool, claim: Uuid) -> Footprint {
    let count = |sql: &'static str| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, i64>(sql)
                .bind(claim)
                .fetch_one(&pool)
                .await
                .expect("count")
        }
    };
    Footprint {
        bbas: count("SELECT count(*) FROM mass_functions WHERE claim_id = $1").await,
        frame_assignments: count("SELECT count(*) FROM claim_frames WHERE claim_id = $1").await,
        divergence_rows: count("SELECT count(*) FROM ds_bayesian_divergence WHERE claim_id = $1")
            .await,
        scoped_beliefs: count("SELECT count(*) FROM ds_combined_beliefs WHERE claim_id = $1").await,
        edges: count(
            "SELECT count(*) FROM edges WHERE (source_id = $1 OR target_id = $1) \
               AND relationship <> 'decomposes_to'",
        )
        .await,
        assessment_events: count(
            "SELECT count(*) FROM events WHERE event_type = 'claim.assessed' \
               AND payload->>'claim_id' = $1::text",
        )
        .await,
        claim_row: sqlx::query_scalar(
            "SELECT to_jsonb(c) - 'updated_at' FROM claims c WHERE c.id = $1",
        )
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("claims row"),
    }
}

/// A cache no fold of these writes produces, recorded on `frame`.
async fn sentinel_cache(pool: &PgPool, claim: Uuid, frame: Uuid) {
    sqlx::query(
        "UPDATE claims SET belief = 0.613, plausibility = 0.887, pignistic_prob = 0.741, \
                belief_frame_id = $2 WHERE id = $1",
    )
    .bind(claim)
    .bind(frame)
    .execute(pool)
    .await
    .expect("set the sentinel cache");
}

async fn cache(pool: &PgPool, claim: Uuid) -> (Option<f64>, Option<f64>, Option<Uuid>) {
    sqlx::query_as("SELECT belief, pignistic_prob, belief_frame_id FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("read the cache")
}

/// `POST /api/v1/frames/:frame/evidence` on `claim` as `agent`: status, body.
async fn post_evidence(addr: SocketAddr, agent: Uuid, frame: Uuid, claim: Uuid) -> (u16, Value) {
    let token = common::mint_token_with_agent(&["claims:read", "claims:write"], agent);
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/frames/{frame}/evidence"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "claim_id": claim,
            "masses": {"0": 0.7, "0,1": 0.3},
            "reliability": 1.0,
        }))
        .send()
        .await
        .expect("evidence request");
    let status = resp.status().as_u16();
    (status, resp.json().await.expect("json body"))
}

/// `POST /api/v1/claims/:claim/assess` as `agent`: status, body.
async fn post_assess(addr: SocketAddr, agent: Uuid, claim: Uuid) -> (u16, Value) {
    let token = common::mint_token_with_agent(&["claims:read", "claims:write"], agent);
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/claims/{claim}/assess"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "evidence_type": "Observation",
            "methodology": "instrumental",
            "confidence": 0.8,
            "supports": true,
        }))
        .send()
        .await
        .expect("assess request");
    let status = resp.status().as_u16();
    (status, resp.json().await.expect("json body"))
}

fn listed_ids(atoms: &Value) -> Vec<String> {
    atoms
        .as_array()
        .unwrap_or_else(|| panic!("visible_atoms is an array: {atoms}"))
        .iter()
        .map(|a| a["id"].as_str().expect("atom id").to_string())
        .collect()
}

fn ids(atoms: &[Uuid]) -> Vec<String> {
    atoms.iter().map(Uuid::to_string).collect()
}

#[sqlx::test(migrations = "../../migrations")]
async fn refuse_answers_422_on_a_compound_and_writes_nothing_on_either_route(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let pool = pool_opts
        .connect_with(conn_opts.clone())
        .await
        .expect("seeding pool");
    let agent = seed_agent(&pool).await;
    let (compound, atoms) = compound_with_atoms(&pool, agent).await;
    let frame = seed_frame(&pool).await;
    let (addr, _shutdown) = spawn_app(&conn_opts, CompoundWriteGuard::Refuse).await;

    let before = footprint(&pool, compound).await;
    for (route, (status, body)) in [
        (
            "frames evidence",
            post_evidence(addr, agent, frame, compound).await,
        ),
        ("assess", post_assess(addr, agent, compound).await),
    ] {
        assert_eq!(status, 422, "{route} on a compound under refuse: {body}");
        assert_eq!(body["error"], "compound_target", "{route}: {body}");
        assert_eq!(body["claim_id"], compound.to_string(), "{route}: {body}");
        assert_eq!(
            body["flag"], "EPIGRAPH_COMPOUND_WRITE_GUARD",
            "{route}: {body}"
        );
        assert_eq!(body["retryable"], false, "{route}: {body}");
        assert!(
            body["message"]
                .as_str()
                .is_some_and(|m| m.contains("nothing was written")),
            "{route}: {body}"
        );
        assert_eq!(listed_ids(&body["visible_atoms"]), ids(&atoms), "{route}");
    }
    assert_eq!(
        footprint(&pool, compound).await,
        before,
        "a refused write must leave nothing behind"
    );

    // Atom targets are not guarded: both routes write as before.
    let (status, body) = post_evidence(addr, agent, frame, atoms[0]).await;
    assert_eq!(status, 201, "{body}");
    assert!(body.get("deprecated_compound_target").is_none(), "{body}");
    let (status, body) = post_assess(addr, agent, atoms[1]).await;
    assert_eq!(status, 200, "{body}");
    assert!(body.get("deprecated_compound_target").is_none(), "{body}");
    assert_eq!(footprint(&pool, atoms[0]).await.bbas, 1);
    assert_eq!(footprint(&pool, atoms[1]).await.bbas, 1);
}

#[sqlx::test(migrations = "../../migrations")]
async fn warn_writes_inert_and_names_the_visible_atoms_on_either_route(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let pool = pool_opts
        .connect_with(conn_opts.clone())
        .await
        .expect("seeding pool");
    let agent = seed_agent(&pool).await;
    let (compound, atoms) = compound_with_atoms(&pool, agent).await;
    let frame = seed_frame(&pool).await;
    sentinel_cache(&pool, compound, frame).await;
    let cache_before = cache(&pool, compound).await;
    let (addr, _shutdown) = spawn_app(&conn_opts, CompoundWriteGuard::Warn).await;

    let (status, body) = post_evidence(addr, agent, frame, compound).await;
    assert_eq!(
        status, 201,
        "warn accepts frames evidence on a compound: {body}"
    );
    let target = &body["deprecated_compound_target"];
    assert_eq!(target["claim_id"], compound.to_string(), "{body}");
    assert_eq!(target["guard"], "warn", "{body}");
    assert_eq!(listed_ids(&target["visible_atoms"]), ids(&atoms), "{body}");
    assert!(
        body["warnings"].as_array().is_some_and(|w| w
            .iter()
            .any(|w| w.as_str().is_some_and(|w| w.contains("is a compound")))),
        "{body}"
    );

    let (status, body) = post_assess(addr, agent, compound).await;
    assert_eq!(
        status, 200,
        "warn accepts an assessment of a compound: {body}"
    );
    let target = &body["deprecated_compound_target"];
    assert_eq!(target["claim_id"], compound.to_string(), "{body}");
    assert_eq!(listed_ids(&target["visible_atoms"]), ids(&atoms), "{body}");

    let after = footprint(&pool, compound).await;
    assert_eq!(after.bbas, 2, "warn stores both rows");
    assert_eq!(
        cache(&pool, compound).await,
        cache_before,
        "no fold of the compound's belief may read the warn-mode rows"
    );

    // An atom under warn carries no field.
    let (status, body) = post_evidence(addr, agent, frame, atoms[0]).await;
    assert_eq!(status, 201, "{body}");
    assert!(body.get("deprecated_compound_target").is_none(), "{body}");
}
