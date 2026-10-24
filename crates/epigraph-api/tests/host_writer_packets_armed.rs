#![cfg(feature = "db")]
//! Kernel-contract pin for a host's labelled claim writers under an ARMED
//! operator binding with the host's service client allowlisted for its human.
//!
//! A host (epiclaw-host) records two kinds of labelled claim on its operator's
//! behalf: an egress-policy approval (`policy`, `policy:network`,
//! `policy:active`, `egress:<host>:<port>`) and a Foreman lifecycle mirror
//! (`foreman`, `lifecycle`, `<feature>`). Its service client's agent S is the
//! token principal; the body author is the host's recorder agent L, which is
//! live-linked to the human H. It used to write them with
//! `POST /api/v1/claims`, which files a public claim in the PRINCIPAL's own
//! personal group, so once armed every such write is refused `OPL02`. It now
//! writes them as packets (`POST /api/v1/submit/packet`), which file the claim
//! in the AUTHOR's operator group, H's group HG, with the labels set in the
//! claim's own transaction.
//!
//! The bodies posted here are the host's own templates
//! (`tests/fixtures/host_packets/*.template.json`, byte-identical to the
//! host's `tests/fixtures/*.template.json`, which its wire tests compare its
//! real request bodies against), rendered with fixture values.
//!
//! This is a CONTRACT PIN, not a regression test of a kernel change: no kernel
//! line changes with it, and it passes whether or not the host has moved. Its
//! red evidence is the mutations below. It runs on the APPLICATION ROLE, armed,
//! through `create_router` with real `client_credentials` tokens, so the
//! bearer, the viewer build, row security and migration 122/149's trigger all
//! decide as in production.
//!
//! * P1 / P2: the egress and mirror packets, S's token, author L: 201, one
//!   claim (L, HG, the labels and properties exactly as sent, public), its
//!   evidence and trace rows also in HG, response with a trace and one
//!   evidence id.
//! * P3: the same body again: 201 `was_duplicate`, same claim and trace, no
//!   new row; the same content with other labels does not relabel.
//! * P4: the same content as a claim the OLD REST body wrote before arming
//!   (owned by S's personal group, no trace): 201 with the kernel's literal
//!   dedup body (`trace_id: null`, `evidence_ids: []`), still owned by S's
//!   group, labels unchanged, no evidence or trace added.
//! * T1: the same content as a non-current claim: 409 `DuplicateNotCurrent`.
//! * N1: a NON-allowlisted service client with a writer membership in HG:
//!   403 `OPL01`, nothing written.
//! * N2: S's token, author S itself: 403 `OPL02` (the allowlist does not
//!   re-home the principal's own authorship).
//! * N3: S's token, author linked to ANOTHER human: 403 `OPL02` (measured;
//!   the trigger's writer-scope check fires before attribution), nothing
//!   written.
//! * N4: S's token, the OLD REST body on `POST /api/v1/claims`, author L:
//!   403 `OPL02`, nothing written. Pins that the REST route was NOT widened.
//! * N5: S's token, author H itself: 201, owned by HG. Pins the reach accepted
//!   for an allowlisted principal (any author of its own human, the human
//!   included); narrowing it later must flip this.
//! * N6: S's token, author an agent of H whose link is RETIRED: 403 `OPL01`.
//! * R1 / R2: the egress revoke (an admin client's standing `claims:admin`
//!   token, admin-scope switch UNARMED, as during the arming window) removes
//!   `policy:active` from the P1 row (HG) and the P4 row (S's group): 200,
//!   label gone, one `claims.admin_write` audit row each.
//!
//! Mutations (each verified to turn this test red; recorded in the PR):
//! M1 the `client_allowlist` arm dropped from `epigraph_author_binding`;
//! M2 `persist_packet` declaring from the principal instead of the author;
//! M3 the labels UPDATE dropped from `persist_packet`;
//! M4 S's writer membership in HG not granted;
//! M5 the properties UPDATE dropped from `persist_packet`.
//!
//! TWO DEPLOYMENT SHAPES. The test above is the shape once the legacy
//! `*_privacy` policies are dropped: S holds a writer membership in HG, and
//! `claims_tenancy`'s WITH CHECK alone admits the HG claim. The second test,
//! `..._through_the_legacy_privacy_policies_without_a_membership`, is the shape
//! of pre-MT-4z deployments where the legacy policies remain: S has NO
//! membership in HG, and the three legacy PERMISSIVE `FOR ALL` policies
//! (`claims_privacy`, `evidence_privacy`, `edges_privacy`, present in no
//! migration, with no WITH CHECK, so their USING is reused as one) are
//! installed with their deployed definitions. Permissive policies OR, so the
//! claim INSERT into HG is admitted by `claims_privacy`, not by membership; the
//! evidence and trace rows then take migration 114's arm (e) and land
//! writer-owned in S's OWN personal group, not in HG. A calibration arm posts
//! the same body before the policies exist and pins the row-security refusal,
//! so the case cannot pass on a schema where membership alone would admit it.
//! M6 (`claims_privacy` alone dropped before the first packet) turns the
//! second test red with the same row-security refusal.

mod viewer_fixture;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use epigraph_api::create_router;
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::{AgentRepository, ScopedPool, SessionGucMode};
use http_body_util::BodyExt;
use sqlx::PgPool;
use tower::ServiceExt;
use tracing_test::traced_test;
use uuid::Uuid;
use viewer_fixture::{
    as_role, database_url_for, downgraded_pool, seed_agent_with_group, seed_human_operator,
};

const EGRESS_TEMPLATE: &str = include_str!("fixtures/host_packets/egress_packet.template.json");
const FOREMAN_TEMPLATE: &str = include_str!("fixtures/host_packets/foreman_packet.template.json");

async fn app_role_state(pool: &PgPool) -> AppState {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app");
    assert!(
        !bypassrls,
        "epigraph_app holds BYPASSRLS: every arm here is vacuous"
    );
    let url = database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let raw = downgraded_pool(pool, "epigraph_app").await;
    let mut state = AppState::with_db(raw, ApiConfig::default());
    state.scoped = Some(scoped);
    state
        .load_entity_type_cache()
        .await
        .expect("load the entity-type cache");
    state
}

/// Render a host template: `{{NAME}}` -> value, then parse.
fn render(template: &str, vars: &[(&str, String)]) -> serde_json::Value {
    let mut out = template.to_string();
    for (name, value) in vars {
        out = out.replace(&format!("{{{{{name}}}}}"), value);
    }
    let mut v: serde_json::Value = serde_json::from_str(&out).expect("a rendered template");
    assert!(
        !out.contains("{{"),
        "an unrendered placeholder in the template: {out}"
    );
    // The host's evidence hash: BLAKE3 hex of the serialised properties.
    let props = serde_json::to_vec(&v["claim"]["properties"]).expect("properties");
    v["evidence"][0]["content_hash"] = serde_json::Value::String(
        epigraph_crypto::ContentHasher::to_hex(&epigraph_crypto::ContentHasher::hash(&props)),
    );
    v
}

fn egress_packet(author: Uuid, host: &str) -> serde_json::Value {
    render(
        EGRESS_TEMPLATE,
        &[
            ("AUTHOR", author.to_string()),
            ("HOST", host.to_string()),
            ("PORT", "443".to_string()),
            ("APPROVER", "fixture-approver".to_string()),
            ("OBSERVED_AT", chrono::Utc::now().to_rfc3339()),
            ("EVIDENCE_HASH", "pending".to_string()),
        ],
    )
}

fn mirror_packet(author: Uuid, work_item: &str) -> serde_json::Value {
    render(
        FOREMAN_TEMPLATE,
        &[
            ("AUTHOR", author.to_string()),
            ("KIND", "reviewing->mergeable".to_string()),
            ("WORK_ITEM", work_item.to_string()),
            ("FEATURE", "feat-fixture".to_string()),
            ("PAYLOAD", r#"{"pr": 9}"#.to_string()),
            ("OBSERVED_AT", chrono::Utc::now().to_rfc3339()),
            ("EVIDENCE_HASH", "pending".to_string()),
        ],
    )
}

/// The OLD host REST body (`POST /api/v1/claims`) for the same approval.
fn rest_egress_body(author: Uuid, host: &str) -> serde_json::Value {
    let p = egress_packet(author, host);
    serde_json::json!({
        "content": p["claim"]["content"],
        "agent_id": author,
        "initial_truth": 0.65,
        "properties": p["claim"]["properties"],
        "labels": p["claim"]["labels"],
    })
}

async fn call(
    state: &AppState,
    method: Method,
    uri: &str,
    bearer: &str,
    body: &serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let resp = create_router(state.clone())
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
                .body(Body::from(serde_json::to_vec(body).expect("json")))
                .expect("request"),
        )
        .await
        .expect("response");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    let json = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| serde_json::Value::String(String::from_utf8_lossy(&bytes).into()));
    (status, json)
}

async fn post_packet(
    state: &AppState,
    bearer: &str,
    body: &serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    call(state, Method::POST, "/api/v1/submit/packet", bearer, body).await
}

/// A service client with a known secret whose agent is `agent`.
async fn seed_service_client(pool: &PgPool, agent: Uuid, seed: &str, scopes: &[&str]) -> Client {
    let secret_bytes: [u8; 32] = *blake3::hash(seed.as_bytes()).as_bytes();
    let secret = hex::encode(secret_bytes);
    let client_id = format!("epigraph_{}", hex::encode(&secret_bytes[..16]));
    let scopes: Vec<String> = scopes.iter().map(|s| (*s).to_string()).collect();
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO oauth_clients (client_id, client_secret_hash, client_name, client_type, \
                                    allowed_scopes, granted_scopes, status, agent_id, \
                                    legal_entity_name, legal_contact_email) \
         VALUES ($1, $2, $3, 'service', $4, $4, 'active', $5, 'Fixture Org', \
                 'fixture@example.invalid') RETURNING id",
    )
    .bind(&client_id)
    .bind(blake3::hash(&secret_bytes).as_bytes().as_slice())
    .bind(seed)
    .bind(&scopes)
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("the service client");
    Client {
        id,
        client_id,
        secret,
    }
}

struct Client {
    id: Uuid,
    client_id: String,
    secret: String,
}

/// A `client_credentials` access token, minted on a superuser-pool router.
async fn token(pool: &PgPool, c: &Client) -> String {
    let (status, body) = call(
        &AppState::with_db(pool.clone(), ApiConfig::default()),
        Method::POST,
        "/oauth/token",
        "unused",
        &serde_json::json!({
            "grant_type": "client_credentials",
            "client_id": c.client_id,
            "client_secret": c.secret,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the client mints: {body}");
    body["access_token"]
        .as_str()
        .unwrap_or_else(|| panic!("an access token: {body}"))
        .to_string()
}

#[derive(Debug, PartialEq)]
struct Row {
    id: Uuid,
    agent_id: Uuid,
    owner_group_id: Uuid,
    labels: Vec<String>,
    properties: Option<serde_json::Value>,
    visibility: String,
    trace_id: Option<Uuid>,
    is_current: bool,
}

async fn rows_with_content(pool: &PgPool, content: &serde_json::Value) -> Vec<Row> {
    let content = content.as_str().expect("content is a string");
    let hash = epigraph_crypto::ContentHasher::hash(content.as_bytes());
    sqlx::query_as::<
        _,
        (
            Uuid,
            Uuid,
            Uuid,
            Vec<String>,
            Option<serde_json::Value>,
            String,
            Option<Uuid>,
            bool,
        ),
    >(
        "SELECT id, agent_id, owner_group_id, labels, properties, visibility::text, trace_id, \
                is_current \
           FROM claims WHERE content_hash = $1 ORDER BY created_at",
    )
    .bind(hash.as_slice())
    .fetch_all(pool)
    .await
    .expect("read back")
    .into_iter()
    .map(
        |(id, agent_id, owner_group_id, labels, properties, visibility, trace_id, is_current)| {
            Row {
                id,
                agent_id,
                owner_group_id,
                labels,
                properties,
                visibility,
                trace_id,
                is_current,
            }
        },
    )
    .collect()
}

/// `(evidence owner groups, reasoning-trace owner groups)` of `claim`.
async fn dependents(pool: &PgPool, claim: Uuid) -> (Vec<Uuid>, Vec<Uuid>) {
    let ev: Vec<Uuid> =
        sqlx::query_scalar("SELECT owner_group_id FROM evidence WHERE claim_id = $1")
            .bind(claim)
            .fetch_all(pool)
            .await
            .expect("evidence");
    let tr: Vec<Uuid> =
        sqlx::query_scalar("SELECT owner_group_id FROM reasoning_traces WHERE claim_id = $1")
            .bind(claim)
            .fetch_all(pool)
            .await
            .expect("traces");
    (ev, tr)
}

async fn admin_writes_for(pool: &PgPool, claim: Uuid) -> Vec<serde_json::Value> {
    sqlx::query_scalar(
        "SELECT details FROM security_events \
          WHERE event_type = 'claims.admin_write' AND details->>'claim_id' = $1",
    )
    .bind(claim.to_string())
    .fetch_all(pool)
    .await
    .expect("audit rows")
}

fn strings(v: &serde_json::Value) -> Vec<String> {
    v.as_array()
        .expect("an array")
        .iter()
        .map(|s| s.as_str().expect("a string").to_string())
        .collect()
}

fn assert_refused(status: StatusCode, body: &serde_json::Value, code: &str, case: &str) {
    assert_eq!(status, StatusCode::FORBIDDEN, "{case}: {body}");
    assert!(
        body.to_string().contains(code),
        "{case} names {code}: {body}"
    );
}

// One fixture, one armed database, every sub-case in order: splitting it would
// re-arm per case and hide the order the legacy rows depend on.
#[allow(clippy::too_many_lines)]
#[sqlx::test(migrations = "../../migrations")]
async fn a_hosts_labelled_packets_land_in_the_bound_humans_group_under_an_armed_allowlist(
    pool: PgPool,
) {
    // ── Fixture (unarmed) ──
    let (h, hg) = seed_human_operator(&pool, "human-h").await;
    let (l, _) = seed_agent_with_group(&pool, "recorder-l").await;
    let (h3, _) = seed_human_operator(&pool, "human-h3").await;
    let (l3, _) = seed_agent_with_group(&pool, "other-human-agent").await;
    let (retired, _) = seed_agent_with_group(&pool, "retired-r").await;
    {
        let mut conn = pool.acquire().await.expect("acquire");
        AgentRepository::link_operator(&mut conn, l, h)
            .await
            .expect("l -> h");
        AgentRepository::link_operator(&mut conn, l3, h3)
            .await
            .expect("l3 -> h3");
        AgentRepository::link_retired_agent(&mut conn, retired, h)
            .await
            .expect("retired -> h");
    }
    let (s, s_group) = seed_agent_with_group(&pool, "service-s").await;
    let s_client = seed_service_client(&pool, s, "host writer s", &["claims:write"]).await;
    let (s2, _) = seed_agent_with_group(&pool, "service-s2").await;
    let s2_client = seed_service_client(&pool, s2, "unbound writer s2", &["claims:write"]).await;
    let (admin, _) = seed_agent_with_group(&pool, "admin-a").await;
    let admin_client = seed_service_client(
        &pool,
        admin,
        "admin client a",
        &["claims:write", "claims:admin"],
    )
    .await;
    let state = app_role_state(&pool).await;
    assert_eq!(
        state.admin_scope_posture().await,
        epigraph_api::middleware::bearer::AdminScopePosture::Unarmed,
        "PREMISE: the admin-scope switch is unarmed, as during the arming window"
    );
    let s_token = token(&pool, &s_client).await;

    // Legacy rows the OLD REST body wrote before the arm: owned by S's own
    // personal group, no trace.
    let legacy_host = format!("legacy-{}.example.test", Uuid::new_v4().simple());
    let (status, body) = call(
        &state,
        Method::POST,
        "/api/v1/claims",
        &s_token,
        &rest_egress_body(l, &legacy_host),
    )
    .await;
    assert!(
        status.is_success() && body["was_created"] == true,
        "CALIBRATION: unarmed REST: {status} {body}"
    );
    let legacy_content = egress_packet(l, &legacy_host)["claim"]["content"].clone();
    let legacy = rows_with_content(&pool, &legacy_content).await;
    assert_eq!(legacy.len(), 1);
    assert_eq!(
        (
            legacy[0].agent_id,
            legacy[0].owner_group_id,
            legacy[0].trace_id
        ),
        (l, s_group, None),
        "PREMISE: a REST row is the principal's, with no trace"
    );
    let legacy_id = legacy[0].id;

    let retired_host = format!("tombstone-{}.example.test", Uuid::new_v4().simple());
    let (status, body) = call(
        &state,
        Method::POST,
        "/api/v1/claims",
        &s_token,
        &rest_egress_body(l, &retired_host),
    )
    .await;
    assert!(
        status.is_success() && body["was_created"] == true,
        "CALIBRATION: unarmed REST: {status} {body}"
    );
    let tombstone_content = egress_packet(l, &retired_host)["claim"]["content"].clone();
    sqlx::query("UPDATE claims SET is_current = false WHERE content_hash = $1")
        .bind(
            epigraph_crypto::ContentHasher::hash(
                tombstone_content.as_str().expect("content").as_bytes(),
            )
            .as_slice(),
        )
        .execute(&pool)
        .await
        .expect("retire the tombstone row");

    // ── Allow S's client for H, give S (and S2) a writer membership in HG, arm ──
    let s_client_id = s_client.id;
    as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        sqlx::query("SELECT * FROM public.epigraph_allow_author_binding_client($1, $2, 'host')")
            .bind(s_client_id)
            .bind(h)
            .execute(&mut *conn)
            .await
            .expect("allow");
        sqlx::query("SELECT armed_now FROM public.epigraph_arm_operator_binding()")
            .execute(&mut *conn)
            .await
            .expect("arm");
        (conn, ())
    })
    .await;
    for writer in [s, s2] {
        sqlx::query(
            "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
             VALUES ($1, $2, ''::bytea, 0, 'writer')",
        )
        .bind(hg)
        .bind(writer)
        .execute(&pool)
        .await
        .expect("a writer membership in HG");
    }
    let s_token = token(&pool, &s_client).await;

    // ── P1: the egress approval packet ──
    let p1 = egress_packet(l, &format!("p1-{}.example.test", Uuid::new_v4().simple()));
    let (status, body) = post_packet(&state, &s_token, &p1).await;
    assert_eq!(status, StatusCode::CREATED, "P1: {body}");
    assert_eq!(body["was_duplicate"], false, "P1: {body}");
    assert!(body["trace_id"].is_string(), "P1 has a trace: {body}");
    assert_eq!(
        body["evidence_ids"].as_array().map(Vec::len),
        Some(1),
        "P1: {body}"
    );
    let rows = rows_with_content(&pool, &p1["claim"]["content"]).await;
    assert_eq!(rows.len(), 1, "P1: one claim");
    let p1_id = rows[0].id;
    assert_eq!(body["claim_id"], p1_id.to_string());
    assert_eq!(
        (
            rows[0].agent_id,
            rows[0].owner_group_id,
            rows[0].labels.clone(),
            rows[0].properties.clone(),
            rows[0].visibility.as_str(),
        ),
        (
            l,
            hg,
            strings(&p1["claim"]["labels"]),
            Some(p1["claim"]["properties"].clone()),
            "public"
        ),
        "P1: authored by L, owned by HG, labels and properties exactly as sent"
    );
    assert_eq!(
        dependents(&pool, p1_id).await,
        (vec![hg], vec![hg]),
        "P1: its evidence and trace are owned by HG"
    );
    let p1_trace = body["trace_id"].clone();

    // ── P2: the Foreman mirror packet ──
    let p2 = mirror_packet(l, &format!("wi-{}", Uuid::new_v4().simple()));
    let (status, body) = post_packet(&state, &s_token, &p2).await;
    assert_eq!(status, StatusCode::CREATED, "P2: {body}");
    assert_eq!(body["was_duplicate"], false, "P2: {body}");
    let rows = rows_with_content(&pool, &p2["claim"]["content"]).await;
    assert_eq!(rows.len(), 1, "P2: one claim");
    assert_eq!(
        (
            rows[0].agent_id,
            rows[0].owner_group_id,
            rows[0].labels.clone(),
            rows[0].properties.clone(),
        ),
        (
            l,
            hg,
            strings(&p2["claim"]["labels"]),
            Some(p2["claim"]["properties"].clone())
        ),
        "P2: authored by L, owned by HG, labels and properties exactly as sent"
    );
    assert_eq!(
        dependents(&pool, rows[0].id).await,
        (vec![hg], vec![hg]),
        "P2"
    );

    // ── P3: the same approval again, then with other labels ──
    let (status, body) = post_packet(&state, &s_token, &p1).await;
    assert_eq!(status, StatusCode::CREATED, "P3: {body}");
    assert_eq!(body["was_duplicate"], true, "P3: {body}");
    assert_eq!(body["claim_id"], p1_id.to_string(), "P3: the same claim");
    assert_eq!(body["trace_id"], p1_trace, "P3: the same trace");
    let mut relabelled = p1.clone();
    relabelled["claim"]["labels"] = serde_json::json!(["policy"]);
    let (status, body) = post_packet(&state, &s_token, &relabelled).await;
    assert_eq!(status, StatusCode::CREATED, "P3 relabel: {body}");
    let rows = rows_with_content(&pool, &p1["claim"]["content"]).await;
    assert_eq!(rows.len(), 1, "P3: still one claim");
    assert_eq!(
        rows[0].labels,
        strings(&p1["claim"]["labels"]),
        "P3: a duplicate never relabels"
    );
    assert_eq!(
        dependents(&pool, p1_id).await,
        (vec![hg], vec![hg]),
        "P3: nothing added"
    );

    // ── P4: dedup onto the legacy REST row ──
    let p4 = egress_packet(l, &legacy_host);
    let (status, body) = post_packet(&state, &s_token, &p4).await;
    assert_eq!(status, StatusCode::CREATED, "P4: {body}");
    assert_eq!(
        (
            &body["claim_id"],
            &body["trace_id"],
            &body["evidence_ids"],
            &body["was_duplicate"]
        ),
        (
            &serde_json::json!(legacy_id),
            &serde_json::Value::Null,
            &serde_json::json!([]),
            &serde_json::json!(true)
        ),
        "P4: the kernel's literal dedup body onto a traceless claim: {body}"
    );
    let rows = rows_with_content(&pool, &legacy_content).await;
    assert_eq!(rows.len(), 1, "P4: still one claim");
    assert_eq!(
        (
            rows[0].owner_group_id,
            rows[0].trace_id,
            rows[0].labels.clone()
        ),
        (s_group, None, strings(&p4["claim"]["labels"])),
        "P4: not re-homed, still traceless, labels unchanged"
    );
    assert_eq!(
        dependents(&pool, legacy_id).await,
        (vec![], vec![]),
        "P4: nothing added"
    );

    // ── T1: dedup onto a non-current claim ──
    let (status, body) = post_packet(&state, &s_token, &egress_packet(l, &retired_host)).await;
    assert_eq!(status, StatusCode::CONFLICT, "T1: {body}");
    assert!(
        body.to_string().contains("DuplicateNotCurrent"),
        "T1: {body}"
    );

    // ── N1: a non-allowlisted service client, writer in HG ──
    let s2_token = token(&pool, &s2_client).await;
    let n1 = egress_packet(l, &format!("n1-{}.example.test", Uuid::new_v4().simple()));
    let (status, body) = post_packet(&state, &s2_token, &n1).await;
    assert_refused(status, &body, "OPL01", "N1");
    assert!(
        rows_with_content(&pool, &n1["claim"]["content"])
            .await
            .is_empty(),
        "N1"
    );

    // ── N2: S's own authorship ──
    let n2 = egress_packet(s, &format!("n2-{}.example.test", Uuid::new_v4().simple()));
    let (status, body) = post_packet(&state, &s_token, &n2).await;
    assert_refused(status, &body, "OPL02", "N2");
    assert!(
        rows_with_content(&pool, &n2["claim"]["content"])
            .await
            .is_empty(),
        "N2"
    );

    // ── N3: an author of another human ──
    let n3 = egress_packet(l3, &format!("n3-{}.example.test", Uuid::new_v4().simple()));
    let (status, body) = post_packet(&state, &s_token, &n3).await;
    assert_refused(status, &body, "OPL02", "N3");
    assert!(
        rows_with_content(&pool, &n3["claim"]["content"])
            .await
            .is_empty(),
        "N3"
    );

    // ── N4: the old REST body ──
    let n4_host = format!("n4-{}.example.test", Uuid::new_v4().simple());
    let (status, body) = call(
        &state,
        Method::POST,
        "/api/v1/claims",
        &s_token,
        &rest_egress_body(l, &n4_host),
    )
    .await;
    assert_refused(status, &body, "OPL02", "N4");
    assert!(
        rows_with_content(&pool, &egress_packet(l, &n4_host)["claim"]["content"])
            .await
            .is_empty(),
        "N4"
    );

    // ── N5: the human itself as author ──
    let n5 = egress_packet(h, &format!("n5-{}.example.test", Uuid::new_v4().simple()));
    let (status, body) = post_packet(&state, &s_token, &n5).await;
    assert_eq!(status, StatusCode::CREATED, "N5: {body}");
    let rows = rows_with_content(&pool, &n5["claim"]["content"]).await;
    assert_eq!(
        rows.iter()
            .map(|r| (r.agent_id, r.owner_group_id))
            .collect::<Vec<_>>(),
        vec![(h, hg)],
        "N5: authored by H, owned by HG"
    );

    // ── N6: a retired agent of H ──
    let n6 = egress_packet(
        retired,
        &format!("n6-{}.example.test", Uuid::new_v4().simple()),
    );
    let (status, body) = post_packet(&state, &s_token, &n6).await;
    assert_refused(status, &body, "OPL01", "N6");
    assert!(
        rows_with_content(&pool, &n6["claim"]["content"])
            .await
            .is_empty(),
        "N6"
    );

    // ── R1 / R2: the egress revoke on the new (HG) and the legacy (S) row ──
    let admin_token = token(&pool, &admin_client).await;
    for (case, claim, owner) in [("R1", p1_id, hg), ("R2", legacy_id, s_group)] {
        let (status, body) = call(
            &state,
            Method::PATCH,
            &format!("/api/v1/claims/{claim}/labels"),
            &admin_token,
            &serde_json::json!({ "add": [], "remove": ["policy:active"] }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{case}: {body}");
        let labels: Vec<String> = sqlx::query_scalar("SELECT labels FROM claims WHERE id = $1")
            .bind(claim)
            .fetch_one(&pool)
            .await
            .expect("labels");
        assert!(
            !labels.iter().any(|l| l == "policy:active")
                && labels.iter().any(|l| l == "policy:network"),
            "{case}: only policy:active is removed: {labels:?}"
        );
        let audit = admin_writes_for(&pool, claim).await;
        assert_eq!(audit.len(), 1, "{case}: one audited admin write: {audit:?}");
        assert_eq!(audit[0]["owner_group_id"], owner.to_string(), "{case}");
        assert_eq!(audit[0]["admin_agent_id"], admin.to_string(), "{case}");
    }
}

/// `(owner_group_id, writer_owned)` of `claim`'s evidence and reasoning-trace
/// rows: `(evidence, traces)`.
async fn dependents_writer_owned(
    pool: &PgPool,
    claim: Uuid,
) -> (Vec<(Uuid, bool)>, Vec<(Uuid, bool)>) {
    let ev: Vec<(Uuid, bool)> =
        sqlx::query_as("SELECT owner_group_id, writer_owned FROM evidence WHERE claim_id = $1")
            .bind(claim)
            .fetch_all(pool)
            .await
            .expect("evidence");
    let tr: Vec<(Uuid, bool)> = sqlx::query_as(
        "SELECT owner_group_id, writer_owned FROM reasoning_traces WHERE claim_id = $1",
    )
    .bind(claim)
    .fetch_all(pool)
    .await
    .expect("traces");
    (ev, tr)
}

/// The legacy policies' helper functions and the three PERMISSIVE `FOR ALL`
/// policies, as deployments that predate their removal still carry them: no
/// WITH CHECK (so USING is reused as one), and a USING that is TRUE for every
/// row without a `fully_private` encryption row.
async fn install_legacy_privacy_policies(pool: &PgPool) {
    let ddl = [
        "CREATE OR REPLACE FUNCTION public.epigraph_current_group_id() \
          RETURNS uuid LANGUAGE plpgsql STABLE AS $function$ \
         DECLARE raw text; \
         BEGIN \
             raw := current_setting('app.group_id', true); \
             IF raw IS NULL OR raw = '' THEN RETURN NULL; END IF; \
             RETURN raw::uuid; \
         EXCEPTION WHEN invalid_text_representation THEN RETURN NULL; \
         END; $function$",
        "CREATE OR REPLACE FUNCTION public.epigraph_is_visible_to_group(p_entity_id uuid, p_table text) \
          RETURNS boolean LANGUAGE plpgsql STABLE AS $function$ \
         DECLARE gid uuid := epigraph_current_group_id(); found boolean; \
         BEGIN \
             IF p_table = 'claim' THEN \
                 SELECT EXISTS(SELECT 1 FROM claim_encryption ce \
                                WHERE ce.claim_id = p_entity_id \
                                  AND ce.privacy_tier = 'fully_private' \
                                  AND (gid IS NULL OR ce.group_id != gid)) INTO found; \
             ELSIF p_table = 'evidence' THEN \
                 SELECT EXISTS(SELECT 1 FROM evidence_encryption ee \
                                WHERE ee.evidence_id = p_entity_id \
                                  AND ee.privacy_tier = 'fully_private' \
                                  AND (gid IS NULL OR ee.group_id != gid)) INTO found; \
             ELSE \
                 found := false; \
             END IF; \
             RETURN NOT found; \
         END; $function$",
        "CREATE POLICY evidence_privacy ON evidence AS PERMISSIVE FOR ALL TO PUBLIC \
           USING (epigraph_is_visible_to_group(id, 'evidence'::text))",
        "CREATE POLICY edges_privacy ON edges AS PERMISSIVE FOR ALL TO PUBLIC \
           USING (epigraph_is_visible_to_group(source_id, 'claim'::text) \
              AND epigraph_is_visible_to_group(source_id, 'evidence'::text) \
              AND epigraph_is_visible_to_group(target_id, 'claim'::text) \
              AND epigraph_is_visible_to_group(target_id, 'evidence'::text))",
        "CREATE POLICY claims_privacy ON claims AS PERMISSIVE FOR ALL TO PUBLIC \
           USING (epigraph_is_visible_to_group(id, 'claim'::text))",
    ];
    for stmt in ddl {
        sqlx::query(stmt)
            .execute(pool)
            .await
            .unwrap_or_else(|e| panic!("install the legacy policies: {e}\n{stmt}"));
    }
}

/// `(table, permissive, roles, cmd, qual, with_check)` of the `*_privacy`
/// policies, as `pg_policies` deparses them.
async fn legacy_privacy_policies(
    pool: &PgPool,
) -> Vec<(String, String, Vec<String>, String, String, Option<String>)> {
    sqlx::query_as(
        "SELECT tablename::text, permissive, roles::text[], cmd, qual, with_check \
           FROM pg_policies \
          WHERE schemaname = 'public' \
            AND policyname IN ('claims_privacy', 'evidence_privacy', 'edges_privacy') \
          ORDER BY tablename",
    )
    .fetch_all(pool)
    .await
    .expect("read pg_policies")
}

// The pre-MT-4z shape (module doc, "TWO DEPLOYMENT SHAPES"). Its own database,
// so the legacy policies it installs reach no other test.
#[allow(clippy::too_many_lines)]
#[sqlx::test(migrations = "../../migrations")]
#[traced_test]
async fn a_hosts_labelled_packets_land_in_the_bound_humans_group_through_the_legacy_privacy_policies_without_a_membership(
    pool: PgPool,
) {
    // ── Fixture (unarmed) ──
    let (h, hg) = seed_human_operator(&pool, "human-h").await;
    let (l, _) = seed_agent_with_group(&pool, "recorder-l").await;
    {
        let mut conn = pool.acquire().await.expect("acquire");
        AgentRepository::link_operator(&mut conn, l, h)
            .await
            .expect("l -> h");
    }
    let (s, s_group) = seed_agent_with_group(&pool, "service-s").await;
    let s_client = seed_service_client(&pool, s, "host writer s", &["claims:write"]).await;
    let state = app_role_state(&pool).await;

    // ── Allow S's client for H and arm; NO membership for S in HG ──
    let s_client_id = s_client.id;
    as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        sqlx::query("SELECT * FROM public.epigraph_allow_author_binding_client($1, $2, 'host')")
            .bind(s_client_id)
            .bind(h)
            .execute(&mut *conn)
            .await
            .expect("allow");
        sqlx::query("SELECT armed_now FROM public.epigraph_arm_operator_binding()")
            .execute(&mut *conn)
            .await
            .expect("arm");
        (conn, ())
    })
    .await;
    let memberships: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT group_id, role::text FROM group_memberships \
          WHERE agent_id = $1 AND revoked_at IS NULL",
    )
    .bind(s)
    .fetch_all(&pool)
    .await
    .expect("S's memberships");
    assert_eq!(
        memberships,
        vec![(s_group, "admin".to_string())],
        "PREMISE: S is only the admin of its own personal group, with nothing in HG"
    );
    let s_token = token(&pool, &s_client).await;

    // ── Calibration: the migrated schema alone refuses the same body ──
    assert!(
        legacy_privacy_policies(&pool).await.is_empty(),
        "PREMISE: no migration installs the legacy *_privacy policies"
    );
    let p1 = egress_packet(l, &format!("p1-{}.example.test", Uuid::new_v4().simple()));
    let (status, body) = post_packet(&state, &s_token, &p1).await;
    // The 500 body is redacted (F-route-error-text-remainder): row security's
    // refusal is read from the server log, and must not be in the body.
    assert!(
        !status.is_success()
            && !body
                .to_string()
                .contains("new row violates row-level security policy for table"),
        "CALIBRATION: the refusal is not passed to the caller: {status} {body}"
    );
    assert!(
        logs_contain("new row violates row-level security policy for table"),
        "CALIBRATION: without the legacy policies and without a membership the HG claim is \
         refused by row security: {status} {body}"
    );
    assert!(
        rows_with_content(&pool, &p1["claim"]["content"])
            .await
            .is_empty(),
        "CALIBRATION: nothing written"
    );

    // ── The legacy policies, with their deployed shape ──
    install_legacy_privacy_policies(&pool).await;
    let installed = legacy_privacy_policies(&pool).await;
    let shape = |table: &str, qual: &str| {
        (
            table.to_string(),
            "PERMISSIVE".to_string(),
            vec!["public".to_string()],
            "ALL".to_string(),
            qual.to_string(),
            None,
        )
    };
    assert_eq!(
        installed,
        vec![
            shape("claims", "epigraph_is_visible_to_group(id, 'claim'::text)"),
            shape(
                "edges",
                "(epigraph_is_visible_to_group(source_id, 'claim'::text) AND \
                 epigraph_is_visible_to_group(source_id, 'evidence'::text) AND \
                 epigraph_is_visible_to_group(target_id, 'claim'::text) AND \
                 epigraph_is_visible_to_group(target_id, 'evidence'::text))"
            ),
            shape(
                "evidence",
                "epigraph_is_visible_to_group(id, 'evidence'::text)"
            ),
        ],
        "PREMISE: the legacy policies as deployed: permissive, public, ALL, no WITH CHECK"
    );

    // ── Q1: the egress approval packet ──
    let (status, body) = post_packet(&state, &s_token, &p1).await;
    assert_eq!(status, StatusCode::CREATED, "Q1: {body}");
    assert_eq!(body["was_duplicate"], false, "Q1: {body}");
    assert!(body["trace_id"].is_string(), "Q1 has a trace: {body}");
    assert_eq!(
        body["evidence_ids"].as_array().map(Vec::len),
        Some(1),
        "Q1: {body}"
    );
    let rows = rows_with_content(&pool, &p1["claim"]["content"]).await;
    assert_eq!(rows.len(), 1, "Q1: one claim");
    let q1_id = rows[0].id;
    assert_eq!(body["claim_id"], q1_id.to_string());
    assert_eq!(
        (
            rows[0].agent_id,
            rows[0].owner_group_id,
            rows[0].labels.clone(),
            rows[0].properties.clone(),
            rows[0].visibility.as_str(),
            rows[0].trace_id.map(|t| t.to_string()),
        ),
        (
            l,
            hg,
            strings(&p1["claim"]["labels"]),
            Some(p1["claim"]["properties"].clone()),
            "public",
            body["trace_id"].as_str().map(str::to_string),
        ),
        "Q1: authored by L, owned by HG, labels and properties exactly as sent"
    );
    assert_eq!(
        dependents_writer_owned(&pool, q1_id).await,
        (vec![(s_group, true)], vec![(s_group, true)]),
        "Q1: its evidence and trace are writer-owned by S's personal group, NOT HG"
    );

    // ── Q2: the Foreman mirror packet ──
    let p2 = mirror_packet(l, &format!("wi-{}", Uuid::new_v4().simple()));
    let (status, body) = post_packet(&state, &s_token, &p2).await;
    assert_eq!(status, StatusCode::CREATED, "Q2: {body}");
    assert_eq!(body["was_duplicate"], false, "Q2: {body}");
    let rows = rows_with_content(&pool, &p2["claim"]["content"]).await;
    assert_eq!(rows.len(), 1, "Q2: one claim");
    assert_eq!(
        (
            rows[0].agent_id,
            rows[0].owner_group_id,
            rows[0].labels.clone(),
            rows[0].properties.clone(),
        ),
        (
            l,
            hg,
            strings(&p2["claim"]["labels"]),
            Some(p2["claim"]["properties"].clone())
        ),
        "Q2: authored by L, owned by HG, labels and properties exactly as sent"
    );
    assert_eq!(
        dependents_writer_owned(&pool, rows[0].id).await,
        (vec![(s_group, true)], vec![(s_group, true)]),
        "Q2: its evidence and trace are writer-owned by S's personal group, NOT HG"
    );
}
