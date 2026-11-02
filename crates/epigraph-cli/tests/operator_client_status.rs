//! `epigraph-operator suspend-client` / `revoke-client` (backlog 0454cbcd),
//! driven through the real binary against a `#[sqlx::test]` database
//! migrated 001 -> head, as a real NOSUPERUSER maintenance login, and checked
//! against the real `/oauth/token` endpoint.
//!
//! What is pinned: the dry run changes nothing and records nothing; `--apply`
//! sets the status, revokes EVERY live refresh chain of the client (reason
//! `client`) and writes one `oauth.client_suspended` / `oauth.client_revoked`
//! audit row naming the login, the reason, the transition and the chain
//! count, in one transaction; afterwards the token endpoint refuses the
//! client's `client_credentials` grant and every refresh token it held; a
//! repeat is reported and writes nothing; a suspended client can be revoked,
//! a revoked one is never suspended (revoke is final); a blank reason and an
//! unknown client are refused with nothing written. Suspending the recorded
//! client of a registered human operator says so, and un-registers the human.

mod viewer_fixture;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use http_body_util::BodyExt;
use sqlx::PgPool;
use std::process::Command;
use tower::ServiceExt;
use uuid::Uuid;
use viewer_fixture as fixture;

const BIN: &str = env!("CARGO_BIN_EXE_epigraph-operator");
const DSN_ENV: &str = "EPIGRAPH_OPERATOR_MAINTENANCE_DSN";

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Run {
    fn show(&self) -> String {
        format!(
            "exit={}\n--- stdout\n{}\n--- stderr\n{}",
            self.code, self.stdout, self.stderr
        )
    }
}

fn run_dsn(args: &[&str], dsn: &str) -> Run {
    let out = Command::new(BIN)
        .args(args)
        .env("RUST_LOG", "warn")
        .env_remove("DATABASE_URL")
        .env_remove("MAINTENANCE_DATABASE_URL")
        .env(DSN_ENV, dsn)
        .output()
        .expect("spawn epigraph-operator");
    Run {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// A fresh NOSUPERUSER login in `epigraph_maintenance`: `(role, dsn)`.
async fn maintenance_login(pool: &PgPool) -> (String, String) {
    let url = fixture::database_url_for(pool).await;
    let role = format!("client_status_maint_{}", Uuid::new_v4().simple());
    sqlx::query(&format!(
        "CREATE ROLE {role} LOGIN PASSWORD 'probe-only' NOSUPERUSER IN ROLE epigraph_maintenance"
    ))
    .execute(pool)
    .await
    .expect("create role");
    let (scheme, rest) = url.split_once("://").expect("scheme");
    let (_, host) = rest.split_once('@').expect("credentials");
    (role.clone(), format!("{scheme}://{role}:probe-only@{host}"))
}

async fn drop_role(pool: &PgPool, role: &str) {
    sqlx::query(&format!("DROP ROLE {role}"))
        .execute(pool)
        .await
        .expect("drop role");
}

/// A service client with a known secret (`identity_provisioning.rs`'s shape):
/// `(oauth_clients.id, client_id, secret)`.
async fn service_client(pool: &PgPool) -> (Uuid, String, String) {
    let (agent, _) = fixture::seed_agent_with_group(pool, "service-principal").await;
    let secret_bytes: [u8; 32] = *blake3::hash(agent.as_bytes()).as_bytes();
    let secret = hex::encode(secret_bytes);
    let client_id = format!("epigraph_{}", hex::encode(&secret_bytes[..16]));
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO oauth_clients (client_id, client_secret_hash, client_name, client_type, \
                                    allowed_scopes, granted_scopes, status, agent_id, \
                                    legal_entity_name, legal_contact_email) \
         VALUES ($1, $2, 'status test service', 'service', ARRAY['claims:read'], \
                 ARRAY['claims:read'], 'active', $3, 'Fixture Org', \
                 'fixture@example.invalid') RETURNING id",
    )
    .bind(&client_id)
    .bind(blake3::hash(&secret_bytes).as_bytes().as_slice())
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("the service client");
    (id, client_id, secret)
}

/// `POST /oauth/token` with `body`: `(status, body)`.
async fn token(pool: &PgPool, body: serde_json::Value) -> (StatusCode, serde_json::Value) {
    let app = epigraph_api::create_router(epigraph_api::AppState::with_db(
        pool.clone(),
        epigraph_api::ApiConfig::default(),
    ));
    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/oauth/token")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .expect("request"),
        )
        .await
        .expect("response");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    let json = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| serde_json::json!({ "raw": String::from_utf8_lossy(&bytes) }));
    (status, json)
}

fn client_credentials(client_id: &str, secret: &str) -> serde_json::Value {
    serde_json::json!({
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": secret,
    })
}

/// `(status, live refresh chains, chains revoked for reason 'client', audit rows)`.
async fn state(pool: &PgPool, id: Uuid) -> (String, i64, i64, i64) {
    sqlx::query_as(
        "SELECT (SELECT status::text FROM oauth_clients WHERE id = $1), \
                (SELECT count(*) FROM refresh_tokens \
                  WHERE client_id = $1 AND revoked_at IS NULL), \
                (SELECT count(*) FROM refresh_tokens \
                  WHERE client_id = $1 AND revoked_reason = 'client'), \
                (SELECT count(*) FROM security_events \
                  WHERE event_type IN ('oauth.client_suspended', 'oauth.client_revoked') \
                    AND details -> 'client' ->> 'id' = $1::text)",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .expect("state")
}

async fn audit(pool: &PgPool, id: Uuid) -> Vec<(String, serde_json::Value)> {
    sqlx::query_as(
        "SELECT event_type, details FROM security_events \
          WHERE event_type IN ('oauth.client_suspended', 'oauth.client_revoked') \
            AND details -> 'client' ->> 'id' = $1::text \
          ORDER BY created_at, id",
    )
    .bind(id)
    .fetch_all(pool)
    .await
    .expect("audit rows")
}

/// `<verb> --client <id> --reason <reason> <extra..>`.
fn verb(verb: &str, client: &str, reason: &str, extra: &[&str]) -> Vec<String> {
    let mut v: Vec<String> = [verb, "--client", client, "--reason", reason]
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    v.extend(extra.iter().map(|s| (*s).to_string()));
    v
}

fn as_args(v: &[String]) -> Vec<&str> {
    v.iter().map(String::as_str).collect()
}

/// The containment act, end to end, on a service client holding two refresh
/// chains.
///
/// Verified to fail: the dry run committing -> its "nothing changed"
/// assertion fails; `epigraph_refresh_token_revoke_client` not called -> the
/// chains stay live and the refresh token still works; the
/// revoked -> suspended refusal removed -> a revoked client is suspended.
#[sqlx::test(migrations = "../../migrations")]
async fn suspend_then_revoke_contains_a_service_client(pool: PgPool) {
    let (id, client_id, secret) = service_client(&pool).await;
    let (ok1, first) = token(&pool, client_credentials(&client_id, &secret)).await;
    let (ok2, _) = token(&pool, client_credentials(&client_id, &secret)).await;
    assert_eq!(
        (ok1, ok2),
        (StatusCode::OK, StatusCode::OK),
        "CALIBRATION: {first}"
    );
    let refresh = first["refresh_token"]
        .as_str()
        .unwrap_or_else(|| panic!("a refresh token: {first}"))
        .to_string();
    assert_eq!(
        state(&pool, id).await,
        ("active".to_string(), 2, 0, 0),
        "PREMISE: two live chains, unaudited"
    );

    let (role, dsn) = maintenance_login(&pool).await;
    let c = id.to_string();
    let suspend = |extra: &[&str]| verb("suspend-client", &c, "leaked secret", extra);
    let revoke = |extra: &[&str]| verb("revoke-client", &c, "rotated out", extra);

    let blank = run_dsn(
        &[
            "suspend-client",
            "--client",
            c.as_str(),
            "--reason",
            "  ",
            "--apply",
        ],
        &dsn,
    );
    let blank_state = state(&pool, id).await;
    let dry = run_dsn(&as_args(&suspend(&[])), &dsn);
    let dry_state = state(&pool, id).await;
    let applied = run_dsn(&as_args(&suspend(&["--apply"])), &dsn);
    let applied_state = state(&pool, id).await;
    let (cc_status, cc_body) = token(&pool, client_credentials(&client_id, &secret)).await;
    let (rt_status, rt_body) = token(
        &pool,
        serde_json::json!({ "grant_type": "refresh_token", "refresh_token": refresh }),
    )
    .await;
    let again = run_dsn(&as_args(&suspend(&["--apply"])), &dsn);
    let again_state = state(&pool, id).await;
    let revoked = run_dsn(&as_args(&revoke(&["--apply"])), &dsn);
    let revoked_state = state(&pool, id).await;
    let back = run_dsn(&as_args(&suspend(&["--apply"])), &dsn);
    let back_state = state(&pool, id).await;
    let revoked_again = run_dsn(&as_args(&revoke(&["--apply"])), &dsn);
    let unknown_id = Uuid::new_v4().to_string();
    let unknown = run_dsn(
        &[
            "revoke-client",
            "--client",
            unknown_id.as_str(),
            "--reason",
            "x",
            "--apply",
        ],
        &dsn,
    );
    let rows = audit(&pool, id).await;
    drop_role(&pool, &role).await;

    assert_ne!(blank.code, 0, "a blank reason is refused: {}", blank.show());
    assert_eq!(blank_state, ("active".to_string(), 2, 0, 0));

    assert_eq!(dry.code, 0, "{}", dry.show());
    assert!(dry.stdout.contains("WOULD BE SUSPENDED"), "{}", dry.show());
    assert!(
        dry.stdout.contains("refresh_chains_revoked=2"),
        "{}",
        dry.show()
    );
    assert_eq!(
        dry_state,
        ("active".to_string(), 2, 0, 0),
        "a dry run changes nothing"
    );

    assert_eq!(applied.code, 0, "{}", applied.show());
    assert!(
        applied.stdout.starts_with("SUSPENDED\t"),
        "{}",
        applied.show()
    );
    assert!(
        applied
            .stdout
            .contains("access tokens already minted stay valid until they expire"),
        "the access-token window is stated: {}",
        applied.show()
    );
    assert_eq!(applied_state, ("suspended".to_string(), 0, 2, 1));
    // `get_by_client_id` reads only an ACTIVE client, so a suspended one is
    // refused as unknown (401), the same answer as a client that never existed.
    assert_eq!(cc_status, StatusCode::UNAUTHORIZED, "{cc_body}");
    assert!(
        cc_body.to_string().contains("Unknown client_id"),
        "{cc_body}"
    );
    assert_ne!(
        rt_status,
        StatusCode::OK,
        "the held refresh token is dead: {rt_body}"
    );

    assert_eq!(again.code, 0, "a repeat is idempotent: {}", again.show());
    assert!(
        again.stdout.starts_with("ALREADY-SUSPENDED\t"),
        "{}",
        again.show()
    );
    assert_eq!(again_state, applied_state, "a repeat writes nothing");

    assert_eq!(revoked.code, 0, "{}", revoked.show());
    assert!(
        revoked.stdout.starts_with("REVOKED\t"),
        "{}",
        revoked.show()
    );
    assert_eq!(revoked_state, ("revoked".to_string(), 0, 2, 2));

    assert_eq!(back.code, 1, "revoke is final: {}", back.show());
    assert!(back.stderr.contains("revoked"), "{}", back.show());
    assert_eq!(back_state, revoked_state, "the refusal writes nothing");

    assert_eq!(revoked_again.code, 0, "{}", revoked_again.show());
    assert!(
        revoked_again.stdout.starts_with("ALREADY-REVOKED\t"),
        "{}",
        revoked_again.show()
    );
    assert_eq!(unknown.code, 1, "{}", unknown.show());

    assert_eq!(rows.len(), 2, "{rows:?}");
    let (kind, d) = &rows[0];
    assert_eq!(kind, "oauth.client_suspended");
    assert_eq!(d["reason"], serde_json::json!("leaked secret"));
    assert_eq!(d["status"]["before"], serde_json::json!("active"));
    assert_eq!(d["status"]["after"], serde_json::json!("suspended"));
    assert_eq!(d["refresh_chains_revoked"], serde_json::json!(2));
    assert_eq!(d["operator"]["session_user"], serde_json::json!(role));
    let (kind, d) = &rows[1];
    assert_eq!(kind, "oauth.client_revoked");
    assert_eq!(d["status"]["before"], serde_json::json!("suspended"));
    assert_eq!(d["status"]["after"], serde_json::json!("revoked"));
    assert_eq!(d["refresh_chains_revoked"], serde_json::json!(0));
}

/// Suspending the ONE client a human-operator registration names
/// un-registers that human (122: `epigraph_is_human_operator` reads that
/// client's status), so the command says so in the dry run, and the apply
/// does exactly that.
///
/// Verified to fail: the human-operator lookup removed -> no HUMAN-OPERATOR
/// line in the dry run.
#[sqlx::test(migrations = "../../migrations")]
async fn suspending_a_humans_recorded_client_says_it_unregisters_the_human(pool: PgPool) {
    let (person, _) = fixture::seed_human_operator(&pool, "status-human").await;
    let client: Uuid = sqlx::query_scalar(
        "SELECT id FROM oauth_clients WHERE agent_id = $1 AND client_type = 'human'",
    )
    .bind(person)
    .fetch_one(&pool)
    .await
    .expect("the human's client");
    let human = |pool: PgPool| async move {
        sqlx::query_scalar::<_, bool>("SELECT public.epigraph_is_human_operator($1)")
            .bind(person)
            .fetch_one(&pool)
            .await
            .expect("human read")
    };
    assert!(human(pool.clone()).await, "PREMISE: a registered human");

    let (role, dsn) = maintenance_login(&pool).await;
    let c = client.to_string();
    let args = [
        "suspend-client",
        "--client",
        c.as_str(),
        "--reason",
        "lost device",
    ];
    let dry = run_dsn(&args, &dsn);
    let dry_human = human(pool.clone()).await;
    let mut apply_args = args.to_vec();
    apply_args.push("--apply");
    let applied = run_dsn(&apply_args, &dsn);
    let applied_human = human(pool.clone()).await;
    drop_role(&pool, &role).await;

    assert_eq!(dry.code, 0, "{}", dry.show());
    assert!(
        dry.stdout.contains(&format!("HUMAN-OPERATOR\t{person}")),
        "{}",
        dry.show()
    );
    assert!(dry_human, "a dry run un-registers nobody");
    assert_eq!(applied.code, 0, "{}", applied.show());
    assert!(!applied_human, "the human is no longer registered");
}
