//! `epigraph-operator sweep-dcr-clients` / `list-dcr-clients` (backlog
//! d3cdd376), driven through the real binary against a `#[sqlx::test]`
//! database migrated 001 → head.
//!
//! What is pinned: only an ACTIVE, dynamically registered (`epigraph_…`,
//! public, agent-less, with a redirect URI) client that is older than the floor
//! and never had an authorization code minted under it is revoked. Every
//! look-alike survives: a DCR client with a (used) code, a young DCR client,
//! the provisioned per-user client (`google:<sub>`, no redirect URIs, no code
//! under its own `client_id`), a legacy secret-holding `epigraph_…` client, a
//! DCR-shaped client with a principal, and one look-alike per remaining clause
//! of the shape: an `epigraph_…` client with an empty and one with a NULL
//! `redirect_uris`, a `google:<sub>` client WITH a redirect URI (only the prefix
//! clause excludes it), and an `epigraphX…` client with a redirect URI (only
//! the literal `_` in the prefix excludes it: `LIKE 'epigraph_%'` would match). One audit row per revoked client; a dry
//! run and the census write nothing; the revoked client id is then refused by
//! `/oauth/authorize` (after a control showing it was accepted before); and the
//! apply runs as a real NOSUPERUSER maintenance login.

mod viewer_fixture;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use sqlx::PgPool;
use std::process::Command;
use tower::ServiceExt;
use uuid::Uuid;
use viewer_fixture as fixture;

const BIN: &str = env!("CARGO_BIN_EXE_epigraph-operator");
const DSN_ENV: &str = "EPIGRAPH_OPERATOR_MAINTENANCE_DSN";
const REDIRECT: &str = "https://claude.ai/api/mcp/auth_callback";
const EVENT: &str = "oauth.dcr_client_swept";

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

/// One `oauth_clients` row, `age_hours` old.
#[allow(clippy::too_many_arguments)]
async fn seed(
    pool: &PgPool,
    client_id: &str,
    secret: Option<&[u8]>,
    redirect_uris: Option<Vec<String>>,
    agent: Option<Uuid>,
    age_hours: i32,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO oauth_clients (id, client_id, client_secret_hash, client_name, client_type, \
                                    redirect_uris, allowed_scopes, granted_scopes, status, \
                                    agent_id, created_at) \
         VALUES ($1, $2, $3, 'Claude', 'human', $4, '{claims:read}', '{claims:read}', 'active', \
                 $5, now() - make_interval(hours => $6))",
    )
    .bind(id)
    .bind(client_id)
    .bind(secret)
    .bind(redirect_uris)
    .bind(agent)
    .bind(age_hours)
    .execute(pool)
    .await
    .expect("seed client");
    id
}

fn dcr_id() -> String {
    format!("epigraph_{}", Uuid::new_v4().simple())
}

fn redirects() -> Option<Vec<String>> {
    Some(vec![REDIRECT.to_string()])
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

/// A redeemed authorization code minted under `client_id` (the DCR id the flow
/// ran under) for the per-user client `per_user`.
async fn seed_used_code(pool: &PgPool, client_id: &str, per_user: Uuid) {
    sqlx::query(
        "INSERT INTO oauth_authorization_codes (code_hash, client_id, oauth_client_id, \
                                                redirect_uri, code_challenge, scopes, \
                                                expires_at, used_at, created_at) \
         VALUES ($1, $2, $3, $4, 'challenge', '{claims:read}', now() - interval '47 hours', \
                 now() - interval '47 hours', now() - interval '47 hours')",
    )
    .bind(Uuid::new_v4().as_bytes().to_vec())
    .bind(client_id)
    .bind(per_user)
    .bind(REDIRECT)
    .execute(pool)
    .await
    .expect("seed code");
}

async fn status(pool: &PgPool, id: Uuid) -> String {
    sqlx::query_scalar("SELECT status::text FROM oauth_clients WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("status")
}

/// Every sweep audit row: `(client.id, details)`.
async fn audit(pool: &PgPool) -> Vec<(String, serde_json::Value)> {
    sqlx::query_as(
        "SELECT details->'client'->>'id', details FROM security_events \
          WHERE event_type = $1 ORDER BY created_at, id",
    )
    .bind(EVENT)
    .fetch_all(pool)
    .await
    .expect("audit rows")
}

/// `GET /oauth/authorize` for `client_id`, fully valid apart from the client:
/// `(status, body)`.
async fn authorize(pool: &PgPool, client_id: &str) -> (StatusCode, String) {
    let state = epigraph_api::AppState::with_db(
        pool.clone(),
        epigraph_api::ApiConfig {
            require_packet_signatures: false,
            max_request_size: 1024 * 1024,
            public_base_url: "https://test.example".to_string(),
            allow_all_identities: true,
        },
    );
    let app = epigraph_api::create_router(state);
    let query = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("response_type", "code"),
            ("client_id", client_id),
            ("redirect_uri", REDIRECT),
            (
                "code_challenge",
                "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            ),
            ("code_challenge_method", "S256"),
            ("state", "s"),
        ])
        .finish();
    let req = Request::builder()
        .uri(format!("/oauth/authorize?{query}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

struct Fixture {
    /// 48 h old DCR client, no code: the ONLY row a sweep may take.
    doomed: (Uuid, String),
    /// Every row that must stay active, with a label.
    survivors: Vec<(Uuid, &'static str)>,
    /// 48 h old DCR client whose code was minted and redeemed.
    used: (Uuid, String),
    /// `client_id`s that are not DCR-shaped, so the census must not list them.
    not_dcr: Vec<(String, &'static str)>,
}

async fn seed_fixture(pool: &PgPool) -> Fixture {
    let doomed_cid = dcr_id();
    let doomed = seed(pool, &doomed_cid, None, redirects(), None, 48).await;

    // The per-user client a Google login provisions: no redirect URIs, no
    // principal yet, public, and no code under its OWN client_id (codes carry
    // the DCR id). Old. It must never be swept.
    let per_user = seed(
        pool,
        &format!("google:{}", Uuid::new_v4().simple()),
        None,
        None,
        None,
        48,
    )
    .await;

    let used_cid = dcr_id();
    let used = seed(pool, &used_cid, None, redirects(), None, 48).await;
    seed_used_code(pool, &used_cid, per_user).await;

    let young = seed(pool, &dcr_id(), None, redirects(), None, 1).await;
    // A legacy `/oauth/register` human client (client_type given): it holds a
    // secret. Forced active for the test (registration makes it pending).
    let legacy_cid = dcr_id();
    let legacy = seed(pool, &legacy_cid, Some(&[7u8; 32]), redirects(), None, 48).await;
    let agent = seed_agent(pool).await;
    let with_principal_cid = dcr_id();
    let with_principal = seed(
        pool,
        &with_principal_cid,
        None,
        redirects(),
        Some(agent),
        48,
    )
    .await;

    // One look-alike per clause that nothing above isolates. Each is old,
    // public, agent-less, active and has no code: exactly one clause of the
    // shape excludes it.
    // `cardinality(redirect_uris) > 0`: an empty array, and NULL.
    let no_redirect_cid = dcr_id();
    let no_redirect = seed(pool, &no_redirect_cid, None, Some(vec![]), None, 48).await;
    let null_redirect_cid = dcr_id();
    let null_redirect = seed(pool, &null_redirect_cid, None, None, None, 48).await;
    // `left(client_id, 9) = 'epigraph_'`: a provider id with a redirect URI.
    let provider_cid = format!("google:{}", Uuid::new_v4().simple());
    let provider = seed(pool, &provider_cid, None, redirects(), None, 48).await;
    // The `_` is a literal: `LIKE 'epigraph_%'` would take this one.
    let near_cid = format!("epigraphX{}", Uuid::new_v4().simple());
    let near = seed(pool, &near_cid, None, redirects(), None, 48).await;

    Fixture {
        doomed: (doomed, doomed_cid),
        survivors: vec![
            (per_user, "per-user provisioned client"),
            (used, "DCR client with a redeemed code"),
            (young, "DCR client younger than the floor"),
            (legacy, "legacy client with a secret"),
            (with_principal, "DCR-shaped client with a principal"),
            (no_redirect, "epigraph_ client with an empty redirect_uris"),
            (null_redirect, "epigraph_ client with a NULL redirect_uris"),
            (provider, "provider client id with a redirect URI"),
            (near, "epigraphX client id (the `_` is literal)"),
        ],
        used: (used, used_cid),
        not_dcr: vec![
            (legacy_cid, "legacy client with a secret"),
            (with_principal_cid, "DCR-shaped client with a principal"),
            (
                no_redirect_cid,
                "epigraph_ client with an empty redirect_uris",
            ),
            (
                null_redirect_cid,
                "epigraph_ client with a NULL redirect_uris",
            ),
            (provider_cid, "provider client id with a redirect URI"),
            (near_cid, "epigraphX client id"),
        ],
    }
}

/// The sweep, end to end, as a real NOSUPERUSER maintenance login: the dry run
/// writes nothing; `--apply` revokes exactly the unused old DCR client with one
/// audit row naming that login; a second `--apply` finds nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn the_sweep_revokes_only_old_dcr_clients_that_never_authorized(pool: PgPool) {
    let fx = seed_fixture(&pool).await;
    let (doomed, doomed_cid) = fx.doomed.clone();

    let url = fixture::database_url_for(&pool).await;
    let role = format!("dcr_maint_{}", Uuid::new_v4().simple());
    sqlx::query(&format!(
        "CREATE ROLE {role} LOGIN PASSWORD 'probe-only' NOSUPERUSER IN ROLE epigraph_maintenance"
    ))
    .execute(&pool)
    .await
    .expect("create role");
    let (scheme, rest) = url.split_once("://").expect("scheme");
    let (_, host) = rest.split_once('@').expect("credentials");
    let dsn = format!("{scheme}://{role}:probe-only@{host}");

    let dry = run_dsn(&["sweep-dcr-clients"], &dsn);
    let dry_status = status(&pool, doomed).await;
    let dry_audit = audit(&pool).await.len();
    let apply = run_dsn(
        &["sweep-dcr-clients", "--apply", "--reason", "dcr sweep test"],
        &dsn,
    );
    let again = run_dsn(&["sweep-dcr-clients", "--apply"], &dsn);
    let rolsuper: bool = sqlx::query_scalar("SELECT rolsuper FROM pg_roles WHERE rolname = $1")
        .bind(&role)
        .fetch_one(&pool)
        .await
        .expect("role row");
    // Drop the cluster-global role BEFORE asserting, so a failure cannot leak it.
    sqlx::query(&format!("DROP ROLE {role}"))
        .execute(&pool)
        .await
        .expect("drop role");
    assert!(!rolsuper, "fixture: the login is not a superuser");

    // Dry run: names the doomed client, changes nothing, records nothing.
    assert_eq!(dry.code, 0, "{}", dry.show());
    assert!(dry.stdout.contains(&doomed_cid), "{}", dry.show());
    assert!(dry.stdout.contains("would revoke 1 "), "{}", dry.show());
    assert_eq!(dry_status, "active", "a dry run changes no status");
    assert_eq!(dry_audit, 0, "a dry run's audit rows are rolled back");

    // Apply: exactly the doomed client.
    assert_eq!(apply.code, 0, "{}", apply.show());
    assert!(apply.stdout.contains("revoked 1 "), "{}", apply.show());
    assert_eq!(status(&pool, doomed).await, "revoked");
    for (id, what) in &fx.survivors {
        assert_eq!(status(&pool, *id).await, "active", "{what} must survive");
    }
    let rows = audit(&pool).await;
    assert_eq!(rows.len(), 1, "one audit row per swept client: {rows:?}");
    assert_eq!(rows[0].0, doomed.to_string());
    assert_eq!(rows[0].1["operator"]["session_user"], role.as_str());
    assert_eq!(rows[0].1["client"]["client_id"], doomed_cid.as_str());
    assert_eq!(rows[0].1["reason"], "dcr sweep test");

    // Idempotent: nothing left to take.
    assert_eq!(again.code, 0, "{}", again.show());
    assert!(again.stdout.contains("revoked 0 "), "{}", again.show());
    assert_eq!(audit(&pool).await.len(), 1);
}

/// After the sweep, `/oauth/authorize` refuses the swept client id. The
/// control shows the same request got past the client lookup before: it fails
/// later, at the (deliberately unconfigured) provider step, with a 500, where
/// every client, redirect-URI and PKCE refusal is a 400. So the
/// `invalid_client` afterwards is the sweep's.
#[sqlx::test(migrations = "../../migrations")]
async fn a_swept_client_is_refused_by_authorize(pool: PgPool) {
    let fx = seed_fixture(&pool).await;
    let (_, doomed_cid) = fx.doomed.clone();
    let url = fixture::database_url_for(&pool).await;

    let (before, body) = authorize(&pool, &doomed_cid).await;
    assert_past_client_lookup(before, &body, "control: the client before the sweep");

    let r = run_dsn(&["sweep-dcr-clients", "--apply"], &url);
    assert_eq!(r.code, 0, "{}", r.show());

    let (after, body) = authorize(&pool, &doomed_cid).await;
    assert_eq!(after, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.contains("invalid_client"), "{body}");

    // A client that did authorize is still accepted.
    let (kept, body) = authorize(&pool, &fx.used.1).await;
    assert_past_client_lookup(kept, &body, "a used DCR client after the sweep");
}

/// `/oauth/authorize` accepted the client and failed only at the (deliberately
/// unconfigured) Google provider, the step after every client check. That
/// step's "google provider not configured" is an `InternalError`, whose body
/// carries only [`epigraph_api::errors::INTERNAL_ERROR_BODY`] (the detail goes
/// to the server log), so the oracle is a redacted 500 that is not a client
/// refusal; the client checks answer 400 (`invalid_client`, `invalid_request`).
fn assert_past_client_lookup(status: StatusCode, body: &str, what: &str) {
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "{what}: expected the provider step's 500, got {status}: {body}"
    );
    assert!(
        body.contains(epigraph_api::errors::INTERNAL_ERROR_BODY)
            && !body.contains("invalid_client")
            && !body.contains("invalid_request"),
        "{what}: the 500 must be the provider step's redacted internal error: {body}"
    );
}

/// `list-dcr-clients` is read-only and marks exactly the doomed client
/// sweepable; the used one shows its code; the per-user client, the legacy and
/// with-principal clients and every look-alike are not DCR clients and are not
/// listed. A floor below one hour is refused before
/// any connection.
#[sqlx::test(migrations = "../../migrations")]
async fn the_census_lists_dcr_clients_and_writes_nothing(pool: PgPool) {
    let fx = seed_fixture(&pool).await;
    let (doomed, doomed_cid) = fx.doomed.clone();
    let url = fixture::database_url_for(&pool).await;

    let r = run_dsn(&["list-dcr-clients"], &url);
    assert_eq!(r.code, 0, "{}", r.show());
    let line = |cid: &str| {
        r.stdout
            .lines()
            .find(|l| l.contains(cid))
            .unwrap_or_else(|| panic!("{cid} not listed: {}", r.show()))
            .to_string()
    };
    assert!(line(&doomed_cid).contains("sweepable=true"), "{}", r.show());
    let used = line(&fx.used.1);
    assert!(used.contains("codes=1"), "{used}");
    assert!(used.contains("sweepable=false"), "{used}");
    assert_eq!(
        r.stdout.matches("sweepable=true").count(),
        1,
        "only the doomed client: {}",
        r.show()
    );
    assert!(!r.stdout.contains("google:"), "{}", r.show());
    for (cid, what) in &fx.not_dcr {
        assert!(
            !r.stdout.contains(cid.as_str()),
            "{what} is not a DCR client and is not listed: {}",
            r.show()
        );
    }
    assert_eq!(
        status(&pool, doomed).await,
        "active",
        "the census writes nothing"
    );
    assert!(audit(&pool).await.is_empty());

    let r = run_dsn(
        &["sweep-dcr-clients", "--older-than-hours", "0", "--apply"],
        &url,
    );
    assert_eq!(r.code, 1, "{}", r.show());
    assert!(r.stderr.contains("at least 1"), "{}", r.show());
    assert_eq!(status(&pool, doomed).await, "active");
}
