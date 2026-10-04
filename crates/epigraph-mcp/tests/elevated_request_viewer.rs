//! The MCP server's per-request viewer under elevation (elevation plan EL-6).
//!
//! `tools::viewer::request_viewer`'s HTTP arm resolves an ELEVATED viewer when
//! the database answers for a live session: a token carrying an elevation
//! claim (`elv`) on its family, or (connector mode, MCP `sudo`) a token with
//! only a family, and the latter ONLY when the server's connector switch is on.
//! The switch is OFF by default (operator ruling, plan EQ-7 unruled). The stdio
//! arm never elevates.
//!
//! The server's `ScopedPool` is DOWNGRADED to `epigraph_app` (this crate's
//! suite otherwise runs as a BYPASSRLS superuser), so the liveness check runs
//! as the application role. Sessions are seeded through migration 125's
//! definers with synthetic evidence, as the database crate's tests do.
//!
//! Each test names the mutation it was run against ("Verified to fail").

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_auth::{AuthContext, ClientType};
use epigraph_db::{ScopedPool, SessionGucMode};
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools::viewer::request_viewer;
use sqlx::PgPool;
use uuid::Uuid;

/// Run `f` as `epigraph_app` with the principal stamped and no elevation.
async fn as_app<F, Fut, T>(pool: &PgPool, principal: Option<Uuid>, f: F) -> T
where
    F: FnOnce(sqlx::pool::PoolConnection<sqlx::Postgres>) -> Fut,
    Fut: std::future::Future<Output = (sqlx::pool::PoolConnection<sqlx::Postgres>, T)>,
{
    let principal = principal.map(|p| p.to_string()).unwrap_or_default();
    fixture::as_role(pool, "epigraph_app", |mut conn| async move {
        sqlx::query(
            "SELECT set_config('epigraph.principal_id', $1, false), \
                    set_config('epigraph.elevation_id', '', false), \
                    set_config('epigraph.family_id', '', false)",
        )
        .bind(&principal)
        .execute(&mut *conn)
        .await
        .expect("stamp");
        let (mut conn, out) = f(conn).await;
        sqlx::query("SELECT set_config('epigraph.principal_id', '', false)")
            .execute(&mut *conn)
            .await
            .expect("unstamp");
        (conn, out)
    })
    .await
}

/// A custodian with one live passkey and one live refresh family of its own
/// human client: `(client row id, family)`. `person` must already exist.
async fn make_holder(pool: &PgPool, person: Uuid, n: u8) -> (Uuid, Uuid) {
    fixture::make_custodian(pool, person).await;
    let client: Uuid = sqlx::query_scalar(
        "SELECT id FROM oauth_clients WHERE agent_id = $1 AND client_type = 'human' \
          ORDER BY created_at LIMIT 1",
    )
    .bind(person)
    .fetch_one(pool)
    .await
    .expect("the human's client");
    let e: Uuid = fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let e = sqlx::query_scalar(
            "SELECT public.epigraph_create_passkey_enrollment($1, 'mcp elevation test', 'key')",
        )
        .bind(person)
        .fetch_one(&mut *conn)
        .await
        .expect("enroll");
        (conn, e)
    })
    .await;
    let mut cred = vec![0xA5_u8; 16];
    cred[0] = n;
    as_app(pool, None, |mut conn| async move {
        sqlx::query(
            "SELECT public.epigraph_set_passkey_enrollment_challenge($1, '{\"rs\": 1}'::jsonb)",
        )
        .bind(e)
        .execute(&mut *conn)
        .await
        .expect("enrollment challenge");
        sqlx::query(
            "SELECT public.epigraph_complete_passkey_enrollment($1, $2, \
                    '{\"cred\": 1}'::jsonb, '00000000-0000-0000-0000-000000000000'::uuid, \
                    'none', true, false)",
        )
        .bind(e)
        .bind(cred)
        .execute(&mut *conn)
        .await
        .expect("complete the enrollment");
        (conn, ())
    })
    .await;
    let hash: Vec<u8> = [
        Uuid::new_v4().as_bytes().to_vec(),
        Uuid::new_v4().as_bytes().to_vec(),
    ]
    .concat();
    let family: Uuid = sqlx::query_scalar(
        "INSERT INTO refresh_tokens (token_hash, client_id, scopes, expires_at) \
         VALUES ($1, $2, ARRAY['claims:read'], now() + interval '1 day') RETURNING id",
    )
    .bind(&hash)
    .bind(client)
    .fetch_one(pool)
    .await
    .expect("a refresh token");
    (client, family)
}

/// A confirmed session for `person` on (`client`, `family`) in `mode`.
async fn session(
    pool: &PgPool,
    person: Uuid,
    client: Uuid,
    family: Uuid,
    n: u8,
    mode: &str,
) -> Uuid {
    let mode_s = mode.to_string();
    let secret: Option<Vec<u8>> = (mode == "grant").then(|| b"an mcp elevation secret".to_vec());
    let ticket: Uuid = as_app(pool, Some(person), |mut conn| async move {
        let t = sqlx::query_scalar(
            "SELECT public.epigraph_create_elevation_ticket($1, $2, $3, 'mcp elevation test', \
                    CASE WHEN $4::bytea IS NULL THEN NULL ELSE sha256($4::bytea) END)",
        )
        .bind(client)
        .bind(family)
        .bind(&mode_s)
        .bind(secret)
        .fetch_one(&mut *conn)
        .await
        .expect("a ticket");
        (conn, t)
    })
    .await;
    let mut cred = vec![0xA5_u8; 16];
    cred[0] = n;
    as_app(pool, None, |mut conn| async move {
        sqlx::query(
            "SELECT public.epigraph_set_elevation_ticket_challenge($1, '{\"st\": 1}'::jsonb)",
        )
        .bind(ticket)
        .execute(&mut *conn)
        .await
        .expect("the ceremony's challenge");
        let (outcome, session): (String, Option<Uuid>) = sqlx::query_as(
            "SELECT outcome, session_id \
               FROM public.epigraph_confirm_elevation($1, $2, 0, false, '{\"ev\": 1}'::jsonb)",
        )
        .bind(ticket)
        .bind(cred)
        .fetch_one(&mut *conn)
        .await
        .expect("confirm");
        assert_eq!(outcome, "confirmed", "CALIBRATION: the ceremony confirms");
        (conn, session.expect("a session"))
    })
    .await
}

/// A server whose `ScopedPool` is the application role.
async fn app_server(pool: &PgPool) -> EpiGraphMcpFull {
    let scoped = ScopedPool::connect_downgraded_for_tests(
        &fixture::database_url_for(pool).await,
        SessionGucMode::Session,
        "epigraph_app",
    )
    .await
    .expect("app-role ScopedPool");
    build_scoped_test_server(pool.clone(), scoped)
}

fn http_auth(person: Uuid, client: Uuid, family: Uuid, elv: Option<Uuid>) -> AuthContext {
    AuthContext {
        client_id: client,
        agent_id: Some(person),
        owner_id: None,
        client_type: ClientType::Human,
        scopes: vec!["claims:read".to_string()],
        jti: Uuid::new_v4(),
        family_id: Some(family),
        elevation_claim: elv,
    }
}

/// A token carrying a live grant-mode session's claim on its family resolves
/// ELEVATED over HTTP, carrying that session; a forged claim, and the same
/// token with no claim (connector switch off), resolve scoped.
///
/// Verified to fail with the HTTP arm ignoring the claim (always
/// `Viewer::resolve`).
#[sqlx::test(migrations = "../../migrations")]
async fn an_elevation_claim_resolves_elevated_over_http(pool: PgPool) {
    let (p, _) = fixture::seed_human_operator(&pool, "mcp-elv-p").await;
    let (client, family) = make_holder(&pool, p, 1).await;
    let live = session(&pool, p, client, family, 1, "grant").await;
    let server = app_server(&pool).await;

    let v = request_viewer(&server, Some(&http_auth(p, client, family, Some(live))))
        .await
        .expect("viewer");
    assert!(v.is_elevated(), "the live claim elevates");
    assert_eq!(v.elevation().map(|e| e.session_id), Some(live));

    for (what, elv) in [("a forged claim", Some(Uuid::new_v4())), ("no claim", None)] {
        let v = request_viewer(&server, Some(&http_auth(p, client, family, elv)))
            .await
            .expect("viewer");
        assert!(!v.is_elevated(), "{what}: resolved elevated");
        assert_ne!(v.predicate_fragment(), " ", "{what}");
    }
}

/// Connector mode (a session found by the token's FAMILY alone) is OFF by
/// default: the server as built resolves scoped. The same server with the
/// switch on resolves elevated (calibration: the session is live and the pool
/// can see it, so the default-off answer is the switch's).
///
/// Verified to fail with the switch defaulting on (the default server
/// elevates), and with the switch's guard dropped from the connector arm.
#[sqlx::test(migrations = "../../migrations")]
async fn connector_mode_is_off_unless_switched_on(pool: PgPool) {
    let (p, _) = fixture::seed_human_operator(&pool, "mcp-conn-p").await;
    let (client, family) = make_holder(&pool, p, 2).await;
    let live = session(&pool, p, client, family, 2, "connector").await;
    let server = app_server(&pool).await;
    let auth = http_auth(p, client, family, None);

    let v = request_viewer(&server, Some(&auth)).await.expect("viewer");
    assert!(
        !v.is_elevated(),
        "connector-mode elevation must be OFF by default (operator ruling, EQ-7)"
    );

    let on = server.clone().with_connector_elevation(true);
    let v = request_viewer(&on, Some(&auth)).await.expect("viewer");
    let e = *v
        .elevation()
        .expect("CALIBRATION: with the switch on, the live connector session elevates");
    assert_eq!((e.session_id, e.connector), (live, true));
}

/// stdio NEVER elevates: the server's own principal holds a live connector
/// session on its family, the switch is ON, and the stdio arm (no
/// `AuthContext`) still resolves scoped. Calibration: the HTTP arm for the same
/// principal and family elevates on the same server.
///
/// A regression pin rather than a mutation target: stdio carries no family,
/// so no one-line change to the current arm elevates it; what this pins is
/// that the server's principal, fully able to elevate over HTTP, still does
/// not over stdio.
#[sqlx::test(migrations = "../../migrations")]
async fn stdio_never_elevates(pool: PgPool) {
    let server = app_server(&pool).await.with_connector_elevation(true);
    let me = server.server_agent_id().await.expect("server agent");
    let (client, family) = make_holder(&pool, me, 3).await;
    let live = session(&pool, me, client, family, 3, "connector").await;

    let http = request_viewer(&server, Some(&http_auth(me, client, family, None)))
        .await
        .expect("viewer");
    assert_eq!(
        http.elevation().map(|e| e.session_id),
        Some(live),
        "CALIBRATION: the HTTP arm elevates this principal on this family"
    );

    let stdio = request_viewer(&server, None).await.expect("stdio viewer");
    assert_eq!(
        stdio.principal(),
        Some(me),
        "CALIBRATION: the same principal"
    );
    assert!(!stdio.is_elevated(), "stdio must never resolve elevated");
}
