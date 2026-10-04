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

// =====================================================================
// EL-7: an elevated request's reads through the tool path
// =====================================================================

fn recall_params(query: &str) -> epigraph_mcp::types::RecallParams {
    epigraph_mcp::types::RecallParams {
        query: query.to_string(),
        min_truth: Some(0.0),
        limit: Some(10),
        tags: vec![],
        agent_id: None,
        frame_id: None,
        perspective_id: None,
        include_workflows: false,
        exclude_contested: false,
        since: None,
        theme_id: None,
        theme_label: None,
        offset: None,
        epistemic_partition: false,
        diversity_radius: None,
    }
}

/// An ELEVATED request's read tools are served (no `ElevatedReadOnly`), and
/// the one read tool the read-path write census flags, `recall`, still writes
/// its audit row: that write runs detached, on a transaction stamped from the
/// principal's own SCOPED viewer (`tools::recall::write_recall_audit`), so
/// migration 126's refusal on `recall_events` and `begin_as`'s elevated
/// refusal never meet it. The row is attributed to the elevated principal.
///
/// Verified to fail with the audit gated on a write transaction opened for
/// the REQUEST's (elevated) viewer in `tools::memory::recall` (`begin_as`
/// refuses it with `ElevatedReadOnly`, and the audit row never lands).
#[sqlx::test(migrations = "../../migrations")]
async fn an_elevated_read_is_served_and_its_recall_audit_lands(pool: PgPool) {
    let (p, p_group) = fixture::seed_human_operator(&pool, "mcp-el7-p").await;
    let (client, family) = make_holder(&pool, p, 4).await;
    let live = session(&pool, p, client, family, 4, "grant").await;
    let mine = fixture::seed_group_claim(&pool, p, p_group, "quorvalium elevated fixture").await;
    let server = app_server(&pool).await;
    let v = request_viewer(&server, Some(&http_auth(p, client, family, Some(live))))
        .await
        .expect("viewer");
    assert!(v.is_elevated(), "CALIBRATION: the request is elevated");

    epigraph_mcp::tools::claims::get_claim(
        &server,
        &v,
        epigraph_mcp::types::GetClaimParams {
            claim_id: mine.to_string(),
            frame_id: None,
            perspective_id: None,
        },
    )
    .await
    .expect("an elevated get_claim is served");
    epigraph_mcp::tools::memory::recall(&server, &v, recall_params("quorvalium"))
        .await
        .expect("an elevated recall is served");

    let mut landed = 0_i64;
    for _ in 0..100 {
        landed = sqlx::query_scalar(
            "SELECT count(*) FROM recall_events WHERE agent_id = $1 AND query_text = 'quorvalium'",
        )
        .bind(p)
        .fetch_one(&pool)
        .await
        .expect("audit count");
        if landed > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(
        landed, 1,
        "the elevated recall's audit row lands, attributed to the principal"
    );
}

/// PINNED GAP (hand-off to the `sudo` and acceptance batches): the MCP read
/// tools read on the server's UNSTAMPED pool with the viewer's fragment, so on
/// the application role an elevated request is NOT widened by migration 126:
/// the arm needs the elevation settings stamped on the connection, and these
/// reads stamp nothing (RLS then admits public rows only). An elevated
/// `get_claim` of another person's private claim therefore answers "not
/// found" today. Calibrations: the same server serves a public claim to the
/// same viewer, and an application connection stamped from the same elevated
/// viewer DOES read that private claim through the arm. Plan §6.2's "after
/// sudo reads all" over MCP needs the MCP reads stamped first; flip this test
/// when they are.
#[sqlx::test(migrations = "../../migrations")]
async fn mcp_reads_are_not_widened_by_the_arms_until_they_are_stamped(pool: PgPool) {
    let (p, _) = fixture::seed_human_operator(&pool, "mcp-el7-gap-p").await;
    let (b, b_group) = fixture::seed_agent_with_group(&pool, "mcp-el7-gap-b").await;
    let (client, family) = make_holder(&pool, p, 5).await;
    let live = session(&pool, p, client, family, 5, "grant").await;
    let theirs = fixture::seed_group_claim(&pool, b, b_group, "B's private claim").await;
    let public = fixture::seed_public_claim(&pool, b, "B's public claim").await;

    let scoped = ScopedPool::connect_downgraded_for_tests(
        &fixture::database_url_for(&pool).await,
        SessionGucMode::Session,
        "epigraph_app",
    )
    .await
    .expect("app-role ScopedPool");
    let app_pool = fixture::downgraded_pool(&pool, "epigraph_app").await;
    let server = build_scoped_test_server(app_pool, scoped.clone());
    let v = request_viewer(&server, Some(&http_auth(p, client, family, Some(live))))
        .await
        .expect("viewer");
    assert!(v.is_elevated(), "CALIBRATION: the request is elevated");

    let get = |id: Uuid| {
        epigraph_mcp::tools::claims::get_claim(
            &server,
            &v,
            epigraph_mcp::types::GetClaimParams {
                claim_id: id.to_string(),
                frame_id: None,
                perspective_id: None,
            },
        )
    };
    get(public)
        .await
        .expect("CALIBRATION: the tool serves a public claim on this server");
    assert!(
        get(theirs).await.is_err(),
        "the unstamped MCP read does not see a foreign private claim, elevated or not"
    );

    let mut conn = scoped.acquire_as(&v).await.expect("stamped checkout");
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM claims WHERE id = $1")
        .bind(theirs)
        .fetch_one(&mut *conn)
        .await
        .expect("stamped read");
    assert_eq!(
        n, 1,
        "CALIBRATION: a connection stamped from the same viewer reads it through the arm"
    );
}

// =====================================================================
// Review cp1: an elevated request writes NOTHING through MCP (plan §1.4)
// =====================================================================

/// A token of `person` that carries the write scope, with or without an
/// elevation claim (the elevate grant once minted write scopes; hand-minted
/// here so the refusal under test is the elevation's, not the scope gate's).
fn writer_auth(person: Uuid, client: Uuid, family: Uuid, elv: Option<Uuid>) -> AuthContext {
    let mut a = http_auth(person, client, family, elv);
    a.scopes = vec!["claims:read".to_string(), "claims:write".to_string()];
    a
}

fn refused_as_elevated<T: std::fmt::Debug>(r: &Result<T, rmcp::model::ErrorData>) -> bool {
    r.as_ref()
        .err()
        .is_some_and(|e| e.message.contains("ELEVATED READ-ONLY"))
}

fn inline_doc(doi: &str) -> epigraph_mcp::types::IngestDocumentInlineParams {
    epigraph_mcp::types::IngestDocumentInlineParams {
        extraction: serde_json::from_value(serde_json::json!({
            "source": {"title": format!("Elevated ingest {doi}"), "doi": doi,
                       "source_type": "Paper", "authors": []},
            "thesis": format!("Elevated ingest thesis {doi}"),
            "thesis_derivation": "TopDown",
            "sections": [{"title": "S", "paragraphs": [{
                "text": format!("Elevated ingest paragraph {doi}"),
                "atoms": [format!("Elevated ingest atom {doi}")],
                "generality": [3], "confidence": 0.8
            }]}],
            "relationships": []
        }))
        .expect("extraction"),
    }
}

fn memorize_params(content: &str) -> epigraph_mcp::types::MemorizeParams {
    epigraph_mcp::types::MemorizeParams {
        content: content.to_string(),
        confidence: Some(0.7),
        tags: Some(vec![]),
        novelty_threshold: Some(0.0),
    }
}

async fn claims_with_content(pool: &PgPool, content: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM claims WHERE content = $1")
        .bind(content)
        .fetch_one(pool)
        .await
        .expect("count")
}

/// An ELEVATED request's write tools, driven on the tool path as the
/// application role, write nothing and answer `ELEVATED READ-ONLY`: a relabel
/// of the principal's OWN claim, a `memorize`, and a DETACHED ingest
/// (`ingest_document_inline`, whose viewer is downgraded by `detach_scoped`
/// before its preflight). The MCP write path stamps its transaction from a
/// freshly resolved SCOPED author viewer, so without its own refusal neither
/// `begin_as`'s elevated refusal nor migration 126's restrictive policies
/// ever see the elevation (review cp1: both writes committed).
/// Calibration: the same principal's unelevated request memorizes.
///
/// Verified to fail with the refusal dropped from `write_identity` (the
/// relabel and the memorize commit), and with the pre-detach refusal dropped
/// from `ingest_document_inline` (the ingest is queued and its paper row
/// lands).
#[sqlx::test(migrations = "../../migrations")]
async fn an_elevated_request_writes_nothing_through_the_tool_path(pool: PgPool) {
    let (p, p_group) = fixture::seed_human_operator(&pool, "mcp-cp1-write-p").await;
    let (client, family) = make_holder(&pool, p, 6).await;
    let live = session(&pool, p, client, family, 6, "grant").await;
    let mine = fixture::seed_group_claim(&pool, p, p_group, "cp1 elevated write target").await;
    let server = app_server(&pool).await;
    let auth = writer_auth(p, client, family, Some(live));
    let v = request_viewer(&server, Some(&auth)).await.expect("viewer");
    assert!(v.is_elevated(), "CALIBRATION: the request is elevated");

    let relabel = epigraph_mcp::tools::claims::update_labels(
        &server,
        &v,
        epigraph_mcp::types::UpdateLabelsParams {
            claim_id: mine.to_string(),
            add: vec!["written-while-elevated".to_string()],
            remove: vec![],
        },
        Some(&auth),
    )
    .await;
    assert!(refused_as_elevated(&relabel), "update_labels: {relabel:?}");
    let labels: Vec<String> = sqlx::query_scalar("SELECT labels FROM claims WHERE id = $1")
        .bind(mine)
        .fetch_one(&pool)
        .await
        .expect("labels");
    assert!(
        !labels.iter().any(|l| l == "written-while-elevated"),
        "an elevated request relabelled a claim"
    );

    let content = format!("cp1 memorize while elevated {}", Uuid::new_v4());
    let memo =
        epigraph_mcp::tools::memory::memorize(&server, &v, memorize_params(&content), Some(&auth))
            .await;
    assert!(refused_as_elevated(&memo), "memorize: {memo:?}");
    assert_eq!(
        claims_with_content(&pool, &content).await,
        0,
        "an elevated request memorized a claim"
    );

    let doi = format!("10.9999/cp1-elevated-{}", Uuid::new_v4());
    let ingest = epigraph_mcp::tools::ingestion::ingest_document_inline(
        &server,
        &v,
        inline_doc(&doi),
        Some(&auth),
    )
    .await;
    assert!(
        refused_as_elevated(&ingest),
        "ingest_document_inline: {ingest:?}"
    );
    // Give a (wrongly) spawned task time to land before asserting it did not.
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    let papers: i64 = sqlx::query_scalar("SELECT count(*) FROM papers WHERE doi = $1")
        .bind(&doi)
        .fetch_one(&pool)
        .await
        .expect("papers");
    assert_eq!(papers, 0, "an elevated request queued an ingest");

    let plain = writer_auth(p, client, family, None);
    let pv = request_viewer(&server, Some(&plain)).await.expect("viewer");
    assert!(!pv.is_elevated(), "CALIBRATION: no claim, not elevated");
    let content = format!("cp1 memorize unelevated {}", Uuid::new_v4());
    epigraph_mcp::tools::memory::memorize(&server, &pv, memorize_params(&content), Some(&plain))
        .await
        .expect("CALIBRATION: the same principal, unelevated, memorizes");
    assert_eq!(claims_with_content(&pool, &content).await, 1);
}

/// THE DISPATCH CHOKEPOINT, over the whole tool table: for an elevated
/// request every tool whose `SCOPE_MAP` scope is not a read scope is refused
/// `ELEVATED READ-ONLY` by `refuse_elevated_write` (which `call_tool` runs
/// after the scope gate, before dispatch), and every read tool passes; for
/// the same principal unelevated, nothing is refused. Connector mode: a
/// family-only token with a live connector session is refused only when the
/// server's connector switch is on (off, it is not elevated at all).
///
/// Verified to fail with `refuse_elevated_write` answering `Ok` for every
/// call (each write tool passes), and with its write test inverted (each
/// read tool is refused).
#[sqlx::test(migrations = "../../migrations")]
async fn every_write_tool_is_refused_to_an_elevated_request_at_dispatch(pool: PgPool) {
    let (p, _) = fixture::seed_human_operator(&pool, "mcp-cp1-dispatch-p").await;
    let (client, family) = make_holder(&pool, p, 8).await;
    let live = session(&pool, p, client, family, 8, "grant").await;
    let server = app_server(&pool).await;
    let elevated = writer_auth(p, client, family, Some(live));
    let plain = writer_auth(p, client, family, None);

    let mut writes = 0;
    for (tool, scope) in epigraph_mcp::scope_map::SCOPE_MAP {
        let r = server.refuse_elevated_write(Some(&elevated), tool).await;
        if scope.ends_with(":read") {
            assert!(r.is_ok(), "{tool} ({scope}) is a read, refused: {r:?}");
        } else {
            writes += 1;
            assert!(refused_as_elevated(&r), "{tool} ({scope}): {r:?}");
        }
        let r = server.refuse_elevated_write(Some(&plain), tool).await;
        assert!(r.is_ok(), "{tool}: refused to an unelevated request: {r:?}");
    }
    assert!(
        writes >= 40,
        "CALIBRATION: the write half of SCOPE_MAP collapsed ({writes})"
    );
    assert!(
        server.refuse_elevated_write(None, "memorize").await.is_ok(),
        "stdio is never elevated"
    );

    let (_, connector_family) = make_holder(&pool, p, 9).await;
    session(&pool, p, client, connector_family, 9, "connector").await;
    let connector = writer_auth(p, client, connector_family, None);
    assert!(
        server
            .refuse_elevated_write(Some(&connector), "memorize")
            .await
            .is_ok(),
        "the connector switch is off: not elevated, not refused"
    );
    let on = server.clone().with_connector_elevation(true);
    let r = on.refuse_elevated_write(Some(&connector), "memorize").await;
    assert!(refused_as_elevated(&r), "connector mode on: {r:?}");
}

/// Source lock: `call_tool` runs `refuse_elevated_write` inside the HTTP
/// gate, AFTER the scope gate and BEFORE `tool_router.call`, so no write tool
/// body runs for an elevated request (no behavioural test in this crate can
/// drive `call_tool`: it needs an rmcp `RequestContext`).
///
/// Verified to fail with the call removed from `call_tool`.
#[test]
fn call_tool_refuses_an_elevated_write_before_dispatch() {
    let path: std::path::PathBuf = [env!("CARGO_MANIFEST_DIR"), "src", "server.rs"]
        .iter()
        .collect();
    let src = std::fs::read_to_string(&path).expect("server.rs");
    let body = &src[src.find("async fn call_tool(").expect("call_tool")..];
    let scope = body
        .find("Self::enforce_tool_scope(auth_owned.as_ref()")
        .expect("the scope gate");
    let refuse = body
        .find(".refuse_elevated_write(auth_owned.as_ref()")
        .expect("call_tool must call refuse_elevated_write");
    let dispatch = body.find("self.tool_router.call(").expect("the dispatch");
    assert!(
        scope < refuse && refuse < dispatch,
        "refuse_elevated_write must run after the scope gate and before dispatch \
         (scope {scope}, refusal {refuse}, dispatch {dispatch})"
    );
}
