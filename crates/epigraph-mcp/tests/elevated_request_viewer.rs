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
/// human client: `(client row id, family)`. `person` must already exist. A
/// LATER passkey of the same person is opened on a confirmed
/// `passkey.register` act since migration 130
/// (`viewer_fixture::passkey_register_act`).
async fn make_holder(pool: &PgPool, person: Uuid, n: u8) -> (Uuid, Uuid) {
    // 125 ships the recorder gate closed and 127 (the recorder) leaves it
    // closed, so no session is live until the migration that opens it;
    // these tests are about what a LIVE session does.
    fixture::open_elevated_access_gate(pool).await;
    fixture::make_custodian(pool, person).await;
    let client: Uuid = sqlx::query_scalar(
        "SELECT id FROM oauth_clients WHERE agent_id = $1 AND client_type = 'human' \
          ORDER BY created_at LIMIT 1",
    )
    .bind(person)
    .fetch_one(pool)
    .await
    .expect("the human's client");
    let act = fixture::passkey_register_act(pool, person, "mcp elevation test", "key").await;
    let e: Uuid = fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let e = sqlx::query_scalar(
            "SELECT public.epigraph_create_passkey_enrollment($1, 'mcp elevation test', 'key', \
                                                              $2)",
        )
        .bind(person)
        .bind(act)
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

/// A server whose `ScopedPool` is the application role. The pool DECLARES the
/// per-access recorder (`epigraph_db::ACCESS_RECORDER_GUC`), standing in, with
/// `make_holder`'s open gate, for a build that records elevated accesses
/// (review cp3: COR-1).
async fn app_server(pool: &PgPool) -> EpiGraphMcpFull {
    let scoped = app_scoped(pool).await;
    build_scoped_test_server(pool.clone(), scoped)
}

/// An application-role `ScopedPool` that declares the per-access recorder.
async fn app_scoped(pool: &PgPool) -> ScopedPool {
    ScopedPool::connect_with_access_recorder_for_tests(
        &fixture::database_url_for(pool).await,
        SessionGucMode::Session,
        epigraph_db::ScopedPoolOptions::default(),
        Some("epigraph_app"),
    )
    .await
    .expect("app-role ScopedPool")
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
        elevation: None,
        admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
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

    let scoped = app_scoped(&pool).await;
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

// =====================================================================
// EL-8: every elevated tool call is recorded through the REAL call_tool,
// over the streamable-HTTP transport with the bearer middleware in front
// =====================================================================

const EL8_SECRET: &[u8] = b"el8-mcp-recorder-test-secret-at-least-32-bytes!!";

/// The router `main` builds for `--listen --jwt-secret`, over an
/// application-role `ScopedPool` that declares the recorder (the HTTP
/// transport's pool), bound to an ephemeral port.
async fn el8_listener(pool: &PgPool) -> String {
    el8_listener_with(pool, epigraph_db::AdminScopeArmingCache::DEFAULT_TTL).await
}

/// [`el8_listener`] whose servers read the admin-scope switch through a cache
/// of interval `arming_ttl` (`Duration::ZERO`: every call reads it).
async fn el8_listener_with(pool: &PgPool, arming_ttl: std::time::Duration) -> String {
    listener(pool, arming_ttl, false).await
}

/// The public origin the EL-11 listeners name the ceremony page under.
const EL11_BASE: &str = "http://localhost:8080";

/// [`el8_listener_with`] whose servers serve connector-mode elevation when
/// `connector` (the switch is OFF in `main` unless enabled) and name the
/// ceremony page under [`EL11_BASE`].
async fn listener(pool: &PgPool, arming_ttl: std::time::Duration, connector: bool) -> String {
    use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
    use rmcp::transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService,
    };
    use std::sync::Arc;
    let scoped = app_scoped(pool).await;
    // The tools' own pool is the application role too, as in production (the
    // MCP reads run on it unstamped: see
    // `mcp_reads_are_not_widened_by_the_arms_until_they_are_stamped`).
    let pool = fixture::downgraded_pool(pool, "epigraph_app").await;
    let signer = Arc::new(epigraph_crypto::AgentSigner::from_bytes(&[0x58; 32]).expect("signer"));
    let embedder = Arc::new(
        epigraph_mcp::embed::McpEmbedder::new(pool.clone(), None).with_scoped_pool(scoped.clone()),
    );
    let service = StreamableHttpService::new(
        move || {
            Ok(
                EpiGraphMcpFull::new_shared(pool.clone(), signer.clone(), embedder.clone(), false)
                    .with_scoped_pool(scoped.clone())
                    .with_admin_scope_arming_ttl(arming_ttl)
                    .with_connector_elevation(connector)
                    .with_public_base_url(Some(EL11_BASE.to_string())),
            )
        },
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default(),
    );
    let state = epigraph_mcp::auth::McpAuthState {
        jwt_config: Arc::new(epigraph_auth::JwtConfig::from_secret(EL8_SECRET)),
        resource_metadata_url: None,
    };
    let router = axum::Router::new().nest_service("/mcp", service).layer(
        axum::middleware::from_fn_with_state(state, epigraph_mcp::auth::bearer_auth_middleware),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        axum::serve(listener, router).await.expect("serve");
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    format!("http://{addr}/mcp")
}

/// A human token for `person` on `client`/`family`, naming `elv`.
fn el8_token(person: Uuid, client: Uuid, family: Uuid, elv: Option<Uuid>) -> String {
    epigraph_auth::JwtConfig::from_secret(EL8_SECRET)
        .issue_access_token(
            client,
            vec!["claims:read".to_string()],
            "human",
            None,
            Some(person),
            chrono::Duration::minutes(10),
            epigraph_auth::AccessTokenBinding {
                family_id: Some(family),
                elevation_id: elv,
            },
        )
        .expect("mint")
        .0
}

async fn el8_post(
    url: &str,
    token: &str,
    session: Option<&str>,
    body: serde_json::Value,
) -> reqwest::Response {
    let mut req = reqwest::Client::new()
        .post(url)
        .header("Authorization", format!("Bearer {token}"))
        .header("Accept", "application/json, text/event-stream")
        .header("Content-Type", "application/json")
        .json(&body);
    if let Some(s) = session {
        req = req.header("Mcp-Session-Id", s);
    }
    req.send().await.expect("POST")
}

/// The first SSE `data:` payload of `resp`, parsed.
async fn el8_data(mut resp: reqwest::Response) -> serde_json::Value {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
    let mut acc = String::new();
    while let Ok(Ok(Some(bytes))) = tokio::time::timeout_at(deadline, resp.chunk()).await {
        acc.push_str(&String::from_utf8_lossy(&bytes));
        if let Some(line) = acc
            .lines()
            .find(|l| l.starts_with("data:") && l.trim_end().len() > 5)
        {
            return serde_json::from_str(line.trim_start_matches("data:").trim())
                .unwrap_or_else(|e| panic!("SSE data is JSON ({e}): {line}"));
        }
    }
    panic!("no SSE data: {acc}");
}

/// Initialize an MCP session on `url` with `token`; its id.
async fn el8_session(url: &str, token: &str) -> String {
    let resp = el8_post(
        url,
        token,
        None,
        serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                       "clientInfo": {"name": "el8-recorder-test", "version": "0"}}
        }),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 200, "initialize");
    let session = resp
        .headers()
        .get("Mcp-Session-Id")
        .expect("session header")
        .to_str()
        .expect("ascii")
        .to_owned();
    let _ = el8_data(resp).await;
    let notif = el8_post(
        url,
        token,
        Some(&session),
        serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    )
    .await;
    assert_eq!(notif.status().as_u16(), 202, "notifications/initialized");
    session
}

/// `tools/call get_claim {claim_id}` through the real `call_tool`; the
/// JSON-RPC answer.
async fn el8_get_claim(url: &str, token: &str, claim: Uuid) -> serde_json::Value {
    let session = el8_session(url, token).await;
    let resp = el8_post(
        url,
        token,
        Some(&session),
        serde_json::json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "get_claim", "arguments": {"claim_id": claim.to_string()}}
        }),
    )
    .await;
    el8_data(resp).await
}

async fn el8_log(pool: &PgPool) -> Vec<(String, i32, Vec<Uuid>, serde_json::Value)> {
    sqlx::query_as(
        "SELECT surface, row_count, owner_group_ids, args FROM elevated_access \
          ORDER BY created_at, id",
    )
    .fetch_all(pool)
    .await
    .expect("the log")
}

/// An elevated tool call through the real `call_tool` is recorded ONCE before
/// its result returns: surface `mcp:get_claim`, the call's id-shaped argument,
/// the token's jti, one row in the result, and no subject for a public row.
/// A call whose result names B's private claim (the MCP read is not widened,
/// so the tool answers "not found", naming the id) is recorded too, against
/// B's group: the attempt is visible to B.
///
/// Verified to fail with `call_tool` returning the tool's result without
/// recording it (no row).
#[sqlx::test(migrations = "../../migrations")]
async fn an_elevated_tool_call_is_recorded_before_its_result_returns(pool: PgPool) {
    let (p, p_group) = fixture::seed_human_operator(&pool, "mcp-el8-p").await;
    let (b, b_group) = fixture::seed_agent_with_group(&pool, "mcp-el8-b").await;
    let (client, family) = make_holder(&pool, p, 8).await;
    let live = session(&pool, p, client, family, 8, "grant").await;
    let mine = fixture::seed_public_claim(&pool, p, "mcp el8 P's public claim").await;
    let _ = p_group;
    let theirs = fixture::seed_group_claim(&pool, b, b_group, "mcp el8 B's claim").await;
    let url = el8_listener(&pool).await;
    let token = el8_token(p, client, family, Some(live));
    let jti = epigraph_auth::JwtConfig::from_secret(EL8_SECRET)
        .validate_token(&token)
        .expect("decodes")
        .jti;

    let answer = el8_get_claim(&url, &token, mine).await;
    assert!(answer.get("result").is_some(), "served: {answer}");
    assert!(
        answer.to_string().contains("mcp el8 P's public claim"),
        "{answer}"
    );
    let log = el8_log(&pool).await;
    assert_eq!(log.len(), 1, "{log:?}");
    let (surface, rows, groups, args) = &log[0];
    assert_eq!(surface, "mcp:get_claim");
    assert_eq!(*rows, 1, "one row in the result");
    assert!(
        groups.is_empty(),
        "a public row names no subject: {groups:?}"
    );
    assert_eq!(
        args["arguments"]["claim_id"],
        serde_json::json!([mine.to_string()])
    );
    assert_eq!(args["jti"], serde_json::json!(jti.to_string()));

    let answer = el8_get_claim(&url, &token, theirs).await;
    assert!(
        !answer.to_string().contains("mcp el8 B's claim"),
        "CALIBRATION: the MCP read is not widened: {answer}"
    );
    let log = el8_log(&pool).await;
    assert_eq!(log.len(), 2, "{log:?}");
    assert_eq!(log[1].2, vec![b_group], "the attempt is recorded for B");
}

/// FAIL-CLOSED: when the recorder cannot record (its EXECUTE revoked from the
/// application role), the elevated call's result is WITHHELD: the caller gets
/// an internal error naming the refusal and none of the row. The same call
/// unelevated is served and writes no row.
///
/// Verified to fail with `record_elevated_call` returning the tool's result
/// when the record fails (the claim is sent).
#[sqlx::test(migrations = "../../migrations")]
async fn a_failed_record_withholds_the_tool_result(pool: PgPool) {
    let (p, p_group) = fixture::seed_human_operator(&pool, "mcp-el8-fail-p").await;
    let (client, family) = make_holder(&pool, p, 9).await;
    let live = session(&pool, p, client, family, 9, "grant").await;
    let mine = fixture::seed_public_claim(&pool, p, "mcp el8 withheld row").await;
    let _ = p_group;
    let url = el8_listener(&pool).await;
    sqlx::query(
        "REVOKE EXECUTE ON FUNCTION public.epigraph_record_elevated_access(text, jsonb, integer, \
         uuid[]) FROM epigraph_app",
    )
    .execute(&pool)
    .await
    .expect("revoke");

    let answer = el8_get_claim(&url, &el8_token(p, client, family, Some(live)), mine).await;
    let text = answer.to_string();
    assert!(
        answer.get("error").is_some(),
        "an error, not a result: {answer}"
    );
    assert!(text.contains("NOT RECORDED"), "{text}");
    assert!(
        !text.contains("mcp el8 withheld row"),
        "none of the row: {text}"
    );

    let answer = el8_get_claim(&url, &el8_token(p, client, family, None), mine).await;
    assert!(
        answer.to_string().contains("mcp el8 withheld row"),
        "CALIBRATION: the unelevated call is served: {answer}"
    );
    assert!(el8_log(&pool).await.is_empty());
}

/// A call that is not elevated writes no row and is served as before: a
/// token with no claim, and a token whose claim names no live session
/// (resolved scoped at dispatch, its claim stripped before the tool runs).
///
/// Verified to fail with `call_tool` treating every claim-carrying call as
/// elevated (the forged claim's result goes to the recorder, which refuses
/// it, and the result is withheld).
#[sqlx::test(migrations = "../../migrations")]
async fn an_unelevated_tool_call_writes_no_row(pool: PgPool) {
    let (p, p_group) = fixture::seed_human_operator(&pool, "mcp-el8-plain-p").await;
    let (client, family) = make_holder(&pool, p, 10).await;
    let mine = fixture::seed_public_claim(&pool, p, "mcp el8 plain row").await;
    let _ = p_group;
    let url = el8_listener(&pool).await;
    for (what, elv) in [("no claim", None), ("forged claim", Some(Uuid::new_v4()))] {
        let answer = el8_get_claim(&url, &el8_token(p, client, family, elv), mine).await;
        assert!(
            answer.to_string().contains("mcp el8 plain row"),
            "{what}: served: {answer}"
        );
    }
    assert!(el8_log(&pool).await.is_empty());
}

/// The binary builds its pool with the recording constructor on the HTTP
/// transport only (`--listen`), and `call_tool` routes an elevated call's
/// result through the recorder. Source lock: `main` is a binary no test
/// constructs, and `call_tool` needs an rmcp request context.
///
/// Verified to fail with `main.rs` building the recording pool on every
/// transport.
#[test]
fn the_http_transport_records_and_declares() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let main = std::fs::read_to_string(root.join("src/main.rs")).unwrap();
    let at = main
        .find("ScopedPool::connect_recording_elevated_access(")
        .expect("main.rs builds the recording pool");
    let before = &main[..at];
    assert!(
        before
            .rfind("if cli.listen.is_some()")
            .is_some_and(|i| at - i < 200),
        "only on the HTTP transport (--listen)"
    );
    let server = std::fs::read_to_string(root.join("src/server.rs")).unwrap();
    let body = &server[server.find("async fn call_tool(").expect("call_tool")..];
    assert!(
        body.contains("crate::elevated_access::record_elevated_call("),
        "call_tool records an elevated call's result"
    );
}

// =====================================================================
// EL-10: the MCP scope gate goes through the check chokepoint
// =====================================================================

/// Arm (`true`) or disarm the admin-scope switch as the maintenance role.
async fn set_admin_switch(pool: &PgPool, armed: bool) {
    fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        sqlx::query("SELECT changed FROM public.epigraph_set_admin_scope_enforcement($1, $2)")
            .bind(armed)
            .bind("el10 mcp test")
            .execute(&mut *conn)
            .await
            .expect("set the admin-scope switch");
        (conn, ())
    })
    .await;
}

/// `tools/call delete_edge` (SCOPE_MAP: `claims:admin`) through the real
/// `call_tool` with `token`; the JSON-RPC answer as text.
async fn el10_delete_edge(url: &str, token: &str) -> String {
    let session = el8_session(url, token).await;
    let resp = el8_post(
        url,
        token,
        Some(&session),
        serde_json::json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "delete_edge",
                       "arguments": {"edge_id": Uuid::new_v4().to_string()}}
        }),
    )
    .await;
    el8_data(resp).await.to_string()
}

/// A STANDING `claims:admin` token (minted directly, as one minted before
/// arming would be) on an MCP admin tool, through the bearer middleware and
/// the real `call_tool` on the application role: unarmed the scope gate
/// passes (whatever the tool then answers for a missing edge); ARMED the gate
/// refuses it for want of `claims:admin`; disarmed it passes again.
///
/// Verified to fail with `enforce_tool_scope` reading the token's scopes
/// directly (armed passes the gate), and with `call_tool` not reading the
/// switch (the bearer middleware's context stays armed: unarmed is refused).
#[sqlx::test(migrations = "../../migrations")]
async fn a_standing_admin_scope_is_absent_on_an_mcp_tool_while_armed(pool: PgPool) {
    let (person, _) = fixture::seed_human_operator(&pool, "el10-mcp-admin").await;
    let token = epigraph_auth::JwtConfig::from_secret(EL8_SECRET)
        .issue_access_token(
            Uuid::new_v4(),
            vec!["claims:read".to_string(), "claims:admin".to_string()],
            "human",
            None,
            Some(person),
            chrono::Duration::minutes(10),
            epigraph_auth::AccessTokenBinding::NONE,
        )
        .expect("mint")
        .0;
    let url = el8_listener_with(&pool, std::time::Duration::ZERO).await;
    let gate = "requires scope 'claims:admin'";

    let unarmed = el10_delete_edge(&url, &token).await;
    assert!(
        !unarmed.contains(gate),
        "unarmed: the gate passes: {unarmed}"
    );
    set_admin_switch(&pool, true).await;
    let armed = el10_delete_edge(&url, &token).await;
    assert!(
        armed.contains(gate),
        "armed: claims:admin is absent: {armed}"
    );
    set_admin_switch(&pool, false).await;
    let again = el10_delete_edge(&url, &token).await;
    assert!(!again.contains(gate), "disarmed: the gate passes: {again}");
}

/// An ELEVATED request's database-checked elevation reaches the MCP scope
/// gate: through the real `call_tool`, P's elevated token (the elevate
/// grant's read scopes plus `platform:admin`, no `claims:admin`) passes
/// `delete_edge`'s `claims:admin` gate and is then refused as ELEVATED
/// READ-ONLY (every write tool is). Calibration: the same scopes on a token
/// whose claim names no live session stop at the scope gate.
///
/// The refusal of that ADMIN write names `epigraph-operator` (plan EQ-5).
///
/// Verified to fail with `call_tool` not setting the request's elevation (the
/// elevated call stops at the scope gate), and with the admin pointer dropped
/// from `refuse_elevated_write`.
#[sqlx::test(migrations = "../../migrations")]
async fn an_elevated_request_holds_the_admin_read_scopes_at_the_mcp_gate(pool: PgPool) {
    let (p, _) = fixture::seed_human_operator(&pool, "el10-mcp-elevated").await;
    let (client, family) = make_holder(&pool, p, 9).await;
    let live = session(&pool, p, client, family, 9, "grant").await;
    let url = el8_listener(&pool).await;
    let mint = |elv: Uuid| {
        epigraph_auth::JwtConfig::from_secret(EL8_SECRET)
            .issue_access_token(
                client,
                vec!["claims:read".to_string(), "platform:admin".to_string()],
                "human",
                None,
                Some(p),
                chrono::Duration::minutes(10),
                epigraph_auth::AccessTokenBinding {
                    family_id: Some(family),
                    elevation_id: Some(elv),
                },
            )
            .expect("mint")
            .0
    };
    let gate = "requires scope 'claims:admin'";

    let forged = el10_delete_edge(&url, &mint(Uuid::new_v4())).await;
    assert!(
        forged.contains(gate),
        "CALIBRATION: no live elevation, no admin scope: {forged}"
    );
    let elevated = el10_delete_edge(&url, &mint(live)).await;
    assert!(
        !elevated.contains(gate) && elevated.contains("ELEVATED READ-ONLY"),
        "elevated: past the scope gate, refused as a write: {elevated}"
    );
    assert!(
        elevated.contains("epigraph-operator"),
        "an admin write's refusal says where admin writes run (plan EQ-5): {elevated}"
    );
}

/// An ELEVATED request reaches no FEDERATED tool (review cp1 COR-1's residual,
/// plan EL-10): the refusal answers `ELEVATED READ-ONLY` and names the tool;
/// an unelevated request passes. Source lock (a federated call needs a live
/// extension to drive end to end): in `call_tool`'s federation branch the
/// elevation is resolved first and the refusal runs before the extension's
/// scope gate and the proxy call.
///
/// Verified to fail with the refusal's call removed from the federation
/// branch, and with the refusal answering `Ok` for an elevated request.
#[test]
fn an_elevated_request_reaches_no_federated_tool() {
    let refused = EpiGraphMcpFull::refuse_elevated_federated(true, "attach_blob");
    assert!(refused_as_elevated(&refused), "{refused:?}");
    assert!(format!("{refused:?}").contains("attach_blob"));
    assert!(EpiGraphMcpFull::refuse_elevated_federated(false, "attach_blob").is_ok());

    let src = include_str!("../src/server.rs");
    let body = &src[src.find("async fn call_tool(").expect("call_tool")..];
    let resolve = body
        .find("self.elevation_at_dispatch(auth_owned.as_mut())")
        .expect("call_tool resolves the elevation");
    let branch = body
        .find("self.federation.route_config(&request.name)")
        .expect("the federation branch");
    let refusal = body
        .find("Self::refuse_elevated_federated(elevated.is_some()")
        .expect("the federation branch refuses an elevated request");
    let gate = body
        .find("Self::enforce_federated_scope(auth_owned.as_ref()")
        .expect("the federated scope gate");
    let proxy = body.find(".invoke(&request.name").expect("the proxy call");
    assert!(
        resolve < branch && branch < refusal && refusal < gate && gate < proxy,
        "resolve the elevation, then refuse it in the federation branch before the \
         extension's scope gate and the proxy call"
    );
}

// =====================================================================
// EL-11: MCP `sudo` / `unsudo`, and the manifest shows them only to role
// holders (D2). Connector mode is OFF by default; the CLI path is served.
// =====================================================================

/// A token for `person` on `client` naming `family`/`elv`, of `client_type`
/// with `scopes`.
fn el11_token(
    person: Uuid,
    client: Uuid,
    family: Option<Uuid>,
    elv: Option<Uuid>,
    client_type: &str,
    scopes: &[&str],
) -> String {
    epigraph_auth::JwtConfig::from_secret(EL8_SECRET)
        .issue_access_token(
            client,
            scopes.iter().map(|s| (*s).to_string()).collect(),
            client_type,
            None,
            Some(person),
            chrono::Duration::minutes(10),
            epigraph_auth::AccessTokenBinding {
                family_id: family,
                elevation_id: elv,
            },
        )
        .expect("mint")
        .0
}

/// The first COMPLETE SSE `data:` line of `resp`, parsed: a tool list is
/// larger than one chunk, so (unlike [`el8_data`]) a line counts only once
/// its newline has arrived.
async fn el11_data(mut resp: reqwest::Response) -> serde_json::Value {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
    let mut acc = String::new();
    while let Ok(Ok(Some(bytes))) = tokio::time::timeout_at(deadline, resp.chunk()).await {
        acc.push_str(&String::from_utf8_lossy(&bytes));
        if let Some(line) = acc
            .split_inclusive('\n')
            .filter(|l| l.ends_with('\n'))
            .find(|l| l.starts_with("data:") && l.trim_end().len() > 5)
        {
            return serde_json::from_str(line.trim_start_matches("data:").trim())
                .unwrap_or_else(|e| panic!("SSE data is JSON ({e}): {line}"));
        }
    }
    panic!("no complete SSE data: {acc}");
}

/// One JSON-RPC request on a fresh MCP session; the answer.
async fn el11_rpc(
    url: &str,
    token: &str,
    method: &str,
    params: serde_json::Value,
) -> serde_json::Value {
    let session = el8_session(url, token).await;
    let resp = el8_post(
        url,
        token,
        Some(&session),
        serde_json::json!({"jsonrpc": "2.0", "id": 2, "method": method, "params": params}),
    )
    .await;
    el11_data(resp).await
}

/// The tool names `tools/list` answers `token`.
async fn el11_list(url: &str, token: &str) -> Vec<String> {
    let answer = el11_rpc(url, token, "tools/list", serde_json::json!({})).await;
    names_of(&answer["result"]["tools"], &answer)
}

/// The tool names the `list_mcp_tools` TOOL answers `token`.
async fn el11_meta_list(url: &str, token: &str) -> Vec<String> {
    let answer = el11_call(url, token, "list_mcp_tools", serde_json::json!({})).await;
    let listed = el11_result(&answer).unwrap_or_else(|| panic!("list_mcp_tools: {answer}"));
    names_of(&listed, &answer)
}

fn names_of(tools: &serde_json::Value, answer: &serde_json::Value) -> Vec<String> {
    tools
        .as_array()
        .unwrap_or_else(|| panic!("a tool array: {answer}"))
        .iter()
        .map(|t| t["name"].as_str().expect("name").to_string())
        .collect()
}

/// `tools/call name(arguments)` for `token`; the JSON-RPC answer.
async fn el11_call(
    url: &str,
    token: &str,
    name: &str,
    arguments: serde_json::Value,
) -> serde_json::Value {
    el11_rpc(
        url,
        token,
        "tools/call",
        serde_json::json!({"name": name, "arguments": arguments}),
    )
    .await
}

/// A successful tool answer's text content, parsed as JSON.
fn el11_result(answer: &serde_json::Value) -> Option<serde_json::Value> {
    if answer["result"]["isError"].as_bool() == Some(true) {
        return None;
    }
    let text = answer["result"]["content"][0]["text"].as_str()?;
    serde_json::from_str(text).ok()
}

/// A tool answer's error text (a JSON-RPC error or an `isError` result).
fn el11_error(answer: &serde_json::Value) -> Option<String> {
    answer["error"]["message"]
        .as_str()
        .map(str::to_string)
        .or_else(|| {
            (answer["result"]["isError"].as_bool() == Some(true))
                .then(|| answer["result"]["content"].to_string())
        })
}

/// The tickets `person` holds: `(mode, redeem hash present, client, family, reason)`.
async fn el11_tickets(pool: &PgPool, person: Uuid) -> Vec<(String, bool, Uuid, Uuid, String)> {
    sqlx::query_as(
        "SELECT mode, redeem_secret_hash IS NOT NULL, client_id, family_id, reason \
           FROM elevation_tickets WHERE person_agent_id = $1 ORDER BY created_at",
    )
    .bind(person)
    .fetch_all(pool)
    .await
    .expect("tickets")
}

/// A further live refresh family of `client`.
async fn el11_family(pool: &PgPool, client: Uuid) -> Uuid {
    let hash: Vec<u8> = [
        Uuid::new_v4().as_bytes().to_vec(),
        Uuid::new_v4().as_bytes().to_vec(),
    ]
    .concat();
    sqlx::query_scalar(
        "INSERT INTO refresh_tokens (token_hash, client_id, scopes, expires_at) \
         VALUES ($1, $2, ARRAY['claims:read'], now() + interval '1 day') RETURNING id",
    )
    .bind(&hash)
    .bind(client)
    .fetch_one(pool)
    .await
    .expect("a refresh token")
}

/// `person`'s own human client.
async fn el11_client(pool: &PgPool, person: Uuid) -> Uuid {
    sqlx::query_scalar(
        "SELECT id FROM oauth_clients WHERE agent_id = $1 AND client_type = 'human' \
          ORDER BY created_at LIMIT 1",
    )
    .bind(person)
    .fetch_one(pool)
    .await
    .expect("the human's client")
}

/// Complete `ticket`'s ceremony through migration 125's definers with the
/// passkey `make_holder(.., n)` enrolled (synthetic evidence, as `session`):
/// the session it opened.
async fn el11_confirm(pool: &PgPool, ticket: Uuid, n: u8) -> Uuid {
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

/// A legacy `instance_admins` row for `person` (frozen since 123; seeded with
/// its triggers off).
async fn el11_legacy_admin(pool: &PgPool, person: Uuid) {
    use sqlx::Executor;
    let mut conn = pool.acquire().await.expect("conn");
    conn.execute("SET session_replication_role = replica")
        .await
        .expect("replica");
    sqlx::query("INSERT INTO instance_admins (agent_id, note) VALUES ($1, 'legacy')")
        .bind(person)
        .execute(&mut *conn)
        .await
        .expect("a legacy row");
    conn.execute("SET session_replication_role = origin")
        .await
        .expect("origin");
}

/// D2: with connector mode ON, the manifest lists `sudo` and `unsudo` to P
/// (a registered human holding the elevating custodian role) and to nobody
/// else: not to A (a registered human whose only standing is a legacy
/// `instance_admins` row), and not to G, an agent, whether its token says
/// `agent` (refused by token type, before any database round trip: a
/// SHORTCUT, not the database's answer) or `human` (the database answers: an
/// agent holds no role). The `list_mcp_tools` TOOL answers each caller the
/// same names as `tools/list`.
///
/// Verified to fail with `listed` admitting `sudo`/`unsudo` to every HTTP
/// caller (no filter: A and G see them), with `list_mcp_tools` listing the
/// router unfiltered, and with `manifest_for` never asking the database
/// (P's list loses them).
#[sqlx::test(migrations = "../../migrations")]
async fn the_manifest_lists_sudo_only_to_a_role_holder(pool: PgPool) {
    let (p, _) = fixture::seed_human_operator(&pool, "el11-list-p").await;
    let (a, _) = fixture::seed_human_operator(&pool, "el11-list-a").await;
    let (g, _) = fixture::seed_agent_with_group(&pool, "el11-list-g").await;
    let (p_client, p_family) = make_holder(&pool, p, 31).await;
    el11_legacy_admin(&pool, a).await;
    let a_client = el11_client(&pool, a).await;
    let a_family = el11_family(&pool, a_client).await;
    let url = listener(&pool, epigraph_db::AdminScopeArmingCache::DEFAULT_TTL, true).await;

    let p_token = el11_token(p, p_client, Some(p_family), None, "human", &["claims:read"]);
    let a_token = el11_token(a, a_client, Some(a_family), None, "human", &["claims:read"]);
    let g_agent = el11_token(
        g,
        Uuid::new_v4(),
        Some(Uuid::new_v4()),
        None,
        "agent",
        &["claims:read"],
    );
    let g_human = el11_token(
        g,
        Uuid::new_v4(),
        Some(Uuid::new_v4()),
        None,
        "human",
        &["claims:read"],
    );

    let has = |names: &[String], tool: &str| names.iter().any(|n| n == tool);
    let p_list = el11_list(&url, &p_token).await;
    assert!(
        has(&p_list, "sudo") && has(&p_list, "unsudo"),
        "the role holder sees both: {p_list:?}"
    );
    assert!(has(&p_list, "get_claim"), "CALIBRATION: an ordinary tool");
    for (who, token) in [
        ("A (instance_admins only)", &a_token),
        ("G (agent token)", &g_agent),
        ("G (agent principal, human-typed token)", &g_human),
    ] {
        let list = el11_list(&url, token).await;
        assert!(has(&list, "get_claim"), "{who}: CALIBRATION: listed at all");
        assert!(
            !has(&list, "sudo") && !has(&list, "unsudo"),
            "{who} must not see sudo/unsudo: {list:?}"
        );
    }
    for (who, token, list) in [
        ("P", &p_token, p_list),
        ("A", &a_token, el11_list(&url, &a_token).await),
    ] {
        let mut meta = el11_meta_list(&url, token).await;
        let mut listed = list;
        meta.sort();
        listed.sort();
        assert_eq!(
            meta, listed,
            "{who}: list_mcp_tools answers what tools/list answers"
        );
    }
}

/// Connector mode is OFF by default (operator ruling, EQ-7 unruled): on a
/// listener built as `main` builds it without the switch, P (who may elevate)
/// is not shown `sudo` (but is shown `unsudo`, which only ever narrows), and
/// a `sudo` call is REFUSED, pointing at the CLI elevate path, with no ticket
/// opened. Calibration: the same P on a listener with the switch on gets a
/// URL and a ticket.
///
/// Verified to fail with `sudo`'s switch guard dropped (the off listener
/// opens a ticket), and with `listed` showing `sudo` regardless of the
/// switch.
#[sqlx::test(migrations = "../../migrations")]
async fn sudo_is_served_only_with_connector_mode_on(pool: PgPool) {
    let (p, _) = fixture::seed_human_operator(&pool, "el11-off-p").await;
    let (client, family) = make_holder(&pool, p, 32).await;
    let token = el11_token(p, client, Some(family), None, "human", &["claims:read"]);
    let off = el8_listener(&pool).await;

    let list = el11_list(&off, &token).await;
    assert!(
        !list.iter().any(|n| n == "sudo"),
        "switch off: no sudo: {list:?}"
    );
    assert!(list.iter().any(|n| n == "unsudo"), "unsudo stays: {list:?}");
    let answer = el11_call(&off, &token, "sudo", serde_json::json!({"reason": "audit"})).await;
    let refused = el11_error(&answer).unwrap_or_else(|| panic!("refused: {answer}"));
    assert!(
        refused.contains("OFF") && refused.contains("/api/v1/elevation/tickets"),
        "the refusal names the CLI path: {refused}"
    );
    assert!(el11_tickets(&pool, p).await.is_empty(), "no ticket opened");

    let on = listener(&pool, epigraph_db::AdminScopeArmingCache::DEFAULT_TTL, true).await;
    let answer = el11_call(&on, &token, "sudo", serde_json::json!({"reason": "audit"})).await;
    assert!(
        el11_result(&answer).is_some_and(|r| r.get("url").is_some()),
        "CALIBRATION: switched on, the same P gets a URL: {answer}"
    );
    assert_eq!(el11_tickets(&pool, p).await.len(), 1);
}

/// `sudo` returns ONLY the ceremony URL: the result's sole key is `url`,
/// `<base>/elevate/<ticket>`, and nothing token-shaped. The ticket is a
/// CONNECTOR-mode ticket with no redeem secret, for P's own client and the
/// token's family, carrying the reason.
///
/// Verified to fail with the ticket opened in grant mode (a redeem hash is
/// stored), with the result naming the ticket id as a separate field, and
/// with `call_tool`'s dispatch exemption removed (a not-elevated `sudo` has
/// its family stripped and is refused).
#[sqlx::test(migrations = "../../migrations")]
async fn sudo_returns_only_the_ceremony_url(pool: PgPool) {
    let (p, _) = fixture::seed_human_operator(&pool, "el11-url-p").await;
    let (client, family) = make_holder(&pool, p, 33).await;
    let token = el11_token(p, client, Some(family), None, "human", &["claims:read"]);
    let url = listener(&pool, epigraph_db::AdminScopeArmingCache::DEFAULT_TTL, true).await;

    let answer = el11_call(
        &url,
        &token,
        "sudo",
        serde_json::json!({"reason": "read B's rows"}),
    )
    .await;
    let result = el11_result(&answer).unwrap_or_else(|| panic!("sudo answered: {answer}"));
    let keys: Vec<&String> = result.as_object().expect("an object").keys().collect();
    assert_eq!(keys, vec!["url"], "only the URL: {result}");
    let page = result["url"].as_str().expect("a string");
    let tickets = el11_tickets(&pool, p).await;
    assert_eq!(tickets.len(), 1, "one ticket");
    let id: Uuid =
        sqlx::query_scalar("SELECT id FROM elevation_tickets WHERE person_agent_id = $1")
            .bind(p)
            .fetch_one(&pool)
            .await
            .expect("ticket id");
    assert_eq!(page, format!("{EL11_BASE}/elevate/{id}"));
    assert_eq!(
        tickets[0],
        (
            "connector".to_string(),
            false,
            client,
            family,
            "read B's rows".to_string()
        ),
        "a connector ticket with no redeem secret, for the caller's client and family"
    );
    let text = answer.to_string();
    assert!(!text.contains("eyJ"), "no token in the answer: {text}");
}

/// ADM-10: after the ceremony a `sudo` ticket opens, P's SAME-family token
/// resolves elevated and its tool call is recorded, while P's OTHER family on
/// the same client is neither elevated nor recorded; `unsudo` then ends it
/// (reason `unsudo`) and the same-family token is plain again. A second
/// `unsudo` has nothing to end.
///
/// Verified to fail with `unsudo` ending nothing, and with the family bound
/// dropped from BOTH layers that hold it (125's `epigraph_elevation_live`
/// family clause and `Viewer::resolve_elevated`'s family cross-check: the
/// other family elevates). Either layer alone still holds it (each single
/// drop was run and survived, by design), and with the dispatch exemption
/// removed (`sudo` loses its family to the strip).
#[sqlx::test(migrations = "../../migrations")]
async fn sudo_elevates_its_own_family_until_unsudo(pool: PgPool) {
    let (p, _) = fixture::seed_human_operator(&pool, "el11-adm10-p").await;
    let (client, family) = make_holder(&pool, p, 34).await;
    let other = el11_family(&pool, client).await;
    let claim = fixture::seed_public_claim(&pool, p, "el11 P's public claim").await;
    let url = listener(&pool, epigraph_db::AdminScopeArmingCache::DEFAULT_TTL, true).await;
    let mine = el11_token(p, client, Some(family), None, "human", &["claims:read"]);
    let theirs = el11_token(p, client, Some(other), None, "human", &["claims:read"]);

    let answer = el11_call(&url, &mine, "sudo", serde_json::json!({"reason": "adm-10"})).await;
    let page = el11_result(&answer).unwrap_or_else(|| panic!("sudo: {answer}"))["url"]
        .as_str()
        .expect("url")
        .to_string();
    let ticket: Uuid = page
        .rsplit('/')
        .next()
        .expect("id")
        .parse()
        .expect("a uuid");
    let session = el11_confirm(&pool, ticket, 34).await;

    let server = app_server(&pool).await.with_connector_elevation(true);
    let same = request_viewer(&server, Some(&http_auth(p, client, family, None)))
        .await
        .expect("viewer");
    assert_eq!(
        same.elevation().map(|e| (e.session_id, e.connector)),
        Some((session, true)),
        "the sudo family is elevated by the connector session"
    );
    let other_viewer = request_viewer(&server, Some(&http_auth(p, client, other, None)))
        .await
        .expect("viewer");
    assert!(
        !other_viewer.is_elevated(),
        "P's other family is NOT elevated"
    );

    let _ = el11_call(
        &url,
        &mine,
        "get_claim",
        serde_json::json!({"claim_id": claim.to_string()}),
    )
    .await;
    assert_eq!(
        el8_log(&pool).await.len(),
        1,
        "the same-family call is recorded"
    );
    let _ = el11_call(
        &url,
        &theirs,
        "get_claim",
        serde_json::json!({"claim_id": claim.to_string()}),
    )
    .await;
    assert_eq!(
        el8_log(&pool).await.len(),
        1,
        "the other family's call is not"
    );

    let answer = el11_call(&url, &mine, "unsudo", serde_json::json!({})).await;
    assert_eq!(
        el11_result(&answer),
        Some(serde_json::json!({"ended": true})),
        "unsudo ends it: {answer}"
    );
    let reason: Option<String> =
        sqlx::query_scalar("SELECT ended_reason FROM elevation_sessions WHERE id = $1")
            .bind(session)
            .fetch_one(&pool)
            .await
            .expect("session");
    assert_eq!(reason.as_deref(), Some("unsudo"));
    let after = request_viewer(&server, Some(&http_auth(p, client, family, None)))
        .await
        .expect("viewer");
    assert!(!after.is_elevated(), "after unsudo the family is plain");
    let _ = el11_call(
        &url,
        &mine,
        "get_claim",
        serde_json::json!({"claim_id": claim.to_string()}),
    )
    .await;
    assert_eq!(el8_log(&pool).await.len(), 1, "and no longer recorded");
    let again = el11_call(&url, &mine, "unsudo", serde_json::json!({})).await;
    assert_eq!(
        el11_result(&again),
        Some(serde_json::json!({"ended": false}))
    );
}

/// `sudo` is refused to an AGENT (the database's ELV02: an agent holds no
/// role, even carrying a live family of its own client) and over STDIO (no
/// `AuthContext`: refused before any viewer is resolved), and opens no
/// ticket either way; `unsudo` is refused over stdio too. Both run with
/// connector mode ON, so neither refusal is the switch's.
///
/// A regression pin: the refusals are the database's and the transport
/// gate's, and no one-line change to the tool body admits either without
/// also failing the ticket count.
#[sqlx::test(migrations = "../../migrations")]
async fn sudo_is_refused_to_an_agent_and_over_stdio(pool: PgPool) {
    let (g, _) = fixture::seed_agent_with_group(&pool, "el11-agent").await;
    let (owner, _) = fixture::seed_human_operator(&pool, "el11-agent-owner").await;
    let owner_client = el11_client(&pool, owner).await;
    let g_client: Uuid = sqlx::query_scalar(
        "INSERT INTO oauth_clients (client_id, client_name, client_type, allowed_scopes, \
                                    granted_scopes, status, agent_id, owner_id) \
         VALUES ($1, 'el11-agent', 'agent', ARRAY['claims:read'], ARRAY['claims:read'], \
                 'active', $2, $3) RETURNING id",
    )
    .bind(format!("el11-agent-{g}"))
    .bind(g)
    .bind(owner_client)
    .fetch_one(&pool)
    .await
    .expect("agent client");
    let g_family = el11_family(&pool, g_client).await;
    let url = listener(&pool, epigraph_db::AdminScopeArmingCache::DEFAULT_TTL, true).await;
    for client_type in ["agent", "human"] {
        let token = el11_token(
            g,
            g_client,
            Some(g_family),
            None,
            client_type,
            &["claims:read"],
        );
        let answer = el11_call(&url, &token, "sudo", serde_json::json!({"reason": "try"})).await;
        let refused = el11_error(&answer).unwrap_or_else(|| panic!("{client_type}: {answer}"));
        assert!(refused.contains("sudo refused"), "{client_type}: {refused}");
    }
    assert!(
        el11_tickets(&pool, g).await.is_empty(),
        "no ticket for the agent"
    );

    let server = app_server(&pool).await.with_connector_elevation(true);
    let stdio = server
        .sudo(
            rmcp::handler::server::wrapper::Parameters(epigraph_mcp::types::SudoParams {
                reason: "stdio".into(),
            }),
            rmcp::model::Extensions::default(),
        )
        .await;
    let refused = format!("{:?}", stdio.expect_err("stdio sudo is refused"));
    assert!(refused.contains("stdio"), "{refused}");
    let stdio = server.unsudo(rmcp::model::Extensions::default()).await;
    assert!(stdio.is_err(), "stdio unsudo is refused");
    let me = server.server_agent_id().await.expect("server agent");
    assert!(
        el11_tickets(&pool, me).await.is_empty(),
        "no ticket over stdio"
    );
}

/// The admin-only-scoped tools are listed as the scope gate would admit
/// them: a STANDING `claims:admin` token sees `delete_edge` while the switch
/// is unarmed (today's behaviour) and not once it is armed; an ELEVATED
/// request (the elevate grant's scopes) sees it armed. A token without the
/// scope never sees it.
///
/// Verified to fail with `list_tools` not reading the switch (the unarmed
/// holder loses it: the bearer's context starts armed), with admin tools
/// listed to every HTTP caller (armed, the standing token sees it), and with
/// `listing_auth` not resolving the elevation (the elevated request loses
/// it).
#[sqlx::test(migrations = "../../migrations")]
async fn the_manifest_lists_admin_tools_as_the_scope_gate_admits_them(pool: PgPool) {
    let (p, _) = fixture::seed_human_operator(&pool, "el11-admin-p").await;
    let (client, family) = make_holder(&pool, p, 35).await;
    let live = session(&pool, p, client, family, 35, "grant").await;
    let url = el8_listener_with(&pool, std::time::Duration::ZERO).await;
    let standing = el11_token(
        p,
        client,
        None,
        None,
        "human",
        &["claims:read", "claims:admin"],
    );
    let plain = el11_token(p, client, None, None, "human", &["claims:read"]);
    let elevated = el11_token(
        p,
        client,
        Some(family),
        Some(live),
        "human",
        &["claims:read", "platform:admin"],
    );
    let lists = |names: Vec<String>| names.iter().any(|n| n == "delete_edge");

    assert!(
        lists(el11_list(&url, &standing).await),
        "unarmed: the standing holder"
    );
    assert!(!lists(el11_list(&url, &plain).await), "no scope: never");
    set_admin_switch(&pool, true).await;
    assert!(
        !lists(el11_list(&url, &standing).await),
        "armed: a standing scope lists nothing"
    );
    assert!(
        lists(el11_list(&url, &elevated).await),
        "armed and elevated: listed"
    );
}
