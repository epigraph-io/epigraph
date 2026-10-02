#![cfg(feature = "db")]
//! Elevation over HTTP (elevation plan EL-5; operator rulings D2 and D5): the
//! ticket API, the ceremony page and its assertion, and the token endpoint's
//! elevate grant, through the REAL router on an APPLICATION-ROLE pool
//! (`SET SESSION AUTHORIZATION epigraph_app`), with every passkey registered
//! through the real enrollment ceremony by an INDEPENDENT authenticator
//! (`epigraph-passkey/tests/support/soft_authenticator.rs`).
//!
//! The rules themselves (who may elevate, the confused deputy, the counter,
//! the 15 minutes) are migration 125's and are mutated in
//! `epigraph-db/tests/elevation_sessions.rs`; what is pinned here is that the
//! API reaches them on the right connection with the right arguments, and
//! what it adds (the 503, the token shape, the grant's polling). Every test
//! names the mutation it was run against.

#[path = "viewer_fixture.rs"]
mod fixture;

#[path = "../../epigraph-passkey/tests/support/soft_authenticator.rs"]
mod support;

use std::net::SocketAddr;
use std::sync::Arc;

use chrono::Duration;
use epigraph_auth::{AccessTokenBinding, JwtConfig};
use epigraph_passkey::{AttestationPolicy, PasskeyConfig, Passkeys};
use reqwest::StatusCode;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use support::{ClientUv, SoftAuthenticator, ORIGIN, RP_ID};
use tokio::sync::oneshot;
use uuid::Uuid;

/// The authenticator model the test authenticators claim.
const MODEL: Uuid = Uuid::from_u128(0x2fc0_579f_8113_47ea_b116_bb5a_8db9_202a);

fn software() -> Passkeys {
    Passkeys::new(PasskeyConfig {
        rp_id: RP_ID.into(),
        origin: ORIGIN.parse().unwrap(),
        policy: AttestationPolicy::SoftwareAllowed,
    })
    .expect("relying party")
}

/// The real router on an application-role pool over `pool`'s database.
struct Server {
    addr: SocketAddr,
    jwt: Arc<JwtConfig>,
    http: reqwest::Client,
    _stop: oneshot::Sender<()>,
}

async fn spawn(pool: &PgPool, passkeys: Option<Passkeys>) -> Server {
    let url = fixture::database_url_for(pool).await;
    let scoped = epigraph_db::ScopedPool::connect_downgraded_for_tests(
        &url,
        epigraph_db::SessionGucMode::Session,
        "epigraph_app",
    )
    .await
    .expect("app-role pool");
    let state =
        epigraph_api::AppState::with_scoped_pool(scoped, epigraph_api::ApiConfig::default())
            .with_passkeys(passkeys.map(Arc::new));
    let jwt = state.jwt_config.clone();
    let app = epigraph_api::create_router(state);
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
    Server {
        addr,
        jwt,
        http: reqwest::Client::new(),
        _stop: tx,
    }
}

impl Server {
    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }

    async fn post(&self, path: &str, token: Option<&str>, body: &Value) -> (StatusCode, Value) {
        let mut req = self.http.post(self.url(path)).json(body);
        if let Some(t) = token {
            req = req.bearer_auth(t);
        }
        let resp = req.send().await.unwrap();
        let status = resp.status();
        (status, resp.json().await.unwrap_or(Value::Null))
    }

    /// A human token for `p`, naming `fam` (or no family).
    fn human_token(&self, p: &Person, fam: Option<Uuid>, elv: Option<Uuid>) -> String {
        self.jwt
            .issue_access_token(
                p.client,
                vec!["claims:read".into()],
                "human",
                None,
                Some(p.person),
                Duration::minutes(30),
                AccessTokenBinding {
                    family_id: fam,
                    elevation_id: elv,
                },
            )
            .expect("mint")
            .0
    }

    async fn open_ticket(&self, token: &str, reason: &str) -> (StatusCode, Value) {
        self.post(
            "/api/v1/elevation/tickets",
            Some(token),
            &json!({ "reason": reason }),
        )
        .await
    }
}

/// A registered human (an active `human` client and a live registry row).
#[derive(Clone, Debug)]
struct Person {
    person: Uuid,
    /// The human client's row id (the token's `sub`).
    client: Uuid,
    /// The human client's `client_id` (what the token endpoint takes).
    client_id: String,
    /// A live refresh family of that client.
    family: Uuid,
}

async fn person(pool: &PgPool, label: &str) -> Person {
    let (person, _) = fixture::seed_human_operator(pool, label).await;
    let (client, client_id): (Uuid, String) = sqlx::query_as(
        "SELECT id, client_id FROM oauth_clients WHERE agent_id = $1 AND client_type = 'human'",
    )
    .bind(person)
    .fetch_one(pool)
    .await
    .expect("the human's client");
    let family = family(pool, client).await;
    Person {
        person,
        client,
        client_id,
        family,
    }
}

/// A live refresh token of `client`, which is its own family.
async fn family(pool: &PgPool, client: Uuid) -> Uuid {
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

/// Register a passkey for `person` the way production does: the enrollment
/// opened on a maintenance session (`epigraph-operator passkey-enroll`), then
/// the page's challenge and finish over HTTP by `auth`.
async fn enroll(pool: &PgPool, s: &Server, person: Uuid, auth: &mut SoftAuthenticator) {
    let id = fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let id: Uuid = sqlx::query_scalar(
            "SELECT public.epigraph_create_passkey_enrollment($1, 'elevation test', 'key')",
        )
        .bind(person)
        .fetch_one(&mut *conn)
        .await
        .expect("open the enrollment");
        (conn, id)
    })
    .await;
    let base = format!("/elevate/enroll/{id}");
    let (status, options) = s.post(&format!("{base}/challenge"), None, &json!({})).await;
    assert_eq!(status, StatusCode::OK, "enrollment challenge: {options}");
    let response = auth.register(ORIGIN, options, ClientUv::AsRequested).await;
    let (status, body) = s.post(&format!("{base}/finish"), None, &response).await;
    assert_eq!(status, StatusCode::OK, "enrollment finish: {body}");
}

/// A platform custodian with one live passkey (on `auth`) and a family.
async fn holder(pool: &PgPool, s: &Server, label: &str, auth: &mut SoftAuthenticator) -> Person {
    let p = person(pool, label).await;
    fixture::make_custodian(pool, p.person).await;
    enroll(pool, s, p.person, auth).await;
    p
}

async fn tickets_of(pool: &PgPool, person: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM elevation_tickets WHERE person_agent_id = $1")
        .bind(person)
        .fetch_one(pool)
        .await
        .expect("count tickets")
}

/// A session for `p`'s ticket `ticket`, confirmed through migration 125's
/// ticket-keyed definers on an unstamped application session with synthetic
/// evidence (the ceremony's own path is pinned by the ceremony tests).
async fn confirm_directly(pool: &PgPool, ticket: Uuid, credential: Vec<u8>) -> Uuid {
    fixture::as_role(pool, "epigraph_app", |mut conn| async move {
        sqlx::query("SELECT public.epigraph_set_elevation_ticket_challenge($1, '{\"s\": 1}')")
            .bind(ticket)
            .execute(&mut *conn)
            .await
            .expect("challenge");
        let (outcome, session): (String, Option<Uuid>) = sqlx::query_as(
            "SELECT outcome, session_id \
               FROM public.epigraph_confirm_elevation($1, $2, 0, true, '{\"e\": 1}')",
        )
        .bind(ticket)
        .bind(credential)
        .fetch_one(&mut *conn)
        .await
        .expect("confirm");
        assert_eq!(outcome, "confirmed", "CALIBRATION: the direct confirm");
        (conn, session.expect("a session"))
    })
    .await
}

async fn credential_of(pool: &PgPool, person: Uuid) -> Vec<u8> {
    sqlx::query_scalar(
        "SELECT credential_id FROM person_authenticators \
          WHERE person_agent_id = $1 AND revoked_at IS NULL ORDER BY created_at LIMIT 1",
    )
    .bind(person)
    .fetch_one(pool)
    .await
    .expect("a live passkey")
}

async fn ended_reason(pool: &PgPool, session: Uuid) -> Option<String> {
    sqlx::query_scalar("SELECT ended_reason FROM elevation_sessions WHERE id = $1")
        .bind(session)
        .fetch_one(pool)
        .await
        .expect("the session")
}

// =====================================================================
// POST /api/v1/elevation/tickets
// =====================================================================

/// CALIBRATION for every refusal below: a custodian with a passkey, on its own
/// family, gets a GRANT-mode ticket for itself: the ceremony path, a secret
/// whose SHA-256 is what the row keeps, and its own client's `client_id`.
///
/// Mutations: the definer called on an unstamped `db_pool` connection -> 403
/// (ELV02); `TicketMode::Connector` -> the row's mode; the hash taken over the
/// hex text instead of the secret's bytes -> the stored hash; the client's row
/// id returned as `client_id` -> the client id.
#[sqlx::test(migrations = "../../migrations")]
async fn a_holder_gets_a_grant_mode_ticket(pool: PgPool) {
    let s = spawn(&pool, Some(software())).await;
    let mut auth = SoftAuthenticator::new(MODEL);
    let p = holder(&pool, &s, "holder", &mut auth).await;
    let (status, body) = s
        .open_ticket(&s.human_token(&p, Some(p.family), None), "read a report")
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let ticket: Uuid = body["ticket_id"].as_str().unwrap().parse().unwrap();
    assert_eq!(body["path"], format!("/elevate/{ticket}"));
    assert_eq!(body["client_id"], p.client_id);
    assert_eq!(body["grant_type"], "urn:epigraph:grant:elevate");
    let secret = hex::decode(body["redeem_secret"].as_str().unwrap()).expect("hex secret");
    assert_eq!(secret.len(), 32);

    let (person, client, fam, mode, reason, hash): (Uuid, Uuid, Uuid, String, String, Vec<u8>) =
        sqlx::query_as(
            "SELECT person_agent_id, client_id, family_id, mode, reason, redeem_secret_hash \
               FROM elevation_tickets WHERE id = $1",
        )
        .bind(ticket)
        .fetch_one(&pool)
        .await
        .expect("the ticket row");
    assert_eq!(
        (person, client, fam, mode.as_str(), reason.as_str()),
        (p.person, p.client, p.family, "grant", "read a report")
    );
    assert_eq!(hash, Sha256::digest(&secret).to_vec());
}

/// D2: a registered human with a passkey and a live family, but no
/// assignment of an elevating role, is refused (ELV02) and no ticket is
/// written. Mutation (125): the ticket guard's elevating-assignment check
/// dropped -> 201.
#[sqlx::test(migrations = "../../migrations")]
async fn a_ticket_is_refused_to_a_human_without_an_elevating_assignment(pool: PgPool) {
    let s = spawn(&pool, Some(software())).await;
    let p = person(&pool, "no-role").await;
    enroll(&pool, &s, p.person, &mut SoftAuthenticator::new(MODEL)).await;
    let (status, body) = s
        .open_ticket(&s.human_token(&p, Some(p.family), None), "try")
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(body.to_string().contains("ELV02"), "{body}");
    assert_eq!(tickets_of(&pool, p.person).await, 0);
}

/// D2: a principal with only a legacy `instance_admins` row (frozen since
/// 123; seeded with its triggers off) is refused: a standing flag is not an
/// elevation. Mutation (125): the guard keyed on "the role OR
/// `instance_admins`" -> 201.
#[sqlx::test(migrations = "../../migrations")]
async fn a_ticket_is_refused_to_an_instance_admins_only_principal(pool: PgPool) {
    let s = spawn(&pool, Some(software())).await;
    let p = person(&pool, "legacy-admin").await;
    enroll(&pool, &s, p.person, &mut SoftAuthenticator::new(MODEL)).await;
    {
        use sqlx::Executor;
        let mut conn = pool.acquire().await.unwrap();
        conn.execute("SET session_replication_role = replica")
            .await
            .unwrap();
        sqlx::query("INSERT INTO instance_admins (agent_id, note) VALUES ($1, 'legacy')")
            .bind(p.person)
            .execute(&mut *conn)
            .await
            .expect("legacy row");
        conn.execute("SET session_replication_role = origin")
            .await
            .unwrap();
    }
    let (status, body) = s
        .open_ticket(&s.human_token(&p, Some(p.family), None), "legacy")
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(tickets_of(&pool, p.person).await, 0);
}

/// An AGENT's token is refused by the DATABASE (ELV02: an agent holds no
/// role), even carrying a `fam` of its own client's live refresh row, so the
/// refusal is not merely the missing-family check. Mutation: as the first
/// refusal above.
#[sqlx::test(migrations = "../../migrations")]
async fn a_ticket_is_refused_to_an_agent(pool: PgPool) {
    let s = spawn(&pool, Some(software())).await;
    let (agent, _) = fixture::seed_agent_with_group(&pool, "agent").await;
    let owner = person(&pool, "owner").await;
    let client: Uuid = sqlx::query_scalar(
        "INSERT INTO oauth_clients (client_id, client_name, client_type, allowed_scopes, \
                                    granted_scopes, status, agent_id, owner_id) \
         VALUES ($1, 'el5-agent', 'agent', ARRAY['claims:read'], ARRAY['claims:read'], \
                 'active', $2, $3) RETURNING id",
    )
    .bind(format!("el5-agent-{agent}"))
    .bind(agent)
    .bind(owner.client)
    .fetch_one(&pool)
    .await
    .expect("agent client");
    let fam = family(&pool, client).await;
    let token = s
        .jwt
        .issue_access_token(
            client,
            vec!["claims:read".into()],
            "agent",
            Some(owner.client),
            Some(agent),
            Duration::minutes(15),
            AccessTokenBinding::family(fam),
        )
        .unwrap()
        .0;
    let (status, body) = s.open_ticket(&token, "agent").await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(body.to_string().contains("ELV02"), "{body}");
    assert_eq!(tickets_of(&pool, agent).await, 0);
}

/// A holder presenting ANOTHER person's family (a forged token: the HS256
/// secret's holder can mint one) is refused (ELV02: the family must be a live
/// family of the principal's OWN human client), whether the token names the
/// holder's client with B's family, or B's client and B's family with the
/// holder as principal. The second case is the one only the family OWNER
/// clause refuses (the first is also refused by the client clause).
/// Mutation (125): `AND c.agent_id = p_person` dropped from
/// `epigraph_family_of_person_is_live` -> the second case gets a ticket.
#[sqlx::test(migrations = "../../migrations")]
async fn a_ticket_is_refused_on_another_persons_family(pool: PgPool) {
    let s = spawn(&pool, Some(software())).await;
    let p = holder(&pool, &s, "holder", &mut SoftAuthenticator::new(MODEL)).await;
    let b = person(&pool, "other").await;
    let on_bs_client = Person {
        client: b.client,
        client_id: b.client_id.clone(),
        ..p.clone()
    };
    for (what, token) in [
        (
            "own client, B's family",
            s.human_token(&p, Some(b.family), None),
        ),
        (
            "B's client and family",
            s.human_token(&on_bs_client, Some(b.family), None),
        ),
    ] {
        let (status, body) = s.open_ticket(&token, "forged family").await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{what}: {body}");
    }
    assert_eq!(tickets_of(&pool, p.person).await, 0);
}

/// A token that names no refresh family is refused BEFORE the database, with
/// its own reason (a ticket binds a family; the database would refuse a made-up
/// one too, with ELV02, which is why the reason is asserted). Mutation: the
/// check removed and the nil family passed on -> the database's ELV02 text.
#[sqlx::test(migrations = "../../migrations")]
async fn a_token_without_a_family_gets_no_ticket(pool: PgPool) {
    let s = spawn(&pool, Some(software())).await;
    let p = holder(&pool, &s, "holder", &mut SoftAuthenticator::new(MODEL)).await;
    let (status, body) = s
        .open_ticket(&s.human_token(&p, None, None), "no fam")
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(
        body.to_string().contains("names no refresh family"),
        "{body}"
    );
    assert_eq!(tickets_of(&pool, p.person).await, 0);
}

/// No relying party configured: no ceremony could ever complete, so ticket
/// creation answers 503 and writes nothing. Mutation: the check removed ->
/// 201.
#[sqlx::test(migrations = "../../migrations")]
async fn without_a_relying_party_ticket_creation_answers_503(pool: PgPool) {
    let configured = spawn(&pool, Some(software())).await;
    let p = holder(
        &pool,
        &configured,
        "holder",
        &mut SoftAuthenticator::new(MODEL),
    )
    .await;
    let s = spawn(&pool, None).await;
    let (status, body) = s
        .open_ticket(&s.human_token(&p, Some(p.family), None), "unconfigured")
        .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(tickets_of(&pool, p.person).await, 0);
}

/// A reason is required (blank -> 400) and bounded (501 characters -> 400).
#[sqlx::test(migrations = "../../migrations")]
async fn a_ticket_needs_a_bounded_reason(pool: PgPool) {
    let s = spawn(&pool, Some(software())).await;
    let p = holder(&pool, &s, "holder", &mut SoftAuthenticator::new(MODEL)).await;
    let token = s.human_token(&p, Some(p.family), None);
    assert_eq!(
        s.open_ticket(&token, "   ").await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        s.open_ticket(&token, &"x".repeat(501)).await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        s.open_ticket(&token, &"x".repeat(500)).await.0,
        StatusCode::CREATED,
        "CALIBRATION: the bound is inclusive"
    );
}

// =====================================================================
// POST /api/v1/elevation/end
// =====================================================================

/// The caller ends its OWN session, by id or by presenting the elevated token;
/// another person's request names it and ends nothing; an ended session ends
/// once. Mutations: the handler ignoring the body's id (using only the
/// token's) -> P's by-id end answers false; `EndReason::Unsudo` -> the recorded
/// reason; the definer called unstamped -> nothing ends.
#[sqlx::test(migrations = "../../migrations")]
async fn the_end_route_ends_only_the_callers_own_session(pool: PgPool) {
    let s = spawn(&pool, Some(software())).await;
    let p = holder(&pool, &s, "holder", &mut SoftAuthenticator::new(MODEL)).await;
    let b = holder(&pool, &s, "other", &mut SoftAuthenticator::new(MODEL)).await;
    let p_token = s.human_token(&p, Some(p.family), None);

    let (_, t) = s.open_ticket(&p_token, "first").await;
    let ticket: Uuid = t["ticket_id"].as_str().unwrap().parse().unwrap();
    let session = confirm_directly(&pool, ticket, credential_of(&pool, p.person).await).await;

    let (status, body) = s
        .post(
            "/api/v1/elevation/end",
            Some(&s.human_token(&b, Some(b.family), None)),
            &json!({ "elevation_id": session }),
        )
        .await;
    assert_eq!(
        (status, body["ended"].as_bool()),
        (StatusCode::OK, Some(false))
    );
    assert_eq!(ended_reason(&pool, session).await, None, "B ended nothing");

    let (status, body) = s
        .post(
            "/api/v1/elevation/end",
            Some(&p_token),
            &json!({ "elevation_id": session }),
        )
        .await;
    assert_eq!(
        (status, body["ended"].as_bool()),
        (StatusCode::OK, Some(true))
    );
    assert_eq!(ended_reason(&pool, session).await.as_deref(), Some("ended"));
    let (_, body) = s
        .post(
            "/api/v1/elevation/end",
            Some(&p_token),
            &json!({ "elevation_id": session }),
        )
        .await;
    assert_eq!(body["ended"].as_bool(), Some(false), "ends once");

    // By the elevated token's own `elv`, with no body.
    let (_, t) = s.open_ticket(&p_token, "second").await;
    let ticket: Uuid = t["ticket_id"].as_str().unwrap().parse().unwrap();
    let second = confirm_directly(&pool, ticket, credential_of(&pool, p.person).await).await;
    let resp = s
        .http
        .post(s.url("/api/v1/elevation/end"))
        .bearer_auth(s.human_token(&p, Some(p.family), Some(second)))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.json::<Value>().await.unwrap()["ended"], true);
    assert_eq!(ended_reason(&pool, second).await.as_deref(), Some("ended"));

    // Nothing named, no elevated token: 400.
    let resp = s
        .http
        .post(s.url("/api/v1/elevation/end"))
        .bearer_auth(&p_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// A second ticket while the family is elevated is refused (409, ELV06).
#[sqlx::test(migrations = "../../migrations")]
async fn an_elevated_family_gets_no_second_ticket(pool: PgPool) {
    let s = spawn(&pool, Some(software())).await;
    let p = holder(&pool, &s, "holder", &mut SoftAuthenticator::new(MODEL)).await;
    let token = s.human_token(&p, Some(p.family), None);
    let (_, t) = s.open_ticket(&token, "first").await;
    let ticket: Uuid = t["ticket_id"].as_str().unwrap().parse().unwrap();
    confirm_directly(&pool, ticket, credential_of(&pool, p.person).await).await;
    let (status, body) = s.open_ticket(&token, "second").await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
}
