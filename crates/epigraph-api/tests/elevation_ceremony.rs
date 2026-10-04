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
use support::{hardware_bound, ClientUv, SoftAuthenticator, TestAttestation, ORIGIN, RP_ID};
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
    spawn_on(scoped, passkeys).await
}

/// The real router on a PRIVILEGED pool: the harness's superuser login, the
/// shape of a request unit whose DSN skips row security.
async fn spawn_privileged(pool: &PgPool) -> Server {
    let url = fixture::database_url_for(pool).await;
    let scoped = epigraph_db::ScopedPool::connect(&url, epigraph_db::SessionGucMode::Session)
        .await
        .expect("privileged pool");
    spawn_on(scoped, None).await
}

async fn spawn_on(scoped: epigraph_db::ScopedPool, passkeys: Option<Passkeys>) -> Server {
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

    /// [`Self::human_token`] with explicit scopes.
    fn scoped_token(&self, p: &Person, elv: Option<Uuid>, scopes: &[&str]) -> String {
        self.jwt
            .issue_access_token(
                p.client,
                scopes.iter().map(|s| (*s).to_string()).collect(),
                "human",
                None,
                Some(p.person),
                Duration::minutes(30),
                AccessTokenBinding {
                    family_id: Some(p.family),
                    elevation_id: elv,
                },
            )
            .expect("mint")
            .0
    }

    async fn get(&self, path: &str, token: &str) -> (StatusCode, Value) {
        let resp = self
            .http
            .get(self.url(path))
            .bearer_auth(token)
            .send()
            .await
            .unwrap();
        let status = resp.status();
        (status, resp.json().await.unwrap_or(Value::Null))
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
    enroll_with(pool, s, person, auth, Value::clone).await;
}

/// [`enroll`], with the authenticator's registration response passed through
/// `shape` first (a packed attestation for an allowlist relying party, or a
/// device-bound rewrite).
async fn enroll_with(
    pool: &PgPool,
    s: &Server,
    person: Uuid,
    auth: &mut SoftAuthenticator,
    shape: impl Fn(&Value) -> Value,
) {
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
    let response = shape(&auth.register(ORIGIN, options, ClientUv::AsRequested).await);
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

// =====================================================================
// The ceremony: /elevate/:ticket, /challenge, /assert
// =====================================================================

/// A grant-mode ticket for `p` (its id and redeem secret), through the API.
async fn open(s: &Server, p: &Person, reason: &str) -> (Uuid, String) {
    let (status, body) = s
        .open_ticket(&s.human_token(p, Some(p.family), None), reason)
        .await;
    assert_eq!(status, StatusCode::CREATED, "ticket: {body}");
    (
        body["ticket_id"].as_str().unwrap().parse().unwrap(),
        body["redeem_secret"].as_str().unwrap().to_string(),
    )
}

impl Server {
    async fn page(&self, ticket: Uuid) -> reqwest::Response {
        self.http
            .get(self.url(&format!("/elevate/{ticket}")))
            .send()
            .await
            .unwrap()
    }

    async fn challenge(&self, ticket: Uuid) -> (StatusCode, Value) {
        self.post(&format!("/elevate/{ticket}/challenge"), None, &json!({}))
            .await
    }

    async fn options(&self, ticket: Uuid) -> Value {
        let (status, options) = self.challenge(ticket).await;
        assert_eq!(status, StatusCode::OK, "challenge: {options}");
        options
    }

    async fn assert_raw(&self, ticket: Uuid, body: &str) -> (StatusCode, Value) {
        let resp = self
            .http
            .post(self.url(&format!("/elevate/{ticket}/assert")))
            .header("content-type", "application/json")
            .body(body.to_string())
            .send()
            .await
            .unwrap();
        let status = resp.status();
        (status, resp.json().await.unwrap_or(Value::Null))
    }

    async fn assert(&self, ticket: Uuid, response: &Value) -> (StatusCode, Value) {
        self.assert_raw(ticket, &response.to_string()).await
    }

    /// The whole ceremony by `auth` over a fresh challenge.
    async fn ceremony(&self, ticket: Uuid, auth: &mut SoftAuthenticator) -> (StatusCode, Value) {
        let options = self.options(ticket).await;
        let response = auth.authenticate(ORIGIN, options).await;
        self.assert(ticket, &response).await
    }
}

/// `(outcome, refusal, session_id)` of a ticket.
async fn ticket_row(pool: &PgPool, ticket: Uuid) -> (Option<String>, Option<String>, Option<Uuid>) {
    sqlx::query_as("SELECT outcome, refusal, session_id FROM elevation_tickets WHERE id = $1")
        .bind(ticket)
        .fetch_one(pool)
        .await
        .expect("the ticket")
}

async fn events(pool: &PgPool, event_type: &str, key: &str, id: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM security_events WHERE event_type = $1 AND details->>$2 = $3",
    )
    .bind(event_type)
    .bind(key)
    .bind(id.to_string())
    .fetch_one(pool)
    .await
    .expect("events")
}

async fn sessions_of(pool: &PgPool, person: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM elevation_sessions WHERE person_agent_id = $1")
        .bind(person)
        .fetch_one(pool)
        .await
        .expect("count sessions")
}

/// The ceremony end to end: the page, a challenge allowing ONLY the ticket
/// person's passkey with user verification required, the holder's assertion,
/// a session on the ticket's family with `platform.elevated`, and the ticket
/// used up (its page is gone).
///
/// Mutations: the confirm handed the library's counter as 0 or the BE flag as
/// false are caught by the counter and BE tests below; the routes unregistered
/// -> red here.
#[sqlx::test(migrations = "../../migrations")]
async fn the_ceremony_confirms_and_opens_a_session(pool: PgPool) {
    let s = spawn(&pool, Some(software())).await;
    let mut auth = SoftAuthenticator::new(MODEL);
    let p = holder(&pool, &s, "holder", &mut auth).await;
    let (ticket, _) = open(&s, &p, "read a report").await;
    assert_eq!(s.page(ticket).await.status(), StatusCode::OK);

    let options = s.options(ticket).await;
    assert_eq!(options["publicKey"]["userVerification"], "required");
    let allowed: Vec<Vec<u8>> = options["publicKey"]["allowCredentials"]
        .as_array()
        .expect("allowCredentials")
        .iter()
        .map(|c| {
            base64::Engine::decode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                c["id"].as_str().unwrap(),
            )
            .unwrap()
        })
        .collect();
    assert_eq!(allowed, vec![credential_of(&pool, p.person).await]);

    let response = auth.authenticate(ORIGIN, options).await;
    let (status, body) = s.assert(ticket, &response).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["outcome"], "confirmed");

    let (outcome, _, session) = ticket_row(&pool, ticket).await;
    assert_eq!(outcome.as_deref(), Some("confirmed"));
    let session = session.expect("a session");
    let (person, fam, mode): (Uuid, Uuid, String) = sqlx::query_as(
        "SELECT person_agent_id, family_id, mode FROM elevation_sessions WHERE id = $1",
    )
    .bind(session)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!((person, fam, mode.as_str()), (p.person, p.family, "grant"));
    assert_eq!(
        events(&pool, "platform.elevated", "session_id", session).await,
        1
    );
    assert_eq!(
        s.page(ticket).await.status(),
        StatusCode::NOT_FOUND,
        "used up"
    );
}

/// THE CONFUSED DEPUTY: P's passkey completing B's ticket (a hostile client
/// ignoring `allowCredentials`) is REFUSED, the ticket is burned, no session
/// opens for anyone, and `platform.elevation_refused` names the mismatch. B's
/// own passkey cannot then complete the burned ticket.
///
/// Mutation: the assertion of a credential outside the ticket person's
/// passkeys answered 400 without reaching the definer -> no refusal recorded,
/// no event, and B's later assertion confirms.
#[sqlx::test(migrations = "../../migrations")]
async fn another_persons_passkey_is_refused_and_audited(pool: PgPool) {
    let s = spawn(&pool, Some(software())).await;
    let mut p_auth = SoftAuthenticator::new(MODEL);
    let _p = holder(&pool, &s, "custodian-p", &mut p_auth).await;
    let mut b_auth = SoftAuthenticator::new(MODEL);
    let b = holder(&pool, &s, "custodian-b", &mut b_auth).await;
    let (ticket, _) = open(&s, &b, "B's request").await;

    let mut options = s.options(ticket).await;
    options["publicKey"]["allowCredentials"] = json!([]);
    let response = p_auth.authenticate(ORIGIN, options).await;
    let (status, body) = s.assert(ticket, &response).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["refusal"], "person_mismatch");

    let (outcome, refusal, session) = ticket_row(&pool, ticket).await;
    assert_eq!(
        (outcome.as_deref(), refusal.as_deref(), session),
        (Some("refused"), Some("person_mismatch"), None)
    );
    assert_eq!(
        events(&pool, "platform.elevation_refused", "ticket_id", ticket).await,
        1
    );
    let evidence_verified: Option<bool> = sqlx::query_scalar(
        "SELECT (assertion_evidence->>'verified')::boolean FROM elevation_tickets WHERE id = $1",
    )
    .bind(ticket)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(evidence_verified, Some(false), "recorded as unverified");

    assert_eq!(
        s.challenge(ticket).await.0,
        StatusCode::NOT_FOUND,
        "the burned ticket is not live"
    );
    let (status, _) = s.assert(ticket, &response).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "nor can it be asserted again"
    );
    let _ = &mut b_auth;
    assert_eq!(sessions_of(&pool, b.person).await, 0);
}

/// ELV05 through the API: an authenticator that replays a counter the
/// database already holds is refused AND audited
/// (`platform.passkey_counter_regressed`), which needs the definer, not the
/// library, to decide. Mutation: the challenge started COUNTED from the stored
/// counter -> the library refuses first: 400, no event.
#[sqlx::test(migrations = "../../migrations")]
async fn a_replayed_counter_is_refused_and_audited(pool: PgPool) {
    let s = spawn(&pool, Some(software())).await;
    let mut auth = SoftAuthenticator::new(MODEL).counting();
    let p = holder(&pool, &s, "holder", &mut auth).await;
    let (first, _) = open(&s, &p, "first").await;
    let (status, body) = s.ceremony(first, &mut auth).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "CALIBRATION: counter 1 confirms: {body}"
    );
    let (_, _, session) = ticket_row(&pool, first).await;
    let (status, _) = s
        .post(
            "/api/v1/elevation/end",
            Some(&s.human_token(&p, Some(p.family), None)),
            &json!({ "elevation_id": session }),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let (second, _) = open(&s, &p, "second").await;
    auth.set_counter(0); // the next assertion replays counter 1
    let (status, body) = s.ceremony(second, &mut auth).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(
        (body["refusal"].as_str(), body["code"].as_str()),
        (Some("counter_regressed"), Some("ELV05"))
    );
    assert_eq!(
        events(
            &pool,
            "platform.passkey_counter_regressed",
            "ticket_id",
            second
        )
        .await,
        1
    );
}

/// A passkey registered DEVICE-BOUND (BE clear) that later asserts
/// backup-eligible is refused, whichever layer catches it: BE with BS (backed
/// up) the library refuses itself (400); BE WITHOUT BS the library's passkey
/// path accepts as an "upgrade", so the asserted flag must reach the definer,
/// which refuses (`backup_eligibility_changed`, 403, audited). No session
/// either way.
///
/// Mutation: the confirm handed `backup_eligible: false` -> the BE-only case
/// confirms.
#[sqlx::test(migrations = "../../migrations")]
async fn a_device_bound_passkey_asserting_backup_eligible_is_refused(pool: PgPool) {
    let s = spawn(&pool, Some(software())).await;
    for (label, auth, want_status, want_refusal) in [
        (
            "backed-up",
            SoftAuthenticator::new(MODEL),
            StatusCode::BAD_REQUEST,
            None,
        ),
        (
            "eligible-only",
            SoftAuthenticator::new(MODEL).eligible_not_backed_up(),
            StatusCode::FORBIDDEN,
            Some("backup_eligibility_changed"),
        ),
    ] {
        let mut auth = auth;
        let p = person(&pool, label).await;
        fixture::make_custodian(&pool, p.person).await;
        enroll_with(&pool, &s, p.person, &mut auth, hardware_bound).await;
        let stored_be: bool = sqlx::query_scalar(
            "SELECT backup_eligible FROM person_authenticators WHERE person_agent_id = $1",
        )
        .bind(p.person)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(!stored_be, "CALIBRATION: {label} registered device-bound");

        let (ticket, _) = open(&s, &p, label).await;
        let (status, body) = s.ceremony(ticket, &mut auth).await;
        assert_eq!(status, want_status, "{label}: {body}");
        assert_eq!(body["refusal"].as_str(), want_refusal, "{label}: {body}");
        assert_eq!(sessions_of(&pool, p.person).await, 0, "{label}");
    }
}

/// The protocol-level "no or garbage assertion" negative: an assertion before
/// any challenge (409), a body that is not JSON or names no credential (400),
/// and the holder's own assertion with a tampered signature (400, the
/// library's refusal) each leave the ticket LIVE, unrefused and without a
/// session; the genuine assertion then confirms.
///
/// Mutation: a library refusal falling through to the confirm definer -> the
/// tampered assertion confirms (or burns) the ticket, and the genuine one
/// does not.
#[sqlx::test(migrations = "../../migrations")]
async fn a_garbage_or_unverified_assertion_leaves_the_ticket_live(pool: PgPool) {
    let s = spawn(&pool, Some(software())).await;
    let mut auth = SoftAuthenticator::new(MODEL);
    let p = holder(&pool, &s, "holder", &mut auth).await;
    let (ticket, _) = open(&s, &p, "garbage").await;

    let (status, body) = s.assert(ticket, &json!({})).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::CONFLICT, Some("no_ceremony_started"))
    );
    let options = s.options(ticket).await;
    assert_eq!(
        s.assert_raw(ticket, "not json").await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        s.assert(ticket, &json!({"id": "x", "type": "public-key"}))
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    let genuine = auth.authenticate(ORIGIN, options).await;
    let mut tampered = genuine.clone();
    let sig = tampered["response"]["signature"]
        .as_str()
        .unwrap()
        .to_string();
    let mut bytes =
        base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &sig).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    tampered["response"]["signature"] = Value::from(base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        &bytes,
    ));
    let (status, body) = s.assert(ticket, &tampered).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    assert_eq!(
        ticket_row(&pool, ticket).await,
        (None, None, None),
        "still live"
    );
    assert_eq!(
        events(&pool, "platform.elevation_refused", "ticket_id", ticket).await,
        0
    );
    assert_eq!(s.page(ticket).await.status(), StatusCode::OK);
    let (status, body) = s.assert(ticket, &genuine).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// EQ-1 (a) end to end: a passkey registered under the ALLOWLIST policy (an
/// attested credential) elevates through the passkey-authentication path.
/// The interop pin for the attested credential's serialized form, which the
/// enrollment tests never asserted with.
#[sqlx::test(migrations = "../../migrations")]
async fn an_attested_passkey_elevates(pool: PgPool) {
    let att = TestAttestation::new("Allowlisted");
    let rp = Passkeys::new(PasskeyConfig {
        rp_id: RP_ID.into(),
        origin: ORIGIN.parse().unwrap(),
        policy: AttestationPolicy::Allowlist {
            ca_pem: att.root_pem(),
            aaguids: [MODEL].into_iter().collect(),
        },
    })
    .expect("relying party");
    let s = spawn(&pool, Some(rp)).await;
    // A hardware key: `rewrap` clears BE/BS at registration, and a synced
    // authenticator would then assert BE and be refused (as it should be).
    let mut auth = SoftAuthenticator::new(MODEL).hardware();
    let p = person(&pool, "attested").await;
    fixture::make_custodian(&pool, p.person).await;
    enroll_with(&pool, &s, p.person, &mut auth, |r| att.rewrap(r)).await;
    let fmt: String = sqlx::query_scalar(
        "SELECT attestation_format FROM person_authenticators WHERE person_agent_id = $1",
    )
    .bind(p.person)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(fmt, "packed", "CALIBRATION: an attested registration");
    let (ticket, _) = open(&s, &p, "attested").await;
    let (status, body) = s.ceremony(ticket, &mut auth).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// The page escapes a hostile reason, loads only the binary's own script, and
/// every ceremony response carries the CSP and capability-URL headers.
/// Mutations: the reason interpolated without `html_escape` -> the raw tag;
/// the ticket page not passed through `harden` -> no CSP.
#[sqlx::test(migrations = "../../migrations")]
async fn the_ticket_page_escapes_and_carries_the_csp(pool: PgPool) {
    let s = spawn(&pool, Some(software())).await;
    let p = holder(&pool, &s, "holder", &mut SoftAuthenticator::new(MODEL)).await;
    let hostile = r#"<script>alert(1)</script><img src=x onerror="y">"#;
    let (ticket, _) = open(&s, &p, hostile).await;
    let page = s.page(ticket).await;
    let challenge = s
        .http
        .post(s.url(&format!("/elevate/{ticket}/challenge")))
        .send()
        .await
        .unwrap();
    let js = s
        .http
        .get(s.url("/elevate/assets/elevate.js"))
        .send()
        .await
        .unwrap();
    for (what, resp) in [("page", &page), ("challenge", &challenge), ("js", &js)] {
        assert_eq!(resp.status(), StatusCode::OK, "{what}");
        let h = resp.headers();
        assert!(
            h["content-security-policy"]
                .to_str()
                .unwrap()
                .starts_with("default-src 'none'; script-src 'self';"),
            "{what}"
        );
        assert_eq!(h["referrer-policy"], "no-referrer", "{what}");
        assert_eq!(h["cache-control"], "no-store", "{what}");
    }
    assert!(js.headers()["content-type"]
        .to_str()
        .unwrap()
        .starts_with("text/javascript"));
    let html = page.text().await.unwrap();
    assert!(!html.contains("<script>alert"), "{html}");
    assert!(!html.contains("<img"), "{html}");
    assert!(
        html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"),
        "{html}"
    );
    assert_eq!(html.matches("<script").count(), 1, "{html}");
    assert!(html.contains(r#"<script src="/elevate/assets/elevate.js"></script>"#));
}

/// No relying party: every ticket ceremony endpoint answers 503 even for a
/// live ticket. An unknown ticket is 404 on every endpoint.
#[sqlx::test(migrations = "../../migrations")]
async fn the_ceremony_fails_closed_unconfigured_and_on_an_unknown_ticket(pool: PgPool) {
    let configured = spawn(&pool, Some(software())).await;
    let p = holder(
        &pool,
        &configured,
        "holder",
        &mut SoftAuthenticator::new(MODEL),
    )
    .await;
    let (ticket, _) = open(&configured, &p, "unconfigured").await;
    let s = spawn(&pool, None).await;
    assert_eq!(
        s.page(ticket).await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(s.challenge(ticket).await.0, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        s.assert(ticket, &json!({})).await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    let unknown = Uuid::new_v4();
    assert_eq!(
        configured.page(unknown).await.status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(configured.challenge(unknown).await.0, StatusCode::NOT_FOUND);
    assert_eq!(
        configured.assert(unknown, &json!({})).await.0,
        StatusCode::NOT_FOUND
    );
}

// =====================================================================
// /oauth/token, grant_type=urn:epigraph:grant:elevate
// =====================================================================

const ELEVATE: &str = "urn:epigraph:grant:elevate";

impl Server {
    async fn redeem(&self, ticket: Uuid, secret: &str, client_id: &str) -> (StatusCode, Value) {
        self.post(
            "/oauth/token",
            None,
            &json!({
                "grant_type": ELEVATE,
                "ticket_id": ticket,
                "redeem_secret": secret,
                "client_id": client_id,
            }),
        )
        .await
    }
}

fn grant_error(r: &(StatusCode, Value)) -> (StatusCode, &str) {
    (r.0, r.1["error"].as_str().unwrap_or_default())
}

/// Give `p`'s human client these granted scopes.
async fn grant_scopes(pool: &PgPool, p: &Person, scopes: &[&str]) {
    sqlx::query("UPDATE oauth_clients SET granted_scopes = $2, allowed_scopes = $2 WHERE id = $1")
        .bind(p.client)
        .bind(scopes.iter().map(|s| (*s).to_string()).collect::<Vec<_>>())
        .execute(pool)
        .await
        .expect("granted scopes");
}

/// The grant mode end to end: `authorization_pending` until the ceremony
/// lands, then ONE elevated token, then `invalid_grant`. The token: the
/// holder as principal, `elv` = the session, `fam` = the ticket's family, the
/// client's scopes minus every standing admin scope plus `platform:admin`, at
/// most 15 minutes, and NO refresh token (the key is absent).
///
/// Mutations: "pending" answered as `invalid_grant` -> the first poll; the
/// response built with a refresh token -> the key is present; the binding
/// without `elv` -> the claim; `client.granted_scopes` minted unstripped ->
/// `claims:admin` present; the redemption run before nothing else changed
/// (second redeem answered `issued`) is the definer's, mutated in
/// `elevation_sessions.rs`.
#[sqlx::test(migrations = "../../migrations")]
async fn the_elevate_grant_waits_for_the_ceremony_then_issues_once(pool: PgPool) {
    let s = spawn(&pool, Some(software())).await;
    let mut auth = SoftAuthenticator::new(MODEL);
    let p = holder(&pool, &s, "holder", &mut auth).await;
    grant_scopes(&pool, &p, &["claims:read", "claims:admin", "groups:admin"]).await;
    let (ticket, secret) = open(&s, &p, "grant mode").await;

    let pending = s.redeem(ticket, &secret, &p.client_id).await;
    assert_eq!(
        grant_error(&pending),
        (StatusCode::BAD_REQUEST, "authorization_pending"),
        "{pending:?}"
    );
    let (status, body) = s.ceremony(ticket, &mut auth).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, _, session) = ticket_row(&pool, ticket).await;
    let session = session.expect("a session");

    let (status, body) = s.redeem(ticket, &secret, &p.client_id).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        body.get("refresh_token").is_none(),
        "no refresh token, not even null: {body}"
    );
    let claims = s
        .jwt
        .validate_token(body["access_token"].as_str().unwrap())
        .expect("a valid token");
    assert_eq!(claims.elv, Some(session), "elv names the session");
    assert_eq!(claims.fam, Some(p.family));
    assert_eq!(claims.agent_id, Some(p.person));
    assert_eq!(claims.sub, p.client);
    let mut scopes = claims.scopes.clone();
    scopes.sort();
    assert_eq!(scopes, vec!["claims:read", "platform:admin"]);
    assert_eq!(body["scope"], "claims:read platform:admin");
    let lifetime = claims.exp - claims.iat;
    assert!((880..=900).contains(&lifetime), "exp - iat = {lifetime}");
    assert_eq!(body["expires_in"].as_i64(), Some(lifetime));

    let again = s.redeem(ticket, &secret, &p.client_id).await;
    assert_eq!(
        grant_error(&again),
        (StatusCode::BAD_REQUEST, "invalid_grant")
    );
}

/// The elevated token is sudo READ (D2): redeemed for a client that holds
/// write scopes (`claims:write`, `agents:write`, `tasks:write`), it carries
/// none of them, only the client's read scopes and `platform:admin`. So a
/// route that authorizes a write on the token's SCOPES alone and writes on
/// the unscoped pool (never meeting `begin_as` or 126's refusals), here
/// `POST /api/v1/agents`, refuses it 403. Calibration: the same person's
/// ordinary token with `agents:write` creates the agent.
///
/// Mutations: `elevated_scopes` keeping the write scopes (the pre-cp1 shape)
/// -> the token carries `agents:write` and the agent is created.
#[sqlx::test(migrations = "../../migrations")]
async fn the_elevated_token_carries_no_write_scope(pool: PgPool) {
    let s = spawn(&pool, Some(software())).await;
    let mut auth = SoftAuthenticator::new(MODEL);
    let p = holder(&pool, &s, "holder", &mut auth).await;
    grant_scopes(
        &pool,
        &p,
        &[
            "claims:read",
            "claims:write",
            "agents:read",
            "agents:write",
            "tasks:write",
        ],
    )
    .await;
    let (ticket, secret) = open(&s, &p, "read only").await;
    let (status, body) = s.ceremony(ticket, &mut auth).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = s.redeem(ticket, &secret, &p.client_id).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let token = body["access_token"].as_str().unwrap().to_string();
    let mut scopes = s.jwt.validate_token(&token).expect("a valid token").scopes;
    scopes.sort();
    assert_eq!(scopes, vec!["agents:read", "claims:read", "platform:admin"]);

    let agent = |key: u8| json!({ "public_key": hex::encode([key; 32]), "display_name": "cp1" });
    let (status, body) = s.post("/api/v1/agents", Some(&token), &agent(0x11)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(body.to_string().contains("agents:write"), "{body}");

    let plain = s.scoped_token(&p, None, &["agents:write"]);
    let (status, body) = s.post("/api/v1/agents", Some(&plain), &agent(0x22)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "CALIBRATION: an ordinary token with agents:write creates it: {body}"
    );
}

/// The grant refuses, with one `invalid_grant` and WITHOUT spending the
/// ticket: a wrong secret, a malformed one, another client's `client_id`, an
/// unknown client; and a request missing a parameter is `invalid_request`.
/// The right triple then still issues.
///
/// Mutations: the secret hashed as its hex text -> the right triple is
/// refused; (125) the redemption's client clause dropped -> B's client
/// issues.
#[sqlx::test(migrations = "../../migrations")]
async fn the_elevate_grant_binds_the_secret_and_the_client(pool: PgPool) {
    let s = spawn(&pool, Some(software())).await;
    let mut auth = SoftAuthenticator::new(MODEL);
    let p = holder(&pool, &s, "holder", &mut auth).await;
    let b = person(&pool, "other").await;
    let (ticket, secret) = open(&s, &p, "binding").await;
    let (status, body) = s.ceremony(ticket, &mut auth).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let wrong = hex::encode([0x5a_u8; 32]);
    for (what, sec, client) in [
        ("wrong secret", wrong.as_str(), p.client_id.as_str()),
        ("malformed secret", "zz", p.client_id.as_str()),
        ("short secret", "abcd", p.client_id.as_str()),
        ("another client", secret.as_str(), b.client_id.as_str()),
        ("unknown client", secret.as_str(), "no-such-client"),
    ] {
        let r = s.redeem(ticket, sec, client).await;
        assert_eq!(
            grant_error(&r),
            (StatusCode::BAD_REQUEST, "invalid_grant"),
            "{what}: {r:?}"
        );
    }
    let r = s
        .post(
            "/oauth/token",
            None,
            &json!({"grant_type": ELEVATE, "redeem_secret": secret, "client_id": p.client_id}),
        )
        .await;
    assert_eq!(
        grant_error(&r),
        (StatusCode::BAD_REQUEST, "invalid_request")
    );

    let (status, body) = s.redeem(ticket, &secret, &p.client_id).await;
    assert_eq!(status, StatusCode::OK, "the refusals spent nothing: {body}");
}

/// The elevate grant never PROVISIONS a principal. A redeemable ticket names a
/// family whose client is already linked to the ticket's person (125's
/// `epigraph_family_of_person_is_live` requires `c.agent_id = p_person`), so a
/// client with no agent can hold no ticket; the grant answers it
/// `invalid_grant` from the client row alone and reaches neither the OAuth
/// principal mint (`ensure_for_client`) nor, through it, the personal-group
/// mint (`personal_group_mint_ratchet` registers exactly three
/// `principal_agent_id` sites in `oauth/token.rs`, the three grants that
/// legitimately provision). The client stays unlinked and no agent is created.
///
/// Mutation: the grant resolving its principal through `principal_agent_id`
/// (the cold path materialises an agent and links the client) -> the client is
/// linked.
#[sqlx::test(migrations = "../../migrations")]
async fn the_elevate_grant_never_provisions_a_principal(pool: PgPool) {
    let s = spawn(&pool, Some(software())).await;
    let client_id = format!("el5-unlinked-{}", Uuid::new_v4());
    let client: Uuid = sqlx::query_scalar(
        "INSERT INTO oauth_clients (client_id, client_name, client_type, allowed_scopes, \
                                    granted_scopes, status, agent_id) \
         VALUES ($1, 'el5-unlinked', 'human', ARRAY['claims:read'], ARRAY['claims:read'], \
                 'active', NULL) RETURNING id",
    )
    .bind(&client_id)
    .fetch_one(&pool)
    .await
    .expect("an unlinked human client");
    let agents = || async {
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM agents")
            .fetch_one(&pool)
            .await
            .expect("count agents")
    };
    let before = agents().await;

    let r = s
        .redeem(Uuid::new_v4(), &hex::encode([0x11_u8; 32]), &client_id)
        .await;
    assert_eq!(
        grant_error(&r),
        (StatusCode::BAD_REQUEST, "invalid_grant"),
        "{r:?}"
    );
    let linked: Option<Uuid> =
        sqlx::query_scalar("SELECT agent_id FROM oauth_clients WHERE id = $1")
            .bind(client)
            .fetch_one(&pool)
            .await
            .expect("the client");
    assert_eq!(linked, None, "the elevate grant linked a principal");
    assert_eq!(agents().await, before, "the elevate grant created an agent");
}

/// A ticket whose 5 minutes pass with no ceremony is `invalid_grant`, no
/// longer `authorization_pending`. Mutation: "invalid" answered as
/// `authorization_pending` -> pending forever.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unconfirmed_ticket_expires_into_invalid_grant(pool: PgPool) {
    let s = spawn(&pool, Some(software())).await;
    let p = holder(&pool, &s, "holder", &mut SoftAuthenticator::new(MODEL)).await;
    let (ticket, secret) = open(&s, &p, "expiring").await;
    {
        use sqlx::Executor;
        let mut conn = pool.acquire().await.unwrap();
        conn.execute("SET session_replication_role = replica")
            .await
            .unwrap();
        sqlx::query(
            "UPDATE elevation_tickets SET created_at = created_at - interval '10 minutes', \
                                          expires_at = expires_at - interval '10 minutes' \
              WHERE id = $1",
        )
        .bind(ticket)
        .execute(&mut *conn)
        .await
        .expect("age the ticket");
        conn.execute("SET session_replication_role = origin")
            .await
            .unwrap();
    }
    let r = s.redeem(ticket, &secret, &p.client_id).await;
    assert_eq!(grant_error(&r), (StatusCode::BAD_REQUEST, "invalid_grant"));
}

/// The elevated token never outlives the ASSIGNMENT: a custodian whose
/// assignment ends in 5 minutes gets a session (and a token) of at most 5
/// minutes, not 15. Mutation: the token's lifetime fixed at 15 minutes ->
/// exp - iat = 900.
#[sqlx::test(migrations = "../../migrations")]
async fn the_elevated_token_never_outlives_the_assignment(pool: PgPool) {
    let s = spawn(&pool, Some(software())).await;
    let mut auth = SoftAuthenticator::new(MODEL);
    let p = person(&pool, "short-assignment").await;
    let _assignment: Uuid = sqlx::query_scalar(
        "SELECT public.epigraph_grant_role('role:platform-custodian', $1, NULL, \
                now() + interval '5 minutes', NULL, 'test: a five-minute assignment')",
    )
    .bind(p.person)
    .fetch_one(&pool)
    .await
    .expect("a five-minute custodian");
    enroll(&pool, &s, p.person, &mut auth).await;
    let (ticket, secret) = open(&s, &p, "short").await;
    let (status, body) = s.ceremony(ticket, &mut auth).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = s.redeem(ticket, &secret, &p.client_id).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let claims = s
        .jwt
        .validate_token(body["access_token"].as_str().unwrap())
        .unwrap();
    let lifetime = claims.exp - claims.iat;
    assert!(
        (200..=300).contains(&lifetime),
        "the token lives with the assignment: {lifetime}"
    );
}

const REDIRECT_URI: &str = "https://claude.ai/api/mcp/auth_callback";
const VERIFIER: &str = "el5-fixed-pkce-code-verifier-of-adequate-length-0123456789";

/// One authorization code for `p`'s own human client.
async fn code_for(pool: &PgPool, p: &Person) -> String {
    use base64::Engine as _;
    let code = format!("code_{}", Uuid::new_v4().simple());
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(Sha256::digest(VERIFIER.as_bytes()));
    epigraph_db::repos::authorization_code::AuthorizationCodeRepository::create(
        pool,
        blake3::hash(code.as_bytes()).as_bytes(),
        &p.client_id,
        p.client,
        REDIRECT_URI,
        &challenge,
        &["claims:read".to_string()],
        None,
        chrono::Utc::now() + Duration::minutes(5),
    )
    .await
    .expect("seed code");
    code
}

/// No other grant mints `elv`: with the family ELEVATED (a live session from
/// the real ceremony), a code exchange and a refresh of that very family each
/// mint a token naming the family and NO elevation. (The external grant's
/// token is pinned the same way in `token_family_claim.rs`.)
///
/// Mutation: the refresh grant's binding given `elevation_id` -> the
/// refreshed token carries `elv`.
#[sqlx::test(migrations = "../../migrations")]
async fn no_other_grant_mints_elv_even_while_the_family_is_elevated(pool: PgPool) {
    let s = spawn(&pool, Some(software())).await;
    let mut auth = SoftAuthenticator::new(MODEL);
    let p = holder(&pool, &s, "holder", &mut auth).await;
    let code = code_for(&pool, &p).await;
    let (status, first) = s
        .post(
            "/oauth/token",
            None,
            &json!({
                "grant_type": "authorization_code",
                "code": code,
                "code_verifier": VERIFIER,
                "redirect_uri": REDIRECT_URI,
                "client_id": p.client_id,
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "code exchange: {first}");
    let token = first["access_token"].as_str().unwrap().to_string();
    let claims = s.jwt.validate_token(&token).unwrap();
    assert_eq!(claims.elv, None);
    let fam = claims.fam.expect("a family");

    // Elevate that family through the real API.
    let (status, t) = s
        .post(
            "/api/v1/elevation/tickets",
            Some(&token),
            &json!({"reason": "elevate the family"}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{t}");
    let ticket: Uuid = t["ticket_id"].as_str().unwrap().parse().unwrap();
    let (status, body) = s.ceremony(ticket, &mut auth).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, _, session) = ticket_row(&pool, ticket).await;
    let live_fam: Uuid =
        sqlx::query_scalar("SELECT family_id FROM elevation_sessions WHERE id = $1")
            .bind(session.unwrap())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        live_fam, fam,
        "CALIBRATION: the code grant's family is elevated"
    );

    let (status, refreshed) = s
        .post(
            "/oauth/token",
            None,
            &json!({"grant_type": "refresh_token", "refresh_token": first["refresh_token"]}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "refresh: {refreshed}");
    let rc = s
        .jwt
        .validate_token(refreshed["access_token"].as_str().unwrap())
        .unwrap();
    assert_eq!((rc.fam, rc.elv), (Some(fam), None));

    let code = code_for(&pool, &p).await;
    let (status, second) = s
        .post(
            "/oauth/token",
            None,
            &json!({
                "grant_type": "authorization_code",
                "code": code,
                "code_verifier": VERIFIER,
                "redirect_uri": REDIRECT_URI,
                "client_id": p.client_id,
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{second}");
    let sc = s
        .jwt
        .validate_token(second["access_token"].as_str().unwrap())
        .unwrap();
    assert_eq!(sc.elv, None);
}

/// `platform:admin` is minted ONLY by the elevate grant (review cp1: until the
/// admin-scope chokepoints exist, nothing stripped it from the other grants,
/// so a client whose `granted_scopes` held it would mint it on a code
/// exchange or a refresh and pre-arm any later check of it). A client holding
/// it gets neither a code-exchange token nor a refreshed token carrying it,
/// and neither response's `scope` names it; its other scope survives. The
/// auth crate's constant is the core crate's.
///
/// Mutations: the refresh site's strip dropped -> the refresh response's
/// `scope` names it (the token itself is still stripped by
/// `issue_access_token`, whose own mutation the auth crate's unit test
/// catches); the code-exchange site's strip dropped -> that response names it.
#[sqlx::test(migrations = "../../migrations")]
async fn no_grant_but_elevate_mints_platform_admin(pool: PgPool) {
    use base64::Engine as _;
    assert_eq!(
        epigraph_auth::ELEVATED_ONLY_SCOPE,
        epigraph_core::canonical_scopes::PLATFORM_ADMIN_SCOPE
    );
    let s = spawn(&pool, Some(software())).await;
    let p = holder(&pool, &s, "holder", &mut SoftAuthenticator::new(MODEL)).await;
    grant_scopes(&pool, &p, &["claims:read", "platform:admin"]).await;
    let code = format!("code_{}", Uuid::new_v4().simple());
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(Sha256::digest(VERIFIER.as_bytes()));
    epigraph_db::repos::authorization_code::AuthorizationCodeRepository::create(
        &pool,
        blake3::hash(code.as_bytes()).as_bytes(),
        &p.client_id,
        p.client,
        REDIRECT_URI,
        &challenge,
        &["claims:read".to_string(), "platform:admin".to_string()],
        None,
        chrono::Utc::now() + Duration::minutes(5),
    )
    .await
    .expect("seed code");
    let (status, first) = s
        .post(
            "/oauth/token",
            None,
            &json!({
                "grant_type": "authorization_code",
                "code": code,
                "code_verifier": VERIFIER,
                "redirect_uri": REDIRECT_URI,
                "client_id": p.client_id,
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "code exchange: {first}");
    let (status, refreshed) = s
        .post(
            "/oauth/token",
            None,
            &json!({"grant_type": "refresh_token", "refresh_token": first["refresh_token"]}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "refresh: {refreshed}");
    for (what, body) in [("code exchange", &first), ("refresh", &refreshed)] {
        let claims = s
            .jwt
            .validate_token(body["access_token"].as_str().unwrap())
            .unwrap();
        assert_eq!(claims.scopes, vec!["claims:read"], "{what}: the token");
        assert_eq!(body["scope"], "claims:read", "{what}: the response");
    }
}

// =====================================================================
// EL-6: what the elevated token's viewer may do through the real router
// =====================================================================

/// A body for `POST /api/v1/edges` that reaches the handler's write
/// transaction (the scope check passes; nothing is validated before it).
fn an_edge() -> Value {
    json!({
        "source_id": Uuid::new_v4(),
        "target_id": Uuid::new_v4(),
        "source_type": "claim",
        "target_type": "claim",
        "relationship": "supports",
    })
}

fn refused_as_elevated(body: &Value) -> bool {
    body.to_string().contains("ELEVATED READ-ONLY")
}

/// The elevated token (the elevate grant's: `elv` = a live session, `fam` =
/// its family) resolves an ELEVATED viewer: a write is refused 403 ELEVATED
/// READ-ONLY, a read of the caller's own private row still answers 200. The
/// same principal's unelevated token, a forged claim, and the claim of an
/// ENDED session all resolve the scoped viewer: the write is not refused for
/// elevation, and the request is served.
///
/// Verified to fail with the extractor ignoring the claim (always the scoped
/// viewer: the elevated write is not refused), and with `AppState::write_as`
/// mapping the refusal to a 500 (the status).
#[sqlx::test(migrations = "../../migrations")]
async fn an_elevated_token_reads_and_writes_nothing(pool: PgPool) {
    let s = spawn(&pool, Some(software())).await;
    let p = holder(&pool, &s, "holder", &mut SoftAuthenticator::new(MODEL)).await;
    let group: Uuid = sqlx::query_scalar(
        "SELECT id FROM groups WHERE did_key = 'did:epigraph:personal:' || $1::text",
    )
    .bind(p.person)
    .fetch_one(&pool)
    .await
    .expect("the personal group");
    let mine = fixture::seed_group_claim(&pool, p.person, group, "P's private row").await;
    let (_, t) = s
        .open_ticket(&s.human_token(&p, Some(p.family), None), "read")
        .await;
    let ticket: Uuid = t["ticket_id"].as_str().unwrap().parse().unwrap();
    let session = confirm_directly(&pool, ticket, credential_of(&pool, p.person).await).await;
    let scopes = ["claims:read", "edges:write"];
    let elevated = s.scoped_token(&p, Some(session), &scopes);

    let (status, body) = s.post("/api/v1/edges", Some(&elevated), &an_edge()).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(refused_as_elevated(&body), "{body}");
    let (status, body) = s.get(&format!("/api/v1/claims/{mine}"), &elevated).await;
    assert_eq!(status, StatusCode::OK, "an elevated read is served: {body}");

    for (what, token) in [
        ("the unelevated token", s.scoped_token(&p, None, &scopes)),
        (
            "a forged claim",
            s.scoped_token(&p, Some(Uuid::new_v4()), &scopes),
        ),
    ] {
        let (status, body) = s.post("/api/v1/edges", Some(&token), &an_edge()).await;
        assert!(
            !refused_as_elevated(&body),
            "{what}: refused as elevated ({status}): {body}"
        );
    }

    // The elevated token ends its own session (the route acts as the
    // principal), and its claim then resolves scoped: served, not refused.
    let resp = s
        .http
        .post(s.url("/api/v1/elevation/end"))
        .bearer_auth(&elevated)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let (status, body) = s.post("/api/v1/edges", Some(&elevated), &an_edge()).await;
    assert!(
        !refused_as_elevated(&body),
        "an ended session's claim is not elevated ({status}): {body}"
    );
    let (status, body) = s.get(&format!("/api/v1/claims/{mine}"), &elevated).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

// =====================================================================
// EL-7: what the elevated token reads through the real router once
// migration 126's arms are in
// =====================================================================

fn ids(v: &Value) -> Vec<String> {
    let items = v
        .get("items")
        .and_then(Value::as_array)
        .or_else(|| v.as_array())
        .cloned()
        .unwrap_or_default();
    items
        .iter()
        .filter_map(|i| i.get("id").and_then(Value::as_str).map(str::to_string))
        .collect()
}

/// A REPRESENTATIVE read set through the real router (plan EL-7: one list and
/// one by-id route per armed class the REST surface stamps): the claim by id
/// and in a list (T-OWN), its evidence (T-OWN, derived by 070), and an edge
/// between two of B's private claims (T-EDGE). The elevated token reads B's
/// private row on each, served 200 with no `ELEVATED READ-ONLY`, so no read
/// route here writes on the elevated connection; the same principal's
/// unelevated token reads none of them (the calibration that the rows ARE
/// private to P).
///
/// Verified to fail with each of 126's `claims_elevated_read`,
/// `evidence_elevated_read` and `edges_elevated_read` made USING (false) (the
/// elevated token no longer reads that row).
#[sqlx::test(migrations = "../../migrations")]
async fn an_elevated_token_reads_foreign_private_rows_through_the_router(pool: PgPool) {
    let s = spawn(&pool, Some(software())).await;
    let p = holder(&pool, &s, "holder", &mut SoftAuthenticator::new(MODEL)).await;
    let (b, b_group) = fixture::seed_agent_with_group(&pool, "el7-b").await;
    let claim = fixture::seed_group_claim(&pool, b, b_group, "zentrovium private claim").await;
    let other = fixture::seed_group_claim(&pool, b, b_group, "zentrovium other claim").await;
    let evidence = fixture::seed_evidence(&pool, claim, "observation").await;
    let edge = fixture::seed_edge(&pool, claim, other).await;
    let (_, t) = s
        .open_ticket(&s.human_token(&p, Some(p.family), None), "read")
        .await;
    let ticket: Uuid = t["ticket_id"].as_str().unwrap().parse().unwrap();
    let session = confirm_directly(&pool, ticket, credential_of(&pool, p.person).await).await;
    let scopes = ["claims:read", "edges:read", "evidence:read"];
    let elevated = s.scoped_token(&p, Some(session), &scopes);
    let plain = s.scoped_token(&p, None, &scopes);

    let reads: [(&str, String, Uuid); 4] = [
        ("claim by id", format!("/api/v1/claims/{claim}"), claim),
        (
            "claim list",
            "/claims?search=zentrovium&limit=100".to_string(),
            claim,
        ),
        (
            "claim evidence",
            format!("/api/v1/claims/{claim}/evidence"),
            evidence,
        ),
        (
            "edge list",
            format!("/api/v1/edges?source_id={claim}"),
            edge,
        ),
    ];
    for (what, path, want) in &reads {
        let (status, body) = s.get(path, &elevated).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "{what}: an elevated read is served: {body}"
        );
        assert!(!refused_as_elevated(&body), "{what}: {body}");
        let seen = if *what == "claim by id" {
            body.get("id").and_then(Value::as_str).map(str::to_string) == Some(want.to_string())
        } else {
            ids(&body).contains(&want.to_string())
        };
        assert!(
            seen,
            "{what}: the elevated token reads B's private row: {body}"
        );

        let (status, body) = s.get(path, &plain).await;
        let seen = status == StatusCode::OK
            && (body.get("id").and_then(Value::as_str) == Some(&want.to_string())
                || ids(&body).contains(&want.to_string()));
        assert!(
            !seen,
            "{what}: CALIBRATION: P unelevated does not read B's private row ({status}): {body}"
        );
    }
}

/// A request unit on a PRIVILEGED DSN never serves an elevated request
/// (review cp2: COR-1, SEC-02). The reviewer's measured failure: on such a
/// unit an elevated token holding only `claims:read` POSTed
/// `/api/v1/claims/{B's private claim}/assess`, the handler found the claim
/// through the elevated viewer's always-true fragment on the unstamped pool
/// and wrote a mass function and a new belief onto it (200), because no row
/// policy or RESTRICTIVE refusal applies to a login that skips row security.
/// Now the token resolves the principal's SCOPED viewer there: the read is
/// 404 and nothing is written. Calibrations, all with the same session: on
/// the application-role unit the elevated token READS B's claim (so the
/// session is live and elevates, before and after) and the plain token does
/// not (so the claim is private to P).
///
/// Verified to fail (the state it was written red against) with 125's
/// privileged-login conjuncts dropped from
/// `epigraph_elevation_session_is_live`: the privileged unit answers 200 to
/// the elevated GET and writes the mass function.
#[sqlx::test(migrations = "../../migrations")]
async fn a_privileged_unit_never_serves_an_elevated_request(pool: PgPool) {
    let app = spawn(&pool, Some(software())).await;
    let p = holder(&pool, &app, "holder", &mut SoftAuthenticator::new(MODEL)).await;
    let (b, b_group) = fixture::seed_agent_with_group(&pool, "cp2-b").await;
    let claim = fixture::seed_group_claim(&pool, b, b_group, "cp2 B private claim").await;
    let (_, t) = app
        .open_ticket(&app.human_token(&p, Some(p.family), None), "read")
        .await;
    let ticket: Uuid = t["ticket_id"].as_str().unwrap().parse().unwrap();
    let session = confirm_directly(&pool, ticket, credential_of(&pool, p.person).await).await;
    let read = format!("/api/v1/claims/{claim}");
    let assess = format!("/api/v1/claims/{claim}/assess");
    let body = json!({"evidence_type": "empirical", "methodology": "instrumental",
                      "confidence": 0.8, "supports": true});
    let written = || {
        let pool = pool.clone();
        async move {
            let mfs: i64 =
                sqlx::query_scalar("SELECT count(*) FROM mass_functions WHERE claim_id = $1")
                    .bind(claim)
                    .fetch_one(&pool)
                    .await
                    .unwrap();
            let belief: Option<f64> = sqlx::query_scalar("SELECT belief FROM claims WHERE id = $1")
                .bind(claim)
                .fetch_one(&pool)
                .await
                .unwrap();
            (mfs, belief)
        }
    };
    let before = written().await;

    let (status, body_seen) = app
        .get(
            &read,
            &app.scoped_token(&p, Some(session), &["claims:read"]),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "CALIBRATION: the session elevates on the application-role unit: {body_seen}"
    );
    let (status, _) = app
        .get(&read, &app.scoped_token(&p, None, &["claims:read"]))
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "CALIBRATION: unelevated, B's claim is private to P"
    );

    let privileged = spawn_privileged(&pool).await;
    let elevated = privileged.scoped_token(&p, Some(session), &["claims:read"]);
    let (status, seen) = privileged.get(&read, &elevated).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a privileged unit reads nothing past P's groups for an elevated token: {seen}"
    );
    let (status, seen) = privileged.post(&assess, Some(&elevated), &body).await;
    assert_ne!(
        status,
        StatusCode::OK,
        "a privileged unit writes nothing for an elevated token: {seen}"
    );
    assert_eq!(
        written().await,
        before,
        "no mass function and no belief written onto B's private claim"
    );

    let (status, _) = app
        .get(
            &read,
            &app.scoped_token(&p, Some(session), &["claims:read"]),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "CALIBRATION: the session is still live (the refusal was the login's)"
    );
}
