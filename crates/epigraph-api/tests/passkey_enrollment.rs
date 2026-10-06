#![cfg(feature = "db")]
//! The passkey enrollment ceremony (elevation plan EL-3), end to end through
//! the real router, on an APPLICATION-ROLE pool (`SET SESSION AUTHORIZATION
//! epigraph_app`, unstamped, as the anonymous page runs in production), with
//! an INDEPENDENT client and authenticator (`passkey-client` /
//! `passkey-authenticator`) and the packed attestation an allowlist relying
//! party needs built over its output
//! (`epigraph-passkey/tests/support/soft_authenticator.rs`).
//!
//! The enrollment is opened the way `epigraph-operator passkey-enroll` opens
//! it: migration 124's definer on a maintenance session.
//!
//! Every test names the mutation it was run against. The protocol refusals
//! (user verification, origin, rp id, attestation) are pinned here end to end
//! and mutated in the crate (`epigraph-passkey/tests/ceremony.rs`); the
//! mutations that matter to the ROUTES (escaping, headers, the 503) are run
//! here.

#[path = "viewer_fixture.rs"]
mod fixture;

#[path = "../../epigraph-passkey/tests/support/soft_authenticator.rs"]
mod support;

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::Arc;

use epigraph_passkey::{AttestationPolicy, PasskeyConfig, Passkeys};
use reqwest::StatusCode;
use serde_json::Value;
use sqlx::PgPool;
use support::{hardware_bound, ClientUv, SoftAuthenticator, TestAttestation, ORIGIN, RP_ID};
use tokio::sync::oneshot;
use uuid::Uuid;

/// The authenticator model the allowlist admits.
const MODEL: Uuid = Uuid::from_u128(0x2fc0_579f_8113_47ea_b116_bb5a_8db9_202a);
/// A model it does not.
const OTHER_MODEL: Uuid = Uuid::from_u128(0xcb69_481e_8ff7_4039_93ec_0a27_29a1_54a8);

/// Spelled here, not imported: a test that shares its subject's constant
/// cannot detect a change to it.
const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; \
                   frame-ancestors 'none'; base-uri 'none'; form-action 'none'";

fn allowlist(att: &TestAttestation) -> Passkeys {
    Passkeys::new(PasskeyConfig {
        rp_id: RP_ID.into(),
        origin: ORIGIN.parse().unwrap(),
        policy: AttestationPolicy::Allowlist {
            ca_pem: att.root_pem(),
            aaguids: [MODEL].into_iter().collect::<BTreeSet<_>>(),
        },
    })
    .expect("relying party")
}

fn software() -> Passkeys {
    Passkeys::new(PasskeyConfig {
        rp_id: RP_ID.into(),
        origin: ORIGIN.parse().unwrap(),
        policy: AttestationPolicy::SoftwareAllowed,
    })
    .expect("relying party")
}

/// The real router on an application-role pool over `pool`'s database.
async fn spawn(pool: &PgPool, passkeys: Option<Passkeys>) -> (SocketAddr, oneshot::Sender<()>) {
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
    (addr, tx)
}

/// A registered human and a live enrollment for it, opened on a maintenance
/// session exactly as `epigraph-operator passkey-enroll` opens one.
async fn enrollment(pool: &PgPool, reason: &str) -> (Uuid, Uuid) {
    let (human, _) = fixture::seed_human_operator(pool, "passkey-holder").await;
    let reason = reason.to_string();
    let id = fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let id: Uuid = sqlx::query_scalar(
            "SELECT public.epigraph_create_passkey_enrollment($1, $2, 'security key')",
        )
        .bind(human)
        .bind(&reason)
        .fetch_one(&mut *conn)
        .await
        .expect("open the enrollment");
        (conn, id)
    })
    .await;
    (human, id)
}

/// The passkeys recorded for `person`: (aaguid, format, user_verified).
async fn passkeys_of(pool: &PgPool, person: Uuid) -> Vec<(Uuid, String, bool)> {
    sqlx::query_as(
        "SELECT aaguid, attestation_format, user_verified FROM person_authenticators \
          WHERE person_agent_id = $1",
    )
    .bind(person)
    .fetch_all(pool)
    .await
    .expect("read passkeys")
}

struct Ceremony {
    base: String,
    http: reqwest::Client,
}

impl Ceremony {
    fn new(addr: SocketAddr, id: Uuid) -> Self {
        Self {
            base: format!("http://{addr}/elevate/enroll/{id}"),
            http: reqwest::Client::new(),
        }
    }

    async fn page(&self) -> reqwest::Response {
        self.http.get(&self.base).send().await.unwrap()
    }

    async fn challenge(&self) -> reqwest::Response {
        self.http
            .post(format!("{}/challenge", self.base))
            .send()
            .await
            .unwrap()
    }

    async fn options(&self) -> Value {
        let resp = self.challenge().await;
        assert_eq!(resp.status(), StatusCode::OK, "challenge");
        resp.json().await.unwrap()
    }

    async fn finish(&self, response: &Value) -> reqwest::Response {
        self.http
            .post(format!("{}/finish", self.base))
            .json(response)
            .send()
            .await
            .unwrap()
    }
}

async fn error_of(resp: reqwest::Response) -> (StatusCode, String) {
    let status = resp.status();
    let body: Value = resp.json().await.unwrap_or(Value::Null);
    (
        status,
        body["error"].as_str().unwrap_or_default().to_string(),
    )
}

/// The ceremony end to end: the page, the challenge, a packed attestation by
/// an allowlisted model, the passkey recorded with user verification, and the
/// enrollment consumed (a second finish is refused as not live).
#[sqlx::test(migrations = "../../migrations")]
async fn an_allowlisted_authenticator_enrolls(pool: PgPool) {
    let att = TestAttestation::new("Allowlisted");
    let (person, id) = enrollment(&pool, "first passkey").await;
    let (addr, _stop) = spawn(&pool, Some(allowlist(&att))).await;
    let c = Ceremony::new(addr, id);

    assert_eq!(c.page().await.status(), StatusCode::OK);
    let options = c.options().await;
    assert_eq!(
        options["publicKey"]["authenticatorSelection"]["userVerification"],
        "required"
    );
    assert_eq!(options["publicKey"]["rp"]["id"], RP_ID);
    let mut auth = SoftAuthenticator::new(MODEL);
    let response = att.rewrap(&auth.register(ORIGIN, options, ClientUv::AsRequested).await);
    let resp = c.finish(&response).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["attestation_format"], "packed");

    assert_eq!(
        passkeys_of(&pool, person).await,
        vec![(MODEL, "packed".to_string(), true)]
    );
    assert_eq!(c.page().await.status(), StatusCode::NOT_FOUND, "consumed");
    assert_eq!(
        error_of(c.finish(&response).await).await.0,
        StatusCode::NOT_FOUND
    );
}

/// D5: an authenticator response without user verification records nothing,
/// and the enrollment stays live for a retry.
#[sqlx::test(migrations = "../../migrations")]
async fn a_registration_without_user_verification_is_refused(pool: PgPool) {
    let att = TestAttestation::new("Allowlisted");
    let (person, id) = enrollment(&pool, "no uv").await;
    let (addr, _stop) = spawn(&pool, Some(allowlist(&att))).await;
    let c = Ceremony::new(addr, id);
    let mut auth = SoftAuthenticator::new(MODEL);
    let response = att.rewrap(
        &auth
            .register(ORIGIN, c.options().await, ClientUv::Skip)
            .await,
    );
    let (status, error) = error_of(c.finish(&response).await).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        error == "user_not_verified" || error == "registration_refused",
        "{error}"
    );
    assert!(passkeys_of(&pool, person).await.is_empty());
    assert_eq!(c.page().await.status(), StatusCode::OK, "still live");
}

/// A response made for another origin (a port, a subdomain) or another rp id
/// is refused and records nothing. Mutation (crate): `allow_any_port(true)` on
/// the relying party -> the port case enrolls.
#[sqlx::test(migrations = "../../migrations")]
async fn a_response_for_another_origin_or_rp_id_is_refused(pool: PgPool) {
    let att = TestAttestation::new("Allowlisted");
    let (person, id) = enrollment(&pool, "wrong origin").await;
    let (addr, _stop) = spawn(&pool, Some(allowlist(&att))).await;
    let c = Ceremony::new(addr, id);
    for (origin, rp_id) in [
        ("https://auth.example.com:8443", None),
        ("https://x.auth.example.com", None),
        (ORIGIN, Some("example.com")),
    ] {
        let mut options = c.options().await;
        if let Some(rp) = rp_id {
            options = SoftAuthenticator::with_rp_id(options, rp);
        }
        let mut auth = SoftAuthenticator::new(MODEL);
        let response = att.rewrap(&auth.register(origin, options, ClientUv::AsRequested).await);
        let (status, error) = error_of(c.finish(&response).await).await;
        assert_eq!(
            (status, error.as_str()),
            (StatusCode::BAD_REQUEST, "registration_refused"),
            "{origin} {rp_id:?}"
        );
    }
    assert!(passkeys_of(&pool, person).await.is_empty());
}

/// EQ-1 (a): an attestation that is not on the allowlist is refused: `none`
/// (a software authenticator, hardware-flagged so the refusal is the
/// attestation's) and a packed attestation of a model the allowlist does not
/// name. Mutation (crate): the allowlist relying party built with no CA list
/// -> the `none` case enrolls.
#[sqlx::test(migrations = "../../migrations")]
async fn an_attestation_off_the_allowlist_is_refused(pool: PgPool) {
    let att = TestAttestation::new("Allowlisted");
    let (person, id) = enrollment(&pool, "off the allowlist").await;
    let (addr, _stop) = spawn(&pool, Some(allowlist(&att))).await;
    let c = Ceremony::new(addr, id);
    for case in ["none", "unlisted model"] {
        let options = c.options().await;
        let response = if case == "none" {
            let mut auth = SoftAuthenticator::new(MODEL);
            hardware_bound(&auth.register(ORIGIN, options, ClientUv::AsRequested).await)
        } else {
            let mut auth = SoftAuthenticator::new(OTHER_MODEL);
            att.rewrap(&auth.register(ORIGIN, options, ClientUv::AsRequested).await)
        };
        let (status, error) = error_of(c.finish(&response).await).await;
        assert_eq!(
            (status, error.as_str()),
            (StatusCode::BAD_REQUEST, "registration_refused"),
            "{case}"
        );
    }
    assert!(passkeys_of(&pool, person).await.is_empty());
}

/// The test-only software policy accepts `none` attestation (the calibration
/// that the refusals above are the allowlist's), recorded with the nil AAGUID.
#[sqlx::test(migrations = "../../migrations")]
async fn the_software_policy_enrolls_a_software_authenticator(pool: PgPool) {
    let (person, id) = enrollment(&pool, "dev").await;
    let (addr, _stop) = spawn(&pool, Some(software())).await;
    let c = Ceremony::new(addr, id);
    let mut auth = SoftAuthenticator::new(MODEL);
    let response = auth
        .register(ORIGIN, c.options().await, ClientUv::AsRequested)
        .await;
    assert_eq!(c.finish(&response).await.status(), StatusCode::OK);
    assert_eq!(
        passkeys_of(&pool, person).await,
        vec![(Uuid::nil(), "none".to_string(), true)]
    );
}

/// The page escapes a hostile reason (it is operator-typed text, rendered on
/// an unauthenticated page). Mutation: the reason interpolated without
/// `html_escape` -> the raw tag appears.
#[sqlx::test(migrations = "../../migrations")]
async fn the_page_escapes_a_hostile_reason(pool: PgPool) {
    let hostile = r#"<script>alert(1)</script><img src=x onerror="y">&'"#;
    let (_, id) = enrollment(&pool, hostile).await;
    let (addr, _stop) = spawn(&pool, Some(software())).await;
    let html = Ceremony::new(addr, id).page().await.text().await.unwrap();
    assert!(!html.contains("<script>alert"), "{html}");
    assert!(!html.contains("<img"), "{html}");
    assert!(
        html.contains(
            "&lt;script&gt;alert(1)&lt;/script&gt;&lt;img src=x onerror=&quot;y&quot;&gt;&amp;&#39;"
        ),
        "{html}"
    );
    // The page's only script is the binary's own, by URL.
    assert_eq!(html.matches("<script").count(), 1, "{html}");
    assert!(html.contains(r#"<script src="/elevate/assets/enroll.js"></script>"#));
}

/// Every ceremony response carries the CSP and the capability-URL headers,
/// and the assets are served with their types. Mutation: the CSP insert in
/// `harden` removed -> the page has none.
#[sqlx::test(migrations = "../../migrations")]
async fn the_ceremony_responses_carry_the_csp(pool: PgPool) {
    let (_, id) = enrollment(&pool, "headers").await;
    let (addr, _stop) = spawn(&pool, Some(software())).await;
    let c = Ceremony::new(addr, id);
    let page = c.page().await;
    let challenge = c.challenge().await;
    let js = c
        .http
        .get(format!("http://{addr}/elevate/assets/enroll.js"))
        .send()
        .await
        .unwrap();
    let css = c
        .http
        .get(format!("http://{addr}/elevate/assets/elevate.css"))
        .send()
        .await
        .unwrap();
    for (what, resp) in [
        ("page", &page),
        ("challenge", &challenge),
        ("js", &js),
        ("css", &css),
    ] {
        assert_eq!(resp.status(), StatusCode::OK, "{what}");
        let h = resp.headers();
        assert_eq!(h["content-security-policy"], CSP, "{what}");
        assert_eq!(h["referrer-policy"], "no-referrer", "{what}");
        assert_eq!(h["cache-control"], "no-store", "{what}");
        assert_eq!(h["x-content-type-options"], "nosniff", "{what}");
    }
    assert!(page.headers()["content-type"]
        .to_str()
        .unwrap()
        .starts_with("text/html"));
    assert!(js.headers()["content-type"]
        .to_str()
        .unwrap()
        .starts_with("text/javascript"));
    assert!(css.headers()["content-type"]
        .to_str()
        .unwrap()
        .starts_with("text/css"));
}

/// No relying party configured: every enrollment endpoint answers 503, even
/// for a live enrollment, and nothing is recorded. Mutation: `passkeys()`
/// falls back to a default relying party when none is configured -> 200.
#[sqlx::test(migrations = "../../migrations")]
async fn without_a_relying_party_every_endpoint_answers_503(pool: PgPool) {
    let (person, id) = enrollment(&pool, "unconfigured").await;
    let (addr, _stop) = spawn(&pool, None).await;
    let c = Ceremony::new(addr, id);
    assert_eq!(c.page().await.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        error_of(c.challenge().await).await,
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "passkeys_not_configured".to_string()
        )
    );
    assert_eq!(
        c.finish(&serde_json::json!({})).await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(passkeys_of(&pool, person).await.is_empty());
}

/// An unknown enrollment is 404 on every endpoint (the page enumerates
/// nothing), and a finish before any challenge is 409.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unknown_or_unstarted_enrollment_is_refused(pool: PgPool) {
    let (_, id) = enrollment(&pool, "unstarted").await;
    let (addr, _stop) = spawn(&pool, Some(software())).await;
    let unknown = Ceremony::new(addr, Uuid::new_v4());
    assert_eq!(unknown.page().await.status(), StatusCode::NOT_FOUND);
    assert_eq!(unknown.challenge().await.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        unknown.finish(&serde_json::json!({})).await.status(),
        StatusCode::NOT_FOUND
    );
    let c = Ceremony::new(addr, id);
    assert_eq!(
        error_of(c.finish(&serde_json::json!({})).await).await,
        (StatusCode::CONFLICT, "no_ceremony_started".to_string())
    );
}
