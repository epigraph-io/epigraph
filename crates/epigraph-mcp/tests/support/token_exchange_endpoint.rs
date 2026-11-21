//! A kernel token endpoint for the federation tests: it serves ONLY the RFC
//! 8693 token-exchange grant, through the kernel's own exchange core
//! (`epigraph_auth::JwtConfig::exchange_token`, the function
//! `epigraph-api`'s `oauth::token_exchange` grant calls). What it leaves out
//! is the grant's database half (revocation denylist, client status), which
//! `epigraph-api/tests/token_exchange_grant.rs` covers against a real
//! database.
//!
//! It records every `subject_token` it is sent, so a test can tell where the
//! caller's bearer went.
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use epigraph_auth::{AccessTokenBinding, JwtConfig};
use epigraph_mcp::federation::client::TokenExchange;

/// The secret the endpoint signs with, and [`kernel_token`] mints with.
pub const SECRET: &[u8] = b"federation-token-exchange-test-secret!!";

/// A kernel access token (aud = the kernel) for a fresh principal holding
/// `scopes`, as the kernel's token endpoint would mint it.
#[must_use]
pub fn kernel_token(secret: &[u8], scopes: &[&str]) -> String {
    JwtConfig::from_secret(secret)
        .issue_access_token(
            uuid::Uuid::new_v4(),
            scopes.iter().map(|s| (*s).to_string()).collect(),
            "human",
            Some(uuid::Uuid::new_v4()),
            Some(uuid::Uuid::new_v4()),
            chrono::Duration::minutes(30),
            AccessTokenBinding::NONE,
        )
        .expect("mint a kernel token")
        .0
}

/// A running endpoint.
pub struct Endpoint {
    /// `http://127.0.0.1:<port>/oauth/token`.
    pub url: String,
    /// Every `subject_token` the endpoint was sent, in order.
    pub subjects: Arc<Mutex<Vec<String>>>,
}

impl Endpoint {
    /// A gateway client of this endpoint.
    #[must_use]
    pub fn exchange(&self) -> TokenExchange {
        TokenExchange::new(&self.url).expect("a loopback http URL is accepted")
    }
}

/// Serve the grant on an ephemeral loopback port, minting with `secret` for
/// the audiences in `audiences` only.
pub async fn spawn_token_endpoint(secret: &'static [u8], audiences: &[&str]) -> Endpoint {
    let allowed: Arc<Vec<String>> = Arc::new(audiences.iter().map(|a| (*a).to_string()).collect());
    let subjects: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let seen = subjects.clone();
    let handler = move |axum::extract::Form(form): axum::extract::Form<HashMap<String, String>>| {
        let allowed = allowed.clone();
        let seen = seen.clone();
        async move {
            let refuse = |error: &str| {
                (
                    axum::http::StatusCode::BAD_REQUEST,
                    axum::Json(serde_json::json!({ "error": error })),
                )
            };
            if form.get("grant_type").map(String::as_str)
                != Some(epigraph_auth::TOKEN_EXCHANGE_GRANT_TYPE)
                || form.get("subject_token_type").map(String::as_str)
                    != Some(epigraph_auth::ACCESS_TOKEN_TYPE)
            {
                return refuse("invalid_request");
            }
            let subject = form.get("subject_token").cloned().unwrap_or_default();
            seen.lock().unwrap().push(subject.clone());
            let scopes: Option<Vec<String>> = form
                .get("scope")
                .map(|s| s.split_whitespace().map(str::to_string).collect());
            match JwtConfig::from_secret(secret).exchange_token(
                &subject,
                form.get("audience").map(String::as_str).unwrap_or_default(),
                &allowed,
                scopes.as_deref(),
            ) {
                Ok(ex) => (
                    axum::http::StatusCode::OK,
                    axum::Json(serde_json::json!({
                        "access_token": ex.token,
                        "token_type": "Bearer",
                        "expires_in": ex.claims.exp - chrono::Utc::now().timestamp(),
                        "scope": ex.claims.scopes.join(" "),
                        "issued_token_type": epigraph_auth::ACCESS_TOKEN_TYPE,
                    })),
                ),
                Err(refusal) => refuse(refusal.oauth_error()),
            }
        }
    };
    let router = axum::Router::new().route("/oauth/token", axum::routing::post(handler));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    Endpoint {
        url: format!("http://{addr}/oauth/token"),
        subjects,
    }
}
