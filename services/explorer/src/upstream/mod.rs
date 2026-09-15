//! Typed client for epigraph-api.
//!
//! Every call goes through one global semaphore (`UPSTREAM_CONCURRENCY`, well
//! under the API's 10-connection pool) with a per-call timeout, forwards the
//! caller's own bearer (never a service token) or calls anonymously, and maps
//! every failure into [`UpstreamError`].
//!
//! 401 policy (plan §3.3): upstream answers a present-but-stale bearer with
//! 401 even on public routes. With a session, the client calls
//! [`crate::auth::refresh_session`] once, retries once with the new token, and
//! on a second 401 (or a failed refresh) drops the session and returns
//! [`UpstreamError::SessionExpired`].
//!
//! Area agents add typed methods as `impl Api<'_>` blocks in their own
//! `upstream/{core,entities,graph}.rs`, built on [`Api::get`],
//! [`Api::get_query`] and [`Api::post`].

use std::sync::{Arc, Mutex};
use std::time::Duration;

use reqwest::header::{ACCEPT, CONTENT_TYPE};
use reqwest::{Method, StatusCode};
use serde::de::DeserializeOwned;
use serde::Serialize;
use thiserror::Error;
use tokio::sync::Semaphore;
use uuid::Uuid;

use crate::auth::{self, RequestAuth};
use crate::config::Config;
use crate::state::AppState;

pub mod core;
pub mod degraded;
pub mod entities;
pub mod graph;
pub mod types;

pub use degraded::{degrade, join_degraded, Degraded};
pub use types::*;

/// Largest upstream body the BFF will buffer.
pub const MAX_UPSTREAM_BODY: usize = 8 * 1024 * 1024;
/// BFF-side cap on `/claims/:id/ego?max_degree=` (plan §3.5).
pub const MAX_EGO_DEGREE: u32 = 80;
/// Default ego degree when the caller has no preference (plan §2.2).
pub const DEFAULT_EGO_DEGREE: u32 = 40;
/// `/claims/:id/provenance-chain?max_depth=` range (plan §2.1).
pub const PROVENANCE_DEPTH_RANGE: (u32, u32) = (1, 8);
/// Longest error message carried from a text/plain upstream body.
const MAX_ERROR_MESSAGE_CHARS: usize = 300;

/// Every way an upstream call can fail. Handlers usually `?` it into
/// [`crate::error::AppError`] (required data) or pass it through
/// [`degrade`] (optional sections).
#[derive(Debug, Clone, Error, PartialEq)]
pub enum UpstreamError {
    /// Upstream 404, with its message (e.g. "Claim with ID … not found").
    #[error("not found: {message}")]
    NotFound { message: String },
    /// 401 on an anonymous or dev-bearer call: the route needs a (valid)
    /// bearer. Never returned for a session — see `SessionExpired`.
    #[error("unauthorized: {message}")]
    Unauthorized { message: String },
    /// 401 that survived refresh + retry, or a refresh that failed. The
    /// session has already been removed from the store.
    #[error("session expired")]
    SessionExpired,
    /// 403, e.g. `group_id` membership.
    #[error("forbidden: {message}")]
    Forbidden { message: String },
    /// Any other 4xx, including axum's text/plain 400 for a bad UUID.
    #[error("upstream rejected the request ({status}): {message}")]
    Rejected {
        status: u16,
        /// The `error` field of a JSON `ApiError` body (`"BadRequest"`, …).
        kind: Option<String>,
        message: String,
    },
    /// 5xx.
    #[error("upstream error ({status}): {message}")]
    Server { status: u16, message: String },
    /// The per-call timeout elapsed, waiting for a semaphore slot or for
    /// the response.
    #[error("upstream timed out")]
    Timeout,
    /// Connection refused/reset/dropped (a handler panic upstream drops the
    /// connection with no response).
    #[error("upstream transport error: {0}")]
    Transport(String),
    /// A 2xx body that did not match the DTO, an oversized body, an
    /// unexpected status class, or an unencodable request body.
    #[error("unexpected upstream response: {0}")]
    Decode(String),
}

impl UpstreamError {
    /// Short, viewer-safe sentence for a degraded section.
    pub fn user_message(&self) -> &'static str {
        match self {
            UpstreamError::NotFound { .. } => "Not found.",
            UpstreamError::Unauthorized { .. } => "Sign in to see this.",
            UpstreamError::SessionExpired => "Your session has expired. Sign in again.",
            UpstreamError::Forbidden { .. } => "You do not have access to this.",
            UpstreamError::Rejected { .. } => "The EpiGraph API rejected this request.",
            UpstreamError::Server { .. } | UpstreamError::Transport(_) => {
                "The EpiGraph API is unavailable right now."
            }
            UpstreamError::Timeout => "The EpiGraph API took too long to answer.",
            UpstreamError::Decode(_) => "The EpiGraph API sent an unexpected response.",
        }
    }
}

/// Process-wide upstream plumbing; one per [`AppState`].
pub struct Upstream {
    http: reqwest::Client,
    base: String,
    semaphore: Arc<Semaphore>,
    timeout: Duration,
}

impl Upstream {
    pub fn new(config: &Config) -> Result<Self, reqwest::Error> {
        let http = reqwest::Client::builder()
            .user_agent(concat!("epigraph-explorer/", env!("CARGO_PKG_VERSION")))
            // A redirect from the API is a bug; never replay a bearer to it.
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(config.upstream_timeout)
            .build()?;
        Ok(Self {
            http,
            base: config.api_url.as_str().trim_end_matches('/').to_string(),
            semaphore: Arc::new(Semaphore::new(config.upstream_concurrency)),
            timeout: config.upstream_timeout,
        })
    }

    /// The shared HTTP client (connection pool). The auth module uses it for
    /// `/oauth/token` and `/oauth/revoke`, which are not bearer calls.
    pub fn http(&self) -> &reqwest::Client {
        &self.http
    }

    /// API origin without a trailing slash, e.g. `http://127.0.0.1:8080`.
    pub fn base_url(&self) -> &str {
        &self.base
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Slots currently free in the global semaphore.
    pub fn available_permits(&self) -> usize {
        self.semaphore.available_permits()
    }
}

/// Raw result of one HTTP exchange.
struct Exchange {
    status: StatusCode,
    content_type: String,
    body: Vec<u8>,
}

/// A per-request view of the upstream client, bound to the caller's auth.
///
/// Build one per handler with [`AppState::api`]; share it by reference
/// across concurrent sub-calls (`tokio::join!`). After a refresh, later
/// calls through the same `Api` use the new token.
pub struct Api<'a> {
    state: &'a AppState,
    auth: RequestAuth,
    token: Mutex<Option<String>>,
}

impl<'a> Api<'a> {
    pub fn new(state: &'a AppState, auth: &RequestAuth) -> Self {
        Self {
            state,
            auth: auth.clone(),
            token: Mutex::new(auth.bearer().map(str::to_string)),
        }
    }

    pub fn auth(&self) -> &RequestAuth {
        &self.auth
    }

    fn current_token(&self) -> Option<String> {
        self.token.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// `GET {api}{path}` → `T`. `path` starts with `/api/v1/…`.
    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, UpstreamError> {
        self.send::<T, ()>(Method::GET, path, None, None).await
    }

    /// `GET {api}{path}?{query}`; `query` is anything `serde_urlencoded`
    /// accepts: `&[("q", "x")]`, a `#[derive(Serialize)]` struct, …
    /// (`Option` fields that are `None` are omitted).
    pub async fn get_query<T, Q>(&self, path: &str, query: &Q) -> Result<T, UpstreamError>
    where
        T: DeserializeOwned,
        Q: Serialize + ?Sized,
    {
        self.send(Method::GET, path, Some(query), None).await
    }

    /// `POST {api}{path}` with a JSON body.
    pub async fn post<T, B>(&self, path: &str, body: &B) -> Result<T, UpstreamError>
    where
        T: DeserializeOwned,
        B: Serialize + ?Sized,
    {
        let bytes = serde_json::to_vec(body)
            .map_err(|e| UpstreamError::Decode(format!("encoding request body: {e}")))?;
        self.send::<T, ()>(Method::POST, path, None, Some(bytes))
            .await
    }

    async fn send<T, Q>(
        &self,
        method: Method,
        path: &str,
        query: Option<&Q>,
        body: Option<Vec<u8>>,
    ) -> Result<T, UpstreamError>
    where
        T: DeserializeOwned,
        Q: Serialize + ?Sized,
    {
        let token = self.current_token();
        let first = self
            .exchange(&method, path, query, body.as_deref(), token.as_deref())
            .await?;
        if first.status != StatusCode::UNAUTHORIZED {
            return decode(first);
        }

        let RequestAuth::Session { id, .. } = &self.auth else {
            return Err(UpstreamError::Unauthorized {
                message: error_message(&first),
            });
        };

        let stale = token.unwrap_or_default();
        let fresh = match auth::refresh_session(self.state, id, &stale).await {
            Ok(t) => t,
            Err(e) => {
                tracing::info!(error = %e, %path, "upstream 401 and refresh failed; ending session");
                self.state.sessions.remove(id);
                return Err(UpstreamError::SessionExpired);
            }
        };
        *self.token.lock().unwrap_or_else(|p| p.into_inner()) = Some(fresh.clone());

        let second = self
            .exchange(&method, path, query, body.as_deref(), Some(&fresh))
            .await?;
        if second.status == StatusCode::UNAUTHORIZED {
            tracing::info!(%path, "upstream 401 after refresh; ending session");
            self.state.sessions.remove(id);
            return Err(UpstreamError::SessionExpired);
        }
        decode(second)
    }

    async fn exchange<Q>(
        &self,
        method: &Method,
        path: &str,
        query: Option<&Q>,
        body: Option<&[u8]>,
        bearer: Option<&str>,
    ) -> Result<Exchange, UpstreamError>
    where
        Q: Serialize + ?Sized,
    {
        let up = &self.state.upstream;
        let _permit = tokio::time::timeout(up.timeout, up.semaphore.acquire())
            .await
            .map_err(|_| {
                tracing::warn!(%path, "upstream semaphore wait timed out");
                UpstreamError::Timeout
            })?
            .map_err(|_| UpstreamError::Transport("upstream client shut down".into()))?;

        let url = format!("{}{}", up.base, path);
        let mut req = up
            .http
            .request(method.clone(), &url)
            .timeout(up.timeout)
            .header(ACCEPT, "application/json");
        if let Some(q) = query {
            req = req.query(q);
        }
        if let Some(t) = bearer {
            req = req.bearer_auth(t);
        }
        if let Some(b) = body {
            req = req
                .header(CONTENT_TYPE, "application/json")
                .body(b.to_vec());
        }

        let mut resp = req.send().await.map_err(|e| map_reqwest(e, path))?;
        let status = resp.status();
        let content_type = resp
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_ascii_lowercase();

        let mut buf = Vec::new();
        while let Some(chunk) = resp.chunk().await.map_err(|e| map_reqwest(e, path))? {
            if buf.len() + chunk.len() > MAX_UPSTREAM_BODY {
                return Err(UpstreamError::Decode(format!(
                    "response body over {MAX_UPSTREAM_BODY} bytes"
                )));
            }
            buf.extend_from_slice(&chunk);
        }

        if !status.is_success() {
            tracing::debug!(%path, status = status.as_u16(), "upstream non-success");
        }
        Ok(Exchange {
            status,
            content_type,
            body: buf,
        })
    }

    // ---- typed calls for the shared DTOs (upstream/types.rs) --------------

    /// `GET /api/v1/claims/:id`.
    pub async fn claim(&self, id: Uuid) -> Result<ClaimResponse, UpstreamError> {
        self.get(&format!("/api/v1/claims/{id}")).await
    }

    /// `GET /api/v1/claims/:id/belief`.
    pub async fn belief(&self, id: Uuid) -> Result<BeliefResponse, UpstreamError> {
        self.get(&format!("/api/v1/claims/{id}/belief")).await
    }

    /// `GET /api/v1/claims/:id/ego`; `max_degree` is clamped to
    /// `1..=MAX_EGO_DEGREE`. `relationships` is a comma-separated filter.
    pub async fn ego(
        &self,
        id: Uuid,
        max_degree: u32,
        relationships: Option<&str>,
    ) -> Result<EgoResponse, UpstreamError> {
        #[derive(Serialize)]
        struct Q<'r> {
            max_degree: u32,
            #[serde(skip_serializing_if = "Option::is_none")]
            relationships: Option<&'r str>,
        }
        let q = Q {
            max_degree: max_degree.clamp(1, MAX_EGO_DEGREE),
            relationships,
        };
        self.get_query(&format!("/api/v1/claims/{id}/ego"), &q)
            .await
    }

    /// `GET /api/v1/claims/:id/placement`.
    pub async fn placement(&self, id: Uuid) -> Result<PlacementResponse, UpstreamError> {
        self.get(&format!("/api/v1/claims/{id}/placement")).await
    }

    /// `GET /api/v1/stats`.
    pub async fn stats(&self) -> Result<StatsResponse, UpstreamError> {
        self.get("/api/v1/stats").await
    }

    /// `GET /api/v1/claims/:id/provenance-chain`; `max_depth` is clamped to
    /// `PROVENANCE_DEPTH_RANGE`.
    pub async fn provenance_chain(
        &self,
        id: Uuid,
        max_depth: u32,
        relationships: Option<&str>,
    ) -> Result<ProvenanceChainResponse, UpstreamError> {
        #[derive(Serialize)]
        struct Q<'r> {
            max_depth: u32,
            #[serde(skip_serializing_if = "Option::is_none")]
            relationships: Option<&'r str>,
        }
        let (lo, hi) = PROVENANCE_DEPTH_RANGE;
        let q = Q {
            max_depth: max_depth.clamp(lo, hi),
            relationships,
        };
        self.get_query(&format!("/api/v1/claims/{id}/provenance-chain"), &q)
            .await
    }
}

fn map_reqwest(e: reqwest::Error, path: &str) -> UpstreamError {
    if e.is_timeout() {
        tracing::warn!(%path, "upstream call timed out");
        UpstreamError::Timeout
    } else {
        tracing::warn!(%path, error = %e, "upstream transport error");
        UpstreamError::Transport(e.without_url().to_string())
    }
}

fn decode<T: DeserializeOwned>(x: Exchange) -> Result<T, UpstreamError> {
    let status = x.status;
    if status.is_success() {
        let body: &[u8] = if x.body.iter().all(u8::is_ascii_whitespace) {
            b"null"
        } else {
            &x.body
        };
        return serde_json::from_slice(body).map_err(|e| UpstreamError::Decode(e.to_string()));
    }

    let message = error_message(&x);
    Err(match status {
        StatusCode::NOT_FOUND => UpstreamError::NotFound { message },
        StatusCode::UNAUTHORIZED => UpstreamError::Unauthorized { message },
        StatusCode::FORBIDDEN => UpstreamError::Forbidden { message },
        s if s.is_client_error() => UpstreamError::Rejected {
            status: s.as_u16(),
            kind: api_error_body(&x).and_then(|b| b.error),
            message,
        },
        s if s.is_server_error() => UpstreamError::Server {
            status: s.as_u16(),
            message,
        },
        s => UpstreamError::Decode(format!("unexpected status {s}")),
    })
}

fn api_error_body(x: &Exchange) -> Option<ApiErrorBody> {
    if x.content_type.contains("json") {
        serde_json::from_slice(&x.body).ok()
    } else {
        None
    }
}

/// The human-readable message from an error response: `message` (else
/// `error`) of a JSON `ApiError` body, else the text/plain body, else the
/// status reason.
fn error_message(x: &Exchange) -> String {
    if let Some(body) = api_error_body(x) {
        if let Some(m) = body.message.or(body.error).filter(|m| !m.trim().is_empty()) {
            return truncate_chars(m.trim(), MAX_ERROR_MESSAGE_CHARS);
        }
    }
    let text = String::from_utf8_lossy(&x.body);
    let text = text.trim();
    if text.is_empty() {
        x.status
            .canonical_reason()
            .unwrap_or("upstream error")
            .to_string()
    } else {
        truncate_chars(text, MAX_ERROR_MESSAGE_CHARS)
    }
}

/// Truncate on a char boundary (never a byte slice), appending `…` if cut.
pub fn truncate_chars(s: &str, max_chars: usize) -> String {
    match s.char_indices().nth(max_chars) {
        Some((idx, _)) => format!("{}…", &s[..idx]),
        None => s.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ex(status: u16, ct: &str, body: &str) -> Exchange {
        Exchange {
            status: StatusCode::from_u16(status).unwrap(),
            content_type: ct.into(),
            body: body.as_bytes().to_vec(),
        }
    }

    #[test]
    fn json_error_bodies_are_parsed() {
        let e = decode::<serde_json::Value>(ex(
            404,
            "application/json",
            r#"{"error":"NotFound","message":"Claim with ID x not found","details":{"entity":"Claim"}}"#,
        ))
        .unwrap_err();
        assert_eq!(
            e,
            UpstreamError::NotFound {
                message: "Claim with ID x not found".into()
            }
        );

        let e = decode::<serde_json::Value>(ex(
            422,
            "application/json; charset=utf-8",
            r#"{"error":"ValidationError","message":"bad field"}"#,
        ))
        .unwrap_err();
        assert_eq!(
            e,
            UpstreamError::Rejected {
                status: 422,
                kind: Some("ValidationError".into()),
                message: "bad field".into()
            }
        );
    }

    #[test]
    fn text_plain_bodies_are_messages() {
        let e = decode::<serde_json::Value>(ex(
            400,
            "text/plain; charset=utf-8",
            "Invalid URL: UUID parsing failed",
        ))
        .unwrap_err();
        assert_eq!(
            e,
            UpstreamError::Rejected {
                status: 400,
                kind: None,
                message: "Invalid URL: UUID parsing failed".into()
            }
        );
        let e = decode::<serde_json::Value>(ex(500, "", "")).unwrap_err();
        assert_eq!(
            e,
            UpstreamError::Server {
                status: 500,
                message: "Internal Server Error".into()
            }
        );
        let e = decode::<serde_json::Value>(ex(403, "text/plain", "no")).unwrap_err();
        assert!(matches!(e, UpstreamError::Forbidden { .. }));
    }

    #[test]
    fn success_bodies_decode_or_fail_typed() {
        let v: Vec<u32> = decode(ex(200, "application/json", "[1,2]")).unwrap();
        assert_eq!(v, [1, 2]);
        let unit: Option<u32> = decode(ex(204, "", "")).unwrap();
        assert_eq!(unit, None);
        let e = decode::<Vec<u32>>(ex(200, "application/json", "{")).unwrap_err();
        assert!(matches!(e, UpstreamError::Decode(_)));
    }

    #[test]
    fn truncation_respects_char_boundaries() {
        assert_eq!(truncate_chars("héllo", 2), "hé…");
        assert_eq!(truncate_chars("μμμ", 3), "μμμ");
        assert_eq!(truncate_chars("", 0), "");
    }
}
