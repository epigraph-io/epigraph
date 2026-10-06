//! Shared application state, cloned into every handler.

use std::sync::Arc;

use axum::http::HeaderValue;

use crate::auth::flow::FlowState;
use crate::auth::{RequestAuth, SessionStore};
use crate::config::Config;
use crate::links::Links;
use crate::security;
use crate::ttl::ResponseCache;
use crate::upstream::capabilities::{Capabilities, CAPABILITY_TTL, UNKNOWN_CAPABILITY_TTL};
use crate::upstream::{Api, Upstream};

/// Everything is behind an `Arc` or is itself a cheap handle, so cloning is
/// a handful of refcount bumps.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub links: Links,
    pub upstream: Arc<Upstream>,
    pub sessions: SessionStore,
    /// Pending logins and embed handoff codes (auth area).
    pub auth_flow: FlowState,
    /// Per-viewer response cache (e.g. the 60 s `/bff/themes` cache). Key
    /// with [`RequestAuth::cache_key`].
    pub cache: ResponseCache,
    /// Precomputed `Content-Security-Policy` value.
    pub csp: HeaderValue,
    /// The same policy with `frame-ancestors 'none'`, for
    /// [`security::UNFRAMABLE_ROUTES`].
    pub csp_unframable: HeaderValue,
    /// Which optional API routes this deployment has (admin acts), as
    /// probed with a viewer's own token and remembered per process.
    pub capabilities: Arc<Capabilities>,
}

impl AppState {
    pub fn new(config: Config) -> anyhow::Result<Self> {
        let upstream = Upstream::new(&config)?;
        let csp = security::content_security_policy(&config.frame_ancestors)?;
        let csp_unframable = security::content_security_policy("'none'")?;
        Ok(Self {
            links: Links::new(&config.public_origin, &config.base_path),
            config: Arc::new(config),
            upstream: Arc::new(upstream),
            sessions: SessionStore::new(),
            auth_flow: FlowState::new(),
            cache: ResponseCache::new(),
            csp,
            csp_unframable,
            capabilities: Arc::new(Capabilities::new(CAPABILITY_TTL, UNKNOWN_CAPABILITY_TTL)),
        })
    }

    /// An upstream client bound to `auth` (usually via `Caller::api` /
    /// `SignedIn::api`).
    pub fn api(&self, auth: &RequestAuth) -> Api<'_> {
        Api::new(self, auth)
    }
}
