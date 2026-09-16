//! Short-lived sign-in state (plan §3.3).
//!
//! OWNED BY THE AUTH AREA — reshape freely; `AppState::auth_flow` holds one
//! `FlowState`.

use std::time::Duration;

use super::session::SessionId;
use crate::ttl::TtlMap;

/// Upstream's authorize session lives 10 minutes; ours need not outlive it.
pub const PENDING_LOGIN_TTL: Duration = Duration::from_secs(10 * 60);
/// Embed handoff codes are single-use and live 60 s.
pub const HANDOFF_TTL: Duration = Duration::from_secs(60);

/// Between `/auth/login` and `/auth/callback`, keyed by OAuth `state`.
#[derive(Clone, Debug)]
pub struct PendingLogin {
    pub pkce_verifier: String,
    /// Browser-visible local path to land on after sign-in.
    pub return_to: String,
    /// `mode=popup` (embed sign-in): the callback posts a handoff code to
    /// `window.opener` instead of setting a first-party cookie.
    pub popup: bool,
}

/// A popup-issued code the iframe redeems at `POST /auth/redeem`.
#[derive(Clone, Debug)]
pub struct Handoff {
    pub session_id: SessionId,
}

#[derive(Clone, Default)]
pub struct FlowState {
    /// OAuth `state` → pending login. Use `take` (single use).
    pub pending: TtlMap<String, PendingLogin>,
    /// Handoff code → session. Use `take` (single use).
    pub handoffs: TtlMap<String, Handoff>,
}

impl FlowState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn purge_expired(&self) -> usize {
        self.pending.purge_expired() + self.handoffs.purge_expired()
    }
}
