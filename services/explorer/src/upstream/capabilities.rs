//! Feature detection for API routes that only some deployments have.
//!
//! The admin-acts listing (`GET /api/v1/admin/acts`) exists only once the
//! elevation stack is deployed. `openapi.json` cannot tell: it lists none of
//! the elevation routes. So the Explorer asks the route itself, with the
//! viewer's own token ([`ADMIN_ACTS_PROBE`]), and reads the answer as a
//! tri-state ([`classify`]):
//!
//! | answer | [`Capability`] |
//! |---|---|
//! | 2xx with the listing's `{"acts": [...]}` envelope | `Present` |
//! | 403 | `Present`: the route exists, this viewer may not use it |
//! | 404 / 405 | `Absent` |
//! | 401 / session expired | `Unknown`: [`Api`] already turned a 401 into refresh-and-retry, so a 401 here is a session problem, not route evidence |
//! | anything else (5xx, timeout, transport, a 2xx of another shape) | `Unknown` |
//!
//! `Present` and `Absent` are facts about the deployment, not the viewer, so
//! they are remembered per process for [`CAPABILITY_TTL`], outside the
//! per-viewer page cache. `Unknown` is never remembered: one viewer's
//! transient failure must not hide the feature for everyone, so the next
//! page asks again. The UI shows the feature only on `Present`.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::de::IgnoredAny;
use serde::Deserialize;

use super::{Api, UpstreamError};

/// The probe request, byte for byte. The kernel's
/// `crates/epigraph-api/tests/unregistered_route_status_test.rs` sends the
/// same string to a router without the route and pins its 404.
pub const ADMIN_ACTS_PROBE: &str = "/api/v1/admin/acts?mine&limit=1";

/// How long a `Present` / `Absent` answer is trusted.
pub const CAPABILITY_TTL: Duration = Duration::from_secs(5 * 60);

/// Whether the API has a feature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    Present,
    Absent,
    Unknown,
}

impl Capability {
    pub fn is_present(self) -> bool {
        self == Capability::Present
    }
}

/// Just enough of the listing to recognise it.
#[derive(Deserialize)]
struct ActsEnvelope {
    #[allow(dead_code)] // its presence is the check
    acts: Vec<IgnoredAny>,
}

/// Read one probe answer (see the module table).
pub fn classify(answer: &Result<(), UpstreamError>) -> Capability {
    match answer {
        Ok(()) => Capability::Present,
        Err(UpstreamError::Forbidden { .. }) => Capability::Present,
        Err(UpstreamError::NotFound { .. }) => Capability::Absent,
        Err(UpstreamError::Rejected { status: 405, .. }) => Capability::Absent,
        Err(_) => Capability::Unknown,
    }
}

impl Api<'_> {
    /// [`ADMIN_ACTS_PROBE`]: `Ok` only for a 2xx carrying the listing's
    /// envelope; a 2xx of any other shape is a decode error.
    pub async fn probe_admin_acts(&self) -> Result<(), UpstreamError> {
        self.get::<ActsEnvelope>(ADMIN_ACTS_PROBE).await.map(|_| ())
    }
}

/// The per-process memory of probe answers.
pub struct Capabilities {
    ttl: Duration,
    admin_acts: Mutex<Option<(Instant, Capability)>>,
}

impl Capabilities {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            admin_acts: Mutex::new(None),
        }
    }

    fn slot(&self) -> std::sync::MutexGuard<'_, Option<(Instant, Capability)>> {
        self.admin_acts.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The remembered admin-acts answer, if one is still fresh. Never
    /// `Unknown`, which is never remembered. Error pages and auth pages read
    /// this and make no call.
    pub fn cached_admin_acts(&self) -> Option<Capability> {
        match *self.slot() {
            Some((until, cap)) if Instant::now() < until => Some(cap),
            _ => None,
        }
    }

    /// Record one answer: `Present` / `Absent` for the TTL; `Unknown` is
    /// dropped (and does not erase a fresh answer).
    pub fn remember_admin_acts(&self, cap: Capability) {
        if cap != Capability::Unknown {
            *self.slot() = Some((Instant::now() + self.ttl, cap));
        }
    }

    /// Whether the API has the admin-acts route: the remembered answer, or
    /// a probe with `api`'s (the viewer's) token.
    pub async fn admin_acts(&self, api: &Api<'_>) -> Capability {
        if let Some(cap) = self.cached_admin_acts() {
            return cap;
        }
        let cap = classify(&api.probe_admin_acts().await);
        self.remember_admin_acts(cap);
        cap
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rejected(status: u16) -> UpstreamError {
        UpstreamError::Rejected {
            status,
            kind: None,
            message: String::new(),
        }
    }

    #[test]
    fn classify_follows_the_mapping() {
        use Capability::*;
        let cases: Vec<(Result<(), UpstreamError>, Capability)> = vec![
            (Ok(()), Present),
            (
                Err(UpstreamError::Forbidden {
                    message: String::new(),
                }),
                Present,
            ),
            (
                Err(UpstreamError::NotFound {
                    message: String::new(),
                }),
                Absent,
            ),
            (Err(rejected(405)), Absent),
            (Err(rejected(400)), Unknown),
            (Err(rejected(429)), Unknown),
            (
                Err(UpstreamError::Unauthorized {
                    message: String::new(),
                }),
                Unknown,
            ),
            (Err(UpstreamError::SessionExpired), Unknown),
            (
                Err(UpstreamError::Server {
                    status: 500,
                    message: String::new(),
                }),
                Unknown,
            ),
            (Err(UpstreamError::Timeout), Unknown),
            (Err(UpstreamError::Transport("reset".into())), Unknown),
            (
                Err(UpstreamError::Decode("not the envelope".into())),
                Unknown,
            ),
        ];
        for (answer, want) in cases {
            assert_eq!(classify(&answer), want, "{answer:?}");
        }
    }

    #[test]
    fn only_present_and_absent_are_remembered_and_only_for_the_ttl() {
        let caps = Capabilities::new(Duration::from_millis(40));
        assert_eq!(caps.cached_admin_acts(), None);

        caps.remember_admin_acts(Capability::Unknown);
        assert_eq!(caps.cached_admin_acts(), None, "unknown is not remembered");

        caps.remember_admin_acts(Capability::Absent);
        assert_eq!(caps.cached_admin_acts(), Some(Capability::Absent));
        caps.remember_admin_acts(Capability::Unknown);
        assert_eq!(
            caps.cached_admin_acts(),
            Some(Capability::Absent),
            "an unknown answer does not erase a fresh one"
        );

        caps.remember_admin_acts(Capability::Present);
        assert_eq!(caps.cached_admin_acts(), Some(Capability::Present));
        std::thread::sleep(Duration::from_millis(60));
        assert_eq!(caps.cached_admin_acts(), None, "expired after the TTL");
    }
}
