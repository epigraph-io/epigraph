//! Degraded sections (plan §3.4): a failed or timed-out sub-call renders its
//! section as unavailable while the rest of the page still renders.
//!
//! Only [`UpstreamError::SessionExpired`] escapes as an error — the page must
//! send the viewer to sign in rather than render with holes.

use std::future::Future;

use serde::Serialize;

use super::UpstreamError;
use crate::error::AppError;

/// One page section's data, or why it is missing. Templates branch on it:
///
/// ```text
/// {% match belief %}
///   {% when Degraded::Available { data } %} … {{ data.pignistic_prob|fmt("{:?}") }} …
///   {% when Degraded::Unavailable { reason } %}
///     <p class="section-unavailable">{{ reason }}</p>
/// {% endmatch %}
/// ```
///
/// or, for a section that is simply hidden when missing:
///
/// ```text
/// {% if let Some(b) = belief.get() %} … {% endif %}
/// ```
///
/// Serializes (for `/bff/*` JSON) as `{"status":"ok","data":…}` or
/// `{"status":"unavailable","reason":"…"}`.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum Degraded<T> {
    #[serde(rename = "ok")]
    Available {
        data: T,
    },
    Unavailable {
        reason: String,
    },
}

// Struct variants keep the JSON self-describing for any `T` (an internally
// tagged newtype variant cannot hold a sequence); these helpers keep Rust
// call sites and templates short.
impl<T> Degraded<T> {
    pub fn ok(data: T) -> Self {
        Degraded::Available { data }
    }

    pub fn unavailable(reason: impl Into<String>) -> Self {
        Degraded::Unavailable {
            reason: reason.into(),
        }
    }

    /// The data if available (templates: `{% if let Some(b) = belief.get() %}`).
    pub fn get(&self) -> Option<&T> {
        match self {
            Degraded::Available { data } => Some(data),
            Degraded::Unavailable { .. } => None,
        }
    }

    pub fn into_option(self) -> Option<T> {
        match self {
            Degraded::Available { data } => Some(data),
            Degraded::Unavailable { .. } => None,
        }
    }

    pub fn is_available(&self) -> bool {
        matches!(self, Degraded::Available { .. })
    }

    /// Why the section is missing, if it is.
    pub fn reason(&self) -> Option<&str> {
        match self {
            Degraded::Available { .. } => None,
            Degraded::Unavailable { reason } => Some(reason),
        }
    }

    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Degraded<U> {
        match self {
            Degraded::Available { data } => Degraded::Available { data: f(data) },
            Degraded::Unavailable { reason } => Degraded::Unavailable { reason },
        }
    }
}

/// Turn a sub-call result into a section value. Every error except
/// `SessionExpired` becomes `Unavailable` with a viewer-safe sentence (and a
/// log line); `SessionExpired` propagates so `?` ends the page.
pub fn degrade<T>(result: Result<T, UpstreamError>) -> Result<Degraded<T>, AppError> {
    match result {
        Ok(data) => Ok(Degraded::ok(data)),
        Err(UpstreamError::SessionExpired) => Err(AppError::SessionExpired),
        Err(e) => {
            tracing::warn!(error = %e, "degraded section");
            Ok(Degraded::unavailable(e.user_message()))
        }
    }
}

/// Run same-typed sub-calls concurrently (all under the global upstream
/// semaphore) and degrade each result. Order matches the input.
pub async fn join_degraded<T, F, I>(calls: I) -> Result<Vec<Degraded<T>>, AppError>
where
    I: IntoIterator<Item = F>,
    F: Future<Output = Result<T, UpstreamError>>,
{
    futures::future::join_all(calls)
        .await
        .into_iter()
        .map(degrade)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn degrade_maps_errors() {
        assert_eq!(degrade(Ok::<_, UpstreamError>(3)).unwrap(), Degraded::ok(3));
        let d = degrade::<u8>(Err(UpstreamError::Timeout)).unwrap();
        assert_eq!(d.reason(), Some(UpstreamError::Timeout.user_message()));
        assert!(d.get().is_none());
        assert!(matches!(
            degrade::<u8>(Err(UpstreamError::SessionExpired)),
            Err(AppError::SessionExpired)
        ));
    }

    #[test]
    fn serializes_self_describing() {
        let ok = serde_json::to_value(Degraded::ok(1)).unwrap();
        assert_eq!(ok, serde_json::json!({"status": "ok", "data": 1}));
        let no = serde_json::to_value(Degraded::<u8>::unavailable("x")).unwrap();
        assert_eq!(
            no,
            serde_json::json!({"status": "unavailable", "reason": "x"})
        );
    }

    #[tokio::test]
    async fn join_preserves_order() {
        let calls = (0..3u8).map(|i| async move {
            if i == 1 {
                Err(UpstreamError::Transport("x".into()))
            } else {
                Ok(i)
            }
        });
        let out = join_degraded(calls).await.unwrap();
        assert_eq!(out[0], Degraded::ok(0));
        assert!(!out[1].is_available());
        assert_eq!(out[2], Degraded::ok(2));
    }
}
