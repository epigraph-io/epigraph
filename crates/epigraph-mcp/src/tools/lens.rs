//! Shared validation for the optional `(frame, perspective)` read lens.
//!
//! The four context-delivery read tools (`recall`, `recall_with_context`,
//! `get_claim`, `get_belief`) accept an optional `(frame_id, perspective_id)`
//! pair. This module centralises the parse + both-or-neither + existence
//! checks so the rule is identical across tools and the existence round-trips
//! run ONCE per call (before any per-claim page loop), not per claim.
//!
//! Note on not-found semantics: `get_perspective_belief` silently reduces an
//! unknown `perspective_id` to the global belief (the engine `unwrap_or_default`
//! reduce-to-global guarantee), so a typo'd UUID would otherwise return
//! global-as-lensed. The existence checks here surface that as an error instead.
//! The codebase has no dedicated not-found `ErrorCode`; per convention
//! (`ds.rs::get_belief`, `claims.rs::get_claim`) not-found is `INVALID_PARAMS`.

use epigraph_db::{FrameRepository, PerspectiveRepository, PgPool};
use uuid::Uuid;

use crate::errors::{internal_error, invalid_params, McpError};

/// Parse one optional lens UUID, naming the field on failure (spec §8 wants the
/// error to say *which* id was malformed).
fn parse_lens_uuid(field: &str, raw: &str) -> Result<Uuid, McpError> {
    Uuid::parse_str(raw).map_err(|e| invalid_params(format!("invalid {field} UUID: {e}")))
}

/// Resolve the both-or-neither lens pair to `Option<(frame_id, perspective_id)>`.
///
/// - both `None` → `Ok(None)` (today's lens-free behaviour).
/// - both `Some` → parse each (naming the field on error) → `Ok(Some((f, p)))`.
/// - exactly one `Some` → `invalid_params` (a lens needs both).
///
/// This is the rule for `recall`, `recall_with_context`, and `get_claim`.
/// `get_belief` has a one-sided rule (frame may appear alone); use
/// [`resolve_lens_get_belief`] there.
///
/// # Errors
/// `INVALID_PARAMS` when exactly one of the pair is supplied, or when a present
/// id is not a valid UUID.
pub fn resolve_lens(
    frame_id: Option<&str>,
    perspective_id: Option<&str>,
) -> Result<Option<(Uuid, Uuid)>, McpError> {
    match (frame_id, perspective_id) {
        (None, None) => Ok(None),
        (Some(f), Some(p)) => {
            let frame = parse_lens_uuid("frame_id", f)?;
            let perspective = parse_lens_uuid("perspective_id", p)?;
            Ok(Some((frame, perspective)))
        }
        (Some(_), None) | (None, Some(_)) => Err(invalid_params(
            "a lens needs both frame_id and perspective_id",
        )),
    }
}

/// Resolve the lens for `get_belief`, whose `frame_id` may legitimately appear
/// alone (its pre-existing framed-but-unlensed behaviour). The lens is active
/// only when `perspective_id` is present, and then `frame_id` is required.
///
/// Returns `Ok(None)` when no `perspective_id` was supplied (the caller keeps
/// its existing global/framed path); `Ok(Some((frame, perspective)))` when a
/// full lens is requested.
///
/// # Errors
/// `INVALID_PARAMS` when `perspective_id` is present without `frame_id`, or when
/// a present id is not a valid UUID.
pub fn resolve_lens_get_belief(
    frame_id: Option<&str>,
    perspective_id: Option<&str>,
) -> Result<Option<(Uuid, Uuid)>, McpError> {
    match perspective_id {
        None => Ok(None),
        Some(p) => {
            let frame = frame_id
                .ok_or_else(|| invalid_params("perspective_id requires frame_id for a lens"))?;
            let frame = parse_lens_uuid("frame_id", frame)?;
            let perspective = parse_lens_uuid("perspective_id", p)?;
            Ok(Some((frame, perspective)))
        }
    }
}

/// Verify both the frame and perspective exist BEFORE any belief compute, so a
/// typo'd UUID fails fast (and the page loop is never entered with a bad lens).
///
/// Must be called once per tool invocation, not per claim.
///
/// # Errors
/// `INVALID_PARAMS` naming the missing entity (codebase convention surfaces
/// not-found as `INVALID_PARAMS`; there is no separate not-found code).
/// `INTERNAL_ERROR` on a database failure.
pub async fn validate_lens_exists(
    pool: &PgPool,
    frame_id: Uuid,
    perspective_id: Uuid,
) -> Result<(), McpError> {
    if FrameRepository::get_by_id(pool, frame_id)
        .await
        .map_err(internal_error)?
        .is_none()
    {
        return Err(invalid_params(format!("frame {frame_id} not found")));
    }
    if PerspectiveRepository::get_by_id(pool, perspective_id)
        .await
        .map_err(internal_error)?
        .is_none()
    {
        return Err(invalid_params(format!(
            "perspective {perspective_id} not found"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_lens_both_absent_is_none() {
        assert!(resolve_lens(None, None).unwrap().is_none());
    }

    #[test]
    fn resolve_lens_only_one_present_errors() {
        // Both directions of the both-or-neither rule must reject.
        assert!(resolve_lens(Some(&Uuid::new_v4().to_string()), None).is_err());
        assert!(resolve_lens(None, Some(&Uuid::new_v4().to_string())).is_err());
    }

    #[test]
    fn resolve_lens_both_present_parses() {
        let f = Uuid::new_v4();
        let p = Uuid::new_v4();
        let got = resolve_lens(Some(&f.to_string()), Some(&p.to_string()))
            .unwrap()
            .unwrap();
        assert_eq!(got, (f, p));
    }

    #[test]
    fn resolve_lens_bad_uuid_names_the_field() {
        let p = Uuid::new_v4().to_string();
        let err = resolve_lens(Some("not-a-uuid"), Some(&p)).unwrap_err();
        assert!(err.message.contains("frame_id"), "msg: {}", err.message);
    }

    #[test]
    fn get_belief_frame_alone_is_unlensed() {
        // frame_id alone is legitimate for get_belief (framed-but-unlensed).
        assert!(
            resolve_lens_get_belief(Some(&Uuid::new_v4().to_string()), None)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn get_belief_perspective_without_frame_errors() {
        let p = Uuid::new_v4().to_string();
        assert!(resolve_lens_get_belief(None, Some(&p)).is_err());
    }

    #[test]
    fn get_belief_full_lens_parses() {
        let f = Uuid::new_v4();
        let p = Uuid::new_v4();
        let got = resolve_lens_get_belief(Some(&f.to_string()), Some(&p.to_string()))
            .unwrap()
            .unwrap();
        assert_eq!(got, (f, p));
    }
}
