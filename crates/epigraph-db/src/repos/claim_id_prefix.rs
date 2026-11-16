//! Abbreviated claim ids (backlog `30d8b667`): resolve an 8-or-more hex
//! prefix such as `30d8b667` to the claims it names, and tell which of a set of
//! claims are wired to a given claim by an edge.
//!
//! # Index-served, not `id::text LIKE`
//!
//! A prefix of a uuid's hex digits names a contiguous range of uuids: pad the
//! prefix with `0` for the lowest and with `f` for the highest. The match is
//! `id BETWEEN lo AND hi`, which the primary-key btree serves, where
//! `id::text LIKE prefix || '%'` would cast and scan every row of `claims`.
//!
//! # What a viewer cannot read is absent
//!
//! Both reads are viewer-spliced. A prefix that names only claims the viewer
//! cannot read returns no match, exactly like a prefix that names nothing, and
//! a hidden edge never counts as wiring.

use sqlx::FromRow;
use uuid::Uuid;

use crate::errors::DbError;

/// Fewest hex digits a prefix may carry. Eight is the abbreviation the
/// corpus's prose and backlog cite (`30d8b667`); fewer would make a
/// prefix-walk over the id space cheap and the matches mostly noise.
pub const MIN_ID_PREFIX_HEX: usize = 8;

/// Longest claim content a prefix match carries, in characters. Enough to
/// tell ambiguous matches apart; the full text is `get_claim`'s.
pub const ID_PREFIX_CONTENT_CHARS: i32 = 300;

/// The inclusive uuid range a hex prefix names, or `None` when `prefix` is not
/// 8 to 32 hex digits. Hyphens are ignored wherever they fall, so a prefix
/// copied from a hyphenated uuid (`30d8b667-0ca4`) works; case is ignored.
#[must_use]
pub fn id_prefix_bounds(prefix: &str) -> Option<(Uuid, Uuid)> {
    let hex: String = prefix
        .trim()
        .chars()
        .filter(|c| *c != '-')
        .map(|c| c.to_ascii_lowercase())
        .collect();
    if hex.len() < MIN_ID_PREFIX_HEX
        || hex.len() > 32
        || !hex.chars().all(|c| c.is_ascii_hexdigit())
    {
        return None;
    }
    let lo = format!("{hex:0<32}");
    let hi = format!("{hex:f<32}");
    Some((Uuid::parse_str(&lo).ok()?, Uuid::parse_str(&hi).ok()?))
}

/// One claim a prefix names.
#[derive(Debug, Clone, FromRow, PartialEq)]
pub struct ClaimIdPrefixMatch {
    pub id: Uuid,
    /// Clipped to [`ID_PREFIX_CONTENT_CHARS`] characters.
    pub content: String,
    pub content_truncated: bool,
    pub is_current: bool,
}

pub struct ClaimIdPrefixRepository;

impl ClaimIdPrefixRepository {
    /// The claims `viewer` may read whose id lies in `[lo, hi]` (from
    /// [`id_prefix_bounds`]), in id order, at most `limit` of them. An
    /// ambiguous prefix returns every match up to `limit`; the caller fetches
    /// `limit + 1` to learn whether there were more.
    ///
    /// # Errors
    /// Returns [`DbError`] when the query fails.
    pub async fn matches<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        lo: Uuid,
        hi: Uuid,
        limit: i64,
    ) -> Result<Vec<ClaimIdPrefixMatch>, DbError> {
        let sql = viewer.splice(
            "SELECT id, \
                    left(content, $4) AS content, \
                    char_length(content) > $4 AS content_truncated, \
                    COALESCE(is_current, true) AS is_current \
             FROM claims \
             WHERE id BETWEEN $1 AND $2 \
               /* {VISIBILITY:claims} */ \
             ORDER BY id \
             LIMIT $3",
            5,
        );
        let mut q = sqlx::query_as::<_, ClaimIdPrefixMatch>(&sql)
            .bind(lo)
            .bind(hi)
            .bind(limit)
            .bind(ID_PREFIX_CONTENT_CHARS);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(executor).await?)
    }

    /// Which of `candidates` share a live (unretracted: `valid_to` unset or in
    /// the future, as `ClaimContextRepository` reads it) edge with
    /// `claim_id` in either direction, of any relationship, counting only
    /// edges `viewer` may read.
    ///
    /// # Errors
    /// Returns [`DbError`] when the query fails.
    pub async fn wired_to<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        claim_id: Uuid,
        candidates: &[Uuid],
    ) -> Result<Vec<Uuid>, DbError> {
        if candidates.is_empty() {
            return Ok(Vec::new());
        }
        let sql = viewer.splice(
            "SELECT DISTINCT CASE WHEN e.source_id = $1 THEN e.target_id ELSE e.source_id END \
             FROM edges e \
             WHERE (e.valid_to IS NULL OR e.valid_to > now()) \
               AND ((e.source_id = $1 AND e.source_type = 'claim' \
                     AND e.target_type = 'claim' AND e.target_id = ANY($2)) \
                 OR (e.target_id = $1 AND e.target_type = 'claim' \
                     AND e.source_type = 'claim' AND e.source_id = ANY($2))) \
               /* {EDGE_VISIBILITY:e} */",
            3,
        );
        let mut q = sqlx::query_scalar::<_, Uuid>(&sql)
            .bind(claim_id)
            .bind(candidates);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(executor).await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eight_hex_digits_name_the_whole_range_under_them() {
        let (lo, hi) = id_prefix_bounds("30d8b667").expect("valid");
        assert_eq!(lo.to_string(), "30d8b667-0000-0000-0000-000000000000");
        assert_eq!(hi.to_string(), "30d8b667-ffff-ffff-ffff-ffffffffffff");
    }

    #[test]
    fn hyphens_and_case_are_ignored_and_a_full_id_names_itself() {
        let (lo, hi) = id_prefix_bounds("30D8B667-0CA4").expect("valid");
        assert_eq!(lo.to_string(), "30d8b667-0ca4-0000-0000-000000000000");
        assert_eq!(hi.to_string(), "30d8b667-0ca4-ffff-ffff-ffffffffffff");
        let full = "1a2b3c4d-0ca4-4b7f-aa85-000000000001";
        let (lo, hi) = id_prefix_bounds(full).expect("valid");
        assert_eq!((lo.to_string(), hi.to_string()), (full.into(), full.into()));
    }

    #[test]
    fn short_long_and_non_hex_prefixes_are_refused() {
        assert_eq!(id_prefix_bounds("30d8b66"), None);
        assert_eq!(id_prefix_bounds(""), None);
        assert_eq!(id_prefix_bounds("30d8b66g"), None);
        assert_eq!(id_prefix_bounds("30d8b667%"), None);
        assert_eq!(id_prefix_bounds(&"a".repeat(33)), None);
    }
}
