//! The list-endpoint pagination convention: one envelope for NEW list
//! endpoints.
//!
//! The convention itself (query `after` + `limit`, response `next_cursor`,
//! when a cursor is signed, what a cursor must never encode, and which
//! endpoints are legacy) is written down in
//! `docs/conventions/api-pagination.md` at the repository root. Read it before
//! adding a list endpoint.
//!
//! This module holds only [`Page`], the envelope a new list endpoint answers
//! with. Existing endpoints keep their own envelopes (`claims`, `results`,
//! ...): renaming a field their clients parse would be a breaking change.
//! `GET /api/v1/recall-events` (`routes/recall_events.rs`) is the first
//! adopter.

use serde::Serialize;

/// One page of a list endpoint: `{"items": [...], "next_cursor": ...}`.
///
/// `next_cursor` is the opaque token the client passes back as `?after=` for
/// the next page, and `null` on the last page. An endpoint that emits it only
/// when another row exists (by reading one row past the page) never makes a
/// client fetch an empty page to learn it is done.
#[derive(Debug, Clone, Serialize)]
pub struct Page<T> {
    /// The rows of this page, in the endpoint's documented order.
    pub items: Vec<T>,
    /// The `?after=` of the next page; `null` when there is none.
    pub next_cursor: Option<String>,
}

impl<T> Page<T> {
    /// Cut `rows`, read with one row past `limit`, into a page: when more
    /// than `limit` rows came back the extra row is dropped and `cursor_of`
    /// names the last row kept; otherwise there is no next page.
    #[must_use]
    pub fn from_overfetch(
        mut rows: Vec<T>,
        limit: usize,
        cursor_of: impl FnOnce(&T) -> String,
    ) -> Self {
        let more = rows.len() > limit;
        rows.truncate(limit);
        let next_cursor = if more {
            rows.last().map(cursor_of)
        } else {
            None
        };
        Self {
            items: rows,
            next_cursor,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Page;

    #[test]
    fn a_full_overfetch_names_the_last_kept_row() {
        let page = Page::from_overfetch(vec![5, 4, 3], 2, |n| format!("c{n}"));
        assert_eq!(page.items, vec![5, 4]);
        assert_eq!(page.next_cursor.as_deref(), Some("c4"));
    }

    #[test]
    fn a_short_or_exact_read_is_the_last_page() {
        let exact = Page::from_overfetch(vec![5, 4], 2, |n| format!("c{n}"));
        assert_eq!(exact.items, vec![5, 4]);
        assert_eq!(exact.next_cursor, None);
        let empty = Page::<i32>::from_overfetch(vec![], 2, |n| format!("c{n}"));
        assert!(empty.items.is_empty());
        assert_eq!(empty.next_cursor, None);
    }

    #[test]
    fn the_envelope_serialises_null_at_the_end() {
        let page = Page::<i32>::from_overfetch(vec![1], 5, |n| n.to_string());
        assert_eq!(
            serde_json::to_value(&page).unwrap(),
            serde_json::json!({"items": [1], "next_cursor": null})
        );
    }
}
