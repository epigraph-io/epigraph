//! Partition-aware access control — relocated to `epigraph-db::access_control`
//! (the shared repo layer used by both HTTP routes and MCP tools, per the
//! repo CLAUDE.md "all SQL stays in crates/epigraph-db/src/repos"). This shim
//! preserves the `crate::access_control::*` import path for the HTTP routes.
#[cfg(feature = "db")]
pub use epigraph_db::access_control::{
    batch_check_content_access, batch_content_access, check_content_access, ContentAccess,
    COARSE_EDGE_TYPES,
};

/// Redact claim content: keep id, truth_value, belief, plausibility, pignistic_prob
/// but replace content with "[REDACTED]".
pub fn redact_claim_content(content: &mut String) {
    *content = "[REDACTED]".to_string();
}

/// Redact every claim-text field the requester may not read, using **one**
/// ownership lookup for the whole response.
///
/// `fields` pairs each mutable text field with the id of the claim it came
/// from; the same claim id may appear more than once (a list row and the same
/// claim quoted as a graph neighbour), and duplicates cost nothing extra
/// because the lookup is set-based. An id missing from the batch result is
/// redacted — [`batch_content_access`] fails closed, and so does this.
///
/// This is the list-shaped counterpart of the `get_claim` convention
/// (`routes/claims.rs`): `check_content_access` + [`redact_claim_content`] for
/// a single claim, this for a page of them. Handlers must not loop
/// `check_content_access` per row — that is a query per result.
#[cfg(feature = "db")]
pub async fn redact_claim_fields<'a, I>(
    pool: &sqlx::PgPool,
    requester: Option<uuid::Uuid>,
    fields: I,
) where
    I: IntoIterator<Item = (uuid::Uuid, &'a mut String)>,
{
    let mut fields: Vec<(uuid::Uuid, &mut String)> = fields.into_iter().collect();
    if fields.is_empty() {
        return;
    }
    let mut ids: Vec<uuid::Uuid> = fields.iter().map(|(id, _)| *id).collect();
    ids.sort_unstable();
    ids.dedup();

    let access = batch_content_access(pool, &ids, requester).await;
    for (id, content) in &mut fields {
        if access.get(id).copied().unwrap_or(ContentAccess::Redacted) == ContentAccess::Redacted {
            redact_claim_content(content);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_claim_content_replaces() {
        let mut content = "Secret claim about something".to_string();
        redact_claim_content(&mut content);
        assert_eq!(content, "[REDACTED]");
    }
}
