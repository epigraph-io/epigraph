//! The atomicity screen as MCP read tools (backlogs `72850d43`, `c4a8436b`).
//!
//! * `screen_claim_atomicity`: [`epigraph_core::atomicity::conjunct_screen`]
//!   for claims named by id, with each one's `decomposes_to` shape.
//! * `query_compound_claims`: the discovery walk. Claims the screen calls
//!   compound, found REGARDLESS of their `decomposes_to` edges, which
//!   `query_undecomposed_claims` cannot do: it excludes every claim with such
//!   an edge, so a compound atom never reaches it.
//!
//! Both read on the caller's viewer-stamped connection
//! (`EpiGraphMcpFull::read_as`); a claim the caller cannot read is reported
//! exactly like one that does not exist, and a hidden edge or neighbour is in
//! no count (`epigraph_db::repos::atomicity_screen`).

use rmcp::model::*;
use serde::Serialize;
use uuid::Uuid;

use crate::errors::{internal_error, invalid_params, parse_uuid, McpError};
use crate::server::EpiGraphMcpFull;
use crate::types::{QueryCompoundClaimsParams, ScreenClaimAtomicityParams};

use epigraph_core::atomicity::{
    conjunct_screen, ConjunctScreen, COMPOUND_ATOM_LABEL, COMPOUND_MIN_CONJUNCTS,
};
use epigraph_db::{AtomicityScreenRepository, ScreenPopulation, ScreenRow};

/// Most ids one `screen_claim_atomicity` call takes.
pub const MAX_SCREEN_IDS: usize = 200;
const DEFAULT_COMPOUND_LIMIT: u32 = 50;
const MAX_COMPOUND_LIMIT: u32 = 200;
const DEFAULT_MAX_SCAN: u32 = 2000;
const MAX_MAX_SCAN: u32 = 10_000;
/// Rows read per statement of the discovery walk.
const SCAN_PAGE: i64 = 500;
/// Characters of content a row carries; the full text is `get_claim`'s.
pub const SCREEN_CONTENT_CHARS: usize = 300;

fn success_json(value: &impl Serialize) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![ContentBlock::text(
        serde_json::to_string_pretty(value).map_err(internal_error)?,
    )]))
}

/// The screen of one claim, as both tools return it.
#[derive(Debug, Serialize)]
struct ScreenedClaim {
    claim_id: Uuid,
    content: String,
    content_truncated: bool,
    is_current: bool,
    #[serde(flatten)]
    screen: ConjunctScreen,
    is_compound: bool,
    /// Visible current children through an in-force `decomposes_to` edge.
    decomposes_to_children: i64,
    /// Visible current parents through an in-force `decomposes_to` edge.
    decomposes_to_parents: i64,
    /// Whether the claim carries the sweep's `compound-atom` label.
    labelled_compound_atom: bool,
}

impl ScreenedClaim {
    fn new(row: ScreenRow, screen: ConjunctScreen) -> Self {
        let total = row.content.chars().count();
        let content: String = row.content.chars().take(SCREEN_CONTENT_CHARS).collect();
        Self {
            claim_id: row.id,
            content,
            content_truncated: total > SCREEN_CONTENT_CHARS,
            is_current: row.is_current,
            is_compound: screen.is_compound(),
            screen,
            decomposes_to_children: row.children,
            decomposes_to_parents: row.parents,
            labelled_compound_atom: row.labels.iter().any(|l| l == COMPOUND_ATOM_LABEL),
        }
    }
}

#[derive(Debug, Serialize)]
struct ScreenResponse {
    claims: Vec<ScreenedClaim>,
    /// Requested ids that name no claim the caller can read.
    not_found: Vec<Uuid>,
}

pub async fn screen_claim_atomicity(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: ScreenClaimAtomicityParams,
) -> Result<CallToolResult, McpError> {
    if params.claim_ids.is_empty() || params.claim_ids.len() > MAX_SCREEN_IDS {
        return Err(invalid_params(format!(
            "claim_ids must name 1 to {MAX_SCREEN_IDS} claims"
        )));
    }
    let mut ids = Vec::with_capacity(params.claim_ids.len());
    for raw in &params.claim_ids {
        let id = parse_uuid(raw)?;
        if !ids.contains(&id) {
            ids.push(id);
        }
    }
    let mut read = server.read_as(viewer, "screen_claim_atomicity").await?;
    let rows = AtomicityScreenRepository::rows_by_ids(&mut *read, viewer, &ids)
        .await
        .map_err(internal_error)?;
    read.commit().await.map_err(internal_error)?;

    let found: std::collections::HashSet<Uuid> = rows.iter().map(|r| r.id).collect();
    let not_found = ids.into_iter().filter(|id| !found.contains(id)).collect();
    let claims = rows
        .into_iter()
        .map(|r| {
            let s = conjunct_screen(&r.content);
            ScreenedClaim::new(r, s)
        })
        .collect();
    success_json(&ScreenResponse { claims, not_found })
}

/// A position in the discovery walk: the last `(created_at, id)` read.
fn encode_cursor(at: chrono::DateTime<chrono::Utc>, id: Uuid) -> String {
    format!(
        "{}|{id}",
        at.to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
    )
}

fn decode_cursor(raw: &str) -> Result<(chrono::DateTime<chrono::Utc>, Uuid), McpError> {
    let bad = || invalid_params("after must be a next_cursor returned by query_compound_claims");
    let (at, id) = raw.split_once('|').ok_or_else(bad)?;
    let at = chrono::DateTime::parse_from_rfc3339(at)
        .map_err(|_| bad())?
        .with_timezone(&chrono::Utc);
    let id = Uuid::parse_str(id).map_err(|_| bad())?;
    Ok((at, id))
}

#[derive(Debug, Serialize)]
struct CompoundPage {
    claims: Vec<ScreenedClaim>,
    /// Rows read and screened by this call.
    scanned: usize,
    /// Pass as `after` to continue; null once the population is exhausted.
    next_cursor: Option<String>,
    exhausted: bool,
}

pub async fn query_compound_claims(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: QueryCompoundClaimsParams,
) -> Result<CallToolResult, McpError> {
    let population = match params.population.as_deref() {
        None | Some("atoms") => ScreenPopulation::Atoms,
        Some("all") => ScreenPopulation::All,
        Some(other) => {
            return Err(invalid_params(format!(
                "population must be \"atoms\" or \"all\", not {other:?}"
            )))
        }
    };
    let leaves_only = params.leaves_only.unwrap_or(true);
    let min_conjuncts = params
        .min_conjuncts
        .map_or(COMPOUND_MIN_CONJUNCTS, |n| n as usize);
    if min_conjuncts < COMPOUND_MIN_CONJUNCTS {
        return Err(invalid_params(format!(
            "min_conjuncts must be at least {COMPOUND_MIN_CONJUNCTS}"
        )));
    }
    let limit = params
        .limit
        .unwrap_or(DEFAULT_COMPOUND_LIMIT)
        .clamp(1, MAX_COMPOUND_LIMIT) as usize;
    let max_scan = params
        .max_scan
        .unwrap_or(DEFAULT_MAX_SCAN)
        .clamp(1, MAX_MAX_SCAN) as usize;
    let mut after = params.after.as_deref().map(decode_cursor).transpose()?;

    let mut read = server.read_as(viewer, "query_compound_claims").await?;
    let mut hits = Vec::new();
    let mut scanned = 0usize;
    let mut exhausted = false;
    // Stops at `limit` hits or `max_scan` reads. A page is read whole and
    // the cursor is the last row SCREENED, so a hit past `limit` on the
    // final page is not skipped: the walk stops at that hit, not after the
    // page.
    'walk: while hits.len() < limit && scanned < max_scan {
        let want = SCAN_PAGE.min((max_scan - scanned) as i64);
        let page = AtomicityScreenRepository::page(&mut *read, viewer, population, after, want)
            .await
            .map_err(internal_error)?;
        let n = page.len();
        for row in page {
            scanned += 1;
            after = Some((row.created_at, row.id));
            let s = conjunct_screen(&row.content);
            if s.conjunct_count >= min_conjuncts && (!leaves_only || row.children == 0) {
                hits.push(ScreenedClaim::new(row, s));
                if hits.len() >= limit {
                    break 'walk;
                }
            }
        }
        if (n as i64) < want {
            exhausted = true;
            break;
        }
    }
    read.commit().await.map_err(internal_error)?;

    success_json(&CompoundPage {
        claims: hits,
        scanned,
        next_cursor: if exhausted {
            None
        } else {
            after.map(|(at, id)| encode_cursor(at, id))
        },
        exhausted,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cursor_round_trips_at_microsecond_precision() {
        let at = chrono::DateTime::parse_from_rfc3339("2026-03-01T10:11:12.123456Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let id = Uuid::new_v4();
        assert_eq!(decode_cursor(&encode_cursor(at, id)).unwrap(), (at, id));
        assert!(decode_cursor("not a cursor").is_err());
        assert!(decode_cursor("2026-03-01T10:11:12Z|nope").is_err());
    }
}
