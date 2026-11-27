//! Edge relationship names both transports write and accept.
//!
//! These live in `epigraph-auth` because it is the one crate both
//! `epigraph-mcp` (which writes the edge) and `epigraph-api` (whose
//! `POST /api/v1/edges` allow-list must accept it) link unconditionally. The
//! API's allow-list compiles without its `db` feature, the only feature that
//! links `epigraph-mcp`, so the API cannot read the name from the MCP crate.

/// Relationship byte string for a closure-basis edge: resolution claim -> the
/// claims that justified closing a backlog item. Written by MCP
/// `resolve_backlog_item` and registered in `epigraph-api`'s
/// `VALID_RELATIONSHIPS`, so the same edge can be asserted and inspected over
/// HTTP.
///
/// LOWERCASE, and one constant on both surfaces. `epigraph-api`'s
/// `is_valid_relationship` matches `VALID_RELATIONSHIPS` case-sensitively and
/// carries both spellings of several names (`DERIVED_FROM` and
/// `derived_from`), so a mismatch would make an edge the tool writes
/// unreachable through `POST /api/v1/edges`. Lowercase matches the
/// claim->claim cluster it belongs with: `alternative_of`, `asserts`,
/// `decomposes_to`.
pub const JUSTIFIES_RELATIONSHIP: &str = "justifies";
