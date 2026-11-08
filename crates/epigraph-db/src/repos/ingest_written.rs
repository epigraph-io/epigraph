//! Which `authored` / `asserts` edges the document ingest wrote.
//!
//! # The problem
//!
//! A provenance read (the agent card's counts, a claim's `authored_by`, a
//! paper's claim list) answers "who wrote this claim" from three edge shapes:
//!
//! * `agent -authored-> paper`, the document's authors;
//! * `paper -asserts-> claim`, the claims the document states;
//! * `agent -asserts-> claim`, an author's attribution of one of them.
//!
//! An edge's SHAPE proves nothing about who wrote it. `POST /api/v1/edges`
//! accepted both `asserts` shapes from any edges:write caller, so a stranger
//! could write `paper -asserts-> X` onto a paper an agent really authored, then
//! `agent -asserts-> X`, and every reader saw the agent credited with X. A
//! write-side gate on that route closes new forgeries but not the rows it let
//! through, nor the next writer that forgets the gate. A signature does not
//! tell the paths apart either: the HTTP route and the MCP link tools sign the
//! edges they write with the same server keys the ingest uses.
//!
//! # The marker
//!
//! The ingest walk writes these three shapes with a reserved property,
//! [`INGEST_WRITTEN_PROPERTY`] (its value: the tool that wrote it), through
//! [`create_ingest_written_edge_if_absent_conn`] and nothing else. Migration
//! 198's `edges_ingest_written_guard` makes the property unforgeable for every
//! application session:
//!
//! * an INSERT carrying the key, whatever its value, is refused (`IWE01`)
//!   unless the writing transaction declared [`INGEST_WRITTEN_SETTING`], which
//!   only this module's writer does, transaction-locally and only around its
//!   own INSERT;
//! * an UPDATE that adds or changes the key is refused the same way (keeping
//!   or dropping it is not);
//! * an UPDATE that moves an endpoint or changes the relationship of a marked
//!   edge drops the key, privileged sessions included: a re-pointed edge is no
//!   longer what the walk wrote.
//!
//! There is no privileged arm. A database login can set the setting itself, as
//! it can write any row; the guarantee is against application callers (HTTP,
//! MCP, the staged promote, any future edge writer), and the application layer
//! refuses the key as well ([`crate::RESERVED_EDGE_PROPERTIES`]) so a caller
//! gets a 400 rather than a database error.
//!
//! # The predicate
//!
//! [`ingest_written_edge_sql`] is THE test a provenance read applies. Every
//! reader of these shapes that means "the ingest wrote it" uses it; none tests
//! the property its own way.
//!
//! # What it does not cover
//!
//! * Edges written before the marker existed carry none, and the walk's
//!   create-if-absent never upgrades an existing row: legacy rows read as
//!   unproven until an operator backfills them.
//! * An existing unmarked row on the same `(source, target, relationship)`
//!   stops the walk writing a marked one (the walk dedups onto it). A writer
//!   can therefore withhold credit by writing first; it cannot create any.
//! * The workflow executor's `agent -asserts-> claim` attributions are not
//!   ingest-written edges: they name authors with no document behind them and
//!   carry no countersign state.

use crate::errors::DbError;
use crate::repos::edge::{EdgeRepository, EdgeRow};
use crate::repos::EdgeSigningKey;
use uuid::Uuid;

/// The reserved edge property the document ingest writes on the edges it
/// authors; its value is the writing tool's name.
pub const INGEST_WRITTEN_PROPERTY: &str = "ingest_written";

/// The transaction-local setting a writer declares to write
/// [`INGEST_WRITTEN_PROPERTY`]. Migration 198's guard reads it.
pub const INGEST_WRITTEN_SETTING: &str = "epigraph.ingest_written_edge";

/// The refusal for an application edge write whose `properties` carry
/// [`INGEST_WRITTEN_PROPERTY`].
pub const INGEST_WRITTEN_KEY_RESERVED: &str =
    "properties.ingest_written is reserved for the edges the document ingest writes \
     (ingest_document, ingest_document_spine); nothing was written";

/// The `(source_type, relationship, target_type)` shapes the walk marks.
pub const INGEST_WRITTEN_SHAPES: &[(&str, &str, &str)] = &[
    ("agent", "authored", "paper"),
    ("paper", "asserts", "claim"),
    ("agent", "asserts", "claim"),
];

/// SQL: true when the edge aliased `alias` was written by the document
/// ingest. The single trust predicate for provenance reads; see the module
/// docs. The guard refuses the key itself, so anything this accepts was
/// written under the walk's declaration.
#[must_use]
pub fn ingest_written_edge_sql(alias: &str) -> String {
    format!("(({alias}.properties ->> '{INGEST_WRITTEN_PROPERTY}') IS NOT NULL)")
}

/// `properties` without [`INGEST_WRITTEN_PROPERTY`]: what the walk writes on
/// an edge it does not mark, so a key smuggled in through a document's
/// extraction never reaches the guard.
#[must_use]
pub fn without_ingest_marker(properties: serde_json::Value) -> serde_json::Value {
    match properties {
        serde_json::Value::Object(mut m) => {
            m.remove(INGEST_WRITTEN_PROPERTY);
            serde_json::Value::Object(m)
        }
        other => other,
    }
}

/// Write one ingest edge, marked [`INGEST_WRITTEN_PROPERTY`] = `tool`, as
/// [`EdgeRepository::create_if_absent_including_retracted_signed_conn`] does
/// (a dedup hit returns the existing row, marked or not, and writes nothing).
///
/// Declares [`INGEST_WRITTEN_SETTING`] for this INSERT only, inside a
/// savepoint of `conn`'s transaction (a transaction of its own on a bare
/// connection), and clears it again before returning, so no other write of
/// the caller's transaction can carry the key.
///
/// # Errors
/// `DbError::InvalidData` for a shape outside [`INGEST_WRITTEN_SHAPES`];
/// otherwise as the wrapped writer.
#[allow(clippy::too_many_arguments)]
pub async fn create_ingest_written_edge_if_absent_conn(
    conn: &mut sqlx::PgConnection,
    key: Option<EdgeSigningKey<'_>>,
    tool: &'static str,
    source_id: Uuid,
    source_type: &str,
    target_id: Uuid,
    target_type: &str,
    relationship: &str,
    properties: Option<serde_json::Value>,
) -> Result<(EdgeRow, bool), DbError> {
    use sqlx::Acquire;
    if !INGEST_WRITTEN_SHAPES
        .iter()
        .any(|(s, r, t)| *s == source_type && *r == relationship && *t == target_type)
    {
        return Err(DbError::InvalidData {
            reason: format!(
                "{source_type} -{relationship}-> {target_type} is not an ingest-written edge shape"
            ),
        });
    }
    let mut props = match properties {
        Some(serde_json::Value::Object(m)) => m,
        Some(serde_json::Value::Null) | None => serde_json::Map::new(),
        Some(other) => {
            return Err(DbError::InvalidData {
                reason: format!("ingest edge properties must be an object, got {other}"),
            })
        }
    };
    props.insert(
        INGEST_WRITTEN_PROPERTY.to_string(),
        serde_json::Value::String(tool.to_string()),
    );
    let mut sp = conn.begin().await?;
    sqlx::query("SELECT pg_catalog.set_config($1, 'on', true)")
        .bind(INGEST_WRITTEN_SETTING)
        .execute(&mut *sp)
        .await?;
    let out = EdgeRepository::create_if_absent_including_retracted_signed_conn(
        &mut sp,
        key,
        source_id,
        source_type,
        target_id,
        target_type,
        relationship,
        Some(serde_json::Value::Object(props)),
        None,
        None,
    )
    .await?;
    sqlx::query("SELECT pg_catalog.set_config($1, '', true)")
        .bind(INGEST_WRITTEN_SETTING)
        .execute(&mut *sp)
        .await?;
    sp.commit().await?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_predicate_reads_the_reserved_key() {
        assert_eq!(
            ingest_written_edge_sql("e2"),
            "((e2.properties ->> 'ingest_written') IS NOT NULL)"
        );
    }

    #[test]
    fn an_unmarked_write_drops_a_smuggled_key() {
        let v = serde_json::json!({"ingest_written": "x", "role": "author"});
        assert_eq!(
            without_ingest_marker(v),
            serde_json::json!({"role": "author"})
        );
        assert_eq!(
            without_ingest_marker(serde_json::json!([1])),
            serde_json::json!([1])
        );
    }
}
