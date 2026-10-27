//! Edge attestation: the digest an edge signature covers, the signing write,
//! the verifier, and the unsigned-edge metric (backlog `dae795f8`).
//!
//! `edges` has carried `signature` / `signer_id` / `content_hash` since the
//! initial schema (with the pair CHECK `edges_signature_requires_signer`), and
//! migration 117's `edges_repoint_unsign` already clears all three when a
//! non-privileged session re-points an edge. Until this module nothing defined
//! what an edge signature SIGNS, so no writer could sign one and no reader could
//! check one. See `docs/architecture/noun-claims-and-verb-edges.md` ("Edge
//! signing") for the writer inventory.
//!
//! # What is signed
//!
//! The ATTESTATION DIGEST ([`edge_attestation_digest`]): BLAKE3 over the
//! canonical JSON of the edge's assertion as stored,
//!
//! ```text
//! { schema: "epigraph-edge-attestation/1", id, source_id, source_type,
//!   target_id, target_type, relationship, properties, valid_from, created_at }
//! ```
//!
//! timestamps as RFC 3339 with microseconds in UTC. It is stored in
//! `edges.content_hash`, and the signature is over the entity-tagged v1 message
//! `epigraph_crypto::signing_message(SignedEntity::Edge, digest)` (ruling R-34),
//! so an edge signature never verifies as a claim or evidence signature.
//!
//! * The edge `id` and `created_at` are inside, so a signature copied onto
//!   another row with the same endpoints does not verify for it.
//! * `valid_to` is NOT inside: retraction is a later act on an assertion that
//!   was made, and retracting an edge must not make its signature read as
//!   tampered. `labels` and `prov_type` are not inside either.
//! * `properties` IS inside (the event metadata of a verb-edge). A later patch
//!   of an edge's properties (`patch_edge`, a workflow's `plan_index` rewrite)
//!   or an administrative re-point therefore reports `content_matches: false`:
//!   the stored signature still verifies over the digest it signed, and the row
//!   no longer matches that digest. That is the truthful report ("changed since
//!   it was signed"), the same split `verify_claim` makes between
//!   `signature_valid` and `hash_check`.
//!
//! The digest is computed from the row AS STORED (read back after the INSERT),
//! never from the writer's input, so JSONB normalisation of `properties` and
//! the database's `created_at` cannot make an honest signature fail to verify.
//!
//! # v1 only
//!
//! The edge verifier accepts ONLY the v1 edge message, never a legacy
//! bare-digest signature (security review of this module, finding 2: "if
//! legacy edge signatures cannot exist, accept only v1"). The attestation
//! schema is defined here for the first time, so no signature made before v1
//! can be over an attestation digest. And a bare-digest signature binds no
//! entity type: claims hash their raw content bytes, so a claim whose content
//! IS an edge's canonical attestation JSON has a content hash equal to that
//! edge's digest, and its pre-v1 claim signature would read as a valid
//! signature of the edge. Signed edges written before this module (bulk
//! attestations, migration 120) are over some other, undefined digest; the
//! verifier reports them `pre_attestation` and never valid.

use crate::errors::DbError;
use crate::visibility::Viewer;
use chrono::{DateTime, SecondsFormat, Utc};
use epigraph_crypto::{
    signing_message, AgentSigner, ContentHasher, SignatureScheme, SignatureVerifier, SignedEntity,
    HASH_SIZE,
};
use serde::Serialize;
use sqlx::Row;
use uuid::Uuid;

/// The `schema` member of every v1 attestation object.
pub const EDGE_ATTESTATION_SCHEMA: &str = "epigraph-edge-attestation/1";

/// The part of an `edges` row its signature attests.
#[derive(Debug, Clone, PartialEq)]
pub struct EdgeAttestation {
    pub id: Uuid,
    pub source_id: Uuid,
    pub source_type: String,
    pub target_id: Uuid,
    pub target_type: String,
    pub relationship: String,
    pub properties: serde_json::Value,
    pub valid_from: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

fn ts(t: &DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Micros, true)
}

/// The canonical JSON text of an edge's attestation object: the exact bytes
/// [`edge_attestation_digest`] hashes, for a verifier outside this crate.
///
/// # Errors
/// Returns `DbError::InvalidData` only if canonical serialization fails, which
/// a `serde_json::Value` cannot do in practice.
pub fn edge_attestation_canonical_json(a: &EdgeAttestation) -> Result<String, DbError> {
    epigraph_crypto::to_canonical_json(&attestation_object(a)).map_err(|e| DbError::InvalidData {
        reason: format!("edge attestation canonicalization: {e}"),
    })
}

/// The attestation digest of an edge (see the module docs for what it covers):
/// BLAKE3 over [`edge_attestation_canonical_json`].
///
/// # Errors
/// Returns `DbError::InvalidData` only if canonical serialization fails, which
/// a `serde_json::Value` cannot do in practice.
pub fn edge_attestation_digest(a: &EdgeAttestation) -> Result<[u8; HASH_SIZE], DbError> {
    ContentHasher::hash_canonical(&attestation_object(a)).map_err(|e| DbError::InvalidData {
        reason: format!("edge attestation canonicalization: {e}"),
    })
}

fn attestation_object(a: &EdgeAttestation) -> serde_json::Value {
    serde_json::json!({
        "schema": EDGE_ATTESTATION_SCHEMA,
        "id": a.id.to_string(),
        "source_id": a.source_id.to_string(),
        "source_type": a.source_type,
        "target_id": a.target_id.to_string(),
        "target_type": a.target_type,
        "relationship": a.relationship,
        "properties": a.properties,
        "valid_from": a.valid_from.as_ref().map(ts),
        "created_at": ts(&a.created_at),
    })
}

/// The key a writer attests the edges it INSERTS with (rulings R-49, R-50):
/// its signer, and the agent whose registered key that signer's public key is
/// (`edges.signer_id`). An MCP server passes its own signer agent, the API its
/// own; neither is the edge's author (an edge's author record is its writer
/// group since migration 120, and what it asserts is its source's author's).
#[derive(Clone, Copy)]
pub struct EdgeSigningKey<'a> {
    pub signer: &'a AgentSigner,
    pub signer_id: Uuid,
}

impl std::fmt::Debug for EdgeSigningKey<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The public half and the agent only; the signer holds a private key.
        f.debug_struct("EdgeSigningKey")
            .field("public_key", &hex::encode(self.signer.public_key()))
            .field("signer_id", &self.signer_id)
            .finish()
    }
}

/// `t` at the microsecond, the precision `timestamptz` stores: a digest over
/// a nanosecond `created_at` would not recompute from the stored row.
#[must_use]
pub fn to_stored_micros(t: DateTime<Utc>) -> DateTime<Utc> {
    DateTime::from_timestamp_micros(t.timestamp_micros()).unwrap_or(t)
}

/// The `WHERE NOT EXISTS` an attested INSERT carries, if any: the symmetric
/// dedup of the `create_symmetric_if_absent*` family (`(a, b)` and `(b, a)`
/// with one relationship are one edge).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SymmetricGuard {
    /// Unconditional INSERT.
    None,
    /// Skip when such an edge IN FORCE exists (the link tools, migration 120).
    InForce,
}

/// A new edge's attestation, before its INSERT: a fresh `id` and the writer's
/// `created_at` (at the microsecond), so the digest is computable before the
/// row exists (ruling R-50).
#[must_use]
#[allow(clippy::too_many_arguments)]
pub(crate) fn new_attestation(
    source_id: Uuid,
    source_type: &str,
    target_id: Uuid,
    target_type: &str,
    relationship: &str,
    properties: serde_json::Value,
    valid_from: Option<DateTime<Utc>>,
) -> EdgeAttestation {
    EdgeAttestation {
        id: Uuid::new_v4(),
        source_id,
        source_type: source_type.to_string(),
        target_id,
        target_type: target_type.to_string(),
        relationship: relationship.to_string(),
        properties,
        valid_from: valid_from.map(to_stored_micros),
        created_at: to_stored_micros(Utc::now()),
    }
}

/// INSERT one edge ATTESTED AT INSERT (ruling R-50): `content_hash` = the
/// attestation digest of `a`, `signature` = the v1 edge signature over it and
/// `signer_id` = `key.signer_id`, in the same statement as the row.
///
/// This is how a world-owned structural verb-edge is signed at all: an
/// application session may INSERT such an edge but not UPDATE it (migration
/// 117), so [`EdgeSignatureRepository::sign_created_edge_conn`] returns
/// `NotSignable` for it.
///
/// The digest the verifier recomputes is over the row AS STORED. The INSERT
/// returns the stored attestation columns and they are recomputed; if they
/// differ from what was signed (a JSONB normalisation of `properties`, a
/// trigger that canonicalises a column), the INSERT is rolled back to its
/// savepoint and made once more over the stored values, so the signature is
/// over exactly what the database holds. A second mismatch is an error and
/// nothing is written: a stored signature over a digest its row does not
/// recompute to would read as tampering.
///
/// Returns `None` when `guard`'s dedup found an existing edge (nothing
/// written). Runs inside a savepoint of `conn`'s transaction (a real
/// transaction on a bare connection).
///
/// # Errors
/// `DbError::QueryFailed` if a statement fails; `DbError::InvalidData` if the
/// stored row twice failed to recompute to the signed digest.
pub(crate) async fn insert_attested_conn(
    conn: &mut sqlx::PgConnection,
    key: EdgeSigningKey<'_>,
    mut a: EdgeAttestation,
    valid_to: Option<DateTime<Utc>>,
    guard: SymmetricGuard,
    on_conflict_do_nothing: bool,
) -> Result<Option<crate::repos::edge::EdgeRow>, DbError> {
    use sqlx::Acquire;
    let guard_sql = match guard {
        SymmetricGuard::None => String::new(),
        SymmetricGuard::InForce => format!(
            " WHERE NOT EXISTS (SELECT 1 FROM edges \
                 WHERE ((source_id = $2 AND target_id = $4) \
                     OR (source_id = $4 AND target_id = $2)) \
                   AND relationship = $6 AND {})",
            crate::repos::edge::EDGE_IN_FORCE_UNALIASED
        ),
    };
    let conflict = if on_conflict_do_nothing {
        " ON CONFLICT DO NOTHING"
    } else {
        ""
    };
    let sql = format!(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship, \
                            properties, valid_from, valid_to, created_at, content_hash, \
                            signature, signer_id) \
         SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13{guard_sql}{conflict} \
         RETURNING id, source_id, source_type::text AS source_type, target_id, \
                   target_type::text AS target_type, relationship::text AS relationship, \
                   properties, valid_from, valid_to, created_at"
    );
    for _attempt in 0..2 {
        let digest = edge_attestation_digest(&a)?;
        let signature = key.signer.sign_entity(SignedEntity::Edge, &digest);
        let mut sp = conn.begin().await?;
        let row = sqlx::query(&sql)
            .bind(a.id)
            .bind(a.source_id)
            .bind(&a.source_type)
            .bind(a.target_id)
            .bind(&a.target_type)
            .bind(&a.relationship)
            .bind(sqlx::types::Json(&a.properties))
            .bind(a.valid_from)
            .bind(valid_to)
            .bind(a.created_at)
            .bind(digest.as_slice())
            .bind(signature.as_slice())
            .bind(key.signer_id)
            .fetch_optional(&mut *sp)
            .await?;
        let Some(row) = row else {
            sp.commit().await?;
            return Ok(None);
        };
        let stored = attestation_of(&row);
        if edge_attestation_digest(&stored)? == digest {
            sp.commit().await?;
            return Ok(Some(crate::repos::edge::EdgeRow {
                id: stored.id,
                source_id: stored.source_id,
                source_type: stored.source_type,
                target_id: stored.target_id,
                target_type: stored.target_type,
                relationship: stored.relationship,
                properties: stored.properties,
                valid_from: stored.valid_from,
                valid_to: row.get("valid_to"),
            }));
        }
        sp.rollback().await?;
        a = stored;
    }
    Err(DbError::InvalidData {
        reason: "the edge row the database stores does not recompute to the digest signed \
                 over it; nothing was written"
            .to_string(),
    })
}

/// What [`EdgeSignatureRepository::sign_created_edge_conn`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeSignOutcome {
    /// The edge now carries `content_hash = digest`, the v1 signature over it
    /// and `signer_id`.
    Signed { digest: [u8; HASH_SIZE] },
    /// The edge already carries a signature or a digest; nothing was written.
    /// An attestation is never overwritten.
    AlreadySigned,
    /// No row this session may update (absent, or another writer's edge under
    /// migration 117's owner-scoped UPDATE policy); nothing was written.
    NotSignable,
}

/// What [`EdgeSignatureRepository::verify_conn`] reports for one edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct EdgeSignatureCheck {
    /// `edges.signature IS NOT NULL`.
    pub signed: bool,
    /// The stored signature verifies, as a v1 EDGE signature, over the STORED
    /// `content_hash`, under a key of the signer that was admitted when the
    /// edge was created (see `key_kind`). A legacy bare-digest signature never
    /// counts (see the module docs, "v1 only").
    pub signature_valid: bool,
    /// Which message verified: always `v1` when `signature_valid`, `None`
    /// otherwise. Kept for symmetry with `verify_claim`'s field.
    pub signature_scheme: Option<SignatureScheme>,
    /// The kind of key that verified: `signing` / `identity-legacy` (an
    /// attested `agent_keys` row whose status and window admit the edge's
    /// `created_at`) or `unattested` (the signer's `agents.public_key`, only
    /// when no attested `agent_keys` row carries it). `None` when nothing
    /// verifies.
    pub key_kind: Option<&'static str>,
    /// The row recomputes to its stored `content_hash`; `None` when no digest
    /// is stored, or when the edge is `pre_attestation` (its stored digest is
    /// then no attestation digest, so there is nothing to compare).
    pub content_matches: Option<bool>,
    /// The edge carries a signature that is NOT a v1 edge attestation under
    /// any key its signer ever registered (admitted or not): a signature made
    /// under an earlier, undefined scheme (a pre-attestation bulk
    /// attestation), a bare-digest or other-entity signature, or garbage. It
    /// attests nothing this verifier can check, and is never valid. A v1
    /// signature whose key was not admitted when the edge was created is NOT
    /// pre-attestation: it is a real attestation by an unadmitted key.
    pub pre_attestation: bool,
    pub signer_id: Option<Uuid>,
}

/// Signed / unsigned edge counts, over the edges a viewer may read.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct EdgeSigningCoverage {
    pub total: i64,
    pub signed: i64,
    pub unsigned: i64,
}

/// Repository for edge attestation.
pub struct EdgeSignatureRepository;

const ATTESTATION_COLUMNS: &str = "e.id, e.source_id, e.source_type::text AS source_type, \
     e.target_id, e.target_type::text AS target_type, e.relationship::text AS relationship, \
     e.properties, e.valid_from, e.created_at, e.signature, e.signer_id, e.content_hash";

fn attestation_of(row: &sqlx::postgres::PgRow) -> EdgeAttestation {
    EdgeAttestation {
        id: row.get("id"),
        source_id: row.get("source_id"),
        source_type: row.get("source_type"),
        target_id: row.get("target_id"),
        target_type: row.get("target_type"),
        relationship: row.get("relationship"),
        properties: row.get("properties"),
        valid_from: row.get("valid_from"),
        created_at: row.get("created_at"),
    }
}

/// `(public_key, key_type, status, valid_from, valid_until)` of one
/// `agent_keys` row, type and status lower-cased.
type KeyRow = (
    Vec<u8>,
    String,
    String,
    DateTime<Utc>,
    Option<DateTime<Utc>>,
);

/// The signer's keys that may verify a signature on a row dated `at`: the
/// shared admission rule ([`crate::repos::agent_key::admitted_signature_keys`],
/// backlog `06a50a30`), the one the claim verifier applies too.
fn admitted_keys(
    rows: &[KeyRow],
    agent_key: Option<Vec<u8>>,
    at: DateTime<Utc>,
) -> Vec<([u8; 32], &'static str)> {
    let lifecycle: Vec<crate::repos::agent_key::KeyLifecycle<'_>> = rows
        .iter()
        .map(
            |(key, key_type, status, from, until)| crate::repos::agent_key::KeyLifecycle {
                public_key: key,
                key_type,
                status,
                valid_from: *from,
                valid_until: *until,
            },
        )
        .collect();
    crate::repos::agent_key::admitted_signature_keys(&lifecycle, agent_key.as_deref(), at)
        .into_iter()
        .map(|a| (a.key, a.kind))
        .collect()
}

impl EdgeSignatureRepository {
    /// Sign an edge THIS session just created: compute the attestation digest
    /// from the stored row and write `content_hash`, the v1 edge signature and
    /// `signer_id` in one UPDATE, on the caller's connection (so inside the
    /// writer's own stamped transaction).
    ///
    /// Call it only for an edge the caller created in this act (`was_created`):
    /// on a dedup hit the row is another write's assertion, and signing it
    /// would attest something this signer did not write. The UPDATE refuses to
    /// overwrite any existing signature or digest. Both the `FOR UPDATE` lock
    /// and the UPDATE carry `viewer`'s WRITE predicate (`{WRITABLE:e}`, bound
    /// to its writable groups; nothing for a maintenance viewer), and row
    /// security (migration 117's owner-scoped UPDATE policy) applies on top,
    /// so a session that may not update the edge signs nothing.
    ///
    /// `signer_id` must be the agent whose registered key is `signer`'s public
    /// key, as for `ClaimRepository::create_strict_signed`.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if a statement fails.
    pub async fn sign_created_edge_conn(
        conn: &mut sqlx::PgConnection,
        viewer: &Viewer,
        edge_id: Uuid,
        signer: &AgentSigner,
        signer_id: Uuid,
    ) -> Result<EdgeSignOutcome, DbError> {
        // Both statements carry the WRITE predicate (the viewer's writable
        // groups; nothing for a maintenance/bypass viewer, where row security
        // decides), so only a writer of the edge locks or attests it.
        let lock_sql = viewer.splice_write(
            &format!(
                "SELECT {ATTESTATION_COLUMNS} FROM edges e \
                  WHERE e.id = $1 /* {{WRITABLE:e}} */ FOR UPDATE"
            ),
            2,
        );
        let mut q = sqlx::query(&lock_sql).bind(edge_id);
        if let Some(w) = viewer.writable_bind() {
            q = q.bind(w);
        }
        let Some(row) = q.fetch_optional(&mut *conn).await? else {
            return Ok(EdgeSignOutcome::NotSignable);
        };
        let existing_sig: Option<Vec<u8>> = row.get("signature");
        let existing_hash: Option<Vec<u8>> = row.get("content_hash");
        if existing_sig.is_some() || existing_hash.is_some() {
            return Ok(EdgeSignOutcome::AlreadySigned);
        }
        let digest = edge_attestation_digest(&attestation_of(&row))?;
        let signature = signer.sign_entity(SignedEntity::Edge, &digest);
        let update_sql = viewer.splice_write(
            "UPDATE edges AS e SET content_hash = $2, signature = $3, signer_id = $4 \
              WHERE e.id = $1 AND e.signature IS NULL AND e.signer_id IS NULL \
                AND e.content_hash IS NULL /* {WRITABLE:e} */",
            5,
        );
        let mut q = sqlx::query(&update_sql)
            .bind(edge_id)
            .bind(digest.as_slice())
            .bind(signature.as_slice())
            .bind(signer_id);
        if let Some(w) = viewer.writable_bind() {
            q = q.bind(w);
        }
        let updated = q.execute(&mut *conn).await?.rows_affected();
        Ok(if updated == 1 {
            EdgeSignOutcome::Signed { digest }
        } else {
            EdgeSignOutcome::NotSignable
        })
    }

    /// Verify one edge's attestation. `None` when `viewer` cannot read the
    /// edge (the EDGE read predicate).
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if a statement fails.
    pub async fn verify_conn(
        conn: &mut sqlx::PgConnection,
        viewer: &Viewer,
        edge_id: Uuid,
    ) -> Result<Option<EdgeSignatureCheck>, DbError> {
        let sql = viewer.splice(
            &format!(
                "SELECT {ATTESTATION_COLUMNS} FROM edges e \
                  WHERE e.id = $1 /* {{EDGE_VISIBILITY:e}} */"
            ),
            2,
        );
        let mut q = sqlx::query(&sql).bind(edge_id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let Some(row) = q.fetch_optional(&mut *conn).await? else {
            return Ok(None);
        };
        let signature: Option<Vec<u8>> = row.get("signature");
        let stored_hash: Option<Vec<u8>> = row.get("content_hash");
        let signer_id: Option<Uuid> = row.get("signer_id");
        let stored_hash: Option<[u8; HASH_SIZE]> =
            stored_hash.and_then(|h| <[u8; HASH_SIZE]>::try_from(h.as_slice()).ok());

        let created_at: DateTime<Utc> = row.get("created_at");
        // The kind of the ADMITTED key that verifies the v1 edge message, and
        // whether ANY key of the signer (admitted or not) does.
        let mut verified: Option<&'static str> = None;
        let mut attests = false;
        if let (Some(sig), Some(h), Some(signer)) = (signature.as_deref(), stored_hash, signer_id) {
            if let Ok(sig) = <[u8; 64]>::try_from(sig) {
                // `agents` and `agent_keys` carry no tenancy columns: a key is
                // public verification material, read unfiltered.
                let rows: Vec<KeyRow> = sqlx::query_as(
                    "SELECT public_key, lower(btrim(key_type)), lower(btrim(status)), \
                            valid_from, valid_until \
                       FROM agent_keys WHERE agent_id = $1 ORDER BY created_at, id",
                )
                .bind(signer)
                .fetch_all(&mut *conn)
                .await?;
                let agent_key: Option<Vec<u8>> =
                    sqlx::query_scalar("SELECT public_key FROM agents WHERE id = $1")
                        .bind(signer)
                        .fetch_optional(&mut *conn)
                        .await?;
                // v1 ONLY: the edge-tagged message, never the bare digest.
                let message = signing_message(SignedEntity::Edge, &h);
                let v1 = |key: &[u8; 32]| {
                    SignatureVerifier::verify(key, &message, &sig).unwrap_or(false)
                };
                verified = admitted_keys(&rows, agent_key.clone(), created_at)
                    .iter()
                    .find(|(key, _)| v1(key))
                    .map(|(_, kind)| *kind);
                attests = verified.is_some()
                    || rows
                        .iter()
                        .map(|(key, ..)| key)
                        .chain(agent_key.iter())
                        .filter_map(|k| <[u8; 32]>::try_from(k.as_slice()).ok())
                        .any(|k| v1(&k));
            }
        }
        let pre_attestation = signature.is_some() && !attests;
        let content_matches = match stored_hash {
            Some(h) if !pre_attestation => {
                Some(edge_attestation_digest(&attestation_of(&row))? == h)
            }
            _ => None,
        };

        Ok(Some(EdgeSignatureCheck {
            signed: signature.is_some(),
            signature_valid: verified.is_some(),
            signature_scheme: verified.map(|_| SignatureScheme::V1),
            key_kind: verified,
            content_matches,
            pre_attestation,
            signer_id,
        }))
    }

    /// The unsigned-edge metric: how many of the edges `viewer` may read carry
    /// a signature, and how many do not.
    ///
    /// `signed` counts rows CARRYING a signature, which includes signatures
    /// made before the attestation scheme existed (bulk attestations, which
    /// [`Self::verify_conn`] reports `pre_attestation` and never valid). It is
    /// therefore an upper bound on verifiable edges, not a count of them;
    /// checking each signature is a per-row Ed25519 verify this aggregate does
    /// not run.
    ///
    /// Viewer-scoped with the EDGE predicate, like every cardinality
    /// `system_stats` reports (PR-09): a corpus-wide count would tell any
    /// caller the size of every group's private edges.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the query fails.
    pub async fn coverage(
        pool: &sqlx::PgPool,
        viewer: &Viewer,
    ) -> Result<EdgeSigningCoverage, DbError> {
        // `WHERE true` gives the marker a predicate to append ` AND (...)` to.
        let sql = viewer.splice(
            r"
            SELECT count(*)::bigint,
                   count(*) FILTER (WHERE eg.signature IS NOT NULL)::bigint
              FROM edges eg
             WHERE true /* {EDGE_VISIBILITY:eg} */
            ",
            1,
        );
        let mut q = sqlx::query_as::<_, (i64, i64)>(&sql);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let (total, signed) = q.fetch_one(pool).await?;
        Ok(EdgeSigningCoverage {
            total,
            signed,
            unsigned: total - signed,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> EdgeAttestation {
        EdgeAttestation {
            id: Uuid::from_u128(1),
            source_id: Uuid::from_u128(2),
            source_type: "agent".into(),
            target_id: Uuid::from_u128(3),
            target_type: "claim".into(),
            relationship: "spawned".into(),
            properties: serde_json::json!({"group": "g", "n": 1}),
            valid_from: None,
            created_at: DateTime::parse_from_rfc3339("2026-10-26T01:02:03.456789Z")
                .unwrap()
                .with_timezone(&Utc),
        }
    }

    /// Every attested field moves the digest; `properties` key order does not.
    #[test]
    fn the_digest_binds_every_attested_field_and_only_those() {
        let base = edge_attestation_digest(&sample()).unwrap();
        type Mutant = (&'static str, Box<dyn Fn(&mut EdgeAttestation)>);
        let mutants: Vec<Mutant> = vec![
            ("id", Box::new(|a| a.id = Uuid::from_u128(9))),
            ("source_id", Box::new(|a| a.source_id = Uuid::from_u128(9))),
            ("source_type", Box::new(|a| a.source_type = "claim".into())),
            ("target_id", Box::new(|a| a.target_id = Uuid::from_u128(9))),
            ("target_type", Box::new(|a| a.target_type = "agent".into())),
            (
                "relationship",
                Box::new(|a| a.relationship = "executed".into()),
            ),
            (
                "properties",
                Box::new(|a| a.properties = serde_json::json!({"group": "h", "n": 1})),
            ),
            (
                "valid_from",
                Box::new(|a| a.valid_from = Some(a.created_at)),
            ),
            (
                "created_at",
                Box::new(|a| a.created_at += chrono::Duration::microseconds(1)),
            ),
        ];
        for (field, mutate) in mutants {
            let mut a = sample();
            mutate(&mut a);
            assert_ne!(
                edge_attestation_digest(&a).unwrap(),
                base,
                "{field} is not bound by the edge digest"
            );
        }
        let mut reordered = sample();
        reordered.properties = serde_json::json!({"n": 1, "group": "g"});
        assert_eq!(edge_attestation_digest(&reordered).unwrap(), base);
    }
}
