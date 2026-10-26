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

use crate::errors::DbError;
use crate::visibility::Viewer;
use chrono::{DateTime, SecondsFormat, Utc};
use epigraph_crypto::{
    AgentSigner, ContentHasher, SignatureScheme, SignatureVerifier, SignedEntity, HASH_SIZE,
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

/// The attestation digest of an edge (see the module docs for what it covers).
///
/// # Errors
/// Returns `DbError::InvalidData` only if canonical serialization fails, which
/// a `serde_json::Value` cannot do in practice.
pub fn edge_attestation_digest(a: &EdgeAttestation) -> Result<[u8; HASH_SIZE], DbError> {
    let canonical = serde_json::json!({
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
    });
    ContentHasher::hash_canonical(&canonical).map_err(|e| DbError::InvalidData {
        reason: format!("edge attestation canonicalization: {e}"),
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
    /// The stored signature verifies, as an EDGE signature, over the STORED
    /// `content_hash`, under a key of the signer that was admitted when the
    /// edge was created (see `key_kind`).
    pub signature_valid: bool,
    /// Which message verified (`v1` / `legacy`); `None` when nothing does. A
    /// legacy (bare-digest) signature counts only when `content_matches` is
    /// `Some(true)`: it binds no entity type, so it is accepted only over this
    /// row's own attestation digest.
    pub signature_scheme: Option<SignatureScheme>,
    /// The kind of key that verified: `signing` / `identity-legacy` (an
    /// attested `agent_keys` row whose status and window admit the edge's
    /// `created_at`) or `unattested` (the signer's `agents.public_key`, only
    /// when no `agent_keys` row carries it). `None` when nothing verifies.
    pub key_kind: Option<&'static str>,
    /// The row recomputes to its stored `content_hash`; `None` when no digest
    /// is stored (an unsigned edge, or a legacy signature with no digest).
    pub content_matches: Option<bool>,
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

/// The signer's keys that may verify a signature on a row dated `at`:
///
/// * each attested `agent_keys` row (`signing`, `identity-legacy`) whose
///   status and window admit `at` ([`crate::repos::agent_key::key_window_admits`],
///   the rule the claim verifier uses), and
/// * the signer's `agents.public_key` ("unattested") only when NO `agent_keys`
///   row of the signer carries those bytes: a key with a recorded lifecycle is
///   governed by it, so a revoked, pending or out-of-window key cannot come
///   back in as the bare agent key.
fn admitted_keys(
    rows: &[KeyRow],
    agent_key: Option<Vec<u8>>,
    at: DateTime<Utc>,
) -> Vec<([u8; 32], &'static str)> {
    let mut out = Vec::new();
    for (key, key_type, status, from, until) in rows {
        let kind = match key_type.as_str() {
            "signing" => "signing",
            "identity-legacy" => "identity-legacy",
            _ => continue,
        };
        if crate::repos::agent_key::key_window_admits(status, *from, *until, at) {
            if let Ok(k) = <[u8; 32]>::try_from(key.as_slice()) {
                out.push((k, kind));
            }
        }
    }
    if let Some(k) = agent_key
        .filter(|k| !rows.iter().any(|(key, ..)| key == k))
        .and_then(|k| <[u8; 32]>::try_from(k.as_slice()).ok())
    {
        out.push((k, "unattested"));
    }
    out
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

        let content_matches = match stored_hash {
            Some(h) => Some(edge_attestation_digest(&attestation_of(&row))? == h),
            None => None,
        };

        let created_at: DateTime<Utc> = row.get("created_at");
        let mut verified: Option<(SignatureScheme, &'static str)> = None;
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
                let keys = admitted_keys(&rows, agent_key, created_at);
                verified = keys.iter().find_map(|(key, kind)| {
                    SignatureVerifier::verify_entity(key, SignedEntity::Edge, &h, &sig)
                        .ok()
                        .flatten()
                        .map(|scheme| (scheme, *kind))
                });
            }
        }
        // A LEGACY (bare-digest) signature binds no entity type, so it counts
        // only when the stored digest really is this row's attestation digest:
        // a bare-digest signature over some claim's or evidence row's content
        // hash, copied here with that hash, never matches and is refused.
        if matches!(verified, Some((SignatureScheme::Legacy, _))) && content_matches != Some(true) {
            verified = None;
        }

        Ok(Some(EdgeSignatureCheck {
            signed: signature.is_some(),
            signature_valid: verified.is_some(),
            signature_scheme: verified.map(|(scheme, _)| scheme),
            key_kind: verified.map(|(_, kind)| kind),
            content_matches,
            signer_id,
        }))
    }

    /// The unsigned-edge metric: how many of the edges `viewer` may read carry
    /// a signature, and how many do not.
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
