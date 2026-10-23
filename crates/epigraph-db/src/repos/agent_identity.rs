//! Host-attested agent identity registration and prompt history (migration 161,
//! agent identity lineage design D3/D4).
//!
//! The database stores each prompt file as a zstd frame addressed by the BLAKE3
//! of its RAW bytes, and runs neither algorithm itself. This repository owns
//! both ends:
//!
//! * [`AgentIdentityRepository::register`] hashes and compresses each file and
//!   calls `epigraph_register_agent_identity`, which only the
//!   `epigraph_identity_attestor` role may execute. The connection's ROLE is
//!   the authorisation: the session principal is a variable any login can set,
//!   so it is never consulted.
//! * [`AgentIdentityRepository::prompt_history`] calls
//!   `epigraph_agent_prompt_history`, which reads the session principal
//!   (operator or admin, else `AID06`), then decompresses every returned file
//!   and re-checks its hash, so a stored blob that no longer matches its key is
//!   an error rather than someone else's text.

use std::borrow::Cow;

use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::errors::DbError;

/// SQLSTATE: the parent named in a registration is not an LLM agent.
pub const PARENT_NOT_LLM_AGENT: &str = "AID03";
/// SQLSTATE: the identity is an existing agent with claims that was never
/// registered, so it is not an EpiClaw identity to adopt.
pub const NOT_ADOPTABLE: &str = "AID05";
/// SQLSTATE: the caller is neither the agent's operator nor an admin.
pub const PROMPT_HISTORY_REFUSED: &str = "AID06";
/// SQLSTATE: the child is linked to a different operator than its live parent's.
pub const OPERATOR_CONFLICT: &str = "AID07";

/// zstd level for stored prompt files (D4). Files are small and written once
/// per identity change, so the slowest standard level costs nothing measurable.
const ZSTD_LEVEL: i32 = 19;

/// The largest raw file the table accepts (`agent_prompt_blobs_raw_size`). Also
/// the decompression bound, so a stored frame cannot expand past it.
pub const MAX_PROMPT_FILE_BYTES: usize = 8 * 1024 * 1024;

/// One prompt file at registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromptFile {
    /// The file does not exist for this container.
    Absent,
    /// The file's raw bytes; stored compressed under the BLAKE3 of these bytes.
    Stored(Vec<u8>),
    /// The host refused to store the file (its capture-time scan found a secret
    /// in it). Recorded by name, with no content.
    Refused,
}

/// What the host attests before a container starts (D3).
#[derive(Debug, Clone)]
pub struct IdentityRegistration {
    /// The identity public key (the agent's `agents.public_key`).
    pub identity_pubkey: [u8; 32],
    /// The identity this group last registered, if any.
    pub parent_agent_id: Option<Uuid>,
    pub model: String,
    /// The identity prompt hash: 64 lowercase hex characters.
    pub prompt_hash: String,
    pub group_folder: String,
    /// The agent's signing public key, registered if it has no active one.
    pub signing_pubkey: Option<[u8; 32]>,
    pub identity_md: PromptFile,
    pub global_claude_md: PromptFile,
    pub group_claude_md: PromptFile,
    pub learned_md: PromptFile,
    /// Which files actually reached the prompt (a JSON object).
    pub in_prompt: Value,
    pub runner_version: Option<String>,
    pub host_sha: Option<String>,
}

/// The outcome of [`AgentIdentityRepository::register`].
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct IdentityRegistered {
    pub agent_id: Uuid,
    pub agent_created: bool,
    pub succession_created: bool,
    pub snapshot_id: Uuid,
    pub snapshot_created: bool,
    pub signing_key_registered: bool,
    /// The agent's operator after the call (a link of any state), if any.
    pub operator_id: Option<Uuid>,
    /// True when THIS call linked the agent to its parent's operator.
    pub inherited: bool,
    /// Why nothing was inherited: `no_parent`, `parent_unlinked`,
    /// `parent_link_retired`, `already_linked` or `link_not_live`.
    pub inherit_reason: Option<String>,
}

/// One stored prompt file, decompressed and verified against its hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromptBlob {
    /// BLAKE3 of `bytes`.
    pub blob_hash: [u8; 32],
    pub bytes: Vec<u8>,
}

impl PromptBlob {
    /// The file as text (lossy only if the file was not UTF-8).
    #[must_use]
    pub fn text(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.bytes)
    }
}

/// One prompt snapshot: what an agent ran in one group, and when.
#[derive(Debug, Clone)]
pub struct PromptSnapshot {
    pub id: Uuid,
    pub group_folder: String,
    pub model: String,
    pub prompt_hash: String,
    pub identity_md: Option<PromptBlob>,
    pub global_claude_md: Option<PromptBlob>,
    pub group_claude_md: Option<PromptBlob>,
    pub learned_md: Option<PromptBlob>,
    pub in_prompt: Value,
    /// Files the host refused to store, by name.
    pub blob_refused: Vec<String>,
    pub runner_version: Option<String>,
    pub host_sha: Option<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

/// One row of an agent's prompt history: an agent in its lineage and, when the
/// caller may read it, one of its snapshots.
#[derive(Debug, Clone)]
pub struct PromptHistoryEntry {
    pub agent_id: Uuid,
    /// `self`, `ancestor` or `descendant`.
    pub relation: String,
    /// 0 for the agent asked about, negative up the lineage, positive down it.
    pub depth: i32,
    /// False for a lineage member the caller does not operate: listed by id,
    /// with no snapshot.
    pub readable: bool,
    /// None when unreadable, or when the agent has no snapshot.
    pub snapshot: Option<PromptSnapshot>,
}

#[derive(sqlx::FromRow)]
struct HistoryRow {
    agent_id: Uuid,
    relation: String,
    depth: i32,
    readable: bool,
    snapshot_id: Option<Uuid>,
    group_folder: Option<String>,
    model: Option<String>,
    prompt_hash: Option<String>,
    in_prompt: Option<Value>,
    blob_refused: Option<Vec<String>>,
    runner_version: Option<String>,
    host_sha: Option<String>,
    first_seen: Option<DateTime<Utc>>,
    last_seen: Option<DateTime<Utc>>,
    identity_md_hash: Option<Vec<u8>>,
    identity_md: Option<Vec<u8>>,
    global_claude_md_hash: Option<Vec<u8>>,
    global_claude_md: Option<Vec<u8>>,
    group_claude_md_hash: Option<Vec<u8>>,
    group_claude_md: Option<Vec<u8>>,
    learned_md_hash: Option<Vec<u8>>,
    learned_md: Option<Vec<u8>>,
}

/// Registration and prompt history for host-attested agent identities.
pub struct AgentIdentityRepository;

impl AgentIdentityRepository {
    /// The snapshot document the registration definer takes: each file as
    /// `null`, `{"refused": true}`, or `{blob_hash, raw_size, codec, content}`
    /// with the BLAKE3 of the RAW bytes and the zstd frame, both hex.
    ///
    /// # Errors
    /// [`DbError::InvalidData`] for a file larger than
    /// [`MAX_PROMPT_FILE_BYTES`], or if compression fails.
    pub fn snapshot_document(reg: &IdentityRegistration) -> Result<Value, DbError> {
        let file = |f: &PromptFile| -> Result<Value, DbError> {
            Ok(match f {
                PromptFile::Absent => Value::Null,
                PromptFile::Refused => json!({"refused": true}),
                PromptFile::Stored(raw) => {
                    if raw.len() > MAX_PROMPT_FILE_BYTES {
                        return Err(DbError::InvalidData {
                            reason: format!(
                                "a prompt file of {} bytes exceeds the {MAX_PROMPT_FILE_BYTES}-byte \
                                 limit",
                                raw.len()
                            ),
                        });
                    }
                    let compressed = zstd::bulk::compress(raw, ZSTD_LEVEL).map_err(|e| {
                        DbError::InvalidData {
                            reason: format!("zstd compression failed: {e}"),
                        }
                    })?;
                    json!({
                        "blob_hash": blake3::hash(raw).to_hex().to_string(),
                        "raw_size": raw.len(),
                        "codec": "zstd",
                        "content": hex::encode(compressed),
                    })
                }
            })
        };
        Ok(json!({
            "identity_md": file(&reg.identity_md)?,
            "global_claude_md": file(&reg.global_claude_md)?,
            "group_claude_md": file(&reg.group_claude_md)?,
            "learned_md": file(&reg.learned_md)?,
            "in_prompt": reg.in_prompt,
            "runner_version": reg.runner_version,
            "host_sha": reg.host_sha,
        }))
    }

    /// Register (or re-register) a host-attested identity through migration
    /// 161's `epigraph_register_agent_identity`. Idempotent: the same identity,
    /// parent, group and files again only bumps the snapshot's `last_seen`.
    ///
    /// The CONNECTION must be the attestor role's: `epigraph_app` and the
    /// maintenance role get 42501, whatever principal the session claims.
    ///
    /// # Errors
    /// `DbError::QueryFailed` carrying SQLSTATE [`PARENT_NOT_LLM_AGENT`],
    /// [`NOT_ADOPTABLE`] or [`OPERATOR_CONFLICT`] for the refusals, 22023 for
    /// malformed input, 42501 for a connection that is not the attestor; each
    /// writes nothing. [`DbError::InvalidData`] from [`Self::snapshot_document`].
    pub async fn register(
        conn: &mut sqlx::PgConnection,
        reg: &IdentityRegistration,
    ) -> Result<IdentityRegistered, DbError> {
        let snapshot = Self::snapshot_document(reg)?;
        Ok(sqlx::query_as::<_, IdentityRegistered>(
            "SELECT agent_id, agent_created, succession_created, snapshot_id, snapshot_created, \
                    signing_key_registered, operator_id, inherited, inherit_reason \
               FROM public.epigraph_register_agent_identity($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(reg.identity_pubkey.as_slice())
        .bind(reg.parent_agent_id)
        .bind(&reg.model)
        .bind(&reg.prompt_hash)
        .bind(&reg.group_folder)
        .bind(reg.signing_pubkey.as_ref().map(|k| k.as_slice()))
        .bind(&snapshot)
        .fetch_one(&mut *conn)
        .await?)
    }

    /// An agent's prompt history and lineage through migration 161's
    /// `epigraph_agent_prompt_history`: one entry per (lineage agent, snapshot),
    /// files decompressed and verified.
    ///
    /// The definer reads the SESSION principal, so the connection must be
    /// stamped with the caller's principal (the operator or an admin).
    ///
    /// # Errors
    /// `DbError::QueryFailed` carrying SQLSTATE [`PROMPT_HISTORY_REFUSED`] when
    /// the caller is neither. [`DbError::InvalidData`] when a stored file does
    /// not decompress, exceeds the size bound, or no longer hashes to its key.
    pub async fn prompt_history(
        conn: &mut sqlx::PgConnection,
        agent_id: Uuid,
    ) -> Result<Vec<PromptHistoryEntry>, DbError> {
        let rows = sqlx::query_as::<_, HistoryRow>(
            "SELECT agent_id, relation, depth, readable, snapshot_id, group_folder, model, \
                    prompt_hash, in_prompt, blob_refused, runner_version, host_sha, first_seen, \
                    last_seen, identity_md_hash, identity_md, global_claude_md_hash, \
                    global_claude_md, group_claude_md_hash, group_claude_md, learned_md_hash, \
                    learned_md \
               FROM public.epigraph_agent_prompt_history($1)",
        )
        .bind(agent_id)
        .fetch_all(&mut *conn)
        .await?;
        rows.into_iter().map(history_entry).collect()
    }
}

fn history_entry(r: HistoryRow) -> Result<PromptHistoryEntry, DbError> {
    let snapshot = match r.snapshot_id {
        None => None,
        Some(id) => Some(PromptSnapshot {
            id,
            group_folder: r.group_folder.unwrap_or_default(),
            model: r.model.unwrap_or_default(),
            prompt_hash: r.prompt_hash.unwrap_or_default(),
            identity_md: verified_blob("identity_md", r.identity_md_hash, r.identity_md)?,
            global_claude_md: verified_blob(
                "global_claude_md",
                r.global_claude_md_hash,
                r.global_claude_md,
            )?,
            group_claude_md: verified_blob(
                "group_claude_md",
                r.group_claude_md_hash,
                r.group_claude_md,
            )?,
            learned_md: verified_blob("learned_md", r.learned_md_hash, r.learned_md)?,
            in_prompt: r.in_prompt.unwrap_or(Value::Null),
            blob_refused: r.blob_refused.unwrap_or_default(),
            runner_version: r.runner_version,
            host_sha: r.host_sha,
            first_seen: r.first_seen.unwrap_or_default(),
            last_seen: r.last_seen.unwrap_or_default(),
        }),
    };
    Ok(PromptHistoryEntry {
        agent_id: r.agent_id,
        relation: r.relation,
        depth: r.depth,
        readable: r.readable,
        snapshot,
    })
}

/// Decompress one stored file and check it against its key.
fn verified_blob(
    file: &str,
    hash: Option<Vec<u8>>,
    content: Option<Vec<u8>>,
) -> Result<Option<PromptBlob>, DbError> {
    let (hash, content) = match (hash, content) {
        (None, None) => return Ok(None),
        (Some(h), Some(c)) => (h, c),
        _ => {
            return Err(DbError::InvalidData {
                reason: format!("{file}: a snapshot names a blob the history did not return"),
            })
        }
    };
    let blob_hash: [u8; 32] = hash
        .as_slice()
        .try_into()
        .map_err(|_| DbError::InvalidData {
            reason: format!("{file}: a blob key is not 32 bytes"),
        })?;
    let bytes = zstd::bulk::decompress(&content, MAX_PROMPT_FILE_BYTES).map_err(|e| {
        DbError::InvalidData {
            reason: format!("{file}: the stored blob does not decompress: {e}"),
        }
    })?;
    if blake3::hash(&bytes).as_bytes() != &blob_hash {
        return Err(DbError::InvalidData {
            reason: format!(
                "{file}: the stored blob does not hash to its key {}; refusing to return it",
                hex::encode(blob_hash)
            ),
        });
    }
    Ok(Some(PromptBlob { blob_hash, bytes }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg(learned: PromptFile) -> IdentityRegistration {
        IdentityRegistration {
            identity_pubkey: [7; 32],
            parent_agent_id: None,
            model: "m".into(),
            prompt_hash: "0".repeat(64),
            group_folder: "g".into(),
            signing_pubkey: None,
            identity_md: PromptFile::Absent,
            global_claude_md: PromptFile::Absent,
            group_claude_md: PromptFile::Absent,
            learned_md: learned,
            in_prompt: json!({}),
            runner_version: None,
            host_sha: None,
        }
    }

    /// The document carries the BLAKE3 of the RAW bytes (not of the frame) and
    /// a frame that decompresses back to them.
    #[test]
    fn the_document_hashes_raw_bytes_and_carries_a_reversible_frame() {
        let raw = b"lesson one\nlesson two\n".to_vec();
        let doc = AgentIdentityRepository::snapshot_document(&reg(PromptFile::Stored(raw.clone())))
            .expect("document");
        let f = &doc["learned_md"];
        assert_eq!(
            f["blob_hash"],
            json!(blake3::hash(&raw).to_hex().to_string())
        );
        assert_eq!(f["raw_size"], json!(raw.len()));
        let frame = hex::decode(f["content"].as_str().expect("hex")).expect("hex");
        assert_ne!(blake3::hash(&frame).to_hex().to_string(), f["blob_hash"]);
        assert_eq!(
            zstd::bulk::decompress(&frame, MAX_PROMPT_FILE_BYTES).expect("frame"),
            raw
        );
        assert_eq!(doc["identity_md"], Value::Null);
    }

    #[test]
    fn an_oversized_file_is_refused_before_it_reaches_the_database() {
        let err = AgentIdentityRepository::snapshot_document(&reg(PromptFile::Stored(vec![
            b'x';
            MAX_PROMPT_FILE_BYTES
                + 1
        ])))
        .expect_err("oversized");
        assert!(matches!(err, DbError::InvalidData { .. }));
        // CALIBRATION: exactly at the bound is accepted.
        AgentIdentityRepository::snapshot_document(&reg(PromptFile::Stored(vec![
            b'x';
            MAX_PROMPT_FILE_BYTES
        ])))
        .expect("at the bound");
    }

    #[test]
    fn a_frame_that_does_not_hash_to_its_key_is_invalid_data() {
        let raw = b"true".to_vec();
        let frame = zstd::bulk::compress(&raw, 3).expect("compress");
        let good = verified_blob(
            "f",
            Some(blake3::hash(&raw).as_bytes().to_vec()),
            Some(frame.clone()),
        )
        .expect("matches")
        .expect("present");
        assert_eq!(good.bytes, raw);
        let err = verified_blob(
            "f",
            Some(blake3::hash(b"other").as_bytes().to_vec()),
            Some(frame),
        )
        .expect_err("mismatch");
        assert!(matches!(err, DbError::InvalidData { .. }));
    }
}
