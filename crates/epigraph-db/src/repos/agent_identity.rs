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
//!   and re-checks its hash. A stored blob that no longer matches its key is
//!   WITHHELD (named in [`PromptSnapshot::withheld_files`]), never returned as
//!   someone else's text; and since blobs are shared across agents, one bad
//!   blob withholds that one file, not every history that names it.
//! * [`AgentIdentityRepository::prompt_history_index`] and
//!   [`AgentIdentityRepository::prompt_history_blob`] split that read for a
//!   server: the first projects only the hashes and metadata out of the same
//!   definer, so no file content crosses the connection; the second fetches,
//!   decompresses and verifies the ONE file a readable snapshot in that
//!   history names. A server's memory then grows with the number of snapshots
//!   and with one file, not with the sum of every file. (The definer itself
//!   still builds its whole result, content included, inside the database.)

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
/// SQLSTATE: the identity already has a different active signing key.
/// Revoking a bound key is a maintenance act; the host then registers anew.
pub const SIGNING_KEY_CONFLICT: &str = "AID08";

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
    /// The agent's signing public key: bound if it has no active one, a no-op
    /// if it is the bound one, refused [`SIGNING_KEY_CONFLICT`] otherwise.
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
    /// True when THIS call recorded the agent's link to its parent's
    /// operator (live or not: see `link_live`).
    pub inherited: bool,
    /// True when the agent is live-linked after the call, i.e. can write.
    pub link_live: bool,
    /// Why nothing (or nothing live) was inherited: `no_parent`,
    /// `parent_unlinked`, `parent_link_retired`, `shared_identity` (an
    /// unlinked identity already running in another group: link it by hand),
    /// `link_refused` (the link body refused, e.g. a shared-signer
    /// fingerprint), `already_linked`, `child_link_retired` or
    /// `link_not_live`.
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
    /// Files whose stored blob failed verification on this read (it did not
    /// decompress, exceeded the size bound, or no longer hashes to its key),
    /// by name. Their field above is `None`: a blob that is not what its key
    /// says is never returned.
    pub withheld_files: Vec<String>,
    /// The runner version and host build of the FIRST start in this state:
    /// a snapshot is one per (agent, group, model, files, `in_prompt`,
    /// refused files), and a later start that differs only in these two
    /// bumps `last_seen` without recording them (design D4's key).
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

/// One prompt snapshot as the content-free index names it: every file by the
/// BLAKE3 of its raw bytes, none of its content.
#[derive(Debug, Clone)]
pub struct PromptSnapshotIndex {
    pub id: Uuid,
    pub group_folder: String,
    pub model: String,
    pub prompt_hash: String,
    pub identity_md: Option<[u8; 32]>,
    pub global_claude_md: Option<[u8; 32]>,
    pub group_claude_md: Option<[u8; 32]>,
    pub learned_md: Option<[u8; 32]>,
    pub in_prompt: Value,
    /// Files the host refused to store, by name.
    pub blob_refused: Vec<String>,
    /// As in [`PromptSnapshot`]: the FIRST start in this state.
    pub runner_version: Option<String>,
    pub host_sha: Option<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

/// One row of [`AgentIdentityRepository::prompt_history_index`]: as
/// [`PromptHistoryEntry`], with the snapshot named by hash only.
#[derive(Debug, Clone)]
pub struct PromptHistoryIndexEntry {
    pub agent_id: Uuid,
    /// `self`, `ancestor` or `descendant`.
    pub relation: String,
    /// 0 for the agent asked about, negative up the lineage, positive down it.
    pub depth: i32,
    /// False for a lineage member the caller does not operate: listed by id,
    /// with no snapshot.
    pub readable: bool,
    /// None when unreadable, or when the agent has no snapshot.
    pub snapshot: Option<PromptSnapshotIndex>,
}

/// The outcome of [`AgentIdentityRepository::prompt_history_blob`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromptBlobRead {
    /// No snapshot the caller may read in that history names the hash.
    NotNamed,
    /// The file, decompressed and re-hashed to its key.
    Verified(PromptBlob),
    /// A readable snapshot names it, but the stored blob failed verification
    /// (it did not decompress, exceeded the size bound, or no longer hashes to
    /// its key); the reason, for the log. Its bytes are never returned.
    Withheld(String),
}

#[derive(sqlx::FromRow)]
struct IndexRow {
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
    global_claude_md_hash: Option<Vec<u8>>,
    group_claude_md_hash: Option<Vec<u8>>,
    learned_md_hash: Option<Vec<u8>>,
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
    /// [`NOT_ADOPTABLE`], [`OPERATOR_CONFLICT`] or [`SIGNING_KEY_CONFLICT`] for
    /// the refusals, 22023 for malformed input (or a signing key already bound
    /// elsewhere), 42501 for a connection that is not the attestor; each writes
    /// nothing. [`DbError::InvalidData`] from [`Self::snapshot_document`].
    pub async fn register(
        conn: &mut sqlx::PgConnection,
        reg: &IdentityRegistration,
    ) -> Result<IdentityRegistered, DbError> {
        let snapshot = Self::snapshot_document(reg)?;
        Ok(sqlx::query_as::<_, IdentityRegistered>(
            "SELECT agent_id, agent_created, succession_created, snapshot_id, snapshot_created, \
                    signing_key_registered, operator_id, inherited, link_live, inherit_reason \
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
    /// A stored file that does not decompress, exceeds the size bound, or no
    /// longer hashes to its key is withheld and named in
    /// [`PromptSnapshot::withheld_files`]; the rest of the history is returned.
    ///
    /// # Errors
    /// `DbError::QueryFailed` carrying SQLSTATE [`PROMPT_HISTORY_REFUSED`] when
    /// the caller is neither.
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
        Ok(rows.into_iter().map(history_entry).collect())
    }

    /// [`Self::prompt_history`] without any file content: the same definer,
    /// the same gate and the same rows, each file named by its key only. No
    /// blob crosses the connection.
    ///
    /// # Errors
    /// As [`Self::prompt_history`]; and [`DbError::InvalidData`] for a stored
    /// key that is not 32 bytes (the blob table's CHECK makes that
    /// unreachable).
    pub async fn prompt_history_index(
        conn: &mut sqlx::PgConnection,
        agent_id: Uuid,
    ) -> Result<Vec<PromptHistoryIndexEntry>, DbError> {
        let rows = sqlx::query_as::<_, IndexRow>(
            "SELECT agent_id, relation, depth, readable, snapshot_id, group_folder, model, \
                    prompt_hash, in_prompt, blob_refused, runner_version, host_sha, first_seen, \
                    last_seen, identity_md_hash, global_claude_md_hash, group_claude_md_hash, \
                    learned_md_hash \
               FROM public.epigraph_agent_prompt_history($1)",
        )
        .bind(agent_id)
        .fetch_all(&mut *conn)
        .await?;
        rows.into_iter().map(index_entry).collect()
    }

    /// One file of an agent's prompt history, by key: fetched only when a
    /// snapshot the caller may READ in `agent_id`'s history (its own, or a
    /// lineage member's the definer marks readable) names `blob_hash`, then
    /// decompressed and re-hashed. Only that file's content crosses the
    /// connection.
    ///
    /// The gate is the definer's: the connection must be stamped with the
    /// caller's principal, exactly as for [`Self::prompt_history`].
    ///
    /// # Errors
    /// As [`Self::prompt_history`]: `AID06` ([`PROMPT_HISTORY_REFUSED`]) for a
    /// caller who is neither the operator nor an admin.
    pub async fn prompt_history_blob(
        conn: &mut sqlx::PgConnection,
        agent_id: Uuid,
        blob_hash: &[u8; 32],
    ) -> Result<PromptBlobRead, DbError> {
        let row: Option<(Option<Vec<u8>>,)> = sqlx::query_as(
            "SELECT CASE $2 WHEN identity_md_hash      THEN identity_md \
                            WHEN global_claude_md_hash THEN global_claude_md \
                            WHEN group_claude_md_hash  THEN group_claude_md \
                            ELSE learned_md END \
               FROM public.epigraph_agent_prompt_history($1) \
              WHERE readable \
                AND $2 IN (identity_md_hash, global_claude_md_hash, group_claude_md_hash, \
                           learned_md_hash) \
              LIMIT 1",
        )
        .bind(agent_id)
        .bind(blob_hash.as_slice())
        .fetch_optional(&mut *conn)
        .await?;
        let Some((content,)) = row else {
            return Ok(PromptBlobRead::NotNamed);
        };
        Ok(
            match verified_blob("blob", Some(blob_hash.to_vec()), content) {
                Ok(Some(blob)) => PromptBlobRead::Verified(blob),
                // Unreachable: a key was given.
                Ok(None) => PromptBlobRead::NotNamed,
                Err(reason) => {
                    tracing::warn!(
                        agent = %agent_id,
                        blob = %hex::encode(blob_hash),
                        %reason,
                        "prompt history: withholding a stored file that failed verification"
                    );
                    PromptBlobRead::Withheld(reason)
                }
            },
        )
    }
}

fn blob_key(file: &str, hash: Option<Vec<u8>>) -> Result<Option<[u8; 32]>, DbError> {
    hash.map(|h| {
        <[u8; 32]>::try_from(h.as_slice()).map_err(|_| DbError::InvalidData {
            reason: format!("prompt history: the {file} key is not 32 bytes"),
        })
    })
    .transpose()
}

fn index_entry(r: IndexRow) -> Result<PromptHistoryIndexEntry, DbError> {
    let snapshot = match r.snapshot_id {
        None => None,
        Some(id) => Some(PromptSnapshotIndex {
            id,
            group_folder: r.group_folder.unwrap_or_default(),
            model: r.model.unwrap_or_default(),
            prompt_hash: r.prompt_hash.unwrap_or_default(),
            identity_md: blob_key("identity_md", r.identity_md_hash)?,
            global_claude_md: blob_key("global_claude_md", r.global_claude_md_hash)?,
            group_claude_md: blob_key("group_claude_md", r.group_claude_md_hash)?,
            learned_md: blob_key("learned_md", r.learned_md_hash)?,
            in_prompt: r.in_prompt.unwrap_or(Value::Null),
            blob_refused: r.blob_refused.unwrap_or_default(),
            runner_version: r.runner_version,
            host_sha: r.host_sha,
            first_seen: r.first_seen.unwrap_or_default(),
            last_seen: r.last_seen.unwrap_or_default(),
        }),
    };
    Ok(PromptHistoryIndexEntry {
        agent_id: r.agent_id,
        relation: r.relation,
        depth: r.depth,
        readable: r.readable,
        snapshot,
    })
}

fn history_entry(r: HistoryRow) -> PromptHistoryEntry {
    let snapshot = r.snapshot_id.map(|id| {
        let mut withheld_files = Vec::new();
        let mut take =
            |file: &str, hash: Option<Vec<u8>>, content: Option<Vec<u8>>| match verified_blob(
                file, hash, content,
            ) {
                Ok(blob) => blob,
                Err(reason) => {
                    tracing::warn!(
                        snapshot = %id,
                        file,
                        %reason,
                        "prompt history: withholding a stored file that failed verification"
                    );
                    withheld_files.push(file.to_string());
                    None
                }
            };
        let identity_md = take("identity_md", r.identity_md_hash, r.identity_md);
        let global_claude_md = take(
            "global_claude_md",
            r.global_claude_md_hash,
            r.global_claude_md,
        );
        let group_claude_md = take("group_claude_md", r.group_claude_md_hash, r.group_claude_md);
        let learned_md = take("learned_md", r.learned_md_hash, r.learned_md);
        PromptSnapshot {
            id,
            group_folder: r.group_folder.unwrap_or_default(),
            model: r.model.unwrap_or_default(),
            prompt_hash: r.prompt_hash.unwrap_or_default(),
            identity_md,
            global_claude_md,
            group_claude_md,
            learned_md,
            in_prompt: r.in_prompt.unwrap_or(Value::Null),
            blob_refused: r.blob_refused.unwrap_or_default(),
            withheld_files,
            runner_version: r.runner_version,
            host_sha: r.host_sha,
            first_seen: r.first_seen.unwrap_or_default(),
            last_seen: r.last_seen.unwrap_or_default(),
        }
    });
    PromptHistoryEntry {
        agent_id: r.agent_id,
        relation: r.relation,
        depth: r.depth,
        readable: r.readable,
        snapshot,
    }
}

/// Decompress one stored file and check it against its key. `Ok(None)` for a
/// file the snapshot does not have; `Err(reason)` for one that must be
/// withheld.
fn verified_blob(
    file: &str,
    hash: Option<Vec<u8>>,
    content: Option<Vec<u8>>,
) -> Result<Option<PromptBlob>, String> {
    let (hash, content) = match (hash, content) {
        (None, None) => return Ok(None),
        (Some(h), Some(c)) => (h, c),
        _ => {
            return Err(format!(
                "{file}: a snapshot names a blob the history did not return"
            ))
        }
    };
    let blob_hash: [u8; 32] = hash
        .as_slice()
        .try_into()
        .map_err(|_| format!("{file}: a blob key is not 32 bytes"))?;
    let bytes = zstd::bulk::decompress(&content, MAX_PROMPT_FILE_BYTES)
        .map_err(|e| format!("{file}: the stored blob does not decompress: {e}"))?;
    if blake3::hash(&bytes).as_bytes() != &blob_hash {
        return Err(format!(
            "{file}: the stored blob does not hash to its key {}",
            hex::encode(blob_hash)
        ));
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
    fn a_frame_that_does_not_hash_to_its_key_is_withheld() {
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
        let reason = verified_blob(
            "f",
            Some(blake3::hash(b"other").as_bytes().to_vec()),
            Some(frame),
        )
        .expect_err("mismatch");
        assert!(reason.contains("does not hash to its key"), "{reason}");
    }
}
