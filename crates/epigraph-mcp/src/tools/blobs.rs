//! `attach_blob` — the single MCP entry point to content-addressed blob storage.
//!
//! MCP has no binary frame, so the payload arrives base64-encoded and is
//! decoded server-side; everything after that — BLAKE3 hash, content-addressed
//! filesystem write, metadata row, and the optional
//! `claim -[derived_from]-> blob` edge — is delegated to
//! [`BlobRepository::store`], the same helper the HTTP route calls.
//!
//! Exactly one tool ships here, matching episcience (which also exposes only
//! `attach_blob` over MCP and serves reads over HTTP). Read tools are
//! deliberately absent.
//!
//! Auth: the uploader is `EpiGraphMcpFull::agent_id()` and nothing else. There
//! is no `uploader_id` parameter to spoof.

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use rmcp::model::{CallToolResult, Content};
use serde::Serialize;
use uuid::Uuid;

use epigraph_db::BlobRepository;

use crate::errors::{internal_error, invalid_params, parse_uuid, McpError};
use crate::server::EpiGraphMcpFull;
use crate::types::AttachBlobParams;

const DEFAULT_FILENAME: &str = "unnamed";
const DEFAULT_MIME: &str = "application/octet-stream";

#[derive(Debug, Serialize)]
struct AttachBlobResult {
    id: Uuid,
    content_hash: String,
    size_bytes: i64,
    filename: String,
    mime_type: String,
    /// `false` when identical bytes from this agent were already stored and the
    /// existing row was returned.
    was_created: bool,
    attached_claim_id: Option<Uuid>,
    edge_id: Option<Uuid>,
    edge_created: bool,
}

pub async fn attach_blob(
    server: &EpiGraphMcpFull,
    params: AttachBlobParams,
) -> Result<CallToolResult, McpError> {
    // Guarded here as well as in the `#[tool_router]` method, exactly as
    // `tools::matching::decide_match_candidate` does: the write path must be
    // closed no matter which entry point reaches it.
    server.reject_if_read_only()?;

    if params.file_bytes_base64.trim().is_empty() {
        return Err(invalid_params("file_bytes_base64 cannot be empty"));
    }

    // Decode BEFORE the size check so the ceiling applies to the real payload,
    // not to its 33%-inflated wire form.
    let bytes = BASE64_STANDARD
        .decode(params.file_bytes_base64.trim().as_bytes())
        .map_err(|e| invalid_params(format!("invalid base64: {e}")))?;

    if bytes.len() > server.max_blob_bytes {
        return Err(invalid_params(format!(
            "blob is {} bytes, exceeding the {}-byte limit",
            bytes.len(),
            server.max_blob_bytes
        )));
    }

    let filename = params
        .filename
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(DEFAULT_FILENAME);
    let mime_type = params
        .mime_type
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(DEFAULT_MIME);

    // `Option<Uuid>` is not expressible in this crate's JsonSchema derive (no
    // schemars uuid feature), so the wire type is a string — same as every
    // other id parameter in `types.rs`. An unparseable value is rejected, not
    // silently dropped.
    let attach_to_claim_id = params
        .attach_to_claim_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(parse_uuid)
        .transpose()?;

    let properties = if params.properties.is_null() {
        serde_json::Value::Object(serde_json::Map::new())
    } else {
        params.properties
    };

    let uploader_id = server.agent_id().await?;

    let stored = BlobRepository::store(
        &server.pool,
        &server.blob_dir,
        filename,
        mime_type,
        &bytes,
        uploader_id,
        attach_to_claim_id,
        &params.labels,
        &properties,
    )
    .await
    .map_err(|e| match e {
        // A hostile filename or an empty payload is the caller's mistake, so it
        // must come back as INVALID_PARAMS rather than an opaque internal error.
        epigraph_db::DbError::InvalidData { reason } => invalid_params(reason),
        other => internal_error(other),
    })?;

    let result = AttachBlobResult {
        id: stored.blob.id,
        content_hash: stored.blob.hash_hex(),
        size_bytes: stored.blob.size_bytes,
        filename: stored.blob.filename.clone(),
        mime_type: stored.blob.mime_type.clone(),
        was_created: stored.was_created,
        attached_claim_id: attach_to_claim_id,
        edge_id: stored.edge_id,
        edge_created: stored.edge_created,
    };

    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(&result).map_err(internal_error)?,
    )]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD as B64;
    use epigraph_core::blob::hash_hex;
    use epigraph_crypto::{AgentSigner, ContentHasher};
    use sqlx::PgPool;
    use std::path::{Path, PathBuf};
    use tempfile::TempDir;

    // ── Scaffolding ──

    fn server(pool: PgPool, dir: &TempDir, read_only: bool) -> EpiGraphMcpFull {
        let embedder = crate::embed::McpEmbedder::new(pool.clone(), None);
        EpiGraphMcpFull::new(pool, AgentSigner::generate(), embedder, read_only)
            .with_blob_dir(dir.path().into())
    }

    fn params(bytes: &[u8]) -> AttachBlobParams {
        AttachBlobParams {
            file_bytes_base64: B64.encode(bytes),
            filename: Some("scan.raw".to_string()),
            mime_type: Some("application/octet-stream".to_string()),
            attach_to_claim_id: None,
            labels: Vec::new(),
            properties: serde_json::Value::Null,
        }
    }

    fn payload(len: usize, seed: u64) -> Vec<u8> {
        let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24) as u8
            })
            .collect()
    }

    fn walk_files(root: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let Ok(entries) = std::fs::read_dir(root) else {
            return out;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                out.extend(walk_files(&path));
            } else {
                out.push(path);
            }
        }
        out
    }

    async fn seed_claim(pool: &PgPool, agent_id: Uuid, content: &str) -> Uuid {
        let content_hash = ContentHasher::hash(content.as_bytes());
        sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO claims (content, content_hash, agent_id, truth_value, labels, properties) \
             VALUES ($1, $2, $3, 0.5, ARRAY[]::text[], '{}'::jsonb) RETURNING id",
        )
        .bind(content)
        .bind(content_hash.as_slice())
        .bind(agent_id)
        .fetch_one(pool)
        .await
        .unwrap()
    }

    // ── Tests ──

    /// Base64 in, REAL bytes on a REAL filesystem path out — byte-identical to
    /// the pre-encoding input — attributed to the server's own agent row.
    #[sqlx::test(migrations = "../../migrations")]
    async fn attach_blob_decodes_base64_and_writes_real_file(pool: PgPool) {
        let dir = TempDir::new().unwrap();
        let srv = server(pool.clone(), &dir, false);
        let content = payload(8192, 0xB10B);

        attach_blob(&srv, params(&content)).await.unwrap();

        let hex = hash_hex(&ContentHasher::hash(&content));
        let expected = dir
            .path()
            .join(&hex[0..2])
            .join(&hex[2..4])
            .join(format!("{hex}.blob"));
        assert!(expected.exists(), "no file at {}", expected.display());
        assert_eq!(std::fs::read(&expected).unwrap(), content);

        let uploader: Uuid = sqlx::query_scalar("SELECT uploader_id FROM blobs")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(uploader, srv.agent_id().await.unwrap());
    }

    /// MCP and HTTP must produce the same graph shape.
    #[sqlx::test(migrations = "../../migrations")]
    async fn attach_blob_attaches_to_claim(pool: PgPool) {
        let dir = TempDir::new().unwrap();
        let srv = server(pool.clone(), &dir, false);
        let agent = srv.agent_id().await.unwrap();
        let claim = seed_claim(&pool, agent, "MCP-attached measurement").await;

        let mut p = params(&payload(512, 9));
        p.attach_to_claim_id = Some(claim.to_string());
        attach_blob(&srv, p).await.unwrap();

        let row = sqlx::query!(
            "SELECT e.source_type, e.target_type, e.relationship, e.target_id \
             FROM edges e WHERE e.source_id = $1",
            claim
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(row.source_type, "claim");
        assert_eq!(row.target_type, "blob");
        assert_eq!(row.relationship, "derived_from");

        let blob_id: Uuid = sqlx::query_scalar("SELECT id FROM blobs")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(row.target_id, blob_id);
    }

    /// The cap applies to the DECODED payload, and a rejection writes nothing.
    #[sqlx::test(migrations = "../../migrations")]
    async fn attach_blob_rejects_oversize_decoded_payload(pool: PgPool) {
        let dir = TempDir::new().unwrap();
        let srv = server(pool.clone(), &dir, false).with_max_blob_bytes(1024);

        let err = attach_blob(&srv, params(&payload(4096, 12)))
            .await
            .expect_err("oversize payload must be rejected");
        assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS);

        assert!(walk_files(dir.path()).is_empty());
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM blobs")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 0);
    }

    /// `reject_if_read_only` fires before any filesystem or DB write.
    #[sqlx::test(migrations = "../../migrations")]
    async fn attach_blob_rejected_on_read_only_server(pool: PgPool) {
        let dir = TempDir::new().unwrap();
        let srv = server(pool.clone(), &dir, true);

        let err = attach_blob(&srv, params(&payload(256, 13)))
            .await
            .expect_err("read-only server must refuse attach_blob");
        assert!(
            format!("{err:?}").to_lowercase().contains("read-only"),
            "expected read-only refusal: {err:?}"
        );

        assert!(walk_files(dir.path()).is_empty());
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM blobs")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 0);
        // The read-only rejection must also precede agent creation.
        let agents: i64 = sqlx::query_scalar("SELECT count(*) FROM agents")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(agents, 0);
    }
}
