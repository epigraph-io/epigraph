//! Repository for content-addressed blob storage.
//!
//! Bytes live on the filesystem under a hash-derived path
//! (`epigraph_core::blob::storage_path`); this table holds only the metadata
//! row. Per CLAUDE.md every blob SQL statement lives here — the HTTP routes and
//! the `attach_blob` MCP tool both call this module and never write blob SQL of
//! their own.
//!
//! # Write order (inverted vs episcience)
//!
//! episcience writes `tmp -> INSERT -> commit -> rename`. This repository does
//! `hash -> write tmp -> fsync -> atomic rename -> INSERT`, because the two
//! failure modes are not symmetric: a DB row pointing at a missing file is a
//! broken read (a 500 on every download of that blob) while an orphan file with
//! no row is inert garbage. The tmp file is named `{hex}.{uuid}.tmp` so
//! concurrent writers of identical bytes never collide, which also removes
//! episcience's `create_new` / `AlreadyExists` branch.
//!
//! On INSERT failure the final file is deliberately NOT removed — another
//! uploader's row may already reference the same content hash.
//!
//! # Subject binding
//!
//! There is no subject column. `attach_to_claim` writes a
//! `claim -[derived_from]-> blob` edge through [`EdgeRepository`], never
//! hand-rolled edge SQL. That is two transactions and is deliberately
//! non-atomic; `docs/architecture/noun-claims-and-verb-edges.md` sanctions
//! exactly this sequence and tolerates an unattached noun if the edge write
//! fails.

use std::path::Path;

use epigraph_core::blob::{sanitize_filename, storage_path};
use epigraph_core::BlobRef;
use epigraph_crypto::ContentHasher;
use sqlx::PgPool;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

use crate::errors::DbError;
use crate::repos::edge::EdgeRepository;

/// Entity type name registered for `blobs` in `entity_types` (migration 070).
pub const BLOB_ENTITY_TYPE: &str = "blob";

/// The verb on the in-band attach edge. Fixed in v1 and not caller-selectable:
/// `derived_from` is already documented in the edge API as "derivative →
/// source", which is exactly "this claim was read off that raw file". Any other
/// verb is reachable through the generic `POST /api/v1/edges`, which accepts
/// `target_type = "blob"` the moment migration 070 has been applied.
pub const ATTACH_RELATIONSHIP: &str = "derived_from";

/// Outcome of [`BlobRepository::store`].
#[derive(Debug, Clone)]
pub struct StoredBlob {
    /// The canonical row for `(content_hash, uploader_id)`.
    pub blob: BlobRef,
    /// `false` when identical bytes from this uploader were already recorded
    /// and the existing row was returned instead — the blob analogue of the
    /// claims `if_not_exists: true` contract.
    pub was_created: bool,
    /// Id of the `claim -[derived_from]-> blob` edge, when `attach_to_claim`
    /// was supplied.
    pub edge_id: Option<Uuid>,
    /// `false` when the attach edge already existed. Re-occurrence is an edge
    /// concern, so the attach is still evaluated even when `was_created` is
    /// `false`.
    pub edge_created: bool,
}

pub struct BlobRepository;

impl BlobRepository {
    /// Write `content` to the content-addressed store and record its metadata.
    ///
    /// Idempotent on `(content_hash, uploader_id)`: re-storing identical bytes
    /// as the same uploader returns the existing row with `was_created =
    /// false`. Two *different* uploaders of identical bytes get two rows over
    /// one on-disk file — provenance preserved, storage deduplicated.
    ///
    /// # Errors
    /// - [`DbError::InvalidData`] for an empty payload or an unsafe filename
    ///   (nothing is written in either case).
    /// - [`DbError::Io`] if the bytes cannot be written to `blob_dir`.
    /// - [`DbError::QueryFailed`] if the metadata insert or the attach edge
    ///   fails — including when `attach_to_claim` names a claim that does not
    ///   exist, which the `edges` validation trigger rejects.
    #[allow(clippy::too_many_arguments)]
    pub async fn store(
        pool: &PgPool,
        blob_dir: &Path,
        filename: &str,
        mime_type: &str,
        content: &[u8],
        uploader_id: Uuid,
        attach_to_claim: Option<Uuid>,
        labels: &[String],
        properties: &serde_json::Value,
    ) -> Result<StoredBlob, DbError> {
        // Guard BEFORE touching the filesystem so a rejected upload leaves no
        // trace: zero files under `blob_dir`, zero rows in `blobs`.
        if content.is_empty() {
            return Err(DbError::InvalidData {
                reason: "blob content must not be empty".to_string(),
            });
        }
        let filename = sanitize_filename(filename).map_err(|e| DbError::InvalidData {
            reason: e.to_string(),
        })?;
        let mime_type = mime_type.trim();
        if mime_type.is_empty() {
            return Err(DbError::InvalidData {
                reason: "blob mime_type must not be empty".to_string(),
            });
        }

        let content_hash = ContentHasher::hash(content);
        let size_bytes = i64::try_from(content.len()).map_err(|_| DbError::InvalidData {
            reason: format!("blob too large to record: {} bytes", content.len()),
        })?;

        Self::write_content(blob_dir, &content_hash, content).await?;

        // ON CONFLICT DO NOTHING + re-SELECT rather than DO UPDATE: the row is
        // a provenance record of who first uploaded these bytes, so a later
        // upload must not silently rewrite its filename, labels or properties.
        let inserted = sqlx::query_as!(
            BlobRef,
            r#"
            INSERT INTO blobs (filename, mime_type, size_bytes, content_hash,
                               uploader_id, labels, properties)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (content_hash, uploader_id) DO NOTHING
            RETURNING id, filename, mime_type, size_bytes, content_hash,
                      uploader_id, labels, properties, created_at
            "#,
            filename,
            mime_type,
            size_bytes,
            &content_hash[..],
            uploader_id,
            labels,
            properties,
        )
        .fetch_optional(pool)
        .await?;

        let (blob, was_created) = match inserted {
            Some(blob) => (blob, true),
            None => (
                Self::get_by_content_hash_and_uploader(pool, &content_hash, uploader_id).await?,
                false,
            ),
        };

        // In-band attach: a separate `create_edge` call the caller must
        // remember is a call the caller eventually forgets.
        let (edge_id, edge_created) = match attach_to_claim {
            Some(claim_id) => {
                let (edge, created) = EdgeRepository::create_if_not_exists(
                    pool,
                    claim_id,
                    "claim",
                    blob.id,
                    BLOB_ENTITY_TYPE,
                    ATTACH_RELATIONSHIP,
                    None,
                    None,
                    None,
                )
                .await?;
                (Some(edge.id), created)
            }
            None => (None, false),
        };

        Ok(StoredBlob {
            blob,
            was_created,
            edge_id,
            edge_created,
        })
    }

    /// Metadata for one blob.
    ///
    /// # Errors
    /// [`DbError::NotFound`] when no such row exists.
    pub async fn get_by_id(pool: &PgPool, id: Uuid) -> Result<BlobRef, DbError> {
        sqlx::query_as!(
            BlobRef,
            r#"
            SELECT id, filename, mime_type, size_bytes, content_hash,
                   uploader_id, labels, properties, created_at
            FROM blobs
            WHERE id = $1
            "#,
            id,
        )
        .fetch_optional(pool)
        .await?
        .ok_or(DbError::NotFound {
            entity: "blob".to_string(),
            id,
        })
    }

    /// Blobs reachable from `claim_id` over an outgoing edge, newest first.
    ///
    /// Deliberately unfiltered on `relationship`: `store` writes
    /// `derived_from`, but a blob attached under any other verb through the
    /// generic edges API is just as much an attachment of this claim and must
    /// still surface here.
    ///
    /// # Errors
    /// [`DbError::QueryFailed`] on a database error.
    pub async fn list_for_claim(pool: &PgPool, claim_id: Uuid) -> Result<Vec<BlobRef>, DbError> {
        // DISTINCT: two verbs between the same claim and blob are two edges but
        // one attachment.
        let rows = sqlx::query_as!(
            BlobRef,
            r#"
            SELECT DISTINCT
                   b.id            AS "id!",
                   b.filename      AS "filename!",
                   b.mime_type     AS "mime_type!",
                   b.size_bytes    AS "size_bytes!",
                   b.content_hash  AS "content_hash!",
                   b.uploader_id   AS "uploader_id!",
                   b.labels        AS "labels!",
                   b.properties    AS "properties!",
                   b.created_at    AS "created_at!"
            FROM blobs b
            JOIN edges e ON e.target_id = b.id
            WHERE e.source_id = $1
              AND e.source_type = 'claim'
              AND e.target_type = 'blob'
            ORDER BY "created_at!" DESC
            "#,
            claim_id,
        )
        .fetch_all(pool)
        .await?;
        Ok(rows)
    }

    /// Read a blob's bytes back off the filesystem.
    ///
    /// # Errors
    /// - [`DbError::NotFound`] with `entity = "blob_content"` when the row
    ///   exists but its file does not, so the route answers 404 rather than
    ///   500. (In a multi-replica deployment this is the symptom of replicas
    ///   not sharing a blob volume.)
    /// - [`DbError::Io`] for any other filesystem failure.
    /// - [`DbError::InvalidData`] if the stored digest is malformed, which the
    ///   `blobs_content_hash_length` CHECK makes unreachable for real rows.
    pub async fn read_content(blob_dir: &Path, blob: &BlobRef) -> Result<Vec<u8>, DbError> {
        let path = blob
            .storage_path(blob_dir)
            .map_err(|e| DbError::InvalidData {
                reason: e.to_string(),
            })?;
        tokio::fs::read(&path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                tracing::warn!(
                    blob_id = %blob.id,
                    path = %path.display(),
                    "blob row exists but its content file is missing"
                );
                DbError::NotFound {
                    entity: "blob_content".to_string(),
                    id: blob.id,
                }
            } else {
                DbError::Io {
                    message: format!("failed to read {}: {e}", path.display()),
                }
            }
        })
    }

    /// Re-hash the on-disk bytes and compare against the recorded digest.
    ///
    /// `false` means the file was modified after it was written — the whole
    /// point of content addressing is that this is detectable.
    ///
    /// # Errors
    /// Whatever [`read_content`](Self::read_content) returns.
    pub async fn verify_integrity(blob_dir: &Path, blob: &BlobRef) -> Result<bool, DbError> {
        let content = Self::read_content(blob_dir, blob).await?;
        Ok(ContentHasher::hash(&content)[..] == blob.content_hash[..])
    }

    /// Re-SELECT after `ON CONFLICT DO NOTHING`.
    async fn get_by_content_hash_and_uploader(
        pool: &PgPool,
        content_hash: &[u8],
        uploader_id: Uuid,
    ) -> Result<BlobRef, DbError> {
        sqlx::query_as!(
            BlobRef,
            r#"
            SELECT id, filename, mime_type, size_bytes, content_hash,
                   uploader_id, labels, properties, created_at
            FROM blobs
            WHERE content_hash = $1 AND uploader_id = $2
            "#,
            content_hash,
            uploader_id,
        )
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| DbError::Io {
            message: "blob insert conflicted but the conflicting row vanished".to_string(),
        })
    }

    /// Write `content` to its content-addressed path, atomically.
    ///
    /// Skips the write entirely when the final path already holds these bytes
    /// (content addressing makes the path itself the dedup key). Otherwise
    /// writes a per-writer unique tmp file, fsyncs it, and renames it into
    /// place; `rename(2)` within a directory is atomic, so a reader never
    /// observes a partial file.
    async fn write_content(
        blob_dir: &Path,
        content_hash: &[u8],
        content: &[u8],
    ) -> Result<(), DbError> {
        let final_path = storage_path(blob_dir, content_hash).map_err(|e| DbError::Io {
            message: e.to_string(),
        })?;
        if tokio::fs::try_exists(&final_path).await.unwrap_or(false) {
            return Ok(());
        }

        let dir = final_path.parent().ok_or_else(|| DbError::Io {
            message: format!("blob path has no parent: {}", final_path.display()),
        })?;
        tokio::fs::create_dir_all(dir)
            .await
            .map_err(|e| DbError::Io {
                message: format!("failed to create {}: {e}", dir.display()),
            })?;

        // `{hex}.{uuid}.tmp` — unique per writer, so two processes storing the
        // same bytes concurrently never fight over one tmp name.
        let tmp_path = dir.join(format!(
            "{}.{}.tmp",
            epigraph_core::blob::hash_hex(content_hash),
            Uuid::new_v4()
        ));

        let write_result = async {
            let mut file = tokio::fs::File::create(&tmp_path).await?;
            file.write_all(content).await?;
            file.sync_all().await
        }
        .await;

        if let Err(e) = write_result {
            let _ = tokio::fs::remove_file(&tmp_path).await;
            return Err(DbError::Io {
                message: format!("failed to write {}: {e}", tmp_path.display()),
            });
        }

        if let Err(e) = tokio::fs::rename(&tmp_path, &final_path).await {
            let _ = tokio::fs::remove_file(&tmp_path).await;
            return Err(DbError::Io {
                message: format!("failed to publish {}: {e}", final_path.display()),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use epigraph_core::blob::hash_hex;
    use sqlx::PgPool;
    use std::path::PathBuf;
    use tempfile::TempDir;

    // ── Scaffolding ──

    async fn seed_agent(pool: &PgPool, name: &str) -> Uuid {
        let mut pub_key = vec![0u8; 32];
        for b in pub_key.iter_mut() {
            *b = rand_byte();
        }
        sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO agents (public_key, display_name) VALUES ($1, $2) RETURNING id",
        )
        .bind(&pub_key)
        .bind(name)
        .fetch_one(pool)
        .await
        .unwrap()
    }

    /// Tiny xorshift so the test crate needs no `rand` dev-dep.
    fn rand_byte() -> u8 {
        use std::cell::Cell;
        thread_local! {
            static STATE: Cell<u64> = const { Cell::new(0x2545_F491_4F6C_DD1D) };
        }
        STATE.with(|s| {
            let mut x = s.get();
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            s.set(x);
            (x >> 33) as u8
        })
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

    /// Deterministic pseudo-random payload — real bytes, not a repeated
    /// constant that a broken writer could accidentally reproduce.
    fn payload(len: usize, seed: u64) -> Vec<u8> {
        // Mix before forcing oddness: `seed | 1` alone maps 100 and 101 to the
        // same state, which would silently make two "different" payloads
        // identical (and dedup into one blob).
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

    /// Every regular file under `root`, recursively (`.tmp` leftovers
    /// included — their presence would be a bug).
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
        out.sort();
        out
    }

    fn empty_props() -> serde_json::Value {
        serde_json::json!({})
    }

    // ── Tests ──

    /// Real bytes on a real filesystem path: the file lands at exactly the
    /// hash-derived location and reads back byte-identical.
    #[sqlx::test(migrations = "../../migrations")]
    async fn store_writes_real_bytes_and_read_content_round_trips(pool: PgPool) {
        let dir = TempDir::new().unwrap();
        let agent = seed_agent(&pool, "blob-repo-test").await;
        let content = payload(1024 * 1024, 0xA11CE);

        let stored = BlobRepository::store(
            &pool,
            dir.path(),
            "gel.tif",
            "image/tiff",
            &content,
            agent,
            None,
            &["raw".to_string()],
            &empty_props(),
        )
        .await
        .unwrap();

        assert!(stored.was_created);
        assert_eq!(stored.blob.size_bytes, content.len() as i64);
        assert_eq!(
            stored.blob.content_hash,
            ContentHasher::hash(&content).to_vec()
        );

        // The literal path the layout promises.
        let hex = hash_hex(&stored.blob.content_hash);
        let expected = dir
            .path()
            .join(&hex[0..2])
            .join(&hex[2..4])
            .join(format!("{hex}.blob"));
        assert!(expected.exists(), "no file at {}", expected.display());
        assert_eq!(std::fs::read(&expected).unwrap(), content);

        // ... and the repository reads the same bytes back.
        let read = BlobRepository::read_content(dir.path(), &stored.blob)
            .await
            .unwrap();
        assert_eq!(read, content);

        // No tmp leftovers.
        assert_eq!(walk_files(dir.path()), vec![expected]);
    }

    /// `(content_hash, uploader_id)` is the canonical key: a re-upload returns
    /// the existing row instead of a second one.
    #[sqlx::test(migrations = "../../migrations")]
    async fn store_is_idempotent_on_content_hash_and_uploader(pool: PgPool) {
        let dir = TempDir::new().unwrap();
        let agent = seed_agent(&pool, "blob-repo-idem").await;
        let content = payload(4096, 0xBEEF);

        let first = BlobRepository::store(
            &pool,
            dir.path(),
            "run.csv",
            "text/csv",
            &content,
            agent,
            None,
            &[],
            &empty_props(),
        )
        .await
        .unwrap();
        let second = BlobRepository::store(
            &pool,
            dir.path(),
            "run.csv",
            "text/csv",
            &content,
            agent,
            None,
            &[],
            &empty_props(),
        )
        .await
        .unwrap();

        assert!(first.was_created);
        assert!(!second.was_created, "second store must reuse the row");
        assert_eq!(first.blob.id, second.blob.id);

        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM blobs")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 1);
        assert_eq!(walk_files(dir.path()).len(), 1);
    }

    /// Two uploaders, identical bytes: two rows (provenance) over one file
    /// (storage dedup).
    #[sqlx::test(migrations = "../../migrations")]
    async fn store_same_bytes_two_uploaders_yields_two_rows_one_file(pool: PgPool) {
        let dir = TempDir::new().unwrap();
        let alice = seed_agent(&pool, "blob-alice").await;
        let bob = seed_agent(&pool, "blob-bob").await;
        let content = payload(2048, 0xC0FFEE);

        let a = BlobRepository::store(
            &pool,
            dir.path(),
            "shared.bin",
            "application/octet-stream",
            &content,
            alice,
            None,
            &[],
            &empty_props(),
        )
        .await
        .unwrap();
        let b = BlobRepository::store(
            &pool,
            dir.path(),
            "shared.bin",
            "application/octet-stream",
            &content,
            bob,
            None,
            &[],
            &empty_props(),
        )
        .await
        .unwrap();

        assert!(a.was_created && b.was_created);
        assert_ne!(a.blob.id, b.blob.id);
        assert_eq!(a.blob.content_hash, b.blob.content_hash);
        assert_eq!(a.blob.uploader_id, alice);
        assert_eq!(b.blob.uploader_id, bob);

        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM blobs")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 2);
        assert_eq!(
            walk_files(dir.path()).len(),
            1,
            "identical bytes must share one file"
        );
    }

    /// The subject-binding decision, end to end. This INSERT only succeeds if
    /// migration 070's `entity_types` row satisfies `edges_target_type_fkey`
    /// AND `validate_edge_reference`'s registry-driven ELSE arm finds the row
    /// in `public.blobs`.
    #[sqlx::test(migrations = "../../migrations")]
    async fn attach_to_claim_creates_claim_to_blob_edge(pool: PgPool) {
        let dir = TempDir::new().unwrap();
        let agent = seed_agent(&pool, "blob-attach").await;
        let claim = seed_claim(&pool, agent, "densitometry says 0.42").await;

        let stored = BlobRepository::store(
            &pool,
            dir.path(),
            "blot.tif",
            "image/tiff",
            &payload(512, 7),
            agent,
            Some(claim),
            &[],
            &empty_props(),
        )
        .await
        .unwrap();

        assert!(stored.edge_created);
        let edge_id = stored.edge_id.expect("attach edge id");

        let row = sqlx::query!(
            "SELECT source_id, source_type, target_id, target_type, relationship \
             FROM edges WHERE id = $1",
            edge_id
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(row.source_id, claim);
        assert_eq!(row.source_type, "claim");
        assert_eq!(row.target_id, stored.blob.id);
        assert_eq!(row.target_type, "blob");
        assert_eq!(row.relationship, "derived_from");
    }

    /// The attach edge is an invariant relationship, so it is created once.
    #[sqlx::test(migrations = "../../migrations")]
    async fn attach_is_idempotent_no_duplicate_edge(pool: PgPool) {
        let dir = TempDir::new().unwrap();
        let agent = seed_agent(&pool, "blob-attach-idem").await;
        let claim = seed_claim(&pool, agent, "same measurement, twice").await;
        let content = payload(256, 11);

        let first = BlobRepository::store(
            &pool,
            dir.path(),
            "m.dat",
            "application/octet-stream",
            &content,
            agent,
            Some(claim),
            &[],
            &empty_props(),
        )
        .await
        .unwrap();
        let second = BlobRepository::store(
            &pool,
            dir.path(),
            "m.dat",
            "application/octet-stream",
            &content,
            agent,
            Some(claim),
            &[],
            &empty_props(),
        )
        .await
        .unwrap();

        assert!(first.edge_created);
        assert!(!second.was_created, "blob row is reused");
        assert!(!second.edge_created, "edge must not be duplicated");
        assert_eq!(first.edge_id, second.edge_id);

        let edges: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM edges WHERE source_id = $1 AND target_type = 'blob'",
        )
        .bind(claim)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(edges, 1);
    }

    /// The registry existence check is LIVE for blobs, not merely an FK on the
    /// type name: an edge to a blob id that does not exist is rejected by
    /// `trigger_validate_edge_refs` with SQLSTATE 23503.
    #[sqlx::test(migrations = "../../migrations")]
    async fn edge_to_nonexistent_blob_id_is_rejected(pool: PgPool) {
        let agent = seed_agent(&pool, "blob-fk").await;
        let claim = seed_claim(&pool, agent, "claim with no blob").await;

        let err = sqlx::query(
            "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
             VALUES ($1, 'claim', $2, 'blob', 'derived_from')",
        )
        .bind(claim)
        .bind(Uuid::new_v4())
        .execute(&pool)
        .await
        .expect_err("edge to a nonexistent blob must be rejected");

        let db_err = err.as_database_error().expect("database error");
        assert_eq!(
            db_err.code().as_deref(),
            Some("23503"),
            "expected foreign_key_violation, got {db_err:?}"
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn list_for_claim_returns_only_attached_blobs(pool: PgPool) {
        let dir = TempDir::new().unwrap();
        let agent = seed_agent(&pool, "blob-list").await;
        let claim = seed_claim(&pool, agent, "two attachments").await;

        let mut attached = Vec::new();
        for (i, name) in ["one.bin", "two.bin"].iter().enumerate() {
            let stored = BlobRepository::store(
                &pool,
                dir.path(),
                name,
                "application/octet-stream",
                &payload(128, 100 + i as u64),
                agent,
                Some(claim),
                &[],
                &empty_props(),
            )
            .await
            .unwrap();
            attached.push(stored.blob.id);
        }
        // A third blob, deliberately unattached.
        let loose = BlobRepository::store(
            &pool,
            dir.path(),
            "loose.bin",
            "application/octet-stream",
            &payload(128, 999),
            agent,
            None,
            &[],
            &empty_props(),
        )
        .await
        .unwrap();

        let listed = BlobRepository::list_for_claim(&pool, claim).await.unwrap();
        let listed_ids: Vec<Uuid> = listed.iter().map(|b| b.id).collect();
        assert_eq!(listed_ids.len(), 2);
        for id in &attached {
            assert!(listed_ids.contains(id));
        }
        assert!(!listed_ids.contains(&loose.blob.id));
        // Newest first.
        assert!(listed[0].created_at >= listed[1].created_at);
    }

    /// Real corruption of a real file.
    #[sqlx::test(migrations = "../../migrations")]
    async fn verify_integrity_detects_on_disk_corruption(pool: PgPool) {
        let dir = TempDir::new().unwrap();
        let agent = seed_agent(&pool, "blob-verify").await;
        let content = payload(4096, 0xD1CE);

        let stored = BlobRepository::store(
            &pool,
            dir.path(),
            "instrument.raw",
            "application/octet-stream",
            &content,
            agent,
            None,
            &[],
            &empty_props(),
        )
        .await
        .unwrap();

        assert!(BlobRepository::verify_integrity(dir.path(), &stored.blob)
            .await
            .unwrap());

        let path = stored.blob.storage_path(dir.path()).unwrap();
        std::fs::write(&path, payload(4096, 0xBAD)).unwrap();

        assert!(
            !BlobRepository::verify_integrity(dir.path(), &stored.blob)
                .await
                .unwrap(),
            "modified bytes must fail verification"
        );
    }

    /// A row whose file has vanished is a 404, not a 500.
    #[sqlx::test(migrations = "../../migrations")]
    async fn read_content_missing_file_is_not_found(pool: PgPool) {
        let dir = TempDir::new().unwrap();
        let agent = seed_agent(&pool, "blob-missing").await;

        let stored = BlobRepository::store(
            &pool,
            dir.path(),
            "vanishing.bin",
            "application/octet-stream",
            &payload(64, 3),
            agent,
            None,
            &[],
            &empty_props(),
        )
        .await
        .unwrap();

        std::fs::remove_file(stored.blob.storage_path(dir.path()).unwrap()).unwrap();

        match BlobRepository::read_content(dir.path(), &stored.blob).await {
            Err(DbError::NotFound { entity, id }) => {
                assert_eq!(entity, "blob_content");
                assert_eq!(id, stored.blob.id);
            }
            other => panic!("expected NotFound{{blob_content}}, got {other:?}"),
        }
    }

    /// Hostile filenames are rejected before anything is written.
    #[sqlx::test(migrations = "../../migrations")]
    async fn store_rejects_hostile_filename(pool: PgPool) {
        let dir = TempDir::new().unwrap();
        let agent = seed_agent(&pool, "blob-hostile").await;

        for bad in ["evil\"; rm -rf /", "a\nb", "../../etc/passwd"] {
            let result = BlobRepository::store(
                &pool,
                dir.path(),
                bad,
                "application/octet-stream",
                &payload(32, 5),
                agent,
                None,
                &[],
                &empty_props(),
            )
            .await;
            assert!(
                matches!(result, Err(DbError::InvalidData { .. })),
                "{bad:?} must be InvalidData, got {result:?}"
            );
        }

        assert!(walk_files(dir.path()).is_empty(), "nothing may be written");
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM blobs")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 0);
    }

    /// The Rust guard fires before the `blobs_size_positive` CHECK is reached.
    #[sqlx::test(migrations = "../../migrations")]
    async fn store_rejects_empty_content(pool: PgPool) {
        let dir = TempDir::new().unwrap();
        let agent = seed_agent(&pool, "blob-empty").await;

        let result = BlobRepository::store(
            &pool,
            dir.path(),
            "nothing.bin",
            "application/octet-stream",
            &[],
            agent,
            None,
            &[],
            &empty_props(),
        )
        .await;
        assert!(
            matches!(result, Err(DbError::InvalidData { .. })),
            "expected InvalidData, got {result:?}"
        );

        assert!(walk_files(dir.path()).is_empty());
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM blobs")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 0);
    }
}
