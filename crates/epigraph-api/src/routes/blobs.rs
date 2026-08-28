//! Content-addressed blob upload, download and integrity endpoints.
//!
//! - `POST   /api/v1/blobs` — upload raw bytes, optionally attaching them to a claim
//! - `GET    /api/v1/blobs/:id` — metadata
//! - `GET    /api/v1/blobs/:id/content` — the bytes
//! - `GET    /api/v1/blobs/:id/verify` — re-hash the file and compare
//! - `GET    /api/v1/claims/:id/blobs` — blobs attached to a claim
//!
//! No SQL lives here; every statement is in
//! `epigraph_db::repos::blob` per CLAUDE.md.
//!
//! # Body shape
//!
//! The upload body is a RAW byte stream, not multipart. Metadata rides in query
//! parameters with the `Content-Type` header as the mime fallback. Multipart's
//! only real advantage — several files and fields per request — is unused here,
//! it would cost a brand-new transitive dependency (`multer`, absent from
//! `Cargo.lock`), and raw bytes avoid base64's 33% inflation. The MCP tool
//! keeps base64 because that protocol has no binary frame.
//!
//! # Auth
//!
//! Every route here — reads included — sits on the `protected` router, so a
//! request without a Bearer token is rejected by `bearer_auth_middleware`
//! before a handler runs. The kernel has no blob-level privacy tier or
//! partition model, and raw instrument bytes are at least as sensitive as claim
//! text, so the correct default with no redaction machinery is closed.
//!
//! The uploader identity is taken ONLY from `AuthContext::agent_id` and is
//! never read off the wire — episcience accepted an `uploader_id` field and
//! compared it to auth; here there is no field to compare.

use axum::body::{Body, Bytes};
use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::Response;
use axum::Json;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::errors::ApiError;
use crate::state::AppState;
use epigraph_core::blob::{sanitize_filename, sanitize_mime_type};
use epigraph_core::BlobRef;
use epigraph_db::BlobRepository;

const DEFAULT_FILENAME: &str = "unnamed";
const DEFAULT_MIME: &str = "application/octet-stream";

/// Metadata for an upload. Everything is optional except the body itself.
#[derive(Debug, Default, Deserialize)]
pub struct UploadBlobQuery {
    /// Display filename. Rejected at write time if it carries a control
    /// character, `"`, `\` or `/`.
    #[serde(default)]
    pub filename: Option<String>,
    /// MIME type. Falls back to the request's `Content-Type` header, then to
    /// `application/octet-stream`. Never trusted for dispatch, and rejected at
    /// write time if it carries a control character or exceeds 255 characters —
    /// it is echoed into the `Content-Type` of `GET .../content`.
    #[serde(default)]
    pub mime_type: Option<String>,
    /// When set, a `claim -[derived_from]-> blob` edge is written in-band.
    #[serde(default)]
    pub attach_to_claim_id: Option<Uuid>,
    /// Comma-separated labels, e.g. `labels=raw,microscopy`.
    #[serde(default)]
    pub labels: Option<String>,
    /// URL-encoded JSON object of free-form properties.
    #[serde(default)]
    pub properties: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct UploadBlobResponse {
    pub id: Uuid,
    pub content_hash: String,
    pub size_bytes: i64,
    pub filename: String,
    pub mime_type: String,
    /// `false` when identical bytes from this uploader already existed and the
    /// existing row was returned — the blob analogue of `if_not_exists: true`.
    pub was_created: bool,
    pub attached_claim_id: Option<Uuid>,
    pub edge_id: Option<Uuid>,
    pub edge_created: bool,
}

#[derive(Debug, Serialize)]
pub struct VerifyBlobResponse {
    pub id: Uuid,
    pub content_hash: String,
    pub integrity_ok: bool,
}

/// `POST /api/v1/blobs`
///
/// # Errors
/// - 401 when the request carries no `AuthContext`.
/// - 403 when the token is not bound to an agent, so no uploader can be recorded.
/// - 400 for an empty body, an oversize body, an unsafe filename, an unsafe or
///   over-long `mime_type`, or unparseable `properties`.
#[cfg(feature = "db")]
pub async fn upload_blob(
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Query(query): Query<UploadBlobQuery>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<UploadBlobResponse>), ApiError> {
    // Fail closed: the uploader is the authenticated principal or nobody. An
    // unattributed blob is unauditable, and provenance is the kernel's whole
    // point.
    let axum::Extension(ref auth) = auth_ctx.ok_or(ApiError::Unauthorized {
        reason: "blob upload requires a Bearer token".to_string(),
    })?;
    let uploader_id = auth.agent_id.ok_or(ApiError::Forbidden {
        reason: "blob upload requires an AuthContext with a bound agent_id; \
                 service-only tokens without agent binding cannot be recorded \
                 as the uploader"
            .to_string(),
    })?;

    // Belt and braces alongside the route's own DefaultBodyLimit: the limit
    // layer rejects with a bare 413, this produces a message naming the cap.
    if body.len() > state.max_blob_bytes {
        return Err(ApiError::ValidationError {
            field: "body".to_string(),
            reason: format!(
                "blob is {} bytes, exceeding the {}-byte limit",
                body.len(),
                state.max_blob_bytes
            ),
        });
    }

    let filename = query
        .filename
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(DEFAULT_FILENAME);

    let mime_type = query
        .mime_type
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .or_else(|| {
            headers
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(ToString::to_string)
        })
        .unwrap_or_else(|| DEFAULT_MIME.to_string());

    let labels: Vec<String> = query
        .labels
        .as_deref()
        .map(|raw| {
            raw.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();

    let properties = match query.properties.as_deref().map(str::trim) {
        Some(raw) if !raw.is_empty() => {
            serde_json::from_str(raw).map_err(|e| ApiError::ValidationError {
                field: "properties".to_string(),
                reason: format!("invalid JSON: {e}"),
            })?
        }
        _ => serde_json::Value::Object(serde_json::Map::new()),
    };

    let stored = BlobRepository::store(
        &state.db_pool,
        &state.blob_dir,
        filename,
        &mime_type,
        &body,
        uploader_id,
        query.attach_to_claim_id,
        &labels,
        &properties,
    )
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(UploadBlobResponse {
            id: stored.blob.id,
            content_hash: stored.blob.hash_hex(),
            size_bytes: stored.blob.size_bytes,
            filename: stored.blob.filename.clone(),
            mime_type: stored.blob.mime_type.clone(),
            was_created: stored.was_created,
            attached_claim_id: query.attach_to_claim_id,
            edge_id: stored.edge_id,
            edge_created: stored.edge_created,
        }),
    ))
}

/// `GET /api/v1/blobs/:id`
///
/// # Errors
/// 404 when no such blob row exists.
#[cfg(feature = "db")]
pub async fn get_blob_metadata(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<BlobRef>, ApiError> {
    Ok(Json(BlobRepository::get_by_id(&state.db_pool, id).await?))
}

/// `GET /api/v1/blobs/:id/content`
///
/// Both header-bearing columns are re-checked here even though the write path
/// already guarantees them: a row poisoned before those guards shipped must
/// still be downloadable, with a fallback value rather than a 500.
///
/// # Errors
/// 404 when the row or its file is missing; 500 on any other I/O failure.
#[cfg(feature = "db")]
pub async fn download_blob(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let blob = BlobRepository::get_by_id(&state.db_pool, id).await?;
    let content = BlobRepository::read_content(&state.blob_dir, &blob).await?;
    let hash_hex = blob.hash_hex();

    // The filename was already sanitized at write time (Rust guard AND the
    // blobs_filename_safe CHECK), so this cannot fail for a well-formed row.
    // Re-checking here anyway: episcience interpolated an unvalidated,
    // caller-supplied string straight into this header, and a header is
    // exactly the place where a lone `"` changes the meaning of the response.
    let disposition = match sanitize_filename(&blob.filename) {
        Ok(name) => format!("attachment; filename=\"{name}\""),
        Err(e) => {
            tracing::error!(blob_id = %blob.id, error = %e, "stored blob filename is unsafe");
            "attachment".to_string()
        }
    };

    // Same belt and braces for the mime type, and for a sharper reason: an
    // unrenderable value here is not a truncated header but a dead row.
    // `Response::builder` defers the parse failure to `.body()`, so a blob
    // stored before `blobs_mime_type_safe` existed would answer 500 on every
    // download, forever. Falling back keeps the bytes reachable.
    let mime_type = match sanitize_mime_type(&blob.mime_type) {
        Ok(mime) => mime,
        Err(e) => {
            tracing::error!(blob_id = %blob.id, error = %e, "stored blob mime_type is unsafe");
            DEFAULT_MIME.to_string()
        }
    };

    Response::builder()
        .header(header::CONTENT_TYPE, mime_type.as_str())
        .header(header::CONTENT_DISPOSITION, disposition)
        .header("X-Content-Hash", hash_hex.as_str())
        .body(Body::from(content))
        .map_err(|e| ApiError::InternalError {
            message: format!("failed to build blob response: {e}"),
        })
}

/// `GET /api/v1/blobs/:id/verify`
///
/// # Errors
/// 404 when the row or its file is missing.
#[cfg(feature = "db")]
pub async fn verify_blob(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<VerifyBlobResponse>, ApiError> {
    let blob = BlobRepository::get_by_id(&state.db_pool, id).await?;
    let integrity_ok = BlobRepository::verify_integrity(&state.blob_dir, &blob).await?;
    Ok(Json(VerifyBlobResponse {
        id: blob.id,
        content_hash: blob.hash_hex(),
        integrity_ok,
    }))
}

/// `GET /api/v1/claims/:id/blobs`
///
/// # Errors
/// 500 on a database failure. An unknown claim id yields an empty list, not a
/// 404 — the query is over edges, not over the claim.
#[cfg(feature = "db")]
pub async fn list_blobs_for_claim(
    State(state): State<AppState>,
    Path(claim_id): Path<Uuid>,
) -> Result<Json<Vec<BlobRef>>, ApiError> {
    Ok(Json(
        BlobRepository::list_for_claim(&state.db_pool, claim_id).await?,
    ))
}

// =============================================================================
// DB-BACKED INTEGRATION TESTS
// =============================================================================

#[cfg(all(test, feature = "db"))]
mod db_tests {
    use super::*;
    use crate::middleware::bearer::AuthContext;
    use crate::middleware::ClientType;
    use crate::state::ApiConfig;
    use axum::extract::DefaultBodyLimit;
    use axum::routing::{get, post};
    use axum::{Extension, Router};
    use epigraph_crypto::ContentHasher;
    use http_body_util::BodyExt;
    use sqlx::PgPool;
    use std::path::{Path as FsPath, PathBuf};
    use tempfile::TempDir;
    use tower::ServiceExt;

    // ── Scaffolding (mirrors routes/edges.rs::db_tests) ──

    async fn test_state(pool: PgPool, dir: &TempDir) -> AppState {
        let state = AppState::with_db(pool, ApiConfig::default()).with_blob_dir(dir.path().into());
        state
            .load_entity_type_cache()
            .await
            .expect("load entity_types cache");
        state
    }

    async fn ensure_system_agent(pool: &PgPool) -> Uuid {
        let mut pub_key = vec![0u8; 32];
        for b in pub_key.iter_mut() {
            *b = rand::random();
        }
        sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO agents (public_key, display_name) VALUES ($1, $2) RETURNING id",
        )
        .bind(&pub_key)
        .bind("api-blobs-test")
        .fetch_one(pool)
        .await
        .unwrap()
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

    fn auth_ctx(agent_id: Uuid) -> AuthContext {
        AuthContext {
            client_id: Uuid::new_v4(),
            agent_id: Some(agent_id),
            owner_id: None,
            client_type: ClientType::Agent,
            scopes: vec!["claims:write".to_string(), "claims:read".to_string()],
            jti: Uuid::new_v4(),
        }
    }

    /// The real blob routes, mounted exactly as `create_router` mounts them —
    /// including the per-route `DefaultBodyLimit` override and the router-wide
    /// `config.max_request_size` limit it must beat.
    fn blobs_router(state: AppState) -> Router {
        let max_blob_bytes = state.max_blob_bytes;
        let max_request_size = state.config.max_request_size;
        Router::new()
            .route(
                "/api/v1/blobs",
                post(upload_blob).layer(DefaultBodyLimit::max(max_blob_bytes)),
            )
            .route("/api/v1/blobs/:id", get(get_blob_metadata))
            .route("/api/v1/blobs/:id/content", get(download_blob))
            .route("/api/v1/blobs/:id/verify", get(verify_blob))
            .route("/api/v1/claims/:id/blobs", get(list_blobs_for_claim))
            .layer(DefaultBodyLimit::max(max_request_size))
            .with_state(state)
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

    fn walk_files(root: &FsPath) -> Vec<PathBuf> {
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

    fn upload_request(uri: &str, content_type: &str, body: Vec<u8>) -> axum::http::Request<Body> {
        axum::http::Request::builder()
            .method("POST")
            .uri(uri)
            .header(header::CONTENT_TYPE, content_type)
            .body(Body::from(body))
            .unwrap()
    }

    fn get_request(uri: &str) -> axum::http::Request<Body> {
        axum::http::Request::builder()
            .uri(uri)
            .body(Body::empty())
            .unwrap()
    }

    async fn parse_body(response: Response) -> serde_json::Value {
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    // ── Tests ──

    /// End-to-end: the bytes that come back out of `GET .../content` are
    /// byte-identical to what went in, and the hash header matches BLAKE3.
    #[sqlx::test(migrations = "../../migrations")]
    async fn upload_then_download_round_trips_bytes(pool: PgPool) {
        let dir = TempDir::new().unwrap();
        let agent = ensure_system_agent(&pool).await;
        let state = test_state(pool, &dir).await;
        let router = blobs_router(state).layer(Extension(auth_ctx(agent)));

        let content = payload(64 * 1024, 0xF00D);
        let response = router
            .clone()
            .oneshot(upload_request(
                "/api/v1/blobs?filename=gel.tif&mime_type=image/tiff",
                "application/octet-stream",
                content.clone(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        let body = parse_body(response).await;
        assert_eq!(body["filename"], "gel.tif");
        assert_eq!(body["mime_type"], "image/tiff");
        assert_eq!(body["was_created"], true);
        assert_eq!(body["size_bytes"], content.len() as i64);
        let id = body["id"].as_str().unwrap().to_string();
        let expected_hash = hex::encode(ContentHasher::hash(&content));
        assert_eq!(body["content_hash"], expected_hash);

        let response = router
            .oneshot(get_request(&format!("/api/v1/blobs/{id}/content")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("X-Content-Hash")
                .unwrap()
                .to_str()
                .unwrap(),
            expected_hash
        );
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .unwrap()
                .to_str()
                .unwrap(),
            "image/tiff"
        );
        let downloaded = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(downloaded.as_ref(), content.as_slice());
    }

    /// The per-route `DefaultBodyLimit` override is LIVE: an 8 KiB upload
    /// succeeds even though the router-wide `max_request_size` is 1 KiB.
    /// Without the override the global cap would silently truncate every blob
    /// upload above 10 MiB in production.
    #[sqlx::test(migrations = "../../migrations")]
    async fn upload_larger_than_global_max_request_size_succeeds(pool: PgPool) {
        let dir = TempDir::new().unwrap();
        let agent = ensure_system_agent(&pool).await;
        let config = ApiConfig {
            max_request_size: 1024,
            ..ApiConfig::default()
        };
        let state = AppState::with_db(pool, config)
            .with_blob_dir(dir.path().into())
            .with_max_blob_bytes(64 * 1024);
        state.load_entity_type_cache().await.unwrap();
        let router = blobs_router(state).layer(Extension(auth_ctx(agent)));

        let content = payload(8 * 1024, 0x5EED);
        let response = router
            .oneshot(upload_request(
                "/api/v1/blobs?filename=big.bin",
                "application/octet-stream",
                content.clone(),
            ))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::CREATED,
            "8 KiB must survive a 1 KiB global limit when max_blob_bytes is 64 KiB"
        );
        let body = parse_body(response).await;
        assert_eq!(body["size_bytes"], content.len() as i64);
    }

    /// Over the blob ceiling: rejected, and nothing lands on disk.
    #[sqlx::test(migrations = "../../migrations")]
    async fn upload_over_max_blob_bytes_is_rejected(pool: PgPool) {
        let dir = TempDir::new().unwrap();
        let agent = ensure_system_agent(&pool).await;
        let state = AppState::with_db(pool.clone(), ApiConfig::default())
            .with_blob_dir(dir.path().into())
            .with_max_blob_bytes(1024);
        state.load_entity_type_cache().await.unwrap();
        let router = blobs_router(state).layer(Extension(auth_ctx(agent)));

        let response = router
            .oneshot(upload_request(
                "/api/v1/blobs?filename=too-big.bin",
                "application/octet-stream",
                payload(4096, 1),
            ))
            .await
            .unwrap();
        assert!(
            response.status().is_client_error(),
            "expected 4xx, got {}",
            response.status()
        );

        assert!(walk_files(dir.path()).is_empty(), "nothing may be written");
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM blobs")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 0);
    }

    /// Fails closed: no `AuthContext` layer at all, so there is no identity to
    /// fall back to and no row is written.
    #[sqlx::test(migrations = "../../migrations")]
    async fn upload_without_auth_is_unauthorized(pool: PgPool) {
        let dir = TempDir::new().unwrap();
        let state = test_state(pool.clone(), &dir).await;
        // Deliberately NO `.layer(Extension(auth_ctx(..)))`.
        let router = blobs_router(state);

        let response = router
            .oneshot(upload_request(
                "/api/v1/blobs?filename=anon.bin",
                "application/octet-stream",
                payload(64, 2),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM blobs")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 0);
        assert!(walk_files(dir.path()).is_empty());
    }

    /// Route → repo → `EdgeRepository` → edges-join read, in one pass.
    #[sqlx::test(migrations = "../../migrations")]
    async fn upload_with_attach_to_claim_id_then_list_route_returns_it(pool: PgPool) {
        let dir = TempDir::new().unwrap();
        let agent = ensure_system_agent(&pool).await;
        let claim = seed_claim(&pool, agent, "attached via the HTTP route").await;
        let state = test_state(pool, &dir).await;
        let router = blobs_router(state).layer(Extension(auth_ctx(agent)));

        let response = router
            .clone()
            .oneshot(upload_request(
                &format!("/api/v1/blobs?filename=trace.csv&attach_to_claim_id={claim}"),
                "text/csv",
                payload(2048, 0xA77AC),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let body = parse_body(response).await;
        assert_eq!(body["edge_created"], true);
        assert!(body["edge_id"].is_string());
        let blob_id = body["id"].as_str().unwrap().to_string();

        let response = router
            .oneshot(get_request(&format!("/api/v1/claims/{claim}/blobs")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let listed = parse_body(response).await;
        let ids: Vec<&str> = listed
            .as_array()
            .unwrap()
            .iter()
            .map(|b| b["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, vec![blob_id.as_str()]);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn verify_route_reports_false_after_on_disk_corruption(pool: PgPool) {
        let dir = TempDir::new().unwrap();
        let agent = ensure_system_agent(&pool).await;
        let state = test_state(pool, &dir).await;
        let router = blobs_router(state).layer(Extension(auth_ctx(agent)));

        let response = router
            .clone()
            .oneshot(upload_request(
                "/api/v1/blobs?filename=raw.dat",
                "application/octet-stream",
                payload(1024, 0xC0DE),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let body = parse_body(response).await;
        let id = body["id"].as_str().unwrap().to_string();

        let response = router
            .clone()
            .oneshot(get_request(&format!("/api/v1/blobs/{id}/verify")))
            .await
            .unwrap();
        assert_eq!(parse_body(response).await["integrity_ok"], true);

        // Corrupt the one file under the root.
        let files = walk_files(dir.path());
        assert_eq!(files.len(), 1);
        std::fs::write(&files[0], payload(1024, 0xBAD)).unwrap();

        let response = router
            .oneshot(get_request(&format!("/api/v1/blobs/{id}/verify")))
            .await
            .unwrap();
        assert_eq!(parse_body(response).await["integrity_ok"], false);
    }

    /// A filename that would break the `Content-Disposition` header never
    /// reaches storage; a legitimate one produces a well-formed header.
    #[sqlx::test(migrations = "../../migrations")]
    async fn download_sanitizes_content_disposition(pool: PgPool) {
        let dir = TempDir::new().unwrap();
        let agent = ensure_system_agent(&pool).await;
        let state = test_state(pool.clone(), &dir).await;
        let router = blobs_router(state).layer(Extension(auth_ctx(agent)));

        // `%22` is a quote — episcience would have echoed it straight into the
        // header, ending the quoted-string early.
        let response = router
            .clone()
            .oneshot(upload_request(
                "/api/v1/blobs?filename=evil%22name.bin",
                "application/octet-stream",
                payload(128, 4),
            ))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "a quote in the filename must be rejected at write time"
        );
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM blobs")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 0);

        // The legitimate case still yields a usable header.
        let response = router
            .clone()
            .oneshot(upload_request(
                "/api/v1/blobs?filename=good-name.bin",
                "application/octet-stream",
                payload(128, 5),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let id = parse_body(response).await["id"]
            .as_str()
            .unwrap()
            .to_string();

        let response = router
            .oneshot(get_request(&format!("/api/v1/blobs/{id}/content")))
            .await
            .unwrap();
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_DISPOSITION)
                .unwrap()
                .to_str()
                .unwrap(),
            "attachment; filename=\"good-name.bin\""
        );
    }

    /// A `mime_type` that cannot be echoed into a `Content-Type` header never
    /// reaches storage; a legitimate one round-trips verbatim.
    ///
    /// The unguarded twin of `download_sanitizes_content_disposition`. Before
    /// this guard, the upload was accepted, the bytes were fsynced, and every
    /// subsequent `GET .../content` answered 500 forever, because
    /// `Response::builder` defers the bad header until `.body()`. The over-long
    /// case was worse still: `varchar(255)` overflowed *after* `write_content`
    /// had already fsynced, leaving an orphan file with no row.
    #[sqlx::test(migrations = "../../migrations")]
    async fn upload_rejects_header_breaking_mime_type(pool: PgPool) {
        let dir = TempDir::new().unwrap();
        let agent = ensure_system_agent(&pool).await;
        let state = test_state(pool.clone(), &dir).await;
        let router = blobs_router(state).layer(Extension(auth_ctx(agent)));

        let over_long = format!("text/{}", "a".repeat(300));
        let cases = [
            ("newline", "text/plain%0AX-Injected:%20yes"),
            ("DEL", "text/plain%7F"),
            ("over 255 chars", over_long.as_str()),
        ];
        for (seed, (label, raw)) in cases.into_iter().enumerate() {
            let response = router
                .clone()
                .oneshot(upload_request(
                    &format!("/api/v1/blobs?filename=probe.bin&mime_type={raw}"),
                    "application/octet-stream",
                    payload(128, 100 + seed as u64),
                ))
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::BAD_REQUEST,
                "{label}: an unsafe mime_type must be rejected at write time"
            );
        }

        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM blobs")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 0, "no row may survive a rejected upload");
        assert!(
            walk_files(dir.path()).is_empty(),
            "no bytes may survive a rejected upload"
        );

        // `/`, `;`, `=` and space are mime grammar, not header-breaking: the
        // legitimate value must survive both the guard and the round trip.
        let response = router
            .clone()
            .oneshot(upload_request(
                "/api/v1/blobs?filename=table.csv&mime_type=text/csv%3B%20charset%3Dutf-8",
                "application/octet-stream",
                payload(128, 7),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let body = parse_body(response).await;
        assert_eq!(body["mime_type"], "text/csv; charset=utf-8");
        let id = body["id"].as_str().unwrap().to_string();

        let response = router
            .oneshot(get_request(&format!("/api/v1/blobs/{id}/content")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .unwrap()
                .to_str()
                .unwrap(),
            "text/csv; charset=utf-8"
        );
    }

    /// A row already poisoned in a live database must still be readable.
    ///
    /// Closing the write path does nothing for bytes uploaded before migration
    /// 075 shipped: their rows persist, and without a read-time fallback every
    /// `GET .../content` on them answers 500 forever. This is the same
    /// belt-and-braces `download_sanitizes_content_disposition` relies on for
    /// `filename`, which is why the CHECK has to be dropped to construct the
    /// case at all — that drop is exactly the pre-075 schema.
    #[sqlx::test(migrations = "../../migrations")]
    async fn download_falls_back_when_stored_mime_type_is_unsafe(pool: PgPool) {
        let dir = TempDir::new().unwrap();
        let agent = ensure_system_agent(&pool).await;
        let state = test_state(pool.clone(), &dir).await;
        let router = blobs_router(state).layer(Extension(auth_ctx(agent)));

        let response = router
            .clone()
            .oneshot(upload_request(
                "/api/v1/blobs?filename=legacy.bin&mime_type=text/plain",
                "application/octet-stream",
                payload(256, 11),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let id: Uuid = parse_body(response).await["id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();

        sqlx::query("ALTER TABLE blobs DROP CONSTRAINT blobs_mime_type_safe")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("UPDATE blobs SET mime_type = $1 WHERE id = $2")
            .bind("text/plain\nX-Injected: yes")
            .bind(id)
            .execute(&pool)
            .await
            .unwrap();

        let response = router
            .oneshot(get_request(&format!("/api/v1/blobs/{id}/content")))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "a poisoned mime_type must not make the bytes unreadable forever"
        );
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .unwrap()
                .to_str()
                .unwrap(),
            DEFAULT_MIME,
            "the fallback must be the same default an unlabelled upload gets"
        );
    }
}
