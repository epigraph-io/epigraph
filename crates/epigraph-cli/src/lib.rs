#[cfg(feature = "db")]
pub mod bootstrap;
#[cfg(feature = "db")]
pub mod bridge;
pub mod decompose;
pub mod enrichment;
#[cfg(feature = "genai")]
pub mod matching_client;
#[cfg(feature = "db")]
pub mod recompute_betp;
#[cfg(feature = "db")]
pub mod reembed;
#[cfg(feature = "genai")]
pub mod rerank;

#[cfg(feature = "db")]
use sqlx::PgPool;
use std::sync::Arc;

/// Connect to postgres via DATABASE_URL environment variable.
#[cfg(feature = "db")]
pub async fn db_connect() -> Result<PgPool, Box<dyn std::error::Error>> {
    let url = std::env::var("DATABASE_URL").map_err(|_| {
        "DATABASE_URL not set — set it to postgresql://epigraph:epigraph@127.0.0.1:5432/epigraph"
    })?;
    Ok(PgPool::connect(&url).await?)
}

/// A [`ScopedPool`](epigraph_db::ScopedPool) plus the unrestricted
/// [`Viewer`](epigraph_db::visibility::Viewer) a CLI maintenance bin needs.
///
/// # Why a CLI bin gets a bypass and a request handler does not
///
/// `crates/epigraph-api/tests/no_bypass_in_handlers.rs` scans
/// `epigraph-api/src/routes/` and `epigraph-mcp/src/tools/` — the two places
/// where code runs on behalf of a caller. A CLI bin has no caller: the operator
/// who ran it IS the authority, the work is corpus-wide by definition
/// (backfills, recomputes, exports), and a per-tenant view of a backfill leaves
/// every other tenant permanently stale. So the bins are outside the lint's
/// scan roots on purpose, not by omission.
///
/// The bypass is still not free: it requires a
/// [`MaintenanceLease`](epigraph_db::visibility::MaintenanceLease) that only
/// `ScopedPool::unscoped_for_maintenance` can mint, and `reason` must be one of
/// the closed [`SystemReason`](epigraph_db::visibility::SystemReason) set that
/// `crates/epigraph-db/tests/viewer_ratchet.rs` counts.
///
/// **Hold the returned `ScopedPool`.** The `MaintenanceConn` the lease came
/// from is dropped at the end of this function — which is sound today (no RLS
/// policy is ENABLEd before PR-17) and is exactly what PR-15 must revisit when
/// the maintenance connection becomes the privileged one. The `Viewer` outlives
/// it here; from PR-17 on it must not.
///
/// This is the first bin-side use of the lease and the template PR-15
/// generalises.
///
/// # Errors
/// Returns an error if `DATABASE_URL` is unset or the pool cannot be built.
#[cfg(feature = "db")]
pub async fn maintenance_pool_and_viewer(
    reason: epigraph_db::visibility::SystemReason,
) -> Result<(epigraph_db::ScopedPool, epigraph_db::visibility::Viewer), Box<dyn std::error::Error>>
{
    let url = std::env::var("DATABASE_URL").map_err(|_| {
        "DATABASE_URL not set — set it to postgresql://epigraph:epigraph@127.0.0.1:5432/epigraph"
    })?;
    let guc_mode = epigraph_db::SessionGucMode::from_env(
        std::env::var("EPIGRAPH_SESSION_GUC_MODE")
            .unwrap_or_default()
            .as_str(),
    );
    let scoped = epigraph_db::ScopedPool::connect(&url, guc_mode).await?;
    let viewer = {
        let (_conn, lease) = scoped.unscoped_for_maintenance(reason).await?;
        epigraph_db::visibility::Viewer::system(&lease, reason)
    };
    Ok((scoped, viewer))
}

/// Create embedding service from OPENAI_API_KEY.
/// Returns None if key is not set (embeddings will be skipped).
pub fn embedding_service() -> Option<Arc<dyn epigraph_embeddings::EmbeddingService>> {
    let api_key = std::env::var("OPENAI_API_KEY").ok()?;
    let config = epigraph_embeddings::EmbeddingConfig::openai(1536);
    let provider = epigraph_embeddings::OpenAiProvider::new(config, api_key).ok()?;
    Some(Arc::new(provider) as Arc<dyn epigraph_embeddings::EmbeddingService>)
}
