#[cfg(feature = "db")]
pub mod bootstrap;
#[cfg(feature = "db")]
pub mod bridge;
pub mod decompose;
pub mod enrichment;
#[cfg(feature = "genai")]
pub mod matching_client;
#[cfg(feature = "db")]
pub mod operator;
#[cfg(feature = "db")]
pub mod recompute_betp;
#[cfg(feature = "db")]
pub mod reembed;
#[cfg(feature = "genai")]
pub mod rerank;
pub mod retarget;

#[cfg(feature = "db")]
use sqlx::PgPool;
use std::sync::Arc;

/// The connection a background writer runs on, and the only pool constructor a
/// CLI binary in this workspace may use.
///
/// # What this replaces, and why the replacement is not cosmetic
///
/// Before PR-15 there were two: `db_connect()` — a bare
/// `PgPool::connect(DATABASE_URL)` — and `maintenance_pool_and_viewer`, which
/// built a `ScopedPool`, minted a bypass [`Viewer`], and returned it. Eleven
/// binaries called *both*: they took the privileged viewer from the second and
/// then ran every query on a raw pool from the first. That combination is the
/// precise failure plan §4.3 describes. A bypass viewer emits no predicate, so
/// once RLS is FORCEd the database — not the viewer — decides what the
/// statement sees, and an unprivileged connection makes a corpus-wide
/// `UPDATE … WHERE id = $1` match **zero rows and exit 0**. Fail-closed
/// regressions look like data loss, not errors.
///
/// So this type owns the pool. `pool()` is the *only* handle a bin gets, it is
/// built on [`MAINTENANCE_DATABASE_URL`](epigraph_db::MAINTENANCE_DATABASE_URL)
/// when one is configured, and its privilege is checked at startup by
/// [`assert_maintenance_privilege`](epigraph_db::assert_maintenance_privilege).
/// There is no second, unconverted spelling left for a bin to reach for —
/// `crates/epigraph-db/tests/no_unmaintained_dsn.rs` fails the build if one
/// reappears.
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
/// # A bypass is minted only where one is spent
///
/// [`Self::viewer`] takes the [`SystemReason`](epigraph_db::visibility::SystemReason),
/// not [`Self::connect`]. Most converted binaries need the privileged
/// *connection* and never call a `Viewer`-taking API at all; making them name a
/// reason would have forced twelve jobs into the ten frozen variants
/// `crates/epigraph-db/tests/viewer_ratchet.rs` holds monotone-decreasing, and
/// would have made `SystemReason::as_str()` — the metric dimension on the
/// "maintenance connection issued" log line — describe work that never
/// bypassed anything.
///
/// # The lifetime — the accidental shape is now a borrow error
///
/// `maintenance_pool_and_viewer` dropped the `MaintenanceConn` inside the
/// constructor, so the `Viewer` it handed back had no privileged connection
/// behind it at all. Its own doc said so: *"The `Viewer` outlives it here; from
/// PR-17 on it must not."* PR-15 fixed that by returning the connection to the
/// caller — but as a SECOND value, so the bypass and the connection it must be
/// spent on stayed together by review rather than by the borrow checker.
///
/// [`Self::viewer`] now returns one [`epigraph_db::MaintenanceSession`] owning
/// both, which yields the viewer only as `&Viewer`. Dropping the session drops
/// the viewer with it, and there is no accessor that moves the viewer out, so
/// the accidental version of `D-PR17-maintenance-lease-coupling-is-a-convention`
/// is now a borrow error rather than a review item. The mint is
/// `ScopedPool::maintenance_session`, so `AppState::maintenance_viewer` and
/// `epigraph_mcp::maintenance::maintenance_viewer` inherit the same shape rather
/// than each re-deriving it.
///
/// A previous revision of this paragraph recorded the guarantee as partial,
/// because `Viewer` was `Clone` and a deliberate clone still produced an owned
/// bypass. `Viewer` is no longer `Clone`, so that half is closed too and the
/// borrow is the whole story for the viewer this session owns — see
/// [`epigraph_db::MaintenanceSession`], where both halves are pinned by
/// doctests. What the type still does not govern is the SPEND: which pool the
/// statements run on is `D-PR17-hybrid-shape-lint`'s key, not a lifetime's.
///
/// ```ignore
/// let maint = MaintenancePool::connect("epigraph-embed-backfill").await?;
/// let session = maint.viewer(SystemReason::EmbeddingBackfill).await?;
/// let viewer = session.viewer();
/// let pool = maint.pool();
/// ```
///
/// # There is no accessor for the inner `ScopedPool`, on purpose
///
/// An earlier revision exposed one. Its `inner` is the *privileged* pool, and
/// the two constructors that would plausibly consume a `ScopedPool` —
/// `AppState::with_scoped_pool` and `EpiGraphMcpFull::with_scoped_pool` — both
/// clone `inner()` into the pool that serves callers. That would put the whole
/// request path on a connection RLS never filters: a fail-OPEN, where every
/// caller sees the whole corpus regardless of their groups, rather than the
/// fail-closed no-op the rest of this type guards against. Stamping tenancy
/// GUCs on such a pool via `acquire_as` would likewise be a no-op dressed as a
/// control. With no callers to serve, the accessor was pure hazard, so it is
/// gone; re-add it only alongside the call site that needs it and a reason.
#[cfg(feature = "db")]
pub struct MaintenancePool {
    scoped: epigraph_db::ScopedPool,
    source: epigraph_db::MaintenanceDsnSource,
}

#[cfg(feature = "db")]
impl MaintenancePool {
    /// Resolve the maintenance DSN from the environment and connect.
    ///
    /// `context` names the process in the startup log line and in the refusal,
    /// so an operator reading a fleet's logs can tell which binary is
    /// unprivileged.
    ///
    /// # Errors
    /// Returns an error if `DATABASE_URL` is unset, if
    /// `MAINTENANCE_DATABASE_URL` names a different database than
    /// `DATABASE_URL`, if the pool cannot be built, or if the connection is
    /// unprivileged while row security is active on a protected table (which
    /// means ENABLE, not only FORCE — see
    /// `epigraph_db::MaintenancePrivilege::rls_active`).
    pub async fn connect(context: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let url = std::env::var("DATABASE_URL").map_err(|_| {
            "DATABASE_URL not set — set it to postgresql://epigraph:epigraph@127.0.0.1:5432/epigraph"
        })?;
        Self::connect_to(&url, context).await
    }

    /// [`Self::connect`] for a binary whose application DSN arrived some other
    /// way — a clap `#[arg(long, env = "DATABASE_URL")]`, or a subcommand
    /// field. `MAINTENANCE_DATABASE_URL` still takes precedence over it.
    ///
    /// # Errors
    /// See [`Self::connect`].
    pub async fn connect_to(
        app_url: &str,
        context: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let (url, source) = epigraph_db::maintenance_database_url(app_url)?;
        let guc_mode = epigraph_db::SessionGucMode::from_env(
            std::env::var("EPIGRAPH_SESSION_GUC_MODE")
                .unwrap_or_default()
                .as_str(),
        );
        // ELEVEN, not ten, and the extra one is not slack.
        //
        // `sqlx`'s `PgPool::connect` default — which the pools these bins used
        // before PR-15 all inherited — is 10. But `Self::viewer` pins one
        // connection for as long as the bypass viewer is alive, which in every
        // converted bin is the whole run, because that is the lifetime bug the
        // old template got wrong. Leaving the cap at 10 would silently reduce
        // every bin's working capacity by one: `recompute_betp` and
        // `recompute_claim_belief` fan out to `--concurrency` tasks (default 8,
        // and 10 is a value an operator would reasonably pass), and the tenth
        // would block for the 30-second acquire timeout and then fail. 10 for
        // the work, 1 for the lease.
        let scoped = epigraph_db::ScopedPool::connect_with_options(
            &url,
            guc_mode,
            epigraph_db::ScopedPoolOptions {
                max_connections: 11,
                ..Default::default()
            },
        )
        .await?;
        epigraph_db::assert_maintenance_privilege(scoped.inner(), source, context).await?;
        Ok(Self { scoped, source })
    }

    /// The pool every query in the binary must run on.
    #[must_use]
    pub const fn pool(&self) -> &PgPool {
        self.scoped.inner()
    }

    /// Which DSN this pool was built from.
    #[must_use]
    pub const fn dsn_source(&self) -> epigraph_db::MaintenanceDsnSource {
        self.source
    }

    /// A bypass viewer and the maintenance connection it must be spent on,
    /// owned together as one [`epigraph_db::MaintenanceSession`].
    ///
    /// The session hands the viewer out only by reference, so a caller can no
    /// longer drop the connection and keep the viewer — the shape that, from
    /// plan §9.2 step 11d onward, silently returns zero rows instead of all of
    /// them. That used to be a call-site convention
    /// (`D-PR17-maintenance-lease-coupling-is-a-convention`) and is now the
    /// borrow checker's job.
    ///
    /// # Errors
    /// `DbError::ConnectionFailed` if the connection cannot be acquired.
    pub async fn viewer(
        &self,
        reason: epigraph_db::visibility::SystemReason,
    ) -> Result<epigraph_db::MaintenanceSession<'_>, epigraph_db::DbError> {
        self.scoped.maintenance_session(reason).await
    }
}

/// Create embedding service from OPENAI_API_KEY.
/// Returns None if key is not set (embeddings will be skipped).
pub fn embedding_service() -> Option<Arc<dyn epigraph_embeddings::EmbeddingService>> {
    let api_key = std::env::var("OPENAI_API_KEY").ok()?;
    let config = epigraph_embeddings::EmbeddingConfig::openai(1536);
    let provider = epigraph_embeddings::OpenAiProvider::new(config, api_key).ok()?;
    Some(Arc::new(provider) as Arc<dyn epigraph_embeddings::EmbeddingService>)
}
