// UNSCOPED-POOL-EXEMPT: Boot and spawned long-lived tasks, in TWO different senses — see the
// matching entry in `epigraph-db/tests/no_unscoped_pool.rs`, which is authoritative for the reason.
// (a) Boot hydration and the metrics sampler: no principal exists at process start or inside the
// sampler, so there is nothing to stamp a connection from. (b) The webhook-dispatcher handoff is
// NOT of that kind: the dispatcher resolves a real `Viewer` per subscription downstream, so a
// Viewer IS constructible there. The follow-up this used to be exempt-until — migration 086, which
// repaired `ClaimRepository::hidden_claim_ids` by putting both arms of its set difference inside a
// SECURITY DEFINER frame — has landed, and the exemption STANDS anyway: this pool is handed over
// once at process start and travels as a `&PgPool` parameter into a detached task, and the probe it
// feeds is now correct on an unstamped connection. Converting it is a separate decision, not a
// consequence of 086.
//
// OPERATOR DECISION D9 (batch W12a): this process holds NO maintenance DSN. It
// refuses to start when `MAINTENANCE_DATABASE_URL` is set, and builds no job
// pool, no maintenance pool and no job runner, and runs no stale-job reaper.
// Every administrative cascade it triggers is deferred (recorded in the act's
// own transaction) and applied by `epigraph-cascade-replay.timer`
// (`replay_deferred_cascades`); the job queue is drained by
// `epigraph-jobs-drain.timer` (`drain_jobs`, in this crate).
use epigraph_api::metrics::Metrics;
use epigraph_api::routes::webhooks::{start_webhook_dispatcher, WebhookDeliveryConfig};
use epigraph_api::{create_router, ApiConfig, AppState};
use std::sync::Arc;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|arg| arg == "--export-openapi") {
        let spec = epigraph_api::openapi::openapi_spec();
        let json = spec
            .to_pretty_json()
            .expect("Failed to serialize OpenAPI spec");
        println!("{}", json);
        return;
    }

    // Initialize tracing subscriber for structured logging.
    //
    // When the `otel` feature is enabled and OTEL_EXPORTER_OTLP_ENDPOINT is
    // set, an additional OpenTelemetry layer is attached that exports spans via
    // OTLP (gRPC) to the configured collector endpoint.  Otherwise only the
    // human-readable stderr formatter is used.
    #[cfg(not(feature = "otel"))]
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info,epigraph_api=debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    #[cfg(feature = "otel")]
    {
        // TODO(otel): When deploying with OTLP support, initialise the pipeline here:
        //
        //   let otlp_endpoint = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok();
        //   if let Some(endpoint) = otlp_endpoint {
        //       let exporter = opentelemetry_otlp::new_exporter()
        //           .tonic()
        //           .with_endpoint(endpoint);
        //       let tracer = opentelemetry_otlp::new_pipeline()
        //           .tracing()
        //           .with_exporter(exporter)
        //           .with_trace_config(opentelemetry_sdk::trace::config()
        //               .with_resource(opentelemetry_sdk::Resource::new(vec![
        //                   opentelemetry::KeyValue::new("service.name", "epigraph-api"),
        //               ])))
        //           .install_batch(opentelemetry_sdk::runtime::Tokio)
        //           .expect("Failed to install OTLP tracer");
        //       let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);
        //       tracing_subscriber::registry()
        //           .with(tracing_subscriber::EnvFilter::new(
        //               std::env::var("RUST_LOG").unwrap_or_else(|_| "info,epigraph_api=debug".into()),
        //           ))
        //           .with(tracing_subscriber::fmt::layer())
        //           .with(otel_layer)
        //           .init();
        //   } else {
        //       // fall through to stderr-only
        //   }
        //
        // The exact API surface changes between opentelemetry* crate versions.
        // This block compiles (feature flag presence is what matters for CI/CD
        // deployment decisions) but the init is deferred to deployment time.
        tracing_subscriber::registry()
            .with(tracing_subscriber::EnvFilter::new(
                std::env::var("RUST_LOG").unwrap_or_else(|_| "info,epigraph_api=debug".into()),
            ))
            .with(tracing_subscriber::fmt::layer())
            .init();

        if std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").is_ok() {
            tracing::info!(
                "OTEL_EXPORTER_OTLP_ENDPOINT is set; \
                 OTLP exporter init is pending deployment configuration"
            );
        }
    }

    // Operator decision D9: a request-serving process never holds the
    // maintenance DSN. Checked before any other gate and before any connection,
    // so the refusal is the first and only thing a misconfigured unit reports.
    // One code path, every environment, no override flag.
    #[cfg(feature = "db")]
    if let Err(refusal) = epigraph_api::state::request_unit_may_start(
        std::env::var(epigraph_db::MAINTENANCE_DATABASE_URL)
            .ok()
            .as_deref(),
    ) {
        eprintln!("ERROR: {refusal}");
        std::process::exit(1);
    }

    // Fail-closed JWT secret gate. Prod refuses to boot with an unset/dev
    // secret; dev/CI opt out with EPIGRAPH_ALLOW_INSECURE_SECRET=1. The dev
    // fallback in AppState::default_jwt_config is unchanged so the suite still
    // compiles and runs.
    let allow_insecure = std::env::var("EPIGRAPH_ALLOW_INSECURE_SECRET")
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false);
    if !allow_insecure {
        let secret = std::env::var("EPIGRAPH_JWT_SECRET").unwrap_or_default();
        if let Err(reason) = epigraph_auth::assert_production_secret(secret.as_bytes()) {
            eprintln!(
                "FATAL: {reason}. Set a real EPIGRAPH_JWT_SECRET (>= 32 bytes, not the dev literal), \
                 or set EPIGRAPH_ALLOW_INSECURE_SECRET=1 for local dev/CI."
            );
            std::process::exit(1);
        }
    }

    // Configure API settings.
    //
    // `require_packet_signatures` enables the Ed25519 **payload** signature gate
    // on `POST /api/v1/submit/packet`. The verifier is implemented
    // (`routes/submit.rs:689` onwards, keyed on `agents.key_kind = 'ed25519'`),
    // so turning this on rejects unsigned and badly-signed packets rather than
    // failing closed on everything.
    //
    // The flag gates ONLY payload-level packet signatures. The old
    // request-signing middleware (`middleware::require_signature`) was deleted;
    // transport authentication is OAuth2 Bearer, unconditionally.
    //
    // The operator-facing env var name is deliberately unchanged.
    let require_packet_signatures = std::env::var("EPIGRAPH_REQUIRE_SIGNATURES")
        .ok()
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false);
    // Public HTTPS base URL this API is reachable at externally (no trailing
    // slash), used to build OAuth discovery documents and consent/redirect
    // links. Defaults to localhost for local dev/CI.
    let public_base_url = std::env::var("EPIGRAPH_PUBLIC_BASE_URL")
        .unwrap_or_else(|_| "http://localhost:8080".to_string());
    // Re-open the pre-PR-02 allow-all identity posture. Default false: a
    // provider with no `allowed_emails`/`allowed_domains` provisions NOBODY,
    // and under EPIGRAPH_ENV=production that combination refuses to boot at all
    // (see oauth::providers::build_registry).
    //
    // EPIGRAPH_ENV is introduced by PR-02. Read ONCE here and threaded into
    // build_registry, rather than read inside the library: a hidden env read in
    // a library function is untestable without mutating process state.
    //
    // UNSET means production. That is the whole point — EPIGRAPH_ENV is new, so
    // it is unset in every deployment that exists today, which is exactly the
    // population the boot assertion is for. Set it explicitly to "development" /
    // "test" / "ci" / "local" (see providers::NON_PRODUCTION_ENVS) to downgrade
    // the empty-allowlist abort to a warning so dev and CI still run.
    let epigraph_env = std::env::var("EPIGRAPH_ENV").unwrap_or_default();
    let allow_all_identities =
        std::env::var("EPIGRAPH_ALLOW_ALL_IDENTITIES").as_deref() == Ok("true");
    let config = ApiConfig {
        require_packet_signatures,
        max_request_size: 10 * 1024 * 1024, // 10MB — figure evidence carries base64 images
        public_base_url,
        allow_all_identities,
    };

    // RFC 9728 resource-metadata URL, advertised in the `WWW-Authenticate`
    // challenge on every 401.
    //
    // Defaults to the document this deployment already serves at
    // `/.well-known/oauth-protected-resource`, derived from
    // `EPIGRAPH_PUBLIC_BASE_URL`, so the URL named in the challenge and the URL
    // that answers cannot drift. Override only when the metadata document is
    // fronted by a different host.
    //
    // Fail fast rather than degrade: a value that cannot be embedded in a
    // header (control characters, non-ASCII) would make every 401 silently drop
    // the challenge, and a newline would let an operator inject a second
    // header. Same shape as `epigraph-mcp`'s `--resource-metadata-url` check.
    let resource_metadata_url = std::env::var("EPIGRAPH_RESOURCE_METADATA_URL")
        .unwrap_or_else(|_| config.resource_metadata_url());
    if let Err(e) = epigraph_api::errors::validate_resource_metadata_url(&resource_metadata_url) {
        tracing::error!(
            url = %resource_metadata_url,
            error = %e,
            "EPIGRAPH_RESOURCE_METADATA_URL is unusable; refusing to start"
        );
        std::process::exit(1);
    }
    epigraph_api::errors::init_resource_metadata_url(Some(resource_metadata_url.clone()));
    tracing::info!(
        resource_metadata_url = %resource_metadata_url,
        "401 responses will advertise this resource-metadata URL"
    );

    // Create embedding service for semantic search. The provider KIND matters
    // only to the `embedding_generation` job handler, which runs in the
    // `drain_jobs` timer (D9), so this process discards it.
    let (embedding_service, _provider_kind) =
        epigraph_api::embedding_restore::embedding_service_from_env();

    // Create application state — connect to PostgreSQL when db feature is enabled
    #[cfg(feature = "db")]
    let state = {
        let database_url = std::env::var("DATABASE_URL")
            .expect("DATABASE_URL must be set when running with db feature");
        tracing::info!("Connecting to PostgreSQL...");

        // Constructed through ScopedPool, not `PgPool::connect`, and that is
        // load-bearing rather than stylistic: `PgPoolOptions::after_release` —
        // the hook that scrubs a released connection's tenancy GUCs, and the
        // single mechanism standing between a recycled connection and a
        // cross-tenant read — can only be installed at pool BUILD time, and
        // `PgPool` exposes no setter for it. A pool built any other way cannot
        // have the scrub retrofitted, so the control would exist only under
        // test.
        let guc_mode = epigraph_db::SessionGucMode::from_env(
            std::env::var("EPIGRAPH_SESSION_GUC_MODE")
                .unwrap_or_default()
                .as_str(),
        );
        let scoped = epigraph_db::ScopedPool::connect(&database_url, guc_mode)
            .await
            .expect("Failed to connect to PostgreSQL");
        // PR-06 stops discarding the `ScopedPool`. `AppState` now carries it
        // alongside the inner `PgPool`, because `Viewer::system` requires a
        // `MaintenanceLease` and `ScopedPool::unscoped_for_maintenance` is the
        // only mint — a process that throws the `ScopedPool` away can never
        // construct a bypass viewer for its own backfill routes. Most handlers
        // still read the raw pool; the conversion target is `AppState::read_as`
        // (reads) and `ScopedPool::begin_as` (writes) — NOT `acquire_as`, which
        // hard-refuses `EPIGRAPH_SESSION_GUC_MODE=transaction`, the pooler
        // fallback this same file advertises to operators a few lines below.
        // `epigraph-db/tests/no_unscoped_pool.rs` is the register of what
        // remains. (This comment previously named `acquire_as` and PR-07/PR-17;
        // both were stale.) PR-15 gave this pool a maintenance *sibling*; D9
        // removed it again, so `AppState::maintenance_viewer` refuses (the
        // routes that used it answer 501 MOVED) and this pool is the process's
        // only one.
        let pool = scoped.inner().clone();
        tracing::info!("PostgreSQL connected");

        // Plan §0.5 boot probe. Session-scoped `set_config` is the whole
        // mechanism by which a request's group set reaches the RLS policies; if
        // the deployment sits behind a transaction-mode pooler the GUCs silently
        // vanish between statements and every policy collapses to
        // `visibility = 'public'`. That is a fail-CLOSED data-loss shape, not an
        // error, so it must be caught at boot rather than in production traffic.
        //
        // It lives on ScopedPool rather than on AppState because
        // `AppState::with_db` is sync and receives a possibly-lazy pool — the
        // same wall `load_entity_type_cache` exists to work around.
        if guc_mode == epigraph_db::SessionGucMode::Transaction {
            tracing::warn!(
                "EPIGRAPH_SESSION_GUC_MODE=transaction — skipping the session-GUC probe. \
                 Every scoped read will run inside begin_as, at a cost of two extra round \
                 trips. Unset this variable on a session-mode endpoint."
            );
        } else {
            scoped.probe_session_gucs().await.expect(
                "FATAL: session GUCs do not survive between statements on one pooled connection. \
                 This deployment is behind a transaction-mode pooler. Set \
                 EPIGRAPH_SESSION_GUC_MODE=transaction to switch every read to begin_as, \
                 or point DATABASE_URL at a session-mode endpoint.",
            );
            tracing::info!("Session-GUC probe passed");
        }

        // Migrations 074/075/084 are DESIGNED to RAISE when their tenancy
        // preconditions do not hold, and this call site .expect()s — so an
        // environment that ships them without an operator in the loop gets an
        // api binary that panics on EVERY boot. Migrations now run only when
        // explicitly asked for; `epigraph-migrate` (ExecStartPre=) is the
        // supported path and is unchanged.
        if epigraph_api::should_migrate_on_boot(
            std::env::var("EPIGRAPH_MIGRATE_ON_BOOT").ok().as_deref(),
        ) {
            // Same schema-head checks as `epigraph-migrate` (issue #492): a
            // database carrying migrations this binary does not embed is
            // refused unless EPIGRAPH_MIGRATE_ALLOW_DB_AHEAD opts in to the
            // rollback case.
            let report = epigraph_api::run_migrations(
                &pool,
                epigraph_api::migrate::MigrateOptions::from_env(),
            )
            .await
            .unwrap_or_else(|e| panic!("Failed to apply pending migrations: {e}"));
            tracing::info!(
                db_head = report.db_head,
                binary_head = report.binary_head,
                applied = report.applied_this_run,
                db_ahead = report.db_ahead,
                ahead = ?report.ahead,
                "Migrations up to date"
            );
        } else {
            tracing::info!(
                "EPIGRAPH_MIGRATE_ON_BOOT unset — skipping migrations; run `epigraph-migrate`"
            );
        }

        // Operator decision D9: no maintenance pool, no job pool, no job runner
        // and no reaper in this process, and the administrative cascade is
        // never enabled here. Every cascade a request triggers is deferred and
        // recorded in the act's own transaction (`cascade.deferred`), and the
        // replay timer applies it; the job queue is the drain timer's. The
        // connection budget is therefore the application pool alone
        // (`docs/deploy.md` §1c-bis).
        tracing::info!(
            target: "tenancy.maintenance",
            "{}",
            epigraph_db::MAINTENANCE_SURFACE_NOT_SERVED
        );
        // Operator binding (migration 122): say at boot whether the valve is
        // open and whether the database is armed, and REFUSE TO START on a
        // privileged DSN of an armed database (operator ruling OQ-7 (b): on
        // such a DSN the trigger checks the author column alone and relieves
        // the cross-human scope). One code path, every environment, no
        // override; an unarmed database (dev, CI) is not refused.
        if let Err(refusal) =
            epigraph_db::operator_binding::check_request_unit_boot(scoped.inner(), "epigraph-api")
                .await
        {
            eprintln!("ERROR: {refusal}");
            std::process::exit(1);
        }
        let state = AppState::with_scoped_pool(scoped, config)
            .with_embedding_service(embedding_service)
            .with_admin_cascade(false);

        // Prime the entity_types registry cache. `with_db` is sync and can't
        // SELECT, so the cache loads here — after migrations (054 seeds the
        // registry) and after the pool is live. A failure is fatal: an empty
        // cache would 400 every edge write at the validity gate.
        state
            .load_entity_type_cache()
            .await
            .expect("Failed to load entity_types registry cache");
        tracing::info!("entity_types registry cache loaded");

        // PR-16 boot assertions (plan §8.2 A5). Same placement and the same
        // reason as the cache load above: `with_db` is sync and cannot SELECT.
        //
        // The trigger check REFUSES. After migration 074 there is no DEFAULT
        // left to catch an undeclared write, so a disabled require-tenancy
        // trigger is not a degraded mode — it is a corpus acquiring rows whose
        // tenancy nobody declared, silently, until the NOT NULL backstop
        // happens to fire.
        state
            .assert_tenancy_triggers_armed()
            .await
            .expect("refusing to serve: tenancy triggers are not armed");

        // The connection-posture check WARNS. See its doc comment: making it
        // fatal today would stop this binary booting in CI and in development,
        // and PR-17 is the PR that repoints DATABASE_URL and can arm it.
        if let Err(e) = state.warn_on_privileged_connection().await {
            tracing::warn!(error = %e, "could not read the connection posture");
        }

        // PR-17's RLS posture assertion. It REFUSES, and it is STAGED on the
        // connecting role: inert on every environment that has not performed
        // plan §9.2 week 11d's credential split, fully armed the moment
        // `current_user` is `epigraph_app`. `epigraph_api::state::rls_verdict`
        // carries the whole argument, including why keying it on
        // `relforcerowsecurity` — which is what PR-17's *Acceptance* line asks
        // for — would brick step 11d, the 077→079 window and the documented
        // `NO FORCE` rollback all at once.
        //
        // Placed AFTER `warn_on_privileged_connection` so a database whose
        // posture is merely unusual is described in the log before this line
        // decides whether it is fatal.
        state
            .assert_rls_posture()
            .await
            .expect("refusing to serve: RLS posture assertion failed");

        state
    };

    #[cfg(not(feature = "db"))]
    let state = AppState::new(config).with_embedding_service(embedding_service);

    // Load external identity providers from providers.toml.
    // EPIGRAPH_PROVIDERS_CONFIG overrides the default path. Missing config is
    // a hard startup error to prevent silent degradation to an empty registry.
    let state = {
        let providers_path = std::env::var("EPIGRAPH_PROVIDERS_CONFIG")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| std::path::PathBuf::from("providers.toml"));
        // build_registry now returns Err (rather than only warning) when a
        // provider has an empty identity allowlist, allow_all_identities is
        // false and EPIGRAPH_ENV does not name a non-production environment.
        // The existing .expect() turns that into a clean startup abort — no new
        // panic site is needed.
        let providers = epigraph_api::oauth::providers::build_registry(
            providers_path.as_path(),
            allow_all_identities,
            &epigraph_env,
        )
        .expect("failed to build providers registry");
        state.with_providers(providers)
    };

    // Hydrate the in-process webhook store from `webhook_subscriptions`
    // (migration 085, PR-10). Before this table existed the store was empty on
    // every boot, so every deploy silently unsubscribed everyone and the
    // symptom — a webhook that stops firing — was indistinguishable from an idle
    // corpus.
    //
    // A hydration failure is logged, not fatal. The server is useful without
    // webhooks; refusing to boot because a delivery cache could not be filled
    // would convert a degraded feature into an outage. It fails in the closed
    // direction anyway: an empty store delivers nothing.
    //
    // The mapping itself lives in `epigraph_api::state::hydrate_webhook_store`
    // rather than here, so it is reachable from a test. A block inside `main`
    // can be reviewed but not executed, which is what
    // `D-PR-bin-server-boot-hydration-test` recorded.
    #[cfg(feature = "db")]
    {
        match epigraph_api::state::hydrate_webhook_store(&state.db_pool, &state.webhook_store).await
        {
            Ok(count) => {
                tracing::info!(count, "webhook subscriptions hydrated");
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "failed to hydrate webhook subscriptions; the fan-out will \
                     deliver nothing until the next successful registration"
                );
            }
        }
    }

    // Start webhook dispatcher (subscribes to event bus for delivery)
    #[cfg(feature = "db")]
    let _webhook_sub = start_webhook_dispatcher(
        &state.event_bus,
        state.db_pool.clone(),
        state.webhook_store.clone(),
        WebhookDeliveryConfig::default(),
    );
    #[cfg(not(feature = "db"))]
    let _webhook_sub = start_webhook_dispatcher(
        &state.event_bus,
        state.webhook_store.clone(),
        WebhookDeliveryConfig::default(),
    );
    tracing::info!("Webhook dispatcher started");

    // Build router with all routes
    let metrics = Arc::new(Metrics::new());

    // ---------------------------------------------------------------------
    // Tenancy undeclared-write sampler (PR-12).
    //
    // Feeds `epigraph_tenancy_undeclared_writes`, the gauge plan §9.2's
    // week-11b gate reads before migration 074 turns migration 070 arm (a)'s
    // `RAISE WARNING` into a hard `23502`.
    //
    // WHY A TASK AND NOT A COLLECTOR. `prometheus_client` does expose
    // `Registry::register_collector`, but `Collector::encode` is SYNCHRONOUS
    // and cannot await an sqlx query, so the value has to be pushed in. That is
    // the whole reason this lives in `bin/server.rs` and not in `metrics.rs`.
    //
    // WHY NOT IN A HANDLER. `no_bypass_in_handlers.rs` and
    // `viewer_route_table_lint.rs` both police request handlers; more to the
    // point, `public_router_allowlist.rs::metrics_is_not_registered_on_either_router`
    // asserts `routes/mod.rs` mentions neither `/metrics` nor `metrics_router`.
    // This adds no route at all — it writes into the same `Arc<Metrics>` the
    // internal listener below already serves.
    //
    // It needs no `Viewer`: `tenancy_undeclared_writes` is an operational
    // counter with no content and no `owner_group_id` (see
    // `CorpusStatsRepository::undeclared_writes_today`).
    //
    // A sampling failure is logged and retried, never fatal: a database blip
    // must not take the API down, and a stale gauge is visible in the
    // scrape's staleness rather than silently reading zero.
    #[cfg(feature = "db")]
    {
        let sampler_pool = state.db_pool.clone();
        // PR-17's canary rides the SAME tick. `AppState` is cheap to clone
        // (every field behind it is an `Arc` or a pool handle) and
        // `sample_canary` needs the state, not the bare pool, so the probe and
        // the boot assertion read through one definition
        // (`AppState::rls_canary_visible`) rather than two copies of the SQL.
        let canary_state = state.clone();
        let sampler_metrics = metrics.clone();
        let interval_secs: u64 = std::env::var("EPIGRAPH_TENANCY_GAUGE_INTERVAL_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(30);
        // THE SAMPLER IS STATEFUL, which is why it is a type in
        // `epigraph_api::tenancy_gauge` and not a closure here: a pass that
        // writes only the rows its query returned can never take a series back
        // DOWN, and `undeclared_writes_today` filters on `current_date`, so the
        // day after an undeclared write the gauge would keep yesterday's value
        // for the life of the process. See that module for the whole argument.
        tokio::spawn(async move {
            let mut ticker =
                tokio::time::interval(std::time::Duration::from_secs(interval_secs.max(1)));
            let mut sampler = epigraph_api::tenancy_gauge::TenancyGaugeSampler::new();
            loop {
                ticker.tick().await;
                if let Err(e) = sampler.sample(&sampler_pool, &sampler_metrics).await {
                    tracing::warn!(
                        error = %e,
                        "tenancy undeclared-write sampler failed; gauge will go stale"
                    );
                }
                // FINAL-PLAN §6.7's re-key backlog rides the same tick, for
                // the same reason the canary does: one interval for an
                // operator to keep in step, and no second pool of connections
                // held for periodic work.
                if let Err(e) = sampler
                    .sample_reseal_required(&sampler_pool, &sampler_metrics)
                    .await
                {
                    tracing::warn!(
                        error = %e,
                        "groups reseal-required sampler failed; gauge will go stale"
                    );
                }
                // Returns no error by design: a canary probe that fails must
                // export -1 ("unmeasured"), never the previous value and never
                // zero. See `TenancyGaugeSampler::sample_canary`.
                sampler.sample_canary(&canary_state, &sampler_metrics).await;
            }
        });
        tracing::info!(
            interval_secs,
            "Tenancy undeclared-write gauge sampler started"
        );
    }

    let app = create_router(state).layer(axum::Extension(metrics.clone()));

    // ---------------------------------------------------------------------
    // Internal metrics listener (PR-03, §10.3 Q1 option (a)).
    //
    // `/metrics` no longer exists on the application router. Prometheus text
    // exposition is an operational surface: it enumerates counters that
    // describe corpus activity, and with the application router now
    // authenticated by default, leaving one unauthenticated route open to the
    // internet would be the single exception that swallows the rule.
    //
    // It binds to 127.0.0.1 by default, so a scraper must be on the host or
    // inside the network namespace. Set EPIGRAPH_METRICS_ADDR to widen it
    // deliberately (e.g. "0.0.0.0:9090" inside a private network).
    //
    // SPAWNED HERE ON PURPOSE — before the `#[cfg(feature = "tls")]` block
    // below, which `return`s from `main` when TLS is configured. Spawning after
    // it would leave every TLS deployment with no metrics at all, and the
    // failure would be silent.
    //
    // A bind failure is a warning, not an abort: losing metrics must not take
    // the API down with it. It is logged loudly enough to alert on.
    let metrics_addr =
        std::env::var("EPIGRAPH_METRICS_ADDR").unwrap_or_else(|_| "127.0.0.1:9090".to_string());
    match tokio::net::TcpListener::bind(&metrics_addr).await {
        Ok(metrics_listener) => {
            tracing::info!(
                addr = %metrics_addr,
                "Internal metrics listener started — update the Prometheus \
                 scrape target: /metrics is no longer on the application port"
            );
            let metrics_app = epigraph_api::metrics::metrics_router(metrics);
            tokio::spawn(async move {
                if let Err(e) = axum::serve(metrics_listener, metrics_app).await {
                    tracing::error!(error = %e, "Internal metrics listener stopped");
                }
            });
        }
        Err(e) => {
            tracing::error!(
                addr = %metrics_addr,
                error = %e,
                "Failed to bind the internal metrics listener; metrics will not \
                 be scrapeable. The API continues to serve."
            );
        }
    }

    // Bind to address. EPIGRAPH_PORT env var allows side-by-side test runs.
    let port: u16 = std::env::var("EPIGRAPH_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8080);
    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));

    // Check for TLS configuration via environment variables.
    // EPIGRAPH_TLS_CERT and EPIGRAPH_TLS_KEY must both be set to enable TLS.
    // In production, Caddy terminates TLS; this path is for direct-access scenarios.
    let tls_cert = std::env::var("EPIGRAPH_TLS_CERT").ok();
    let tls_key = std::env::var("EPIGRAPH_TLS_KEY").ok();

    #[cfg(feature = "tls")]
    if let (Some(cert), Some(key)) = (tls_cert, tls_key) {
        use epigraph_api::tls::TlsConfig;

        tracing::info!(
            "TLS enabled — Starting EpiGraph API server (HTTPS) on {}",
            addr
        );
        tracing::info!("Health check available at https://{}/health", addr);

        let tls_config = TlsConfig {
            cert_path: cert.into(),
            key_path: key.into(),
        };
        let rustls_config = tls_config
            .into_rustls_config()
            .await
            .expect("Failed to load TLS certificate/key");

        axum_server::bind_rustls(addr, rustls_config)
            .serve(app.into_make_service())
            .await
            .expect("TLS server error");
        return;
    }

    #[cfg(not(feature = "tls"))]
    {
        // Suppress unused variable warnings when TLS feature is disabled
        let _ = tls_cert;
        let _ = tls_key;
    }

    tracing::info!("Starting EpiGraph API server on {}", addr);
    tracing::info!("Health check available at http://{}/health", addr);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("Failed to bind to address");

    tracing::info!("Server listening on {}", addr);

    axum::serve(listener, app).await.expect("Server error");
}
