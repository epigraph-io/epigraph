//! `epigraph-explorer`: config → state → router → serve on 127.0.0.1.

use std::net::SocketAddr;
use std::process::ExitCode;

use epigraph_explorer::{app, AppState, Config};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let config = match Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("epigraph-explorer: configuration error: {e}");
            return ExitCode::from(2);
        }
    };

    match run(config).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "epigraph-explorer failed");
            ExitCode::FAILURE
        }
    }
}

async fn run(config: Config) -> anyhow::Result<()> {
    if config.client_id.is_none() {
        tracing::warn!("EPIGRAPH_EXPLORER_CLIENT_ID is unset: sign-in is disabled");
    }
    if config.dev_bearer.is_some() {
        tracing::warn!(
            "EPIGRAPH_EXPLORER_DEV_BEARER is set: every anonymous request uses it (dev only)"
        );
    }
    if config.insecure_cookies {
        tracing::warn!("EPIGRAPH_EXPLORER_INSECURE_COOKIES is set: session cookies lack Secure");
    }

    // Loopback only: the reverse proxy is the public edge.
    let addr = SocketAddr::from(([127, 0, 0, 1], config.port));
    tracing::info!(?config, "configuration loaded");

    let state = AppState::new(config)?;
    let _housekeeping = app::spawn_housekeeping(state.clone());
    let base_path = state.config.base_path.clone();
    let router = app::build_app(state);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, %base_path, "epigraph-explorer listening");
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    tracing::info!("epigraph-explorer stopped");
    Ok(())
}

/// Resolve on Ctrl-C or SIGTERM; in-flight requests are allowed to finish.
async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            tracing::error!(error = %e, "cannot listen for Ctrl-C");
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(e) => {
                tracing::error!(error = %e, "cannot listen for SIGTERM");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("shutdown signal received");
}
