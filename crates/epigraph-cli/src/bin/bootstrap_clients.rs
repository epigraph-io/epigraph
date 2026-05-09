//! Idempotently provisions the three canonical service-type OAuth clients:
//! `epigraph-admin`, `epigraph-ro`, `epigraph-wo`.
//!
//! Intended for first-time setup of an EpiGraph deployment cloned from the
//! public repo. Replaces the ad-hoc `epigraph-admin/-ro/-wo` user roles that
//! existed in EpigraphV2.
//!
//! Usage:
//! ```bash
//! cargo run --bin bootstrap_clients -- \
//!     --legal-entity-name "Acme Corp" \
//!     --legal-contact-email "ops@acme.example" \
//!     --database-url "postgres://epigraph:epigraph@127.0.0.1:5432/epigraph"
//! ```
//!
//! The plaintext secret is printed ONCE per creation. Capture it; the DB
//! stores only the blake3 hash. Re-runs are safe — existing rows are
//! reported and not touched.

use anyhow::{Context, Result};
use clap::Parser;
use epigraph_cli::bootstrap::{bootstrap_canonical_clients, ClientOutcome};
use sqlx::postgres::PgPoolOptions;

#[derive(Parser, Debug)]
#[command(
    name = "bootstrap_clients",
    about = "Idempotently provision the canonical epigraph-admin, epigraph-ro, and epigraph-wo OAuth clients."
)]
struct Args {
    /// Postgres connection string. Falls back to $DATABASE_URL.
    #[arg(long, env = "DATABASE_URL")]
    database_url: String,

    /// Legal entity name. Required by the `services_must_have_legal_entity`
    /// CHECK constraint on `oauth_clients`. Same value applied to all three.
    #[arg(long)]
    legal_entity_name: String,

    /// Legal contact email. Required by the same CHECK constraint.
    #[arg(long)]
    legal_contact_email: String,

    /// If set, the new clients are stamped with this `owner_id` (a UUID
    /// from `oauth_clients.id` of the owning client). Optional.
    #[arg(long)]
    owner_client_id: Option<uuid::Uuid>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = dotenvy::dotenv();
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&args.database_url)
        .await
        .context("connect to database")?;

    let outcomes = bootstrap_canonical_clients(
        &pool,
        &args.legal_entity_name,
        &args.legal_contact_email,
        args.owner_client_id,
    )
    .await?;

    let mut created_count = 0usize;
    for o in &outcomes {
        match o {
            ClientOutcome::Existing { name, client_id } => {
                println!("EXISTS:  name={name:<16} client_id={client_id}");
            }
            ClientOutcome::Created {
                name,
                client_id,
                client_secret,
            } => {
                println!(
                    "CREATED: name={name:<16} client_id={client_id} client_secret={client_secret}"
                );
                created_count += 1;
            }
        }
    }

    if created_count > 0 {
        eprintln!();
        eprintln!(
            "{created_count} client secret(s) above are shown ONCE. Capture them now — \
             the database stores only their blake3 hashes and they cannot be recovered."
        );
    }

    Ok(())
}
