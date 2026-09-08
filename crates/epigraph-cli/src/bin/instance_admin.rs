//! `epigraph-instance-admin` — grant, revoke and list the D4 privatization
//! authority.
//!
//! # This binary is the ONLY writer of `instance_admins`
//!
//! Migration 083 revokes INSERT, UPDATE and DELETE on that table from
//! `epigraph_app`, and the INSERT and UPDATE policies it installs have
//! `epigraph_bypass()` as their only disjunct — a `session_user` test that is
//! false on an app connection and that a `SECURITY DEFINER` frame cannot flip.
//! DELETE gets no policy at all, so there the pair is the REVOKE plus absence
//! and no role can delete a row. The request path therefore cannot write this
//! table — deliberately. There is no HTTP route, no MCP tool and no job that
//! grants instance administrator. Granting is an operator action taken out of
//! band, over `epigraph_maintenance`, and this is where it lives.
//!
//! # Why the pool is a `MaintenancePool` and not a bare `PgPool`
//!
//! `no_unmaintained_dsn.rs` scans `crates/epigraph-cli/src/bin` and fails on any
//! pool built by a spelling other than the maintenance constructor — including a
//! second construction inside a file that also uses the right one. That lint is
//! keyed on POOL CONSTRUCTION rather than on `DATABASE_URL`, because a
//! DSN-keyed check certifies a broken tree as fixed. Here the requirement is
//! not merely stylistic: every write below is denied outright to `epigraph_app`,
//! so a bare app pool would make this binary fail with `42501` on every
//! subcommand except `list`, and `list` would silently narrow to the caller's
//! own row under `instance_admins_self_or_definer` and report success.
//!
//! # Empty is the correct initial state
//!
//! Migration 083 seeds nothing. An empty `instance_admins` means nobody can
//! privatize, and every privatization attempt is refused until an operator runs
//! `grant` here. That is an acceptance clause of PR-18, not a gap this binary
//! exists to close on startup.

use clap::{Parser, Subcommand};
use uuid::Uuid;

#[derive(Parser)]
#[command(
    name = "epigraph-instance-admin",
    about = "Manage instance administrators (the D4 privatization authority)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Grant instance administrator to an agent.
    Grant {
        /// The agent receiving the authority.
        #[arg(long)]
        agent_id: Uuid,
        /// The operator's own agent id, recorded as `granted_by`.
        #[arg(long)]
        granted_by: Option<Uuid>,
        /// Free-text justification, stored on the row.
        #[arg(long)]
        note: Option<String>,
    },
    /// Revoke a live grant. Never deletes the row.
    Revoke {
        #[arg(long)]
        agent_id: Uuid,
    },
    /// List grants.
    List {
        /// Include revoked grants.
        #[arg(long)]
        include_revoked: bool,
    },
    /// Report whether an agent is a live instance administrator.
    ///
    /// Asks `epigraph_is_instance_admin(uuid)`, which is the same predicate the
    /// request path uses, so a green answer here and a 403 from the API cannot
    /// disagree about the database's opinion.
    Check {
        #[arg(long)]
        agent_id: Uuid,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();

    let maint = epigraph_cli::MaintenancePool::connect("epigraph-instance-admin")
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let pool = maint.pool().clone();

    use epigraph_db::repos::instance_admin::InstanceAdminRepository;

    match cli.command {
        Command::Grant {
            agent_id,
            granted_by,
            note,
        } => {
            let row = InstanceAdminRepository::grant(&pool, agent_id, granted_by, note.as_deref())
                .await?;
            println!(
                "granted instance:admin to {} at {} (granted_by={:?})",
                row.agent_id, row.granted_at, row.granted_by
            );
        }
        Command::Revoke { agent_id } => {
            let revoked = InstanceAdminRepository::revoke(&pool, agent_id).await?;
            if revoked {
                println!("revoked instance:admin from {agent_id}");
            } else {
                // Not an error: the end state the operator asked for holds. A
                // non-zero exit here would make a re-run of a completed
                // playbook step look like a failure.
                println!("{agent_id} held no live grant; nothing to revoke");
            }
        }
        Command::List { include_revoked } => {
            let rows = InstanceAdminRepository::list(&pool, include_revoked).await?;
            if rows.is_empty() {
                println!("no instance administrators");
            }
            for r in rows {
                println!(
                    "{}\tgranted_at={}\trevoked_at={:?}\tgranted_by={:?}\tnote={:?}",
                    r.agent_id, r.granted_at, r.revoked_at, r.granted_by, r.note
                );
            }
        }
        Command::Check { agent_id } => {
            let active = InstanceAdminRepository::is_active(&pool, agent_id).await?;
            println!("{agent_id}\tinstance_admin={active}");
            if !active {
                // A distinct exit code so a deploy script can branch on it
                // without parsing stdout.
                std::process::exit(1);
            }
        }
    }

    Ok(())
}
