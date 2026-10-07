//! `epigraph-instance-admin` — check and list the D4 privatization authority.
//!
//! # Since migration 123 this binary writes nothing
//!
//! Instance administration is `role:platform-custodian`, held by a registered
//! human through a timestamped assignment, and `instance_admins` is frozen for
//! every role. `grant` and `revoke` therefore refuse (exit 1) before connecting
//! and name their replacements, `epigraph-operator grant-role` and
//! `epigraph-operator end-role-assignment`; `check` answers from the role (the
//! same predicate the request path uses); `list` prints the legacy rows, which
//! confer nothing.
//!
//! # It was the ONLY writer of `instance_admins` (083 to 122)
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
    /// REMOVED (migration 123): refuses and names `epigraph-operator grant-role`.
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
    /// REMOVED (migration 123): refuses and names
    /// `epigraph-operator end-role-assignment`.
    Revoke {
        #[arg(long)]
        agent_id: Uuid,
    },
    /// List the legacy `instance_admins` rows (read-only since 123; they
    /// confer nothing).
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

    // Refused before any connection: the table is frozen (CUS05), and an
    // operator running a pre-123 playbook gets the replacement verb, not a
    // database error.
    match &cli.command {
        Command::Grant { agent_id, .. } => {
            eprintln!(
                "epigraph-instance-admin grant was removed in migration 123: instance \
                 administration is role:platform-custodian, held by a registered human. Run \
                 `epigraph-operator grant-role --role role:platform-custodian --holder {agent_id} \
                 (--valid-to <RFC3339> | --open-ended) --reason <text> [--granted-by <live \
                 custodian>] --apply` on the maintenance DSN. Nothing was changed."
            );
            std::process::exit(1);
        }
        Command::Revoke { agent_id } => {
            eprintln!(
                "epigraph-instance-admin revoke was removed in migration 123. List the holder's \
                 assignments with `epigraph-operator list-role-assignments` and end one with \
                 `epigraph-operator end-role-assignment --assignment <id> --reason <text> \
                 --apply`. ({agent_id}: nothing was changed.)"
            );
            std::process::exit(1);
        }
        Command::List { .. } | Command::Check { .. } => {}
    }

    let maint = epigraph_cli::MaintenancePool::connect("epigraph-instance-admin")
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let pool = maint.pool().clone();

    use epigraph_db::repos::instance_admin::InstanceAdminRepository;

    match cli.command {
        Command::Grant { .. } | Command::Revoke { .. } => unreachable!("refused above"),
        Command::List { include_revoked } => {
            let rows = InstanceAdminRepository::list(&pool, include_revoked).await?;
            println!(
                "legacy instance_admins rows (read-only since migration 123; they confer \
                 nothing). Holders of role:platform-custodian: epigraph-operator \
                 list-role-assignments"
            );
            if rows.is_empty() {
                println!("no legacy rows");
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
