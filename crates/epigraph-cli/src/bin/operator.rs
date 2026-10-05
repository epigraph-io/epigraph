//! `epigraph-operator` — the one-time operator ownership backfill.
//!
//! See `epigraph_cli::operator` for what each subcommand does and why. This
//! file is argument parsing and exit codes only.
//!
//! Every subcommand is a DRY RUN unless `--apply` is given (the two scope
//! commands take exactly one of `--dry-run` / `--apply`, and refuse neither),
//! and every subcommand connects on `EPIGRAPH_OPERATOR_MAINTENANCE_DSN` alone
//! and refuses a session user that is not a member of `epigraph_maintenance`.
//!
//! Exit codes: 0 success; 1 refused or failed before writing (for
//! `hide-evidence --apply`, also an invariant violation, rolled back); 2 a
//! batch violated an invariant and was rolled back (under `--apply` the run
//! stops there); 3 `link-retired` refused at least one id, `link` left the
//! agent without a LIVE link (its link is retired, or its membership revoked),
//! or `reown-reverse` HELD at least one claim or hidden row (it is not fully
//! restored). `arm-operator-binding --apply` exits 1 when the census of unbound
//! recent writers refused it.
//!
//! Usage:
//!     epigraph-operator link-retired --agents-file retired.txt --operator <uuid> \
//!         [--attest-shared-signer <uuid,...>] [--apply]
//!     epigraph-operator reown-claims --claims-file claims.txt --operator <uuid> \
//!         --derived follow-claim --manifest-out reown-1.jsonl [--apply]
//!     epigraph-operator reown-reverse --manifest reown-2.jsonl --manifest reown-1.jsonl [--apply]
//!     epigraph-operator hide-evidence --claims-file claims.txt --operator <uuid> \
//!         --hide-evidence-type testimony [--hide-evidence-label L] [--hide-evidence-ids f] \
//!         [--apply --confirm-hide N --manifest-out hide-1.jsonl [--reason TEXT]]
//!     epigraph-operator reown-reverse --manifest hide-1.jsonl [--apply]
//!     epigraph-operator register-human-operator --agent <uuid> --client <uuid> --reason TEXT [--apply]
//!     epigraph-operator revoke-human-operator --agent <uuid> --reason TEXT [--apply]
//!     epigraph-operator link --operator <uuid> (--agent <uuid> | --agent-model M \
//!         --agent-system-prompt-hash H) [--apply]
//!     epigraph-operator arm-operator-binding [--recent-days 14] [--allow-unbound-writers] [--apply]
//!     epigraph-operator link-legacy-authors --operator <uuid> [--exclude-agents-file F] \
//!         [--quiet-days 30 | --no-quiet-window] [--apply]
//!     epigraph-operator reown-linked --operator <uuid> --legacy-owner operator|platform \
//!         --manifest-out reown-linked-1.jsonl [--apply]
//!     epigraph-operator grant-client-scope <client-id> <scope> (--dry-run | --apply) [--reason TEXT]
//!     epigraph-operator revoke-client-scope <client-id> <scope> (--dry-run | --apply) [--reason TEXT]

use clap::{Parser, Subcommand};
use epigraph_cli::operator::{
    self, arm, bind, client_scope, hide, human, legacy, link, reown, reown_linked, reverse,
};
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Parser)]
#[command(
    name = "epigraph-operator",
    about = "Operator ownership backfill (retired links, claim re-own, and its reversal), \
             operator binding (live links, the legacy-author tie, arming), and audited \
             admin-only scope grants on human OAuth clients"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Register a HUMAN operator (migration 122's audited registry). Only the
    /// agent of an active human OAuth client can be registered.
    RegisterHumanOperator {
        /// The human's own agent id.
        #[arg(long)]
        agent: Uuid,
        /// The human's own OAuth client (`oauth_clients.id`, an ACTIVE
        /// `human` client of `--agent`) this registration is for. Required:
        /// the human test keys on this one client, and the application role
        /// may insert `oauth_clients` rows, so it is never inferred.
        #[arg(long)]
        client: Uuid,
        /// Recorded on the registry row and in the audit row.
        #[arg(long)]
        reason: String,
        /// Commit. Without it, the call and its audit row roll back.
        #[arg(long)]
        apply: bool,
    },
    /// Revoke a human operator's registration. Final for that row: every agent
    /// live-linked to the human stops authoring (OPL01).
    RevokeHumanOperator {
        /// The human's agent id.
        #[arg(long)]
        agent: Uuid,
        /// Recorded on the row and in the audit row.
        #[arg(long)]
        reason: String,
        /// Commit. Without it, the call and its audit row roll back.
        #[arg(long)]
        apply: bool,
    },
    /// Record a LIVE operator link for ONE agent (migration 107's
    /// `epigraph_link_operator`), binding it to a human operator (migration
    /// 122). Run by a host before it spawns the agent: under D9 the agent's own
    /// app DSN cannot record the link. Idempotent.
    Link {
        /// An existing agent id.
        #[arg(long)]
        agent: Option<Uuid>,
        /// With `--agent-system-prompt-hash`: the identity a stdio
        /// `epigraph-mcp` derives (`EPIGRAPH_AGENT_MODEL`). The agent is
        /// created as `epigraph-mcp` would create it if it does not exist yet.
        #[arg(long)]
        agent_model: Option<String>,
        /// The lowercase-hex BLAKE3 prompt hash (`EPIGRAPH_AGENT_SYSTEM_PROMPT_HASH`).
        #[arg(long)]
        agent_system_prompt_hash: Option<String>,
        /// The human operator's agent id.
        #[arg(long)]
        operator: Uuid,
        /// Also revoke every writer/admin row the agent holds in a group its
        /// operator does not write (listed as FOREIGN-WRITE either way).
        #[arg(long)]
        revoke_foreign_writes: bool,
        /// Perform the link. Without it, everything runs in a transaction that
        /// is rolled back.
        #[arg(long)]
        apply: bool,
    },
    /// Turn operator-binding enforcement ON for this database (migration 122),
    /// once and irreversibly, after reporting every agent that wrote claims
    /// recently and is not bound to a human operator.
    ArmOperatorBinding {
        /// The census window: agents that authored claims in this many days.
        #[arg(long, default_value_t = 14)]
        recent_days: i32,
        /// Arm even though the census lists unbound recent writers (their
        /// writes are refused from then on).
        #[arg(long)]
        allow_unbound_writers: bool,
        /// Arm. Without it, only the report is printed.
        #[arg(long)]
        apply: bool,
    },
    /// Tie every legacy author (an agent that authored a tier-A row and has no
    /// operator link) to a HUMAN operator with a RETIRED link, in one audited
    /// call (migration 122). Skipped agents are listed with the reason.
    LinkLegacyAuthors {
        /// The human operator's agent id.
        #[arg(long)]
        operator: Uuid,
        /// Agent ids never to tie (one per line; `#` comments allowed).
        #[arg(long)]
        exclude_agents_file: Option<PathBuf>,
        /// Skip, as `recent_writer`, every agent that authored a claim in this
        /// many days: it may still be running and wants a LIVE link.
        #[arg(long, default_value_t = 30, conflicts_with = "no_quiet_window")]
        quiet_days: i64,
        /// Tie recent writers too (no quiet window).
        #[arg(long)]
        no_quiet_window: bool,
        /// Commit. Without it, the call runs in a transaction that is rolled
        /// back.
        #[arg(long)]
        apply: bool,
    },
    /// Move every claim owned by a LINKED author's own personal group into its
    /// operator's personal group (`reown-claims` with `--derived follow-claim`
    /// over the claims the predicate selects). Resumable: a re-run selects
    /// what is left. Run one instance at a time.
    ReownLinked {
        /// The operator's agent id.
        #[arg(long)]
        operator: Uuid,
        /// Where to write the undo manifest. Must not exist; use a new path
        /// per run.
        #[arg(long)]
        manifest_out: PathBuf,
        /// Perform the writes. Without it, every batch rolls back.
        #[arg(long)]
        apply: bool,
        /// Claims per transaction.
        #[arg(long, default_value_t = 200)]
        batch_size: usize,
        /// `lock_timeout` for each batch (a PostgreSQL interval).
        #[arg(long, default_value = "5s")]
        lock_timeout: String,
        /// Who owns the legacy corpus (as `epigraph-tenancy-backfill run`):
        /// `operator` moves every linked author's personal-group claims;
        /// `platform` only LIVE-linked authors'. Required.
        #[arg(long, value_enum)]
        legacy_owner: reown_linked::LegacyOwner,
    },
    /// Record a RETIRED operator link for each agent id in a file.
    LinkRetired {
        /// One agent UUID per line; `#` comments and blank lines ignored.
        #[arg(long)]
        agents_file: PathBuf,
        /// The operator's agent id.
        #[arg(long)]
        operator: Uuid,
        /// Retire FORMER shared HTTP signers (batch HTTP-id, migration 116):
        /// the principals, besides the operator, that the listed agents'
        /// OPERATED_BY auth-lineage names and whose every write through them
        /// the operator attests is its own (comma-separated; may be empty).
        /// Without this flag each id goes through 107's retire, which refuses
        /// a shared signer. With it, `--agents-file` must list exactly one id.
        #[arg(long, value_delimiter = ',', num_args = 0..)]
        attest_shared_signer: Option<Vec<Uuid>>,
        /// Perform the calls. Without it, every call runs in a transaction that
        /// is rolled back.
        #[arg(long)]
        apply: bool,
    },
    /// Move the listed claims, and the rows they carry, into the operator's
    /// personal group.
    ReownClaims {
        /// One claim UUID per line; only these claims are ever touched.
        #[arg(long)]
        claims_file: PathBuf,
        /// The operator's agent id.
        #[arg(long)]
        operator: Uuid,
        /// What a derived row written by an agent NOT linked to the operator
        /// does. Required: it is a policy decision, so there is no default.
        #[arg(long, value_enum)]
        derived: reown::DerivedMode,
        /// Where to write the undo manifest. Must not exist. Written and
        /// fsynced before the first write under `--apply`.
        #[arg(long)]
        manifest_out: PathBuf,
        /// Perform the writes. Without it, every batch runs in its own
        /// transaction that is rolled back when the batch ends.
        #[arg(long)]
        apply: bool,
        /// Claims per transaction.
        #[arg(long, default_value_t = 200)]
        batch_size: usize,
        /// `lock_timeout` for each batch (a PostgreSQL interval).
        #[arg(long, default_value = "5s")]
        lock_timeout: String,
        /// Opt-in evidence hiding. With none of these the run is unchanged.
        #[command(flatten)]
        hide: hide::HideArgs,
    },
    /// Report, and with `--apply` hide and pin, selected evidence on the
    /// operator's claims. Reversed by `reown-reverse --manifest`.
    HideEvidence {
        /// One claim UUID per line: the claims whose evidence is in scope.
        #[arg(long)]
        claims_file: PathBuf,
        /// The operator's agent id.
        #[arg(long)]
        operator: Uuid,
        #[command(flatten)]
        hide: hide::HideArgs,
        /// Hide the selected rows. Needs `--confirm-hide <N>` and
        /// `--manifest-out`, and the kernel pin guard (migration 110).
        #[arg(long)]
        apply: bool,
        /// Where to write the undo manifest under `--apply`. Must not exist.
        /// Written and fsynced before the write.
        #[arg(long)]
        manifest_out: Option<PathBuf>,
        /// Recorded on every pin.
        #[arg(
            long,
            default_value = "hidden by the operator (epigraph-operator hide-evidence)"
        )]
        reason: String,
        /// `lock_timeout` for the write (a PostgreSQL interval).
        #[arg(long, default_value = "5s")]
        lock_timeout: String,
    },
    /// Grant ONE admin-only scope to a HUMAN's own OAuth client, in both
    /// `allowed_scopes` and `granted_scopes`, with a `security_events` row.
    GrantClientScope(ScopeArgs),
    /// Revoke ONE admin-only scope from a HUMAN's own OAuth client, from both
    /// arrays, with a `security_events` row. A live access token keeps the
    /// scope until it expires; the next refresh drops it.
    RevokeClientScope(ScopeArgs),
    /// Restore every row a manifest's run moved to the owner it recorded.
    ReownReverse {
        /// A manifest to reverse. Repeatable: several are applied newest-first
        /// by their header `created_at`, whatever order they are given in.
        #[arg(long, required = true)]
        manifest: Vec<PathBuf>,
        #[arg(long)]
        apply: bool,
        #[arg(long, default_value_t = 200)]
        batch_size: usize,
        #[arg(long, default_value = "5s")]
        lock_timeout: String,
    },
}

/// The arguments of `grant-client-scope` and `revoke-client-scope`.
#[derive(clap::Args)]
#[command(group(clap::ArgGroup::new("mode").required(true).args(["dry_run", "apply"])))]
struct ScopeArgs {
    /// The client's `oauth_clients.id` (a UUID; not the `client_id` string).
    client: Uuid,
    /// An admin-only scope (`epigraph_core::canonical_scopes::ADMIN_ONLY_SCOPES`).
    scope: String,
    /// Run everything, the audit row included, in a transaction that is rolled
    /// back, and print what would change.
    #[arg(long)]
    dry_run: bool,
    /// Commit the change and its audit row.
    #[arg(long)]
    apply: bool,
    /// Recorded in the audit row.
    #[arg(long)]
    reason: Option<String>,
}

async fn main_inner() -> anyhow::Result<i32> {
    let cli = Cli::parse();
    // Refuse a non-admin-only scope before any connection is made.
    if let Command::GrantClientScope(a) | Command::RevokeClientScope(a) = &cli.command {
        client_scope::validate_scope(&a.scope)?;
    }
    if let Command::ReownClaims { batch_size, .. }
    | Command::ReownReverse { batch_size, .. }
    | Command::ReownLinked { batch_size, .. } = &cli.command
    {
        if *batch_size == 0 {
            anyhow::bail!("--batch-size must be at least 1");
        }
    }
    let db = operator::connect().await?;
    eprintln!(
        "epigraph-operator: connected as {} (member of epigraph_maintenance)",
        db.session_user
    );
    let mut conn = db.pool().acquire().await?;
    let mut stdout = std::io::stdout();
    match cli.command {
        Command::RegisterHumanOperator {
            agent,
            client,
            reason,
            apply,
        } => {
            let now = human::register(&mut conn, agent, client, &reason, apply).await?;
            println!(
                "{}{}\tagent={agent}\tclient={client}",
                if apply { "" } else { "WOULD BE " },
                if now {
                    "REGISTERED"
                } else {
                    "ALREADY-REGISTERED"
                }
            );
            if !apply {
                println!("DRY RUN: the registration and its audit row were rolled back.");
            }
            Ok(0)
        }
        Command::RevokeHumanOperator {
            agent,
            reason,
            apply,
        } => {
            let now = human::revoke(&mut conn, agent, &reason, apply).await?;
            println!(
                "{}{}\tagent={agent}",
                if apply { "" } else { "WOULD BE " },
                if now { "REVOKED" } else { "NOT-REGISTERED" }
            );
            if !apply {
                println!("DRY RUN: the revocation and its audit row were rolled back.");
            }
            Ok(0)
        }
        Command::Link {
            agent,
            agent_model,
            agent_system_prompt_hash,
            operator: op,
            revoke_foreign_writes,
            apply,
        } => {
            let spec = bind::AgentSpec::from_flags(agent, agent_model, agent_system_prompt_hash)?;
            let outcome = bind::run(
                db.pool(),
                &mut conn,
                &spec,
                op,
                revoke_foreign_writes,
                apply,
            )
            .await?;
            println!("{}", bind::describe(&outcome, op, apply));
            for line in bind::describe_foreign(&outcome, apply) {
                println!("{line}");
            }
            if !apply {
                println!("DRY RUN: the link above ran and was rolled back.");
            }
            Ok(if outcome.link.link_live { 0 } else { 3 })
        }
        Command::ArmOperatorBinding {
            recent_days,
            allow_unbound_writers,
            apply,
        } => {
            let report = arm::run(&mut conn, recent_days, apply, allow_unbound_writers).await?;
            for line in arm::describe(&report, recent_days, apply) {
                println!("{line}");
            }
            Ok(if report.refused { 1 } else { 0 })
        }
        Command::LinkLegacyAuthors {
            operator: op,
            exclude_agents_file,
            quiet_days,
            no_quiet_window,
            apply,
        } => {
            if !no_quiet_window && quiet_days <= 0 {
                anyhow::bail!("--quiet-days must be at least 1 (or pass --no-quiet-window)");
            }
            let exclude = match exclude_agents_file {
                Some(f) => operator::read_ids_file(&f)?,
                None => Vec::new(),
            };
            let opts = legacy::Options {
                operator: op,
                exclude,
                quiet_since: (!no_quiet_window)
                    .then(|| chrono::Utc::now() - chrono::Duration::days(quiet_days)),
                apply,
            };
            let rows = legacy::run(&mut conn, &opts).await?;
            for line in legacy::describe(&rows, &opts) {
                println!("{line}");
            }
            Ok(0)
        }
        Command::ReownLinked {
            operator: op,
            manifest_out,
            apply,
            batch_size,
            lock_timeout,
            legacy_owner,
        } => {
            let ids = reown_linked::candidates(&mut conn, op, legacy_owner).await?;
            if legacy_owner == reown_linked::LegacyOwner::Platform {
                let left = reown_linked::retired_left_behind(&mut conn, op).await?;
                println!(
                    "REPORT\t{left} claim(s) owned by a RETIRED-linked author's own personal group \
                     are left in place (--legacy-owner platform)"
                );
            }
            println!(
                "reown-linked: operator={op} candidates={} (claims owned by a linked author's own \
                 personal group)",
                ids.len()
            );
            if ids.is_empty() {
                println!("RESULT\n  claims moved: 0 (nothing to move)");
                return Ok(0);
            }
            let opts = reown::Options {
                operator: op,
                mode: reown::DerivedMode::FollowClaim,
                manifest_out,
                apply,
                batch_size,
                lock_timeout,
                hide: hide::HideArgs::default(),
            };
            reown::validate(&opts)?;
            let report = reown::run(&mut conn, &opts, &ids, &mut stdout).await?;
            Ok(if report.batch_failures.is_empty() {
                0
            } else {
                2
            })
        }
        Command::LinkRetired {
            agents_file,
            operator: op,
            attest_shared_signer,
            apply,
        } => {
            let agents = operator::read_ids_file(&agents_file)?;
            if agents.is_empty() {
                anyhow::bail!("no agent ids in {}", agents_file.display());
            }
            // An attestation covers ONE former signer: the principals it names
            // are the ones THAT signer carried. Applied to several ids, one set
            // would be recorded as attested for every signer in the file.
            if attest_shared_signer.is_some() && agents.len() > 1 {
                anyhow::bail!(
                    "--attest-shared-signer attests the principals of ONE former shared signer, \
                     but {} lists {} agent ids; run it once per signer with a one-id file",
                    agents_file.display(),
                    agents.len()
                );
            }
            println!(
                "link-retired: operator={op} agents={} mode={}{}",
                agents.len(),
                if apply { "APPLY" } else { "DRY-RUN" },
                match &attest_shared_signer {
                    Some(p) => format!(" shared-signer attested={p:?}"),
                    None => String::new(),
                }
            );
            let results = link::run(
                &mut conn,
                &agents,
                op,
                attest_shared_signer.as_deref(),
                apply,
            )
            .await?;
            let mut refused = 0;
            for (a, s) in &results {
                if s.is_refusal() {
                    refused += 1;
                }
                println!("{}", link::describe(*a, s));
            }
            if !apply {
                println!("DRY RUN: every call above ran and was rolled back.");
            }
            Ok(if refused > 0 { 3 } else { 0 })
        }
        Command::ReownClaims {
            claims_file,
            operator: op,
            derived,
            manifest_out,
            apply,
            batch_size,
            lock_timeout,
            hide,
        } => {
            let ids = operator::read_ids_file(&claims_file)?;
            if ids.is_empty() {
                anyhow::bail!("no claim ids in {}", claims_file.display());
            }
            let opts = reown::Options {
                operator: op,
                mode: derived,
                manifest_out,
                apply,
                batch_size,
                lock_timeout,
                hide,
            };
            reown::validate(&opts)?;
            let report = reown::run(&mut conn, &opts, &ids, &mut stdout).await?;
            Ok(if report.batch_failures.is_empty() {
                0
            } else {
                2
            })
        }
        Command::HideEvidence {
            claims_file,
            operator: op,
            hide,
            apply,
            manifest_out,
            reason,
            lock_timeout,
        } => {
            let ids = operator::read_ids_file(&claims_file)?;
            if ids.is_empty() {
                anyhow::bail!("no claim ids in {}", claims_file.display());
            }
            let opts = hide::Standalone {
                operator: op,
                args: hide,
                apply,
                manifest_out,
                reason,
                lock_timeout,
            };
            hide::run_standalone(&mut conn, &opts, &ids, &mut stdout).await?;
            Ok(0)
        }
        Command::GrantClientScope(a) | Command::RevokeClientScope(a) if !a.dry_run && !a.apply => {
            // Unreachable through clap (the `mode` group is required); kept so
            // a refactor that drops the group cannot turn a bare invocation
            // into a write.
            anyhow::bail!("exactly one of --dry-run or --apply is required")
        }
        cmd @ (Command::GrantClientScope(_) | Command::RevokeClientScope(_)) => {
            let (op, a) = match cmd {
                Command::GrantClientScope(a) => (client_scope::ScopeOp::Grant, a),
                Command::RevokeClientScope(a) => (client_scope::ScopeOp::Revoke, a),
                _ => unreachable!("matched above"),
            };
            let who = client_scope::Operator::of_this_process(db.session_user.clone());
            let outcome = client_scope::run(
                &mut conn,
                op,
                a.client,
                &a.scope,
                a.apply,
                a.reason.as_deref(),
                &who,
            )
            .await?;
            println!("{}", client_scope::describe(&outcome));
            Ok(0)
        }
        Command::ReownReverse {
            manifest,
            apply,
            batch_size,
            lock_timeout,
        } => {
            let opts = reverse::Options {
                manifests: manifest,
                apply,
                batch_size,
                lock_timeout,
            };
            let report = reverse::run(&mut conn, &opts, &mut stdout).await?;
            Ok(if !report.batch_failures.is_empty() {
                2
            } else if !report.held.is_empty() {
                3
            } else {
                0
            })
        }
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    match main_inner().await {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("epigraph-operator: {e:#}");
            std::process::exit(1);
        }
    }
}
