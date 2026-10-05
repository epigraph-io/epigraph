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
//!     epigraph-operator arm-admin-scopes --reason TEXT [--apply]
//!     epigraph-operator disarm-admin-scopes --reason TEXT [--apply]
//!     epigraph-operator grant-client-scope <client-id> <scope> (--dry-run | --apply) [--reason TEXT]
//!     epigraph-operator grant-role --role role:platform-custodian --holder <uuid> \
//!         (--valid-to <RFC3339> | --open-ended) [--valid-from <RFC3339>] \
//!         [--granted-by <uuid>] --reason TEXT [--act <uuid>] [--apply]
//!     epigraph-operator end-role-assignment --assignment <uuid> --reason TEXT [--act <uuid>] \
//!         [--apply]
//!     epigraph-operator list-role-assignments [--role R] [--include-ended]
//!     epigraph-operator custodial-supersede --claim <uuid> (--content TEXT | --content-file F) \
//!         --truth <0..1> --assignment <uuid> --actor <uuid> --reason TEXT [--allow-owned] \
//!         [--act <uuid>] [--apply]
//!     epigraph-operator revoke-client-scope <client-id> <scope> (--dry-run | --apply) [--reason TEXT]
//!     epigraph-operator passkey-enroll --person <uuid> --reason TEXT [--label TEXT] \
//!         [--act <uuid>] [--apply]
//!     epigraph-operator list-passkeys [--person <uuid>] [--include-revoked]
//!     epigraph-operator revoke-passkey --id <uuid> --reason TEXT [--apply]
//!     epigraph-operator end-elevation (--session <uuid> | --person <uuid>) --reason TEXT [--apply]
//!     epigraph-operator list-elevations [--person <uuid>] [--live]

use clap::{Parser, Subcommand};
use epigraph_cli::operator::{
    self, admin_scopes, arm, bind, client_scope, custodian, elevation, hide, human, legacy, link,
    passkey, reown, reown_linked, reverse,
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
    /// Grant a platform role (migration 123) to a REGISTERED HUMAN for an
    /// explicit window. Agents never hold a role (CUS01); once a custodian
    /// exists every grant names a live custodian as --granted-by (CUS03).
    GrantRole {
        /// `role:platform-custodian` or `role:auditor`.
        #[arg(long)]
        role: String,
        /// The human's own agent id (a registered human operator).
        #[arg(long)]
        holder: Uuid,
        /// When the assignment starts (RFC 3339; default now; never in the past).
        #[arg(long)]
        valid_from: Option<chrono::DateTime<chrono::Utc>>,
        /// When the assignment ends (RFC 3339). Exactly one of this and
        /// --open-ended.
        #[arg(long)]
        valid_to: Option<chrono::DateTime<chrono::Utc>>,
        /// Grant with no end: it is ended only by end-role-assignment.
        #[arg(long)]
        open_ended: bool,
        /// The granting custodian's agent id (required once any live custodian
        /// exists; omitted only for the bootstrap grant).
        #[arg(long)]
        granted_by: Option<Uuid>,
        /// Recorded on the assignment and in its audit row.
        #[arg(long)]
        reason: String,
        /// A CONFIRMED `role.grant` admin act (migration 130) whose args are
        /// exactly these flags, proposed by --granted-by. Required once the
        /// grantor holds a passkey (ELV10 otherwise).
        #[arg(long)]
        act: Option<Uuid>,
        /// Commit. Without it, the grant, its audit row and its projection roll back.
        #[arg(long)]
        apply: bool,
    },
    /// End a role assignment now (its revoke stamp; an ended assignment is final).
    EndRoleAssignment {
        /// The assignment id (list-role-assignments).
        #[arg(long)]
        assignment: Uuid,
        /// Recorded on the assignment and in its audit row.
        #[arg(long)]
        reason: String,
        /// A CONFIRMED `role.end` admin act (migration 130) for this
        /// assignment and this reason. Required while any live custodian holds
        /// a passkey (ELV10 otherwise).
        #[arg(long)]
        act: Option<Uuid>,
        /// Commit. Without it, the end and its audit row roll back.
        #[arg(long)]
        apply: bool,
    },
    /// Revise a platform-corpus claim as the custodian: the supersede act,
    /// the edge migration and a `platform.custodial_act` audit row naming the
    /// assignment, in ONE transaction on the maintenance DSN (migration 123).
    /// World-owned claims only unless --allow-owned. Exit 2: the act did not
    /// leave what it must, rolled back.
    CustodialSupersede {
        /// The current claim to revise.
        #[arg(long)]
        claim: Uuid,
        /// The revised text.
        #[arg(long, conflicts_with = "content_file")]
        content: Option<String>,
        /// A file holding the revised text.
        #[arg(long)]
        content_file: Option<PathBuf>,
        /// The successor's truth value, in [0, 1].
        #[arg(long)]
        truth: f64,
        /// The actor's live role:platform-custodian assignment.
        #[arg(long)]
        assignment: Uuid,
        /// The custodian (a registered human) on whose authority this runs.
        #[arg(long)]
        actor: Uuid,
        /// Recorded on the supersedes edge and in the audit row.
        #[arg(long)]
        reason: String,
        /// Admit a claim the world group does not own.
        #[arg(long)]
        allow_owned: bool,
        /// A CONFIRMED `claim.custodial_supersede` admin act (migration 130)
        /// whose args are exactly these flags (the content's SHA-256, the
        /// truth to six places), proposed by --actor. Required once the actor
        /// holds a passkey (ELV10 otherwise).
        #[arg(long)]
        act: Option<Uuid>,
        /// Commit. Without it, the act and its audit row roll back.
        #[arg(long)]
        apply: bool,
    },
    /// Open a passkey ENROLLMENT TICKET (migration 124) for a REGISTERED
    /// HUMAN, live for 15 minutes, and print its ceremony path
    /// (`/elevate/enroll/<id>`, under the deployment's public base URL). The
    /// human completes it on the device that holds the authenticator. Agents
    /// never hold a passkey (ELV01).
    PasskeyEnroll {
        /// The human's own agent id (a registered human operator).
        #[arg(long)]
        person: Uuid,
        /// Recorded on the ticket and in its audit row.
        #[arg(long)]
        reason: String,
        /// A name for the passkey (e.g. the device), copied onto it.
        #[arg(long)]
        label: Option<String>,
        /// A CONFIRMED `passkey.register` admin act (migration 130) of this
        /// person, whose args are exactly these flags. Required for a LATER
        /// passkey (ELV10 otherwise).
        #[arg(long)]
        act: Option<Uuid>,
        /// Commit. Without it, the ticket and its audit row roll back.
        #[arg(long)]
        apply: bool,
    },
    /// List passkeys (live ones unless --include-revoked).
    ListPasskeys {
        /// Only this human's passkeys.
        #[arg(long)]
        person: Option<Uuid>,
        /// Include revoked passkeys.
        #[arg(long)]
        include_revoked: bool,
    },
    /// Revoke a passkey now (break-glass; audited; a revoked passkey is final).
    RevokePasskey {
        /// The passkey id (list-passkeys).
        #[arg(long)]
        id: Uuid,
        /// Recorded on the passkey and in its audit row.
        #[arg(long)]
        reason: String,
        /// Commit. Without it, the revoke and its audit row roll back.
        #[arg(long)]
        apply: bool,
    },
    /// End live elevation sessions now: one by id, or every un-ended session
    /// of a person (any person's; each audited `platform.elevation_ended` with
    /// the reason, ended_by = this maintenance login).
    #[command(group(clap::ArgGroup::new("target").required(true).args(["session", "person"])))]
    EndElevation {
        /// The elevation session id (`list-elevations`; the `elv` claim).
        #[arg(long)]
        session: Option<Uuid>,
        /// End every un-ended session of this person instead.
        #[arg(long)]
        person: Option<Uuid>,
        /// Why. Recorded in each end's audit row (`operator_reason`).
        #[arg(long)]
        reason: String,
        /// Commit. Without it, the end and its audit rows roll back.
        #[arg(long)]
        apply: bool,
    },
    /// List elevation sessions, newest first (all of them unless --live).
    ListElevations {
        /// Only this person's sessions.
        #[arg(long)]
        person: Option<Uuid>,
        /// Only un-ended, unexpired sessions (the row's own columns; the
        /// per-statement liveness re-checks are not evaluated here).
        #[arg(long)]
        live: bool,
    },
    /// List role assignments (un-ended ones unless --include-ended).
    ListRoleAssignments {
        /// Only this role.
        #[arg(long)]
        role: Option<String>,
        /// Include ended assignments.
        #[arg(long)]
        include_ended: bool,
    },
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
    /// Arm migration 128's admin-scope switch: from then on every mint strips
    /// the admin-only scopes and every path that hands scopes out refuses
    /// them. Audited. Without `--apply`, the change is rolled back.
    ArmAdminScopes(AdminScopeArgs),
    /// Disarm migration 128's admin-scope switch (the rollback): admin-only
    /// scopes are standing authority again. Audited. Without `--apply`, the
    /// change is rolled back.
    DisarmAdminScopes(AdminScopeArgs),
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

/// The arguments of `arm-admin-scopes` and `disarm-admin-scopes`.
#[derive(clap::Args)]
struct AdminScopeArgs {
    /// Why (recorded in the audit event). Required.
    #[arg(long)]
    reason: String,
    /// Commit the change. Without it, the change and its audit event run in a
    /// transaction that is rolled back.
    #[arg(long)]
    apply: bool,
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
    // Refuse a blank switch reason before any connection is made.
    if let Command::ArmAdminScopes(a) | Command::DisarmAdminScopes(a) = &cli.command {
        admin_scopes::validate_reason(&a.reason)?;
    }
    // Refuse a non-admin-only scope before any connection is made.
    if let Command::GrantClientScope(a) | Command::RevokeClientScope(a) = &cli.command {
        client_scope::validate_scope(&a.scope)?;
    }
    // A grant names its window explicitly; refused before any connection.
    let window = if let Command::GrantRole {
        role,
        valid_from,
        valid_to,
        open_ended,
        ..
    } = &cli.command
    {
        Some(custodian::Window::from_flags(
            role,
            *valid_from,
            *valid_to,
            *open_ended,
        )?)
    } else {
        None
    };
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
        Command::GrantRole {
            role,
            holder,
            granted_by,
            reason,
            act,
            apply,
            ..
        } => {
            let window = window.expect("validated above");
            if let Some(act) = act {
                let Some(grantor) = granted_by else {
                    eprintln!(
                        "epigraph-operator: REFUSED: a grant on a confirmed act names its \
                         grantor: --granted-by <the act's proposer>. Nothing was changed."
                    );
                    return Ok(1);
                };
                let args = custodian::grant_act_args(&role, holder, window, &reason);
                if let Some(why) = custodian::act_refusal(
                    &mut conn,
                    act,
                    epigraph_db::admin_act::ROLE_GRANT,
                    &args,
                    Some(grantor),
                )
                .await?
                {
                    eprintln!("epigraph-operator: REFUSED: {why}. Nothing was changed.");
                    return Ok(1);
                }
            }
            let row = custodian::grant(
                &mut conn, &role, holder, window, granted_by, &reason, act, apply,
            )
            .await?;
            println!(
                "{}GRANTED\t{}{}",
                if apply { "" } else { "WOULD BE " },
                custodian::describe(&row),
                act.map_or_else(String::new, |a| format!("\tact={a}"))
            );
            if !apply {
                println!(
                    "DRY RUN: the grant, its audit row and its graph projection were rolled back."
                );
            }
            Ok(0)
        }
        Command::EndRoleAssignment {
            assignment,
            reason,
            act,
            apply,
        } => {
            if let Some(act) = act {
                let args = custodian::end_act_args(assignment, &reason);
                if let Some(why) = custodian::act_refusal(
                    &mut conn,
                    act,
                    epigraph_db::admin_act::ROLE_END,
                    &args,
                    None,
                )
                .await?
                {
                    eprintln!("epigraph-operator: REFUSED: {why}. Nothing was changed.");
                    return Ok(1);
                }
            }
            let (ended, row) = custodian::end(&mut conn, assignment, &reason, act, apply).await?;
            println!(
                "{}{}\t{}{}",
                if apply || !ended { "" } else { "WOULD BE " },
                if ended { "ENDED" } else { "ALREADY-ENDED" },
                custodian::describe(&row),
                act.map_or_else(String::new, |a| format!("\tact={a}"))
            );
            if !apply {
                println!("DRY RUN: the end and its audit row were rolled back.");
            }
            Ok(0)
        }
        Command::CustodialSupersede {
            claim,
            content,
            content_file,
            truth,
            assignment,
            actor,
            reason,
            allow_owned,
            act,
            apply,
        } => {
            let content = match (content, content_file) {
                (Some(c), None) => c,
                (None, Some(f)) => std::fs::read_to_string(&f)
                    .map_err(|e| anyhow::anyhow!("reading {}: {e}", f.display()))?,
                _ => anyhow::bail!("exactly one of --content / --content-file"),
            };
            let req = custodian::SupersedeRequest {
                claim,
                content,
                truth,
                assignment,
                actor,
                reason,
                allow_owned,
                act,
                apply,
            };
            match custodian::custodial_supersede(&mut conn, &req).await? {
                custodian::SupersedeOutcome::Done(r) => {
                    println!(
                        "{}SUPERSEDED\told={}\tnew={}\tauthor={}\towner={}\tedges_moved={}\t\
                         custodial_act={}\tassignment={assignment}\tactor={actor}{}",
                        if r.applied { "" } else { "WOULD BE " },
                        r.old,
                        r.new,
                        r.author,
                        r.owner,
                        r.edges_moved,
                        r.act_event,
                        r.admin_act
                            .map_or_else(String::new, |a| format!("\tact={a}"))
                    );
                    if r.applied {
                        println!(
                            "NOTE: the successor has no embedding until the next embedding \
                             backfill; it is a live_missing row until then."
                        );
                    } else {
                        println!(
                            "DRY RUN: the supersede, its edge migration and its audit row were \
                             rolled back."
                        );
                    }
                    Ok(0)
                }
                custodian::SupersedeOutcome::Refused(why) => {
                    eprintln!("epigraph-operator: REFUSED: {why}");
                    Ok(1)
                }
                custodian::SupersedeOutcome::Invariant(why) => {
                    eprintln!("epigraph-operator: INVARIANT VIOLATED: {why}");
                    Ok(2)
                }
            }
        }
        Command::PasskeyEnroll {
            person,
            reason,
            label,
            act,
            apply,
        } => {
            if let Some(act) = act {
                let args = passkey::register_act_args(person, label.as_deref(), &reason);
                if let Some(why) = custodian::act_refusal(
                    &mut conn,
                    act,
                    epigraph_db::admin_act::PASSKEY_REGISTER,
                    &args,
                    Some(person),
                )
                .await?
                {
                    eprintln!("epigraph-operator: REFUSED: {why}. Nothing was changed.");
                    return Ok(1);
                }
            }
            let row =
                passkey::enroll(&mut conn, person, &reason, label.as_deref(), act, apply).await?;
            println!(
                "{}ENROLLED\t{}",
                if apply { "" } else { "WOULD BE " },
                passkey::describe_enrollment(&row)
            );
            if apply {
                println!(
                    "Open the ceremony path under the deployment's public base URL, on the device \
                     that holds the authenticator, before {}.",
                    row.expires_at.to_rfc3339()
                );
            } else {
                println!(
                    "DRY RUN: the ticket and its audit row were rolled back; the ceremony path \
                     above is not live."
                );
            }
            Ok(0)
        }
        Command::ListPasskeys {
            person,
            include_revoked,
        } => {
            let rows =
                epigraph_db::PasskeyRepository::list(&mut conn, person, include_revoked).await?;
            if rows.is_empty() {
                println!("no passkeys");
            }
            for row in &rows {
                println!("{}", passkey::describe(row));
            }
            Ok(0)
        }
        Command::RevokePasskey { id, reason, apply } => {
            let (revoked, row) = passkey::revoke(&mut conn, id, &reason, apply).await?;
            println!(
                "{}{}\t{}",
                if apply || !revoked { "" } else { "WOULD BE " },
                if revoked {
                    "REVOKED"
                } else {
                    "ALREADY-REVOKED"
                },
                passkey::describe(&row)
            );
            if !apply {
                println!("DRY RUN: the revoke and its audit row were rolled back.");
            }
            Ok(0)
        }
        Command::EndElevation {
            session,
            person,
            reason,
            apply,
        } => {
            let target = match (session, person) {
                (Some(id), _) => elevation::Target::Session(id),
                (None, Some(p)) => elevation::Target::Person(p),
                (None, None) => unreachable!("clap requires --session or --person"),
            };
            let outcomes = elevation::end(&mut conn, target, &reason, apply).await?;
            if outcomes.is_empty() {
                println!("NOT-LIVE\tno un-ended session");
            }
            for (session, ended) in &outcomes {
                println!(
                    "{}{}\t{session}",
                    if apply || !ended { "" } else { "WOULD BE " },
                    if *ended { "ENDED" } else { "NOT-LIVE" },
                );
            }
            if !apply {
                println!("DRY RUN: the end and its audit rows were rolled back.");
            }
            Ok(0)
        }
        Command::ListElevations { person, live } => {
            let rows = elevation::list(&mut conn, person, live).await?;
            if rows.is_empty() {
                println!("no elevation sessions");
            }
            for row in &rows {
                println!("{}", elevation::describe(row));
            }
            Ok(0)
        }
        Command::ListRoleAssignments {
            role,
            include_ended,
        } => {
            let rows = epigraph_db::RoleAssignmentRepository::list(
                &mut conn,
                role.as_deref(),
                include_ended,
            )
            .await?;
            if rows.is_empty() {
                println!("no role assignments");
            }
            for row in &rows {
                println!("{}", custodian::describe(row));
            }
            Ok(0)
        }
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
        cmd @ (Command::ArmAdminScopes(_) | Command::DisarmAdminScopes(_)) => {
            let (arm, a) = match cmd {
                Command::ArmAdminScopes(a) => (true, a),
                Command::DisarmAdminScopes(a) => (false, a),
                _ => unreachable!("matched above"),
            };
            let outcome = admin_scopes::run(&mut conn, arm, &a.reason, a.apply).await?;
            for line in admin_scopes::describe(&outcome) {
                println!("{line}");
            }
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
