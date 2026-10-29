//! `decompose_claims` — split standalone compound claims into atomic
//! propositions + wire parent -decomposes_to-> atom edges.
//!
//! The decompose primitive the dead `decomposition-cycle` schedule needs.
//! Enumerates via `ClaimRepository::list_undecomposed`, decomposes each batch
//! through the prepaid Claude path (`create_llm_client("epigraph")`, which
//! prefers CLAUDE_CODE_OAUTH_TOKEN — NEVER the Anthropic-SDK pay-per-token
//! variant the V2 `_api.py`/`_openai.py` scripts used), parses with
//! `epigraph_cli::decompose::parse_batch_response`, and persists atoms through
//! the canonical API claim path so embedding, author-key signing and the
//! atom's derivation evidence happen on write. NO DS mass function is written
//! for an atom: `POST /api/v1/claims` has no DS auto-wire.
//!
//! # Evidence policy for atoms (U041, backlog 3590a2d8)
//!
//! Atoms carry derivation PROVENANCE, not derived BELIEF, until
//! `decomposes_to` propagation exists. Each atom POST names its parent in
//! `derived_from`, and the API records one `document` evidence row on the atom
//! (the parent's text, `properties.derived_from_claim` = parent id) in the
//! atom's own transaction, so `get_provenance` shows where it came from. The
//! atom's truth stays at 0.5 until INDEPENDENT evidence arrives: its only
//! warrant at birth is "the parent states it", and when the parent is itself
//! evidence-free (the legacy 2026-02/03 imports) any belief given to the atom
//! would be laundered from it. Only `visibility = 'public'` parents are
//! selected ([`epigraph_cli::decompose::check_publicly_decomposable`]).
//!
//! Required: DATABASE_URL (plus MAINTENANCE_DATABASE_URL on the maintenance
//! path; see "Running as an agent" for the path without it), and
//! CLAUDE_CODE_OAUTH_TOKEN.
//! API base: EPIGRAPH_API (primary) or EPIGRAPH_API_URL (container fallback),
//! default http://127.0.0.1:8080. Auth token: EPIGRAPH_TOKEN if set, otherwise
//! minted via client_credentials from EPIGRAPH_SERVICE_CLIENT_ID +
//! EPIGRAPH_SERVICE_SECRET against EPIGRAPH_OAUTH_TOKEN_URL (default
//! `{api_base}/oauth/token`). If NEITHER is available the run aborts before
//! the first write — it does NOT proceed with an empty bearer token.
//! Use `--provider mock` for a dry compile/smoke without credentials (it
//! returns an empty batch, so nothing is written, and auth is therefore not
//! resolved at all). Use `--provider fixture`
//! plus `DECOMPOSE_FIXTURE_PATH=<file.json>` to exercise the atom/edge WRITE
//! path deterministically without an LLM call — see [`FixtureLlmClient`] for
//! the file format.
//!
//! # Selection (`--priority`, `--ids-file`, eligibility filters)
//!
//! `--priority oldest` (default) is the historical `created_at ASC` crawl.
//! `--priority conflict` puts undecomposed claims that are the TARGET of a
//! contradicts/refutes edge first (edge count desc, newest edge, id), then
//! REPORTS the decomposed parents that are still conflict targets — those go
//! to `--retarget`, not to the LLM again. `--priority recent` is newest first.
//! `--ids-file` names claims explicitly (one UUID per line, `#` comments).
//!
//! Two filters default ON: skip `backlog`-labelled claims
//! (`--include-backlog`) and skip claims that look atomic, one sentence and
//! ≤ 160 chars (`--include-short`, see `epigraph_cli::decompose::looks_atomic`).
//! Every explicit `--ids-file` id a filter rejects is printed with its reason.
//! The population is paged so filters never starve a run; `--max-scan` bounds
//! the rows read.
//!
//! `--singleton-ledger <file>` (backlog 68d03c24, U040): a parent the model
//! answers with ONE atom gets no edge, so it stays undecomposed; without a
//! record every later run re-selects it and pays for the same answer again.
//! With the flag, a normal run and `--apply-plan` append each such verdict
//! (claim id + BLAKE3 of the judged text) to the JSONL file, and selection
//! skips a parent whose id and exact text the file holds
//! (`skipped_judged_atomic=` on the `selection:` line; `--include-judged-atomic`
//! asks again). `--dry-run` and `--plan` only read it. A parent whose text
//! changes is asked again.
//!
//! # Running as an agent (`--as-agent <agent id>`; backlog 9a877b7c)
//!
//! Without the flag the binary is a maintenance job: it connects through
//! `epigraph_cli::MaintenancePool` and refuses to start unless the connection
//! satisfies `epigraph_bypass()`. An agent container holds only the ordinary
//! application login in `DATABASE_URL`, which that refusal rejects. A
//! scheduled run in an agent container therefore takes this path, which
//! needs no maintenance DSN:
//!
//! * the application login in `DATABASE_URL` as a `ScopedPool`; no
//!   maintenance DSN is read and no privilege is asserted;
//! * every read on a connection stamped for the acting agent, so selection
//!   sees what row-level security shows that agent (public rows, plus rows of
//!   its own groups), and the `decomposes_to` edges in a transaction stamped
//!   for it, so each edge records the agent's group as its writer (migration
//!   120) rather than landing ownerless. Atoms still go through
//!   `POST /api/v1/claims` with the API token;
//! * a writing run asks the database which group its edges would record
//!   (`epigraph_writer_group()`, the trigger's own function), prints it on
//!   the `connection:` line (`writer_group=`), and refuses when there is none
//!   (`has no writer group`);
//! * the old refusal's purpose, no silent zero-row run, is kept by the
//!   result: a `--priority oldest|recent` scan that reads NO undecomposed
//!   claim fails (`sees no undecomposed claim`); judged-atomic and short
//!   parents stay in that population, so on a live corpus it is never empty.
//!   `--priority conflict` reads only the targets of a live conflict edge,
//!   which may legitimately be none: it fails only when the session sees no
//!   claim at all (`sees no claim at all`). `chosen=0` over a visible
//!   population is the steady state and exits 0. `--ids-file` names every id
//!   it skips, so it is not subject to this;
//! * `--retarget` stays on the maintenance path, and `--priority conflict`'s
//!   report of decomposed conflict parents is printed only there.
//!
//! Pass the agent the API token acts as (the service client's agent). The
//! binary does not check that the two match: atoms are created as the
//! token's agent and edges as `--as-agent`, so a mismatch splits their
//! attribution. That is an operator check at deploy time, not a privilege
//! question (the application login can already stamp any agent).
//!
//! Coverage against the maintenance view (measured on a fixture in
//! `tests/decompose_claims_as_agent.rs`):
//!
//! 1. a group-private parent outside the agent's groups is not read at all.
//!    That loses nothing: only public parents are ever decomposed
//!    (`skipped_not_public` on the maintenance path);
//! 2. a PUBLIC parent whose only `decomposes_to` edges are hidden from the
//!    agent (private to a group it is not in) reads as undecomposed, because
//!    row security also filters the `NOT EXISTS` edge probe. The run
//!    decomposes it again. Where the hidden edge points at a private atom,
//!    the result is a second set of public atoms. Where it points at a
//!    PUBLIC atom and the model returns the same text, `if_not_exists`
//!    returns that same atom, and the edge dedup probe
//!    (`EdgeRepository::create_if_absent_including_retracted_conn`) is
//!    filtered by row security on this login too, so a second, public
//!    `(parent, atom, decomposes_to)` edge is written next to the hidden
//!    one (no unique index stops it since migration 018). The second case is
//!    derived from the code, not measured.
//!
//! The `--singleton-ledger` and `--count-eligible` flags behave identically
//! on both paths.
//!
//! # Modes
//!
//! * default — select, decompose through the LLM, persist.
//! * `--dry-run` — select and print; no LLM call, no write.
//! * `--plan <file>` — select, CALL the LLM, print the proposed atoms, write a
//!   JSONL plan; nothing is written to the graph and no API auth is needed.
//! * `--apply-plan <file>` — persist exactly that plan with NO LLM call. A plan
//!   line whose parent has since been decomposed, retired, or edited is
//!   refused and reported.
//! * `--retarget` — move contradicts/refutes edges from decomposed parents to
//!   the atoms they dispute (`epigraph_cli::retarget`). DRY RUN by default: the
//!   LLM is called, the mapping printed, a manifest written (`--manifest`),
//!   nothing else. `--retarget --apply` writes through the API;
//!   `--retarget --apply-plan <manifest>` applies a reviewed manifest with no
//!   LLM call. Both retarget writing modes first check this process's belief
//!   modes against the API's `/health` and refuse on any difference, before
//!   the database or the token mint (`epigraph_cli::belief_mode_check`, SPEC
//!   §10.2); the retarget dry run is exempt.
//!
//! Every writing mode resolves API auth BEFORE any LLM call (gh-375).
//!
//! # Running the writes in production
//!
//! * Pause the scheduled `decomposition-cycle` and avoid API redeploys while
//!   `--apply-plan` or `--retarget --apply` runs. Selection/verification and
//!   the write are not one transaction, and the scheduled cycle also selects
//!   then persists, so overlapping runs can decompose one parent twice. An
//!   API restart mid-run is recoverable (a failed plan line leaves its parent
//!   undecomposed; a retarget entry records the error and is resumed) but
//!   costs a re-run.
//! * Runtime dependencies: the API's token mint (`/oauth/token`; other
//!   branches add a `refuse_operated_agent` check there, which fails closed
//!   before any LLM call), and for `--retarget` writes an `edges:write` GRANT
//!   on the service client (the mint asks for `claims:write edges:write`).
//!   Whether the API writes edge BBAs at all depends on the role it runs as
//!   (see `epigraph_cli::retarget`, "When an atom edge carries no BBA"); a
//!   `--retarget --apply --limit 1` run shows `atom_edges_not_ds_wired`.
//! * The eligibility filters are ON by default for every `--priority`,
//!   including the scheduled `oldest` crawl, whose head is ≈87k short 2026-03
//!   extracts the filter skips; such a run may read `--max-scan` rows and
//!   choose few. Point the schedule at `--priority conflict` (then `recent`)
//!   before redeploying this binary.
//! * Steady state (U040 ruling, 2026-10-14): a DAILY `--priority recent
//!   --limit L --singleton-ledger <durable path>` run, with L sized so
//!   `7 × L ≥ 1.5 ×` the measured weekly inflow (≈410/week on 2026-10-14, so
//!   L = 100). Keep the ledger next to the durable run logs, never in the
//!   ephemeral container, and pass the SAME path to `--apply-plan` catch-up
//!   runs. Add the flag to a schedule only after this binary is deployed: an
//!   older binary rejects it and the run fails.
//! * Measuring the drain: `--count-eligible` reads on past `--limit` (up to
//!   `--max-scan`) and prints `selection: eligible=N` — the parents that pass
//!   every filter, judged-atomic verdicts included. A scheduled run that
//!   carries it shows week over week whether the eligible population falls;
//!   `--dry-run --count-eligible --max-scan <population>` is the one-off
//!   measurement (OFFSET paging: run it off-hours).

use clap::Parser;
use epigraph_cli::decompose::{
    atom_create_body, persist_planned, plan_decomposition_batches_with_gaps, read_plan_jsonl,
    run_decomposition_batches, select_candidates, verify_plan, visible_claim_count,
    write_plan_jsonl, writer_group, AtomParent, BatchClaim, DecomposeDb, EligibilityFilters,
    PlanGaps, Priority, SingletonLedger,
};
use epigraph_cli::enrichment::llm_client::{FixtureLlmClient, LlmProvider};
use epigraph_cli::retarget::{
    apply_retarget, load_retarget_items, read_retarget_manifest, run_retarget, verdict,
    EdgeApiClient, RetargetOptions,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum PriorityArg {
    Conflict,
    Recent,
    Oldest,
}

impl From<PriorityArg> for Priority {
    fn from(p: PriorityArg) -> Self {
        match p {
            PriorityArg::Conflict => Priority::Conflict,
            PriorityArg::Recent => Priority::Recent,
            PriorityArg::Oldest => Priority::Oldest,
        }
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "decompose_claims",
    about = "Decompose undecomposed compound claims into atoms, or retarget conflict edges onto atoms"
)]
struct Cli {
    /// Max claims (or, with --retarget, conflict edges) to process this run.
    #[arg(long, default_value_t = 200)]
    limit: i64,
    /// Claims (or retarget items) per LLM call.
    #[arg(long, default_value_t = 10)]
    batch_size: usize,
    /// LLM provider selector for create_llm_client ("epigraph" auto, or
    /// "mock"), or "fixture" for the deterministic test provider (requires
    /// DECOMPOSE_FIXTURE_PATH).
    #[arg(long, default_value = "epigraph")]
    provider: String,
    /// Enumerate only — do not call the LLM or write anything. With
    /// --retarget this is already the default and the LLM IS called.
    #[arg(long, default_value_t = false)]
    dry_run: bool,
    /// Candidate order.
    #[arg(long, value_enum, default_value_t = PriorityArg::Oldest)]
    priority: PriorityArg,
    /// Decompose exactly these claim ids (one UUID per line; blank lines and
    /// `#` comments ignored), still subject to the eligibility filters.
    #[arg(long)]
    ids_file: Option<PathBuf>,
    /// Do not skip `backlog`-labelled claims.
    #[arg(long, default_value_t = false)]
    include_backlog: bool,
    /// Do not skip claims that look atomic (one sentence, <= 160 chars).
    #[arg(long, default_value_t = false)]
    include_short: bool,
    /// JSONL ledger of parents the model already answered with one atom
    /// ("already atomic"). A normal run and `--apply-plan` append every such
    /// verdict to it; selection skips a parent whose id and exact text it
    /// holds, so the same claim is never re-asked. `--dry-run` and `--plan`
    /// only read it. Absent: nothing is recorded and nothing is skipped.
    #[arg(long)]
    singleton_ledger: Option<PathBuf>,
    /// With --singleton-ledger: select parents the ledger holds anyway (their
    /// verdicts are still recorded).
    #[arg(long, default_value_t = false)]
    include_judged_atomic: bool,
    /// Keep reading past --limit (up to --max-scan rows) and print how many
    /// eligible parents remain (`eligible=`; `>=` when --max-scan stopped the
    /// count). The parents processed are exactly those a run without it
    /// chooses, but the `skipped_*` counts then cover every row read, not only
    /// the rows a plain run would read. Not with --ids-file.
    #[arg(long, default_value_t = false)]
    count_eligible: bool,
    /// Stop reading the undecomposed population after this many rows.
    #[arg(long, default_value_t = 20_000)]
    max_scan: usize,
    /// Run as this agent (an `agents.id`) on the ordinary application login
    /// in DATABASE_URL, through row-level security, with NO maintenance DSN:
    /// selection reads what that agent can see, and `decomposes_to` edges are
    /// written as it. A decomposing run needs the agent to hold a writable
    /// group. Without the flag the run takes the maintenance path
    /// (MAINTENANCE_DATABASE_URL, privilege checked at startup). Not with
    /// --retarget. See the module doc, "Running as an agent".
    #[arg(long)]
    as_agent: Option<uuid::Uuid>,
    /// Call the LLM, print the proposed atoms, write this JSONL plan, and
    /// write NOTHING to the graph.
    #[arg(long)]
    plan: Option<PathBuf>,
    /// Persist exactly this plan (or, with --retarget, this manifest) with no
    /// LLM call.
    #[arg(long)]
    apply_plan: Option<PathBuf>,
    /// Retarget contradicts/refutes edges from decomposed parents onto atoms.
    #[arg(long, default_value_t = false)]
    retarget: bool,
    /// With --retarget: perform the writes (default is a dry run).
    #[arg(long, default_value_t = false)]
    apply: bool,
    /// With --retarget: manifest path to write (default
    /// `retarget-manifest-<UTC timestamp>.jsonl`). Refused if it exists.
    #[arg(long)]
    manifest: Option<PathBuf>,
    /// With --retarget --apply / --apply-plan: proceed although this process's
    /// belief modes differ from the API's `/health` report (or cannot be
    /// read). For tests and a deliberate, recorded override only.
    #[arg(long, hide = true)]
    allow_mode_skew: bool,
    /// With --retarget: also revisit edges already marked `retargeted_to`
    /// (fully wired ones included). An edge that already has atom edges is
    /// resumed from them and re-checked, not re-asked of the LLM.
    #[arg(long, default_value_t = false)]
    include_marked: bool,
}

/// What this invocation does. Derived from the flags by [`resolve_mode`], a
/// pure function so the flag rules are unit-tested.
#[derive(Debug, PartialEq, Eq)]
enum Mode {
    /// `--dry-run`: select and print.
    Enumerate,
    /// `--plan <file>`.
    Plan(PathBuf),
    /// `--apply-plan <file>`.
    ApplyPlan(PathBuf),
    /// Select, LLM, persist.
    Run,
    /// `--retarget` without `--apply`.
    RetargetDryRun(PathBuf),
    /// `--retarget --apply`.
    RetargetApply(PathBuf),
    /// `--retarget --apply-plan <manifest>`.
    RetargetApplyPlan(PathBuf),
}

impl Mode {
    /// Whether this mode writes through the API and therefore needs auth
    /// resolved up front. `Run` depends on the provider (see
    /// [`provider_writes_to_api`]).
    fn writes(&self, provider: &str) -> bool {
        match self {
            Mode::Enumerate | Mode::Plan(_) | Mode::RetargetDryRun(_) => false,
            Mode::Run => provider_writes_to_api(provider),
            Mode::ApplyPlan(_) | Mode::RetargetApply(_) | Mode::RetargetApplyPlan(_) => true,
        }
    }

    /// Whether this mode is a retarget WRITE, which runs the belief-mode check
    /// (SPEC §10.2). Decomposition modes are not wave runs and are not checked.
    fn is_retarget_write(&self) -> bool {
        matches!(self, Mode::RetargetApply(_) | Mode::RetargetApplyPlan(_))
    }

    /// The OAuth scope a minted token must carry for this mode's writes.
    ///
    /// Decomposition POSTs `/api/v1/claims` (`claims:write`). Retarget POSTs
    /// and PATCHes `/api/v1/edges`, which `create_edge` / `patch_edge` gate on
    /// `edges:write`; a token minted with the historical `claims:write` alone
    /// would 403 on the first retarget write. The service client must be
    /// GRANTED `edges:write` for the mint to succeed — an operator check,
    /// since a refused scope fails the mint before any LLM call.
    fn mint_scope(&self) -> &'static str {
        match self {
            Mode::RetargetApply(_) | Mode::RetargetApplyPlan(_) => "claims:write edges:write",
            _ => "claims:write",
        }
    }
}

fn default_manifest_path(now: chrono::DateTime<chrono::Utc>) -> PathBuf {
    PathBuf::from(format!(
        "retarget-manifest-{}.jsonl",
        now.format("%Y%m%dT%H%M%SZ")
    ))
}

fn resolve_mode(cli: &Cli, now: chrono::DateTime<chrono::Utc>) -> Result<Mode, String> {
    if cli.plan.is_some() && cli.apply_plan.is_some() {
        return Err("--plan and --apply-plan are mutually exclusive".into());
    }
    if cli.dry_run && (cli.apply || cli.apply_plan.is_some()) {
        return Err("--dry-run cannot be combined with --apply or --apply-plan".into());
    }
    if cli.as_agent.is_some() && cli.retarget {
        return Err(
            "--retarget runs only on the maintenance path; it does not apply to --as-agent".into(),
        );
    }
    if cli.include_judged_atomic && cli.singleton_ledger.is_none() {
        return Err("--include-judged-atomic needs --singleton-ledger".into());
    }
    if cli.count_eligible && (cli.ids_file.is_some() || cli.apply_plan.is_some() || cli.retarget) {
        return Err(
            "--count-eligible counts the paged population; it does not apply to --ids-file, \
             --apply-plan or --retarget"
                .into(),
        );
    }
    if cli.retarget && cli.singleton_ledger.is_some() {
        return Err(
            "--singleton-ledger records decomposition verdicts; --retarget makes none".into(),
        );
    }
    if cli.apply_plan.is_some() && cli.ids_file.is_some() {
        return Err(
            "--apply-plan persists the plan's own claims; --ids-file does not apply".into(),
        );
    }
    if cli.retarget {
        if cli.plan.is_some() {
            return Err(
                "--retarget's dry run IS its plan: use --manifest <file>, then \
                 --retarget --apply-plan <file>"
                    .into(),
            );
        }
        if cli.ids_file.is_some() {
            return Err(
                "--ids-file selects claims to decompose; it does not apply to --retarget".into(),
            );
        }
        if let Some(m) = &cli.apply_plan {
            if cli.apply {
                return Err("--apply-plan already applies; drop --apply".into());
            }
            return Ok(Mode::RetargetApplyPlan(m.clone()));
        }
        let manifest = cli
            .manifest
            .clone()
            .unwrap_or_else(|| default_manifest_path(now));
        return Ok(if cli.apply {
            Mode::RetargetApply(manifest)
        } else {
            Mode::RetargetDryRun(manifest)
        });
    }
    if cli.apply || cli.manifest.is_some() || cli.include_marked {
        return Err("--apply, --manifest and --include-marked require --retarget".into());
    }
    if let Some(p) = &cli.plan {
        return Ok(Mode::Plan(p.clone()));
    }
    if let Some(p) = &cli.apply_plan {
        return Ok(Mode::ApplyPlan(p.clone()));
    }
    if cli.dry_run {
        return Ok(Mode::Enumerate);
    }
    Ok(Mode::Run)
}

/// The `--as-agent` connection: the application login in DATABASE_URL as a
/// [`epigraph_db::ScopedPool`], and the acting agent's viewer resolved on it.
///
/// No maintenance DSN is read and no privilege is asserted: this path is
/// unprivileged on purpose. A mode that writes asks the database which group
/// its `decomposes_to` edges would record as their writer
/// ([`epigraph_cli::decompose::writer_group`], the very function the edge
/// trigger uses) and refuses when the answer is none, because those edges
/// would carry no owner. A read-only mode proceeds as whatever the agent can
/// see (for an agent with no group, public rows only).
async fn connect_as_agent(
    agent: uuid::Uuid,
    writes: bool,
) -> Result<(epigraph_db::ScopedPool, epigraph_db::visibility::Viewer), Box<dyn std::error::Error>>
{
    let url = std::env::var("DATABASE_URL")
        .map_err(|_| "DATABASE_URL not set; --as-agent runs on the application login in it")?;
    let guc_mode = epigraph_db::SessionGucMode::from_env(
        std::env::var("EPIGRAPH_SESSION_GUC_MODE")
            .unwrap_or_default()
            .as_str(),
    );
    let scoped = epigraph_db::ScopedPool::connect(&url, guc_mode).await?;
    if guc_mode == epigraph_db::SessionGucMode::Session {
        scoped.probe_session_gucs().await?;
    }
    let viewer = epigraph_db::visibility::Viewer::resolve(scoped.inner(), agent).await?;
    let groups = viewer.group_bind().map_or(0, <[uuid::Uuid]>::len);
    let writable = viewer.writable_groups().len();
    // Only a writing mode asks: the question opens a write transaction.
    let writer = if writes {
        Some(writer_group(&scoped, &viewer).await?)
    } else {
        None
    };
    let shown = match writer {
        None => "n/a (read-only mode)".to_string(),
        Some(None) => "none".to_string(),
        Some(Some(g)) => g.to_string(),
    };
    eprintln!(
        "connection: --as-agent {agent} on the application login (DATABASE_URL), through \
         row-level security; no maintenance DSN; groups={groups} writable={writable} \
         writer_group={shown}"
    );
    if writer == Some(None) {
        return Err(format!(
            "--as-agent {agent}: the agent has no writer group (epigraph_writer_group() is \
             NULL for it), so the decomposes_to edges this run writes would carry no owner. \
             Pass the agent the API token acts as (the service client's agent); it needs a \
             writable personal group of its own or of its operator."
        )
        .into());
    }
    Ok((scoped, viewer))
}

/// The `--as-agent` zero-visible refusal (see its call site).
fn zero_visible_refusal(agent: uuid::Uuid) -> String {
    format!(
        "--as-agent {agent}: this session sees no undecomposed claim at all, so the run would \
         read zero rows and exit 0. The login in DATABASE_URL reads through row-level \
         security: check that it is an application login with its table grants, and that the \
         claims it should decompose are public. Refusing to run."
    )
}

/// The `--as-agent` refusal for a population that may legitimately be empty
/// (`--priority conflict`): the session sees no claim at all.
fn no_claim_visible_refusal(agent: uuid::Uuid) -> String {
    format!(
        "--as-agent {agent}: this session sees no claim at all, so the run would read zero \
         rows and exit 0. The login in DATABASE_URL reads through row-level security: check \
         that it is an application login with its table grants. Refusing to run."
    )
}

/// Parse an `--ids-file`: one UUID per line, blank lines and `#` comments
/// ignored. A malformed line is an error naming the line, not a skip.
fn parse_ids_file(raw: &str) -> Result<Vec<uuid::Uuid>, String> {
    let mut out = Vec::new();
    for (n, line) in raw.lines().enumerate() {
        let t = line.split('#').next().unwrap_or("").trim();
        if t.is_empty() {
            continue;
        }
        out.push(
            uuid::Uuid::parse_str(t)
                .map_err(|e| format!("--ids-file line {}: {t:?} is not a UUID: {e}", n + 1))?,
        );
    }
    Ok(out)
}

/// Treat a set-but-empty env var as absent.
///
/// Shell templating can export an env var with an unresolved-to-empty value
/// (`EPIGRAPH_API=""`) rather than leaving it unset; `Option::or` alone does
/// NOT catch that case since `Some("")` is not `None`. An empty `api_base`
/// turns `format!("{api_base}/api/v1/claims")` into the relative path
/// "/api/v1/claims", which `reqwest` rejects with `RelativeUrlWithoutBase` —
/// the hardening for that hypothesis in backlog a422da87.
fn non_empty(value: Option<String>) -> Option<String> {
    value.filter(|s| !s.is_empty())
}

// API base precedence (`EPIGRAPH_API`, then `EPIGRAPH_API_URL`, then
// `http://127.0.0.1:8080`): one spelling, shared with the belief-mode check,
// so the API a retarget write checks is the API it writes to.
use epigraph_cli::belief_mode_check::resolve_api_base;

/// OAuth token endpoint precedence: explicit `EPIGRAPH_OAUTH_TOKEN_URL`
/// first (matches the epiclaw-host `container.rs` convention of constructing
/// it as `{api_url}/oauth/token` and exporting it directly), falling back to
/// `{api_base}/oauth/token` when that specific env var isn't set. Set-but-
/// empty is treated as absent, same as [`resolve_api_base`].
fn resolve_token_url(oauth_token_url: Option<String>, api_base: &str) -> String {
    non_empty(oauth_token_url)
        .unwrap_or_else(|| format!("{}/oauth/token", api_base.trim_end_matches('/')))
}

/// Env var naming the JSON fixture file consumed by `--provider fixture`.
const FIXTURE_PATH_ENV: &str = "DECOMPOSE_FIXTURE_PATH";

/// Resolve the `--provider` selector to a concrete client.
///
/// `epigraph` / `mock` / any registered name go through the kernel factory
/// unchanged. `fixture` is handled HERE rather than in `create_llm_client`
/// because `epigraph_interfaces::default_llm_provider` skips only the literal
/// name `"mock"`: any *registered* active provider is eligible for `--provider
/// epigraph` auto-detect when Anthropic credentials are absent, so registering
/// a fixture provider would make canned atoms silently writable in production.
/// Keeping it out of the registry means it is reachable only via this explicit
/// branch, and only when `DECOMPOSE_FIXTURE_PATH` is also set — two locks, both
/// opt-in.
///
/// Takes the already-read env value rather than reading it here so the guard is
/// a pure function, testable without mutating global process env.
fn resolve_llm_client(
    provider: &str,
    fixture_path: Option<String>,
) -> Result<Arc<dyn LlmProvider>, Box<dyn std::error::Error>> {
    if provider == "fixture" {
        let path = fixture_path.ok_or(
            "--provider fixture requires DECOMPOSE_FIXTURE_PATH=<file.json> (a JSON object \
             keyed by claim text)",
        )?;
        return Ok(Arc::new(FixtureLlmClient::from_path(
            std::path::Path::new(&path),
        )?));
    }
    Ok(epigraph_cli::enrichment::llm_client::create_llm_client(
        provider,
    )?)
}

/// `None` unless both service-client credential env values are present AND
/// non-empty. Split out from `mint_service_token` as a pure guard so the
/// "don't even attempt a mint without both creds" behavior is unit-testable
/// without an HTTP mock. Set-but-empty is treated as absent (see
/// [`non_empty`]) so `EPIGRAPH_SERVICE_CLIENT_ID=""` fails fast via
/// [`AuthError::NoCredentials`] instead of attempting (and failing) a mint
/// with an empty client_id.
fn resolve_service_credentials(
    client_id: Option<String>,
    client_secret: Option<String>,
) -> Option<(String, String)> {
    Some((non_empty(client_id)?, non_empty(client_secret)?))
}

/// The decided authentication strategy for the claims-POST calls: either
/// reuse a caller-supplied token verbatim, or mint a fresh one from
/// service-client credentials. Never a bare empty string —
/// [`resolve_auth_plan`] only returns this once at least one usable auth
/// path exists.
#[derive(Debug, PartialEq, Eq)]
enum AuthPlan {
    UseToken(String),
    Mint {
        client_id: String,
        client_secret: String,
    },
}

/// Fail-fast reason: neither an explicit token nor a client-credentials pair
/// was available.
///
/// This binary previously chose the opposite: it logged "proceeding with an
/// EMPTY bearer token, every API write below will 401" and ran anyway. That
/// fail-open is what gh-375 tracks — the LLM calls (which cost money and
/// time) all completed and only then did every write 401, so a whole
/// scheduled run was burned to produce nothing.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
enum AuthError {
    #[error(
        "no auth material available: EPIGRAPH_TOKEN is unset/empty and \
         EPIGRAPH_SERVICE_CLIENT_ID/EPIGRAPH_SERVICE_SECRET are not both set; \
         cannot authenticate claims-POST calls"
    )]
    NoCredentials,
}

/// Decide how to authenticate: reuse an already-set non-empty token (never
/// force a mint over a caller-supplied token), otherwise plan a mint from
/// service-client credentials, otherwise fail fast rather than proceeding
/// with an empty bearer token.
fn resolve_auth_plan(
    env_token: Option<String>,
    credentials: Option<(String, String)>,
) -> Result<AuthPlan, AuthError> {
    if let Some(token) = non_empty(env_token) {
        return Ok(AuthPlan::UseToken(token));
    }
    match credentials {
        Some((client_id, client_secret)) => Ok(AuthPlan::Mint {
            client_id,
            client_secret,
        }),
        None => Err(AuthError::NoCredentials),
    }
}

/// Why a mint attempt failed. Distinguishes "server reachable but rejected
/// us" from "response body wasn't a usable token" so callers (and tests) get
/// a clear signal instead of a silently-empty string.
#[derive(Debug, thiserror::Error)]
enum MintError {
    #[error("token endpoint request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("token endpoint returned HTTP {0}")]
    HttpStatus(reqwest::StatusCode),
    #[error("token endpoint response was not a usable token: {0}")]
    MalformedResponse(String),
}

/// Mint a bearer token from service-client credentials via the OAuth
/// client_credentials flow. Pure aside from the network call: takes the
/// already-resolved endpoint/credentials/client rather than reading env or
/// constructing its own `reqwest::Client`, so it's unit-testable against a
/// mock HTTP server (wiremock) without touching process env.
///
/// `scope` is what the calling mode will spend: see [`Mode::mint_scope`].
async fn mint_service_token(
    client_id: &str,
    client_secret: &str,
    token_url: &str,
    scope: &str,
    http: &reqwest::Client,
) -> Result<String, MintError> {
    let resp = http
        .post(token_url)
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("scope", scope),
        ])
        .send()
        .await?;
    let status = resp.status();
    if !status.is_success() {
        return Err(MintError::HttpStatus(status));
    }
    let json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| MintError::MalformedResponse(e.to_string()))?;
    json.get("access_token")
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .ok_or_else(|| {
            MintError::MalformedResponse(format!(
                "no string 'access_token' field in response body: {json}"
            ))
        })
}

/// Whether a run under `provider` can reach the claims-POST path at all.
///
/// `mock` resolves to [`epigraph_cli::enrichment::llm_client::MockLlmClient`]
/// built with NO pre-configured responses, which returns an empty JSON array
/// for every `complete_json` call; `parse_batch_response` then yields zero
/// decompositions and the submit closure is never invoked. So a `--provider
/// mock` run provably performs no authenticated request, and the module doc
/// promises exactly that ("a dry compile/smoke without credentials").
/// Requiring auth for it would break that documented smoke path.
///
/// `fixture` is deliberately NOT exempt: its whole purpose is to exercise
/// the atom/edge WRITE path deterministically, so it does POST and does need
/// a token.
fn provider_writes_to_api(provider: &str) -> bool {
    provider != "mock"
}

/// Resolve the bearer token for API writes, or fail fast (gh-375). Called
/// BEFORE any LLM work in every writing mode.
async fn resolve_token(
    api_base: &str,
    scope: &str,
    http: &reqwest::Client,
) -> Result<String, Box<dyn std::error::Error>> {
    // EPIGRAPH_TOKEN if present (non-empty) and used as-is; otherwise mint a
    // fresh bearer token from service-client credentials via
    // client_credentials, so container deployments work without a token-mint
    // preamble in the schedule. If NEITHER is available, fail fast HERE —
    // before the LLM batches run — rather than proceeding with an empty
    // bearer token that only surfaces as a 401 after every batch has already
    // been paid for (gh-375).
    //
    // Diagnostic-only logging: never the token value itself, only its
    // provenance and length (distinguishes "empty" from "present but wrong"
    // without leaking the credential — backlog a422da87's reported
    // non-determinism needs exactly this to disambiguate an auth failure from
    // a URL-builder failure across repeated scheduled runs).
    let plan = resolve_auth_plan(
        std::env::var("EPIGRAPH_TOKEN").ok(),
        resolve_service_credentials(
            std::env::var("EPIGRAPH_SERVICE_CLIENT_ID").ok(),
            std::env::var("EPIGRAPH_SERVICE_SECRET").ok(),
        ),
    )?;
    Ok(match plan {
        AuthPlan::UseToken(t) => {
            eprintln!("token: using EPIGRAPH_TOKEN from env (len={})", t.len());
            t
        }
        AuthPlan::Mint {
            client_id,
            client_secret,
        } => {
            let token_url =
                resolve_token_url(std::env::var("EPIGRAPH_OAUTH_TOKEN_URL").ok(), api_base);
            eprintln!("token: minting via client_credentials at {token_url} (scope={scope})");
            let minted =
                mint_service_token(&client_id, &client_secret, &token_url, scope, http).await?;
            eprintln!(
                "token: minted via client_credentials (len={})",
                minted.len()
            );
            minted
        }
    })
}

/// Canonical atom create via `POST /api/v1/claims`: author-key signing, embed
/// on write, and one derivation evidence row naming `parent` (no DS mass; see
/// the module doc's evidence policy).
///
/// The body is [`atom_create_body`] (pure, unit-tested in
/// `tests/decompose_atom_create_body.rs`). `if_not_exists=true`: when a prior
/// run already decomposed the same parent, identical atom text produces the
/// same content_hash. Without this flag the API returns 409; with it,
/// create_or_get returns the existing claim ID so persist_decomposition can
/// re-wire edges idempotently.
async fn submit_atom(
    http: reqwest::Client,
    api_base: String,
    token: String,
    atom_text: String,
    generality: i64,
    parent: AtomParent,
) -> Result<uuid::Uuid, Box<dyn std::error::Error>> {
    // Diagnostic-only (backlog a422da87): build+log the URL BEFORE sending, so
    // a RelativeUrlWithoutBase-style construction bug is visible even if the
    // request itself never reaches the wire.
    let url = format!("{api_base}/api/v1/claims");
    eprintln!("POST {url}");
    let resp = match http
        .post(&url)
        .bearer_auth(&token)
        .json(&atom_create_body(&atom_text, generality, parent))
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!(
                "POST {url} FAILED before a response was received: \
                 is_builder={} is_request={} is_connect={} is_timeout={} \
                 detail={e}",
                e.is_builder(),
                e.is_request(),
                e.is_connect(),
                e.is_timeout()
            );
            return Err(e.into());
        }
    };
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        eprintln!("POST {url} -> HTTP {status}, body={body}");
        return Err(format!("POST {url} -> HTTP {status}: {body}").into());
    }
    let v: serde_json::Value = resp.json().await?;
    let id = v
        .get("id")
        .or_else(|| v.get("claim_id"))
        .and_then(|x| x.as_str())
        .ok_or("API create returned no claim id")?;
    Ok(uuid::Uuid::parse_str(id)?)
}

/// Print a plan (proposed atoms per claim) to stdout.
fn print_plan(plans: &[epigraph_cli::decompose::PlannedDecomposition]) {
    for p in plans {
        let note = if p.atoms.len() <= 1 {
            " (already atomic; would be skipped)"
        } else {
            ""
        };
        println!("{}\t{} atoms{note}", p.claim_id, p.atoms.len());
        for (a, g) in p.atoms.iter().zip(p.generality.iter()) {
            println!("    [gen {g}] {a}");
        }
    }
}

/// Refuse to overwrite a manifest: plan lines accumulating from two runs in
/// one file would make `--apply-plan` apply both.
fn fresh_manifest(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if path.exists() {
        return Err(format!(
            "manifest {} already exists; pass a new --manifest path",
            path.display()
        )
        .into());
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let mode = resolve_mode(&cli, chrono::Utc::now())?;
    // A retarget write is a wave run: before the database, the ledger and the
    // token mint, its belief modes must match the API's (SPEC §10.2).
    if mode.is_retarget_write() {
        epigraph_cli::belief_mode_check::enforce_or_exit(
            "decompose_claims --retarget",
            epigraph_cli::belief_mode_check::RunIntent::Writes,
            cli.allow_mode_skew,
        )
        .await;
    }
    // Before the DB, auth and any LLM call: a ledger path a recording mode
    // cannot write must fail now, not after the verdicts are paid for.
    let mut ledger = open_singleton_ledger(cli.singleton_ledger.as_deref(), &mode)?;

    // Built AFTER clap has parsed: an argv error must be reported as an argv
    // error, not as a connection failure.
    //
    // Two paths. Without --as-agent: the maintenance bin it always was — the
    // operator is the authority and the work is corpus-wide (see
    // `epigraph_cli::MaintenancePool` for why that earns a bypass and a
    // request handler does not), and the session is held for the whole run
    // because the lease attests to THAT connection. With --as-agent: the
    // ordinary application login, no bypass, every statement stamped for the
    // acting agent (see `DecomposeDb`).
    let maint;
    let session;
    let scoped;
    let acting;
    let (db, viewer, maint_pool): (
        &dyn DecomposeDb,
        &epigraph_db::visibility::Viewer,
        Option<&sqlx::PgPool>,
    ) = match cli.as_agent {
        None => {
            maint = epigraph_cli::MaintenancePool::connect("decompose_claims").await?;
            session = maint
                .viewer(epigraph_db::visibility::SystemReason::TenancyBackfill)
                .await?;
            (
                maint.pool() as &dyn DecomposeDb,
                session.viewer(),
                Some(maint.pool()),
            )
        }
        Some(agent) => {
            let (pool, viewer) = connect_as_agent(agent, mode.writes(&cli.provider)).await?;
            scoped = pool;
            acting = viewer;
            (&scoped as &dyn DecomposeDb, &acting, None)
        }
    };

    // API base: EPIGRAPH_API takes precedence; EPIGRAPH_API_URL is the
    // container-standard name exposed by epiclaw-host. If neither is set we
    // fall back to localhost.
    let api_base = resolve_api_base(
        std::env::var("EPIGRAPH_API").ok(),
        std::env::var("EPIGRAPH_API_URL").ok(),
    );
    let http = reqwest::Client::new();

    // Auth FIRST in every writing mode, before any LLM call (gh-375). Skipped
    // entirely for a mode that cannot reach the write path; see
    // `Mode::writes` / `provider_writes_to_api`.
    let token = if mode.writes(&cli.provider) {
        eprintln!("api_base={api_base}");
        resolve_token(&api_base, mode.mint_scope(), &http).await?
    } else {
        eprintln!("token: not resolved — this mode performs no API write");
        String::new()
    };

    match mode {
        Mode::RetargetDryRun(manifest) | Mode::RetargetApply(manifest) => {
            let apply = cli.apply;
            fresh_manifest(&manifest)?;
            let opts = RetargetOptions {
                include_marked: cli.include_marked,
                limit: usize::try_from(cli.limit.max(1)).unwrap_or(1),
                batch_size: cli.batch_size,
                apply,
            };
            let llm = resolve_llm_client(&cli.provider, std::env::var(FIXTURE_PATH_ENV).ok())?;
            // The dry run is handed NO API client at all, so it cannot write
            // even through a bug in the `apply` gate below it.
            let api = apply.then(|| EdgeApiClient {
                http,
                api_base,
                token,
            });
            let pool = maint_pool.ok_or("--retarget needs the maintenance path")?;
            let run =
                run_retarget(pool, viewer, llm.as_ref(), api.as_ref(), &manifest, opts).await?;
            eprintln!(
                "retarget: {} conflict edges on decomposed parents{}",
                run.plan.len(),
                if cli.include_marked {
                    " (including already-marked)"
                } else {
                    " (already-marked edges skipped)"
                }
            );
            if run.plan.is_empty() {
                return Ok(());
            }
            print_retarget_plan(&run.plan);
            eprintln!("manifest: {}", manifest.display());
            if !apply {
                eprintln!(
                    "dry run: nothing written. Re-run with --apply, or --apply-plan {}",
                    manifest.display()
                );
                return Ok(());
            }
            print_applied(&run.applied);
        }
        Mode::RetargetApplyPlan(manifest) => {
            let plan = read_retarget_manifest(&manifest)?;
            eprintln!(
                "retarget: applying {} plan entries from {} (no LLM call)",
                plan.len(),
                manifest.display()
            );
            let api = EdgeApiClient {
                http,
                api_base,
                token,
            };
            // Each applied line is appended to the manifest as its entry
            // finishes, not at the end.
            let pool = maint_pool.ok_or("--retarget needs the maintenance path")?;
            let applied = apply_retarget(pool, viewer, &api, &plan, Some(&manifest)).await?;
            print_applied(&applied);
        }
        Mode::ApplyPlan(path) => {
            let planned = read_plan_jsonl(&path)?;
            eprintln!(
                "apply-plan: {} plan lines from {} (no LLM call)",
                planned.len(),
                path.display()
            );
            let (ok, drifted) = verify_plan(db, viewer, planned).await?;
            for (p, why) in &drifted {
                eprintln!("REFUSED {}: {why:?}", p.claim_id);
            }
            let embedder = epigraph_cli::embedding_service();
            let submit = move |t: String, g: i64, p: AtomParent| {
                submit_atom(http.clone(), api_base.clone(), token.clone(), t, g, p)
            };
            let totals =
                persist_planned(db, viewer, &ok, embedder, ledger.as_mut(), &submit).await?;
            for (id, why) in &totals.failed {
                eprintln!("FAILED {id}: {why}");
            }
            eprintln!(
                "apply-plan complete: {} applied, {} failed (still undecomposed; re-run this \
                 plan to retry them), {} refused, {} atoms, {} decomposes_to edges",
                ok.len() - totals.failed.len(),
                totals.failed.len(),
                drifted.len(),
                totals.atoms,
                totals.edges
            );
        }
        Mode::Enumerate | Mode::Plan(_) | Mode::Run => {
            let filters = EligibilityFilters {
                skip_backlog: !cli.include_backlog,
                skip_short: !cli.include_short,
            };
            let ids = match &cli.ids_file {
                Some(p) => Some(parse_ids_file(&std::fs::read_to_string(p)?)?),
                None => None,
            };
            let limit = usize::try_from(cli.limit.max(1)).unwrap_or(1);
            let judged_atomic = if cli.include_judged_atomic {
                None
            } else {
                ledger.as_ref()
            };
            // `--count-eligible` reads on past `--limit`; the first `limit`
            // chosen are the same parents, in the same order, either way.
            let scan_limit = if cli.count_eligible {
                limit.max(cli.max_scan)
            } else {
                limit
            };
            let mut sel = select_candidates(
                db,
                viewer,
                cli.priority.into(),
                ids.as_deref(),
                filters,
                judged_atomic,
                scan_limit,
                cli.max_scan,
            )
            .await?;
            let eligible = cli
                .count_eligible
                .then(|| keep_within_limit(&mut sel, limit, scan_limit));
            report_selection(&sel, ids.is_some(), cli.priority, eligible);
            if let Some(agent) = cli.as_agent {
                // What the maintenance path's startup refusal protected: a
                // job that cannot see the corpus must not read zero rows and
                // exit 0. Keyed on rows READ, before any filter: a visible
                // population with nothing eligible (`chosen=0`) is the steady
                // state. Not for --ids-file, which names every id it skips.
                if ids.is_none() && sel.scanned == 0 {
                    match cli.priority {
                        // The population is every undecomposed claim the
                        // session can see; LLM-judged and short parents stay
                        // in it, so on a live corpus it is never empty.
                        PriorityArg::Oldest | PriorityArg::Recent => {
                            return Err(zero_visible_refusal(agent).into());
                        }
                        // Only the targets of a live conflict edge: empty is a
                        // legitimate answer. Fail only if the session sees no
                        // claim at all.
                        PriorityArg::Conflict => {
                            let visible = visible_claim_count(db, viewer).await?;
                            if visible == 0 {
                                return Err(no_claim_visible_refusal(agent).into());
                            }
                            eprintln!(
                                "selection: no undecomposed conflict target among the \
                                 {visible} claims this session sees; nothing to do"
                            );
                        }
                    }
                }
            }
            if cli.priority == PriorityArg::Conflict {
                match maint_pool {
                    Some(pool) => report_decomposed_conflict_parents(pool, viewer).await?,
                    None => eprintln!(
                        "conflict: decomposed parents that are still conflict targets are \
                         reported only on the maintenance path (they go to --retarget)"
                    ),
                }
            }
            let claims: Vec<BatchClaim> = sel
                .chosen
                .iter()
                .map(|c| BatchClaim {
                    claim_id: c.id,
                    agent_id: c.agent_id,
                    content: c.content.clone(),
                })
                .collect();
            if matches!(mode, Mode::Enumerate) || claims.is_empty() {
                for c in &claims {
                    println!("{}\t{}", c.claim_id, c.content);
                }
                return Ok(());
            }
            // Refuse an existing plan path BEFORE any LLM call, not after
            // (write_plan_jsonl refuses it too, but only once the calls are
            // spent).
            if let Mode::Plan(path) = &mode {
                if path.exists() {
                    return Err(format!(
                        "plan file {} already exists; pass a new --plan path",
                        path.display()
                    )
                    .into());
                }
            }
            // Prepaid Claude path. create_llm_client("epigraph") returns the
            // first active provider (Anthropic-from-env, OAuth-preferred);
            // "mock" for smoke; "fixture" for a deterministic, credential-free
            // write-path exercise.
            let llm = resolve_llm_client(&cli.provider, std::env::var(FIXTURE_PATH_ENV).ok())?;
            if let Mode::Plan(path) = &mode {
                let (plans, gaps) =
                    plan_decomposition_batches_with_gaps(&claims, llm.as_ref(), cli.batch_size)
                        .await;
                write_plan_jsonl(path, &plans)?;
                print_plan(&plans);
                let singletons: Vec<uuid::Uuid> = plans
                    .iter()
                    .filter(|p| p.atoms.len() <= 1)
                    .map(|p| p.claim_id)
                    .collect();
                report_unplanned(&gaps, &singletons);
                eprintln!(
                    "plan: {} of {} claims answered; written to {} — nothing persisted. \
                     Apply with --apply-plan {}",
                    plans.len(),
                    claims.len(),
                    path.display(),
                    path.display()
                );
                return Ok(());
            }
            let embedder = epigraph_cli::embedding_service();
            let totals = run_decomposition_batches(
                db,
                viewer,
                &claims,
                llm.as_ref(),
                cli.batch_size,
                embedder,
                ledger.as_mut(),
                move |t, g, p| submit_atom(http.clone(), api_base.clone(), token.clone(), t, g, p),
            )
            .await?;
            report_unplanned(&totals.gaps, &totals.singletons);
            eprintln!(
                "decompose complete: {} atoms, {} decomposes_to edges",
                totals.atoms, totals.edges
            );
        }
    }
    Ok(())
}

/// Load `--singleton-ledger`. A mode that records verdicts (a normal run,
/// `--apply-plan`) opens it for append, creating it if missing; every other
/// mode only reads it and creates nothing.
fn open_singleton_ledger(
    path: Option<&Path>,
    mode: &Mode,
) -> Result<Option<SingletonLedger>, Box<dyn std::error::Error>> {
    let Some(path) = path else {
        return Ok(None);
    };
    let ledger = if matches!(mode, Mode::Run | Mode::ApplyPlan(_)) {
        SingletonLedger::open_for_append(path)?
    } else {
        SingletonLedger::load(path)?
    };
    eprintln!(
        "singleton ledger: {} judged-atomic verdicts in {}",
        ledger.len(),
        ledger.path().display()
    );
    Ok(Some(ledger))
}

/// Name every chosen claim that was sent to the LLM and produced nothing to
/// write, one line each, so no claim — above all one named in `--ids-file` —
/// disappears between selection and the totals.
fn report_unplanned(gaps: &PlanGaps, singletons: &[uuid::Uuid]) {
    for (id, why) in &gaps.llm_error {
        eprintln!("LLM-ERROR {id}: the batch's LLM call failed ({why}); not decomposed");
    }
    for id in &gaps.no_answer {
        eprintln!("NO-ANSWER {id}: the model returned no usable answer; not decomposed");
    }
    for id in singletons {
        eprintln!("SINGLETON {id}: the model returned one atom (already atomic); not decomposed");
    }
}

/// How many eligible parents a `--count-eligible` scan saw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EligibleCount {
    seen: usize,
    /// The scan stopped (at `--max-scan`) before the population ran out, so
    /// `seen` is a lower bound.
    at_least: bool,
}

/// `--count-eligible`: `sel` was filled up to `scan_limit`. Keep the first
/// `limit` chosen — the parents a plain run would process — and return the
/// count of eligible parents the scan saw.
fn keep_within_limit(
    sel: &mut epigraph_cli::decompose::Selection,
    limit: usize,
    scan_limit: usize,
) -> EligibleCount {
    let seen = sel.chosen.len();
    sel.chosen.truncate(limit);
    // Filling `scan_limit` also stops the scan, without setting `scan_capped`.
    let at_least = sel.scan_capped || seen >= scan_limit;
    // The capped warning is about not reaching `--limit`; the count reports
    // its own bound.
    sel.scan_capped = sel.scan_capped && sel.chosen.len() < limit;
    EligibleCount { seen, at_least }
}

/// Summarize what selection chose and passed over. Every explicit
/// `--ids-file` id that is not decomposed is printed WITH its reason.
fn report_selection(
    sel: &epigraph_cli::decompose::Selection,
    explicit: bool,
    priority: PriorityArg,
    eligible: Option<EligibleCount>,
) {
    use epigraph_cli::decompose::Ineligible;
    let count = |f: fn(&Ineligible) -> bool| sel.skipped.iter().filter(|(_, w)| f(w)).count();
    // Each reason counted by its own variant: a remainder would silently fold
    // a new reason into another's column.
    let backlog = count(|w| matches!(w, Ineligible::Backlog));
    let not_public = count(|w| matches!(w, Ineligible::NotPublic { .. }));
    let atomic = count(|w| matches!(w, Ineligible::LooksAtomic { .. }));
    let judged = count(|w| matches!(w, Ineligible::JudgedAtomic));
    eprintln!(
        "selection: priority={priority:?}{} scanned={} chosen={} skipped_backlog={backlog} \
         skipped_looks_atomic={atomic} skipped_judged_atomic={judged} \
         skipped_not_public={not_public}",
        if explicit { " (ids-file order)" } else { "" },
        sel.scanned,
        sel.chosen.len(),
    );
    if let Some(e) = eligible {
        eprintln!(
            "selection: eligible={}{} (parents that pass every filter, in {} rows read; the \
             skipped_* counts cover the same rows)",
            if e.at_least { ">=" } else { "" },
            e.seen,
            sel.scanned
        );
    }
    if sel.scan_capped {
        eprintln!(
            "selection: stopped at --max-scan={} rows before reaching --limit; raise --max-scan \
             or change --priority",
            sel.scanned
        );
    }
    if explicit {
        for (id, why) in &sel.skipped {
            eprintln!("SKIP {id} (named in --ids-file): {why}");
        }
        for id in &sel.not_undecomposed {
            eprintln!(
                "SKIP {id} (named in --ids-file): not in the undecomposed population \
                 (absent, retired, telemetry, already decomposed, or an atom)"
            );
        }
        for id in &sel.over_limit {
            eprintln!(
                "SKIP {id} (named in --ids-file): eligible but past --limit; raise --limit \
                 or re-run with the remaining ids"
            );
        }
    }
}

/// `--priority conflict`'s second half: decomposed parents that are STILL
/// conflict targets. They are not sent to the LLM again; they are reported
/// for `--retarget`.
async fn report_decomposed_conflict_parents(
    pool: &sqlx::PgPool,
    viewer: &epigraph_db::visibility::Viewer,
) -> Result<(), Box<dyn std::error::Error>> {
    let items = load_retarget_items(pool, viewer, false, 10_000).await?;
    let mut by_parent: std::collections::BTreeMap<uuid::Uuid, usize> =
        std::collections::BTreeMap::new();
    for i in &items {
        *by_parent.entry(i.parent_id).or_default() += 1;
    }
    let mut ranked: Vec<(uuid::Uuid, usize)> = by_parent.into_iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    eprintln!(
        "conflict: {} decomposed parents still carry {} unmarked conflict edges — \
         route to --retarget, not the LLM",
        ranked.len(),
        items.len()
    );
    for (parent, n) in ranked {
        eprintln!("RETARGET-CANDIDATE {parent}\t{n} conflict edges");
    }
    Ok(())
}

fn print_retarget_plan(plan: &[epigraph_cli::retarget::RetargetPlanEntry]) {
    let mut left: Vec<&epigraph_cli::retarget::RetargetPlanEntry> = Vec::new();
    for e in plan {
        if e.verdict == verdict::ATOMS {
            println!(
                "{}\t{} {} -> parent {} => atoms {:?}",
                e.edge_id, e.source_id, e.relationship, e.parent_id, e.chosen_atom_ids
            );
        } else {
            left.push(e);
        }
    }
    for e in &left {
        println!(
            "{}\tLEFT ON PARENT ({}{}) {} {} -> parent {}",
            e.edge_id,
            e.verdict,
            e.reason
                .as_deref()
                .map(|r| format!(": {r}"))
                .unwrap_or_default(),
            e.source_id,
            e.relationship,
            e.parent_id
        );
    }
    let held = plan
        .iter()
        .filter(|e| e.verdict == verdict::ATOMS)
        .filter_map(|e| epigraph_cli::retarget::hold_reason(&e.relationship))
        .count();
    if held > 0 {
        eprintln!(
            "note: {held} of the atom mappings above are held retargets, which --apply \
             reports and does not write; see epigraph_cli::retarget::HELD_RELATIONSHIPS"
        );
    }
    let count = |v: &str| plan.iter().filter(|e| e.verdict == v).count();
    eprintln!(
        "retarget plan: {} edges — atoms={} whole={} unclear={} malformed={} no_answer={} llm_error={}",
        plan.len(),
        count(verdict::ATOMS),
        count(verdict::WHOLE),
        count(verdict::UNCLEAR),
        count(verdict::MALFORMED),
        count(verdict::NO_ANSWER),
        count(verdict::LLM_ERROR),
    );
}
fn print_applied(applied: &[epigraph_cli::retarget::AppliedEntry]) {
    let mut created = 0;
    let mut existing = 0;
    let mut blocked = 0;
    let mut unwired = 0;
    let mut reasserted = 0;
    let mut marked = 0;
    let held = applied.iter().filter(|a| a.held).count();
    for a in applied {
        created += a.created_edge_ids.len();
        existing += a.existing_edge_ids.len();
        blocked += a.blocked_by_retired_edge.len();
        reasserted += a.reasserted_edge_ids.len();
        unwired += a
            .created_edge_ids
            .iter()
            .chain(a.existing_edge_ids.iter())
            .filter(|id| !a.ds_wired_edge_ids.contains(id))
            .count();
        if a.parent_marked {
            marked += 1;
        }
        for err in &a.errors {
            eprintln!("ERROR edge {}: {err}", a.edge_id);
        }
        for atom in &a.blocked_by_retired_edge {
            eprintln!(
                "BLOCKED edge {}: a retired edge to atom {atom} exists; not resurrected",
                a.edge_id
            );
        }
    }
    eprintln!(
        "retarget apply: {} entries — created={created} existing={existing} \
         reasserted={reasserted} blocked_by_retired={blocked} held={held} \
         parents_marked={marked} atom_edges_not_ds_wired={unwired}",
        applied.len()
    );
    if unwired > 0 {
        eprintln!(
            "note: {unwired} atom edges carry no DS BBA yet. Either the source claim has no \
             belief interval (SourceFactorless), or the API cannot write mass_functions — e.g. it \
             runs as epigraph_app while the edge DS path (routes/edges.rs \
             trigger_edge_ds_recomputation) is still unstamped; the API boot log's RLS-posture \
             line says which role it runs as. Each is recorded in the parent edge's \
             `retarget_unwired`, so the next --retarget run resumes that edge (no LLM call) and \
             re-asserts it until it wires."
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{
        mint_service_token, provider_writes_to_api, resolve_api_base, resolve_auth_plan,
        resolve_llm_client, resolve_service_credentials, resolve_token_url, AuthError, AuthPlan,
        MintError,
    };
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // --- mode resolution ---

    use super::{parse_ids_file, resolve_mode, Cli, Mode};
    use clap::Parser;
    use std::path::PathBuf;

    fn mode_of(args: &[&str]) -> Result<Mode, String> {
        let mut argv = vec!["decompose_claims"];
        argv.extend_from_slice(args);
        let cli = Cli::try_parse_from(argv).map_err(|e| e.to_string())?;
        let now = chrono::DateTime::parse_from_rfc3339("2026-09-24T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        resolve_mode(&cli, now)
    }

    /// `--as-agent` accepts every decomposition mode and refuses every
    /// `--retarget` mode, which stays on the maintenance path.
    #[test]
    fn as_agent_takes_the_decomposition_modes_and_refuses_retarget() {
        let a = "5f1c2d3e-0000-4000-8000-000000000001";
        assert_eq!(mode_of(&["--as-agent", a]).unwrap(), Mode::Run);
        assert_eq!(
            mode_of(&["--as-agent", a, "--dry-run"]).unwrap(),
            Mode::Enumerate
        );
        assert!(matches!(
            mode_of(&["--as-agent", a, "--apply-plan", "p.jsonl"]).unwrap(),
            Mode::ApplyPlan(_)
        ));
        for retarget in [
            &["--retarget"][..],
            &["--retarget", "--apply"][..],
            &["--retarget", "--apply-plan", "m.jsonl"][..],
        ] {
            let mut args = vec!["--as-agent", a];
            args.extend_from_slice(retarget);
            let err = mode_of(&args).unwrap_err();
            assert!(err.contains("--as-agent"), "{retarget:?}: {err}");
        }
        assert!(mode_of(&["--as-agent", "not-a-uuid"]).is_err());
    }

    /// No flags = the historical write run, `oldest` order.
    #[test]
    fn no_flags_is_a_normal_run_in_oldest_order() {
        assert_eq!(mode_of(&[]).unwrap(), Mode::Run);
        let cli = Cli::try_parse_from(["decompose_claims"]).unwrap();
        assert_eq!(cli.priority, super::PriorityArg::Oldest);
        assert!(
            !cli.include_backlog && !cli.include_short,
            "filters default ON"
        );
    }

    /// `--count-eligible` keeps exactly the parents a plain run chooses (the
    /// first `--limit`, in order) and reports how many eligible parents the
    /// scan saw, as a lower bound when the scan was cut off. It counts the
    /// paged population only.
    #[test]
    fn count_eligible_keeps_the_plain_runs_choice_and_bounds_the_count() {
        use epigraph_db::repos::decomposition_priority::DecomposeCandidate;
        let cand = |n: u128| DecomposeCandidate {
            id: uuid::Uuid::from_u128(n),
            agent_id: uuid::Uuid::from_u128(0),
            content: format!("Parent {n}. Second sentence."),
            content_hash: vec![],
            labels: vec![],
            created_at: chrono::Utc::now(),
            visibility: "public".into(),
            conflict_edges: 0,
            newest_conflict_at: None,
        };
        let sel_of = |n: u128, capped: bool| epigraph_cli::decompose::Selection {
            chosen: (1..=n).map(cand).collect(),
            scanned: 9_000,
            scan_capped: capped,
            ..Default::default()
        };

        // Population exhausted: an exact count, and the first `limit` kept.
        let mut sel = sel_of(5, false);
        let e = super::keep_within_limit(&mut sel, 2, 20_000);
        assert_eq!(
            e,
            super::EligibleCount {
                seen: 5,
                at_least: false
            }
        );
        assert_eq!(
            sel.chosen.iter().map(|c| c.id).collect::<Vec<_>>(),
            vec![uuid::Uuid::from_u128(1), uuid::Uuid::from_u128(2)]
        );
        assert!(!sel.scan_capped);

        // --max-scan stopped the scan: a lower bound, and the "did not reach
        // --limit" warning is withdrawn once --limit is met.
        let mut sel = sel_of(5, true);
        let e = super::keep_within_limit(&mut sel, 2, 20_000);
        assert!(e.at_least && e.seen == 5, "{e:?}");
        assert!(!sel.scan_capped);

        // Filling the scan limit also stops the scan, without `scan_capped`.
        let mut sel = sel_of(4, false);
        let e = super::keep_within_limit(&mut sel, 2, 4);
        assert!(e.at_least, "{e:?}");

        // Fewer eligible than --limit and capped: the warning stays.
        let mut sel = sel_of(1, true);
        let e = super::keep_within_limit(&mut sel, 2, 20_000);
        assert!(e.at_least && sel.scan_capped, "{e:?}");

        for bad in [
            &["--count-eligible", "--ids-file", "ids.txt"][..],
            &["--count-eligible", "--apply-plan", "p.jsonl"][..],
            &["--count-eligible", "--retarget"][..],
        ] {
            let err = mode_of(bad).unwrap_err();
            assert!(err.contains("--count-eligible"), "{bad:?}: {err}");
        }
        assert_eq!(
            mode_of(&["--dry-run", "--count-eligible"]).unwrap(),
            Mode::Enumerate
        );
    }

    /// `--singleton-ledger` is a decomposition flag: it composes with every
    /// decomposition mode, `--include-judged-atomic` is meaningless without
    /// it, and `--retarget` (which makes no decomposition verdict) refuses it.
    /// A recording mode opens the file for append; the read-only modes do not
    /// create it.
    #[test]
    fn singleton_ledger_flags_compose_only_with_decomposition_modes() {
        let ledger = std::env::temp_dir().join(format!("ledger-{}.jsonl", uuid::Uuid::new_v4()));
        let l = ledger.to_str().unwrap();
        assert_eq!(
            mode_of(&["--priority", "recent", "--singleton-ledger", l]).unwrap(),
            Mode::Run
        );
        assert_eq!(
            mode_of(&["--apply-plan", "p.jsonl", "--singleton-ledger", l]).unwrap(),
            Mode::ApplyPlan(PathBuf::from("p.jsonl"))
        );
        let err = mode_of(&["--include-judged-atomic"]).unwrap_err();
        assert!(err.contains("--singleton-ledger"), "{err}");
        let err = mode_of(&["--retarget", "--singleton-ledger", l]).unwrap_err();
        assert!(err.contains("--retarget"), "{err}");

        let r = super::open_singleton_ledger(Some(&ledger), &Mode::Enumerate).unwrap();
        assert!(r.is_some_and(|l| l.is_empty()));
        assert!(!ledger.exists(), "--dry-run creates no ledger file");
        let r = super::open_singleton_ledger(Some(&ledger), &Mode::Plan("p".into())).unwrap();
        assert!(r.is_some());
        assert!(!ledger.exists(), "--plan creates no ledger file");
        super::open_singleton_ledger(Some(&ledger), &Mode::Run).unwrap();
        assert!(
            ledger.exists(),
            "a recording run proves the path writable before any LLM call"
        );
        std::fs::remove_file(&ledger).ok();
        assert!(super::open_singleton_ledger(None, &Mode::Run)
            .unwrap()
            .is_none());
    }

    /// `--retarget` is a DRY RUN unless `--apply` is given, and neither dry
    /// mode resolves API auth.
    #[test]
    fn retarget_defaults_to_dry_run_and_only_apply_writes() {
        let dry = mode_of(&["--retarget"]).unwrap();
        assert_eq!(
            dry,
            Mode::RetargetDryRun(PathBuf::from("retarget-manifest-20260924T120000Z.jsonl"))
        );
        assert!(!dry.writes("epigraph"), "a dry run must not need auth");
        let apply = mode_of(&["--retarget", "--apply", "--manifest", "m.jsonl"]).unwrap();
        assert_eq!(apply, Mode::RetargetApply(PathBuf::from("m.jsonl")));
        assert!(apply.writes("mock"), "apply writes regardless of provider");
        assert_eq!(
            mode_of(&["--retarget", "--apply-plan", "m.jsonl"]).unwrap(),
            Mode::RetargetApplyPlan(PathBuf::from("m.jsonl"))
        );
    }

    /// `--plan` needs no auth (it writes nothing); `--apply-plan` does.
    #[test]
    fn plan_writes_nothing_and_apply_plan_writes() {
        let plan = mode_of(&["--plan", "p.jsonl"]).unwrap();
        assert_eq!(plan, Mode::Plan(PathBuf::from("p.jsonl")));
        assert!(!plan.writes("epigraph"));
        let apply = mode_of(&["--apply-plan", "p.jsonl"]).unwrap();
        assert_eq!(apply, Mode::ApplyPlan(PathBuf::from("p.jsonl")));
        assert!(
            apply.writes("mock"),
            "apply-plan POSTs whatever the provider"
        );
        assert!(!Mode::Enumerate.writes("epigraph"));
    }

    #[test]
    fn contradictory_flag_combinations_are_refused() {
        for args in [
            &["--plan", "a", "--apply-plan", "b"][..],
            &["--dry-run", "--apply-plan", "b"],
            &["--retarget", "--dry-run", "--apply"],
            &["--apply"],
            &["--manifest", "m"],
            &["--include-marked"],
            &["--retarget", "--plan", "p"],
            &["--retarget", "--ids-file", "i"],
            &["--retarget", "--apply", "--apply-plan", "m"],
            &["--apply-plan", "p", "--ids-file", "i"],
        ] {
            assert!(mode_of(args).is_err(), "{args:?} must be refused");
        }
    }

    #[test]
    fn ids_file_parses_uuids_comments_and_blank_lines() {
        let a = "0b5d5c1e-8f2a-4b7e-9a51-2d9f3c8e1a01";
        let b = "0b5d5c1e-8f2a-4b7e-9a51-2d9f3c8e1a02";
        let raw = format!("# header\n{a}\n\n  {b}   # trailing comment\n");
        let ids = parse_ids_file(&raw).unwrap();
        assert_eq!(
            ids,
            vec![
                uuid::Uuid::parse_str(a).unwrap(),
                uuid::Uuid::parse_str(b).unwrap()
            ]
        );
        let err = parse_ids_file(&format!("{a}\nnot-a-uuid\n")).unwrap_err();
        assert!(
            err.contains("line 2"),
            "a bad line is an error naming it: {err}"
        );
    }

    // --- fail-fast auth resolution (gh-375) ---
    //
    // Re-landed from PR #337, which was merged and reverted 12 minutes later
    // by PR #341 with a body of exactly "Reverts epigraph-io/epigraph#337"
    // and no comments. The revert was a process correction, not a functional
    // one: CI was green on the merge commit 284a20f9 ("test success",
    // "Security audit (advisory) success"), no commit landed between the
    // merge and the revert, the same account merged and reverted, and #337's
    // own body ends "DO NOT MERGE — flagging for manual review".

    /// A caller-supplied `EPIGRAPH_TOKEN` is used verbatim and is never
    /// overridden by a mint, even when service-client credentials are also
    /// present. An operator who exports a specific token means that token.
    #[test]
    fn resolve_auth_plan_prefers_an_explicit_token_over_available_credentials() {
        let plan = resolve_auth_plan(
            Some("caller-supplied-token".to_string()),
            Some(("id".to_string(), "secret".to_string())),
        )
        .expect("an explicit token is sufficient auth material");
        assert_eq!(
            plan,
            AuthPlan::UseToken("caller-supplied-token".to_string())
        );
    }

    /// No token but a complete credential pair ⇒ plan a mint.
    #[test]
    fn resolve_auth_plan_mints_when_no_token_but_credentials_present() {
        let plan = resolve_auth_plan(None, Some(("id".to_string(), "secret".to_string())))
            .expect("credentials alone are sufficient auth material");
        assert_eq!(
            plan,
            AuthPlan::Mint {
                client_id: "id".to_string(),
                client_secret: "secret".to_string(),
            }
        );
    }

    /// `EPIGRAPH_TOKEN=""` (shell templating that resolved to empty rather
    /// than leaving the var unset) must be treated as absent, not as a
    /// zero-length bearer token.
    #[test]
    fn resolve_auth_plan_treats_a_set_but_empty_token_as_absent() {
        let plan = resolve_auth_plan(
            Some(String::new()),
            Some(("id".to_string(), "secret".to_string())),
        )
        .expect("an empty token must fall through to the credential path");
        assert_eq!(
            plan,
            AuthPlan::Mint {
                client_id: "id".to_string(),
                client_secret: "secret".to_string(),
            }
        );
    }

    /// THE gh-375 REGRESSION GUARD. With neither a token nor credentials the
    /// binary must refuse to start. The reverted behaviour was to log
    /// "proceeding with an EMPTY bearer token, every API write below will
    /// 401" and continue — burning a full LLM batch run before failing.
    #[test]
    fn resolve_auth_plan_fails_fast_when_no_auth_material_is_available() {
        let err = resolve_auth_plan(None, None)
            .expect_err("no auth material at all must fail fast, not yield an empty token");
        assert_eq!(err, AuthError::NoCredentials);
    }

    /// A set-but-empty credential must not trigger a doomed mint attempt;
    /// it fails fast the same way a missing one does.
    #[test]
    fn resolve_service_credentials_treats_set_but_empty_as_absent() {
        assert_eq!(
            resolve_service_credentials(Some(String::new()), Some("secret".to_string())),
            None
        );
        assert_eq!(
            resolve_service_credentials(Some("id".to_string()), Some(String::new())),
            None
        );
    }

    /// `EPIGRAPH_API=""` must not win over a usable `EPIGRAPH_API_URL`:
    /// an empty base makes `format!("{api_base}/api/v1/claims")` a relative
    /// path, which reqwest rejects with `RelativeUrlWithoutBase`.
    #[test]
    fn resolve_api_base_skips_a_set_but_empty_override() {
        assert_eq!(
            resolve_api_base(Some(String::new()), Some("https://api.example".to_string())),
            "https://api.example"
        );
        assert_eq!(
            resolve_api_base(Some(String::new()), Some(String::new())),
            "http://127.0.0.1:8080"
        );
    }

    // --- resolve_token_url: EPIGRAPH_OAUTH_TOKEN_URL precedence ---

    /// epiclaw-host's `container.rs` documents `EPIGRAPH_OAUTH_TOKEN_URL` as
    /// the manual-flow env var; the shipped mint never read it and always
    /// hardcoded `{api_base}/oauth/token`.
    #[test]
    fn resolve_token_url_prefers_an_explicit_oauth_token_url() {
        assert_eq!(
            resolve_token_url(
                Some("https://auth.example/token".to_string()),
                "https://api.example"
            ),
            "https://auth.example/token"
        );
    }

    #[test]
    fn resolve_token_url_falls_back_to_api_base_and_strips_a_trailing_slash() {
        assert_eq!(
            resolve_token_url(None, "https://api.example/"),
            "https://api.example/oauth/token"
        );
        assert_eq!(
            resolve_token_url(Some(String::new()), "https://api.example"),
            "https://api.example/oauth/token"
        );
    }

    /// `--provider mock` must stay usable with zero credentials: the module
    /// doc promises "a dry compile/smoke without credentials", and a mock
    /// run provably issues no authenticated request. `fixture` DOES write,
    /// so it is not exempt.
    #[test]
    fn only_the_mock_provider_is_exempt_from_auth_resolution() {
        assert!(!provider_writes_to_api("mock"));
        assert!(provider_writes_to_api("epigraph"));
        assert!(provider_writes_to_api("fixture"));
    }

    /// Retarget writes `/api/v1/edges`, which checks `edges:write`; the mint
    /// must ask for it, and ONLY the retarget writers widen the scope.
    #[test]
    fn only_retarget_writers_mint_edges_write() {
        assert_eq!(
            mode_of(&["--retarget", "--apply"]).unwrap().mint_scope(),
            "claims:write edges:write"
        );
        assert_eq!(
            mode_of(&["--retarget", "--apply-plan", "m"])
                .unwrap()
                .mint_scope(),
            "claims:write edges:write"
        );
        assert_eq!(mode_of(&[]).unwrap().mint_scope(), "claims:write");
        assert_eq!(
            mode_of(&["--apply-plan", "p"]).unwrap().mint_scope(),
            "claims:write"
        );
    }

    /// The scope reaches the token endpoint's form body verbatim: a mock that
    /// only answers a request carrying `edges:write` must be satisfied.
    #[tokio::test]
    async fn mint_service_token_sends_the_requested_scope() {
        use wiremock::matchers::body_string_contains;
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .and(body_string_contains("scope=claims%3Awrite+edges%3Awrite"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"access_token": "edge-scoped"})),
            )
            .mount(&server)
            .await;
        let http = reqwest::Client::new();
        let token_url = format!("{}/oauth/token", server.uri());
        let token = mint_service_token(
            "client-id",
            "client-secret",
            &token_url,
            "claims:write edges:write",
            &http,
        )
        .await
        .expect("the mock answers only a request carrying edges:write");
        assert_eq!(token, "edge-scoped");
    }

    // --- mint_service_token: HTTP mock coverage ---

    #[tokio::test]
    async fn mint_service_token_returns_parsed_token_on_success() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"access_token": "minted-jwt-value"})),
            )
            .mount(&server)
            .await;

        let http = reqwest::Client::new();
        let token_url = format!("{}/oauth/token", server.uri());
        let token = mint_service_token(
            "client-id",
            "client-secret",
            &token_url,
            "claims:write",
            &http,
        )
        .await
        .expect("mock server returns a valid token");
        assert_eq!(token, "minted-jwt-value");
    }

    #[tokio::test]
    async fn mint_service_token_errors_clearly_on_non_200_response() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "error": "invalid_client"
            })))
            .mount(&server)
            .await;

        let http = reqwest::Client::new();
        let token_url = format!("{}/oauth/token", server.uri());
        let err = mint_service_token(
            "client-id",
            "wrong-secret",
            &token_url,
            "claims:write",
            &http,
        )
        .await
        .expect_err("401 must surface as an Err, not a silently empty string");
        assert!(matches!(err, MintError::HttpStatus(status) if status == 401));
    }

    #[tokio::test]
    async fn mint_service_token_errors_clearly_on_malformed_json_body() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
            .mount(&server)
            .await;

        let http = reqwest::Client::new();
        let token_url = format!("{}/oauth/token", server.uri());
        let err = mint_service_token(
            "client-id",
            "client-secret",
            &token_url,
            "claims:write",
            &http,
        )
        .await
        .expect_err("a malformed JSON body must surface as an Err");
        assert!(matches!(err, MintError::MalformedResponse(_)));
    }

    #[tokio::test]
    async fn mint_service_token_errors_clearly_when_access_token_field_missing() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"token_type": "bearer"})),
            )
            .mount(&server)
            .await;

        let http = reqwest::Client::new();
        let token_url = format!("{}/oauth/token", server.uri());
        let err = mint_service_token(
            "client-id",
            "client-secret",
            &token_url,
            "claims:write",
            &http,
        )
        .await
        .expect_err("a response with no access_token field must be a clear error");
        assert!(matches!(err, MintError::MalformedResponse(_)));
    }

    /// `--provider fixture` without `DECOMPOSE_FIXTURE_PATH` must fail, not
    /// fall back to some default fixture: selecting the canned-response
    /// provider requires two deliberate acts, so a production run can never
    /// reach it by omission.
    #[test]
    fn fixture_provider_requires_an_explicit_fixture_path() {
        let err = match resolve_llm_client("fixture", None) {
            Ok(_) => panic!("fixture provider must not resolve without DECOMPOSE_FIXTURE_PATH"),
            Err(e) => e.to_string(),
        };
        assert!(
            err.contains("DECOMPOSE_FIXTURE_PATH"),
            "error must name the missing env var: {err}"
        );
    }

    /// A stray `DECOMPOSE_FIXTURE_PATH` in the environment must not divert any
    /// other selector — `mock` still resolves to `mock`, and the fixture path
    /// is ignored entirely.
    #[test]
    fn fixture_path_does_not_divert_other_providers() {
        let client = resolve_llm_client("mock", Some("/nonexistent/fixture.json".to_string()))
            .expect("mock must resolve regardless of DECOMPOSE_FIXTURE_PATH");
        assert_eq!(client.name(), "mock");
    }

    /// The `fixture` provider must never be reachable through the kernel
    /// factory, because registry membership is what makes a provider eligible
    /// for `--provider epigraph` auto-detect (which skips only the literal name
    /// `mock`). If this ever starts returning `Ok`, canned atoms have become
    /// silently writable in production whenever Anthropic credentials are
    /// absent.
    #[test]
    fn fixture_is_not_reachable_through_the_kernel_factory() {
        let err = match epigraph_cli::enrichment::llm_client::create_llm_client("fixture") {
            Ok(_) => panic!("`fixture` must not be a registered provider"),
            Err(e) => e.to_string(),
        };
        assert!(
            err.contains("Unknown LLM provider"),
            "fixture must be unknown to the registry: {err}"
        );
    }

    /// An unreadable fixture file is a hard error — never a silent empty batch
    /// that would look like a clean no-op run.
    #[test]
    fn fixture_provider_rejects_a_missing_fixture_file() {
        let err = match resolve_llm_client(
            "fixture",
            Some("/nonexistent/decompose-fixture.json".to_string()),
        ) {
            Ok(_) => panic!("a missing fixture file must not resolve"),
            Err(e) => e.to_string(),
        };
        assert!(
            err.contains("unreadable"),
            "error must explain the file could not be read: {err}"
        );
    }

    #[test]
    fn resolve_api_base_prefers_epigraph_api_when_both_set() {
        assert_eq!(
            resolve_api_base(
                Some("https://explicit.example".to_string()),
                Some("http://container-standard.example".to_string()),
            ),
            "https://explicit.example"
        );
    }

    #[test]
    fn resolve_api_base_falls_back_to_epigraph_api_url() {
        assert_eq!(
            resolve_api_base(None, Some("http://container-standard.example".to_string())),
            "http://container-standard.example"
        );
    }

    #[test]
    fn resolve_api_base_defaults_to_localhost_when_neither_set() {
        assert_eq!(resolve_api_base(None, None), "http://127.0.0.1:8080");
    }

    #[test]
    fn resolve_service_credentials_none_when_client_id_missing() {
        assert_eq!(
            resolve_service_credentials(None, Some("secret".to_string())),
            None
        );
    }

    #[test]
    fn resolve_service_credentials_none_when_client_secret_missing() {
        assert_eq!(
            resolve_service_credentials(Some("id".to_string()), None),
            None
        );
    }

    #[test]
    fn resolve_service_credentials_some_when_both_present() {
        assert_eq!(
            resolve_service_credentials(Some("id".to_string()), Some("secret".to_string())),
            Some(("id".to_string(), "secret".to_string()))
        );
    }
}
