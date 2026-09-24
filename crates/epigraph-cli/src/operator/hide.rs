//! Opt-in evidence hiding (operator directive 2026-09-23, Amendment 2): the
//! selectors, the preview, every refusal between them and a write, the write
//! itself (`hide-evidence --apply`), and its reversal (`reown-reverse` on a
//! hide manifest).
//!
//! # What a hide is
//!
//! A selected evidence row that is `public` becomes `visibility = 'group'`,
//! owned by the operator's personal group, and is PINNED in migration 110's
//! `evidence_visibility_pins`. The pin is what keeps it hidden: without it,
//! 070's insert arm re-publishes the row at the next evidence INSERT for its
//! claim and 072's update arm at the next claim owner or visibility change.
//! With it, propagation never widens the row; its owner follows the claim
//! except onto world or seed (see 110's header). Exactly the selected rows
//! change and no other row's visibility does.
//!
//! # The guards, in the order `--apply` meets them
//!
//! 1. A dry run by default; `--apply` also needs `--confirm-hide <N>` with N
//!    equal to the planned hidden-row count ([`refuse_apply`]).
//! 2. B-H4, unenforced hiding. Permissive policies are OR'ed, and production
//!    carries an orphan PERMISSIVE `evidence_privacy` policy (in no
//!    migration; USING effectively TRUE), so while it exists any application
//!    session reads a `group` evidence row and hiding has NO effect.
//!    [`extra_evidence_policies`] finds every permissive SELECT-capable policy
//!    on `evidence` other than `evidence_tenancy`. A dry run prints a loud
//!    warning; `--apply` refuses unless `--accept-unenforced-hide` is given,
//!    and then reports the rows as hidden-but-UNENFORCED.
//! 3. The kernel guard (B-H2): the pin table and BOTH pin-aware trigger
//!    bodies, read from the live catalog ([`guard_status`]).
//! 4. `--manifest-out`, a new file, written and `fsync`ed before the write.
//! 5. Under the write's own locks: the in-scope claims `FOR UPDATE` (an
//!    evidence INSERT takes `FOR KEY SHARE` on its claim through the foreign
//!    key, and a claim tenancy change needs the row lock, so neither can land
//!    mid-hide) and their evidence rows `FOR UPDATE`; then the plan is
//!    re-derived and must equal the dry plan row for row, and the count must
//!    still equal `--confirm-hide`.
//! 6. After the write and before the commit, the invariants: every selected
//!    row is `(target, 'group')` and pinned; every other evidence row of the
//!    in-scope claims is unchanged; the transaction's row census
//!    (`pg_stat_xact_user_tables`) is exactly N evidence updates and N pin
//!    inserts; and what an UNSTAMPED `epigraph_app` session can read lost
//!    exactly the selected rows (with an accepted unenforced policy it must
//!    lose nothing it could not before, and the run says the hide is not
//!    enforced). Any violation rolls everything back.
//!
//! # Selectors are a union
//!
//! A row is selected when it matches ANY selector: its id is in the ids file,
//! OR its `evidence_type` is one of the `--hide-evidence-type` values, OR one
//! of its `labels` is one of the `--hide-evidence-label` values. Only evidence
//! attached to claims in scope is ever selected; an id in the ids file that is
//! not is REPORTED as out of scope, never hidden.
//!
//! # `reown-claims` does not hide under `--apply`
//!
//! A re-own batch's invariants are that every row it touches stays `public`
//! and that the app-readable set does not change; a hide breaks both by
//! design. So `reown-claims --apply` with a hide selector refuses before its
//! manifest, and the order is: re-own first, then `hide-evidence --apply` over
//! the moved claims (its own manifest). A claim with a hidden row is HELD by a
//! later re-own (a non-public derived row), so hiding first would block it.
//!
//! # Reversal
//!
//! `reown-reverse --manifest <hide manifest>` ([`reverse_manifest`]) is a
//! compare-and-swap per row: a row still in the post state this run recorded
//! (`(target, 'group')`, pinned), whose claim is still in the state recorded
//! at the hide, is unpinned and put back on its recorded prior
//! `(owner, visibility)`; a row already on its prior state and unpinned is
//! skipped; anything else is HELD and named. Same locks and census as the
//! write.
//!
//! # What hiding does NOT cover (B-H3), stated so it is not over-read
//!
//! Measured in `epigraph-db/tests/hidden_evidence_read_probe.rs`: every
//! repository read that returns evidence content filters a hidden row for a
//! non-member, on a privileged pool and under RLS. NOT hidden, by design or
//! as known limits, and reported per plan as `HIDE-SURFACE` lines:
//!
//! * the claim's own text (`claims.content`) and any harvester fragment text,
//!   which stay public — hiding evidence does not hide what the claim says;
//! * edges touching a hidden row: their ids, relationship and properties stay
//!   readable where their endpoints were (a hide must not change other rows);
//! * `mass_functions` rows naming the hidden row (`evidence_id`,
//!   `evidence_type`): metadata, no content;
//! * any BYPASSRLS or superuser connection, and every maintenance binary on a
//!   privileged pool, which read every row regardless;
//! * anything emitted before the hide (events, caches, exports, search
//!   results): hiding is forward-only and retracts nothing.

use super::manifest::{Record, Writer};
use super::tables::{self, Attached, RowKey, Snapshot, TableSpec, Tenancy};
use anyhow::{bail, Context};
use serde_json::json;
use sqlx::PgConnection;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use uuid::Uuid;

/// `evidence_type_valid`'s seven values (migration 001's CHECK).
pub const EVIDENCE_TYPES: &[&str] = &[
    "document",
    "observation",
    "testimony",
    "computation",
    "reference",
    "figure",
    "conversational",
];

/// The `operation` a hide manifest's header carries, which `reown-reverse`
/// dispatches on.
pub const OPERATION: &str = "hide-evidence";

/// The hide flags, shared by `reown-claims` and `hide-evidence`.
#[derive(Clone, Debug, Default, clap::Args)]
pub struct HideArgs {
    /// File of evidence UUIDs to hide (one per line).
    #[arg(long)]
    pub hide_evidence_ids: Option<PathBuf>,
    /// Hide every in-scope evidence row of this `evidence_type`. Repeatable.
    #[arg(long)]
    pub hide_evidence_type: Vec<String>,
    /// Hide every in-scope evidence row carrying this label. Repeatable.
    #[arg(long)]
    pub hide_evidence_label: Vec<String>,
    /// Under `--apply`, the planned hidden-row count, repeated back.
    #[arg(long)]
    pub confirm_hide: Option<usize>,
    /// Proceed although a permissive policy on `evidence` other than
    /// `evidence_tenancy` means hiding would not be enforced.
    #[arg(long)]
    pub accept_unenforced_hide: bool,
}

/// The parsed selectors.
#[derive(Clone, Debug, Default)]
pub struct Selector {
    pub ids: BTreeSet<Uuid>,
    pub types: BTreeSet<String>,
    pub labels: BTreeSet<String>,
}

impl Selector {
    /// # Errors
    /// The ids file is unreadable or malformed, or a type is not one of
    /// [`EVIDENCE_TYPES`].
    pub fn from_args(a: &HideArgs) -> anyhow::Result<Self> {
        let ids = match &a.hide_evidence_ids {
            Some(p) => super::read_ids_file(p)?.into_iter().collect(),
            None => BTreeSet::new(),
        };
        for t in &a.hide_evidence_type {
            if !EVIDENCE_TYPES.contains(&t.as_str()) {
                bail!(
                    "--hide-evidence-type {t:?} is not an evidence_type; expected one of {}",
                    EVIDENCE_TYPES.join(", ")
                );
            }
        }
        Ok(Self {
            ids,
            types: a.hide_evidence_type.iter().cloned().collect(),
            labels: a.hide_evidence_label.iter().cloned().collect(),
        })
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ids.is_empty() && self.types.is_empty() && self.labels.is_empty()
    }

    /// Whether an attached row is selected. Only `evidence` rows ever are.
    #[must_use]
    pub fn matches(&self, a: &Attached) -> bool {
        if a.table != "evidence" {
            return false;
        }
        Uuid::parse_str(&a.pk).is_ok_and(|id| self.ids.contains(&id))
            || a.evidence_type
                .as_ref()
                .is_some_and(|t| self.types.contains(t))
            || a.labels.iter().any(|l| self.labels.contains(l))
    }

    fn to_json(&self) -> serde_json::Value {
        json!({
            "ids": self.ids.iter().map(Uuid::to_string).collect::<Vec<_>>(),
            "types": self.types,
            "labels": self.labels,
        })
    }
}

/// The rows a selector picks out of a snapshot.
#[derive(Debug, Default)]
pub struct Plan {
    /// Selected, currently public: these would be hidden.
    pub rows: Vec<Attached>,
    /// Selected but already not public: left exactly as they are.
    pub already_private: usize,
    /// Ids from the ids file that are not evidence of any claim in scope.
    pub out_of_scope: Vec<Uuid>,
}

impl Plan {
    #[must_use]
    pub fn by_type(&self) -> BTreeMap<String, usize> {
        let mut m = BTreeMap::new();
        for r in &self.rows {
            *m.entry(r.evidence_type.clone().unwrap_or_default())
                .or_default() += 1;
        }
        m
    }

    #[must_use]
    pub fn by_claim(&self) -> BTreeMap<Uuid, usize> {
        let mut m = BTreeMap::new();
        for r in &self.rows {
            *m.entry(r.claim).or_default() += 1;
        }
        m
    }

    /// `(evidence id, claim, tenancy)` of every row to hide, sorted: what a
    /// re-plan under the locks must reproduce exactly.
    fn fingerprint(&self) -> Vec<(String, Uuid, Tenancy)> {
        let mut v: Vec<_> = self
            .rows
            .iter()
            .map(|r| (r.pk.clone(), r.claim, r.tenancy.clone()))
            .collect();
        v.sort();
        v
    }

    fn ids(&self) -> Vec<Uuid> {
        self.rows
            .iter()
            .filter_map(|r| Uuid::parse_str(&r.pk).ok())
            .collect()
    }
}

/// Select from `attached` (the evidence of the claims in scope).
#[must_use]
pub fn plan(sel: &Selector, attached: &Snapshot) -> Plan {
    let mut p = Plan::default();
    let mut seen_ids = BTreeSet::new();
    for a in attached.values() {
        if a.table == "evidence" {
            if let Ok(id) = Uuid::parse_str(&a.pk) {
                seen_ids.insert(id);
            }
        }
        if !sel.matches(a) {
            continue;
        }
        if a.tenancy.visibility == "public" {
            p.rows.push(a.clone());
        } else {
            p.already_private += 1;
        }
    }
    p.out_of_scope = sel.ids.difference(&seen_ids).copied().collect();
    p
}

fn preview(s: Option<&str>) -> String {
    match s {
        None => "(no raw_content)".to_string(),
        Some(t) => t
            .chars()
            .take(80)
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect(),
    }
}

/// The dry-run report: counts per type and per claim, then one preview line
/// per row.
///
/// # Errors
/// Writing to `out` fails.
pub fn print(out: &mut dyn std::io::Write, p: &Plan) -> anyhow::Result<()> {
    writeln!(
        out,
        "HIDE-PLAN: {} evidence row(s) would become visibility=group, owned by the operator's \
         personal group ({} selected row(s) already not public are left as they are)",
        p.rows.len(),
        p.already_private
    )?;
    for (t, n) in p.by_type() {
        writeln!(out, "HIDE-TYPE\t{t}\t{n}")?;
    }
    for (c, n) in p.by_claim() {
        writeln!(out, "HIDE-CLAIM\t{c}\t{n}")?;
    }
    let mut rows: Vec<&Attached> = p.rows.iter().collect();
    rows.sort_by(|a, b| (a.claim, &a.pk).cmp(&(b.claim, &b.pk)));
    for r in rows {
        writeln!(
            out,
            "HIDE\t{}\t{}\t{}\t{}",
            r.pk,
            r.claim,
            r.evidence_type.as_deref().unwrap_or(""),
            preview(r.preview.as_deref())
        )?;
    }
    for id in &p.out_of_scope {
        writeln!(
            out,
            "HIDE-OUT-OF-SCOPE\t{id}\tnot evidence of any claim in scope; never hidden"
        )?;
    }
    Ok(())
}

/// Whether the kernel guard (B-H2) that stops propagation re-publishing a
/// hidden row is present in the live schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuardStatus {
    pub pin_table: bool,
    pub propagate_arm_pinned: bool,
    pub inherit_arm_pinned: bool,
}

impl GuardStatus {
    #[must_use]
    pub const fn complete(self) -> bool {
        self.pin_table && self.propagate_arm_pinned && self.inherit_arm_pinned
    }
}

/// Read the guard's presence from the catalog: the pin table exists, and BOTH
/// tenancy trigger bodies consult it.
///
/// # Errors
/// A catalog read fails.
pub async fn guard_status(conn: &mut PgConnection) -> anyhow::Result<GuardStatus> {
    let (pin_table, propagate_arm_pinned, inherit_arm_pinned): (bool, bool, bool) =
        sqlx::query_as(
            "SELECT to_regclass('public.evidence_visibility_pins') IS NOT NULL, \
                    COALESCE((SELECT prosrc LIKE '%evidence_visibility_pins%' FROM pg_proc \
                               WHERE oid = to_regprocedure('public.epigraph_propagate_tenancy()')), \
                             false), \
                    COALESCE((SELECT prosrc LIKE '%evidence_visibility_pins%' FROM pg_proc \
                               WHERE oid = to_regprocedure('public.epigraph_inherit_tenancy_stmt()')), \
                             false)",
        )
        .fetch_one(&mut *conn)
        .await
        .context("reading the evidence pin guard from the catalog")?;
    Ok(GuardStatus {
        pin_table,
        propagate_arm_pinned,
        inherit_arm_pinned,
    })
}

/// Permissive policies on `evidence`, other than `evidence_tenancy`, that
/// apply to reads (`cmd` ALL or SELECT). Each is OR'ed with the tenancy policy,
/// so any one whose USING admits a `group` row defeats hiding.
///
/// # Errors
/// The catalog read fails.
pub async fn extra_evidence_policies(conn: &mut PgConnection) -> anyhow::Result<Vec<String>> {
    Ok(sqlx::query_scalar(
        "SELECT policyname::text FROM pg_policies \
          WHERE schemaname = 'public' AND tablename = 'evidence' \
            AND permissive = 'PERMISSIVE' AND cmd IN ('ALL', 'SELECT') \
            AND policyname <> 'evidence_tenancy' \
          ORDER BY 1",
    )
    .fetch_all(&mut *conn)
    .await?)
}

/// The loud warning a dry run prints when hiding would not be enforced.
///
/// # Errors
/// Writing to `out` fails.
pub fn warn_unenforced(out: &mut dyn std::io::Write, policies: &[String]) -> anyhow::Result<()> {
    if policies.is_empty() {
        return Ok(());
    }
    writeln!(
        out,
        "WARNING: HIDING WILL NOT BE ENFORCED. Permissive polic{} on evidence other than \
         evidence_tenancy: {}. Permissive policies are OR'ed, so an application session can \
         still read a visibility=group evidence row. --apply refuses unless \
         --accept-unenforced-hide is given.",
        if policies.len() == 1 { "y" } else { "ies" },
        policies.join(", ")
    )?;
    Ok(())
}

/// The refusals between a hide plan and a write, in order: the count
/// confirmation, the unenforced-hide policy check, and the kernel guard.
///
/// # Errors
/// The first check that fails.
pub fn refuse_apply(
    p: &Plan,
    args: &HideArgs,
    policies: &[String],
    guard: GuardStatus,
) -> anyhow::Result<()> {
    match args.confirm_hide {
        Some(n) if n == p.rows.len() => {}
        Some(n) => bail!(
            "--confirm-hide {n} does not match the planned hidden-row count {}; refusing",
            p.rows.len()
        ),
        None => bail!(
            "--apply with a hide selector requires --confirm-hide {} (the planned hidden-row \
             count, repeated back); refusing",
            p.rows.len()
        ),
    }
    if !policies.is_empty() && !args.accept_unenforced_hide {
        bail!(
            "hiding would NOT be enforced: permissive polic{} {} on evidence admit group rows \
             to every application session. Drop {} first, or pass --accept-unenforced-hide; \
             refusing",
            if policies.len() == 1 { "y" } else { "ies" },
            policies.join(", "),
            if policies.len() == 1 { "it" } else { "them" }
        );
    }
    if !guard.complete() {
        bail!(
            "the kernel guard that keeps a hidden row hidden is not in this schema (pin table: \
             {}, update arm pinned: {}, insert arm pinned: {}). Without it the next claim \
             update, or the next evidence insert for the same claim, re-publishes every hidden \
             row (migrations 070/072), so a hide would not hold. Apply migration 110 \
             (evidence_visibility_pins); refusing",
            guard.pin_table,
            guard.propagate_arm_pinned,
            guard.inherit_arm_pinned
        );
    }
    Ok(())
}

/// `reown-claims --apply` with a hide selector: refused once the plan's own
/// checks pass (see the module doc).
///
/// # Errors
/// Always.
pub fn refuse_hide_in_reown() -> anyhow::Result<()> {
    bail!(
        "reown-claims does not hide under --apply: a re-own batch keeps every row it touches \
         public, and a hide makes rows group-private. Re-own first (without the hide flags), \
         then run hide-evidence --apply over the moved claims; it writes its own manifest, \
         which reown-reverse reverses. Refusing before the manifest and before any write"
    )
}

/// Everything `hide-evidence` was told.
#[derive(Clone, Debug)]
pub struct Standalone {
    pub operator: Uuid,
    pub args: HideArgs,
    pub apply: bool,
    pub manifest_out: Option<PathBuf>,
    pub reason: String,
    pub lock_timeout: String,
}

/// Which listed claims are the operator's: owned by its personal group, or
/// authored by the operator or by an agent linked to it (retired or actor).
async fn scope(
    conn: &mut PgConnection,
    operator: Uuid,
    target: Uuid,
    claims: &[Uuid],
    rows: &[tables::ClaimRow],
) -> anyhow::Result<(Vec<Uuid>, Vec<(Uuid, String)>)> {
    let by_id: BTreeMap<Uuid, &tables::ClaimRow> = rows.iter().map(|r| (r.id, r)).collect();
    let mut in_scope = Vec::new();
    let mut held = Vec::new();
    for id in claims {
        let Some(c) = by_id.get(id) else {
            held.push((*id, "not found".to_string()));
            continue;
        };
        let linked = c.author == operator
            || super::operator_of_author(conn, c.author).await? == Some(operator);
        if c.owner == target || linked {
            in_scope.push(c.id);
        } else {
            held.push((
                *id,
                "neither owned by the operator's group nor authored by the operator or an agent \
                 linked to it"
                    .to_string(),
            ));
        }
    }
    Ok((in_scope, held))
}

fn evidence_specs(specs: &[TableSpec]) -> anyhow::Result<Vec<TableSpec>> {
    let v: Vec<TableSpec> = specs
        .iter()
        .filter(|s| s.name == "evidence")
        .cloned()
        .collect();
    if v.is_empty() {
        bail!("epigraph_propagate_tenancy no longer cascades to evidence; refusing");
    }
    Ok(v)
}

/// The B-H3 surfaces this plan leaves readable, counted: edges touching a
/// selected row and `mass_functions` naming one.
async fn print_surfaces(
    conn: &mut PgConnection,
    out: &mut dyn std::io::Write,
    ids: &[Uuid],
) -> anyhow::Result<()> {
    if ids.is_empty() {
        return Ok(());
    }
    let (edges, masses): (i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM edges \
                  WHERE (source_type = 'evidence' AND source_id = ANY($1)) \
                     OR (target_type = 'evidence' AND target_id = ANY($1))), \
                (SELECT count(*) FROM mass_functions WHERE evidence_id = ANY($1))",
    )
    .bind(ids)
    .fetch_one(&mut *conn)
    .await?;
    writeln!(
        out,
        "HIDE-SURFACE\tedges\t{edges}\tedges touching a hidden row keep their tenancy: ids, \
         relationship and properties stay readable where they were"
    )?;
    writeln!(
        out,
        "HIDE-SURFACE\tmass_functions\t{masses}\trows naming a hidden row keep evidence_id and \
         evidence_type readable (metadata, no content)"
    )?;
    writeln!(
        out,
        "HIDE-SURFACE\tnot hidden\tthe claims' own text and harvester fragments stay public; \
         any BYPASSRLS or superuser connection reads every row; content emitted before the \
         hide (events, caches, exports, search results) is not retracted"
    )?;
    Ok(())
}

/// `hide-evidence`: the selectors over the evidence of claims that are NOT
/// moving; with `--apply`, the write.
///
/// A listed claim is in scope only if it is already the operator's: owned by
/// the operator's personal group, or authored by the operator or by an agent
/// linked to it (retired or actor). Any other listed claim is HELD — hiding
/// moves a row into the operator's group, and taking a row away from a group
/// the operator has no claim on is not this tool's call.
///
/// # Errors
/// A refusal (see the module doc) or a database error. On any error after the
/// manifest was created nothing was committed.
pub async fn run_standalone(
    conn: &mut PgConnection,
    opts: &Standalone,
    claims: &[Uuid],
    out: &mut dyn std::io::Write,
) -> anyhow::Result<()> {
    let sel = Selector::from_args(&opts.args)?;
    if sel.is_empty() {
        bail!(
            "hide-evidence needs at least one selector: --hide-evidence-ids, \
             --hide-evidence-type or --hide-evidence-label"
        );
    }
    if opts.apply && opts.reason.trim().is_empty() {
        bail!("--reason must not be empty; it is recorded on every pin");
    }
    let operator = opts.operator;
    let target = super::operator_group(conn, operator).await?;
    let specs = evidence_specs(&tables::propagated_tables(conn).await?)?;
    let rows = tables::fetch_claims(conn, claims, false).await?;
    writeln!(
        out,
        "hide-evidence: operator={operator} target_group={target} claims={} mode={}",
        claims.len(),
        if opts.apply { "APPLY" } else { "DRY-RUN" }
    )?;
    let (in_scope, held) = scope(conn, operator, target, claims, &rows).await?;
    for (id, why) in &held {
        writeln!(out, "HELD\t{id}\t{why}")?;
    }
    let attached = tables::fetch_attached(conn, &specs, &in_scope).await?;
    let p = plan(&sel, &attached);
    print(out, &p)?;
    let policies = extra_evidence_policies(conn).await?;
    warn_unenforced(out, &policies)?;
    let guard = guard_status(conn).await?;
    print_surfaces(conn, out, &p.ids()).await?;
    if !opts.apply {
        writeln!(
            out,
            "DRY RUN: nothing was written.{}",
            if guard.complete() {
                ""
            } else {
                " --apply refuses on this schema: the kernel pin guard is absent."
            }
        )?;
        return Ok(());
    }
    refuse_apply(&p, &opts.args, &policies, guard)?;
    let Some(manifest_out) = opts.manifest_out.as_ref() else {
        bail!(
            "hide-evidence --apply requires --manifest-out <new file>: the undo record, written \
             and fsynced before the write; refusing"
        );
    };
    if p.rows.is_empty() {
        writeln!(out, "HIDE: nothing to hide; no manifest written")?;
        return Ok(());
    }
    tables::probe_session_switch(conn).await?;

    let mut tx = sqlx::Connection::begin(&mut *conn).await?;
    let result = apply_in(
        &mut tx,
        opts,
        &sel,
        &specs,
        claims,
        target,
        &in_scope,
        &p,
        &policies,
        manifest_out,
        out,
    )
    .await;
    match result {
        Ok(n) => {
            tx.commit().await?;
            writeln!(
                out,
                "HIDDEN: {n} evidence row(s) are visibility=group, owned by {target}, and pinned. \
                 Manifest: {}{}",
                manifest_out.display(),
                if policies.is_empty() {
                    String::new()
                } else {
                    format!(
                        ". NOT ENFORCED while {} exist(s): an application session can still \
                         read them",
                        policies.join(", ")
                    )
                }
            )?;
            Ok(())
        }
        Err(e) => {
            tx.rollback().await?;
            Err(e.context(
                "hide-evidence rolled back: nothing was committed to the database (a manifest, \
                 if created, holds no post records, so reversing it is a no-op)",
            ))
        }
    }
}

/// The write, inside the caller's transaction. Returns the rows hidden.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn apply_in(
    conn: &mut PgConnection,
    opts: &Standalone,
    sel: &Selector,
    specs: &[TableSpec],
    claims: &[Uuid],
    target: Uuid,
    in_scope: &[Uuid],
    p: &Plan,
    policies: &[String],
    manifest_out: &std::path::Path,
    out: &mut dyn std::io::Write,
) -> anyhow::Result<usize> {
    sqlx::query("SELECT set_config('lock_timeout', $1, true)")
        .bind(&opts.lock_timeout)
        .execute(&mut *conn)
        .await?;
    // Locks: the listed claims, then their evidence rows.
    let locked = tables::fetch_claims(conn, claims, true).await?;
    let (scope_now, _) = scope(conn, opts.operator, target, claims, &locked).await?;
    if scope_now != in_scope {
        bail!(
            "the claims in scope changed between the plan and the lock (another writer moved \
             one); re-run the dry run"
        );
    }
    sqlx::query("SELECT id FROM evidence WHERE claim_id = ANY($1) ORDER BY id FOR UPDATE")
        .bind(in_scope)
        .execute(&mut *conn)
        .await
        .context("locking the in-scope evidence rows")?;
    let s0 = tables::fetch_attached(conn, specs, in_scope).await?;
    let p_now = plan(sel, &s0);
    if p_now.fingerprint() != p.fingerprint() {
        bail!(
            "the evidence selected under the lock ({} row(s)) is not the plan's ({} row(s)): \
             another writer changed a row since the dry plan; re-run the dry run",
            p_now.rows.len(),
            p.rows.len()
        );
    }
    let n = p_now.rows.len();
    if opts.args.confirm_hide != Some(n) {
        bail!("--confirm-hide no longer matches the {n} row(s) selected under the lock");
    }
    let ids = p_now.ids();
    let spec = &specs[0];

    // ---- manifest first, fsynced ----
    let header = json!({
        "manifest": "epigraph-operator hide-evidence",
        "operation": OPERATION,
        "version": super::manifest::VERSION,
        "operator": opts.operator,
        "target_group_id": target,
        "created_at": chrono::Utc::now().to_rfc3339(),
        "reason": opts.reason,
        "selectors": sel.to_json(),
        "planned_rows": n,
        "unenforced_by": policies,
    });
    let mut w = Writer::create_new(manifest_out, &header)?;
    let prior: Vec<Record> = p_now
        .rows
        .iter()
        .map(|r| Record {
            table: "evidence".into(),
            id: spec.id_json(&r.pk),
            owner_group_id: r.tenancy.owner,
            visibility: r.tenancy.visibility.clone(),
            co_owner_group_id: None,
            claim_id: r.claim,
            hidden: true,
            after: false,
            neighbour: false,
        })
        .collect();
    w.append(&prior)?;

    let keys: BTreeSet<RowKey> = s0.keys().cloned().collect();
    let readable_before = tables::app_readable(conn, specs, in_scope, &keys).await?;
    let counters_before = tables::xact_counters(conn).await?;

    // ---- the write: pin, then hide ----
    let pinned = sqlx::query(
        "INSERT INTO evidence_visibility_pins (evidence_id, pinned_by, reason) \
         SELECT unnest($1::uuid[]), $2, $3",
    )
    .bind(&ids)
    .bind(opts.operator)
    .bind(&opts.reason)
    .execute(&mut *conn)
    .await
    .context("INSERT evidence_visibility_pins")?
    .rows_affected();
    let hidden = sqlx::query(
        "UPDATE evidence SET owner_group_id = $2, visibility = 'group' \
          WHERE id = ANY($1) AND visibility = 'public'",
    )
    .bind(&ids)
    .bind(target)
    .execute(&mut *conn)
    .await
    .context("UPDATE evidence")?
    .rows_affected();

    let s2 = tables::fetch_attached(conn, specs, in_scope).await?;
    let counters_after = tables::xact_counters(conn).await?;
    let readable_after = tables::app_readable(conn, specs, in_scope, &keys).await?;
    let pins_now: Vec<Uuid> = sqlx::query_scalar(
        "SELECT evidence_id FROM evidence_visibility_pins WHERE evidence_id = ANY($1)",
    )
    .bind(&ids)
    .fetch_all(&mut *conn)
    .await?;

    // ---- invariants ----
    let mut v = Vec::new();
    let n64 = i64::try_from(n).unwrap_or(i64::MAX);
    if usize::try_from(pinned).ok() != Some(n) || usize::try_from(hidden).ok() != Some(n) {
        v.push(format!(
            "pinned {pinned} and hid {hidden} row(s), the plan selected {n}"
        ));
    }
    if pins_now.len() != n {
        v.push(format!(
            "{} of {n} selected row(s) carry a pin",
            pins_now.len()
        ));
    }
    let selected: BTreeSet<RowKey> = p_now
        .rows
        .iter()
        .map(|r| (r.table.clone(), r.pk.clone()))
        .collect();
    let want = Tenancy {
        owner: target,
        visibility: "group".into(),
        co_owner: None,
    };
    for (k, a) in &s0 {
        let Some(got) = s2.get(k) else {
            v.push(format!("{} {} vanished during the hide", k.0, k.1));
            continue;
        };
        if selected.contains(k) {
            if got.tenancy != want {
                v.push(format!(
                    "{} {} ended as {:?}, not {want:?}",
                    k.0, k.1, got.tenancy
                ));
            }
        } else if got.tenancy != a.tenancy {
            v.push(format!(
                "{} {} is not selected and changed {:?} -> {:?}",
                k.0, k.1, a.tenancy, got.tenancy
            ));
        }
    }
    let mut expect: BTreeMap<String, (i64, i64, i64)> = BTreeMap::new();
    expect.insert("evidence".into(), (0, n64, 0));
    expect.insert("evidence_visibility_pins".into(), (n64, 0, 0));
    v.extend(super::reown::counter_violations(
        &super::reown::counter_delta(&counters_before, &counters_after),
        &expect,
    ));
    let lost: BTreeSet<RowKey> = readable_before
        .difference(&readable_after)
        .cloned()
        .collect();
    let gained: Vec<&RowKey> = readable_after.difference(&readable_before).collect();
    if !gained.is_empty() {
        v.push(format!(
            "an unstamped epigraph_app session GAINED rows: {gained:?}"
        ));
    }
    if policies.is_empty() {
        if lost != selected {
            v.push(format!(
                "an unstamped epigraph_app session lost {lost:?}; the hide selected {selected:?}"
            ));
        }
    } else if !lost.is_subset(&selected) {
        v.push(format!(
            "an unstamped epigraph_app session lost unselected rows: {:?}",
            lost.difference(&selected).collect::<Vec<_>>()
        ));
    }
    if !v.is_empty() {
        bail!(
            "{} invariant violation(s), rolled back:\n    - {}",
            v.len(),
            v.join("\n    - ")
        );
    }

    // ---- post records: the rows and their claims, fsynced before commit ----
    let claim_rows = tables::fetch_claims(
        conn,
        &p_now.by_claim().into_keys().collect::<Vec<_>>(),
        false,
    )
    .await?;
    let mut post: Vec<Record> = claim_rows
        .iter()
        .map(|c| Record {
            table: "claims".into(),
            id: json!(c.id.to_string()),
            owner_group_id: c.owner,
            visibility: c.visibility.clone(),
            co_owner_group_id: None,
            claim_id: c.id,
            hidden: false,
            after: true,
            neighbour: true,
        })
        .collect();
    post.extend(p_now.rows.iter().map(|r| Record {
        table: "evidence".into(),
        id: spec.id_json(&r.pk),
        owner_group_id: target,
        visibility: "group".into(),
        co_owner_group_id: None,
        claim_id: r.claim,
        hidden: true,
        after: true,
        neighbour: false,
    }));
    w.append_post(&post)?;
    writeln!(
        out,
        "INVARIANTS: held (exactly {n} row(s) hidden and pinned; no other row changed)"
    )?;
    Ok(n)
}

/// What reversing one hide manifest did.
#[derive(Debug, Default)]
pub struct Unhide {
    pub restored: usize,
    pub already: usize,
    pub missing: usize,
    pub held: Vec<(Uuid, String)>,
}

/// Is `m` a hide manifest?
#[must_use]
pub fn is_hide_manifest(m: &super::manifest::Manifest) -> bool {
    m.header.get("operation").and_then(|v| v.as_str()) == Some(OPERATION)
}

/// Reverse one hide manifest, in one transaction on `conn` (the caller begins
/// and commits or rolls back). See the module doc's "Reversal".
///
/// # Errors
/// The manifest is malformed, or a statement or invariant fails.
#[allow(clippy::too_many_lines)]
pub async fn reverse_manifest(
    conn: &mut PgConnection,
    m: &super::manifest::Manifest,
    lock_timeout: &str,
) -> anyhow::Result<Unhide> {
    let version = m.header.get("version").and_then(serde_json::Value::as_i64);
    if version != Some(super::manifest::VERSION) {
        bail!(
            "hide manifest version is {version:?}, expected {}",
            super::manifest::VERSION
        );
    }
    let target: Uuid = m
        .header
        .get("target_group_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("hide manifest header has no target_group_id"))
        .and_then(|s| Uuid::parse_str(s).context("target_group_id"))?;
    let specs = evidence_specs(&tables::propagated_tables(conn).await?)?;
    let spec = &specs[0];
    let mut prior: BTreeMap<String, &Record> = BTreeMap::new();
    let mut post: BTreeMap<String, &Record> = BTreeMap::new();
    let mut claim_state: BTreeMap<Uuid, (Uuid, String)> = BTreeMap::new();
    for r in &m.records {
        match (r.table.as_str(), r.after) {
            ("evidence", false) if r.hidden => {
                prior.entry(spec.pk_from_json(&r.id)?).or_insert(r);
            }
            ("evidence", true) if r.hidden => {
                post.insert(spec.pk_from_json(&r.id)?, r);
            }
            ("claims", true) if r.neighbour => {
                claim_state.insert(r.claim_id, (r.owner_group_id, r.visibility.clone()));
            }
            _ => bail!(
                "hide manifest carries an unexpected record: {:?}",
                r.to_json()
            ),
        }
    }
    let mut out = Unhide::default();
    // A row with no post record was never hidden by this run (it rolled back
    // after the prior records were written): nothing to undo.
    let work: Vec<(&String, &Record, &Record)> = prior
        .iter()
        .filter_map(|(pk, p)| post.get(pk).map(|q| (pk, *p, *q)))
        .collect();
    if work.is_empty() {
        return Ok(out);
    }
    sqlx::query("SELECT set_config('lock_timeout', $1, true)")
        .bind(lock_timeout)
        .execute(&mut *conn)
        .await?;
    let claims: Vec<Uuid> = claim_state.keys().copied().collect();
    let locked = tables::fetch_claims(conn, &claims, true).await?;
    let now_claims: BTreeMap<Uuid, (Uuid, String)> = locked
        .iter()
        .map(|c| (c.id, (c.owner, c.visibility.clone())))
        .collect();
    sqlx::query("SELECT id FROM evidence WHERE claim_id = ANY($1) ORDER BY id FOR UPDATE")
        .bind(&claims)
        .execute(&mut *conn)
        .await?;
    let s0 = tables::fetch_attached(conn, &specs, &claims).await?;
    let pinned: BTreeSet<String> = sqlx::query_scalar::<_, Uuid>(
        "SELECT p.evidence_id FROM evidence_visibility_pins p \
           JOIN evidence e ON e.id = p.evidence_id WHERE e.claim_id = ANY($1)",
    )
    .bind(&claims)
    .fetch_all(&mut *conn)
    .await?
    .into_iter()
    .map(|u| u.to_string())
    .collect();
    let mut restore: Vec<(String, &Record)> = Vec::new();
    for (pk, p, q) in &work {
        let key = ("evidence".to_string(), (*pk).clone());
        let Some(a) = s0.get(&key) else {
            out.missing += 1;
            continue;
        };
        let id = Uuid::parse_str(pk).unwrap_or_default();
        let prior_t = Tenancy {
            owner: p.owner_group_id,
            visibility: p.visibility.clone(),
            co_owner: None,
        };
        let post_t = Tenancy {
            owner: q.owner_group_id,
            visibility: q.visibility.clone(),
            co_owner: None,
        };
        let is_pinned = pinned.contains(*pk);
        if a.tenancy == prior_t && !is_pinned {
            out.already += 1;
            continue;
        }
        if a.tenancy != post_t || !is_pinned || q.owner_group_id != target {
            out.held.push((
                id,
                format!(
                    "evidence is {:?} (pinned: {is_pinned}), neither this hide's post state \
                     {:?} pinned nor its prior {:?} unpinned: something changed it since",
                    a.tenancy, post_t, prior_t
                ),
            ));
            continue;
        }
        if claim_state.get(&a.claim) != now_claims.get(&a.claim) {
            out.held.push((
                id,
                format!(
                    "its claim {} is {:?}, not {:?} as at the hide: unhiding now would leave the \
                     row out of step with its claim; reverse the later change first",
                    a.claim,
                    now_claims.get(&a.claim),
                    claim_state.get(&a.claim)
                ),
            ));
            continue;
        }
        restore.push(((*pk).clone(), *p));
    }
    if restore.is_empty() {
        return Ok(out);
    }
    let keys: BTreeSet<RowKey> = s0.keys().cloned().collect();
    let readable_before = tables::app_readable(conn, &specs, &claims, &keys).await?;
    let counters_before = tables::xact_counters(conn).await?;
    let ids: Vec<Uuid> = restore
        .iter()
        .filter_map(|(pk, _)| Uuid::parse_str(pk).ok())
        .collect();
    let unpinned = sqlx::query("DELETE FROM evidence_visibility_pins WHERE evidence_id = ANY($1)")
        .bind(&ids)
        .execute(&mut *conn)
        .await
        .context("DELETE evidence_visibility_pins")?
        .rows_affected();
    let rows: Vec<(String, Tenancy)> = restore
        .iter()
        .map(|(pk, p)| {
            (
                pk.clone(),
                Tenancy {
                    owner: p.owner_group_id,
                    visibility: p.visibility.clone(),
                    co_owner: None,
                },
            )
        })
        .collect();
    let written = tables::write_tenancy(conn, spec, &claims, &rows).await?;
    let s2 = tables::fetch_attached(conn, &specs, &claims).await?;
    let counters_after = tables::xact_counters(conn).await?;
    let readable_after = tables::app_readable(conn, &specs, &claims, &keys).await?;

    let mut v = Vec::new();
    let n = restore.len();
    let n64 = i64::try_from(n).unwrap_or(i64::MAX);
    if usize::try_from(unpinned).ok() != Some(n) || usize::try_from(written).ok() != Some(n) {
        v.push(format!(
            "unpinned {unpinned} and restored {written} row(s), {n} planned"
        ));
    }
    let restored_keys: BTreeSet<RowKey> = restore
        .iter()
        .map(|(pk, _)| ("evidence".to_string(), pk.clone()))
        .collect();
    for (k, a) in &s0 {
        let got = s2.get(k).map(|x| &x.tenancy);
        if let Some((_, p)) = restore.iter().find(|(pk, _)| *pk == k.1) {
            if got.map(|t| (t.owner, t.visibility.as_str()))
                != Some((p.owner_group_id, p.visibility.as_str()))
            {
                v.push(format!(
                    "{} {} ended as {got:?}, not its prior record",
                    k.0, k.1
                ));
            }
        } else if got != Some(&a.tenancy) {
            v.push(format!(
                "{} {} was not reversed and changed {:?} -> {got:?}",
                k.0, k.1, a.tenancy
            ));
        }
    }
    let mut expect: BTreeMap<String, (i64, i64, i64)> = BTreeMap::new();
    expect.insert("evidence".into(), (0, n64, 0));
    expect.insert("evidence_visibility_pins".into(), (0, 0, n64));
    v.extend(super::reown::counter_violations(
        &super::reown::counter_delta(&counters_before, &counters_after),
        &expect,
    ));
    let lost: Vec<&RowKey> = readable_before.difference(&readable_after).collect();
    if !lost.is_empty() {
        v.push(format!(
            "an unstamped epigraph_app session LOST rows: {lost:?}"
        ));
    }
    let gained: BTreeSet<RowKey> = readable_after
        .difference(&readable_before)
        .cloned()
        .collect();
    if !gained.is_subset(&restored_keys) {
        v.push(format!(
            "an unstamped epigraph_app session gained unrestored rows: {:?}",
            gained.difference(&restored_keys).collect::<Vec<_>>()
        ));
    }
    if !v.is_empty() {
        bail!(
            "{} invariant violation(s):\n    - {}",
            v.len(),
            v.join("\n    - ")
        );
    }
    out.restored = n;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operator::tables::Tenancy;

    fn ev(pk: Uuid, t: &str, labels: &[&str], vis: &str) -> Attached {
        Attached {
            table: "evidence".into(),
            pk: pk.to_string(),
            claim: Uuid::nil(),
            claims: BTreeSet::new(),
            tenancy: Tenancy {
                owner: Uuid::nil(),
                visibility: vis.into(),
                co_owner: None,
            },
            writer: None,
            endpoints_public: None,
            shared_outside: false,
            neighbours: BTreeSet::new(),
            evidence_type: Some(t.into()),
            labels: labels.iter().map(|s| (*s).to_string()).collect(),
            preview: Some("line one\nline two".into()),
        }
    }

    #[test]
    fn selectors_are_a_union_and_only_select_evidence() {
        let (a, b, c) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let sel = Selector {
            ids: [a].into(),
            types: ["testimony".to_string()].into(),
            labels: ["private".to_string()].into(),
        };
        assert!(sel.matches(&ev(a, "document", &[], "public")));
        assert!(sel.matches(&ev(b, "testimony", &[], "public")));
        assert!(sel.matches(&ev(c, "document", &["x", "private"], "public")));
        assert!(!sel.matches(&ev(c, "document", &["x"], "public")));
        let mut not_ev = ev(a, "document", &[], "public");
        not_ev.table = "triples".into();
        assert!(!sel.matches(&not_ev));
    }

    #[test]
    fn an_unknown_type_is_refused() {
        let args = HideArgs {
            hide_evidence_type: vec!["rumour".into()],
            ..Default::default()
        };
        assert!(Selector::from_args(&args).is_err());
    }

    #[test]
    fn the_confirm_count_policy_and_guard_refusals_come_in_order() {
        let p = Plan {
            rows: vec![ev(Uuid::new_v4(), "document", &[], "public")],
            ..Default::default()
        };
        let none = GuardStatus {
            pin_table: false,
            propagate_arm_pinned: false,
            inherit_arm_pinned: false,
        };
        let mut a = HideArgs::default();
        let e = refuse_apply(&p, &a, &[], none).unwrap_err().to_string();
        assert!(e.contains("requires --confirm-hide 1"), "{e}");
        a.confirm_hide = Some(2);
        let e = refuse_apply(&p, &a, &[], none).unwrap_err().to_string();
        assert!(e.contains("does not match"), "{e}");
        a.confirm_hide = Some(1);
        let pol = vec!["evidence_privacy".to_string()];
        let e = refuse_apply(&p, &a, &pol, none).unwrap_err().to_string();
        assert!(e.contains("--accept-unenforced-hide"), "{e}");
        a.accept_unenforced_hide = true;
        let e = refuse_apply(&p, &a, &pol, none).unwrap_err().to_string();
        assert!(e.contains("kernel guard") && e.contains("110"), "{e}");
        let full = GuardStatus {
            pin_table: true,
            propagate_arm_pinned: true,
            inherit_arm_pinned: true,
        };
        assert!(refuse_apply(&p, &a, &pol, full).is_ok());
        assert!(refuse_hide_in_reown()
            .unwrap_err()
            .to_string()
            .contains("hide-evidence --apply"));
    }

    #[test]
    fn the_preview_is_eighty_characters_on_one_line() {
        assert_eq!(preview(Some("a\nb")), "a b");
        assert_eq!(preview(Some(&"x".repeat(200))).chars().count(), 80);
        assert_eq!(preview(None), "(no raw_content)");
    }
}
