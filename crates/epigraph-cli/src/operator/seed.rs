//! `reown-seed`: move claims that migration 074's seed escape hatch stamped
//! onto the memberless seed group to the owner their author's declaration
//! gives them (backlog 0512ca33).
//!
//! # Why these rows exist
//!
//! Until migration 113 the seed arm of `epigraph_claims_require_tenancy` fired
//! for ANY superuser session (`pg_has_role` implies every role for a
//! superuser), so an undeclared claim written over a superuser DSN was stamped
//! `('public', 00000000-0000-0000-0000-00000000dead)`. Its claim-derived rows
//! (evidence, …) inherited the same owner. The seed group has no members by
//! design: while such a row is public it is merely mis-attributed, and the day
//! it is privatised nobody can read it.
//!
//! # The derived owner
//!
//! For each seed-owned claim, from its author (`claims.agent_id`):
//!
//! 1. the author has an `operator_links` row (retired or acting) →
//!    the OPERATOR's personal group (creator-tested, as `reown-claims` takes
//!    it); else
//! 2. the author's OWN personal group (`kind = 'personal'`, created by the
//!    author), provided the author still holds a LIVE membership there; else
//! 3. no owner: the claim is HELD with the reason. Nothing is provisioned — a
//!    repair tool that minted groups would be a second, unreviewed path to the
//!    personal-group mint (`personal_group_mint_ratchet.rs`).
//!
//! Rule 1 reads `epigraph_operator_of_author` (the "whose are this author's
//! claims?" read, retired links included), NOT `epigraph_operator_actor`, the
//! read migration 113's superuser arm and `default_decl_for_author` use to
//! decide where a NEW write lands. Those answer different questions on
//! purpose: a retired identity may not author into its operator's group (it
//! holds no membership there), but what it already wrote is the operator's
//! (107 section 7), which is the rule `reown-claims` and the ownership gate's
//! target side apply. A repair of ownership asks the ownership question.
//!
//! # How the move is made
//!
//! By `reown`'s batch machinery, unchanged, with [`super::reown::Rule::Seed`]
//! as the eligibility test: every claim listed (or, with no list, every claim
//! the seed group owns) is grouped by its derived owner, and each group is one
//! `reown-claims`-shaped run with that owner as its target — locks, re-classify
//! under the lock (a claim whose derived owner changed since the plan is
//! HELD), manifest recorded and fsynced first, one `UPDATE claims`, and every
//! invariant (only public rows move, visibility never changes, nothing outside
//! the set is written, nothing becomes less readable to an unstamped
//! application session). Derived rows always FOLLOW the claim: they inherited
//! the seed group from it, so keeping them there would keep the defect.
//!
//! # Manifests and reversal
//!
//! One manifest per target group, `<manifest-dir>/reown-seed-<target>.jsonl`,
//! each an ordinary version-2 re-own manifest (`reown-reverse` takes them all
//! in one invocation and restores every row to the seed group). A single
//! manifest cannot carry two targets: reversal's compare-and-swap is keyed on
//! the one `target_group_id` its header names.
//!
//! # What it does not touch
//!
//! Rows owned by the seed group that no seed-owned claim carries — the six
//! root tables, which have no author to derive from, and any derived row whose
//! claim is owned elsewhere — are COUNTED in the report and left alone.

use super::manifest::{Sink, Writer};
use super::reown::{
    classify, records_for, run_batch, tally, Caches, Classified, Ctx, DerivedMode, Hold, Known,
    Rule, RunReport,
};
use super::tables::{self, fetch_claims};
use super::{authors_personal_group, operator_group, operator_of_author, SEED};
use anyhow::{bail, Context};
use epigraph_db::repos::OperatorRepairRepository;
use epigraph_db::GroupMembershipRepository;
use serde_json::json;
use sqlx::PgConnection;
use std::collections::BTreeMap;
use std::path::PathBuf;
use uuid::Uuid;

/// Everything `reown-seed` was told.
#[derive(Clone, Debug)]
pub struct Options {
    /// The claims to consider. `None`: every claim the seed group owns.
    pub claims: Option<Vec<Uuid>>,
    /// Where the per-target manifests go. Must exist; each file must not.
    pub manifest_dir: PathBuf,
    pub apply: bool,
    pub batch_size: usize,
    pub lock_timeout: String,
}

/// The owner `author`'s claims belong to (see the module doc), or why there
/// is none. A read failure is an `Err` of the outer result.
///
/// # Errors
/// A read fails.
pub async fn derive_owner(
    conn: &mut PgConnection,
    author: Uuid,
) -> anyhow::Result<Result<Uuid, String>> {
    if let Some(op) = operator_of_author(conn, author).await? {
        return Ok(operator_group(conn, op)
            .await
            .map_err(|e| format!("linked to operator {op}, whose group is unusable: {e:#}")));
    }
    let Some(personal) = authors_personal_group(conn, author).await? else {
        return Ok(Err(
            "the author has no personal group of its own (none, or a squatted did); reown-seed \
             never provisions one"
                .into(),
        ));
    };
    let live = GroupMembershipRepository::get_member_role_conn(conn, personal, author)
        .await
        .context("reading the author's membership")?;
    if live.is_none() {
        return Ok(Err(format!(
            "the author holds no live membership in its personal group {personal} (revoked); the \
             application path refuses its writes (RVK01), so this tool does not choose for it"
        )));
    }
    Ok(Ok(personal))
}

/// [`derive_owner`] through `caches.derived`.
///
/// # Errors
/// A read fails.
pub async fn derive_owner_cached(
    conn: &mut PgConnection,
    author: Uuid,
    caches: &mut Caches,
) -> anyhow::Result<Result<Uuid, String>> {
    if let Some(v) = caches.derived.get(&author) {
        return Ok(v.clone());
    }
    let v = derive_owner(conn, author).await?;
    caches.derived.insert(author, v.clone());
    Ok(v)
}

/// What the whole run did.
#[derive(Default, Debug)]
pub struct Report {
    pub requested: usize,
    /// Claims held before any target was chosen (not found, not seed-owned,
    /// no derivable owner).
    pub held: Vec<(Uuid, Hold)>,
    /// Per target group: that run's report.
    pub per_target: BTreeMap<Uuid, RunReport>,
    /// Manifests written (under `--apply`).
    pub manifests: Vec<PathBuf>,
    /// Seed-owned rows per tier-A table before the run.
    pub seed_owned_before: Vec<(String, i64)>,
}

impl Report {
    #[must_use]
    pub fn claims_moved(&self) -> usize {
        self.per_target.values().map(|r| r.claims_moved).sum()
    }

    #[must_use]
    pub fn batch_failures(&self) -> usize {
        self.per_target
            .values()
            .map(|r| r.batch_failures.len())
            .sum()
    }
}

fn manifest_path(dir: &std::path::Path, target: Uuid) -> PathBuf {
    dir.join(format!("reown-seed-{target}.jsonl"))
}

/// Plan, then run each target group's batches.
///
/// # Errors
/// A failure outside a batch (planning, a manifest, the connection).
#[allow(clippy::too_many_lines)]
pub async fn run(
    conn: &mut PgConnection,
    opts: &Options,
    out: &mut dyn std::io::Write,
) -> anyhow::Result<Report> {
    if opts.batch_size == 0 {
        bail!("--batch-size must be at least 1");
    }
    if !opts.manifest_dir.is_dir() {
        bail!(
            "--manifest-dir {} is not an existing directory",
            opts.manifest_dir.display()
        );
    }
    let specs = tables::propagated_tables(conn).await?;
    let unkeyed = tables::unkeyed_tables(conn, &specs).await?;
    tables::probe_session_switch(conn).await?;

    let mut report = Report {
        seed_owned_before: OperatorRepairRepository::count_owned_by_per_table_conn(conn, SEED)
            .await?,
        ..Default::default()
    };
    let requested = match &opts.claims {
        Some(ids) => ids.clone(),
        None => OperatorRepairRepository::claim_ids_owned_by_conn(conn, SEED).await?,
    };
    report.requested = requested.len();

    writeln!(
        out,
        "reown-seed: seed_group={SEED} selection={} mode={}",
        if opts.claims.is_some() {
            "--claims-file"
        } else {
            "every seed-owned claim"
        },
        if opts.apply { "APPLY" } else { "DRY-RUN" }
    )?;
    for (t, n) in &report.seed_owned_before {
        writeln!(out, "SEED-OWNED\t{t}\t{n}")?;
    }

    // ---- derive a target per claim ----
    let mut caches = Caches::default();
    let mut by_target: BTreeMap<Uuid, Vec<Uuid>> = BTreeMap::new();
    for chunk in requested.chunks(opts.batch_size) {
        let rows = fetch_claims(conn, chunk, false).await?;
        let by_id: BTreeMap<Uuid, _> = rows.iter().map(|r| (r.id, r)).collect();
        for id in chunk {
            let Some(c) = by_id.get(id) else {
                report.held.push((*id, Hold::NotFound));
                continue;
            };
            if c.owner != SEED {
                report
                    .held
                    .push((*id, Hold::NotSeedOwned { owner: c.owner }));
                continue;
            }
            match derive_owner_cached(conn, c.author, &mut caches).await? {
                Ok(t) => by_target.entry(t).or_default().push(*id),
                Err(reason) => report.held.push((
                    *id,
                    Hold::NoDerivedOwner {
                        author: c.author,
                        reason,
                    },
                )),
            }
        }
    }
    writeln!(
        out,
        "PLAN: {} requested, {} held before targeting, {} target group(s)",
        requested.len(),
        report.held.len(),
        by_target.len()
    )?;
    for (id, h) in &report.held {
        writeln!(out, "HELD\t{id}\t{h}")?;
    }
    for (t, ids) in &by_target {
        writeln!(out, "TARGET\t{t}\t{} claim(s)", ids.len())?;
    }

    // ---- one reown-shaped run per target ----
    let mut last_created: Option<chrono::DateTime<chrono::Utc>> = None;
    for (target, ids) in &by_target {
        let mut rep = RunReport {
            requested: ids.len(),
            ..Default::default()
        };
        let mut plan = Classified::default();
        for chunk in ids.chunks(opts.batch_size) {
            let rows = fetch_claims(conn, chunk, false).await?;
            let c = classify(conn, &specs, chunk, &rows, Rule::Seed, *target, &mut caches).await?;
            plan.eligible.extend(c.eligible);
            plan.held.extend(c.held);
            plan.already.extend(c.already);
            plan.attached.extend(c.attached);
        }
        rep.plan_eligible = plan.eligible.len();
        rep.plan_already = plan.already.len();
        rep.plan_held.clone_from(&plan.held);
        for (t, _) in plan.attached.keys() {
            *rep.plan_attached_by_table.entry(t.clone()).or_default() += 1;
        }
        writeln!(
            out,
            "TARGET {target}: {} eligible, {} held",
            plan.eligible.len(),
            plan.held.len()
        )?;
        for (id, h) in &plan.held {
            writeln!(out, "HELD\t{id}\t{h}")?;
        }
        for (t, n) in &rep.plan_attached_by_table {
            writeln!(out, "PLAN-ROWS\t{target}\t{t}\t{n}")?;
        }
        if plan.eligible.is_empty() {
            report.per_target.insert(*target, rep);
            continue;
        }

        let path = manifest_path(&opts.manifest_dir, *target);
        let mut sink = if opts.apply {
            // Strictly increasing `created_at` across this run's manifests:
            // `reown-reverse` orders manifests by it and refuses a tie.
            let mut now = chrono::Utc::now();
            if let Some(prev) = last_created {
                if now <= prev {
                    now = prev + chrono::Duration::microseconds(1);
                }
            }
            last_created = Some(now);
            let header = json!({
                "manifest": "epigraph-operator reown-seed",
                "version": super::manifest::VERSION,
                "seed_group_id": SEED,
                "target_group_id": target,
                "derived": DerivedMode::FollowClaim.as_str(),
                "created_at": now.to_rfc3339(),
            });
            let mut w = Writer::create_new(&path, &header)?;
            w.append(&records_for(&plan.eligible, &plan.attached, &specs))?;
            report.manifests.push(path.clone());
            Sink::File(w)
        } else {
            let mut s = Sink::Memory(Default::default(), 0);
            s.record(&records_for(&plan.eligible, &plan.attached, &specs))?;
            s
        };
        writeln!(
            out,
            "MANIFEST\t{}\t{} row record(s){}",
            path.display(),
            sink.len(),
            if opts.apply {
                " written and fsynced before any write"
            } else {
                " (dry run: not written)"
            }
        )?;

        let ctx = Ctx {
            specs: &specs,
            unkeyed: &unkeyed,
            rule: Rule::Seed,
            target: *target,
            mode: DerivedMode::FollowClaim,
            lock_timeout: &opts.lock_timeout,
        };
        let mut known = Known::from_plan(&plan);
        let eligible: Vec<Uuid> = plan.eligible.iter().map(|c| c.id).collect();
        let batches: Vec<&[Uuid]> = eligible.chunks(opts.batch_size).collect();
        let total = batches.len();
        for (i, batch) in batches.iter().enumerate() {
            let mut tx = sqlx::Connection::begin(&mut *conn).await?;
            let r = run_batch(&mut tx, &ctx, batch, &mut sink, &mut caches, &known).await;
            let ok = r.is_ok();
            if opts.apply && ok {
                tx.commit().await?;
                if let Ok(b) = &r {
                    known.commit(b);
                }
            } else {
                tx.rollback().await?;
            }
            if !tally(&mut rep, out, i + 1, total, r, opts.apply)? {
                break;
            }
        }
        rep.manifest_rows = sink.len();
        for (id, h) in &rep.held_under_lock {
            writeln!(out, "HELD-UNDER-LOCK\t{id}\t{h}")?;
        }
        let stop = opts.apply && !rep.batch_failures.is_empty();
        report.per_target.insert(*target, rep);
        if stop {
            writeln!(out, "STOPPED: no further target group was attempted")?;
            break;
        }
    }

    writeln!(out, "RESULT")?;
    writeln!(
        out,
        "  claims moved off the seed group: {}",
        report.claims_moved()
    )?;
    let mut moved: BTreeMap<&String, usize> = BTreeMap::new();
    for r in report.per_target.values() {
        for (t, n) in &r.moved_by_table {
            *moved.entry(t).or_default() += n;
        }
    }
    for (t, n) in moved {
        writeln!(out, "  {t}: rows moved: {n}, all public before and after")?;
    }
    writeln!(
        out,
        "  invariants: {}",
        if report.batch_failures() == 0 {
            "all held in every batch".to_string()
        } else {
            format!(
                "{} batch(es) violated and were rolled back",
                report.batch_failures()
            )
        }
    )?;
    if opts.apply {
        if !report.manifests.is_empty() {
            let args: Vec<String> = report
                .manifests
                .iter()
                .map(|p| format!("--manifest {}", p.display()))
                .collect();
            writeln!(
                out,
                "UNDO: epigraph-operator reown-reverse {} --apply",
                args.join(" ")
            )?;
        }
    } else {
        writeln!(
            out,
            "DRY RUN: each batch above ran in its own transaction and was rolled back; no manifest \
             was written."
        )?;
    }
    writeln!(
        out,
        "NOT TOUCHED: seed-owned rows no seed-owned claim carries (root tables, or derived rows \
         of a claim owned elsewhere) stay where they are; the SEED-OWNED lines above count them \
         with the claims' own rows."
    )?;
    Ok(report)
}
