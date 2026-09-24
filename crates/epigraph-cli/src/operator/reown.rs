//! `reown-claims`: move an explicit list of claims into the operator's personal
//! group.
//!
//! # What is eligible
//!
//! Only the claim ids in the file, and of those only a claim whose
//!
//! 1. author has an `operator_links` row (retired or actor) naming
//!    `--operator` — read through `epigraph_operator_of_author`, the ownership
//!    gate's own TARGET-side read;
//! 2. current owner is the `world` group or the author's OWN personal group (a
//!    `kind = 'personal'` group the author itself created — the creator test
//!    branch A applies to operator groups, so a squatted group does not count);
//! 3. every row it would carry with it is `public`: the claim, every row of
//!    every table `epigraph_propagate_tenancy` cascades to, every harvester
//!    fragment it is the provenance of, and every edge touching it, including
//!    that edge's other endpoint.
//!
//! Every other listed claim is HELD, reported with its reason, and never
//! written. Rule 3 is the operator's 2026-09-23 directive: the trigger copies
//! the claim's `(owner_group_id, visibility)` onto every derived row, so moving
//! a claim with a group-private derived row would either widen that row to
//! public or move it out of the one group that can read it. A re-own must never
//! make anything less visible to anyone, and under rule 3 it cannot: every row
//! it touches is public before and after, and a public row is readable through
//! every tenancy policy's `visibility = 'public'` arm whoever owns it.
//!
//! # `--derived`
//!
//! Required, with no default, because it is a policy decision:
//!
//! * `follow-claim`: every derived row takes the new owner (what the trigger
//!   does on its own).
//! * `keep-writer`: a derived row whose WRITER is not linked to the operator
//!   keeps the owner it had. The trigger moves it; this module puts it back in
//!   the same transaction.
//!
//! A table with no writer column, or a row whose writer is NULL, FOLLOWS the
//! claim in both modes (see `tables::WRITER_COLUMNS`). Edges take the trigger's
//! meet of their endpoints, which for two public endpoints is `world`.
//!
//! KEEP-WRITER IS NOT DURABLE ON ITS OWN. Migration 070's insert arm
//! (`epigraph_inherit_tenancy_stmt`) re-syncs EVERY row of a table to its claim
//! whenever a new row for that claim is inserted into that table. A kept row
//! therefore takes the claim's (new) owner the next time anything writes a
//! derived row of the same kind for the same claim. It stays public either way.
//!
//! # Each batch is one transaction, and checks itself before committing
//!
//! `SET LOCAL lock_timeout`; `SELECT ... FOR UPDATE` on the batch's claims (a
//! derived-row INSERT takes `FOR KEY SHARE` on its parent claim through the
//! foreign key, which that lock blocks); `LOCK TABLE ... IN SHARE ROW
//! EXCLUSIVE MODE` on every cascade table whose `claim_id` has NO such key
//! (`tables::unkeyed_tables`, read from `pg_constraint` at run time — review
//! measured three), because the row lock does not exclude an INSERT there; so
//! no derived row can appear mid-batch in any cascade table. Then re-classify
//! under the locks; record any row the plan had not seen in the manifest
//! (fsynced) BEFORE writing; then one `UPDATE claims`, the keep-writer
//! restores, and the invariants. Any violation rolls the batch back.
//!
//! `edges` is not locked: its tenancy trigger (`epigraph_edges_tenancy`, 070/072)
//! is a BEFORE row trigger that sets only the NEW row, from its endpoints, and
//! for two public endpoints (the only kind this tool moves) the result is
//! `(world, public)` whoever owns the claims — a concurrent edge INSERT can
//! neither land stale nor rewrite a moved row.
//!
//! The invariants:
//!
//! * every claim is owned by the target and its visibility is unchanged;
//! * every touched row's visibility is unchanged, and it is `public`;
//! * every touched row is in exactly the state the plan predicted, so the rows
//!   moved per table equal the rows planned;
//! * NO ROW OUTSIDE THE SET CHANGED: `pg_stat_xact_user_tables` counts every
//!   row this transaction inserted, updated or deleted in every table,
//!   including rows a trigger wrote. The delta must equal exactly the claims
//!   updated, the rows the trigger was observed to change, and the rows this
//!   module restored — and zero in every other table;
//! * the set of these rows an UNSTAMPED `epigraph_app` session can read (under
//!   `SET LOCAL SESSION AUTHORIZATION`, the switch `epigraph_bypass()` cannot
//!   be fooled by) is identical before and after, compared by key.
//!
//! A re-run skips a claim its target already owns, so an interrupted run
//! resumes where it stopped.
//!
//! # What this cannot restore
//!
//! `claims.updated_at` is stamped `now()` by `claims_updated_at` (migration
//! 001, an unconditional `BEFORE UPDATE` trigger) on the re-own and again on
//! the reversal. It is the one column neither this module nor
//! `reown-reverse` can put back.

use super::manifest::{Record, Sink, Writer};
use super::tables::{
    self, app_readable, fetch_attached, fetch_claims, refetch_tenancy, write_tenancy,
    writer_is_linked, xact_counters, Attached, ClaimRow, Kind, RowKey, Snapshot, TableSpec,
    Tenancy,
};
use super::{authors_personal_group, operator_group, operator_of_author, owner_is_takeable, WORLD};
use anyhow::{bail, Context};
use serde_json::json;
use sqlx::PgConnection;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::PathBuf;
use uuid::Uuid;

/// `--derived`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum DerivedMode {
    /// Every derived row takes the claim's new owner.
    FollowClaim,
    /// A derived row written by an agent not linked to the operator keeps its
    /// owner.
    KeepWriter,
}

impl DerivedMode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FollowClaim => "follow-claim",
            Self::KeepWriter => "keep-writer",
        }
    }
}

/// Everything `reown-claims` was told.
#[derive(Clone, Debug)]
pub struct Options {
    pub operator: Uuid,
    pub mode: DerivedMode,
    pub manifest_out: PathBuf,
    pub apply: bool,
    pub batch_size: usize,
    pub lock_timeout: String,
    /// The opt-in hide flags (Amendment 2). With no selector set the run is
    /// exactly the Amendment 1 re-own.
    pub hide: super::hide::HideArgs,
}

/// Why a listed claim is not moved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Hold {
    NotFound,
    AuthorNotLinked {
        author: Uuid,
        operator: Option<Uuid>,
    },
    OwnerNotEligible {
        owner: Uuid,
    },
    ClaimNotPublic {
        visibility: String,
    },
    RowsNotPublic {
        by_table: BTreeMap<String, usize>,
    },
    EdgeEndpointNotPublic {
        edges: usize,
    },
    /// A row (or the claim) is not in the state this run last knew it in —
    /// the plan's reading, or an earlier batch's result — so another writer
    /// changed it after the plan recorded its prior state.
    ChangedSincePlan {
        table: String,
        id: String,
    },
}

impl fmt::Display for Hold {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => write!(f, "not found"),
            Self::AuthorNotLinked { author, operator } => match operator {
                Some(o) => write!(f, "author {author} is linked to a different operator ({o})"),
                None => write!(f, "author {author} has no operator link"),
            },
            Self::OwnerNotEligible { owner } => write!(
                f,
                "owned by group {owner}, which is neither world nor the author's own personal group"
            ),
            Self::ClaimNotPublic { visibility } => {
                write!(f, "claim visibility is {visibility}, not public")
            }
            Self::RowsNotPublic { by_table } => {
                write!(f, "non-public rows would move with it:")?;
                for (t, n) in by_table {
                    write!(f, " {t}={n}")?;
                }
                Ok(())
            }
            Self::EdgeEndpointNotPublic { edges } => write!(
                f,
                "{edges} edge(s) touching it have a non-public endpoint, so the trigger's meet \
                 would change their visibility"
            ),
            Self::ChangedSincePlan { table, id } => write!(
                f,
                "{table} {id} changed since the plan recorded it (another writer); its recorded \
                 prior state would be stale, so the claim is not moved in this run"
            ),
        }
    }
}

/// A classification of some claims.
#[derive(Default, Debug)]
pub struct Classified {
    pub eligible: Vec<ClaimRow>,
    pub held: Vec<(Uuid, Hold)>,
    pub already: Vec<Uuid>,
    /// Attached rows of the ELIGIBLE claims only.
    pub attached: Snapshot,
}

/// Caches for the per-agent reads.
#[derive(Default)]
pub struct Caches {
    pub operator_of: BTreeMap<Uuid, Option<Uuid>>,
    pub personal: BTreeMap<Uuid, Option<Uuid>>,
    pub linked_writer: BTreeMap<Uuid, bool>,
}

/// The state this run last knew each row and claim to be in: the plan's
/// reading, then each COMMITTED batch's post-state.
///
/// The manifest records a row's prior state once, at the plan (records are
/// de-duplicated by key). A row another writer changes between the plan and
/// its batch would therefore keep a STALE prior record, and a reversal would
/// restore the stale owner (review finding). So each batch compares what it
/// finds under the lock with this map and HOLDS every claim a changed row
/// hangs off. A change made by THIS run's earlier batch (a shared edge or
/// fragment) is expected, not a change: committed batches write their
/// post-state here. A dry run never does, because it rolls every batch back.
#[derive(Default, Debug)]
pub struct Known {
    pub claims: BTreeMap<Uuid, (Uuid, String)>,
    pub rows: BTreeMap<RowKey, Tenancy>,
}

impl Known {
    /// Seed from the plan.
    #[must_use]
    pub fn from_plan(plan: &Classified) -> Self {
        Self {
            claims: plan
                .eligible
                .iter()
                .map(|c| (c.id, (c.owner, c.visibility.clone())))
                .collect(),
            rows: plan
                .attached
                .iter()
                .map(|(k, a)| (k.clone(), a.tenancy.clone()))
                .collect(),
        }
    }

    /// Record a committed batch's result.
    pub fn commit(&mut self, b: &BatchOutcome) {
        for (id, st) in &b.post_claims {
            self.claims.insert(*id, st.clone());
        }
        for (k, t) in &b.post_rows {
            self.rows.insert(k.clone(), t.clone());
        }
    }
}

/// Classify the claims named by `requested`, whose current rows are `rows`.
///
/// # Errors
/// A read fails.
pub async fn classify(
    conn: &mut PgConnection,
    specs: &[TableSpec],
    requested: &[Uuid],
    rows: &[ClaimRow],
    operator: Uuid,
    target: Uuid,
    caches: &mut Caches,
) -> anyhow::Result<Classified> {
    let by_id: BTreeMap<Uuid, &ClaimRow> = rows.iter().map(|r| (r.id, r)).collect();
    let mut out = Classified::default();
    let mut candidates: Vec<ClaimRow> = Vec::new();
    for id in requested {
        let Some(c) = by_id.get(id) else {
            out.held.push((*id, Hold::NotFound));
            continue;
        };
        if c.owner == target {
            out.already.push(c.id);
            continue;
        }
        let op = match caches.operator_of.get(&c.author) {
            Some(v) => *v,
            None => {
                let v = operator_of_author(conn, c.author).await?;
                caches.operator_of.insert(c.author, v);
                v
            }
        };
        if op != Some(operator) {
            out.held.push((
                c.id,
                Hold::AuthorNotLinked {
                    author: c.author,
                    operator: op,
                },
            ));
            continue;
        }
        let personal = match caches.personal.get(&c.author) {
            Some(v) => *v,
            None => {
                let v = authors_personal_group(conn, c.author).await?;
                caches.personal.insert(c.author, v);
                v
            }
        };
        if !owner_is_takeable(c.owner, personal) {
            out.held
                .push((c.id, Hold::OwnerNotEligible { owner: c.owner }));
            continue;
        }
        if c.visibility != "public" {
            out.held.push((
                c.id,
                Hold::ClaimNotPublic {
                    visibility: c.visibility.clone(),
                },
            ));
            continue;
        }
        candidates.push((*c).clone());
    }
    if candidates.is_empty() {
        return Ok(out);
    }
    let ids: Vec<Uuid> = candidates.iter().map(|c| c.id).collect();
    let attached = fetch_attached(conn, specs, &ids).await?;
    let mut bad_rows: BTreeMap<Uuid, BTreeMap<String, usize>> = BTreeMap::new();
    let mut bad_edges: BTreeMap<Uuid, usize> = BTreeMap::new();
    for a in attached.values() {
        for claim in &a.claims {
            if a.tenancy.visibility != "public" {
                *bad_rows
                    .entry(*claim)
                    .or_default()
                    .entry(a.table.clone())
                    .or_default() += 1;
            } else if a.endpoints_public == Some(false) {
                *bad_edges.entry(*claim).or_default() += 1;
            }
        }
    }
    let mut eligible_ids = BTreeSet::new();
    for c in candidates {
        if let Some(by_table) = bad_rows.remove(&c.id) {
            out.held.push((c.id, Hold::RowsNotPublic { by_table }));
        } else if let Some(edges) = bad_edges.remove(&c.id) {
            out.held.push((c.id, Hold::EdgeEndpointNotPublic { edges }));
        } else {
            eligible_ids.insert(c.id);
            out.eligible.push(c);
        }
    }
    out.attached = attached
        .into_iter()
        .filter(|(_, a)| a.claims.iter().any(|c| eligible_ids.contains(c)))
        .collect();
    Ok(out)
}

fn spec_of<'a>(specs: &'a [TableSpec], table: &str) -> &'a TableSpec {
    tables::spec(specs, table).expect("attached rows come only from specs")
}

/// The state a row must be in after the re-own.
fn expected(a: &Attached, specs: &[TableSpec], target: Uuid, keep: &BTreeSet<RowKey>) -> Tenancy {
    if keep.contains(&(a.table.clone(), a.pk.clone())) {
        return a.tenancy.clone();
    }
    match spec_of(specs, &a.table).kind {
        // The trigger's meet of two public endpoints.
        Kind::Edges => Tenancy {
            owner: WORLD,
            visibility: "public".into(),
            co_owner: None,
        },
        _ => Tenancy {
            owner: target,
            visibility: "public".into(),
            co_owner: None,
        },
    }
}

/// The rows `--derived keep-writer` leaves on their prior owner: a writer
/// column, a non-NULL writer, and that writer not linked to the operator.
async fn kept_rows(
    conn: &mut PgConnection,
    attached: &Snapshot,
    mode: DerivedMode,
    operator: Uuid,
    caches: &mut Caches,
) -> anyhow::Result<BTreeSet<RowKey>> {
    let mut out = BTreeSet::new();
    if mode != DerivedMode::KeepWriter {
        return Ok(out);
    }
    for (k, a) in attached {
        if let Some(w) = a.writer {
            if !writer_is_linked(conn, &mut caches.linked_writer, w, operator).await? {
                out.insert(k.clone());
            }
        }
    }
    Ok(out)
}

/// Rows written by an agent NOT linked to the operator, per table and per
/// writer — the rows that in `follow-claim` mode land in the operator's group
/// although neither the operator nor its agents wrote them.
#[derive(Default, Debug)]
pub struct Spill {
    pub by_table: BTreeMap<String, usize>,
    pub by_writer: BTreeMap<Uuid, usize>,
    /// Rows with no writer of record (no writer column, or NULL), per table.
    pub unattributed: BTreeMap<String, usize>,
    /// Fragments that are also the provenance of a claim not being moved.
    pub shared_fragments: usize,
    /// Per eligible claim: edges whose OTHER endpoint is a claim that is not
    /// moving (held, or not listed). The trigger recomputes their owner as
    /// the meet, so a held claim's neighbourhood is rewritten too.
    pub neighbour_edges: BTreeMap<Uuid, usize>,
}

async fn spill(
    conn: &mut PgConnection,
    attached: &Snapshot,
    eligible: &BTreeSet<Uuid>,
    operator: Uuid,
    caches: &mut Caches,
) -> anyhow::Result<Spill> {
    let mut s = Spill::default();
    for a in attached.values() {
        if a.shared_outside {
            s.shared_fragments += 1;
        }
        if a.table == "edges"
            && a.claims
                .iter()
                .chain(a.neighbours.iter())
                .any(|c| !eligible.contains(c))
        {
            for c in a.claims.intersection(eligible) {
                *s.neighbour_edges.entry(*c).or_default() += 1;
            }
        }
        match a.writer {
            Some(w) => {
                if !writer_is_linked(conn, &mut caches.linked_writer, w, operator).await? {
                    *s.by_table.entry(a.table.clone()).or_default() += 1;
                    *s.by_writer.entry(w).or_default() += 1;
                }
            }
            None => {
                *s.unattributed.entry(a.table.clone()).or_default() += 1;
            }
        }
    }
    Ok(s)
}

/// Manifest records for claims and their attached rows.
#[must_use]
pub fn records_for(claims: &[ClaimRow], attached: &Snapshot, specs: &[TableSpec]) -> Vec<Record> {
    let mut out = Vec::with_capacity(claims.len() + attached.len());
    for c in claims {
        out.push(Record {
            table: "claims".into(),
            id: json!(c.id.to_string()),
            owner_group_id: c.owner,
            visibility: c.visibility.clone(),
            co_owner_group_id: None,
            claim_id: c.id,
            hidden: false,
            after: false,
            neighbour: false,
        });
    }
    for a in attached.values() {
        let spec = spec_of(specs, &a.table);
        out.push(Record {
            table: a.table.clone(),
            id: spec.id_json(&a.pk),
            owner_group_id: a.tenancy.owner,
            visibility: a.tenancy.visibility.clone(),
            co_owner_group_id: (spec.kind == Kind::Edges).then_some(a.tenancy.co_owner),
            claim_id: a.claim,
            hidden: false,
            after: false,
            neighbour: false,
        });
    }
    out
}

/// Every claim a checked row hangs off that this batch did NOT move: the
/// fragment's other provenance claims, the edge's other claim endpoint, and a
/// claim of the batch itself that was held.
fn neighbours_of(s0: &Snapshot, moved: &BTreeSet<Uuid>) -> Vec<Uuid> {
    let mut out = BTreeSet::new();
    for a in s0.values() {
        for c in a.claims.iter().chain(a.neighbours.iter()) {
            if !moved.contains(c) {
                out.insert(*c);
            }
        }
    }
    out.into_iter().collect()
}

/// POST-state records for a batch that is about to commit: every moved claim,
/// every row the batch checked (in the state the batch left it in), and every
/// NEIGHBOUR claim's current state (see `manifest`'s module doc).
fn post_records_for(
    claims: &[ClaimRow],
    s0: &Snapshot,
    s2: &BTreeMap<RowKey, Tenancy>,
    neighbours: &[ClaimRow],
    specs: &[TableSpec],
) -> Vec<Record> {
    let mut out = Vec::with_capacity(claims.len() + s2.len() + neighbours.len());
    for n in neighbours {
        out.push(Record {
            table: "claims".into(),
            id: json!(n.id.to_string()),
            owner_group_id: n.owner,
            visibility: n.visibility.clone(),
            co_owner_group_id: None,
            claim_id: n.id,
            hidden: false,
            after: true,
            neighbour: true,
        });
    }
    for c in claims {
        out.push(Record {
            table: "claims".into(),
            id: json!(c.id.to_string()),
            owner_group_id: c.owner,
            visibility: c.visibility.clone(),
            co_owner_group_id: None,
            claim_id: c.id,
            hidden: false,
            after: true,
            neighbour: false,
        });
    }
    for (k, t) in s2 {
        let spec = spec_of(specs, &k.0);
        out.push(Record {
            table: k.0.clone(),
            id: spec.id_json(&k.1),
            owner_group_id: t.owner,
            visibility: t.visibility.clone(),
            co_owner_group_id: (spec.kind == Kind::Edges).then_some(t.co_owner),
            claim_id: s0.get(k).map_or(Uuid::nil(), |a| a.claim),
            hidden: false,
            after: true,
            neighbour: false,
        });
    }
    out
}

/// What one batch did.
#[derive(Default, Debug)]
pub struct BatchOutcome {
    pub claims_moved: usize,
    pub moved_by_table: BTreeMap<String, usize>,
    pub kept_by_table: BTreeMap<String, usize>,
    pub held: Vec<(Uuid, Hold)>,
    pub already: Vec<Uuid>,
    pub newly_recorded: usize,
    /// The moved claims' `(owner, visibility)` after the batch.
    pub post_claims: Vec<(Uuid, (Uuid, String))>,
    /// Every row the batch checked, in its state after the batch.
    pub post_rows: BTreeMap<RowKey, Tenancy>,
}

/// A batch that must not commit.
#[derive(Debug)]
pub enum BatchError {
    /// The batch ran and an invariant failed; each string is one violation.
    Invariant(Vec<String>),
    /// A statement failed (including a lock timeout).
    Db(anyhow::Error),
}

impl fmt::Display for BatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invariant(v) => {
                write!(f, "{} invariant violation(s):", v.len())?;
                for x in v {
                    write!(f, "\n    - {x}")?;
                }
                Ok(())
            }
            Self::Db(e) => write!(f, "{e:#}"),
        }
    }
}

impl From<anyhow::Error> for BatchError {
    fn from(e: anyhow::Error) -> Self {
        Self::Db(e)
    }
}

impl From<sqlx::Error> for BatchError {
    fn from(e: sqlx::Error) -> Self {
        Self::Db(e.into())
    }
}

/// Fixed inputs to every batch.
pub struct Ctx<'a> {
    pub specs: &'a [TableSpec],
    /// Cascade tables with no immediate key to `claims`, locked per batch.
    pub unkeyed: &'a [String],
    pub operator: Uuid,
    pub target: Uuid,
    pub mode: DerivedMode,
    pub lock_timeout: &'a str,
}

/// `after - before` per table, dropping all-zero rows.
#[must_use]
pub fn counter_delta(
    before: &BTreeMap<String, (i64, i64, i64)>,
    after: &BTreeMap<String, (i64, i64, i64)>,
) -> BTreeMap<String, (i64, i64, i64)> {
    let mut out = BTreeMap::new();
    for (t, a) in after {
        let b = before.get(t).copied().unwrap_or((0, 0, 0));
        let d = (a.0 - b.0, a.1 - b.1, a.2 - b.2);
        if d != (0, 0, 0) {
            out.insert(t.clone(), d);
        }
    }
    out
}

/// Compare an observed counter delta with the expected one; one message per
/// table that differs.
#[must_use]
pub fn counter_violations(
    observed: &BTreeMap<String, (i64, i64, i64)>,
    expected: &BTreeMap<String, (i64, i64, i64)>,
) -> Vec<String> {
    let mut v = Vec::new();
    let tables: BTreeSet<&String> = observed.keys().chain(expected.keys()).collect();
    for t in tables {
        let o = observed.get(t).copied().unwrap_or((0, 0, 0));
        let e = expected.get(t).copied().unwrap_or((0, 0, 0));
        if o != e {
            v.push(format!(
                "table {t}: this transaction inserted/updated/deleted {o:?} rows, the batch \
                 accounts for {e:?} (a row outside the eligible set changed)"
            ));
        }
    }
    v
}

/// Run one batch on a connection that is inside a transaction (or savepoint).
/// Does NOT commit.
///
/// # Errors
/// [`BatchError::Invariant`] when a check fails; [`BatchError::Db`] when a
/// statement fails. Either way the caller must roll the batch back.
pub async fn run_batch(
    conn: &mut PgConnection,
    ctx: &Ctx<'_>,
    batch: &[Uuid],
    sink: &mut Sink,
    caches: &mut Caches,
    known: &Known,
) -> Result<BatchOutcome, BatchError> {
    let mut out = BatchOutcome::default();
    sqlx::query("SELECT set_config('lock_timeout', $1, true)")
        .bind(ctx.lock_timeout)
        .execute(&mut *conn)
        .await?;
    let locked = fetch_claims(conn, batch, true).await?;
    tables::lock_unkeyed_tables(conn, ctx.unkeyed).await?;
    let c = classify(
        conn,
        ctx.specs,
        batch,
        &locked,
        ctx.operator,
        ctx.target,
        caches,
    )
    .await?;
    out.held = c.held;
    out.already = c.already;

    // Changed since the plan (see [`Known`]): hold every claim a changed row
    // hangs off, and drop the rows only those claims carried.
    let eligible_ids: BTreeSet<Uuid> = c.eligible.iter().map(|r| r.id).collect();
    let mut changed: BTreeMap<Uuid, (String, String)> = BTreeMap::new();
    for row in &c.eligible {
        if let Some(st) = known.claims.get(&row.id) {
            if (row.owner, row.visibility.clone()) != *st {
                changed
                    .entry(row.id)
                    .or_insert_with(|| ("claims".into(), row.id.to_string()));
            }
        }
    }
    for (k, a) in &c.attached {
        if let Some(t) = known.rows.get(k) {
            if *t != a.tenancy {
                for cl in a.claims.intersection(&eligible_ids) {
                    changed
                        .entry(*cl)
                        .or_insert_with(|| (k.0.clone(), k.1.clone()));
                }
            }
        }
    }
    let eligible: Vec<ClaimRow> = c
        .eligible
        .into_iter()
        .filter(|r| !changed.contains_key(&r.id))
        .collect();
    for (id, (table, row)) in changed {
        out.held
            .push((id, Hold::ChangedSincePlan { table, id: row }));
    }
    if eligible.is_empty() {
        return Ok(out);
    }
    let claim_ids: Vec<Uuid> = eligible.iter().map(|r| r.id).collect();
    let keep_ids: BTreeSet<Uuid> = claim_ids.iter().copied().collect();
    let s0: Snapshot = c
        .attached
        .into_iter()
        .filter(|(_, a)| a.claims.iter().any(|cl| keep_ids.contains(cl)))
        .collect();

    // Manifest first: any row the plan did not see is recorded, and fsynced,
    // before the write that moves it.
    out.newly_recorded = sink.record(&records_for(&eligible, &s0, ctx.specs))?;

    let keep = kept_rows(conn, &s0, ctx.mode, ctx.operator, caches).await?;
    let keys: BTreeSet<RowKey> = s0.keys().cloned().collect();
    let readable_before = app_readable(conn, ctx.specs, &claim_ids, &keys).await?;
    let counters_before = xact_counters(conn).await?;

    let moved = sqlx::query(
        "UPDATE claims SET owner_group_id = $2 \
          WHERE id = ANY($1) AND owner_group_id IS DISTINCT FROM $2",
    )
    .bind(&claim_ids)
    .bind(ctx.target)
    .execute(&mut *conn)
    .await
    .context("UPDATE claims")?
    .rows_affected();

    let s1 = refetch_tenancy(conn, ctx.specs, &claim_ids, &keys).await?;
    let mut trigger_changed: BTreeMap<String, i64> = BTreeMap::new();
    for (k, a) in &s0 {
        if s1.get(k) != Some(&a.tenancy) {
            *trigger_changed.entry(k.0.clone()).or_default() += 1;
        }
    }

    // keep-writer: put back what the trigger moved.
    let mut restored: BTreeMap<String, i64> = BTreeMap::new();
    let mut to_restore: BTreeMap<String, Vec<(String, Tenancy)>> = BTreeMap::new();
    for k in &keep {
        let a = &s0[k];
        if s1.get(k) != Some(&a.tenancy) {
            to_restore
                .entry(k.0.clone())
                .or_default()
                .push((k.1.clone(), a.tenancy.clone()));
        }
    }
    for (t, rows) in &to_restore {
        let n = write_tenancy(conn, spec_of(ctx.specs, t), &claim_ids, rows).await?;
        restored.insert(t.clone(), i64::try_from(n).unwrap_or(i64::MAX));
    }

    let s2 = refetch_tenancy(conn, ctx.specs, &claim_ids, &keys).await?;
    let after_claims = fetch_claims(conn, &claim_ids, false).await?;
    let counters_after = xact_counters(conn).await?;
    let readable_after = app_readable(conn, ctx.specs, &claim_ids, &keys).await?;

    // ---- invariants ----
    let mut v = Vec::new();
    if usize::try_from(moved).ok() != Some(claim_ids.len()) {
        v.push(format!(
            "UPDATE claims moved {moved} row(s), the batch planned {}",
            claim_ids.len()
        ));
    }
    let before_claims: BTreeMap<Uuid, &ClaimRow> = eligible.iter().map(|r| (r.id, r)).collect();
    for a in &after_claims {
        let b = before_claims[&a.id];
        if a.owner != ctx.target {
            v.push(format!(
                "claim {} is owned by {}, not the target",
                a.id, a.owner
            ));
        }
        if a.visibility != b.visibility {
            v.push(format!(
                "claim {} visibility changed {} -> {}",
                a.id, b.visibility, a.visibility
            ));
        }
    }
    let mut planned: BTreeMap<String, usize> = BTreeMap::new();
    let mut actual: BTreeMap<String, usize> = BTreeMap::new();
    for (k, a) in &s0 {
        let want = expected(a, ctx.specs, ctx.target, &keep);
        if want != a.tenancy {
            *planned.entry(k.0.clone()).or_default() += 1;
        }
        let Some(got) = s2.get(k) else {
            v.push(format!("{} {} vanished during the batch", k.0, k.1));
            continue;
        };
        if *got != a.tenancy {
            *actual.entry(k.0.clone()).or_default() += 1;
        }
        if got.visibility != a.tenancy.visibility {
            v.push(format!(
                "{} {} visibility changed {} -> {}",
                k.0, k.1, a.tenancy.visibility, got.visibility
            ));
        } else if got.visibility != "public" {
            v.push(format!(
                "{} {} is {} after the batch, not public",
                k.0, k.1, got.visibility
            ));
        }
        if *got != want {
            v.push(format!(
                "{} {} ended as {got:?}, the plan says {want:?}",
                k.0, k.1
            ));
        }
    }
    if planned != actual {
        v.push(format!(
            "rows moved per table {actual:?} differ from rows planned {planned:?}"
        ));
    }
    let mut expect_counts: BTreeMap<String, (i64, i64, i64)> = BTreeMap::new();
    expect_counts.insert(
        "claims".into(),
        (0, i64::try_from(claim_ids.len()).unwrap_or(i64::MAX), 0),
    );
    for (t, n) in &trigger_changed {
        expect_counts.entry(t.clone()).or_default().1 += n;
    }
    for (t, n) in &restored {
        expect_counts.entry(t.clone()).or_default().1 += n;
    }
    expect_counts.retain(|_, d| *d != (0, 0, 0));
    v.extend(counter_violations(
        &counter_delta(&counters_before, &counters_after),
        &expect_counts,
    ));
    if readable_before != readable_after {
        let lost: Vec<_> = readable_before.difference(&readable_after).collect();
        let gained: Vec<_> = readable_after.difference(&readable_before).collect();
        v.push(format!(
            "the rows an unstamped epigraph_app session can read changed: lost {lost:?}, \
             gained {gained:?}"
        ));
    }
    if !v.is_empty() {
        return Err(BatchError::Invariant(v));
    }
    // The post-state, fsynced under the batch's locks BEFORE the caller
    // commits: what reversal compares against (see `manifest`).
    let moved_ids: BTreeSet<Uuid> = claim_ids.iter().copied().collect();
    let neighbour_rows = fetch_claims(conn, &neighbours_of(&s0, &moved_ids), false).await?;
    sink.record_post(&post_records_for(
        &after_claims,
        &s0,
        &s2,
        &neighbour_rows,
        ctx.specs,
    ))?;
    out.claims_moved = claim_ids.len();
    out.moved_by_table = actual;
    out.post_claims = after_claims
        .iter()
        .map(|c| (c.id, (c.owner, c.visibility.clone())))
        .collect();
    out.post_rows = s2;
    for k in &keep {
        *out.kept_by_table.entry(k.0.clone()).or_default() += 1;
    }
    Ok(out)
}

/// The whole run's result, for the caller to print and to pick an exit code.
#[derive(Default, Debug)]
pub struct RunReport {
    pub requested: usize,
    pub plan_eligible: usize,
    pub plan_attached_by_table: BTreeMap<String, usize>,
    pub plan_held: Vec<(Uuid, Hold)>,
    pub plan_already: usize,
    pub spill: Spill,
    pub batches_ok: usize,
    pub batch_failures: Vec<(usize, String)>,
    pub claims_moved: usize,
    pub moved_by_table: BTreeMap<String, usize>,
    pub kept_by_table: BTreeMap<String, usize>,
    pub held_under_lock: Vec<(Uuid, Hold)>,
    pub manifest_rows: usize,
}

/// Fold one batch's result into the report and print it. Returns `false` when
/// the run must stop (a failed batch under `--apply`).
fn tally(
    report: &mut RunReport,
    out: &mut dyn std::io::Write,
    n: usize,
    total: usize,
    result: Result<BatchOutcome, BatchError>,
    apply: bool,
) -> anyhow::Result<bool> {
    match result {
        Ok(b) => {
            report.batches_ok += 1;
            report.claims_moved += b.claims_moved;
            for (t, k) in b.moved_by_table {
                *report.moved_by_table.entry(t).or_default() += k;
            }
            for (t, k) in b.kept_by_table {
                *report.kept_by_table.entry(t).or_default() += k;
            }
            report.held_under_lock.extend(b.held);
            writeln!(
                out,
                "BATCH {n}/{total}\tOK\t{} claim(s) moved{}",
                b.claims_moved,
                if b.newly_recorded > 0 {
                    format!(", {} row(s) recorded late under the lock", b.newly_recorded)
                } else {
                    String::new()
                }
            )?;
            Ok(true)
        }
        Err(e) => {
            writeln!(out, "BATCH {n}/{total}\tROLLED BACK\t{e}")?;
            report.batch_failures.push((n, e.to_string()));
            if apply {
                writeln!(out, "STOPPED: no further batch was attempted")?;
                return Ok(false);
            }
            Ok(true)
        }
    }
}

/// Plan, then run every batch.
///
/// Under `apply`, the manifest is created and the whole plan recorded before
/// the first batch, each batch commits on its own, and the run stops at the
/// first failed batch. Otherwise each batch runs in its OWN transaction, which
/// is rolled back as soon as the batch ends: a dry run against production
/// holds a batch's row and table locks for that batch only, never for the
/// whole run (review finding: one transaction with savepoints kept every
/// batch's `FOR UPDATE` and cascade row locks until the end, because
/// `RELEASE SAVEPOINT` keeps locks). The cost is that a batch does not see an
/// earlier batch's effects, which only changes how rows shared across batches
/// are checked, not what the plan reports.
///
/// # Errors
/// A failure outside a batch (planning, the manifest, the connection).
pub async fn run(
    conn: &mut PgConnection,
    opts: &Options,
    requested: &[Uuid],
    out: &mut dyn std::io::Write,
) -> anyhow::Result<RunReport> {
    let mut report = RunReport {
        requested: requested.len(),
        ..Default::default()
    };
    let specs = tables::propagated_tables(conn).await?;
    let unkeyed = tables::unkeyed_tables(conn, &specs).await?;
    let target = operator_group(conn, opts.operator).await?;
    tables::probe_session_switch(conn).await?;
    let mut caches = Caches::default();

    // ---- plan (read-only) ----
    let mut plan = Classified::default();
    for chunk in requested.chunks(opts.batch_size.max(1)) {
        let rows = fetch_claims(conn, chunk, false).await?;
        let c = classify(
            conn,
            &specs,
            chunk,
            &rows,
            opts.operator,
            target,
            &mut caches,
        )
        .await?;
        plan.eligible.extend(c.eligible);
        plan.held.extend(c.held);
        plan.already.extend(c.already);
        plan.attached.extend(c.attached);
    }
    report.plan_eligible = plan.eligible.len();
    report.plan_already = plan.already.len();
    report.plan_held.clone_from(&plan.held);
    for (t, _) in plan.attached.keys() {
        *report.plan_attached_by_table.entry(t.clone()).or_default() += 1;
    }
    let eligible_set: BTreeSet<Uuid> = plan.eligible.iter().map(|c| c.id).collect();
    report.spill = spill(
        conn,
        &plan.attached,
        &eligible_set,
        opts.operator,
        &mut caches,
    )
    .await?;

    writeln!(
        out,
        "reown-claims: operator={} target_group={target} derived={} mode={}",
        opts.operator,
        opts.mode.as_str(),
        if opts.apply { "APPLY" } else { "DRY-RUN" }
    )?;
    writeln!(
        out,
        "PLAN: {} requested, {} eligible, {} held, {} already owned by the target",
        requested.len(),
        plan.eligible.len(),
        plan.held.len(),
        plan.already.len()
    )?;
    for (id, h) in &plan.held {
        writeln!(out, "HELD\t{id}\t{h}")?;
    }
    if !unkeyed.is_empty() {
        writeln!(
            out,
            "LOCKED-PER-BATCH\t{}\t(no key to claims, so each batch holds SHARE ROW EXCLUSIVE on \
             them: writers to these tables wait for the batch)",
            unkeyed.join(",")
        )?;
    }
    for (t, n) in &report.plan_attached_by_table {
        writeln!(out, "PLAN-ROWS\t{t}\t{n}")?;
    }
    writeln!(
        out,
        "RULE: rows with no writer of record (no writer column, or NULL) follow the claim in both \
         --derived modes; edges take the trigger's meet of their endpoints (world, for two public \
         endpoints)"
    )?;
    for (t, n) in &report.spill.unattributed {
        writeln!(out, "UNATTRIBUTED\t{t}\t{n}")?;
    }
    writeln!(
        out,
        "SPILL (rows written by agents NOT linked to the operator; {} in this mode): {} row(s)",
        match opts.mode {
            DerivedMode::FollowClaim => "they MOVE to the operator group",
            DerivedMode::KeepWriter => "they KEEP their prior owner",
        },
        report.spill.by_table.values().sum::<usize>()
    )?;
    for (t, n) in &report.spill.by_table {
        writeln!(out, "SPILL-TABLE\t{t}\t{n}")?;
    }
    for (w, n) in &report.spill.by_writer {
        writeln!(out, "SPILL-WRITER\t{w}\t{n}")?;
    }
    if report.spill.shared_fragments > 0 {
        writeln!(
            out,
            "SHARED-FRAGMENTS\t{}\t(also the provenance of a claim not being moved; they move \
             with the eligible claim, and stay public)",
            report.spill.shared_fragments
        )?;
    }
    for (c, n) in &report.spill.neighbour_edges {
        writeln!(
            out,
            "NEIGHBOUR-EDGES\t{c}\t{n}\t(edges to a claim that is NOT moving: the trigger \
             recomputes their owner as the meet of their endpoints, so that claim's \
             neighbourhood is rewritten too; they stay public, and the manifest records them)"
        )?;
    }

    // ---- opt-in hiding (Amendment 2) ----
    let selector = super::hide::Selector::from_args(&opts.hide)?;
    if !selector.is_empty() {
        let hide_plan = super::hide::plan(&selector, &plan.attached);
        super::hide::print(out, &hide_plan)?;
        let policies = super::hide::extra_evidence_policies(conn).await?;
        super::hide::warn_unenforced(out, &policies)?;
        let guard = super::hide::guard_status(conn).await?;
        if opts.apply {
            // Refused BEFORE the manifest and before any write: a re-own that
            // was asked to hide must not run half of what it was asked. The
            // plan's own refusals first, so their messages still name the
            // count, the unenforced policy or the missing guard.
            super::hide::refuse_apply(&hide_plan, &opts.hide, &policies, guard)?;
            super::hide::refuse_hide_in_reown()?;
        }
        writeln!(
            out,
            "HIDE: not simulated in this dry run; the re-own below runs WITHOUT it. \
             reown-claims --apply with a hide selector refuses: re-own first, then run \
             hide-evidence --apply over the moved claims{}",
            if guard.complete() {
                ""
            } else {
                " (and the kernel pin guard, migration 110, is absent from this schema)"
            }
        )?;
    }

    // ---- manifest ----
    let mut sink = if opts.apply {
        let header = json!({
            "manifest": "epigraph-operator reown-claims",
            "version": super::manifest::VERSION,
            "operator": opts.operator,
            "target_group_id": target,
            "derived": opts.mode.as_str(),
            "created_at": chrono::Utc::now().to_rfc3339(),
        });
        let mut w = Writer::create_new(&opts.manifest_out, &header)?;
        w.append(&records_for(&plan.eligible, &plan.attached, &specs))?;
        Sink::File(w)
    } else {
        let mut s = Sink::Memory(Default::default(), 0);
        s.record(&records_for(&plan.eligible, &plan.attached, &specs))?;
        s
    };
    writeln!(
        out,
        "MANIFEST\t{}\t{} row record(s){}",
        opts.manifest_out.display(),
        sink.len(),
        if opts.apply {
            " written and fsynced before any write"
        } else {
            " (dry run: not written)"
        }
    )?;

    // ---- batches ----
    let ctx = Ctx {
        specs: &specs,
        unkeyed: &unkeyed,
        operator: opts.operator,
        target,
        mode: opts.mode,
        lock_timeout: &opts.lock_timeout,
    };
    let mut known = Known::from_plan(&plan);
    let eligible: Vec<Uuid> = plan.eligible.iter().map(|c| c.id).collect();
    let batches: Vec<&[Uuid]> = eligible.chunks(opts.batch_size.max(1)).collect();
    let total = batches.len();
    if opts.apply {
        for (i, batch) in batches.iter().enumerate() {
            let mut tx = sqlx::Connection::begin(&mut *conn).await?;
            let r = run_batch(&mut tx, &ctx, batch, &mut sink, &mut caches, &known).await;
            if let Ok(b) = &r {
                tx.commit().await?;
                known.commit(b);
            } else {
                tx.rollback().await?;
            }
            if !tally(&mut report, out, i + 1, total, r, true)? {
                break;
            }
        }
    } else {
        for (i, batch) in batches.iter().enumerate() {
            let mut tx = sqlx::Connection::begin(&mut *conn).await?;
            let r = run_batch(&mut tx, &ctx, batch, &mut sink, &mut caches, &known).await;
            tx.rollback().await?;
            tally(&mut report, out, i + 1, total, r, false)?;
        }
    }
    report.manifest_rows = sink.len();

    for (id, h) in &report.held_under_lock {
        writeln!(out, "HELD-UNDER-LOCK\t{id}\t{h}")?;
    }
    writeln!(out, "RESULT")?;
    writeln!(out, "  claims moved: {}", report.claims_moved)?;
    let mut all_tables: BTreeSet<&String> = report.plan_attached_by_table.keys().collect();
    all_tables.extend(report.moved_by_table.keys());
    for t in all_tables {
        writeln!(
            out,
            "  {t}: rows moved: {}, all public before and after{}",
            report.moved_by_table.get(t).copied().unwrap_or(0),
            report
                .kept_by_table
                .get(t)
                .map(|n| format!(" ({n} kept on their writer's owner)"))
                .unwrap_or_default()
        )?;
    }
    writeln!(
        out,
        "  invariants: {}",
        if report.batch_failures.is_empty() {
            "all held in every batch".to_string()
        } else {
            format!(
                "{} batch(es) violated and were rolled back",
                report.batch_failures.len()
            )
        }
    )?;
    if !opts.apply {
        writeln!(
            out,
            "DRY RUN: each batch above ran in its own transaction and was rolled back, so no \
             lock outlived its batch; a batch does not see an earlier batch's effects, so a row \
             shared across batches is checked against its current state."
        )?;
    }
    if report.batch_failures.is_empty() && opts.apply && report.claims_moved < plan.eligible.len() {
        writeln!(
            out,
            "NOTE: {} planned claim(s) were held under the lock. To retry them, re-run with a \
             NEW --manifest-out. To undo, pass EVERY manifest to one reown-reverse (it applies \
             them newest first); a manifest reversed on its own HOLDS any row a newer run moved",
            plan.eligible.len() - report.claims_moved
        )?;
    }
    Ok(report)
}

/// Refuse obviously bad options before connecting.
///
/// # Errors
/// A zero batch size.
pub fn validate(opts: &Options) -> anyhow::Result<()> {
    if opts.batch_size == 0 {
        bail!("--batch-size must be at least 1");
    }
    Ok(())
}
