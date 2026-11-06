//! `reown-workflows`: move listed workflow LINEAGES (every generation of each
//! `canonical_name`) out of a source group and into a TEAM group, keeping every
//! row's visibility; and the exact reversal of such a run (`reown-reverse` on a
//! reown-workflows manifest).
//!
//! The source is the operator's personal group, or `--from-group` (which the
//! operator must administer). The target must be an active `team` group the
//! operator administers. It is an audited maintenance act in the shape of
//! `restrict-claims`: dry run by default; `--apply` needs `--confirm-count`
//! (the dry run's eligible workflow-row count), `--ruling` and `--reason`; the
//! manifest is created before the first write and every batch records its rows,
//! `fsync`ed, before its write; one `security_events` row per applied run.
//!
//! # The rule: only rows the SOURCE group owns move, and nothing narrows
//!
//! A row moves only while it is `('public', source)`. Visibility is never
//! written. So every row this tool writes is public before and after, and a
//! public row is readable through every tenancy policy's `visibility =
//! 'public'` arm whoever owns it: no reader gains or loses a row. Migration
//! 197's atlas epoch is bumped only by a public-to-non-public narrowing, so a
//! run never bumps it; every batch asserts `atlas_layout_epoch` unchanged and
//! that this transaction wrote no row there.
//!
//! # What moves, table by table
//!
//! * `workflows`: every generation of a listed lineage owned by the source.
//!   A lineage with a generation that is not public, or that a third group
//!   owns, is HELD whole (moving part of a lineage would split its plan across
//!   owners; moving a private row changes who reads it). A lineage whose rows
//!   are all the target's already counts as done.
//! * `claims`: the plan claims, i.e. the target of every `executes` edge from
//!   any of those rows (thesis, phases, steps, operation atoms; retracted
//!   edges count too, as migration 183's backfill counts them), plus every
//!   claim in the same `step_lineage_id` as one of them (an evolved step's
//!   successor is executed by no workflow; the plan reaches it through its
//!   lineage). A plan claim is LEFT, and reported, when it is:
//!   - SHARED: executed by a workflow outside the listed lineages, asserted by
//!     a paper, or decomposed into from a claim outside the plans (level-3
//!     atoms are content-addressed in the namespace documents share), or in a
//!     step lineage with such a member. A shared claim is never moved;
//!   - owned by a group other than the source, or not public;
//!   - carrying a row the cascade would move that is not `('public', source)`
//!     (a third group's derived row, pinned evidence), or an edge with a
//!     non-public endpoint.
//! * The claims' DERIVED rows (`epigraph_propagate_tenancy`'s `derived[]`
//!   tables and harvester fragments, read from the live trigger by
//!   `tables::propagated_tables`): the cascade copies the claim's new owner
//!   onto every one that is not writer-owned. A WRITER-OWNED row (migration
//!   114: another writer's evidence, BBA or trace) is left by the trigger while
//!   the claim stays public, and stays its writer's here.
//! * `edges`: an edge moves when it is `('public', source)` with no co-owner,
//!   both endpoints public, at least one endpoint in the plans (a listed
//!   workflow row or a plan claim), and it is EITHER a plan relationship
//!   ([`PLAN_RELATIONSHIPS`]) OR has both endpoints in the plans (a
//!   cross-reference between two steps). Since migration 120 the edges a
//!   workflow ingest writes split in two:
//!   - claim-to-claim plan edges (`decomposes_to`, `step_follows`,
//!     `phase_follows`, cross-references, an evolved step's `supersedes` /
//!     `revises`) are owned by the WRITER's group, which for the ingest system
//!     agent live-linked to the operator is the operator's personal group.
//!     These move;
//!   - every edge with a workflow, agent or paper endpoint (`executes`,
//!     `variant_of`, `asserts`, `AUTHORED`) is STRUCTURAL: migration 120 stamps
//!     it `('public', world)`, owned by no group. It is not the source's, so it
//!     does not move, and its public visibility already serves every reader.
//!     `workflows.parent_id` is a column of the moving row, not a separate row.
//!     The dry run counts these.
//!
//!   The trigger does not rewrite any of these on its own: since migration 120
//!   a public-to-public owner change of an endpoint leaves every public edge
//!   alone. So this tool updates the moving edges' `owner_group_id` itself. It
//!   does NOT rewrite `writer_group_id`: that is the author record (migration
//!   120) and stays the writing session's group. Consequence: a later
//!   privatize-then-revert of a moved plan restores such an edge to its
//!   writer's group, as for any writer-owned edge.
//!
//! # Batches, locks and the check under them
//!
//! Lineages that share a plan claim, a cascaded row, or an edge between their
//! plans form one COMPONENT, and a component never spans two batches. Each
//! batch is one transaction: `SET LOCAL lock_timeout`; `LOCK TABLE workflows IN
//! SHARE ROW EXCLUSIVE MODE` (every ingest inserts its `workflows` row before
//! its `executes` edges, so no plan can start reusing one of these claims
//! mid-batch, while edge writes elsewhere in the corpus are not stalled); the
//! component's workflow rows, claims and moving edges `FOR UPDATE`; the
//! cascade tables with no key to `claims` (`tables::lock_unkeyed_tables`).
//! Then the batch re-plans ITS lineages under the locks and HOLDS every
//! component whose plan differs from the dry plan's in any row or state.
//!
//! The batch then records the prior state, writes three statements
//! (`workflows`, `claims`, `edges`), and checks before committing: every moved
//! row is `('public', target)`; every writer-owned row and every edge that
//! stays is unchanged (`writer_group_id` included); `pg_stat_xact_user_tables`
//! counts exactly the planned rows per table and none elsewhere; an UNSTAMPED
//! `epigraph_app` session reads exactly the same keys before and after; and
//! the atlas epoch is unchanged. Any violation rolls the batch back (exit 2).
//!
//! # Reversal (`reown-reverse --manifest <this manifest>`)
//!
//! All of one manifest in ONE transaction, a compare-and-swap per row: a row
//! with a post record is restored when it is in its post state, skipped when it
//! is already in its prior state, and anything else REFUSES THE WHOLE
//! MANIFEST (nothing is written; exit 3). It also refuses when a moved lineage
//! has gained a workflow row this run did not move (a new generation), when a
//! moved claim is now executed by a workflow this run did not move, and when a
//! row the cascade would carry back is not public. Exact or nothing: a partial
//! restore would split a plan between two owners. `claims.updated_at` (migration
//! 001's trigger) is the one column neither direction can put back.

use super::manifest::{self, Record, Sink, Writer};
use super::reown::{counter_delta, counter_violations, BatchError};
use super::restrict::{check_target, operator_details, sha256_file, sha256_hex};
use super::tables::{
    self, fetch_attached, fetch_claims, xact_counters, ClaimRow, Kind, RowKey, Snapshot, TableSpec,
    Tenancy,
};
use super::{operator_group, SEED, WORLD};
use anyhow::{anyhow, bail, Context};
use epigraph_db::{SecurityEventRepository, SecurityEventRow};
use serde_json::{json, Value};
use sqlx::{PgConnection, Row};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// The `operation` a manifest's header carries; `reown-reverse` dispatches on
/// it.
pub const OPERATION: &str = "reown-workflows";
/// `security_events.event_type` of an applied run.
pub const EVENT_APPLY: &str = "operator.workflows_reowned";
/// `security_events.event_type` of an applied reversal of one manifest.
pub const EVENT_REVERSE: &str = "operator.workflows_reown_reversed";

/// The relationships the workflow write paths create (ingest, `add_step`,
/// `evolve_step`, authorship). A source-owned public edge with one of these
/// and at least one endpoint in the plans moves; any other relationship moves
/// only when BOTH endpoints are in the plans.
pub const PLAN_RELATIONSHIPS: &[&str] = &[
    "executes",
    "variant_of",
    "decomposes_to",
    "step_follows",
    "phase_follows",
    "supersedes",
    "revises",
    "asserts",
    "AUTHORED",
];

const PUBLIC: &str = "public";

/// Everything `reown-workflows` was told.
#[derive(Clone, Debug)]
pub struct Options {
    pub names_file: PathBuf,
    pub target: Uuid,
    pub operator: Uuid,
    pub from_group: Option<Uuid>,
    pub manifest_out: PathBuf,
    pub apply: bool,
    pub confirm_count: Option<usize>,
    pub ruling: String,
    pub reason: String,
    /// Lineages per transaction (a component is never split).
    pub batch_size: usize,
    pub lock_timeout: String,
}

/// Refuse obviously bad options before connecting.
///
/// # Errors
/// A zero batch size; under `--apply`, an empty ruling or reason, or no
/// `--confirm-count`.
pub fn validate(opts: &Options) -> anyhow::Result<()> {
    if opts.batch_size == 0 {
        bail!("--batch-size must be at least 1");
    }
    if opts.apply {
        if opts.ruling.trim().is_empty() {
            bail!("--apply requires a non-empty --ruling (recorded in the audit row)");
        }
        if opts.reason.trim().is_empty() {
            bail!("--apply requires a non-empty --reason (recorded in the audit row)");
        }
        if opts.confirm_count.is_none() {
            bail!(
                "--apply requires --confirm-count <N>: the dry run's ELIGIBLE-WORKFLOW-ROWS, \
                 repeated back"
            );
        }
    }
    Ok(())
}

/// One canonical name per line; surrounding whitespace trimmed; blank lines
/// and `#` comments ignored; duplicates dropped with order kept.
///
/// # Errors
/// The file cannot be read, or names nothing.
pub fn read_names_file(path: &Path) -> anyhow::Result<Vec<String>> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for line in text.lines() {
        let n = line.trim();
        if n.is_empty() || n.starts_with('#') {
            continue;
        }
        if seen.insert(n.to_string()) {
            out.push(n.to_string());
        }
    }
    if out.is_empty() {
        bail!("no canonical names in {}", path.display());
    }
    Ok(out)
}

/// The source and target groups, refusing every combination this verb must
/// not run on. Returns `(source, target)`.
///
/// # Errors
/// `--from-group` is world or seed or not administered by the operator; the
/// operator has no personal group; the target is the source, not an active
/// team group, or not administered by the operator.
pub async fn resolve_groups(
    conn: &mut PgConnection,
    opts: &Options,
) -> anyhow::Result<(Uuid, Uuid)> {
    let source = match opts.from_group {
        Some(g) => {
            if g == WORLD || g == SEED {
                bail!("--from-group {g} is the world or seed group; refusing");
            }
            if !live_admin(conn, g, opts.operator).await? {
                bail!(
                    "--operator {} is not a live admin of --from-group {g}; refusing (this verb \
                     takes rows only out of a group the operator administers)",
                    opts.operator
                );
            }
            g
        }
        None => operator_group(conn, opts.operator).await?,
    };
    if source == opts.target {
        bail!(
            "--target-group {} is the source group; nothing to move",
            opts.target
        );
    }
    let kind = check_target(conn, opts.target, opts.operator).await?;
    if kind != "team" {
        bail!(
            "--target-group {} is kind {kind}, not a team group; refusing (a lineage moves into a \
             team, never into a person's own group)",
            opts.target
        );
    }
    Ok((source, opts.target))
}

async fn live_admin(conn: &mut PgConnection, group: Uuid, agent: Uuid) -> anyhow::Result<bool> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM group_memberships \
                         WHERE group_id = $1 AND agent_id = $2 AND role = 'admin' \
                           AND revoked_at IS NULL)",
    )
    .bind(group)
    .bind(agent)
    .fetch_one(&mut *conn)
    .await?)
}

// ─────────────────────────────────────────────────────────────────────────────
// The plan
// ─────────────────────────────────────────────────────────────────────────────

/// A `workflows` row.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct WfRow {
    pub id: Uuid,
    pub canonical_name: String,
    pub generation: i32,
    pub tenancy: Tenancy,
}

/// An `edges` row touching the plans.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct EdgeRow {
    pub id: Uuid,
    pub source: (Uuid, String),
    pub target: (Uuid, String),
    pub relationship: String,
    pub tenancy: Tenancy,
    pub writer_group: Option<Uuid>,
    pub endpoints_public: bool,
}

/// Why a listed lineage does not move.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LineageHold {
    NotFound,
    OwnedElsewhere { generation: i32, owner: Uuid },
    NotPublic { generation: i32, visibility: String },
}

impl fmt::Display for LineageHold {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => write!(f, "no workflow row has this canonical name"),
            Self::OwnedElsewhere { generation, owner } => write!(
                f,
                "generation {generation} is owned by group {owner}, neither the source nor the \
                 target; the whole lineage stays"
            ),
            Self::NotPublic {
                generation,
                visibility,
            } => write!(
                f,
                "generation {generation} has visibility {visibility}, not public; a re-own keeps \
                 visibility and moving a private plan changes who reads it, so the whole lineage \
                 stays"
            ),
        }
    }
}

/// Why a plan claim stays where it is.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Left {
    NotFound,
    Shared(Vec<String>),
    NotSourceOwned {
        owner: Uuid,
    },
    NotPublic {
        visibility: String,
    },
    ForeignRow {
        table: String,
        id: String,
        state: String,
    },
    EdgeEndpointNotPublic {
        edge: Uuid,
    },
}

impl fmt::Display for Left {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => write!(f, "an executes edge names it, but no such claim exists"),
            Self::Shared(by) => write!(
                f,
                "SHARED ({}); it stays on its owner, never moved silently",
                by.join("; ")
            ),
            Self::NotSourceOwned { owner } => {
                write!(f, "owned by group {owner}, not the source group")
            }
            Self::NotPublic { visibility } => write!(f, "visibility {visibility}, not public"),
            Self::ForeignRow { table, id, state } => write!(
                f,
                "{table} {id} is {state}: the cascade would move a row the source group does not \
                 own (public)"
            ),
            Self::EdgeEndpointNotPublic { edge } => {
                write!(f, "edge {edge} touching it has a non-public endpoint")
            }
        }
    }
}

/// Lineages that must move together, and everything that moves with them.
#[derive(Clone, Debug, Default)]
pub struct Component {
    /// Sorted.
    pub lineages: Vec<String>,
    /// Source-owned rows: they move.
    pub workflows: Vec<WfRow>,
    /// Plan claims that move.
    pub claims: Vec<ClaimRow>,
    pub left: Vec<(Uuid, Left)>,
    pub already_claims: Vec<Uuid>,
    /// Derived and fragment rows the cascade moves (not writer-owned).
    pub rows: Snapshot,
    /// Writer-owned rows: they stay.
    pub kept_rows: Snapshot,
    /// Edges that move.
    pub edges: Vec<EdgeRow>,
    /// Edges touching the plans that stay, with why.
    pub edges_kept: Vec<(EdgeRow, &'static str)>,
}

impl Component {
    /// Everything the batch re-plans and compares, in a stable text form.
    fn fingerprint(&self) -> String {
        let mut claims: Vec<_> = self
            .claims
            .iter()
            .map(|c| (c.id, c.author, c.owner, c.visibility.clone()))
            .collect();
        claims.sort();
        let mut left = self.left.clone();
        left.sort();
        let mut already = self.already_claims.clone();
        already.sort();
        let rows: Vec<_> = self
            .rows
            .iter()
            .chain(self.kept_rows.iter())
            .map(|(k, a)| {
                (
                    k.clone(),
                    a.tenancy.clone(),
                    a.writer_owned,
                    a.claims.clone(),
                )
            })
            .collect();
        let mut wf = self.workflows.clone();
        wf.sort();
        let mut edges = self.edges.clone();
        edges.sort();
        let mut kept: Vec<_> = self.edges_kept.clone();
        kept.sort();
        format!(
            "{:?}",
            (&self.lineages, wf, claims, left, already, rows, edges, kept)
        )
    }

    fn claim_ids(&self) -> Vec<Uuid> {
        self.claims.iter().map(|c| c.id).collect()
    }
}

/// The plan of a whole run.
#[derive(Debug, Default)]
pub struct Plan {
    pub held: Vec<(String, LineageHold)>,
    pub already: Vec<String>,
    pub components: Vec<Component>,
}

/// A tiny union-find over lineage names.
#[derive(Default)]
struct Dsu(BTreeMap<String, String>);

impl Dsu {
    fn find(&mut self, x: &str) -> String {
        let p = self.0.get(x).cloned().unwrap_or_else(|| x.to_string());
        if p == x {
            self.0.insert(x.to_string(), p.clone());
            return p;
        }
        let r = self.find(&p);
        self.0.insert(x.to_string(), r.clone());
        r
    }

    fn union(&mut self, a: &str, b: &str) {
        let (ra, rb) = (self.find(a), self.find(b));
        if ra != rb {
            let (lo, hi) = if ra < rb { (ra, rb) } else { (rb, ra) };
            self.0.insert(hi, lo);
        }
    }
}

fn add_reason(map: &mut BTreeMap<Uuid, BTreeSet<String>>, id: Uuid, why: String) {
    map.entry(id).or_default().insert(why);
}

/// Plan the listed lineages: which hold, which are done, and per component
/// what moves.
///
/// # Errors
/// A read fails.
#[allow(clippy::too_many_lines)]
pub async fn plan(
    conn: &mut PgConnection,
    specs: &[TableSpec],
    names: &[String],
    source: Uuid,
    target: Uuid,
) -> anyhow::Result<Plan> {
    let mut out = Plan::default();
    let rows = sqlx::query(
        "SELECT id, canonical_name, generation, owner_group_id, visibility::text FROM workflows \
          WHERE canonical_name = ANY($1) ORDER BY canonical_name, generation, id",
    )
    .bind(names)
    .fetch_all(&mut *conn)
    .await
    .context("reading workflows")?;
    let mut by_name: BTreeMap<String, Vec<WfRow>> = BTreeMap::new();
    for r in &rows {
        let w = WfRow {
            id: r.get(0),
            canonical_name: r.get(1),
            generation: r.get(2),
            tenancy: Tenancy {
                owner: r.get(3),
                visibility: r.get(4),
                co_owner: None,
            },
        };
        by_name.entry(w.canonical_name.clone()).or_default().push(w);
    }

    // ---- lineages ----
    let mut eligible: BTreeMap<String, Vec<WfRow>> = BTreeMap::new();
    for name in names {
        let Some(gens) = by_name.get(name) else {
            out.held.push((name.clone(), LineageHold::NotFound));
            continue;
        };
        let bad = gens.iter().find_map(|w| {
            if w.tenancy.visibility != PUBLIC {
                Some(LineageHold::NotPublic {
                    generation: w.generation,
                    visibility: w.tenancy.visibility.clone(),
                })
            } else if w.tenancy.owner != source && w.tenancy.owner != target {
                Some(LineageHold::OwnedElsewhere {
                    generation: w.generation,
                    owner: w.tenancy.owner,
                })
            } else {
                None
            }
        });
        if let Some(h) = bad {
            out.held.push((name.clone(), h));
        } else if gens.iter().all(|w| w.tenancy.owner == target) {
            out.already.push(name.clone());
        } else {
            eligible.insert(name.clone(), gens.clone());
        }
    }
    if eligible.is_empty() {
        return Ok(out);
    }
    let wf_lineage: BTreeMap<Uuid, String> = eligible
        .iter()
        .flat_map(|(n, gens)| gens.iter().map(move |w| (w.id, n.clone())))
        .collect();
    let wall: Vec<Uuid> = wf_lineage.keys().copied().collect();

    // ---- plan claims: executed, then their step lineages ----
    let exec: Vec<(Uuid, Uuid)> = sqlx::query_as(
        "SELECT source_id, target_id FROM edges \
          WHERE source_type = 'workflow' AND target_type = 'claim' \
            AND relationship = 'executes' AND source_id = ANY($1)",
    )
    .bind(&wall)
    .fetch_all(&mut *conn)
    .await
    .context("reading executes edges")?;
    let mut claim_lineages: BTreeMap<Uuid, BTreeSet<String>> = BTreeMap::new();
    for (w, c) in &exec {
        claim_lineages
            .entry(*c)
            .or_default()
            .insert(wf_lineage[w].clone());
    }
    let executed: Vec<Uuid> = claim_lineages.keys().copied().collect();
    let step_rows: Vec<(Uuid, Uuid)> = sqlx::query_as(
        "SELECT c.id, c.step_lineage_id FROM claims c \
          WHERE c.step_lineage_id IN (SELECT e.step_lineage_id FROM claims e \
                                       WHERE e.id = ANY($1) AND e.step_lineage_id IS NOT NULL)",
    )
    .bind(&executed)
    .fetch_all(&mut *conn)
    .await
    .context("reading step lineages")?;
    let mut step_of: BTreeMap<Uuid, Uuid> = BTreeMap::new();
    let mut step_members: BTreeMap<Uuid, BTreeSet<Uuid>> = BTreeMap::new();
    for (c, l) in &step_rows {
        step_of.insert(*c, *l);
        step_members.entry(*l).or_default().insert(*c);
    }
    for members in step_members.values() {
        let mut ls = BTreeSet::new();
        for m in members {
            if let Some(x) = claim_lineages.get(m) {
                ls.extend(x.iter().cloned());
            }
        }
        for m in members {
            claim_lineages
                .entry(*m)
                .or_default()
                .extend(ls.iter().cloned());
        }
    }
    let all_claims: Vec<Uuid> = claim_lineages.keys().copied().collect();

    let mut dsu = Dsu::default();
    for n in eligible.keys() {
        dsu.find(n);
    }
    for ls in claim_lineages.values() {
        let mut it = ls.iter();
        if let Some(first) = it.next() {
            for o in it {
                dsu.union(first, o);
            }
        }
    }

    // ---- shared ----
    let mut shared: BTreeMap<Uuid, BTreeSet<String>> = BTreeMap::new();
    for r in sqlx::query(
        "SELECT e.target_id, e.source_id, w.canonical_name FROM edges e \
           LEFT JOIN workflows w ON w.id = e.source_id \
          WHERE e.relationship = 'executes' AND e.source_type = 'workflow' \
            AND e.target_type = 'claim' AND e.target_id = ANY($1) AND e.source_id <> ALL($2)",
    )
    .bind(&all_claims)
    .bind(&wall)
    .fetch_all(&mut *conn)
    .await
    .context("reading other plans' executes edges")?
    {
        let (c, w, n): (Uuid, Uuid, Option<String>) = (r.get(0), r.get(1), r.get(2));
        add_reason(
            &mut shared,
            c,
            format!(
                "also executed by workflow {w} ({}), outside the listed lineages",
                n.unwrap_or_default()
            ),
        );
    }
    for (c, p) in sqlx::query_as::<_, (Uuid, Uuid)>(
        "SELECT target_id, source_id FROM edges \
          WHERE target_type = 'claim' AND target_id = ANY($1) AND source_type = 'paper'",
    )
    .bind(&all_claims)
    .fetch_all(&mut *conn)
    .await
    .context("reading paper edges")?
    {
        add_reason(&mut shared, c, format!("asserted by paper {p}"));
    }
    for (c, s) in sqlx::query_as::<_, (Uuid, Uuid)>(
        "SELECT target_id, source_id FROM edges \
          WHERE relationship = 'decomposes_to' AND source_type = 'claim' \
            AND target_type = 'claim' AND target_id = ANY($1) AND source_id <> ALL($1)",
    )
    .bind(&all_claims)
    .fetch_all(&mut *conn)
    .await
    .context("reading outside decompositions")?
    {
        add_reason(
            &mut shared,
            c,
            format!("decomposed into from claim {s}, outside the plans"),
        );
    }
    // A step lineage with a shared member is shared whole.
    let shared_steps: BTreeSet<Uuid> = shared
        .keys()
        .filter_map(|c| step_of.get(c))
        .copied()
        .collect();
    for l in &shared_steps {
        for m in &step_members[l] {
            if !shared.contains_key(m) {
                add_reason(
                    &mut shared,
                    *m,
                    format!("in step lineage {l}, which has a shared member"),
                );
            }
        }
    }

    // ---- claims ----
    let claim_rows = fetch_claims(conn, &all_claims, false).await?;
    let by_id: BTreeMap<Uuid, ClaimRow> = claim_rows.into_iter().map(|c| (c.id, c)).collect();
    let mut left: BTreeMap<Uuid, Left> = BTreeMap::new();
    let mut already: BTreeSet<Uuid> = BTreeSet::new();
    let mut candidates: BTreeSet<Uuid> = BTreeSet::new();
    for id in &all_claims {
        let Some(c) = by_id.get(id) else {
            left.insert(*id, Left::NotFound);
            continue;
        };
        if c.owner == target && c.visibility == PUBLIC {
            already.insert(*id);
        } else if let Some(by) = shared.get(id) {
            left.insert(*id, Left::Shared(by.iter().cloned().collect()));
        } else if c.owner != source {
            left.insert(*id, Left::NotSourceOwned { owner: c.owner });
        } else if c.visibility != PUBLIC {
            left.insert(
                *id,
                Left::NotPublic {
                    visibility: c.visibility.clone(),
                },
            );
        } else {
            candidates.insert(*id);
        }
    }

    // ---- cascaded rows ----
    let cand: Vec<Uuid> = candidates.iter().copied().collect();
    let attached = fetch_attached(conn, specs, &cand).await?;
    for a in attached.values() {
        if a.writer_owned == Some(true) {
            continue;
        }
        let ok = a.tenancy.owner == source
            && a.tenancy.visibility == PUBLIC
            && a.tenancy.co_owner.is_none()
            && !a.shared_outside;
        if !ok {
            for c in a.claims.intersection(&candidates) {
                left.entry(*c).or_insert_with(|| Left::ForeignRow {
                    table: a.table.clone(),
                    id: a.pk.clone(),
                    state: format!(
                        "({}, {}){}",
                        a.tenancy.owner,
                        a.tenancy.visibility,
                        if a.shared_outside {
                            ", shared with a claim outside the plans"
                        } else {
                            ""
                        }
                    ),
                });
            }
        }
    }
    candidates.retain(|c| !left.contains_key(c));

    // ---- edges ----
    let edge_rows = fetch_edges(conn, &all_claims, &wall).await?;
    for e in &edge_rows {
        if e.endpoints_public {
            continue;
        }
        for (id, ty) in [&e.source, &e.target] {
            if ty == "claim" && candidates.contains(id) {
                left.entry(*id)
                    .or_insert(Left::EdgeEndpointNotPublic { edge: e.id });
            }
        }
    }
    candidates.retain(|c| !left.contains_key(c));
    // A cascaded row shared by a moving claim and one that stays (a harvester
    // fragment) would move with the first: the first stays too, to a fixpoint.
    loop {
        let mut more = Vec::new();
        for a in attached.values() {
            if a.writer_owned == Some(true) || a.claims.iter().all(|c| candidates.contains(c)) {
                continue;
            }
            for c in a.claims.iter().filter(|c| candidates.contains(c)) {
                more.push((*c, a.table.clone(), a.pk.clone()));
            }
        }
        if more.is_empty() {
            break;
        }
        for (c, table, id) in more {
            left.entry(c).or_insert(Left::ForeignRow {
                table,
                id,
                state: "shared with a plan claim that stays".to_string(),
            });
            candidates.remove(&c);
        }
    }

    let inside =
        |id: &Uuid| wf_lineage.contains_key(id) || candidates.contains(id) || already.contains(id);
    let lineage_of = |id: &Uuid| -> Option<String> {
        wf_lineage.get(id).cloned().or_else(|| {
            claim_lineages
                .get(id)
                .and_then(|s| s.iter().next().cloned())
        })
    };
    // Rows shared by two plans' claims join their components.
    for a in attached.values() {
        let ls: Vec<String> = a
            .claims
            .iter()
            .filter(|c| candidates.contains(c))
            .filter_map(&lineage_of)
            .collect();
        for w in ls.windows(2) {
            dsu.union(&w[0], &w[1]);
        }
    }
    let mut moving_edges: Vec<EdgeRow> = Vec::new();
    let mut kept_edges: Vec<(EdgeRow, &'static str)> = Vec::new();
    for e in edge_rows {
        // Any edge between two plan rows joins their lineages (whatever stays
        // or moves), so a batch's re-plan of its own lineages reads exactly
        // what the whole plan read.
        if let (Some(a), Some(b)) = (lineage_of(&e.source.0), lineage_of(&e.target.0)) {
            dsu.union(&a, &b);
        }
        let (s_in, t_in) = (inside(&e.source.0), inside(&e.target.0));
        if !s_in && !t_in {
            continue;
        }
        let plan_rel = PLAN_RELATIONSHIPS.contains(&e.relationship.as_str());
        let why: Option<&'static str> = if e.tenancy.owner == target {
            Some("already the target's")
        } else if e.tenancy.owner == WORLD {
            Some("structural: world-owned (a workflow, agent or paper endpoint)")
        } else if e.tenancy.owner != source {
            Some("owned by another group")
        } else if e.tenancy.visibility != PUBLIC || e.tenancy.co_owner.is_some() {
            Some("source-owned but not public, or co-owned")
        } else if !e.endpoints_public {
            Some("an endpoint is not public")
        } else if !(plan_rel || (s_in && t_in)) {
            Some("source-owned, not a plan edge, one endpoint outside the plans")
        } else {
            None
        };
        match why {
            None => moving_edges.push(e),
            Some(w) => kept_edges.push((e, w)),
        }
    }

    // ---- components ----
    let mut comps: BTreeMap<String, Component> = BTreeMap::new();
    for (n, gens) in &eligible {
        let root = dsu.find(n);
        let c = comps.entry(root).or_default();
        c.lineages.push(n.clone());
        c.workflows
            .extend(gens.iter().filter(|w| w.tenancy.owner == source).cloned());
    }
    let root_of = |id: &Uuid, dsu: &mut Dsu| lineage_of(id).map(|l| dsu.find(&l));
    for id in &candidates {
        if let Some(r) = root_of(id, &mut dsu) {
            if let Some(c) = comps.get_mut(&r) {
                c.claims.push(by_id[id].clone());
            }
        }
    }
    for (id, why) in &left {
        if let Some(r) = root_of(id, &mut dsu) {
            if let Some(c) = comps.get_mut(&r) {
                c.left.push((*id, why.clone()));
            }
        }
    }
    for id in &already {
        if let Some(r) = root_of(id, &mut dsu) {
            if let Some(c) = comps.get_mut(&r) {
                c.already_claims.push(*id);
            }
        }
    }
    for (k, a) in attached {
        let Some(owner_claim) = a.claims.iter().find(|c| candidates.contains(c)).copied() else {
            continue;
        };
        if let Some(r) = root_of(&owner_claim, &mut dsu) {
            if let Some(c) = comps.get_mut(&r) {
                if a.writer_owned == Some(true) {
                    c.kept_rows.insert(k, a);
                } else {
                    c.rows.insert(k, a);
                }
            }
        }
    }
    let edge_root = |e: &EdgeRow, dsu: &mut Dsu| {
        [&e.source.0, &e.target.0]
            .into_iter()
            .filter(|id| inside(id))
            .find_map(|id| lineage_of(id).map(|l| dsu.find(&l)))
    };
    for e in moving_edges {
        if let Some(r) = edge_root(&e, &mut dsu) {
            if let Some(c) = comps.get_mut(&r) {
                c.edges.push(e);
            }
        }
    }
    for (e, w) in kept_edges {
        if let Some(r) = edge_root(&e, &mut dsu) {
            if let Some(c) = comps.get_mut(&r) {
                c.edges_kept.push((e, w));
            }
        }
    }
    for c in comps.values_mut() {
        c.lineages.sort();
    }
    out.components = comps.into_values().collect();
    Ok(out)
}

/// Every edge with an endpoint among `claims` (as a claim) or `workflows` (as
/// a workflow), with its tenancy and whether both endpoints are public under
/// `epigraph_node_tenancy` (the function the edges trigger meets with).
async fn fetch_edges(
    conn: &mut PgConnection,
    claims: &[Uuid],
    workflows: &[Uuid],
) -> anyhow::Result<Vec<EdgeRow>> {
    let rows = sqlx::query(
        "SELECT e.id, e.source_id, e.source_type::text, e.target_id, e.target_type::text, \
                e.relationship::text, e.owner_group_id, e.visibility::text, e.co_owner_group_id, \
                e.writer_group_id, (s.v = 'public' AND t.v = 'public') \
           FROM edges e \
           CROSS JOIN LATERAL public.epigraph_node_tenancy(e.source_id, e.source_type) s \
           CROSS JOIN LATERAL public.epigraph_node_tenancy(e.target_id, e.target_type) t \
          WHERE (e.source_type = 'claim' AND e.source_id = ANY($1)) \
             OR (e.target_type = 'claim' AND e.target_id = ANY($1)) \
             OR (e.source_type = 'workflow' AND e.source_id = ANY($2)) \
             OR (e.target_type = 'workflow' AND e.target_id = ANY($2)) \
          ORDER BY e.id",
    )
    .bind(claims)
    .bind(workflows)
    .fetch_all(&mut *conn)
    .await
    .context("reading edges")?;
    Ok(rows
        .iter()
        .map(|r| EdgeRow {
            id: r.get(0),
            source: (r.get(1), r.get(2)),
            target: (r.get(3), r.get(4)),
            relationship: r.get(5),
            tenancy: Tenancy {
                owner: r.get(6),
                visibility: r.get(7),
                co_owner: r.get(8),
            },
            writer_group: r.get(9),
            endpoints_public: r.get(10),
        })
        .collect())
}

async fn fetch_edges_by_id(conn: &mut PgConnection, ids: &[Uuid]) -> anyhow::Result<Vec<EdgeRow>> {
    let rows = sqlx::query(
        "SELECT e.id, e.source_id, e.source_type::text, e.target_id, e.target_type::text, \
                e.relationship::text, e.owner_group_id, e.visibility::text, e.co_owner_group_id, \
                e.writer_group_id, true \
           FROM edges e WHERE e.id = ANY($1) ORDER BY e.id",
    )
    .bind(ids)
    .fetch_all(&mut *conn)
    .await
    .context("re-reading edges")?;
    Ok(rows
        .iter()
        .map(|r| EdgeRow {
            id: r.get(0),
            source: (r.get(1), r.get(2)),
            target: (r.get(3), r.get(4)),
            relationship: r.get(5),
            tenancy: Tenancy {
                owner: r.get(6),
                visibility: r.get(7),
                co_owner: r.get(8),
            },
            writer_group: r.get(9),
            endpoints_public: r.get(10),
        })
        .collect())
}

async fn workflow_tenancy(
    conn: &mut PgConnection,
    ids: &[Uuid],
) -> anyhow::Result<BTreeMap<Uuid, Tenancy>> {
    let rows: Vec<(Uuid, Uuid, String)> = sqlx::query_as(
        "SELECT id, owner_group_id, visibility::text FROM workflows WHERE id = ANY($1)",
    )
    .bind(ids)
    .fetch_all(&mut *conn)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, owner, visibility)| {
            (
                id,
                Tenancy {
                    owner,
                    visibility,
                    co_owner: None,
                },
            )
        })
        .collect())
}

async fn atlas_epoch(conn: &mut PgConnection) -> anyhow::Result<Option<i64>> {
    let exists: bool =
        sqlx::query_scalar("SELECT to_regclass('public.atlas_layout_epoch') IS NOT NULL")
            .fetch_one(&mut *conn)
            .await?;
    if !exists {
        return Ok(None);
    }
    Ok(Some(
        sqlx::query_scalar("SELECT n FROM atlas_layout_epoch")
            .fetch_one(&mut *conn)
            .await?,
    ))
}

/// The `workflows` and `edges` keys an UNSTAMPED `epigraph_app` session reads
/// among `wf` and `edges` (the claims and cascaded rows go through
/// `tables::app_readable`).
async fn app_readable_wf_edges(
    conn: &mut PgConnection,
    wf: &[Uuid],
    edges: &[Uuid],
) -> anyhow::Result<BTreeSet<RowKey>> {
    sqlx::query("SET LOCAL SESSION AUTHORIZATION epigraph_app")
        .execute(&mut *conn)
        .await
        .context("SET LOCAL SESSION AUTHORIZATION epigraph_app was refused")?;
    let inner = async {
        sqlx::query(
            "SELECT set_config('epigraph.group_ids', '', true), \
                    set_config('epigraph.writable_group_ids', '', true), \
                    set_config('epigraph.principal_id', '', true), \
                    set_config('epigraph.elevation_id', '', true), \
                    set_config('epigraph.family_id', '', true)",
        )
        .execute(&mut *conn)
        .await?;
        let bypass: bool = sqlx::query_scalar("SELECT public.epigraph_bypass()")
            .fetch_one(&mut *conn)
            .await?;
        if bypass {
            bail!(
                "epigraph_app reports epigraph_bypass() = true; the readability check is vacuous"
            );
        }
        let mut out = BTreeSet::new();
        let w: Vec<String> =
            sqlx::query_scalar("SELECT id::text FROM workflows WHERE id = ANY($1)")
                .bind(wf)
                .fetch_all(&mut *conn)
                .await?;
        out.extend(w.into_iter().map(|k| ("workflows".to_string(), k)));
        let e: Vec<String> = sqlx::query_scalar("SELECT id::text FROM edges WHERE id = ANY($1)")
            .bind(edges)
            .fetch_all(&mut *conn)
            .await?;
        out.extend(e.into_iter().map(|k| ("edges".to_string(), k)));
        Ok::<_, anyhow::Error>(out)
    }
    .await;
    let reset = sqlx::query("SET LOCAL SESSION AUTHORIZATION DEFAULT")
        .execute(&mut *conn)
        .await;
    let out = inner?;
    reset?;
    Ok(out)
}

async fn write_audit(
    conn: &mut PgConnection,
    event_type: &str,
    operator: Uuid,
    details: Value,
) -> anyhow::Result<()> {
    let (client_addr, _) = SecurityEventRepository::connection_origin_conn(conn).await?;
    let row = SecurityEventRow {
        id: Uuid::new_v4(),
        event_type: event_type.to_string(),
        agent_id: Some(operator),
        success: Some(true),
        details,
        ip_address: client_addr,
        user_agent: None,
        correlation_id: None,
        created_at: chrono::Utc::now(),
    };
    SecurityEventRepository::log_conn(conn, &row)
        .await
        .context("writing the audit row")?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Manifest records
// ─────────────────────────────────────────────────────────────────────────────

fn rec(table: &str, id: Value, t: &Tenancy, anchor: Uuid, after: bool, edge: bool) -> Record {
    Record {
        table: table.to_string(),
        id,
        owner_group_id: t.owner,
        visibility: t.visibility.clone(),
        co_owner_group_id: edge.then_some(t.co_owner),
        claim_id: anchor,
        hidden: false,
        after,
        neighbour: false,
        writer_owned: None,
    }
}

fn spec_of<'a>(specs: &'a [TableSpec], table: &str) -> &'a TableSpec {
    tables::spec(specs, table).expect("attached rows come only from specs")
}

/// Prior records of every row a component moves.
fn prior_records(c: &Component, specs: &[TableSpec]) -> Vec<Record> {
    let mut out = Vec::new();
    for w in &c.workflows {
        out.push(rec(
            "workflows",
            json!(w.id.to_string()),
            &w.tenancy,
            w.id,
            false,
            false,
        ));
    }
    for cl in &c.claims {
        let t = Tenancy {
            owner: cl.owner,
            visibility: cl.visibility.clone(),
            co_owner: None,
        };
        out.push(rec(
            "claims",
            json!(cl.id.to_string()),
            &t,
            cl.id,
            false,
            false,
        ));
    }
    for a in c.rows.values() {
        out.push(rec(
            &a.table,
            spec_of(specs, &a.table).id_json(&a.pk),
            &a.tenancy,
            a.claim,
            false,
            false,
        ));
    }
    for e in &c.edges {
        out.push(rec(
            "edges",
            json!(e.id.to_string()),
            &e.tenancy,
            Uuid::nil(),
            false,
            true,
        ));
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// A batch
// ─────────────────────────────────────────────────────────────────────────────

/// Fixed inputs to every batch.
pub struct Ctx<'a> {
    pub specs: &'a [TableSpec],
    pub unkeyed: &'a [String],
    pub source: Uuid,
    pub target: Uuid,
    pub lock_timeout: &'a str,
}

/// What one batch did.
#[derive(Default, Debug)]
pub struct BatchOutcome {
    pub workflows_moved: usize,
    pub claims_moved: usize,
    pub edges_moved: usize,
    pub rows_moved: BTreeMap<String, usize>,
    pub held: Vec<(Vec<String>, String)>,
}

/// Run one batch (the given components) inside the caller's transaction. Does
/// NOT commit.
///
/// # Errors
/// [`BatchError::Invariant`] when a check fails; [`BatchError::Db`] when a
/// statement fails. Either way the caller rolls the batch back.
#[allow(clippy::too_many_lines)]
pub async fn run_batch(
    conn: &mut PgConnection,
    ctx: &Ctx<'_>,
    planned: &[&Component],
    sink: &mut Sink,
    audit: Option<(&Value, Uuid)>,
) -> Result<BatchOutcome, BatchError> {
    let mut out = BatchOutcome::default();
    sqlx::query("SELECT set_config('lock_timeout', $1, true)")
        .bind(ctx.lock_timeout)
        .execute(&mut *conn)
        .await?;
    sqlx::query("LOCK TABLE public.workflows IN SHARE ROW EXCLUSIVE MODE")
        .execute(&mut *conn)
        .await
        .map_err(|e| BatchError::Db(anyhow!("locking workflows: {e}")))?;
    let names: Vec<String> = planned
        .iter()
        .flat_map(|c| c.lineages.iter().cloned())
        .collect();
    sqlx::query("SELECT id FROM workflows WHERE canonical_name = ANY($1) ORDER BY id FOR UPDATE")
        .bind(&names)
        .fetch_all(&mut *conn)
        .await?;
    let lock_claims: Vec<Uuid> = planned.iter().flat_map(|c| c.claim_ids()).collect();
    fetch_claims(conn, &lock_claims, true).await?;
    tables::lock_unkeyed_tables(conn, ctx.unkeyed).await?;
    let lock_edges: Vec<Uuid> = planned
        .iter()
        .flat_map(|c| c.edges.iter().map(|e| e.id))
        .collect();
    sqlx::query("SELECT id FROM edges WHERE id = ANY($1) ORDER BY id FOR UPDATE")
        .bind(&lock_edges)
        .fetch_all(&mut *conn)
        .await?;

    // ---- re-plan under the locks; hold every component that changed ----
    let now = plan(conn, ctx.specs, &names, ctx.source, ctx.target).await?;
    let mut comps: Vec<Component> = Vec::new();
    for p in planned {
        match now.components.iter().find(|c| c.lineages == p.lineages) {
            Some(c) if c.fingerprint() == p.fingerprint() => comps.push(c.clone()),
            _ => out.held.push((
                p.lineages.clone(),
                "a row of these plans changed since the dry plan read it (another writer); \
                 nothing of them is moved in this run"
                    .to_string(),
            )),
        }
    }
    if comps.is_empty() {
        return Ok(out);
    }

    let wf_ids: Vec<Uuid> = comps
        .iter()
        .flat_map(|c| c.workflows.iter().map(|w| w.id))
        .collect();
    let claim_ids: Vec<Uuid> = comps.iter().flat_map(Component::claim_ids).collect();
    let edge_ids: Vec<Uuid> = comps
        .iter()
        .flat_map(|c| c.edges.iter().map(|e| e.id))
        .collect();
    let kept_edges: Vec<&EdgeRow> = comps
        .iter()
        .flat_map(|c| c.edges_kept.iter().map(|(e, _)| e))
        .collect();
    let kept_edge_ids: Vec<Uuid> = kept_edges.iter().map(|e| e.id).collect();
    let all_edge_ids: Vec<Uuid> = edge_ids.iter().chain(&kept_edge_ids).copied().collect();
    let rows: Snapshot = comps
        .iter()
        .flat_map(|c| c.rows.iter().map(|(k, a)| (k.clone(), a.clone())))
        .collect();
    let kept_rows: Snapshot = comps
        .iter()
        .flat_map(|c| c.kept_rows.iter().map(|(k, a)| (k.clone(), a.clone())))
        .collect();
    let keys: BTreeSet<RowKey> = rows.keys().chain(kept_rows.keys()).cloned().collect();

    // Manifest first, fsynced, before the write it describes.
    let mut prior = Vec::new();
    for c in &comps {
        prior.extend(prior_records(c, ctx.specs));
    }
    sink.record(&prior)?;

    if let Some((details, operator)) = audit {
        write_audit(conn, EVENT_APPLY, operator, details.clone()).await?;
    }
    let readable_before = tables::app_readable(conn, ctx.specs, &claim_ids, &keys).await?;
    let readable_wf_before = app_readable_wf_edges(conn, &wf_ids, &all_edge_ids).await?;
    let epoch_before = atlas_epoch(conn).await?;
    let counters_before = xact_counters(conn).await?;

    let n_wf = sqlx::query(
        "UPDATE workflows SET owner_group_id = $2 \
          WHERE id = ANY($1) AND owner_group_id = $3 AND visibility = 'public'",
    )
    .bind(&wf_ids)
    .bind(ctx.target)
    .bind(ctx.source)
    .execute(&mut *conn)
    .await
    .context("UPDATE workflows")?
    .rows_affected();
    let n_claims = sqlx::query(
        "UPDATE claims SET owner_group_id = $2 \
          WHERE id = ANY($1) AND owner_group_id = $3 AND visibility = 'public'",
    )
    .bind(&claim_ids)
    .bind(ctx.target)
    .bind(ctx.source)
    .execute(&mut *conn)
    .await
    .context("UPDATE claims")?
    .rows_affected();
    let n_edges = sqlx::query(
        "UPDATE edges SET owner_group_id = $2 \
          WHERE id = ANY($1) AND owner_group_id = $3 AND visibility = 'public' \
            AND co_owner_group_id IS NULL",
    )
    .bind(&edge_ids)
    .bind(ctx.target)
    .bind(ctx.source)
    .execute(&mut *conn)
    .await
    .context("UPDATE edges")?
    .rows_affected();

    let counters_after = xact_counters(conn).await?;
    let epoch_after = atlas_epoch(conn).await?;
    let wf_after = workflow_tenancy(conn, &wf_ids).await?;
    let claims_after = fetch_claims(conn, &claim_ids, false).await?;
    let attached_after = fetch_attached(conn, ctx.specs, &claim_ids).await?;
    let edges_after: BTreeMap<Uuid, EdgeRow> = fetch_edges_by_id(conn, &all_edge_ids)
        .await?
        .into_iter()
        .map(|e| (e.id, e))
        .collect();
    let readable_after = tables::app_readable(conn, ctx.specs, &claim_ids, &keys).await?;
    let readable_wf_after = app_readable_wf_edges(conn, &wf_ids, &all_edge_ids).await?;

    // ---- invariants ----
    let moved = Tenancy {
        owner: ctx.target,
        visibility: PUBLIC.into(),
        co_owner: None,
    };
    let mut v = Vec::new();
    for (what, n, want) in [
        ("workflows", n_wf, wf_ids.len()),
        ("claims", n_claims, claim_ids.len()),
        ("edges", n_edges, edge_ids.len()),
    ] {
        if usize::try_from(n).ok() != Some(want) {
            v.push(format!(
                "UPDATE {what} moved {n} row(s), the batch planned {want}"
            ));
        }
    }
    for id in &wf_ids {
        if wf_after.get(id) != Some(&moved) {
            v.push(format!("workflow {id} ended as {:?}", wf_after.get(id)));
        }
    }
    for c in &claims_after {
        if c.owner != ctx.target || c.visibility != PUBLIC {
            v.push(format!(
                "claim {} ended as ({}, {})",
                c.id, c.owner, c.visibility
            ));
        }
    }
    let mut rows_moved: BTreeMap<String, usize> = BTreeMap::new();
    for k in rows.keys() {
        match attached_after.get(k) {
            Some(b) if b.tenancy == moved => *rows_moved.entry(k.0.clone()).or_default() += 1,
            other => v.push(format!(
                "{} {} ended as {:?}, the plan says {moved:?}",
                k.0,
                k.1,
                other.map(|b| &b.tenancy)
            )),
        }
    }
    for (k, a) in &kept_rows {
        if attached_after.get(k).map(|b| &b.tenancy) != Some(&a.tenancy) {
            v.push(format!(
                "writer-owned {} {} changed; it must stay its writer's",
                k.0, k.1
            ));
        }
    }
    for k in attached_after.keys() {
        if !keys.contains(k) {
            v.push(format!("{} {} appeared during the batch", k.0, k.1));
        }
    }
    let planned_edges: BTreeMap<Uuid, &EdgeRow> = comps
        .iter()
        .flat_map(|c| c.edges.iter().map(|e| (e.id, e)))
        .collect();
    for (id, before) in &planned_edges {
        match edges_after.get(id) {
            Some(e) if e.tenancy == moved && e.writer_group == before.writer_group => {}
            other => v.push(format!(
                "edge {id} ended as {:?} (writer {:?}); the plan says {moved:?} with writer \
                 {:?} unchanged",
                other.map(|e| &e.tenancy),
                other.map(|e| e.writer_group),
                before.writer_group
            )),
        }
    }
    for before in &kept_edges {
        match edges_after.get(&before.id) {
            Some(e) if e.tenancy == before.tenancy && e.writer_group == before.writer_group => {}
            other => v.push(format!(
                "edge {} that stays changed to {:?}",
                before.id,
                other.map(|e| &e.tenancy)
            )),
        }
    }
    let mut expect: BTreeMap<String, (i64, i64, i64)> = BTreeMap::new();
    let as_i64 = |n: usize| i64::try_from(n).unwrap_or(i64::MAX);
    for (t, n) in [
        ("workflows", wf_ids.len()),
        ("claims", claim_ids.len()),
        ("edges", edge_ids.len()),
    ] {
        expect.insert(t.to_string(), (0, as_i64(n), 0));
    }
    let mut planned_rows: BTreeMap<String, usize> = BTreeMap::new();
    for k in rows.keys() {
        *planned_rows.entry(k.0.clone()).or_default() += 1;
    }
    for (t, n) in &planned_rows {
        expect.entry(t.clone()).or_default().1 += as_i64(*n);
    }
    expect.retain(|_, d| *d != (0, 0, 0));
    v.extend(counter_violations(
        &counter_delta(&counters_before, &counters_after),
        &expect,
    ));
    if epoch_before != epoch_after {
        v.push(format!(
            "atlas_layout_epoch moved {epoch_before:?} -> {epoch_after:?}; a public-to-public \
             move must not narrow anything (migration 197)"
        ));
    }
    if readable_before != readable_after || readable_wf_before != readable_wf_after {
        v.push(
            "the rows an unstamped epigraph_app session can read changed; a re-own must not \
             change visibility"
                .to_string(),
        );
    }
    if !v.is_empty() {
        return Err(BatchError::Invariant(v));
    }

    // ---- post records, fsynced before the caller commits ----
    let mut post = Vec::new();
    for id in &wf_ids {
        post.push(rec(
            "workflows",
            json!(id.to_string()),
            &moved,
            *id,
            true,
            false,
        ));
    }
    for id in &claim_ids {
        post.push(rec(
            "claims",
            json!(id.to_string()),
            &moved,
            *id,
            true,
            false,
        ));
    }
    for (k, a) in &rows {
        post.push(rec(
            &k.0,
            spec_of(ctx.specs, &k.0).id_json(&k.1),
            &moved,
            a.claim,
            true,
            false,
        ));
    }
    for id in &edge_ids {
        post.push(rec(
            "edges",
            json!(id.to_string()),
            &moved,
            Uuid::nil(),
            true,
            true,
        ));
    }
    sink.record_post(&post)?;
    out.workflows_moved = wf_ids.len();
    out.claims_moved = claim_ids.len();
    out.edges_moved = edge_ids.len();
    out.rows_moved = rows_moved;
    Ok(out)
}

// ─────────────────────────────────────────────────────────────────────────────
// The run
// ─────────────────────────────────────────────────────────────────────────────

/// The whole run's result.
#[derive(Default, Debug)]
pub struct RunReport {
    pub eligible_workflow_rows: usize,
    pub batches_ok: usize,
    pub batch_failures: Vec<(usize, String)>,
    pub workflows_moved: usize,
    pub claims_moved: usize,
    pub edges_moved: usize,
    pub rows_moved: BTreeMap<String, usize>,
    pub held_under_lock: Vec<(Vec<String>, String)>,
    pub audit_written: bool,
}

fn print_plan(out: &mut dyn std::io::Write, p: &Plan) -> anyhow::Result<usize> {
    for (n, h) in &p.held {
        writeln!(out, "HELD-LINEAGE\t{n}\t{h}")?;
    }
    for n in &p.already {
        writeln!(
            out,
            "ALREADY-LINEAGE\t{n}\tevery generation is the target's"
        )?;
    }
    let mut eligible_rows = 0usize;
    let mut claims = 0usize;
    let mut rows: BTreeMap<String, usize> = BTreeMap::new();
    let mut kept_rows: BTreeMap<String, usize> = BTreeMap::new();
    let mut edges: BTreeMap<String, usize> = BTreeMap::new();
    let mut kept_edges: BTreeMap<&str, usize> = BTreeMap::new();
    for c in &p.components {
        writeln!(out, "COMPONENT\t{}", c.lineages.join(","))?;
        for w in &c.workflows {
            writeln!(
                out,
                "WORKFLOW\t{}\t{}\tgeneration {}",
                w.id, w.canonical_name, w.generation
            )?;
        }
        for (id, why) in &c.left {
            writeln!(out, "LEFT-CLAIM\t{id}\t{why}")?;
        }
        eligible_rows += c.workflows.len();
        claims += c.claims.len();
        for k in c.rows.keys() {
            *rows.entry(k.0.clone()).or_default() += 1;
        }
        for k in c.kept_rows.keys() {
            *kept_rows.entry(k.0.clone()).or_default() += 1;
        }
        for e in &c.edges {
            *edges.entry(e.relationship.clone()).or_default() += 1;
        }
        for (_, w) in &c.edges_kept {
            *kept_edges.entry(*w).or_default() += 1;
        }
    }
    writeln!(out, "CLAIMS-MOVE\t{claims}")?;
    for (t, n) in &rows {
        writeln!(
            out,
            "ROWS-MOVE\t{t}\t{n}\t(the cascade carries them with their claim)"
        )?;
    }
    for (t, n) in &kept_rows {
        writeln!(
            out,
            "ROWS-KEPT\t{t}\t{n}\t(writer-owned: they stay their writer's)"
        )?;
    }
    for (r, n) in &edges {
        writeln!(out, "EDGES-MOVE\t{r}\t{n}")?;
    }
    for (w, n) in &kept_edges {
        writeln!(out, "EDGES-STAY\t{n}\t{w}")?;
    }
    writeln!(out, "ELIGIBLE-WORKFLOW-ROWS\t{eligible_rows}")?;
    Ok(eligible_rows)
}

/// Plan, then run every batch.
///
/// # Errors
/// A refusal or a failure outside a batch (groups, plan, `--confirm-count`,
/// the manifest, the connection).
#[allow(clippy::too_many_lines)]
pub async fn run(
    conn: &mut PgConnection,
    opts: &Options,
    names: &[String],
    out: &mut dyn std::io::Write,
) -> anyhow::Result<RunReport> {
    let mut report = RunReport::default();
    let specs: Vec<TableSpec> = tables::propagated_tables(conn)
        .await?
        .into_iter()
        .filter(|s| s.kind != Kind::Edges)
        .collect();
    let unkeyed = tables::unkeyed_tables(conn, &specs).await?;
    let (source, target) = resolve_groups(conn, opts).await?;
    tables::probe_session_switch(conn).await?;
    let names_sha256 = sha256_file(&opts.names_file)?;

    let p = plan(conn, &specs, names, source, target).await?;
    writeln!(
        out,
        "reown-workflows: operator={} source_group={source} target_group={target} mode={}",
        opts.operator,
        if opts.apply { "APPLY" } else { "DRY-RUN" }
    )?;
    writeln!(
        out,
        "PLAN: {} lineage(s) listed, {} held, {} already the target's, {} component(s) to move",
        names.len(),
        p.held.len(),
        p.already.len(),
        p.components.len()
    )?;
    let eligible = print_plan(out, &p)?;
    report.eligible_workflow_rows = eligible;
    writeln!(
        out,
        "RULE: only ('public', source) rows move and no visibility is written; structural \
         world-owned edges (executes, variant_of, asserts) are no group's and stay; \
         writer_group_id is not rewritten"
    )?;
    if opts.apply && opts.confirm_count != Some(eligible) {
        bail!(
            "--confirm-count {:?} does not match the plan's ELIGIBLE-WORKFLOW-ROWS {eligible}; \
             refusing. Nothing was written.",
            opts.confirm_count
        );
    }
    if p.components.is_empty() {
        writeln!(out, "RESULT\n  nothing to move; no manifest written")?;
        return Ok(report);
    }

    // ---- manifest ----
    let header = json!({
        "manifest": "epigraph-operator reown-workflows",
        "operation": OPERATION,
        "version": manifest::VERSION,
        "operator": opts.operator,
        "source_group_id": source,
        "target_group_id": target,
        "created_at": chrono::Utc::now().to_rfc3339(),
        "ruling": opts.ruling,
        "reason": opts.reason,
        "names_file_sha256": names_sha256,
        "lineages": p.components.iter().flat_map(|c| c.lineages.clone()).collect::<Vec<_>>(),
    });
    let header_sha256 = sha256_hex(serde_json::to_string(&header)?.as_bytes());
    let mut sink = if opts.apply {
        Sink::File(Writer::create_new(&opts.manifest_out, &header)?)
    } else {
        Sink::Memory(Default::default(), 0)
    };
    writeln!(
        out,
        "MANIFEST\t{}\t{}",
        opts.manifest_out.display(),
        if opts.apply {
            "header written and fsynced; each batch records its rows before its write"
        } else {
            "(dry run: not written)"
        }
    )?;
    let audit_details = json!({
        "tool": "epigraph-operator",
        "command": "reown-workflows",
        "ruling": opts.ruling,
        "reason": opts.reason,
        "operator_person": opts.operator,
        "operator": operator_details(conn).await?,
        "source_group_id": source,
        "target_group_id": target,
        "names_file_sha256": names_sha256,
        "manifest_path": opts.manifest_out.display().to_string(),
        "manifest_header_sha256": header_sha256,
        "planned": {
            "listed": names.len(),
            "held": p.held.len(),
            "already": p.already.len(),
            "components": p.components.len(),
            "eligible_workflow_rows": eligible,
        },
        "batch_size": opts.batch_size,
    });

    // ---- batches: whole components, up to batch_size lineages each ----
    let mut batches: Vec<Vec<&Component>> = Vec::new();
    let mut cur: Vec<&Component> = Vec::new();
    let mut cur_n = 0usize;
    for c in &p.components {
        if !cur.is_empty() && cur_n + c.lineages.len() > opts.batch_size {
            batches.push(std::mem::take(&mut cur));
            cur_n = 0;
        }
        cur_n += c.lineages.len();
        cur.push(c);
    }
    if !cur.is_empty() {
        batches.push(cur);
    }
    let ctx = Ctx {
        specs: &specs,
        unkeyed: &unkeyed,
        source,
        target,
        lock_timeout: &opts.lock_timeout,
    };
    let total = batches.len();
    for (i, batch) in batches.iter().enumerate() {
        let mut tx = sqlx::Connection::begin(&mut *conn).await?;
        let audit =
            (opts.apply && !report.audit_written).then_some((&audit_details, opts.operator));
        let r = run_batch(&mut tx, &ctx, batch, &mut sink, audit).await;
        let ok = r.is_ok();
        let wrote = matches!(&r, Ok(b) if b.workflows_moved + b.claims_moved + b.edges_moved > 0);
        if opts.apply && ok && wrote {
            tx.commit().await?;
            report.audit_written = true;
        } else {
            tx.rollback().await?;
        }
        match r {
            Ok(b) => {
                report.batches_ok += 1;
                report.workflows_moved += b.workflows_moved;
                report.claims_moved += b.claims_moved;
                report.edges_moved += b.edges_moved;
                for (t, n) in b.rows_moved {
                    *report.rows_moved.entry(t).or_default() += n;
                }
                writeln!(
                    out,
                    "BATCH {}/{total}\tOK\t{} workflow row(s), {} claim(s), {} edge(s){}",
                    i + 1,
                    b.workflows_moved,
                    b.claims_moved,
                    b.edges_moved,
                    if opts.apply {
                        ""
                    } else {
                        " (rolled back: dry run)"
                    }
                )?;
                report.held_under_lock.extend(b.held);
            }
            Err(e) => {
                writeln!(out, "BATCH {}/{total}\tROLLED BACK\t{e}", i + 1)?;
                report.batch_failures.push((i + 1, e.to_string()));
                if opts.apply {
                    writeln!(out, "STOPPED: no further batch was attempted")?;
                    break;
                }
            }
        }
    }
    for (ls, why) in &report.held_under_lock {
        writeln!(out, "HELD-UNDER-LOCK\t{}\t{why}", ls.join(","))?;
    }
    writeln!(out, "RESULT")?;
    writeln!(out, "  workflow rows moved: {}", report.workflows_moved)?;
    writeln!(out, "  claims moved: {}", report.claims_moved)?;
    writeln!(out, "  edges moved: {}", report.edges_moved)?;
    for (t, n) in &report.rows_moved {
        writeln!(out, "  {t}: rows moved with their claim: {n}")?;
    }
    writeln!(
        out,
        "  invariants: {}",
        if report.batch_failures.is_empty() {
            "all held in every batch (visibility unchanged, atlas epoch unchanged)".to_string()
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
            "DRY RUN: each batch ran in its own transaction and was rolled back; no manifest and \
             no audit row were written."
        )?;
    }
    Ok(report)
}

// ─────────────────────────────────────────────────────────────────────────────
// Reversal
// ─────────────────────────────────────────────────────────────────────────────

/// Whether a manifest is a `reown-workflows` one.
#[must_use]
pub fn is_reown_workflows_manifest(m: &manifest::Manifest) -> bool {
    m.header.get("operation").and_then(Value::as_str) == Some(OPERATION)
}

fn header_uuid(m: &manifest::Manifest, key: &str, path: &Path) -> anyhow::Result<Uuid> {
    m.header
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("{}: header has no {key}", path.display()))
        .and_then(|s| Uuid::parse_str(s).with_context(|| format!("{}: {key}", path.display())))
}

/// Restore one reown-workflows manifest, all of it in one transaction, or
/// nothing. Returns `false` when the caller must stop (an `--apply` that was
/// refused or failed).
///
/// # Errors
/// A malformed manifest or a failure outside the transaction's checks.
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
pub async fn reverse_manifest(
    conn: &mut PgConnection,
    path: &Path,
    m: &manifest::Manifest,
    all_specs: &[TableSpec],
    unkeyed: &[String],
    opts: &super::reverse::Options,
    report: &mut super::reverse::Report,
    out: &mut dyn std::io::Write,
) -> anyhow::Result<bool> {
    if m.header.get("version").and_then(Value::as_i64) != Some(manifest::VERSION) {
        bail!(
            "{}: manifest version is not {}; refusing",
            path.display(),
            manifest::VERSION
        );
    }
    let specs: Vec<TableSpec> = all_specs
        .iter()
        .filter(|s| s.kind != Kind::Edges)
        .cloned()
        .collect();
    let source = header_uuid(m, "source_group_id", path)?;
    let target = header_uuid(m, "target_group_id", path)?;
    let operator = header_uuid(m, "operator", path)?;

    // ---- the records ----
    let mut prior: BTreeMap<RowKey, Record> = BTreeMap::new();
    let mut post: BTreeMap<RowKey, Record> = BTreeMap::new();
    for r in &m.records {
        let pk = match r.table.as_str() {
            "workflows" | "claims" | "edges" => {
                r.id.as_str()
                    .ok_or_else(|| anyhow!("{}: {} id is not a string", path.display(), r.table))?
                    .to_string()
            }
            t => tables::spec(&specs, t)
                .ok_or_else(|| {
                    anyhow!(
                        "{}: names table {t}, which the live cascade does not reach; refusing",
                        path.display()
                    )
                })?
                .pk_from_json(&r.id)?,
        };
        let key = (r.table.clone(), pk);
        if r.after {
            post.insert(key, r.clone());
        } else {
            prior.entry(key).or_insert_with(|| r.clone());
        }
    }
    let ids_of = |t: &str| -> Vec<Uuid> {
        post.keys()
            .filter(|k| k.0 == t)
            .filter_map(|k| Uuid::parse_str(&k.1).ok())
            .collect()
    };
    let wf_ids = ids_of("workflows");
    let claim_ids = ids_of("claims");
    let edge_ids = ids_of("edges");
    let all_wf_prior: Vec<Uuid> = prior
        .keys()
        .filter(|k| k.0 == "workflows")
        .filter_map(|k| Uuid::parse_str(&k.1).ok())
        .collect();
    writeln!(
        out,
        "REOWN-WORKFLOWS-MANIFEST\t{}\tsource_group={source}\ttarget_group={target}\t\
         moved: {} workflow row(s), {} claim(s), {} edge(s)",
        path.display(),
        wf_ids.len(),
        claim_ids.len(),
        edge_ids.len()
    )?;
    if post.is_empty() {
        writeln!(out, "  nothing was moved by this run; nothing to reverse")?;
        return Ok(true);
    }

    let mut tx = sqlx::Connection::begin(&mut *conn).await?;
    let r = reverse_tx(
        &mut tx,
        &specs,
        unkeyed,
        &opts.lock_timeout,
        target,
        (&prior, &post),
        (&wf_ids, &claim_ids, &edge_ids, &all_wf_prior),
        opts.apply.then(|| {
            (
                json!({
                    "tool": "epigraph-operator",
                    "command": "reown-reverse (reown-workflows manifest)",
                    "ruling": m.header.get("ruling"),
                    "operator_person": operator,
                    "source_group_id": source,
                    "target_group_id": target,
                    "manifest_path": path.display().to_string(),
                    "manifest_sha256": sha256_file(path).unwrap_or_default(),
                }),
                operator,
            )
        }),
    )
    .await;
    match r {
        Ok(RevOutcome::Held(held)) => {
            tx.rollback().await?;
            writeln!(
                out,
                "  REFUSED: {} row(s) changed since the run; nothing of this manifest is restored",
                held.len()
            )?;
            report.held.extend(held);
            Ok(!opts.apply)
        }
        Ok(RevOutcome::Already(n)) => {
            tx.rollback().await?;
            writeln!(
                out,
                "  every moved row ({n}) is already on its recorded prior state"
            )?;
            report.already += claim_ids.len();
            Ok(true)
        }
        Ok(RevOutcome::Restored(by_table)) => {
            if opts.apply {
                tx.commit().await?;
            } else {
                tx.rollback().await?;
            }
            for (t, n) in &by_table {
                writeln!(
                    out,
                    "  {t}: {n} row(s) restored to the recorded prior{}",
                    if opts.apply {
                        ""
                    } else {
                        " (dry run: rolled back)"
                    }
                )?;
                if t == "claims" {
                    report.claims_restored += n;
                } else {
                    *report.rows_restored.entry(t.clone()).or_default() += n;
                }
            }
            Ok(true)
        }
        Err(e) => {
            tx.rollback().await?;
            writeln!(out, "  ROLLED BACK\t{e}")?;
            report.batch_failures.push((0, e.to_string()));
            Ok(!opts.apply)
        }
    }
}

enum RevOutcome {
    Held(Vec<(Uuid, String)>),
    Already(usize),
    Restored(BTreeMap<String, usize>),
}

fn same(r: &Record, t: &Tenancy) -> bool {
    r.owner_group_id == t.owner
        && r.visibility == t.visibility
        && r.co_owner_group_id.is_none_or(|co| co == t.co_owner)
}

fn payload(recs: &[&Record]) -> Value {
    Value::Array(
        recs.iter()
            .map(|r| {
                json!({
                    "id": r.id,
                    "o": r.owner_group_id,
                    "co": r.co_owner_group_id.flatten(),
                })
            })
            .collect(),
    )
}

#[allow(
    clippy::too_many_lines,
    clippy::too_many_arguments,
    clippy::type_complexity
)]
async fn reverse_tx(
    conn: &mut PgConnection,
    specs: &[TableSpec],
    unkeyed: &[String],
    lock_timeout: &str,
    target: Uuid,
    (prior, post): (&BTreeMap<RowKey, Record>, &BTreeMap<RowKey, Record>),
    (wf_ids, claim_ids, edge_ids, all_wf_prior): (&[Uuid], &[Uuid], &[Uuid], &[Uuid]),
    audit: Option<(Value, Uuid)>,
) -> Result<RevOutcome, BatchError> {
    sqlx::query("SELECT set_config('lock_timeout', $1, true)")
        .bind(lock_timeout)
        .execute(&mut *conn)
        .await?;
    sqlx::query("LOCK TABLE public.workflows IN SHARE ROW EXCLUSIVE MODE")
        .execute(&mut *conn)
        .await?;
    sqlx::query("SELECT id FROM workflows WHERE id = ANY($1) ORDER BY id FOR UPDATE")
        .bind(wf_ids)
        .fetch_all(&mut *conn)
        .await?;
    fetch_claims(conn, claim_ids, true).await?;
    tables::lock_unkeyed_tables(conn, unkeyed).await?;
    sqlx::query("SELECT id FROM edges WHERE id = ANY($1) ORDER BY id FOR UPDATE")
        .bind(edge_ids)
        .fetch_all(&mut *conn)
        .await?;

    // ---- current state ----
    let wf_now = workflow_tenancy(conn, wf_ids).await?;
    let claims_now: BTreeMap<Uuid, Tenancy> = fetch_claims(conn, claim_ids, false)
        .await?
        .into_iter()
        .map(|c| {
            (
                c.id,
                Tenancy {
                    owner: c.owner,
                    visibility: c.visibility,
                    co_owner: None,
                },
            )
        })
        .collect();
    let edges_now: BTreeMap<Uuid, EdgeRow> = fetch_edges_by_id(conn, edge_ids)
        .await?
        .into_iter()
        .map(|e| (e.id, e))
        .collect();
    let attached_now = fetch_attached(conn, specs, claim_ids).await?;
    let current = |k: &RowKey| -> Option<Tenancy> {
        let id = Uuid::parse_str(&k.1).ok();
        match k.0.as_str() {
            "workflows" => id.and_then(|i| wf_now.get(&i).cloned()),
            "claims" => id.and_then(|i| claims_now.get(&i).cloned()),
            "edges" => id.and_then(|i| edges_now.get(&i).map(|e| e.tenancy.clone())),
            _ => attached_now.get(k).map(|a| a.tenancy.clone()),
        }
    };

    // ---- compare-and-swap ----
    let mut held: Vec<(Uuid, String)> = Vec::new();
    let mut restore: Vec<&RowKey> = Vec::new();
    let mut already = 0usize;
    for (k, p) in post {
        let Some(pr) = prior.get(k) else {
            held.push((
                Uuid::nil(),
                format!("{} {}: a post record with no prior", k.0, k.1),
            ));
            continue;
        };
        let anchor = Uuid::parse_str(&k.1).unwrap_or(pr.claim_id);
        match current(k) {
            None => held.push((anchor, format!("{} {} no longer exists", k.0, k.1))),
            Some(t) if same(p, &t) => restore.push(k),
            Some(t) if same(pr, &t) => already += 1,
            Some(t) => held.push((
                anchor,
                format!(
                    "{} {} is ({}, {}), neither the post state ({}, {}) this run left nor its \
                     prior ({}, {}): it changed since",
                    k.0,
                    k.1,
                    t.owner,
                    t.visibility,
                    p.owner_group_id,
                    p.visibility,
                    pr.owner_group_id,
                    pr.visibility
                ),
            )),
        }
    }
    // A lineage this run moved that has gained a workflow row it did not move.
    let names: Vec<String> =
        sqlx::query_scalar("SELECT DISTINCT canonical_name FROM workflows WHERE id = ANY($1)")
            .bind(wf_ids)
            .fetch_all(&mut *conn)
            .await?;
    for (id, name, generation) in sqlx::query_as::<_, (Uuid, String, i32)>(
        "SELECT id, canonical_name, generation FROM workflows \
          WHERE canonical_name = ANY($1) AND id <> ALL($2) ORDER BY canonical_name, generation",
    )
    .bind(&names)
    .bind(all_wf_prior)
    .fetch_all(&mut *conn)
    .await?
    {
        held.push((
            id,
            format!(
                "lineage {name} has workflow row {id} (generation {generation}) that this run did \
                 not move: a generation joined it after the move, and restoring the rest would \
                 split the lineage"
            ),
        ));
    }
    for (c, w) in sqlx::query_as::<_, (Uuid, Uuid)>(
        "SELECT target_id, source_id FROM edges \
          WHERE relationship = 'executes' AND source_type = 'workflow' AND target_type = 'claim' \
            AND target_id = ANY($1) AND source_id <> ALL($2)",
    )
    .bind(claim_ids)
    .bind(all_wf_prior)
    .fetch_all(&mut *conn)
    .await?
    {
        held.push((
            c,
            format!("claim {c} is now also executed by workflow {w}, which this run did not move"),
        ));
    }
    for (k, a) in &attached_now {
        if post.contains_key(k) || a.writer_owned == Some(true) {
            continue;
        }
        if a.tenancy.visibility != PUBLIC || a.tenancy.co_owner.is_some() {
            held.push((
                a.claim,
                format!(
                    "{} {} on a moved claim is ({}, {}): the cascade back would widen it",
                    k.0, k.1, a.tenancy.owner, a.tenancy.visibility
                ),
            ));
        }
    }
    if !held.is_empty() {
        return Ok(RevOutcome::Held(held));
    }
    if restore.is_empty() {
        return Ok(RevOutcome::Already(already));
    }

    // ---- write ----
    if let Some((details, operator)) = audit {
        write_audit(conn, EVENT_REVERSE, operator, details).await?;
    }
    let restore_ids = |t: &str| -> Vec<Uuid> {
        restore
            .iter()
            .filter(|k| k.0 == t)
            .filter_map(|k| Uuid::parse_str(&k.1).ok())
            .collect()
    };
    let r_wf = restore_ids("workflows");
    let r_claims = restore_ids("claims");
    let r_edges = restore_ids("edges");
    let attached_keys: BTreeSet<RowKey> = attached_now.keys().cloned().collect();
    let readable_before = tables::app_readable(conn, specs, claim_ids, &attached_keys).await?;
    let readable_wf_before = app_readable_wf_edges(conn, wf_ids, edge_ids).await?;
    let epoch_before = atlas_epoch(conn).await?;
    let counters_before = xact_counters(conn).await?;

    let recs = |t: &str| -> Vec<&Record> {
        restore
            .iter()
            .filter(|k| k.0 == t)
            .map(|k| &prior[*k])
            .collect()
    };
    let n_wf = sqlx::query(
        "UPDATE workflows w SET owner_group_id = m.o \
           FROM jsonb_to_recordset($1::jsonb) AS m(id uuid, o uuid, co uuid) \
          WHERE w.id = m.id AND w.owner_group_id = $2",
    )
    .bind(payload(&recs("workflows")))
    .bind(target)
    .execute(&mut *conn)
    .await
    .context("restoring workflows")?
    .rows_affected();
    let n_claims = sqlx::query(
        "UPDATE claims c SET owner_group_id = m.o \
           FROM jsonb_to_recordset($1::jsonb) AS m(id uuid, o uuid, co uuid) \
          WHERE c.id = m.id AND c.owner_group_id = $2",
    )
    .bind(payload(&recs("claims")))
    .bind(target)
    .execute(&mut *conn)
    .await
    .context("restoring claims")?
    .rows_affected();
    let n_edges = sqlx::query(
        "UPDATE edges e SET owner_group_id = m.o, co_owner_group_id = m.co \
           FROM jsonb_to_recordset($1::jsonb) AS m(id uuid, o uuid, co uuid) \
          WHERE e.id = m.id AND e.owner_group_id = $2",
    )
    .bind(payload(&recs("edges")))
    .bind(target)
    .execute(&mut *conn)
    .await
    .context("restoring edges")?
    .rows_affected();

    let counters_after = xact_counters(conn).await?;
    let epoch_after = atlas_epoch(conn).await?;
    let wf_after = workflow_tenancy(conn, wf_ids).await?;
    let claims_after: BTreeMap<Uuid, (Uuid, String)> = fetch_claims(conn, claim_ids, false)
        .await?
        .into_iter()
        .map(|c| (c.id, (c.owner, c.visibility)))
        .collect();
    let edges_after: BTreeMap<Uuid, EdgeRow> = fetch_edges_by_id(conn, edge_ids)
        .await?
        .into_iter()
        .map(|e| (e.id, e))
        .collect();
    let attached_after = fetch_attached(conn, specs, claim_ids).await?;
    let readable_after = tables::app_readable(conn, specs, claim_ids, &attached_keys).await?;
    let readable_wf_after = app_readable_wf_edges(conn, wf_ids, edge_ids).await?;

    let mut v = Vec::new();
    for (what, n, want) in [
        ("workflows", n_wf, r_wf.len()),
        ("claims", n_claims, r_claims.len()),
        ("edges", n_edges, r_edges.len()),
    ] {
        if usize::try_from(n).ok() != Some(want) {
            v.push(format!(
                "restoring {what} wrote {n} row(s), {want} were due"
            ));
        }
    }
    for (k, pr) in prior.iter().filter(|(k, _)| post.contains_key(*k)) {
        let id = Uuid::parse_str(&k.1).ok();
        let now: Option<Tenancy> = match k.0.as_str() {
            "workflows" => id.and_then(|i| wf_after.get(&i).cloned()),
            "claims" => id.and_then(|i| {
                claims_after.get(&i).map(|(o, vis)| Tenancy {
                    owner: *o,
                    visibility: vis.clone(),
                    co_owner: None,
                })
            }),
            "edges" => id.and_then(|i| edges_after.get(&i).map(|e| e.tenancy.clone())),
            _ => attached_after.get(k).map(|a| a.tenancy.clone()),
        };
        match now {
            Some(t) if same(pr, &t) => {}
            other => v.push(format!(
                "{} {} ended as {other:?}, its recorded prior is ({}, {})",
                k.0, k.1, pr.owner_group_id, pr.visibility
            )),
        }
    }
    for e in edges_after.values() {
        if edges_now.get(&e.id).map(|b| b.writer_group) != Some(e.writer_group) {
            v.push(format!("edge {} writer_group_id changed", e.id));
        }
    }
    let mut derived_changed: BTreeMap<String, i64> = BTreeMap::new();
    for (k, a) in &attached_now {
        match attached_after.get(k) {
            Some(b) if b.tenancy != a.tenancy => {
                if a.writer_owned == Some(true) {
                    v.push(format!("writer-owned {} {} changed", k.0, k.1));
                }
                *derived_changed.entry(k.0.clone()).or_default() += 1;
            }
            Some(_) => {}
            None => v.push(format!("{} {} vanished", k.0, k.1)),
        }
    }
    let as_i64 = |n: usize| i64::try_from(n).unwrap_or(i64::MAX);
    let mut expect: BTreeMap<String, (i64, i64, i64)> = BTreeMap::new();
    for (t, n) in [
        ("workflows", r_wf.len()),
        ("claims", r_claims.len()),
        ("edges", r_edges.len()),
    ] {
        expect.insert(t.to_string(), (0, as_i64(n), 0));
    }
    for (t, n) in &derived_changed {
        expect.entry(t.clone()).or_default().1 += n;
    }
    expect.retain(|_, d| *d != (0, 0, 0));
    v.extend(counter_violations(
        &counter_delta(&counters_before, &counters_after),
        &expect,
    ));
    if epoch_before != epoch_after {
        v.push(format!(
            "atlas_layout_epoch moved {epoch_before:?} -> {epoch_after:?} (migration 197)"
        ));
    }
    if readable_before != readable_after || readable_wf_before != readable_wf_after {
        v.push("the rows an unstamped epigraph_app session can read changed".to_string());
    }
    if !v.is_empty() {
        return Err(BatchError::Invariant(v));
    }
    let mut by_table: BTreeMap<String, usize> = BTreeMap::new();
    for k in &restore {
        *by_table.entry(k.0.clone()).or_default() += 1;
    }
    Ok(RevOutcome::Restored(by_table))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_file_trims_skips_comments_and_dedups() {
        let dir = std::env::temp_dir().join(format!("reown-wf-names-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("n.txt");
        std::fs::write(&p, "# c\n\n  alpha \nbeta\nalpha\n").unwrap();
        assert_eq!(read_names_file(&p).unwrap(), vec!["alpha", "beta"]);
        std::fs::write(&p, "# only a comment\n").unwrap();
        assert!(read_names_file(&p).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn apply_needs_a_count_a_ruling_and_a_reason() {
        let o = Options {
            names_file: PathBuf::from("n"),
            target: Uuid::new_v4(),
            operator: Uuid::new_v4(),
            from_group: None,
            manifest_out: PathBuf::from("m"),
            apply: true,
            confirm_count: Some(1),
            ruling: "r".into(),
            reason: "why".into(),
            batch_size: 25,
            lock_timeout: "5s".into(),
        };
        assert!(validate(&o).is_ok());
        assert!(validate(&Options {
            confirm_count: None,
            ..o.clone()
        })
        .is_err());
        assert!(validate(&Options {
            ruling: " ".into(),
            ..o.clone()
        })
        .is_err());
        assert!(validate(&Options {
            reason: String::new(),
            ..o.clone()
        })
        .is_err());
        assert!(validate(&Options {
            batch_size: 0,
            apply: false,
            ..o
        })
        .is_err());
    }

    #[test]
    fn the_union_find_joins_transitively() {
        let mut d = Dsu::default();
        d.union("c", "b");
        d.union("b", "a");
        assert_eq!(d.find("c"), d.find("a"));
        assert_ne!(d.find("x"), d.find("a"));
    }
}
