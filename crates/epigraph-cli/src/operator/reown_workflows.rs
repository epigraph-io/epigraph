//! `reown-workflows`: move listed workflow LINEAGES (every generation of each
//! `canonical_name`) out of a source group and into a TEAM group, either
//! keeping every row's visibility (`--visibility keep`, the default) or
//! narrowing every moved row to the target group (`--visibility group`); or,
//! with the target equal to the source, narrow the lineages IN PLACE within
//! their owner group (`--visibility group` required). And the exact reversal
//! of such a run (`reown-reverse` on a reown-workflows manifest).
//!
//! The source is the operator's personal group, or `--from-group` (which the
//! operator must administer). A move's target must be an active `team` group
//! the operator administers. An in-place run's target IS the source, so it is
//! authorized by the source path alone (the operator's own personal group, or
//! a group the operator administers); any active group but the world and seed
//! groups qualifies. It is an audited maintenance act in the shape of
//! `restrict-claims`: dry run by default; `--apply` needs `--confirm-count`
//! (the dry run's eligible workflow-row count), `--ruling` and `--reason`; the
//! manifest is created before the first write and every batch records its
//! rows, `fsync`ed, before its write; one `security_events` row per applied
//! run.
//!
//! # The two acts
//!
//! A row moves only while it is `('public', source)`, the FROM state. It ends
//! in the TO state:
//!
//! * `--visibility keep`: `('public', target)`. Every row this writes is public
//!   before and after, and a public row is readable through every tenancy
//!   policy's `visibility = 'public'` arm whoever owns it: no reader gains or
//!   loses a row, and migration 197's atlas epoch (bumped only by a
//!   public-to-non-public narrowing) never moves. Every batch asserts both.
//! * `--visibility group`: `('group', target)`, a NARROWING through the
//!   database's own narrowing path. The `workflows` rows are written directly
//!   (migration 183: a maintenance session re-tenants them); the plan claims go
//!   through one `UPDATE claims SET owner_group_id, visibility = 'group'`, so
//!   `epigraph_propagate_tenancy` narrows their derived rows and fragments and
//!   re-meets every edge with a claim endpoint, and migration 197's trigger
//!   bumps the atlas epoch once in the batch's transaction. Every batch asserts
//!   the bump, and that an unstamped `epigraph_app` session lost EXACTLY the
//!   rows that went public to group. Re-run `atlas_layout --apply` afterwards.
//!   With the target equal to the source this is the in-place narrowing: no
//!   `workflows` row, plan claim, or row that follows its claim changes owner.
//!
//! # What moves, table by table
//!
//! * `workflows`: every generation of a listed lineage, which must all be in
//!   the FROM state. A lineage with a generation in any other state is HELD
//!   whole (moving part of a lineage would split its plan across owners or
//!   visibilities). A lineage whose generations are all in the TO state counts
//!   as done; one that is PART in the TO state and part in the FROM state is
//!   HELD: its manifest would record only the FROM part, and the reversal,
//!   which refuses a lineage row it did not see, could then never restore it.
//!   Remedy for such a lineage: reverse the earlier run that moved part of it
//!   (which refuses while the plan has grown), or move the stray generation by
//!   hand with a reviewed maintenance act.
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
//!     non-public endpoint;
//!   - when narrowing, also: carrying another writer's row (migration 114)
//!     that is not public, an edge that is not public and that the narrowing
//!     would hand to the target (another group's declared edge), or an edge
//!     with an EVIDENCE endpoint (the cascade does not re-meet those);
//!   - sharing a cascaded row (a harvester fragment) with a plan claim that
//!     stays (to a fixpoint).
//! * The claims' DERIVED rows (`epigraph_propagate_tenancy`'s `derived[]`
//!   tables and harvester fragments, read from the live trigger by
//!   `tables::propagated_tables`): the cascade copies the claim's new tuple
//!   onto every one that is not writer-owned. A WRITER-OWNED row (migration
//!   114: another writer's evidence, BBA or trace) is left by the trigger while
//!   the claim stays public, and stays its writer's under `keep`; a narrowing
//!   takes it into the claim's group and clears its flag (114's rule, as for
//!   `restrict-claims`), and the manifest records the flag so the reversal
//!   puts it back. An outsider's challenge (migration 168) is never moved; it
//!   becomes unreadable with its claim.
//! * `edges`:
//!   - `keep`: an edge moves when it is `('public', source)` with no co-owner,
//!     both endpoints public, at least one endpoint in the plans (a listed
//!     workflow row or a plan claim), and it is EITHER a plan relationship
//!     ([`PLAN_RELATIONSHIPS`]) OR has both endpoints in the plans (a
//!     cross-reference between two steps). Since migration 120 the
//!     claim-to-claim plan edges an ingest writes are owned by the WRITER's
//!     group (for the ingest system agent live-linked to the operator, the
//!     operator's personal group): these move. Every edge with a workflow,
//!     agent or paper endpoint (`executes`, `variant_of`, `asserts`,
//!     `AUTHORED`) is STRUCTURAL, `('public', world)`, owned by no group, and
//!     stays, as does a claim-to-claim edge written before migration 120
//!     (legacy, world-owned). The trigger does not rewrite any of these on its
//!     own: since migration 120 a public-to-public owner change of an endpoint
//!     leaves every public edge alone, so this tool updates the moving edges'
//!     `owner_group_id` itself.
//!   - `group`: no edge is left more visible than the plan it describes.
//!     Every edge with a moved CLAIM endpoint, whoever owns it (the plan
//!     edges, world-owned `executes` / `asserts` and legacy edges, other
//!     writers' public edges), is re-met by the cascade to `('group', target)`
//!     (migration 120's rule: a narrowing takes the meet, and a writer loses
//!     its edge, as for 114's writer-owned rows). An edge whose only moving
//!     endpoint is a WORKFLOW row (`variant_of` between generations,
//!     `AUTHORED` from the author agent, `executes` into a LEFT claim) has no
//!     claim endpoint for the cascade to meet: `epigraph_node_tenancy` treats a
//!     workflow as tenancy-less (migration 183 left it so). Left public, it
//!     would publish the existence, author and step links of a now private
//!     plan. This tool narrows each such edge itself to the meet of the
//!     workflow row's new tuple and its other endpoint (restrict's
//!     [`super::restrict::narrowed`]: kept when already narrower). That is an
//!     explicit `('group', G)` declaration between non-group endpoints, which
//!     072's first stamping arm (kept by migration 120) preserves on any later
//!     re-point. An edge whose narrowing would hand another group's row to the
//!     target holds its whole lineage.
//!
//!   `writer_group_id` is never rewritten: it is the author record (migration
//!   120).
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
//! The batch then records the prior state of every row it changes AND of every
//! plan row it saw and does not change (left and already claims, rows that
//! stay, edges that stay: the reversal's growth check reads them), writes, and
//! checks before committing: every changed row is in its planned state; every
//! row that stays is unchanged (`writer_group_id` included);
//! `pg_stat_xact_user_tables` counts exactly the planned rows per table and
//! none elsewhere; an UNSTAMPED `epigraph_app` session reads exactly the same
//! keys (keep) or lost exactly the narrowed keys (group); and the atlas epoch
//! is unchanged (keep) or bumped once (group). Any violation rolls the batch
//! back (exit 2).
//!
//! # Reversal (`reown-reverse --manifest <this manifest>`)
//!
//! All of one manifest in ONE transaction, a compare-and-swap per row: a row
//! with a post record is restored when it is in its post state (tenancy,
//! `writer_owned`, and for an edge its endpoints and relationship), skipped
//! when it is already in its prior state, and anything else REFUSES THE WHOLE
//! MANIFEST (nothing is written; exit 3). It also refuses when the plan GREW
//! since the run, i.e. under the locks it finds any of:
//! * a workflow row of a moved lineage that the run did not see (a new
//!   generation);
//! * a claim a manifest workflow executes (retracted edges included), or a
//!   member of a manifest claim's step lineage (an evolved step's successor),
//!   that the run did not see;
//! * a moved claim now executed by a workflow the run did not move;
//! * a row attached to a moved claim, or an edge touching a moved claim or
//!   workflow, that the run did not see (new evidence, a BBA, a new link);
//! * a moved claim or its evidence sealed since.
//!
//! Exact or nothing: a partial restore would split a plan between two owners.
//! The widening statement (claims back to public) runs with migration 074's
//! `epigraph.allow_declassify` armed around it only; derived rows, writer-owned
//! flags and edges are then put back on their OWN recorded tuples. A reversal
//! never moves the atlas epoch (a widening does not bump it, and nothing
//! decrements it). `claims.updated_at` (migration 001's trigger) is the one
//! column neither direction can put back.

use super::manifest::{self, Record, Sink, Writer};
use super::reown::{counter_delta, counter_violations, BatchError};
use super::restrict::{
    self, check_target, is_outsider_challenge, meet, narrowed, narrows, operator_details,
    readability_violations, sha256_file, sha256_hex, RowState,
};
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
/// The header's `record_format`: records carry prior-only "seen" rows
/// (`neighbour: true`), `writer_owned`, and an edge's endpoints and
/// relationship in its `id`. The reversal refuses any other format.
pub const RECORD_FORMAT: &str = "reown-workflows/2";
/// `security_events.event_type` of an applied run.
pub const EVENT_APPLY: &str = "operator.workflows_reowned";
/// `security_events.event_type` of an applied reversal of one manifest.
pub const EVENT_REVERSE: &str = "operator.workflows_reown_reversed";

/// The relationships the workflow write paths create (ingest, `add_step`,
/// `evolve_step`, authorship). Under `keep`, a source-owned public edge with
/// one of these and at least one endpoint in the plans moves; any other
/// relationship moves only when BOTH endpoints are in the plans.
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
const GROUP: &str = "group";

/// What a run does to visibility.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Visibility {
    /// Every moved row stays public.
    Keep,
    /// Every moved row becomes `group`-visible to the target.
    Group,
}

impl Visibility {
    /// # Errors
    /// Anything but `keep` or `group`.
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        match s {
            "keep" => Ok(Self::Keep),
            "group" => Ok(Self::Group),
            other => bail!("--visibility must be keep or group, not {other:?}"),
        }
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Keep => "keep",
            Self::Group => "group",
        }
    }
}

/// The resolved act: where rows come from, where they go, and how visible.
#[derive(Clone, Copy, Debug)]
pub struct Act {
    pub source: Uuid,
    pub target: Uuid,
    pub visibility: Visibility,
}

impl Act {
    /// The state a row must be in to move.
    #[must_use]
    pub fn from_state(&self) -> Tenancy {
        Tenancy {
            owner: self.source,
            visibility: PUBLIC.into(),
            co_owner: None,
        }
    }

    /// The state a moved row ends in.
    #[must_use]
    pub fn to_state(self) -> Tenancy {
        Tenancy {
            owner: self.target,
            visibility: self.to_vis().into(),
            co_owner: None,
        }
    }

    fn to_vis(self) -> &'static str {
        match self.visibility {
            Visibility::Keep => PUBLIC,
            Visibility::Group => GROUP,
        }
    }

    #[must_use]
    pub fn narrows(&self) -> bool {
        self.visibility == Visibility::Group
    }

    #[must_use]
    pub fn in_place(&self) -> bool {
        self.source == self.target
    }

    fn name(&self) -> &'static str {
        match (self.in_place(), self.visibility) {
            (true, _) => "NARROW-IN-PLACE",
            (false, Visibility::Keep) => "MOVE",
            (false, Visibility::Group) => "MOVE-AND-NARROW",
        }
    }
}

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
    pub visibility: Visibility,
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
/// not run on. Returns `(source, target)`; equal for an in-place narrowing.
///
/// # Errors
/// `--from-group` is world or seed or not administered by the operator; the
/// operator has no personal group; the target is the source without
/// `--visibility group`, or a move's target is not an active team group the
/// operator administers.
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
        if opts.visibility != Visibility::Group {
            bail!(
                "--target-group {} is the source group: a run that moves nothing can only narrow \
                 in place; pass --visibility group (or name a team group to move into)",
                opts.target
            );
        }
        // In place: authorized by the source path (the operator's own group,
        // or a group the operator administers).
        let status: Option<String> =
            sqlx::query_scalar("SELECT status::text FROM groups WHERE id = $1")
                .bind(source)
                .fetch_optional(&mut *conn)
                .await?;
        if status.as_deref() != Some("active") {
            bail!("the source group {source} is not active ({status:?}); refusing");
        }
        return Ok((source, source));
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

/// An endpoint's `(group, visibility)` under `epigraph_node_tenancy`.
pub type NodeState = (Uuid, String);

/// An `edges` row touching the plans.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct EdgeRow {
    pub id: Uuid,
    pub source: (Uuid, String),
    pub target: (Uuid, String),
    pub relationship: String,
    pub tenancy: Tenancy,
    pub writer_group: Option<Uuid>,
    pub source_state: NodeState,
    pub target_state: NodeState,
}

impl EdgeRow {
    fn endpoints_public(&self) -> bool {
        self.source_state.1 == PUBLIC && self.target_state.1 == PUBLIC
    }

    /// The manifest id: the edge id with its endpoints and relationship, so a
    /// reversal can tell a re-pointed edge from the one it moved.
    fn id_json(&self) -> Value {
        json!({
            "id": self.id.to_string(),
            "s": self.source.0.to_string(),
            "st": self.source.1,
            "t": self.target.0.to_string(),
            "tt": self.target.1,
            "r": self.relationship,
        })
    }

    fn shape(&self) -> EdgeShape {
        (
            self.source.clone(),
            self.target.clone(),
            self.relationship.clone(),
        )
    }
}

/// An edge's endpoints and relationship.
type EdgeShape = ((Uuid, String), (Uuid, String), String);

fn edge_from_json(v: &Value) -> anyhow::Result<(String, EdgeShape)> {
    let s = |k: &str| {
        v.get(k)
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("edge record id lacks {k}: {v}"))
    };
    let u = |k: &str| -> anyhow::Result<Uuid> { Ok(Uuid::parse_str(s(k)?)?) };
    Ok((
        u("id")?.to_string(),
        (
            (u("s")?, s("st")?.to_string()),
            (u("t")?, s("tt")?.to_string()),
            s("r")?.to_string(),
        ),
    ))
}

/// An edge this run changes, and the state it ends in.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct MovingEdge {
    pub row: EdgeRow,
    pub post: Tenancy,
    /// Written by this tool (`keep`'s owner move, or a narrowing of an edge
    /// with no moved claim endpoint); otherwise the cascade re-meets it.
    pub explicit: bool,
}

/// Why a listed lineage does not move.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LineageHold {
    NotFound,
    OwnedElsewhere {
        generation: i32,
        owner: Uuid,
    },
    NotPublic {
        generation: i32,
        visibility: String,
    },
    /// Some generations are in the TO state already and some in the FROM
    /// state.
    PartlyMoved {
        source_gens: Vec<i32>,
        target_gens: Vec<i32>,
    },
    /// Narrowing an edge of the plan would hand another group's row to the
    /// target.
    ForeignEdge {
        edge: Uuid,
        state: String,
    },
}

impl fmt::Display for LineageHold {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => write!(f, "no workflow row has this canonical name"),
            Self::OwnedElsewhere { generation, owner } => write!(
                f,
                "generation {generation} is owned by group {owner}, and is neither the source's \
                 public row nor in this run's target state; the whole lineage stays"
            ),
            Self::NotPublic {
                generation,
                visibility,
            } => write!(
                f,
                "generation {generation} has visibility {visibility}, not public, and is not in \
                 this run's target state; the whole lineage stays"
            ),
            Self::PartlyMoved {
                source_gens,
                target_gens,
            } => write!(
                f,
                "partly the target's already (generations {target_gens:?}) and partly the \
                 source's ({source_gens:?}); a lineage moves whole, and a run that moved only \
                 part of it could not be reversed exactly, so it stays"
            ),
            Self::ForeignEdge { edge, state } => write!(
                f,
                "edge {edge} of this plan is {state}: narrowing it to the target would make \
                 another group's row readable by the target; the whole lineage stays"
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
    EdgeWouldWiden {
        edge: Uuid,
        state: String,
    },
    EvidenceEdge {
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
            Self::EdgeWouldWiden { edge, state } => write!(
                f,
                "edge {edge} touching it is {state}: the narrowing would re-meet it into the \
                 target, making another group's row readable there"
            ),
            Self::EvidenceEdge { edge } => write!(
                f,
                "edge {edge} has an endpoint on its evidence, which the cascade does not re-meet \
                 when the claim narrows; it stays rather than leave that edge public"
            ),
        }
    }
}

/// Lineages that must move together, and everything that moves with them.
#[derive(Clone, Debug, Default)]
pub struct Component {
    /// Sorted.
    pub lineages: Vec<String>,
    /// Rows in the FROM state: they move.
    pub workflows: Vec<WfRow>,
    /// Plan claims that move.
    pub claims: Vec<ClaimRow>,
    pub left: Vec<(Uuid, Left)>,
    pub already_claims: Vec<Uuid>,
    /// The left and already claims' rows, as seen (the manifest's "seen" set).
    pub seen_claims: Vec<ClaimRow>,
    /// Derived and fragment rows the cascade changes.
    pub rows: Snapshot,
    /// Rows attached to moving claims that stay as they are (writer-owned under
    /// `keep`; an outsider's challenge under `group`).
    pub kept_rows: Snapshot,
    /// Edges that change.
    pub edges: Vec<MovingEdge>,
    /// Edges touching the plans that stay, with why.
    pub edges_kept: Vec<(EdgeRow, &'static str)>,
}

impl Component {
    /// Everything the batch re-plans and compares, in a stable text form.
    fn fingerprint(&self) -> String {
        let mut claims: Vec<_> = self
            .claims
            .iter()
            .chain(self.seen_claims.iter())
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

fn tuple_text(t: &Tenancy) -> String {
    match t.co_owner {
        Some(co) => format!("({}, {}, co-owner {co})", t.owner, t.visibility),
        None => format!("({}, {})", t.owner, t.visibility),
    }
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
    act: &Act,
) -> anyhow::Result<Plan> {
    let (source, target) = (act.source, act.target);
    let (from, to) = (act.from_state(), act.to_state());
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
        let mut source_gens = Vec::new();
        let mut target_gens = Vec::new();
        let mut bad = None;
        for w in gens {
            if w.tenancy == from {
                source_gens.push(w.generation);
            } else if w.tenancy == to {
                target_gens.push(w.generation);
            } else if bad.is_none() {
                bad = Some(if w.tenancy.visibility == PUBLIC {
                    LineageHold::OwnedElsewhere {
                        generation: w.generation,
                        owner: w.tenancy.owner,
                    }
                } else {
                    LineageHold::NotPublic {
                        generation: w.generation,
                        visibility: w.tenancy.visibility.clone(),
                    }
                });
            }
        }
        if let Some(h) = bad {
            out.held.push((name.clone(), h));
        } else if !source_gens.is_empty() && !target_gens.is_empty() {
            out.held.push((
                name.clone(),
                LineageHold::PartlyMoved {
                    source_gens,
                    target_gens,
                },
            ));
        } else if source_gens.is_empty() {
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
        let state = Tenancy {
            owner: c.owner,
            visibility: c.visibility.clone(),
            co_owner: None,
        };
        if state == to {
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
        let foreign = if a.writer_owned == Some(true) {
            // Another writer's row (114). Under `keep` it stays its writer's;
            // a narrowing takes it into the claim's group (an outsider's
            // challenge excepted, 168), so it must be public.
            act.narrows()
                && !is_outsider_challenge(&a.table, a.writer_owned)
                && a.tenancy.visibility != PUBLIC
        } else {
            a.tenancy != from || a.shared_outside
        };
        if foreign {
            for c in a.claims.intersection(&candidates) {
                left.entry(*c).or_insert_with(|| Left::ForeignRow {
                    table: a.table.clone(),
                    id: a.pk.clone(),
                    state: format!(
                        "{}{}{}",
                        tuple_text(&a.tenancy),
                        if a.writer_owned == Some(true) {
                            ", another writer's"
                        } else {
                            ""
                        },
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
        for (id, ty) in [&e.source, &e.target] {
            if ty != "claim" || !candidates.contains(id) {
                continue;
            }
            if !e.endpoints_public() {
                left.entry(*id)
                    .or_insert(Left::EdgeEndpointNotPublic { edge: e.id });
            } else if act.narrows() && !narrows(&e.tenancy, &to) {
                // Both endpoints public: the cascade's meet is the target.
                left.entry(*id).or_insert(Left::EdgeWouldWiden {
                    edge: e.id,
                    state: tuple_text(&e.tenancy),
                });
            }
        }
    }
    if act.narrows() {
        // Edges with an EVIDENCE endpoint of a moving claim: the cascade does
        // not re-meet them, so the claim stays rather than leave them public.
        let ev_claim: BTreeMap<Uuid, BTreeSet<Uuid>> = attached
            .values()
            .filter(|a| a.table == "evidence")
            .filter_map(|a| {
                Uuid::parse_str(&a.pk)
                    .ok()
                    .map(|id| (id, a.claims.intersection(&candidates).copied().collect()))
            })
            .collect();
        let ev: Vec<Uuid> = ev_claim.keys().copied().collect();
        for (edge, s, st, t, tt) in sqlx::query_as::<_, (Uuid, Uuid, String, Uuid, String)>(
            "SELECT id, source_id, source_type::text, target_id, target_type::text FROM edges \
              WHERE (source_type = 'evidence' AND source_id = ANY($1)) \
                 OR (target_type = 'evidence' AND target_id = ANY($1))",
        )
        .bind(&ev)
        .fetch_all(&mut *conn)
        .await
        .context("reading evidence-endpoint edges")?
        {
            for (n, ty) in [(s, st), (t, tt)] {
                if ty != "evidence" {
                    continue;
                }
                for c in ev_claim.get(&n).into_iter().flatten() {
                    left.entry(*c).or_insert(Left::EvidenceEdge { edge });
                }
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
    // The tuples of workflow endpoints outside the listed lineages (an edge's
    // narrowing meets with them).
    let outside_wf: Vec<Uuid> = edge_rows
        .iter()
        .flat_map(|e| [&e.source, &e.target])
        .filter(|(id, ty)| ty == "workflow" && !wf_lineage.contains_key(id))
        .map(|(id, _)| *id)
        .collect();
    let outside_wf_state = workflow_tenancy(conn, &outside_wf).await?;
    let to_node: NodeState = (to.owner, to.visibility.clone());
    let mut moving_edges: Vec<MovingEdge> = Vec::new();
    let mut kept_edges: Vec<(EdgeRow, &'static str)> = Vec::new();
    let mut foreign_edges: Vec<(String, LineageHold)> = Vec::new();
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
        if !act.narrows() {
            let plan_rel = PLAN_RELATIONSHIPS.contains(&e.relationship.as_str());
            let why: Option<&'static str> = if e.tenancy.owner == target {
                Some("already the target's")
            } else if e.tenancy.owner == WORLD
                && !(matches!(e.source.1.as_str(), "claim" | "evidence")
                    && matches!(e.target.1.as_str(), "claim" | "evidence"))
            {
                Some("structural: world-owned (a workflow, agent or paper endpoint)")
            } else if e.tenancy.owner == WORLD {
                Some(
                    "legacy world-owned claim-to-claim edge (written before writer ownership, \
                     migration 120): no group's, stays administrative",
                )
            } else if e.tenancy.owner != source {
                Some("owned by another group")
            } else if e.tenancy.visibility != PUBLIC || e.tenancy.co_owner.is_some() {
                Some("source-owned but not public, or co-owned")
            } else if !e.endpoints_public() {
                Some("an endpoint is not public")
            } else if !(plan_rel || (s_in && t_in)) {
                Some("source-owned, not a plan edge, one endpoint outside the plans")
            } else {
                None
            };
            match why {
                None => moving_edges.push(MovingEdge {
                    row: e,
                    post: to.clone(),
                    explicit: true,
                }),
                Some(w) => kept_edges.push((e, w)),
            }
            continue;
        }
        // ---- narrowing ----
        let moving_claim = |(id, ty): &(Uuid, String)| ty == "claim" && candidates.contains(id);
        let moving_wf = |(id, ty): &(Uuid, String)| ty == "workflow" && wf_lineage.contains_key(id);
        if moving_claim(&e.source) || moving_claim(&e.target) {
            // The cascade re-meets it: one endpoint goes to ('group', target)
            // and the other is public (or moving, or already there).
            if e.tenancy == to {
                kept_edges.push((e, "already as narrow as its plan"));
            } else {
                moving_edges.push(MovingEdge {
                    row: e,
                    post: to.clone(),
                    explicit: false,
                });
            }
            continue;
        }
        if !(moving_wf(&e.source) || moving_wf(&e.target)) {
            kept_edges.push((e, "touches only plan rows that do not change"));
            continue;
        }
        // A moving workflow endpoint and no moving claim endpoint: narrowed
        // here, to the meet of the workflow's new tuple and the other end.
        let state_of = |n: &(Uuid, String), st: &NodeState| -> NodeState {
            if moving_wf(n) {
                to_node.clone()
            } else if n.1 == "workflow" {
                outside_wf_state
                    .get(&n.0)
                    .map_or_else(|| st.clone(), |t| (t.owner, t.visibility.clone()))
            } else {
                st.clone()
            }
        };
        let m = meet(
            &state_of(&e.source, &e.source_state),
            &state_of(&e.target, &e.target_state),
        );
        let desired = narrowed(&e.tenancy, m);
        if desired == e.tenancy {
            kept_edges.push((e, "already as narrow as its plan"));
        } else if !narrows(&e.tenancy, &desired) {
            for n in [&e.source, &e.target] {
                if let Some(l) = wf_lineage.get(&n.0) {
                    foreign_edges.push((
                        l.clone(),
                        LineageHold::ForeignEdge {
                            edge: e.id,
                            state: tuple_text(&e.tenancy),
                        },
                    ));
                }
            }
            kept_edges.push((e, "would widen; its lineage is held"));
        } else {
            moving_edges.push(MovingEdge {
                row: e,
                post: desired,
                explicit: true,
            });
        }
    }

    // ---- components ----
    let mut comps: BTreeMap<String, Component> = BTreeMap::new();
    for (n, gens) in &eligible {
        let root = dsu.find(n);
        let c = comps.entry(root).or_default();
        c.lineages.push(n.clone());
        c.workflows
            .extend(gens.iter().filter(|w| w.tenancy == from).cloned());
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
                // A dangling executes target is recorded too, so the reversal
                // does not mistake it for a step added after the run.
                c.seen_claims
                    .push(by_id.get(id).cloned().unwrap_or(ClaimRow {
                        id: *id,
                        author: Uuid::nil(),
                        owner: Uuid::nil(),
                        visibility: "absent".to_string(),
                    }));
            }
        }
    }
    for id in &already {
        if let Some(r) = root_of(id, &mut dsu) {
            if let Some(c) = comps.get_mut(&r) {
                c.already_claims.push(*id);
                c.seen_claims.push(by_id[id].clone());
            }
        }
    }
    for (k, a) in attached {
        let Some(owner_claim) = a.claims.iter().find(|c| candidates.contains(c)).copied() else {
            continue;
        };
        if let Some(r) = root_of(&owner_claim, &mut dsu) {
            if let Some(c) = comps.get_mut(&r) {
                let stays = if act.narrows() {
                    is_outsider_challenge(&a.table, a.writer_owned)
                } else {
                    a.writer_owned == Some(true)
                };
                if stays {
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
        if let Some(r) = edge_root(&e.row, &mut dsu) {
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
    // A lineage with an edge the narrowing cannot take holds its component.
    let mut held_roots: BTreeMap<String, LineageHold> = BTreeMap::new();
    for (l, h) in foreign_edges {
        held_roots.entry(dsu.find(&l)).or_insert(h);
    }
    for (root, c) in comps {
        if let Some(h) = held_roots.get(&root) {
            for l in c.lineages {
                out.held.push((l, h.clone()));
            }
            continue;
        }
        let mut c = c;
        c.lineages.sort();
        out.components.push(c);
    }
    Ok(out)
}

const EDGE_COLUMNS: &str = "e.id, e.source_id, e.source_type::text, e.target_id, \
     e.target_type::text, e.relationship::text, e.owner_group_id, e.visibility::text, \
     e.co_owner_group_id, e.writer_group_id, s.g, s.v::text, t.g, t.v::text";

fn edge_from_row(r: &sqlx::postgres::PgRow) -> EdgeRow {
    EdgeRow {
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
        source_state: (r.get(10), r.get(11)),
        target_state: (r.get(12), r.get(13)),
    }
}

/// Every edge with an endpoint among `claims` (as a claim) or `workflows` (as
/// a workflow), with its tenancy and its endpoints' states under
/// `epigraph_node_tenancy` (the function the edges trigger meets with).
async fn fetch_edges(
    conn: &mut PgConnection,
    claims: &[Uuid],
    workflows: &[Uuid],
) -> anyhow::Result<Vec<EdgeRow>> {
    let rows = sqlx::query(&format!(
        "SELECT {EDGE_COLUMNS} \
           FROM edges e \
           CROSS JOIN LATERAL public.epigraph_node_tenancy(e.source_id, e.source_type) s \
           CROSS JOIN LATERAL public.epigraph_node_tenancy(e.target_id, e.target_type) t \
          WHERE (e.source_type = 'claim' AND e.source_id = ANY($1)) \
             OR (e.target_type = 'claim' AND e.target_id = ANY($1)) \
             OR (e.source_type = 'workflow' AND e.source_id = ANY($2)) \
             OR (e.target_type = 'workflow' AND e.target_id = ANY($2)) \
          ORDER BY e.id"
    ))
    .bind(claims)
    .bind(workflows)
    .fetch_all(&mut *conn)
    .await
    .context("reading edges")?;
    Ok(rows.iter().map(edge_from_row).collect())
}

async fn fetch_edges_by_id(conn: &mut PgConnection, ids: &[Uuid]) -> anyhow::Result<Vec<EdgeRow>> {
    let rows = sqlx::query(&format!(
        "SELECT {EDGE_COLUMNS} \
           FROM edges e \
           CROSS JOIN LATERAL public.epigraph_node_tenancy(e.source_id, e.source_type) s \
           CROSS JOIN LATERAL public.epigraph_node_tenancy(e.target_id, e.target_type) t \
          WHERE e.id = ANY($1) ORDER BY e.id"
    ))
    .bind(ids)
    .fetch_all(&mut *conn)
    .await
    .context("re-reading edges")?;
    Ok(rows.iter().map(edge_from_row).collect())
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

/// Every key an unstamped application session reads among these rows.
async fn readable(
    conn: &mut PgConnection,
    specs: &[TableSpec],
    claims: &[Uuid],
    keys: &BTreeSet<RowKey>,
    wf: &[Uuid],
    edges: &[Uuid],
) -> anyhow::Result<BTreeSet<RowKey>> {
    let mut out = tables::app_readable(conn, specs, claims, keys).await?;
    out.extend(app_readable_wf_edges(conn, wf, edges).await?);
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

/// A record. `seen` marks a prior-only record of a row this run saw and did
/// not change (it carries `neighbour: true`; the reversal reads it for its
/// growth check, never restores it).
#[allow(clippy::too_many_arguments)]
fn rec(
    table: &str,
    id: Value,
    t: &Tenancy,
    anchor: Uuid,
    after: bool,
    edge: bool,
    writer_owned: Option<bool>,
    seen: bool,
) -> Record {
    Record {
        table: table.to_string(),
        id,
        owner_group_id: t.owner,
        visibility: t.visibility.clone(),
        co_owner_group_id: edge.then_some(t.co_owner),
        claim_id: anchor,
        hidden: false,
        after,
        neighbour: seen,
        writer_owned,
    }
}

fn spec_of<'a>(specs: &'a [TableSpec], table: &str) -> &'a TableSpec {
    tables::spec(specs, table).expect("attached rows come only from specs")
}

fn claim_tenancy(c: &ClaimRow) -> Tenancy {
    Tenancy {
        owner: c.owner,
        visibility: c.visibility.clone(),
        co_owner: None,
    }
}

/// Prior records of every row a component changes, and "seen" records of
/// every plan row it saw and leaves.
fn prior_records(c: &Component, specs: &[TableSpec]) -> Vec<Record> {
    let mut out = Vec::new();
    for w in &c.workflows {
        let id = json!(w.id.to_string());
        out.push(rec(
            "workflows",
            id,
            &w.tenancy,
            w.id,
            false,
            false,
            None,
            false,
        ));
    }
    for cl in &c.claims {
        let id = json!(cl.id.to_string());
        out.push(rec(
            "claims",
            id,
            &claim_tenancy(cl),
            cl.id,
            false,
            false,
            None,
            false,
        ));
    }
    for cl in &c.seen_claims {
        let id = json!(cl.id.to_string());
        out.push(rec(
            "claims",
            id,
            &claim_tenancy(cl),
            cl.id,
            false,
            false,
            None,
            true,
        ));
    }
    for (rows, seen) in [(&c.rows, false), (&c.kept_rows, true)] {
        for a in rows.values() {
            out.push(rec(
                &a.table,
                spec_of(specs, &a.table).id_json(&a.pk),
                &a.tenancy,
                a.claim,
                false,
                false,
                a.writer_owned,
                seen,
            ));
        }
    }
    for e in &c.edges {
        let r = &e.row;
        out.push(rec(
            "edges",
            r.id_json(),
            &r.tenancy,
            Uuid::nil(),
            false,
            true,
            None,
            false,
        ));
    }
    for (e, _) in &c.edges_kept {
        out.push(rec(
            "edges",
            e.id_json(),
            &e.tenancy,
            Uuid::nil(),
            false,
            true,
            None,
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
    pub act: Act,
    pub lock_timeout: &'a str,
    /// Tables whose row security does not enforce a `group` row (restrict's
    /// `unenforced_reasons`); the readability check is a subset check there.
    pub unenforced: &'a BTreeMap<String, Vec<String>>,
}

/// What one batch did.
#[derive(Default, Debug)]
pub struct BatchOutcome {
    pub workflows_moved: usize,
    pub claims_moved: usize,
    pub edges_moved: usize,
    pub rows_moved: BTreeMap<String, usize>,
    pub held: Vec<(Vec<String>, String)>,
    pub epoch_bumped: bool,
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
    let act = ctx.act;
    let to = act.to_state();
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
        .flat_map(|c| c.edges.iter().map(|e| e.row.id))
        .collect();
    sqlx::query("SELECT id FROM edges WHERE id = ANY($1) ORDER BY id FOR UPDATE")
        .bind(&lock_edges)
        .fetch_all(&mut *conn)
        .await?;

    // ---- re-plan under the locks; hold every component that changed ----
    let now = plan(conn, ctx.specs, &names, &act).await?;
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
    let moving: Vec<&MovingEdge> = comps.iter().flat_map(|c| c.edges.iter()).collect();
    let explicit: Vec<&MovingEdge> = moving.iter().copied().filter(|e| e.explicit).collect();
    let kept_edges: Vec<&EdgeRow> = comps
        .iter()
        .flat_map(|c| c.edges_kept.iter().map(|(e, _)| e))
        .collect();
    let all_edge_ids: Vec<Uuid> = moving
        .iter()
        .map(|e| e.row.id)
        .chain(kept_edges.iter().map(|e| e.id))
        .collect();
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
    let readable_before =
        readable(conn, ctx.specs, &claim_ids, &keys, &wf_ids, &all_edge_ids).await?;
    let epoch_before = atlas_epoch(conn).await?;
    let bump_due = tables::layout_epoch_bump_due(conn).await?;
    let counters_before = xact_counters(conn).await?;

    let n_wf = sqlx::query(
        "UPDATE workflows SET owner_group_id = $2, visibility = $4 \
          WHERE id = ANY($1) AND owner_group_id = $3 AND visibility = 'public'",
    )
    .bind(&wf_ids)
    .bind(act.target)
    .bind(act.source)
    .bind(act.to_vis())
    .execute(&mut *conn)
    .await
    .context("UPDATE workflows")?
    .rows_affected();
    let n_claims = sqlx::query(
        "UPDATE claims SET owner_group_id = $2, visibility = $4 \
          WHERE id = ANY($1) AND owner_group_id = $3 AND visibility = 'public'",
    )
    .bind(&claim_ids)
    .bind(act.target)
    .bind(act.source)
    .bind(act.to_vis())
    .execute(&mut *conn)
    .await
    .context("UPDATE claims")?
    .rows_affected();
    // The edges this tool writes itself, compare-and-swapped on their prior.
    let payload: Vec<Value> = explicit
        .iter()
        .map(|e| {
            json!({"id": e.row.id, "o": e.post.owner, "v": e.post.visibility,
                   "co": e.post.co_owner, "po": e.row.tenancy.owner,
                   "pv": e.row.tenancy.visibility, "pco": e.row.tenancy.co_owner})
        })
        .collect();
    let n_edges = sqlx::query(
        "UPDATE edges e SET owner_group_id = m.o, visibility = m.v, co_owner_group_id = m.co \
           FROM jsonb_to_recordset($1::jsonb) \
                AS m(id uuid, o uuid, v text, co uuid, po uuid, pv text, pco uuid) \
          WHERE e.id = m.id \
            AND (e.owner_group_id, e.visibility::text, e.co_owner_group_id) \
                IS NOT DISTINCT FROM (m.po, m.pv, m.pco)",
    )
    .bind(Value::Array(payload))
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
    let readable_after =
        readable(conn, ctx.specs, &claim_ids, &keys, &wf_ids, &all_edge_ids).await?;

    // ---- invariants ----
    let mut v = Vec::new();
    for (what, n, want) in [
        ("workflows", n_wf, wf_ids.len()),
        ("claims", n_claims, claim_ids.len()),
        ("edges", n_edges, explicit.len()),
    ] {
        if usize::try_from(n).ok() != Some(want) {
            v.push(format!(
                "UPDATE {what} changed {n} row(s), the batch planned {want}"
            ));
        }
    }
    for id in &wf_ids {
        if wf_after.get(id) != Some(&to) {
            v.push(format!("workflow {id} ended as {:?}", wf_after.get(id)));
        }
    }
    for c in &claims_after {
        if claim_tenancy(c) != to {
            v.push(format!(
                "claim {} ended as ({}, {})",
                c.id, c.owner, c.visibility
            ));
        }
    }
    let mut rows_moved: BTreeMap<String, usize> = BTreeMap::new();
    let mut expect_lost: BTreeSet<RowKey> = BTreeSet::new();
    for (k, a) in &rows {
        // A writer-owned row a narrowing takes loses its flag (114).
        let want = RowState {
            tenancy: to.clone(),
            writer_owned: a.writer_owned.map(|_| false),
        };
        match attached_after.get(k) {
            Some(b) if RowState::of(b) == want => {
                *rows_moved.entry(k.0.clone()).or_default() += 1;
            }
            other => v.push(format!(
                "{} {} ended as {:?}, the plan says {want}",
                k.0,
                k.1,
                other.map(RowState::of)
            )),
        }
        if a.tenancy.visibility == PUBLIC && to.visibility != PUBLIC {
            expect_lost.insert(k.clone());
        }
    }
    for (k, a) in &kept_rows {
        if attached_after.get(k).map(RowState::of) != Some(RowState::of(a)) {
            v.push(format!("{} {} changed; it must stay as it is", k.0, k.1));
        }
        // 168: an outsider's challenge is readable only with its claim.
        if act.narrows() && a.tenancy.visibility == PUBLIC {
            expect_lost.insert(k.clone());
        }
    }
    for k in attached_after.keys() {
        if !keys.contains(k) {
            v.push(format!("{} {} appeared during the batch", k.0, k.1));
        }
    }
    let mut narrowed_edge = false;
    for e in &moving {
        let before = &e.row;
        match edges_after.get(&before.id) {
            Some(a)
                if a.tenancy == e.post
                    && a.writer_group == before.writer_group
                    && a.shape() == before.shape() => {}
            other => v.push(format!(
                "edge {} ended as {:?} (writer {:?}); the plan says {:?} with writer {:?} \
                 unchanged",
                before.id,
                other.map(|e| &e.tenancy),
                other.map(|e| e.writer_group),
                e.post,
                before.writer_group
            )),
        }
        if before.tenancy.visibility == PUBLIC && e.post.visibility != PUBLIC {
            narrowed_edge = true;
            expect_lost.insert(("edges".to_string(), before.id.to_string()));
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
    if act.narrows() {
        for id in &claim_ids {
            expect_lost.insert(("claims".to_string(), id.to_string()));
        }
        for id in &wf_ids {
            expect_lost.insert(("workflows".to_string(), id.to_string()));
        }
    }
    let mut expect: BTreeMap<String, (i64, i64, i64)> = BTreeMap::new();
    let as_i64 = |n: usize| i64::try_from(n).unwrap_or(i64::MAX);
    for (t, n) in [
        ("workflows", wf_ids.len()),
        ("claims", claim_ids.len()),
        ("edges", moving.len()),
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
    // Migration 197: one bump for the transaction's first public-to-non-public
    // narrowing of a claim or an edge (workflows carry no trigger).
    let bump = act.narrows() && bump_due && (!claim_ids.is_empty() || narrowed_edge);
    if bump {
        expect.insert("atlas_layout_epoch".to_string(), (0, 1, 0));
    }
    expect.retain(|_, d| *d != (0, 0, 0));
    v.extend(counter_violations(
        &counter_delta(&counters_before, &counters_after),
        &expect,
    ));
    let epoch_want = if bump {
        epoch_before.map(|n| n + 1)
    } else {
        epoch_before
    };
    if epoch_after != epoch_want {
        v.push(format!(
            "atlas_layout_epoch moved {epoch_before:?} -> {epoch_after:?}, expected \
             {epoch_want:?} (migration 197: a narrowing bumps it once, a public-to-public move \
             never)"
        ));
    }
    v.extend(readability_violations(
        &readable_before,
        &readable_after,
        &expect_lost,
        &BTreeSet::new(),
        ctx.unenforced,
    ));
    if !v.is_empty() {
        return Err(BatchError::Invariant(v));
    }

    // ---- post records, fsynced before the caller commits ----
    let mut post = Vec::new();
    for id in &wf_ids {
        post.push(rec(
            "workflows",
            json!(id.to_string()),
            &to,
            *id,
            true,
            false,
            None,
            false,
        ));
    }
    for id in &claim_ids {
        post.push(rec(
            "claims",
            json!(id.to_string()),
            &to,
            *id,
            true,
            false,
            None,
            false,
        ));
    }
    for (k, a) in &rows {
        post.push(rec(
            &k.0,
            spec_of(ctx.specs, &k.0).id_json(&k.1),
            &to,
            a.claim,
            true,
            false,
            a.writer_owned.map(|_| false),
            false,
        ));
    }
    for e in &moving {
        post.push(rec(
            "edges",
            e.row.id_json(),
            &e.post,
            Uuid::nil(),
            true,
            true,
            None,
            false,
        ));
    }
    sink.record_post(&post)?;
    out.workflows_moved = wf_ids.len();
    out.claims_moved = claim_ids.len();
    out.edges_moved = moving.len();
    out.rows_moved = rows_moved;
    out.epoch_bumped = bump;
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
    pub epoch_bumps: usize,
}

fn print_plan(out: &mut dyn std::io::Write, p: &Plan) -> anyhow::Result<usize> {
    for (n, h) in &p.held {
        writeln!(out, "HELD-LINEAGE\t{n}\t{h}")?;
    }
    for n in &p.already {
        writeln!(
            out,
            "ALREADY-LINEAGE\t{n}\tevery generation is in this run's target state"
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
            let how = if e.explicit { "" } else { " (cascade)" };
            *edges
                .entry(format!("{}{how}", e.row.relationship))
                .or_default() += 1;
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
        writeln!(out, "ROWS-KEPT\t{t}\t{n}\t(they stay as they are)")?;
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
    let all_specs = tables::propagated_tables(conn).await?;
    let specs: Vec<TableSpec> = all_specs
        .iter()
        .filter(|s| s.kind != Kind::Edges)
        .cloned()
        .collect();
    let unkeyed = tables::unkeyed_tables(conn, &specs).await?;
    let (source, target) = resolve_groups(conn, opts).await?;
    let act = Act {
        source,
        target,
        visibility: opts.visibility,
    };
    tables::probe_session_switch(conn).await?;
    let names_sha256 = sha256_file(&opts.names_file)?;
    // A narrowing is enforced only where row security hides a `group` row.
    // `workflows` (183's `workflows_read`) is checked empirically by every
    // batch's readability invariant instead.
    let unenforced = if act.narrows() {
        restrict::unenforced_reasons(conn, &all_specs).await?
    } else {
        BTreeMap::new()
    };

    let p = plan(conn, &specs, names, &act).await?;
    writeln!(
        out,
        "reown-workflows: operator={} source_group={source} target_group={target} act={} \
         visibility={} mode={}",
        opts.operator,
        act.name(),
        act.visibility.as_str(),
        if opts.apply { "APPLY" } else { "DRY-RUN" }
    )?;
    writeln!(
        out,
        "PLAN: {} lineage(s) listed, {} held, {} already in the target state, {} component(s) \
         to move",
        names.len(),
        p.held.len(),
        p.already.len(),
        p.components.len()
    )?;
    let eligible = print_plan(out, &p)?;
    report.eligible_workflow_rows = eligible;
    if act.narrows() {
        writeln!(
            out,
            "RULE: only ('public', source) rows change, and each ends ('group', target): the \
             claims narrow through the tenancy cascade (derived rows, fragments, every edge with \
             a claim endpoint; another writer's public row joins the claim's group and loses \
             its writer_owned flag, which the manifest records); an edge whose only changing \
             endpoint is a workflow row is narrowed by this tool to the meet of its endpoints; \
             writer_group_id is not rewritten; the atlas epoch bumps once per batch"
        )?;
        if unenforced.is_empty() {
            writeln!(
                out,
                "ENFORCEMENT: ENFORCED (no permissive read policy beyond <table>_tenancy on any \
                 table the cascade reaches)"
            )?;
        } else {
            let d = unenforced
                .iter()
                .map(|(t, ps)| format!("{t}: {}", ps.join(", ")))
                .collect::<Vec<_>>()
                .join("; ");
            writeln!(out, "WARNING: UNENFORCED: {d}")?;
            if opts.apply {
                bail!("a narrowing would not be enforced on: {d}. Refusing; nothing was written.");
            }
        }
    } else {
        writeln!(
            out,
            "RULE: only ('public', source) rows move and no visibility is written; structural \
             world-owned edges (executes, variant_of, asserts, AUTHORED) are no group's and \
             stay; writer_group_id is not rewritten"
        )?;
    }
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
        "record_format": RECORD_FORMAT,
        "version": manifest::VERSION,
        "operator": opts.operator,
        "source_group_id": source,
        "target_group_id": target,
        "visibility": act.visibility.as_str(),
        "act": act.name(),
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
        "act": act.name(),
        "visibility": act.visibility.as_str(),
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
        "enforcement": if unenforced.is_empty() {
            json!({"state": "ENFORCED"})
        } else {
            json!({"state": "UNENFORCED", "by": unenforced})
        },
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
        act,
        lock_timeout: &opts.lock_timeout,
        unenforced: &unenforced,
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
                report.epoch_bumps += usize::from(b.epoch_bumped);
                for (t, n) in b.rows_moved {
                    *report.rows_moved.entry(t).or_default() += n;
                }
                writeln!(
                    out,
                    "BATCH {}/{total}\tOK\t{} workflow row(s), {} claim(s), {} edge(s){}{}",
                    i + 1,
                    b.workflows_moved,
                    b.claims_moved,
                    b.edges_moved,
                    if b.epoch_bumped {
                        ", atlas epoch bumped"
                    } else {
                        ""
                    },
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
        if !report.batch_failures.is_empty() {
            format!(
                "{} batch(es) violated and were rolled back",
                report.batch_failures.len()
            )
        } else if act.narrows() {
            "all held in every batch (exactly the narrowed rows became unreadable to an \
             unstamped session; the atlas epoch bumped once per batch)"
                .to_string()
        } else {
            "all held in every batch (visibility unchanged, atlas epoch unchanged)".to_string()
        }
    )?;
    if act.narrows() && opts.apply && report.epoch_bumps > 0 {
        writeln!(
            out,
            "ATLAS: the layout epoch moved; re-run `atlas_layout --apply` so the atlas is served \
             again"
        )?;
    }
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

/// A manifest read back, keyed.
#[derive(Default)]
struct Recorded {
    /// Rows this run changed: their prior.
    prior: BTreeMap<RowKey, Record>,
    /// Rows this run changed: their post.
    post: BTreeMap<RowKey, Record>,
    /// Plan rows this run saw and left.
    seen: BTreeMap<RowKey, Record>,
    /// Every recorded edge's endpoints and relationship.
    shapes: BTreeMap<String, EdgeShape>,
}

impl Recorded {
    fn knows(&self, k: &RowKey) -> bool {
        self.prior.contains_key(k) || self.seen.contains_key(k)
    }

    fn ids(map: &BTreeMap<RowKey, Record>, t: &str) -> Vec<Uuid> {
        map.keys()
            .filter(|k| k.0 == t)
            .filter_map(|k| Uuid::parse_str(&k.1).ok())
            .collect()
    }
}

fn read_records(
    m: &manifest::Manifest,
    specs: &[TableSpec],
    path: &Path,
) -> anyhow::Result<Recorded> {
    let mut r = Recorded::default();
    for rec in &m.records {
        let pk = match rec.table.as_str() {
            "workflows" | "claims" => rec
                .id
                .as_str()
                .ok_or_else(|| anyhow!("{}: {} id is not a string", path.display(), rec.table))?
                .to_string(),
            "edges" => {
                let (pk, shape) = edge_from_json(&rec.id)
                    .with_context(|| format!("{}: an edge record", path.display()))?;
                r.shapes.insert(pk.clone(), shape);
                pk
            }
            t => tables::spec(specs, t)
                .ok_or_else(|| {
                    anyhow!(
                        "{}: names table {t}, which the live cascade does not reach; refusing",
                        path.display()
                    )
                })?
                .pk_from_json(&rec.id)?,
        };
        let key = (rec.table.clone(), pk);
        if rec.after {
            r.post.insert(key, rec.clone());
        } else if rec.neighbour {
            r.seen.entry(key).or_insert_with(|| rec.clone());
        } else {
            r.prior.entry(key).or_insert_with(|| rec.clone());
        }
    }
    Ok(r)
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
    if m.header.get("record_format").and_then(Value::as_str) != Some(RECORD_FORMAT) {
        bail!(
            "{}: record_format is not {RECORD_FORMAT} (a manifest from an older build records \
             neither the rows it saw nor its edges' endpoints, so its plan's growth cannot be \
             checked); refusing",
            path.display()
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
    let visibility = Visibility::parse(
        m.header
            .get("visibility")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("{}: header has no visibility", path.display()))?,
    )?;
    let act = Act {
        source,
        target,
        visibility,
    };
    let rec = read_records(m, &specs, path)?;
    let (wf_ids, claim_ids, edge_ids) = (
        Recorded::ids(&rec.post, "workflows"),
        Recorded::ids(&rec.post, "claims"),
        Recorded::ids(&rec.post, "edges"),
    );
    writeln!(
        out,
        "REOWN-WORKFLOWS-MANIFEST\t{}\tsource_group={source}\ttarget_group={target}\t\
         act={}\tmoved: {} workflow row(s), {} claim(s), {} edge(s)",
        path.display(),
        act.name(),
        wf_ids.len(),
        claim_ids.len(),
        edge_ids.len()
    )?;
    if rec.post.is_empty() {
        writeln!(out, "  nothing was moved by this run; nothing to reverse")?;
        return Ok(true);
    }
    let unenforced = if act.narrows() {
        restrict::unenforced_reasons(conn, all_specs).await?
    } else {
        BTreeMap::new()
    };

    let mut tx = sqlx::Connection::begin(&mut *conn).await?;
    let r = reverse_tx(
        &mut tx,
        &specs,
        unkeyed,
        &opts.lock_timeout,
        &act,
        &rec,
        &unenforced,
        opts.apply.then(|| {
            (
                json!({
                    "tool": "epigraph-operator",
                    "command": "reown-reverse (reown-workflows manifest)",
                    "act": act.name(),
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
                "  REFUSED: {} reason(s): the plan changed or grew since the run; nothing of this \
                 manifest is restored",
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

/// A row's full recorded state.
fn state_of_record(r: &Record) -> RowState {
    RowState::of_record(r)
}

/// Whether `cur` is the recorded state `r` (tenancy, the `writer_owned` flag
/// where recorded, and for an edge its endpoints and relationship).
fn matches(r: &Record, cur: &RowState, shape: Option<(&EdgeShape, &EdgeShape)>) -> bool {
    let want = state_of_record(r);
    let co_ok = r
        .co_owner_group_id
        .is_none_or(|co| co == cur.tenancy.co_owner);
    want.tenancy.owner == cur.tenancy.owner
        && want.tenancy.visibility == cur.tenancy.visibility
        && co_ok
        && r.writer_owned.is_none_or(|w| cur.writer_owned == Some(w))
        && shape.is_none_or(|(a, b)| a == b)
}

#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
async fn reverse_tx(
    conn: &mut PgConnection,
    specs: &[TableSpec],
    unkeyed: &[String],
    lock_timeout: &str,
    act: &Act,
    rec: &Recorded,
    unenforced: &BTreeMap<String, Vec<String>>,
    audit: Option<(Value, Uuid)>,
) -> Result<RevOutcome, BatchError> {
    let wf_ids = Recorded::ids(&rec.post, "workflows");
    let claim_ids = Recorded::ids(&rec.post, "claims");
    let edge_ids = Recorded::ids(&rec.post, "edges");
    let manifest_wf: Vec<Uuid> = {
        let mut v = Recorded::ids(&rec.prior, "workflows");
        v.extend(Recorded::ids(&rec.seen, "workflows"));
        v
    };
    let known_claims: BTreeSet<Uuid> = Recorded::ids(&rec.prior, "claims")
        .into_iter()
        .chain(Recorded::ids(&rec.seen, "claims"))
        .collect();
    let known_claim_vec: Vec<Uuid> = known_claims.iter().copied().collect();

    sqlx::query("SELECT set_config('lock_timeout', $1, true)")
        .bind(lock_timeout)
        .execute(&mut *conn)
        .await?;
    sqlx::query("LOCK TABLE public.workflows IN SHARE ROW EXCLUSIVE MODE")
        .execute(&mut *conn)
        .await?;
    sqlx::query("SELECT id FROM workflows WHERE id = ANY($1) ORDER BY id FOR UPDATE")
        .bind(&wf_ids)
        .fetch_all(&mut *conn)
        .await?;
    fetch_claims(conn, &claim_ids, true).await?;
    tables::lock_unkeyed_tables(conn, unkeyed).await?;
    sqlx::query("SELECT id FROM edges WHERE id = ANY($1) ORDER BY id FOR UPDATE")
        .bind(&edge_ids)
        .fetch_all(&mut *conn)
        .await?;

    // ---- current state ----
    let wf_now = workflow_tenancy(conn, &wf_ids).await?;
    let claims_now: BTreeMap<Uuid, Tenancy> = fetch_claims(conn, &claim_ids, false)
        .await?
        .into_iter()
        .map(|c| (c.id, claim_tenancy(&c)))
        .collect();
    let edges_now: BTreeMap<Uuid, EdgeRow> = fetch_edges_by_id(conn, &edge_ids)
        .await?
        .into_iter()
        .map(|e| (e.id, e))
        .collect();
    let attached_now = fetch_attached(conn, specs, &claim_ids).await?;
    let plain = |t: Tenancy| RowState {
        tenancy: t,
        writer_owned: None,
    };
    let current = |k: &RowKey| -> Option<RowState> {
        let id = Uuid::parse_str(&k.1).ok();
        match k.0.as_str() {
            "workflows" => id.and_then(|i| wf_now.get(&i).cloned()).map(plain),
            "claims" => id.and_then(|i| claims_now.get(&i).cloned()).map(plain),
            "edges" => id
                .and_then(|i| edges_now.get(&i))
                .map(|e| plain(e.tenancy.clone())),
            _ => attached_now.get(k).map(RowState::of),
        }
    };
    let shape_now = |k: &RowKey| -> Option<EdgeShape> {
        (k.0 == "edges")
            .then(|| Uuid::parse_str(&k.1).ok())
            .flatten()
            .and_then(|i| edges_now.get(&i))
            .map(EdgeRow::shape)
    };

    // ---- compare-and-swap ----
    let mut held: Vec<(Uuid, String)> = Vec::new();
    let mut restore: Vec<&RowKey> = Vec::new();
    let mut already = 0usize;
    for (k, p) in &rec.post {
        let Some(pr) = rec.prior.get(k) else {
            held.push((
                Uuid::nil(),
                format!("{} {}: a post record with no prior", k.0, k.1),
            ));
            continue;
        };
        let anchor = Uuid::parse_str(&k.1).unwrap_or(pr.claim_id);
        let recorded_shape = rec.shapes.get(&k.1).filter(|_| k.0 == "edges");
        let now_shape = shape_now(k);
        let shapes = match (recorded_shape, now_shape.as_ref()) {
            (Some(a), Some(b)) => Some((a, b)),
            _ => None,
        };
        match current(k) {
            None => held.push((anchor, format!("{} {} no longer exists", k.0, k.1))),
            Some(_) if shapes.is_some_and(|(a, b)| a != b) => held.push((
                anchor,
                format!(
                    "edge {} now joins {:?}, not {:?} as this run moved it: it was re-pointed \
                     since (an evolved step's supersede cascade), so restoring it would hand \
                     the source a link into the team's plan",
                    k.1,
                    now_shape.as_ref().map(|s| (&s.0, &s.1, &s.2)),
                    recorded_shape.map(|s| (&s.0, &s.1, &s.2)),
                ),
            )),
            Some(t) if matches(p, &t, shapes) => restore.push(k),
            Some(t) if matches(pr, &t, shapes) => already += 1,
            Some(t) => held.push((
                anchor,
                format!(
                    "{} {} is {t}, neither the post state {} this run left nor its prior {}: it \
                     changed since",
                    k.0,
                    k.1,
                    state_of_record(p),
                    state_of_record(pr)
                ),
            )),
        }
    }

    // ---- growth since the run ----
    // A generation of a moved lineage that the run did not see.
    let names: Vec<String> =
        sqlx::query_scalar("SELECT DISTINCT canonical_name FROM workflows WHERE id = ANY($1)")
            .bind(&wf_ids)
            .fetch_all(&mut *conn)
            .await?;
    for (id, name, generation) in sqlx::query_as::<_, (Uuid, String, i32)>(
        "SELECT id, canonical_name, generation FROM workflows \
          WHERE canonical_name = ANY($1) AND id <> ALL($2) ORDER BY canonical_name, generation",
    )
    .bind(&names)
    .bind(&manifest_wf)
    .fetch_all(&mut *conn)
    .await?
    {
        held.push((
            id,
            format!(
                "lineage {name} has workflow row {id} (generation {generation}) that this run did \
                 not see: a generation joined it after the move, and restoring the rest would \
                 split the lineage"
            ),
        ));
    }
    // A claim a manifest workflow executes that the run did not see (add_step).
    for (c, w) in sqlx::query_as::<_, (Uuid, Uuid)>(
        "SELECT DISTINCT target_id, source_id FROM edges \
          WHERE relationship = 'executes' AND source_type = 'workflow' AND target_type = 'claim' \
            AND source_id = ANY($1) AND target_id <> ALL($2)",
    )
    .bind(&manifest_wf)
    .bind(&known_claim_vec)
    .fetch_all(&mut *conn)
    .await?
    {
        held.push((
            c,
            format!(
                "claim {c} is executed by workflow {w}, which this run moved, but the run never \
                 saw it: a step was added after the move"
            ),
        ));
    }
    // A member of a recorded claim's step lineage that the run did not see
    // (evolve_step's successor).
    for (c, l) in sqlx::query_as::<_, (Uuid, Uuid)>(
        "SELECT c.id, c.step_lineage_id FROM claims c \
          WHERE c.step_lineage_id IN (SELECT k.step_lineage_id FROM claims k \
                                       WHERE k.id = ANY($1) AND k.step_lineage_id IS NOT NULL) \
            AND c.id <> ALL($1)",
    )
    .bind(&known_claim_vec)
    .fetch_all(&mut *conn)
    .await?
    {
        held.push((
            c,
            format!(
                "claim {c} joined step lineage {l} of the moved plan after the run (an evolved \
                 step's successor); restoring the rest would split the step lineage"
            ),
        ));
    }
    // A moved claim another workflow now executes.
    for (c, w) in sqlx::query_as::<_, (Uuid, Uuid)>(
        "SELECT target_id, source_id FROM edges \
          WHERE relationship = 'executes' AND source_type = 'workflow' AND target_type = 'claim' \
            AND target_id = ANY($1) AND source_id <> ALL($2)",
    )
    .bind(&claim_ids)
    .bind(&manifest_wf)
    .fetch_all(&mut *conn)
    .await?
    {
        held.push((
            c,
            format!("claim {c} is now also executed by workflow {w}, which this run did not move"),
        ));
    }
    // A row on a moved claim that the run did not see.
    for (k, a) in &attached_now {
        if !rec.knows(k) {
            held.push((
                a.claim,
                format!(
                    "{} {} on moved claim {} was written after the run ({}); the reversal would \
                     carry it to the source",
                    k.0,
                    k.1,
                    a.claim,
                    RowState::of(a)
                ),
            ));
        }
    }
    // An edge on a moved claim or workflow that the run did not see.
    for e in fetch_edges(conn, &claim_ids, &wf_ids).await? {
        if !rec.knows(&("edges".to_string(), e.id.to_string())) {
            held.push((
                e.id,
                format!(
                    "edge {} ({} {} -[{}]-> {} {}) touches the moved plan and was written after \
                     the run",
                    e.id, e.source.1, e.source.0, e.relationship, e.target.1, e.target.0
                ),
            ));
        }
    }
    // A seal since the run: a sealed claim or row cannot be made public.
    for c in sqlx::query_scalar::<_, Uuid>(
        "SELECT DISTINCT claim_id FROM claim_encryption WHERE claim_id = ANY($1)",
    )
    .bind(&claim_ids)
    .fetch_all(&mut *conn)
    .await?
    {
        held.push((c, format!("claim {c} has been sealed since the run")));
    }
    for ev in sqlx::query_scalar::<_, Uuid>(
        "SELECT ee.evidence_id FROM evidence_encryption ee \
           JOIN evidence e ON e.id = ee.evidence_id WHERE e.claim_id = ANY($1)",
    )
    .bind(&claim_ids)
    .fetch_all(&mut *conn)
    .await?
    {
        held.push((ev, format!("evidence {ev} has been sealed since the run")));
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
    let attached_keys: BTreeSet<RowKey> = attached_now.keys().cloned().collect();
    let readable_before =
        readable(conn, specs, &claim_ids, &attached_keys, &wf_ids, &edge_ids).await?;
    let epoch_before = atlas_epoch(conn).await?;
    let edges_pre: BTreeMap<Uuid, Tenancy> = fetch_edges(conn, &claim_ids, &wf_ids)
        .await?
        .into_iter()
        .map(|e| (e.id, e.tenancy))
        .collect();
    let counters_before = xact_counters(conn).await?;

    let to_vis = act.to_vis();
    let payload = |t: &str| -> Value {
        Value::Array(
            restore
                .iter()
                .filter(|k| k.0 == t)
                .map(|k| {
                    let r = &rec.prior[*k];
                    json!({"id": k.1, "o": r.owner_group_id, "v": r.visibility,
                           "co": r.co_owner_group_id.flatten()})
                })
                .collect(),
        )
    };
    let count = |t: &str| restore.iter().filter(|k| k.0 == t).count();
    let n_wf = sqlx::query(
        "UPDATE workflows w SET owner_group_id = m.o, visibility = m.v \
           FROM jsonb_to_recordset($1::jsonb) AS m(id uuid, o uuid, v text, co uuid) \
          WHERE w.id = m.id AND w.owner_group_id = $2 AND w.visibility = $3",
    )
    .bind(payload("workflows"))
    .bind(act.target)
    .bind(to_vis)
    .execute(&mut *conn)
    .await
    .context("restoring workflows")?
    .rows_affected();
    // The one widening statement on claims (074's guard), armed around it only.
    let widens = act.narrows();
    if widens {
        sqlx::query("SELECT set_config('epigraph.allow_declassify', 'yes', true)")
            .execute(&mut *conn)
            .await?;
    }
    let n_claims = sqlx::query(
        "UPDATE claims c SET owner_group_id = m.o, visibility = m.v \
           FROM jsonb_to_recordset($1::jsonb) AS m(id uuid, o uuid, v text, co uuid) \
          WHERE c.id = m.id AND c.owner_group_id = $2 AND c.visibility = $3",
    )
    .bind(payload("claims"))
    .bind(act.target)
    .bind(to_vis)
    .execute(&mut *conn)
    .await
    .context("restoring claims")?
    .rows_affected();
    if widens {
        sqlx::query("SELECT set_config('epigraph.allow_declassify', '', true)")
            .execute(&mut *conn)
            .await?;
    }

    // What the cascade did to the attached rows and edges.
    let attached_mid = fetch_attached(conn, specs, &claim_ids).await?;
    let mut trigger_changed: BTreeMap<String, i64> = BTreeMap::new();
    for (k, a) in &attached_now {
        if attached_mid.get(k).map(RowState::of) != Some(RowState::of(a)) {
            *trigger_changed.entry(k.0.clone()).or_default() += 1;
        }
    }
    let mut edges_trigger = 0i64;
    for e in fetch_edges(conn, &claim_ids, &wf_ids).await? {
        if edges_pre.get(&e.id).is_some_and(|t| *t != e.tenancy) {
            edges_trigger += 1;
        }
    }
    if edges_trigger > 0 {
        *trigger_changed.entry("edges".to_string()).or_default() += edges_trigger;
    }

    // Recorded derived rows back on their OWN recorded tuple (writer_owned
    // included).
    let mut to_write: BTreeMap<String, Vec<(String, RowState)>> = BTreeMap::new();
    for k in &restore {
        if matches!(k.0.as_str(), "workflows" | "claims" | "edges") {
            continue;
        }
        let want = state_of_record(&rec.prior[*k]);
        if attached_mid.get(*k).map(RowState::of) != Some(want.clone()) {
            to_write
                .entry(k.0.clone())
                .or_default()
                .push((k.1.clone(), want));
        }
    }
    let mut restored_writes: BTreeMap<String, i64> = BTreeMap::new();
    for (t, rows) in &to_write {
        let n = restrict::write_rows(conn, spec_of(specs, t), &claim_ids, rows)
            .await
            .map_err(BatchError::Db)?;
        restored_writes.insert(t.clone(), i64::try_from(n).unwrap_or(i64::MAX));
    }
    // Recorded edges back on their recorded tuple.
    let edges_mid: BTreeMap<Uuid, Tenancy> = fetch_edges_by_id(conn, &edge_ids)
        .await?
        .into_iter()
        .map(|e| (e.id, e.tenancy))
        .collect();
    let edge_payload: Vec<Value> = restore
        .iter()
        .filter(|k| k.0 == "edges")
        .filter_map(|k| {
            let r = &rec.prior[*k];
            let want = state_of_record(r).tenancy;
            let id = Uuid::parse_str(&k.1).ok()?;
            (edges_mid.get(&id) != Some(&want)).then(
                || json!({"id": id, "o": want.owner, "v": want.visibility, "co": want.co_owner}),
            )
        })
        .collect();
    let n_edge_writes = edge_payload.len();
    let n_edges = sqlx::query(
        "UPDATE edges e SET owner_group_id = m.o, visibility = m.v, co_owner_group_id = m.co \
           FROM jsonb_to_recordset($1::jsonb) AS m(id uuid, o uuid, v text, co uuid) \
          WHERE e.id = m.id",
    )
    .bind(Value::Array(edge_payload))
    .execute(&mut *conn)
    .await
    .context("restoring edges")?
    .rows_affected();
    if n_edges > 0 {
        *restored_writes.entry("edges".to_string()).or_default() +=
            i64::try_from(n_edges).unwrap_or(i64::MAX);
    }

    let counters_after = xact_counters(conn).await?;
    let epoch_after = atlas_epoch(conn).await?;
    let wf_after = workflow_tenancy(conn, &wf_ids).await?;
    let claims_after: BTreeMap<Uuid, Tenancy> = fetch_claims(conn, &claim_ids, false)
        .await?
        .into_iter()
        .map(|c| (c.id, claim_tenancy(&c)))
        .collect();
    let edges_after: BTreeMap<Uuid, EdgeRow> = fetch_edges_by_id(conn, &edge_ids)
        .await?
        .into_iter()
        .map(|e| (e.id, e))
        .collect();
    let attached_after = fetch_attached(conn, specs, &claim_ids).await?;
    let readable_after =
        readable(conn, specs, &claim_ids, &attached_keys, &wf_ids, &edge_ids).await?;

    let mut v = Vec::new();
    for (what, n, want) in [
        ("workflows", n_wf, count("workflows")),
        ("claims", n_claims, count("claims")),
        ("edges", n_edges, n_edge_writes),
    ] {
        if usize::try_from(n).ok() != Some(want) {
            v.push(format!(
                "restoring {what} wrote {n} row(s), {want} were due"
            ));
        }
    }
    let mut expect_gained: BTreeSet<RowKey> = BTreeSet::new();
    for k in &restore {
        let pr = &rec.prior[*k];
        let id = Uuid::parse_str(&k.1).ok();
        let now: Option<RowState> = match k.0.as_str() {
            "workflows" => id.and_then(|i| wf_after.get(&i).cloned()).map(plain),
            "claims" => id.and_then(|i| claims_after.get(&i).cloned()).map(plain),
            "edges" => id
                .and_then(|i| edges_after.get(&i))
                .map(|e| plain(e.tenancy.clone())),
            _ => attached_after.get(*k).map(RowState::of),
        };
        match now {
            Some(t) if matches(pr, &t, None) => {}
            other => v.push(format!(
                "{} {} ended as {}, its recorded prior is {}",
                k.0,
                k.1,
                other.map_or_else(|| "nothing".to_string(), |t| t.to_string()),
                state_of_record(pr)
            )),
        }
        if pr.visibility == PUBLIC && rec.post[*k].visibility != PUBLIC {
            expect_gained.insert((*k).clone());
        }
    }
    // 168: an outsider's challenge is readable again with its claim.
    if act.narrows() {
        for (k, a) in &attached_now {
            if is_outsider_challenge(&k.0, a.writer_owned) && a.tenancy.visibility == PUBLIC {
                expect_gained.insert(k.clone());
            }
        }
    }
    for e in edges_after.values() {
        if edges_now.get(&e.id).map(|b| b.writer_group) != Some(e.writer_group) {
            v.push(format!("edge {} writer_group_id changed", e.id));
        }
    }
    for (k, a) in &attached_now {
        if !attached_after.contains_key(k) {
            v.push(format!("{} {} vanished", k.0, k.1));
        } else if !rec.prior.contains_key(k)
            && attached_after.get(k).map(RowState::of) != Some(RowState::of(a))
        {
            v.push(format!(
                "{} {}, which this run did not change, changed",
                k.0, k.1
            ));
        }
    }
    let as_i64 = |n: usize| i64::try_from(n).unwrap_or(i64::MAX);
    let mut expect: BTreeMap<String, (i64, i64, i64)> = BTreeMap::new();
    for (t, n) in [("workflows", n_wf), ("claims", n_claims)] {
        expect.insert(
            t.to_string(),
            (0, as_i64(usize::try_from(n).unwrap_or(0)), 0),
        );
    }
    for (t, n) in trigger_changed.iter().chain(restored_writes.iter()) {
        expect.entry(t.clone()).or_default().1 += n;
    }
    expect.retain(|_, d| *d != (0, 0, 0));
    v.extend(counter_violations(
        &counter_delta(&counters_before, &counters_after),
        &expect,
    ));
    if epoch_before != epoch_after {
        v.push(format!(
            "atlas_layout_epoch moved {epoch_before:?} -> {epoch_after:?}; a reversal never \
             narrows (migration 197)"
        ));
    }
    v.extend(readability_violations(
        &readable_before,
        &readable_after,
        &BTreeSet::new(),
        &expect_gained,
        unenforced,
    ));
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

    fn opts() -> Options {
        Options {
            names_file: PathBuf::from("n"),
            target: Uuid::new_v4(),
            operator: Uuid::new_v4(),
            from_group: None,
            manifest_out: PathBuf::from("m"),
            apply: true,
            confirm_count: Some(1),
            ruling: "r".into(),
            reason: "why".into(),
            visibility: Visibility::Keep,
            batch_size: 25,
            lock_timeout: "5s".into(),
        }
    }

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
        let o = opts();
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
    fn visibility_parses_keep_and_group_only() {
        assert_eq!(Visibility::parse("keep").unwrap(), Visibility::Keep);
        assert_eq!(Visibility::parse("group").unwrap(), Visibility::Group);
        assert!(Visibility::parse("public").is_err());
        assert!(Visibility::parse("").is_err());
    }

    #[test]
    fn the_act_names_its_states() {
        let (s, t) = (Uuid::from_u128(1), Uuid::from_u128(2));
        let mv = Act {
            source: s,
            target: t,
            visibility: Visibility::Keep,
        };
        assert_eq!(mv.to_state().visibility, "public");
        assert_eq!(mv.name(), "MOVE");
        let narrow = Act {
            visibility: Visibility::Group,
            ..mv
        };
        assert_eq!(
            narrow.to_state(),
            Tenancy {
                owner: t,
                visibility: "group".into(),
                co_owner: None
            }
        );
        let in_place = Act {
            target: s,
            ..narrow
        };
        assert_eq!(in_place.to_state().owner, in_place.from_state().owner);
        assert_eq!(in_place.name(), "NARROW-IN-PLACE");
    }

    #[test]
    fn the_union_find_joins_transitively() {
        let mut d = Dsu::default();
        d.union("c", "b");
        d.union("b", "a");
        assert_eq!(d.find("c"), d.find("a"));
        assert_ne!(d.find("x"), d.find("a"));
    }

    #[test]
    fn an_edge_record_carries_its_endpoints() {
        let e = EdgeRow {
            id: Uuid::from_u128(9),
            source: (Uuid::from_u128(1), "claim".into()),
            target: (Uuid::from_u128(2), "claim".into()),
            relationship: "decomposes_to".into(),
            tenancy: Tenancy {
                owner: Uuid::from_u128(3),
                visibility: "public".into(),
                co_owner: None,
            },
            writer_group: None,
            source_state: (Uuid::nil(), "public".into()),
            target_state: (Uuid::nil(), "public".into()),
        };
        let (pk, shape) = edge_from_json(&e.id_json()).unwrap();
        assert_eq!(pk, e.id.to_string());
        assert_eq!(shape, e.shape());
    }
}
