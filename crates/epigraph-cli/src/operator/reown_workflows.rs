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
//!   NOT COVERED: `behavioral_executions` (a plan's recorded runs: goal text,
//!   goal embedding, step beliefs, tool pattern) has no tenancy columns and no
//!   row security (migration 069 ledgers it PENDING), so no narrowing can hide
//!   its rows. The dry run counts them (`BEHAVIORAL-EXECUTIONS`); the read
//!   paths must gate them on the workflow's readability.
//!
//! # A private move (`--from-visibility group`)
//!
//! Lineages that are ALREADY private, `('group', source)`, move whole to
//! `('group', target)` with `--from-visibility group --visibility group`:
//! a group-private pipeline that belongs to another group, or a narrowed
//! lineage that belongs in the operator's own group. The target is another
//! group: an active `team` or `community` group the operator administers, or
//! the operator's OWN personal group (`regroup::check_private_target`, the
//! rule `regroup-claims` applies); never another person's personal group nor
//! an operated agent's. The source (`--from-group`, or the default) is held
//! to the same rule (`check_private_source`): its rows are private, so
//! another person's or an operated agent's personal group never gives them
//! up, whoever administers it or runs the tool. `--catch-up` is refused. It
//! is the public act's machinery with the FROM state `('group', source)`:
//!
//! * a SEALED row holds its lineage (`LineageHold::Sealed`): a plan claim
//!   with a `claim_encryption` row or a sealed version
//!   (`claim_version_encryption`), an evidence row of one with an
//!   `evidence_encryption` row, or a moving edge with an `edge_encryption`
//!   row. Its ciphertext is keyed to the group that sealed it and a move does
//!   not re-key it, so ciphertext never leaves that group; an `--apply` then
//!   exits 3. Each batch locks the moving claims, edges and evidence rows
//!   `FOR UPDATE` (which blocks a new seal's foreign key) and re-plans, so a
//!   seal that lands after the dry run holds too;
//! * a generation or an unshared plan claim that is PUBLIC is public input,
//!   the public act's to narrow first: a public generation holds its lineage
//!   (`PublicInput`), and an unshared public plan claim, or a public derived
//!   row, holds it as a hand-off (an `--apply` exits 3), because moving the
//!   rest would split the plan. Nothing becomes public, and nothing public is
//!   narrowed but the plan's own edges (an edge is never more visible than
//!   the plan it describes; such an edge bumps the atlas epoch as in the
//!   public act);
//! * [`hand_off`] lets a private row the SOURCE owns (or the target already
//!   owns) change owner, when its new tuple still requires every group its
//!   old one did with the source replaced by the target (a co-owner is
//!   kept). A private row a third group owns still holds the lineage;
//! * a plan claim shared with a lineage the list omits stays where it is,
//!   reported as SHARED and, when that lineage is the source's in the FROM
//!   state, as `SHARED-SPLIT`. Every edge between a moved row and one that
//!   stays in its group is co-owned by both groups and printed
//!   (`CO-OWNED-EDGE`);
//! * an edge to a group-private node of another type with its own tenancy (a
//!   frame, context, perspective, community or reasoning trace that does not
//!   end in the TO state) holds its lineage: the cascade meets such a node as
//!   public, so the edge would go to the target naming a node the target
//!   cannot read;
//! * an unstamped session reads none of these rows before or after, so every
//!   batch also reads them as a session whose read set is ONLY the source and
//!   one whose read set is ONLY the target, before and after, and each must
//!   read exactly what the tenancy model says (a public row, or one whose
//!   owner and co-owner are that group);
//! * the manifest header records `from_visibility: group`; `reown-reverse`
//!   reverses it exactly, without arming 074's declassify guard (no claim
//!   widens).
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
//!
//!   `--catch-up` (with `--visibility group`) is the remedy for a generation
//!   that joined a lineage AFTER its act: it takes only a lineage that has a
//!   generation in the TO state, and its other generations are STRAY (FROM,
//!   or, in a move, the source's private state, which is neither FROM nor
//!   TO). A lineage with no generation in TO is the main act's, never a
//!   catch-up's: SKIPPED when it is all FROM, HELD otherwise. In a MOVE the
//!   act must also be on record: at least one of the lineage's TO
//!   generations must be one an `--after-manifest` (the manifest of the act
//!   it catches up to, or of an earlier catch-up of it) moved into exactly
//!   this run's TO state. A lineage whose TO generations no such manifest
//!   moved is HELD (`NotActed`), by design: the target may own it natively,
//!   a catch-up must never hand the source's rows to a group just because
//!   that group owns a generation of the same name, and no act of this tool
//!   takes such a lineage (it stays until a ruling). One recorded generation
//!   is enough: an act takes a lineage only whole, so a TO generation it did
//!   not record joined after it (an undeclared re-ingest lands in TO, see
//!   below). Without `--after-manifest`, a move's catch-up holds every
//!   lineage with a TO generation. IN PLACE no act need be on record, and
//!   `NotActed` never applies: TO is the source's own private state, so a
//!   catch-up can only narrow the source's own public generations (and
//!   their plan rows) into it, whether its TO generations were narrowed by
//!   an act or were private from the start. A plain `--catch-up` does it; an
//!   `--after-manifest` is still checked there, but not needed. A catch-up
//!   changes the stray generations and their plan rows under the main act's
//!   rules, with ONE exemption from the hand-off rule, for the stray
//!   generations' OWN rows ([`StrayScope`]): their `workflows` rows, the
//!   source's private plan claims only they reach, and those claims' plan
//!   edges among themselves, the lineage's TO rows and their author agent.
//!   These go into exactly the TO state. Every other row keeps the hand-off
//!   rule, so a catch-up never widens anything else: a private derived row
//!   (evidence on a new step), a private edge to a row outside the plans, or
//!   a private step the main act left holds the lineage, and an `--apply`
//!   exits 3. The TO generations and claims are recorded as SEEN, so the
//!   reversal's growth check accepts them, and are never written. It is
//!   audited, manifested and reversed exactly like the main act; reversing
//!   the catch-up puts the lineage back in the state it found it in, and the
//!   original manifest then refuses (a generation joined after it).
//!
//!   A stray generation is the exception, not the rule: the workflow ingest
//!   gives an undeclared new generation of a group lineage its head's group
//!   (the generation-inheritance rule in epigraph-ingest-executor's
//!   `workflow.rs`: `inherited_generation_group`, or
//!   `inherited_generation_tenancy` once renamed), so after the act a
//!   re-ingest lands in TO, or is refused to a caller that does not write TO.
//!   A stray one comes from an ingest that DECLARED the source group, or from
//!   a server built before that inheritance (which wrote a new generation
//!   public).
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
//!   - owned by a group other than the source, or not public (under
//!     `--catch-up`, a stray generation's own private claim is taken; see
//!     [`StrayScope`]);
//!   - `keep` only: carrying a row the cascade would move that is not
//!     `('public', source)` (a third group's derived row, pinned evidence), or
//!     an edge with a non-public endpoint, or sharing a cascaded row (a
//!     harvester fragment) with a plan claim that stays (to a fixpoint);
//!   - `group` only: sharing a harvester fragment with a claim that does not
//!     end in the TO state (the cascade would narrow the fragment for both),
//!     to a fixpoint, with its step lineage. It is reported as SHARED.
//!
//!   A narrowing leaves a plan claim public for no other reason. It decides
//!   every cascaded row and edge by the state the database leaves it in (the
//!   cascade's meet; pinned evidence keeps its owner, 110; an outsider's
//!   challenge stays, 168), not by the `keep` rules: a row or edge already in
//!   that state (an edge to a row private to the target, or in place to the
//!   same group; evidence already pinned private there) is unchanged and never
//!   blocks. Only a HAND-OFF does ([`hand_off`]): a non-public row whose OWNER
//!   would become the target (a private row of the source, in a move, or of
//!   another group), a widening, or another group's public row the database
//!   does not itself take (114's writer-owned rows and 120's edges it does).
//!   A hand-off HOLDS THE WHOLE LINEAGE (and every lineage joined to it), and
//!   an `--apply` exits 3. Holding a move on a source-private edge is a
//!   choice: the target would get owner and delete rights over a row the
//!   source kept private, which a ruling to narrow public plans does not
//!   cover. The remedy is a separate act on that row (or, for the rows a
//!   generation that joined after the act wrote itself, `--catch-up`).
//!
//!   A claim shared with a source-owned PUBLIC lineage the list omits is
//!   named on a `SHARED-SPLIT` line: no run of either list narrows it alone,
//!   so lineages that share a plan claim must be listed in ONE run.
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
//! row that stays is unchanged (`writer_group_id` included); under a
//! narrowing, no plan row of its lineages is still public (re-checked after
//! the commits; a row found public exits 3, `LEFT-PUBLIC`);
//! `pg_stat_xact_user_tables` counts exactly the planned rows per table and
//! none elsewhere; an UNSTAMPED `epigraph_app` session reads exactly the same
//! keys (keep) or lost exactly the narrowed keys (group); and the atlas epoch
//! is unchanged (keep) or bumped once (group). Any violation rolls the batch
//! back (exit 2). An `--apply` whose batches held a component under lock, or
//! moved a different number of workflow rows than `--confirm-count`, exits 3.
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
//!   member of a MOVED claim's step lineage (an evolved step's successor),
//!   that the run did not see (a lineage the run left as shared belongs to
//!   another plan too, so its growth does not block this reversal);
//! * a moved claim now executed by a workflow the run did not move;
//! * a row attached to a moved claim, or an edge touching a moved claim or
//!   workflow, that the run did not see (new evidence, a BBA, a new link);
//! * a moved claim, a version of one, its evidence or a moved edge sealed
//!   since (`claim_encryption`, `claim_version_encryption`,
//!   `evidence_encryption`, `edge_encryption`).
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

/// `--from-visibility`: `public` (the default: the public act) or `group` (a
/// private move). Returns whether the move is private.
///
/// # Errors
/// Anything but `public` or `group`.
pub fn parse_from_visibility(s: &str) -> anyhow::Result<bool> {
    match s {
        "public" => Ok(false),
        "group" => Ok(true),
        other => bail!("--from-visibility must be public or group, not {other:?}"),
    }
}

/// The resolved act: where rows come from, where they go, and how visible.
#[derive(Clone, Copy, Debug)]
pub struct Act {
    pub source: Uuid,
    pub target: Uuid,
    pub visibility: Visibility,
    /// `--catch-up`: take only lineages with a generation in the TO state, and
    /// change only their other (stray) generations; the stray generations' own
    /// private rows may go into the TO state ([`StrayScope`]).
    pub catch_up: bool,
    /// `--from-visibility group`: a PRIVATE MOVE. The FROM state is
    /// `('group', source)`, the TO state `('group', target)`, and the target
    /// is another group ([`resolve_groups`]). Public input is never taken.
    pub from_private: bool,
}

impl Act {
    /// The state a row must be in to move.
    #[must_use]
    pub fn from_state(&self) -> Tenancy {
        Tenancy {
            owner: self.source,
            visibility: if self.from_private { GROUP } else { PUBLIC }.into(),
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

    /// `('group', source)`: the source's private state. In place it IS the TO
    /// state. In a move, `--catch-up` takes a generation in it beside
    /// generations already in TO. The workflow ingest gives an undeclared new
    /// generation of a group lineage its head's group (the ingest executor's
    /// generation-inheritance rule), so after a move a re-ingest lands in TO;
    /// a generation lands here only when its ingest declares the source group.
    #[must_use]
    pub fn source_private(&self) -> Tenancy {
        Tenancy {
            owner: self.source,
            visibility: GROUP.into(),
            co_owner: None,
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
        if self.from_private {
            return "PRIVATE-MOVE";
        }
        match (self.in_place(), self.visibility, self.catch_up) {
            (true, _, false) => "NARROW-IN-PLACE",
            (true, _, true) => "CATCH-UP-NARROW-IN-PLACE",
            (false, Visibility::Keep, _) => "MOVE",
            (false, Visibility::Group, false) => "MOVE-AND-NARROW",
            (false, Visibility::Group, true) => "CATCH-UP-MOVE-AND-NARROW",
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
    /// `--catch-up` (see [`Act::catch_up`]); needs `--visibility group`.
    pub catch_up: bool,
    /// `--from-visibility group` (see [`Act::from_private`]); needs
    /// `--visibility group`, never `--catch-up`.
    pub from_private: bool,
    /// `--after-manifest` (`--catch-up` only): the manifests of the acts a
    /// catch-up follows. A move's catch-up takes a lineage only when one of
    /// its TO generations is a row one of them moved into the TO state; in
    /// place they are checked but not needed.
    pub after_manifests: Vec<PathBuf>,
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
    if opts.catch_up && opts.visibility != Visibility::Group {
        bail!(
            "--catch-up needs --visibility group: it catches a lineage up to a narrowing that \
             already ran"
        );
    }
    if !opts.after_manifests.is_empty() && !opts.catch_up {
        bail!("--after-manifest is for --catch-up only: it names the act a catch-up follows");
    }
    if opts.from_private {
        if opts.visibility != Visibility::Group {
            bail!(
                "--from-visibility group needs --visibility group: a private move keeps every \
                 row group-private (it ends ('group', target))"
            );
        }
        if opts.catch_up {
            bail!(
                "--from-visibility group does not take --catch-up: a private move takes a \
                 lineage whole, from ('group', source) only"
            );
        }
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
/// operator administers. A private move's target is the source, or not one
/// `regroup::check_private_target` accepts; its source is not an active team
/// or community group nor a registered human operator's own personal group
/// ([`check_private_source`]).
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
    if opts.from_private {
        // The rows are PRIVATE, so the source is held to the target's rule:
        // an active team or community group the operator administers, or the
        // operator's OWN personal group. Another person's or an operated
        // agent's personal group never gives up its private rows to a team,
        // whoever administers it; nor does an operated agent's own group when
        // the agent itself is passed as --operator (the default source).
        check_private_source(conn, source, opts.operator).await?;
        if source == opts.target {
            bail!(
                "--target-group {} is the source group: a private move moves between two groups \
                 (to narrow public lineages in place, omit --from-visibility)",
                opts.target
            );
        }
        // An active team or community group the operator administers, or the
        // operator's OWN personal group (the rule regroup-claims applies).
        super::regroup::check_private_target(conn, opts.target, opts.operator).await?;
        return Ok((source, opts.target));
    }
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

/// A private move's source (a `--from-group` already checked: not world or
/// seed, the operator a live admin; or the default, `operator_group`): an
/// ACTIVE `team` or `community` group, or the operator's own personal group
/// ([`super::regroup::own_personal_group`]: the operator a registered human).
///
/// # Errors
/// The group is missing, not active, of another kind, or a personal group
/// that is not the operator's own.
async fn check_private_source(
    conn: &mut PgConnection,
    source: Uuid,
    operator: Uuid,
) -> anyhow::Result<()> {
    let row: Option<(String, String)> =
        sqlx::query_as("SELECT kind::text, status::text FROM groups WHERE id = $1")
            .bind(source)
            .fetch_optional(&mut *conn)
            .await?;
    let Some((kind, status)) = row else {
        bail!("--from-group {source}: no such group; refusing");
    };
    if status != "active" {
        bail!("--from-group {source} has status {status:?}, not active; refusing");
    }
    match kind.as_str() {
        "team" | "community" => Ok(()),
        "personal" => {
            if super::regroup::own_personal_group(conn, operator).await? != Some(source) {
                bail!(
                    "--from-group {source} is a personal group that is not the operator's own \
                     personal group (did:epigraph:personal:{operator}, created by the operator, \
                     a registered human operator); refusing: a private move takes private rows \
                     only out of a team or community group the operator administers, or out of \
                     the operator's own personal group, never out of another person's or an \
                     operated agent's"
                );
            }
            Ok(())
        }
        other => bail!(
            "--from-group {source} is kind {other}, not a team or community group nor the \
             operator's own personal group; refusing"
        ),
    }
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
    /// (A private move only.) A public generation: public input is the public
    /// act's (`--from-visibility public`), never a private move's.
    PublicInput {
        generation: i32,
        owner: Uuid,
    },
    OwnedElsewhere {
        generation: i32,
        owner: Uuid,
    },
    NotPublic {
        generation: i32,
        visibility: String,
        /// (A move only.) A source-private generation of a lineage with a
        /// generation in the TO state: `--catch-up` takes it when an act on
        /// record moved those generations there.
        catch_up: bool,
    },
    /// `--catch-up` in a MOVE (never in place): the lineage has generations
    /// in the TO state, but no `--after-manifest` moved any of them there
    /// (the target may own it natively), so it is not a catch-up's.
    NotActed {
        target_gens: Vec<i32>,
    },
    /// Some generations are in the TO state already and some in the FROM
    /// state.
    PartlyMoved {
        source_gens: Vec<i32>,
        target_gens: Vec<i32>,
        /// The act is in place (target = source): a plain `--catch-up` takes
        /// the FROM generations, no act need be on record.
        in_place: bool,
    },
    /// Narrowing the plan would hand a row to the target that the target must
    /// not get (see [`hand_off`]). Holds every lineage joined to it, and an
    /// `--apply` exits 3.
    HandOff {
        table: String,
        id: String,
        prior: String,
        post: String,
        why: &'static str,
    },
    /// (A private move only.) A row of the plan is SEALED: its ciphertext
    /// (`seal`, keyed to the group that sealed it) does not move with the
    /// row, so the target's members would get a row they cannot decrypt and
    /// the source's would lose one they can. Holds every lineage joined to
    /// it, and an `--apply` exits 3, as a hand-off does.
    Sealed {
        /// `claim`, `evidence` or `edge`.
        what: &'static str,
        id: Uuid,
        /// The table holding the ciphertext.
        seal: &'static str,
        /// The group its key epoch belongs to.
        group: Uuid,
    },
}

impl LineageHold {
    /// A hold that leaves a plan the operator listed for narrowing public, by
    /// the narrowing's own rule: an `--apply` with one exits 3.
    #[must_use]
    pub fn is_hand_off(&self) -> bool {
        matches!(self, Self::HandOff { .. } | Self::Sealed { .. })
    }
}

/// What the operator can do with a MOVE's lineage that has generations in the
/// target state beside the source's: a catch-up takes it only when an act of
/// this tool moved those generations there; a generation the target owns
/// natively is held by design, and no act of this tool takes the lineage.
const MOVE_CATCH_UP_HINT: &str = "if an act of this tool moved the target's generations there, \
     run again with --catch-up --after-manifest <exactly that act's manifest> (plus each \
     catch-up manifest of it) to take only the other generations, recording the target's as \
     seen; if none did, the target owns them natively, and the lineage is held by design (a \
     catch-up never hands the source's rows to a group on a shared name alone): no act of \
     this tool takes it, and it stays as it is until a ruling";

impl fmt::Display for LineageHold {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => write!(f, "no workflow row has this canonical name"),
            Self::PublicInput { generation, owner } => write!(
                f,
                "generation {generation} is ({owner}, public): a private move never takes public \
                 input (narrow it first with the public act, --visibility group); the whole \
                 lineage stays"
            ),
            Self::OwnedElsewhere { generation, owner } => write!(
                f,
                "generation {generation} is owned by group {owner}, and is in neither this run's \
                 FROM state (the source's) nor its target state; the whole lineage stays"
            ),
            Self::NotPublic {
                generation,
                visibility,
                catch_up,
            } => write!(
                f,
                "generation {generation} has visibility {visibility}, not public, and is not in \
                 this run's target state; the whole lineage stays{}",
                if *catch_up {
                    // Only a move has a source-private state apart from TO.
                    format!(
                        " (the source's private generation of a lineage with generations already \
                         in this run's target state: {MOVE_CATCH_UP_HINT})"
                    )
                } else {
                    String::new()
                }
            ),
            Self::PartlyMoved {
                source_gens,
                target_gens,
                in_place,
            } => write!(
                f,
                "partly the target's already (generations {target_gens:?}) and partly the \
                 source's ({source_gens:?}); a run that moved only part of it could not be \
                 reversed exactly, so it stays ({})",
                if *in_place {
                    "in place, run again with --catch-up to narrow only the public generations, \
                     recording the others as seen"
                } else {
                    MOVE_CATCH_UP_HINT
                }
            ),
            Self::NotActed { target_gens } => write!(
                f,
                "its generations in this run's target state ({target_gens:?}) were not moved there \
                 by any --after-manifest; the whole lineage stays ({MOVE_CATCH_UP_HINT})"
            ),
            Self::HandOff {
                table,
                id,
                prior,
                post,
                why,
            } => write!(
                f,
                "{table} {id} is {prior}; narrowing this plan would make it {post}, and {why}; \
                 the whole lineage stays (an --apply exits 3)"
            ),
            Self::Sealed {
                what,
                id,
                seal,
                group,
            } => write!(
                f,
                "{what} {id} is sealed ({seal}, keyed to group {group}): a move does not re-key \
                 its ciphertext, so the target's members could not decrypt it; ciphertext never \
                 leaves the group it is keyed to, and the whole lineage stays (an --apply exits 3)"
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

impl Left {
    /// A claim a narrowing may leave public: it is another plan's too, or not
    /// the source's to narrow, or does not exist. Every other plan claim of a
    /// narrowed lineage must end non-public (the run's last check).
    fn may_stay_public(&self) -> bool {
        matches!(
            self,
            Self::NotFound | Self::Shared(_) | Self::NotSourceOwned { .. }
        )
    }
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
    /// Generations that change (the FROM state, or under `--catch-up` a stray
    /// source's private state).
    pub workflows: Vec<WfRow>,
    /// Generations already in the TO state (`--catch-up`): recorded as seen,
    /// never written.
    pub seen_workflows: Vec<WfRow>,
    /// Plan claims that move.
    pub claims: Vec<ClaimRow>,
    pub left: Vec<(Uuid, Left)>,
    pub already_claims: Vec<Uuid>,
    /// The left and already claims' rows, as seen (the manifest's "seen" set).
    pub seen_claims: Vec<ClaimRow>,
    /// Derived and fragment rows the cascade changes, and the state each ends
    /// in.
    pub rows: Snapshot,
    pub rows_post: BTreeMap<RowKey, RowState>,
    /// Rows attached to moving claims that stay as they are (writer-owned under
    /// `keep`; an outsider's challenge under `group`).
    pub kept_rows: Snapshot,
    /// Edges that change.
    pub edges: Vec<MovingEdge>,
    /// Edges touching the plans that stay, with why.
    pub edges_kept: Vec<(EdgeRow, &'static str)>,
    /// Left SHARED claims also executed by a source-owned public lineage this
    /// list omits, with that lineage: narrowed in separate runs, such a claim
    /// stays public for good.
    pub splits: Vec<(Uuid, String)>,
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
        let mut seen_wf = self.seen_workflows.clone();
        seen_wf.sort();
        let mut edges = self.edges.clone();
        edges.sort();
        let mut kept: Vec<_> = self.edges_kept.clone();
        kept.sort();
        format!(
            "{:?}",
            (
                &self.lineages,
                wf,
                seen_wf,
                claims,
                left,
                already,
                rows,
                &self.rows_post,
                edges,
                kept
            )
        )
    }

    fn claim_ids(&self) -> Vec<Uuid> {
        self.claims.iter().map(|c| c.id).collect()
    }

    /// Every generation of the component's lineages.
    fn all_workflow_ids(&self) -> Vec<Uuid> {
        self.workflows
            .iter()
            .chain(self.seen_workflows.iter())
            .map(|w| w.id)
            .collect()
    }

    /// The claims that end non-public: the ones it narrows and the ones
    /// already in the TO state.
    fn narrowed_claim_ids(&self) -> Vec<Uuid> {
        self.claims
            .iter()
            .map(|c| c.id)
            .chain(self.already_claims.iter().copied())
            .collect()
    }
}

/// The plan of a whole run.
#[derive(Debug, Default)]
pub struct Plan {
    pub held: Vec<(String, LineageHold)>,
    pub already: Vec<String>,
    /// `--catch-up`: lineages with no stray generation (the main act's).
    pub skipped: Vec<String>,
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

/// Why narrowing a row from `prior` to `post` would hand the target something
/// it must not get, or `None` when it hands nothing:
///
/// * `prior == post`: nothing changes (an edge to a row already private to the
///   target, or in place to the same group; a cascaded row already in the TO
///   state). Never blocks.
/// * `own` (`--catch-up` only): one of the stray generations' OWN rows (see
///   [`StrayScope`]) going into exactly the TO state from a private tuple only
///   the source and the target read. The operator's ruling to move the lineage
///   covers the generation that joined it late; every other row, derived rows
///   included, keeps the rules below.
/// * `post` readable by a group that cannot read `prior`: a widening.
/// * a non-public `prior` whose owner changes: the target would become the
///   OWNER (delete and re-tenant rights) of a row its owner keeps private,
///   which no ruling to narrow public plans covers. A same-owner narrowing
///   (a co-owner added) is fine.
/// * a public `prior` the database's own narrowing does not take: another
///   group's derived row that is not writer-owned (`public_taken` is true for
///   migration 114's writer-owned rows and for every public edge, which 120's
///   meet re-owns by design; the source's, the target's and world rows are
///   always taken).
///
/// A PRIVATE MOVE ([`Act::from_private`]) is the operator's act on the
/// source's private rows, so a private row OWNED by the source (or already by
/// the target) may change owner, as `regroup-claims` moves it: when `post` is
/// not public and requires every group `prior` requires, with the source
/// replaced by the target ([`moved_image`]; a co-owner `prior` requires is
/// kept). A private row a third group owns still holds, and a public `prior`
/// keeps the rules above.
fn hand_off(
    act: &Act,
    prior: &Tenancy,
    post: &Tenancy,
    public_taken: bool,
    own: bool,
) -> Option<&'static str> {
    if prior == post {
        return None;
    }
    let ours = |g: Uuid| g == act.source || g == act.target;
    if act.from_private
        && prior.visibility != PUBLIC
        && post.visibility != PUBLIC
        && ours(prior.owner)
        && restrict::reader_groups(post).is_superset(&moved_image(act, prior))
    {
        return None;
    }
    if own
        && act.catch_up
        && *post == act.to_state()
        && prior.visibility != PUBLIC
        && ours(prior.owner)
        && prior.co_owner.is_none_or(ours)
    {
        return None;
    }
    if !narrows(prior, post) {
        return Some("that would make it readable by a group that cannot read it now");
    }
    if prior.visibility != PUBLIC {
        return (post.owner != prior.owner).then_some(
            "it is private to its owner, so the target would become the owner of a row it was \
             never given",
        );
    }
    if public_taken || [act.source, act.target, WORLD].contains(&prior.owner) {
        None
    } else {
        Some(
            "it is another group's public row, which only that group's own narrowing may take \
             (not writer-owned, so the database does not hand it over)",
        )
    }
}

/// The groups a reader of `t` must belong to, with the act's source replaced
/// by its target: what a row must still require once a private move carried
/// it (`regroup-claims`' image rule).
fn moved_image(act: &Act, t: &Tenancy) -> BTreeSet<Uuid> {
    restrict::reader_groups(t)
        .into_iter()
        .map(|g| if g == act.source { act.target } else { g })
        .collect()
}

/// `--catch-up`: the stray generations' OWN rows, the only rows its hand-off
/// exemption covers ([`hand_off`]'s `own`).
///
/// * `workflows`: the generations it changes (the non-TO generations of a
///   lineage that has a generation in the TO state);
/// * `claims`: the source's private plan claims ONLY those generations reach:
///   executed by one of them, by no other generation (retracted edges count),
///   in no step lineage with a member another generation executes (the moved
///   plan reaches an evolved step through its lineage, so a private step the
///   main act left is never one of these), and not SHARED;
/// * edges: an edge touching one of those rows whose every endpoint is one of
///   them, a row of the same lineages already in the TO state, or (an
///   `AUTHORED` edge) the author agent the ingest records.
///
/// Derived rows (evidence, BBAs, fragments, ...) are never own rows: a private
/// one holds the lineage as in the main act.
#[derive(Default)]
struct StrayScope {
    workflows: BTreeSet<Uuid>,
    claims: BTreeSet<Uuid>,
    to_workflows: BTreeSet<Uuid>,
    to_claims: BTreeSet<Uuid>,
}

impl StrayScope {
    fn own(&self, (id, ty): &(Uuid, String)) -> bool {
        match ty.as_str() {
            "workflow" => self.workflows.contains(id),
            "claim" => self.claims.contains(id),
            _ => false,
        }
    }

    fn in_to(&self, (id, ty): &(Uuid, String)) -> bool {
        match ty.as_str() {
            "workflow" => self.to_workflows.contains(id),
            "claim" => self.to_claims.contains(id),
            _ => false,
        }
    }

    fn owns_edge(&self, e: &EdgeRow) -> bool {
        let ends = [&e.source, &e.target];
        ends.iter().any(|n| self.own(n))
            && ends.iter().all(|n| {
                self.own(n) || self.in_to(n) || (n.1 == "agent" && e.relationship == "AUTHORED")
            })
    }
}

/// What the narrowing classification decided.
#[derive(Default)]
struct Narrowed {
    rows: Snapshot,
    rows_post: BTreeMap<RowKey, RowState>,
    kept_rows: Snapshot,
    moving: Vec<MovingEdge>,
    kept: Vec<(EdgeRow, &'static str)>,
    /// Edges with an evidence endpoint and no plan-claim endpoint (read here).
    ev_edges: Vec<EdgeRow>,
    /// The plan nodes a hold anchors on, and the hold.
    hand_offs: Vec<(Vec<Uuid>, LineageHold)>,
}

/// The narrowing's classification of the candidates' rows and the plans'
/// edges. Decides each row's and edge's state AFTER the narrowing as the
/// database computes it, and holds (by [`hand_off`]) only what would hand the
/// target a row it must not get; everything else narrows. A candidate leaves
/// only as SHARED: a harvester fragment it shares with a claim that does not
/// end in the TO state (the cascade would narrow the fragment for both), to a
/// fixpoint, with its step lineage.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn classify_narrowing(
    conn: &mut PgConnection,
    act: &Act,
    candidates: &mut BTreeSet<Uuid>,
    left: &mut BTreeMap<Uuid, Left>,
    step_of: &BTreeMap<Uuid, Uuid>,
    step_members: &BTreeMap<Uuid, BTreeSet<Uuid>>,
    attached: &Snapshot,
    edge_rows: &[EdgeRow],
    moving_wf: &BTreeSet<Uuid>,
    inside_node: &dyn Fn(&(Uuid, String)) -> bool,
    stray: &StrayScope,
) -> anyhow::Result<Narrowed> {
    let to = act.to_state();
    let to_node: NodeState = (to.owner, to.visibility.clone());
    let mut out = Narrowed::default();

    // ---- fragments shared with a claim that does not end in TO ----
    let neighbours: Vec<Uuid> = attached
        .values()
        .filter(|a| a.table == "harvester_fragments")
        .flat_map(|a| a.neighbours.iter().copied())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let neighbours_in_to: BTreeSet<Uuid> = fetch_claims(conn, &neighbours, false)
        .await?
        .into_iter()
        .filter(|c| claim_tenancy(c) == to)
        .map(|c| c.id)
        .collect();
    loop {
        let mut drop: Vec<(Uuid, String)> = Vec::new();
        for a in attached
            .values()
            .filter(|a| a.table == "harvester_fragments")
        {
            let stays = a.claims.iter().any(|c| !candidates.contains(c))
                || a.neighbours.iter().any(|n| !neighbours_in_to.contains(n));
            if stays {
                for c in a.claims.iter().filter(|c| candidates.contains(c)) {
                    drop.push((
                        *c,
                        format!(
                            "shares harvester fragment {} with a claim this run does not narrow \
                             (the cascade would narrow it for both)",
                            a.pk
                        ),
                    ));
                }
            }
        }
        if drop.is_empty() {
            break;
        }
        for (c, why) in drop {
            if !candidates.remove(&c) {
                continue;
            }
            left.insert(c, Left::Shared(vec![why]));
            if let Some(l) = step_of.get(&c) {
                for m in step_members.get(l).into_iter().flatten() {
                    if candidates.remove(m) {
                        left.insert(
                            *m,
                            Left::Shared(vec![format!(
                                "in step lineage {l}, a member of which stays shared"
                            )]),
                        );
                    }
                }
            }
        }
    }

    // ---- the candidates' cascaded rows, as the cascade leaves them ----
    let evidence: Vec<Uuid> = attached
        .keys()
        .filter(|k| k.0 == "evidence")
        .filter_map(|k| Uuid::parse_str(&k.1).ok())
        .collect();
    let pinned = restrict::pinned_of(conn, &evidence).await?;
    for (k, a) in attached {
        let anchors: Vec<Uuid> = a
            .claims
            .iter()
            .filter(|c| candidates.contains(c))
            .copied()
            .collect();
        if anchors.is_empty() {
            continue;
        }
        let writer_owned = a.writer_owned == Some(true);
        let post = if is_outsider_challenge(&a.table, a.writer_owned) {
            // 168: the challenger's; never moved (its READ follows the claim).
            RowState::of(a)
        } else if writer_owned {
            // 114: a narrowing takes it into the claim's group, flag cleared.
            RowState {
                tenancy: to.clone(),
                writer_owned: Some(false),
            }
        } else if k.0 == "evidence" && pinned.contains(&k.1) {
            // 110: a pinned row keeps its owner and is forced to 'group'.
            RowState {
                tenancy: Tenancy {
                    owner: a.tenancy.owner,
                    visibility: GROUP.into(),
                    co_owner: None,
                },
                writer_owned: a.writer_owned,
            }
        } else {
            RowState {
                tenancy: to.clone(),
                writer_owned: a.writer_owned,
            }
        };
        if post == RowState::of(a) {
            out.kept_rows.insert(k.clone(), a.clone());
            continue;
        }
        // A private move never takes a public row (an outsider's challenge
        // is never moved, so it never reaches here).
        let public_input = act.from_private && a.tenancy.visibility == PUBLIC;
        // A derived row is never one of a stray generation's own rows.
        if let Some(why) = if public_input {
            Some(
                "it is public: a private move never takes a public row (narrow the plan first \
                 with the public act, --visibility group)",
            )
        } else {
            hand_off(act, &a.tenancy, &post.tenancy, writer_owned, false)
        } {
            out.hand_offs.push((
                anchors,
                LineageHold::HandOff {
                    table: k.0.clone(),
                    id: k.1.clone(),
                    prior: RowState::of(a).to_string(),
                    post: post.to_string(),
                    why,
                },
            ));
            continue;
        }
        out.rows.insert(k.clone(), a.clone());
        out.rows_post.insert(k.clone(), post);
    }
    // Evidence whose tuple changes: an edge on it is narrowed with it.
    let ev_post: BTreeMap<Uuid, NodeState> = out
        .rows
        .iter()
        .filter(|(k, _)| k.0 == "evidence")
        .filter_map(|(k, _)| {
            let t = &out.rows_post[k].tenancy;
            Uuid::parse_str(&k.1)
                .ok()
                .map(|id| (id, (t.owner, t.visibility.clone())))
        })
        .collect();
    let known: BTreeSet<Uuid> = edge_rows.iter().map(|e| e.id).collect();
    let ev_ids: Vec<Uuid> = ev_post.keys().copied().collect();
    out.ev_edges = fetch_edges_on_evidence(conn, &ev_ids)
        .await?
        .into_iter()
        .filter(|e| !known.contains(&e.id))
        .collect();

    // ---- edges, as the cascade (or this tool) leaves them ----
    let wf_ends: Vec<Uuid> = edge_rows
        .iter()
        .chain(out.ev_edges.iter())
        .flat_map(|e| [&e.source, &e.target])
        .filter(|(id, ty)| ty == "workflow" && !moving_wf.contains(id))
        .map(|(id, _)| *id)
        .collect();
    let wf_state = workflow_tenancy(conn, &wf_ends).await?;
    let cand_claim = |(id, ty): &(Uuid, String)| ty == "claim" && candidates.contains(id);
    let changing_node = |(id, ty): &(Uuid, String)| {
        (ty == "workflow" && moving_wf.contains(id))
            || (ty == "evidence" && ev_post.contains_key(id))
    };
    let all_edges: Vec<EdgeRow> = edge_rows
        .iter()
        .chain(out.ev_edges.iter())
        .cloned()
        .collect();
    // A private move: every endpoint of a type with its own tenancy other
    // than a workflow (a frame, context, perspective, community or reasoning
    // trace), with the tuple it ends in (its own, or a moving trace's post).
    let other_nodes = if act.from_private {
        let mut m = node_tuples(conn, &all_edges).await?;
        for ((id, _), (table, t)) in &mut m {
            if let Some(p) = out.rows_post.get(&(table.clone(), id.to_string())) {
                *t = p.tenancy.clone();
            }
        }
        m
    } else {
        BTreeMap::new()
    };
    for e in all_edges {
        if !inside_node(&e.source) && !inside_node(&e.target) {
            continue;
        }
        // The cascade re-meets every edge with a narrowing CLAIM endpoint,
        // reading a workflow (or agent, paper) endpoint as ('public', world)
        // and evidence as the cascade just left it. Any other edge with a
        // changing endpoint is this tool's to narrow, to the meet of its
        // endpoints' tuples (a workflow's own), unless it is already narrower.
        let cascade = cand_claim(&e.source) || cand_claim(&e.target);
        if !cascade && !changing_node(&e.source) && !changing_node(&e.target) {
            out.kept
                .push((e, "touches only plan rows that do not change"));
            continue;
        }
        let node = |n: &(Uuid, String), cur: &NodeState| -> NodeState {
            match n.1.as_str() {
                "claim" if candidates.contains(&n.0) => to_node.clone(),
                "evidence" => ev_post.get(&n.0).cloned().unwrap_or_else(|| cur.clone()),
                "workflow" if !cascade => {
                    if moving_wf.contains(&n.0) {
                        to_node.clone()
                    } else {
                        wf_state
                            .get(&n.0)
                            .map_or_else(|| cur.clone(), |t| (t.owner, t.visibility.clone()))
                    }
                }
                _ => cur.clone(),
            }
        };
        let m = meet(
            &node(&e.source, &e.source_state),
            &node(&e.target, &e.target_state),
        );
        let post = if cascade {
            m.unwrap_or_else(|| e.tenancy.clone())
        } else {
            narrowed(&e.tenancy, m)
        };
        if post == e.tenancy {
            out.kept.push((e, "already as narrow as its plan"));
            continue;
        }
        // The cascade meets such a node as public: an edge to a group-private
        // node that does not end in the TO state would go to the target while
        // naming a node the target's members cannot read.
        let private_node = [&e.source, &e.target].into_iter().any(|n| {
            other_nodes
                .get(n)
                .is_some_and(|(_, t)| t.visibility != PUBLIC && *t != to)
        });
        let why = if private_node {
            Some(
                "it names a group-private node (a frame, context, perspective, community or \
                 reasoning trace) that does not move with the plan, which the cascade counts as \
                 public: moved, the edge would name a node its new readers cannot read",
            )
        } else {
            hand_off(act, &e.tenancy, &post, true, stray.owns_edge(&e))
        };
        if let Some(why) = why {
            let anchors = vec![e.source.0, e.target.0];
            out.hand_offs.push((
                anchors,
                LineageHold::HandOff {
                    table: "edges".into(),
                    id: e.id.to_string(),
                    prior: tuple_text(&e.tenancy),
                    post: tuple_text(&post),
                    why,
                },
            ));
            out.kept.push((
                e,
                "narrowing it would hand it to the target; its lineage is held",
            ));
            continue;
        }
        out.moving.push(MovingEdge {
            row: e,
            post,
            explicit: !cascade,
        });
    }
    Ok(out)
}

/// Plan the listed lineages: which hold, which are done, and per component
/// what moves. `acted` (`--catch-up`): the `workflows` rows the
/// `--after-manifest`s moved into the TO state ([`acted_generations`]); read
/// only in a move (in place no act need be on record).
///
/// # Errors
/// A read fails.
#[allow(clippy::too_many_lines)]
pub async fn plan(
    conn: &mut PgConnection,
    specs: &[TableSpec],
    names: &[String],
    act: &Act,
    acted: &BTreeSet<Uuid>,
) -> anyhow::Result<Plan> {
    let (source, target) = (act.source, act.target);
    let (from, to) = (act.from_state(), act.to_state());
    let source_private = act.source_private();
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
    // A generation is FROM ('public', source), TO, or (a move) the source's
    // private state; anything else holds the lineage. Without --catch-up a
    // lineage moves only from the FROM state whole; with it, a lineage moves
    // only when it has a generation in TO (its other generations are STRAY:
    // FROM, or the source's private state), and its TO generations are seen.
    let mut eligible: BTreeMap<String, Vec<WfRow>> = BTreeMap::new();
    let mut moving_wf: BTreeSet<Uuid> = BTreeSet::new();
    for name in names {
        let Some(gens) = by_name.get(name) else {
            out.held.push((name.clone(), LineageHold::NotFound));
            continue;
        };
        let (mut from_g, mut to_g, mut priv_g) = (Vec::new(), Vec::new(), Vec::new());
        let mut other = None;
        for w in gens {
            if w.tenancy == from {
                from_g.push(w);
            } else if w.tenancy == to {
                to_g.push(w);
            } else if w.tenancy == source_private {
                priv_g.push(w);
            } else if other.is_none() {
                other = Some(w);
            }
        }
        let not_public = |w: &WfRow, catch_up: bool| LineageHold::NotPublic {
            generation: w.generation,
            visibility: w.tenancy.visibility.clone(),
            catch_up,
        };
        if let Some(w) = other {
            out.held.push((
                name.clone(),
                if act.from_private && w.tenancy.visibility == PUBLIC {
                    LineageHold::PublicInput {
                        generation: w.generation,
                        owner: w.tenancy.owner,
                    }
                } else if act.from_private || w.tenancy.visibility == PUBLIC {
                    // A private move: another group's private generation.
                    LineageHold::OwnedElsewhere {
                        generation: w.generation,
                        owner: w.tenancy.owner,
                    }
                } else {
                    not_public(w, false)
                },
            ));
            continue;
        }
        if from_g.is_empty() && priv_g.is_empty() {
            out.already.push(name.clone());
            continue;
        }
        // Stray: a generation beside generations already in TO. A lineage
        // with none in TO is the main act's (which holds or moves it whole).
        let stray = !to_g.is_empty();
        if !act.catch_up {
            if let Some(w) = priv_g.first() {
                out.held.push((name.clone(), not_public(w, stray)));
                continue;
            }
            if !to_g.is_empty() {
                out.held.push((
                    name.clone(),
                    LineageHold::PartlyMoved {
                        source_gens: from_g.iter().map(|w| w.generation).collect(),
                        target_gens: to_g.iter().map(|w| w.generation).collect(),
                        in_place: act.in_place(),
                    },
                ));
                continue;
            }
        } else if !stray {
            match priv_g.first() {
                None => out.skipped.push(name.clone()),
                Some(w) => out.held.push((name.clone(), not_public(w, false))),
            }
            continue;
        } else if !act.in_place() && !to_g.is_empty() && !to_g.iter().any(|w| acted.contains(&w.id))
        {
            // A stray lineage of a MOVE, but no act on record moved its TO
            // generations: the target may own it natively, so its source rows
            // are no catch-up's. In place TO is the source's own private
            // state, so a catch-up only narrows the source's own public rows
            // into it, and no act need be on record. Vacuous without a TO
            // generation: whether such a lineage is a catch-up's at all is
            // the stray rule's alone.
            out.held.push((
                name.clone(),
                LineageHold::NotActed {
                    target_gens: to_g.iter().map(|w| w.generation).collect(),
                },
            ));
            continue;
        }
        moving_wf.extend(from_g.iter().chain(priv_g.iter()).map(|w| w.id));
        eligible.insert(name.clone(), gens.clone());
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
    // A claim shared with a source-owned PUBLIC lineage the list omits: no
    // run of either list ever narrows it alone.
    let mut split_of: BTreeMap<Uuid, BTreeSet<String>> = BTreeMap::new();
    for r in sqlx::query(
        "SELECT e.target_id, e.source_id, w.canonical_name, w.owner_group_id, \
                w.visibility::text FROM edges e \
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
        let (o, v): (Option<Uuid>, Option<String>) = (r.get(3), r.get(4));
        let n = n.unwrap_or_default();
        add_reason(
            &mut shared,
            c,
            format!("also executed by workflow {w} ({n}), outside the listed lineages"),
        );
        // The source's lineage in this run's FROM state (public, or under a
        // private move the source's private state).
        if o == Some(source) && v.as_deref() == Some(from.visibility.as_str()) {
            split_of.entry(c).or_default().insert(n);
        }
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
    // A private move's unshared PUBLIC plan claims: public input, which holds
    // the whole lineage (moving the rest would split the plan).
    let mut public_input: Vec<Uuid> = Vec::new();
    let mut stray = StrayScope::default();
    if act.catch_up {
        stray.workflows.clone_from(&moving_wf);
        stray.to_workflows = wf_lineage
            .keys()
            .filter(|w| !moving_wf.contains(w))
            .copied()
            .collect();
        let mut executors: BTreeMap<Uuid, BTreeSet<Uuid>> = BTreeMap::new();
        for (w, c) in &exec {
            executors.entry(*c).or_default().insert(*w);
        }
        let by_other = |c: &Uuid| {
            executors
                .get(c)
                .is_some_and(|ws| ws.iter().any(|w| !moving_wf.contains(w)))
        };
        for c in executors.keys() {
            let reached_otherwise = by_other(c)
                || step_of
                    .get(c)
                    .is_some_and(|l| step_members[l].iter().any(&by_other));
            if !reached_otherwise
                && !shared.contains_key(c)
                && by_id
                    .get(c)
                    .is_some_and(|r| claim_tenancy(r) == source_private)
            {
                stray.claims.insert(*c);
            }
        }
    }
    for id in &all_claims {
        let Some(c) = by_id.get(id) else {
            left.insert(*id, Left::NotFound);
            continue;
        };
        let state = claim_tenancy(c);
        if state == to {
            already.insert(*id);
        } else if let Some(by) = shared.get(id) {
            left.insert(*id, Left::Shared(by.iter().cloned().collect()));
        } else if c.owner != source {
            left.insert(*id, Left::NotSourceOwned { owner: c.owner });
        } else if act.from_private && c.visibility == PUBLIC {
            public_input.push(*id);
        } else if c.visibility != from.visibility && !stray.claims.contains(id) {
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

    stray.to_claims.clone_from(&already);
    let cand: Vec<Uuid> = candidates.iter().copied().collect();
    let attached = fetch_attached(conn, specs, &cand).await?;
    let edge_rows = fetch_edges(conn, &all_claims, &wall).await?;
    let mut rows_out = Snapshot::new();
    let mut rows_post: BTreeMap<RowKey, RowState> = BTreeMap::new();
    let mut kept_rows_out = Snapshot::new();
    let mut moving_edges: Vec<MovingEdge> = Vec::new();
    let mut kept_edges: Vec<(EdgeRow, &'static str)> = Vec::new();
    let mut ev_edges: Vec<EdgeRow> = Vec::new();
    let mut hand_offs: Vec<(Vec<Uuid>, LineageHold)> = Vec::new();
    // Evidence of a candidate -> its claim (an edge on it belongs to that plan).
    let ev_claim: BTreeMap<Uuid, Uuid> = attached
        .iter()
        .filter(|(k, _)| k.0 == "evidence")
        .filter_map(|(k, a)| Uuid::parse_str(&k.1).ok().map(|id| (id, a.claim)))
        .collect();

    if act.narrows() {
        // A plan node (the classification narrows `candidates`, so this reads
        // the set it started from; an edge on a claim it then leaves is kept).
        let cand_before = candidates.clone();
        let inside_node = |(id, ty): &(Uuid, String)| -> bool {
            match ty.as_str() {
                "workflow" => wf_lineage.contains_key(id),
                "claim" => cand_before.contains(id) || already.contains(id),
                "evidence" => ev_claim.contains_key(id),
                _ => false,
            }
        };
        let n = classify_narrowing(
            conn,
            act,
            &mut candidates,
            &mut left,
            &step_of,
            &step_members,
            &attached,
            &edge_rows,
            &moving_wf,
            &inside_node,
            &stray,
        )
        .await?;
        rows_out = n.rows;
        rows_post = n.rows_post;
        kept_rows_out = n.kept_rows;
        moving_edges = n.moving;
        kept_edges = n.kept;
        ev_edges = n.ev_edges;
        hand_offs = n.hand_offs;
        if act.from_private {
            // Every plan claim the move started from (step members
            // included), every evidence row of one, every moving edge.
            hand_offs.extend(sealed_holds(conn, &cand, &ev_claim, &moving_edges).await?);
        }
        for id in &public_input {
            hand_offs.push((
                vec![*id],
                LineageHold::HandOff {
                    table: "claims".into(),
                    id: id.to_string(),
                    prior: tuple_text(&Tenancy {
                        owner: source,
                        visibility: PUBLIC.into(),
                        co_owner: None,
                    }),
                    post: tuple_text(&to),
                    why: "it is public: a private move never takes public input (narrow the plan \
                          first with the public act, --visibility group), and moving the rest \
                          would split the plan",
                },
            ));
        }
    } else {
        // ---- keep: cascaded rows ----
        for a in attached.values() {
            // Another writer's row (114) stays its writer's under `keep`.
            let foreign = a.writer_owned != Some(true) && (a.tenancy != from || a.shared_outside);
            if foreign {
                for c in a.claims.intersection(&candidates) {
                    left.entry(*c).or_insert_with(|| Left::ForeignRow {
                        table: a.table.clone(),
                        id: a.pk.clone(),
                        state: format!(
                            "{}{}",
                            tuple_text(&a.tenancy),
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
        // ---- keep: an edge with a non-public endpoint ----
        for e in &edge_rows {
            for (id, ty) in [&e.source, &e.target] {
                if ty == "claim" && candidates.contains(id) && !e.endpoints_public() {
                    left.entry(*id)
                        .or_insert(Left::EdgeEndpointNotPublic { edge: e.id });
                }
            }
        }
        candidates.retain(|c| !left.contains_key(c));
        // A cascaded row shared by a moving claim and one that stays (a
        // harvester fragment) would move with the first: the first stays
        // too, to a fixpoint.
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
        for (k, a) in &attached {
            if !a.claims.iter().any(|c| candidates.contains(c)) {
                continue;
            }
            if a.writer_owned == Some(true) {
                kept_rows_out.insert(k.clone(), a.clone());
            } else {
                rows_post.insert(
                    k.clone(),
                    RowState {
                        tenancy: to.clone(),
                        writer_owned: a.writer_owned,
                    },
                );
                rows_out.insert(k.clone(), a.clone());
            }
        }
        // ---- keep: edges ----
        let inside = |id: &Uuid| {
            wf_lineage.contains_key(id) || candidates.contains(id) || already.contains(id)
        };
        for e in &edge_rows {
            let (s_in, t_in) = (inside(&e.source.0), inside(&e.target.0));
            if !s_in && !t_in {
                continue;
            }
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
                    row: e.clone(),
                    post: to.clone(),
                    explicit: true,
                }),
                Some(w) => kept_edges.push((e.clone(), w)),
            }
        }
    }

    let inside = |id: &Uuid| {
        wf_lineage.contains_key(id)
            || candidates.contains(id)
            || already.contains(id)
            || ev_claim.get(id).is_some_and(|c| candidates.contains(c))
    };
    let lineage_of = |id: &Uuid| -> Option<String> {
        wf_lineage.get(id).cloned().or_else(|| {
            let c = ev_claim.get(id).unwrap_or(id);
            claim_lineages.get(c).and_then(|s| s.iter().next().cloned())
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
    // Any edge between two plan rows joins their lineages (whatever stays or
    // moves), so a batch's re-plan of its own lineages reads exactly what the
    // whole plan read.
    for e in edge_rows.iter().chain(ev_edges.iter()) {
        if let (Some(a), Some(b)) = (lineage_of(&e.source.0), lineage_of(&e.target.0)) {
            dsu.union(&a, &b);
        }
    }

    // ---- components ----
    let mut comps: BTreeMap<String, Component> = BTreeMap::new();
    for (n, gens) in &eligible {
        let root = dsu.find(n);
        let c = comps.entry(root).or_default();
        c.lineages.push(n.clone());
        for w in gens {
            if moving_wf.contains(&w.id) {
                c.workflows.push(w.clone());
            } else {
                c.seen_workflows.push(w.clone());
            }
        }
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
                if matches!(why, Left::Shared(_)) {
                    for n in split_of.get(id).into_iter().flatten() {
                        c.splits.push((*id, n.clone()));
                    }
                }
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
    for (stays, snap) in [(false, rows_out), (true, kept_rows_out)] {
        for (k, a) in snap {
            let Some(owner_claim) = a.claims.iter().find(|c| candidates.contains(c)).copied()
            else {
                continue;
            };
            if let Some(r) = root_of(&owner_claim, &mut dsu) {
                if let Some(c) = comps.get_mut(&r) {
                    if stays {
                        c.kept_rows.insert(k, a);
                    } else {
                        if let Some(p) = rows_post.get(&k) {
                            c.rows_post.insert(k.clone(), p.clone());
                        }
                        c.rows.insert(k, a);
                    }
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
    // A component a narrowing would hand a row it must not get is held whole.
    let mut held_roots: BTreeMap<String, LineageHold> = BTreeMap::new();
    for (anchors, h) in hand_offs {
        for a in anchors {
            if let Some(r) = root_of(&a, &mut dsu) {
                held_roots.entry(r).or_insert_with(|| h.clone());
            }
        }
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

/// Every edge with an EVIDENCE endpoint among `evidence` (the cascade never
/// re-meets these when the claim narrows).
async fn fetch_edges_on_evidence(
    conn: &mut PgConnection,
    evidence: &[Uuid],
) -> anyhow::Result<Vec<EdgeRow>> {
    if evidence.is_empty() {
        return Ok(Vec::new());
    }
    let rows = sqlx::query(&format!(
        "SELECT {EDGE_COLUMNS} \
           FROM edges e \
           CROSS JOIN LATERAL public.epigraph_node_tenancy(e.source_id, e.source_type) s \
           CROSS JOIN LATERAL public.epigraph_node_tenancy(e.target_id, e.target_type) t \
          WHERE (e.source_type = 'evidence' AND e.source_id = ANY($1)) \
             OR (e.target_type = 'evidence' AND e.target_id = ANY($1)) \
          ORDER BY e.id"
    ))
    .bind(evidence)
    .fetch_all(&mut *conn)
    .await
    .context("reading evidence-endpoint edges")?;
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

/// A private move's sealed rows, each a hold anchored on its plan claim (or a
/// moving edge's endpoints): a claim among `claims` with a `claim_encryption`
/// row or a sealed version (`claim_version_encryption`), an evidence row of
/// `evidence` (evidence id -> its claim) with an `evidence_encryption` row,
/// and a moving edge with an `edge_encryption` row. The ciphertext stays keyed
/// to its group whatever the row's tuple becomes (`regroup-claims` holds the
/// same claims and evidence, `Hold::Sealed`/`Hold::SealedEvidence`).
async fn sealed_holds(
    conn: &mut PgConnection,
    claims: &[Uuid],
    evidence: &BTreeMap<Uuid, Uuid>,
    edges: &[MovingEdge],
) -> anyhow::Result<Vec<(Vec<Uuid>, LineageHold)>> {
    let mut out = Vec::new();
    for (seal, sql) in [
        (
            "claim_encryption",
            "SELECT claim_id, group_id FROM claim_encryption WHERE claim_id = ANY($1)",
        ),
        (
            "claim_version_encryption",
            "SELECT DISTINCT ON (claim_id) claim_id, group_id FROM claim_version_encryption \
              WHERE claim_id = ANY($1) ORDER BY claim_id, group_id",
        ),
    ] {
        let rows: Vec<(Uuid, Uuid)> = sqlx::query_as(sql)
            .bind(claims)
            .fetch_all(&mut *conn)
            .await
            .with_context(|| format!("reading {seal}"))?;
        for (id, group) in rows {
            out.push((
                vec![id],
                LineageHold::Sealed {
                    what: "claim",
                    id,
                    seal,
                    group,
                },
            ));
        }
    }
    let ev: Vec<Uuid> = evidence.keys().copied().collect();
    let rows: Vec<(Uuid, Uuid)> = sqlx::query_as(
        "SELECT evidence_id, group_id FROM evidence_encryption WHERE evidence_id = ANY($1)",
    )
    .bind(&ev)
    .fetch_all(&mut *conn)
    .await
    .context("reading evidence_encryption")?;
    for (id, group) in rows {
        out.push((
            vec![evidence[&id]],
            LineageHold::Sealed {
                what: "evidence",
                id,
                seal: "evidence_encryption",
                group,
            },
        ));
    }
    let ends: BTreeMap<Uuid, Vec<Uuid>> = edges
        .iter()
        .map(|e| (e.row.id, vec![e.row.source.0, e.row.target.0]))
        .collect();
    let ids: Vec<Uuid> = ends.keys().copied().collect();
    let rows: Vec<(Uuid, Uuid)> =
        sqlx::query_as("SELECT edge_id, group_id FROM edge_encryption WHERE edge_id = ANY($1)")
            .bind(&ids)
            .fetch_all(&mut *conn)
            .await
            .context("reading edge_encryption")?;
    for (id, group) in rows {
        out.push((
            ends[&id].clone(),
            LineageHold::Sealed {
                what: "edge",
                id,
                seal: "edge_encryption",
                group,
            },
        ));
    }
    Ok(out)
}

/// Every endpoint of `edges` whose entity type has its own tenancy columns
/// and is not a workflow (`regroup::node_types`: a frame, context,
/// perspective, community, reasoning trace, ...): `(id, type) -> (table, its
/// own tuple)`. `epigraph_node_tenancy` answers public for these, so the
/// edges trigger's meet does not see a group-private one.
async fn node_tuples(
    conn: &mut PgConnection,
    edges: &[EdgeRow],
) -> anyhow::Result<BTreeMap<(Uuid, String), (String, Tenancy)>> {
    let nodes = super::regroup::node_types(conn).await?;
    let mut by_type: BTreeMap<String, BTreeSet<Uuid>> = BTreeMap::new();
    for e in edges {
        for (id, ty) in [&e.source, &e.target] {
            if ty != "workflow" && nodes.contains_key(ty) {
                by_type.entry(ty.clone()).or_default().insert(*id);
            }
        }
    }
    let mut out = BTreeMap::new();
    for (ty, ids) in by_type {
        let table = &nodes[&ty];
        let v: Vec<Uuid> = ids.into_iter().collect();
        let rows: Vec<(Uuid, Uuid, String)> = sqlx::query_as(&format!(
            "SELECT id, owner_group_id, visibility::text FROM public.\"{table}\" \
              WHERE id = ANY($1)"
        ))
        .bind(&v)
        .fetch_all(&mut *conn)
        .await
        .with_context(|| format!("reading the tenancy of {ty} endpoints"))?;
        for (id, owner, visibility) in rows {
            out.insert(
                (id, ty.clone()),
                (
                    table.clone(),
                    Tenancy {
                        owner,
                        visibility,
                        co_owner: None,
                    },
                ),
            );
        }
    }
    Ok(out)
}

/// The plan rows of `comps` that are PUBLIC now: every generation of their
/// lineages; every plan claim but those a narrowing may leave public
/// ([`Left::may_stay_public`]); the narrowed claims' cascaded rows (an
/// outsider's challenge excepted: migration 168 gates its read on the claim);
/// every edge on a generation, a narrowed claim or that claim's evidence.
/// After a narrowing this must be empty.
async fn still_public(
    conn: &mut PgConnection,
    specs: &[TableSpec],
    comps: &[&Component],
) -> anyhow::Result<Vec<RowKey>> {
    let mut out: BTreeSet<RowKey> = BTreeSet::new();
    let names: Vec<String> = comps.iter().flat_map(|c| c.lineages.clone()).collect();
    let wf: Vec<Uuid> = comps.iter().flat_map(|c| c.all_workflow_ids()).collect();
    for id in sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM workflows WHERE (canonical_name = ANY($1) OR id = ANY($2)) \
            AND visibility = 'public'",
    )
    .bind(&names)
    .bind(&wf)
    .fetch_all(&mut *conn)
    .await
    .context("re-reading the generations")?
    {
        out.insert(("workflows".to_string(), id.to_string()));
    }
    let narrowed: Vec<Uuid> = comps.iter().flat_map(|c| c.narrowed_claim_ids()).collect();
    let checked: Vec<Uuid> = narrowed
        .iter()
        .copied()
        .chain(
            comps
                .iter()
                .flat_map(|c| c.left.iter())
                .filter(|(_, why)| !why.may_stay_public())
                .map(|(id, _)| *id),
        )
        .collect();
    for id in sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM claims WHERE id = ANY($1) AND visibility = 'public'",
    )
    .bind(&checked)
    .fetch_all(&mut *conn)
    .await
    .context("re-reading the plan claims")?
    {
        out.insert(("claims".to_string(), id.to_string()));
    }
    let attached = fetch_attached(conn, specs, &narrowed).await?;
    for (k, a) in &attached {
        if a.tenancy.visibility == PUBLIC && !is_outsider_challenge(&k.0, a.writer_owned) {
            out.insert(k.clone());
        }
    }
    let ev: Vec<Uuid> = attached
        .keys()
        .filter(|k| k.0 == "evidence")
        .filter_map(|k| Uuid::parse_str(&k.1).ok())
        .collect();
    let mut edges = fetch_edges(conn, &narrowed, &wf).await?;
    edges.extend(fetch_edges_on_evidence(conn, &ev).await?);
    for e in edges {
        if e.tenancy.visibility == PUBLIC {
            out.insert(("edges".to_string(), e.id.to_string()));
        }
    }
    Ok(out.into_iter().collect())
}

/// `behavioral_executions` rows about `comps`' plans: a run of one of their
/// generations or of a narrowed claim (a flat workflow), or one recorded
/// against a narrowed step. The table has no tenancy columns and no row
/// security, so a narrowing cannot hide them.
async fn behavioral_rows(conn: &mut PgConnection, comps: &[&Component]) -> anyhow::Result<i64> {
    let claims: Vec<Uuid> = comps.iter().flat_map(|c| c.narrowed_claim_ids()).collect();
    let ids: Vec<Uuid> = comps
        .iter()
        .flat_map(|c| c.all_workflow_ids())
        .chain(claims.iter().copied())
        .collect();
    let exists: bool =
        sqlx::query_scalar("SELECT to_regclass('public.behavioral_executions') IS NOT NULL")
            .fetch_one(&mut *conn)
            .await?;
    if !exists {
        return Ok(0);
    }
    sqlx::query_scalar(
        "SELECT count(*) FROM behavioral_executions \
          WHERE workflow_id = ANY($1) OR step_claim_id = ANY($2)",
    )
    .bind(&ids)
    .bind(&claims)
    .fetch_one(&mut *conn)
    .await
    .context("counting behavioral_executions")
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

/// The `workflows` and `edges` keys an `epigraph_app` session whose read set
/// is exactly `groups` (empty: UNSTAMPED) reads among `wf` and `edges` (the
/// claims and cascaded rows go through `tables::app_readable_as`).
async fn app_readable_wf_edges(
    conn: &mut PgConnection,
    wf: &[Uuid],
    edges: &[Uuid],
    groups: &[Uuid],
) -> anyhow::Result<BTreeSet<RowKey>> {
    let read_set = groups
        .iter()
        .map(Uuid::to_string)
        .collect::<Vec<_>>()
        .join(",");
    sqlx::query("SET LOCAL SESSION AUTHORIZATION epigraph_app")
        .execute(&mut *conn)
        .await
        .context("SET LOCAL SESSION AUTHORIZATION epigraph_app was refused")?;
    let inner = async {
        sqlx::query(
            "SELECT set_config('epigraph.group_ids', $1, true), \
                    set_config('epigraph.writable_group_ids', '', true), \
                    set_config('epigraph.principal_id', '', true), \
                    set_config('epigraph.elevation_id', '', true), \
                    set_config('epigraph.family_id', '', true)",
        )
        .bind(&read_set)
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
    readable_as(conn, specs, claims, keys, wf, edges, &[]).await
}

/// Every key an application session whose read set is exactly `groups`
/// reads among these rows (empty `groups`: the unstamped session).
async fn readable_as(
    conn: &mut PgConnection,
    specs: &[TableSpec],
    claims: &[Uuid],
    keys: &BTreeSet<RowKey>,
    wf: &[Uuid],
    edges: &[Uuid],
    groups: &[Uuid],
) -> anyhow::Result<BTreeSet<RowKey>> {
    let mut out = tables::app_readable_as(conn, specs, claims, keys, groups).await?;
    out.extend(app_readable_wf_edges(conn, wf, edges, groups).await?);
    Ok(out)
}

/// A private move's view check: for each of the source and the target, the
/// keys among `model` (key -> tuple) a reader of ONLY that group reads, by
/// the tenancy model (a public row, or one whose owner and co-owner are both
/// that group), must be exactly the keys `db` says such a session reads. A
/// challenge is left out (migration 168 gates an outsider's on its claim), and
/// so is every table whose row security is not enforced.
fn view_violations(
    when: &str,
    views: &[(Uuid, BTreeSet<RowKey>)],
    model: &BTreeMap<RowKey, Tenancy>,
    unenforced: &BTreeMap<String, Vec<String>>,
) -> Vec<String> {
    let mut v = Vec::new();
    let checked = |k: &RowKey| k.0 != "challenges" && !unenforced.contains_key(&k.0);
    for (g, db) in views {
        let read: BTreeSet<Uuid> = std::iter::once(*g).collect();
        let want: BTreeSet<&RowKey> = model
            .iter()
            .filter(|(k, t)| {
                checked(k)
                    && (t.visibility == PUBLIC || restrict::reader_groups(t).is_subset(&read))
            })
            .map(|(k, _)| k)
            .collect();
        let got: BTreeSet<&RowKey> = db.iter().filter(|k| checked(k)).collect();
        for k in want.difference(&got) {
            v.push(format!(
                "{when}: a reader of only group {g} cannot read {} {}, which the tenancy model \
                 says it reads",
                k.0, k.1
            ));
        }
        for k in got.difference(&want) {
            v.push(format!(
                "{when}: a reader of only group {g} reads {} {}, which the tenancy model says it \
                 cannot",
                k.0, k.1
            ));
        }
    }
    v
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
    for (wfs, seen) in [(&c.workflows, false), (&c.seen_workflows, true)] {
        for w in wfs {
            let id = json!(w.id.to_string());
            out.push(rec(
                "workflows",
                id,
                &w.tenancy,
                w.id,
                false,
                false,
                None,
                seen,
            ));
        }
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
    /// `--catch-up`: the rows the `--after-manifest`s moved into TO.
    pub acted: &'a BTreeSet<Uuid>,
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
    /// Under a narrowing: plan rows of these components still public after
    /// the writes (the run's last check; must be empty).
    pub left_public: Vec<RowKey>,
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
    if act.from_private {
        // A seal inserted now would take FOR KEY SHARE on its row: the claims
        // (and moving edges, below) are locked FOR UPDATE already, and an
        // UPDATE's own lock does not block it, so the evidence rows are
        // locked FOR UPDATE too. The re-plan below then reads every seal that
        // landed since the dry plan, and holds its lineage.
        sqlx::query("SELECT id FROM evidence WHERE claim_id = ANY($1) ORDER BY id FOR UPDATE")
            .bind(&lock_claims)
            .fetch_all(&mut *conn)
            .await?;
    }
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
    let now = plan(conn, ctx.specs, &names, &act, ctx.acted).await?;
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
    let rows_post: BTreeMap<RowKey, RowState> = comps
        .iter()
        .flat_map(|c| c.rows_post.iter().map(|(k, p)| (k.clone(), p.clone())))
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
    // A private move: the unstamped view reads none of these private rows, so
    // it cannot see the move; a reader of only the source and one of only the
    // target can, and must read exactly what the tenancy model says, before
    // (proving the model) and after (proving the move).
    let view_groups: Vec<Uuid> = if act.from_private {
        vec![act.source, act.target]
    } else {
        Vec::new()
    };
    let mut views_before = Vec::new();
    for g in &view_groups {
        views_before.push((
            *g,
            readable_as(
                conn,
                ctx.specs,
                &claim_ids,
                &keys,
                &wf_ids,
                &all_edge_ids,
                &[*g],
            )
            .await?,
        ));
    }
    let epoch_before = atlas_epoch(conn).await?;
    let bump_due = tables::layout_epoch_bump_due(conn).await?;
    let counters_before = xact_counters(conn).await?;

    // Each row compare-and-swapped on the prior the plan read (the FROM state,
    // or under --catch-up the source's private state).
    let wf_payload: Vec<Value> = comps
        .iter()
        .flat_map(|c| c.workflows.iter())
        .map(|w| json!({"id": w.id, "po": w.tenancy.owner, "pv": w.tenancy.visibility}))
        .collect();
    let n_wf = sqlx::query(
        "UPDATE workflows w SET owner_group_id = $2, visibility = $3 \
           FROM jsonb_to_recordset($1::jsonb) AS m(id uuid, po uuid, pv text) \
          WHERE w.id = m.id AND w.owner_group_id = m.po AND w.visibility::text = m.pv",
    )
    .bind(Value::Array(wf_payload))
    .bind(act.target)
    .bind(act.to_vis())
    .execute(&mut *conn)
    .await
    .context("UPDATE workflows")?
    .rows_affected();
    let claim_payload: Vec<Value> = comps
        .iter()
        .flat_map(|c| c.claims.iter())
        .map(|c| json!({"id": c.id, "po": c.owner, "pv": c.visibility}))
        .collect();
    let n_claims = sqlx::query(
        "UPDATE claims c SET owner_group_id = $2, visibility = $3 \
           FROM jsonb_to_recordset($1::jsonb) AS m(id uuid, po uuid, pv text) \
          WHERE c.id = m.id AND c.owner_group_id = m.po AND c.visibility::text = m.pv",
    )
    .bind(Value::Array(claim_payload))
    .bind(act.target)
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
    let mut views_after = Vec::new();
    for g in &view_groups {
        views_after.push((
            *g,
            readable_as(
                conn,
                ctx.specs,
                &claim_ids,
                &keys,
                &wf_ids,
                &all_edge_ids,
                &[*g],
            )
            .await?,
        ));
    }

    // ---- invariants ----
    let mut v = Vec::new();
    if act.from_private {
        let mut model_before: BTreeMap<RowKey, Tenancy> = BTreeMap::new();
        let mut model_after: BTreeMap<RowKey, Tenancy> = BTreeMap::new();
        for w in comps.iter().flat_map(|c| c.workflows.iter()) {
            let k = ("workflows".to_string(), w.id.to_string());
            model_before.insert(k.clone(), w.tenancy.clone());
            model_after.insert(k, to.clone());
        }
        for c in comps.iter().flat_map(|c| c.claims.iter()) {
            let k = ("claims".to_string(), c.id.to_string());
            model_before.insert(k.clone(), claim_tenancy(c));
            model_after.insert(k, to.clone());
        }
        for (k, a) in &rows {
            model_before.insert(k.clone(), a.tenancy.clone());
            if let Some(p) = rows_post.get(k) {
                model_after.insert(k.clone(), p.tenancy.clone());
            }
        }
        for (k, a) in &kept_rows {
            model_before.insert(k.clone(), a.tenancy.clone());
            model_after.insert(k.clone(), a.tenancy.clone());
        }
        for e in &moving {
            let k = ("edges".to_string(), e.row.id.to_string());
            model_before.insert(k.clone(), e.row.tenancy.clone());
            model_after.insert(k, e.post.clone());
        }
        for e in &kept_edges {
            let k = ("edges".to_string(), e.id.to_string());
            model_before.insert(k.clone(), e.tenancy.clone());
            model_after.insert(k, e.tenancy.clone());
        }
        v.extend(view_violations(
            "before the move",
            &views_before,
            &model_before,
            ctx.unenforced,
        ));
        v.extend(view_violations(
            "after the move",
            &views_after,
            &model_after,
            ctx.unenforced,
        ));
    }
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
        // The state the plan predicted the cascade leaves it in (a
        // writer-owned row a narrowing takes loses its flag, 114; pinned
        // evidence keeps its owner, 110).
        let Some(want) = rows_post.get(k) else {
            v.push(format!("{} {} has no planned post state", k.0, k.1));
            continue;
        };
        match attached_after.get(k) {
            Some(b) if RowState::of(b) == *want => {
                *rows_moved.entry(k.0.clone()).or_default() += 1;
            }
            other => v.push(format!(
                "{} {} ended as {:?}, the plan says {want}",
                k.0,
                k.1,
                other.map(RowState::of)
            )),
        }
        if a.tenancy.visibility == PUBLIC && want.tenancy.visibility != PUBLIC {
            expect_lost.insert(k.clone());
        }
    }
    for (k, a) in &kept_rows {
        if attached_after.get(k).map(RowState::of) != Some(RowState::of(a)) {
            v.push(format!("{} {} changed; it must stay as it is", k.0, k.1));
        }
        // 168: an outsider's challenge is readable only with its claim.
        if act.narrows()
            && is_outsider_challenge(&k.0, a.writer_owned)
            && a.tenancy.visibility == PUBLIC
        {
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
    // A row that was public and ends non-public; a stray generation's own
    // private row a catch-up re-owns was never readable to an unstamped
    // session.
    let public_claims: Vec<Uuid> = comps
        .iter()
        .flat_map(|c| c.claims.iter())
        .filter(|c| c.visibility == PUBLIC)
        .map(|c| c.id)
        .collect();
    if act.narrows() {
        for id in &public_claims {
            expect_lost.insert(("claims".to_string(), id.to_string()));
        }
        for w in comps.iter().flat_map(|c| c.workflows.iter()) {
            if w.tenancy.visibility == PUBLIC {
                expect_lost.insert(("workflows".to_string(), w.id.to_string()));
            }
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
    let bump = act.narrows() && bump_due && (!public_claims.is_empty() || narrowed_edge);
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
    // The run's last check: no plan row of a narrowed lineage stays public.
    if act.narrows() {
        let committed: Vec<&Component> = comps.iter().collect();
        out.left_public = still_public(conn, ctx.specs, &committed).await?;
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
        let p = &rows_post[k];
        post.push(rec(
            &k.0,
            spec_of(ctx.specs, &k.0).id_json(&k.1),
            &p.tenancy,
            a.claim,
            true,
            false,
            p.writer_owned,
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
    /// Lineages held because narrowing them would hand the target a row it
    /// must not get ([`LineageHold::HandOff`]).
    pub held_hand_off: Vec<String>,
    /// Plan rows of narrowed lineages still public after the writes.
    pub left_public: Vec<RowKey>,
    /// `behavioral_executions` rows about the narrowed plans (no tenancy).
    pub behavioral_rows: i64,
}

/// The process exit code of a run: 2 when a batch was rolled back; 3 when an
/// `--apply` held a component under lock, moved a different number of
/// workflow rows than the operator confirmed, held a lineage on a hand-off, or
/// left a plan row of a narrowed lineage public (a shortfall must not pass as
/// success); else 0. A lineage the plan holds for its state (`NotPublic`,
/// `OwnedElsewhere`, `PartlyMoved`, a move's `NotActed`) is reported and exits 0: the
/// dry run excluded it from the confirmed count, and it is not this act's.
#[must_use]
pub fn exit_code(report: &RunReport, opts: &Options) -> i32 {
    if !report.batch_failures.is_empty() {
        2
    } else if opts.apply
        && (!report.held_under_lock.is_empty()
            || Some(report.workflows_moved) != opts.confirm_count
            || !report.held_hand_off.is_empty()
            || !report.left_public.is_empty())
    {
        3
    } else {
        0
    }
}

fn print_plan(out: &mut dyn std::io::Write, p: &Plan, act: &Act) -> anyhow::Result<usize> {
    for (n, h) in &p.held {
        writeln!(out, "HELD-LINEAGE\t{n}\t{h}")?;
    }
    for n in &p.already {
        writeln!(
            out,
            "ALREADY-LINEAGE\t{n}\tevery generation is in this run's target state"
        )?;
    }
    for n in &p.skipped {
        writeln!(
            out,
            "SKIPPED-LINEAGE\t{n}\tno stray generation: every generation is in the FROM state, \
             so it is the main act's (run without --catch-up)"
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
        for (id, other) in &c.splits {
            if act.from_private {
                writeln!(
                    out,
                    "SHARED-SPLIT\t{id}\t{other}\talso executed by the source's private lineage \
                     {other}, which this list omits: moved in separate runs it never moves and \
                     stays in the source; list both lineages in one run, or rule on it"
                )?;
            } else {
                writeln!(
                    out,
                    "SHARED-SPLIT\t{id}\t{other}\talso executed by the source's public lineage \
                     {other}, which this list omits: narrowed in separate runs it stays public \
                     for good; list both lineages in one run, or rule on it"
                )?;
            }
        }
        if act.from_private {
            for e in c.edges.iter().filter(|e| e.post.co_owner.is_some()) {
                writeln!(
                    out,
                    "CO-OWNED-EDGE\t{}\t{} {} -[{}]-> {} {}\t{} -> {}\tits other end stays in \
                     its group: only a member of both groups reads it",
                    e.row.id,
                    e.row.source.1,
                    e.row.source.0,
                    e.row.relationship,
                    e.row.target.1,
                    e.row.target.0,
                    tuple_text(&e.row.tenancy),
                    tuple_text(&e.post)
                )?;
            }
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
        catch_up: opts.catch_up,
        from_private: opts.from_private,
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

    let mut acted = BTreeSet::new();
    let mut after_lines = Vec::new();
    for path in &opts.after_manifests {
        let ids = acted_generations(path, &act)?;
        after_lines.push(format!(
            "AFTER-MANIFEST\t{}\t{} workflow row(s) it moved into this run's target state",
            path.display(),
            ids.len()
        ));
        acted.extend(ids);
    }
    let p = plan(conn, &specs, names, &act, &acted).await?;
    writeln!(
        out,
        "reown-workflows: operator={} source_group={source} target_group={target} act={} \
         visibility={} mode={}",
        opts.operator,
        act.name(),
        act.visibility.as_str(),
        if opts.apply { "APPLY" } else { "DRY-RUN" }
    )?;
    for l in &after_lines {
        writeln!(out, "{l}")?;
    }
    writeln!(
        out,
        "PLAN: {} lineage(s) listed, {} held, {} already in the target state, {} component(s) \
         to move",
        names.len(),
        p.held.len(),
        p.already.len(),
        p.components.len()
    )?;
    let eligible = print_plan(out, &p, &act)?;
    report.eligible_workflow_rows = eligible;
    report.held_hand_off = p
        .held
        .iter()
        .filter(|(_, h)| h.is_hand_off())
        .map(|(n, _)| n.clone())
        .collect();
    if act.narrows() {
        // behavioral_executions has no tenancy: report, never claim to hide.
        for c in &p.components {
            let n = behavioral_rows(conn, &[c]).await?;
            if n > 0 {
                writeln!(
                    out,
                    "BEHAVIORAL-EXECUTIONS\t{n}\t{}\trow(s) stay publicly readable (no RLS)",
                    c.lineages.join(",")
                )?;
            }
        }
        let all: Vec<&Component> = p.components.iter().collect();
        report.behavioral_rows = behavioral_rows(conn, &all).await?;
        writeln!(
            out,
            "BEHAVIORAL-EXECUTIONS-TOTAL\t{}\trow(s) recording runs of these plans (goal text, \
             goal embedding, step beliefs, tool pattern) stay readable to every application \
             session: behavioral_executions has no tenancy columns and no row security, so this \
             narrowing cannot hide them",
            report.behavioral_rows
        )?;
    }
    if act.narrows() {
        if act.from_private {
            writeln!(
                out,
                "RULE: a PRIVATE MOVE: only ('group', source) generations and plan claims change, \
                 each ends ('group', target), whole lineages only; a public generation or unshared \
                 public plan claim holds its lineage (public input is the public act's), and so does \
                 a public derived row; the claims move through the tenancy cascade (derived rows, \
                 fragments, every edge with a claim endpoint); an edge with no moving claim endpoint \
                 (a workflow's, or one on a moving step's evidence) is written by this tool to the \
                 meet of its endpoints; an edge to a plan claim that stays (SHARED, or another \
                 group's) is co-owned by both groups (CO-OWNED-EDGE); a row the move would hand to \
                 the target that the source does not own (a third group's private row), a widening, \
                 an edge to a group-private node that does not move, or a SEALED claim, claim \
                 version, evidence row or edge (its ciphertext stays keyed to its group), holds its \
                 whole lineage, and an --apply then exits 3; writer_group_id is not rewritten; every batch checks what \
                 a reader of only the source and of only the target reads, before and after"
            )?;
        } else {
            writeln!(
                out,
                "RULE: only ('public', source) generations and plan claims change (with --catch-up \
                 also a stray generation's own private ones), and each ends ('group', target); the \
                 claims narrow through the tenancy cascade (derived rows, fragments, every edge with \
                 a claim endpoint; another writer's public row joins the claim's group and loses its \
                 writer_owned flag, which the manifest records; pinned evidence keeps its owner); \
                 an edge with no narrowing claim endpoint (a workflow's, or one on a narrowing \
                 step's evidence) is narrowed by this tool to the meet of its endpoints; a plan \
                 claim stays public only when SHARED or not the source's; a row the narrowing \
                 would hand to the target (a private row changing owner, a widening, another \
                 group's public row the database does not take) holds its whole lineage, and an \
                 --apply then exits 3; writer_group_id is not rewritten; the atlas epoch bumps once \
                 per batch that narrows a public row"
            )?;
        }
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
        if exit_code(&report, opts) == 3 {
            for n in &report.held_hand_off {
                writeln!(
                    out,
                    "SHORTFALL\theld\t{n}\t{} would hand the target a row it must not get (its \
                     HELD-LINEAGE line); it stays {}; exit 3",
                    if act.from_private {
                        "moving it"
                    } else {
                        "narrowing it"
                    },
                    if act.from_private {
                        "where it is"
                    } else {
                        "public"
                    }
                )?;
            }
        }
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
        "from_visibility": act.from_state().visibility,
        "catch_up": act.catch_up,
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
        "from_visibility": act.from_state().visibility,
        "catch_up": act.catch_up,
        "behavioral_executions_unhidden": report.behavioral_rows,
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
        acted: &acted,
    };
    let total = batches.len();
    let mut committed: Vec<&Component> = Vec::new();
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
                if opts.apply && wrote {
                    committed.extend(
                        batch
                            .iter()
                            .copied()
                            .filter(|c| !b.held.iter().any(|(ls, _)| *ls == c.lineages)),
                    );
                }
                for k in &b.left_public {
                    if !report.left_public.contains(k) {
                        report.left_public.push(k.clone());
                    }
                }
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
    // The run's last check, after the commits: every plan row of every
    // narrowed (non-held) lineage is non-public.
    if act.narrows() && opts.apply && !committed.is_empty() {
        for k in still_public(conn, &specs, &committed).await? {
            if !report.left_public.contains(&k) {
                report.left_public.push(k);
            }
        }
    }
    for (t, id) in &report.left_public {
        writeln!(
            out,
            "LEFT-PUBLIC\t{t}\t{id}\ta plan row of a narrowed lineage is still public"
        )?;
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
            format!(
                "all held in every batch: the rows this run narrowed became unreadable to an \
                 unstamped session, and the atlas epoch bumped once per batch that narrowed a \
                 public row. NOT covered: {} behavioral_executions row(s) about these plans, \
                 which carry no tenancy and stay readable",
                report.behavioral_rows
            )
        } else {
            "all held in every batch (visibility unchanged, atlas epoch unchanged)".to_string()
        }
    )?;
    if exit_code(&report, opts) == 3 {
        for n in &report.held_hand_off {
            writeln!(
                out,
                "SHORTFALL\theld\t{n}\t{} would hand the target a row it must not get (its \
                 HELD-LINEAGE line); it stays {}",
                if act.from_private {
                    "moving it"
                } else {
                    "narrowing it"
                },
                if act.from_private {
                    "where it is"
                } else {
                    "public"
                }
            )?;
        }
        if !report.left_public.is_empty() {
            writeln!(
                out,
                "SHORTFALL\tleft-public\t{} plan row(s) of narrowed lineages are still public \
                 (the LEFT-PUBLIC lines)",
                report.left_public.len()
            )?;
        }
        writeln!(
            out,
            "SHORTFALL: {} workflow row(s) moved, {:?} confirmed; exit 3",
            report.workflows_moved, opts.confirm_count
        )?;
    }
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

fn check_format(m: &manifest::Manifest, path: &Path) -> anyhow::Result<()> {
    if !is_reown_workflows_manifest(m) {
        bail!(
            "{}: not a reown-workflows manifest; refusing",
            path.display()
        );
    }
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
    Ok(())
}

/// `--after-manifest`: the `workflows` rows a manifest of an act on the same
/// source and target moved into exactly `act`'s TO state (a post record in
/// that state). The plan intersects them with the rows in the TO state NOW,
/// so a recorded batch that rolled back counts for nothing.
///
/// # Errors
/// The manifest cannot be read, is not a current reown-workflows manifest, or
/// records an act on another source or target.
pub fn acted_generations(path: &Path, act: &Act) -> anyhow::Result<BTreeSet<Uuid>> {
    let m = manifest::read(path)?;
    check_format(&m, path)?;
    for (key, want) in [
        ("source_group_id", act.source),
        ("target_group_id", act.target),
    ] {
        let got = header_uuid(&m, key, path)?;
        if got != want {
            bail!(
                "{}: --after-manifest records an act with {key} {got}, not this run's {want}; \
                 refusing",
                path.display()
            );
        }
    }
    let to = act.to_state();
    let mut out = BTreeSet::new();
    for r in &m.records {
        if r.table == "workflows"
            && r.after
            && r.owner_group_id == to.owner
            && r.visibility == to.visibility
        {
            let id =
                r.id.as_str()
                    .and_then(|s| Uuid::parse_str(s).ok())
                    .ok_or_else(|| anyhow!("{}: a workflows id is not a uuid", path.display()))?;
            out.insert(id);
        }
    }
    Ok(out)
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
    check_format(m, path)?;
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
        catch_up: m
            .header
            .get("catch_up")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        // Absent in a manifest written before the private move existed: the
        // public act.
        from_private: parse_from_visibility(
            m.header
                .get("from_visibility")
                .and_then(Value::as_str)
                .unwrap_or("public"),
        )?,
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
    // A member of a moved claim's step lineage that the run did not see
    // (evolve_step's successor).
    // Only a MOVED claim's lineage counts: a lineage the run left (shared with
    // another plan) is not this run's, and another team evolving it must not
    // block this reversal. A moved lineage is never shared, so growth there is
    // the moved plan's own.
    for (c, l) in sqlx::query_as::<_, (Uuid, Uuid)>(
        "SELECT c.id, c.step_lineage_id FROM claims c \
          WHERE c.step_lineage_id IN (SELECT k.step_lineage_id FROM claims k \
                                       WHERE k.id = ANY($1) AND k.step_lineage_id IS NOT NULL) \
            AND c.id <> ALL($2)",
    )
    .bind(&claim_ids)
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
    for c in sqlx::query_scalar::<_, Uuid>(
        "SELECT DISTINCT claim_id FROM claim_version_encryption WHERE claim_id = ANY($1)",
    )
    .bind(&claim_ids)
    .fetch_all(&mut *conn)
    .await?
    {
        held.push((
            c,
            format!("claim {c} has a version sealed since the run (claim_version_encryption)"),
        ));
    }
    for e in
        sqlx::query_scalar::<_, Uuid>("SELECT edge_id FROM edge_encryption WHERE edge_id = ANY($1)")
            .bind(&edge_ids)
            .fetch_all(&mut *conn)
            .await?
    {
        held.push((
            e,
            format!("edge {e} has been sealed since the run (edge_encryption)"),
        ));
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
    // A private move's reversal moves claims group to group: it widens no
    // claim, so the guard stays unarmed.
    let widens = act.narrows() && !act.from_private;
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
            catch_up: false,
            from_private: false,
            after_manifests: Vec::new(),
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
            ..o.clone()
        })
        .is_err());
        assert!(
            validate(&Options {
                catch_up: true,
                ..o.clone()
            })
            .is_err(),
            "--catch-up needs --visibility group"
        );
        assert!(
            validate(&Options {
                after_manifests: vec![PathBuf::from("a")],
                visibility: Visibility::Group,
                ..o.clone()
            })
            .is_err(),
            "--after-manifest is for --catch-up only"
        );
        assert!(validate(&Options {
            catch_up: true,
            visibility: Visibility::Group,
            after_manifests: vec![PathBuf::from("a")],
            ..o
        })
        .is_ok());
    }

    #[test]
    fn visibility_parses_keep_and_group_only() {
        assert_eq!(Visibility::parse("keep").unwrap(), Visibility::Keep);
        assert_eq!(Visibility::parse("group").unwrap(), Visibility::Group);
        assert!(Visibility::parse("public").is_err());
        assert!(Visibility::parse("").is_err());
    }

    #[test]
    fn an_apply_that_held_or_fell_short_of_the_confirmed_count_exits_3() {
        let o = Options {
            confirm_count: Some(3),
            ..opts()
        };
        let ok = RunReport {
            workflows_moved: 3,
            ..Default::default()
        };
        assert_eq!(exit_code(&ok, &o), 0);
        let short = RunReport {
            workflows_moved: 2,
            ..Default::default()
        };
        assert_eq!(exit_code(&short, &o), 3, "fewer rows than confirmed");
        let held = RunReport {
            workflows_moved: 3,
            held_under_lock: vec![(vec!["a".into()], "changed".into())],
            ..Default::default()
        };
        assert_eq!(exit_code(&held, &o), 3, "a component held under lock");
        let handed = RunReport {
            workflows_moved: 3,
            held_hand_off: vec!["alpha".into()],
            ..Default::default()
        };
        assert_eq!(exit_code(&handed, &o), 3, "a lineage held on a hand-off");
        let public = RunReport {
            workflows_moved: 3,
            left_public: vec![("claims".into(), "c".into())],
            ..Default::default()
        };
        assert_eq!(exit_code(&public, &o), 3, "a plan row left public");
        let failed = RunReport {
            batch_failures: vec![(1, "x".into())],
            ..Default::default()
        };
        assert_eq!(exit_code(&failed, &o), 2);
        // A dry run moves nothing and confirms nothing: 0.
        let dry = Options {
            apply: false,
            confirm_count: None,
            ..opts()
        };
        assert_eq!(exit_code(&RunReport::default(), &dry), 0);
    }

    #[test]
    fn the_act_names_its_states() {
        let (s, t) = (Uuid::from_u128(1), Uuid::from_u128(2));
        let mv = Act {
            source: s,
            target: t,
            visibility: Visibility::Keep,
            catch_up: false,
            from_private: false,
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
        assert_eq!(in_place.source_private(), in_place.to_state());
        let catch_up = Act {
            catch_up: true,
            ..narrow
        };
        assert_eq!(catch_up.name(), "CATCH-UP-MOVE-AND-NARROW");
    }

    fn t(owner: u128, visibility: &str, co: Option<u128>) -> Tenancy {
        Tenancy {
            owner: Uuid::from_u128(owner),
            visibility: visibility.into(),
            co_owner: co.map(Uuid::from_u128),
        }
    }

    #[test]
    fn a_hand_off_is_only_a_row_the_target_must_not_get() {
        // source 1, target 2, a third group 3.
        let act = Act {
            source: Uuid::from_u128(1),
            target: Uuid::from_u128(2),
            visibility: Visibility::Group,
            catch_up: false,
            from_private: false,
        };
        let held = |prior: Tenancy, post: Tenancy, taken: bool| {
            hand_off(&act, &prior, &post, taken, false).is_some()
        };
        // Nothing changes: never a hand-off (in place, or already the target's).
        assert!(!held(t(2, "group", None), t(2, "group", None), false));
        // The source's and world public rows, and any public edge: taken.
        assert!(!held(t(1, "public", None), t(2, "group", None), false));
        assert!(!held(t(0, "public", None), t(2, "group", None), false));
        assert!(!held(t(3, "public", None), t(2, "group", None), true));
        // A third group's public row the database does not hand over: held.
        assert!(held(t(3, "public", None), t(2, "group", None), false));
        // A private row whose owner would become the target: held.
        assert!(held(t(1, "group", None), t(2, "group", Some(1)), true));
        assert!(held(t(1, "group", None), t(2, "group", None), true));
        // A widening: held.
        assert!(held(t(3, "group", None), t(2, "group", None), true));
        // Same owner, a co-owner added: narrower, held by no one.
        assert!(!held(t(2, "group", None), t(2, "group", Some(3)), true));
        // --catch-up exempts only a stray generation's OWN row (`own`), going
        // into exactly the TO state from a tuple only source and target read.
        let cu = Act {
            catch_up: true,
            ..act
        };
        let held_own =
            |prior: Tenancy, post: Tenancy| hand_off(&cu, &prior, &post, true, true).is_some();
        assert!(hand_off(&act, &t(1, "group", None), &t(2, "group", None), true, true).is_some());
        assert!(hand_off(&cu, &t(1, "group", None), &t(2, "group", None), true, false).is_some());
        assert!(!held_own(t(1, "group", None), t(2, "group", None)));
        assert!(!held_own(t(2, "group", Some(1)), t(2, "group", None)));
        assert!(held_own(t(1, "group", None), t(2, "group", Some(1))));
        assert!(held_own(t(3, "group", None), t(2, "group", None)));
        assert!(held_own(t(1, "group", Some(3)), t(2, "group", None)));
    }

    #[test]
    fn a_private_move_takes_the_sources_private_rows_and_holds_the_rest() {
        // source 1, target 2, a third group 3.
        let act = Act {
            source: Uuid::from_u128(1),
            target: Uuid::from_u128(2),
            visibility: Visibility::Group,
            catch_up: false,
            from_private: true,
        };
        assert_eq!(act.from_state(), t(1, "group", None));
        assert_eq!(act.to_state(), t(2, "group", None));
        assert_eq!(act.name(), "PRIVATE-MOVE");
        let held = |prior: Tenancy, post: Tenancy| hand_off(&act, &prior, &post, true, false);
        // The source's private row, into the target: the act itself.
        assert!(held(t(1, "group", None), t(2, "group", None)).is_none());
        // Co-owned with a group that stays (a shared claim's edge): kept.
        assert!(held(t(1, "group", None), t(2, "group", Some(1))).is_none());
        assert!(held(t(2, "group", Some(3)), t(2, "group", Some(3))).is_none());
        assert!(held(t(1, "group", Some(3)), t(2, "group", Some(3))).is_none());
        // ...but dropping a co-owner the row requires is a widening: held.
        assert!(held(t(1, "group", Some(3)), t(2, "group", None)).is_some());
        // A third group's private row: held.
        assert!(held(t(3, "group", None), t(2, "group", None)).is_some());
        assert!(held(t(3, "group", Some(1)), t(2, "group", Some(3))).is_some());
        // Never to public.
        assert!(held(t(1, "group", None), t(2, "public", None)).is_some());
        // The public act's rule does not change: a source-private row is held
        // there.
        let public_act = Act {
            from_private: false,
            ..act
        };
        assert!(hand_off(
            &public_act,
            &t(1, "group", None),
            &t(2, "group", None),
            true,
            false
        )
        .is_some());
    }

    #[test]
    fn a_private_move_needs_group_visibility_and_no_catch_up() {
        assert!(parse_from_visibility("group").unwrap());
        assert!(!parse_from_visibility("public").unwrap());
        assert!(parse_from_visibility("private").is_err());
        let private = Options {
            from_private: true,
            visibility: Visibility::Group,
            ..opts()
        };
        validate(&private).unwrap();
        let keep = Options {
            visibility: Visibility::Keep,
            ..private.clone()
        };
        assert!(validate(&keep).is_err());
        let cu = Options {
            catch_up: true,
            ..private
        };
        assert!(validate(&cu).is_err());
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
