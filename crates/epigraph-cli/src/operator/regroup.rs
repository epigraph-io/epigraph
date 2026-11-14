//! `regroup-claims`: move an explicit list of claims that are group-private in
//! one group (`('group', SOURCE)`) to another (`('group', TARGET)`), together
//! with every row that follows ONLY those claims, keeping `group` visibility;
//! and the exact reversal of such a run (`reown-reverse` on a regroup
//! manifest).
//!
//! `restrict-claims` moves PUBLIC claims into a group; reversing an old
//! restriction and restricting again would open a public window and, on a
//! linked graph, leave rows public that shared an edge with the claims. This
//! verb moves group to group in one audited, compare-and-swap-manifested act
//! and never makes anything public.
//!
//! # What is eligible
//!
//! A listed claim that is `('group', SOURCE)` and not sealed. A claim already
//! `('group', TARGET)` counts as done, so a re-run resumes. Every other listed
//! claim is HELD with its reason: a public claim (`public-claim`: regroup never
//! touches public input; that is `restrict-claims`' job), a claim of another
//! group (`not-in-source`), a sealed claim (`sealed`: a `claim_encryption`
//! row, or a `claim_version_encryption` row on one of its versions, whose
//! version row would follow the claim; the ciphertext is keyed to the group
//! that sealed it).
//!
//! A claim is also HELD, WHOLE, when a row it carries would not follow it
//! cleanly, so a claim is never moved partially:
//!
//! * `public-row`: a public derived row, fragment or edge. The cascade would
//!   narrow it into the target; this tool does not touch public rows.
//! * `third-group`: a row owned by a group that is neither the source nor the
//!   target (another writer's row: the cascade would carry it into the target).
//! * `sealed-evidence`: evidence with an `evidence_encryption` row. Its
//!   ciphertext is keyed to the group that sealed it; moved, the row would sit
//!   in the target where no target member can decrypt it.
//! * `sealed-edge`: an edge with an `edge_encryption` row whose tuple the
//!   move would change. Its ciphertext is keyed to the group that sealed it;
//!   re-tupled, that group could lose the row while the row's new readers
//!   cannot decrypt it.
//! * `pinned`: pinned evidence (migration 110). The cascade never changes its
//!   owner, so it would stay in the source while its claim moved.
//! * `edge-would-widen`: an edge whose new meet would drop a group its current
//!   tuple requires (a declared or co-owned edge of a third group).
//! * `changed`: a row an earlier batch of this run recorded changed since.
//!
//! The pre-pass runs the same row checks, read-only, so the plan's eligible
//! count (the number `--confirm-count` repeats back) already excludes them;
//! each batch repeats them under its locks. A batch takes its claims, their
//! evidence and their edges `FOR UPDATE` before it reads the seal tables, so
//! a seal (whose foreign key onto the row would wait for the lock) either
//! committed before the read or lands after the batch commits.
//!
//! # What follows the claim
//!
//! One `UPDATE claims SET owner_group_id = TARGET` (visibility stays `group`).
//! `epigraph_propagate_tenancy` copies the new owner onto every derived row
//! (writer-owned ones too, clearing their flag, migration 114), onto the
//! harvester fragments the claim is the provenance of, and re-meets every edge
//! with the claim as an endpoint (migration 122's edges arm):
//!
//! * a derived row that is `('group', SOURCE)` becomes `('group', TARGET)`;
//! * an OUTSIDER's challenge (migration 168) is the challenger's and stays as
//!   it is (its readability follows the claim, migration 168);
//! * a fragment the claim shares with a claim that does not end in the target
//!   is a NODE: the cascade narrows it and this tool puts it back, in the same
//!   transaction, as `restrict-claims` does;
//! * an edge takes the EXACT MEET of its endpoints: the INSERT rule, applied
//!   to what each endpoint is. An edge whose other end is a claim or evidence
//!   that stays in the source becomes `('group', TARGET, co-owner SOURCE)` (or
//!   `(SOURCE, group, co-owner TARGET)` when the source end is its source),
//!   readable only by a member of both. Every such edge is reported
//!   (`CO-OWNED-EDGE` lines and a count).
//! * an edge whose other end is a NODE with its own tenancy (at head: a
//!   workflow, frame, context, perspective, community or reasoning trace;
//!   every entity type whose table has `owner_group_id` and `visibility`, read
//!   from the schema at start and printed as `NODE-TYPES`) is met with the
//!   node's OWN tuple (a reasoning trace that follows a moved claim counts as
//!   moved). An edge to such a trace is read through the trace as well as
//!   through its other end, as an evidence edge is read through the evidence:
//!   the batch that moves the trace re-meets it whichever batch moved its
//!   other end, and an edge from a claim outside the run to a moving trace
//!   takes the exact meet too (co-owned, reported as `CO-OWNED-EDGE`; a public
//!   one holds the claim, `public-row`).
//!   `epigraph_node_tenancy` (070), and so the trigger, count such a node as
//!   public (a workflow excepted since migration 219, which meets it with its
//!   own row, as this tool does): left alone, the trigger would put an edge
//!   from a source-private context on `('group', TARGET)` alone, which
//!   source-only members lose and target-only members gain while it names a
//!   node they cannot read. The
//!   tool writes the exact meet instead (co-owned with the node's group) and
//!   reports every edge to a group-private node that is not the target's
//!   (`SOURCE-NODE-EDGE` lines and a count). A public node, or one in the
//!   target, contributes nothing, so such an edge goes to the target alone.
//! * an edge with an EVIDENCE endpoint is not re-met by the trigger; this tool
//!   writes the meet itself, in the same transaction, and records it.
//!
//! The exact meet of a node edge is not what the trigger derives: a later act
//! that re-tenants the claim again (another regroup, a restriction, the
//! privatization pipeline's edge re-meet) puts it back on the tenancy-less
//! meet. The reversal of THIS act checks it (below). An edge to a
//! group-private node that is NOT in the source (a target node, which is not
//! reported, or a third group's) had a recorded tuple wider than the node
//! before the act, so the reversal holds its claim rather than write that
//! tuple back. The dry run and the apply predict that hold for every edge (its
//! first recorded prior against the meet of its endpoints with every row this
//! run moved back on its prior) and report each such edge with the claims it
//! names (`IRREVERSIBLE-EDGE` lines and a count): those claims will not be
//! reversible by this tool.
//!
//! An edge is accepted only when its new meet is at least as narrow as its
//! current tuple with the source replaced by the target; otherwise it holds
//! its claim (`edge-would-widen`).
//!
//! # Invariants checked in every batch, before its commit
//!
//! Each batch first holds `SHARE ROW EXCLUSIVE` on `edges`,
//! `harvester_fragments` and the derived tables with no key to claims
//! (`LOCKED-PER-BATCH`), so a concurrent INSERT on a moving claim either
//! commits before the batch reads its rows or is stamped after the move: no
//! edge or fragment lands on the pre-move tuple behind the batch. That blocks
//! every write to those tables on the instance while a batch runs.
//!
//! Every moved claim is `('group', TARGET)`; every recorded row ends exactly
//! where the rule above puts it and no row became public; the per-table row
//! census matches the plan (no other row of any table changed); and three
//! READABILITY checks, each by switching `session_user` to `epigraph_app`:
//! an unstamped session reads exactly what it read before; a session whose
//! read set is {SOURCE}, and one whose read set is {TARGET}, read EXACTLY the
//! rows the tenancy model predicts, before and after (the before check proves
//! the model; the after check proves the move).
//!
//! # Authorization
//!
//! On the maintenance DSN (as every verb), with `--operator` a REGISTERED
//! human operator (`epigraph_is_human_operator`) who is a live admin of BOTH
//! groups. The target must be an active `team` or `community` group, or the
//! operator's OWN personal group (the one carrying the operator's personal
//! did_key, created by the operator; never another person's, nor an operated
//! agent's: see [`check_private_target`]). The SOURCE is held to the same
//! rule ([`check_private_source`]): an active `team` or `community` group, or
//! the operator's own personal group; another person's personal group and an
//! operated agent's never give up their claims, whoever administers them.
//! Neither group may be the world or seed group; source and target differ.
//! There is no
//! other operator identity: `restrict-claims` authorizes by the target's
//! admin, and this verb adds the source's admin and the human registry.
//!
//! # Manifest, audit, reversal
//!
//! The manifest (version 2, `operation: regroup-claims`) records every row's
//! prior `(owner_group_id, visibility, co_owner_group_id on edges,
//! writer_owned)` before the batch's write, and post records before its commit,
//! as `restrict-claims` does. One `security_events` row
//! (`privatization.cli_regroup`) per `--apply` run, in the first batch that
//! changes anything. `reown-reverse --manifest` reverses it as a
//! compare-and-swap per claim: a claim is restored only while it is still in
//! the state this run left it; a recorded row that is in neither its prior nor
//! its post state (nor the meet a partial reversal leaves an edge on), a row
//! written after the act (the cascade would carry it into the source), a
//! neighbour that moved since, a claim, claim version, evidence row or edge
//! sealed since (an edge only when the reversal would change its tuple; the
//! run held every sealed edge it would have re-tupled), or an edge whose
//! recorded tuple would be WIDER than the exact meet of its endpoints after
//! the restore (an endpoint the neighbour watch does not cover moved: a
//! foreign claim's evidence, a node), HOLDS the claim. An edge is put back on
//! its recorded tuple only once every endpoint this manifest moved is back;
//! until then it carries the meet of its current endpoints. One
//! `privatization.cli_regroup_reverse` row per reversed manifest.
//!
//! # Exit codes
//!
//! 0 success; 1 refused before writing; 2 a batch violated an invariant and was
//! rolled back; 3 under `--apply`, any listed claim was held or the moved count
//! differs from `--confirm-count` (the list is not fully regrouped).

use super::manifest::{self, Record, Sink, Writer};
use super::reown::{counter_delta, counter_violations, BatchError};
use super::restrict::{
    claim_record, edge_ends, edge_ids, evidence_ids, fetch_evidence_edges, is_outsider_challenge,
    meet, narrows, operator_details, pinned_of, reader_groups, record_of, sha256_file, sha256_hex,
    spec_of, states_of, unenforced_reasons, write_audit, write_rows, EdgeEnds, RowState,
};
use super::tables::{
    self, app_readable, app_readable_as, fetch_attached, fetch_claims, xact_counters, Attached,
    ClaimRow, Kind, RowKey, Snapshot, TableSpec, Tenancy,
};
use super::{SEED, WORLD};
use anyhow::{anyhow, bail, Context};
use serde_json::{json, Value};
use sqlx::PgConnection;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// The `operation` a regroup manifest's header carries; `reown-reverse`
/// dispatches on it.
pub const OPERATION: &str = "regroup-claims";
/// `security_events.event_type` of an applied run.
pub const EVENT_APPLY: &str = "privatization.cli_regroup";
/// `security_events.event_type` of an applied reversal of one manifest.
pub const EVENT_REVERSE: &str = "privatization.cli_regroup_reverse";

const GROUP: &str = "group";
const PUBLIC: &str = "public";

/// Everything `regroup-claims` was told.
#[derive(Clone, Debug)]
pub struct Options {
    pub claims_file: PathBuf,
    pub source: Uuid,
    pub target: Uuid,
    pub operator: Uuid,
    pub manifest_out: PathBuf,
    pub apply: bool,
    pub confirm_count: Option<usize>,
    pub ruling: String,
    pub reason: String,
    pub batch_size: usize,
    pub lock_timeout: String,
    /// How many claims the dry-run sample lists row by row.
    pub sample: usize,
}

/// Refuse obviously bad options before connecting.
///
/// # Errors
/// A zero batch size; the same group twice; under `--apply`, an empty ruling
/// or reason, or no `--confirm-count`.
pub fn validate(opts: &Options) -> anyhow::Result<()> {
    if opts.batch_size == 0 {
        bail!("--batch-size must be at least 1");
    }
    if opts.source == opts.target {
        bail!(
            "--target-group {} is the source group; refusing (a regroup moves claims between \
             two groups)",
            opts.target
        );
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
                "--apply requires --confirm-count <N>: the dry run's eligible claim count, \
                 repeated back"
            );
        }
    }
    Ok(())
}

/// Why a listed claim is not moved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Hold {
    NotFound,
    PublicClaim {
        owner: Uuid,
    },
    NotInSource {
        owner: Uuid,
        visibility: String,
    },
    /// The claim is sealed: `seal` is `claim_encryption` (the claim itself)
    /// or `claim_version_encryption` (one of its versions).
    Sealed {
        seal: &'static str,
    },
    SealedEvidence {
        id: String,
    },
    /// An edge with an `edge_encryption` row whose tuple the move would
    /// change, keyed to `group`.
    SealedEdge {
        id: String,
        group: Uuid,
    },
    PublicRow {
        table: String,
        id: String,
        state: String,
    },
    ThirdGroup {
        table: String,
        id: String,
        state: String,
    },
    Pinned {
        id: String,
    },
    EdgeWouldWiden {
        id: String,
        from: String,
        to: String,
    },
    ChangedSinceRecorded {
        table: String,
        id: String,
    },
}

impl Hold {
    /// The short reason code printed on every HELD line.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotFound => "not-found",
            Self::PublicClaim { .. } => "public-claim",
            Self::NotInSource { .. } => "not-in-source",
            Self::Sealed { .. } => "sealed",
            Self::SealedEvidence { .. } => "sealed-evidence",
            Self::SealedEdge { .. } => "sealed-edge",
            Self::PublicRow { .. } => "public-row",
            Self::ThirdGroup { .. } => "third-group",
            Self::Pinned { .. } => "pinned",
            Self::EdgeWouldWiden { .. } => "edge-would-widen",
            Self::ChangedSinceRecorded { .. } => "changed",
        }
    }
}

impl fmt::Display for Hold {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => write!(f, "not found"),
            Self::PublicClaim { owner } => write!(
                f,
                "the claim is ({owner}, public); regroup never touches a public claim (that is \
                 restrict-claims)"
            ),
            Self::NotInSource { owner, visibility } => write!(
                f,
                "the claim is ({owner}, {visibility}), not ('group', source)"
            ),
            Self::Sealed { seal } => write!(
                f,
                "the claim is sealed ({seal}): its ciphertext is keyed to the group that sealed \
                 it, so the row would move where no target member can decrypt it"
            ),
            Self::SealedEvidence { id } => write!(
                f,
                "evidence {id} is sealed (evidence_encryption): its ciphertext is keyed to the \
                 source group, so the row would move where no target member can decrypt it"
            ),
            Self::SealedEdge { id, group } => write!(
                f,
                "edge {id} is sealed (edge_encryption, keyed to group {group}): the move would \
                 change its tuple, and its ciphertext never leaves the group that holds its key"
            ),
            Self::PublicRow { table, id, state } => write!(
                f,
                "{table} {id} is {state}: the cascade would narrow a public row, which regroup \
                 never touches"
            ),
            Self::ThirdGroup { table, id, state } => write!(
                f,
                "{table} {id} is {state}, owned by neither the source nor the target: the \
                 cascade would carry another group's row into the target"
            ),
            Self::Pinned { id } => write!(
                f,
                "evidence {id} is pinned (migration 110): its owner never changes, so it would \
                 stay in the source while its claim moved"
            ),
            Self::EdgeWouldWiden { id, from, to } => write!(
                f,
                "edge {id} is {from} and its new meet would be {to}, which drops a group its \
                 current tuple requires"
            ),
            Self::ChangedSinceRecorded { table, id } => write!(
                f,
                "{table} {id} changed since this run recorded it (another writer); its recorded \
                 prior would be stale"
            ),
        }
    }
}

/// The claim-level classification. `Ok(true)`: a candidate; `Ok(false)`:
/// already `('group', target)`.
fn classify_claim(c: &ClaimRow, source: Uuid, target: Uuid) -> Result<bool, Hold> {
    if c.visibility == GROUP && c.owner == target {
        return Ok(false);
    }
    if c.visibility == GROUP && c.owner == source {
        return Ok(true);
    }
    if c.visibility == PUBLIC {
        return Err(Hold::PublicClaim { owner: c.owner });
    }
    Err(Hold::NotInSource {
        owner: c.owner,
        visibility: c.visibility.clone(),
    })
}

fn tenancy(owner: Uuid) -> Tenancy {
    Tenancy {
        owner,
        visibility: GROUP.into(),
        co_owner: None,
    }
}

/// `t`'s required reader groups with `source` replaced by `target`: what the
/// row requires once the act it carries out is applied.
fn image(t: &Tenancy, source: Uuid, target: Uuid) -> BTreeSet<Uuid> {
    reader_groups(t)
        .into_iter()
        .map(|g| if g == source { target } else { g })
        .collect()
}

/// An edge may take `m`: it is not public and requires every group the
/// edge's current tuple requires, after the source-to-target swap.
fn edge_accepts(prior: &Tenancy, m: &Tenancy, source: Uuid, target: Uuid) -> bool {
    m.visibility != PUBLIC && reader_groups(m).is_superset(&image(prior, source, target))
}

/// A row with tenancy `t` is readable by a session whose read set is `groups`
/// (077's tenancy policies, 072's co-owner arm).
fn readable_by(t: &Tenancy, groups: &BTreeSet<Uuid>) -> bool {
    t.visibility == PUBLIC
        || (groups.contains(&t.owner) && t.co_owner.is_none_or(|c| groups.contains(&c)))
}

/// What a session reading `groups` can read among `claims` and `rows`, by the
/// tenancy model: a row by its own tuple, a challenge only with its claim
/// (168's `challenges_claim_readable`).
fn model_readable(
    claims: &BTreeMap<Uuid, Tenancy>,
    rows: &BTreeMap<RowKey, (Tenancy, Uuid)>,
    groups: &BTreeSet<Uuid>,
) -> BTreeSet<RowKey> {
    let mut out: BTreeSet<RowKey> = claims
        .iter()
        .filter(|(_, t)| readable_by(t, groups))
        .map(|(id, _)| ("claims".to_string(), id.to_string()))
        .collect();
    for (k, (t, claim)) in rows {
        let claim_ok =
            k.0 != "challenges" || claims.get(claim).is_some_and(|c| readable_by(c, groups));
        if readable_by(t, groups) && claim_ok {
            out.insert(k.clone());
        }
    }
    out
}

/// The edge-endpoint types, other than `claim` and `evidence`, whose backing
/// table carries its own `(owner_group_id, visibility)`: entity type -> table.
///
/// `epigraph_node_tenancy` (070) answers `('public', world)` for every type but
/// claim, evidence and (since migration 219) workflow, so the trigger's meet
/// treats such a node as public even when the row itself is group-private (a
/// frame, context, perspective or community, migration 062; a reasoning trace,
/// which follows its claim; a workflow, migration 183, until 219). A workflow
/// stays in this map: reading its own row agrees with the oracle. Read from the schema,
/// not from `entity_types.tenancy_tier` (which still says `derived` for
/// `workflow`), so a type that gains tenancy columns later is covered.
pub type NodeTypes = BTreeMap<String, String>;

fn is_plain_ident(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && s.bytes()
            .next()
            .is_some_and(|b| b.is_ascii_lowercase() || b == b'_')
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// [`NodeTypes`], read from `entity_types` and `information_schema`.
///
/// # Errors
/// The read fails, or a registered table name is not a plain identifier.
pub async fn node_types(conn: &mut PgConnection) -> anyhow::Result<NodeTypes> {
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT et.type_name::text, et.table_name::text FROM public.entity_types et \
          WHERE et.type_name NOT IN ('claim', 'evidence') \
            AND et.table_name IS NOT NULL AND et.schema_name = 'public' \
            AND EXISTS (SELECT 1 FROM information_schema.columns c \
                         WHERE c.table_schema = 'public' AND c.table_name = et.table_name \
                           AND c.column_name = 'owner_group_id') \
            AND EXISTS (SELECT 1 FROM information_schema.columns c \
                         WHERE c.table_schema = 'public' AND c.table_name = et.table_name \
                           AND c.column_name = 'visibility') \
          ORDER BY 1",
    )
    .fetch_all(&mut *conn)
    .await
    .context("reading the tenanted edge-endpoint types")?;
    for (ty, t) in &rows {
        if !is_plain_ident(t) {
            bail!("entity type {ty} names table {t:?}, which is not a plain identifier; refusing");
        }
    }
    Ok(rows.into_iter().collect())
}

/// `restrict::edge_ends`, with every endpoint of a [`NodeTypes`] type read
/// from its OWN row instead of `epigraph_node_tenancy`'s public answer: the
/// exact meet of what the two endpoints are. A node row that is gone keeps
/// the oracle's answer.
async fn ends_of(
    conn: &mut PgConnection,
    nodes: &NodeTypes,
    ids: &[Uuid],
) -> anyhow::Result<BTreeMap<String, EdgeEnds>> {
    let mut ends = edge_ends(conn, ids).await?;
    let mut by_type: BTreeMap<String, BTreeSet<Uuid>> = BTreeMap::new();
    for e in ends.values() {
        for (id, ty) in [&e.source, &e.target] {
            if nodes.contains_key(ty) {
                by_type.entry(ty.clone()).or_default().insert(*id);
            }
        }
    }
    let mut own: BTreeMap<(String, Uuid), (Uuid, String)> = BTreeMap::new();
    for (ty, idset) in by_type {
        let v: Vec<Uuid> = idset.into_iter().collect();
        let rows: Vec<(Uuid, Uuid, String)> = sqlx::query_as(&format!(
            "SELECT id, owner_group_id, visibility::text FROM public.\"{}\" WHERE id = ANY($1)",
            nodes[&ty]
        ))
        .bind(&v)
        .fetch_all(&mut *conn)
        .await
        .with_context(|| format!("reading the tenancy of {ty} endpoints"))?;
        for (id, o, vis) in rows {
            own.insert((ty.clone(), id), (o, vis));
        }
    }
    for e in ends.values_mut() {
        if let Some(st) = own.get(&(e.source.1.clone(), e.source.0)) {
            e.source_state = st.clone();
        }
        if let Some(st) = own.get(&(e.target.1.clone(), e.target.0)) {
            e.target_state = st.clone();
        }
    }
    Ok(ends)
}

/// One edge as `fetch_node_edges` reads it: id, source (id, type), target
/// (id, type), owner, visibility, co-owner, writer.
type NodeEdgeRow = (
    Uuid,
    Uuid,
    String,
    Uuid,
    String,
    Uuid,
    String,
    Option<Uuid>,
    Option<Uuid>,
);

/// Every edge with an endpoint that is a [`NodeTypes`] row in `attached` (a
/// reasoning trace that follows a candidate), as `restrict::fetch_evidence_edges`
/// reads every edge with an endpoint that is attached evidence. An edge between
/// a claim of an earlier batch and the trace of a later batch's claim is
/// reached through the claim in the earlier batch and through the trace in
/// the later one, so the later batch re-meets it (apply) and settles it
/// (reverse). An edge from a claim outside the run to a moving trace is
/// reached too: it takes the exact meet, like every other edge of a moving row.
///
/// The edge hangs off the claim of each endpoint that is an attached row
/// (node or evidence) and each endpoint that is a claim in `in_set`; a claim
/// endpoint outside `in_set` is a neighbour. Keys in `skip` (already read
/// through a claim or evidence endpoint) are left out.
///
/// # Errors
/// The read fails.
async fn fetch_node_edges(
    conn: &mut PgConnection,
    nodes: &NodeTypes,
    attached: &Snapshot,
    in_set: &BTreeSet<Uuid>,
    skip: &BTreeSet<RowKey>,
) -> anyhow::Result<Snapshot> {
    let mut out = Snapshot::new();
    let table_type: BTreeMap<&str, &str> = nodes
        .iter()
        .map(|(ty, t)| (t.as_str(), ty.as_str()))
        .collect();
    // (entity type, id) -> the claim the row follows, for every attached node
    // row and every attached evidence row.
    let mut row_claim: BTreeMap<(String, Uuid), Uuid> = BTreeMap::new();
    for (k, a) in attached {
        let ty = if k.0 == "evidence" {
            "evidence"
        } else if let Some(ty) = table_type.get(k.0.as_str()) {
            ty
        } else {
            continue;
        };
        if let Ok(id) = Uuid::parse_str(&k.1) {
            row_claim.insert((ty.to_string(), id), a.claim);
        }
    }
    let (tys, ids): (Vec<String>, Vec<Uuid>) = row_claim
        .keys()
        .filter(|(ty, _)| ty != "evidence")
        .cloned()
        .unzip();
    if ids.is_empty() {
        return Ok(out);
    }
    let sql = format!(
        "SELECT DISTINCT e.id, e.source_id, e.source_type::text, e.target_id, \
                e.target_type::text, e.owner_group_id, e.visibility::text, \
                e.co_owner_group_id, {} \
           FROM edges e \
           JOIN unnest($1::text[], $2::uuid[]) AS n(ty, id) \
             ON (e.source_type::text = n.ty AND e.source_id = n.id) \
             OR (e.target_type::text = n.ty AND e.target_id = n.id)",
        tables::EDGE_WRITER_SQL
    );
    let rows: Vec<NodeEdgeRow> = sqlx::query_as(&sql)
        .bind(&tys)
        .bind(&ids)
        .fetch_all(&mut *conn)
        .await
        .context("reading edges with a node endpoint")?;
    for (id, s_id, s_ty, t_id, t_ty, owner, visibility, co_owner, writer) in rows {
        let key = ("edges".to_string(), id.to_string());
        if skip.contains(&key) {
            continue;
        }
        let mut claims = BTreeSet::new();
        let mut neighbours = BTreeSet::new();
        for (nid, ty) in [(s_id, s_ty), (t_id, t_ty)] {
            if ty == "claim" {
                if in_set.contains(&nid) {
                    claims.insert(nid);
                } else {
                    neighbours.insert(nid);
                }
            } else if let Some(c) = row_claim.get(&(ty, nid)) {
                claims.insert(*c);
            }
        }
        let Some(claim) = claims.iter().next().copied() else {
            continue;
        };
        out.insert(
            key,
            Attached {
                table: "edges".into(),
                pk: id.to_string(),
                claim,
                claims,
                tenancy: Tenancy {
                    owner,
                    visibility,
                    co_owner,
                },
                writer,
                endpoints_public: None,
                shared_outside: false,
                neighbours,
                writer_owned: None,
                evidence_type: None,
                labels: Vec::new(),
                preview: None,
            },
        );
    }
    Ok(out)
}

/// A node `(id, type)` or a state `(owner, visibility)`.
type Pair = (Uuid, String);

/// The endpoint of `e` that is a [`NodeTypes`] node, with its own state.
fn node_end<'e>(nodes: &NodeTypes, e: &'e EdgeEnds) -> Option<(&'e Pair, &'e Pair)> {
    if nodes.contains_key(&e.source.1) {
        Some((&e.source, &e.source_state))
    } else if nodes.contains_key(&e.target.1) {
        Some((&e.target, &e.target_state))
    } else {
        None
    }
}

/// The operator's OWN personal group, when the operator is a registered human
/// operator ([`super::operator_group`]'s test: the group carrying
/// `did:epigraph:personal:<operator>` and created by the operator); `None`
/// otherwise. The one personal group a group-to-group move may name, as its
/// target here or as a private workflow move's source.
///
/// # Errors
/// The registry read fails.
pub async fn own_personal_group(
    conn: &mut PgConnection,
    operator: Uuid,
) -> anyhow::Result<Option<Uuid>> {
    let human: bool = sqlx::query_scalar("SELECT public.epigraph_is_human_operator($1)")
        .bind(operator)
        .fetch_one(&mut *conn)
        .await
        .context("reading the human-operator registry")?;
    Ok(if human {
        super::operator_group(conn, operator).await.ok()
    } else {
        None
    })
}

/// The SOURCE of a group-to-group move of private rows (`regroup-claims`, a
/// private `reown-workflows` move), checked: an ACTIVE `team` or `community`
/// group, or the operator's own personal group ([`own_personal_group`]: the
/// operator a registered human). The caller checks that the operator is a
/// live admin of it and that it is not the world or seed group; `flag` names
/// the option the source came from, for the refusal.
///
/// Another person's personal group and an operated agent's are refused
/// whoever administers them: their private rows never leave them through
/// this verb, into the operator's own group or into a team.
///
/// # Errors
/// The group is missing, not active, of another kind, or a personal group
/// that is not the operator's own.
pub async fn check_private_source(
    conn: &mut PgConnection,
    source: Uuid,
    operator: Uuid,
    flag: &str,
) -> anyhow::Result<()> {
    let row: Option<(String, String)> =
        sqlx::query_as("SELECT kind::text, status::text FROM groups WHERE id = $1")
            .bind(source)
            .fetch_optional(&mut *conn)
            .await?;
    let Some((kind, status)) = row else {
        bail!("{flag} {source}: no such group; refusing");
    };
    if status != "active" {
        bail!("{flag} {source} has status {status:?}, not active; refusing");
    }
    match kind.as_str() {
        "team" | "community" => Ok(()),
        "personal" => {
            if own_personal_group(conn, operator).await? != Some(source) {
                bail!(
                    "{flag} {source} is a personal group that is not the operator's own \
                     personal group (did:epigraph:personal:{operator}, created by the operator, \
                     a registered human operator); refusing: a group-to-group move takes \
                     private rows only out of a team or community group the operator \
                     administers, or out of the operator's own personal group, never out of \
                     another person's or an operated agent's"
                );
            }
            Ok(())
        }
        other => bail!(
            "{flag} {source} is kind {other}, not a team or community group nor the operator's \
             own personal group; refusing"
        ),
    }
}

/// The target of a group-to-group move, checked: an active group the
/// operator is a live admin of ([`super::restrict::check_target`], which also
/// refuses the world and seed groups), of kind `team` or `community`, or the
/// operator's OWN personal group. Returns its kind.
///
/// "Own" is [`super::operator_group`]'s test: the group carrying
/// `did:epigraph:personal:<operator>` and created by the operator, and the
/// operator is a registered human operator. Every other personal group is
/// refused whoever administers it: another person's, and an OPERATED agent's
/// (its own writes land there and it administers it; the ownership model
/// moves an operated agent's claims out of it into the operator's group,
/// `reown-linked`, never into it).
///
/// # Errors
/// The target is missing, world or seed, not active, not administered by the
/// operator, of another kind, or a personal group that is not the operator's
/// own.
pub async fn check_private_target(
    conn: &mut PgConnection,
    target: Uuid,
    operator: Uuid,
) -> anyhow::Result<String> {
    let kind = super::restrict::check_target(conn, target, operator).await?;
    match kind.as_str() {
        "team" | "community" => Ok(kind),
        "personal" => {
            if own_personal_group(conn, operator).await? != Some(target) {
                bail!(
                    "--target-group {target} is a personal group that is not the operator's own \
                     personal group (did:epigraph:personal:{operator}, created by the operator, \
                     a registered human operator); refusing: claims move into a team or \
                     community group, or into the operator's own personal group only"
                );
            }
            Ok(kind)
        }
        other => bail!(
            "--target-group {target} is kind {other}, not a team or community group nor the \
             operator's own personal group; refusing"
        ),
    }
}

/// The source and target groups and the operator, checked. Returns the
/// target's kind.
///
/// # Errors
/// Either group is missing, world or seed; the source is not one
/// [`check_private_source`] accepts, nor the target one
/// [`check_private_target`] accepts; the operator is not a registered human
/// operator or not a live admin of both groups.
pub async fn check_groups(
    conn: &mut PgConnection,
    source: Uuid,
    target: Uuid,
    operator: Uuid,
) -> anyhow::Result<String> {
    if source == target {
        bail!("--target-group {target} is the source group; refusing");
    }
    if source == WORLD || source == SEED {
        bail!("--source-group {source} is the world or seed group; refusing");
    }
    let src: Option<String> = sqlx::query_scalar("SELECT kind::text FROM groups WHERE id = $1")
        .bind(source)
        .fetch_optional(&mut *conn)
        .await?;
    match src.as_deref() {
        None => bail!("--source-group {source}: no such group; refusing. Nothing was written."),
        Some("world" | "seed") => bail!("--source-group {source} is world or seed; refusing"),
        Some(_) => {}
    }
    let human: bool = sqlx::query_scalar("SELECT public.epigraph_is_human_operator($1)")
        .bind(operator)
        .fetch_one(&mut *conn)
        .await
        .context("reading the human-operator registry")?;
    if !human {
        bail!(
            "--operator {operator} is not a registered human operator; refusing (a regroup is \
             a person's act)"
        );
    }
    // The rows are private on both sides: the source is held to the target's
    // rule, so another person's or an operated agent's personal group never
    // gives up its claims, whoever administers it.
    check_private_source(conn, source, operator, "--source-group").await?;
    let kind = check_private_target(conn, target, operator).await?;
    let admin: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM group_memberships \
                         WHERE group_id = $1 AND agent_id = $2 AND role = 'admin' \
                           AND revoked_at IS NULL)",
    )
    .bind(source)
    .bind(operator)
    .fetch_one(&mut *conn)
    .await?;
    if !admin {
        bail!(
            "--operator {operator} is not a live admin of --source-group {source}; refusing (a \
             regroup needs an admin of both groups)"
        );
    }
    Ok(kind)
}

/// The last state this run recorded or left each row in: a row recorded by an
/// earlier batch that another writer changed since holds its claims.
#[derive(Default, Debug)]
struct Known {
    rows: BTreeMap<RowKey, RowState>,
    /// The FIRST prior this run recorded for each row: the one
    /// `reverse::resolve` keeps, so the one a reversal writes back.
    priors: BTreeMap<RowKey, RowState>,
    /// Claims an earlier batch of this run moved (a reversal puts them back
    /// in the source).
    claims: BTreeSet<Uuid>,
}

/// Fixed inputs to every batch.
#[derive(Clone, Copy)]
struct Ctx<'a> {
    specs: &'a [TableSpec],
    /// Every table each batch locks (`batch_lock_tables`).
    unkeyed: &'a [String],
    nodes: &'a NodeTypes,
    source: Uuid,
    target: Uuid,
    lock_timeout: &'a str,
    sample: usize,
}

/// The row-level classification of a set of candidate claims.
struct Classified {
    attached: Snapshot,
    pinned: BTreeSet<String>,
    already_in_target: BTreeSet<Uuid>,
    hold: BTreeMap<Uuid, Hold>,
}

impl Classified {
    /// A fragment narrows (moves) only when every claim it is the provenance
    /// of ends in the target: one of `moving`, or one already there.
    fn fragment_moves(&self, a: &Attached, moving: &BTreeSet<Uuid>) -> bool {
        a.claims.iter().all(|c| moving.contains(c))
            && a.neighbours
                .iter()
                .all(|c| self.already_in_target.contains(c))
    }
}

/// The evidence rows among `ids` that are sealed (an `evidence_encryption`
/// row): their ciphertext is keyed to the group that sealed them.
async fn sealed_evidence_of(
    conn: &mut PgConnection,
    ids: &[Uuid],
) -> anyhow::Result<BTreeSet<String>> {
    if ids.is_empty() {
        return Ok(BTreeSet::new());
    }
    let v: Vec<Uuid> = sqlx::query_scalar(
        "SELECT evidence_id FROM evidence_encryption WHERE evidence_id = ANY($1)",
    )
    .bind(ids)
    .fetch_all(&mut *conn)
    .await
    .context("reading evidence_encryption")?;
    Ok(v.into_iter().map(|u| u.to_string()).collect())
}

/// The edges among `ids` that are sealed (an `edge_encryption` row), with the
/// group their ciphertext is keyed to.
async fn sealed_edges_of(
    conn: &mut PgConnection,
    ids: &[Uuid],
) -> anyhow::Result<BTreeMap<String, Uuid>> {
    if ids.is_empty() {
        return Ok(BTreeMap::new());
    }
    let v: Vec<(Uuid, Uuid)> =
        sqlx::query_as("SELECT edge_id, group_id FROM edge_encryption WHERE edge_id = ANY($1)")
            .bind(ids)
            .fetch_all(&mut *conn)
            .await
            .context("reading edge_encryption")?;
    Ok(v.into_iter().map(|(e, g)| (e.to_string(), g)).collect())
}

/// Take `ids` of `table` (`edges` or `evidence`) `FOR UPDATE`, in id order,
/// inside a batch. A seal's foreign key onto the row takes `FOR KEY SHARE`,
/// which neither the batch's table locks nor its later UPDATEs (`FOR NO KEY
/// UPDATE`) block; with the rows locked first, a seal either committed before
/// the batch reads the seal table or waits until the batch commits.
async fn lock_rows(conn: &mut PgConnection, table: &str, ids: &[Uuid]) -> anyhow::Result<()> {
    if ids.is_empty() {
        return Ok(());
    }
    let sql = match table {
        "edges" => "SELECT id FROM edges WHERE id = ANY($1) ORDER BY id FOR UPDATE",
        "evidence" => "SELECT id FROM evidence WHERE id = ANY($1) ORDER BY id FOR UPDATE",
        other => bail!("lock_rows: unexpected table {other}"),
    };
    sqlx::query(sql)
        .bind(ids)
        .execute(&mut *conn)
        .await
        .with_context(|| format!("locking {table} rows"))?;
    Ok(())
}

/// The claims among `ids` that are sealed, with the table that seals them: a
/// `claim_encryption` row (the claim itself), or else a
/// `claim_version_encryption` row (one of its versions; the version row
/// follows the claim, away from the group that keys its ciphertext).
/// `reown-workflows`' private move holds the same set.
async fn sealed_claims_of(
    conn: &mut PgConnection,
    ids: &[Uuid],
) -> anyhow::Result<BTreeMap<Uuid, &'static str>> {
    let mut out = BTreeMap::new();
    if ids.is_empty() {
        return Ok(out);
    }
    for (seal, sql) in [
        (
            "claim_encryption",
            "SELECT DISTINCT claim_id FROM claim_encryption WHERE claim_id = ANY($1)",
        ),
        (
            "claim_version_encryption",
            "SELECT DISTINCT claim_id FROM claim_version_encryption WHERE claim_id = ANY($1)",
        ),
    ] {
        let v: Vec<Uuid> = sqlx::query_scalar(sql)
            .bind(ids)
            .fetch_all(&mut *conn)
            .await
            .with_context(|| format!("reading {seal}"))?;
        for id in v {
            out.entry(id).or_insert(seal);
        }
    }
    Ok(out)
}

/// The tables every batch (apply and reverse) holds `SHARE ROW EXCLUSIVE` on
/// for its duration: the derived tables with no key to claims
/// (`tables::unkeyed_tables`), plus `edges` and `harvester_fragments`.
///
/// Why the last two: a concurrent INSERT of an edge (or fragment) on a moving
/// claim is stamped by its trigger from the claim as that statement reads it,
/// so one that read the claim before the batch's commit would land on the
/// pre-move (source) tuple after the commit, outside every check. The lock
/// makes such an INSERT either commit before the batch reads its rows (the
/// batch then sees and moves it) or wait until the batch commits (its trigger,
/// which reads the claim with a fresh snapshot, then sees the move). Cost: a
/// batch, dry runs included, blocks every edge and fragment write on the
/// instance while it runs; keep batches short.
fn batch_lock_tables(unkeyed: &[String]) -> Vec<String> {
    let mut out: Vec<String> = unkeyed.to_vec();
    for t in ["edges", "harvester_fragments"] {
        if !out.iter().any(|u| u == t) {
            out.push(t.to_string());
        }
    }
    out
}

/// Read every row the candidates carry and decide, per row, whether it
/// follows cleanly; a row that does not holds every candidate it hangs off.
/// `lock` (inside a batch): the evidence and edge rows are taken `FOR UPDATE`
/// before their seal tables are read ([`lock_rows`]).
async fn classify_rows(
    conn: &mut PgConnection,
    ctx: &Ctx<'_>,
    cands: &BTreeSet<Uuid>,
    known: &Known,
    lock: bool,
) -> anyhow::Result<Classified> {
    let cand_ids: Vec<Uuid> = cands.iter().copied().collect();
    let mut attached = fetch_attached(conn, ctx.specs, &cand_ids).await?;
    if lock {
        lock_rows(conn, "evidence", &evidence_ids(&attached)).await?;
    }
    let pinned = pinned_of(conn, &evidence_ids(&attached)).await?;
    let sealed_ev = sealed_evidence_of(conn, &evidence_ids(&attached)).await?;
    let ev_claim: BTreeMap<Uuid, Uuid> = attached
        .iter()
        .filter(|(k, _)| k.0 == "evidence" && !pinned.contains(&k.1))
        .filter_map(|(k, a)| Uuid::parse_str(&k.1).ok().map(|id| (id, a.claim)))
        .collect();
    let claim_edge_keys: BTreeSet<RowKey> = attached.keys().cloned().collect();
    let ev_edges = fetch_evidence_edges(conn, &ev_claim, cands, &claim_edge_keys).await?;
    attached.extend(ev_edges);
    let seen: BTreeSet<RowKey> = attached.keys().cloned().collect();
    let node_edges = fetch_node_edges(conn, ctx.nodes, &attached, cands, &seen).await?;
    attached.extend(node_edges);
    let keys: BTreeSet<RowKey> = attached.keys().cloned().collect();
    if lock {
        lock_rows(conn, "edges", &edge_ids(&keys)).await?;
    }
    let sealed_edges = sealed_edges_of(conn, &edge_ids(&keys)).await?;
    let ends = ends_of(conn, ctx.nodes, &edge_ids(&keys)).await?;
    let frag_neighbours: Vec<Uuid> = attached
        .values()
        .filter(|a| a.table == "harvester_fragments")
        .flat_map(|a| a.neighbours.iter().copied())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let already_in_target: BTreeSet<Uuid> = fetch_claims(conn, &frag_neighbours, false)
        .await?
        .into_iter()
        .filter(|c| c.owner == ctx.target && c.visibility == GROUP)
        .map(|c| c.id)
        .collect();
    let mut cl = Classified {
        attached: Snapshot::new(),
        pinned,
        already_in_target,
        hold: BTreeMap::new(),
    };
    let moves = |(id, ty): &(Uuid, String)| -> bool {
        match ty.as_str() {
            "claim" => cands.contains(id),
            "evidence" => {
                let pk = id.to_string();
                attached.contains_key(&("evidence".to_string(), pk.clone()))
                    && !cl.pinned.contains(&pk)
            }
            // A node row that follows a candidate (a reasoning trace).
            other => ctx
                .nodes
                .get(other)
                .is_some_and(|t| attached.contains_key(&(t.clone(), id.to_string()))),
        }
    };
    let in_target = (ctx.target, GROUP.to_string());
    let mut hold: BTreeMap<Uuid, Hold> = BTreeMap::new();
    for (k, a) in &attached {
        let state = RowState::of(a).to_string();
        let why = match spec_of(ctx.specs, &k.0).kind {
            Kind::Edges if a.tenancy.visibility == PUBLIC => Some(Hold::PublicRow {
                table: k.0.clone(),
                id: k.1.clone(),
                state,
            }),
            Kind::Edges => {
                let m = ends.get(&k.1).and_then(|e| {
                    let s = if moves(&e.source) {
                        in_target.clone()
                    } else {
                        e.source_state.clone()
                    };
                    let t = if moves(&e.target) {
                        in_target.clone()
                    } else {
                        e.target_state.clone()
                    };
                    meet(&s, &t)
                });
                match m {
                    // A sealed edge the move would re-tuple: its ciphertext
                    // stays keyed to its group, which would lose the row.
                    Some(m) if edge_accepts(&a.tenancy, &m, ctx.source, ctx.target) => sealed_edges
                        .get(&k.1)
                        .filter(|_| m != a.tenancy)
                        .map(|g| Hold::SealedEdge {
                            id: k.1.clone(),
                            group: *g,
                        }),
                    other => Some(Hold::EdgeWouldWiden {
                        id: k.1.clone(),
                        from: state,
                        to: other.map_or_else(
                            || "public (or its endpoints are unreadable)".to_string(),
                            |t| {
                                RowState {
                                    tenancy: t,
                                    writer_owned: None,
                                }
                                .to_string()
                            },
                        ),
                    }),
                }
            }
            _ if k.0 == "evidence" && sealed_ev.contains(&k.1) => {
                Some(Hold::SealedEvidence { id: k.1.clone() })
            }
            _ if k.0 == "evidence" && cl.pinned.contains(&k.1) => {
                Some(Hold::Pinned { id: k.1.clone() })
            }
            // Migration 168: an outsider's challenge is the challenger's; the
            // cascade leaves it, and so does this act.
            _ if is_outsider_challenge(&k.0, a.writer_owned) => None,
            Kind::Fragments if !cl.fragment_moves(a, cands) => None,
            _ if a.tenancy.visibility == PUBLIC => Some(Hold::PublicRow {
                table: k.0.clone(),
                id: k.1.clone(),
                state,
            }),
            _ if a.tenancy.co_owner.is_none()
                && (a.tenancy.owner == ctx.source || a.tenancy.owner == ctx.target) =>
            {
                None
            }
            _ => Some(Hold::ThirdGroup {
                table: k.0.clone(),
                id: k.1.clone(),
                state,
            }),
        };
        let why = why.or_else(|| {
            known
                .rows
                .get(k)
                .is_some_and(|st| *st != RowState::of(a))
                .then(|| Hold::ChangedSinceRecorded {
                    table: k.0.clone(),
                    id: k.1.clone(),
                })
        });
        if let Some(h) = why {
            for c in a.claims.intersection(cands) {
                hold.entry(*c).or_insert_with(|| h.clone());
            }
        }
    }
    cl.attached = attached;
    cl.hold = hold;
    Ok(cl)
}

/// Where each recorded row of a moving claim must end, given the endpoints'
/// states `ends` after the claims' UPDATE.
fn wanted(
    ctx: &Ctx<'_>,
    cl: &Classified,
    k: &RowKey,
    a: &Attached,
    kept_nodes: &BTreeSet<RowKey>,
    ends: &BTreeMap<String, super::restrict::EdgeEnds>,
) -> Result<RowState, String> {
    let spec = spec_of(ctx.specs, &k.0);
    let before = RowState::of(a);
    match spec.kind {
        Kind::Edges => match ends.get(&k.1) {
            None => Err(format!("edge {} has no endpoints row after the batch", k.1)),
            Some(e) => match meet(&e.source_state, &e.target_state) {
                Some(t) => Ok(RowState {
                    tenancy: t,
                    writer_owned: None,
                }),
                None => Err(format!(
                    "edge {} has two public endpoints after the batch; one of them is a moved \
                     claim or its evidence",
                    k.1
                )),
            },
        },
        _ if k.0 == "evidence" && cl.pinned.contains(&k.1) => Ok(before),
        _ if is_outsider_challenge(&k.0, a.writer_owned) => Ok(before),
        _ if kept_nodes.contains(k) => Ok(before),
        _ => Ok(RowState {
            tenancy: tenancy(ctx.target),
            writer_owned: spec.writer_owned.then_some(false),
        }),
    }
}

/// An `IRREVERSIBLE-EDGE` line and the claims it names.
pub type Irreversible = (String, BTreeSet<Uuid>);

/// What one apply batch did.
#[derive(Default, Debug)]
pub struct BatchOutcome {
    pub claims_moved: usize,
    pub moved_by_table: BTreeMap<String, usize>,
    pub held: Vec<(Uuid, Hold)>,
    pub already: usize,
    pub post_rows: BTreeMap<RowKey, RowState>,
    pub co_owned: Vec<String>,
    /// Every edge with a node end, by id, with its `SOURCE-NODE-EDGE` line
    /// (an edge to a group-private node, not the target's, that keeps
    /// requiring the node's group) or `None` when this batch leaves it with
    /// nothing to report. A later batch's verdict replaces an earlier one's:
    /// an edge to the trace of a later batch's claim is settled there.
    pub node_edges: Vec<(String, Option<String>)>,
    /// Every edge of the batch, by id, with its `IRREVERSIBLE-EDGE` line and
    /// the claims it names (its recorded prior is wider than the meet its
    /// endpoints will have after a restore, so `reown-reverse` will hold
    /// them), or `None`. A later batch's verdict replaces an earlier one's.
    pub irreversible: Vec<(String, Option<Irreversible>)>,
    /// The prior of every row this batch recorded.
    pub prior_rows: BTreeMap<RowKey, RowState>,
    /// The claims this batch moved.
    pub moved_claims: BTreeSet<Uuid>,
    pub sample: Vec<String>,
    pub audit_written: bool,
}

/// The three readability views of one batch: unstamped, {source}, {target}.
async fn three_views(
    conn: &mut PgConnection,
    ctx: &Ctx<'_>,
    claims: &[Uuid],
    keys: &BTreeSet<RowKey>,
) -> anyhow::Result<[BTreeSet<RowKey>; 3]> {
    Ok([
        app_readable(conn, ctx.specs, claims, keys).await?,
        app_readable_as(conn, ctx.specs, claims, keys, &[ctx.source]).await?,
        app_readable_as(conn, ctx.specs, claims, keys, &[ctx.target]).await?,
    ])
}

/// Compare the measured views with the model's, before and after.
#[allow(clippy::too_many_arguments)]
fn view_violations(
    ctx: &Ctx<'_>,
    when: &str,
    measured: &[BTreeSet<RowKey>; 3],
    claims: &BTreeMap<Uuid, Tenancy>,
    rows: &BTreeMap<RowKey, (Tenancy, Uuid)>,
    unstamped_expected: Option<&BTreeSet<RowKey>>,
) -> Vec<String> {
    let mut v = Vec::new();
    if let Some(u) = unstamped_expected {
        if measured[0] != *u {
            v.push(format!(
                "{when}: an unstamped epigraph_app session reads {:?}, it read {u:?} before",
                measured[0]
            ));
        }
    }
    for (i, (who, g)) in [("source", ctx.source), ("target", ctx.target)]
        .into_iter()
        .enumerate()
    {
        let groups: BTreeSet<Uuid> = std::iter::once(g).collect();
        let want = model_readable(claims, rows, &groups);
        if measured[i + 1] != want {
            v.push(format!(
                "{when}: a session reading only the {who} group reads {:?}; the tenancy model \
                 says {want:?}",
                measured[i + 1]
            ));
        }
    }
    v
}

#[allow(clippy::too_many_lines)]
async fn run_batch(
    conn: &mut PgConnection,
    ctx: &Ctx<'_>,
    batch: &[Uuid],
    sink: &mut Sink,
    known: &Known,
    audit: Option<(&Value, Uuid)>,
) -> Result<BatchOutcome, BatchError> {
    let mut out = BatchOutcome::default();
    sqlx::query("SELECT set_config('lock_timeout', $1, true)")
        .bind(ctx.lock_timeout)
        .execute(&mut *conn)
        .await?;
    let locked = fetch_claims(conn, batch, true).await?;
    tables::lock_unkeyed_tables(conn, ctx.unkeyed).await?;
    // The claims are locked FOR UPDATE above, so no seal of either kind (a
    // foreign key onto `claims`) can land on one before this batch commits.
    let sealed = sealed_claims_of(conn, batch).await?;

    let by_id: BTreeMap<Uuid, &ClaimRow> = locked.iter().map(|r| (r.id, r)).collect();
    let mut cands: BTreeSet<Uuid> = BTreeSet::new();
    for id in batch {
        let Some(c) = by_id.get(id) else {
            out.held.push((*id, Hold::NotFound));
            continue;
        };
        match classify_claim(c, ctx.source, ctx.target) {
            Ok(false) => out.already += 1,
            Ok(true) if sealed.contains_key(id) => {
                out.held.push((*id, Hold::Sealed { seal: sealed[id] }))
            }
            Ok(true) => {
                cands.insert(*id);
            }
            Err(h) => out.held.push((*id, h)),
        }
    }
    if cands.is_empty() {
        return Ok(out);
    }
    let cl = classify_rows(conn, ctx, &cands, known, true).await?;
    let eligible: Vec<ClaimRow> = cands
        .iter()
        .filter(|id| !cl.hold.contains_key(id))
        .map(|id| (*by_id[id]).clone())
        .collect();
    out.held
        .extend(cl.hold.iter().map(|(c, h)| (*c, h.clone())));
    if eligible.is_empty() {
        return Ok(out);
    }
    let claim_ids: Vec<Uuid> = eligible.iter().map(|c| c.id).collect();
    let moving: BTreeSet<Uuid> = claim_ids.iter().copied().collect();
    let s0: Snapshot = cl
        .attached
        .iter()
        .filter(|(_, a)| a.claims.iter().any(|c| moving.contains(c)))
        .map(|(k, a)| (k.clone(), a.clone()))
        .collect();
    let keys: BTreeSet<RowKey> = s0.keys().cloned().collect();
    let kept_nodes: BTreeSet<RowKey> = s0
        .iter()
        .filter(|(_, a)| a.table == "harvester_fragments" && !cl.fragment_moves(a, &moving))
        .map(|(k, _)| k.clone())
        .collect();

    // ---- manifest first: every prior, fsynced before the write ----
    let mut prior: Vec<Record> = eligible
        .iter()
        .map(|c| claim_record(c, false, false))
        .collect();
    for (k, a) in &s0 {
        prior.push(record_of(
            spec_of(ctx.specs, &k.0),
            k,
            a.claim,
            &RowState::of(a),
            false,
        ));
    }
    sink.record(&prior)?;

    let views_before = three_views(conn, ctx, &claim_ids, &keys).await?;
    let counters_before = xact_counters(conn).await?;

    let moved = sqlx::query(
        "UPDATE claims SET owner_group_id = $2 \
          WHERE id = ANY($1) AND owner_group_id = $3 AND visibility = 'group'",
    )
    .bind(&claim_ids)
    .bind(ctx.target)
    .bind(ctx.source)
    .execute(&mut *conn)
    .await
    .context("UPDATE claims")?
    .rows_affected();

    // NODES the cascade reached and must not move: back on their tuple.
    let mid = states_of(conn, ctx.specs, &claim_ids, &kept_nodes).await?;
    let node_writes: Vec<(String, RowState)> = kept_nodes
        .iter()
        .filter_map(|k| {
            let a = s0.get(k)?;
            (mid.get(k) != Some(&RowState::of(a))).then(|| (k.1.clone(), RowState::of(a)))
        })
        .collect();
    let nodes_restored = write_rows(
        conn,
        spec_of(ctx.specs, "harvester_fragments"),
        &claim_ids,
        &node_writes,
    )
    .await?;

    // Every edge: the EXACT meet of its endpoints now. The trigger re-met the
    // claim-endpoint edges, but with a node endpoint (a workflow, a frame...)
    // counted as public; it does not re-meet evidence-endpoint edges at all.
    // Both are written here; an edge the trigger already put on its exact
    // meet is not written again.
    let edge_keys: BTreeSet<RowKey> = keys.iter().filter(|k| k.0 == "edges").cloned().collect();
    let mid_edges = states_of(conn, ctx.specs, &claim_ids, &edge_keys).await?;
    let ends_mid = ends_of(conn, ctx.nodes, &edge_ids(&edge_keys)).await?;
    let mut edge_writes: Vec<(String, RowState)> = Vec::new();
    let mut trigger_edges = 0i64;
    for k in &edge_keys {
        let (Some(a), Some(cur)) = (s0.get(k), mid_edges.get(k)) else {
            continue;
        };
        if cur.tenancy != a.tenancy {
            trigger_edges += 1;
        }
        let Some(m) = ends_mid
            .get(&k.1)
            .and_then(|e| meet(&e.source_state, &e.target_state))
        else {
            continue;
        };
        if m != cur.tenancy {
            edge_writes.push((
                k.1.clone(),
                RowState {
                    tenancy: m,
                    writer_owned: None,
                },
            ));
        }
    }
    let edges_written =
        write_rows(conn, spec_of(ctx.specs, "edges"), &claim_ids, &edge_writes).await?;

    let s2 = states_of(conn, ctx.specs, &claim_ids, &keys).await?;
    let after_claims = fetch_claims(conn, &claim_ids, false).await?;
    let ends = ends_of(conn, ctx.nodes, &edge_ids(&keys)).await?;
    let counters_after = xact_counters(conn).await?;
    let views_after = three_views(conn, ctx, &claim_ids, &keys).await?;

    // ---- invariants ----
    let mut v = Vec::new();
    if usize::try_from(moved).ok() != Some(claim_ids.len()) {
        v.push(format!(
            "UPDATE claims moved {moved} row(s), the batch planned {}",
            claim_ids.len()
        ));
    }
    for c in &after_claims {
        if c.owner != ctx.target || c.visibility != GROUP {
            v.push(format!(
                "claim {} is ({}, {}), not ('group', {})",
                c.id, c.owner, c.visibility, ctx.target
            ));
        }
    }
    let mut planned: BTreeMap<String, usize> = BTreeMap::new();
    let mut actual: BTreeMap<String, usize> = BTreeMap::new();
    let mut rows_before: BTreeMap<RowKey, (Tenancy, Uuid)> = BTreeMap::new();
    let mut rows_after: BTreeMap<RowKey, (Tenancy, Uuid)> = BTreeMap::new();
    for (k, a) in &s0 {
        let before = RowState::of(a);
        rows_before.insert(k.clone(), (before.tenancy.clone(), a.claim));
        let want = match wanted(ctx, &cl, k, a, &kept_nodes, &ends) {
            Ok(w) => w,
            Err(e) => {
                v.push(e);
                continue;
            }
        };
        if want != before {
            *planned.entry(k.0.clone()).or_default() += 1;
        }
        let Some(got) = s2.get(k) else {
            v.push(format!("{} {} vanished during the batch", k.0, k.1));
            continue;
        };
        rows_after.insert(k.clone(), (got.tenancy.clone(), a.claim));
        if *got != before {
            *actual.entry(k.0.clone()).or_default() += 1;
        }
        if *got != want {
            v.push(format!("{} {} ended as {got}, expected {want}", k.0, k.1));
        }
        if got.tenancy.visibility == PUBLIC && before.tenancy.visibility != PUBLIC {
            v.push(format!("{} {} WIDENED from {before} to {got}", k.0, k.1));
        }
        if got.tenancy.visibility == PUBLIC && *got != before {
            v.push(format!("{} {} was changed while public", k.0, k.1));
        }
    }
    if planned != actual {
        v.push(format!(
            "rows changed per table {actual:?} differ from rows planned {planned:?}"
        ));
    }
    if usize::try_from(edges_written).ok() != Some(edge_writes.len()) {
        v.push(format!(
            "the edge meet write changed {edges_written} row(s), {} were planned",
            edge_writes.len()
        ));
    }
    let mut expect_counts: BTreeMap<String, (i64, i64, i64)> = BTreeMap::new();
    expect_counts.insert(
        "claims".into(),
        (0, i64::try_from(claim_ids.len()).unwrap_or(i64::MAX), 0),
    );
    if nodes_restored > 0 {
        expect_counts
            .entry("harvester_fragments".into())
            .or_default()
            .1 += 2 * i64::try_from(nodes_restored).unwrap_or(i64::MAX);
    }
    for (t, n) in planned.iter().filter(|(t, _)| t.as_str() != "edges") {
        expect_counts.entry(t.clone()).or_default().1 += i64::try_from(*n).unwrap_or(i64::MAX);
    }
    // An edge row is updated once by the trigger (when it changed it) and once
    // by the meet write (when it wrote it).
    let edge_updates = trigger_edges + i64::try_from(edges_written).unwrap_or(i64::MAX);
    if edge_updates > 0 {
        expect_counts.entry("edges".into()).or_default().1 += edge_updates;
    }
    v.extend(counter_violations(
        &counter_delta(&counters_before, &counters_after),
        &expect_counts,
    ));
    let claims_before: BTreeMap<Uuid, Tenancy> =
        eligible.iter().map(|c| (c.id, tenancy(c.owner))).collect();
    let claims_after: BTreeMap<Uuid, Tenancy> = after_claims
        .iter()
        .map(|c| {
            (
                c.id,
                Tenancy {
                    owner: c.owner,
                    visibility: c.visibility.clone(),
                    co_owner: None,
                },
            )
        })
        .collect();
    v.extend(view_violations(
        ctx,
        "before the move",
        &views_before,
        &claims_before,
        &rows_before,
        None,
    ));
    v.extend(view_violations(
        ctx,
        "after the move",
        &views_after,
        &claims_after,
        &rows_after,
        Some(&views_before[0]),
    ));
    if !v.is_empty() {
        return Err(BatchError::Invariant(v));
    }

    // ---- the audit row, in the first batch that changes anything ----
    if let Some((details, operator)) = audit {
        let mut d = details.clone();
        d["first_batch"] = json!({
            "claims_moved": claim_ids.len(),
            "rows_moved_by_table": actual,
        });
        write_audit(conn, EVENT_APPLY, operator, d).await?;
        out.audit_written = true;
    }

    // ---- post records, fsynced before the caller commits ----
    let neighbour_ids: Vec<Uuid> = s0
        .values()
        .flat_map(|a| a.claims.iter().chain(a.neighbours.iter()))
        .filter(|c| !moving.contains(c))
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let neighbours = fetch_claims(conn, &neighbour_ids, false).await?;
    let mut post: Vec<Record> = neighbours
        .iter()
        .map(|n| claim_record(n, true, true))
        .collect();
    post.extend(after_claims.iter().map(|c| claim_record(c, true, false)));
    for (k, st) in &s2 {
        post.push(record_of(
            spec_of(ctx.specs, &k.0),
            k,
            s0.get(k).map_or(Uuid::nil(), |a| a.claim),
            st,
            true,
        ));
    }
    sink.record_post(&post)?;

    // ---- the co-owned edges (every one), the node edges, and the sample ----
    for (k, st) in s2.iter().filter(|(k, _)| k.0 == "edges") {
        let Some(e) = ends.get(&k.1) else {
            continue;
        };
        if let Some((node, node_state)) = node_end(ctx.nodes, e) {
            // A group-private node that is not the target's: the edge keeps
            // requiring that node's group, so it is narrower than the claim.
            if node_state.1 == GROUP && node_state.0 != ctx.target {
                let label = if node_state.0 == ctx.source {
                    "source group".to_string()
                } else {
                    format!("group {}", node_state.0)
                };
                out.node_edges.push((
                    k.1.clone(),
                    Some(format!(
                        "SOURCE-NODE-EDGE\t{}\tclaim {}\t{} -> {}\t{} {} ({}, {}): {label}\t\
                         readable only by a member of every group the tuple names",
                        k.1,
                        s0.get(k).map_or(Uuid::nil(), |a| a.claim),
                        s0.get(k)
                            .map_or_else(|| "?".to_string(), |a| RowState::of(a).to_string()),
                        st,
                        node.1,
                        node.0,
                        node_state.0,
                        node_state.1,
                    )),
                ));
                continue;
            }
            // The node requires nothing beyond the target (public, in the
            // target, or a trace that moved with its claim). The edge is
            // co-owned only through its OTHER end, reported below.
            out.node_edges.push((k.1.clone(), None));
        }
        let Some(co) = st.tenancy.co_owner else {
            continue;
        };
        let moved_end = |n: &(Uuid, String)| match n.1.as_str() {
            "claim" => moving.contains(&n.0),
            "evidence" => s0.contains_key(&("evidence".to_string(), n.0.to_string())),
            ty => ctx
                .nodes
                .get(ty)
                .is_some_and(|t| s0.contains_key(&(t.clone(), n.0.to_string()))),
        };
        let (other, other_state) = if moved_end(&e.source) {
            (&e.target, &e.target_state)
        } else {
            (&e.source, &e.source_state)
        };
        let label = if other_state.0 == ctx.source && other_state.1 == GROUP {
            "source group".to_string()
        } else {
            format!("group {}", other_state.0)
        };
        out.co_owned.push(format!(
            "CO-OWNED-EDGE\t{}\tclaim {}\t{} -> {}\tother end {} {} ({}, {}): {label}\t\
             readable only by a member of both {} and {co}",
            k.1,
            s0.get(k).map_or(Uuid::nil(), |a| a.claim),
            s0.get(k)
                .map_or_else(|| "?".to_string(), |a| RowState::of(a).to_string()),
            st,
            other.1,
            other.0,
            other_state.0,
            other_state.1,
            st.tenancy.owner
        ));
    }
    // ---- the edges the reversal will refuse ----
    // `reown-reverse` writes an edge's FIRST recorded prior back only when it
    // is at least as narrow as the meet of its endpoints after the restore
    // (every row this run moved back on its prior, every other endpoint as it
    // is now); otherwise it holds the claim. Predict that here, so the dry
    // run says which claims the act could not undo (an edge to a node of the
    // target or of a third group: its prior, stamped with the node counted as
    // public, was already wider than the node).
    let prior_of = |k: &RowKey| -> Option<RowState> {
        known
            .priors
            .get(k)
            .cloned()
            .or_else(|| s0.get(k).map(RowState::of))
    };
    let at_restore = |n: &Pair, now: &Pair| -> Pair {
        let key = match n.1.as_str() {
            "claim" if moving.contains(&n.0) || known.claims.contains(&n.0) => {
                return (ctx.source, GROUP.to_string());
            }
            "claim" => return now.clone(),
            "evidence" => ("evidence".to_string(), n.0.to_string()),
            ty => match ctx.nodes.get(ty) {
                Some(t) => (t.clone(), n.0.to_string()),
                None => return now.clone(),
            },
        };
        prior_of(&key).map_or_else(
            || now.clone(),
            |st| (st.tenancy.owner, st.tenancy.visibility),
        )
    };
    for (k, a) in s0.iter().filter(|(k, _)| k.0 == "edges") {
        let (Some(e), Some(prior)) = (ends.get(&k.1), prior_of(k)) else {
            continue;
        };
        let ss = at_restore(&e.source, &e.source_state);
        let ts = at_restore(&e.target, &e.target_state);
        let verdict = meet(&ss, &ts)
            .filter(|m| !narrows(m, &prior.tenancy))
            .map(|m| {
                let names: BTreeSet<Uuid> = a.claims.intersection(&moving).copied().collect();
                let list = names
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(",");
                let line = format!(
                    "IRREVERSIBLE-EDGE\t{}\tclaim {list}\t{prior} -> {}\tafter a restore {} {} \
                     ({}, {}) and {} {} ({}, {}) meet at {}\tthe recorded tuple is wider than \
                     that meet, so reown-reverse will hold claim {list}: it will not be reversible",
                    k.1,
                    s2.get(k)
                        .map_or_else(|| "?".to_string(), ToString::to_string),
                    e.source.1,
                    e.source.0,
                    ss.0,
                    ss.1,
                    e.target.1,
                    e.target.0,
                    ts.0,
                    ts.1,
                    RowState {
                        tenancy: m,
                        writer_owned: None
                    }
                );
                (line, names)
            });
        out.irreversible.push((k.1.clone(), verdict));
    }
    out.prior_rows = s0
        .iter()
        .map(|(k, a)| (k.clone(), RowState::of(a)))
        .collect();
    out.moved_claims.clone_from(&moving);

    for c in eligible.iter().take(ctx.sample) {
        out.sample.push(format!(
            "SAMPLE\t{}\tclaims\t{}\t({}, {}) -> ('group', {})",
            c.id, c.id, c.owner, c.visibility, ctx.target
        ));
        for (k, a) in s0.iter().filter(|(_, a)| a.claims.contains(&c.id)) {
            out.sample.push(format!(
                "SAMPLE\t{}\t{}\t{}\t{} -> {}",
                c.id,
                k.0,
                k.1,
                RowState::of(a),
                s2.get(k)
                    .map_or_else(|| "?".to_string(), ToString::to_string)
            ));
        }
    }
    out.claims_moved = claim_ids.len();
    out.moved_by_table = actual;
    out.post_rows = s2;
    Ok(out)
}

/// The whole run's result.
#[derive(Default, Debug)]
pub struct RunReport {
    pub requested: usize,
    pub eligible: usize,
    pub already: usize,
    pub held_at_plan: Vec<(Uuid, Hold)>,
    pub held_under_lock: Vec<(Uuid, Hold)>,
    pub batch_failures: Vec<(usize, String)>,
    pub claims_moved: usize,
    pub moved_by_table: BTreeMap<String, usize>,
    pub co_owned_edges: usize,
    pub source_node_edges: usize,
    /// Edges whose reversal will hold their claim, and those claims.
    pub irreversible_edges: usize,
    pub irreversible_claims: usize,
    pub manifest_rows: usize,
    pub audit_written: bool,
}

/// The exit code for `report` (see the module doc).
#[must_use]
pub fn exit_code(report: &RunReport, opts: &Options) -> i32 {
    if !report.batch_failures.is_empty() {
        2
    } else if opts.apply
        && (!report.held_at_plan.is_empty()
            || !report.held_under_lock.is_empty()
            || Some(report.claims_moved) != opts.confirm_count)
    {
        3
    } else {
        0
    }
}

/// The pre-pass: every claim classified, and every candidate's rows, with no
/// lock held and nothing written. It reads up to 5000 claims at once, so its
/// candidate set is a superset of any batch's: a row verdict can only be
/// stricter here than under a batch's lock (the plan never promises a claim a
/// batch will hold for a reason the plan could see).
async fn pre_pass(
    conn: &mut PgConnection,
    ctx: &Ctx<'_>,
    ids: &[Uuid],
) -> anyhow::Result<(Vec<Uuid>, Vec<Uuid>, Vec<(Uuid, Hold)>)> {
    let (mut eligible, mut already, mut held) = (Vec::new(), Vec::new(), Vec::new());
    for chunk in ids.chunks(5000) {
        let rows = fetch_claims(conn, chunk, false).await?;
        let sealed = sealed_claims_of(conn, chunk).await?;
        let by_id: BTreeMap<Uuid, &ClaimRow> = rows.iter().map(|r| (r.id, r)).collect();
        let mut cands = BTreeSet::new();
        for id in chunk {
            let Some(c) = by_id.get(id) else {
                held.push((*id, Hold::NotFound));
                continue;
            };
            match classify_claim(c, ctx.source, ctx.target) {
                Ok(false) => already.push(*id),
                Ok(true) if sealed.contains_key(id) => {
                    held.push((*id, Hold::Sealed { seal: sealed[id] }))
                }
                Ok(true) => {
                    cands.insert(*id);
                }
                Err(h) => held.push((*id, h)),
            }
        }
        if cands.is_empty() {
            continue;
        }
        let cl = classify_rows(conn, ctx, &cands, &Known::default(), false).await?;
        for id in chunk {
            if !cands.contains(id) {
                continue;
            }
            match cl.hold.get(id) {
                Some(h) => held.push((*id, h.clone())),
                None => eligible.push(*id),
            }
        }
    }
    Ok((eligible, already, held))
}

/// Plan, refuse or confirm, then run the batches.
///
/// # Errors
/// A refusal, or a failure outside a batch.
#[allow(clippy::too_many_lines)]
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
    let ids_sha256 = sha256_file(&opts.claims_file)?;
    let target_kind = check_groups(conn, opts.source, opts.target, opts.operator).await?;
    let specs = tables::propagated_tables(conn).await?;
    if let Some(t) = specs
        .iter()
        .find(|t| super::restrict::role_of(&t.name).is_none())
    {
        bail!(
            "the tenancy cascade reaches table {}, which is not classified as node, link or \
             dependent (restrict::TABLE_ROLES); refusing",
            t.name
        );
    }
    let unkeyed = batch_lock_tables(&tables::unkeyed_tables(conn, &specs).await?);
    let nodes = node_types(conn).await?;
    tables::probe_session_switch(conn).await?;
    let guard = super::hide::guard_status(conn).await?;
    if !guard.complete() {
        bail!(
            "the evidence pin guard (migration 110) is not complete in this schema; a pinned \
             row's handling is part of this tool's model, refusing"
        );
    }
    let unenforced = unenforced_reasons(conn, &specs).await?;
    if !unenforced.is_empty() {
        bail!(
            "row security is not an enforced boundary on {unenforced:?} (a permissive read \
             policy beyond <table>_tenancy, or row security disabled): a group row there is \
             readable by every session, so a regroup would not decide who reads it; refusing"
        );
    }
    let ctx = Ctx {
        specs: &specs,
        unkeyed: &unkeyed,
        nodes: &nodes,
        source: opts.source,
        target: opts.target,
        lock_timeout: &opts.lock_timeout,
        sample: if opts.apply { 0 } else { opts.sample },
    };
    let (eligible, already, held) = pre_pass(conn, &ctx, requested).await?;
    report.eligible = eligible.len();
    report.already = already.len();
    report.held_at_plan.clone_from(&held);

    writeln!(
        out,
        "regroup-claims: source_group={} target_group={} ({target_kind}) operator={} mode={}",
        opts.source,
        opts.target,
        opts.operator,
        if opts.apply { "APPLY" } else { "DRY-RUN" }
    )?;
    writeln!(
        out,
        "PLAN: {} requested, {} eligible, {} held, {} already ('group', target)",
        requested.len(),
        eligible.len(),
        held.len(),
        already.len()
    )?;
    let mut by_reason: BTreeMap<&'static str, usize> = BTreeMap::new();
    for (_, h) in &held {
        *by_reason.entry(h.code()).or_default() += 1;
    }
    for (r, n) in &by_reason {
        writeln!(out, "HELD-COUNT\t{r}\t{n}")?;
    }
    for (id, h) in &held {
        writeln!(out, "HELD\t{id}\t{}\t{h}", h.code())?;
    }
    writeln!(
        out,
        "LOCKED-PER-BATCH\t{}\t(each batch holds SHARE ROW EXCLUSIVE on them: no concurrent \
         write to them on the instance while it runs)",
        unkeyed.join(",")
    )?;
    writeln!(
        out,
        "NODE-TYPES\t{}\t(edge endpoints with their own tenancy: the meet reads the node's own row)",
        nodes
            .iter()
            .map(|(ty, t)| format!("{ty}={t}"))
            .collect::<Vec<_>>()
            .join(",")
    )?;
    writeln!(
        out,
        "RULE: every row that follows a moved claim goes from ('group', source) to ('group', \
         target); an edge takes the exact meet of its endpoints (an end that stays in the source, \
         a claim or evidence (CO-OWNED-EDGE) or a group-private node such as a workflow or frame \
         (SOURCE-NODE-EDGE), makes it co-owned); a shared fragment and an outsider's challenge \
         stay as they are; a sealed claim (a claim_encryption or claim_version_encryption row) \
         is HELD, and so, whole, is a claim with a public, pinned, sealed-evidence, sealed-edge \
         (an edge_encryption row the move would re-tuple) or third-group row; nothing becomes \
         public"
    )?;

    if opts.apply {
        match opts.confirm_count {
            Some(n) if n == eligible.len() => {}
            Some(n) => bail!(
                "--confirm-count {n} does not match the {} eligible claim(s); refusing. Nothing \
                 was written.",
                eligible.len()
            ),
            None => bail!("--apply requires --confirm-count; refusing"),
        }
        if eligible.is_empty() {
            writeln!(
                out,
                "RESULT\n  claims moved: 0 (nothing eligible; no manifest written)"
            )?;
            return Ok(report);
        }
    }

    let header = json!({
        "manifest": "epigraph-operator regroup-claims",
        "operation": OPERATION,
        "version": manifest::VERSION,
        "operator": opts.operator,
        "source_group_id": opts.source,
        "target_group_id": opts.target,
        "created_at": chrono::Utc::now().to_rfc3339(),
        "ruling": opts.ruling,
        "reason": opts.reason,
        "claims_file_sha256": ids_sha256,
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
        "command": "regroup-claims",
        "ruling": opts.ruling,
        "reason": opts.reason,
        "operator_person": opts.operator,
        "operator": operator_details(conn).await?,
        "source_group_id": opts.source,
        "target_group_id": opts.target,
        "target_group_kind": target_kind,
        "claims_file_sha256": ids_sha256,
        "manifest_path": opts.manifest_out.display().to_string(),
        "manifest_header_sha256": header_sha256,
        "planned": {
            "requested": requested.len(),
            "eligible": eligible.len(),
            "held": held.len(),
            "already": already.len(),
        },
        "batch_size": opts.batch_size,
    });

    let mut known = Known::default();
    let batches: Vec<&[Uuid]> = eligible.chunks(opts.batch_size).collect();
    let total = batches.len();
    let mut sampled = 0usize;
    let mut co_owned: Vec<String> = Vec::new();
    let mut node_edges: BTreeMap<String, String> = BTreeMap::new();
    let mut irreversible: BTreeMap<String, Irreversible> = BTreeMap::new();
    for (i, batch) in batches.iter().enumerate() {
        let mut tx = sqlx::Connection::begin(&mut *conn).await?;
        let audit =
            (opts.apply && !report.audit_written).then_some((&audit_details, opts.operator));
        let ctx_i = Ctx {
            sample: ctx.sample.saturating_sub(sampled),
            ..ctx
        };
        let r = run_batch(&mut tx, &ctx_i, batch, &mut sink, &known, audit).await;
        if opts.apply && r.is_ok() {
            tx.commit().await?;
        } else {
            tx.rollback().await?;
        }
        match r {
            Ok(b) => {
                report.claims_moved += b.claims_moved;
                for (t, n) in &b.moved_by_table {
                    *report.moved_by_table.entry(t.clone()).or_default() += n;
                }
                report.held_under_lock.extend(b.held);
                report.audit_written |= b.audit_written;
                if opts.apply {
                    known.rows.extend(b.post_rows);
                    for (k, st) in b.prior_rows {
                        known.priors.entry(k).or_insert(st);
                    }
                    known.claims.extend(b.moved_claims);
                }
                for (id, v) in b.irreversible {
                    match v {
                        Some(v) => irreversible.insert(id, v),
                        None => irreversible.remove(&id),
                    };
                }
                for l in &b.sample {
                    writeln!(out, "{l}")?;
                }
                sampled += b.sample.iter().filter(|l| l.contains("\tclaims\t")).count();
                co_owned.extend(b.co_owned);
                for (id, l) in b.node_edges {
                    match l {
                        Some(l) => node_edges.insert(id, l),
                        None => node_edges.remove(&id),
                    };
                }
                writeln!(
                    out,
                    "BATCH {}/{total}\tOK\t{} claim(s) moved",
                    i + 1,
                    b.claims_moved
                )?;
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
    // An edge between two claims of different batches is reported by the
    // first batch (co-owned then) and settled by the second: keep the last
    // state of each edge only, and report those still co-owned.
    let mut last: BTreeMap<String, String> = BTreeMap::new();
    for l in co_owned {
        let id = l.split('\t').nth(1).unwrap_or_default().to_string();
        last.insert(id, l);
    }
    let settled: BTreeSet<String> = known
        .rows
        .iter()
        .filter(|(k, st)| k.0 == "edges" && st.tenancy.co_owner.is_none())
        .map(|(k, _)| k.1.clone())
        .collect();
    last.retain(|id, _| !settled.contains(id));
    report.co_owned_edges = last.len();
    for l in last.values() {
        writeln!(out, "{l}")?;
    }
    report.source_node_edges = node_edges.len();
    for l in node_edges.values() {
        writeln!(out, "{l}")?;
    }
    report.irreversible_edges = irreversible.len();
    report.irreversible_claims = irreversible
        .values()
        .flat_map(|(_, c)| c.iter())
        .collect::<BTreeSet<_>>()
        .len();
    for (l, _) in irreversible.values() {
        writeln!(out, "{l}")?;
    }
    report.manifest_rows = sink.len();
    for (id, h) in &report.held_under_lock {
        writeln!(out, "HELD-UNDER-LOCK\t{id}\t{}\t{h}", h.code())?;
    }
    writeln!(out, "RESULT")?;
    writeln!(out, "  claims moved: {}", report.claims_moved)?;
    for (t, n) in &report.moved_by_table {
        writeln!(out, "  {t}: rows moved: {n}")?;
    }
    writeln!(
        out,
        "  co-owned edges: {} (an edge whose other end is not in the target)",
        report.co_owned_edges
    )?;
    writeln!(
        out,
        "  source-node edges: {} (an edge to a group-private node of a NODE-TYPES type that \
         is not the target's; it stays co-owned with that node's group)",
        report.source_node_edges
    )?;
    writeln!(
        out,
        "  irreversible edges: {} (IRREVERSIBLE-EDGE: reown-reverse will hold the {} claim(s) \
         they name, which this tool then cannot reverse)",
        report.irreversible_edges, report.irreversible_claims
    )?;
    writeln!(out, "  manifest row records: {}", report.manifest_rows)?;
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
    writeln!(
        out,
        "  audit row: {}",
        if report.audit_written {
            format!("written ({EVENT_APPLY})")
        } else if opts.apply {
            "none (nothing was changed)".to_string()
        } else {
            "none (dry run)".to_string()
        }
    )?;
    if !opts.apply {
        writeln!(
            out,
            "DRY RUN: each batch ran in its own transaction and was rolled back; no manifest, no \
             audit row. A batch does not see an earlier batch's effects, so an edge between \
             claims of two batches shows as co-owned here."
        )?;
    }
    Ok(report)
}

// ─────────────────────────────────────────────────────────────────────────────
// Reversal
// ─────────────────────────────────────────────────────────────────────────────

/// Is `m` a regroup manifest?
#[must_use]
pub fn is_regroup_manifest(m: &manifest::Manifest) -> bool {
    m.header.get("operation").and_then(Value::as_str) == Some(OPERATION)
}

/// What one reversal batch did.
#[derive(Default, Debug)]
struct RevOutcome {
    claims_restored: usize,
    rows_restored: BTreeMap<String, usize>,
    deferred_ids: BTreeSet<String>,
    settled_ids: BTreeSet<String>,
    held: Vec<(Uuid, String)>,
    never_moved: usize,
    already: usize,
    audit_written: bool,
}

const NEWER_FIRST: &str = "if a NEWER run moved it, reverse that manifest first (pass every \
                           manifest to one reown-reverse and it orders them newest-first)";

/// Fixed inputs to every reversal batch.
struct RevCtx<'a> {
    specs: &'a [TableSpec],
    unkeyed: &'a [String],
    nodes: &'a NodeTypes,
    res: &'a super::reverse::Resolved,
    source: Uuid,
    lock_timeout: &'a str,
}

/// One reversal batch of a regroup manifest, inside the caller's transaction.
/// Does NOT commit.
#[allow(clippy::too_many_lines)]
async fn reverse_batch(
    conn: &mut PgConnection,
    rc: &RevCtx<'_>,
    batch: &[(Uuid, Record)],
    audit: Option<(&Value, Uuid)>,
) -> Result<RevOutcome, BatchError> {
    let (specs, res) = (rc.specs, rc.res);
    let ctx = Ctx {
        specs,
        unkeyed: rc.unkeyed,
        nodes: rc.nodes,
        source: rc.source,
        target: res.target,
        lock_timeout: rc.lock_timeout,
        sample: 0,
    };
    let mut out = RevOutcome::default();
    sqlx::query("SELECT set_config('lock_timeout', $1, true)")
        .bind(rc.lock_timeout)
        .execute(&mut *conn)
        .await?;
    let ids: Vec<Uuid> = batch.iter().map(|(id, _)| *id).collect();
    let locked = fetch_claims(conn, &ids, true).await?;
    tables::lock_unkeyed_tables(conn, rc.unkeyed).await?;
    let sealed = sealed_claims_of(conn, &ids).await?;
    let now: BTreeMap<Uuid, &ClaimRow> = locked.iter().map(|c| (c.id, c)).collect();
    let prior_claims: BTreeMap<Uuid, &Record> = res.claims.iter().map(|(i, r)| (*i, r)).collect();

    // ---- claims: the CAS ----
    let mut cands: Vec<(Uuid, &Record)> = Vec::new();
    for (id, rec) in batch {
        let Some(post) = res.claim_posts.get(id) else {
            out.never_moved += 1;
            continue;
        };
        let Some(c) = now.get(id) else {
            out.held.push((*id, "claim no longer exists".into()));
            continue;
        };
        if c.owner == rec.owner_group_id && c.visibility == rec.visibility {
            out.already += 1;
            continue;
        }
        if c.owner != post.owner_group_id || c.visibility != post.visibility {
            out.held.push((
                *id,
                format!(
                    "claim is ({}, {}) now; this manifest's run left it ({}, {}); something moved \
                     it since, not reversing; {NEWER_FIRST}",
                    c.owner, c.visibility, post.owner_group_id, post.visibility
                ),
            ));
            continue;
        }
        if rec.visibility != GROUP || rec.owner_group_id != rc.source {
            out.held.push((
                *id,
                format!(
                    "the manifest records prior ({}, {}), which regroup-claims never moves; not \
                     reversing",
                    rec.owner_group_id, rec.visibility
                ),
            ));
            continue;
        }
        if let Some(seal) = sealed.get(id) {
            out.held.push((
                *id,
                format!(
                    "the claim has been sealed since the run ({seal}); its ciphertext is not \
                     the source group's, so restoring it would leave it undecryptable; not \
                     reversing"
                ),
            ));
            continue;
        }
        cands.push((*id, rec));
    }
    if cands.is_empty() {
        return Ok(out);
    }
    let cand_ids: BTreeSet<Uuid> = cands.iter().map(|(id, _)| *id).collect();
    let cand_vec: Vec<Uuid> = cand_ids.iter().copied().collect();
    let mut attached = fetch_attached(conn, specs, &cand_vec).await?;
    let ev_claim: BTreeMap<Uuid, Uuid> = attached
        .iter()
        .filter(|(k, _)| k.0 == "evidence")
        .filter_map(|(k, a)| Uuid::parse_str(&k.1).ok().map(|id| (id, a.claim)))
        .collect();
    let claim_edge_keys: BTreeSet<RowKey> = attached.keys().cloned().collect();
    let ev_edges = fetch_evidence_edges(conn, &ev_claim, &cand_ids, &claim_edge_keys).await?;
    // Every evidence edge counts: an unrecorded one was written after the act.
    attached.extend(ev_edges);
    // So does every edge to a node row that follows a candidate (a reasoning
    // trace): the later batch of a run settles an edge between a claim of an
    // earlier batch and its trace.
    let seen: BTreeSet<RowKey> = attached.keys().cloned().collect();
    let node_edges = fetch_node_edges(conn, rc.nodes, &attached, &cand_ids, &seen).await?;
    attached.extend(node_edges);
    let all_keys: BTreeSet<RowKey> = attached.keys().cloned().collect();
    lock_rows(conn, "evidence", &evidence_ids(&attached)).await?;
    lock_rows(conn, "edges", &edge_ids(&all_keys)).await?;
    let ends_now = ends_of(conn, rc.nodes, &edge_ids(&all_keys)).await?;

    // The manifest's recorded prior of an edge endpoint it moved: a claim its
    // run moved, or a row it recorded (evidence, or a node row such as a
    // reasoning trace that followed its claim). An endpoint's CURRENT state
    // is its own row's (`ends_of`).
    let recorded_prior = |(id, ty): &Pair| -> Option<Pair> {
        let r: Option<&Record> = match ty.as_str() {
            "claim" if res.claim_posts.contains_key(id) => prior_claims.get(id).copied(),
            "claim" => None,
            "evidence" => res.rows.get(&("evidence".to_string(), id.to_string())),
            other => rc
                .nodes
                .get(other)
                .and_then(|t| res.rows.get(&(t.clone(), id.to_string()))),
        };
        r.map(|r| (r.owner_group_id, r.visibility.clone()))
    };
    // Is `node`, now in `state`, one this manifest moved and NOT yet back on
    // its prior?
    let pending =
        |node: &Pair, state: &Pair| -> bool { recorded_prior(node).is_some_and(|r| r != *state) };

    // ---- rows: the CAS; an unrecorded row would be carried into the source ----
    let mut drift: BTreeMap<Uuid, String> = BTreeMap::new();
    for (k, a) in &attached {
        let cur = RowState::of(a);
        let why = match res.rows.get(k) {
            Some(prior) => {
                let p = RowState::of_record(prior);
                let q = res.row_posts.get(k).map(RowState::of_record);
                // A partial reversal leaves an edge on the meet of its current
                // endpoints while one recorded endpoint is back and another
                // is not; that state is this reversal's own.
                let partial = k.0 == "edges"
                    && ends_now.get(&k.1).is_some_and(|e| {
                        let some_back =
                            [(&e.source, &e.source_state), (&e.target, &e.target_state)]
                                .into_iter()
                                .any(|(n, st)| recorded_prior(n).is_some() && !pending(n, st));
                        some_back
                            && meet(&e.source_state, &e.target_state).as_ref() == Some(&cur.tenancy)
                    });
                (cur != p && q.as_ref() != Some(&cur) && !partial).then(|| {
                    format!(
                        "{} {} is {cur} now; this run left it {} and recorded {p} before; not \
                         reversing; {NEWER_FIRST}",
                        k.0,
                        k.1,
                        q.as_ref()
                            .map_or_else(|| "unchanged".to_string(), ToString::to_string)
                    )
                })
            }
            None => Some(format!(
                "{} {} is {cur} and was written after the regroup; restoring the claim would \
                 carry it into the source group, so not reversing",
                k.0, k.1
            )),
        };
        if let Some(why) = why {
            for cl in a.claims.intersection(&cand_ids) {
                drift.entry(*cl).or_insert_with(|| why.clone());
            }
        }
    }
    // ---- neighbours: a claim sharing a recorded row that has moved since ----
    let watched: BTreeSet<Uuid> = attached
        .iter()
        .filter(|(k, _)| res.rows.contains_key(*k))
        .flat_map(|(_, a)| a.neighbours.iter().copied())
        .filter(|n| !res.claim_posts.contains_key(n) && res.neighbours.contains_key(n))
        .collect();
    if !watched.is_empty() {
        let wv: Vec<Uuid> = watched.iter().copied().collect();
        let rows: Vec<(Uuid, Uuid, String)> = sqlx::query_as(
            "SELECT id, owner_group_id, visibility::text FROM claims \
              WHERE id = ANY($1) ORDER BY id FOR SHARE",
        )
        .bind(&wv)
        .fetch_all(&mut *conn)
        .await?;
        let now_n: BTreeMap<Uuid, (Uuid, String)> =
            rows.into_iter().map(|(i, o, v)| (i, (o, v))).collect();
        for (k, a) in &attached {
            if !res.rows.contains_key(k) {
                continue;
            }
            for n in &a.neighbours {
                let Some(rec) = res.neighbours.get(n) else {
                    continue;
                };
                if res.claim_posts.contains_key(n) {
                    continue;
                }
                let cur = now_n.get(n);
                if cur != Some(&(rec.owner_group_id, rec.visibility.clone())) {
                    let why = format!(
                        "claim {n}, which shares {} {} with it, is {} now and was ({}, {}) when \
                         this run moved it; not reversing; {NEWER_FIRST}",
                        k.0,
                        k.1,
                        cur.map_or_else(|| "gone".to_string(), |(o, v)| format!("({o}, {v})")),
                        rec.owner_group_id,
                        rec.visibility
                    );
                    for cl in a.claims.intersection(&cand_ids) {
                        drift.entry(*cl).or_insert_with(|| why.clone());
                    }
                }
            }
        }
    }
    // ---- sealed evidence: its ciphertext is keyed to the group that sealed
    // it, so restoring the row would leave it where its readers cannot
    // decrypt it ----
    let sealed_ev = sealed_evidence_of(conn, &evidence_ids(&attached)).await?;
    for (k, a) in attached
        .iter()
        .filter(|(k, _)| k.0 == "evidence" && sealed_ev.contains(&k.1))
    {
        let why = format!(
            "evidence {} has been sealed since the run (evidence_encryption); its ciphertext is \
             not the source group's, so restoring it would leave it undecryptable; not reversing",
            k.1
        );
        for cl in a.claims.intersection(&cand_ids) {
            drift.entry(*cl).or_insert_with(|| why.clone());
        }
    }
    // ---- sealed edges: the run held every sealed edge it would re-tuple, so
    // a sealed edge whose tuple the reversal would change (its recorded prior
    // differs from its tuple now, or it waits on an endpoint not yet back)
    // was sealed since the run, under a key the source does not hold ----
    let sealed_edges = sealed_edges_of(conn, &edge_ids(&all_keys)).await?;
    for (k, a) in attached.iter().filter(|(k, _)| k.0 == "edges") {
        let Some(group) = sealed_edges.get(&k.1) else {
            continue;
        };
        let changes = res.rows.get(k).is_none_or(|rec| {
            RowState::of_record(rec).tenancy != a.tenancy
                || ends_now.get(&k.1).is_some_and(|e| {
                    pending(&e.source, &e.source_state) || pending(&e.target, &e.target_state)
                })
        });
        if !changes {
            continue;
        }
        let why = format!(
            "edge {} is sealed (edge_encryption, keyed to group {group}); restoring its claim \
             would change its tuple, and its ciphertext never leaves the group that holds its \
             key; not reversing",
            k.1
        );
        for cl in a.claims.intersection(&cand_ids) {
            drift.entry(*cl).or_insert_with(|| why.clone());
        }
    }
    // ---- an edge put back on its recorded tuple must be at least as narrow
    // as the meet of its endpoints as they will be after this batch: an
    // endpoint that moved since (a claim outside the manifest, ITS evidence,
    // a node) may require a group the recorded tuple does not.
    //
    // The loop repeats until a round holds nothing new, but at this head the
    // second round never does. A hold only takes claims out of `work_ids`,
    // which turns an endpoint `after` called restored into one it does not.
    // Such an endpoint is either still off its recorded prior (pending: the
    // edge waits on the meet and is skipped) or already on it (its state is
    // the same either way), and an endpoint with no recorded prior never
    // depended on `work_ids`. So no checked edge sees a new state, and every
    // edge that failed in the first round has no claim left in `work_ids`.
    // The repeat is defensive: it keeps the check sound if `after` ever
    // changes so that a hold can change a checked state. A test cannot make
    // it fire, and a one-round mutant is equivalent. ----
    let mut work_ids: BTreeSet<Uuid> = cand_ids
        .iter()
        .filter(|c| !drift.contains_key(*c))
        .copied()
        .collect();
    loop {
        let mut newly: Vec<(Uuid, String)> = Vec::new();
        for (k, a) in attached.iter().filter(|(k, _)| k.0 == "edges") {
            let Some(rec) = res.rows.get(k) else {
                continue;
            };
            if a.claims.is_disjoint(&work_ids) {
                continue;
            }
            let Some(e) = ends_now.get(&k.1) else {
                continue;
            };
            // An endpoint's state after this batch, and whether it is one this
            // manifest moved that is still not back (the edge then waits on
            // the meet, which is safe by construction).
            let after = |n: &Pair, now: &Pair| -> (Pair, bool) {
                let recorded = recorded_prior(n);
                let restored = match n.1.as_str() {
                    "claim" => work_ids.contains(&n.0),
                    ty => {
                        let table = if ty == "evidence" {
                            Some("evidence")
                        } else {
                            rc.nodes.get(ty).map(String::as_str)
                        };
                        table.is_some_and(|t| {
                            attached
                                .get(&(t.to_string(), n.0.to_string()))
                                .is_some_and(|ra| !ra.claims.is_disjoint(&work_ids))
                        })
                    }
                };
                let state = match (&recorded, restored) {
                    (Some(r), true) => r.clone(),
                    _ => now.clone(),
                };
                let pending = recorded.as_ref().is_some_and(|r| *r != state);
                (state, pending)
            };
            let (ss, s_pending) = after(&e.source, &e.source_state);
            let (ts, t_pending) = after(&e.target, &e.target_state);
            if s_pending || t_pending {
                continue;
            }
            let recorded = RowState::of_record(rec);
            if let Some(m) = meet(&ss, &ts) {
                if !narrows(&m, &recorded.tenancy) {
                    let why = format!(
                        "edge {} would go back to {recorded}, but its endpoints after the \
                         restore ({} {} ({}, {}), {} {} ({}, {})) meet at {}: an endpoint moved \
                         since and the recorded tuple would widen the edge; not reversing",
                        k.1,
                        e.source.1,
                        e.source.0,
                        ss.0,
                        ss.1,
                        e.target.1,
                        e.target.0,
                        ts.0,
                        ts.1,
                        RowState {
                            tenancy: m,
                            writer_owned: None
                        }
                    );
                    for c in a.claims.intersection(&work_ids) {
                        newly.push((*c, why.clone()));
                    }
                }
            }
        }
        if newly.is_empty() {
            break;
        }
        for (c, why) in newly {
            work_ids.remove(&c);
            drift.entry(c).or_insert(why);
        }
    }
    let work: Vec<(Uuid, &Record)> = cands
        .into_iter()
        .filter(|(id, _)| !drift.contains_key(id))
        .collect();
    out.held.extend(drift);
    if work.is_empty() {
        return Ok(out);
    }
    let claim_ids: Vec<Uuid> = work.iter().map(|(id, _)| *id).collect();
    let work_ids: BTreeSet<Uuid> = claim_ids.iter().copied().collect();
    let s0: Snapshot = attached
        .into_iter()
        .filter(|(_, a)| a.claims.iter().any(|c| work_ids.contains(c)))
        .collect();
    let keys: BTreeSet<RowKey> = s0.keys().cloned().collect();
    let views_before = three_views(conn, &ctx, &claim_ids, &keys).await?;
    let counters_before = xact_counters(conn).await?;

    // ---- claims: back on their recorded owner (visibility stays group) ----
    let payload: Vec<Value> = work
        .iter()
        .map(|(id, r)| json!({"id": id, "o": r.owner_group_id}))
        .collect();
    let claims_updated = sqlx::query(
        "UPDATE claims c SET owner_group_id = m.o \
           FROM jsonb_to_recordset($1::jsonb) AS m(id uuid, o uuid) \
          WHERE c.id = m.id AND c.owner_group_id = $2 AND c.visibility = 'group' \
            AND m.o = $3",
    )
    .bind(Value::Array(payload))
    .bind(res.target)
    .bind(rc.source)
    .execute(&mut *conn)
    .await
    .context("UPDATE claims (restore)")?
    .rows_affected();

    let s1 = states_of(conn, specs, &claim_ids, &keys).await?;
    let mut trigger_changed: BTreeMap<String, i64> = BTreeMap::new();
    for (k, a) in &s0 {
        if s1.get(k) != Some(&RowState::of(a)) {
            *trigger_changed.entry(k.0.clone()).or_default() += 1;
        }
    }

    // ---- recorded non-edge rows back on their OWN recorded tuple ----
    let mut to_write: BTreeMap<String, Vec<(String, RowState)>> = BTreeMap::new();
    for k in keys.iter().filter(|k| k.0 != "edges") {
        if let (Some(rec), Some(cur)) = (res.rows.get(k), s1.get(k)) {
            let want = RowState::of_record(rec);
            if *cur != want {
                to_write
                    .entry(k.0.clone())
                    .or_default()
                    .push((k.1.clone(), want));
            }
        }
    }
    let mut restored: BTreeMap<String, i64> = BTreeMap::new();
    for (t, rows) in &to_write {
        let n = write_rows(conn, spec_of(specs, t), &claim_ids, rows).await?;
        restored.insert(t.clone(), i64::try_from(n).unwrap_or(i64::MAX));
    }

    // ---- recorded edges: their recorded tuple once every endpoint this
    // manifest moved is back; otherwise the meet of their endpoints now ----
    let ends = ends_of(conn, rc.nodes, &edge_ids(&keys)).await?;
    let mut deferred: BTreeSet<String> = BTreeSet::new();
    let mut edge_rows: Vec<(String, RowState)> = Vec::new();
    let mut edge_want: BTreeMap<RowKey, RowState> = BTreeMap::new();
    for k in keys.iter().filter(|k| k.0 == "edges") {
        let (Some(rec), Some(cur), Some(e)) = (res.rows.get(k), s1.get(k), ends.get(&k.1)) else {
            continue;
        };
        let want = if pending(&e.source, &e.source_state) || pending(&e.target, &e.target_state) {
            deferred.insert(k.1.clone());
            match meet(&e.source_state, &e.target_state) {
                Some(m) => RowState {
                    tenancy: m,
                    writer_owned: None,
                },
                None => cur.clone(),
            }
        } else {
            RowState::of_record(rec)
        };
        if *cur != want {
            edge_rows.push((k.1.clone(), want.clone()));
        }
        edge_want.insert(k.clone(), want);
    }
    if !edge_rows.is_empty() {
        let n = write_rows(conn, spec_of(specs, "edges"), &claim_ids, &edge_rows).await?;
        *restored.entry("edges".into()).or_default() += i64::try_from(n).unwrap_or(i64::MAX);
    }

    let s2 = states_of(conn, specs, &claim_ids, &keys).await?;
    let after = fetch_claims(conn, &claim_ids, false).await?;
    let counters_after = xact_counters(conn).await?;
    let views_after = three_views(conn, &ctx, &claim_ids, &keys).await?;

    // ---- invariants ----
    let mut v = Vec::new();
    let recs: BTreeMap<Uuid, &Record> = work.iter().map(|(id, r)| (*id, *r)).collect();
    for c in &after {
        let r = recs[&c.id];
        if c.owner != r.owner_group_id || c.visibility != r.visibility {
            v.push(format!(
                "claim {} is ({}, {}), the manifest records ({}, {})",
                c.id, c.owner, c.visibility, r.owner_group_id, r.visibility
            ));
        }
    }
    let mut rows_before: BTreeMap<RowKey, (Tenancy, Uuid)> = BTreeMap::new();
    let mut rows_after: BTreeMap<RowKey, (Tenancy, Uuid)> = BTreeMap::new();
    for (k, a) in &s0 {
        rows_before.insert(k.clone(), (a.tenancy.clone(), a.claim));
        let Some(got) = s2.get(k) else {
            v.push(format!("{} {} vanished during the batch", k.0, k.1));
            continue;
        };
        rows_after.insert(k.clone(), (got.tenancy.clone(), a.claim));
        let want = match edge_want.get(k) {
            Some(w) => w.clone(),
            None => match res.rows.get(k) {
                Some(rec) => RowState::of_record(rec),
                None => {
                    v.push(format!("{} {} is not recorded", k.0, k.1));
                    continue;
                }
            },
        };
        if *got != want {
            v.push(format!("{} {} ended as {got}, expected {want}", k.0, k.1));
        }
        if got.tenancy.visibility == PUBLIC && a.tenancy.visibility != PUBLIC {
            v.push(format!("{} {} WIDENED to {got}", k.0, k.1));
        }
        if k.0 == "edges" {
            if let Some(m) = ends
                .get(&k.1)
                .and_then(|e| meet(&e.source_state, &e.target_state))
            {
                if !narrows(&m, &got.tenancy) {
                    v.push(format!(
                        "edge {} ended as {got}, wider than the meet {} of its endpoints",
                        k.1,
                        RowState {
                            tenancy: m,
                            writer_owned: None
                        }
                    ));
                }
            }
        }
    }
    let mut expect_counts: BTreeMap<String, (i64, i64, i64)> = BTreeMap::new();
    if claims_updated > 0 {
        expect_counts.insert(
            "claims".into(),
            (0, i64::try_from(claims_updated).unwrap_or(i64::MAX), 0),
        );
    }
    for (t, n) in trigger_changed.iter().chain(restored.iter()) {
        expect_counts.entry(t.clone()).or_default().1 += n;
    }
    expect_counts.retain(|_, d| *d != (0, 0, 0));
    v.extend(counter_violations(
        &counter_delta(&counters_before, &counters_after),
        &expect_counts,
    ));
    let claims_before: BTreeMap<Uuid, Tenancy> = claim_ids
        .iter()
        .map(|c| (*c, tenancy(res.target)))
        .collect();
    let claims_after: BTreeMap<Uuid, Tenancy> = after
        .iter()
        .map(|c| {
            (
                c.id,
                Tenancy {
                    owner: c.owner,
                    visibility: c.visibility.clone(),
                    co_owner: None,
                },
            )
        })
        .collect();
    v.extend(view_violations(
        &ctx,
        "before the reversal",
        &views_before,
        &claims_before,
        &rows_before,
        None,
    ));
    v.extend(view_violations(
        &ctx,
        "after the reversal",
        &views_after,
        &claims_after,
        &rows_after,
        Some(&views_before[0]),
    ));
    if !v.is_empty() {
        return Err(BatchError::Invariant(v));
    }
    if let Some((details, operator)) = audit {
        let mut d = details.clone();
        d["first_batch"] = json!({"claims_restored": claims_updated});
        write_audit(conn, EVENT_REVERSE, operator, d).await?;
        out.audit_written = true;
    }
    out.claims_restored = usize::try_from(claims_updated).unwrap_or(usize::MAX);
    out.settled_ids = keys
        .iter()
        .filter(|k| k.0 == "edges" && res.rows.contains_key(*k) && !deferred.contains(&k.1))
        .map(|k| k.1.clone())
        .collect();
    out.deferred_ids = deferred;
    for (t, n) in restored {
        out.rows_restored
            .insert(t, usize::try_from(n).unwrap_or(usize::MAX));
    }
    Ok(out)
}

/// Reverse one regroup manifest, batch by batch; folds into `report`.
/// Returns `false` when the run must stop (a failed batch under `--apply`).
///
/// # Errors
/// A failure outside a batch.
#[allow(clippy::too_many_arguments)]
pub async fn reverse_manifest(
    conn: &mut PgConnection,
    path: &Path,
    m: &manifest::Manifest,
    specs: &[TableSpec],
    unkeyed: &[String],
    opts: &super::reverse::Options,
    report: &mut super::reverse::Report,
    out: &mut dyn std::io::Write,
) -> anyhow::Result<bool> {
    let res = super::reverse::resolve(m, specs)?;
    let uuid_of = |k: &str| -> anyhow::Result<Uuid> {
        m.header
            .get(k)
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("{}: regroup manifest header has no {k}", path.display()))
            .and_then(|s| Uuid::parse_str(s).with_context(|| k.to_string()))
    };
    let operator = uuid_of("operator")?;
    let source = uuid_of("source_group_id")?;
    let unenforced = unenforced_reasons(conn, specs).await?;
    if !unenforced.is_empty() {
        bail!(
            "row security is not an enforced boundary on {unenforced:?}; a regroup reversal \
             checks readability by group and refuses without it"
        );
    }
    let details = json!({
        "tool": "epigraph-operator",
        "command": "reown-reverse (regroup manifest)",
        "ruling": m.header.get("ruling"),
        "operator_person": operator,
        "operator": operator_details(conn).await?,
        "source_group_id": source,
        "target_group_id": res.target,
        "manifest_path": path.display().to_string(),
        "manifest_sha256": sha256_file(path)?,
        "manifest_header_sha256": sha256_hex(serde_json::to_string(&m.header)?.as_bytes()),
        "planned": {
            "claims_in_manifest": res.claims.len(),
            "claims_moved_by_its_run": res.claim_posts.len(),
        },
    });
    writeln!(
        out,
        "REGROUP-MANIFEST\t{}\tsource_group={source}\ttarget_group={}\tclaims={}\tmoved={}\trows={}",
        path.display(),
        res.target,
        res.claims.len(),
        res.claim_posts.len(),
        res.rows.len()
    )?;
    let locks = batch_lock_tables(unkeyed);
    let nodes = node_types(conn).await?;
    let rc = RevCtx {
        specs,
        unkeyed: &locks,
        nodes: &nodes,
        res: &res,
        source,
        lock_timeout: &opts.lock_timeout,
    };
    let batches: Vec<&[(Uuid, Record)]> = res.claims.chunks(opts.batch_size).collect();
    let total = batches.len();
    let mut audited = false;
    let mut still_deferred: BTreeSet<String> = BTreeSet::new();
    for (i, batch) in batches.iter().enumerate() {
        let mut tx = sqlx::Connection::begin(&mut *conn).await?;
        let audit = (opts.apply && !audited).then_some((&details, operator));
        let r = reverse_batch(&mut tx, &rc, batch, audit).await;
        if opts.apply && r.is_ok() {
            tx.commit().await?;
        } else {
            tx.rollback().await?;
        }
        match r {
            Ok(o) => {
                writeln!(
                    out,
                    "BATCH {}/{total}\tOK\t{} claim(s) restored, {} edge(s) on an interim meet \
                     until a later batch",
                    i + 1,
                    o.claims_restored,
                    o.deferred_ids.len()
                )?;
                audited |= o.audit_written;
                report.claims_restored += o.claims_restored;
                for (t, k) in o.rows_restored {
                    *report.rows_restored.entry(t).or_default() += k;
                }
                report.held.extend(o.held);
                report.never_moved += o.never_moved;
                report.already += o.already;
                for e in &o.settled_ids {
                    still_deferred.remove(e);
                }
                still_deferred.extend(o.deferred_ids);
            }
            Err(e) => {
                writeln!(out, "BATCH {}/{total}\tROLLED BACK\t{e}", i + 1)?;
                report.batch_failures.push((i + 1, e.to_string()));
                if opts.apply {
                    writeln!(out, "STOPPED: no further batch was attempted")?;
                    return Ok(false);
                }
            }
        }
    }
    report.regroup_audit_rows += usize::from(audited);
    report.regroup_edges_deferred += still_deferred.len();
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn g(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    fn t(o: u128, v: &str, co: Option<u128>) -> Tenancy {
        Tenancy {
            owner: g(o),
            visibility: v.into(),
            co_owner: co.map(g),
        }
    }

    #[test]
    fn an_edge_accepts_the_meet_unless_it_drops_a_group() {
        let (s, d) = (g(1), g(2));
        // Both ends move: (S) -> (D).
        assert!(edge_accepts(
            &t(1, "group", None),
            &t(2, "group", None),
            s,
            d
        ));
        // The other end stays in S: (S) -> (D, co S), narrower than the image.
        assert!(edge_accepts(
            &t(1, "group", None),
            &t(2, "group", Some(1)),
            s,
            d
        ));
        // To a third group's claim: (S, co H) -> (D, co H).
        assert!(edge_accepts(
            &t(1, "group", Some(3)),
            &t(2, "group", Some(3)),
            s,
            d
        ));
        // A declared third-group co-owner the meet would drop: refused.
        assert!(!edge_accepts(
            &t(1, "group", Some(3)),
            &t(2, "group", None),
            s,
            d
        ));
        // A third group's edge: refused.
        assert!(!edge_accepts(
            &t(3, "group", None),
            &t(2, "group", None),
            s,
            d
        ));
        // Never public.
        assert!(!edge_accepts(
            &t(0, "public", None),
            &t(0, "public", None),
            s,
            d
        ));
    }

    #[test]
    fn readability_follows_owner_and_co_owner() {
        let only = |n: u128| -> BTreeSet<Uuid> { std::iter::once(g(n)).collect() };
        let both: BTreeSet<Uuid> = [g(1), g(2)].into();
        assert!(readable_by(&t(0, "public", None), &BTreeSet::new()));
        assert!(readable_by(&t(1, "group", None), &only(1)));
        assert!(!readable_by(&t(1, "group", None), &only(2)));
        assert!(!readable_by(&t(2, "group", Some(1)), &only(1)));
        assert!(!readable_by(&t(2, "group", Some(1)), &only(2)));
        assert!(readable_by(&t(2, "group", Some(1)), &both));
    }

    #[test]
    fn claims_classify_by_source_and_target() {
        let c = |o: u128, v: &str| ClaimRow {
            id: g(9),
            author: g(9),
            owner: g(o),
            visibility: v.into(),
        };
        assert_eq!(classify_claim(&c(1, "group"), g(1), g(2)), Ok(true));
        assert_eq!(classify_claim(&c(2, "group"), g(1), g(2)), Ok(false));
        assert_eq!(
            classify_claim(&c(0, "public"), g(1), g(2))
                .unwrap_err()
                .code(),
            "public-claim"
        );
        assert_eq!(
            classify_claim(&c(3, "group"), g(1), g(2))
                .unwrap_err()
                .code(),
            "not-in-source"
        );
    }

    #[test]
    fn apply_needs_a_ruling_a_reason_a_count_and_two_groups() {
        let mut o = Options {
            claims_file: PathBuf::from("x"),
            source: g(1),
            target: g(2),
            operator: g(3),
            manifest_out: PathBuf::from("m"),
            apply: true,
            confirm_count: Some(1),
            ruling: "r".into(),
            reason: "why".into(),
            batch_size: 10,
            lock_timeout: "5s".into(),
            sample: 0,
        };
        assert!(validate(&o).is_ok());
        o.reason = " ".into();
        assert!(validate(&o).unwrap_err().to_string().contains("--reason"));
        o.reason = "why".into();
        o.confirm_count = None;
        assert!(validate(&o)
            .unwrap_err()
            .to_string()
            .contains("--confirm-count"));
        o.apply = false;
        assert!(validate(&o).is_ok());
        o.target = g(1);
        assert!(validate(&o)
            .unwrap_err()
            .to_string()
            .contains("is the source group"));
    }
}
