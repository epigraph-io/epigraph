//! `restrict-claims`: move an explicit list of PUBLIC claims, and every row that
//! follows them, into a target GROUP with `visibility = 'group'`; and the exact
//! reversal of such a run (`reown-reverse` on a restrict manifest).
//!
//! This is the admin privatization act as an audited maintenance command: a
//! single operator, on the maintenance DSN, with a manifest written before the
//! first write and one `security_events` row per run. It is modelled on
//! `reown-claims` (batches, locks, manifest, census) and `hide-evidence` (a
//! narrowing, and the unenforced-policy guard); see those modules' docs for the
//! mechanisms shared here.
//!
//! # What is eligible
//!
//! A listed claim that is `public` and owned by the WORLD group. With
//! `--allow-non-world-owner`, any public claim. Every other listed claim is
//! HELD with its reason; a claim already `('group', target)` counts as done, so
//! a re-run resumes where the last one stopped.
//!
//! A claim is also HELD when a row it would carry is NOT public and NOT already
//! the target's: a derived row, a harvester fragment, or an edge touching it
//! that is `('group', H)` for some other group H (or co-owned). The tenancy
//! trigger would move that row into the target, i.e. make H's row readable by
//! the target's members. The one exception is PINNED evidence (migration 110):
//! the trigger leaves its owner and its `group` visibility exactly as they are.
//!
//! # What follows the claim (the cascade, unchanged)
//!
//! One `UPDATE claims SET visibility = 'group', owner_group_id = <target>`.
//! `epigraph_propagate_tenancy` then copies the claim's tenancy onto every row
//! of its `derived[]` tables (evidence, reasoning traces, BBAs, versions, ...,
//! other writers' rows included: a narrowing takes a writer-owned row into the
//! claim's group and clears its `writer_owned` flag, migration 114, except an
//! outsider's writer-owned challenge, which stays the challenger's, migration
//! 168), onto the
//! harvester fragments it is the provenance of, and re-meets every edge with
//! the claim as an endpoint (migration 122's edges arm).
//!
//! # Nodes stay; dependent and link rows narrow
//!
//! The rule is that edges (links) disappear, not the nodes they connect. Every
//! table this touches is classified in [`TABLE_ROLES`]: the claim's own
//! DEPENDENT rows and every LINK row (an edge, a cluster, frame or
//! neighbourhood assignment, an entity mention, a provenance link) narrow; the
//! node at the other end (another claim, its evidence, a frame, a cluster, an
//! entity) is never written. The one NODE the cascade itself reaches is a
//! harvester fragment (through its provenance link): the trigger narrows it,
//! and this tool puts it back in the same transaction unless every claim it is
//! the provenance of ends in the target. The census then proves no other row
//! of any table changed.
//!
//! # Edges with an evidence endpoint
//!
//! The trigger does not re-meet an edge whose endpoint is the claim's
//! EVIDENCE (claim->evidence, evidence->evidence). The rule is that an edge is
//! no more visible than its least visible endpoint, so this tool narrows each
//! such edge itself, in the same transaction, to the meet of its endpoints
//! (the trigger's own convention, so it ends exactly as a claim-endpoint edge
//! would), unless the edge is already at least as narrow, when it keeps its
//! tuple. Such an edge is recorded and reversed like every other row (and
//! deferred like one while another moved endpoint is not back). An edge of
//! ANOTHER group on that evidence holds the claim, as any widening row does.
//! Pinned evidence does not narrow, so its edges are not touched. Nothing else
//! is written; the plan reports how many evidence-endpoint edges there are.
//!
//! # The manifest records every row's full prior tenancy
//!
//! Written and `fsync`ed before the write that changes the rows it describes
//! (the run's header before the first batch; each batch's prior records under
//! the batch's locks, before its UPDATE). Per row: `owner_group_id`,
//! `visibility`, `co_owner_group_id` on edges, and `writer_owned` where the
//! table carries it. Then POST records, as `reown-claims` writes them.
//!
//! # Reversal (`reown-reverse --manifest <restrict manifest>`)
//!
//! A compare-and-swap per claim, as for a re-own, but restoring VISIBILITY too:
//!
//! * The claims UPDATE is the only statement that widens `group -> public`,
//!   which migration 074's `claims_block_widening` refuses unless
//!   `epigraph.allow_declassify = 'yes'`. The GUC is set transaction-locally
//!   immediately before that one statement and cleared immediately after it,
//!   and the statement's payload is only the claims whose RECORDED prior
//!   visibility is `public`.
//! * Every recorded derived row and fragment is put back on its OWN recorded
//!   tuple (writer-owned rows get their writer's group and their flag back).
//! * Every recorded EDGE is put back on its own recorded tuple, never on a meet
//!   recomputed from its endpoints (a declared `('group', H)` edge
//!   between public claims would come back PUBLIC). An edge is restored only
//!   once every endpoint this manifest moved is back on its recorded prior;
//!   until then it keeps the trigger's (narrow) meet and is counted as
//!   deferred, and the batch that restores its last moved endpoint restores it.
//!
//! # Enforcement
//!
//! Permissive policies are OR'ed. A permissive read policy on one of these
//! tables other than its `<table>_tenancy` (and migration 126's exact
//! `<table>_elevated_read`), or row security disabled on it, means a `group`
//! row there is still readable by every application session. The run detects
//! that per table, prints it, refuses `--apply` unless `--accept-unenforced`,
//! and then says UNENFORCED in its report and its audit row. The readability
//! invariant is per table: where enforced, an unstamped `epigraph_app` session
//! must lose EXACTLY the rows that went `public -> group`; where not, a subset.
//!
//! # Audit
//!
//! One `security_events` row per `--apply` run, written inside the FIRST batch
//! transaction that changes anything, so no committed change exists without
//! it and a failed audit insert rolls that batch back. It binds the run by the
//! SHA-256 of the manifest's header line and of the id file. One row per
//! reversed restrict manifest likewise, carrying the SHA-256 of the whole
//! manifest file. A dry run writes none.
//!
//! # What this cannot restore
//!
//! `claims.updated_at` (migration 001's unconditional trigger), as for a
//! re-own.

use super::manifest::{self, Record, Sink, Writer};
use super::reown::{counter_delta, counter_violations, BatchError};
use super::tables::{
    self, app_readable, fetch_attached, fetch_claims, xact_counters, Attached, ClaimRow, Kind,
    RowKey, Snapshot, TableSpec, Tenancy,
};
use super::{SEED, WORLD};
use anyhow::{anyhow, bail, Context};
use epigraph_db::{SecurityEventRepository, SecurityEventRow};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, Row};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// The `operation` a restrict manifest's header carries; `reown-reverse`
/// dispatches on it.
pub const OPERATION: &str = "restrict-claims";
/// `security_events.event_type` of an applied run.
pub const EVENT_APPLY: &str = "privatization.cli_restrict";
/// `security_events.event_type` of an applied reversal of one manifest.
pub const EVENT_REVERSE: &str = "privatization.cli_restrict_reverse";

/// What a table touched by a restriction IS, which decides whether its rows
/// narrow with the claim. The rule: the claim's own DEPENDENT rows and every
/// LINK row (an association of the claim with another node) narrow; a NODE
/// never narrows merely because it is connected to a narrowed claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// A row that belongs to the claim alone (keyed by its `claim_id`).
    Dependent,
    /// A row associating the claim with another node (an edge, a cluster or
    /// frame or neighbourhood assignment, an entity mention, a provenance
    /// link). The other node is not touched.
    Link,
    /// A node the cascade reaches through a link (a harvester fragment through
    /// its provenance): it narrows only when EVERY claim it is the provenance
    /// of is restricted into the target; otherwise it keeps its tuple.
    SharedNode,
}

/// The [`Role`] of every table `epigraph_propagate_tenancy` (plus `claims`,
/// fragments and edges) touches. A closed list: a table the cascade gains is
/// refused until it is classified here.
pub const TABLE_ROLES: &[(&str, Role)] = &[
    ("claims", Role::Dependent),
    ("evidence", Role::Dependent),
    ("reasoning_traces", Role::Dependent),
    ("mass_functions", Role::Dependent),
    ("ds_combined_beliefs", Role::Dependent),
    ("ds_bayesian_divergence", Role::Dependent),
    ("claim_versions", Role::Dependent),
    ("challenges", Role::Dependent),
    ("triples", Role::Dependent),
    ("experiment_triples", Role::Dependent),
    ("claim_signature_revocations", Role::Dependent),
    ("entity_mentions", Role::Link),
    ("experiment_entity_mentions", Role::Link),
    ("claim_frames", Role::Link),
    ("claim_clusters", Role::Link),
    ("claim_cluster_membership", Role::Link),
    ("claim_neighborhood_membership", Role::Link),
    ("harvester_claim_provenance", Role::Link),
    ("edges", Role::Link),
    ("harvester_fragments", Role::SharedNode),
];

/// The classification of `table`, if it has one.
#[must_use]
pub fn role_of(table: &str) -> Option<Role> {
    TABLE_ROLES
        .iter()
        .find(|(t, _)| *t == table)
        .map(|(_, r)| *r)
}

/// Everything `restrict-claims` was told.
#[derive(Clone, Debug)]
pub struct Options {
    pub claims_file: PathBuf,
    pub target: Uuid,
    pub operator: Uuid,
    pub manifest_out: PathBuf,
    pub apply: bool,
    pub confirm_count: Option<usize>,
    pub accept_unenforced: bool,
    pub allow_non_world_owner: bool,
    pub ruling: String,
    pub reason: String,
    pub batch_size: usize,
    pub max_batches: Option<usize>,
    pub lock_timeout: String,
    /// How many claims the dry-run sample lists row by row.
    pub sample: usize,
}

/// Refuse obviously bad options before connecting.
///
/// # Errors
/// A zero batch size or batch limit; under `--apply`, an empty ruling or
/// reason, or no `--confirm-count`.
pub fn validate(opts: &Options) -> anyhow::Result<()> {
    if opts.batch_size == 0 {
        bail!("--batch-size must be at least 1");
    }
    if opts.max_batches == Some(0) {
        bail!("--max-batches must be at least 1");
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

/// The full tenancy of one row as this tool records and restores it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RowState {
    pub tenancy: Tenancy,
    /// `Some` only on a table that carries `writer_owned`.
    pub writer_owned: Option<bool>,
}

impl RowState {
    fn of(a: &Attached) -> Self {
        Self {
            tenancy: a.tenancy.clone(),
            writer_owned: a.writer_owned,
        }
    }

    fn of_record(r: &Record) -> Self {
        Self {
            tenancy: Tenancy {
                owner: r.owner_group_id,
                visibility: r.visibility.clone(),
                co_owner: r.co_owner_group_id.flatten(),
            },
            writer_owned: r.writer_owned,
        }
    }
}

impl fmt::Display for RowState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({}, {}", self.tenancy.owner, self.tenancy.visibility)?;
        if let Some(co) = self.tenancy.co_owner {
            write!(f, ", co-owner {co}")?;
        }
        if let Some(w) = self.writer_owned {
            write!(f, ", writer_owned={w}")?;
        }
        write!(f, ")")
    }
}

/// Why a listed claim is not moved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Hold {
    NotFound,
    NotPublic {
        visibility: String,
        owner: Uuid,
    },
    OwnerNotWorld {
        owner: Uuid,
    },
    Sealed,
    WouldWiden {
        table: String,
        id: String,
        from: String,
        to: String,
    },
    ChangedSinceRecorded {
        table: String,
        id: String,
    },
}

impl fmt::Display for Hold {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => write!(f, "not found"),
            Self::NotPublic { visibility, owner } => write!(
                f,
                "claim is ({owner}, {visibility}), not public (a restriction narrows public \
                 claims only)"
            ),
            Self::OwnerNotWorld { owner } => write!(
                f,
                "public but owned by group {owner}, not the world group (only the world-owned \
                 corpus moves unless --allow-non-world-owner)"
            ),
            Self::Sealed => write!(f, "the claim is sealed (claim_encryption)"),
            Self::WouldWiden {
                table,
                id,
                from,
                to,
            } => write!(
                f,
                "{table} {id} is {from} and the cascade would make it {to}: readable by someone \
                 who cannot read it now (another group's row moved into the target)"
            ),
            Self::ChangedSinceRecorded { table, id } => write!(
                f,
                "{table} {id} changed since this run recorded it (another writer); its recorded \
                 prior would be stale, so the claim is not moved in this run"
            ),
        }
    }
}

/// The claim-level classification (no attached rows read).
fn classify_claim(c: &ClaimRow, target: Uuid, allow_non_world: bool) -> Result<bool, Hold> {
    if c.owner == target && c.visibility == "group" {
        return Ok(false);
    }
    if c.visibility != "public" {
        return Err(Hold::NotPublic {
            visibility: c.visibility.clone(),
            owner: c.owner,
        });
    }
    if c.owner != WORLD && !allow_non_world {
        return Err(Hold::OwnerNotWorld { owner: c.owner });
    }
    Ok(true)
}

async fn sealed_of(conn: &mut PgConnection, ids: &[Uuid]) -> anyhow::Result<BTreeSet<Uuid>> {
    let v: Vec<Uuid> = sqlx::query_scalar(
        "SELECT DISTINCT claim_id FROM claim_encryption WHERE claim_id = ANY($1)",
    )
    .bind(ids)
    .fetch_all(&mut *conn)
    .await
    .context("reading claim_encryption")?;
    Ok(v.into_iter().collect())
}

/// The claim-level pass over the whole list, in chunks, holding nothing.
#[derive(Default, Debug)]
pub struct Pre {
    pub eligible: Vec<Uuid>,
    pub already: Vec<Uuid>,
    pub held: Vec<(Uuid, Hold)>,
}

async fn pre_pass(
    conn: &mut PgConnection,
    ids: &[Uuid],
    target: Uuid,
    allow_non_world: bool,
) -> anyhow::Result<Pre> {
    let mut out = Pre::default();
    for chunk in ids.chunks(5000) {
        let rows = fetch_claims(conn, chunk, false).await?;
        let sealed = sealed_of(conn, chunk).await?;
        let by_id: BTreeMap<Uuid, &ClaimRow> = rows.iter().map(|r| (r.id, r)).collect();
        for id in chunk {
            let Some(c) = by_id.get(id) else {
                out.held.push((*id, Hold::NotFound));
                continue;
            };
            match classify_claim(c, target, allow_non_world) {
                Ok(false) => out.already.push(*id),
                Ok(true) if sealed.contains(id) => out.held.push((*id, Hold::Sealed)),
                Ok(true) => out.eligible.push(*id),
                Err(h) => out.held.push((*id, h)),
            }
        }
    }
    Ok(out)
}

/// The target group: it exists, is `active`, is neither the world nor the
/// seed group, and `operator` is a live admin of it (the D4 "admin role in the
/// target group" condition). Returns its kind.
///
/// # Errors
/// Any of those does not hold.
pub async fn check_target(
    conn: &mut PgConnection,
    target: Uuid,
    operator: Uuid,
) -> anyhow::Result<String> {
    if target == WORLD || target == SEED {
        bail!("--target-group {target} is the world or seed group; refusing");
    }
    let row: Option<(String, String)> =
        sqlx::query_as("SELECT kind::text, status::text FROM groups WHERE id = $1")
            .bind(target)
            .fetch_optional(&mut *conn)
            .await?;
    let Some((kind, status)) = row else {
        bail!("--target-group {target}: no such group; refusing. Nothing was written.");
    };
    if status != "active" {
        bail!("--target-group {target} has status {status:?}, not active; refusing");
    }
    if kind == "world" || kind == "seed" {
        bail!("--target-group {target} is kind {kind}; refusing");
    }
    let admin: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM group_memberships \
                         WHERE group_id = $1 AND agent_id = $2 AND role = 'admin' \
                           AND revoked_at IS NULL)",
    )
    .bind(target)
    .bind(operator)
    .fetch_one(&mut *conn)
    .await?;
    if !admin {
        bail!(
            "--operator {operator} is not a live admin of --target-group {target}; refusing \
             (a restriction moves claims only into a group the operator administers)"
        );
    }
    Ok(kind)
}

/// The reason row security is not an enforced boundary on a table.
pub const RLS_DISABLED: &str = "ROW LEVEL SECURITY DISABLED";

/// Per table of `specs`: why a `group` row there is NOT hidden from an
/// ordinary application session. Empty when every table is enforced.
///
/// A permissive policy that applies to reads (`cmd` ALL or SELECT) other than
/// the table's own `<table>_tenancy` is OR'ed with it, so one whose USING
/// admits a group row defeats the restriction. Migration 126's
/// `<table>_elevated_read` is not a reason in its exact 126 form (`TO
/// epigraph_app`, `USING ((SELECT epigraph_is_elevated()))`, no WITH CHECK):
/// it admits an ELEVATED session only. Row security disabled on the table is a
/// reason (no policy is consulted then).
///
/// # Errors
/// A catalog read fails.
pub async fn unenforced_reasons(
    conn: &mut PgConnection,
    specs: &[TableSpec],
) -> anyhow::Result<BTreeMap<String, Vec<String>>> {
    let names: Vec<String> = specs.iter().map(|s| s.name.clone()).collect();
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT tablename::text, policyname::text FROM pg_policies \
          WHERE schemaname = 'public' AND tablename = ANY($1) \
            AND permissive = 'PERMISSIVE' AND cmd IN ('ALL', 'SELECT') \
            AND policyname <> tablename || '_tenancy' \
            AND NOT (policyname = tablename || '_elevated_read' \
                     AND cmd = 'SELECT' \
                     AND roles = ARRAY['epigraph_app']::name[] \
                     AND qual = '( SELECT epigraph_is_elevated() AS epigraph_is_elevated)' \
                     AND with_check IS NULL) \
          ORDER BY 1, 2",
    )
    .bind(&names)
    .fetch_all(&mut *conn)
    .await
    .context("reading pg_policies")?;
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (t, p) in rows {
        out.entry(t).or_default().push(p);
    }
    let disabled: Vec<String> = sqlx::query_scalar(
        "SELECT c.relname::text FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
          WHERE n.nspname = 'public' AND c.relname = ANY($1) AND NOT c.relrowsecurity \
          ORDER BY 1",
    )
    .bind(&names)
    .fetch_all(&mut *conn)
    .await?;
    for t in disabled {
        out.entry(t).or_default().push(RLS_DISABLED.to_string());
    }
    Ok(out)
}

fn describe_unenforced(r: &BTreeMap<String, Vec<String>>) -> String {
    r.iter()
        .map(|(t, ps)| format!("{t}: {}", ps.join(", ")))
        .collect::<Vec<_>>()
        .join("; ")
}

/// Pinned evidence among `ids` (migration 110).
async fn pinned_of(conn: &mut PgConnection, ids: &[Uuid]) -> anyhow::Result<BTreeSet<String>> {
    if ids.is_empty() {
        return Ok(BTreeSet::new());
    }
    let v: Vec<Uuid> = sqlx::query_scalar(
        "SELECT evidence_id FROM evidence_visibility_pins WHERE evidence_id = ANY($1)",
    )
    .bind(ids)
    .fetch_all(&mut *conn)
    .await
    .context("reading evidence_visibility_pins")?;
    Ok(v.into_iter().map(|u| u.to_string()).collect())
}

fn evidence_ids(s: &Snapshot) -> Vec<Uuid> {
    s.keys()
        .filter(|(t, _)| t == "evidence")
        .filter_map(|(_, pk)| Uuid::parse_str(pk).ok())
        .collect()
}

/// One edge's endpoints, and each endpoint's CURRENT `(owner, visibility)`
/// under `epigraph_node_tenancy` (the function the trigger's meet agrees with).
#[derive(Clone, Debug)]
pub struct EdgeEnds {
    pub source: (Uuid, String),
    pub target: (Uuid, String),
    pub source_state: (Uuid, String),
    pub target_state: (Uuid, String),
}

async fn edge_ends(
    conn: &mut PgConnection,
    ids: &[Uuid],
) -> anyhow::Result<BTreeMap<String, EdgeEnds>> {
    if ids.is_empty() {
        return Ok(BTreeMap::new());
    }
    let rows = sqlx::query(
        "SELECT e.id::text, e.source_id, e.source_type::text, s.g, s.v::text, \
                e.target_id, e.target_type::text, t.g, t.v::text \
           FROM edges e \
           CROSS JOIN LATERAL public.epigraph_node_tenancy(e.source_id, e.source_type) s \
           CROSS JOIN LATERAL public.epigraph_node_tenancy(e.target_id, e.target_type) t \
          WHERE e.id = ANY($1)",
    )
    .bind(ids)
    .fetch_all(&mut *conn)
    .await
    .context("reading edge endpoints")?;
    Ok(rows
        .iter()
        .map(|r| {
            (
                r.get::<String, _>(0),
                EdgeEnds {
                    source: (r.get(1), r.get(2)),
                    source_state: (r.get(3), r.get(4)),
                    target: (r.get(5), r.get(6)),
                    target_state: (r.get(7), r.get(8)),
                },
            )
        })
        .collect())
}

/// Migration 122's edges meet, as `epigraph_propagate_tenancy` computes it
/// from the endpoints' tenancy. `None` when the meet is public: the trigger
/// then leaves the edge as it is.
#[must_use]
pub fn meet(s: &(Uuid, String), t: &(Uuid, String)) -> Option<Tenancy> {
    let (sp, tp) = (s.1 == "public", t.1 == "public");
    if sp && tp {
        return None;
    }
    let owner = if sp { t.0 } else { s.0 };
    let co = (s.1 == "group" && t.1 == "group" && s.0 != t.0).then_some(t.0);
    Some(Tenancy {
        owner,
        visibility: "group".into(),
        co_owner: co,
    })
}

/// The groups a reader must belong to ALL of to read a row: none for a public
/// row, the owner (and the co-owner) for a group row.
fn reader_groups(t: &Tenancy) -> BTreeSet<Uuid> {
    if t.visibility == "public" {
        BTreeSet::new()
    } else {
        std::iter::once(t.owner).chain(t.co_owner).collect()
    }
}

/// `after` is readable by no one who cannot read `before`: its required
/// groups include all of `before`'s.
#[must_use]
pub fn narrows(before: &Tenancy, after: &Tenancy) -> bool {
    reader_groups(after).is_superset(&reader_groups(before))
}

/// The tuple an edge takes when its endpoints are now `ends`, under the rule
/// "an edge is no more visible than its least visible endpoint": the meet of
/// its endpoints (migration 122's convention, so an evidence-endpoint edge
/// ends exactly as a claim-endpoint edge would), unless the edge is ALREADY at
/// least as narrow as that meet, in which case it keeps its tuple. The result
/// is never wider than `prior` unless `prior` and the meet are incomparable
/// (another group's edge), which the caller holds before writing.
#[must_use]
pub fn narrowed(prior: &Tenancy, ends_meet: Option<Tenancy>) -> Tenancy {
    match ends_meet {
        None => prior.clone(),
        Some(m) if narrows(&m, prior) => prior.clone(),
        Some(m) => m,
    }
}

/// Edges with an EVIDENCE endpoint among `ev_claim`'s keys (evidence id ->
/// its claim), as attached rows of that claim. Edges whose key is in `skip`
/// are left out (the claim-endpoint edges `fetch_attached` already returned).
/// `claims` is every claim of `ev_claim` the edge touches through an evidence
/// endpoint, plus any claim endpoint in `in_set`; `neighbours` is any claim
/// endpoint outside `in_set`.
///
/// Each row's `writer` is its SOURCE claim's author
/// ([`super::tables::EDGE_WRITER_SQL`], ruling R-49), so an evidence-sourced
/// edge is unattributed (`None`). Nothing in `restrict-claims` decides on that
/// writer (it narrows an edge by its endpoints' meet, [`narrowed`]; only
/// `reown-claims --derived keep-writer` reads `Attached::writer`); public for
/// the R-49 reader test (`tests/edge_author_not_signer.rs`).
///
/// # Errors
/// When the read fails.
pub async fn fetch_evidence_edges(
    conn: &mut PgConnection,
    ev_claim: &BTreeMap<Uuid, Uuid>,
    in_set: &BTreeSet<Uuid>,
    skip: &BTreeSet<RowKey>,
) -> anyhow::Result<Snapshot> {
    let mut out = Snapshot::new();
    if ev_claim.is_empty() {
        return Ok(out);
    }
    let ev: Vec<Uuid> = ev_claim.keys().copied().collect();
    // The writer is the source claim's author (`tables::EDGE_WRITER_SQL`,
    // ruling R-49), never the attesting `signer_id`.
    let sql = format!(
        "SELECT e.id, e.source_id, e.source_type::text, e.target_id, e.target_type::text, \
                e.owner_group_id, e.visibility::text, e.co_owner_group_id, \
                {} \
           FROM edges e \
          WHERE (e.source_type = 'evidence' AND e.source_id = ANY($1)) \
             OR (e.target_type = 'evidence' AND e.target_id = ANY($1))",
        super::tables::EDGE_WRITER_SQL
    );
    let rows = sqlx::query(&sql)
        .bind(&ev)
        .fetch_all(&mut *conn)
        .await
        .context("reading edges with an evidence endpoint")?;
    for r in &rows {
        let id: Uuid = r.get(0);
        let key = ("edges".to_string(), id.to_string());
        if skip.contains(&key) {
            continue;
        }
        let mut claims = BTreeSet::new();
        let mut neighbours = BTreeSet::new();
        for (nid, ty) in [
            (r.get::<Uuid, _>(1), r.get::<String, _>(2)),
            (r.get::<Uuid, _>(3), r.get::<String, _>(4)),
        ] {
            match ty.as_str() {
                "evidence" => {
                    if let Some(c) = ev_claim.get(&nid) {
                        claims.insert(*c);
                    }
                }
                "claim" if in_set.contains(&nid) => {
                    claims.insert(nid);
                }
                "claim" => {
                    neighbours.insert(nid);
                }
                _ => {}
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
                    owner: r.get(5),
                    visibility: r.get(6),
                    co_owner: r.get(7),
                },
                writer: r.get(8),
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

/// The current state of exactly `keys`: what `fetch_attached` returns for
/// `claims`, plus any edge key it does not return (an evidence-endpoint edge),
/// read by id. A key that no longer resolves is absent.
async fn states_of(
    conn: &mut PgConnection,
    specs: &[TableSpec],
    claims: &[Uuid],
    keys: &BTreeSet<RowKey>,
) -> anyhow::Result<BTreeMap<RowKey, RowState>> {
    let fresh = fetch_attached(conn, specs, claims).await?;
    let mut out: BTreeMap<RowKey, RowState> = keys
        .iter()
        .filter_map(|k| fresh.get(k).map(|a| (k.clone(), RowState::of(a))))
        .collect();
    let missing: Vec<Uuid> = keys
        .iter()
        .filter(|k| k.0 == "edges" && !out.contains_key(*k))
        .filter_map(|k| Uuid::parse_str(&k.1).ok())
        .collect();
    if !missing.is_empty() {
        let rows: Vec<(Uuid, Uuid, String, Option<Uuid>)> = sqlx::query_as(
            "SELECT id, owner_group_id, visibility::text, co_owner_group_id FROM edges \
              WHERE id = ANY($1)",
        )
        .bind(&missing)
        .fetch_all(&mut *conn)
        .await?;
        for (id, o, v, co) in rows {
            out.insert(
                ("edges".to_string(), id.to_string()),
                RowState {
                    tenancy: Tenancy {
                        owner: o,
                        visibility: v,
                        co_owner: co,
                    },
                    writer_owned: None,
                },
            );
        }
    }
    Ok(out)
}

fn edge_ids(keys: &BTreeSet<RowKey>) -> Vec<Uuid> {
    keys.iter()
        .filter(|(t, _)| t == "edges")
        .filter_map(|(_, pk)| Uuid::parse_str(pk).ok())
        .collect()
}

fn record_of(spec: &TableSpec, key: &RowKey, claim: Uuid, st: &RowState, after: bool) -> Record {
    Record {
        table: key.0.clone(),
        id: spec.id_json(&key.1),
        owner_group_id: st.tenancy.owner,
        visibility: st.tenancy.visibility.clone(),
        co_owner_group_id: (spec.kind == Kind::Edges).then_some(st.tenancy.co_owner),
        claim_id: claim,
        hidden: false,
        after,
        neighbour: false,
        writer_owned: st.writer_owned,
    }
}

fn claim_record(c: &ClaimRow, after: bool, neighbour: bool) -> Record {
    Record {
        table: "claims".into(),
        id: json!(c.id.to_string()),
        owner_group_id: c.owner,
        visibility: c.visibility.clone(),
        co_owner_group_id: None,
        claim_id: c.id,
        hidden: false,
        after,
        neighbour,
        writer_owned: None,
    }
}

fn spec_of<'a>(specs: &'a [TableSpec], table: &str) -> &'a TableSpec {
    tables::spec(specs, table).expect("attached rows come only from specs")
}

/// Write each row's full recorded tuple (owner, visibility, co-owner on edges,
/// and `writer_owned` where the table has it). Only rows that differ are
/// touched, so the count is exactly the rows changed.
async fn write_rows(
    conn: &mut PgConnection,
    spec: &TableSpec,
    claims: &[Uuid],
    rows: &[(String, RowState)],
) -> anyhow::Result<u64> {
    if rows.is_empty() {
        return Ok(0);
    }
    if !spec.writer_owned {
        let plain: Vec<(String, Tenancy)> = rows
            .iter()
            .map(|(pk, st)| (pk.clone(), st.tenancy.clone()))
            .collect();
        return tables::write_tenancy(conn, spec, claims, &plain).await;
    }
    if spec.kind != Kind::Derived {
        bail!("{}: writer_owned on a non-derived table", spec.name);
    }
    let payload: Vec<Value> = rows
        .iter()
        .map(|(pk, st)| {
            json!({"pk": pk, "o": st.tenancy.owner, "v": st.tenancy.visibility,
                   "w": st.writer_owned})
        })
        .collect();
    let sql = format!(
        "UPDATE \"{name}\" AS t SET owner_group_id = m.o, visibility = m.v, \
                writer_owned = COALESCE(m.w, t.writer_owned) \
           FROM jsonb_to_recordset($1::jsonb) AS m(pk text, o uuid, v text, w boolean) \
          WHERE t.claim_id = ANY($2) AND {pk} = m.pk \
            AND (t.owner_group_id, t.visibility::text, t.writer_owned) \
                IS DISTINCT FROM (m.o, m.v, COALESCE(m.w, t.writer_owned))",
        name = spec.name,
        pk = spec.pk_expr("t"),
    );
    let res = sqlx::query(&sql)
        .bind(Value::Array(payload))
        .bind(claims)
        .execute(&mut *conn)
        .await
        .with_context(|| format!("writing tenancy on {}", spec.name))?;
    Ok(res.rows_affected())
}

/// The readability check, per table: `lost` must equal `expect_lost` on an
/// enforced table and be a subset of it on an unenforced one; `gained` the same
/// against `expect_gained`. Returns one message per violation.
fn readability_violations(
    before: &BTreeSet<RowKey>,
    after: &BTreeSet<RowKey>,
    expect_lost: &BTreeSet<RowKey>,
    expect_gained: &BTreeSet<RowKey>,
    unenforced: &BTreeMap<String, Vec<String>>,
) -> Vec<String> {
    let lost: BTreeSet<RowKey> = before.difference(after).cloned().collect();
    let gained: BTreeSet<RowKey> = after.difference(before).cloned().collect();
    let mut v = Vec::new();
    let tables: BTreeSet<&String> = lost
        .iter()
        .chain(gained.iter())
        .chain(expect_lost.iter())
        .chain(expect_gained.iter())
        .map(|(t, _)| t)
        .collect();
    for t in tables {
        let sel = |s: &BTreeSet<RowKey>| -> BTreeSet<RowKey> {
            s.iter().filter(|(x, _)| x == t).cloned().collect()
        };
        let (l, g, el, eg) = (
            sel(&lost),
            sel(&gained),
            sel(expect_lost),
            sel(expect_gained),
        );
        if unenforced.contains_key(t) {
            if !l.is_subset(&el) {
                v.push(format!(
                    "{t}: an unstamped epigraph_app session lost rows that did not narrow: {:?}",
                    l.difference(&el).collect::<Vec<_>>()
                ));
            }
            if !g.is_subset(&eg) {
                v.push(format!(
                    "{t}: an unstamped epigraph_app session gained rows that did not widen: {:?}",
                    g.difference(&eg).collect::<Vec<_>>()
                ));
            }
        } else {
            if l != el {
                v.push(format!(
                    "{t}: an unstamped epigraph_app session lost {l:?}; the rows that narrowed \
                     are {el:?}"
                ));
            }
            if g != eg {
                v.push(format!(
                    "{t}: an unstamped epigraph_app session gained {g:?}; the rows that widened \
                     are {eg:?}"
                ));
            }
        }
    }
    v
}

/// The operator process and connection, for an audit row.
pub(super) async fn operator_details(conn: &mut PgConnection) -> anyhow::Result<Value> {
    let session_user: String = sqlx::query_scalar("SELECT session_user::text")
        .fetch_one(&mut *conn)
        .await?;
    let op = super::client_scope::Operator::of_this_process(session_user);
    let (client_addr, application_name) = SecurityEventRepository::connection_origin_conn(conn)
        .await
        .context("reading the connection's origin")?;
    Ok(json!({
        "session_user": op.session_user,
        "os_user": op.os_user,
        "os_user_source": "environment (SUDO_USER, USER, LOGNAME): advisory, settable by the \
                           caller",
        "process_uid": op.process_uid,
        "process_user": op.process_user,
        "login_uid": op.login_uid,
        "login_user": op.login_user,
        "client_addr": client_addr,
        "application_name": application_name,
    }))
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

/// Lower-case hex SHA-256.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// SHA-256 of a file, streamed.
///
/// # Errors
/// The file cannot be read.
pub fn sha256_file(path: &Path) -> anyhow::Result<String> {
    use std::io::Read;
    let mut f = std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex::encode(h.finalize()))
}

/// The last state this run recorded or left each row in (see
/// `reown::Known`): a row this run already recorded that another writer has
/// changed since HOLDS its claims, because its recorded prior is stale.
#[derive(Default, Debug)]
struct Known {
    rows: BTreeMap<RowKey, RowState>,
}

/// Fixed inputs to every apply batch.
#[derive(Clone, Copy)]
struct Ctx<'a> {
    specs: &'a [TableSpec],
    unkeyed: &'a [String],
    target: Uuid,
    allow_non_world: bool,
    lock_timeout: &'a str,
    unenforced: &'a BTreeMap<String, Vec<String>>,
    sample: usize,
}

/// What one apply batch did.
#[derive(Default, Debug)]
pub struct BatchOutcome {
    pub claims_moved: usize,
    pub moved_by_table: BTreeMap<String, usize>,
    pub held: Vec<(Uuid, Hold)>,
    pub already: usize,
    pub newly_recorded: usize,
    pub post_rows: BTreeMap<RowKey, RowState>,
    pub sample: Vec<String>,
    pub audit_written: bool,
}

/// One apply batch inside the caller's transaction. Does NOT commit. With
/// `audit = Some(details)`, writes the run's audit row in this transaction if
/// the batch moves at least one claim.
#[allow(clippy::too_many_lines)]
/// A `challenges` row an OUTSIDER wrote on a public claim (migration 168,
/// ruling R-CH1): owned by the challenger's group and never moved by the
/// tenancy cascade, unlike 114's writer-owned evidence, BBAs and traces, which
/// a narrowing hands to the claim. The prediction must say so, or the batch's
/// own invariants roll back every restrict of a claim that carries one. Its
/// READABILITY does follow the claim (168's `challenges_claim_readable`,
/// ruling R-CH1b), so the readability invariant expects it lost on apply and
/// regained on reverse.
fn is_outsider_challenge(table: &str, writer_owned: Option<bool>) -> bool {
    table == "challenges" && writer_owned == Some(true)
}

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
    let sealed = sealed_of(conn, batch).await?;

    // ---- claims, re-classified under the lock ----
    let by_id: BTreeMap<Uuid, &ClaimRow> = locked.iter().map(|r| (r.id, r)).collect();
    let mut cands: Vec<ClaimRow> = Vec::new();
    for id in batch {
        let Some(c) = by_id.get(id) else {
            out.held.push((*id, Hold::NotFound));
            continue;
        };
        match classify_claim(c, ctx.target, ctx.allow_non_world) {
            Ok(false) => out.already += 1,
            Ok(true) if sealed.contains(id) => out.held.push((*id, Hold::Sealed)),
            Ok(true) => cands.push((*c).clone()),
            Err(h) => out.held.push((*id, h)),
        }
    }
    if cands.is_empty() {
        return Ok(out);
    }
    let cand_ids: Vec<Uuid> = cands.iter().map(|c| c.id).collect();
    let cand_set: BTreeSet<Uuid> = cand_ids.iter().copied().collect();
    let mut attached = fetch_attached(conn, ctx.specs, &cand_ids).await?;
    let pinned = pinned_of(conn, &evidence_ids(&attached)).await?;
    // Edges with an EVIDENCE endpoint that narrows (the candidates' unpinned
    // evidence): the tenancy trigger does not re-meet them, so this tool
    // narrows them itself (an edge is no more visible than its least visible
    // endpoint) and records them like every other row.
    let ev_claim: BTreeMap<Uuid, Uuid> = attached
        .iter()
        .filter(|(k, _)| k.0 == "evidence" && !pinned.contains(&k.1))
        .filter_map(|(k, a)| Uuid::parse_str(&k.1).ok().map(|id| (id, a.claim)))
        .collect();
    let claim_edge_keys: BTreeSet<RowKey> = attached.keys().cloned().collect();
    let ev_edges = fetch_evidence_edges(conn, &ev_claim, &cand_set, &claim_edge_keys).await?;
    let ev_edge_keys: BTreeSet<RowKey> = ev_edges.keys().cloned().collect();
    attached.extend(ev_edges);

    // ---- rows the cascade would WIDEN, or that went stale ----
    // Each row's state after the move is predicted as the trigger computes it:
    // a derived row or fragment takes ('group', target) unless it is pinned
    // evidence (unchanged); an edge takes the meet of its endpoints with every
    // candidate claim (and its unpinned evidence) on ('group', target). A row
    // whose predicted reader set is not a SUBSET of its current one (another
    // group's row moved into the target) holds every candidate it hangs off.
    let attached_keys: BTreeSet<RowKey> = attached.keys().cloned().collect();
    let pre_ends = edge_ends(conn, &edge_ids(&attached_keys)).await?;
    let moves_to_target = |(id, ty): &(Uuid, String)| -> bool {
        match ty.as_str() {
            "claim" => cand_set.contains(id),
            "evidence" => {
                let pk = id.to_string();
                attached.contains_key(&("evidence".to_string(), pk.clone()))
                    && !pinned.contains(&pk)
            }
            _ => false,
        }
    };
    let in_target = (ctx.target, "group".to_string());
    // A fragment is a NODE (Role::SharedNode): it narrows only if every claim
    // it is the provenance of ends in the target (a candidate, or a claim
    // already there). Otherwise it keeps its tuple.
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
        .filter(|c| c.owner == ctx.target && c.visibility == "group")
        .map(|c| c.id)
        .collect();
    let fragment_narrows = |a: &Attached, moving: &BTreeSet<Uuid>| -> bool {
        a.claims.iter().all(|c| moving.contains(c))
            && a.neighbours.iter().all(|c| already_in_target.contains(c))
    };
    let mut hold: BTreeMap<Uuid, Hold> = BTreeMap::new();
    for (k, a) in &attached {
        let predicted = match spec_of(ctx.specs, &k.0).kind {
            Kind::Edges => pre_ends.get(&k.1).map(|e| {
                let s = if moves_to_target(&e.source) {
                    in_target.clone()
                } else {
                    e.source_state.clone()
                };
                let t = if moves_to_target(&e.target) {
                    in_target.clone()
                } else {
                    e.target_state.clone()
                };
                if ev_edge_keys.contains(k) {
                    narrowed(&a.tenancy, meet(&s, &t))
                } else {
                    meet(&s, &t).unwrap_or_else(|| a.tenancy.clone())
                }
            }),
            _ if k.0 == "evidence" && pinned.contains(&k.1) => Some(a.tenancy.clone()),
            // Migration 168 (R-CH1): an outsider's challenge is the
            // challenger's and the cascade never moves it.
            _ if is_outsider_challenge(&k.0, a.writer_owned) => Some(a.tenancy.clone()),
            Kind::Fragments if !fragment_narrows(a, &cand_set) => Some(a.tenancy.clone()),
            _ => Some(Tenancy {
                owner: ctx.target,
                visibility: "group".into(),
                co_owner: None,
            }),
        };
        let why = match predicted {
            None => Some(Hold::WouldWiden {
                table: k.0.clone(),
                id: k.1.clone(),
                from: RowState::of(a).to_string(),
                to: "(edge endpoints unreadable)".into(),
            }),
            Some(p) if !narrows(&a.tenancy, &p) => Some(Hold::WouldWiden {
                table: k.0.clone(),
                id: k.1.clone(),
                from: RowState::of(a).to_string(),
                to: RowState {
                    tenancy: p,
                    writer_owned: None,
                }
                .to_string(),
            }),
            Some(_) if known.rows.get(k).is_some_and(|st| *st != RowState::of(a)) => {
                Some(Hold::ChangedSinceRecorded {
                    table: k.0.clone(),
                    id: k.1.clone(),
                })
            }
            Some(_) => None,
        };
        if let Some(h) = why {
            for c in a.claims.intersection(&cand_set) {
                hold.entry(*c).or_insert_with(|| h.clone());
            }
        }
    }
    let eligible: Vec<ClaimRow> = cands
        .into_iter()
        .filter(|c| !hold.contains_key(&c.id))
        .collect();
    out.held.extend(hold);
    if eligible.is_empty() {
        return Ok(out);
    }
    let claim_ids: Vec<Uuid> = eligible.iter().map(|c| c.id).collect();
    let moving: BTreeSet<Uuid> = claim_ids.iter().copied().collect();
    let s0: Snapshot = attached
        .into_iter()
        .filter(|(_, a)| a.claims.iter().any(|c| moving.contains(c)))
        .collect();
    let keys: BTreeSet<RowKey> = s0.keys().cloned().collect();
    let kept_nodes: BTreeSet<RowKey> = s0
        .iter()
        .filter(|(_, a)| a.table == "harvester_fragments" && !fragment_narrows(a, &moving))
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
    out.newly_recorded = sink.record(&prior)?;

    let readable_before = app_readable(conn, ctx.specs, &claim_ids, &keys).await?;
    let counters_before = xact_counters(conn).await?;

    let moved = sqlx::query(
        "UPDATE claims SET visibility = 'group', owner_group_id = $2 \
          WHERE id = ANY($1) AND visibility = 'public' AND owner_group_id IS DISTINCT FROM $2",
    )
    .bind(&claim_ids)
    .bind(ctx.target)
    .execute(&mut *conn)
    .await
    .context("UPDATE claims")?
    .rows_affected();

    // NODES the cascade reached and must not narrow: back on their tuple.
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

    // The evidence-endpoint edges: the narrowest of their endpoints NOW.
    let ev_keys_moving: BTreeSet<RowKey> = keys.intersection(&ev_edge_keys).cloned().collect();
    let ends_ev = edge_ends(conn, &edge_ids(&ev_keys_moving)).await?;
    let mut ev_writes: Vec<(String, RowState)> = Vec::new();
    for k in &ev_keys_moving {
        let (Some(a), Some(e)) = (s0.get(k), ends_ev.get(&k.1)) else {
            continue;
        };
        let want = narrowed(&a.tenancy, meet(&e.source_state, &e.target_state));
        if want != a.tenancy {
            ev_writes.push((
                k.1.clone(),
                RowState {
                    tenancy: want,
                    writer_owned: None,
                },
            ));
        }
    }
    write_rows(conn, spec_of(ctx.specs, "edges"), &claim_ids, &ev_writes).await?;

    let s2 = states_of(conn, ctx.specs, &claim_ids, &keys).await?;
    let after_claims = fetch_claims(conn, &claim_ids, false).await?;
    let ends = edge_ends(conn, &edge_ids(&keys)).await?;
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
    // (1) every moved claim is ('group', target).
    for c in &after_claims {
        if c.owner != ctx.target || c.visibility != "group" {
            v.push(format!(
                "claim {} is ({}, {}), not ('group', {})",
                c.id, c.owner, c.visibility, ctx.target
            ));
        }
    }
    // (2) derived rows and fragments follow the claim, pinned evidence is
    // unchanged; (3) every edge is the meet of its endpoints now.
    let mut planned: BTreeMap<String, usize> = BTreeMap::new();
    let mut actual: BTreeMap<String, usize> = BTreeMap::new();
    let mut expect_lost: BTreeSet<RowKey> = eligible
        .iter()
        .map(|c| ("claims".to_string(), c.id.to_string()))
        .collect();
    for (k, a) in &s0 {
        let spec = spec_of(ctx.specs, &k.0);
        let before = RowState::of(a);
        let want = match spec.kind {
            Kind::Edges if ev_edge_keys.contains(k) => match ends.get(&k.1) {
                None => {
                    v.push(format!("edge {} has no endpoints row after the batch", k.1));
                    continue;
                }
                Some(e) => RowState {
                    tenancy: narrowed(&before.tenancy, meet(&e.source_state, &e.target_state)),
                    writer_owned: None,
                },
            },
            Kind::Edges => match ends.get(&k.1) {
                None => {
                    v.push(format!("edge {} has no endpoints row after the batch", k.1));
                    continue;
                }
                Some(e) => match meet(&e.source_state, &e.target_state) {
                    Some(t) => RowState {
                        tenancy: t,
                        writer_owned: None,
                    },
                    None => {
                        v.push(format!(
                            "edge {} still has two public endpoints after the batch; one of \
                             them is a moved claim",
                            k.1
                        ));
                        before.clone()
                    }
                },
            },
            _ if k.0 == "evidence" && pinned.contains(&k.1) => before.clone(),
            _ if is_outsider_challenge(&k.0, a.writer_owned) => before.clone(),
            _ if kept_nodes.contains(k) => before.clone(),
            _ => RowState {
                tenancy: Tenancy {
                    owner: ctx.target,
                    visibility: "group".into(),
                    co_owner: None,
                },
                writer_owned: spec.writer_owned.then_some(false),
            },
        };
        if want != before {
            *planned.entry(k.0.clone()).or_default() += 1;
        }
        if before.tenancy.visibility == "public" && want.tenancy.visibility != "public" {
            expect_lost.insert(k.clone());
        }
        // 168 (R-CH1b): an outsider's challenge keeps its public tuple, but a
        // challenge is readable only with its claim, so a session that loses
        // the claim loses the challenge too.
        if is_outsider_challenge(&k.0, a.writer_owned) && before.tenancy.visibility == "public" {
            expect_lost.insert(k.clone());
        }
        let Some(got) = s2.get(k) else {
            v.push(format!("{} {} vanished during the batch", k.0, k.1));
            continue;
        };
        if *got != before {
            *actual.entry(k.0.clone()).or_default() += 1;
        }
        if *got != want {
            v.push(format!("{} {} ended as {got}, expected {want}", k.0, k.1));
        }
        if !narrows(&before.tenancy, &got.tenancy) {
            v.push(format!(
                "{} {} WIDENED from {before} to {got}: readable by someone who could not read it",
                k.0, k.1
            ));
        }
        // (3b) no edge is more visible than its least visible endpoint.
        if let Some(m) = ends
            .get(&k.1)
            .filter(|_| k.0 == "edges")
            .and_then(|e| meet(&e.source_state, &e.target_state))
        {
            if !narrows(&m, &got.tenancy) {
                v.push(format!(
                    "edge {} is {got}, more visible than its least visible endpoint ({}, {})",
                    k.1, m.owner, m.visibility
                ));
            }
        }
    }
    if planned != actual {
        v.push(format!(
            "rows changed per table {actual:?} differ from rows planned {planned:?}"
        ));
    }
    // (4) the census: exactly the claims, and exactly the planned rows.
    let mut expect_counts: BTreeMap<String, (i64, i64, i64)> = BTreeMap::new();
    expect_counts.insert(
        "claims".into(),
        (0, i64::try_from(claim_ids.len()).unwrap_or(i64::MAX), 0),
    );
    if nodes_restored > 0 {
        // The cascade narrowed them and this batch put them back: two updates.
        expect_counts
            .entry("harvester_fragments".into())
            .or_default()
            .1 += 2 * i64::try_from(nodes_restored).unwrap_or(i64::MAX);
    }
    for (t, n) in &planned {
        expect_counts.entry(t.clone()).or_default().1 += i64::try_from(*n).unwrap_or(i64::MAX);
    }
    v.extend(counter_violations(
        &counter_delta(&counters_before, &counters_after),
        &expect_counts,
    ));
    // (5) what an unstamped application session can read.
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

    // ---- the sample ----
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
    // Rows this batch recorded for the first time keep their prior as the
    // last-known state until the commit replaces it with the post state.
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
    pub batches_ok: usize,
    pub batch_failures: Vec<(usize, String)>,
    pub claims_moved: usize,
    pub moved_by_table: BTreeMap<String, usize>,
    pub manifest_rows: usize,
    pub audit_written: bool,
    pub stopped_by_limit: bool,
    pub unenforced: BTreeMap<String, Vec<String>>,
}

/// Count the edges whose endpoint is EVIDENCE of one of `claims`: the trigger
/// does not re-meet them, so they keep their tenancy (reported, not changed).
async fn evidence_endpoint_edges(conn: &mut PgConnection, claims: &[Uuid]) -> anyhow::Result<i64> {
    let mut n = 0i64;
    for chunk in claims.chunks(5000) {
        let k: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM edges e WHERE \
               (e.source_type = 'evidence' AND e.source_id IN \
                  (SELECT id FROM evidence WHERE claim_id = ANY($1))) \
            OR (e.target_type = 'evidence' AND e.target_id IN \
                  (SELECT id FROM evidence WHERE claim_id = ANY($1)))",
        )
        .bind(chunk)
        .fetch_one(&mut *conn)
        .await?;
        n += k;
    }
    Ok(n)
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
    let target_kind = check_target(conn, opts.target, opts.operator).await?;
    let specs = tables::propagated_tables(conn).await?;
    if let Some(t) = specs.iter().find(|t| role_of(&t.name).is_none()) {
        bail!(
            "the tenancy cascade reaches table {}, which restrict-claims has not classified as \
             node, link or dependent (restrict::TABLE_ROLES); refusing",
            t.name
        );
    }
    let unkeyed = tables::unkeyed_tables(conn, &specs).await?;
    tables::probe_session_switch(conn).await?;
    let guard = super::hide::guard_status(conn).await?;
    if !guard.complete() {
        bail!(
            "the evidence pin guard (migration 110) is not complete in this schema; a pinned row's \
             handling is part of this tool's model, refusing"
        );
    }
    report.unenforced = unenforced_reasons(conn, &specs).await?;

    let pre = pre_pass(conn, requested, opts.target, opts.allow_non_world_owner).await?;
    report.eligible = pre.eligible.len();
    report.already = pre.already.len();
    report.held_at_plan.clone_from(&pre.held);

    writeln!(
        out,
        "restrict-claims: target_group={} ({target_kind}) operator={} mode={}{}",
        opts.target,
        opts.operator,
        if opts.apply { "APPLY" } else { "DRY-RUN" },
        if opts.allow_non_world_owner {
            " allow-non-world-owner"
        } else {
            ""
        }
    )?;
    writeln!(
        out,
        "PLAN: {} requested, {} eligible, {} held, {} already ('group', target)",
        requested.len(),
        pre.eligible.len(),
        pre.held.len(),
        pre.already.len()
    )?;
    let mut by_reason: BTreeMap<&'static str, usize> = BTreeMap::new();
    for (_, h) in &pre.held {
        *by_reason
            .entry(match h {
                Hold::NotFound => "not-found",
                Hold::NotPublic { .. } => "not-public",
                Hold::OwnerNotWorld { .. } => "owner-not-world",
                Hold::Sealed => "sealed",
                Hold::WouldWiden { .. } => "would-widen",
                Hold::ChangedSinceRecorded { .. } => "changed",
            })
            .or_default() += 1;
    }
    for (r, n) in &by_reason {
        writeln!(out, "HELD-COUNT\t{r}\t{n}")?;
    }
    for (id, h) in &pre.held {
        writeln!(out, "HELD\t{id}\t{h}")?;
    }
    if !unkeyed.is_empty() {
        writeln!(
            out,
            "LOCKED-PER-BATCH\t{}\t(no key to claims: each batch holds SHARE ROW EXCLUSIVE on them)",
            unkeyed.join(",")
        )?;
    }
    let ev_edges = evidence_endpoint_edges(conn, &pre.eligible).await?;
    writeln!(
        out,
        "EVIDENCE-ENDPOINT-EDGES\t{ev_edges}\t(edges with an evidence endpoint of an eligible \
         claim: narrowed with it to the narrowest of their endpoints unless already narrower; \
         recorded and restored like every edge)"
    )?;
    writeln!(
        out,
        "RULE: every derived row, fragment and edge of a moved claim follows it into the target \
         (other writers' rows included; a writer-owned row loses its flag, and the manifest \
         records it); pinned evidence and an outsider's writer-owned challenge are unchanged; a \
         claim carrying a non-public row that is not the target's is HELD"
    )?;
    if report.unenforced.is_empty() {
        writeln!(
            out,
            "ENFORCEMENT: ENFORCED (no permissive read policy beyond <table>_tenancy on any table \
             this touches)"
        )?;
    } else {
        writeln!(
            out,
            "WARNING: UNENFORCED. Legacy permissive policies admit group rows to every \
             application session on: {}. --apply refuses unless --accept-unenforced is given, and \
             then reports the run as UNENFORCED.",
            describe_unenforced(&report.unenforced)
        )?;
    }

    // ---- refusals before anything is written ----
    if opts.apply {
        if !report.unenforced.is_empty() && !opts.accept_unenforced {
            bail!(
                "the restriction would NOT be enforced ({}). Pass --accept-unenforced to proceed \
                 anyway; refusing. Nothing was written.",
                describe_unenforced(&report.unenforced)
            );
        }
        match opts.confirm_count {
            Some(n) if n == pre.eligible.len() => {}
            Some(n) => bail!(
                "--confirm-count {n} does not match the {} eligible claim(s); refusing. Nothing \
                 was written.",
                pre.eligible.len()
            ),
            None => bail!("--apply requires --confirm-count; refusing"),
        }
        if pre.eligible.is_empty() {
            writeln!(
                out,
                "RESULT\n  claims moved: 0 (nothing eligible; no manifest written)"
            )?;
            return Ok(report);
        }
    }
    let enforcement = if report.unenforced.is_empty() {
        json!({"state": "ENFORCED"})
    } else {
        json!({"state": "UNENFORCED", "by": report.unenforced})
    };

    // ---- manifest ----
    let header = json!({
        "manifest": "epigraph-operator restrict-claims",
        "operation": OPERATION,
        "version": manifest::VERSION,
        "operator": opts.operator,
        "target_group_id": opts.target,
        "created_at": chrono::Utc::now().to_rfc3339(),
        "ruling": opts.ruling,
        "reason": opts.reason,
        "claims_file_sha256": ids_sha256,
        "allow_non_world_owner": opts.allow_non_world_owner,
        "enforcement": enforcement,
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
        "command": "restrict-claims",
        "ruling": opts.ruling,
        "reason": opts.reason,
        "operator_person": opts.operator,
        "operator": operator_details(conn).await?,
        "target_group_id": opts.target,
        "target_group_kind": target_kind,
        "claims_file_sha256": ids_sha256,
        "manifest_path": opts.manifest_out.display().to_string(),
        "manifest_header_sha256": header_sha256,
        "planned": {
            "requested": requested.len(),
            "eligible": pre.eligible.len(),
            "held": pre.held.len(),
            "already": pre.already.len(),
        },
        "batch_size": opts.batch_size,
        "enforcement": enforcement,
    });

    // ---- batches ----
    let ctx = Ctx {
        specs: &specs,
        unkeyed: &unkeyed,
        target: opts.target,
        allow_non_world: opts.allow_non_world_owner,
        lock_timeout: &opts.lock_timeout,
        unenforced: &report.unenforced,
        sample: if opts.apply { 0 } else { opts.sample },
    };
    let mut known = Known::default();
    let batches: Vec<&[Uuid]> = pre.eligible.chunks(opts.batch_size).collect();
    let total = batches.len();
    let limit = opts.max_batches.unwrap_or(usize::MAX).min(total);
    let mut sampled = 0usize;
    for (i, batch) in batches.iter().take(limit).enumerate() {
        let mut tx = sqlx::Connection::begin(&mut *conn).await?;
        let audit =
            (opts.apply && !report.audit_written).then_some((&audit_details, opts.operator));
        let ctx_i = Ctx {
            sample: ctx.sample.saturating_sub(sampled),
            ..ctx
        };
        let r = run_batch(&mut tx, &ctx_i, batch, &mut sink, &known, audit).await;
        let ok = r.is_ok();
        if opts.apply && ok {
            tx.commit().await?;
        } else {
            tx.rollback().await?;
        }
        match r {
            Ok(b) => {
                report.batches_ok += 1;
                report.claims_moved += b.claims_moved;
                for (t, n) in &b.moved_by_table {
                    *report.moved_by_table.entry(t.clone()).or_default() += n;
                }
                report.held_under_lock.extend(b.held);
                report.audit_written |= b.audit_written;
                if opts.apply {
                    for (k, st) in b.post_rows {
                        known.rows.insert(k, st);
                    }
                }
                for l in &b.sample {
                    writeln!(out, "{l}")?;
                }
                sampled += b.sample.iter().filter(|l| l.contains("\tclaims\t")).count();
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
    if limit < total && report.batch_failures.is_empty() {
        report.stopped_by_limit = true;
        writeln!(
            out,
            "STOPPED by --max-batches after {limit} of {total} batch(es); re-run with a NEW \
             --manifest-out to continue (moved claims count as already done)"
        )?;
    }
    report.manifest_rows = sink.len();
    for (id, h) in &report.held_under_lock {
        writeln!(out, "HELD-UNDER-LOCK\t{id}\t{h}")?;
    }
    writeln!(out, "RESULT")?;
    writeln!(out, "  claims moved: {}", report.claims_moved)?;
    for (t, n) in &report.moved_by_table {
        writeln!(out, "  {t}: rows moved: {n}")?;
    }
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
        "  enforcement: {}",
        if report.unenforced.is_empty() {
            "ENFORCED".to_string()
        } else {
            format!("UNENFORCED ({})", describe_unenforced(&report.unenforced))
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
             audit row."
        )?;
    }
    Ok(report)
}

// ─────────────────────────────────────────────────────────────────────────────
// Reversal
// ─────────────────────────────────────────────────────────────────────────────

/// Is `m` a restrict manifest?
#[must_use]
pub fn is_restrict_manifest(m: &manifest::Manifest) -> bool {
    m.header.get("operation").and_then(Value::as_str) == Some(OPERATION)
}

/// What one reversal batch did.
#[derive(Default, Debug)]
pub struct RevOutcome {
    pub claims_restored: usize,
    pub rows_restored: BTreeMap<String, usize>,
    pub edges_deferred: usize,
    /// Recorded edges this batch left on their meet (an endpoint pending).
    pub deferred_ids: BTreeSet<String>,
    /// Recorded edges this batch left on their recorded tuple.
    pub settled_ids: BTreeSet<String>,
    pub held: Vec<(Uuid, String)>,
    pub never_moved: usize,
    pub already: usize,
    pub audit_written: bool,
}

const NEWER_FIRST: &str = "if a NEWER run moved it, reverse that manifest first (pass every \
                           manifest to one reown-reverse and it orders them newest-first)";

/// One reversal batch of a restrict manifest, inside the caller's
/// transaction. Does NOT commit.
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
async fn reverse_batch(
    conn: &mut PgConnection,
    specs: &[TableSpec],
    unkeyed: &[String],
    res: &super::reverse::Resolved,
    batch: &[(Uuid, Record)],
    lock_timeout: &str,
    unenforced: &BTreeMap<String, Vec<String>>,
    audit: Option<(&Value, Uuid)>,
) -> Result<RevOutcome, BatchError> {
    let mut out = RevOutcome::default();
    sqlx::query("SELECT set_config('lock_timeout', $1, true)")
        .bind(lock_timeout)
        .execute(&mut *conn)
        .await?;
    let ids: Vec<Uuid> = batch.iter().map(|(id, _)| *id).collect();
    let locked = fetch_claims(conn, &ids, true).await?;
    tables::lock_unkeyed_tables(conn, unkeyed).await?;
    let sealed = sealed_of(conn, &ids).await?;
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
        if rec.visibility != "public" {
            out.held.push((
                *id,
                format!(
                    "the manifest records prior visibility {}, which restrict-claims never moves; \
                     not reversing",
                    rec.visibility
                ),
            ));
            continue;
        }
        if sealed.contains(id) {
            out.held.push((
                *id,
                "the claim has been sealed since; it cannot be made public".into(),
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
    // The RECORDED edges with an evidence endpoint (this run narrowed them);
    // unrecorded ones are not touched by a claim's restoration, so they are
    // not part of this reversal.
    let ev_claim: BTreeMap<Uuid, Uuid> = attached
        .iter()
        .filter(|(k, _)| k.0 == "evidence")
        .filter_map(|(k, a)| Uuid::parse_str(&k.1).ok().map(|id| (id, a.claim)))
        .collect();
    let claim_edge_keys: BTreeSet<RowKey> = attached.keys().cloned().collect();
    let ev_edges = fetch_evidence_edges(conn, &ev_claim, &cand_ids, &claim_edge_keys).await?;
    attached.extend(
        ev_edges
            .into_iter()
            .filter(|(k, _)| res.rows.contains_key(k)),
    );

    // ---- rows: the CAS; an unrecorded non-public row would be widened ----
    let mut drift: BTreeMap<Uuid, String> = BTreeMap::new();
    for (k, a) in &attached {
        let cur = RowState::of(a);
        let why = match res.rows.get(k) {
            Some(prior) => {
                let p = RowState::of_record(prior);
                let q = res.row_posts.get(k).map(RowState::of_record);
                (cur != p && q.as_ref() != Some(&cur)).then(|| {
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
            None if a.tenancy.visibility != "public" => Some(format!(
                "{} {} is {cur} and was written after the restriction; restoring the claim would \
                 copy public visibility onto it, so not reversing",
                k.0, k.1
            )),
            None => None,
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
    let s0: BTreeMap<RowKey, Attached> = attached
        .into_iter()
        .filter(|(_, a)| a.claims.iter().any(|c| work_ids.contains(c)))
        .collect();
    let keys: BTreeSet<RowKey> = s0.keys().cloned().collect();
    let readable_before = app_readable(conn, specs, &claim_ids, &keys).await?;
    let counters_before = xact_counters(conn).await?;

    // ---- claims: the ONE widening statement, the GUC armed around it only ----
    let payload: Vec<Value> = work
        .iter()
        .filter(|(_, r)| r.visibility == "public")
        .map(|(id, r)| json!({"id": id, "o": r.owner_group_id, "v": r.visibility}))
        .collect();
    sqlx::query("SELECT set_config('epigraph.allow_declassify', 'yes', true)")
        .execute(&mut *conn)
        .await?;
    let claims_updated = sqlx::query(
        "UPDATE claims c SET owner_group_id = m.o, visibility = m.v \
           FROM jsonb_to_recordset($1::jsonb) AS m(id uuid, o uuid, v text) \
          WHERE c.id = m.id AND m.v = 'public' \
            AND c.owner_group_id = $2 AND c.visibility = 'group'",
    )
    .bind(Value::Array(payload))
    .bind(res.target)
    .execute(&mut *conn)
    .await
    .context("UPDATE claims (restore)")?
    .rows_affected();
    sqlx::query("SELECT set_config('epigraph.allow_declassify', '', true)")
        .execute(&mut *conn)
        .await?;

    let s1 = states_of(conn, specs, &claim_ids, &keys).await?;
    let mut trigger_changed: BTreeMap<String, i64> = BTreeMap::new();
    for (k, a) in &s0 {
        if s1.get(k) != Some(&RowState::of(a)) {
            *trigger_changed.entry(k.0.clone()).or_default() += 1;
        }
    }

    // ---- recorded non-edge rows back on their OWN recorded tuple ----
    let mut to_write: BTreeMap<String, Vec<(String, RowState)>> = BTreeMap::new();
    for k in &keys {
        if k.0 == "edges" {
            continue;
        }
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

    // ---- recorded edges: back on their recorded tuple once every endpoint
    // this manifest moved is back on its recorded prior; deferred otherwise ----
    let ends = edge_ends(conn, &edge_ids(&keys)).await?;
    let moved_ev: Vec<Uuid> = ends
        .values()
        .flat_map(|e| [&e.source, &e.target])
        .filter(|(id, ty)| {
            ty == "evidence" && res.rows.contains_key(&("evidence".into(), id.to_string()))
        })
        .map(|(id, _)| *id)
        .collect();
    let ev_now: BTreeMap<Uuid, (Uuid, String)> = if moved_ev.is_empty() {
        BTreeMap::new()
    } else {
        sqlx::query_as::<_, (Uuid, Uuid, String)>(
            "SELECT id, owner_group_id, visibility::text FROM evidence WHERE id = ANY($1)",
        )
        .bind(&moved_ev)
        .fetch_all(&mut *conn)
        .await?
        .into_iter()
        .map(|(i, o, v)| (i, (o, v)))
        .collect()
    };
    let moved_cl: Vec<Uuid> = ends
        .values()
        .flat_map(|e| [&e.source, &e.target])
        .filter(|(id, ty)| ty == "claim" && res.claim_posts.contains_key(id))
        .map(|(id, _)| *id)
        .collect();
    let cl_now: BTreeMap<Uuid, (Uuid, String)> = fetch_claims(conn, &moved_cl, false)
        .await?
        .into_iter()
        .map(|c| (c.id, (c.owner, c.visibility)))
        .collect();
    let pending = |(id, ty): &(Uuid, String)| -> bool {
        match ty.as_str() {
            "claim" => prior_claims.get(id).is_some_and(|r| {
                res.claim_posts.contains_key(id)
                    && cl_now.get(id) != Some(&(r.owner_group_id, r.visibility.clone()))
            }),
            "evidence" => res
                .rows
                .get(&("evidence".to_string(), id.to_string()))
                .is_some_and(|r| ev_now.get(id) != Some(&(r.owner_group_id, r.visibility.clone()))),
            _ => false,
        }
    };
    let mut deferred: BTreeSet<String> = BTreeSet::new();
    let mut edge_rows: Vec<(String, RowState)> = Vec::new();
    for k in keys.iter().filter(|k| k.0 == "edges") {
        let (Some(rec), Some(cur), Some(e)) = (res.rows.get(k), s1.get(k), ends.get(&k.1)) else {
            continue;
        };
        if pending(&e.source) || pending(&e.target) {
            deferred.insert(k.1.clone());
            continue;
        }
        let want = RowState::of_record(rec);
        if *cur != want {
            edge_rows.push((k.1.clone(), want));
        }
    }
    if !edge_rows.is_empty() {
        let n = write_rows(conn, spec_of(specs, "edges"), &claim_ids, &edge_rows).await?;
        *restored.entry("edges".into()).or_default() += i64::try_from(n).unwrap_or(i64::MAX);
    }

    let s2 = states_of(conn, specs, &claim_ids, &keys).await?;
    let after = fetch_claims(conn, &claim_ids, false).await?;
    let ends_after = edge_ends(conn, &edge_ids(&keys)).await?;
    let counters_after = xact_counters(conn).await?;
    let readable_after = app_readable(conn, specs, &claim_ids, &keys).await?;

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
    let mut expect_gained: BTreeSet<RowKey> = work
        .iter()
        .map(|(id, _)| ("claims".to_string(), id.to_string()))
        .collect();
    for (k, a) in &s0 {
        let Some(got) = s2.get(k) else {
            v.push(format!("{} {} vanished during the batch", k.0, k.1));
            continue;
        };
        let Some(rec) = res.rows.get(k) else {
            continue;
        };
        if k.0 == "edges" && deferred.contains(&k.1) {
            match ends_after
                .get(&k.1)
                .and_then(|e| meet(&e.source_state, &e.target_state))
            {
                // Still at least as narrow as its least visible endpoint (the
                // trigger's meet, or this run's narrower recorded state).
                Some(m) if narrows(&m, &got.tenancy) => {}
                other => v.push(format!(
                    "deferred edge {} is {got}, more visible than the meet of its endpoints \
                     {other:?}",
                    k.1
                )),
            }
            continue;
        }
        let want = RowState::of_record(rec);
        if *got != want {
            v.push(format!(
                "{} {} ended as {got}, the manifest records {want}",
                k.0, k.1
            ));
        }
        // An edge put back on its record must have every endpoint this
        // manifest moved back on ITS record, read from the database now: a
        // restored edge never outruns an endpoint that is still restricted.
        if k.0 == "edges" {
            if let Some(e) = ends_after.get(&k.1) {
                for (node, state) in [(&e.source, &e.source_state), (&e.target, &e.target_state)] {
                    let recorded = match node.1.as_str() {
                        "claim" if res.claim_posts.contains_key(&node.0) => prior_claims
                            .get(&node.0)
                            .map(|r| (r.owner_group_id, r.visibility.clone())),
                        "evidence" => res
                            .rows
                            .get(&("evidence".to_string(), node.0.to_string()))
                            .map(|r| (r.owner_group_id, r.visibility.clone())),
                        _ => None,
                    };
                    if let Some(r) = recorded {
                        if *state != r {
                            v.push(format!(
                                "edge {} was restored while its endpoint {} {} is ({}, {}), not \
                                 its recorded ({}, {})",
                                k.1, node.1, node.0, state.0, state.1, r.0, r.1
                            ));
                        }
                    }
                }
            }
        }
        if a.tenancy.visibility != "public" && want.tenancy.visibility == "public" {
            expect_gained.insert(k.clone());
        }
        // 168 (R-CH1b): an outsider's public challenge becomes readable again
        // with its claim (the mirror of the apply's expected loss).
        if is_outsider_challenge(&k.0, a.writer_owned)
            && want.tenancy.visibility == "public"
            && recs.get(&a.claim).is_some_and(|r| r.visibility == "public")
        {
            expect_gained.insert(k.clone());
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
    if let Some((details, operator)) = audit {
        let mut d = details.clone();
        d["first_batch"] = json!({"claims_restored": claims_updated});
        write_audit(conn, EVENT_REVERSE, operator, d).await?;
        out.audit_written = true;
    }
    out.claims_restored = usize::try_from(claims_updated).unwrap_or(usize::MAX);
    out.edges_deferred = deferred.len();
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

/// Reverse one restrict manifest, batch by batch; folds into `report`.
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
    let operator: Uuid = m
        .header
        .get("operator")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            anyhow!(
                "{}: restrict manifest header has no operator",
                path.display()
            )
        })
        .and_then(|s| Uuid::parse_str(s).context("operator"))?;
    let unenforced = unenforced_reasons(conn, specs).await?;
    let details = json!({
        "tool": "epigraph-operator",
        "command": "reown-reverse (restrict manifest)",
        "ruling": m.header.get("ruling"),
        "operator_person": operator,
        "operator": operator_details(conn).await?,
        "target_group_id": res.target,
        "manifest_path": path.display().to_string(),
        "manifest_sha256": sha256_file(path)?,
        "manifest_header_sha256": sha256_hex(serde_json::to_string(&m.header)?.as_bytes()),
        "planned": {
            "claims_in_manifest": res.claims.len(),
            "claims_moved_by_its_run": res.claim_posts.len(),
        },
        "enforcement": if unenforced.is_empty() {
            json!({"state": "ENFORCED"})
        } else {
            json!({"state": "UNENFORCED", "by": unenforced})
        },
    });
    writeln!(
        out,
        "RESTRICT-MANIFEST\t{}\ttarget_group={}\tclaims={}\tmoved={}\trows={}",
        path.display(),
        res.target,
        res.claims.len(),
        res.claim_posts.len(),
        res.rows.len()
    )?;
    let batches: Vec<&[(Uuid, Record)]> = res.claims.chunks(opts.batch_size).collect();
    let total = batches.len();
    let mut audited = false;
    let mut still_deferred: BTreeSet<String> = BTreeSet::new();
    for (i, batch) in batches.iter().enumerate() {
        let mut tx = sqlx::Connection::begin(&mut *conn).await?;
        let audit = (opts.apply && !audited).then_some((&details, operator));
        let r = reverse_batch(
            &mut tx,
            specs,
            unkeyed,
            &res,
            batch,
            &opts.lock_timeout,
            &unenforced,
            audit,
        )
        .await;
        if opts.apply && r.is_ok() {
            tx.commit().await?;
        } else {
            tx.rollback().await?;
        }
        match r {
            Ok(o) => {
                writeln!(
                    out,
                    "BATCH {}/{total}\tOK\t{} claim(s) restored, {} edge(s) deferred to a later \
                     batch",
                    i + 1,
                    o.claims_restored,
                    o.edges_deferred
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
    report.restrict_audit_rows += usize::from(audited);
    report.edges_deferred += still_deferred.len();
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn st(o: u128, v: &str) -> (Uuid, String) {
        (Uuid::from_u128(o), v.to_string())
    }

    #[test]
    fn the_meet_mirrors_migration_122() {
        assert_eq!(meet(&st(1, "public"), &st(2, "public")), None);
        let m = meet(&st(1, "public"), &st(2, "group")).unwrap();
        assert_eq!((m.owner, m.co_owner), (Uuid::from_u128(2), None));
        let m = meet(&st(1, "group"), &st(2, "public")).unwrap();
        assert_eq!((m.owner, m.co_owner), (Uuid::from_u128(1), None));
        let m = meet(&st(1, "group"), &st(1, "group")).unwrap();
        assert_eq!((m.owner, m.co_owner), (Uuid::from_u128(1), None));
        let m = meet(&st(1, "group"), &st(2, "group")).unwrap();
        assert_eq!(
            (m.owner, m.co_owner),
            (Uuid::from_u128(1), Some(Uuid::from_u128(2)))
        );
        assert_eq!(m.visibility, "group");
    }

    #[test]
    fn narrowed_takes_the_meet_unless_already_narrower() {
        let t = |o: u128, v: &str, co: Option<u128>| Tenancy {
            owner: Uuid::from_u128(o),
            visibility: v.into(),
            co_owner: co.map(Uuid::from_u128),
        };
        // public edge, an endpoint now in group 1: the meet.
        assert_eq!(
            narrowed(&t(0, "public", None), Some(t(1, "group", None))),
            t(1, "group", None)
        );
        // already narrower (1 AND 2) than the meet (1): kept.
        assert_eq!(
            narrowed(&t(1, "group", Some(2)), Some(t(1, "group", None))),
            t(1, "group", Some(2))
        );
        // equal reader set: kept, not rewritten.
        assert_eq!(
            narrowed(&t(1, "group", None), Some(t(1, "group", None))),
            t(1, "group", None)
        );
        // incomparable (another group's edge): the meet, which the caller
        // detects as a widening and holds.
        let n = narrowed(&t(3, "group", None), Some(t(1, "group", None)));
        assert!(!narrows(&t(3, "group", None), &n));
        // both endpoints public: unchanged.
        assert_eq!(narrowed(&t(5, "public", None), None), t(5, "public", None));
    }

    #[test]
    fn readability_is_exact_where_enforced_and_a_subset_where_not() {
        let k = |t: &str, i: &str| (t.to_string(), i.to_string());
        let before: BTreeSet<RowKey> = [k("claims", "a"), k("evidence", "e")].into();
        let after: BTreeSet<RowKey> = BTreeSet::new();
        let expect: BTreeSet<RowKey> = [k("claims", "a"), k("evidence", "e")].into();
        let none = BTreeMap::new();
        assert!(
            readability_violations(&before, &after, &expect, &BTreeSet::new(), &none).is_empty()
        );
        // Enforced: losing nothing when two rows narrowed is a violation.
        let v = readability_violations(&before, &before, &expect, &BTreeSet::new(), &none);
        assert_eq!(v.len(), 2, "{v:?}");
        // Unenforced claims and evidence: losing nothing is allowed.
        let mut un = BTreeMap::new();
        un.insert("claims".to_string(), vec!["claims_privacy".to_string()]);
        un.insert("evidence".to_string(), vec!["evidence_privacy".to_string()]);
        assert!(
            readability_violations(&before, &before, &expect, &BTreeSet::new(), &un).is_empty()
        );
        // Gaining anything unexpected is a violation either way.
        let more: BTreeSet<RowKey> = [k("claims", "a"), k("evidence", "e"), k("edges", "x")].into();
        assert_eq!(
            readability_violations(&before, &more, &expect, &BTreeSet::new(), &un).len(),
            1
        );
    }

    #[test]
    fn apply_needs_a_ruling_a_reason_and_a_confirmed_count() {
        let mut o = Options {
            claims_file: PathBuf::from("x"),
            target: Uuid::from_u128(7),
            operator: Uuid::from_u128(8),
            manifest_out: PathBuf::from("m"),
            apply: true,
            confirm_count: Some(1),
            accept_unenforced: false,
            allow_non_world_owner: false,
            ruling: "r".into(),
            reason: "why".into(),
            batch_size: 10,
            max_batches: None,
            lock_timeout: "5s".into(),
            sample: 0,
        };
        assert!(validate(&o).is_ok());
        o.ruling = " ".into();
        assert!(validate(&o).unwrap_err().to_string().contains("--ruling"));
        o.ruling = "r".into();
        o.confirm_count = None;
        assert!(validate(&o)
            .unwrap_err()
            .to_string()
            .contains("--confirm-count"));
        o.apply = false;
        assert!(validate(&o).is_ok());
        o.batch_size = 0;
        assert!(validate(&o).is_err());
    }
}
