//! Which rows move with a claim, read from the database rather than assumed.
//!
//! # The derived-table list is parsed from the live trigger
//!
//! `epigraph_propagate_tenancy` (migrations 070, 072) is the `claims` AFTER
//! UPDATE trigger that copies a claim's `(owner_group_id, visibility)` onto
//! every row derived from it. Its body carries the list as a literal,
//! `derived text[] := ARRAY[...]`, plus two further arms: `harvester_fragments`
//! (through `harvester_claim_provenance`) and `edges` (the MEET of both
//! endpoints). [`propagated_tables`] parses that literal out of `pg_proc` at run
//! time, so the set this tool snapshots, records and verifies is the set the
//! trigger actually cascades to on the database it is pointed at. A table the
//! trigger gains that this module cannot attribute is a REFUSAL, not a silent
//! omission: see [`WRITER_COLUMNS`].
//!
//! # Primary keys are read too
//!
//! Four of the derived tables have composite keys (`claim_frames`,
//! `claim_cluster_membership`, `claim_neighborhood_membership`,
//! `harvester_claim_provenance`), so a row is identified by its `pg_constraint`
//! primary key, never by an assumed `id` column. Every key column is required
//! to be `uuid`, which every one is today; anything else is refused.

use anyhow::{anyhow, bail, Context};
use serde_json::{json, Map, Value};
use sqlx::{PgConnection, Row};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

/// The column naming the agent that wrote a row, per table the trigger's
/// `derived[]` array may name. `None` means the table records no writer: its
/// rows are projections computed from the claim (beliefs, clusters, extracted
/// triples and mentions, frame assignments), and they are attributed to the
/// claim — they FOLLOW it in both `--derived` modes. That rule is printed in
/// every run's output.
///
/// This is a closed list on purpose. If `epigraph_propagate_tenancy` names a
/// table that is not here, [`propagated_tables`] refuses to run, and
/// `tests/operator_reown.rs::every_propagated_table_has_a_writer_rule` fails in
/// CI, so a migration that extends the cascade must decide the new table's
/// attribution here in the same change.
pub const WRITER_COLUMNS: &[(&str, Option<&str>)] = &[
    ("triples", None),
    ("entity_mentions", None),
    ("claim_versions", Some("created_by")),
    ("mass_functions", Some("source_agent_id")),
    ("ds_combined_beliefs", None),
    ("ds_bayesian_divergence", None),
    ("claim_frames", None),
    ("harvester_claim_provenance", None),
    ("evidence", Some("signer_id")),
    ("challenges", Some("challenger_id")),
    ("reasoning_traces", None),
    ("experiment_triples", None),
    ("experiment_entity_mentions", None),
    ("claim_clusters", None),
    ("claim_cluster_membership", None),
    ("claim_neighborhood_membership", None),
    ("claim_signature_revocations", Some("revoked_by")),
];

/// `edges.signer_id` is the writer of an edge.
pub const EDGE_WRITER: &str = "signer_id";

/// How a table hangs off a claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// `claims` itself.
    Claims,
    /// One of the trigger's `derived[]` tables: `claim_id` is the parent.
    Derived,
    /// `harvester_fragments`, reached through `harvester_claim_provenance`.
    Fragments,
    /// `edges` touching the claim as source or target.
    Edges,
}

/// One table the re-own touches.
#[derive(Clone, Debug)]
pub struct TableSpec {
    /// Table name, validated as a plain identifier and present in the closed
    /// lists above, so it is safe to splice into SQL.
    pub name: String,
    /// Primary-key columns, in `pg_constraint.conkey` order. All `uuid`.
    pub pk: Vec<String>,
    /// The writer column, if the table has one.
    pub writer: Option<String>,
    /// How rows are reached from a claim.
    pub kind: Kind,
}

impl TableSpec {
    /// `t.<pk>::text`, or the comma-joined key columns for a composite key.
    /// UUIDs contain no commas, so the join is unambiguous.
    #[must_use]
    pub fn pk_expr(&self, alias: &str) -> String {
        if self.pk.len() == 1 {
            format!("{alias}.\"{}\"::text", self.pk[0])
        } else {
            let cols: Vec<String> = self
                .pk
                .iter()
                .map(|c| format!("{alias}.\"{c}\"::text"))
                .collect();
            format!("concat_ws(',', {})", cols.join(", "))
        }
    }

    /// The manifest's `id` for a canonical key: the bare string for a
    /// single-column key, an object of column → value for a composite one.
    #[must_use]
    pub fn id_json(&self, pk: &str) -> Value {
        if self.pk.len() == 1 {
            Value::String(pk.to_string())
        } else {
            let mut m = Map::new();
            for (c, v) in self.pk.iter().zip(pk.split(',')) {
                m.insert(c.clone(), Value::String(v.to_string()));
            }
            Value::Object(m)
        }
    }

    /// Inverse of [`Self::id_json`].
    ///
    /// # Errors
    /// The value's shape does not match this table's key.
    pub fn pk_from_json(&self, id: &Value) -> anyhow::Result<String> {
        match id {
            Value::String(s) if self.pk.len() == 1 => Ok(s.clone()),
            Value::Object(m) if self.pk.len() > 1 => {
                let mut parts = Vec::with_capacity(self.pk.len());
                for c in &self.pk {
                    let v = m
                        .get(c)
                        .and_then(Value::as_str)
                        .ok_or_else(|| anyhow!("{}: id lacks key column {c}", self.name))?;
                    parts.push(v.to_string());
                }
                Ok(parts.join(","))
            }
            other => bail!("{}: id {other} does not match key {:?}", self.name, self.pk),
        }
    }
}

fn is_plain_ident(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && s.chars()
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c == '_')
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// Parse the table names out of the trigger body's `derived text[] :=
/// ARRAY[...]` literal.
///
/// # Errors
/// The literal is missing, empty, or names something that is not a plain
/// identifier.
pub fn parse_derived_array(src: &str) -> anyhow::Result<Vec<String>> {
    let anchor = "derived text[] := ARRAY[";
    let start = src
        .find(anchor)
        .ok_or_else(|| anyhow!("epigraph_propagate_tenancy has no `{anchor}` literal"))?
        + anchor.len();
    let end = src[start..]
        .find(']')
        .ok_or_else(|| anyhow!("unterminated derived[] literal"))?
        + start;
    let body = &src[start..end];
    let mut out = Vec::new();
    for piece in body.split(',') {
        let t = piece.trim().trim_matches('\'');
        if t.is_empty() {
            continue;
        }
        if !is_plain_ident(t) {
            bail!("derived[] names {t:?}, which is not a plain identifier");
        }
        out.push(t.to_string());
    }
    if out.is_empty() {
        bail!("derived[] literal is empty");
    }
    Ok(out)
}

async fn pk_columns(conn: &mut PgConnection, table: &str) -> anyhow::Result<Vec<String>> {
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT a.attname::text, format_type(a.atttypid, a.atttypmod) \
           FROM pg_constraint k \
           CROSS JOIN LATERAL unnest(k.conkey) WITH ORDINALITY AS u(attnum, ord) \
           JOIN pg_attribute a ON a.attrelid = k.conrelid AND a.attnum = u.attnum \
          WHERE k.conrelid = to_regclass('public.' || $1) AND k.contype = 'p' \
          ORDER BY u.ord",
    )
    .bind(table)
    .fetch_all(&mut *conn)
    .await?;
    if rows.is_empty() {
        bail!("table {table} has no primary key");
    }
    for (c, ty) in &rows {
        if ty != "uuid" {
            bail!("table {table}: primary-key column {c} is {ty}, not uuid");
        }
    }
    Ok(rows.into_iter().map(|(c, _)| c).collect())
}

async fn require_columns(
    conn: &mut PgConnection,
    table: &str,
    cols: &[&str],
) -> anyhow::Result<()> {
    let have: Vec<String> = sqlx::query_scalar(
        "SELECT column_name::text FROM information_schema.columns \
          WHERE table_schema = 'public' AND table_name = $1",
    )
    .bind(table)
    .fetch_all(&mut *conn)
    .await?;
    for c in cols {
        if !have.iter().any(|h| h == c) {
            bail!("table {table} has no column {c}");
        }
    }
    Ok(())
}

/// Every table a claim's re-own touches: `claims`, the trigger's `derived[]`
/// tables, `harvester_fragments` and `edges`.
///
/// # Errors
/// The trigger function is missing; its `derived[]` names a table with no
/// entry in [`WRITER_COLUMNS`]; its fragment or edge arm is gone; or a table's
/// shape is not what this module handles.
pub async fn propagated_tables(conn: &mut PgConnection) -> anyhow::Result<Vec<TableSpec>> {
    let src: Option<String> = sqlx::query_scalar(
        "SELECT prosrc FROM pg_proc \
          WHERE oid = to_regprocedure('public.epigraph_propagate_tenancy()')",
    )
    .fetch_optional(&mut *conn)
    .await?;
    let src = src.ok_or_else(|| anyhow!("public.epigraph_propagate_tenancy() does not exist"))?;
    let derived = parse_derived_array(&src).context("reading epigraph_propagate_tenancy")?;
    for arm in ["public.harvester_fragments", "public.edges"] {
        if !src.contains(arm) {
            bail!(
                "epigraph_propagate_tenancy no longer has its {arm} arm; this tool's model of the \
                 cascade is out of date, refusing"
            );
        }
    }
    let enabled: Option<String> = sqlx::query_scalar(
        "SELECT tgenabled::text FROM pg_trigger \
          WHERE tgrelid = 'public.claims'::regclass AND tgname = 'claims_propagate_tenancy'",
    )
    .fetch_optional(&mut *conn)
    .await?;
    if enabled.as_deref() != Some("O") {
        bail!(
            "trigger claims_propagate_tenancy is absent or not enabled (tgenabled={enabled:?}); \
             a re-own without it would leave every derived row behind, refusing"
        );
    }

    let mut specs = vec![TableSpec {
        name: "claims".into(),
        pk: pk_columns(conn, "claims").await?,
        writer: None,
        kind: Kind::Claims,
    }];
    for t in derived {
        let Some((_, writer)) = WRITER_COLUMNS.iter().find(|(n, _)| *n == t) else {
            bail!(
                "epigraph_propagate_tenancy cascades to table {t}, which has no writer rule in \
                 epigraph_cli::operator::tables::WRITER_COLUMNS. Decide its attribution there \
                 before re-owning anything."
            );
        };
        let mut need = vec!["claim_id", "owner_group_id", "visibility"];
        if let Some(w) = writer {
            need.push(w);
        }
        require_columns(conn, &t, &need).await?;
        specs.push(TableSpec {
            pk: pk_columns(conn, &t).await?,
            name: t,
            writer: writer.map(str::to_string),
            kind: Kind::Derived,
        });
    }
    require_columns(
        conn,
        "harvester_fragments",
        &["id", "owner_group_id", "visibility"],
    )
    .await?;
    specs.push(TableSpec {
        name: "harvester_fragments".into(),
        pk: pk_columns(conn, "harvester_fragments").await?,
        writer: None,
        kind: Kind::Fragments,
    });
    require_columns(
        conn,
        "edges",
        &[
            "id",
            "owner_group_id",
            "visibility",
            "co_owner_group_id",
            EDGE_WRITER,
        ],
    )
    .await?;
    specs.push(TableSpec {
        name: "edges".into(),
        pk: pk_columns(conn, "edges").await?,
        writer: Some(EDGE_WRITER.into()),
        kind: Kind::Edges,
    });
    for s in &specs {
        if !is_plain_ident(&s.name) {
            bail!("refusing table name {:?}", s.name);
        }
    }
    Ok(specs)
}

/// `(owner_group_id, visibility, co_owner_group_id)` of one row.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Tenancy {
    pub owner: Uuid,
    pub visibility: String,
    /// `edges` only; `None` everywhere else.
    pub co_owner: Option<Uuid>,
}

/// A row reached from a claim, with the facts the re-own decides on.
#[derive(Clone, Debug)]
pub struct Attached {
    pub table: String,
    /// Canonical key text (see [`TableSpec::pk_expr`]).
    pub pk: String,
    /// The claim this row was reached through (the lowest such id when several).
    pub claim: Uuid,
    /// EVERY claim in the queried set this row hangs off. An edge between two
    /// queried claims, or a fragment that is the provenance of several, hangs
    /// off each of them, and a non-public row must hold every one.
    pub claims: BTreeSet<Uuid>,
    pub tenancy: Tenancy,
    /// The writer column's value, when the table has one.
    pub writer: Option<Uuid>,
    /// Edges only: both endpoints resolve `public` under
    /// `epigraph_node_tenancy`, the function the trigger computes the meet with.
    pub endpoints_public: Option<bool>,
    /// Fragments only: the fragment is also the provenance of a claim outside
    /// the set being moved.
    pub shared_outside: bool,
    /// Evidence only: `evidence_type`, `labels` and the first 80 characters of
    /// `raw_content`, for the hide selectors and their preview.
    pub evidence_type: Option<String>,
    pub labels: Vec<String>,
    pub preview: Option<String>,
}

/// Map key: `(table, canonical pk)`.
pub type RowKey = (String, String);

/// A snapshot of rows by key.
pub type Snapshot = BTreeMap<RowKey, Attached>;

/// The `claims` rows for `ids`, optionally locked `FOR UPDATE` (in id order,
/// so two runs cannot deadlock on each other).
#[derive(Clone, Debug)]
pub struct ClaimRow {
    pub id: Uuid,
    pub author: Uuid,
    pub owner: Uuid,
    pub visibility: String,
}

/// # Errors
/// The query fails (including a `lock_timeout`).
pub async fn fetch_claims(
    conn: &mut PgConnection,
    ids: &[Uuid],
    for_update: bool,
) -> anyhow::Result<Vec<ClaimRow>> {
    let sql = format!(
        "SELECT id, agent_id, owner_group_id, visibility::text FROM claims \
          WHERE id = ANY($1) ORDER BY id{}",
        if for_update { " FOR UPDATE" } else { "" }
    );
    let rows = sqlx::query(&sql).bind(ids).fetch_all(&mut *conn).await?;
    Ok(rows
        .iter()
        .map(|r| ClaimRow {
            id: r.get(0),
            author: r.get(1),
            owner: r.get(2),
            visibility: r.get(3),
        })
        .collect())
}

fn insert_min(out: &mut Snapshot, mut row: Attached) {
    let key = (row.table.clone(), row.pk.clone());
    match out.get_mut(&key) {
        Some(existing) => {
            existing.claims.insert(row.claim);
            if row.claim < existing.claim {
                existing.claim = row.claim;
            }
        }
        None => {
            row.claims.insert(row.claim);
            out.insert(key, row);
        }
    }
}

/// Every row attached to `claims` in every non-`claims` table of `specs`.
///
/// # Errors
/// A query fails.
pub async fn fetch_attached(
    conn: &mut PgConnection,
    specs: &[TableSpec],
    claims: &[Uuid],
) -> anyhow::Result<Snapshot> {
    let mut out = Snapshot::new();
    for s in specs {
        match s.kind {
            Kind::Claims => {}
            Kind::Derived => {
                let writer = s
                    .writer
                    .as_ref()
                    .map_or_else(|| "NULL::uuid".to_string(), |w| format!("t.\"{w}\""));
                let ev = if s.name == "evidence" {
                    "t.evidence_type::text, COALESCE(t.labels, ARRAY[]::text[]), \
                     left(t.raw_content, 80)"
                } else {
                    "NULL::text, ARRAY[]::text[], NULL::text"
                };
                let sql = format!(
                    "SELECT {pk}, t.claim_id, t.owner_group_id, t.visibility::text, {writer}, {ev} \
                       FROM \"{name}\" t WHERE t.claim_id = ANY($1)",
                    pk = s.pk_expr("t"),
                    name = s.name
                );
                for r in sqlx::query(&sql).bind(claims).fetch_all(&mut *conn).await? {
                    insert_min(
                        &mut out,
                        Attached {
                            table: s.name.clone(),
                            pk: r.get(0),
                            claim: r.get(1),
                            claims: BTreeSet::new(),
                            tenancy: Tenancy {
                                owner: r.get(2),
                                visibility: r.get(3),
                                co_owner: None,
                            },
                            writer: r.get(4),
                            endpoints_public: None,
                            shared_outside: false,
                            evidence_type: r.get(5),
                            labels: r.get(6),
                            preview: r.get(7),
                        },
                    );
                }
            }
            Kind::Fragments => {
                let sql = format!(
                    "SELECT {pk}, p.claim_id, f.owner_group_id, f.visibility::text, \
                            EXISTS (SELECT 1 FROM harvester_claim_provenance p2 \
                                     WHERE p2.fragment_id = f.id AND p2.claim_id <> ALL($1)) \
                       FROM harvester_fragments f \
                       JOIN harvester_claim_provenance p ON p.fragment_id = f.id \
                      WHERE p.claim_id = ANY($1)",
                    pk = s.pk_expr("f")
                );
                for r in sqlx::query(&sql).bind(claims).fetch_all(&mut *conn).await? {
                    insert_min(
                        &mut out,
                        Attached {
                            table: s.name.clone(),
                            pk: r.get(0),
                            claim: r.get(1),
                            claims: BTreeSet::new(),
                            tenancy: Tenancy {
                                owner: r.get(2),
                                visibility: r.get(3),
                                co_owner: None,
                            },
                            writer: None,
                            endpoints_public: None,
                            shared_outside: r.get(4),
                            evidence_type: None,
                            labels: Vec::new(),
                            preview: None,
                        },
                    );
                }
            }
            Kind::Edges => {
                let sql = format!(
                    "SELECT {pk}, c.cid, \
                            e.owner_group_id, e.visibility::text, e.co_owner_group_id, \
                            e.\"{EDGE_WRITER}\", (s.v = 'public' AND tt.v = 'public') \
                       FROM edges e \
                       CROSS JOIN LATERAL (VALUES \
                            (CASE WHEN e.source_type = 'claim' THEN e.source_id END), \
                            (CASE WHEN e.target_type = 'claim' THEN e.target_id END)) AS c(cid) \
                       CROSS JOIN LATERAL public.epigraph_node_tenancy(e.source_id, e.source_type) s \
                       CROSS JOIN LATERAL public.epigraph_node_tenancy(e.target_id, e.target_type) tt \
                      WHERE ((e.source_type = 'claim' AND e.source_id = ANY($1)) \
                          OR (e.target_type = 'claim' AND e.target_id = ANY($1))) \
                        AND c.cid = ANY($1)",
                    pk = s.pk_expr("e")
                );
                for r in sqlx::query(&sql).bind(claims).fetch_all(&mut *conn).await? {
                    insert_min(
                        &mut out,
                        Attached {
                            table: s.name.clone(),
                            pk: r.get(0),
                            claim: r.get(1),
                            claims: BTreeSet::new(),
                            tenancy: Tenancy {
                                owner: r.get(2),
                                visibility: r.get(3),
                                co_owner: r.get(4),
                            },
                            writer: r.get(5),
                            endpoints_public: Some(r.get(6)),
                            shared_outside: false,
                            evidence_type: None,
                            labels: Vec::new(),
                            preview: None,
                        },
                    );
                }
            }
        }
    }
    Ok(out)
}

/// Re-read the tenancy of exactly the rows in `keys`, for the post-write
/// checks. A key that no longer resolves is absent from the result.
///
/// # Errors
/// A query fails.
pub async fn refetch_tenancy(
    conn: &mut PgConnection,
    specs: &[TableSpec],
    claims: &[Uuid],
    keys: &BTreeSet<RowKey>,
) -> anyhow::Result<BTreeMap<RowKey, Tenancy>> {
    let fresh = fetch_attached(conn, specs, claims).await?;
    let mut out = BTreeMap::new();
    for k in keys {
        if let Some(a) = fresh.get(k) {
            out.insert(k.clone(), a.tenancy.clone());
        }
    }
    Ok(out)
}

/// Write `target` tenancy onto the rows of one table, by key. Only rows whose
/// tenancy differs are touched, so the returned count is exactly the number of
/// rows changed.
///
/// `scope` narrows the scan through an indexed column: `claim_id` for a
/// derived table, `id` for fragments and edges.
///
/// # Errors
/// The update fails.
pub async fn write_tenancy(
    conn: &mut PgConnection,
    spec: &TableSpec,
    claims: &[Uuid],
    rows: &[(String, Tenancy)],
) -> anyhow::Result<u64> {
    if rows.is_empty() {
        return Ok(0);
    }
    let payload: Vec<Value> = rows
        .iter()
        .map(|(pk, t)| json!({"pk": pk, "o": t.owner, "v": t.visibility, "co": t.co_owner}))
        .collect();
    let (scope, bind_ids): (&str, Vec<Uuid>) = match spec.kind {
        Kind::Derived => ("t.claim_id = ANY($2)", claims.to_vec()),
        Kind::Fragments | Kind::Edges => (
            "t.id = ANY($2)",
            rows.iter()
                .filter_map(|(pk, _)| Uuid::parse_str(pk).ok())
                .collect(),
        ),
        Kind::Claims => bail!("write_tenancy does not write claims"),
    };
    let (set_co, cmp_co) = if spec.kind == Kind::Edges {
        (", co_owner_group_id = m.co", ", t.co_owner_group_id")
    } else {
        ("", "")
    };
    let m_co = if spec.kind == Kind::Edges {
        ", m.co"
    } else {
        ""
    };
    let sql = format!(
        "UPDATE \"{name}\" AS t SET owner_group_id = m.o, visibility = m.v{set_co} \
           FROM jsonb_to_recordset($1::jsonb) AS m(pk text, o uuid, v text, co uuid) \
          WHERE {scope} AND {pk} = m.pk \
            AND (t.owner_group_id, t.visibility::text{cmp_co}) IS DISTINCT FROM (m.o, m.v{m_co})",
        name = spec.name,
        pk = spec.pk_expr("t"),
    );
    let res = sqlx::query(&sql)
        .bind(Value::Array(payload))
        .bind(&bind_ids)
        .execute(&mut *conn)
        .await
        .with_context(|| format!("writing tenancy on {}", spec.name))?;
    Ok(res.rows_affected())
}

/// The cascade's `derived[]` tables whose `claim_id` has NO immediate foreign
/// key to `claims(id)`, read from `pg_constraint` at run time.
///
/// A batch's `SELECT ... FOR UPDATE` on its claims excludes a concurrent
/// derived INSERT only through that foreign key: the INSERT's RI check takes
/// `FOR KEY SHARE` on the parent claim, which `FOR UPDATE` blocks. A table
/// without the key (review measured three: `claim_versions`,
/// `ds_combined_beliefs`, `claim_cluster_membership`) is not excluded, and a
/// concurrent INSERT there both lands on the claim's OLD owner and, through
/// migration 070's statement-level inherit trigger, can rewrite a row the
/// batch already moved and verified after the batch commits. A deferrable key
/// is checked at commit, after the batch's lock may be gone, so it counts as
/// absent.
///
/// # Errors
/// The catalog read fails.
pub async fn unkeyed_tables(
    conn: &mut PgConnection,
    specs: &[TableSpec],
) -> anyhow::Result<Vec<String>> {
    let mut out = Vec::new();
    for s in specs.iter().filter(|s| s.kind == Kind::Derived) {
        let keyed: bool = sqlx::query_scalar(
            "SELECT EXISTS ( \
                SELECT 1 FROM pg_constraint k \
                  JOIN pg_attribute a ON a.attrelid = k.conrelid AND a.attnum = k.conkey[1] \
                 WHERE k.conrelid = to_regclass('public.' || $1) \
                   AND k.contype = 'f' \
                   AND k.confrelid = 'public.claims'::regclass \
                   AND array_length(k.conkey, 1) = 1 \
                   AND a.attname = 'claim_id' \
                   AND NOT k.condeferrable)",
        )
        .bind(&s.name)
        .fetch_one(&mut *conn)
        .await?;
        if !keyed {
            out.push(s.name.clone());
        }
    }
    Ok(out)
}

/// Take `SHARE ROW EXCLUSIVE` on every table [`unkeyed_tables`] named, for the
/// rest of the current transaction.
///
/// That mode blocks every concurrent INSERT/UPDATE/DELETE on the table (and
/// every other holder of the same mode, so two batches cannot deadlock on
/// upgrading it), and still admits plain reads. Held for one short batch. The
/// transaction's `lock_timeout` applies, so a table held by a long writer rolls
/// the batch back instead of stalling it.
///
/// # Errors
/// The lock is not granted within `lock_timeout`.
pub async fn lock_unkeyed_tables(conn: &mut PgConnection, tables: &[String]) -> anyhow::Result<()> {
    if tables.is_empty() {
        return Ok(());
    }
    for t in tables {
        if !is_plain_ident(t) {
            bail!("refusing table name {t:?}");
        }
    }
    let list: Vec<String> = tables.iter().map(|t| format!("public.\"{t}\"")).collect();
    sqlx::query(&format!(
        "LOCK TABLE {} IN SHARE ROW EXCLUSIVE MODE",
        list.join(", ")
    ))
    .execute(&mut *conn)
    .await
    .with_context(|| format!("locking the tables with no key to claims: {tables:?}"))?;
    Ok(())
}

/// Row-change counters for the current transaction, per `public` table:
/// `(inserted, updated, deleted)`, from `pg_stat_xact_user_tables`.
///
/// The counters include every row a trigger wrote inside this transaction, so
/// a before/after delta is a complete census of what the transaction changed,
/// not only what this module's own statements did.
///
/// # Errors
/// The query fails.
pub async fn xact_counters(
    conn: &mut PgConnection,
) -> anyhow::Result<BTreeMap<String, (i64, i64, i64)>> {
    let rows: Vec<(String, i64, i64, i64)> = sqlx::query_as(
        "SELECT relname::text, n_tup_ins, n_tup_upd, n_tup_del \
           FROM pg_stat_xact_user_tables WHERE schemaname = 'public'",
    )
    .fetch_all(&mut *conn)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(n, i, u, d)| (n, (i, u, d)))
        .collect())
}

/// Refuse up front, before any manifest or write, when this connection cannot
/// switch `session_user` to `epigraph_app` — the readability check inside
/// every batch depends on it, and a run that could only discover that in its
/// first batch would already have created its manifest.
///
/// # Errors
/// The switch is refused.
pub async fn probe_session_switch(conn: &mut PgConnection) -> anyhow::Result<()> {
    let mut tx = sqlx::Connection::begin(&mut *conn).await?;
    let r = sqlx::query("SET LOCAL SESSION AUTHORIZATION epigraph_app")
        .execute(&mut *tx)
        .await;
    tx.rollback().await?;
    r.map(|_| ()).context(
        "this connection cannot SET SESSION AUTHORIZATION epigraph_app, which every batch needs \
         to check that no row became less readable to an unstamped application session. Use a \
         maintenance DSN whose login may switch session_user (a superuser); refusing before \
         writing anything",
    )
}

/// The keys an UNSTAMPED `epigraph_app` session can read among `claims` and
/// the attached rows, measured by switching `session_user` to `epigraph_app`
/// with `SET LOCAL SESSION AUTHORIZATION` for the duration of the reads.
///
/// `SET LOCAL ROLE` would be vacuous: `epigraph_bypass()` reads
/// `session_user`, which `SET ROLE` leaves as the maintenance login. The switch
/// requires the connecting role to be a superuser; if it is refused the whole
/// batch fails closed.
///
/// # Errors
/// The session switch is refused, or a read fails.
pub async fn app_readable(
    conn: &mut PgConnection,
    specs: &[TableSpec],
    claims: &[Uuid],
    attached: &BTreeSet<RowKey>,
) -> anyhow::Result<BTreeSet<RowKey>> {
    sqlx::query("SET LOCAL SESSION AUTHORIZATION epigraph_app")
        .execute(&mut *conn)
        .await
        .context(
            "SET LOCAL SESSION AUTHORIZATION epigraph_app was refused. The post-state check \
             that no row became less readable needs a connection that may switch session_user \
             (a superuser login); refusing to write without it",
        )?;
    let result = app_readable_inner(conn, specs, claims, attached).await;
    let reset = sqlx::query("SET LOCAL SESSION AUTHORIZATION DEFAULT")
        .execute(&mut *conn)
        .await;
    // The read's own error is the informative one; a failed read aborts the
    // transaction, and the reset then fails only because of it.
    let out = result?;
    reset?;
    Ok(out)
}

async fn app_readable_inner(
    conn: &mut PgConnection,
    specs: &[TableSpec],
    claims: &[Uuid],
    attached: &BTreeSet<RowKey>,
) -> anyhow::Result<BTreeSet<RowKey>> {
    sqlx::query(
        "SELECT set_config('epigraph.group_ids', '', true), \
                set_config('epigraph.writable_group_ids', '', true), \
                set_config('epigraph.principal_id', '', true)",
    )
    .execute(&mut *conn)
    .await?;
    let bypass: bool = sqlx::query_scalar("SELECT public.epigraph_bypass()")
        .fetch_one(&mut *conn)
        .await?;
    if bypass {
        bail!(
            "epigraph_app reports epigraph_bypass() = true; the readability check would be vacuous"
        );
    }
    let mut out = BTreeSet::new();
    for s in specs {
        let ids_of_table: Vec<Uuid> = attached
            .iter()
            .filter(|(t, _)| *t == s.name)
            .filter_map(|(_, pk)| Uuid::parse_str(pk).ok())
            .collect();
        let sql = match s.kind {
            Kind::Claims => "SELECT c.id::text FROM claims c WHERE c.id = ANY($1)".to_string(),
            Kind::Derived => format!(
                "SELECT {} FROM \"{}\" t WHERE t.claim_id = ANY($1)",
                s.pk_expr("t"),
                s.name
            ),
            Kind::Fragments | Kind::Edges => format!(
                "SELECT {} FROM \"{}\" t WHERE t.id = ANY($1)",
                s.pk_expr("t"),
                s.name
            ),
        };
        let bind: &[Uuid] = match s.kind {
            Kind::Claims | Kind::Derived => claims,
            Kind::Fragments | Kind::Edges => &ids_of_table,
        };
        let rows: Vec<String> = sqlx::query_scalar(&sql)
            .bind(bind)
            .fetch_all(&mut *conn)
            .await
            .with_context(|| format!("reading {} as epigraph_app", s.name))?;
        for pk in rows {
            let key = (s.name.clone(), pk);
            if s.kind == Kind::Claims || attached.contains(&key) {
                out.insert(key);
            }
        }
    }
    Ok(out)
}

/// Whether a writer counts as the operator's for `--derived keep-writer`: the
/// operator itself, or an agent whose `operator_links` row (retired or not)
/// names the operator.
///
/// # Errors
/// The query fails.
pub async fn writer_is_linked(
    conn: &mut PgConnection,
    cache: &mut BTreeMap<Uuid, bool>,
    writer: Uuid,
    operator: Uuid,
) -> anyhow::Result<bool> {
    if writer == operator {
        return Ok(true);
    }
    if let Some(v) = cache.get(&writer) {
        return Ok(*v);
    }
    let linked = super::operator_of_author(conn, writer).await? == Some(operator);
    cache.insert(writer, linked);
    Ok(linked)
}

/// Which evidence-bearing tables exist among the specs; used by callers that
/// only care about one table.
#[must_use]
pub fn spec<'a>(specs: &'a [TableSpec], name: &str) -> Option<&'a TableSpec> {
    specs.iter().find(|s| s.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_072_literal() {
        let src = "DECLARE t text; expected bigint; actual bigint;\n\
                   derived text[] := ARRAY[\n  'triples','entity_mentions',\n  'claim_versions'];\n\
                   BEGIN";
        assert_eq!(
            parse_derived_array(src).unwrap(),
            vec!["triples", "entity_mentions", "claim_versions"]
        );
    }

    #[test]
    fn refuses_a_non_identifier() {
        let src = "derived text[] := ARRAY['ok','bad name'];";
        assert!(parse_derived_array(src).is_err());
        assert!(parse_derived_array("no literal here").is_err());
    }

    #[test]
    fn composite_ids_round_trip() {
        let s = TableSpec {
            name: "claim_frames".into(),
            pk: vec!["claim_id".into(), "frame_id".into()],
            writer: None,
            kind: Kind::Derived,
        };
        let pk = "a1,b2";
        let j = s.id_json(pk);
        assert_eq!(j, json!({"claim_id": "a1", "frame_id": "b2"}));
        assert_eq!(s.pk_from_json(&j).unwrap(), pk);
        assert!(s.pk_from_json(&json!("a1")).is_err());
    }
}
