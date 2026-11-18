//! The read-only cache-owner audit (`cache_owner_audit`, backlog d33a5c9f).
//!
//! One seeded world holds one row per category and the controls next to each:
//!
//! * (1) `repointed_cache`: a claim whose cache records `claim_validity`
//!   while the owner rule elects `binary_truth`, and one whose cache records
//!   no frame; controls: a cache that records its owner, a claim with no cache,
//!   and a re-pointed cache on a claim that is no longer current.
//! * (2) `compound_cached`: a compound holding a cache over a live BBA, and
//!   the d33a5c9f (2) shape, a compound whose only BBA is retracted while its
//!   value stays cached; control: a compound with no cache.
//! * (3) `edge_without_bba`: an epistemic edge created over HTTP (its create
//!   provenance row, written by the real `ProvenanceRepository::append`) whose
//!   source would wire today, and an MCP-shaped one (no provenance row) whose
//!   source is factorless; controls: an edge with a live edge-keyed BBA, one
//!   whose edge-keyed BBA is retracted (the wire's "ever wired" test counts
//!   it), an out-of-force edge, and the structural `decomposes_to` edges.
//!
//! The categorisation is asserted exactly, and every category is pinned by a
//! mutation of the audit that turns its arm red (recorded in the commit).
//! The read-only half: the report's `transaction_read_only` is read inside the
//! audit's transaction, and every table the audit reads is byte-identical
//! before and after it. The binary is driven end to end too: its JSONL, its
//! refusal of an existing `--out`, and its refusal without a configured
//! maintenance DSN.

#[path = "viewer_fixture.rs"]
mod viewer_fixture;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use epigraph_cli::cache_owner_audit::{run_read_only, Options, Report};
use epigraph_db::{FrameRepository, MassFunctionRepository, PerspectiveRepository};
use sqlx::PgPool;
use uuid::Uuid;

const BIN: &str = env!("CARGO_BIN_EXE_cache_owner_audit");

async fn frame_named(pool: &PgPool, name: &str) -> Uuid {
    let existing: Option<Uuid> = sqlx::query_scalar("SELECT id FROM frames WHERE name = $1")
        .bind(name)
        .fetch_optional(pool)
        .await
        .expect("read the frame");
    if let Some(id) = existing {
        return id;
    }
    FrameRepository::create(pool, name, None, &["TRUE".to_string(), "FALSE".to_string()])
        .await
        .expect("create the frame")
        .id
}

/// A live input BBA by `agent` (perspective `perspective`, if any).
async fn bba(
    pool: &PgPool,
    claim: Uuid,
    frame: Uuid,
    agent: Uuid,
    perspective: Option<Uuid>,
) -> Uuid {
    MassFunctionRepository::store_with_perspective(
        pool,
        claim,
        frame,
        Some(agent),
        perspective,
        &serde_json::json!({"0": 0.6, "0,1": 0.4}),
        None,
        Some("discount"),
        Some(1.0),
        None,
        "unknown",
        None,
    )
    .await
    .expect("store the BBA")
}

async fn retract(pool: &PgPool, row: Uuid, by: Uuid) {
    sqlx::query(
        "UPDATE mass_functions SET retracted_at = now(), retracted_by = $2, \
                retract_reason = 'd33a5c9f audit fixture' WHERE id = $1",
    )
    .bind(row)
    .bind(by)
    .execute(pool)
    .await
    .expect("retract the BBA");
}

/// Set the claim's cache, recording `frame`.
async fn cache(pool: &PgPool, claim: Uuid, belief: f64, plausibility: f64, frame: Option<Uuid>) {
    sqlx::query(
        "UPDATE claims SET belief = $2, plausibility = $3, pignistic_prob = ($2 + $3) / 2, \
                belief_frame_id = $4 WHERE id = $1",
    )
    .bind(claim)
    .bind(belief)
    .bind(plausibility)
    .bind(frame)
    .execute(pool)
    .await
    .expect("set the cache");
}

async fn edge(pool: &PgPool, source: Uuid, target: Uuid, relationship: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, $2, 'claim', $3, 'claim', $4)",
    )
    .bind(id)
    .bind(source)
    .bind(target)
    .bind(relationship)
    .execute(pool)
    .await
    .expect("seed the edge");
    id
}

/// The BBA the edge wire stores: on the target, keyed on the edge.
async fn edge_bba(pool: &PgPool, edge_id: Uuid, target: Uuid, frame: Uuid, agent: Uuid) -> Uuid {
    PerspectiveRepository::ensure_edge_perspective(pool, edge_id, Some(agent))
        .await
        .expect("the edge's perspective");
    bba(pool, target, frame, agent, Some(edge_id)).await
}

/// What `POST /edges` records after it creates an edge, through the same
/// repository call (`middleware::provenance::record_provenance`).
async fn http_create_provenance(pool: &PgPool, edge_id: Uuid) {
    let client = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO oauth_clients (id, client_id, client_name, client_type, allowed_scopes, \
                                    granted_scopes, status, created_at, updated_at) \
         VALUES ($1, $2, 'd33a5c9f-audit-client', 'human', ARRAY['edges:write'], \
                 ARRAY['edges:write'], 'active', now(), now())",
    )
    .bind(client)
    .bind(client.to_string())
    .execute(pool)
    .await
    .expect("an oauth client");
    epigraph_db::ProvenanceRepository::append(
        pool,
        "edge",
        edge_id,
        "create",
        client,
        client,
        &[epigraph_db::repos::provenance::AUTO_POLICY_AUTHORIZER_ID],
        "auto_policy",
        blake3::hash(edge_id.as_bytes()).as_bytes(),
        &[],
        Uuid::new_v4(),
        &["edges:write".to_string()],
        None,
    )
    .await
    .expect("the create provenance row");
}

struct World {
    owned: Uuid,
    repointed: Uuid,
    unrecorded: Uuid,
    compound_live: Uuid,
    compound_retracted: Uuid,
    binary_truth: Uuid,
    claim_validity: Uuid,
    http_edge: Uuid,
    mcp_edge: Uuid,
}

async fn seed_world(pool: &PgPool) -> World {
    let (agent, _) = viewer_fixture::seed_agent_with_group(pool, "d33a5c9f-audit").await;
    let binary_truth = frame_named(pool, "binary_truth").await;
    let claim_validity = frame_named(pool, "claim_validity").await;
    let claim = |c: &'static str| viewer_fixture::seed_public_claim(pool, agent, c);

    // (1) controls and rows.
    let owned = claim("audit: cache recorded on its owner").await;
    bba(pool, owned, binary_truth, agent, None).await;
    cache(pool, owned, 0.6, 1.0, Some(binary_truth)).await;

    let repointed = claim("audit: cache re-pointed to claim_validity").await;
    bba(pool, repointed, binary_truth, agent, None).await;
    bba(pool, repointed, claim_validity, agent, None).await;
    cache(pool, repointed, 0.3, 0.9, Some(claim_validity)).await;

    let unrecorded = claim("audit: cache recording no frame").await;
    bba(pool, unrecorded, binary_truth, agent, None).await;
    cache(pool, unrecorded, 0.6, 1.0, None).await;

    let uncached = claim("audit: input but no cache").await;
    bba(pool, uncached, binary_truth, agent, None).await;

    let retired = claim("audit: re-pointed but no longer current").await;
    bba(pool, retired, binary_truth, agent, None).await;
    bba(pool, retired, claim_validity, agent, None).await;
    cache(pool, retired, 0.3, 0.9, Some(claim_validity)).await;
    sqlx::query("UPDATE claims SET is_current = false WHERE id = $1")
        .bind(retired)
        .execute(pool)
        .await
        .expect("retire the claim");

    // (2) compounds: an in-force `decomposes_to` out-edge to a current leaf.
    let leaf = claim("audit: compound leaf").await;
    let compound_live = claim("audit: compound with a live BBA and a cache").await;
    edge(pool, compound_live, leaf, "decomposes_to").await;
    bba(pool, compound_live, binary_truth, agent, None).await;
    cache(pool, compound_live, 0.6, 1.0, Some(binary_truth)).await;

    let compound_retracted = claim("audit: compound whose only BBA is retracted").await;
    edge(pool, compound_retracted, leaf, "decomposes_to").await;
    let row = bba(pool, compound_retracted, binary_truth, agent, None).await;
    retract(pool, row, agent).await;
    cache(pool, compound_retracted, 0.6, 1.0, Some(binary_truth)).await;

    let compound_uncached = claim("audit: compound with no cache").await;
    edge(pool, compound_uncached, leaf, "decomposes_to").await;
    bba(pool, compound_uncached, binary_truth, agent, None).await;

    // (3) edges. A source with a confident cache (the wire would store a BBA
    // from it today) and a factorless one.
    let strong_source = claim("audit: confident edge source").await;
    cache(pool, strong_source, 0.9, 0.95, Some(binary_truth)).await;
    let factorless_source = claim("audit: factorless edge source").await;
    let target = claim("audit: edge target").await;

    let http_edge = edge(pool, strong_source, target, "supports").await;
    http_create_provenance(pool, http_edge).await;
    let mcp_edge = edge(pool, factorless_source, target, "supports").await;

    let wired = edge(pool, strong_source, target, "corroborates").await;
    edge_bba(pool, wired, target, binary_truth, agent).await;
    let wired_then_retracted = edge(pool, strong_source, target, "refutes").await;
    let row = edge_bba(pool, wired_then_retracted, target, binary_truth, agent).await;
    retract(pool, row, agent).await;

    let out_of_force = edge(pool, strong_source, target, "supports").await;
    http_create_provenance(pool, out_of_force).await;
    sqlx::query(
        "UPDATE edges SET valid_from = now() - interval '2 days', \
                          valid_to = now() - interval '1 day' WHERE id = $1",
    )
    .bind(out_of_force)
    .execute(pool)
    .await
    .expect("take the edge out of force");

    World {
        owned,
        repointed,
        unrecorded,
        compound_live,
        compound_retracted,
        binary_truth,
        claim_validity,
        http_edge,
        mcp_edge,
    }
}

async fn audit(pool: &PgPool, opts: &Options) -> (Report, Vec<serde_json::Value>) {
    let (_scoped, viewer) = viewer_fixture::bypass(pool).await;
    let mut conn = pool.acquire().await.expect("a connection");
    let mut out = Vec::new();
    let report = run_read_only(&mut conn, &viewer, opts, &mut out)
        .await
        .expect("the audit");
    let lines = std::str::from_utf8(&out)
        .expect("utf-8 findings")
        .lines()
        .map(|l| serde_json::from_str(l).expect("a JSON line"))
        .collect();
    (report, lines)
}

fn ids_of(lines: &[serde_json::Value], category: &str, key: &str) -> BTreeSet<Uuid> {
    lines
        .iter()
        .filter(|l| l["category"] == category)
        .map(|l| l[key].as_str().expect("an id").parse().expect("a uuid"))
        .collect()
}

fn set(ids: &[Uuid]) -> BTreeSet<Uuid> {
    ids.iter().copied().collect()
}

/// Every table the audit reads, whole: what the audit must not move.
async fn snapshot(pool: &PgPool) -> Vec<Option<String>> {
    let mut out = Vec::new();
    for table in [
        "claims",
        "mass_functions",
        "edges",
        "provenance_log",
        "frames",
        "claim_frames",
        "perspectives",
    ] {
        out.push(
            sqlx::query_scalar(&format!(
                "SELECT md5(string_agg(to_jsonb(t)::text, '|' ORDER BY to_jsonb(t)::text)) \
                   FROM {table} t"
            ))
            .fetch_one(pool)
            .await
            .expect("snapshot a table"),
        );
    }
    out
}

#[sqlx::test(migrations = "../../migrations")]
async fn each_category_holds_exactly_its_seeded_rows(pool: PgPool) {
    let w = seed_world(&pool).await;
    let (report, lines) = audit(&pool, &Options::default()).await;

    // (1): the re-pointed cache and the cache recording no frame; not the
    // owned cache, the uncached claim or the retired claim.
    assert_eq!(
        ids_of(&lines, "repointed_cache", "claim_id"),
        set(&[w.repointed, w.unrecorded]),
        "category (1)"
    );
    assert_eq!(report.repointed_cache.count, 2);
    assert_eq!(report.repointed_cache_unrecorded_frame, 1);
    let line = lines
        .iter()
        .find(|l| l["claim_id"] == w.repointed.to_string())
        .expect("the re-pointed claim's line");
    assert_eq!(line["stored_frame_id"], w.claim_validity.to_string());
    assert_eq!(
        line["owner_frame_id"],
        w.binary_truth.to_string(),
        "the owner rule elects binary_truth over claim_validity"
    );
    assert!(
        !ids_of(&lines, "repointed_cache", "claim_id").contains(&w.owned),
        "a cache recorded on its owner is no finding"
    );

    // (2): both cached compounds, the retracted-only one included; not the
    // uncached compound.
    assert_eq!(
        ids_of(&lines, "compound_cached", "claim_id"),
        set(&[w.compound_live, w.compound_retracted]),
        "category (2)"
    );
    assert_eq!(report.compound_cached.count, 2);
    assert_eq!(report.ownerless_cached_not_compound, 0);

    // (3): the two unwired epistemic edges, the HTTP one flagged; not the
    // wired, the retracted-wire, the out-of-force or the structural edges.
    assert_eq!(
        ids_of(&lines, "edge_without_bba", "edge_id"),
        set(&[w.http_edge, w.mcp_edge]),
        "category (3)"
    );
    assert_eq!(report.edges_without_bba.count, 2);
    assert_eq!(report.edges_without_bba_http.count, 1);
    assert_eq!(report.edges_without_bba_http.sample, vec![w.http_edge]);
    assert_eq!(report.edges_without_bba_http_would_wire, 1);
    let state = |edge: Uuid| {
        lines
            .iter()
            .find(|l| l["edge_id"] == edge.to_string())
            .expect("the edge's line")["source_state"]
            .clone()
    };
    assert_eq!(state(w.http_edge), "would_wire");
    assert_eq!(state(w.mcp_edge), "factorless");
    assert_eq!(
        report.epistemic_relationships,
        vec![
            "corroborates".to_string(),
            "refutes".to_string(),
            "supports".to_string()
        ],
        "decomposes_to is structural: the wire's own gate leaves it out"
    );
    // Four in-force epistemic edges: the two findings, the wired one and the
    // retracted-wire one (the out-of-force edge is not scanned).
    assert_eq!(report.edges_scanned, 4);

    assert!(report.claims_complete && report.edges_complete);
    assert_eq!(lines.len(), 6, "one line per finding: {lines:?}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_audit_runs_read_only_and_writes_nothing(pool: PgPool) {
    seed_world(&pool).await;
    let before = snapshot(&pool).await;
    let (report, lines) = audit(&pool, &Options::default()).await;
    assert!(!lines.is_empty(), "PREMISE: the audit found something");
    assert!(
        report.transaction_read_only,
        "the audit's transaction must be READ ONLY"
    );
    assert_eq!(report.transaction_isolation, "repeatable read");
    assert_eq!(
        snapshot(&pool).await,
        before,
        "the audit wrote to a table it reads"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_limit_truncates_each_pass_and_says_so(pool: PgPool) {
    seed_world(&pool).await;
    let (report, _) = audit(
        &pool,
        &Options {
            page_size: 2,
            limit: Some(3),
            sample: 1,
            ..Options::default()
        },
    )
    .await;
    assert_eq!(report.claims_scanned, 3);
    assert!(!report.claims_complete, "more claims are left");
    assert_eq!(report.edges_scanned, 3);
    assert!(!report.edges_complete, "one more edge is left");
    assert!(report.repointed_cache.sample.len() <= 1);

    // Paging alone (no limit) reaches the same totals as one page.
    let (paged, _) = audit(
        &pool,
        &Options {
            page_size: 1,
            ..Options::default()
        },
    )
    .await;
    let (whole, _) = audit(&pool, &Options::default()).await;
    assert_eq!(paged, whole);
}

// ------------------------------------------------------------- the binary

struct Run {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

fn run_bin(dir: &Path, args: &[&str], database_url: &str, maintenance: Option<&str>) -> Run {
    let mut cmd = Command::new(BIN);
    cmd.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("DATABASE_URL", database_url)
        .env("RUST_LOG", "warn")
        .args(args)
        .current_dir(dir);
    if let Some(m) = maintenance {
        cmd.env("MAINTENANCE_DATABASE_URL", m);
    }
    let out = cmd.output().expect("run the binary");
    Run {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

struct Dir(PathBuf);

impl Dir {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!("cache-owner-audit-{}", Uuid::new_v4().simple()));
        std::fs::create_dir(&p).expect("temp dir");
        Self(p)
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_binary_writes_the_findings_and_refuses_what_it_must(pool: PgPool) {
    let w = seed_world(&pool).await;
    let url = viewer_fixture::database_url_for(&pool).await;
    let dir = Dir::new();
    let out = dir.0.join("findings.jsonl");
    let out_arg = out.to_str().expect("a utf-8 path");

    // No configured maintenance DSN: refused, and no file is left behind.
    let refused = run_bin(&dir.0, &["--out", out_arg], &url, None);
    assert_ne!(
        refused.code,
        Some(0),
        "an unset MAINTENANCE_DATABASE_URL must refuse"
    );
    assert!(!out.exists(), "a refused run creates no findings file");

    let before = snapshot(&pool).await;
    let ran = run_bin(&dir.0, &["--out", out_arg], &url, Some(&url));
    assert_eq!(
        ran.code,
        Some(0),
        "the run failed: {}\n{}",
        ran.stderr,
        ran.stdout
    );
    assert_eq!(
        snapshot(&pool).await,
        before,
        "the binary wrote to the database"
    );
    let report: serde_json::Value = serde_json::from_str(&ran.stdout).expect("a JSON summary");
    assert_eq!(report["transaction_read_only"], true);
    assert_eq!(report["repointed_cache"]["count"], 2);
    assert_eq!(report["compound_cached"]["count"], 2);
    assert_eq!(report["edges_without_bba"]["count"], 2);
    let lines: Vec<serde_json::Value> = std::fs::read_to_string(&out)
        .expect("the findings file")
        .lines()
        .map(|l| serde_json::from_str(l).expect("a JSON line"))
        .collect();
    assert_eq!(
        ids_of(&lines, "repointed_cache", "claim_id"),
        set(&[w.repointed, w.unrecorded])
    );

    // An existing --out is never overwritten.
    let again = run_bin(&dir.0, &["--out", out_arg], &url, Some(&url));
    assert_ne!(again.code, Some(0), "an existing --out must refuse");
    assert_eq!(
        std::fs::read_to_string(&out)
            .expect("the findings file")
            .lines()
            .count(),
        lines.len(),
        "the refused run left the earlier findings alone"
    );
}
