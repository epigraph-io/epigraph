//! `epigraph-operator backfill-evidence-edges` and `reverse-evidence-edges`
//! (backlog 2d60f619), driven through the real binary on the maintenance DSN
//! against a `#[sqlx::test]` database migrated 001 -> head.
//!
//! # The fixture
//!
//! * `missing_public` / `missing_group`: evidence with no edge to its claim
//!   (a public claim, a group claim). The two rows the backfill writes.
//! * `legacy`: evidence with a legacy upper-case `SUPPORTS` edge. Present.
//! * `retracted`: evidence whose only edge to its claim is retracted. Never
//!   re-written.
//! * `on_sealed_claim`: no edge, but its claim is sealed (`claim_encryption`).
//! * `sealed`: no edge, and the evidence row itself is sealed
//!   (`evidence_encryption`). Both sealed rows are skipped and reported.

mod viewer_fixture;

use epigraph_crypto::AgentSigner;
use epigraph_mcp::embed::McpEmbedder;
use epigraph_mcp::EpiGraphMcpFull;
use sqlx::PgPool;
use std::path::{Path, PathBuf};
use std::process::Command;
use uuid::Uuid;
use viewer_fixture as fixture;

const BIN: &str = env!("CARGO_BIN_EXE_epigraph-operator");
const DSN_ENV: &str = "EPIGRAPH_OPERATOR_MAINTENANCE_DSN";
const EPOCH: i32 = 1;

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Run {
    fn show(&self) -> String {
        format!(
            "exit={}\n--- stdout\n{}\n--- stderr\n{}",
            self.code, self.stdout, self.stderr
        )
    }
}

async fn run_op(pool: &PgPool, args: &[&str]) -> Run {
    let url = fixture::database_url_for(pool).await;
    let out = Command::new(BIN)
        .args(args)
        .env("RUST_LOG", "warn")
        .env_remove("DATABASE_URL")
        .env_remove("MAINTENANCE_DATABASE_URL")
        .env(DSN_ENV, &url)
        .output()
        .expect("spawn epigraph-operator");
    Run {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("operator-evidence-edges-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&d).expect("scratch dir");
    d.join(name)
}

fn p(path: &Path) -> &str {
    path.to_str().expect("utf-8 path")
}

#[allow(dead_code)]
struct Fx {
    group: Uuid,
    public_claim: Uuid,
    group_claim: Uuid,
    sealed_claim: Uuid,
    missing_public: Uuid,
    missing_group: Uuid,
    legacy: Uuid,
    retracted: Uuid,
    on_sealed_claim: Uuid,
    sealed: Uuid,
}

async fn seal_group(pool: &PgPool, agent: Uuid) -> Uuid {
    let g: Uuid = sqlx::query_scalar(
        "INSERT INTO groups (display_name, did_key, public_key, kind, created_by_agent_id) \
         VALUES ('ev-edge seal', 'did:epigraph:personal:' || gen_random_uuid()::text, \
                 ''::bytea, 'personal', $1) RETURNING id",
    )
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("seal group");
    sqlx::query("INSERT INTO group_key_epochs (group_id, epoch, status) VALUES ($1, $2, 'active')")
        .bind(g)
        .bind(EPOCH)
        .execute(pool)
        .await
        .expect("epoch");
    g
}

async fn seed(pool: &PgPool) -> Fx {
    let (agent, group) = fixture::seed_agent_with_group(pool, "ev-edge-backfill").await;
    let public_claim = fixture::seed_public_claim(pool, agent, "a public claim").await;
    let group_claim = fixture::seed_group_claim(pool, agent, group, "a group claim").await;
    let sealed_claim = fixture::seed_group_claim(pool, agent, group, "a sealed claim").await;

    let missing_public = fixture::seed_evidence(pool, public_claim, "document").await;
    let missing_group = fixture::seed_evidence(pool, group_claim, "document").await;
    let legacy = fixture::seed_evidence(pool, public_claim, "observation").await;
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'evidence', $2, 'claim', 'SUPPORTS')",
    )
    .bind(legacy)
    .bind(public_claim)
    .execute(pool)
    .await
    .expect("legacy SUPPORTS edge");
    let retracted = fixture::seed_evidence(pool, public_claim, "testimony").await;
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, \
                            valid_to) \
         VALUES ($1, 'evidence', $2, 'claim', 'supports', now() - interval '1 day')",
    )
    .bind(retracted)
    .bind(public_claim)
    .execute(pool)
    .await
    .expect("retracted edge");

    let seal = seal_group(pool, agent).await;
    let on_sealed_claim = fixture::seed_evidence(pool, sealed_claim, "document").await;
    sqlx::query(
        "INSERT INTO claim_encryption (claim_id, group_id, epoch, privacy_tier, \
                                       encrypted_content) \
         VALUES ($1, $2, $3, 'fully_private', ''::bytea)",
    )
    .bind(sealed_claim)
    .bind(seal)
    .bind(EPOCH)
    .execute(pool)
    .await
    .expect("seal the claim");
    let sealed = fixture::seed_evidence(pool, public_claim, "reference").await;
    sqlx::query(
        "INSERT INTO evidence_encryption (evidence_id, group_id, epoch, privacy_tier, \
                                          encrypted_content) \
         VALUES ($1, $2, $3, 'fully_private', ''::bytea)",
    )
    .bind(sealed)
    .bind(seal)
    .bind(EPOCH)
    .execute(pool)
    .await
    .expect("seal the evidence");

    Fx {
        group,
        public_claim,
        group_claim,
        sealed_claim,
        missing_public,
        missing_group,
        legacy,
        retracted,
        on_sealed_claim,
        sealed,
    }
}

/// Every edges row, as text, sorted: the exact state a reversal must restore.
async fn edges_snapshot(pool: &PgPool) -> Vec<String> {
    sqlx::query_scalar("SELECT to_jsonb(e)::text FROM edges e ORDER BY id")
        .fetch_all(pool)
        .await
        .expect("edges snapshot")
}

/// Evidence rows with no edge of any kind to their claim, sealed or not.
async fn missing(pool: &PgPool) -> Vec<Uuid> {
    sqlx::query_scalar(
        "SELECT ev.id FROM evidence ev \
          WHERE NOT EXISTS (SELECT 1 FROM edges x WHERE x.source_type = 'evidence' \
                              AND x.source_id = ev.id AND x.target_type = 'claim' \
                              AND x.target_id = ev.claim_id) \
          ORDER BY ev.id",
    )
    .fetch_all(pool)
    .await
    .expect("missing")
}

/// `(relationship, owner_group_id, visibility)` of every edge from `ev`.
async fn edges_of(pool: &PgPool, ev: Uuid) -> Vec<(String, Uuid, String)> {
    sqlx::query_as(
        "SELECT relationship, owner_group_id, visibility::text FROM edges \
          WHERE source_id = $1 ORDER BY relationship",
    )
    .bind(ev)
    .fetch_all(pool)
    .await
    .expect("edges of")
}

async fn evidence_tenancy(pool: &PgPool, ev: Uuid) -> (Uuid, String) {
    sqlx::query_as("SELECT owner_group_id, visibility::text FROM evidence WHERE id = $1")
        .bind(ev)
        .fetch_one(pool)
        .await
        .expect("evidence tenancy")
}

fn sorted(mut v: Vec<Uuid>) -> Vec<Uuid> {
    v.sort();
    v
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_dry_run_counts_exactly_the_missing_edges_and_writes_nothing(pool: PgPool) {
    let fx = seed(&pool).await;
    let before = edges_snapshot(&pool).await;
    let run = run_op(&pool, &["backfill-evidence-edges"]).await;
    assert_eq!(run.code, 0, "{}", run.show());
    let out = &run.stdout;
    for line in [
        "evidence rows: 6",
        "  SUPPORTS: 1",
        "rows whose only edges to their claim are retracted (left alone): 1",
        "SKIPPED, sealed: 2 missing row(s) (1 on a sealed claim, 1 sealed evidence;",
        "to_write: 2",
        "ground the claim): 0",
        "    supports: 2",
        "    no_bba_default_supports: 2",
        "    group/personal -> group/personal: 1",
        "    public/world -> public/world: 1",
        "DRY RUN",
    ] {
        assert!(out.contains(line), "missing {line:?}:\n{}", run.show());
    }
    assert!(!out.contains("refutes"), "{}", run.show());
    assert_eq!(
        edges_snapshot(&pool).await,
        before,
        "a dry run writes nothing"
    );
    assert_eq!(
        missing(&pool).await,
        sorted(vec![
            fx.missing_public,
            fx.missing_group,
            fx.on_sealed_claim,
            fx.sealed
        ]),
        "control: the fixture's missing rows"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn apply_leaves_none_missing_reverse_restores_exactly_and_a_second_apply_writes_nothing(
    pool: PgPool,
) {
    let fx = seed(&pool).await;
    let before = edges_snapshot(&pool).await;

    // Two runs of one batch of one row each: the second picks up the rest.
    let m1 = scratch("m1.jsonl");
    let run = run_op(
        &pool,
        &[
            "backfill-evidence-edges",
            "--apply",
            "--confirm-count",
            "2",
            "--manifest-out",
            p(&m1),
            "--reason",
            "test backfill",
            "--batch-size",
            "1",
            "--max-batches",
            "1",
        ],
    )
    .await;
    assert_eq!(run.code, 0, "{}", run.show());
    assert!(
        run.stdout
            .contains("APPLIED: 1 edge(s) in 1 committed batch(es)"),
        "{}",
        run.show()
    );
    let m2 = scratch("m2.jsonl");
    let run = run_op(
        &pool,
        &[
            "backfill-evidence-edges",
            "--apply",
            "--confirm-count",
            "1",
            "--manifest-out",
            p(&m2),
            "--reason",
            "test backfill, the rest",
        ],
    )
    .await;
    assert_eq!(run.code, 0, "{}", run.show());
    assert!(run.stdout.contains("APPLIED: 1 edge(s)"), "{}", run.show());

    // Zero missing, the sealed rows excepted (and reported).
    assert_eq!(
        missing(&pool).await,
        sorted(vec![fx.on_sealed_claim, fx.sealed]),
        "after apply only the sealed rows lack an edge"
    );
    // Each written edge: `supports`, never wider than its evidence row.
    for ev in [fx.missing_public, fx.missing_group] {
        let edges = edges_of(&pool, ev).await;
        assert_eq!(edges.len(), 1, "{edges:?}");
        assert_eq!(edges[0].0, "supports");
        let (owner, vis) = evidence_tenancy(&pool, ev).await;
        assert_eq!((edges[0].1, edges[0].2.clone()), (owner, vis), "{ev}");
    }
    assert_eq!(
        edges_of(&pool, fx.missing_group).await[0].1,
        fx.group,
        "the group claim's evidence edge is the group's"
    );
    // The legacy and retracted rows are untouched.
    assert_eq!(edges_of(&pool, fx.legacy).await.len(), 1);
    assert_eq!(edges_of(&pool, fx.retracted).await.len(), 1);

    // A second apply finds nothing and writes nothing.
    let after_apply = edges_snapshot(&pool).await;
    let dry = run_op(&pool, &["backfill-evidence-edges"]).await;
    assert!(dry.stdout.contains("to_write: 0"), "{}", dry.show());
    let m3 = scratch("m3.jsonl");
    let again = run_op(
        &pool,
        &[
            "backfill-evidence-edges",
            "--apply",
            "--confirm-count",
            "0",
            "--manifest-out",
            p(&m3),
            "--reason",
            "again",
        ],
    )
    .await;
    assert_eq!(again.code, 0, "{}", again.show());
    assert!(
        again.stdout.contains("APPLIED: 0 edge(s)"),
        "{}",
        again.show()
    );
    assert_eq!(edges_snapshot(&pool).await, after_apply, "nothing written");

    // Reverse: a dry run changes nothing; apply restores the exact rows.
    for m in [&m2, &m1] {
        let dry = run_op(&pool, &["reverse-evidence-edges", "--manifest", p(m)]).await;
        assert_eq!(dry.code, 0, "{}", dry.show());
        assert!(
            dry.stdout
                .contains("DRY RUN (rolled back): 1 recorded edge(s); 1 deleted"),
            "{}",
            dry.show()
        );
    }
    assert_eq!(edges_snapshot(&pool).await, after_apply);
    for m in [&m3, &m2, &m1] {
        let r = run_op(
            &pool,
            &["reverse-evidence-edges", "--manifest", p(m), "--apply"],
        )
        .await;
        assert_eq!(r.code, 0, "{}", r.show());
    }
    assert_eq!(
        edges_snapshot(&pool).await,
        before,
        "the reversal restores the edges table exactly"
    );
    // A second reversal deletes nothing.
    let r = run_op(
        &pool,
        &["reverse-evidence-edges", "--manifest", p(&m1), "--apply"],
    )
    .await;
    assert!(
        r.stdout
            .contains("REVERSED: 1 recorded edge(s); 0 deleted; 1 already gone"),
        "{}",
        r.show()
    );
    let audit: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM security_events \
          WHERE event_type IN ('evidence_claim_edge.backfill', \
                               'evidence_claim_edge.backfill_reverse')",
    )
    .fetch_one(&pool)
    .await
    .expect("audit rows");
    assert_eq!(
        audit, 4,
        "one audit row per applied run that wrote (2) and per reversal that deleted (2)"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_wrong_confirm_count_refuses_and_writes_nothing(pool: PgPool) {
    seed(&pool).await;
    let before = edges_snapshot(&pool).await;
    let m = scratch("m.jsonl");
    let run = run_op(
        &pool,
        &[
            "backfill-evidence-edges",
            "--apply",
            "--confirm-count",
            "3",
            "--manifest-out",
            p(&m),
            "--reason",
            "wrong count",
        ],
    )
    .await;
    assert_ne!(run.code, 0, "{}", run.show());
    assert!(run.stderr.contains("--confirm-count 3"), "{}", run.show());
    assert_eq!(edges_snapshot(&pool).await, before);
    assert!(!m.exists(), "no manifest for a refused run");
}

/// Direction from the evidence's own BBA, filed by the real tool: evidence
/// filed AGAINST a claim through `update_with_evidence(supports = false)`,
/// its edge then removed (as a pre-change row would have none), is backfilled
/// `refutes`.
#[sqlx::test(migrations = "../../migrations")]
async fn evidence_filed_against_its_claim_is_backfilled_refutes(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let scoped = fixture::scoped_pool(&pool).await;
    let signer = AgentSigner::from_bytes(&[0xA7u8; 32]).expect("signer");
    let embedder = McpEmbedder::new(pool.clone(), None).with_scoped_pool(scoped.clone());
    let server =
        EpiGraphMcpFull::new(pool.clone(), signer, embedder, false).with_scoped_pool(scoped);
    let (agent, _) = fixture::seed_agent_with_group(&pool, "ev-edge-bba").await;
    let claim = fixture::seed_public_claim(&pool, agent, "a claim argued against").await;

    epigraph_mcp::tools::claims::update_with_evidence(
        &server,
        &viewer,
        epigraph_mcp::types::UpdateWithEvidenceParams {
            canonical_name: None,
            step_index: None,
            claim_id: claim.to_string(),
            evidence_type: "empirical".to_string(),
            evidence_data: "a measurement against the claim".to_string(),
            source_url: None,
            supports: false,
            strength: 0.8,
            labels: vec![],
        },
        None,
    )
    .await
    .expect("update_with_evidence");
    let ev: Uuid = sqlx::query_scalar("SELECT id FROM evidence WHERE claim_id = $1")
        .bind(claim)
        .fetch_one(&pool)
        .await
        .expect("the filed evidence");
    assert_eq!(
        edges_of(&pool, ev).await.len(),
        1,
        "control: the tool wrote the edge"
    );
    sqlx::query("DELETE FROM edges WHERE source_id = $1")
        .bind(ev)
        .execute(&pool)
        .await
        .expect("drop the edge, as an older row lacks it");
    let bbas: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM mass_functions WHERE evidence_id = $1 AND retracted_at IS NULL",
    )
    .bind(ev)
    .fetch_one(&pool)
    .await
    .expect("bbas");
    assert_eq!(bbas, 1, "control: the evidence's BBA is the vote");

    let dry = run_op(&pool, &["backfill-evidence-edges"]).await;
    assert!(
        dry.stdout.contains("    refutes: 1") && dry.stdout.contains("    bba_against: 1"),
        "{}",
        dry.show()
    );
    let m = scratch("m.jsonl");
    let run = run_op(
        &pool,
        &[
            "backfill-evidence-edges",
            "--apply",
            "--confirm-count",
            "1",
            "--manifest-out",
            p(&m),
            "--reason",
            "polarity",
        ],
    )
    .await;
    assert_eq!(run.code, 0, "{}", run.show());
    let edges = edges_of(&pool, ev).await;
    assert_eq!(edges.len(), 1, "{edges:?}");
    assert_eq!(edges[0].0, "refutes", "{}", run.show());
}

/// The census counts a row sealed BOTH ways (its claim and itself) once in
/// its skipped total, and names the rows whose edge will not ground their
/// claim (a derivation row here).
#[sqlx::test(migrations = "../../migrations")]
async fn the_census_counts_a_doubly_sealed_row_once_and_names_provenance_rows(pool: PgPool) {
    let (agent, group) = fixture::seed_agent_with_group(&pool, "ev-edge-census").await;
    let sealed_claim = fixture::seed_group_claim(&pool, agent, group, "sealed twice").await;
    let both = fixture::seed_evidence(&pool, sealed_claim, "document").await;
    let seal = seal_group(&pool, agent).await;
    sqlx::query(
        "INSERT INTO claim_encryption (claim_id, group_id, epoch, privacy_tier, \
                                       encrypted_content) \
         VALUES ($1, $2, $3, 'fully_private', ''::bytea)",
    )
    .bind(sealed_claim)
    .bind(seal)
    .bind(EPOCH)
    .execute(&pool)
    .await
    .expect("seal the claim");
    sqlx::query(
        "INSERT INTO evidence_encryption (evidence_id, group_id, epoch, privacy_tier, \
                                          encrypted_content) \
         VALUES ($1, $2, $3, 'fully_private', ''::bytea)",
    )
    .bind(both)
    .bind(seal)
    .bind(EPOCH)
    .execute(&pool)
    .await
    .expect("seal the evidence");
    let derived_claim = fixture::seed_public_claim(&pool, agent, "an atom").await;
    sqlx::query(
        "INSERT INTO evidence (claim_id, evidence_type, content_hash, raw_content, properties) \
         VALUES ($1, 'document', $2, 'the parent text', $3)",
    )
    .bind(derived_claim)
    .bind(vec![9u8; 32])
    .bind(serde_json::json!({
        "type": "document", "mime_type": "text/plain", "source_url": null, "checksum": null,
        "derived_from_claim": Uuid::new_v4().to_string(), "method": "decomposition"
    }))
    .execute(&pool)
    .await
    .expect("derivation row");
    assert_eq!(missing(&pool).await.len(), 2, "control: both rows lack an edge");

    let run = run_op(&pool, &["backfill-evidence-edges"]).await;
    assert_eq!(run.code, 0, "{}", run.show());
    for line in [
        "SKIPPED, sealed: 1 missing row(s) (1 on a sealed claim, 1 sealed evidence;",
        "to_write: 1",
        "ground the claim): 1",
    ] {
        assert!(run.stdout.contains(line), "missing {line:?}:\n{}", run.show());
    }
}

/// The advisory lock name the operator verbs hold (the CLI's `LOCK_NAME`).
const LOCK_NAME: &str = "epigraph-operator:backfill-evidence-edges";

/// An applied run, and an applied reversal, refuse to start while another
/// holds the lock, and write nothing (no edge, no manifest).
#[sqlx::test(migrations = "../../migrations")]
async fn an_applied_run_or_reversal_refuses_while_another_holds_the_lock(pool: PgPool) {
    seed(&pool).await;
    let before = edges_snapshot(&pool).await;
    let mut holder = pool.acquire().await.expect("holder connection");
    sqlx::query("SELECT pg_advisory_lock(hashtextextended($1, 0))")
        .bind(LOCK_NAME)
        .execute(&mut *holder)
        .await
        .expect("hold the lock");

    let m = scratch("locked.jsonl");
    let apply = [
        "backfill-evidence-edges",
        "--apply",
        "--confirm-count",
        "2",
        "--manifest-out",
        p(&m),
        "--reason",
        "while locked",
    ];
    let run = run_op(&pool, &apply).await;
    assert_ne!(run.code, 0, "{}", run.show());
    assert!(run.stderr.contains("advisory lock"), "{}", run.show());
    assert_eq!(edges_snapshot(&pool).await, before, "nothing written");
    assert!(!m.exists(), "no manifest for a refused run");

    // A dry run is read-only and takes no lock.
    let dry = run_op(&pool, &["backfill-evidence-edges"]).await;
    assert_eq!(dry.code, 0, "{}", dry.show());

    // Released, the same apply runs; re-held, its reversal refuses.
    sqlx::query("SELECT pg_advisory_unlock(hashtextextended($1, 0))")
        .bind(LOCK_NAME)
        .execute(&mut *holder)
        .await
        .expect("release");
    let run = run_op(&pool, &apply).await;
    assert_eq!(run.code, 0, "{}", run.show());
    let applied = edges_snapshot(&pool).await;
    assert_ne!(applied, before, "control: the unlocked apply wrote");
    sqlx::query("SELECT pg_advisory_lock(hashtextextended($1, 0))")
        .bind(LOCK_NAME)
        .execute(&mut *holder)
        .await
        .expect("hold the lock again");
    let r = run_op(
        &pool,
        &["reverse-evidence-edges", "--manifest", p(&m), "--apply"],
    )
    .await;
    assert_ne!(r.code, 0, "{}", r.show());
    assert!(r.stderr.contains("advisory lock"), "{}", r.show());
    assert_eq!(edges_snapshot(&pool).await, applied, "nothing deleted");
}

