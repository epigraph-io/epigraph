//! `epigraph-operator backfill-ingest-markers` and `reverse-ingest-markers`,
//! driven through the real binary against a `#[sqlx::test]` database migrated
//! 001 -> head, then read back through the provenance readers (the agent
//! card's counts, `query_paper`'s per-ingest listing, a claim's
//! `authored_by`) on an `epigraph_app` session.
//!
//! # The legacy fixture
//!
//! Edges written before the ingest marker existed, each seeded raw:
//!
//! * paper P1, UNSIGNED: author A authored P1, P1 asserts C1, A asserts C1 (a
//!   legacy triangle). Author W authored P1 too, and W's `asserts` C1 is a
//!   workflow attribution (excluded). X asserts C1 with no authorship (not a
//!   triangle: excluded). C1 was filed by an unrelated agent F.
//! * paper P2, SIGNED by a real ingesting agent S: B authored P2, P2 asserts
//!   C2, B asserts C2, all signed by S; C2 is filed by S and carries S's
//!   extraction trace of P2 (a provable creation). C4, also filed by S and
//!   stated by P2 under S's signature, carries an extraction trace of ANOTHER
//!   document: not provably P2's creation, so it gets no record. Author D
//!   authored P2 and
//!   asserts C2 UNSIGNED: a split triangle (D's rows are `legacy-ingest`,
//!   P2's assertion is S's), which must keep reading 0.
//! * paper P3, signed by a bulk ATTESTATION identity: A authored P3, P3
//!   asserts C3, A asserts C3.
//!
//! Before the run every reader reads these as nothing (the marker era);
//! after it they read as they did before the marker existed, per principal.
//!
//! All names and identifiers are invented.

mod viewer_fixture;

use epigraph_db::pool::{ScopedPool, SessionGucMode};
use epigraph_db::visibility::Viewer;
use epigraph_db::{AgentLookupRepository, AuthoredByRepository, PaperRepository};
use sqlx::PgPool;
use std::path::PathBuf;
use std::process::Command;
use uuid::Uuid;
use viewer_fixture as fixture;

const BIN: &str = env!("CARGO_BIN_EXE_epigraph-operator");
const DSN_ENV: &str = "EPIGRAPH_OPERATOR_MAINTENANCE_DSN";

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
    let d = std::env::temp_dir().join(format!("operator-backfill-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&d).expect("scratch dir");
    d.join(name)
}

async fn paper(pool: &PgPool, doi: &str, title: &str) -> Uuid {
    sqlx::query_scalar("INSERT INTO papers (doi, title) VALUES ($1, $2) RETURNING id")
        .bind(doi)
        .bind(title)
        .fetch_one(pool)
        .await
        .expect("paper")
}

/// One pre-marker edge, seeded raw (as the legacy writers left them),
/// signed by `signer` when given (an opaque signature: nothing here verifies
/// it, and the backfill must leave it byte for byte).
async fn edge(
    pool: &PgPool,
    src: (Uuid, &str),
    tgt: (Uuid, &str),
    rel: &str,
    props: serde_json::Value,
    signer: Option<Uuid>,
) -> Uuid {
    let (sig, hash): (Option<Vec<u8>>, Option<Vec<u8>>) = match signer {
        Some(s) => (
            Some(s.as_bytes().iter().copied().cycle().take(64).collect()),
            Some(
                s.as_bytes()
                    .iter()
                    .copied()
                    .rev()
                    .cycle()
                    .take(32)
                    .collect(),
            ),
        ),
        None => (None, None),
    };
    sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, \
                            properties, signature, signer_id, content_hash) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id",
    )
    .bind(src.0)
    .bind(src.1)
    .bind(tgt.0)
    .bind(tgt.1)
    .bind(rel)
    .bind(props)
    .bind(sig)
    .bind(signer)
    .bind(hash)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("seed {rel} edge: {e}"))
}

#[allow(dead_code)]
struct Fx {
    s: Uuid,
    attest: Uuid,
    f: Uuid,
    a: Uuid,
    b: Uuid,
    d: Uuid,
    w: Uuid,
    x: Uuid,
    p1: Uuid,
    p2: Uuid,
    p3: Uuid,
    c1: Uuid,
    c2: Uuid,
    c3: Uuid,
    c4: Uuid,
    signed: Vec<Uuid>,
}

async fn seed(pool: &PgPool) -> Fx {
    let (s, _) = fixture::seed_agent_with_group(pool, "backfill-ingester").await;
    let (attest, _) = fixture::seed_agent_with_group(pool, "backfill-attestation").await;
    let (f, _) = fixture::seed_agent_with_group(pool, "backfill-filer").await;
    let mut authors = Vec::new();
    for l in ["a", "b", "d", "w", "x"] {
        authors.push(
            fixture::seed_agent_with_group(pool, &format!("backfill-author-{l}"))
                .await
                .0,
        );
    }
    let (a, b, d, w, x) = (authors[0], authors[1], authors[2], authors[3], authors[4]);
    let p1 = paper(pool, "10.9999/backfill-unsigned", "Unsigned Legacy").await;
    let p2 = paper(pool, "10.9999/backfill-signed", "Signed Legacy").await;
    let p3 = paper(pool, "10.9999/backfill-attested", "Attested Legacy").await;
    let c1 = fixture::seed_public_claim(pool, f, "a legacy unsigned finding").await;
    let c2 = fixture::seed_public_claim(pool, s, "a legacy signed finding").await;
    let c3 = fixture::seed_public_claim(pool, f, "a legacy attested finding").await;
    let c4 = fixture::seed_public_claim(pool, s, "a legacy signed finding of another source").await;
    let t4: Uuid = sqlx::query_scalar(
        "INSERT INTO reasoning_traces (claim_id, reasoning_type, explanation, created_at) \
         SELECT $1, 'deductive', \
                'Extracted from ''Elsewhere'' (DOI: 10.9999/backfill-elsewhere); level 3 (atom)', \
                c.created_at + interval '2 seconds' \
           FROM claims c WHERE c.id = $1 RETURNING id",
    )
    .bind(c4)
    .fetch_one(pool)
    .await
    .expect("trace of another source");
    sqlx::query("UPDATE claims SET trace_id = $2 WHERE id = $1")
        .bind(c4)
        .bind(t4)
        .execute(pool)
        .await
        .expect("trace id");
    // C2's own extraction trace of P2, written right after the claim (the
    // walk hangs it only on a claim it creates).
    let t: Uuid = sqlx::query_scalar(
        "INSERT INTO reasoning_traces (claim_id, reasoning_type, explanation, created_at) \
         SELECT $1, 'deductive', \
                'Extracted from ''Signed Legacy'' (DOI: 10.9999/backfill-signed); level 3 (atom)', \
                c.created_at + interval '2 seconds' \
           FROM claims c WHERE c.id = $1 RETURNING id",
    )
    .bind(c2)
    .fetch_one(pool)
    .await
    .expect("trace");
    sqlx::query("UPDATE claims SET trace_id = $2 WHERE id = $1")
        .bind(c2)
        .bind(t)
        .execute(pool)
        .await
        .expect("trace id");

    let none = serde_json::json!({});
    let pos = |n: i64| serde_json::json!({"position": n, "role": "author"});
    // P1, unsigned.
    edge(pool, (a, "agent"), (p1, "paper"), "authored", pos(0), None).await;
    edge(pool, (w, "agent"), (p1, "paper"), "authored", pos(1), None).await;
    edge(
        pool,
        (p1, "paper"),
        (c1, "claim"),
        "asserts",
        none.clone(),
        None,
    )
    .await;
    edge(
        pool,
        (a, "agent"),
        (c1, "claim"),
        "asserts",
        none.clone(),
        None,
    )
    .await;
    edge(
        pool,
        (w, "agent"),
        (c1, "claim"),
        "asserts",
        serde_json::json!({"source": "workflow_attribution", "role": "author"}),
        None,
    )
    .await;
    edge(
        pool,
        (x, "agent"),
        (c1, "claim"),
        "asserts",
        none.clone(),
        None,
    )
    .await;
    // P2, signed by the ingesting agent S; D's rows unsigned.
    let mut signed = vec![
        edge(
            pool,
            (b, "agent"),
            (p2, "paper"),
            "authored",
            pos(0),
            Some(s),
        )
        .await,
        edge(
            pool,
            (p2, "paper"),
            (c2, "claim"),
            "asserts",
            none.clone(),
            Some(s),
        )
        .await,
        edge(
            pool,
            (b, "agent"),
            (c2, "claim"),
            "asserts",
            none.clone(),
            Some(s),
        )
        .await,
        edge(
            pool,
            (p2, "paper"),
            (c4, "claim"),
            "asserts",
            none.clone(),
            Some(s),
        )
        .await,
        edge(
            pool,
            (b, "agent"),
            (c4, "claim"),
            "asserts",
            none.clone(),
            Some(s),
        )
        .await,
    ];
    edge(pool, (d, "agent"), (p2, "paper"), "authored", pos(1), None).await;
    edge(
        pool,
        (d, "agent"),
        (c2, "claim"),
        "asserts",
        none.clone(),
        None,
    )
    .await;
    // P3, signed by the attestation identity.
    signed.push(
        edge(
            pool,
            (a, "agent"),
            (p3, "paper"),
            "authored",
            pos(0),
            Some(attest),
        )
        .await,
    );
    signed.push(
        edge(
            pool,
            (p3, "paper"),
            (c3, "claim"),
            "asserts",
            none.clone(),
            Some(attest),
        )
        .await,
    );
    signed.push(
        edge(
            pool,
            (a, "agent"),
            (c3, "claim"),
            "asserts",
            none,
            Some(attest),
        )
        .await,
    );
    Fx {
        s,
        attest,
        f,
        a,
        b,
        d,
        w,
        x,
        p1,
        p2,
        p3,
        c1,
        c2,
        c3,
        c4,
        signed,
    }
}

async fn app_pool(pool: &PgPool) -> ScopedPool {
    ScopedPool::connect_downgraded_for_tests(
        &fixture::database_url_for(pool).await,
        SessionGucMode::Session,
        "epigraph_app",
    )
    .await
    .expect("app-role ScopedPool")
}

/// `(authored_papers, pending_authored_papers, asserted_claims)` of `agent`'s
/// card as `caller` reads it.
async fn counts(pool: &PgPool, scoped: &ScopedPool, caller: Uuid, agent: Uuid) -> (i64, i64, i64) {
    let v = Viewer::resolve(pool, caller).await.expect("resolve");
    let mut read = scoped.read_as(&v).await.expect("read");
    let card = AgentLookupRepository::card(&mut read, &v, agent)
        .await
        .expect("card")
        .expect("agent exists");
    read.commit().await.expect("finish");
    (
        card.counts.authored_papers,
        card.counts.pending_authored_papers,
        card.counts.asserted_claims,
    )
}

/// `query_paper`'s per-ingest reads of `paper` as a public reader:
/// `(ingest principals, that principal's authors, its asserted-claim count)`.
async fn listing(
    pool: &PgPool,
    scoped: &ScopedPool,
    paper: Uuid,
    by: Uuid,
) -> (Vec<Uuid>, Vec<Uuid>, i64) {
    let v = fixture::public_viewer(pool).await;
    let mut read = scoped.read_as(&v).await.expect("read");
    let mut principals: Vec<Uuid> = PaperRepository::ingest_principals(&mut *read, &v, paper, 10)
        .await
        .expect("principals")
        .into_iter()
        .map(|p| p.ingested_by)
        .collect();
    principals.sort();
    let mut authors: Vec<Uuid> = PaperRepository::list_authors_by(&mut *read, &v, paper, by, 50)
        .await
        .expect("authors")
        .into_iter()
        .map(|a| a.agent_id)
        .collect();
    authors.sort();
    let n = PaperRepository::count_asserted_claims_by(&mut *read, &v, paper, by)
        .await
        .expect("count");
    read.commit().await.expect("finish");
    (principals, authors, n)
}

/// A claim's `authored_by` block as JSON, read by a stranger.
async fn authored_by(
    pool: &PgPool,
    scoped: &ScopedPool,
    caller: Uuid,
    claim: Uuid,
) -> serde_json::Value {
    let (agent, at): (Uuid, chrono::DateTime<chrono::Utc>) =
        sqlx::query_as("SELECT agent_id, created_at FROM claims WHERE id = $1")
            .bind(claim)
            .fetch_one(pool)
            .await
            .expect("claim");
    let v = Viewer::resolve(pool, caller).await.expect("resolve");
    let mut read = scoped.read_as(&v).await.expect("read");
    let out = AuthoredByRepository::for_claim(
        &mut read,
        &v,
        claim,
        agent,
        at,
        epigraph_db::PROMPT_SNAPSHOT_AUDIENCE,
    )
    .await
    .expect("authored_by");
    read.commit().await.expect("finish");
    serde_json::to_value(out).expect("json")
}

/// Every edge row's mutable state, sorted: what a dry run and a reversal
/// must leave exactly as it was.
async fn edge_snapshot(pool: &PgPool) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT jsonb_build_object('id', id, 'labels', labels, 'properties', properties, \
                                   'signature', encode(signature, 'hex'), \
                                   'content_hash', encode(content_hash, 'hex'), \
                                   'signer_id', signer_id, 'valid_to', valid_to)::text \
           FROM edges ORDER BY id",
    )
    .fetch_all(pool)
    .await
    .expect("snapshot")
}

async fn audit_count(pool: &PgPool, event: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM security_events WHERE event_type = $1")
        .bind(event)
        .fetch_one(pool)
        .await
        .expect("audit count")
}

async fn register_legacy(pool: &PgPool) -> Uuid {
    let r = run_op(
        pool,
        &[
            "register-system-agent",
            "--role",
            "legacy-ingest",
            "--create-agent",
            "--reason",
            "the legacy ingest-marker backfill principal",
            "--apply",
        ],
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.show());
    sqlx::query_scalar("SELECT agent_id FROM system_agents WHERE role = 'legacy-ingest'")
        .fetch_one(pool)
        .await
        .expect("registered")
}

fn classify<'a>(fx: &Fx, s: &'a str, attest: &'a str) -> Vec<&'a str> {
    let _ = fx;
    vec!["--ingest-signer", s, "--attestation-signer", attest]
}

/// The whole act: before it every reader reads the legacy fixture as nothing;
/// a dry run writes nothing and plans exactly the stampable edges; the apply
/// makes every reader read it as it did before the marker existed, per
/// principal, keeps every signed row's attestation byte for byte, and writes
/// the one provable creation record; the reversal restores every edge row
/// exactly.
#[sqlx::test(migrations = "../../migrations")]
async fn a_backfill_makes_legacy_edges_read_as_before_the_marker_and_reverses_exactly(
    pool: PgPool,
) {
    let fx = seed(&pool).await;
    let scoped = app_pool(&pool).await;
    let (reader, _) = fixture::seed_agent_with_group(&pool, "backfill-reader").await;

    // The marker era: nothing reads.
    for who in [fx.a, fx.b, fx.d, fx.w, fx.x] {
        assert_eq!(
            counts(&pool, &scoped, reader, who).await,
            (0, 0, 0),
            "CALIBRATION: a pre-marker edge never counts"
        );
    }
    assert_eq!(
        authored_by(&pool, &scoped, reader, fx.c2).await["source"],
        "agent"
    );

    let legacy = register_legacy(&pool).await;
    let (s, attest) = (fx.s.to_string(), fx.attest.to_string());
    let before = edge_snapshot(&pool).await;

    // Dry run: read-only, the plan, every signer unclassified.
    let dry = run_op(&pool, &["backfill-ingest-markers"]).await;
    assert_eq!(dry.code, 0, "{}", dry.show());
    assert!(
        dry.stdout.contains("TOTAL\tedges_to_stamp=14"),
        "{}",
        dry.show()
    );
    assert!(
        dry.stdout
            .contains("KIND\tagent-authored-paper\tcandidates=5"),
        "{}",
        dry.show()
    );
    assert!(
        dry.stdout
            .contains("KIND\tpaper-asserts-claim\tcandidates=4"),
        "{}",
        dry.show()
    );
    assert!(
        dry.stdout
            .contains("KIND\tagent-asserts-claim\tcandidates=5"),
        "{}",
        dry.show()
    );
    assert!(
        dry.stdout
            .contains("TRIANGLES\tlegacy=5\tsplit_by_principal=1"),
        "{}",
        dry.show()
    );
    assert!(
        dry.stdout.contains("CREATION-RECORDS\tprovable=1"),
        "{}",
        dry.show()
    );
    assert!(dry.stdout.contains("UNCLASSIFIED"), "{}", dry.show());
    // The classification evidence: S's paper assertions target claims S
    // filed; the attestation identity's do not.
    let signer_line = |id: Uuid| {
        dry.stdout
            .lines()
            .find(|l| l.starts_with(&format!("SIGNER\t{id}")))
            .unwrap_or_else(|| panic!("no SIGNER line for {id}: {}", dry.show()))
            .to_string()
    };
    assert!(
        signer_line(fx.s).contains("paper_asserts_onto_claims_it_filed=2/2"),
        "{}",
        dry.show()
    );
    assert!(
        signer_line(fx.attest).contains("paper_asserts_onto_claims_it_filed=0/1"),
        "{}",
        dry.show()
    );
    assert_eq!(
        edge_snapshot(&pool).await,
        before,
        "a dry run writes nothing"
    );

    // Refusals: unclassified signers, then a wrong count. Nothing written.
    let m0 = scratch("refused.jsonl");
    let refused = run_op(
        &pool,
        &[
            "backfill-ingest-markers",
            "--apply",
            "--confirm-count",
            "14",
            "--manifest-out",
            m0.to_str().unwrap(),
            "--ruling",
            "test ruling",
            "--reason",
            "test",
        ],
    )
    .await;
    assert_ne!(refused.code, 0, "{}", refused.show());
    assert!(
        refused.stderr.contains("not classified"),
        "{}",
        refused.show()
    );
    let mut args = vec![
        "backfill-ingest-markers",
        "--apply",
        "--confirm-count",
        "13",
        "--manifest-out",
        m0.to_str().unwrap(),
        "--ruling",
        "test ruling",
        "--reason",
        "test",
    ];
    args.extend(classify(&fx, &s, &attest));
    let wrong = run_op(&pool, &args).await;
    assert_ne!(wrong.code, 0, "{}", wrong.show());
    assert!(wrong.stderr.contains("does not match"), "{}", wrong.show());
    assert_eq!(
        edge_snapshot(&pool).await,
        before,
        "a refused run writes nothing"
    );
    assert_eq!(audit_count(&pool, "ingest_marker.backfill").await, 0);

    // Apply.
    let manifest = scratch("backfill-1.jsonl");
    let mut args = vec![
        "backfill-ingest-markers",
        "--apply",
        "--confirm-count",
        "14",
        "--manifest-out",
        manifest.to_str().unwrap(),
        "--ruling",
        "test ruling",
        "--reason",
        "test",
        "--batch-size",
        "3",
    ];
    args.extend(classify(&fx, &s, &attest));
    let applied = run_op(&pool, &args).await;
    assert_eq!(applied.code, 0, "{}", applied.show());
    assert!(
        applied.stdout.contains("CREATION-RECORDS-WRITTEN\t1"),
        "{}",
        applied.show()
    );
    assert_eq!(audit_count(&pool, "ingest_marker.backfill").await, 1);

    // Every reader reads the legacy fixture as before the marker era.
    assert_eq!(
        counts(&pool, &scoped, reader, fx.a).await,
        (2, 0, 2),
        "A: P1+P3, C1+C3"
    );
    assert_eq!(
        counts(&pool, &scoped, reader, fx.b).await,
        (1, 0, 2),
        "B: P2, C2+C4 (all S's)"
    );
    assert_eq!(
        counts(&pool, &scoped, reader, fx.d).await,
        (1, 0, 0),
        "D's triangle is split between principals: its claim still reads 0"
    );
    assert_eq!(
        counts(&pool, &scoped, reader, fx.w).await,
        (1, 0, 0),
        "a workflow attribution is never stamped"
    );
    assert_eq!(
        counts(&pool, &scoped, reader, fx.x).await,
        (0, 0, 0),
        "an asserts edge with no legacy authorship of the paper is not stamped"
    );
    let mut ab = vec![fx.a, fx.w];
    ab.sort();
    assert_eq!(
        listing(&pool, &scoped, fx.p1, legacy).await,
        (vec![legacy], ab, 1)
    );
    let mut p2_principals = vec![legacy, fx.s];
    p2_principals.sort();
    assert_eq!(
        listing(&pool, &scoped, fx.p2, fx.s).await,
        (p2_principals, vec![fx.b], 2),
        "query_paper lists S's own ingest of P2"
    );
    assert_eq!(
        listing(&pool, &scoped, fx.p3, legacy).await,
        (vec![legacy], vec![fx.a], 1),
        "an attestation-signed edge reads as the legacy ingest"
    );
    // The provable creation: C2 reads as P2's literature, B its author.
    let c2 = authored_by(&pool, &scoped, reader, fx.c2).await;
    assert_eq!(c2["source"], "literature", "{c2}");
    assert_eq!(c2["paper"]["paper"]["id"], serde_json::json!(fx.p2), "{c2}");
    let primary: Vec<serde_json::Value> = c2["paper"]["authors"]
        .as_array()
        .expect("authors")
        .iter()
        .map(|a| a["id"].clone())
        .collect();
    assert_eq!(primary, vec![serde_json::json!(fx.b)], "{c2}");
    assert_eq!(
        c2["ingested_by"]["agent"]["id"],
        serde_json::json!(fx.s),
        "{c2}"
    );
    // No provable creation: keeps reading as filed by its agent.
    for (c, filer) in [(fx.c1, fx.f), (fx.c3, fx.f), (fx.c4, fx.s)] {
        let block = authored_by(&pool, &scoped, reader, c).await;
        assert_eq!(block["source"], "agent", "{block}");
        assert_eq!(block["agent"]["id"], serde_json::json!(filer), "{block}");
    }
    // The attestation is untouched: a signed row's properties, signature and
    // content hash are what was signed.
    for id in &fx.signed {
        let (props, sig, hash): (serde_json::Value, Vec<u8>, Vec<u8>) =
            sqlx::query_as("SELECT properties, signature, content_hash FROM edges WHERE id = $1")
                .bind(id)
                .fetch_one(&pool)
                .await
                .expect("signed row");
        let was = before
            .iter()
            .find(|r| r.contains(&id.to_string()))
            .expect("in the snapshot");
        assert!(!props.as_object().unwrap().contains_key("ingest_written"));
        assert!(was.contains(&hex::encode(&sig)), "signature changed: {was}");
        assert!(
            was.contains(&hex::encode(&hash)),
            "content hash changed: {was}"
        );
    }

    // A second run finds nothing left to stamp.
    let again = run_op(&pool, &["backfill-ingest-markers"]).await;
    assert!(
        again.stdout.contains("TOTAL\tedges_to_stamp=0"),
        "{}",
        again.show()
    );

    // Reverse: every edge row exactly as before, the record gone.
    let dry_rev = run_op(
        &pool,
        &[
            "reverse-ingest-markers",
            "--manifest",
            manifest.to_str().unwrap(),
        ],
    )
    .await;
    assert_eq!(dry_rev.code, 0, "{}", dry_rev.show());
    assert!(
        dry_rev
            .stdout
            .contains("WOULD BE REVERSED\tedges_restored=14"),
        "{}",
        dry_rev.show()
    );
    let rev = run_op(
        &pool,
        &[
            "reverse-ingest-markers",
            "--manifest",
            manifest.to_str().unwrap(),
            "--apply",
        ],
    )
    .await;
    assert_eq!(rev.code, 0, "{}", rev.show());
    assert!(
        rev.stdout
            .contains("REVERSED\tedges_restored=14\tedges_held=0\trecords_deleted=1"),
        "{}",
        rev.show()
    );
    assert_eq!(
        edge_snapshot(&pool).await,
        before,
        "the reversal restores every edge row"
    );
    assert_eq!(
        audit_count(&pool, "ingest_marker.backfill_reverse").await,
        1
    );
    assert_eq!(counts(&pool, &scoped, reader, fx.a).await, (0, 0, 0));
}

/// `--apply` refuses before any write when no `legacy-ingest` principal is
/// registered.
#[sqlx::test(migrations = "../../migrations")]
async fn apply_refuses_without_the_legacy_principal(pool: PgPool) {
    let fx = seed(&pool).await;
    let before = edge_snapshot(&pool).await;
    let m = scratch("unregistered.jsonl");
    let (s, attest) = (fx.s.to_string(), fx.attest.to_string());
    let mut args = vec![
        "backfill-ingest-markers",
        "--apply",
        "--confirm-count",
        "14",
        "--manifest-out",
        m.to_str().unwrap(),
        "--ruling",
        "test ruling",
        "--reason",
        "test",
    ];
    args.extend(classify(&fx, &s, &attest));
    let r = run_op(&pool, &args).await;
    assert_ne!(r.code, 0, "{}", r.show());
    assert!(r.stderr.contains("legacy-ingest"), "{}", r.show());
    assert_eq!(edge_snapshot(&pool).await, before);
    assert!(!m.exists(), "no manifest for a refused run");
}

/// The principal is created with a key whose secret never existed, and the
/// registration is 148's own (audited, immutable): a second create is a
/// no-op naming the registered agent.
#[sqlx::test(migrations = "../../migrations")]
async fn the_legacy_principal_is_registered_once(pool: PgPool) {
    let dry = run_op(
        &pool,
        &[
            "register-system-agent",
            "--role",
            "legacy-ingest",
            "--create-agent",
            "--reason",
            "test",
        ],
    )
    .await;
    assert_eq!(dry.code, 0, "{}", dry.show());
    assert!(
        dry.stdout.contains("WOULD BE CREATED-AND-REGISTERED"),
        "{}",
        dry.show()
    );
    let none: Option<Uuid> =
        sqlx::query_scalar("SELECT agent_id FROM system_agents WHERE role = 'legacy-ingest'")
            .fetch_optional(&pool)
            .await
            .expect("read");
    assert_eq!(none, None, "a dry run registers nothing");
    let id = register_legacy(&pool).await;
    let again = run_op(
        &pool,
        &[
            "register-system-agent",
            "--role",
            "legacy-ingest",
            "--create-agent",
            "--reason",
            "test",
            "--apply",
        ],
    )
    .await;
    assert_eq!(again.code, 0, "{}", again.show());
    assert!(
        again.stdout.contains(&format!(
            "ALREADY-REGISTERED\trole=legacy-ingest\tagent={id}"
        )),
        "{}",
        again.show()
    );
    let audited: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM security_events WHERE event_type = 'operator.system_agent_registered'",
    )
    .fetch_one(&pool)
    .await
    .expect("audit");
    assert_eq!(audited, 1);
}
