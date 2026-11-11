//! `epigraph-operator backfill-ingest-markers` and `reverse-ingest-markers`,
//! driven through the real binary against a `#[sqlx::test]` database migrated
//! 001 -> head, then read back through the provenance readers (the agent
//! card's counts, `query_paper`'s per-ingest listing, a claim's
//! `authored_by` and its `ingesters`) on an `epigraph_app` session.
//!
//! # The legacy fixture
//!
//! Edges written before the ingest marker existed, each seeded raw. Every
//! paper's edges take ONE principal: the real ingest signer when all of its
//! real-signed `authored` and paper `asserts` edges name one, else the
//! `legacy-ingest` principal.
//!
//! * P1, UNSIGNED (legacy-ingest): A, W, V and M authored P1; P1 asserts C1
//!   and C6; A asserts C1 (a chain). W's `asserts` C1 is a workflow
//!   attribution (excluded); X asserts C1 with no authorship (excluded).
//! * P2, SIGNED by the ingesting agent S (principal S): B authored P2, P2
//!   asserts C2 and C4, B asserts both, all signed by S. D and M authored P2
//!   UNSIGNED, and P2 asserts C6 unsigned: they take S, the paper's
//!   principal. D asserts C2 signed by D's OWN key, a signer nobody
//!   classifies (an agent -> claim edge takes its principal from its paper,
//!   so its signer needs no classification). C2 is filed by S and carries S's
//!   extraction trace of P2 (a provable creation); C4, also S's, carries an
//!   extraction trace of ANOTHER document (no creation record).
//! * P3, signed by a bulk ATTESTATION identity (legacy-ingest): A authored
//!   P3, P3 asserts C3, A asserts C3.
//! * P4, CONFLICTING real signers (legacy-ingest): E authored P4 signed by S,
//!   G authored P4 signed by a second ingester S2; P4 asserts C5 signed by S;
//!   E asserts C5 signed by S. C5 is filed by S with S's extraction trace of
//!   P4, but the paper's principal is legacy-ingest, so no creation record.
//! * M asserts C6, closing chains through P1 (legacy-ingest, the OLDER paper
//!   assertion) and P2 (S): it takes the principal of its oldest chain.
//! * LATE edges, written after the `--written-before` cutoff: V asserts C1;
//!   L authored P1 (a late leg), and L asserts C1 before the cutoff. None is
//!   stamped under the cutoff.
//!
//! Before the run every reader reads these as nothing (the marker era); after
//! it they read as one ingest per paper.
//!
//! All names and identifiers are invented.

mod viewer_fixture;

use epigraph_db::pool::{ScopedPool, SessionGucMode};
use epigraph_db::visibility::Viewer;
use epigraph_db::{
    AgentLookupRepository, AuthoredByRepository, ClaimIngestRepository, PaperRepository,
};
use sqlx::PgPool;
use std::collections::BTreeSet;
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
    run_op_env(pool, args, &[]).await
}

/// [`run_op`] with extra environment variables (the test-only crash hook).
async fn run_op_env(pool: &PgPool, args: &[&str], env: &[(&str, &str)]) -> Run {
    let url = fixture::database_url_for(pool).await;
    let out = Command::new(BIN)
        .args(args)
        .envs(env.iter().copied())
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
/// it, and the backfill must leave it byte for byte). `late` writes it an
/// hour after the transaction's own clock: after the run's cutoff.
async fn edge_at(
    pool: &PgPool,
    src: (Uuid, &str),
    tgt: (Uuid, &str),
    rel: &str,
    props: serde_json::Value,
    signer: Option<Uuid>,
    late: bool,
) -> Uuid {
    edge_row(pool, src, tgt, rel, props, signer, late, false).await
}

/// [`edge_at`], RETRACTED when `retracted` (its `valid_to` written at insert,
/// a millisecond after it: out of force by the time any run reads it).
#[allow(clippy::too_many_arguments)]
async fn edge_row(
    pool: &PgPool,
    src: (Uuid, &str),
    tgt: (Uuid, &str),
    rel: &str,
    props: serde_json::Value,
    signer: Option<Uuid>,
    late: bool,
    retracted: bool,
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
                            properties, signature, signer_id, content_hash, created_at, valid_to) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, \
                 CASE WHEN $10 THEN now() + interval '1 hour' ELSE now() END, \
                 CASE WHEN $11 THEN now() + interval '1 millisecond' END) RETURNING id",
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
    .bind(late)
    .bind(retracted)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("seed {rel} edge: {e}"))
}

async fn edge(
    pool: &PgPool,
    src: (Uuid, &str),
    tgt: (Uuid, &str),
    rel: &str,
    props: serde_json::Value,
    signer: Option<Uuid>,
) -> Uuid {
    edge_at(pool, src, tgt, rel, props, signer, false).await
}

/// `claim`'s reasoning trace, written right after the claim (the walk hangs
/// its extraction trace only on a claim it creates).
async fn trace(pool: &PgPool, claim: Uuid, explanation: &str) {
    let t: Uuid = sqlx::query_scalar(
        "INSERT INTO reasoning_traces (claim_id, reasoning_type, explanation, created_at) \
         SELECT $1, 'deductive', $2, c.created_at + interval '2 seconds' \
           FROM claims c WHERE c.id = $1 RETURNING id",
    )
    .bind(claim)
    .bind(explanation)
    .fetch_one(pool)
    .await
    .expect("trace");
    sqlx::query("UPDATE claims SET trace_id = $2 WHERE id = $1")
        .bind(claim)
        .bind(t)
        .execute(pool)
        .await
        .expect("trace id");
}

#[allow(dead_code)]
struct Fx {
    s: Uuid,
    s2: Uuid,
    attest: Uuid,
    f: Uuid,
    a: Uuid,
    b: Uuid,
    d: Uuid,
    e: Uuid,
    g: Uuid,
    l: Uuid,
    m: Uuid,
    v: Uuid,
    w: Uuid,
    x: Uuid,
    papers: [Uuid; 4],
    claims: [Uuid; 6],
    signed: Vec<Uuid>,
    /// The cutoff: after every legacy edge, before every late one.
    t: String,
}

async fn seed(pool: &PgPool) -> Fx {
    let (s, _) = fixture::seed_agent_with_group(pool, "backfill-ingester").await;
    let (s2, _) = fixture::seed_agent_with_group(pool, "backfill-ingester-two").await;
    let (attest, _) = fixture::seed_agent_with_group(pool, "backfill-attestation").await;
    let (f, _) = fixture::seed_agent_with_group(pool, "backfill-filer").await;
    let mut au = Vec::new();
    for n in ["a", "b", "d", "e", "g", "l", "m", "v", "w", "x"] {
        au.push(
            fixture::seed_agent_with_group(pool, &format!("backfill-author-{n}"))
                .await
                .0,
        );
    }
    let (a, b, d, e, g, l, m, v, w, x) = (
        au[0], au[1], au[2], au[3], au[4], au[5], au[6], au[7], au[8], au[9],
    );
    let p1 = paper(pool, "10.9999/backfill-unsigned", "Unsigned Legacy").await;
    let p2 = paper(pool, "10.9999/backfill-signed", "Signed Legacy").await;
    let p3 = paper(pool, "10.9999/backfill-attested", "Attested Legacy").await;
    let p4 = paper(pool, "10.9999/backfill-conflict", "Conflicting Legacy").await;
    let c1 = fixture::seed_public_claim(pool, f, "a legacy unsigned finding").await;
    let c2 = fixture::seed_public_claim(pool, s, "a legacy signed finding").await;
    let c3 = fixture::seed_public_claim(pool, f, "a legacy attested finding").await;
    let c4 = fixture::seed_public_claim(pool, s, "a legacy signed finding of another source").await;
    let c5 = fixture::seed_public_claim(pool, s, "a legacy finding of a conflicted paper").await;
    let c6 = fixture::seed_public_claim(pool, f, "a legacy finding two papers state").await;
    trace(
        pool,
        c2,
        "Extracted from 'Signed Legacy' (DOI: 10.9999/backfill-signed); level 3 (atom)",
    )
    .await;
    trace(
        pool,
        c4,
        "Extracted from 'Elsewhere' (DOI: 10.9999/backfill-elsewhere); level 3 (atom)",
    )
    .await;
    trace(
        pool,
        c5,
        "Extracted from 'Conflicting Legacy' (DOI: 10.9999/backfill-conflict); level 3 (atom)",
    )
    .await;

    let empty = || serde_json::json!({});
    let pos = |n: i64| serde_json::json!({"position": n, "role": "author"});
    let ag = |id: Uuid| (id, "agent");
    let pa = |id: Uuid| (id, "paper");
    let cl = |id: Uuid| (id, "claim");
    let mut signed = Vec::new();

    // P1, unsigned. P1's assertion of C6 is written BEFORE P2's: M's oldest
    // chain onto C6 runs through P1.
    edge(pool, ag(a), pa(p1), "authored", pos(0), None).await;
    edge(pool, ag(w), pa(p1), "authored", pos(1), None).await;
    edge(pool, ag(v), pa(p1), "authored", pos(2), None).await;
    edge(pool, ag(m), pa(p1), "authored", pos(3), None).await;
    edge(pool, pa(p1), cl(c1), "asserts", empty(), None).await;
    edge(pool, pa(p1), cl(c6), "asserts", empty(), None).await;
    edge(pool, ag(a), cl(c1), "asserts", empty(), None).await;
    edge(
        pool,
        ag(w),
        cl(c1),
        "asserts",
        serde_json::json!({"source": "workflow_attribution", "role": "author"}),
        None,
    )
    .await;
    edge(pool, ag(x), cl(c1), "asserts", empty(), None).await;
    edge(pool, ag(l), cl(c1), "asserts", empty(), None).await;

    // P2, signed by S; D's and M's authorships and P2's assertion of C6
    // unsigned; D's assertion of C2 signed by D's own key.
    for (src, tgt, rel, props) in [
        (ag(b), pa(p2), "authored", pos(0)),
        (pa(p2), cl(c2), "asserts", empty()),
        (ag(b), cl(c2), "asserts", empty()),
        (pa(p2), cl(c4), "asserts", empty()),
        (ag(b), cl(c4), "asserts", empty()),
    ] {
        signed.push(edge(pool, src, tgt, rel, props, Some(s)).await);
    }
    edge(pool, ag(d), pa(p2), "authored", pos(1), None).await;
    edge(pool, ag(m), pa(p2), "authored", pos(2), None).await;
    edge(pool, pa(p2), cl(c6), "asserts", empty(), None).await;
    signed.push(edge(pool, ag(d), cl(c2), "asserts", empty(), Some(d)).await);
    edge(pool, ag(m), cl(c6), "asserts", empty(), None).await;

    // P3, signed by the attestation identity.
    for (src, tgt, rel, props) in [
        (ag(a), pa(p3), "authored", pos(0)),
        (pa(p3), cl(c3), "asserts", empty()),
        (ag(a), cl(c3), "asserts", empty()),
    ] {
        signed.push(edge(pool, src, tgt, rel, props, Some(attest)).await);
    }

    // P4, two real signers.
    for (src, tgt, rel, props, by) in [
        (ag(e), pa(p4), "authored", pos(0), s),
        (ag(g), pa(p4), "authored", pos(1), s2),
        (pa(p4), cl(c5), "asserts", empty(), s),
        (ag(e), cl(c5), "asserts", empty(), s),
    ] {
        signed.push(edge(pool, src, tgt, rel, props, Some(by)).await);
    }

    // The cutoff, from the database's clock: after every edge above.
    let t: String = sqlx::query_scalar(
        "SELECT to_char((max(created_at) + interval '1 millisecond') AT TIME ZONE 'UTC', \
                        'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') FROM edges",
    )
    .fetch_one(pool)
    .await
    .expect("cutoff");
    // Late: written after the cutoff.
    edge_at(pool, ag(v), cl(c1), "asserts", empty(), None, true).await;
    edge_at(pool, ag(l), pa(p1), "authored", pos(4), None, true).await;

    Fx {
        s,
        s2,
        attest,
        f,
        a,
        b,
        d,
        e,
        g,
        l,
        m,
        v,
        w,
        x,
        papers: [p1, p2, p3, p4],
        claims: [c1, c2, c3, c4, c5, c6],
        signed,
        t,
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

/// One ingest's word on one claim: `(paper, principal, claim, created_claim)`.
type IngestFact = (Uuid, Uuid, Uuid, bool);

/// The per-ingest invariant, read both ways as a public reader: every
/// `(paper, principal, claim, created_claim)` `query_paper` lists
/// (`ingest_principals` x `list_asserted_claims_by`) over `papers`, and every
/// one `get_claim`'s `ingesters` lists (`ClaimIngestRepository::for_claim`)
/// over `claims`. Returns both sets.
async fn ingest_facts(
    pool: &PgPool,
    scoped: &ScopedPool,
    papers: &[Uuid],
    claims: &[Uuid],
) -> (BTreeSet<IngestFact>, BTreeSet<IngestFact>) {
    let v = fixture::public_viewer(pool).await;
    let mut read = scoped.read_as(&v).await.expect("read");
    let mut by_paper = BTreeSet::new();
    for p in papers {
        for principal in PaperRepository::ingest_principals(&mut *read, &v, *p, 50)
            .await
            .expect("principals")
        {
            for row in PaperRepository::list_asserted_claims_by(
                &mut *read,
                &v,
                *p,
                principal.ingested_by,
                500,
                0,
            )
            .await
            .expect("claims by")
            {
                by_paper.insert((*p, principal.ingested_by, row.claim.id, row.created_claim));
            }
        }
    }
    let mut by_claim = BTreeSet::new();
    for c in claims {
        for r in ClaimIngestRepository::for_claim(&mut read, &v, *c)
            .await
            .expect("ingesters")
            .records
        {
            by_claim.insert((r.paper_id, r.ingested_by, *c, r.created_claim));
        }
    }
    read.commit().await.expect("finish");
    (by_paper, by_claim)
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

async fn stamped_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM edges WHERE labels @> ARRAY['epigraph:ingest_written']::text[]",
    )
    .fetch_one(pool)
    .await
    .expect("stamped")
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

/// S and S2 are real ingesters, the attestation identity is not. D (who
/// signed only an agent -> claim edge) is left unclassified on purpose.
fn classify(fx: &Fx) -> Vec<String> {
    vec![
        "--ingest-signer".into(),
        fx.s.to_string(),
        "--ingest-signer".into(),
        fx.s2.to_string(),
        "--attestation-signer".into(),
        fx.attest.to_string(),
    ]
}

/// `backfill-ingest-markers --apply` with the given count, manifest and
/// extra arguments, every signer classified, under the fixture's cutoff.
async fn apply(
    pool: &PgPool,
    fx: &Fx,
    count: u64,
    manifest: &std::path::Path,
    extra: &[&str],
) -> Run {
    apply_as(pool, &fx.t, classify(fx), count, manifest, extra, &[]).await
}

/// `backfill-ingest-markers --apply` under cutoff `t` with the given
/// classification flags.
async fn apply_as(
    pool: &PgPool,
    t: &str,
    classes: Vec<String>,
    count: u64,
    manifest: &std::path::Path,
    extra: &[&str],
    env: &[(&str, &str)],
) -> Run {
    let count = count.to_string();
    let mut args: Vec<String> = [
        "backfill-ingest-markers",
        "--apply",
        "--confirm-count",
        &count,
        "--written-before",
        t,
        "--manifest-out",
        manifest.to_str().unwrap(),
        "--ruling",
        "test ruling",
        "--reason",
        "test",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect();
    args.extend(classes);
    args.extend(extra.iter().map(|s| (*s).to_string()));
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    run_op_env(pool, &refs, env).await
}

/// The whole act. Before it every reader reads the legacy fixture as
/// nothing. A dry run writes nothing and plans exactly the stampable edges
/// under the cutoff, one principal per paper. The apply makes each paper read
/// as ONE ingest (its principal's), keeps every signed row's attestation byte
/// for byte, writes the one provable creation record and a non-creation
/// record for every other stamped assertion, so `query_paper` and
/// `get_claim`'s `ingesters` agree on every claim. The reversal restores
/// every edge row exactly.
#[sqlx::test(migrations = "../../migrations")]
async fn a_backfill_reads_each_legacy_paper_as_one_ingest_and_reverses_exactly(pool: PgPool) {
    let fx = seed(&pool).await;
    let [p1, p2, p3, p4] = fx.papers;
    let [c1, c2, c3, c4, c5, c6] = fx.claims;
    let scoped = app_pool(&pool).await;
    let (reader, _) = fixture::seed_agent_with_group(&pool, "backfill-reader").await;

    // The marker era: nothing reads.
    for who in [fx.a, fx.b, fx.d, fx.e, fx.g, fx.m, fx.v, fx.w, fx.x] {
        assert_eq!(
            counts(&pool, &scoped, reader, who).await,
            (0, 0, 0),
            "CALIBRATION: a pre-marker edge never counts"
        );
    }
    assert_eq!(
        authored_by(&pool, &scoped, reader, c2).await["source"],
        "agent"
    );

    let legacy = register_legacy(&pool).await;
    let before = edge_snapshot(&pool).await;

    // Dry run with no cutoff: every unmarked edge counts, late ones too.
    let open = run_op(&pool, &["backfill-ingest-markers"]).await;
    assert_eq!(open.code, 0, "{}", open.show());
    assert!(
        open.stdout.contains("CUTOFF\twritten_before=none"),
        "{}",
        open.show()
    );
    assert!(
        open.stdout.contains("TOTAL\tedges_to_stamp=27"),
        "{}",
        open.show()
    );

    // Dry run under the cutoff, classified: the plan.
    let mut args = vec![
        "backfill-ingest-markers".to_string(),
        "--written-before".into(),
        fx.t.clone(),
    ];
    args.extend(classify(&fx));
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let dry = run_op(&pool, &refs).await;
    assert_eq!(dry.code, 0, "{}", dry.show());
    for want in [
        format!("CUTOFF\twritten_before={}", fx.t),
        "KIND\tagent-authored-paper\tcandidates=10".to_string(),
        "KIND\tpaper-asserts-claim\tcandidates=7".to_string(),
        "KIND\tagent-asserts-claim\tcandidates=7".to_string(),
        "PAPERS\tpapers=4\tby_one_ingest_signer=1\tlegacy_ingest_no_real_signer=2\t\
         legacy_ingest_conflicting_signers=1"
            .to_string(),
        format!("PAPER-PRINCIPAL\t{}\tpapers=1", fx.s),
        "CHAINS\tchains=8\tchains_on_another_principal=1\tagent_asserts_multi_principal=1"
            .to_string(),
        "CREATION-RECORDS\tprovable=1".to_string(),
        "NON-CREATION-RECORDS\tplanned=6".to_string(),
        "TOTAL\tedges_to_stamp=24".to_string(),
    ] {
        assert!(
            dry.stdout.contains(&want),
            "missing {want:?}: {}",
            dry.show()
        );
    }
    let mut both = [fx.s, fx.s2];
    both.sort();
    assert!(
        dry.stdout.contains(&format!(
            "CONFLICT\tpaper={p4}\tsigners={},{}",
            both[0], both[1]
        )),
        "{}",
        dry.show()
    );
    let signer_line = |id: Uuid| {
        dry.stdout
            .lines()
            .find(|l| l.starts_with(&format!("SIGNER\t{id}")))
            .unwrap_or_else(|| panic!("no SIGNER line for {id}: {}", dry.show()))
            .to_string()
    };
    // The classification evidence: S's paper assertions target claims S
    // filed; the attestation identity's do not. D signed only an agent ->
    // claim edge: reported, never required.
    assert!(
        signer_line(fx.s).contains("authored=2\tpaper_asserts=3\tagent_asserts=3"),
        "{}",
        dry.show()
    );
    assert!(
        signer_line(fx.s).contains("paper_asserts_onto_claims_it_filed=3/3"),
        "{}",
        dry.show()
    );
    assert!(
        signer_line(fx.attest).contains("paper_asserts_onto_claims_it_filed=0/1"),
        "{}",
        dry.show()
    );
    assert!(
        signer_line(fx.d).contains("agent-asserts-only:info"),
        "{}",
        dry.show()
    );
    assert!(!dry.stdout.contains("UNCLASSIFIED"), "{}", dry.show());
    assert_eq!(
        edge_snapshot(&pool).await,
        before,
        "a dry run writes nothing"
    );

    // Refusals, nothing written: no cutoff; unclassified signers (D is never
    // among them); a wrong count.
    let m0 = scratch("refused.jsonl");
    let mut args = vec![
        "backfill-ingest-markers".to_string(),
        "--apply".into(),
        "--confirm-count".into(),
        "24".into(),
        "--manifest-out".into(),
        m0.to_str().unwrap().into(),
        "--ruling".into(),
        "test ruling".into(),
        "--reason".into(),
        "test".into(),
    ];
    args.extend(classify(&fx));
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let no_cut = run_op(&pool, &refs).await;
    assert_ne!(no_cut.code, 0, "{}", no_cut.show());
    assert!(
        no_cut.stderr.contains("--written-before"),
        "{}",
        no_cut.show()
    );
    let refused = run_op(
        &pool,
        &[
            "backfill-ingest-markers",
            "--apply",
            "--confirm-count",
            "24",
            "--written-before",
            &fx.t,
            "--manifest-out",
            m0.to_str().unwrap(),
            "--ruling",
            "test ruling",
            "--reason",
            "test",
            "--ingest-signer",
            &fx.s.to_string(),
        ],
    )
    .await;
    assert_ne!(refused.code, 0, "{}", refused.show());
    assert!(
        refused.stderr.contains("not classified")
            && refused.stderr.contains(&fx.s2.to_string())
            && !refused.stderr.contains(&fx.d.to_string()),
        "{}",
        refused.show()
    );
    let wrong = apply(&pool, &fx, 23, &m0, &[]).await;
    assert_ne!(wrong.code, 0, "{}", wrong.show());
    assert!(wrong.stderr.contains("does not match"), "{}", wrong.show());
    assert_eq!(
        edge_snapshot(&pool).await,
        before,
        "a refused run writes nothing"
    );
    assert_eq!(audit_count(&pool, "ingest_marker.backfill").await, 0);
    assert!(!m0.exists(), "no manifest for a refused run");

    // Apply.
    let manifest = scratch("backfill-1.jsonl");
    let applied = apply(&pool, &fx, 24, &manifest, &["--batch-size", "3"]).await;
    assert_eq!(applied.code, 0, "{}", applied.show());
    for want in [
        "CREATION-RECORDS-WRITTEN\t1",
        "NON-CREATION-RECORDS-WRITTEN\t6",
    ] {
        assert!(applied.stdout.contains(want), "{want}: {}", applied.show());
    }
    assert_eq!(audit_count(&pool, "ingest_marker.backfill").await, 1);
    let audit: serde_json::Value = sqlx::query_scalar(
        "SELECT details FROM security_events WHERE event_type = 'ingest_marker.backfill'",
    )
    .fetch_one(&pool)
    .await
    .expect("audit row");
    assert_eq!(audit["written_before"], serde_json::json!(fx.t), "{audit}");
    let header: serde_json::Value = serde_json::from_str(
        std::fs::read_to_string(&manifest)
            .expect("manifest")
            .lines()
            .next()
            .expect("header"),
    )
    .expect("header json");
    assert_eq!(
        header["written_before"],
        serde_json::json!(fx.t),
        "{header}"
    );

    // Each paper reads as one ingest: its principal's.
    let cards = [
        (fx.a, (2, 0, 2), "A: P1+P3, C1+C3 (both legacy-ingest)"),
        (fx.b, (1, 0, 2), "B: P2, C2+C4 (S)"),
        (
            fx.d,
            (1, 0, 1),
            "D: P2 and C2, all S's: the paper's principal",
        ),
        (
            fx.e,
            (1, 0, 1),
            "E: P4 and C5, all legacy-ingest (conflicting signers)",
        ),
        (fx.g, (1, 0, 0), "G: P4"),
        (
            fx.m,
            (2, 0, 1),
            "M: P1+P2, C6 once (its oldest chain, through P1)",
        ),
        (fx.v, (1, 0, 0), "V: P1; its late assertion is not stamped"),
        (
            fx.l,
            (0, 0, 0),
            "L: a late authorship is not stamped, nor its chain",
        ),
        (fx.w, (1, 0, 0), "a workflow attribution is never stamped"),
        (
            fx.x,
            (0, 0, 0),
            "an asserts edge with no legacy authorship is not stamped",
        ),
    ];
    for (who, want, why) in cards {
        assert_eq!(counts(&pool, &scoped, reader, who).await, want, "{why}");
    }
    // M's assertion of C6 closes chains through P1 (legacy-ingest, the older
    // paper assertion) and P2 (S): it takes its oldest chain's principal.
    let m_c6: Vec<String> = sqlx::query_scalar(
        "SELECT labels FROM edges WHERE source_id = $1 AND target_id = $2 \
            AND relationship = 'asserts'",
    )
    .bind(fx.m)
    .bind(c6)
    .fetch_one(&pool)
    .await
    .expect("M asserts C6");
    assert!(
        m_c6.contains(&format!("epigraph:ingest_written_by:{legacy}")),
        "the oldest chain's principal: {m_c6:?}"
    );
    let sorted = |mut v: Vec<Uuid>| {
        v.sort();
        v
    };
    assert_eq!(
        listing(&pool, &scoped, p1, legacy).await,
        (vec![legacy], sorted(vec![fx.a, fx.w, fx.v, fx.m]), 2)
    );
    assert_eq!(
        listing(&pool, &scoped, p2, fx.s).await,
        (vec![fx.s], sorted(vec![fx.b, fx.d, fx.m]), 3),
        "P2 is ONE ingest, S's: its unsigned edges take the paper's principal"
    );
    assert_eq!(
        listing(&pool, &scoped, p3, legacy).await,
        (vec![legacy], vec![fx.a], 1),
        "an attestation-signed paper reads as the legacy ingest"
    );
    assert_eq!(
        listing(&pool, &scoped, p4, legacy).await,
        (vec![legacy], sorted(vec![fx.e, fx.g]), 1),
        "a paper with two real signers reads as the legacy ingest"
    );

    // query_paper and get_claim's ingesters agree on every claim.
    let (by_paper, by_claim) = ingest_facts(&pool, &scoped, &fx.papers, &fx.claims).await;
    let want: BTreeSet<IngestFact> = [
        (p1, legacy, c1, false),
        (p1, legacy, c6, false),
        (p2, fx.s, c2, true),
        (p2, fx.s, c4, false),
        (p2, fx.s, c6, false),
        (p3, legacy, c3, false),
        (p4, legacy, c5, false),
    ]
    .into_iter()
    .collect();
    assert_eq!(by_paper, want, "query_paper's per-ingest listing");
    assert_eq!(
        by_claim, by_paper,
        "get_claim's ingesters disagree with query_paper"
    );

    // The provable creation: C2 reads as P2's literature, its primary authors
    // the authorships S's ingest of P2 holds (B, D, M in position order).
    let block = authored_by(&pool, &scoped, reader, c2).await;
    assert_eq!(block["source"], "literature", "{block}");
    assert_eq!(
        block["paper"]["paper"]["id"],
        serde_json::json!(p2),
        "{block}"
    );
    let primary: Vec<serde_json::Value> = block["paper"]["authors"]
        .as_array()
        .expect("authors")
        .iter()
        .map(|a| a["id"].clone())
        .collect();
    assert_eq!(
        primary,
        vec![
            serde_json::json!(fx.b),
            serde_json::json!(fx.d),
            serde_json::json!(fx.m)
        ],
        "{block}"
    );
    assert_eq!(
        block["ingested_by"]["agent"]["id"],
        serde_json::json!(fx.s),
        "{block}"
    );
    // No provable creation (C5: its paper's principal is legacy-ingest, which
    // can never be a filer): keeps reading as filed by its agent.
    for (c, filer) in [(c1, fx.f), (c3, fx.f), (c4, fx.s), (c5, fx.s), (c6, fx.f)] {
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

    // A second run under the same cutoff finds nothing left to stamp.
    let again = run_op(
        &pool,
        &["backfill-ingest-markers", "--written-before", &fx.t],
    )
    .await;
    assert!(
        again.stdout.contains("TOTAL\tedges_to_stamp=0"),
        "{}",
        again.show()
    );

    // Reverse: every edge row exactly as before, every record gone.
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
            .contains("WOULD BE REVERSED\tedges_restored=24"),
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
            .contains("REVERSED\tedges_restored=24\tedges_held=0\trecords_deleted=7"),
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
    let (by_paper, by_claim) = ingest_facts(&pool, &scoped, &fx.papers, &fx.claims).await;
    assert!(
        by_paper.is_empty() && by_claim.is_empty(),
        "{by_paper:?} {by_claim:?}"
    );
}

/// A reversal acts only on the batches its run COMMITTED. Run 1 stops after
/// one batch; run 2 (a new manifest) stamps the rest. Run 2's edges are then
/// appended to run 1's manifest as a batch with no commit line, as a batch
/// that failed after its lines were written would leave them. Reversing run 1
/// restores only its committed batch and leaves run 2's labels; reversing
/// run 2 then restores every edge row.
#[sqlx::test(migrations = "../../migrations")]
async fn a_reversal_acts_only_on_its_runs_committed_batches(pool: PgPool) {
    let fx = seed(&pool).await;
    let scoped = app_pool(&pool).await;
    register_legacy(&pool).await;
    let before = edge_snapshot(&pool).await;

    let m1 = scratch("run-1.jsonl");
    let r1 = apply(
        &pool,
        &fx,
        24,
        &m1,
        &["--batch-size", "3", "--max-batches", "1"],
    )
    .await;
    assert_eq!(r1.code, 0, "{}", r1.show());
    assert_eq!(stamped_count(&pool).await, 3, "CALIBRATION: one batch of 3");
    let m2 = scratch("run-2.jsonl");
    let r2 = apply(&pool, &fx, 21, &m2, &["--batch-size", "3"]).await;
    assert_eq!(r2.code, 0, "{}", r2.show());
    assert_eq!(stamped_count(&pool).await, 24, "CALIBRATION: all stamped");

    // Run 2's edge lines, appended to run 1's manifest as an uncommitted
    // batch.
    let mut appended = String::new();
    for line in std::fs::read_to_string(&m2).expect("m2").lines().skip(1) {
        let mut v: serde_json::Value = serde_json::from_str(line).expect("line");
        if v.get("edge").is_some() {
            v["batch"] = serde_json::json!(999);
            appended.push_str(&v.to_string());
            appended.push('\n');
        }
    }
    assert!(!appended.is_empty(), "CALIBRATION: run 2 stamped edges");
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(&m1)
        .expect("open m1");
    std::io::Write::write_all(&mut f, appended.as_bytes()).expect("append");
    drop(f);

    let rev1 = run_op(
        &pool,
        &[
            "reverse-ingest-markers",
            "--manifest",
            m1.to_str().unwrap(),
            "--apply",
        ],
    )
    .await;
    assert_eq!(rev1.code, 0, "{}", rev1.show());
    assert!(
        rev1.stdout
            .contains("REVERSED\tedges_restored=3\tedges_held=0\trecords_deleted=0"),
        "{}",
        rev1.show()
    );
    assert!(
        rev1.stdout.contains("UNCOMMITTED-BATCH\t999\tedges=21"),
        "{}",
        rev1.show()
    );
    assert_eq!(
        stamped_count(&pool).await,
        21,
        "run 2's labels survive the reversal of run 1"
    );
    let (by_paper, by_claim) = ingest_facts(&pool, &scoped, &fx.papers, &fx.claims).await;
    assert_eq!(
        by_paper.len(),
        7,
        "run 2's records still read: {by_paper:?}"
    );
    assert_eq!(by_claim, by_paper);

    let rev2 = run_op(
        &pool,
        &[
            "reverse-ingest-markers",
            "--manifest",
            m2.to_str().unwrap(),
            "--apply",
        ],
    )
    .await;
    assert_eq!(rev2.code, 0, "{}", rev2.show());
    assert_eq!(
        edge_snapshot(&pool).await,
        before,
        "both reversals restore every edge row"
    );
}

/// The record lines a manifest holds.
fn records_in(manifest: &std::path::Path) -> usize {
    std::fs::read_to_string(manifest)
        .expect("manifest")
        .lines()
        .skip(1)
        .filter(|l| {
            serde_json::from_str::<serde_json::Value>(l)
                .expect("line")
                .get("record")
                .is_some()
        })
        .count()
}

async fn record_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM edges WHERE relationship = 'ingested_claim'")
        .fetch_one(pool)
        .await
        .expect("records")
}

/// A PACED run (`--max-batches`, resumed with a new manifest) keeps
/// `query_paper` and `get_claim`'s `ingesters` agreeing after EVERY run and
/// after reversing any run alone, newest first: each run writes the ingest
/// records of exactly the paper assertions it stamped, even when it stops at
/// `--max-batches`, and its manifest holds those records only.
#[sqlx::test(migrations = "../../migrations")]
async fn a_paced_run_agrees_after_each_run_and_each_reversal(pool: PgPool) {
    let fx = seed(&pool).await;
    let scoped = app_pool(&pool).await;
    register_legacy(&pool).await;
    let before = edge_snapshot(&pool).await;

    // Run 1: four batches of the 10 authorships, then one batch of 3 paper
    // assertions, then its records.
    let m1 = scratch("paced-1.jsonl");
    let r1 = apply(
        &pool,
        &fx,
        24,
        &m1,
        &["--batch-size", "3", "--max-batches", "5"],
    )
    .await;
    assert_eq!(r1.code, 0, "{}", r1.show());
    assert!(
        r1.stdout.contains("STAMPED\tpaper-asserts-claim\t3"),
        "CALIBRATION: one batch of paper assertions: {}",
        r1.show()
    );
    assert_eq!(stamped_count(&pool).await, 13, "CALIBRATION");
    let (by_paper, by_claim) = ingest_facts(&pool, &scoped, &fx.papers, &fx.claims).await;
    assert_eq!(by_paper.len(), 3, "run 1's assertions read: {by_paper:?}");
    assert_eq!(
        by_claim, by_paper,
        "after a run that stopped at --max-batches, get_claim's ingesters disagree with \
         query_paper"
    );

    let m2 = scratch("paced-2.jsonl");
    let r2 = apply(&pool, &fx, 11, &m2, &["--batch-size", "3"]).await;
    assert_eq!(r2.code, 0, "{}", r2.show());
    assert_eq!(stamped_count(&pool).await, 24, "CALIBRATION: all stamped");
    let (by_paper, by_claim) = ingest_facts(&pool, &scoped, &fx.papers, &fx.claims).await;
    assert_eq!(by_paper.len(), 7, "{by_paper:?}");
    assert_eq!(by_claim, by_paper);
    assert_eq!(
        (records_in(&m1), records_in(&m2)),
        (3, 4),
        "each manifest holds the records of its own run's assertions"
    );

    // Reverse run 2 alone: run 1's stamps and records still agree.
    let rev2 = run_op(
        &pool,
        &[
            "reverse-ingest-markers",
            "--manifest",
            m2.to_str().unwrap(),
            "--apply",
        ],
    )
    .await;
    assert_eq!(rev2.code, 0, "{}", rev2.show());
    assert!(
        rev2.stdout
            .contains("REVERSED\tedges_restored=11\tedges_held=0\trecords_deleted=4"),
        "{}",
        rev2.show()
    );
    assert_eq!(stamped_count(&pool).await, 13);
    let (by_paper, by_claim) = ingest_facts(&pool, &scoped, &fx.papers, &fx.claims).await;
    assert_eq!(by_paper.len(), 3, "{by_paper:?}");
    assert_eq!(
        by_claim, by_paper,
        "after reversing run 2 alone, get_claim's ingesters disagree with query_paper"
    );

    let rev1 = run_op(
        &pool,
        &[
            "reverse-ingest-markers",
            "--manifest",
            m1.to_str().unwrap(),
            "--apply",
        ],
    )
    .await;
    assert_eq!(rev1.code, 0, "{}", rev1.show());
    assert!(
        rev1.stdout
            .contains("REVERSED\tedges_restored=13\tedges_held=0\trecords_deleted=3"),
        "{}",
        rev1.show()
    );
    assert_eq!(edge_snapshot(&pool).await, before);
}

/// The process KILLED between batches, after a paper-assertion batch
/// committed (a test-only hook aborts it there, as SIGKILL would: no
/// unwinding, no summary, no NEXT line). The batches it committed carry their
/// ingest records already, so `query_paper` and `get_claim`'s `ingesters`
/// agree with nothing repaired. Then the runbook's resume (a fresh dry run's
/// total, a new manifest) finishes the backfill, and the two manifests,
/// newest first, reverse it exactly with the readers agreeing after each.
/// `at` is where the hook aborts: `line` after the batch's `committed_batch`
/// line, `commit` right after its COMMIT, before that line.
#[cfg(debug_assertions)]
async fn a_run_killed_after_a_paper_assertion_batch(pool: PgPool, at: &str) {
    let fx = seed(&pool).await;
    let scoped = app_pool(&pool).await;
    register_legacy(&pool).await;
    let before = edge_snapshot(&pool).await;

    // Batch size 3: batches 1-4 are the 10 authorships, batch 5 the first
    // three paper assertions; the hook kills the run right after it.
    let m1 = scratch(&format!("killed-{at}.jsonl"));
    let crash = format!("5:{at}");
    let r1 = apply_as(
        &pool,
        &fx.t,
        classify(&fx),
        24,
        &m1,
        &["--batch-size", "3"],
        &[(
            epigraph_cli::operator::backfill_markers::TEST_CRASH_ENV,
            &crash,
        )],
    )
    .await;
    assert_eq!(
        r1.code,
        -1,
        "CALIBRATION: killed by a signal: {}",
        r1.show()
    );
    assert!(
        !r1.stdout.contains("MANIFEST\t") && !r1.stdout.contains("STAMPED\t"),
        "CALIBRATION: a killed run prints no summary: {}",
        r1.show()
    );
    assert_eq!(
        stamped_count(&pool).await,
        13,
        "CALIBRATION: 5 batches committed"
    );
    let (by_paper, by_claim) = ingest_facts(&pool, &scoped, &fx.papers, &fx.claims).await;
    assert_eq!(
        by_paper.len(),
        3,
        "CALIBRATION: the killed run's three paper assertions read: {by_paper:?}"
    );
    assert_eq!(
        by_claim, by_paper,
        "a run killed after a paper-assertion batch committed leaves get_claim's ingesters \
         disagreeing with query_paper"
    );
    assert_eq!(
        records_in(&m1),
        3,
        "the killed run's manifest holds its records"
    );

    // The runbook's resume.
    let mut dry: Vec<String> = vec![
        "backfill-ingest-markers".into(),
        "--written-before".into(),
        fx.t.clone(),
    ];
    dry.extend(classify(&fx));
    let dry: Vec<&str> = dry.iter().map(String::as_str).collect();
    let d = run_op(&pool, &dry).await;
    assert_eq!(d.code, 0, "{}", d.show());
    assert!(
        d.stdout.contains("TOTAL\tedges_to_stamp=11"),
        "{}",
        d.show()
    );
    let m2 = scratch(&format!("killed-{at}-resume.jsonl"));
    let r2 = apply(&pool, &fx, 11, &m2, &["--batch-size", "3"]).await;
    assert_eq!(r2.code, 0, "{}", r2.show());
    assert!(!r2.stdout.contains("NEXT\t"), "{}", r2.show());
    assert_eq!(stamped_count(&pool).await, 24);
    let (by_paper, by_claim) = ingest_facts(&pool, &scoped, &fx.papers, &fx.claims).await;
    assert_eq!(by_paper.len(), 7, "{by_paper:?}");
    assert_eq!(by_claim, by_paper);
    assert_eq!(
        by_paper.iter().filter(|f| f.3).count(),
        1,
        "the one provable creation record, whichever run wrote it: {by_paper:?}"
    );
    assert_eq!(records_in(&m1) + records_in(&m2), 7);

    // A kill after COMMIT but before the committed_batch line leaves batch 5
    // out of m1's committed set; the operator appends the line by hand first
    // (what the reversal's UNCOMMITTED-BATCH line says to check).
    if at == "commit" {
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&m1)
            .expect("manifest");
        std::io::Write::write_all(&mut f, b"{\"committed_batch\":5}\n").expect("append");
    }
    for (m, want) in [
        (
            &m2,
            "REVERSED\tedges_restored=11\tedges_held=0\trecords_deleted=4",
        ),
        (
            &m1,
            "REVERSED\tedges_restored=13\tedges_held=0\trecords_deleted=3",
        ),
    ] {
        let rev = run_op(
            &pool,
            &[
                "reverse-ingest-markers",
                "--manifest",
                m.to_str().unwrap(),
                "--apply",
            ],
        )
        .await;
        assert_eq!(rev.code, 0, "{}", rev.show());
        assert!(rev.stdout.contains(want), "{want}: {}", rev.show());
        let (by_paper, by_claim) = ingest_facts(&pool, &scoped, &fx.papers, &fx.claims).await;
        assert_eq!(by_claim, by_paper);
    }
    assert_eq!(edge_snapshot(&pool).await, before);
}

/// Killed between batches (after the `committed_batch` line).
#[cfg(debug_assertions)]
#[sqlx::test(migrations = "../../migrations")]
async fn a_run_killed_between_batches_leaves_the_readers_agreeing(pool: PgPool) {
    a_run_killed_after_a_paper_assertion_batch(pool, "line").await;
}

/// Killed right after a batch's COMMIT, before its `committed_batch` line:
/// the batch's records committed with its stamps all the same.
#[cfg(debug_assertions)]
#[sqlx::test(migrations = "../../migrations")]
async fn a_run_killed_right_after_a_commit_leaves_the_readers_agreeing(pool: PgPool) {
    a_run_killed_after_a_paper_assertion_batch(pool, "commit").await;
}

/// A REVERSAL killed part-way (the test-only hook aborts it after its fourth
/// committed transaction: newest first, the three agent-assertion batches,
/// then the last paper-assertion batch) leaves no stamp without its record:
/// each committed batch is reversed in one transaction, records and labels
/// together. The readers agree at the kill, and re-running the reversal
/// finishes the rest and restores every edge row exactly.
#[cfg(debug_assertions)]
#[sqlx::test(migrations = "../../migrations")]
async fn a_reversal_killed_part_way_leaves_the_readers_agreeing(pool: PgPool) {
    let fx = seed(&pool).await;
    let scoped = app_pool(&pool).await;
    register_legacy(&pool).await;
    let before = edge_snapshot(&pool).await;
    let m = scratch("reverse-killed.jsonl");
    let r = apply(&pool, &fx, 24, &m, &["--batch-size", "3"]).await;
    assert_eq!(r.code, 0, "{}", r.show());
    assert_eq!(records_in(&m), 7, "CALIBRATION");

    let args = [
        "reverse-ingest-markers",
        "--manifest",
        m.to_str().unwrap(),
        "--apply",
    ];
    let killed = run_op_env(
        &pool,
        &args,
        &[(
            epigraph_cli::operator::backfill_markers::TEST_CRASH_ENV,
            "4:reverse",
        )],
    )
    .await;
    assert_eq!(killed.code, -1, "CALIBRATION: killed: {}", killed.show());
    let (by_paper, by_claim) = ingest_facts(&pool, &scoped, &fx.papers, &fx.claims).await;
    assert_eq!(
        by_claim, by_paper,
        "a reversal killed part-way leaves get_claim's ingesters disagreeing with query_paper"
    );
    assert_eq!(by_paper.len(), 6, "CALIBRATION: {by_paper:?}");
    assert_eq!(
        stamped_count(&pool).await,
        16,
        "CALIBRATION: the 7 agent assertions and the last paper assertion restored"
    );

    let rerun = run_op(&pool, &args).await;
    assert_eq!(rerun.code, 0, "{}", rerun.show());
    assert!(
        rerun.stdout.contains(
            "REVERSED\tedges_restored=16\tedges_held=8\trecords_deleted=6\trecords_held=1"
        ),
        "{}",
        rerun.show()
    );
    assert_eq!(edge_snapshot(&pool).await, before);
}

/// A failed INGEST RECORD write rolls its paper-assertion batch back WITH its
/// stamps: a record is written in its stamps' own transaction, so no
/// committed batch ever lacks its records. The run reports the failure (exit
/// 2), its summary and a `NEXT` resume line (no reverse-first), and the
/// readers agree (the committed authorships, no paper assertion). Following
/// the resume finishes the backfill, and the two manifests reverse it
/// exactly.
#[sqlx::test(migrations = "../../migrations")]
async fn a_failed_record_write_rolls_back_its_batchs_stamps(pool: PgPool) {
    let fx = seed(&pool).await;
    let scoped = app_pool(&pool).await;
    register_legacy(&pool).await;
    let before = edge_snapshot(&pool).await;
    sqlx::query(
        "CREATE FUNCTION test_refuse_ingest_record() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN \
           IF NEW.relationship = 'ingested_claim' THEN \
             RAISE EXCEPTION 'test: ingest records refused'; \
           END IF; \
           RETURN NEW; \
         END $$",
    )
    .execute(&pool)
    .await
    .expect("refusing function");
    sqlx::query(
        "CREATE TRIGGER test_refuse_ingest_record BEFORE INSERT ON edges \
         FOR EACH ROW EXECUTE FUNCTION test_refuse_ingest_record()",
    )
    .execute(&pool)
    .await
    .expect("refusing trigger");

    let m1 = scratch("records-fail.jsonl");
    let r1 = apply(&pool, &fx, 24, &m1, &["--batch-size", "3"]).await;
    assert_eq!(r1.code, 2, "{}", r1.show());
    for want in [
        "STAMPED\tagent-authored-paper\t10",
        "\nCREATION-RECORDS-WRITTEN\t0",
        "NON-CREATION-RECORDS-WRITTEN\t0",
        "BATCH-FAILED\tpaper-asserts-claim batch 5",
        "test: ingest records refused",
        "MANIFEST\t",
        "NEXT\tresume:",
    ] {
        assert!(r1.stdout.contains(want), "{want}: {}", r1.show());
    }
    assert!(
        !r1.stdout.contains("STAMPED\tpaper-asserts-claim"),
        "a batch whose records failed must not keep its stamps: {}",
        r1.show()
    );
    assert!(!r1.stdout.contains("reverse first"), "{}", r1.show());
    assert_eq!(
        stamped_count(&pool).await,
        10,
        "the failed batch's stamps rolled back with its records"
    );
    assert_eq!(
        record_count(&pool).await,
        0,
        "CALIBRATION: no record written"
    );
    let (by_paper, by_claim) = ingest_facts(&pool, &scoped, &fx.papers, &fx.claims).await;
    assert_eq!(by_claim, by_paper, "{}", r1.show());

    sqlx::query("DROP TRIGGER test_refuse_ingest_record ON edges")
        .execute(&pool)
        .await
        .expect("drop trigger");
    let m2 = scratch("records-after.jsonl");
    let r2 = apply(&pool, &fx, 14, &m2, &["--batch-size", "3"]).await;
    assert_eq!(r2.code, 0, "{}", r2.show());
    for want in [
        "STAMPED\tpaper-asserts-claim\t7",
        "\nCREATION-RECORDS-WRITTEN\t1",
        "NON-CREATION-RECORDS-WRITTEN\t6",
    ] {
        assert!(r2.stdout.contains(want), "{want}: {}", r2.show());
    }
    let (by_paper, by_claim) = ingest_facts(&pool, &scoped, &fx.papers, &fx.claims).await;
    assert_eq!(by_paper.len(), 7, "{by_paper:?}");
    assert_eq!(by_claim, by_paper);

    for (m, want) in [
        (
            &m2,
            "REVERSED\tedges_restored=14\tedges_held=0\trecords_deleted=7",
        ),
        (
            &m1,
            "REVERSED\tedges_restored=10\tedges_held=0\trecords_deleted=0",
        ),
    ] {
        let rev = run_op(
            &pool,
            &[
                "reverse-ingest-markers",
                "--manifest",
                m.to_str().unwrap(),
                "--apply",
            ],
        )
        .await;
        assert_eq!(rev.code, 0, "{}", rev.show());
        assert!(rev.stdout.contains(want), "{want}: {}", rev.show());
        let (by_paper, by_claim) = ingest_facts(&pool, &scoped, &fx.papers, &fx.claims).await;
        assert_eq!(by_claim, by_paper);
    }
    assert_eq!(edge_snapshot(&pool).await, before);
}

/// A failed EDGE batch still leaves the batches the run committed their
/// records: the agent-assertion phase fails after the authorships and the
/// paper assertions committed, and the run writes those assertions' records,
/// reports the failure (exit 2) and reverses exactly.
#[sqlx::test(migrations = "../../migrations")]
async fn an_edge_batch_failure_still_writes_the_committed_stamps_records(pool: PgPool) {
    let fx = seed(&pool).await;
    let scoped = app_pool(&pool).await;
    register_legacy(&pool).await;
    let before = edge_snapshot(&pool).await;
    sqlx::query(
        "CREATE FUNCTION test_refuse_agent_assertion_stamp() RETURNS trigger \
         LANGUAGE plpgsql AS $$ \
         BEGIN \
           IF NEW.source_type = 'agent' AND NEW.relationship = 'asserts' \
              AND NOT (OLD.labels @> ARRAY['epigraph:ingest_written']::text[]) \
              AND NEW.labels @> ARRAY['epigraph:ingest_written']::text[] THEN \
             RAISE EXCEPTION 'test: agent assertions refused'; \
           END IF; \
           RETURN NEW; \
         END $$",
    )
    .execute(&pool)
    .await
    .expect("refusing function");
    sqlx::query(
        "CREATE TRIGGER test_refuse_agent_assertion_stamp BEFORE UPDATE ON edges \
         FOR EACH ROW EXECUTE FUNCTION test_refuse_agent_assertion_stamp()",
    )
    .execute(&pool)
    .await
    .expect("refusing trigger");

    let m1 = scratch("edges-fail.jsonl");
    let r1 = apply(&pool, &fx, 24, &m1, &[]).await;
    assert_eq!(r1.code, 2, "{}", r1.show());
    for want in [
        "STAMPED\tagent-authored-paper\t10",
        "STAMPED\tpaper-asserts-claim\t7",
        "BATCH-FAILED\tagent-asserts-claim",
        "test: agent assertions refused",
        "\nCREATION-RECORDS-WRITTEN\t1",
        "NON-CREATION-RECORDS-WRITTEN\t6",
        "NEXT\tresume:",
    ] {
        assert!(r1.stdout.contains(want), "{want}: {}", r1.show());
    }
    assert!(!r1.stdout.contains("NEXT\treverse first:"), "{}", r1.show());
    assert!(
        !r1.stdout.contains("lock timeout"),
        "a trigger refusal is no lock timeout: {}",
        r1.show()
    );
    assert!(
        !r1.stdout.contains("STAMPED\tagent-asserts-claim"),
        "{}",
        r1.show()
    );
    assert_eq!(records_in(&m1), 7);
    let (by_paper, by_claim) = ingest_facts(&pool, &scoped, &fx.papers, &fx.claims).await;
    assert_eq!(by_paper.len(), 7, "{by_paper:?}");
    assert_eq!(
        by_claim, by_paper,
        "after a failed edge batch, get_claim's ingesters disagree with query_paper"
    );

    sqlx::query("DROP TRIGGER test_refuse_agent_assertion_stamp ON edges")
        .execute(&pool)
        .await
        .expect("drop trigger");
    let rev = run_op(
        &pool,
        &[
            "reverse-ingest-markers",
            "--manifest",
            m1.to_str().unwrap(),
            "--apply",
        ],
    )
    .await;
    assert_eq!(rev.code, 0, "{}", rev.show());
    assert!(
        rev.stdout
            .contains("REVERSED\tedges_restored=17\tedges_held=0\trecords_deleted=7"),
        "{}",
        rev.show()
    );
    assert_eq!(edge_snapshot(&pool).await, before);
}

/// A lock timeout against a concurrent writer, the realistic way a run stops,
/// takes the caught path too. A second connection holds a row lock on every
/// agent assertion, so the third kind's locked candidate SELECT times out
/// under `--lock-timeout` after the authorships and paper assertions
/// committed. The run still writes those assertions' records, prints its
/// summary and a NEXT line naming the resume (or the reversal), and exits 2;
/// `query_paper` and `get_claim`'s `ingesters` agree. Following the NEXT line
/// (a fresh dry run's total, a new manifest) finishes the backfill, and the
/// two manifests reverse it exactly.
#[sqlx::test(migrations = "../../migrations")]
async fn a_lock_timeout_on_the_candidate_select_still_writes_the_committed_stamps_records(
    pool: PgPool,
) {
    let fx = seed(&pool).await;
    let scoped = app_pool(&pool).await;
    register_legacy(&pool).await;
    let before = edge_snapshot(&pool).await;

    let mut holder = pool.begin().await.expect("holder");
    let held: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM edges \
          WHERE source_type = 'agent' AND relationship = 'asserts' AND target_type = 'claim' \
          FOR UPDATE",
    )
    .fetch_all(&mut *holder)
    .await
    .expect("hold the agent assertions");
    assert!(!held.is_empty(), "CALIBRATION: agent assertions to hold");

    let m1 = scratch("lock-timeout.jsonl");
    let r1 = apply(&pool, &fx, 24, &m1, &["--lock-timeout", "300ms"]).await;
    holder.rollback().await.expect("release");
    assert_eq!(r1.code, 2, "{}", r1.show());
    let failed: Vec<&str> = r1
        .stdout
        .lines()
        .filter(|l| l.starts_with("BATCH-FAILED\t"))
        .collect();
    assert!(
        failed.len() == 1
            && failed[0].starts_with("BATCH-FAILED\tagent-asserts-claim")
            && failed[0].contains("canceling statement due to lock timeout"),
        "the BATCH-FAILED line itself carries the database's cause: {}",
        r1.show()
    );
    for want in [
        "STAMPED\tagent-authored-paper\t10",
        "STAMPED\tpaper-asserts-claim\t7",
        "\nCREATION-RECORDS-WRITTEN\t1",
        "NON-CREATION-RECORDS-WRITTEN\t6",
        "MANIFEST\t",
        "NEXT\tresume:",
        "--lock-timeout",
    ] {
        assert!(r1.stdout.contains(want), "{want}: {}", r1.show());
    }
    assert!(
        !r1.stdout.contains("STAMPED\tagent-asserts-claim"),
        "{}",
        r1.show()
    );
    assert_eq!(stamped_count(&pool).await, 17, "CALIBRATION");
    assert_eq!(records_in(&m1), 7);
    assert_eq!(record_count(&pool).await, 7);
    let (by_paper, by_claim) = ingest_facts(&pool, &scoped, &fx.papers, &fx.claims).await;
    assert_eq!(by_paper.len(), 7, "{by_paper:?}");
    assert_eq!(
        by_claim, by_paper,
        "after a lock timeout on the candidate SELECT, get_claim's ingesters disagree with \
         query_paper"
    );

    // The NEXT line's resume: a fresh dry run under the same cutoff and
    // classification, then --apply with its total and a new manifest.
    let mut dry: Vec<String> = vec![
        "backfill-ingest-markers".into(),
        "--written-before".into(),
        fx.t.clone(),
    ];
    dry.extend(classify(&fx));
    let dry: Vec<&str> = dry.iter().map(String::as_str).collect();
    let d = run_op(&pool, &dry).await;
    assert_eq!(d.code, 0, "{}", d.show());
    assert!(d.stdout.contains("TOTAL\tedges_to_stamp=7"), "{}", d.show());
    let m2 = scratch("lock-timeout-resume.jsonl");
    let r2 = apply(&pool, &fx, 7, &m2, &[]).await;
    assert_eq!(r2.code, 0, "{}", r2.show());
    assert!(!r2.stdout.contains("NEXT\t"), "{}", r2.show());
    assert_eq!(stamped_count(&pool).await, 24);
    let (by_paper, by_claim) = ingest_facts(&pool, &scoped, &fx.papers, &fx.claims).await;
    assert_eq!(by_paper.len(), 7, "{by_paper:?}");
    assert_eq!(by_claim, by_paper);

    for (m, want) in [
        (
            &m2,
            "REVERSED\tedges_restored=7\tedges_held=0\trecords_deleted=0",
        ),
        (
            &m1,
            "REVERSED\tedges_restored=17\tedges_held=0\trecords_deleted=7",
        ),
    ] {
        let rev = run_op(
            &pool,
            &[
                "reverse-ingest-markers",
                "--manifest",
                m.to_str().unwrap(),
                "--apply",
            ],
        )
        .await;
        assert_eq!(rev.code, 0, "{}", rev.show());
        assert!(rev.stdout.contains(want), "{want}: {}", rev.show());
        let (by_paper, by_claim) = ingest_facts(&pool, &scoped, &fx.papers, &fx.claims).await;
        assert_eq!(by_claim, by_paper);
    }
    assert_eq!(edge_snapshot(&pool).await, before);
}

/// `--apply` refuses before any write when no `legacy-ingest` principal is
/// registered.
#[sqlx::test(migrations = "../../migrations")]
async fn apply_refuses_without_the_legacy_principal(pool: PgPool) {
    let fx = seed(&pool).await;
    let before = edge_snapshot(&pool).await;
    let m = scratch("unregistered.jsonl");
    let r = apply(&pool, &fx, 24, &m, &[]).await;
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

/// The dry run the deploy waits on runs BEFORE this stack is deployed: on a
/// database without the marker migrations (198, 199, 208) and with no
/// `legacy-ingest` principal. It must still report the census, say what is
/// missing, and refuse `--apply` with nothing written.
#[sqlx::test(migrations = false)]
async fn the_dry_run_works_before_the_marker_migrations_are_applied(pool: PgPool) {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../migrations");
    let dir = std::env::temp_dir().join(format!("backfill-premarker-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).expect("dir");
    for e in std::fs::read_dir(&src).expect("migrations") {
        let p = e.expect("entry").path();
        let n = p.file_name().expect("name").to_string_lossy().to_string();
        if !n.ends_with(".sql") || ["198_", "199_", "208_"].iter().any(|v| n.starts_with(v)) {
            continue;
        }
        std::fs::copy(&p, dir.join(&n)).expect("copy");
    }
    let mut m = sqlx::migrate::Migrator::new(dir.as_path())
        .await
        .expect("migrator");
    m.set_ignore_missing(true);
    // On a connection of its own: a migration's session settings must not
    // stay on a pooled connection the fixture then writes through.
    let mut conn =
        <sqlx::PgConnection as sqlx::Connection>::connect(&fixture::database_url_for(&pool).await)
            .await
            .expect("migration connection");
    m.run(&mut conn)
        .await
        .expect("every migration but 198, 199, 208");
    sqlx::Connection::close(conn).await.expect("close");
    let present: Vec<i64> =
        sqlx::query_scalar("SELECT version FROM _sqlx_migrations WHERE version IN (198, 199, 208)")
            .fetch_all(&pool)
            .await
            .expect("versions");
    assert!(present.is_empty(), "CALIBRATION: {present:?}");

    let fx = seed(&pool).await;
    let before = edge_snapshot(&pool).await;
    let mut args = vec![
        "backfill-ingest-markers".to_string(),
        "--written-before".into(),
        fx.t.clone(),
    ];
    args.extend(classify(&fx));
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let dry = run_op(&pool, &refs).await;
    assert_eq!(dry.code, 0, "{}", dry.show());
    for want in [
        "SCHEMA\tguard_208=MISSING\tlegacy_ingest=NOT-REGISTERED",
        "TOTAL\tedges_to_stamp=24",
        "CREATION-RECORDS\tprovable=1",
    ] {
        assert!(dry.stdout.contains(want), "{want}: {}", dry.show());
    }

    let m0 = scratch("premarker.jsonl");
    let r = apply(&pool, &fx, 24, &m0, &[]).await;
    assert_ne!(r.code, 0, "{}", r.show());
    assert!(r.stderr.contains("migration 208"), "{}", r.show());
    assert_eq!(edge_snapshot(&pool).await, before, "nothing written");
    assert!(!m0.exists(), "no manifest for a refused run");
}

/// A second legacy fixture: the INPUTS of a paper's principal. A paper's
/// principal is decided from the real signers of its legacy `authored` AND
/// paper `asserts` edges, both under the run's cutoff; the creation proof
/// reads both legs under it too.
///
/// * P5, ASSERTIONS-ONLY signer (principal S): H and R authored P5 unsigned;
///   P5 asserts C7 signed by S, C8 and C14 unsigned; H asserts C7 and C8.
///   LATE: N authored P5 signed by the second ingester S2 (after the cutoff,
///   so P5 has no conflict).
/// * P6, CONFLICT BETWEEN ASSERTIONS (legacy-ingest): J authored P6 unsigned,
///   R authored P6 unsigned and RETRACTED; P6 asserts C9 signed by S and C10
///   signed by S2, and C14 unsigned (written BEFORE P5's assertion of C14);
///   J asserts C9.
/// * P7, CONFLICT ACROSS KINDS (legacy-ingest): K authored P7 signed by S,
///   P7 asserts C11 signed by S2; K asserts C11.
/// * P8, PROVABLE (principal S): Q authored P8 signed by S, P8 asserts C12
///   signed by S (C12 filed by S with S's extraction trace of P8); Q asserts
///   C12. LATE: P8 asserts C13 signed by S, C13 shaped exactly like C12.
/// * P9, ITS ONLY SIGNED AUTHORSHIP LATE (principal S): P9 asserts C15 signed
///   by S (C15 filed by S with S's extraction trace of P9). LATE: U authored
///   P9 signed by S. No legacy authorship of S's, so no creation record.
/// * R asserts C14, closing chains through P6 (legacy-ingest, the OLDER paper
///   assertion, but R's authorship of P6 is retracted) and P5 (S, in force).
///
/// All names and identifiers are invented.
#[allow(dead_code)]
struct Px {
    s: Uuid,
    s2: Uuid,
    f: Uuid,
    h: Uuid,
    j: Uuid,
    k: Uuid,
    n: Uuid,
    q: Uuid,
    r: Uuid,
    u: Uuid,
    papers: [Uuid; 5],
    claims: [Uuid; 9],
    t: String,
}

impl Px {
    /// S and S2 are the only signers of an `authored` or paper `asserts`
    /// edge: both real ingesters.
    fn classify(&self) -> Vec<String> {
        vec![
            "--ingest-signer".into(),
            self.s.to_string(),
            "--ingest-signer".into(),
            self.s2.to_string(),
        ]
    }
}

async fn seed_principal_inputs(pool: &PgPool) -> Px {
    let (s, _) = fixture::seed_agent_with_group(pool, "principal-ingester").await;
    let (s2, _) = fixture::seed_agent_with_group(pool, "principal-ingester-two").await;
    let (f, _) = fixture::seed_agent_with_group(pool, "principal-filer").await;
    let mut au = Vec::new();
    for n in ["h", "j", "k", "n", "q", "r", "u"] {
        au.push(
            fixture::seed_agent_with_group(pool, &format!("principal-author-{n}"))
                .await
                .0,
        );
    }
    let (h, j, k, n, q, r, u) = (au[0], au[1], au[2], au[3], au[4], au[5], au[6]);
    let p5 = paper(pool, "10.9999/principal-asserts-only", "Assertions Signed").await;
    let p6 = paper(
        pool,
        "10.9999/principal-asserts-conflict",
        "Assertions Disagree",
    )
    .await;
    let p7 = paper(pool, "10.9999/principal-cross-conflict", "Kinds Disagree").await;
    let p8 = paper(pool, "10.9999/principal-provable", "Provable Legacy").await;
    let p9 = paper(pool, "10.9999/principal-late-author", "Author Came Late").await;
    let c7 =
        fixture::seed_public_claim(pool, f, "a finding only its assertion's signer vouches for")
            .await;
    let c8 = fixture::seed_public_claim(pool, f, "an unsigned finding of the same paper").await;
    let c9 = fixture::seed_public_claim(pool, f, "a finding one ingester asserted").await;
    let c10 = fixture::seed_public_claim(pool, f, "a finding another ingester asserted").await;
    let c11 = fixture::seed_public_claim(pool, f, "a finding asserted across a split").await;
    let c12 = fixture::seed_public_claim(pool, s, "a provable legacy finding").await;
    let c13 = fixture::seed_public_claim(pool, s, "a finding asserted after the cutoff").await;
    let c14 = fixture::seed_public_claim(pool, f, "a finding two papers state").await;
    let c15 =
        fixture::seed_public_claim(pool, s, "a finding whose signed authorship came late").await;
    for c in [c12, c13] {
        trace(
            pool,
            c,
            "Extracted from 'Provable Legacy' (DOI: 10.9999/principal-provable); level 3 (atom)",
        )
        .await;
    }
    trace(
        pool,
        c15,
        "Extracted from 'Author Came Late' (DOI: 10.9999/principal-late-author); level 3 (atom)",
    )
    .await;

    let empty = || serde_json::json!({});
    let pos = |n: i64| serde_json::json!({"position": n, "role": "author"});
    let ag = |id: Uuid| (id, "agent");
    let pa = |id: Uuid| (id, "paper");
    let cl = |id: Uuid| (id, "claim");

    // P6 first: its assertion of C14 is the OLDER of R's two chains, and it
    // runs through R's retracted authorship.
    edge(pool, ag(j), pa(p6), "authored", pos(0), None).await;
    edge_row(pool, ag(r), pa(p6), "authored", pos(1), None, false, true).await;
    edge(pool, pa(p6), cl(c9), "asserts", empty(), Some(s)).await;
    edge(pool, pa(p6), cl(c10), "asserts", empty(), Some(s2)).await;
    edge(pool, pa(p6), cl(c14), "asserts", empty(), None).await;
    edge(pool, ag(j), cl(c9), "asserts", empty(), None).await;
    // P5: its one real signer is on an assertion.
    edge(pool, ag(h), pa(p5), "authored", pos(0), None).await;
    edge(pool, ag(r), pa(p5), "authored", pos(1), None).await;
    edge(pool, pa(p5), cl(c7), "asserts", empty(), Some(s)).await;
    edge(pool, pa(p5), cl(c8), "asserts", empty(), None).await;
    edge(pool, pa(p5), cl(c14), "asserts", empty(), None).await;
    edge(pool, ag(h), cl(c7), "asserts", empty(), None).await;
    edge(pool, ag(h), cl(c8), "asserts", empty(), None).await;
    edge(pool, ag(r), cl(c14), "asserts", empty(), None).await;
    // P7: S on the authorship, S2 on the assertion.
    edge(pool, ag(k), pa(p7), "authored", pos(0), Some(s)).await;
    edge(pool, pa(p7), cl(c11), "asserts", empty(), Some(s2)).await;
    edge(pool, ag(k), cl(c11), "asserts", empty(), None).await;
    // P8: provable.
    edge(pool, ag(q), pa(p8), "authored", pos(0), Some(s)).await;
    edge(pool, pa(p8), cl(c12), "asserts", empty(), Some(s)).await;
    edge(pool, ag(q), cl(c12), "asserts", empty(), None).await;
    // P9: a signed assertion, no legacy authorship.
    edge(pool, pa(p9), cl(c15), "asserts", empty(), Some(s)).await;

    let t: String = sqlx::query_scalar(
        "SELECT to_char((max(created_at) + interval '1 millisecond') AT TIME ZONE 'UTC', \
                        'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') FROM edges",
    )
    .fetch_one(pool)
    .await
    .expect("cutoff");
    // Late: after the cutoff.
    edge_at(pool, ag(n), pa(p5), "authored", pos(2), Some(s2), true).await;
    edge_at(pool, pa(p8), cl(c13), "asserts", empty(), Some(s), true).await;
    edge_at(pool, ag(u), pa(p9), "authored", pos(0), Some(s), true).await;

    Px {
        s,
        s2,
        f,
        h,
        j,
        k,
        n,
        q,
        r,
        u,
        papers: [p5, p6, p7, p8, p9],
        claims: [c7, c8, c9, c10, c11, c12, c13, c14, c15],
        t,
    }
}

/// A paper's principal reads the signers of its paper `asserts` edges as
/// well as its `authored` ones, and only edges written before the cutoff
/// decide it or prove a creation. A paper whose only real signer is on an
/// assertion takes that signer, and its authors' cards count its claims;
/// two real signers on its assertions, or one on an authorship and another
/// on an assertion, make it a CONFLICT read as the legacy ingest. A late
/// second signer moves no principal; a late, provable-shaped assertion and a
/// late signed authorship prove no creation.
#[sqlx::test(migrations = "../../migrations")]
async fn a_papers_principal_reads_its_assertions_signers_under_the_cutoff(pool: PgPool) {
    let px = seed_principal_inputs(&pool).await;
    let [p5, p6, p7, p8, p9] = px.papers;
    let [c7, c8, c9, c10, c11, c12, _c13, c14, c15] = px.claims;
    let scoped = app_pool(&pool).await;
    let (reader, _) = fixture::seed_agent_with_group(&pool, "principal-reader").await;
    let legacy = register_legacy(&pool).await;

    let mut args = vec![
        "backfill-ingest-markers".to_string(),
        "--written-before".into(),
        px.t.clone(),
    ];
    args.extend(px.classify());
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let dry = run_op(&pool, &refs).await;
    assert_eq!(dry.code, 0, "{}", dry.show());
    let mut both = [px.s, px.s2];
    both.sort();
    for want in [
        "KIND\tagent-authored-paper\tcandidates=6".to_string(),
        "KIND\tpaper-asserts-claim\tcandidates=9".to_string(),
        "KIND\tagent-asserts-claim\tcandidates=6".to_string(),
        "PAPERS\tpapers=5\tby_one_ingest_signer=3\tlegacy_ingest_no_real_signer=0\t\
         legacy_ingest_conflicting_signers=2"
            .to_string(),
        format!("PAPER-PRINCIPAL\t{}\tpapers=3", px.s),
        format!("CONFLICT\tpaper={p6}\tsigners={},{}", both[0], both[1]),
        format!("CONFLICT\tpaper={p7}\tsigners={},{}", both[0], both[1]),
        "CHAINS\tchains=7\tchains_on_another_principal=1\tagent_asserts_multi_principal=1"
            .to_string(),
        "CREATION-RECORDS\tprovable=1".to_string(),
        "NON-CREATION-RECORDS\tplanned=8".to_string(),
        "TOTAL\tedges_to_stamp=21".to_string(),
    ] {
        assert!(
            dry.stdout.contains(&want),
            "missing {want:?}: {}",
            dry.show()
        );
    }
    assert!(
        !dry.stdout.contains(&format!("CONFLICT\tpaper={p5}")),
        "a late second signer is no conflict: {}",
        dry.show()
    );
    assert!(!dry.stdout.contains("UNCLASSIFIED"), "{}", dry.show());

    let manifest = scratch("principal-inputs.jsonl");
    let applied = apply_as(
        &pool,
        &px.t,
        px.classify(),
        21,
        &manifest,
        &["--batch-size", "4"],
        &[],
    )
    .await;
    assert_eq!(applied.code, 0, "{}", applied.show());
    for want in [
        "CREATION-RECORDS-WRITTEN\t1",
        "NON-CREATION-RECORDS-WRITTEN\t8",
    ] {
        assert!(applied.stdout.contains(want), "{want}: {}", applied.show());
    }

    let sorted = |mut v: Vec<Uuid>| {
        v.sort();
        v
    };
    assert_eq!(
        listing(&pool, &scoped, p5, px.s).await,
        (vec![px.s], sorted(vec![px.h, px.r]), 3),
        "a paper whose one real signer is on an assertion is that signer's ingest"
    );
    assert_eq!(
        listing(&pool, &scoped, p6, legacy).await,
        (vec![legacy], vec![px.j], 3),
        "two real signers on a paper's assertions: the legacy ingest"
    );
    assert_eq!(
        listing(&pool, &scoped, p7, legacy).await,
        (vec![legacy], vec![px.k], 1),
        "one real signer on an authorship, another on an assertion: the legacy ingest"
    );
    assert_eq!(
        listing(&pool, &scoped, p8, px.s).await,
        (vec![px.s], vec![px.q], 1),
        "a late assertion is not stamped"
    );
    assert_eq!(
        listing(&pool, &scoped, p9, px.s).await,
        (vec![px.s], vec![], 1),
        "a late authorship is not stamped"
    );
    for (who, want, why) in [
        (px.h, (1, 0, 2), "H: P5 and C7+C8, all S's"),
        (px.j, (1, 0, 1), "J: P6 and C9, legacy-ingest"),
        (px.k, (1, 0, 1), "K: P7 and C11, legacy-ingest"),
        (px.q, (1, 0, 1), "Q: P8 and C12, S's"),
        (px.n, (0, 0, 0), "N: a late authorship is not stamped"),
        (px.u, (0, 0, 0), "U: a late authorship is not stamped"),
    ] {
        assert_eq!(counts(&pool, &scoped, reader, who).await, want, "{why}");
    }

    let (by_paper, by_claim) = ingest_facts(&pool, &scoped, &px.papers, &px.claims).await;
    let want: BTreeSet<IngestFact> = [
        (p5, px.s, c7, false),
        (p5, px.s, c8, false),
        (p5, px.s, c14, false),
        (p6, legacy, c9, false),
        (p6, legacy, c10, false),
        (p6, legacy, c14, false),
        (p7, legacy, c11, false),
        (p8, px.s, c12, true),
        (p9, px.s, c15, false),
    ]
    .into_iter()
    .collect();
    assert_eq!(by_paper, want, "query_paper's per-ingest listing");
    assert_eq!(
        by_claim, by_paper,
        "get_claim's ingesters disagree with query_paper"
    );
}

/// An agent assertion closing chains through papers of different principals
/// takes the principal of its oldest IN-FORCE chain: a chain through a
/// retracted authorship never credits the claim (the agent card reads only
/// in-force legs), so it must not name the principal either. R's chain
/// through P6 is older but its authorship is retracted; its chain through P5
/// (S) is in force, so R's assertion of C14 is S's and R's card counts C14.
#[sqlx::test(migrations = "../../migrations")]
async fn an_agent_assertion_takes_its_oldest_in_force_chains_principal(pool: PgPool) {
    let px = seed_principal_inputs(&pool).await;
    let c14 = px.claims[7];
    let scoped = app_pool(&pool).await;
    let (reader, _) = fixture::seed_agent_with_group(&pool, "principal-reader").await;
    register_legacy(&pool).await;

    let manifest = scratch("in-force-chain.jsonl");
    let applied = apply_as(&pool, &px.t, px.classify(), 21, &manifest, &[], &[]).await;
    assert_eq!(applied.code, 0, "{}", applied.show());
    let r_c14: Vec<String> = sqlx::query_scalar(
        "SELECT labels FROM edges WHERE source_id = $1 AND target_id = $2 \
            AND relationship = 'asserts'",
    )
    .bind(px.r)
    .bind(c14)
    .fetch_one(&pool)
    .await
    .expect("R asserts C14");
    assert!(
        r_c14.contains(&format!("epigraph:ingest_written_by:{}", px.s)),
        "the oldest IN-FORCE chain's principal: {r_c14:?}"
    );
    assert_eq!(
        counts(&pool, &scoped, reader, px.r).await,
        (1, 0, 1),
        "R: P5 (its P6 authorship is retracted) and C14 through P5"
    );
}

/// The low and high ids of P5's two legacy `asserts` copies of one claim:
/// a run stamps in edge-id order, so a paced run's first run takes the low
/// copy and the resume the high one.
const LOW_COPY: &str = "00000000-0000-4000-8000-000000000002";
const HIGH_COPY: &str = "ffffffff-ffff-4fff-bfff-fffffffffffe";

/// The standard fixture plus P5: one legacy unsigned authorship (V) and TWO
/// legacy unsigned `P5 -asserts-> C7` edges (a re-ingest writes a new edge;
/// edges carry no triple uniqueness), all well before the cutoff. Both copies
/// take legacy-ingest, and the record writer keeps one record per paper,
/// claim and principal. Returns `(P5, C7)`.
async fn seed_duplicate_pair(pool: &PgPool, fx: &Fx) -> (Uuid, Uuid) {
    let p5 = paper(pool, "10.9999/backfill-duplicate", "Duplicated Legacy").await;
    let c7 = fixture::seed_public_claim(pool, fx.f, "a legacy finding asserted twice").await;
    for (id, src, src_t, tgt, tgt_t, rel, props) in [
        (
            Uuid::new_v4(),
            fx.v,
            "agent",
            p5,
            "paper",
            "authored",
            serde_json::json!({"position": 0, "role": "author"}),
        ),
        (
            Uuid::parse_str(LOW_COPY).unwrap(),
            p5,
            "paper",
            c7,
            "claim",
            "asserts",
            serde_json::json!({}),
        ),
        (
            Uuid::parse_str(HIGH_COPY).unwrap(),
            p5,
            "paper",
            c7,
            "claim",
            "asserts",
            serde_json::json!({}),
        ),
    ] {
        sqlx::query(
            "INSERT INTO edges (id, source_id, source_type, target_id, target_type, \
                                relationship, properties, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, '2000-01-01T00:00:00Z')",
        )
        .bind(id)
        .bind(src)
        .bind(src_t)
        .bind(tgt)
        .bind(tgt_t)
        .bind(rel)
        .bind(props)
        .execute(pool)
        .await
        .unwrap_or_else(|e| panic!("seed P5 {rel}: {e}"));
    }
    (p5, c7)
}

/// Whether edge `id` carries the backfill's stamp.
async fn is_stamped(pool: &PgPool, id: &str) -> bool {
    sqlx::query_scalar(
        "SELECT labels @> ARRAY['epigraph:ingest_written']::text[] FROM edges WHERE id = $1",
    )
    .bind(Uuid::parse_str(id).unwrap())
    .fetch_one(pool)
    .await
    .expect("stamped?")
}

/// Two legacy copies of one `paper -asserts-> claim` pair land in different
/// runs of a paced backfill: the resume stamps the second copy but writes no
/// record (the first run's record already covers that paper, claim and
/// principal), so its stamp rests on the first run's record. Reversing the
/// FIRST run's manifest alone would delete that record and leave the second
/// stamp without one. So that reversal is refused, dry run and `--apply`
/// alike, with nothing written, naming the edge and the newer manifest to
/// reverse first; reversing newest first then restores every edge row.
#[sqlx::test(migrations = "../../migrations")]
async fn a_reversal_refuses_while_a_newer_runs_stamp_rests_on_its_records(pool: PgPool) {
    let fx = seed(&pool).await;
    let (p5, c7) = seed_duplicate_pair(&pool, &fx).await;
    let mut papers = fx.papers.to_vec();
    papers.push(p5);
    let mut claims = fx.claims.to_vec();
    claims.push(c7);
    let scoped = app_pool(&pool).await;
    let legacy = register_legacy(&pool).await;
    let before = edge_snapshot(&pool).await;

    // Batches 1-4: the 11 authorships; batch 5: the first three paper
    // assertions, in id order, so the LOW copy.
    let m1 = scratch("dup-1.jsonl");
    let r1 = apply(
        &pool,
        &fx,
        27,
        &m1,
        &["--batch-size", "3", "--max-batches", "5"],
    )
    .await;
    assert_eq!(r1.code, 0, "{}", r1.show());
    assert!(
        is_stamped(&pool, LOW_COPY).await && !is_stamped(&pool, HIGH_COPY).await,
        "CALIBRATION: run 1 stamps the low copy only"
    );
    let m2 = scratch("dup-2.jsonl");
    let r2 = apply(&pool, &fx, 13, &m2, &["--batch-size", "3"]).await;
    assert_eq!(r2.code, 0, "{}", r2.show());
    assert!(
        is_stamped(&pool, HIGH_COPY).await,
        "CALIBRATION: run 2 stamps the high copy"
    );
    let (by_paper, by_claim) = ingest_facts(&pool, &scoped, &papers, &claims).await;
    assert!(
        by_paper.contains(&(p5, legacy, c7, false)),
        "CALIBRATION: {by_paper:?}"
    );
    assert_eq!(by_claim, by_paper, "CALIBRATION: both runs agree");
    assert_eq!(
        (records_in(&m1), records_in(&m2)),
        (3, 5),
        "CALIBRATION: run 2 writes no record for the high copy"
    );

    let stamped = edge_snapshot(&pool).await;
    let records = record_count(&pool).await;
    for apply_flag in [false, true] {
        let mut args = vec!["reverse-ingest-markers", "--manifest", m1.to_str().unwrap()];
        if apply_flag {
            args.push("--apply");
        }
        let rev = run_op(&pool, &args).await;
        assert_ne!(
            rev.code,
            0,
            "reversing the older manifest alone (apply={apply_flag}) must be refused: {}",
            rev.show()
        );
        assert!(
            rev.stderr.contains(HIGH_COPY) && rev.stderr.contains("newer manifest"),
            "the refusal names the edge and says to reverse the newer manifest first: {}",
            rev.show()
        );
        assert_eq!(
            edge_snapshot(&pool).await,
            stamped,
            "a refused reversal changes no edge row"
        );
        assert_eq!(record_count(&pool).await, records, "no record deleted");
        assert_eq!(
            audit_count(&pool, "ingest_marker.backfill_reverse").await,
            0,
            "no audit row"
        );
    }

    for (m, want) in [
        (
            &m2,
            "REVERSED\tedges_restored=13\tedges_held=0\trecords_deleted=5\trecords_held=0",
        ),
        (
            &m1,
            "REVERSED\tedges_restored=14\tedges_held=0\trecords_deleted=3\trecords_held=0",
        ),
    ] {
        let rev = run_op(
            &pool,
            &[
                "reverse-ingest-markers",
                "--manifest",
                m.to_str().unwrap(),
                "--apply",
            ],
        )
        .await;
        assert_eq!(rev.code, 0, "{}", rev.show());
        assert!(rev.stdout.contains(want), "{want}: {}", rev.show());
        let (by_paper, by_claim) = ingest_facts(&pool, &scoped, &papers, &claims).await;
        assert_eq!(by_claim, by_paper);
    }
    assert_eq!(edge_snapshot(&pool).await, before);
    assert_eq!(record_count(&pool).await, 0);
}
