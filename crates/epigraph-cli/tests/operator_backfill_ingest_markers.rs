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
                            properties, signature, signer_id, content_hash, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, \
                 CASE WHEN $10 THEN now() + interval '1 hour' ELSE now() END) RETURNING id",
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
    let count = count.to_string();
    let mut args: Vec<String> = [
        "backfill-ingest-markers",
        "--apply",
        "--confirm-count",
        &count,
        "--written-before",
        &fx.t,
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
    args.extend(classify(fx));
    args.extend(extra.iter().map(|s| (*s).to_string()));
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    run_op(pool, &refs).await
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
