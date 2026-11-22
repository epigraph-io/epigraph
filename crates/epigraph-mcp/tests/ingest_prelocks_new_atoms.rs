//! `ingest_document` takes every new atom's `(content_hash, agent)` dedup lock
//! FIRST, in lock-key order, before it writes any claim (backlog 5b587ae8).
//!
//! It used to take them one atom at a time, in document order, inside the
//! walk: an ingest then waited on a pair while holding the locks (and rows) of
//! the atoms before it, which is half of a 40P01 cycle against any other
//! multi-pair writer or a consolidation. The DB-level order and deadlock
//! tests are `epigraph-db/tests/claim_dedup_lock_order.rs`; this one proves
//! the ingest walk is wired to the pre-lock.
//!
//! Another connection holds the dedup lock of the document's atom with the
//! LOWEST key, placed LAST in the document. Pre-locking in key order, the
//! ingest waits on that lock holding no other dedup lock; locking per atom in
//! document order, it would wait there holding the two earlier atoms' locks.
//!
//! Both server pools are `epigraph_app` (row security enforced).

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;

use epigraph_crypto::ContentHasher;
use epigraph_db::{ClaimRepository, ScopedPool, SessionGucMode};
use epigraph_ingest::document::schema::DocumentExtraction;
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools::ingestion::do_ingest_document;
use sqlx::PgPool;
use std::time::Duration;
use uuid::Uuid;

async fn app_role_server(pool: &PgPool) -> EpiGraphMcpFull {
    let url = fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let plain = fixture::downgraded_pool(pool, "epigraph_app").await;
    let signer = epigraph_crypto::AgentSigner::from_bytes(&[0xE5; 32]).expect("signer");
    let embedder = epigraph_mcp::embed::McpEmbedder::new(plain.clone(), None)
        .with_scoped_pool(scoped.clone())
        .with_generator(std::sync::Arc::new(|_text: &str| Ok(vec![0.01_f32; 1536])));
    EpiGraphMcpFull::new(plain, signer, embedder, /* read_only */ false).with_scoped_pool(scoped)
}

fn extraction(doi: &str, atoms: &[String]) -> DocumentExtraction {
    let generality: Vec<u8> = atoms.iter().map(|_| 3).collect();
    serde_json::from_value(serde_json::json!({
        "source": {"title": format!("Prelock doc {doi}"), "doi": doi,
                   "source_type": "Paper", "authors": []},
        "thesis": format!("Prelock thesis {doi}"),
        "thesis_derivation": "TopDown",
        "sections": [{"title": "S", "paragraphs": [{
            "text": format!("Prelock paragraph {doi}"),
            "atoms": atoms,
            "generality": generality, "confidence": 0.8
        }]}],
        "relationships": []
    }))
    .expect("extraction")
}

async fn key_of(pool: &PgPool, content: &str, agent: Uuid) -> i32 {
    sqlx::query_scalar("SELECT hashtext(encode($1, 'hex') || $2::text)")
        .bind(ContentHasher::hash(content.as_bytes()).to_vec())
        .bind(agent)
        .fetch_one(pool)
        .await
        .expect("key")
}

/// `(pid, key as objid, granted)` of every dedup-lock row in `pg_locks`.
async fn dedup_locks(pool: &PgPool) -> Vec<(i32, i64, bool)> {
    sqlx::query_as(
        "SELECT pid, objid::bigint, granted FROM pg_locks \
          WHERE locktype = 'advisory' AND objsubid = 2 \
            AND classid::bigint = (hashtext('epigraph.claim_dedup')::bigint & 4294967295)",
    )
    .fetch_all(pool)
    .await
    .expect("pg_locks")
}

#[sqlx::test(migrations = "../../migrations")]
async fn ingest_waits_on_its_lowest_new_atom_holding_no_other_dedup_lock(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let viewer = epigraph_mcp::tools::viewer::request_viewer(&server, None)
        .await
        .expect("stdio viewer");

    // Calibration: which agent this server's ingest writes atoms as.
    let probe = format!("Prelock calibration atom {}", Uuid::new_v4());
    do_ingest_document(
        &server,
        &viewer,
        &extraction("10.9999/prelock-calibration", std::slice::from_ref(&probe)),
        None,
        epigraph_core::VisibilityChoice::Public,
    )
    .await
    .map_err(|e| e.message.to_string())
    .expect("calibration ingest");
    let agent: Uuid = sqlx::query_scalar("SELECT agent_id FROM claims WHERE content = $1")
        .bind(&probe)
        .fetch_one(&pool)
        .await
        .expect("the calibration atom and its author");

    // Three new atoms, the lowest-keyed one LAST in the document.
    let mut atoms: Vec<(i32, String)> = Vec::new();
    for i in 0..3 {
        let text = format!("Prelock atom {i} {}", Uuid::new_v4());
        atoms.push((key_of(&pool, &text, agent).await, text));
    }
    atoms.sort();
    let lowest = atoms[0].clone();
    let in_doc_order: Vec<String> = vec![atoms[1].1.clone(), atoms[2].1.clone(), lowest.1.clone()];

    let mut blocker = pool.begin().await.expect("blocker");
    let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *blocker)
        .await
        .expect("pid");
    ClaimRepository::lock_content_hash_agent(
        &mut blocker,
        &ContentHasher::hash(lowest.1.as_bytes()),
        agent,
    )
    .await
    .expect("hold the lowest atom's pair");

    let doc = extraction("10.9999/prelock-ordered", &in_doc_order);
    let task = tokio::spawn(async move {
        do_ingest_document(
            &server,
            &viewer,
            &doc,
            None,
            epigraph_core::VisibilityChoice::Public,
        )
        .await
        .map(|_| ())
        .map_err(|e| e.message.to_string())
    });

    // The ingest's backend: the one waiting on a dedup lock.
    let mut waiting = None;
    for _ in 0..300 {
        waiting = dedup_locks(&pool)
            .await
            .into_iter()
            .find(|(pid, _, granted)| *pid != blocker_pid && !granted);
        if waiting.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let (ingest_pid, waited_on, _) = waiting.expect("the ingest waits on a dedup lock");
    assert_eq!(
        waited_on,
        i64::from(lowest.0) & 0xffff_ffff,
        "the ingest waits on the blocked (lowest) atom's pair"
    );
    let held: Vec<i64> = dedup_locks(&pool)
        .await
        .into_iter()
        .filter(|(pid, _, granted)| *pid == ingest_pid && *granted)
        .map(|(_, key, _)| key)
        .collect();
    assert!(
        held.is_empty(),
        "pre-locking in key order, the ingest holds no other dedup lock while it waits on the \
         lowest one; it holds {held:?} (the earlier atoms' locks, taken in document order)"
    );

    blocker.commit().await.expect("release");
    tokio::time::timeout(Duration::from_secs(30), task)
        .await
        .expect("the ingest finishes once released")
        .expect("join")
        .expect("the ingest succeeds");
    let written: i64 =
        sqlx::query_scalar("SELECT count(*) FROM claims WHERE content = ANY($1) AND agent_id = $2")
            .bind(&in_doc_order)
            .bind(agent)
            .fetch_one(&pool)
            .await
            .expect("count");
    assert_eq!(written, 3, "every atom was written once");
}
