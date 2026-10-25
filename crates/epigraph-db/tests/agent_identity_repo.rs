//! `AgentIdentityRepository` (migration 161, agent identity lineage D3/D4): the
//! Rust side of registration and prompt history.
//!
//! The database stores each prompt file as a zstd frame addressed by the BLAKE3
//! of its RAW bytes, and cannot run either algorithm itself. So the repository
//! owns both ends: `register` hashes and compresses, `prompt_history`
//! decompresses and re-checks the hash. These tests pin that the round trip is
//! exact, that a stored blob which no longer matches its hash is an ERROR
//! rather than a wrong answer, and that "refused" and "absent" stay distinct.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::{
    AgentIdentityRepository, AgentRepository, DbError, IdentityRegistration, PromptFile,
};
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

const ATTESTOR: &str = "epigraph_identity_attestor";

fn random32() -> [u8; 32] {
    let a = Uuid::new_v4();
    let b = Uuid::new_v4();
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(a.as_bytes());
    out[16..].copy_from_slice(b.as_bytes());
    out
}

fn registration(files: [PromptFile; 4]) -> IdentityRegistration {
    let pubkey = random32();
    let [identity_md, global_claude_md, group_claude_md, learned_md] = files;
    IdentityRegistration {
        identity_pubkey: pubkey,
        parent_agent_id: None,
        model: "test-model-1".to_string(),
        prompt_hash: blake3::hash(&pubkey).to_hex().to_string(),
        group_folder: "g-repo".to_string(),
        signing_pubkey: Some(random32()),
        identity_md,
        global_claude_md,
        group_claude_md,
        learned_md,
        in_prompt: json!({"global_claude_md": true, "group_claude_md": true, "learned_md": true}),
        runner_version: Some("runner-test".to_string()),
        host_sha: None,
    }
}

async fn register(pool: &PgPool, reg: IdentityRegistration) -> epigraph_db::IdentityRegistered {
    fixture::as_role(pool, ATTESTOR, |mut conn| async move {
        let r = AgentIdentityRepository::register(&mut conn, &reg).await;
        (conn, r)
    })
    .await
    .expect("the attestor registers through the repository")
}

/// A registered human operator, linked to `agent` by the maintenance path.
async fn operate(pool: &PgPool, agent: Uuid) -> Uuid {
    let operator = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'system')")
        .bind(operator)
        .bind(random32().to_vec())
        .execute(pool)
        .await
        .expect("seed operator");
    fixture::make_human_operator(pool, operator).await;
    fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let r = AgentRepository::link_operator(&mut conn, agent, operator).await;
        (conn, r)
    })
    .await
    .expect("link");
    operator
}

async fn history_as(
    pool: &PgPool,
    principal: Uuid,
    agent: Uuid,
) -> Result<Vec<epigraph_db::PromptHistoryEntry>, DbError> {
    fixture::as_role(pool, "epigraph_app", |mut conn| async move {
        sqlx::query("SELECT set_config('epigraph.principal_id', $1, false)")
            .bind(principal.to_string())
            .execute(&mut *conn)
            .await
            .expect("set principal");
        let r = AgentIdentityRepository::prompt_history(&mut conn, agent).await;
        (conn, r)
    })
    .await
}

/// Every stored file comes back byte for byte (multi-byte UTF-8 included), its
/// hash is the BLAKE3 of the RAW bytes, a compressible file is stored smaller
/// than it is, and an absent file stays absent.
#[sqlx::test(migrations = "../../migrations")]
async fn every_file_round_trips_byte_for_byte_under_its_raw_hash(pool: PgPool) {
    let global = "global rules: cite sources\n".as_bytes().to_vec();
    let group = "groupe — règles locales ✓\n".as_bytes().to_vec();
    let learned = "a lesson repeated many times\n".repeat(500).into_bytes();
    let reg = registration([
        PromptFile::Absent,
        PromptFile::Stored(global.clone()),
        PromptFile::Stored(group.clone()),
        PromptFile::Stored(learned.clone()),
    ]);
    let out = register(&pool, reg).await;
    let operator = operate(&pool, out.agent_id).await;

    let stored: Vec<(i32, i32)> = sqlx::query_as(
        "SELECT b.raw_size, octet_length(b.content) FROM agent_prompt_snapshots s \
           JOIN agent_prompt_blobs b ON b.blob_hash = s.learned_md WHERE s.id = $1",
    )
    .bind(out.snapshot_id)
    .fetch_all(&pool)
    .await
    .expect("stored learned blob");
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].0 as usize, learned.len());
    assert!(
        (stored[0].1 as usize) < learned.len() / 10,
        "a highly repetitive file must be stored compressed ({} of {} bytes)",
        stored[0].1,
        learned.len()
    );

    let entries = history_as(&pool, operator, out.agent_id)
        .await
        .expect("the operator reads the history");
    let me = entries
        .iter()
        .find(|e| e.relation == "self")
        .expect("self entry");
    let snap = me.snapshot.as_ref().expect("a readable snapshot");
    assert_eq!(snap.id, out.snapshot_id);
    assert!(snap.identity_md.is_none(), "an absent file stays absent");
    assert!(snap.blob_refused.is_empty());
    for (got, want) in [
        (&snap.global_claude_md, &global),
        (&snap.group_claude_md, &group),
        (&snap.learned_md, &learned),
    ] {
        let blob = got.as_ref().expect("a stored file");
        assert_eq!(&blob.bytes, want, "the file must come back byte for byte");
        assert_eq!(&blob.blob_hash, blake3::hash(want).as_bytes());
    }
    assert_eq!(
        snap.group_claude_md.as_ref().map(|b| b.text().into_owned()),
        Some("groupe — règles locales ✓\n".to_string())
    );
}

/// A blob whose stored content no longer hashes to its key (tampered, or a
/// hash collision the database cannot detect) is WITHHELD from the history
/// read, never returned as someone else's text under this agent's name. And
/// because blobs are shared across agents (one group CLAUDE.md template, many
/// identities), one bad blob must not fail every history that names it: the
/// read still returns, with that file absent and the agent's other files
/// intact (review CR7). CALIBRATION: the same read before the tamper returns
/// the template.
#[sqlx::test(migrations = "../../migrations")]
async fn a_blob_that_no_longer_matches_its_hash_is_withheld_not_fatal(pool: PgPool) {
    let template = b"the shared group template\n".to_vec();
    let lesson = b"the true lesson\n".to_vec();
    let a = register(
        &pool,
        registration([
            PromptFile::Absent,
            PromptFile::Absent,
            PromptFile::Stored(template.clone()),
            PromptFile::Stored(lesson.clone()),
        ]),
    )
    .await;
    let b = register(
        &pool,
        registration([
            PromptFile::Absent,
            PromptFile::Absent,
            PromptFile::Stored(template.clone()),
            PromptFile::Stored(b"another agent's lesson\n".to_vec()),
        ]),
    )
    .await;
    let operator = operate(&pool, a.agent_id).await;
    let before = history_as(&pool, operator, a.agent_id)
        .await
        .expect("an untampered history reads");
    let snap = before
        .iter()
        .find(|e| e.relation == "self")
        .and_then(|e| e.snapshot.as_ref())
        .expect("self snapshot");
    assert_eq!(
        snap.group_claude_md.as_ref().map(|f| f.bytes.clone()),
        Some(template.clone()),
        "CALIBRATION: the template reads before the tamper"
    );
    assert!(snap.withheld_files.is_empty());

    let forged = zstd::bulk::compress(b"a forged template\n", 3).expect("compress");
    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("ALTER TABLE agent_prompt_blobs DISABLE TRIGGER USER")
        .execute(&mut *tx)
        .await
        .expect("disable the append-only guard (superuser, test only)");
    let n = sqlx::query(
        "UPDATE agent_prompt_blobs SET content = $1, raw_size = $2 \
          WHERE blob_hash = (SELECT group_claude_md FROM agent_prompt_snapshots WHERE id = $3)",
    )
    .bind(&forged)
    .bind(b"a forged template\n".len() as i32)
    .bind(a.snapshot_id)
    .execute(&mut *tx)
    .await
    .expect("tamper")
    .rows_affected();
    assert_eq!(n, 1);
    sqlx::query("ALTER TABLE agent_prompt_blobs ENABLE TRIGGER USER")
        .execute(&mut *tx)
        .await
        .expect("re-enable");
    tx.commit().await.expect("commit");

    let other_operator = operate(&pool, b.agent_id).await;
    for (who, agent, own) in [
        (operator, a.agent_id, lesson.clone()),
        (
            other_operator,
            b.agent_id,
            b"another agent's lesson\n".to_vec(),
        ),
    ] {
        let entries = history_as(&pool, who, agent)
            .await
            .expect("one bad shared blob must not fail the whole history read");
        let snap = entries
            .iter()
            .find(|e| e.relation == "self")
            .and_then(|e| e.snapshot.as_ref())
            .expect("self snapshot");
        assert!(
            snap.group_claude_md.is_none(),
            "a blob that does not hash to its key must not be returned"
        );
        assert_eq!(snap.withheld_files, vec!["group_claude_md".to_string()]);
        assert_eq!(
            snap.learned_md.as_ref().map(|f| f.bytes.clone()),
            Some(own),
            "the agent's other files are intact"
        );
    }
}

/// A file the host refused to store is reported by name with no content, and
/// is distinguishable from a file that was simply absent.
#[sqlx::test(migrations = "../../migrations")]
async fn a_refused_file_is_named_and_an_absent_file_is_not(pool: PgPool) {
    let reg = registration([
        PromptFile::Absent,
        PromptFile::Absent,
        PromptFile::Stored(b"group\n".to_vec()),
        PromptFile::Refused,
    ]);
    let out = register(&pool, reg).await;
    let operator = operate(&pool, out.agent_id).await;
    let entries = history_as(&pool, operator, out.agent_id)
        .await
        .expect("history");
    let snap = entries
        .iter()
        .find(|e| e.relation == "self")
        .and_then(|e| e.snapshot.as_ref())
        .expect("self snapshot");
    assert_eq!(snap.blob_refused, vec!["learned_md".to_string()]);
    assert!(snap.learned_md.is_none());
    assert!(snap.identity_md.is_none());
    assert!(!snap.blob_refused.contains(&"identity_md".to_string()));
    assert!(snap.group_claude_md.is_some());
}
