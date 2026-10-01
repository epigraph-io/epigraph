//! `epigraph-operator custodial-supersede` (migration 123), through the real
//! binary on the maintenance DSN variable, on an ARMED database: the
//! custodian's one edit path for the platform corpus, replacing the hand-run
//! SQL sequence the operator-binding runbook carried.

mod viewer_fixture;

use sqlx::PgPool;
use std::process::Command;
use uuid::Uuid;
use viewer_fixture as fixture;

const BIN: &str = env!("CARGO_BIN_EXE_epigraph-operator");
const DSN_ENV: &str = "EPIGRAPH_OPERATOR_MAINTENANCE_DSN";
const WORLD: Uuid = Uuid::nil();

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
        .env_remove("EPIGRAPH_OPERATOR_LINK_ENFORCEMENT")
        .env(DSN_ENV, url)
        .output()
        .expect("spawn epigraph-operator");
    Run {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

async fn insert_claim(pool: &PgPool, author: Uuid, group: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, $2, $3, 0.5, $4, true, 'public', $5)",
    )
    .bind(id)
    .bind(format!("corpus claim {id}"))
    .bind(id.as_bytes().repeat(2))
    .bind(author)
    .bind(group)
    .execute(pool)
    .await
    .expect("claim");
    id
}

async fn edge(pool: &PgPool, source: Uuid, target: Uuid, relationship: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, \
                            visibility, owner_group_id) \
         VALUES ($1, 'claim', $2, 'claim', $3, 'public', $4) RETURNING id",
    )
    .bind(source)
    .bind(target)
    .bind(relationship)
    .bind(WORLD)
    .fetch_one(pool)
    .await
    .expect("edge")
}

async fn current(pool: &PgPool, claim: Uuid) -> bool {
    sqlx::query_scalar("SELECT COALESCE(is_current, true) FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("claim")
}

async fn acts(pool: &PgPool) -> Vec<(String, String)> {
    sqlx::query_as(
        "SELECT details->>'assignment_id', details->>'target' FROM security_events \
          WHERE event_type = 'platform.custodial_act' ORDER BY created_at, id",
    )
    .fetch_all(pool)
    .await
    .expect("acts")
}

/// The arguments of one `custodial-supersede`; the revised text names the
/// claim, so two revisions never share a content hash.
fn supersede_args(claim: &str, assignment: &str, actor: &str, apply: bool) -> Vec<String> {
    let mut args: Vec<String> = [
        "custodial-supersede",
        "--claim",
        claim,
        "--content",
        &format!("the custodian's revision of {claim}"),
        "--truth",
        "0.7",
        "--assignment",
        assignment,
        "--actor",
        actor,
        "--reason",
        "custodial revision test",
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    if apply {
        args.push("--apply".to_string());
    }
    args
}

async fn supersede(pool: &PgPool, claim: &str, assignment: &str, actor: &str, apply: bool) -> Run {
    let args = supersede_args(claim, assignment, actor, apply);
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    run_op(pool, &refs).await
}

/// Armed, on the maintenance DSN: a corpus claim by a RETIRED-linked author
/// and one by an UNLINKED author are each revised once. The successor is
/// world/public under the inherited author, one `supersedes` edge links it,
/// a strengthening edge follows it while a `contradicts` edge stays on the
/// predecessor, and one `platform.custodial_act` names the assignment. A dry
/// run writes nothing. An assignment of another holder, an ended one and one
/// not yet begun are CUS04 with nothing written; a claim the world group
/// does not own is refused (exit 1) without `--allow-owned` and revised, under
/// its own author and group, with it.
///
/// Verified to fail: the edge migration skipped (`migrate_superseded_edges_conn`
/// not called) -> the strengthening edge stays on the predecessor; the act
/// committed before its audit record (the supersede committed on its own,
/// then the record attempted) -> the CUS04 run with another holder's
/// assignment leaves the predecessor retired; the assignment check skipped
/// (`record_custodial_act` not called) -> the other holder's assignment
/// revises the claim and no act is recorded; the `--allow-owned` check made
/// unconditional -> the owned claim is never revised.
#[sqlx::test(migrations = "../../migrations")]
async fn custodial_supersede_replaces_the_hand_sql(pool: PgPool) {
    let (a, a_group) = fixture::seed_human_operator(&pool, "custodian-a").await;
    let (b, _) = fixture::seed_human_operator(&pool, "custodian-b").await;
    let (legacy, _) = fixture::seed_agent_with_group(&pool, "legacy").await;
    let (unlinked, _) = fixture::seed_agent_with_group(&pool, "unlinked").await;
    let c_ret = insert_claim(&pool, legacy, WORLD).await;
    let c_unl = insert_claim(&pool, unlinked, WORLD).await;
    let c_own = insert_claim(&pool, a, a_group).await;
    let supporter = insert_claim(&pool, unlinked, WORLD).await;
    let critic = insert_claim(&pool, unlinked, WORLD).await;
    let c_more = insert_claim(&pool, unlinked, WORLD).await;
    let c_more2 = insert_claim(&pool, unlinked, WORLD).await;
    let (c_more_s, c_more2_s) = (c_more.to_string(), c_more2.to_string());
    let supports = edge(&pool, supporter, c_ret, "supports").await;
    let contradicts = edge(&pool, critic, c_ret, "contradicts").await;
    {
        let mut conn = pool.acquire().await.expect("acquire");
        epigraph_db::AgentRepository::link_retired_agent(&mut conn, legacy, a)
            .await
            .expect("the legacy author's retired tie to A");
    }
    let ia = fixture::make_custodian(&pool, a).await;
    let ib = fixture::make_custodian(&pool, b).await;
    fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        sqlx::query("SELECT * FROM public.epigraph_arm_operator_binding()")
            .execute(&mut *conn)
            .await
            .expect("arm");
        (conn, ())
    })
    .await;
    let (a_s, ia_s, ib_s) = (a.to_string(), ia.to_string(), ib.to_string());
    let (c_ret_s, c_unl_s, c_own_s) = (c_ret.to_string(), c_unl.to_string(), c_own.to_string());

    // Dry run: nothing.
    let dry = supersede(&pool, &c_ret_s, &ia_s, &a_s, false).await;
    assert_eq!(dry.code, 0, "{}", dry.show());
    assert!(dry.stdout.contains("WOULD BE SUPERSEDED"), "{}", dry.show());
    assert!(current(&pool, c_ret).await, "a dry run retires nothing");
    assert!(acts(&pool).await.is_empty(), "a dry run records nothing");

    // Refused: another holder's assignment.
    let other = supersede(&pool, &c_ret_s, &ib_s, &a_s, true).await;
    assert_eq!(other.code, 1, "{}", other.show());
    assert!(other.stderr.contains("CUS04"), "{}", other.show());
    assert!(current(&pool, c_ret).await, "a refused run retires nothing");

    // Applied, on the retired-linked author's corpus claim.
    let applied = supersede(&pool, &c_ret_s, &ia_s, &a_s, true).await;
    assert_eq!(applied.code, 0, "{}", applied.show());
    let successor: (Uuid, Uuid, Uuid, String, bool) = sqlx::query_as(
        "SELECT id, agent_id, owner_group_id, visibility, COALESCE(is_current, true) \
           FROM claims WHERE supersedes = $1",
    )
    .bind(c_ret)
    .fetch_one(&pool)
    .await
    .expect("one successor");
    let new = successor.0;
    assert_eq!(
        (successor.1, successor.2, successor.3.as_str(), successor.4),
        (legacy, WORLD, "public", true),
        "world/public, the inherited author, current"
    );
    assert!(!current(&pool, c_ret).await, "the predecessor is retired");
    let supersedes_edges: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM edges WHERE relationship = 'supersedes' \
            AND source_id = $1 AND target_id = $2",
    )
    .bind(new)
    .bind(c_ret)
    .fetch_one(&pool)
    .await
    .expect("supersedes edge");
    assert_eq!(supersedes_edges, 1);
    let targets: (Uuid, Uuid) = sqlx::query_as(
        "SELECT (SELECT target_id FROM edges WHERE id = $1), \
                (SELECT target_id FROM edges WHERE id = $2)",
    )
    .bind(supports)
    .bind(contradicts)
    .fetch_one(&pool)
    .await
    .expect("edge targets");
    assert_eq!(
        targets,
        (new, c_ret),
        "the strengthening edge follows; contradicts stays"
    );
    assert_eq!(
        acts(&pool).await,
        vec![(ia_s.clone(), c_ret_s.clone())],
        "one custodial act, naming the assignment"
    );

    // Applied, on the UNLINKED author's corpus claim.
    let unl = supersede(&pool, &c_unl_s, &ia_s, &a_s, true).await;
    assert_eq!(unl.code, 0, "{}", unl.show());
    assert!(!current(&pool, c_unl).await);
    let unl_successor: (Uuid, Uuid, String, bool) = sqlx::query_as(
        "SELECT agent_id, owner_group_id, visibility, COALESCE(is_current, true) \
           FROM claims WHERE supersedes = $1",
    )
    .bind(c_unl)
    .fetch_one(&pool)
    .await
    .expect("one successor of the unlinked author's claim");
    assert_eq!(
        (
            unl_successor.0,
            unl_successor.1,
            unl_successor.2.as_str(),
            unl_successor.3
        ),
        (unlinked, WORLD, "public", true),
        "the unlinked author's successor: its author, world/public, current"
    );

    // Not platform corpus: refused without --allow-owned, revised with it
    // (operator decision OQ-8's override; review TST-MTC-12).
    let owned = supersede(&pool, &c_own_s, &ia_s, &a_s, true).await;
    assert_eq!(owned.code, 1, "{}", owned.show());
    assert!(current(&pool, c_own).await);
    let mut args = supersede_args(&c_own_s, &ia_s, &a_s, true);
    args.push("--allow-owned".to_string());
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let allowed = run_op(&pool, &refs).await;
    assert_eq!(allowed.code, 0, "{}", allowed.show());
    assert!(!current(&pool, c_own).await, "the owned claim is retired");
    let own_successor: (Uuid, Uuid, bool) = sqlx::query_as(
        "SELECT agent_id, owner_group_id, COALESCE(is_current, true) \
           FROM claims WHERE supersedes = $1",
    )
    .bind(c_own)
    .fetch_one(&pool)
    .await
    .expect("one successor of the owned claim");
    assert_eq!(
        own_successor,
        (a, a_group, true),
        "the owned claim's successor keeps its author and its group"
    );

    // An ENDED assignment, and one not yet begun: CUS04, nothing written.
    let ended: bool =
        sqlx::query_scalar("SELECT public.epigraph_end_role_assignment($1, 'test end')")
            .bind(ib)
            .fetch_one(&pool)
            .await
            .expect("end B");
    assert!(ended);
    let b_s = b.to_string();
    let r = supersede(&pool, &c_more_s, &ib_s, &b_s, true).await;
    assert_eq!(r.code, 1, "an ended assignment: {}", r.show());
    assert!(r.stderr.contains("CUS04"), "{}", r.show());
    let future: Uuid = sqlx::query_scalar(
        "SELECT public.epigraph_grant_role('role:platform-custodian', $1, \
                now() + interval '1 day', NULL, $2, 'from tomorrow')",
    )
    .bind(b)
    .bind(a)
    .fetch_one(&pool)
    .await
    .expect("a future assignment for B");
    let future_s = future.to_string();
    let r = supersede(&pool, &c_more2_s, &future_s, &b_s, true).await;
    assert_eq!(r.code, 1, "an assignment not yet begun: {}", r.show());
    assert!(current(&pool, c_more).await && current(&pool, c_more2).await);
    assert_eq!(
        acts(&pool).await.len(),
        3,
        "only the three applied revisions (two corpus, one --allow-owned)"
    );
}
