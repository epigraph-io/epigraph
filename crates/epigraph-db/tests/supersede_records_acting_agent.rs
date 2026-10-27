//! A supersession records the agent that PERFORMED it (backlog 73085534,
//! operator ruling R-23).
//!
//! `ClaimRepository::supersede_act_conn` restates the retired claim under the
//! retired claim's author (`claims.agent_id`), the documented contract the
//! ruling keeps. Until this fix the acting agent appeared nowhere in the graph
//! (only in the cascade's `security_events` rows), so a successor written by
//! agent B read as agent A's work. The act now also writes ONE `AUTHORED` edge
//! from the acting agent to the successor, in the act's own transaction, with
//! the properties the workflow writes use for the same purpose (#600,
//! `epigraph_ingest_executor::record_caller_authorship`).

use epigraph_core::{ClaimId, TruthValue};
use epigraph_db::{ClaimRepository, SupersedeActor};
use sqlx::PgPool;
use uuid::Uuid;

async fn seed_agent(pool: &PgPool, name: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name, agent_type) \
         VALUES (sha256(gen_random_uuid()::text::bytea), $1, 'system') RETURNING id",
    )
    .bind(name)
    .fetch_one(pool)
    .await
    .expect("seed agent")
}

async fn seed_claim(pool: &PgPool, author: Uuid) -> Uuid {
    let text = format!("a claim to supersede {}", Uuid::new_v4());
    sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current) \
         VALUES ($1, sha256($1::bytea), 0.5, $2, true) RETURNING id",
    )
    .bind(&text)
    .bind(author)
    .fetch_one(pool)
    .await
    .expect("seed claim")
}

/// Every `AUTHORED` edge INTO `claim`: `(source_id, source_type, properties)`.
async fn authored_into(pool: &PgPool, claim: Uuid) -> Vec<(Uuid, String, serde_json::Value)> {
    sqlx::query_as(
        "SELECT source_id, source_type, COALESCE(properties, '{}'::jsonb) FROM edges \
          WHERE relationship = 'AUTHORED' AND target_id = $1 AND target_type = 'claim' \
          ORDER BY source_id",
    )
    .bind(claim)
    .fetch_all(pool)
    .await
    .expect("read AUTHORED edges")
}

/// Agent B supersedes agent A's claim: the successor keeps A as its author
/// (the contract R-23 keeps) AND carries exactly one `AUTHORED` edge, from B,
/// with the #600 properties. A gets no edge from the act.
#[sqlx::test(migrations = "../../migrations")]
async fn the_successor_keeps_its_author_and_records_the_acting_agent(pool: PgPool) {
    let a = seed_agent(&pool, "author-a").await;
    let b = seed_agent(&pool, "actor-b").await;
    let old = seed_claim(&pool, a).await;

    let mut tx = pool.begin().await.expect("begin");
    let (new, returned_old) = ClaimRepository::supersede_act_conn(
        &mut tx,
        ClaimId::from_uuid(old),
        "a correction written by B",
        TruthValue::clamped(0.6),
        "B corrects A",
        SupersedeActor::new(b, epigraph_db::SupersedeTool::SupersedeClaim),
    )
    .await
    .expect("B's supersession lands");
    tx.commit().await.expect("commit");
    assert_eq!(returned_old, old);

    let author: Uuid = sqlx::query_scalar("SELECT agent_id FROM claims WHERE id = $1")
        .bind(new)
        .fetch_one(&pool)
        .await
        .expect("the successor");
    assert_eq!(author, a, "the successor inherits the predecessor's author");

    assert_eq!(
        authored_into(&pool, new).await,
        vec![(
            b,
            "agent".to_string(),
            serde_json::json!({"tool": "supersede_claim", "was_created": true, "supersede_act": "supersede_claim"}),
        )],
        "exactly one AUTHORED edge, from the acting agent B, with the #600 properties \
         and the act's reserved marker"
    );
}

/// The edge is part of the ACT: when writing it fails, the act fails, and
/// nothing of it lands (no successor, the predecessor still current), so a
/// successor never exists without the record of who wrote it.
///
/// The failure is forced with a trigger on `edges` that raises only for an
/// `AUTHORED` insert (the technique of
/// `epigraph-engine/tests/admin_cascade_failed_reason.rs`), so the act's
/// other writes, including its `supersedes` edge, go through.
///
/// Verified to fail: the edge write's error swallowed (`.ok()` in place of
/// `?`): the act returns `Ok` and its successor lands with no actor edge.
#[sqlx::test(migrations = "../../migrations")]
async fn a_failed_authorship_edge_fails_the_act(pool: PgPool) {
    let a = seed_agent(&pool, "author-a").await;
    let b = seed_agent(&pool, "actor-b").await;
    let old = seed_claim(&pool, a).await;
    sqlx::query(
        "CREATE FUNCTION test_refuse_authored() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN IF NEW.relationship = 'AUTHORED' THEN \
           RAISE EXCEPTION 'forced AUTHORED failure'; END IF; RETURN NEW; END $$",
    )
    .execute(&pool)
    .await
    .expect("create the forcing function");
    sqlx::query(
        "CREATE TRIGGER test_refuse_authored BEFORE INSERT ON edges \
         FOR EACH ROW EXECUTE FUNCTION test_refuse_authored()",
    )
    .execute(&pool)
    .await
    .expect("create the forcing trigger");

    let mut tx = pool.begin().await.expect("begin");
    let result = ClaimRepository::supersede_act_conn(
        &mut tx,
        ClaimId::from_uuid(old),
        "a correction whose authorship cannot be recorded",
        TruthValue::clamped(0.6),
        "forced failure",
        SupersedeActor::new(b, epigraph_db::SupersedeTool::SupersedeClaim),
    )
    .await;
    assert!(
        result.is_err(),
        "the act must fail when its authorship edge cannot be written: {result:?}"
    );
    drop(tx);

    let successors: i64 = sqlx::query_scalar("SELECT count(*) FROM claims WHERE supersedes = $1")
        .bind(old)
        .fetch_one(&pool)
        .await
        .expect("count successors");
    assert_eq!(successors, 0, "no successor landed");
    let current: bool = sqlx::query_scalar("SELECT is_current FROM claims WHERE id = $1")
        .bind(old)
        .fetch_one(&pool)
        .await
        .expect("the predecessor");
    assert!(current, "the failed act retired nothing");
}

/// `actor` supersedes `old` through the WHOLE supersession (the act and the
/// edge migration, on this privileged pool), as the request paths and their
/// cascade do. Returns the successor.
async fn supersede_through_the_cascade(pool: &PgPool, old: Uuid, actor: Uuid) -> Uuid {
    let (new, _) = ClaimRepository::supersede(
        pool,
        ClaimId::from_uuid(old),
        &format!("a restatement of {old}"),
        TruthValue::clamped(0.6),
        "chain probe",
        SupersedeActor::new(actor, epigraph_db::SupersedeTool::SupersedeClaim),
    )
    .await
    .expect("supersede");
    new
}

/// A chain of two supersessions: B restates A's v0 as v1, then C restates v1
/// as v2. The act's edge records who wrote THAT claim, so the second
/// supersession's edge migration must leave B's edge on v1 (B wrote v1, not
/// v2), and v2 carries C's edge alone. Moving it onto v2 erased the record of
/// v1's writer and credited B with a claim it never wrote.
#[sqlx::test(migrations = "../../migrations")]
async fn a_second_supersession_leaves_the_first_actors_edge_on_the_claim_it_wrote(pool: PgPool) {
    let a = seed_agent(&pool, "author-a").await;
    let b = seed_agent(&pool, "actor-b").await;
    let c = seed_agent(&pool, "actor-c").await;
    let v0 = seed_claim(&pool, a).await;

    let v1 = supersede_through_the_cascade(&pool, v0, b).await;
    let v2 = supersede_through_the_cascade(&pool, v1, c).await;

    let act = |who: Uuid| {
        (
            who,
            "agent".to_string(),
            serde_json::json!({"tool": "supersede_claim", "was_created": true, "supersede_act": "supersede_claim"}),
        )
    };
    assert_eq!(
        authored_into(&pool, v1).await,
        vec![act(b)],
        "the retired v1 keeps the record of its writer B"
    );
    assert_eq!(
        authored_into(&pool, v2).await,
        vec![act(c)],
        "v2 records C, who wrote it, and nothing from B"
    );
    let author: Uuid = sqlx::query_scalar("SELECT agent_id FROM claims WHERE id = $1")
        .bind(v2)
        .fetch_one(&pool)
        .await
        .expect("v2");
    assert_eq!(author, a, "v2 still inherits the chain's author");
}

/// The edge migration leaves an `AUTHORED` edge on the retired claim only when
/// it carries the act's reserved marker (`supersede_act`), which no caller can
/// write. An edge that merely spells a supersession `tool` (a property any
/// edge writer could set) is an ordinary authorship edge of the retired claim
/// and moves onto the successor like every other.
#[sqlx::test(migrations = "../../migrations")]
async fn a_tool_spelling_without_the_act_marker_does_not_pin_an_edge_to_the_retired_claim(
    pool: PgPool,
) {
    let a = seed_agent(&pool, "author-a").await;
    let x = seed_agent(&pool, "tool-speller-x").await;
    let b = seed_agent(&pool, "actor-b").await;
    let old = seed_claim(&pool, a).await;
    let spelled: Uuid = sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, \
                            properties) \
         VALUES ($1, 'agent', $2, 'claim', 'AUTHORED', \
                 '{\"tool\": \"supersede_claim\", \"was_created\": true}') RETURNING id",
    )
    .bind(x)
    .bind(old)
    .fetch_one(&pool)
    .await
    .expect("an AUTHORED edge spelling the act's tool");

    let new = supersede_through_the_cascade(&pool, old, b).await;

    let target: Uuid = sqlx::query_scalar("SELECT target_id FROM edges WHERE id = $1")
        .bind(spelled)
        .fetch_one(&pool)
        .await
        .expect("the spelled edge");
    assert_eq!(
        target, new,
        "an edge without the act's marker moves onto the successor"
    );
    let on_old: Vec<Uuid> = authored_into(&pool, old)
        .await
        .into_iter()
        .map(|(source, _, _)| source)
        .collect();
    assert!(
        on_old.is_empty(),
        "nothing is pinned to the retired claim: {on_old:?}"
    );
}
