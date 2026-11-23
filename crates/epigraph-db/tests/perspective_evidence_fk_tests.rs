#[path = "viewer_fixture.rs"]
mod fixture;

// Regression tests for C-1 (one BBA per evidence row) and its keying.
//
// Background: commit 355cf4f passed `evidence.id` as
// `mass_functions.perspective_id` to defeat the unique constraint on
// `(claim, frame, agent, perspective_id=NULL)`, but never inserted a row
// into `perspectives` for that id — every multi-evidence update path
// (report_workflow_outcome, update_with_evidence) hit FK violation. f0038820
// then wrote a pseudo-perspective per evidence row to satisfy the FK. Since
// migration 267 (backlog 1777638e) the evidence row keys its BBA through
// `mass_functions`' own slot (`slot_kind = 'evidence'`, `slot_id`), which has
// no foreign key and needs no `perspectives` row, and `perspective_id` names
// genuine perspectives only.

use epigraph_db::{BbaSlot, MassFunctionRepository};
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

async fn seed_agent(pool: &PgPool, key_byte: u8) -> sqlx::Result<Uuid> {
    let agent_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agents (id, public_key) \
         VALUES ($1, decode(repeat($2, 32), 'hex'))",
    )
    .bind(agent_id)
    .bind(format!("{key_byte:02x}"))
    .execute(pool)
    .await?;
    Ok(agent_id)
}

async fn seed_claim(pool: &PgPool, agent_id: Uuid, hash_byte: u8) -> sqlx::Result<Uuid> {
    let claim_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id) \
         VALUES ($1, 'fk-regression-claim', decode(repeat($2, 32), 'hex'), $3)",
    )
    .bind(claim_id)
    .bind(format!("{hash_byte:02x}"))
    .bind(agent_id)
    .execute(pool)
    .await?;
    Ok(claim_id)
}

async fn seed_frame(pool: &PgPool) -> sqlx::Result<Uuid> {
    let frame_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO frames (id, name, hypotheses) \
         VALUES ($1, $2, ARRAY['TRUE','FALSE']::text[])",
    )
    .bind(frame_id)
    .bind(format!("fk-regression-{frame_id}"))
    .execute(pool)
    .await?;
    Ok(frame_id)
}

fn masses() -> serde_json::Value {
    json!({"TRUE": 0.7, "FALSE": 0.0, "{TRUE,FALSE}": 0.3})
}

async fn store_evidence(
    pool: &PgPool,
    claim: Uuid,
    frame: Uuid,
    agent: Uuid,
    evidence: Uuid,
) -> Result<Uuid, epigraph_db::DbError> {
    MassFunctionRepository::store_in_slot(
        pool,
        claim,
        frame,
        Some(agent),
        BbaSlot::Evidence(evidence),
        &masses(),
        None,
        Some("auto_wire"),
        Some(0.7),
        Some("observation"),
        "unknown",
        None,
    )
    .await
}

/// C-1 on the slot: two evidence rows of one agent are two BBAs, a third
/// write on the first evidence row's slot upserts it, and none of it needs a
/// `perspectives` row (the slot has no foreign key).
#[sqlx::test(migrations = "../../migrations")]
async fn evidence_slots_keep_one_bba_per_evidence_with_no_perspective_row(
    pool: PgPool,
) -> sqlx::Result<()> {
    let agent_id = seed_agent(&pool, 0xAA).await?;
    let claim_id = seed_claim(&pool, agent_id, 0xAB).await?;
    let frame_id = seed_frame(&pool).await?;
    let (ev1, ev2) = (Uuid::new_v4(), Uuid::new_v4());

    let first = store_evidence(&pool, claim_id, frame_id, agent_id, ev1)
        .await
        .expect("an evidence slot needs no perspectives row");
    let second = store_evidence(&pool, claim_id, frame_id, agent_id, ev2)
        .await
        .expect("second evidence slot");
    let again = store_evidence(&pool, claim_id, frame_id, agent_id, ev1)
        .await
        .expect("re-store on the first slot");
    assert_ne!(first, second, "two evidence rows are two BBAs");
    assert_eq!(again, first, "the same slot is the same row (upsert)");

    let perspectives: i64 =
        sqlx::query_scalar("SELECT count(*) FROM perspectives WHERE id = ANY($1)")
            .bind(vec![ev1, ev2])
            .fetch_one(&pool)
            .await?;
    assert_eq!(
        perspectives, 0,
        "no perspectives row was written for a slot"
    );
    let keys: Vec<(Option<Uuid>, Option<String>, Option<Uuid>)> = sqlx::query_as(
        "SELECT perspective_id, slot_kind, slot_id FROM mass_functions \
          WHERE claim_id = $1 ORDER BY id",
    )
    .bind(claim_id)
    .fetch_all(&pool)
    .await?;
    assert_eq!(keys.len(), 2);
    assert!(
        keys.iter()
            .all(|(p, k, s)| p.is_none() && k.as_deref() == Some("evidence") && s.is_some()),
        "{keys:?}"
    );
    Ok(())
}

/// `perspective_id` still names a perspective (the FK stands), and the
/// agent's unscoped row and an evidence slot are distinct keys.
#[sqlx::test(migrations = "../../migrations")]
async fn a_perspective_id_must_name_a_perspective_and_differs_from_a_slot(
    pool: PgPool,
) -> sqlx::Result<()> {
    let agent_id = seed_agent(&pool, 0xCC).await?;
    let claim_id = seed_claim(&pool, agent_id, 0xCD).await?;
    let frame_id = seed_frame(&pool).await?;
    let evidence_id = Uuid::new_v4();

    let bad = MassFunctionRepository::store_with_perspective(
        &pool,
        claim_id,
        frame_id,
        Some(agent_id),
        Some(evidence_id),
        &masses(),
        None,
        Some("auto_wire"),
        Some(0.7),
        Some("observation"),
        "unknown",
        None,
    )
    .await;
    assert!(
        bad.is_err(),
        "an evidence id is not a perspective: the FK refuses it"
    );

    let unscoped = MassFunctionRepository::store_with_perspective(
        &pool,
        claim_id,
        frame_id,
        Some(agent_id),
        None,
        &masses(),
        None,
        Some("auto_wire"),
        Some(0.7),
        Some("observation"),
        "unknown",
        None,
    )
    .await
    .expect("the agent's unscoped row");
    let slotted = store_evidence(&pool, claim_id, frame_id, agent_id, evidence_id)
        .await
        .expect("the evidence slot");
    assert_ne!(
        unscoped, slotted,
        "no perspective and an evidence slot are two keys"
    );
    Ok(())
}

/// The row shape `mass_functions_slot_shape` holds: a slot's kind and id go
/// together, the kind is one of three, and a row is never both a
/// perspective's and a slot's.
#[sqlx::test(migrations = "../../migrations")]
async fn the_slot_shape_is_enforced(pool: PgPool) -> sqlx::Result<()> {
    let agent_id = seed_agent(&pool, 0xEE).await?;
    let claim_id = seed_claim(&pool, agent_id, 0xEF).await?;
    let frame_id = seed_frame(&pool).await?;
    let perspective: Uuid =
        sqlx::query_scalar("INSERT INTO perspectives (name) VALUES ('genuine') RETURNING id")
            .fetch_one(&pool)
            .await?;
    // (perspective_id, slot_kind, slot_id, what the case is)
    type Case<'a> = (Option<Uuid>, Option<&'a str>, Option<Uuid>, &'a str);
    let cases: [Case; 4] = [
        (None, Some("edge"), None, "a kind without an id"),
        (None, None, Some(Uuid::new_v4()), "an id without a kind"),
        (None, Some("lens"), Some(Uuid::new_v4()), "an unknown kind"),
        (
            Some(perspective),
            Some("edge"),
            Some(Uuid::new_v4()),
            "a perspective and a slot",
        ),
    ];
    for (p, kind, id, what) in cases {
        let err = sqlx::query(
            "INSERT INTO mass_functions (claim_id, frame_id, source_agent_id, perspective_id, \
                                         slot_kind, slot_id, masses) \
             VALUES ($1, $2, $3, $4, $5, $6, '{}'::jsonb)",
        )
        .bind(claim_id)
        .bind(frame_id)
        .bind(agent_id)
        .bind(p)
        .bind(kind)
        .bind(id)
        .execute(&pool)
        .await
        .expect_err(what);
        assert!(
            err.to_string().contains("mass_functions_slot_shape"),
            "{what}: refused by mass_functions_slot_shape ({err})"
        );
    }
    Ok(())
}
