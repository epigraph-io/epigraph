//! FINAL-PLAN §8.6 — `privatization_revert.rs`.
//!
//! "`restrict` round trip is bit-identical on `content`, `content_tsv` and
//! `embedding`; **`seal` revert is permitted once unsealed and 409s while
//! sealed** (ops F13)."
//!
//! # Acceptance clause 10, and what PR-21 changed about it
//!
//! The 409 arm ships and is asserted below, against a `mode='seal'` plan
//! persisted through the repository (see
//! `privatization_fixture::create_plan_with_mode` for why that path still
//! exists now that the route also answers for `seal`).
//!
//! When this file was written the positive arm — a seal plan whose items were
//! genuinely sealed and then unsealed CAN be reverted — was unexercisable,
//! because nothing in the product wrote a seal. **PR-21 changed that**: the
//! manifest ceremony is in `privatization_seal.rs`, which drives a real seal and
//! a real unseal through the routes. The positive arm IS now asserted, there:
//! `a_sealed_plan_becomes_revertible_once_its_items_are_unsealed` seals a plan,
//! unseals every item through the key ceremony, and requires the revert to
//! succeed. A reader arriving here to check whether clause 10 is discharged
//! should read that test; this file is the other half. What this file still
//! measures is the
//! refusal's CONDITION — the same request accepted once the encryption row is
//! gone — against a stub ciphertext, which keeps the revert assertions
//! independent of the key ceremony's own correctness.

#[path = "privatization_fixture.rs"]
mod fx;

use epigraph_api::errors::ApiError;
use fx::viewer_fixture;
use sqlx::PgPool;
use uuid::Uuid;

/// A `restrict` round trip leaves `content`, `content_tsv` and `embedding`
/// byte-for-byte as they were — at BOTH ends, not only at the end.
///
/// # Why the apply is measured too
///
/// The clause is written about the round trip, and a round trip that mangled the
/// three columns on apply and restored them on revert would satisfy a
/// before/after comparison while leaving the corpus wrong for the whole time the
/// privatization was in force — which is precisely the window the operator cares
/// about. The three columns are therefore snapshotted at three points.
///
/// # Why `content_tsv` is compared as text and not as a boolean "still there"
///
/// `content_tsv` is `GENERATED ALWAYS` (migration 050). A statement that
/// rewrote `content` would regenerate it silently, so "it is non-null" proves
/// nothing; only the value can tell an untouched column from a re-derived one.
#[sqlx::test(migrations = "../../migrations")]
async fn a_restrict_round_trip_is_bit_identical_on_content_tsv_and_embedding(pool: PgPool) {
    let world = fx::World::seed(&pool).await;
    let scoped = fx::scoped(&pool).await;

    let parent = viewer_fixture::seed_public_claim(&pool, world.actor, "round trip parent").await;
    let child = viewer_fixture::seed_public_claim(&pool, world.actor, "round trip child").await;
    fx::derived_from(&pool, child, parent).await;
    fx::give_embedding(&pool, parent).await;
    fx::give_embedding(&pool, child).await;

    let before = fx::content_triple(&pool, parent).await;
    assert!(
        before.2.is_some() && !before.1.is_empty(),
        "CALIBRATION: the fixture must give the claim an embedding AND a tsvector, or the \
         bit-identity assertion is comparing two NULLs"
    );

    let (plan, _) = fx::create_plan(&pool, &world, &[parent]).await;
    let items = fx::items(&pool, plan).await;
    assert_eq!(
        items.len(),
        2,
        "CALIBRATION: the closure must reach the derived child, or the revert below un-applies \
         one row and the boundary-edge arm is never exercised"
    );

    let correlation = fx::dispatch(&pool, &world, plan, "applying").await;
    fx::run_apply(&scoped, &fx::apply_job(plan, world.actor, &correlation), 50)
        .await
        .expect("apply");
    assert_eq!(fx::plan_state(&pool, plan).await, "applied");
    assert_eq!(fx::tenancy(&pool, parent).await.0, "group");

    let during = fx::content_triple(&pool, parent).await;
    assert_eq!(
        before, during,
        "`restrict` must not touch content, content_tsv or embedding. FINAL-PLAN §6.5.4's \
         argument for retaining them is that they are three columns of the SAME row and RLS is \
         row-level, so the predicate that hides one hides all three atomically — an argument that \
         is only sound while the columns are untouched"
    );

    // The boundary edge between two now-private endpoints must be `group`.
    let edge_before_revert: (String, Uuid) = sqlx::query_as(
        "SELECT visibility::text, owner_group_id FROM edges \
          WHERE source_id = $1 AND target_id = $2",
    )
    .bind(child)
    .bind(parent)
    .fetch_one(&pool)
    .await
    .expect("read the boundary edge");
    assert_eq!(
        edge_before_revert,
        ("group".to_string(), world.target_group),
        "the endpoint meet must have narrowed the edge with its endpoints"
    );

    let revert_correlation = fx::dispatch(&pool, &world, plan, "reverting").await;
    fx::run_revert(
        &scoped,
        &fx::revert_job(plan, world.actor, &revert_correlation),
        50,
    )
    .await
    .expect("revert");

    assert_eq!(fx::plan_state(&pool, plan).await, "reverted");
    assert_eq!(
        fx::tenancy(&pool, parent).await.0,
        "public",
        "a `restrict` revert must restore the visibility the freeze captured. Migration 074's \
         `claims_block_widening` refuses group -> public unless the admin declassification \
         surface arms `epigraph.allow_declassify`, and this is that surface"
    );
    assert_eq!(fx::tenancy(&pool, child).await.0, "public");

    let after = fx::content_triple(&pool, parent).await;
    assert_eq!(
        before, after,
        "a `restrict` round trip must be bit-identical on content, content_tsv and embedding"
    );

    let edge_after: (String, Uuid) = sqlx::query_as(
        "SELECT visibility::text, owner_group_id FROM edges \
          WHERE source_id = $1 AND target_id = $2",
    )
    .bind(child)
    .bind(parent)
    .fetch_one(&pool)
    .await
    .expect("read the boundary edge");
    assert_eq!(
        edge_after.0, "public",
        "the boundary meet must RE-RUN on revert. Migration 072's propagation trigger carries \
         `NOT (e.visibility = 'group' AND m.v = 'public')` — it narrows an edge and refuses to \
         widen one — so without an explicit meet the reverted plan leaves its edges private \
         forever and reports itself undone"
    );

    let actions = fx::audit_actions(&pool, plan).await;
    assert!(
        actions.iter().any(|a| a == "item.apply") && actions.iter().any(|a| a == "item.revert"),
        "both directions must leave a per-item audit trail, got {actions:?}"
    );

    // THE AUDIT ROWS MUST RECORD THE TRANSITION, NOT JUST THE FACT OF ONE.
    // `GET /admin/privatization/audit` serves both columns verbatim, so a row
    // whose before and after are equal is a wrong value on a shipped read
    // surface — and it is what a single projection produces on the revert path,
    // because `privatization_plan_items.before_visibility` is the frozen
    // PRE-APPLY image and never moves.
    assert_eq!(
        fx::audit_pairs(&pool, plan, parent, "item.apply").await,
        vec![(Some("public".to_string()), Some("group".to_string()))],
        "the apply row must read public -> group"
    );
    assert_eq!(
        fx::audit_pairs(&pool, plan, parent, "item.revert").await,
        vec![(Some("group".to_string()), Some("public".to_string()))],
        "the revert row must read group -> public. Reusing the apply projection here would \
         record public -> public for an operation that went the other way"
    );
}

/// A revert restores only the rows that still carry THIS plan's tenancy stamp.
///
/// # The control, and why it is the fail-closed direction
///
/// `privatization_plan_items.before_visibility` is a SELECTION-time pre-image:
/// it is written once, by the freeze, and describes the row as it stood before
/// this plan touched it. That is the right value to write back to a row this
/// plan still owns, and the wrong value to write to a row some other decision
/// has since taken over — `privatization_one_active_per_group` is unique on
/// `target_group_id`, not per claim, so a second plan against a different group
/// is an ordinary thing to exist. `restore_claims_conn` therefore matches on
/// `visibility = 'group' AND owner_group_id = <this plan's target>` and leaves
/// everything else alone; this is the one statement in the subsystem that can
/// widen a row's tenancy, so "leave it alone" is the safe answer and the
/// selection-time value is not.
///
/// The positive direction is measured by the round-trip test above, so this one
/// can be exactly the negative.
#[sqlx::test(migrations = "../../migrations")]
async fn a_revert_leaves_a_claim_another_decision_now_owns_alone(pool: PgPool) {
    let world = fx::World::seed(&pool).await;
    let scoped = fx::scoped(&pool).await;

    let stays = viewer_fixture::seed_public_claim(&pool, world.actor, "re-owned").await;
    let (plan, _) = fx::create_plan(&pool, &world, &[stays]).await;
    let correlation = fx::dispatch(&pool, &world, plan, "applying").await;
    fx::run_apply(&scoped, &fx::apply_job(plan, world.actor, &correlation), 50)
        .await
        .expect("apply");
    assert_eq!(
        fx::tenancy(&pool, stays).await,
        ("group".to_string(), world.target_group),
        "CALIBRATION: the apply must have stamped the claim, or the stamp check below is \
         trivially satisfied"
    );

    // AN INDEPENDENT DECISION takes the claim over: it now belongs to a
    // different group, and this plan's selection-time pre-image no longer
    // describes where it came from.
    //
    // Since migration 093 a group -> group move is itself refused unless
    // `epigraph.allow_declassify` is armed, so the independent decision takes
    // that audited route here, on one connection because the GUC is
    // session-scoped. The trigger is still NOT the control for the revert below.
    // `restore_claims_conn` arms the same GUC, so 093 would admit a restore over
    // this row. The stamp check is what leaves it alone.
    let (_, other_group) = viewer_fixture::seed_agent_with_group(&pool, "other-owner").await;
    {
        use sqlx::Executor;
        let mut conn = pool.acquire().await.expect("acquire");
        conn.execute("SET epigraph.allow_declassify = 'yes'")
            .await
            .expect("arm the audit GUC");
        sqlx::query("UPDATE claims SET visibility = 'group', owner_group_id = $2 WHERE id = $1")
            .bind(stays)
            .bind(other_group)
            .execute(&mut *conn)
            .await
            .expect("hand the claim to another group");
        conn.execute("RESET epigraph.allow_declassify")
            .await
            .expect("disarm the audit GUC");
    }

    let revert_correlation = fx::dispatch(&pool, &world, plan, "reverting").await;
    fx::run_revert(
        &scoped,
        &fx::revert_job(plan, world.actor, &revert_correlation),
        50,
    )
    .await
    .expect("revert");

    assert_eq!(fx::plan_state(&pool, plan).await, "reverted");
    assert_eq!(
        fx::tenancy(&pool, stays).await,
        ("group".to_string(), other_group),
        "the revert must leave a row this plan no longer owns exactly as it found it"
    );
    assert!(
        fx::audit_pairs(&pool, plan, stays, "item.revert")
            .await
            .is_empty(),
        "and it must not claim in the audit trail to have moved a row it did not move"
    );
}

/// A revert un-applies only the items this plan actually MOVED, not every item
/// it was frozen over.
///
/// # Why an item state has to mean "changed", not "looked at"
///
/// `restrict_claims_conn` moves only `visibility = 'public'` rows, so that
/// re-processing a committed batch fires no trigger and rewrites no derived
/// table. (Until migration 093 the guard was an `IS DISTINCT FROM` pair; see
/// [`an_apply_never_moves_a_claim_private_to_another_group`] for why it
/// narrowed.) The same guard makes the statement a NO-OP on a row that is already in
/// the target group — which a plan frozen while that row was public will meet as
/// an ordinary matter, with no race:
/// `privatization_one_active_per_group` excludes only CONCURRENT running plans,
/// so two plans against the same group whose frozen sets overlap simply run one
/// after the other. `Direction::Revert` consumes items in `applied`, so if such
/// an item were marked `applied` the revert would write this plan's
/// selection-time pre-image — typically `public` — over a row this plan never
/// changed, with `epigraph.allow_declassify` armed. The item is marked `skipped`
/// instead, which is migration 080's own vocabulary for the difference.
#[sqlx::test(migrations = "../../migrations")]
async fn a_revert_unapplies_only_the_items_this_plan_actually_moved(pool: PgPool) {
    let world = fx::World::seed(&pool).await;
    let scoped = fx::scoped(&pool).await;

    let shared = viewer_fixture::seed_public_claim(&pool, world.actor, "shared subject").await;

    // SECOND plan first: it is frozen while the claim is still public, so its
    // pre-image says `public`. Nothing about this is concurrent — it is simply
    // an older preview.
    let (second, _) = fx::create_plan(&pool, &world, &[shared]).await;
    let (first, _) = fx::create_plan(&pool, &world, &[shared]).await;

    let correlation = fx::dispatch(&pool, &world, first, "applying").await;
    fx::run_apply(
        &scoped,
        &fx::apply_job(first, world.actor, &correlation),
        50,
    )
    .await
    .expect("apply the first plan");
    assert_eq!(
        fx::tenancy(&pool, shared).await,
        ("group".to_string(), world.target_group),
        "CALIBRATION: the first plan must have moved the row"
    );

    let correlation = fx::dispatch(&pool, &world, second, "applying").await;
    fx::run_apply(
        &scoped,
        &fx::apply_job(second, world.actor, &correlation),
        50,
    )
    .await
    .expect("apply the second plan");
    let states: Vec<String> = fx::items(&pool, second)
        .await
        .into_iter()
        .map(|(_, _, s)| s)
        .collect();
    assert_eq!(
        states,
        vec!["skipped".to_string()],
        "the second plan changed nothing about this row, so its item must not say `applied`"
    );

    let correlation = fx::dispatch(&pool, &world, second, "reverting").await;
    fx::run_revert(
        &scoped,
        &fx::revert_job(second, world.actor, &correlation),
        50,
    )
    .await
    .expect("revert the second plan");
    assert_eq!(fx::plan_state(&pool, second).await, "reverted");
    assert_eq!(
        fx::tenancy(&pool, shared).await,
        ("group".to_string(), world.target_group),
        "reverting a plan that moved nothing must move nothing; the row is still where the FIRST \
         plan put it"
    );
    assert!(
        fx::audit_pairs(&pool, second, shared, "item.revert")
            .await
            .is_empty(),
        "and no revert audit row may claim otherwise"
    );
}

/// **An apply never moves a claim that is private to ANOTHER group.** The plan
/// still applies and reverts around it
/// (D-PR16-ownership-transfer-is-unguarded).
///
/// # How a plan reaches such a row
///
/// Selection walks the closure under a bypass viewer, and the freeze records
/// every id it resolves, with no tenancy filter. That is deliberate: the
/// preview has to count what is there. So a public seed that another group's
/// private claims were derived from pulls those claims into the frozen set.
/// Before this fix `restrict_claims_conn` matched any row whose owner differed
/// from the target and re-owned them into it. A's members lost them, the
/// target's members gained them, and A's admins were never asked. The drift
/// rescan already called that "a seizure the operator did not ask for" and
/// filtered it. The primary apply path did not.
///
/// # What each half of the fix contributes
///
/// Migration 093 refuses the move in the database on a connection without the
/// audit GUC, which the apply never arms. On its own that would turn the
/// seizure into a batch failing `42501` on every retry. The caller half,
/// `restrict_claims_conn` moving only `public` rows, is what lets the plan
/// finish, with the foreign rows `skipped`.
///
/// The SEALED foreign row is the sharper case. Its ciphertext is bound to A's
/// key epoch, so re-owning it would give the target group a row it cannot
/// decrypt and take it away from the group that can.
#[sqlx::test(migrations = "../../migrations")]
async fn an_apply_never_moves_a_claim_private_to_another_group(pool: PgPool) {
    let world = fx::World::seed(&pool).await;
    let scoped = fx::scoped(&pool).await;

    let seed = viewer_fixture::seed_public_claim(&pool, world.actor, "public seed").await;
    let (bystander, group_a) = viewer_fixture::seed_agent_with_group(&pool, "bystander").await;
    let foreign = viewer_fixture::seed_group_claim(&pool, bystander, group_a, "private to A").await;
    let foreign_sealed =
        viewer_fixture::seed_group_claim(&pool, bystander, group_a, "sealed in A").await;
    fx::encrypt_claim(&pool, foreign_sealed, group_a).await;
    fx::derived_from(&pool, foreign, seed).await;
    fx::derived_from(&pool, foreign_sealed, seed).await;

    let (plan, _) = fx::create_plan(&pool, &world, &[seed]).await;
    let frozen: Vec<Uuid> = fx::items(&pool, plan)
        .await
        .into_iter()
        .map(|(id, _, _)| id)
        .collect();
    for id in [seed, foreign, foreign_sealed] {
        assert!(
            frozen.contains(&id),
            "CALIBRATION: the frozen set must contain {id}, or this test never offers the \
             apply a foreign-group row to move. Frozen: {frozen:?}"
        );
    }

    let correlation = fx::dispatch(&pool, &world, plan, "applying").await;
    fx::run_apply(&scoped, &fx::apply_job(plan, world.actor, &correlation), 50)
        .await
        .expect("a plan that reaches another group's private claims must still apply");
    assert_eq!(fx::plan_state(&pool, plan).await, "applied");

    assert_eq!(
        fx::tenancy(&pool, seed).await,
        ("group".to_string(), world.target_group),
        "CALIBRATION: the public seed must have moved, or nothing was applied at all"
    );
    for (label, id) in [("private", foreign), ("sealed", foreign_sealed)] {
        assert_eq!(
            fx::tenancy(&pool, id).await,
            ("group".to_string(), group_a),
            "the {label} claim is group A's; a plan targeting another group must not take it"
        );
    }
    let states: std::collections::HashMap<Uuid, String> = fx::items(&pool, plan)
        .await
        .into_iter()
        .map(|(id, _, s)| (id, s))
        .collect();
    assert_eq!(states[&seed], "applied");
    assert_eq!(
        states[&foreign], "skipped",
        "an item this plan did not move must not say `applied`, or the revert would write its \
         pre-image back over a row this plan never touched"
    );
    assert_eq!(states[&foreign_sealed], "skipped");

    let correlation = fx::dispatch(&pool, &world, plan, "reverting").await;
    fx::run_revert(
        &scoped,
        &fx::revert_job(plan, world.actor, &correlation),
        50,
    )
    .await
    .expect("revert");
    assert_eq!(fx::plan_state(&pool, plan).await, "reverted");
    let world_group = viewer_fixture::world_group(&pool).await;
    assert_eq!(
        fx::tenancy(&pool, seed).await,
        ("public".to_string(), world_group),
        "the revert must still restore the row this plan did move"
    );
    for id in [foreign, foreign_sealed] {
        assert_eq!(
            fx::tenancy(&pool, id).await,
            ("group".to_string(), group_a),
            "and leave group A's claims where they were"
        );
    }
}

/// A `restrict` plan whose frozen set contains an already-encrypted claim is
/// still revertible.
///
/// # Why this is the regression that protects reversibility
///
/// `claim_encryption` is migration 060's table and belongs to the pre-existing
/// encrypted-subgraph feature; it is written from the ordinary claims surface
/// and has nothing to do with D4 seal mode. Nothing in the selection path
/// excludes such a claim — `resolve_seeds` accepts any id and the closure and
/// the content-lineage hull both run under the bypass viewer — so a `restrict`
/// plan can legitimately contain one. If the still-sealed count were not scoped
/// to `mode='seal'`, that plan could never be reverted, and full reversibility
/// is the property §6.5.4 rests the case for `restrict` on.
#[sqlx::test(migrations = "../../migrations")]
async fn a_restrict_plan_containing_an_encrypted_claim_is_still_revertible(pool: PgPool) {
    let world = fx::World::seed(&pool).await;
    let scoped = fx::scoped(&pool).await;
    let state = fx::split_state(&pool).await;
    let auth = fx::auth_for(world.actor);

    let claim = viewer_fixture::seed_public_claim(&pool, world.actor, "encrypted subject").await;
    let (plan, digest) = fx::create_plan(&pool, &world, &[claim]).await;
    assert_eq!(
        fx::plan_shape(&pool, plan).await.1,
        "restrict",
        "CALIBRATION: this must be a restrict plan, or it is measuring the seal arm"
    );
    let correlation = fx::dispatch(&pool, &world, plan, "applying").await;
    fx::run_apply(&scoped, &fx::apply_job(plan, world.actor, &correlation), 50)
        .await
        .expect("apply");

    // Migration 081's `claim_encryption_no_public_sealed` refuses this row while
    // the claim is public, which is why it comes after the apply.
    fx::encrypt_claim(&pool, claim, world.target_group).await;

    let (status, _) = epigraph_api::routes::privatization::revert_plan(
        epigraph_api::middleware::bearer::ViewerExtractor(
            epigraph_db::visibility::Viewer::resolve(&pool, world.actor)
                .await
                .expect("resolve the actor's viewer"),
        ),
        axum::extract::State(state),
        Some(axum::Extension(auth)),
        axum::extract::Path(plan),
        axum::Json(epigraph_api::routes::privatization::RevertRequest {
            plan_digest: format!("b3:{}", hex::encode(digest)),
        }),
    )
    .await
    .expect("a restrict plan that sealed nothing must be revertible");
    assert_eq!(status, axum::http::StatusCode::ACCEPTED);
    assert_eq!(fx::plan_state(&pool, plan).await, "reverting");
}

/// `revert` is refused with `409` and the still-sealed count while any item of
/// the plan is sealed (ops F13).
///
/// The refusal exists because migration 074's `claims_block_widening` has a
/// sealed arm with NO GUC override (sec F11): a sealed claim made public would
/// be a permanently unreadable row whose `content` is a stub and whose
/// `content_hash` no longer agrees with it. So the route must refuse BEFORE
/// dispatch rather than letting a batch fail `42501` half-way.
#[sqlx::test(migrations = "../../migrations")]
async fn revert_is_refused_while_a_seal_plan_item_is_still_sealed(pool: PgPool) {
    let world = fx::World::seed(&pool).await;
    let scoped = fx::scoped(&pool).await;
    let state = fx::split_state(&pool).await;
    let auth = fx::auth_for(world.actor);

    // Migration 081's plan guard refuses `mode='seal'` against anything but a
    // KEYED group, and migration 060's `groups_public_key_shape` requires a
    // 32-byte key on one. The fixture's group is `personal`, so it is promoted
    // here rather than in `World::seed` — every other test in this slice is
    // about `restrict` and must keep exercising the ordinary shape.
    let claim = viewer_fixture::seed_public_claim(&pool, world.actor, "sealed subject").await;
    sqlx::query(
        "UPDATE groups SET kind = 'team', public_key = decode(repeat('ab', 32), 'hex') \
          WHERE id = $1",
    )
    .bind(world.target_group)
    .execute(&pool)
    .await
    .expect("promote the target group to a keyed one");
    // The same guard also requires an ACTIVE key epoch on a seal target.
    sqlx::query(
        "INSERT INTO group_key_epochs (group_id, epoch, status) VALUES ($1, 0, 'active') \
         ON CONFLICT DO NOTHING",
    )
    .bind(world.target_group)
    .execute(&pool)
    .await
    .expect("seed the active key epoch");
    let (plan, digest) = fx::create_plan_with_mode(&pool, &world, &[claim], "seal").await;
    assert_eq!(
        fx::plan_shape(&pool, plan).await.1,
        "seal",
        "CALIBRATION: the still-sealed count is scoped to seal-mode plans, so a restrict plan \
         here would assert the refusal against a mode that cannot produce it"
    );
    let correlation = fx::dispatch(&pool, &world, plan, "applying").await;
    fx::run_apply(&scoped, &fx::apply_job(plan, world.actor, &correlation), 50)
        .await
        .expect("apply");

    // The claim is now `group`, so migration 081's `claim_encryption_no_public_sealed`
    // permits the encryption row. Inserting it against a PUBLIC claim would
    // raise 42501, which is why this comes after the apply and not before it.
    fx::encrypt_claim(&pool, claim, world.target_group).await;

    let echoed = format!("b3:{}", hex::encode(digest));
    let err = epigraph_api::routes::privatization::revert_plan(
        epigraph_api::middleware::bearer::ViewerExtractor(
            epigraph_db::visibility::Viewer::resolve(&pool, world.actor)
                .await
                .expect("resolve the actor's viewer"),
        ),
        axum::extract::State(state.clone()),
        Some(axum::Extension(auth.clone())),
        axum::extract::Path(plan),
        axum::Json(epigraph_api::routes::privatization::RevertRequest {
            plan_digest: echoed.clone(),
        }),
    )
    .await
    .expect_err("a plan with a sealed item must not be revertible");
    assert!(
        matches!(&err, ApiError::Conflict { reason } if reason.contains('1')),
        "expected a 409 carrying the still-sealed count, got {err:?}"
    );
    assert_eq!(
        fx::plan_state(&pool, plan).await,
        "applied",
        "a refused revert must not move the plan"
    );

    // The positive direction, as far as this build can go: with the encryption
    // row gone the same request is accepted. This is what makes the assertion
    // above a measurement of the SEAL condition rather than of a revert that
    // never worked.
    sqlx::query("DELETE FROM claim_encryption WHERE claim_id = $1")
        .bind(claim)
        .execute(&pool)
        .await
        .expect("unseal");
    let (status, _) = epigraph_api::routes::privatization::revert_plan(
        epigraph_api::middleware::bearer::ViewerExtractor(
            epigraph_db::visibility::Viewer::resolve(&pool, world.actor)
                .await
                .expect("resolve the actor's viewer"),
        ),
        axum::extract::State(state.clone()),
        Some(axum::Extension(auth)),
        axum::extract::Path(plan),
        axum::Json(epigraph_api::routes::privatization::RevertRequest {
            plan_digest: echoed,
        }),
    )
    .await
    .expect("an unsealed plan must be revertible");
    assert_eq!(status, axum::http::StatusCode::ACCEPTED);
    assert_eq!(fx::plan_state(&pool, plan).await, "reverting");

    let queued: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM jobs WHERE job_type = 'privatization_revert' AND state = 'pending'",
    )
    .fetch_one(&pool)
    .await
    .expect("count queued revert jobs");
    assert_eq!(
        queued, 1,
        "the dispatch must enqueue exactly one job. `enqueue_unique_pending` would have made a \
         second plan's job silently vanish, which is why the repo uses a plain enqueue"
    );

    let _ = Uuid::nil();
}
