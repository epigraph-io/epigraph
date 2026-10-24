//! Migration 168 (operator ruling R-CH1): an OUTSIDER's challenge is owned by
//! the outsider.
//!
//! An outsider is a challenger that cannot write the challenged claim's owning
//! group. Before 168 every `challenges` row copied its claim's
//! `(owner_group_id, visibility)` (074's BEFORE-row inherit, 070 arm (c)'s
//! re-sync, arm (d)'s propagation), so 077's `WITH CHECK` asked for the CLAIM's
//! group and every outsider's challenge was refused with 42501. Now:
//!
//! * an outsider's challenge on a PUBLIC claim lands owned by the challenger's
//!   own write group (`epigraph_writer_group()`, the group a plain claim by it
//!   would land in), `visibility = 'public'`, `writer_owned = true`;
//! * an insider's challenge inherits the claim's tenancy exactly as before;
//! * a later insert on the claim (arm (c)) and a change of the claim's owner or
//!   visibility (arm (d), privatization included) never move the outsider's
//!   row: the claim's tenancy is not the outsider's to follow;
//! * the outsider cannot re-flag, re-point or re-scope its row;
//! * a non-public claim the challenger cannot write is still refused.
//!
//! # Why every arm runs as `epigraph_app`
//!
//! `#[sqlx::test]` connects as the superuser `epigraph`, which bypasses row
//! security and which 114's attach rule deliberately leaves on the inherit
//! path, so an arm shaped "the insert now lands" would pass on a tree without
//! 168 on the harness connection. Every write below runs as the non-bypassing
//! `epigraph_app`, stamped exactly as `ScopedPool::begin_as` stamps a request.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::repos::{ChallengeRepository, CorpusStatsRepository};
use epigraph_db::visibility::Viewer;
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

async fn assert_app_role_does_not_bypass(pool: &PgPool) {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app's rolbypassrls");
    assert!(
        !bypassrls,
        "epigraph_app holds BYPASSRLS, so every arm in this file is vacuous"
    );
}

fn csv(ids: &[Uuid]) -> String {
    ids.iter()
        .map(Uuid::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

/// Stamp `conn` for `agent` exactly as `ScopedPool::begin_as` would.
async fn stamp(conn: &mut PgConnection, pool: &PgPool, agent: Uuid) {
    let v = Viewer::resolve(pool, agent).await.expect("resolve viewer");
    let groups = csv(v.group_bind().expect("scoped viewer"));
    let writable = csv(v.writable_groups());
    assert!(
        !writable.is_empty(),
        "a challenger with no writable group makes every arm vacuous"
    );
    sqlx::query(
        "SELECT set_config('epigraph.group_ids', $1, false), \
                set_config('epigraph.writable_group_ids', $2, false), \
                set_config('epigraph.principal_id', $3, false)",
    )
    .bind(groups)
    .bind(writable)
    .bind(agent.to_string())
    .execute(&mut *conn)
    .await
    .expect("stamp session gucs");
}

/// A public claim owned by `group` (the shape the MCP write path gives a claim
/// its author submits).
async fn public_claim_owned_by(pool: &PgPool, agent: Uuid, group: Uuid, tag: &str) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, $2, $3, 0.5, $4, true, 'public', $5)",
    )
    .bind(id)
    .bind(format!("challenge ownership fixture {tag}"))
    .bind(&hash)
    .bind(agent)
    .bind(group)
    .execute(pool)
    .await
    .expect("seed a public claim owned by a group");
    id
}

async fn challenge(
    conn: &mut PgConnection,
    claim: Uuid,
    challenger: Uuid,
    tag: &str,
) -> Result<Uuid, sqlx::Error> {
    ChallengeRepository::create(
        &mut *conn,
        claim,
        Some(challenger),
        "factual_error",
        &format!("challenge ownership fixture: {tag}"),
    )
    .await
}

/// `(owner_group_id, visibility, writer_owned)` of one challenge, read on the
/// harness connection.
async fn tenancy(pool: &PgPool, id: Uuid) -> (Uuid, String, bool) {
    sqlx::query_as(
        "SELECT owner_group_id, visibility::text, writer_owned FROM challenges WHERE id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("read challenge {id}: {e}"))
}

/// The ids of the challenges `agent`'s stamped app session can read.
async fn readable_by(
    conn: &mut PgConnection,
    pool: &PgPool,
    agent: Uuid,
    claim: Uuid,
) -> Vec<Uuid> {
    stamp(conn, pool, agent).await;
    let mut ids: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM challenges WHERE claim_id = $1")
        .bind(claim)
        .fetch_all(&mut *conn)
        .await
        .expect("read challenges as the app role");
    ids.sort();
    ids
}

/// R-CH1's main arm. An outsider challenges a public claim another agent's
/// group owns, and a WORLD-owned public claim (most public claims in
/// production): both land, owned by the outsider's own personal group, public
/// and flagged. The claim's owner and the outsider both read it.
#[sqlx::test(migrations = "../../migrations")]
async fn an_outsiders_challenge_on_a_public_claim_is_owned_by_the_outsider(pool: PgPool) {
    let (owner, owner_group) = fixture::seed_agent_with_group(&pool, "ch-owner").await;
    let (outsider, outsider_group) = fixture::seed_agent_with_group(&pool, "ch-outsider").await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "ch-stranger").await;
    let claim = public_claim_owned_by(&pool, owner, owner_group, "group-owned").await;
    let world_claim = fixture::seed_public_claim(&pool, owner, "world-owned public claim").await;
    assert_app_role_does_not_bypass(&pool).await;

    let p = pool.clone();
    let (on_group, on_world, seen_by_owner, seen_by_outsider, seen_by_stranger) =
        fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
            stamp(&mut conn, &p, outsider).await;
            let a = challenge(
                &mut conn,
                claim,
                outsider,
                "outsider on a group-owned claim",
            )
            .await;
            let b = challenge(
                &mut conn,
                world_claim,
                outsider,
                "outsider on a world claim",
            )
            .await;
            let o = readable_by(&mut conn, &p, owner, claim).await;
            let x = readable_by(&mut conn, &p, outsider, claim).await;
            let s = readable_by(&mut conn, &p, stranger, claim).await;
            (conn, (a, b, o, x, s))
        })
        .await;

    let on_group = on_group.expect(
        "an outsider's challenge on a public claim must land (R-CH1); before 168 the row \
         inherited the claim's group and 077 refused it",
    );
    let on_world = on_world.expect("an outsider's challenge on a world-owned public claim lands");
    assert_eq!(
        tenancy(&pool, on_group).await,
        (outsider_group, "public".to_string(), true),
        "owned by the OUTSIDER's group, public, flagged writer-owned"
    );
    assert_eq!(
        tenancy(&pool, on_world).await,
        (outsider_group, "public".to_string(), true)
    );
    assert_eq!(
        seen_by_owner,
        vec![on_group],
        "the claim's owner reads the challenge"
    );
    assert_eq!(
        seen_by_outsider,
        vec![on_group],
        "the outsider reads its own"
    );
    assert_eq!(
        seen_by_stranger,
        vec![on_group],
        "a public challenge on a public claim is public"
    );
}

/// The insider rule is unchanged: a challenger that CAN write the claim's
/// group gets a row that inherits the claim's tenancy, public or not, and is
/// not flagged.
#[sqlx::test(migrations = "../../migrations")]
async fn an_insiders_challenge_still_inherits_the_claims_tenancy(pool: PgPool) {
    let (owner, owner_group) = fixture::seed_agent_with_group(&pool, "ch-insider").await;
    let public = public_claim_owned_by(&pool, owner, owner_group, "insider public").await;
    let private = fixture::seed_group_claim(&pool, owner, owner_group, "insider private").await;
    assert_app_role_does_not_bypass(&pool).await;

    let p = pool.clone();
    let (a, b) = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, owner).await;
        let a = challenge(&mut conn, public, owner, "insider on public").await;
        let b = challenge(&mut conn, private, owner, "insider on private").await;
        (conn, (a, b))
    })
    .await;
    assert_eq!(
        tenancy(&pool, a.expect("insider on public")).await,
        (owner_group, "public".to_string(), false)
    );
    assert_eq!(
        tenancy(&pool, b.expect("insider on private")).await,
        (owner_group, "group".to_string(), false)
    );
}

/// Arm (c) and arm (d) leave the outsider's row alone. A later insert on the
/// same claim (the owner's challenge, and one on the privileged harness
/// connection) re-syncs the claim's rows and must not re-stamp the outsider's;
/// re-owning the claim and then PRIVATIZING it moves the insider's challenge
/// (the control) and never the outsider's.
#[sqlx::test(migrations = "../../migrations")]
async fn neither_propagation_arm_drags_an_outsiders_challenge_along(pool: PgPool) {
    let (owner, owner_group) = fixture::seed_agent_with_group(&pool, "ch-prop-owner").await;
    let (outsider, outsider_group) = fixture::seed_agent_with_group(&pool, "ch-prop-out").await;
    let claim = public_claim_owned_by(&pool, owner, owner_group, "propagation").await;
    assert_app_role_does_not_bypass(&pool).await;

    let p = pool.clone();
    let (theirs, insiders) = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, outsider).await;
        let t = challenge(&mut conn, claim, outsider, "outsider").await;
        stamp(&mut conn, &p, owner).await;
        let i = challenge(&mut conn, claim, owner, "insider, later").await;
        (conn, (t, i))
    })
    .await;
    let theirs = theirs.expect("the outsider's challenge lands");
    let insiders = insiders.expect("the insider's challenge lands");
    sqlx::query(
        "INSERT INTO challenges (claim_id, challenge_type, explanation, state) \
         VALUES ($1, 'factual_error', 'harness insert', 'pending')",
    )
    .bind(claim)
    .execute(&pool)
    .await
    .expect("a privileged insert on the same claim fires arm (c) again");

    let outsiders_row = (outsider_group, "public".to_string(), true);
    assert_eq!(
        tenancy(&pool, theirs).await,
        outsiders_row,
        "arm (c) must not re-stamp the outsider's row to the claim's owner"
    );

    // Arm (d), the claim stays public: re-own it.
    let (_, new_group) = fixture::seed_agent_with_group(&pool, "ch-prop-new-owner").await;
    sqlx::query("UPDATE claims SET owner_group_id = $2 WHERE id = $1")
        .bind(claim)
        .bind(new_group)
        .execute(&pool)
        .await
        .expect("re-own the claim");
    assert_eq!(tenancy(&pool, theirs).await, outsiders_row);
    assert_eq!(
        tenancy(&pool, insiders).await,
        (new_group, "public".to_string(), false),
        "control: the insider's challenge follows the re-own"
    );

    // Arm (d), the claim NARROWS.
    sqlx::query("UPDATE claims SET visibility = 'group' WHERE id = $1")
        .bind(claim)
        .execute(&pool)
        .await
        .expect("privatize the claim");
    assert_eq!(
        tenancy(&pool, theirs).await,
        outsiders_row,
        "privatizing the claim must not drag the outsider's challenge into the claim's group"
    );
    assert_eq!(
        tenancy(&pool, insiders).await,
        (new_group, "group".to_string(), false),
        "control: the insider's challenge narrows with the claim"
    );
}

/// The outsider owns its row but may not re-flag it, re-point it at another
/// claim, or re-scope it: those track a claim that is not the outsider's.
#[sqlx::test(migrations = "../../migrations")]
async fn an_outsider_cannot_reflag_repoint_or_rescope_its_challenge(pool: PgPool) {
    let (owner, owner_group) = fixture::seed_agent_with_group(&pool, "ch-guard-owner").await;
    let (outsider, outsider_group) = fixture::seed_agent_with_group(&pool, "ch-guard-out").await;
    let claim = public_claim_owned_by(&pool, owner, owner_group, "guarded").await;
    let other = fixture::seed_group_claim(&pool, owner, owner_group, "a private claim").await;
    assert_app_role_does_not_bypass(&pool).await;

    let p = pool.clone();
    let (mine, unflag, repoint, rescope) =
        fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
            stamp(&mut conn, &p, outsider).await;
            let mine = challenge(&mut conn, claim, outsider, "mine")
                .await
                .expect("the outsider's challenge lands");
            let unflag = sqlx::query("UPDATE challenges SET writer_owned = false WHERE id = $1")
                .bind(mine)
                .execute(&mut *conn)
                .await;
            let repoint = sqlx::query("UPDATE challenges SET claim_id = $2 WHERE id = $1")
                .bind(mine)
                .bind(other)
                .execute(&mut *conn)
                .await;
            let rescope = sqlx::query("UPDATE challenges SET visibility = 'group' WHERE id = $1")
                .bind(mine)
                .execute(&mut *conn)
                .await;
            (conn, (mine, unflag, repoint, rescope))
        })
        .await;
    for (what, out) in [
        ("unflag", unflag),
        ("repoint", repoint),
        ("rescope", rescope),
    ] {
        let e = out.expect_err(what);
        assert!(
            e.to_string().contains("only a maintenance session"),
            "{what}: refused by the writer-owner guard: {e}"
        );
    }
    assert_eq!(
        tenancy(&pool, mine).await,
        (outsider_group, "public".to_string(), true)
    );
    let claim_now: Uuid = sqlx::query_scalar("SELECT claim_id FROM challenges WHERE id = $1")
        .bind(mine)
        .fetch_one(&pool)
        .await
        .expect("claim_id");
    assert_eq!(claim_now, claim);
}

/// Writer-owned rows exist only on PUBLIC claims. A group-private claim the
/// challenger can READ (a reader member) but not write is refused as before,
/// and so is one it cannot read at all; nothing is written either way.
#[sqlx::test(migrations = "../../migrations")]
async fn a_non_public_claim_the_challenger_cannot_write_is_still_refused(pool: PgPool) {
    let (owner, owner_group) = fixture::seed_agent_with_group(&pool, "ch-np-owner").await;
    let (reader, _) = fixture::seed_agent_with_group(&pool, "ch-np-reader").await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "ch-np-stranger").await;
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'reader')",
    )
    .bind(owner_group)
    .bind(reader)
    .execute(&pool)
    .await
    .expect("reader membership");
    let private = fixture::seed_group_claim(&pool, owner, owner_group, "np private").await;
    assert_app_role_does_not_bypass(&pool).await;

    let p = pool.clone();
    let (by_reader, by_stranger) = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, reader).await;
        let r = challenge(&mut conn, private, reader, "reader").await;
        stamp(&mut conn, &p, stranger).await;
        let s = challenge(&mut conn, private, stranger, "stranger").await;
        (conn, (r, s))
    })
    .await;
    by_reader.expect_err("a reader of a private claim cannot challenge it");
    by_stranger.expect_err("a stranger cannot challenge a private claim");
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM challenges WHERE claim_id = $1")
        .bind(private)
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(n, 0, "nothing written");
}

/// Ruling R-CH1b, enforced in the DATABASE and in the repo layer. The
/// outsider's challenge stays the outsider's when the claim is privatized
/// (owner unchanged), but it is readable only by a session that can read the
/// claim: to a stranger, and to the outsider itself once it loses the claim,
/// the challenge id reads exactly like a nonexistent one; the claim's group
/// members (owner and a reader member) still see it.
///
/// Two layers, each measured on its own:
/// * row security (migration 168's restrictive read policy), as `epigraph_app`
///   with the stamp of each reader;
/// * the in-query predicate of `ChallengeRepository::{get, list_for_claim,
///   get_gap_challenges}`, on the superuser harness pool, which bypasses row
///   security, so only the repo's own claim predicate can hide the row.
#[sqlx::test(migrations = "../../migrations")]
async fn a_privatized_claims_outsider_challenge_reads_only_with_the_claim(pool: PgPool) {
    let (owner, owner_group) = fixture::seed_agent_with_group(&pool, "ch-read-owner").await;
    let (outsider, outsider_group) = fixture::seed_agent_with_group(&pool, "ch-read-out").await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "ch-read-stranger").await;
    let (member, _) = fixture::seed_agent_with_group(&pool, "ch-read-member").await;
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'reader')",
    )
    .bind(owner_group)
    .bind(member)
    .execute(&pool)
    .await
    .expect("reader membership");
    let claim = public_claim_owned_by(&pool, owner, owner_group, "read gate").await;
    assert_app_role_does_not_bypass(&pool).await;

    let p = pool.clone();
    let theirs = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, outsider).await;
        let t = challenge(&mut conn, claim, outsider, "outsider, then privatized").await;
        (conn, t)
    })
    .await
    .expect("the outsider's challenge lands");
    // An outsider-owned GAP challenge on the same claim, for
    // `get_gap_challenges` (no transport writes gap types from outside; the
    // shape is set on the harness as 168's attach rule would set it).
    let gap: Uuid = sqlx::query_scalar(
        "INSERT INTO challenges (claim_id, challenger_id, challenge_type, explanation, state) \
         VALUES ($1, $2, 'epistemic_gap_structural', 'gap fixture', 'pending') RETURNING id",
    )
    .bind(claim)
    .bind(outsider)
    .fetch_one(&pool)
    .await
    .expect("seed a gap challenge");
    sqlx::query(
        "UPDATE challenges SET owner_group_id = $2, visibility = 'public', writer_owned = true \
          WHERE id = $1",
    )
    .bind(gap)
    .bind(outsider_group)
    .execute(&pool)
    .await
    .expect("make the gap challenge outsider-owned");

    sqlx::query("UPDATE claims SET visibility = 'group' WHERE id = $1")
        .bind(claim)
        .execute(&pool)
        .await
        .expect("the owner privatizes the claim");
    assert_eq!(
        tenancy(&pool, theirs).await,
        (outsider_group, "public".to_string(), true),
        "ownership stays with the outsider"
    );

    // Layer 1: row security.
    let p = pool.clone();
    let missing = Uuid::new_v4();
    let seen = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        let mut out = Vec::new();
        for (who, agent) in [
            ("stranger", stranger),
            ("outsider", outsider),
            ("owner", owner),
            ("member", member),
        ] {
            stamp(&mut conn, &p, agent).await;
            let by_id: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM challenges WHERE id = $1")
                .bind(theirs)
                .fetch_all(&mut *conn)
                .await
                .expect("read by id");
            let by_missing: Vec<Uuid> =
                sqlx::query_scalar("SELECT id FROM challenges WHERE id = $1")
                    .bind(missing)
                    .fetch_all(&mut *conn)
                    .await
                    .expect("read a missing id");
            let on_claim: i64 =
                sqlx::query_scalar("SELECT count(*) FROM challenges WHERE claim_id = $1")
                    .bind(claim)
                    .fetch_one(&mut *conn)
                    .await
                    .expect("count on the claim");
            out.push((who, by_id, by_missing, on_claim));
        }
        (conn, out)
    })
    .await;
    for (who, by_id, by_missing, on_claim) in seen {
        match who {
            "stranger" | "outsider" => {
                assert_eq!(
                    by_id, by_missing,
                    "{who}: the challenge reads exactly like a nonexistent id"
                );
                assert!(by_id.is_empty(), "{who}");
                assert_eq!(on_claim, 0, "{who}: nothing hangs off the private claim");
            }
            _ => {
                assert_eq!(by_id, vec![theirs], "{who}: a claim reader still sees it");
                assert_eq!(on_claim, 2, "{who}: both challenges");
            }
        }
    }

    // Layer 2: the repo's own predicate, with row security bypassed.
    for (who, agent, visible) in [
        ("stranger", stranger, false),
        ("outsider", outsider, false),
        ("owner", owner, true),
        ("member", member, true),
    ] {
        let v = Viewer::resolve(&pool, agent).await.expect("viewer");
        let got = ChallengeRepository::get(&pool, &v, theirs)
            .await
            .expect("get");
        assert_eq!(got.is_some(), visible, "{who}: get");
        let listed = ChallengeRepository::list_for_claim(&pool, &v, claim)
            .await
            .expect("list_for_claim");
        assert_eq!(listed.len(), if visible { 2 } else { 0 }, "{who}: list");
        let gaps = ChallengeRepository::get_gap_challenges(&pool, &v, None, None, 100)
            .await
            .expect("get_gap_challenges");
        assert_eq!(
            gaps.iter().any(|g| g.id == gap),
            visible,
            "{who}: get_gap_challenges"
        );
        // `system_stats`' corpus count: both challenges are public, so only
        // the claim's predicate keeps them out of a non-reader's count.
        let counts = CorpusStatsRepository::tenant_counts(&pool, &v, true)
            .await
            .expect("tenant_counts");
        assert_eq!(
            counts.challenges,
            Some(if visible { 2 } else { 0 }),
            "{who}: corpus challenge count"
        );
    }
}
