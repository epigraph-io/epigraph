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

// =========================================================================
// Operator ruling R-3: the claim's owner sets an outsider's challenge's
// resolution status, and nothing else.
// =========================================================================

/// The SQLSTATE of a database error, or `None` for any other error.
fn sqlstate(e: &sqlx::Error) -> Option<String> {
    e.as_database_error()
        .and_then(|d| d.code())
        .map(|c| c.into_owned())
}

/// Every column of one challenge EXCEPT the four resolution columns
/// (`state`, `resolved_by`, `resolved_at`, `resolution_details`), read on the
/// harness connection: the outsider's text, its type, its challenger, its
/// claim, its tenancy and its flag.
async fn content_columns(pool: &PgPool, id: Uuid) -> serde_json::Value {
    sqlx::query_scalar(
        "SELECT to_jsonb(ch) - 'state' - 'resolved_by' - 'resolved_at' - 'resolution_details' \
           FROM challenges ch WHERE ch.id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("read challenge {id}: {e}"))
}

/// `(state, resolved_by, resolved_at IS NOT NULL, resolution_details)`.
async fn resolution(
    pool: &PgPool,
    id: Uuid,
) -> (String, Option<Uuid>, bool, Option<serde_json::Value>) {
    sqlx::query_as(
        "SELECT state::text, resolved_by, resolved_at IS NOT NULL, resolution_details \
           FROM challenges WHERE id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("read challenge {id}: {e}"))
}

/// The `security_events` rows recording a claim-owner resolution of `id`:
/// `(agent_id, details)`.
async fn resolution_audit(pool: &PgPool, id: Uuid) -> Vec<(Option<Uuid>, serde_json::Value)> {
    sqlx::query_as(
        "SELECT agent_id, details FROM security_events \
          WHERE event_type = 'challenges.claim_owner_resolution' \
            AND details->>'challenge_id' = $1::text \
          ORDER BY created_at",
    )
    .bind(id)
    .fetch_all(pool)
    .await
    .expect("read the resolution audit")
}

/// R-3's main arm. An outsider challenges a public claim; the claim's owner
/// sets the challenge's resolution status through
/// `ChallengeRepository::resolve_as_claim_owner`, as the non-bypassing
/// application role. The status lands, `resolved_by` names the owner (the
/// session principal, not a caller-supplied id), and one append-only
/// `security_events` row names the resolver. Every other column (the
/// outsider's text, its challenger, its claim, its owner and flag) is
/// byte-identical: the outsider keeps ownership.
///
/// The same owner, by plain SQL, can neither edit the outsider's text nor
/// re-own the row (077's WITH CHECK, 115's owner guard), nor delete it (115's
/// restrictive DELETE policy filters the row, so the DELETE affects nothing).
#[sqlx::test(migrations = "../../migrations")]
async fn the_claims_owner_sets_an_outsiders_challenge_status_and_nothing_else(pool: PgPool) {
    let (owner, owner_group) = fixture::seed_agent_with_group(&pool, "ch-res-owner").await;
    let (outsider, outsider_group) = fixture::seed_agent_with_group(&pool, "ch-res-out").await;
    let claim = public_claim_owned_by(&pool, owner, owner_group, "resolution").await;
    assert_app_role_does_not_bypass(&pool).await;

    let p = pool.clone();
    let theirs = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, outsider).await;
        let t = challenge(&mut conn, claim, outsider, "the outsider's own words").await;
        (conn, t)
    })
    .await
    .expect("the outsider's challenge lands");
    assert_eq!(
        tenancy(&pool, theirs).await,
        (outsider_group, "public".to_string(), true),
        "CALIBRATION: the row is outsider-owned before the owner acts"
    );
    let before = content_columns(&pool, theirs).await;

    let details = serde_json::json!({ "reason": "the cited figure is correct" });
    let d = details.clone();
    let p = pool.clone();
    let (resolved, edit, reown, deleted) =
        fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
            stamp(&mut conn, &p, owner).await;
            let r = ChallengeRepository::resolve_as_claim_owner(
                &mut *conn,
                theirs,
                "rejected",
                Some(&d),
            )
            .await;
            let edit = sqlx::query("UPDATE challenges SET explanation = 'rewritten' WHERE id = $1")
                .bind(theirs)
                .execute(&mut *conn)
                .await;
            let reown = sqlx::query("UPDATE challenges SET owner_group_id = $2 WHERE id = $1")
                .bind(theirs)
                .bind(owner_group)
                .execute(&mut *conn)
                .await;
            let deleted = sqlx::query("DELETE FROM challenges WHERE id = $1")
                .bind(theirs)
                .execute(&mut *conn)
                .await
                .expect("a filtered DELETE is not an error")
                .rows_affected();
            (conn, (r, edit, reown, deleted))
        })
        .await;

    resolved.expect(
        "the claim's owner sets the status of an outsider's challenge (R-3); a plain UPDATE \
         is refused by 077's WITH CHECK because the row is the outsider's",
    );
    assert_eq!(
        resolution(&pool, theirs).await,
        ("rejected".to_string(), Some(owner), true, Some(details)),
        "status, resolver (the session principal), time and details are set"
    );
    let audit = resolution_audit(&pool, theirs).await;
    assert_eq!(audit.len(), 1, "exactly one audit record: {audit:?}");
    assert_eq!(
        audit[0].0,
        Some(owner),
        "the audit record names the resolver"
    );
    assert_eq!(audit[0].1["resolver_agent_id"], owner.to_string());
    assert_eq!(audit[0].1["claim_id"], claim.to_string());
    assert_eq!(audit[0].1["claim_owner_group_id"], owner_group.to_string());
    assert_eq!(
        audit[0].1["challenge_owner_group_id"],
        outsider_group.to_string()
    );
    assert_eq!(audit[0].1["state_before"], "pending");
    assert_eq!(audit[0].1["state_after"], "rejected");

    assert!(
        edit.is_err(),
        "the owner cannot edit the outsider's text: {edit:?}"
    );
    assert!(
        reown.is_err(),
        "the owner cannot re-own the outsider's row: {reown:?}"
    );
    assert_eq!(
        deleted, 0,
        "the owner cannot delete the outsider's challenge"
    );
    assert_eq!(
        content_columns(&pool, theirs).await,
        before,
        "every non-resolution column, the outsider's text and ownership included, is unchanged"
    );
}

/// Only a WRITER of the challenged claim's owning group sets the status, only
/// to a resolver's state, and an unreadable claim's challenge answers exactly
/// as a nonexistent id. The outsider itself, a stranger, and a READER member
/// of the claim's group are refused (42501); `withdrawn` (the challenger's
/// act) and a state outside the core set are refused (22023); a stranger
/// asking about a private claim's challenge gets the same error, code and
/// text, as for a random id. Nothing is written by any refusal, and the same
/// call by the owner then lands (the refusals were not malformed calls).
#[sqlx::test(migrations = "../../migrations")]
async fn only_a_writer_of_the_claims_group_sets_a_challenges_status(pool: PgPool) {
    let (owner, owner_group) = fixture::seed_agent_with_group(&pool, "ch-rs-owner").await;
    let (outsider, _) = fixture::seed_agent_with_group(&pool, "ch-rs-out").await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "ch-rs-stranger").await;
    let (member, _) = fixture::seed_agent_with_group(&pool, "ch-rs-member").await;
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'reader')",
    )
    .bind(owner_group)
    .bind(member)
    .execute(&pool)
    .await
    .expect("reader membership");
    let claim = public_claim_owned_by(&pool, owner, owner_group, "status refusals").await;
    let private = fixture::seed_group_claim(&pool, owner, owner_group, "rs private").await;
    let on_private: Uuid = sqlx::query_scalar(
        "INSERT INTO challenges (claim_id, challenger_id, challenge_type, explanation, state) \
         VALUES ($1, $2, 'factual_error', 'an insider on a private claim', 'pending') \
         RETURNING id",
    )
    .bind(private)
    .bind(owner)
    .fetch_one(&pool)
    .await
    .expect("seed a challenge on the private claim");
    assert_app_role_does_not_bypass(&pool).await;

    let p = pool.clone();
    let theirs = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, outsider).await;
        let t = challenge(&mut conn, claim, outsider, "status refusals").await;
        (conn, t)
    })
    .await
    .expect("the outsider's challenge lands");

    let missing = Uuid::new_v4();
    let p = pool.clone();
    let (by_who, bad_states, hidden, nonexistent, then_owner) =
        fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
            let mut by_who = Vec::new();
            for (who, agent) in [
                ("outsider", outsider),
                ("stranger", stranger),
                ("reader member", member),
            ] {
                stamp(&mut conn, &p, agent).await;
                let r = ChallengeRepository::resolve_as_claim_owner(
                    &mut *conn, theirs, "accepted", None,
                )
                .await;
                by_who.push((who, r));
            }
            stamp(&mut conn, &p, owner).await;
            let mut bad_states = Vec::new();
            for state in ["withdrawn", "resolved", "pending"] {
                let r =
                    ChallengeRepository::resolve_as_claim_owner(&mut *conn, theirs, state, None)
                        .await;
                bad_states.push((state, r));
            }
            stamp(&mut conn, &p, stranger).await;
            let hidden = ChallengeRepository::resolve_as_claim_owner(
                &mut *conn, on_private, "accepted", None,
            )
            .await;
            let nonexistent =
                ChallengeRepository::resolve_as_claim_owner(&mut *conn, missing, "accepted", None)
                    .await;
            stamp(&mut conn, &p, owner).await;
            let then_owner = ChallengeRepository::resolve_as_claim_owner(
                &mut *conn,
                theirs,
                "under_review",
                None,
            )
            .await;
            (conn, (by_who, bad_states, hidden, nonexistent, then_owner))
        })
        .await;

    for (who, r) in &by_who {
        let e = r.as_ref().expect_err(who);
        assert_eq!(
            sqlstate(e).as_deref(),
            Some("42501"),
            "{who}: refused as a non-writer of the claim's group: {e}"
        );
    }
    for (state, r) in &bad_states {
        let e = r.as_ref().expect_err(state);
        assert_eq!(
            sqlstate(e).as_deref(),
            Some("22023"),
            "{state}: not a resolution status the claim's owner sets: {e}"
        );
    }
    let hidden = hidden.expect_err("a stranger cannot resolve a private claim's challenge");
    let nonexistent = nonexistent.expect_err("a random id resolves nothing");
    assert_eq!(
        (sqlstate(&hidden), hidden.to_string()),
        (sqlstate(&nonexistent), nonexistent.to_string()),
        "a private claim's challenge answers exactly as a random id"
    );
    assert_eq!(
        resolution(&pool, on_private).await,
        ("pending".to_string(), None, false, None),
        "the private claim's challenge is untouched"
    );
    assert!(
        resolution_audit(&pool, on_private).await.is_empty(),
        "a refusal writes no audit record"
    );

    then_owner.expect("CALIBRATION: the owner's well-formed call lands");
    assert_eq!(
        resolution(&pool, theirs).await,
        ("under_review".to_string(), Some(owner), false, None),
        "only the owner's call changed the status"
    );
    assert_eq!(
        resolution_audit(&pool, theirs).await.len(),
        1,
        "one audit record, the owner's; none for the refused calls"
    );
}

/// The whole row, read on the harness connection.
async fn whole_row(pool: &PgPool, id: Uuid) -> serde_json::Value {
    sqlx::query_scalar("SELECT to_jsonb(ch) FROM challenges ch WHERE ch.id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap_or_else(|e| panic!("read challenge {id}: {e}"))
}

/// A WITHDRAWN challenge is not resolved by the claim's owner. Withdrawal is
/// the challenger's act (the outsider's own plain UPDATE of its own row, which
/// 077 admits), and R-3 lets the claim's owner set a RESOLUTION status, not
/// overturn the challenger's withdrawal: the definer refuses a row whose
/// CURRENT state is `withdrawn` (CR06, 55000), for every resolver state, and
/// writes nothing (the row is byte-identical and no audit row exists). The
/// same owner's call on a live challenge then lands (the calibration: the
/// refusal is the withdrawal, not a malformed call).
#[sqlx::test(migrations = "../../migrations")]
async fn the_claims_owner_does_not_resolve_a_withdrawn_challenge(pool: PgPool) {
    let (owner, owner_group) = fixture::seed_agent_with_group(&pool, "ch-wd-owner").await;
    let (outsider, _) = fixture::seed_agent_with_group(&pool, "ch-wd-out").await;
    let claim = public_claim_owned_by(&pool, owner, owner_group, "withdrawn").await;
    assert_app_role_does_not_bypass(&pool).await;

    let p = pool.clone();
    let (withdrawn, live) = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, outsider).await;
        let w = challenge(&mut conn, claim, outsider, "later withdrawn")
            .await
            .expect("the outsider's challenge lands");
        let l = challenge(&mut conn, claim, outsider, "still live")
            .await
            .expect("the outsider's second challenge lands");
        let n = sqlx::query("UPDATE challenges SET state = 'withdrawn' WHERE id = $1")
            .bind(w)
            .execute(&mut *conn)
            .await
            .expect("the outsider withdraws its own challenge")
            .rows_affected();
        assert_eq!(n, 1, "CALIBRATION: the withdrawal landed");
        (conn, (w, l))
    })
    .await;
    assert_eq!(
        resolution(&pool, withdrawn).await.0,
        "withdrawn",
        "CALIBRATION: the row is withdrawn before the owner acts"
    );
    let before = whole_row(&pool, withdrawn).await;

    let p = pool.clone();
    let (refused, then_live) = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, owner).await;
        let mut refused = Vec::new();
        for state in ["under_review", "accepted", "rejected"] {
            let r = ChallengeRepository::resolve_as_claim_owner(&mut *conn, withdrawn, state, None)
                .await;
            refused.push((state, r));
        }
        let l =
            ChallengeRepository::resolve_as_claim_owner(&mut *conn, live, "rejected", None).await;
        (conn, (refused, l))
    })
    .await;

    for (state, r) in &refused {
        let e = r
            .as_ref()
            .expect_err("the owner does not overturn the challenger's withdrawal");
        assert_eq!(
            sqlstate(e).as_deref(),
            Some("55000"),
            "{state}: refused because the challenge is withdrawn: {e}"
        );
        assert!(
            e.to_string().contains("CR06"),
            "{state}: refused by the withdrawn-row check, not another one: {e}"
        );
    }
    assert_eq!(
        whole_row(&pool, withdrawn).await,
        before,
        "the withdrawn row is byte-identical"
    );
    assert!(
        resolution_audit(&pool, withdrawn).await.is_empty(),
        "a refusal writes no audit record"
    );
    then_live.expect("CALIBRATION: the owner resolves the challenger's live challenge");
    assert_eq!(resolution(&pool, live).await.0, "rejected");
}

/// A caller that cannot read a challenge's claim neither learns that the
/// challenge exists nor waits on it. The row is the shape ruling R-5 keeps:
/// an outsider's PUBLIC, writer-owned challenge on a claim that has since been
/// restricted (arm (d) leaves the row where it is). While another transaction
/// holds a lock on that row, a stranger and the outsider itself (neither can
/// read the restricted claim) get, at once, exactly the error a random id
/// gets: the definer filters on the claim's readability BEFORE it locks
/// anything, and locks the claim before the challenge (the order arm (d)'s
/// propagation takes). Nothing is written or audited.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unreadable_claims_challenge_is_neither_found_nor_waited_on(pool: PgPool) {
    let (owner, owner_group) = fixture::seed_agent_with_group(&pool, "ch-lk-owner").await;
    let (outsider, outsider_group) = fixture::seed_agent_with_group(&pool, "ch-lk-out").await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "ch-lk-stranger").await;
    let claim = public_claim_owned_by(&pool, owner, owner_group, "restricted later").await;
    assert_app_role_does_not_bypass(&pool).await;

    let p = pool.clone();
    let theirs = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, outsider).await;
        let t = challenge(&mut conn, claim, outsider, "on a claim restricted later").await;
        (conn, t)
    })
    .await
    .expect("the outsider's challenge lands");
    sqlx::query("UPDATE claims SET visibility = 'group' WHERE id = $1")
        .bind(claim)
        .execute(&pool)
        .await
        .expect("restrict the claim");
    assert_eq!(
        tenancy(&pool, theirs).await,
        (outsider_group, "public".to_string(), true),
        "CALIBRATION: the kept row is the outsider's and public on a restricted claim"
    );
    let before = whole_row(&pool, theirs).await;

    let mut held = pool.begin().await.expect("begin the holder");
    sqlx::query("SELECT 1 FROM challenges WHERE id = $1 FOR UPDATE")
        .bind(theirs)
        .execute(&mut *held)
        .await
        .expect("hold a lock on the hidden challenge");

    let missing = Uuid::new_v4();
    let p = pool.clone();
    let answers = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        sqlx::query("SET lock_timeout = '300ms'")
            .execute(&mut *conn)
            .await
            .expect("bound the wait");
        let mut answers = Vec::new();
        for (who, agent) in [("stranger", stranger), ("outsider", outsider)] {
            stamp(&mut conn, &p, agent).await;
            let hidden =
                ChallengeRepository::resolve_as_claim_owner(&mut *conn, theirs, "accepted", None)
                    .await;
            let random =
                ChallengeRepository::resolve_as_claim_owner(&mut *conn, missing, "accepted", None)
                    .await;
            answers.push((who, hidden, random));
        }
        sqlx::query("RESET lock_timeout")
            .execute(&mut *conn)
            .await
            .expect("reset the bound");
        (conn, answers)
    })
    .await;
    held.rollback().await.expect("release the holder");

    for (who, hidden, random) in &answers {
        let hidden = hidden
            .as_ref()
            .expect_err("a non-reader resolves nothing on a hidden challenge");
        let random = random.as_ref().expect_err("a random id resolves nothing");
        assert_eq!(
            (sqlstate(hidden), hidden.to_string()),
            (sqlstate(random), random.to_string()),
            "{who}: the hidden challenge answers exactly as a random id (no wait, no oracle)"
        );
        assert_eq!(sqlstate(random).as_deref(), Some("P0002"), "{who}");
    }
    assert_eq!(
        whole_row(&pool, theirs).await,
        before,
        "the hidden row is untouched"
    );
    assert!(
        resolution_audit(&pool, theirs).await.is_empty(),
        "a refusal writes no audit record"
    );
}
