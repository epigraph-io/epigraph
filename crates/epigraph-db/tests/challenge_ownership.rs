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

    // The audit record cannot be rewritten or deleted either, by the outsider
    // (which owns the row; since migration 170 it cannot rewrite the row's
    // resolution columns) or by the resolver.
    for agent in [outsider, owner] {
        let p = pool.clone();
        fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
            stamp(&mut conn, &p, agent).await;
            let _ = sqlx::query(
                "UPDATE security_events SET agent_id = NULL, details = '{}'::jsonb \
                  WHERE event_type = 'challenges.claim_owner_resolution'",
            )
            .execute(&mut *conn)
            .await;
            let _ = sqlx::query(
                "DELETE FROM security_events \
                  WHERE event_type = 'challenges.claim_owner_resolution'",
            )
            .execute(&mut *conn)
            .await;
            (conn, ())
        })
        .await;
    }
    assert_eq!(
        resolution_audit(&pool, theirs).await,
        audit,
        "no application session rewrites or deletes the resolution audit"
    );

    let edit = edit.expect_err("the owner cannot edit the outsider's text");
    assert_eq!(
        (sqlstate(&edit).as_deref(), edit.to_string()),
        (
            Some("42501"),
            "error returned from database: new row violates row-level security policy for \
             table \"challenges\""
                .to_string()
        ),
        "the edit is refused by 077's WITH CHECK (the row is the outsider's)"
    );
    let reown = reown.expect_err("the owner cannot re-own the outsider's row");
    assert_eq!(
        sqlstate(&reown).as_deref(),
        Some("42501"),
        "re-owning is refused: {reown}"
    );
    assert!(
        reown.to_string().contains(
            "epigraph tenancy: an UPDATE of challenges changes owner_group_id or \
             co_owner_group_id; only a maintenance session re-owns a row"
        ),
        "the re-own is refused by 115's owner guard (challenges_owner_immutable): {reown}"
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

/// THE DEFINER PATH (`epigraph_resolve_challenge`): only a WRITER of the
/// challenged claim's owning group sets a status through it, only to a
/// resolver's state, and an unreadable claim's challenge answers exactly as a
/// nonexistent id. The outsider itself, a stranger, and a READER member of the
/// claim's group are refused (42501); `withdrawn` (the challenger's act) and a
/// state outside the core set are refused (22023); a stranger asking about a
/// private claim's challenge gets the same error, code and text, as for a
/// random id. Nothing is written by any refusal, and the same call by the
/// owner then lands (the refusals were not malformed calls).
///
/// `resolved` is refused although the ruling's text lists it as an example
/// status: the schema's vocabulary (`ChallengeState`: pending, under_review,
/// accepted, rejected, withdrawn) has no `resolved`, and the ruling's
/// "resolved" is a resolution, i.e. `accepted` or `rejected`.
///
/// Exclusivity of the resolution columns (no plain-SQL UPDATE of them by any
/// application session, the outsider owner included) is ruling R-13 and
/// migration 170, pinned by `resolution_columns_change_only_through_the_definer`.
#[sqlx::test(migrations = "../../migrations")]
async fn only_a_writer_of_the_claims_group_sets_a_status_through_the_definer(pool: PgPool) {
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

/// CR01: a session with groups but NO principal sets no status. It has
/// nothing to name as the resolver, so the definer refuses before anything
/// else: the call is stamped with the claim owner's groups (readable and
/// writable, so CR02 and CR03 would both pass) and an empty principal, which
/// isolates the principal check. Nothing is written and no audit row exists.
#[sqlx::test(migrations = "../../migrations")]
async fn a_session_without_a_principal_sets_no_challenge_status(pool: PgPool) {
    let (owner, owner_group) = fixture::seed_agent_with_group(&pool, "ch-np-owner").await;
    let (outsider, _) = fixture::seed_agent_with_group(&pool, "ch-np-out").await;
    let claim = public_claim_owned_by(&pool, owner, owner_group, "no principal").await;
    assert_app_role_does_not_bypass(&pool).await;

    let p = pool.clone();
    let theirs = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, outsider).await;
        let t = challenge(&mut conn, claim, outsider, "no principal").await;
        (conn, t)
    })
    .await
    .expect("the outsider's challenge lands");
    let before = whole_row(&pool, theirs).await;

    let p = pool.clone();
    let refused = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, owner).await;
        sqlx::query("SELECT set_config('epigraph.principal_id', '', false)")
            .execute(&mut *conn)
            .await
            .expect("drop the principal, keep the owner's groups");
        let r =
            ChallengeRepository::resolve_as_claim_owner(&mut *conn, theirs, "accepted", None).await;
        (conn, r)
    })
    .await;
    let e = refused.expect_err("a principal-less session sets no status");
    assert_eq!(sqlstate(&e).as_deref(), Some("42501"), "{e}");
    assert!(
        e.to_string().contains("CR01"),
        "refused for the missing principal, not by another check: {e}"
    );
    assert_eq!(
        whole_row(&pool, theirs).await,
        before,
        "the row is byte-identical"
    );
    assert!(
        resolution_audit(&pool, theirs).await.is_empty(),
        "a refusal writes no audit record"
    );

    let p = pool.clone();
    let then_owner = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, owner).await;
        let o =
            ChallengeRepository::resolve_as_claim_owner(&mut *conn, theirs, "accepted", None).await;
        (conn, o)
    })
    .await;
    then_owner.expect("CALIBRATION: the same groups WITH the principal set the status");
    assert_eq!(resolution(&pool, theirs).await.1, Some(owner));
}

// =========================================================================
// RULING R-13 (migration 170): the resolution columns change only through
// `epigraph_resolve_challenge`; an application session may only WITHDRAW.
// =========================================================================

/// The text every R-13 refusal carries (migration 170's guard).
const CR07: &str = "CR07";

/// R-13's main arm. Since migration 168 the OUTSIDER owns its challenge row,
/// so 077 let it plain-UPDATE that row's own resolution columns, including
/// `resolved_by`: it could name ANY agent as the resolver readers are shown,
/// or file a challenge born `accepted` with a forged resolver. And a writer of
/// the claim's group could do the same, unaudited, on an insider's row. Now,
/// for every application session (the non-bypassing `epigraph_app`, stamped
/// as a request is):
///
/// * the outsider's plain UPDATE of `resolved_by`, of `state` to a resolution
///   (`under_review`, `accepted`) or of `resolution_details` is refused
///   (42501, CR07), and so is an INSERT born with a resolution;
/// * the claim's owner's plain UPDATE of an INSIDER's row (which 077 admits:
///   the row is the claim group's) is refused the same way: the definer is
///   the one path, for both shapes of row;
/// * the definer still lands, stamping the real caller, and (ruling R-14) the
///   owner may re-resolve a settled challenge, each change audited;
/// * the outsider may still WITHDRAW its own unresolved challenge, and only
///   that: `state = 'withdrawn'` with the other three columns untouched, which
///   is the one change the ruling leaves it. A SETTLED challenge (`accepted` /
///   `rejected`) is not withdrawn: the definer refuses to resolve a withdrawn
///   row (CR06), so a withdrawal after the verdict would bury the claim
///   owner's verdict where nobody can restate it.
///
/// Every refused statement leaves the row byte-identical.
#[sqlx::test(migrations = "../../migrations")]
async fn resolution_columns_change_only_through_the_definer(pool: PgPool) {
    let (owner, owner_group) = fixture::seed_agent_with_group(&pool, "ch-r13-owner").await;
    let (outsider, outsider_group) = fixture::seed_agent_with_group(&pool, "ch-r13-out").await;
    let (forged, _) = fixture::seed_agent_with_group(&pool, "ch-r13-forged").await;
    let claim = public_claim_owned_by(&pool, owner, owner_group, "r13").await;
    assert_app_role_does_not_bypass(&pool).await;

    let p = pool.clone();
    let (theirs, later_withdrawn) =
        fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
            stamp(&mut conn, &p, outsider).await;
            let t = challenge(&mut conn, claim, outsider, "r13 outsider")
                .await
                .expect("the outsider's challenge lands");
            let w = challenge(&mut conn, claim, outsider, "r13 outsider, withdrawn later")
                .await
                .expect("the outsider's second challenge lands");
            (conn, (t, w))
        })
        .await;
    let p = pool.clone();
    let insiders = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, owner).await;
        let i = challenge(&mut conn, claim, owner, "r13 insider").await;
        (conn, i)
    })
    .await
    .expect("the insider's challenge lands");
    assert_eq!(
        tenancy(&pool, theirs).await,
        (outsider_group, "public".to_string(), true),
        "CALIBRATION: the outsider owns its row, so 077 admits its UPDATEs of it"
    );
    assert_eq!(
        tenancy(&pool, insiders).await,
        (owner_group, "public".to_string(), false),
        "CALIBRATION: the insider's row is the claim group's, so 077 admits the owner's UPDATEs"
    );
    let theirs_before = whole_row(&pool, theirs).await;
    let insiders_before = whole_row(&pool, insiders).await;

    // The outsider, on its own row, and an INSERT born resolved.
    let p = pool.clone();
    let outsider_writes = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, outsider).await;
        let mut out = Vec::new();
        for (what, sql) in [
            (
                "forge resolved_by",
                "UPDATE challenges SET resolved_by = $2 WHERE id = $1",
            ),
            (
                "self-accept with a forged resolver",
                "UPDATE challenges SET state = 'accepted', resolved_by = $2, \
                 resolved_at = now(), resolution_details = '{\"by\": \"forged\"}' WHERE id = $1",
            ),
            (
                "set under_review",
                "UPDATE challenges SET state = 'under_review' WHERE id = $1 AND $2::uuid IS NOT NULL",
            ),
            (
                "write resolution_details",
                "UPDATE challenges SET resolution_details = '{}' WHERE id = $1 AND $2::uuid IS NOT NULL",
            ),
        ] {
            let r = sqlx::query(sql)
                .bind(theirs)
                .bind(forged)
                .execute(&mut *conn)
                .await;
            out.push((what, r.map(|d| d.rows_affected())));
        }
        let born = sqlx::query(
            "INSERT INTO challenges (claim_id, challenger_id, challenge_type, explanation, \
                                     state, resolved_by, resolved_at) \
             VALUES ($1, $2, 'factual_error', 'born accepted', 'accepted', $3, now())",
        )
        .bind(claim)
        .bind(outsider)
        .bind(forged)
        .execute(&mut *conn)
        .await;
        out.push(("INSERT born accepted", born.map(|d| d.rows_affected())));
        (conn, out)
    })
    .await;

    // The claim's owner, by plain SQL on the insider's row.
    let p = pool.clone();
    let owner_plain = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, owner).await;
        let r = sqlx::query(
            "UPDATE challenges SET state = 'accepted', resolved_by = $2, resolved_at = now() \
              WHERE id = $1",
        )
        .bind(insiders)
        .bind(forged)
        .execute(&mut *conn)
        .await;
        (conn, r.map(|d| d.rows_affected()))
    })
    .await;

    for (what, r) in outsider_writes.iter().chain(std::iter::once(&(
        "owner's plain UPDATE of an insider's row",
        owner_plain,
    ))) {
        let e = r
            .as_ref()
            .expect_err(&format!("{what}: refused (R-13), not landed"));
        assert_eq!(sqlstate(e).as_deref(), Some("42501"), "{what}: {e}");
        assert!(
            format!("{e:?}").contains(CR07),
            "{what}: refused by migration 170's resolution guard, not another check: {e:?}"
        );
    }
    assert_eq!(
        whole_row(&pool, theirs).await,
        theirs_before,
        "the outsider's row is untouched"
    );
    assert_eq!(
        whole_row(&pool, insiders).await,
        insiders_before,
        "the insider's row is untouched"
    );
    let born: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM challenges WHERE claim_id = $1 AND explanation = 'born accepted'",
    )
    .bind(claim)
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(born, 0, "no challenge is born resolved");

    // The definer still lands for both rows, stamping the real caller; R-14:
    // pending -> accepted directly, then a re-resolution, each audited.
    let p = pool.clone();
    let definer = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, owner).await;
        let a =
            ChallengeRepository::resolve_as_claim_owner(&mut *conn, theirs, "accepted", None).await;
        let b =
            ChallengeRepository::resolve_as_claim_owner(&mut *conn, theirs, "rejected", None).await;
        let c = ChallengeRepository::resolve_as_claim_owner(&mut *conn, insiders, "accepted", None)
            .await;
        (conn, (a, b, c))
    })
    .await;
    definer.0.expect("R-14: pending -> accepted directly");
    definer
        .1
        .expect("R-14: the owner re-resolves a settled challenge");
    definer
        .2
        .expect("the insider's row resolves through the definer too");
    assert_eq!(
        resolution(&pool, theirs).await,
        ("rejected".to_string(), Some(owner), true, None)
    );
    assert_eq!(
        resolution(&pool, insiders).await.1,
        Some(owner),
        "the real caller"
    );
    let audit = resolution_audit(&pool, theirs).await;
    assert_eq!(
        audit
            .iter()
            .map(|(_, d)| d["state_after"].clone())
            .collect::<Vec<_>>(),
        vec![serde_json::json!("accepted"), serde_json::json!("rejected")],
        "every resolution of the outsider's row is audited: {audit:?}"
    );

    // The one change left to the outsider: withdrawing an UNRESOLVED challenge.
    let p = pool.clone();
    let (withdrew, settled) = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, outsider).await;
        let w = sqlx::query("UPDATE challenges SET state = 'withdrawn' WHERE id = $1")
            .bind(later_withdrawn)
            .execute(&mut *conn)
            .await;
        let s = sqlx::query("UPDATE challenges SET state = 'withdrawn' WHERE id = $1")
            .bind(theirs)
            .execute(&mut *conn)
            .await;
        (conn, (w, s))
    })
    .await;
    assert_eq!(
        withdrew
            .expect("the outsider withdraws its own pending challenge")
            .rows_affected(),
        1
    );
    assert_eq!(
        resolution(&pool, later_withdrawn).await,
        ("withdrawn".to_string(), None, false, None),
        "a withdrawal changes the state and nothing else"
    );
    let settled = settled.expect_err("a settled challenge is not withdrawn");
    assert_eq!(sqlstate(&settled).as_deref(), Some("42501"), "{settled}");
    assert!(format!("{settled:?}").contains(CR07), "{settled:?}");
    assert_eq!(
        resolution(&pool, theirs).await.0,
        "rejected",
        "the verdict stands"
    );
}

/// R-13's one exception is the CHALLENGER withdrawing ITS OWN challenge. An
/// insider's challenge is owned by the claim's group, so row security admits
/// every writer of that group to UPDATE it; without the challenger check the
/// claim's owner could plain-UPDATE a colleague's challenge to `withdrawn`,
/// unaudited, and 168's CR06 would then refuse every resolution of it. Here a
/// second writer of the owner's group files a challenge; the owner's
/// withdrawal of it is refused (CR07) and the row is untouched, and the
/// colleague's own withdrawal lands (the calibration).
#[sqlx::test(migrations = "../../migrations")]
async fn only_the_challenger_withdraws_its_challenge(pool: PgPool) {
    let (owner, owner_group) = fixture::seed_agent_with_group(&pool, "ch-wd2-owner").await;
    let (colleague, _) = fixture::seed_agent_with_group(&pool, "ch-wd2-colleague").await;
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'writer')",
    )
    .bind(owner_group)
    .bind(colleague)
    .execute(&pool)
    .await
    .expect("writer membership");
    let claim = public_claim_owned_by(&pool, owner, owner_group, "withdraw own").await;
    assert_app_role_does_not_bypass(&pool).await;

    let p = pool.clone();
    let theirs = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, colleague).await;
        let t = challenge(&mut conn, claim, colleague, "a colleague's challenge").await;
        (conn, t)
    })
    .await
    .expect("the colleague's challenge lands");
    assert_eq!(
        tenancy(&pool, theirs).await,
        (owner_group, "public".to_string(), false),
        "CALIBRATION: an insider's row is the claim group's, so row security admits the owner"
    );
    let before = whole_row(&pool, theirs).await;

    let p = pool.clone();
    let by_owner = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, owner).await;
        let r = sqlx::query("UPDATE challenges SET state = 'withdrawn' WHERE id = $1")
            .bind(theirs)
            .execute(&mut *conn)
            .await;
        (conn, r.map(|d| d.rows_affected()))
    })
    .await;
    let e = by_owner.expect_err("the claim's owner does not withdraw a colleague's challenge");
    assert_eq!(sqlstate(&e).as_deref(), Some("42501"), "{e}");
    assert!(
        format!("{e:?}").contains(CR07),
        "refused by the guard: {e:?}"
    );
    assert_eq!(
        whole_row(&pool, theirs).await,
        before,
        "the row is untouched"
    );

    let p = pool.clone();
    let by_challenger = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, colleague).await;
        let r = sqlx::query("UPDATE challenges SET state = 'withdrawn' WHERE id = $1")
            .bind(theirs)
            .execute(&mut *conn)
            .await;
        (conn, r.map(|d| d.rows_affected()))
    })
    .await;
    assert_eq!(
        by_challenger.expect("the challenger withdraws its own challenge"),
        1
    );
    assert_eq!(resolution(&pool, theirs).await.0, "withdrawn");
}

// =========================================================================
// Migration 170, DELETE: no application session deletes a challenge.
// =========================================================================

/// The text the DELETE refusal carries (migration 170's guard).
const CR09: &str = "CR09";

/// Make `agent` a writer member of `group`.
async fn add_writer(pool: &PgPool, group: Uuid, agent: Uuid) {
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'writer')",
    )
    .bind(group)
    .bind(agent)
    .execute(pool)
    .await
    .expect("writer membership");
}

/// No application session deletes a challenge. 115's restrictive DELETE
/// policy admits every writer of the row's owning group, and since 168 the
/// OUTSIDER owns its challenge row, so without a DELETE rule the outsider
/// could remove its own challenge after the claim's owner ruled on it (which
/// goes around R-13: withdrawal is the challenger's one way to retract), and a
/// writer of the claim's group could remove a colleague's insider challenge;
/// neither is audited. No binary path deletes a challenge on an application
/// session: the seal ceremony deletes an insider's challenge on a maintenance
/// connection, and `challenges.claim_id`'s foreign key has no `ON DELETE`
/// action, so there is no cascade to keep working.
///
/// Every arm runs as the non-bypassing `epigraph_app`, stamped as a request
/// is, and is refused with CR09 (42501); every row survives byte-identical:
/// * the outsider deletes its own SETTLED (rejected) challenge;
/// * the outsider deletes its own PENDING challenge;
/// * the claim's owner deletes a colleague's insider challenge;
/// * the colleague deletes its own insider challenge.
///
/// Calibrations: each deleter READS the row on the same stamped session (so a
/// refusal is the guard, not row security filtering the row out), and the
/// privileged harness connection still deletes.
#[sqlx::test(migrations = "../../migrations")]
async fn no_application_session_deletes_a_challenge(pool: PgPool) {
    let (owner, owner_group) = fixture::seed_agent_with_group(&pool, "ch-del-owner").await;
    let (outsider, outsider_group) = fixture::seed_agent_with_group(&pool, "ch-del-out").await;
    let (colleague, _) = fixture::seed_agent_with_group(&pool, "ch-del-colleague").await;
    add_writer(&pool, owner_group, colleague).await;
    let claim = public_claim_owned_by(&pool, owner, owner_group, "delete").await;
    assert_app_role_does_not_bypass(&pool).await;

    let p = pool.clone();
    let (settled, pending) = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, outsider).await;
        let s = challenge(&mut conn, claim, outsider, "delete: settled later")
            .await
            .expect("the outsider's first challenge lands");
        let q = challenge(&mut conn, claim, outsider, "delete: stays pending")
            .await
            .expect("the outsider's second challenge lands");
        (conn, (s, q))
    })
    .await;
    let p = pool.clone();
    let insiders = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, colleague).await;
        let i = challenge(&mut conn, claim, colleague, "delete: a colleague's").await;
        (conn, i)
    })
    .await
    .expect("the colleague's insider challenge lands");
    let p = pool.clone();
    fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, owner).await;
        let r = ChallengeRepository::resolve_as_claim_owner(&mut *conn, settled, "rejected", None)
            .await;
        (conn, r)
    })
    .await
    .expect("the claim's owner rules on the outsider's challenge");
    assert_eq!(
        resolution(&pool, settled).await.0,
        "rejected",
        "CALIBRATION: the first challenge is settled"
    );
    assert_eq!(
        tenancy(&pool, settled).await,
        (outsider_group, "public".to_string(), true),
        "CALIBRATION: the outsider owns its rows, so 115 admits its DELETEs of them"
    );
    assert_eq!(
        tenancy(&pool, insiders).await,
        (owner_group, "public".to_string(), false),
        "CALIBRATION: the insider's row is the claim group's, so 115 admits the owner's DELETE"
    );
    let mut before = Vec::new();
    for id in [settled, pending, insiders] {
        before.push((id, whole_row(&pool, id).await));
    }

    for (agent, id, what) in [
        (
            outsider,
            settled,
            "the outsider deletes its own settled challenge",
        ),
        (
            outsider,
            pending,
            "the outsider deletes its own pending challenge",
        ),
        (
            owner,
            insiders,
            "the claim's owner deletes a colleague's insider challenge",
        ),
        (
            colleague,
            insiders,
            "the challenger deletes its own insider challenge",
        ),
    ] {
        let p = pool.clone();
        let (visible, deleted) = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
            stamp(&mut conn, &p, agent).await;
            let visible: i64 = sqlx::query_scalar("SELECT count(*) FROM challenges WHERE id = $1")
                .bind(id)
                .fetch_one(&mut *conn)
                .await
                .expect("read the challenge as the app role");
            let deleted = sqlx::query("DELETE FROM challenges WHERE id = $1")
                .bind(id)
                .execute(&mut *conn)
                .await
                .map(|d| d.rows_affected());
            (conn, (visible, deleted))
        })
        .await;
        assert_eq!(
            visible, 1,
            "CALIBRATION ({what}): the deleter reads the row, so row security does not hide it"
        );
        let e = deleted.expect_err(&format!("{what}: refused, not deleted"));
        assert_eq!(sqlstate(&e).as_deref(), Some("42501"), "{what}: {e}");
        assert!(
            format!("{e:?}").contains(CR09),
            "{what}: refused by migration 170's delete guard, not another check: {e:?}"
        );
    }
    for (id, row) in before {
        assert_eq!(
            whole_row(&pool, id).await,
            row,
            "challenge {id} survives byte-identical"
        );
    }

    // CALIBRATION: a privileged connection (the harness superuser; the seal
    // ceremony's maintenance connection is privileged the same way) deletes.
    let n = sqlx::query("DELETE FROM challenges WHERE id = $1")
        .bind(pending)
        .execute(&pool)
        .await
        .expect("a privileged delete of a challenge")
        .rows_affected();
    assert_eq!(n, 1, "the privileged connection deletes the row");
}

// =========================================================================
// Migration 170, challenger_id: fixed at filing, and it is the filer.
// =========================================================================

/// The text the challenger refusal carries (migration 170's guard).
const CR08: &str = "CR08";

/// `challenger_id` is set once, when the challenge is filed, and it names the
/// filer. R-13's one exception (the challenger withdraws its own challenge)
/// keys on `challenger_id = epigraph_principal_id()`, and readers are shown
/// `challenger_id` as who filed the challenge, so for every application
/// session (the non-bypassing `epigraph_app`, stamped as a request is):
///
/// * an UPDATE that CHANGES `challenger_id` is refused (CR08, 42501), by the
///   claim's owner on a colleague's insider row (row security admits the
///   owner's UPDATEs of it) and by the outsider on its own row; each row is
///   byte-identical, and the owner's withdrawal of the colleague's challenge
///   that follows is still refused (CR07), so the row stays `pending`;
/// * an INSERT whose `challenger_id` is not the session principal (another
///   agent, or NULL) is refused (CR08), and nothing is written.
///
/// Calibrations: the filer's own INSERT lands; an UPDATE that names
/// `challenger_id` without changing it lands (the rule is about a change, not
/// about the column being mentioned); and the privileged harness connection
/// still re-attributes a row.
#[sqlx::test(migrations = "../../migrations")]
async fn challenger_id_is_fixed_at_filing_and_names_the_filer(pool: PgPool) {
    let (owner, owner_group) = fixture::seed_agent_with_group(&pool, "ch-cid-owner").await;
    let (outsider, _) = fixture::seed_agent_with_group(&pool, "ch-cid-out").await;
    let (colleague, _) = fixture::seed_agent_with_group(&pool, "ch-cid-colleague").await;
    let (forged, _) = fixture::seed_agent_with_group(&pool, "ch-cid-forged").await;
    add_writer(&pool, owner_group, colleague).await;
    let claim = public_claim_owned_by(&pool, owner, owner_group, "challenger id").await;
    assert_app_role_does_not_bypass(&pool).await;

    let p = pool.clone();
    let theirs = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, outsider).await;
        let t = challenge(&mut conn, claim, outsider, "challenger id: the outsider's").await;
        (conn, t)
    })
    .await
    .expect("CALIBRATION: the outsider files as itself");
    let p = pool.clone();
    let insiders = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, colleague).await;
        let i = challenge(&mut conn, claim, colleague, "challenger id: a colleague's").await;
        (conn, i)
    })
    .await
    .expect("CALIBRATION: the colleague files as itself");
    let theirs_before = whole_row(&pool, theirs).await;
    let insiders_before = whole_row(&pool, insiders).await;

    // The claim's owner makes itself the challenger of a colleague's row, then
    // withdraws it: two statements, the first must already be refused.
    let p = pool.clone();
    let (relabel, withdraw) = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, owner).await;
        let r = sqlx::query("UPDATE challenges SET challenger_id = $2 WHERE id = $1")
            .bind(insiders)
            .bind(owner)
            .execute(&mut *conn)
            .await
            .map(|d| d.rows_affected());
        let w = sqlx::query("UPDATE challenges SET state = 'withdrawn' WHERE id = $1")
            .bind(insiders)
            .execute(&mut *conn)
            .await
            .map(|d| d.rows_affected());
        (conn, (r, w))
    })
    .await;
    let e = relabel.expect_err("the owner cannot make itself the challenger of a colleague's row");
    assert_eq!(sqlstate(&e).as_deref(), Some("42501"), "{e}");
    assert!(
        format!("{e:?}").contains(CR08),
        "refused by migration 170's challenger guard: {e:?}"
    );
    let e = withdraw.expect_err("the owner's withdrawal of a colleague's challenge stays refused");
    assert!(format!("{e:?}").contains(CR07), "{e:?}");
    assert_eq!(
        whole_row(&pool, insiders).await,
        insiders_before,
        "the colleague's row is untouched and still pending"
    );
    assert_eq!(resolution(&pool, insiders).await.0, "pending");

    // The outsider re-attributes its own row, and files in another's name.
    let p = pool.clone();
    let (own_relabel, as_other, as_nobody, same_value) =
        fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
            stamp(&mut conn, &p, outsider).await;
            let r = sqlx::query("UPDATE challenges SET challenger_id = $2 WHERE id = $1")
                .bind(theirs)
                .bind(forged)
                .execute(&mut *conn)
                .await
                .map(|d| d.rows_affected());
            let insert = "INSERT INTO challenges (claim_id, challenger_id, challenge_type, \
                                                  explanation) \
                          VALUES ($1, $2, 'factual_error', 'challenger id: filed for another')";
            let o = sqlx::query(insert)
                .bind(claim)
                .bind(Some(forged))
                .execute(&mut *conn)
                .await
                .map(|d| d.rows_affected());
            let n = sqlx::query(insert)
                .bind(claim)
                .bind(None::<Uuid>)
                .execute(&mut *conn)
                .await
                .map(|d| d.rows_affected());
            let s = sqlx::query(
                "UPDATE challenges SET challenger_id = challenger_id, explanation = explanation \
                  WHERE id = $1",
            )
            .bind(theirs)
            .execute(&mut *conn)
            .await
            .map(|d| d.rows_affected());
            (conn, (r, o, n, s))
        })
        .await;
    for (what, r) in [
        ("the outsider re-attributes its own challenge", own_relabel),
        ("an INSERT naming another agent as the challenger", as_other),
        ("an INSERT naming no challenger", as_nobody),
    ] {
        let e = r.expect_err(&format!("{what}: refused, not landed"));
        assert_eq!(sqlstate(&e).as_deref(), Some("42501"), "{what}: {e}");
        assert!(
            format!("{e:?}").contains(CR08),
            "{what}: refused by migration 170's challenger guard: {e:?}"
        );
    }
    assert_eq!(
        same_value.expect("CALIBRATION: naming challenger_id without changing it lands"),
        1
    );
    assert_eq!(
        whole_row(&pool, theirs).await,
        theirs_before,
        "the outsider's row is untouched"
    );
    let filed_for_another: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM challenges \
          WHERE claim_id = $1 AND explanation = 'challenger id: filed for another'",
    )
    .bind(claim)
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(filed_for_another, 0, "nothing is filed in another's name");

    // CALIBRATION: a privileged connection re-attributes (an operator repair).
    let n = sqlx::query("UPDATE challenges SET challenger_id = $2 WHERE id = $1")
        .bind(theirs)
        .bind(forged)
        .execute(&pool)
        .await
        .expect("a privileged re-attribution")
        .rows_affected();
    assert_eq!(n, 1);
}
