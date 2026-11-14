//! Migration 218 (backlog 73ea4d4d, 77fbf3f9): a harvester fragment cited by
//! several claims takes the MOST RESTRICTIVE of them, and the application role
//! may not UPDATE `harvester_claim_provenance`.
//!
//! # The defect
//!
//! A fragment reaches its claims only through `harvester_claim_provenance`, and
//! one fragment may be cited by several claims. Before 218:
//!
//! * the provenance trigger (089/115) stamped a sentinel-owned fragment with
//!   `UPDATE … FROM newprov JOIN claims`, which applies ONE of the joined rows,
//!   chosen by plan order, when several provenance rows for one fragment arrive
//!   in one statement;
//! * arm (d) (168) copied a changed claim's tuple onto every fragment it cites,
//!   whatever the other citers are: publicizing one citer made a fragment
//!   public while another citer was group-private.
//!
//! # Why the trigger tests use two fragments in opposite row orders
//!
//! Which joined row an `UPDATE … FROM` applies is decided by the plan, so a
//! single fragment can land on the right citer by luck. Two fragments whose
//! citers are inserted in OPPOSITE orders, in one statement, cannot both land on
//! the same citer under any fixed scan order; the winner rule must put both on
//! it.
//!
//! # Who is a candidate
//!
//! Only a claim the firing act names: the provenance stamp ranks the rows of
//! the statement that fired, and arm (d) ranks the claims its statement
//! changed. A link an application session wrote earlier (115 section 9 stamps
//! nothing from it) never decides a fragment, and arm (d) never moves a
//! fragment to a claim it did not change. The two `…never…` tests below pin
//! that, from a real `epigraph_app` session.
//!
//! # Verified to fail
//!
//! * Migration 218 replaced by a no-op (115's and 168's bodies): every test
//!   fails on its own assertion except
//!   `an_earlier_unstamped_link_never_decides_a_later_stamp` (115's property,
//!   which 218 must keep) and
//!   `moving_one_group_citer_to_another_group_still_carries_the_fragment` (a
//!   pin of 168's behaviour that 218 must keep).
//! * The first draft of 218 (every provenance row ranked, arm (d) ranking
//!   every citer of the fragment): exactly
//!   `an_earlier_unstamped_link_never_decides_a_later_stamp` and
//!   `publicizing_a_citer_never_hands_its_fragment_to_another_citers_group`
//!   fail, on their tenancy assertions.
//! * Arm (d)'s keep-a-group-fragment guard disabled: exactly
//!   `publicizing_one_citer_leaves_a_fragment_another_citer_keeps_private`,
//!   `a_fragment_no_changed_claim_decides_stays_with_its_current_group` and
//!   `publicizing_a_citer_never_hands_its_fragment_to_another_citers_group`
//!   fail.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::visibility::Viewer;
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

/// Migration 074's seed group.
const SEED: Uuid = Uuid::from_u128(0xdead);

async fn tenancy_of(pool: &PgPool, fragment: Uuid) -> (Uuid, String) {
    sqlx::query_as("SELECT owner_group_id, visibility::text FROM harvester_fragments WHERE id = $1")
        .bind(fragment)
        .fetch_one(pool)
        .await
        .expect("read fragment tenancy")
}

/// A claim with the given tenancy, written directly (the harness is a
/// superuser, so 074's checks see a declared row).
async fn claim(pool: &PgPool, agent: Uuid, visibility: &str, owner: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, $2, sha256(convert_to($2, 'UTF8')), 0.8, $3, true, $4, $5)",
    )
    .bind(id)
    .bind(format!("claim {id}"))
    .bind(agent)
    .bind(visibility)
    .bind(owner)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}

/// A fragment of its own source, declaring `(visibility, owner)`.
async fn fragment(pool: &PgPool, visibility: &str, owner: Uuid) -> Uuid {
    sqlx::query_scalar(
        "WITH s AS (INSERT INTO harvester_sources (content_hash, modality, visibility, \
                                                   owner_group_id) \
                    VALUES (sha256(convert_to(gen_random_uuid()::text, 'UTF8')), 'text', \
                            'public', $2) \
                    RETURNING id) \
         INSERT INTO harvester_fragments (source_id, content_hash, content_text, \
                                          visibility, owner_group_id) \
         SELECT s.id, sha256(convert_to(gen_random_uuid()::text, 'UTF8')), 'chunk', $1, $2 \
           FROM s RETURNING id",
    )
    .bind(visibility)
    .bind(owner)
    .fetch_one(pool)
    .await
    .expect("seed fragment")
}

/// ONE INSERT statement of provenance rows, in the order given. The rows'
/// own tenancy is left to arm (c).
async fn link_in_one_statement(pool: &PgPool, rows: &[(Uuid, Uuid)]) {
    let claims: Vec<Uuid> = rows.iter().map(|r| r.0).collect();
    let frags: Vec<Uuid> = rows.iter().map(|r| r.1).collect();
    sqlx::query(
        "INSERT INTO harvester_claim_provenance (claim_id, fragment_id) \
         SELECT c, f FROM unnest($1::uuid[], $2::uuid[]) WITH ORDINALITY AS u(c, f, o) \
          ORDER BY o",
    )
    .bind(&claims)
    .bind(&frags)
    .execute(pool)
    .await
    .expect("link fragments to claims");
}

/// Two fresh groups, `(lower, higher)` by uuid order.
async fn two_groups(pool: &PgPool) -> ((Uuid, Uuid), (Uuid, Uuid)) {
    let a = fixture::seed_agent_with_group(pool, "frag-a").await;
    let b = fixture::seed_agent_with_group(pool, "frag-b").await;
    if a.1 < b.1 {
        (a, b)
    } else {
        (b, a)
    }
}

/// The provenance trigger: a world-owned fragment cited in one statement by a
/// public claim and a group-private claim is the private claim's, whichever
/// row comes first; and of two group-private citers, the lower owner id wins,
/// whichever row comes first.
#[sqlx::test(migrations = "../../migrations")]
async fn the_provenance_stamp_takes_the_most_restrictive_citer_whatever_the_row_order(
    pool: PgPool,
) {
    let world = fixture::world_group(&pool).await;
    let ((agent_lo, lo), (agent_hi, hi)) = two_groups(&pool).await;
    let public_lo = claim(&pool, agent_lo, "public", lo).await;
    let private_hi = claim(&pool, agent_hi, "group", hi).await;
    let private_lo = claim(&pool, agent_lo, "group", lo).await;

    let pub_first = fragment(&pool, "public", world).await;
    let priv_first = fragment(&pool, "public", world).await;
    let lo_first = fragment(&pool, "public", world).await;
    let hi_first = fragment(&pool, "public", world).await;
    link_in_one_statement(
        &pool,
        &[
            (public_lo, pub_first),
            (private_hi, pub_first),
            (private_hi, priv_first),
            (public_lo, priv_first),
            (private_lo, lo_first),
            (private_hi, lo_first),
            (private_hi, hi_first),
            (private_lo, hi_first),
        ],
    )
    .await;

    for (f, what) in [
        (pub_first, "public citer first"),
        (priv_first, "private citer first"),
    ] {
        assert_eq!(
            tenancy_of(&pool, f).await,
            (hi, "group".to_string()),
            "{what}: a fragment cited by a public claim and a group-private claim must be the \
             private claim's (most restrictive wins), not whichever row the plan applied"
        );
    }
    for (f, what) in [
        (lo_first, "lower group first"),
        (hi_first, "higher group first"),
    ] {
        assert_eq!(
            tenancy_of(&pool, f).await,
            (lo, "group".to_string()),
            "{what}: of two group-private citers the lower owner id wins, so the result does \
             not depend on row order"
        );
    }
}

/// The provenance trigger: at equal visibility a real owner beats the seed
/// sentinel, which owns nothing, whichever row comes first.
#[sqlx::test(migrations = "../../migrations")]
async fn the_provenance_stamp_puts_a_real_owner_before_the_seed_sentinel(pool: PgPool) {
    let world = fixture::world_group(&pool).await;
    let (agent, group) = fixture::seed_agent_with_group(&pool, "frag-real").await;
    let real = claim(&pool, agent, "public", group).await;
    let seeded = claim(&pool, agent, "public", SEED).await;
    assert!(
        SEED < group,
        "CALIBRATION: the seed id sorts first, so only the seed-last key can put the real \
         owner first"
    );

    let real_first = fragment(&pool, "public", world).await;
    let seed_first = fragment(&pool, "public", world).await;
    link_in_one_statement(
        &pool,
        &[
            (real, real_first),
            (seeded, real_first),
            (seeded, seed_first),
            (real, seed_first),
        ],
    )
    .await;
    for f in [real_first, seed_first] {
        assert_eq!(
            tenancy_of(&pool, f).await,
            (group, "public".to_string()),
            "a public claim of a real group must win over a public seed-owned claim"
        );
    }
}

/// Arm (d): publicizing one citer of a fragment another citer keeps
/// group-private leaves the fragment group-private; publicizing the other too
/// then makes it public (the fragment still follows its claims).
#[sqlx::test(migrations = "../../migrations")]
async fn publicizing_one_citer_leaves_a_fragment_another_citer_keeps_private(pool: PgPool) {
    let (agent, group) = fixture::seed_agent_with_group(&pool, "frag-pub").await;
    let a = claim(&pool, agent, "group", group).await;
    let b = claim(&pool, agent, "group", group).await;
    let shared = fragment(&pool, "group", group).await;
    link_in_one_statement(&pool, &[(a, shared), (b, shared)]).await;
    assert_eq!(
        tenancy_of(&pool, shared).await,
        (group, "group".to_string()),
        "CALIBRATION: the shared fragment starts group-private"
    );

    let publicize = |id: Uuid| {
        let pool = pool.clone();
        async move {
            let mut tx = pool.begin().await.expect("begin");
            sqlx::query("SELECT set_config('epigraph.allow_declassify', 'yes', true)")
                .execute(&mut *tx)
                .await
                .expect("allow the declassification");
            sqlx::query("UPDATE claims SET visibility = 'public' WHERE id = $1")
                .bind(id)
                .execute(&mut *tx)
                .await
                .expect("publicize");
            tx.commit().await.expect("commit");
        }
    };

    publicize(a).await;
    assert_eq!(
        tenancy_of(&pool, shared).await,
        (group, "group".to_string()),
        "claim B still cites the fragment and is group-private: publicizing claim A must not \
         make B's source text public"
    );
    publicize(b).await;
    assert_eq!(
        tenancy_of(&pool, shared).await,
        (group, "public".to_string()),
        "with every citer public the fragment follows them to public"
    );
}

/// Arm (d): when the changed claim goes public and two group-private citers of
/// different groups remain, the fragment stays exactly where it is (owner and
/// visibility): it is neither made public nor moved to the lower group id.
#[sqlx::test(migrations = "../../migrations")]
async fn a_fragment_no_changed_claim_decides_stays_with_its_current_group(pool: PgPool) {
    let ((agent_lo, lo), (agent_hi, hi)) = two_groups(&pool).await;
    let publicized = claim(&pool, agent_hi, "group", hi).await;
    let other_lo = claim(&pool, agent_lo, "group", lo).await;
    let other_hi = claim(&pool, agent_hi, "group", hi).await;
    let shared = fragment(&pool, "group", hi).await;
    link_in_one_statement(
        &pool,
        &[(publicized, shared), (other_lo, shared), (other_hi, shared)],
    )
    .await;

    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("SELECT set_config('epigraph.allow_declassify', 'yes', true)")
        .execute(&mut *tx)
        .await
        .expect("allow the declassification");
    sqlx::query("UPDATE claims SET visibility = 'public' WHERE id = $1")
        .bind(publicized)
        .execute(&mut *tx)
        .await
        .expect("publicize");
    tx.commit().await.expect("commit");

    assert_eq!(
        tenancy_of(&pool, shared).await,
        (hi, "group".to_string()),
        "two group-private citers remain: the fragment stays group-private and with the group \
         that already owns it (not moved to the lower group id, and not made public)"
    );
}

/// Arm (d), a PIN (it passes on 168 too): at equal visibility the changed
/// claim decides, so moving one group-private citer to another group still
/// carries the shared fragment with it, as `reown-claims`, `regroup-claims`
/// and `restrict-claims` model the cascade. The fragment's current owner is the
/// group the OTHER citer stays in, and the target is the LOWER id, so the
/// current-owner key alone would keep it: only the changed-claim key moves it.
/// A fragment the moved claim alone cites follows it too (control).
#[sqlx::test(migrations = "../../migrations")]
async fn moving_one_group_citer_to_another_group_still_carries_the_fragment(pool: PgPool) {
    let ((_, lo), (agent_hi, hi)) = two_groups(&pool).await;
    let moving = claim(&pool, agent_hi, "group", hi).await;
    let staying = claim(&pool, agent_hi, "group", hi).await;
    let shared = fragment(&pool, "group", hi).await;
    let own = fragment(&pool, "group", hi).await;
    link_in_one_statement(&pool, &[(moving, shared), (staying, shared), (moving, own)]).await;

    sqlx::query("UPDATE claims SET owner_group_id = $1 WHERE id = $2")
        .bind(lo)
        .bind(moving)
        .execute(&pool)
        .await
        .expect("move the claim to the other group");

    assert_eq!(
        tenancy_of(&pool, shared).await,
        (lo, "group".to_string()),
        "at equal visibility the moved claim decides: the shared fragment moves with it, as \
         migration 168 moved it"
    );
    assert_eq!(
        tenancy_of(&pool, own).await,
        (lo, "group".to_string()),
        "control: a fragment only the moved claim cites follows it"
    );
}

/// 77fbf3f9: the application role holds no UPDATE on the provenance table,
/// table-level or on any column, and an UPDATE that re-points a row is
/// refused with 42501. INSERT, SELECT and DELETE stay (calibration).
///
/// Never calls `fixture::grant_app_privileges`, which grants UPDATE on every
/// table and would re-grant exactly what 218 revokes.
#[sqlx::test(migrations = "../../migrations")]
async fn the_app_role_cannot_update_provenance(pool: PgPool) {
    let (update, any_column, insert, select, delete): (bool, bool, bool, bool, bool) =
        sqlx::query_as(
            "SELECT has_table_privilege('epigraph_app', 'public.harvester_claim_provenance', \
                                        'UPDATE'), \
                    has_any_column_privilege('epigraph_app', \
                                             'public.harvester_claim_provenance', 'UPDATE'), \
                    has_table_privilege('epigraph_app', 'public.harvester_claim_provenance', \
                                        'INSERT'), \
                    has_table_privilege('epigraph_app', 'public.harvester_claim_provenance', \
                                        'SELECT'), \
                    has_table_privilege('epigraph_app', 'public.harvester_claim_provenance', \
                                        'DELETE')",
        )
        .fetch_one(&pool)
        .await
        .expect("read the app role's privileges");
    assert!(
        insert && select && delete,
        "CALIBRATION: the harvest path's INSERT, the reads and 115's owner-scoped DELETE keep \
         their grants (insert={insert}, select={select}, delete={delete})"
    );
    assert!(
        !update && !any_column,
        "epigraph_app must hold no UPDATE on harvester_claim_provenance (table={update}, any \
         column={any_column}): a re-pointed fragment_id or claim_id runs no stamping trigger"
    );

    let (agent, group) = fixture::seed_agent_with_group(&pool, "frag-upd").await;
    let c = claim(&pool, agent, "group", group).await;
    let f = fragment(&pool, "group", group).await;
    let other = fragment(&pool, "group", group).await;
    link_in_one_statement(&pool, &[(c, f)]).await;

    let code = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        let r = sqlx::query(
            "UPDATE harvester_claim_provenance SET fragment_id = $1 \
              WHERE claim_id = $2 AND fragment_id = $3",
        )
        .bind(other)
        .bind(c)
        .bind(f)
        .execute(&mut *conn)
        .await;
        let code = r.err().and_then(|e| {
            e.as_database_error()
                .and_then(|d| d.code().map(|c| c.to_string()))
        });
        (conn, code)
    })
    .await;
    assert_eq!(
        code.as_deref(),
        Some("42501"),
        "the app role's UPDATE of a provenance row must be refused for want of the privilege"
    );
}

/// Stamp `conn` for `agent` exactly as `ScopedPool::begin_as` would (the
/// same helper as `owner_scoped_delete.rs`).
async fn stamp(conn: &mut PgConnection, pool: &PgPool, agent: Uuid) {
    let csv = |ids: &[Uuid]| {
        ids.iter()
            .map(Uuid::to_string)
            .collect::<Vec<_>>()
            .join(",")
    };
    let v = Viewer::resolve(pool, agent).await.expect("resolve viewer");
    let groups = csv(v.group_bind().expect("scoped viewer"));
    let writable = csv(v.writable_groups());
    assert!(
        !writable.is_empty(),
        "a writer with no writable group makes the app-session arms vacuous"
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

/// As `epigraph_app` stamped for `agent`: INSERT each `(claim, fragment)` link
/// (when `links` is non-empty), then DELETE `deletes`. Returns
/// `(links inserted, fragments deleted)`.
async fn as_app_session(
    pool: &PgPool,
    agent: Uuid,
    links: Vec<(Uuid, Uuid)>,
    deletes: Vec<Uuid>,
) -> (u64, u64) {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app's rolbypassrls");
    assert!(
        !bypassrls,
        "epigraph_app holds BYPASSRLS: the test is vacuous"
    );
    let p = pool.clone();
    fixture::as_role(pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, agent).await;
        let mut linked = 0;
        for (claim, frag) in links {
            linked += sqlx::query(
                "INSERT INTO harvester_claim_provenance (claim_id, fragment_id) VALUES ($1, $2)",
            )
            .bind(claim)
            .bind(frag)
            .execute(&mut *conn)
            .await
            .expect("the app session links a fragment to its own claim")
            .rows_affected();
        }
        let deleted = sqlx::query("DELETE FROM harvester_fragments WHERE id = ANY($1)")
            .bind(&deletes[..])
            .execute(&mut *conn)
            .await
            .expect("the app session's DELETE")
            .rows_affected();
        (conn, (linked, deleted))
    })
    .await
}

async fn provenance_rows(pool: &PgPool, claim: Uuid, fragment: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM harvester_claim_provenance WHERE claim_id = $1 AND fragment_id = $2",
    )
    .bind(claim)
    .bind(fragment)
    .fetch_one(pool)
    .await
    .expect("read provenance")
}

/// Review finding 1: the provenance stamp ranks only the rows of the statement
/// that fired. An application session T links its own group-private claim to
/// two sentinel-owned fragments; 115 section 9 stamps nothing from that. Later
/// the privileged harvester links one fragment to a seed-owned public claim and
/// the other to a world-owned public claim. Neither fragment becomes T's: the
/// first takes the seed claim's tuple (115's own result), the second stays
/// world-owned (115 ignores a world citer), T's DELETE removes nothing, and the
/// harvester's provenance rows survive. Ranking every provenance row of the
/// fragment would let T's earlier link win both.
#[sqlx::test(migrations = "../../migrations")]
async fn an_earlier_unstamped_link_never_decides_a_later_stamp(pool: PgPool) {
    let world = fixture::world_group(&pool).await;
    let (author, _) = fixture::seed_agent_with_group(&pool, "frag-author").await;
    let (t, t_group) = fixture::seed_agent_with_group(&pool, "frag-t").await;
    let t_private = claim(&pool, t, "group", t_group).await;
    let seed_public = claim(&pool, author, "public", SEED).await;
    let world_public = claim(&pool, author, "public", world).await;
    let via_seed = fragment(&pool, "public", world).await;
    let via_world = fragment(&pool, "public", world).await;

    let (linked, _) = as_app_session(
        &pool,
        t,
        vec![(t_private, via_seed), (t_private, via_world)],
        vec![],
    )
    .await;
    assert_eq!(linked, 2, "CALIBRATION: both app-session links landed");
    for f in [via_seed, via_world] {
        assert_eq!(
            tenancy_of(&pool, f).await,
            (world, "public".to_string()),
            "CALIBRATION: an application session's link stamps nothing (115 section 9)"
        );
    }

    link_in_one_statement(&pool, &[(seed_public, via_seed)]).await;
    link_in_one_statement(&pool, &[(world_public, via_world)]).await;
    assert_eq!(
        tenancy_of(&pool, via_seed).await,
        (SEED, "public".to_string()),
        "the privileged link names the seed-owned public claim, so the fragment takes ITS \
         tuple; the earlier unstamped link must not decide it"
    );
    assert_eq!(
        tenancy_of(&pool, via_world).await,
        (world, "public".to_string()),
        "the privileged link names a world-owned claim, which donates nothing; the earlier \
         unstamped link must not decide the fragment either"
    );

    let (_, deleted) = as_app_session(&pool, t, vec![], vec![via_seed, via_world]).await;
    assert_eq!(
        deleted, 0,
        "T owns neither fragment, so its DELETE removes none"
    );
    assert_eq!(provenance_rows(&pool, seed_public, via_seed).await, 1);
    assert_eq!(provenance_rows(&pool, world_public, via_world).await, 1);
}

/// Review finding 2: arm (d) never hands a fragment to a claim its statement
/// did not change. Author A's group-private claim gives the fragment A's group;
/// an application session T then links its own group-private claim to it; A's
/// claim is publicized. The fragment stays A's and group-private (T's citer is
/// still group-private, so it is not made public, and it does not move to T's
/// group); T's DELETE removes nothing and A's provenance row survives.
#[sqlx::test(migrations = "../../migrations")]
async fn publicizing_a_citer_never_hands_its_fragment_to_another_citers_group(pool: PgPool) {
    let world = fixture::world_group(&pool).await;
    let (a, a_group) = fixture::seed_agent_with_group(&pool, "frag-a-owner").await;
    let (t, t_group) = fixture::seed_agent_with_group(&pool, "frag-t-linker").await;
    let a_claim = claim(&pool, a, "group", a_group).await;
    let t_private = claim(&pool, t, "group", t_group).await;
    let shared = fragment(&pool, "public", world).await;
    link_in_one_statement(&pool, &[(a_claim, shared)]).await;
    assert_eq!(
        tenancy_of(&pool, shared).await,
        (a_group, "group".to_string()),
        "CALIBRATION: the harvester's link stamps the fragment with A's claim"
    );
    let (linked, _) = as_app_session(&pool, t, vec![(t_private, shared)], vec![]).await;
    assert_eq!(linked, 1, "CALIBRATION: T's link landed");

    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("SELECT set_config('epigraph.allow_declassify', 'yes', true)")
        .execute(&mut *tx)
        .await
        .expect("allow the declassification");
    sqlx::query("UPDATE claims SET visibility = 'public' WHERE id = $1")
        .bind(a_claim)
        .execute(&mut *tx)
        .await
        .expect("publicize A's claim");
    tx.commit().await.expect("commit");

    assert_eq!(
        tenancy_of(&pool, shared).await,
        (a_group, "group".to_string()),
        "publicizing A's claim must leave the fragment with A's group and group-private: \
         never moved to T's group (T's claim was not changed), never made public while T's \
         claim cites it"
    );
    let (_, deleted) = as_app_session(&pool, t, vec![], vec![shared]).await;
    assert_eq!(
        deleted, 0,
        "T does not own the fragment, so its DELETE removes nothing"
    );
    assert_eq!(
        provenance_rows(&pool, a_claim, shared).await,
        1,
        "A's provenance row survived"
    );
}

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

/// The embedded migrations with `version <= max`.
fn up_to(max: i64) -> sqlx::migrate::Migrator {
    sqlx::migrate::Migrator {
        migrations: std::borrow::Cow::Owned(
            MIGRATOR
                .migrations
                .iter()
                .filter(|m| m.version <= max)
                .cloned()
                .collect(),
        ),
        ignore_missing: false,
        locking: true,
        no_tx: false,
    }
}

/// Run `migrator` on one connection and reset it: 001's pg_dump header leaves
/// session-level SETs behind.
async fn migrate(pool: &PgPool, migrator: &sqlx::migrate::Migrator) {
    let mut conn = pool.acquire().await.expect("acquire");
    migrator.run(&mut *conn).await.expect("migrate");
    sqlx::query("RESET ALL")
        .execute(&mut *conn)
        .await
        .expect("RESET ALL");
}

/// Every function in `public` (whole definition, owner, ACL) plus the
/// provenance table's ACL: what 218 changes.
async fn catalog(pool: &PgPool) -> std::collections::BTreeSet<String> {
    let mut rows: Vec<String> = sqlx::query_scalar(
        "SELECT p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ') ' \
                || CASE WHEN p.prokind IN ('f', 'p') THEN md5(pg_get_functiondef(p.oid)) \
                        ELSE md5(p.prosrc) END \
                || ' ' || p.proowner::regrole::text || ' ' || COALESCE(p.proacl::text, '-') \
           FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace",
    )
    .fetch_all(pool)
    .await
    .expect("function catalog");
    let acl: String = sqlx::query_scalar(
        "SELECT 'harvester_claim_provenance(acl) ' \
                || COALESCE((SELECT string_agg(a::text, ',' ORDER BY a::text) \
                               FROM unnest(relacl) a), '-') \
           FROM pg_class WHERE oid = 'public.harvester_claim_provenance'::regclass",
    )
    .fetch_one(pool)
    .await
    .expect("table acl");
    rows.push(acl);
    rows.into_iter().collect()
}

/// `docs/runbooks/218-undo.sql` returns the functions and the provenance
/// table's ACL to their state below 218 (so it restates 115's and 168's
/// bodies byte for byte), and a second run changes nothing.
#[sqlx::test(migrations = false)]
async fn the_218_undo_returns_the_catalog_below_218(pool: PgPool) {
    migrate(&pool, &up_to(217)).await;
    let before = catalog(&pool).await;
    migrate(&pool, &up_to(218)).await;
    let through = catalog(&pool).await;
    let changed: std::collections::BTreeSet<String> = through
        .symmetric_difference(&before)
        .map(|e| e.split('(').next().unwrap_or_default().to_string())
        .collect();
    assert_eq!(
        changed,
        [
            "epigraph_inherit_fragment_tenancy_stmt",
            "epigraph_propagate_tenancy",
            "harvester_claim_provenance",
        ]
        .into_iter()
        .map(String::from)
        .collect(),
        "CALIBRATION: 218 re-states the two fragment-stamping bodies and revokes one table \
         privilege, nothing else"
    );

    let undo = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/runbooks/218-undo.sql"),
    )
    .expect("read the undo runbook");
    for run in ["first", "second"] {
        sqlx::raw_sql(&undo)
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("the {run} run of the undo applies: {e}"));
        let after = catalog(&pool).await;
        assert_eq!(
            after.symmetric_difference(&before).collect::<Vec<_>>(),
            Vec::<&String>::new(),
            "after the {run} run the catalog is exactly as below 218"
        );
    }
}
