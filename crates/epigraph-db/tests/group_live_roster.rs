//! Migration 273's `epigraph_group_live_roster(group)` (backlogs 93ed2ec3,
//! f712db53): the EXPLICIT members of one group whose row still counts,
//! answered only to a session that already reads that group's roster.
//!
//! Every gate arm is driven on the APPLICATION ROLE through the production
//! stamp (`Viewer::resolve`, then `ScopedPool::read_as` on a downgraded
//! `epigraph_app` pool). The harness superuser passes the gate through its
//! `rolsuper` arm, so a gate test on that pool would pass with no gate at all.
//!
//! The team every test uses (`team`) is a verb-made team group (164) with:
//!
//! * `owner`, its admin, a registered human (a plain direct member);
//! * `writer`, a registered human with a `writer` row;
//! * `lapsed`, a human with an unrevoked `writer` row whose registration has
//!   been revoked, so the row no longer counts (164);
//! * `derived`, a registered human with NO row, a member only through a live
//!   assignment of a role bound to the group (165).

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::{ScopedPool, SessionGucMode, Viewer};
use sqlx::PgPool;
use uuid::Uuid;

const ROLE: &str = "role:group-live-roster-test";

/// 236's `epigraph_live_memberships_unbound` body, whose direct arm 273
/// copies. Changing the twin without re-stating the roster fails here.
const TWIN_MD5: &str = "7648baee271b2163a52c28db1b4a74b6";

struct Team {
    group: Uuid,
    owner: Uuid,
    writer: Uuid,
    lapsed: Uuid,
    derived: Uuid,
}

async fn team(pool: &PgPool, name: &str) -> Team {
    let (owner, _) = fixture::seed_human_operator(pool, &format!("{name}-owner")).await;
    let (writer, _) = fixture::seed_human_operator(pool, &format!("{name}-writer")).await;
    let (lapsed, _) = fixture::seed_human_operator(pool, &format!("{name}-lapsed")).await;
    let (derived, _) = fixture::seed_human_operator(pool, &format!("{name}-derived")).await;
    let group = fixture::verb_team_group(pool, &format!("Synthetic {name} Team"), owner).await;
    fixture::verb_team_group_add(pool, group, writer, "writer").await;
    fixture::verb_team_group_add(pool, group, lapsed, "writer").await;
    fixture::bind_new_role_to_group(pool, ROLE, group, "writer", false).await;
    fixture::grant_role_now(pool, ROLE, derived).await;
    fixture::revoke_human_operator(pool, lapsed).await;
    assert!(
        fixture::has_unrevoked_row(pool, group, lapsed).await,
        "PREMISE: the lapsed row is still unrevoked"
    );
    assert!(
        !fixture::has_unrevoked_row(pool, group, derived).await,
        "PREMISE: the derived member holds no row"
    );
    Team {
        group,
        owner,
        writer,
        lapsed,
        derived,
    }
}

async fn app_scoped(pool: &PgPool) -> ScopedPool {
    ScopedPool::connect_downgraded_for_tests(
        &fixture::database_url_for(pool).await,
        SessionGucMode::Session,
        "epigraph_app",
    )
    .await
    .expect("app-role ScopedPool")
}

const ROSTER_SQL: &str =
    "SELECT agent_id, role FROM public.epigraph_group_live_roster($1) ORDER BY agent_id";

fn sorted(mut v: Vec<(Uuid, String)>) -> Vec<(Uuid, String)> {
    v.sort();
    v
}

/// The roster of `group` as `as_agent` reads it on the application role,
/// stamped from `as_agent`'s resolved viewer, plus (for the subset check) the
/// raw unrevoked rows the same connection's row security admits.
async fn read_as(
    pool: &PgPool,
    scoped: &ScopedPool,
    as_agent: Uuid,
    group: Uuid,
) -> (Vec<(Uuid, String)>, Vec<(Uuid, String)>) {
    let viewer = Viewer::resolve(pool, as_agent).await.expect("resolve");
    let mut read = scoped.read_as(&viewer).await.expect("read_as");
    let roster: Vec<(Uuid, String)> = sqlx::query_as(ROSTER_SQL)
        .bind(group)
        .fetch_all(&mut *read)
        .await
        .expect("the roster answers");
    let raw: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT agent_id, role::text FROM group_memberships \
          WHERE group_id = $1 AND revoked_at IS NULL ORDER BY agent_id",
    )
    .bind(group)
    .fetch_all(&mut *read)
    .await
    .expect("the raw roster read");
    (roster, raw)
}

/// A member reads the group's live explicit roster: the owner and the writer,
/// not the lapsed row and not the derived member. Every row is one the same
/// connection could already read from `group_memberships` (the subset that
/// section 3 of the migration argues), and the raw read on that connection
/// still shows the lapsed row (so the filter is the function's, not row
/// security's).
#[sqlx::test(migrations = "../../migrations")]
async fn a_member_reads_the_live_explicit_roster_and_nothing_else(pool: PgPool) {
    let t = team(&pool, "member").await;
    let scoped = app_scoped(&pool).await;
    let want = sorted(vec![
        (t.owner, "admin".to_string()),
        (t.writer, "writer".to_string()),
    ]);
    for (who, as_agent) in [
        ("the admin", t.owner),
        ("a writer", t.writer),
        ("a role-derived member", t.derived),
    ] {
        let (roster, raw) = read_as(&pool, &scoped, as_agent, t.group).await;
        assert_eq!(roster, want, "{who}: the live explicit roster");
        assert!(
            roster.iter().all(|r| raw.contains(r)),
            "{who}: every roster row is one row security already shows this session: \
             roster {roster:?}, raw {raw:?}"
        );
        assert!(
            raw.iter().any(|(a, _)| *a == t.lapsed),
            "{who}: CALIBRATION: the raw read on the same connection still shows the lapsed row"
        );
    }
}

/// Nobody outside the group's stamp reads its roster: a stranger, a member of
/// ANOTHER group, the lapsed member (its resolved stamp no longer holds the
/// group although its row is unrevoked), and an unstamped application session.
/// A maintenance session reads it (the operator CLI's DSN).
#[sqlx::test(migrations = "../../migrations")]
async fn a_session_outside_the_group_reads_no_roster(pool: PgPool) {
    let t = team(&pool, "outside").await;
    let (other_owner, _) = fixture::seed_human_operator(&pool, "outside-other").await;
    let other = fixture::verb_team_group(&pool, "Synthetic Other Team", other_owner).await;
    let (stranger, _) = fixture::seed_human_operator(&pool, "outside-stranger").await;
    let scoped = app_scoped(&pool).await;

    let (roster, _) = read_as(&pool, &scoped, t.owner, t.group).await;
    assert_eq!(roster.len(), 2, "POSITIVE CONTROL: the owner reads it");

    let lapsed_viewer = Viewer::resolve(&pool, t.lapsed).await.expect("resolve");
    assert!(
        !lapsed_viewer
            .group_bind()
            .is_some_and(|g| g.contains(&t.group)),
        "PREMISE: the lapsed member's resolved stamp does not hold the group"
    );
    for (who, as_agent, group) in [
        ("a stranger", stranger, t.group),
        ("the lapsed member", t.lapsed, t.group),
        ("a member of another group", other_owner, t.group),
        ("a member asking for another group", t.owner, other),
    ] {
        let (roster, _) = read_as(&pool, &scoped, as_agent, group).await;
        assert!(roster.is_empty(), "{who}: no roster, got {roster:?}");
    }

    // A principal stamp alone does not open the gate, even the group's own
    // creator's (077's creator and principal arms show it rows): only the
    // stamped group set does.
    let group = t.group;
    let owner = t.owner;
    let n: i64 = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        sqlx::query("SELECT set_config('epigraph.principal_id', $1, false)")
            .bind(owner.to_string())
            .execute(&mut *conn)
            .await
            .expect("stamp the principal only");
        let n: i64 =
            sqlx::query_scalar("SELECT count(*) FROM public.epigraph_group_live_roster($1)")
                .bind(group)
                .fetch_one(&mut *conn)
                .await
                .expect("the roster answers");
        sqlx::query("SELECT set_config('epigraph.principal_id', '', false)")
            .execute(&mut *conn)
            .await
            .expect("clear");
        (conn, n)
    })
    .await;
    assert_eq!(
        n, 0,
        "a principal-only stamp (even the creator's) reads no roster"
    );

    let n: i64 = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        let n: i64 =
            sqlx::query_scalar("SELECT count(*) FROM public.epigraph_group_live_roster($1)")
                .bind(group)
                .fetch_one(&mut *conn)
                .await
                .expect("the roster answers");
        (conn, n)
    })
    .await;
    assert_eq!(n, 0, "an unstamped application session reads no roster");

    let n: i64 = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let n: i64 =
            sqlx::query_scalar("SELECT count(*) FROM public.epigraph_group_live_roster($1)")
                .bind(group)
                .fetch_one(&mut *conn)
                .await
                .expect("the roster answers");
        (conn, n)
    })
    .await;
    assert_eq!(n, 2, "a maintenance session reads the live roster");
}

/// The roster's copy of the twin's direct arm decides like the twin: for every
/// unrevoked row in a verb-made team (live and lapsed, 164), a keyed team made
/// outside the verbs (no lapse rule), and a personal group (its owner's row,
/// live, and an allowlisted agent's row after its allowance was revoked,
/// lapsed by 235), the row is listed exactly when
/// `epigraph_live_memberships_unbound(agent)` answers the group.
/// No agent here holds a derived membership of these groups, so the twin's
/// derived arm adds nothing to compare.
#[sqlx::test(migrations = "../../migrations")]
async fn the_roster_decides_each_row_like_the_unbound_twin(pool: PgPool) {
    let (owner, _) = fixture::seed_human_operator(&pool, "parity-owner").await;
    let (live, _) = fixture::seed_human_operator(&pool, "parity-live").await;
    let (lapsed, _) = fixture::seed_human_operator(&pool, "parity-lapsed").await;
    let (plain, personal) = fixture::seed_agent_with_group(&pool, "parity-plain").await;
    let verb = fixture::verb_team_group(&pool, "Synthetic Parity Team", owner).await;
    fixture::verb_team_group_add(&pool, verb, live, "writer").await;
    fixture::verb_team_group_add(&pool, verb, lapsed, "reader").await;
    fixture::revoke_human_operator(&pool, lapsed).await;
    // A keyed team made outside the verbs: no did:epigraph:group: key, so a
    // revoked registration does not lapse its row.
    let keyed: Uuid = sqlx::query_scalar(
        "INSERT INTO groups (display_name, did_key, public_key, kind, created_by_agent_id) \
         VALUES ('Synthetic Keyed Team', 'did:key:parity-' || gen_random_uuid()::text, $1, \
                 'team', $2) RETURNING id",
    )
    .bind(blake3::hash(b"parity keyed team").as_bytes().as_slice())
    .bind(owner)
    .fetch_one(&pool)
    .await
    .expect("keyed team");
    for (agent, role) in [(owner, "admin"), (lapsed, "writer"), (plain, "reader")] {
        sqlx::query(
            "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
             VALUES ($1, $2, ''::bytea, 0, $3)",
        )
        .bind(keyed)
        .bind(agent)
        .bind(role)
        .execute(&pool)
        .await
        .expect("keyed team row");
    }

    // 235's shape: an agent with a writer row in `plain`'s PERSONAL group and
    // an allowance naming `plain` that has since been REVOKED. The revoked row
    // still names the owner, so the row lapses (the agent's live human is no
    // longer the owner). Planted past the allowlist's guard (replica mode), as
    // `author_binding_allowlist.rs` does.
    let (allowlisted, _) = fixture::seed_agent_with_group(&pool, "parity-allowlisted").await;
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'writer')",
    )
    .bind(personal)
    .bind(allowlisted)
    .execute(&pool)
    .await
    .expect("the allowlisted agent's personal-group row");
    let client: Uuid = sqlx::query_scalar(
        "INSERT INTO oauth_clients (client_id, client_name, client_type, allowed_scopes, \
                                    status, agent_id, legal_entity_name, legal_contact_email) \
         VALUES ($1, 'fixture allowlisted service', 'service', ARRAY['claims:write'], \
                 'active', $2, 'Fixture Org', 'fixture@example.invalid') RETURNING id",
    )
    .bind(format!("fixture-allowlisted-{allowlisted}"))
    .bind(allowlisted)
    .fetch_one(&pool)
    .await
    .expect("the allowlisted agent's client");
    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *tx)
        .await
        .expect("replica");
    sqlx::query(
        "INSERT INTO author_binding_clients (client_id, agent_id, operator_id, reason, \
                                             revoked_at, revoked_by, revoked_reason) \
         VALUES ($1, $2, $3, 'planted', now(), 'planted', 'planted')",
    )
    .bind(client)
    .bind(allowlisted)
    .bind(plain)
    .execute(&mut *tx)
    .await
    .expect("plant a revoked allowance");
    tx.commit().await.expect("commit");
    let twin_allowlisted: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM public.epigraph_live_memberships_unbound($1) \
          WHERE group_id = $2)",
    )
    .bind(allowlisted)
    .bind(personal)
    .fetch_one(&pool)
    .await
    .expect("twin");
    assert!(
        !twin_allowlisted,
        "PREMISE: the twin lapses the allowlisted agent's personal-group row (235)"
    );

    let mut lapsed_seen = false;
    for group in [verb, keyed, personal] {
        let rows: Vec<Uuid> = sqlx::query_scalar(
            "SELECT agent_id FROM group_memberships WHERE group_id = $1 AND revoked_at IS NULL",
        )
        .bind(group)
        .fetch_all(&pool)
        .await
        .expect("rows");
        assert!(!rows.is_empty(), "PREMISE: group {group} has rows");
        let roster: Vec<Uuid> =
            sqlx::query_scalar("SELECT agent_id FROM public.epigraph_group_live_roster($1)")
                .bind(group)
                .fetch_all(&pool)
                .await
                .expect("roster");
        for agent in rows {
            let twin: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM public.epigraph_live_memberships_unbound($1) \
                  WHERE group_id = $2)",
            )
            .bind(agent)
            .bind(group)
            .fetch_one(&pool)
            .await
            .expect("twin");
            lapsed_seen |= !twin;
            assert_eq!(
                roster.contains(&agent),
                twin,
                "group {group}, agent {agent}: the roster and the twin disagree"
            );
        }
    }
    assert!(lapsed_seen, "CALIBRATION: at least one row is lapsed");
}

/// Catalog: a maintenance-owned SECURITY DEFINER on `pg_catalog, pg_temp`,
/// executable by the application role and not by PUBLIC, with a realistic
/// row estimate (backlog 8377cf18); and the twin it copies from still carries
/// the body 273 was written from.
#[sqlx::test(migrations = "../../migrations")]
async fn the_roster_is_a_pinned_maintenance_definer_over_an_unchanged_twin(pool: PgPool) {
    let (definer, owner, app, public_acl, rows, config): (
        bool,
        String,
        bool,
        bool,
        f32,
        Vec<String>,
    ) = sqlx::query_as(
        "SELECT p.prosecdef, pg_get_userbyid(p.proowner)::text, \
                has_function_privilege('epigraph_app', p.oid, 'EXECUTE'), \
                p.proacl IS NULL OR EXISTS (SELECT 1 FROM aclexplode(p.proacl) x \
                                             WHERE x.grantee = 0), \
                p.prorows, COALESCE(p.proconfig, ARRAY[]::text[]) \
           FROM pg_proc p \
          WHERE p.oid = to_regprocedure('public.epigraph_group_live_roster(uuid)')",
    )
    .fetch_one(&pool)
    .await
    .expect("the roster exists");
    assert!(definer, "SECURITY DEFINER");
    assert_eq!(owner, "epigraph_maintenance");
    assert!(app, "the application role executes it");
    assert!(!public_acl, "an explicit ACL without PUBLIC");
    assert!(rows <= 50.0, "a realistic ROWS estimate, got {rows}");
    assert_eq!(config, vec!["search_path=pg_catalog, pg_temp".to_string()]);

    let twin: String = sqlx::query_scalar(
        "SELECT md5(prosrc) FROM pg_proc \
          WHERE oid = to_regprocedure('public.epigraph_live_memberships_unbound(uuid)')",
    )
    .fetch_one(&pool)
    .await
    .expect("the twin exists");
    assert_eq!(
        twin, TWIN_MD5,
        "epigraph_live_memberships_unbound was re-stated: re-state \
         epigraph_group_live_roster's copy of its direct arm with the same delta, then \
         update this md5"
    );
}
