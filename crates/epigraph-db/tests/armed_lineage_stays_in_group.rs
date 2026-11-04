//! Migration 153: once the operator binding is armed, an application session
//! keeps a CURRENT successor in its predecessor's owner group.
//!
//! Before 153 the tenancy trigger (074, arm 1) only fills an UNDECLARED
//! `owner_group_id` from the predecessor, so a writer could attach a current
//! successor, declared in its own group, to a claim another group owns (the
//! platform corpus included) while that predecessor stayed current. Such a
//! row squats the predecessor's lineage: 123's inherited-author rule needs "no
//! other current successor", so the custodial supersede of that claim is then
//! refused `OPL01` (calibrated below). Three statements reach the state: an
//! INSERT, a first `SET supersedes` on a row that stays current, and a re-open
//! of a retired row that names it. 153 refuses each with `OPL02`, armed, on a
//! non-privileged session, and changes nothing else.
//!
//! The application arms run as `epigraph_app` under `SET SESSION
//! AUTHORIZATION`, stamped exactly as `ScopedPool` stamps a request.

#[path = "viewer_fixture.rs"]
mod fixture;

use sqlx::PgPool;
use uuid::Uuid;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

/// The world group (migration 060): the owner of the platform corpus.
const WORLD: Uuid = Uuid::nil();

/// The fragment of 153's refusal that no earlier check's text carries.
const CROSS_GROUP: &str = "keeps a current successor in its predecessor's owner group";

fn sqlstate(e: &sqlx::Error) -> Option<String> {
    e.as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(|c| c.to_string())
}

fn code_of<T: std::fmt::Debug>(r: &Result<T, sqlx::Error>) -> Option<String> {
    r.as_ref().err().and_then(sqlstate)
}

/// `Err` with SQLSTATE `OPL02` and 153's own text: the cross-group check
/// refused, not an earlier one.
fn assert_cross_group<T: std::fmt::Debug>(r: &Result<T, sqlx::Error>, what: &str) {
    assert_eq!(
        code_of(r).as_deref(),
        Some("OPL02"),
        "{what}: expected OPL02, got {r:?}"
    );
    let text = r.as_ref().expect_err("refused").to_string();
    assert!(
        text.contains(CROSS_GROUP),
        "{what}: expected the cross-group refusal, got {text}"
    );
}

/// A `('public', group)` claim by `author` on whatever connection `exec` is,
/// naming `supersedes` and `is_current` as given.
async fn insert_row<'e, E>(
    exec: E,
    author: Uuid,
    group: Uuid,
    supersedes: Option<Uuid>,
    current: bool,
) -> Result<Uuid, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    insert_row_with(exec, author, "public", group, supersedes, current).await
}

/// [`insert_row`] with the claim's `visibility` given.
async fn insert_row_with<'e, E>(
    exec: E,
    author: Uuid,
    visibility: &str,
    group: Uuid,
    supersedes: Option<Uuid>,
    current: bool,
) -> Result<Uuid, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id, supersedes) \
         VALUES ($1, $2, $3, 0.5, $4, $5, $6, $7, $8)",
    )
    .bind(id)
    .bind(format!("lineage probe {id}"))
    .bind(id.as_bytes().repeat(2))
    .bind(author)
    .bind(current)
    .bind(visibility)
    .bind(group)
    .bind(supersedes)
    .execute(exec)
    .await?;
    Ok(id)
}

/// A current `('public', group)` claim with no lineage.
async fn insert_claim<'e, E>(exec: E, author: Uuid, group: Uuid) -> Result<Uuid, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    insert_row(exec, author, group, None, true).await
}

/// Arm the operator binding as the maintenance role would.
async fn arm(pool: &PgPool) {
    fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        sqlx::query("SELECT * FROM public.epigraph_arm_operator_binding()")
            .execute(&mut *conn)
            .await
            .expect("arm");
        (conn, ())
    })
    .await;
}

/// Run `f` as `epigraph_app` stamped as `principal`, with `groups` as its read
/// and writable set (the GUCs `ScopedPool` stamps); cleared afterwards.
async fn as_app<F, Fut, T>(pool: &PgPool, principal: Uuid, groups: &[Uuid], f: F) -> T
where
    F: FnOnce(sqlx::pool::PoolConnection<sqlx::Postgres>) -> Fut,
    Fut: std::future::Future<Output = (sqlx::pool::PoolConnection<sqlx::Postgres>, T)>,
{
    as_app_session(pool, Some(principal), groups, false, f).await
}

/// [`as_app`], with the principal optional (`None`: an UNSTAMPED session,
/// a route that forgot its viewer) and the session's OPL01 valve
/// (`epigraph.operator_link_enforcement = 'off'`) opened when `valve_open`.
async fn as_app_session<F, Fut, T>(
    pool: &PgPool,
    principal: Option<Uuid>,
    groups: &[Uuid],
    valve_open: bool,
    f: F,
) -> T
where
    F: FnOnce(sqlx::pool::PoolConnection<sqlx::Postgres>) -> Fut,
    Fut: std::future::Future<Output = (sqlx::pool::PoolConnection<sqlx::Postgres>, T)>,
{
    let set = groups
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let principal = principal.map(|p| p.to_string()).unwrap_or_default();
    fixture::as_role(pool, "epigraph_app", |mut conn| async move {
        sqlx::query(
            "SELECT set_config('epigraph.principal_id', $1, false), \
                    set_config('epigraph.group_ids', $2, false), \
                    set_config('epigraph.writable_group_ids', $2, false), \
                    set_config('epigraph.operator_link_enforcement', $3, false)",
        )
        .bind(principal)
        .bind(&set)
        .bind(if valve_open { "off" } else { "" })
        .execute(&mut *conn)
        .await
        .expect("stamp");
        let (mut conn, out) = f(conn).await;
        sqlx::query(
            "SELECT set_config('epigraph.principal_id', '', false), \
                    set_config('epigraph.group_ids', '', false), \
                    set_config('epigraph.writable_group_ids', '', false), \
                    set_config('epigraph.operator_link_enforcement', '', false)",
        )
        .execute(&mut *conn)
        .await
        .expect("unstamp");
        (conn, out)
    })
    .await
}

/// One statement binding `id` (and `to`, when the SQL names `$2`) on an
/// application session stamped as `principal`; rows affected.
async fn update_as(
    pool: &PgPool,
    principal: Uuid,
    groups: &[Uuid],
    sql: &'static str,
    id: Uuid,
    to: Option<Uuid>,
) -> Result<u64, sqlx::Error> {
    as_app(pool, principal, groups, |mut conn| async move {
        let mut q = sqlx::query(sql).bind(id);
        if sql.contains("$2") {
            q = q.bind(to);
        }
        let r = q.execute(&mut *conn).await.map(|d| d.rows_affected());
        (conn, r)
    })
    .await
}

/// The supersede act (`ClaimRepository::supersede_act_conn`, what REST, MCP
/// and `epigraph-operator custodial-supersede` run) on `conn`, in its own
/// transaction, committed on success. Returns the successor.
async fn supersede_on(
    conn: &mut sqlx::PgConnection,
    old: Uuid,
) -> Result<Uuid, epigraph_db::DbError> {
    let mut tx = sqlx::Connection::begin(&mut *conn).await.expect("begin");
    // The acting agent the act records (backlog 73085534): this
    // fixture acts as the claim's own author.
    let supersede_actor: uuid::Uuid =
        sqlx::query_scalar("SELECT agent_id FROM claims WHERE id = $1")
            .bind(old)
            .fetch_optional(&mut *tx)
            .await
            .expect("read the superseded claim's author")
            .unwrap_or_else(uuid::Uuid::nil);
    let r = epigraph_db::ClaimRepository::supersede_act_conn(
        &mut tx,
        epigraph_core::ClaimId::from_uuid(old),
        &format!("a revision of {old}"),
        epigraph_core::TruthValue::new(0.6).expect("truth"),
        "lineage probe",
        epigraph_db::SupersedeActor::new(
            supersede_actor,
            epigraph_db::SupersedeTool::SupersedeClaim,
        ),
    )
    .await;
    if r.is_ok() {
        tx.commit().await.expect("commit");
    }
    r.map(|(new, _)| new)
}

/// Whether the supersede act was refused `OPL01` (the binding), as the
/// repository maps it.
fn is_opl01(e: &epigraph_db::DbError) -> bool {
    matches!(e, epigraph_db::DbError::OperatorLinkRequired { .. })
}

/// `(owner_group_id, supersedes, is_current)` of `id`.
async fn row_of(pool: &PgPool, id: Uuid) -> (Uuid, Option<Uuid>, bool) {
    sqlx::query_as(
        "SELECT owner_group_id, supersedes, COALESCE(is_current, true) FROM claims WHERE id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .expect("row")
}

async fn successors_of(pool: &PgPool, id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM claims WHERE supersedes = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("count")
}

/// A world-owned current claim by an UNBOUND legacy author (the platform
/// corpus shape), written before arming as the corpus was.
async fn corpus_claim(pool: &PgPool) -> Uuid {
    let (legacy, _) = fixture::seed_agent_with_group(pool, "legacy-author").await;
    insert_claim(pool, legacy, WORLD)
        .await
        .expect("corpus claim")
}

/// The three statements that attach a current successor in the writer's own
/// group `g` to `pred`, owned elsewhere: (1) an INSERT naming it; (2) a plain
/// own claim, then a first `SET supersedes` while it stays current; (3) a
/// retired row naming it, then a re-open. Each `Result` is the statement that
/// creates the current cross-group successor.
async fn three_doors(
    pool: &PgPool,
    writer: Uuid,
    groups: &[Uuid],
    g: Uuid,
    pred: Uuid,
) -> [(Result<u64, sqlx::Error>, &'static str); 3] {
    let insert = as_app(pool, writer, groups, |mut conn| async move {
        let r = insert_row(&mut *conn, writer, g, Some(pred), true)
            .await
            .map(|_| 1);
        (conn, r)
    })
    .await;

    let plain = as_app(pool, writer, groups, |mut conn| async move {
        let r = insert_claim(&mut *conn, writer, g).await;
        (conn, r)
    })
    .await
    .expect("a plain own claim");
    let first_set = update_as(
        pool,
        writer,
        groups,
        "UPDATE claims SET supersedes = $2 WHERE id = $1",
        plain,
        Some(pred),
    )
    .await;

    let retired = as_app(pool, writer, groups, |mut conn| async move {
        let r = insert_row(&mut *conn, writer, g, Some(pred), false).await;
        (conn, r)
    })
    .await
    .expect("a retired row naming the predecessor is the dedup shape, admitted");
    let reopen = update_as(
        pool,
        writer,
        groups,
        "UPDATE claims SET is_current = true WHERE id = $1",
        retired,
        None,
    )
    .await;

    [
        (
            insert,
            "an INSERT of a current successor in the writer's group",
        ),
        (
            first_set,
            "a first SET supersedes on a claim that stays current",
        ),
        (reopen, "a re-open of a retired row naming the predecessor"),
    ]
}

/// Armed, a registered human on an application session attaches no current
/// successor in its own group to a world-owned corpus claim, by any of the
/// three statements, and its own valve does not relieve it (`OPL02`, keyed on
/// arming). Nothing is written, the corpus claim stays current, and its
/// custodial revision on a privileged session still restates it in the world
/// group.
///
/// Verified to fail (each alone, against 153's body): the INSERT/re-open check
/// removed -> the INSERT and the re-open land; its `v_reopen` term removed ->
/// the re-open lands; the narrowed early return restored to 123's
/// (`OR OLD.supersedes IS NULL`) -> the first `SET supersedes` lands; the
/// first-set check removed -> the same.
#[sqlx::test(migrations = "../../migrations")]
async fn an_armed_application_session_attaches_no_successor_across_groups(pool: PgPool) {
    let (a, ag) = fixture::seed_human_operator(&pool, "human-a").await;
    let corpus = corpus_claim(&pool).await;
    arm(&pool).await;

    for (r, what) in three_doors(&pool, a, &[ag], ag, corpus).await {
        assert_cross_group(&r, what);
    }
    assert_eq!(
        successors_of(&pool, corpus).await,
        1,
        "only the retired row (the dedup shape) names the corpus claim"
    );
    let current_successors: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM claims WHERE supersedes = $1 AND COALESCE(is_current, true)",
    )
    .bind(corpus)
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(current_successors, 0, "no current successor was attached");

    // The valve relieves OPL01 only; this is OPL02.
    let r = as_app(&pool, a, &[ag], |mut conn| async move {
        sqlx::query("SELECT set_config('epigraph.operator_link_enforcement', 'off', false)")
            .execute(&mut *conn)
            .await
            .expect("open the valve");
        let r = insert_row(&mut *conn, a, ag, Some(corpus), true).await;
        (conn, r)
    })
    .await;
    assert_cross_group(&r, "the INSERT with the session's valve open");

    assert_eq!(
        row_of(&pool, corpus).await,
        (WORLD, None, true),
        "the corpus claim is untouched and current"
    );
    // The sanctioned path: a privileged session's supersede act restates it
    // in the world group.
    let successor = fixture::as_role(&pool, "epigraph_maintenance", |mut m| async move {
        let r = supersede_on(&mut m, corpus).await;
        (m, r)
    })
    .await
    .expect("the custodial supersede of the corpus claim");
    assert_eq!(
        row_of(&pool, successor).await,
        (WORLD, Some(corpus), true),
        "the custodial successor stays in the world group"
    );
}

/// Group EQUALITY, not "a group the writer writes": a human that writes two
/// groups still does not move a lineage between them on an application
/// session (it supersedes in place, or retires the old claim itself). Another
/// human's group is refused the same way.
///
/// Verified to fail: the check keyed on `NOT epigraph_operator_writes_group(
/// <writer's human>, <predecessor's group>)` instead of group equality -> the
/// G1 -> G2 successor lands.
#[sqlx::test(migrations = "../../migrations")]
async fn a_lineage_does_not_move_between_groups_the_writer_writes(pool: PgPool) {
    let (a, g1) = fixture::seed_human_operator(&pool, "human-a").await;
    let (b, bg) = fixture::seed_human_operator(&pool, "human-b").await;
    let (_, g2) = fixture::seed_agent_with_group(&pool, "second-group-owner").await;
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'writer')",
    )
    .bind(g2)
    .bind(a)
    .execute(&pool)
    .await
    .expect("A writes G2 too");
    let own = insert_claim(&pool, a, g1)
        .await
        .expect("A's own claim in G1");
    let bs = insert_claim(&pool, b, bg).await.expect("B's claim");
    arm(&pool).await;
    let sets = [g1, g2];

    // CALIBRATION: A writes G2.
    as_app(&pool, a, &sets, |mut conn| async move {
        let r = insert_claim(&mut *conn, a, g2).await;
        (conn, r)
    })
    .await
    .expect("A writes G2");

    for (r, what) in three_doors(&pool, a, &sets, g2, own).await {
        assert_cross_group(&r, &format!("own G1 claim, successor in G2: {what}"));
    }
    for (r, what) in three_doors(&pool, a, &sets, g1, bs).await {
        assert_cross_group(&r, &format!("another human's claim: {what}"));
    }
    assert_eq!(row_of(&pool, own).await, (g1, None, true));
    assert_eq!(row_of(&pool, bs).await, (bg, None, true));
}

/// 153 reads the predecessor's owner group in its SECURITY DEFINER frame
/// (maintenance-owned, so `claims_tenancy` admits the read), so a
/// GROUP-PRIVATE predecessor the writer cannot read is checked like any other:
/// the INSERT and the first `SET supersedes` naming it are refused. A re-body
/// that moved the read into an invoker helper would see no such row and fail
/// open for exactly the private claims.
///
/// Verified to fail: the function body restored to 123's (no 153 check) ->
/// the INSERT lands although the writer reads no such row.
#[sqlx::test(migrations = "../../migrations")]
async fn a_private_predecessor_the_writer_cannot_read_is_checked_too(pool: PgPool) {
    let (a, ag) = fixture::seed_human_operator(&pool, "human-a").await;
    let (b, bg) = fixture::seed_human_operator(&pool, "human-b").await;
    let private = fixture::seed_group_claim(&pool, b, bg, "B's group-private claim").await;
    arm(&pool).await;

    // CALIBRATION: A's session reads no such row.
    let seen: i64 = as_app(&pool, a, &[ag], |mut conn| async move {
        let n = sqlx::query_scalar("SELECT count(*) FROM claims WHERE id = $1")
            .bind(private)
            .fetch_one(&mut *conn)
            .await
            .expect("count");
        (conn, n)
    })
    .await;
    assert_eq!(seen, 0, "A cannot read B's group-private claim");

    let insert = as_app(&pool, a, &[ag], |mut conn| async move {
        let r = insert_row_with(&mut *conn, a, "group", ag, Some(private), true).await;
        (conn, r)
    })
    .await;
    assert_cross_group(&insert, "an INSERT naming an unreadable private claim");

    let plain = as_app(&pool, a, &[ag], |mut conn| async move {
        let r = insert_row_with(&mut *conn, a, "group", ag, None, true).await;
        (conn, r)
    })
    .await
    .expect("a plain own group-private claim");
    let first_set = update_as(
        &pool,
        a,
        &[ag],
        "UPDATE claims SET supersedes = $2 WHERE id = $1",
        plain,
        Some(private),
    )
    .await;
    assert_cross_group(
        &first_set,
        "a first SET supersedes naming an unreadable private claim",
    );
    assert_eq!(successors_of(&pool, private).await, 0);
}

/// "Every refusal 123 makes keeps its code and text": on an UNSTAMPED
/// application session (no principal), 123's no-principal refusal comes
/// first. While the binding is enforced the INSERT of a cross-group successor
/// is refused `OPL01`, which the valve relieves; with the session's valve open
/// it then meets 153's `OPL02`, which the valve does not relieve.
///
/// Verified to fail: 153's INSERT/re-open check moved above the
/// re-attribution check and the no-principal refusal -> the enforced session
/// gets `OPL02` with 153's text instead of `OPL01`.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unstamped_session_meets_123s_refusal_before_153s(pool: PgPool) {
    let (a, ag) = fixture::seed_human_operator(&pool, "human-a").await;
    let corpus = corpus_claim(&pool).await;
    arm(&pool).await;

    let enforced = as_app_session(&pool, None, &[ag], false, |mut conn| async move {
        let r = insert_row(&mut *conn, a, ag, Some(corpus), true).await;
        (conn, r)
    })
    .await;
    assert_eq!(
        code_of(&enforced).as_deref(),
        Some("OPL01"),
        "enforced, no principal: 123's refusal first, got {enforced:?}"
    );
    let text = enforced.as_ref().expect_err("refused").to_string();
    assert!(
        text.contains("carries no authenticated principal") && !text.contains(CROSS_GROUP),
        "enforced, no principal: 123's text, got {text}"
    );

    let valve_open = as_app_session(&pool, None, &[ag], true, |mut conn| async move {
        let r = insert_row(&mut *conn, a, ag, Some(corpus), true).await;
        (conn, r)
    })
    .await;
    assert_cross_group(&valve_open, "no principal, the session's valve open");
    assert_eq!(successors_of(&pool, corpus).await, 0);
}

/// "Every refusal 123 makes keeps its code and text": an UPDATE that
/// re-attributes a claim AND first-sets a cross-group `supersedes` is refused
/// with 123's re-attribution text, not 153's.
///
/// Verified to fail: the first-set check without its same-author term ->
/// 153's text wins.
#[sqlx::test(migrations = "../../migrations")]
async fn a_reattributing_update_keeps_123s_refusal_text(pool: PgPool) {
    let (a, ag) = fixture::seed_human_operator(&pool, "human-a").await;
    let (b, _) = fixture::seed_human_operator(&pool, "human-b").await;
    let corpus = corpus_claim(&pool).await;
    let own = insert_claim(&pool, a, ag).await.expect("A's own claim");
    arm(&pool).await;

    let r = as_app(&pool, a, &[ag], |mut conn| async move {
        let r = sqlx::query("UPDATE claims SET agent_id = $2, supersedes = $3 WHERE id = $1")
            .bind(own)
            .bind(b)
            .bind(corpus)
            .execute(&mut *conn)
            .await
            .map(|d| d.rows_affected());
        (conn, r)
    })
    .await;
    assert_eq!(code_of(&r).as_deref(), Some("OPL02"), "{r:?}");
    let text = r.as_ref().expect_err("refused").to_string();
    assert!(
        text.contains("does not re-attribute") && !text.contains(CROSS_GROUP),
        "123's re-attribution text, got {text}"
    );
    assert_eq!(row_of(&pool, own).await, (ag, None, true));
}

/// What 153 must NOT change, armed: the supersede act on the writer's own
/// claim; a human's supersede of its own legacy (retired-linked) author's
/// claim, the inherited author; the custodial supersede and any raw write on a
/// privileged session; the dedup and consolidate acts themselves (a first
/// `supersedes` set while retiring the row), the dedup act pointing at a
/// canonical in another group; and a first `supersedes` within the row's own
/// group.
#[sqlx::test(migrations = "../../migrations")]
async fn the_sanctioned_lineage_writes_are_unchanged(pool: PgPool) {
    let (a, ag) = fixture::seed_human_operator(&pool, "human-a").await;
    let (legacy, _) = fixture::seed_agent_with_group(&pool, "a-legacy").await;
    let own = insert_claim(&pool, a, ag).await.expect("A's own claim");
    let legacy_claim = insert_claim(&pool, legacy, ag)
        .await
        .expect("the legacy identity's claim in A's group");
    {
        let mut conn = pool.acquire().await.expect("acquire");
        epigraph_db::AgentRepository::link_retired_agent(&mut conn, legacy, a)
            .await
            .expect("the legacy identity's retired tie to A");
    }
    let corpus = corpus_claim(&pool).await;
    let corpus2 = corpus_claim(&pool).await;
    let corpus3 = corpus_claim(&pool).await;
    arm(&pool).await;
    let ga = [ag];

    // The supersede act on A's own claim.
    let s_own = as_app(&pool, a, &ga, |mut conn| async move {
        let r = supersede_on(&mut conn, own).await;
        (conn, r)
    })
    .await
    .expect("A supersedes its own claim");
    assert_eq!(row_of(&pool, s_own).await, (ag, Some(own), true));

    // The inherited author: A supersedes its legacy identity's claim.
    let s_legacy = as_app(&pool, a, &ga, |mut conn| async move {
        let r = supersede_on(&mut conn, legacy_claim).await;
        (conn, r)
    })
    .await
    .expect("A supersedes its legacy author's claim");
    assert_eq!(
        row_of(&pool, s_legacy).await,
        (ag, Some(legacy_claim), true)
    );

    // The custodial supersede (maintenance DSN), and a raw cross-group write
    // on a privileged session: only a privileged session crosses groups.
    let s_corpus = fixture::as_role(&pool, "epigraph_maintenance", |mut m| async move {
        let r = supersede_on(&mut m, corpus).await;
        (m, r)
    })
    .await
    .expect("the custodial supersede");
    assert_eq!(row_of(&pool, s_corpus).await, (WORLD, Some(corpus), true));
    insert_row(&pool, a, ag, Some(corpus2), true)
        .await
        .expect("a privileged session's raw cross-group successor");

    // The dedup act (`ClaimRepository::mark_duplicate_act_conn`, what the
    // REST and MCP dedup routes run): a first supersedes set while retiring,
    // here pointing an own duplicate at a world-owned canonical. `corpus3`
    // has no successor of its own, so nothing but 153 could refuse it.
    let dup = as_app(&pool, a, &ga, |mut conn| async move {
        let r = insert_claim(&mut *conn, a, ag).await;
        (conn, r)
    })
    .await
    .expect("a duplicate");
    as_app(&pool, a, &ga, |mut conn| async move {
        let r = epigraph_db::ClaimRepository::mark_duplicate_act_conn(
            &mut conn,
            epigraph_core::ClaimId::from_uuid(dup),
            epigraph_core::ClaimId::from_uuid(corpus3),
        )
        .await;
        (conn, r)
    })
    .await
    .expect("the dedup act points a retired duplicate at a canonical elsewhere");
    assert_eq!(row_of(&pool, dup).await, (ag, Some(corpus3), false));

    // The consolidate act (`ClaimRepository::consolidate_act_conn`): a new
    // merged claim, each source pointed at it while retired.
    let (s1, s2) = as_app(&pool, a, &ga, |mut conn| async move {
        let s1 = insert_claim(&mut *conn, a, ag).await;
        let s2 = insert_claim(&mut *conn, a, ag).await;
        (conn, s1.and_then(|s1| s2.map(|s2| (s1, s2))))
    })
    .await
    .expect("two sources");
    let merged = as_app(&pool, a, &ga, |mut conn| async move {
        let r = epigraph_db::ClaimRepository::consolidate_act_conn(
            &mut conn,
            &[s1, s2],
            "A's merged claim",
            0.7,
            epigraph_db::ConsolidateMode::Merge,
            "merge",
            a,
        )
        .await;
        (conn, r)
    })
    .await
    .expect("the consolidate act")
    .merged_id;
    for s in [s1, s2] {
        assert_eq!(row_of(&pool, s).await, (ag, Some(merged), false));
    }

    // A first supersedes within the row's own group, the row staying current.
    let (x1, x2) = as_app(&pool, a, &ga, |mut conn| async move {
        let x1 = insert_claim(&mut *conn, a, ag).await;
        let x2 = insert_claim(&mut *conn, a, ag).await;
        (conn, x1.and_then(|x1| x2.map(|x2| (x1, x2))))
    })
    .await
    .expect("two own claims");
    assert_eq!(
        update_as(
            &pool,
            a,
            &ga,
            "UPDATE claims SET supersedes = $2 WHERE id = $1",
            x2,
            Some(x1)
        )
        .await
        .expect("a same-group first supersedes"),
        1
    );
}

/// Applying 153 changes no write on a database nobody armed: the three
/// statements are admitted on an application session, as before.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unarmed_database_is_unchanged(pool: PgPool) {
    let (a, ag) = fixture::seed_human_operator(&pool, "human-a").await;
    let corpus = corpus_claim(&pool).await;
    for (r, what) in three_doors(&pool, a, &[ag], ag, corpus).await {
        assert_eq!(r.as_ref().ok(), Some(&1), "unarmed, {what}: {r:?}");
    }
}

/// CALIBRATION of the harm 153 prevents (and of why rows written before
/// arming need a census): a current successor in another group, attached while
/// UNARMED, disables the custodial supersede of the corpus claim once armed.
/// 123's inherited-author rule needs "no other current successor", so the
/// privileged restatement under the claim's unbound legacy author is refused
/// `OPL01`; the same supersede of an unsquatted corpus claim is admitted.
#[sqlx::test(migrations = "../../migrations")]
async fn a_squatting_successor_blocks_the_custodial_supersede(pool: PgPool) {
    let (a, ag) = fixture::seed_human_operator(&pool, "human-a").await;
    let squatted = corpus_claim(&pool).await;
    let clean = corpus_claim(&pool).await;
    as_app(&pool, a, &[ag], |mut conn| async move {
        let r = insert_row(&mut *conn, a, ag, Some(squatted), true).await;
        (conn, r)
    })
    .await
    .expect("unarmed, the squat lands");
    arm(&pool).await;

    let blocked = fixture::as_role(&pool, "epigraph_maintenance", |mut m| async move {
        let r = supersede_on(&mut m, squatted).await;
        (m, r)
    })
    .await;
    assert!(
        blocked.as_ref().is_err_and(is_opl01),
        "the custodial supersede of a squatted corpus claim is refused OPL01: {blocked:?}"
    );
    assert_eq!(row_of(&pool, squatted).await, (WORLD, None, true));
    fixture::as_role(&pool, "epigraph_maintenance", |mut m| async move {
        let r = supersede_on(&mut m, clean).await;
        (m, r)
    })
    .await
    .expect("the custodial supersede of an unsquatted corpus claim");
}

// =====================================================================
// The rollback.
// =====================================================================

fn up_to_below(version: i64) -> sqlx::migrate::Migrator {
    sqlx::migrate::Migrator {
        migrations: std::borrow::Cow::Owned(
            MIGRATOR
                .migrations
                .iter()
                .filter(|m| m.version < version)
                .cloned()
                .collect(),
        ),
        ignore_missing: false,
        locking: true,
        no_tx: false,
    }
}

async fn migrate(pool: &PgPool, migrator: &sqlx::migrate::Migrator) {
    let mut conn = pool.acquire().await.expect("acquire");
    migrator.run(&mut *conn).await.expect("migrate");
    sqlx::query("RESET ALL")
        .execute(&mut *conn)
        .await
        .expect("RESET ALL");
}

/// The definition, owner and ACL of the function 153 re-bodies.
async fn trigger_function(pool: &PgPool) -> (String, String, Option<String>) {
    sqlx::query_as(
        "SELECT pg_get_functiondef(p.oid), p.proowner::regrole::text, p.proacl::text \
           FROM pg_proc p \
          WHERE p.oid = 'public.epigraph_claims_require_operator_binding()'::regprocedure",
    )
    .fetch_one(pool)
    .await
    .expect("the claims binding trigger function")
}

/// `docs/runbooks/153-undo.sql`, applied twice to a database that went
/// pre-153 -> 153 (not to head), restores the pre-153 definition of the claims binding
/// trigger function byte for byte, with its owner and ACL; at 153 the function
/// is owned by the maintenance role.
#[sqlx::test(migrations = false)]
async fn the_153_rollback_restores_the_pre_153_trigger_body(pool: PgPool) {
    migrate(&pool, &up_to_below(153)).await;
    let before = trigger_function(&pool).await;
    // Up to 153 INCLUSIVE, not head: the undo reverses 153 alone, so a later
    // migration's change must not be charged to it.
    migrate(&pool, &up_to_below(154)).await;
    let at_153 = trigger_function(&pool).await;
    assert_ne!(
        at_153.0, before.0,
        "CALIBRATION: 153 re-bodied the function"
    );
    assert_eq!(
        at_153.1, "epigraph_maintenance",
        "153 keeps the function maintenance-owned"
    );
    assert_eq!(at_153.2, before.2, "153 keeps the function's ACL");

    let undo = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/runbooks/153-undo.sql"),
    )
    .expect("153-undo.sql");
    for run in 1..=2 {
        sqlx::raw_sql(&undo)
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("the undo script applies (run {run}): {e}"));
    }
    assert_eq!(
        trigger_function(&pool).await,
        before,
        "the function is not its pre-153 self after the undo"
    );
}
