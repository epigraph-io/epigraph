//! Migration 264 (backlog 9073f0a5): restoring a role's running successor
//! after its root identity was detached, in one audited act.
//!
//! Before 264, attaching a detached root identity by name again did not give
//! the group back to its running successor: the successor's old succession
//! copy, chained to the root's DETACHED row, still covered the window, and
//! 166's attach-time follow copies only into gaps. Recovery was the manual
//! pair "detach the running identity's stale copy, attach it by name"
//! (`group_role_membership.rs::a_detach_anywhere_in_the_chain_revokes_the_
//! successors_copies` pins that the plain re-attach still behaves that way).
//! `epigraph_restore_role_successor(role, root, successor, valid_to, reason)`
//! does the pair in one transaction, and only where a copy written fresh from
//! the root's row would admit the successor.
//!
//! What is pinned, each refusal next to the control that shows the same shape
//! is restored when the refused condition is absent:
//!
//! * the restore: after the root's re-attach the successor is still out (the
//!   defect); one call gives it the group back (read, write, an armed write
//!   lands), detaches exactly its stale copy, writes one
//!   `platform.role_successor_restored` audit row, and a repeat writes
//!   nothing. The verb also re-attaches the root itself, and reports a
//!   registered descendant its restore leaves out;
//! * the refusals (`ROL04`, nothing written, the root not attached either):
//!   a successor that runs in another folder too (179's folder rule), one the
//!   operator detached itself (195's sticky detach), one copied through a
//!   middle identity the operator detached, one with a second, detached
//!   parent (195's lineage walk), one not copied through the named root, and
//!   any transaction but READ COMMITTED;
//! * the review's additions: a `root` that never held a row made by name
//!   (a middle identity) is refused, so it cannot undo its own detach or
//!   step around the real root's; a successor still out through 195's walk
//!   is refused, never reported `successor_unchanged`; the root's re-attach
//!   is audited when the successor needs nothing; a `valid_to` the kept root
//!   row does not end at is refused 22023; a finite window ends the
//!   successor with the root;
//! * only the maintenance role executes it.
//!
//! Every write runs on a session whose `session_user` is the deployed role
//! (`SET SESSION AUTHORIZATION`), never on the harness superuser.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::{AgentRepository, Viewer};
use sqlx::PgPool;
use uuid::Uuid;

/// A synthetic, non-elevating role key used throughout.
const ROLE: &str = "role:team-member";
const ROL04: &str = "ROL04";

fn sqlstate(e: &sqlx::Error) -> Option<String> {
    e.as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(|c| c.to_string())
}

/// `Err` with SQLSTATE `code` whose message carries `fragment`.
fn assert_refused<T: std::fmt::Debug>(
    r: &Result<T, sqlx::Error>,
    code: &str,
    fragment: &str,
    what: &str,
) {
    let err = r
        .as_ref()
        .err()
        .unwrap_or_else(|| panic!("{what}: expected {code}, got {r:?}"));
    assert_eq!(sqlstate(err).as_deref(), Some(code), "{what}: {err:?}");
    let msg = err
        .as_database_error()
        .map(|d| d.message().to_string())
        .unwrap_or_default();
    assert!(
        msg.contains(fragment),
        "{what}: expected the refusal to say {fragment:?}, got {msg:?}"
    );
}

async fn maint(pool: &PgPool) -> sqlx::pool::PoolConnection<sqlx::Postgres> {
    use sqlx::Executor;
    let mut conn = pool.acquire().await.expect("acquire");
    conn.execute("SET SESSION AUTHORIZATION epigraph_maintenance")
        .await
        .expect("downgrade to the maintenance role");
    conn
}

async fn reset(mut conn: sqlx::pool::PoolConnection<sqlx::Postgres>) {
    use sqlx::Executor;
    conn.execute("RESET SESSION AUTHORIZATION")
        .await
        .expect("reset session authorization");
}

/// A team group bound to ROLE at `writer` in 179's `attached_agents` mode,
/// and a registered human holding ROLE from now on. Returns `(human, group)`.
async fn attached_group_held(pool: &PgPool, name: &str) -> (Uuid, Uuid) {
    let (owner, _) = fixture::seed_human_operator(pool, &format!("{name}-owner")).await;
    let (h, _) = fixture::seed_human_operator(pool, &format!("{name}-holder")).await;
    let mut c = maint(pool).await;
    let group: Uuid = sqlx::query_scalar("SELECT public.epigraph_create_team_group($1, $2, $3)")
        .bind(name)
        .bind(owner)
        .bind("role successor restore test")
        .fetch_one(&mut *c)
        .await
        .expect("create the team group");
    let _binding: Uuid = sqlx::query_scalar(
        "SELECT public.epigraph_define_group_role($1, $2, $3, 'writer', 'attached_agents'::text, \
                                                 'role successor restore test')",
    )
    .bind(ROLE)
    .bind("synthetic team role (restore)")
    .bind(group)
    .fetch_one(&mut *c)
    .await
    .expect("define the role and bind it, attached agents only");
    let _assignment: Uuid = sqlx::query_scalar(
        "SELECT public.epigraph_grant_role($1, $2, now(), NULL, NULL, 'role successor restore test')",
    )
    .bind(ROLE)
    .bind(h)
    .fetch_one(&mut *c)
    .await
    .expect("grant the role");
    reset(c).await;
    (h, group)
}

fn identity_key() -> Vec<u8> {
    [
        Uuid::new_v4().as_bytes().to_vec(),
        Uuid::new_v4().as_bytes().to_vec(),
    ]
    .concat()
}

/// Register an identity through the attestor's verb in `folder`, naming
/// `parent`; returns the agent id.
async fn register_in(pool: &PgPool, key: &[u8], parent: Option<Uuid>, folder: &str) -> Uuid {
    let key = key.to_vec();
    let hash = blake3::hash(&key).to_hex().to_string();
    let folder = folder.to_string();
    fixture::as_role(pool, "epigraph_identity_attestor", |mut conn| async move {
        let id: Uuid = sqlx::query_scalar(
            "SELECT agent_id FROM public.epigraph_register_agent_identity( \
                 $1, $2, 'test-model-264', $3, $4, NULL, $5)",
        )
        .bind(&key)
        .bind(parent)
        .bind(&hash)
        .bind(&folder)
        .bind(serde_json::json!({"in_prompt": {}}))
        .fetch_one(&mut *conn)
        .await
        .expect("the attestor registers the identity");
        (conn, id)
    })
    .await
}

async fn link_to(pool: &PgPool, agent: Uuid, human: Uuid) {
    let mut c = pool.acquire().await.expect("acquire");
    let out = AgentRepository::link_operator(&mut c, agent, human)
        .await
        .expect("link the identity");
    assert!(out.link_live, "PREMISE: a live link: {out:?}");
}

async fn attach_to_role(pool: &PgPool, agent: Uuid) -> Uuid {
    fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let id: Uuid = sqlx::query_scalar(
            "SELECT public.epigraph_attach_agent_to_role($1, $2, now() - interval '5 seconds', \
                                                         NULL, 'restore test attach')",
        )
        .bind(ROLE)
        .bind(agent)
        .fetch_one(&mut *conn)
        .await
        .expect("the maintenance role attaches");
        (conn, id)
    })
    .await
}

async fn detach_from_role(pool: &PgPool, agent: Uuid) -> i32 {
    fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let n: i32 = sqlx::query_scalar(
            "SELECT public.epigraph_detach_agent_from_role($1, $2, 'restore test detach')",
        )
        .bind(ROLE)
        .bind(agent)
        .fetch_one(&mut *conn)
        .await
        .expect("the maintenance role detaches");
        (conn, n)
    })
    .await
}

type Step = (String, Uuid, Option<Uuid>);

/// The verb, on a session whose `session_user` is `role`, with `valid_to`
/// NULL.
async fn restore_as(
    pool: &PgPool,
    role: &str,
    root: Uuid,
    successor: Uuid,
) -> Result<Vec<Step>, sqlx::Error> {
    restore_until(pool, role, root, successor, None).await
}

/// The verb with `valid_to` = `now() + valid_in` (an interval literal), or
/// NULL.
async fn restore_until(
    pool: &PgPool,
    role: &str,
    root: Uuid,
    successor: Uuid,
    valid_in: Option<&str>,
) -> Result<Vec<Step>, sqlx::Error> {
    let valid_in = valid_in.map(str::to_string);
    fixture::as_role(pool, role, |mut conn| async move {
        let r = sqlx::query_as::<_, Step>(
            "SELECT out_step, out_agent_id, out_attachment_id \
               FROM public.epigraph_restore_role_successor($1, $2, $3, \
                        now() + $4::interval, 'restore test: job is back')",
        )
        .bind(ROLE)
        .bind(root)
        .bind(successor)
        .bind(valid_in)
        .fetch_all(&mut *conn)
        .await;
        (conn, r)
    })
    .await
}

async fn restore(pool: &PgPool, root: Uuid, successor: Uuid) -> Result<Vec<Step>, sqlx::Error> {
    restore_as(pool, "epigraph_maintenance", root, successor).await
}

fn steps(r: &[Step]) -> Vec<(&str, Uuid)> {
    r.iter().map(|(s, a, _)| (s.as_str(), *a)).collect()
}

/// `(readable, writable)`: whether `agent`'s viewer carries `group`.
async fn resolves(pool: &PgPool, agent: Uuid, group: Uuid) -> (bool, bool) {
    let viewer = Viewer::resolve(pool, agent).await.expect("resolve");
    (
        viewer.group_bind().is_some_and(|g| g.contains(&group)),
        viewer.writable_groups().contains(&group),
    )
}

/// `principal` writes its own `group` claim, stamped as its resolved viewer.
async fn write_honest(pool: &PgPool, principal: Uuid, group: Uuid) -> Result<Uuid, sqlx::Error> {
    let viewer = Viewer::resolve(pool, principal).await.expect("resolve");
    let join = |s: &[Uuid]| {
        s.iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",")
    };
    let read = join(viewer.group_bind().unwrap_or_default());
    let write = join(viewer.writable_groups());
    fixture::as_role(pool, "epigraph_app", |mut conn| async move {
        sqlx::query(
            "SELECT set_config('epigraph.principal_id', $1, false), \
                    set_config('epigraph.group_ids', $2, false), \
                    set_config('epigraph.writable_group_ids', $3, false)",
        )
        .bind(principal.to_string())
        .bind(&read)
        .bind(&write)
        .execute(&mut *conn)
        .await
        .expect("stamp");
        let id = Uuid::new_v4();
        let r = sqlx::query(
            "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                                 visibility, owner_group_id) \
             VALUES ($1, $2, $3, 0.5, $4, true, 'group', $5)",
        )
        .bind(id)
        .bind(format!("role successor restore probe {id}"))
        .bind(id.as_bytes().repeat(2))
        .bind(principal)
        .bind(group)
        .execute(&mut *conn)
        .await
        .map(|_| id);
        sqlx::query(
            "SELECT set_config('epigraph.principal_id', '', false), \
                    set_config('epigraph.group_ids', '', false), \
                    set_config('epigraph.writable_group_ids', '', false)",
        )
        .execute(&mut *conn)
        .await
        .expect("unstamp");
        (conn, r)
    })
    .await
}

async fn arm(pool: &PgPool) {
    let mut c = maint(pool).await;
    sqlx::query("SELECT armed_now FROM public.epigraph_arm_operator_binding()")
        .fetch_one(&mut *c)
        .await
        .expect("the maintenance role arms");
    reset(c).await;
}

/// Un-detached ROLE rows of `agent` live now, made by name.
async fn live_by_name(pool: &PgPool, agent: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM role_agents WHERE agent_id = $1 AND role = $2 \
            AND inherited_from IS NULL AND detached_at IS NULL \
            AND valid_from <= now() AND (valid_to IS NULL OR now() < valid_to)",
    )
    .bind(agent)
    .bind(ROLE)
    .fetch_one(pool)
    .await
    .expect("live rows made by name")
}

/// The un-detached ROLE copies of `agent` whose window has not ended (a
/// re-attach dated a few seconds back also copies the gap before a stale
/// copy's start, which ended in the past and is left alone).
async fn live_copies(pool: &PgPool, agent: Uuid) -> Vec<Uuid> {
    sqlx::query_scalar(
        "SELECT id FROM role_agents WHERE agent_id = $1 AND role = $2 \
            AND inherited_from IS NOT NULL AND detached_at IS NULL \
            AND (valid_to IS NULL OR valid_to > now()) ORDER BY id",
    )
    .bind(agent)
    .bind(ROLE)
    .fetch_all(pool)
    .await
    .expect("live copies")
}

/// `(role_agents rows, security_events rows)`: what a refusal must leave as
/// it was.
async fn footprint(pool: &PgPool) -> (i64, i64) {
    sqlx::query_as(
        "SELECT (SELECT count(*) FROM role_agents), (SELECT count(*) FROM security_events)",
    )
    .fetch_one(pool)
    .await
    .expect("footprint")
}

async fn restored_events(pool: &PgPool, successor: Uuid) -> Vec<serde_json::Value> {
    sqlx::query_scalar(
        "SELECT details FROM security_events \
          WHERE event_type = 'platform.role_successor_restored' AND agent_id = $1 ORDER BY id",
    )
    .bind(successor)
    .fetch_all(pool)
    .await
    .expect("restore audit rows")
}

/// root -> mid -> newest in `folder`, the root linked to `h` and attached by
/// name, each later identity a member through its registration copy.
async fn lineage(pool: &PgPool, h: Uuid, group: Uuid, folder: &str) -> [Uuid; 3] {
    let root = register_in(pool, &identity_key(), None, folder).await;
    link_to(pool, root, h).await;
    attach_to_role(pool, root).await;
    let mid = register_in(pool, &identity_key(), Some(root), folder).await;
    let newest = register_in(pool, &identity_key(), Some(mid), folder).await;
    for (who, what) in [(root, "root"), (mid, "mid"), (newest, "newest")] {
        assert_eq!(
            resolves(pool, who, group).await,
            (true, true),
            "PREMISE: the {what} is a member"
        );
    }
    [root, mid, newest]
}

/// THE DEFECT AND THE FIX. Detaching the root takes the group from the
/// running identity two hops down, and attaching the root by name again does
/// NOT give it back (its stale copy still covers the window). One restore
/// call does: it keeps the root's new row, detaches exactly the newest's
/// stale copy, attaches the newest by name, and the newest reads, writes and
/// (armed) writes through its viewer again. The mid, not named, stays out.
/// One audit row names the act; a repeat changes nothing and writes no row.
/// CONTROL (the fresh copy the verb mirrors): an identity registered from the
/// re-attached root now is a member through its copy.
#[sqlx::test(migrations = "../../migrations")]
async fn one_call_restores_the_running_successor_after_the_root_is_reattached(pool: PgPool) {
    let (h, group) = attached_group_held(&pool, "Synthetic Restore Team").await;
    let [root, mid, newest] = lineage(&pool, h, group, "g-job").await;
    let stale = live_copies(&pool, newest).await;
    assert_eq!(stale.len(), 1, "PREMISE: one copy");

    assert_eq!(detach_from_role(&pool, root).await, 1, "root detached");
    assert_eq!(
        resolves(&pool, newest, group).await,
        (false, false),
        "cut off"
    );
    let root_row = attach_to_role(&pool, root).await;
    assert_eq!(
        resolves(&pool, root, group).await,
        (true, true),
        "root back"
    );
    assert_eq!(
        resolves(&pool, newest, group).await,
        (false, false),
        "THE DEFECT: the plain re-attach leaves the running successor out"
    );

    let before = footprint(&pool).await;
    let out = restore(&pool, root, newest).await.expect("the restore");
    assert_eq!(
        steps(&out),
        vec![
            ("root_already_attached", root),
            ("copy_detached", newest),
            ("successor_attached", newest),
        ],
        "{out:?}"
    );
    assert_eq!(out[0].2, Some(root_row), "the root's own row is kept");
    assert_eq!(
        out[1].2,
        Some(stale[0]),
        "exactly the stale copy is detached"
    );
    assert!(live_copies(&pool, newest).await.is_empty(), "no copy left");
    assert_eq!(live_by_name(&pool, newest).await, 1, "attached by name");

    assert_eq!(
        resolves(&pool, newest, group).await,
        (true, true),
        "the running successor is a member again"
    );
    write_honest(&pool, newest, group)
        .await
        .expect("and writes on an application session");
    arm(&pool).await;
    write_honest(&pool, newest, group)
        .await
        .expect("and writes armed");
    assert_eq!(
        resolves(&pool, mid, group).await,
        (false, false),
        "the mid, not named, stays out"
    );

    let events = restored_events(&pool, newest).await;
    assert_eq!(events.len(), 1, "one restore audit row: {events:?}");
    let e = &events[0];
    assert_eq!(e["role"], ROLE);
    assert_eq!(e["root"], root.to_string());
    assert_eq!(e["root_attachment"], root_row.to_string());
    assert_eq!(e["root_attached_now"], false);
    assert_eq!(e["successor_attachment"], out[2].2.expect("id").to_string());
    assert_eq!(e["detached"], serde_json::json!([stale[0].to_string()]));
    assert_eq!(e["reason"], "restore test: job is back");
    assert_eq!(e["recorded_by"], "epigraph_maintenance");
    // 166's own per-row events: one detach, one attach.
    let (_, events_before) = before;
    let (_, events_after) = footprint(&pool).await;
    assert!(events_after >= events_before + 3, "per-row audit rows too");

    let mid_footprint = footprint(&pool).await;
    let again = restore(&pool, root, newest).await.expect("a repeat");
    assert_eq!(
        steps(&again),
        vec![
            ("root_already_attached", root),
            ("successor_already_attached", newest)
        ],
    );
    assert_eq!(
        footprint(&pool).await,
        mid_footprint,
        "a repeat writes nothing"
    );

    let fresh = register_in(&pool, &identity_key(), Some(root), "g-job").await;
    assert_eq!(
        resolves(&pool, fresh, group).await,
        (true, true),
        "CONTROL: a copy written fresh from the re-attached root admits"
    );
}

/// THE VERB ATTACHES THE ROOT TOO, AND REPORTS WHAT IT LEAVES OUT. With the
/// root still detached, naming the MID re-attaches the root by name and
/// restores the mid; the newest, registered from the mid, still holds a copy
/// chained through the mid's old (now detached) copy and is reported
/// `descendant_still_out`, not changed. Naming the mid as the root of a second
/// call restores the newest (the mid now holds a row made by name).
#[sqlx::test(migrations = "../../migrations")]
async fn the_verb_reattaches_the_root_and_reports_a_descendant_it_leaves_out(pool: PgPool) {
    let (h, group) = attached_group_held(&pool, "Synthetic Restore Root Team").await;
    let [root, mid, newest] = lineage(&pool, h, group, "g-job").await;
    assert_eq!(detach_from_role(&pool, root).await, 1, "root detached");
    assert_eq!(live_by_name(&pool, root).await, 0, "PREMISE");

    let out = restore(&pool, root, mid).await.expect("the restore");
    assert_eq!(
        steps(&out),
        vec![
            ("root_attached", root),
            ("copy_detached", mid),
            ("successor_attached", mid),
            ("descendant_still_out", newest),
        ],
        "{out:?}"
    );
    assert_eq!(
        live_by_name(&pool, root).await,
        1,
        "the root attached by name"
    );
    assert_eq!(resolves(&pool, root, group).await, (true, true), "root");
    assert_eq!(resolves(&pool, mid, group).await, (true, true), "mid");
    assert_eq!(
        resolves(&pool, newest, group).await,
        (false, false),
        "the newest, reported and not changed"
    );
    let events = restored_events(&pool, mid).await;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["root_attached_now"], true);
    assert_eq!(
        events[0]["descendants_still_out"],
        serde_json::json!([newest.to_string()])
    );

    let out = restore(&pool, mid, newest)
        .await
        .expect("the second restore");
    assert_eq!(
        steps(&out),
        vec![
            ("root_already_attached", mid),
            ("copy_detached", newest),
            ("successor_attached", newest),
        ],
        "{out:?}"
    );
    assert_eq!(resolves(&pool, newest, group).await, (true, true), "newest");
}

/// Assert a refusal left `role_agents` and `security_events` exactly as they
/// were, and the root no row made by name.
async fn assert_nothing_written(pool: &PgPool, before: (i64, i64), root: Uuid) {
    assert_eq!(footprint(pool).await, before, "a refusal writes nothing");
    assert_eq!(
        live_by_name(pool, root).await,
        0,
        "not even the root's re-attach"
    );
}

/// 179'S FOLDER RULE. A successor that also runs in another group folder (a
/// shared identity) is admitted nowhere through a copy, so it is not
/// restored (an attachment made by name would skip the rule). CONTROL: the
/// same shape in one folder is restored.
#[sqlx::test(migrations = "../../migrations")]
async fn a_shared_successor_is_not_restored(pool: PgPool) {
    let (h, group) = attached_group_held(&pool, "Synthetic Restore Shared Team").await;
    let root = register_in(&pool, &identity_key(), None, "g-job").await;
    link_to(&pool, root, h).await;
    attach_to_role(&pool, root).await;
    let shared_key = identity_key();
    let shared = register_in(&pool, &shared_key, None, "g-fleet").await;
    link_to(&pool, shared, h).await;
    assert_eq!(
        register_in(&pool, &shared_key, Some(root), "g-job").await,
        shared
    );
    let single = register_in(&pool, &identity_key(), Some(root), "g-job").await;
    assert_eq!(live_copies(&pool, shared).await.len(), 1, "PREMISE: copied");
    assert_eq!(
        resolves(&pool, shared, group).await,
        (false, false),
        "PREMISE"
    );
    assert_eq!(detach_from_role(&pool, root).await, 1, "root detached");

    let before = footprint(&pool).await;
    assert_refused(
        &restore(&pool, root, shared).await,
        ROL04,
        "group folder",
        "the shared successor",
    );
    assert_nothing_written(&pool, before, root).await;
    assert_eq!(
        resolves(&pool, shared, group).await,
        (false, false),
        "still out"
    );

    restore(&pool, root, single)
        .await
        .expect("CONTROL: the single-folder successor");
    assert_eq!(
        resolves(&pool, single, group).await,
        (true, true),
        "CONTROL"
    );
}

/// 195'S STICKY DETACH. A successor the operator detached ITSELF is not
/// restored by restoring its root (attach it by name if that is meant).
#[sqlx::test(migrations = "../../migrations")]
async fn a_successor_detached_itself_is_not_restored(pool: PgPool) {
    let (h, group) = attached_group_held(&pool, "Synthetic Restore Sticky Team").await;
    let [root, _mid, newest] = lineage(&pool, h, group, "g-job").await;
    assert_eq!(detach_from_role(&pool, newest).await, 1, "newest detached");
    assert_eq!(detach_from_role(&pool, root).await, 1, "root detached");

    let before = footprint(&pool).await;
    assert_refused(
        &restore(&pool, root, newest).await,
        ROL04,
        "sticky",
        "a successor detached itself",
    );
    assert_nothing_written(&pool, before, root).await;
    assert_eq!(resolves(&pool, newest, group).await, (false, false), "out");
}

/// A DETACHED MIDDLE IDENTITY. The newest's copy chains through the mid's
/// copy, which the operator detached: that detach is the mid's own, and
/// restoring the root does not undo it. CONTROL: a second lineage, only the
/// root detached, is restored.
#[sqlx::test(migrations = "../../migrations")]
async fn a_successor_copied_through_a_detached_middle_identity_is_not_restored(pool: PgPool) {
    let (h, group) = attached_group_held(&pool, "Synthetic Restore Mid Team").await;
    let [root, mid, newest] = lineage(&pool, h, group, "g-job-1").await;
    assert_eq!(detach_from_role(&pool, mid).await, 1, "mid detached");
    assert_eq!(detach_from_role(&pool, root).await, 1, "root detached");

    let before = footprint(&pool).await;
    assert_refused(
        &restore(&pool, root, newest).await,
        ROL04,
        "below",
        "copied through a detached middle identity",
    );
    assert_nothing_written(&pool, before, root).await;
    assert_eq!(resolves(&pool, newest, group).await, (false, false), "out");

    let [root2, _, newest2] = lineage(&pool, h, group, "g-job-2").await;
    assert_eq!(detach_from_role(&pool, root2).await, 1, "root2 detached");
    restore(&pool, root2, newest2).await.expect("CONTROL");
    assert_eq!(
        resolves(&pool, newest2, group).await,
        (true, true),
        "CONTROL"
    );
}

/// 195'S LINEAGE WALK. The successor's copy chains straight to the root, but
/// it was ALSO registered from a second parent the operator detached: 195
/// keeps it out whichever parent its copy names, so the restore refuses it.
/// CONTROL: the same two-parent shape with the second parent never detached
/// is restored.
#[sqlx::test(migrations = "../../migrations")]
async fn a_successor_with_a_second_detached_parent_is_not_restored(pool: PgPool) {
    let (h, group) = attached_group_held(&pool, "Synthetic Restore Two Parents Team").await;
    let two_parents = |folder: &'static str| {
        let pool = pool.clone();
        async move {
            let root = register_in(&pool, &identity_key(), None, folder).await;
            link_to(&pool, root, h).await;
            attach_to_role(&pool, root).await;
            let s_key = identity_key();
            let s = register_in(&pool, &s_key, Some(root), folder).await;
            let p2 = register_in(&pool, &identity_key(), Some(root), folder).await;
            assert_eq!(register_in(&pool, &s_key, Some(p2), folder).await, s);
            assert_eq!(live_copies(&pool, s).await.len(), 1, "PREMISE: one copy");
            (root, s, p2)
        }
    };

    let (root, s, p2) = two_parents("g-job-1").await;
    assert_eq!(
        detach_from_role(&pool, p2).await,
        1,
        "second parent detached"
    );
    assert_eq!(detach_from_role(&pool, root).await, 1, "root detached");
    let before = footprint(&pool).await;
    assert_refused(
        &restore(&pool, root, s).await,
        ROL04,
        "descends from",
        "a successor with a detached second parent",
    );
    assert_nothing_written(&pool, before, root).await;
    assert_eq!(resolves(&pool, s, group).await, (false, false), "out");

    let (root2, s2, _) = two_parents("g-job-2").await;
    assert_eq!(detach_from_role(&pool, root2).await, 1, "root2 detached");
    restore(&pool, root2, s2).await.expect("CONTROL");
    assert_eq!(resolves(&pool, s2, group).await, (true, true), "CONTROL");
}

/// THE NAMED ROOT MUST BE THE ONE THE COPY CAME FROM. A successor of another
/// detached root is not restored by naming an unrelated attached identity.
#[sqlx::test(migrations = "../../migrations")]
async fn a_successor_not_copied_through_the_named_root_is_not_restored(pool: PgPool) {
    let (h, group) = attached_group_held(&pool, "Synthetic Restore Wrong Root Team").await;
    let [other, _, _] = lineage(&pool, h, group, "g-job").await;
    let [root, _, newest] = lineage(&pool, h, group, "g-job").await;
    assert_eq!(detach_from_role(&pool, root).await, 1, "root detached");

    let before = footprint(&pool).await;
    assert_refused(
        &restore(&pool, other, newest).await,
        ROL04,
        "not copied through",
        "an unrelated root",
    );
    assert_eq!(footprint(&pool).await, before, "nothing written");
    assert_eq!(resolves(&pool, newest, group).await, (false, false), "out");
}

/// READ COMMITTED ONLY, and the maintenance role only.
#[sqlx::test(migrations = "../../migrations")]
async fn only_the_maintenance_role_restores_and_only_under_read_committed(pool: PgPool) {
    let (h, group) = attached_group_held(&pool, "Synthetic Restore Guard Team").await;
    let [root, _, newest] = lineage(&pool, h, group, "g-job").await;
    assert_eq!(detach_from_role(&pool, root).await, 1, "root detached");
    let before = footprint(&pool).await;

    for role in ["epigraph_app", "epigraph_identity_attestor"] {
        let r = restore_as(&pool, role, root, newest).await;
        assert_eq!(
            r.as_ref().err().and_then(sqlstate).as_deref(),
            Some("42501"),
            "{role} may not execute it: {r:?}"
        );
    }

    let rr: Result<Vec<Step>, sqlx::Error> =
        fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
            use sqlx::Executor;
            conn.execute("BEGIN ISOLATION LEVEL REPEATABLE READ")
                .await
                .expect("begin");
            let r = sqlx::query_as::<_, Step>(
                "SELECT out_step, out_agent_id, out_attachment_id \
                   FROM public.epigraph_restore_role_successor($1, $2, $3, NULL, 'rr')",
            )
            .bind(ROLE)
            .bind(root)
            .bind(newest)
            .fetch_all(&mut *conn)
            .await;
            conn.execute("ROLLBACK").await.expect("rollback");
            (conn, r)
        })
        .await;
    assert_refused(&rr, ROL04, "READ COMMITTED", "a repeatable-read restore");
    assert_nothing_written(&pool, before, root).await;

    restore(&pool, root, newest)
        .await
        .expect("CONTROL: the maintenance role, read committed");
    assert_eq!(
        resolves(&pool, newest, group).await,
        (true, true),
        "CONTROL"
    );
}

/// NOTHING TO RESTORE. A successor whose copy still chains through live rows
/// (its root was never detached) is reported `successor_unchanged`: the verb
/// writes nothing, and above all does not swap a working copy for an
/// attachment made by name (which would survive a later detach of the root).
#[sqlx::test(migrations = "../../migrations")]
async fn a_successor_that_was_never_cut_off_is_left_as_it_is(pool: PgPool) {
    let (h, group) = attached_group_held(&pool, "Synthetic Restore Unchanged Team").await;
    let [root, _, newest] = lineage(&pool, h, group, "g-job").await;
    let copies = live_copies(&pool, newest).await;
    let before = footprint(&pool).await;

    let out = restore(&pool, root, newest).await.expect("the call");
    assert_eq!(
        steps(&out),
        vec![
            ("root_already_attached", root),
            ("successor_unchanged", newest)
        ],
    );
    assert_eq!(footprint(&pool).await, before, "nothing written");
    assert_eq!(live_copies(&pool, newest).await, copies, "its copy kept");
    assert_eq!(live_by_name(&pool, newest).await, 0, "no row made by name");
    assert_eq!(
        resolves(&pool, newest, group).await,
        (true, true),
        "a member"
    );
}

/// THE NAMED ROOT MUST HAVE BEEN ATTACHED BY NAME (review of 264). Naming a
/// MIDDLE identity, one that only ever held succession copies, as `--root`
/// would attach it by name and so:
///
/// * (a) undo the operator's own sticky detach of that middle identity (the
///   real root still attached); or
/// * (b) step around the detach of the real root above it.
///
/// Both are refused `ROL04` with nothing written: the middle identity gets no
/// row made by name, and it and the successor stay out. CONTROL: in (b),
/// naming the real root restores the successor.
#[sqlx::test(migrations = "../../migrations")]
async fn a_root_never_attached_by_name_is_not_reattached(pool: PgPool) {
    let (h, group) = attached_group_held(&pool, "Synthetic Restore Middle Root Team").await;

    // (a) the root attached and live; the operator detached the mid.
    let [root, mid, newest] = lineage(&pool, h, group, "g-job-1").await;
    assert_eq!(detach_from_role(&pool, mid).await, 1, "mid detached");
    assert_eq!(resolves(&pool, mid, group).await, (false, false), "PREMISE");
    assert_eq!(
        resolves(&pool, newest, group).await,
        (false, false),
        "PREMISE"
    );
    assert_eq!(live_by_name(&pool, root).await, 1, "PREMISE: root live");
    let before = footprint(&pool).await;
    assert_refused(
        &restore(&pool, mid, newest).await,
        ROL04,
        "never attached by name",
        "(a) a sticky-detached middle identity named as the root",
    );
    assert_eq!(footprint(&pool).await, before, "(a) nothing written");
    assert_eq!(
        live_by_name(&pool, mid).await,
        0,
        "(a) the mid not attached"
    );
    assert_eq!(resolves(&pool, mid, group).await, (false, false), "(a) mid");
    assert_eq!(
        resolves(&pool, newest, group).await,
        (false, false),
        "(a) newest"
    );

    // (b) the real root detached; the mid never was.
    let [root2, mid2, newest2] = lineage(&pool, h, group, "g-job-2").await;
    assert_eq!(detach_from_role(&pool, root2).await, 1, "root2 detached");
    let before = footprint(&pool).await;
    assert_refused(
        &restore(&pool, mid2, newest2).await,
        ROL04,
        "never attached by name",
        "(b) a middle identity named in place of the detached root",
    );
    assert_eq!(footprint(&pool).await, before, "(b) nothing written");
    assert_eq!(
        live_by_name(&pool, mid2).await,
        0,
        "(b) the mid not attached"
    );
    assert_eq!(
        resolves(&pool, newest2, group).await,
        (false, false),
        "(b) newest"
    );

    restore(&pool, root2, newest2)
        .await
        .expect("CONTROL: the real root named");
    assert_eq!(
        resolves(&pool, newest2, group).await,
        (true, true),
        "CONTROL"
    );
}

/// NOT "UNCHANGED" WHILE STILL OUT (review of 264). The root was never
/// detached and the successor's copy chains through the root's live row, but
/// the successor was also registered from a second parent the operator
/// detached, so 195's walk keeps it out. The verb must not report
/// `successor_unchanged` (its copies "already work"): it refuses `ROL04`
/// naming that parent, and writes nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn a_successor_still_out_is_not_reported_unchanged(pool: PgPool) {
    let (h, group) = attached_group_held(&pool, "Synthetic Restore Not Unchanged Team").await;
    let root = register_in(&pool, &identity_key(), None, "g-job").await;
    link_to(&pool, root, h).await;
    attach_to_role(&pool, root).await;
    let s_key = identity_key();
    let s = register_in(&pool, &s_key, Some(root), "g-job").await;
    let p2 = register_in(&pool, &identity_key(), Some(root), "g-job").await;
    assert_eq!(register_in(&pool, &s_key, Some(p2), "g-job").await, s);
    assert_eq!(live_copies(&pool, s).await.len(), 1, "PREMISE: one copy");
    assert_eq!(
        detach_from_role(&pool, p2).await,
        1,
        "second parent detached"
    );
    assert_eq!(
        resolves(&pool, s, group).await,
        (false, false),
        "PREMISE: 195's walk keeps it out"
    );
    assert_eq!(live_by_name(&pool, root).await, 1, "PREMISE: root live");

    let before = footprint(&pool).await;
    assert_refused(
        &restore(&pool, root, s).await,
        ROL04,
        "descends from",
        "a successor out through a detached second parent",
    );
    assert_eq!(footprint(&pool).await, before, "nothing written");
    assert_eq!(resolves(&pool, s, group).await, (false, false), "still out");
}

/// THE ROOT'S RE-ATTACH IS AUDITED EVEN WHEN THE SUCCESSOR NEEDS NOTHING
/// (review of 264). The successor was registered from the root while the
/// root was detached (no copy then); the verb's re-attach of the root copies
/// into its gap, so it is admitted without a restore. One
/// `platform.role_successor_restored` row records that the verb attached the
/// root, with outcome `successor_unchanged`; and likewise
/// `successor_already_attached` for a successor already attached by name.
#[sqlx::test(migrations = "../../migrations")]
async fn a_root_attached_for_a_successor_that_needs_nothing_is_audited(pool: PgPool) {
    let (h, group) = attached_group_held(&pool, "Synthetic Restore Audit Team").await;
    let root = register_in(&pool, &identity_key(), None, "g-job").await;
    link_to(&pool, root, h).await;
    attach_to_role(&pool, root).await;
    assert_eq!(detach_from_role(&pool, root).await, 1, "root detached");
    let s = register_in(&pool, &identity_key(), Some(root), "g-job").await;
    assert!(
        live_copies(&pool, s).await.is_empty(),
        "PREMISE: no copy from a detached root"
    );

    let out = restore(&pool, root, s).await.expect("the call");
    assert_eq!(
        steps(&out),
        vec![("root_attached", root), ("successor_unchanged", s)],
        "{out:?}"
    );
    assert_eq!(live_copies(&pool, s).await.len(), 1, "the follow's copy");
    assert_eq!(resolves(&pool, s, group).await, (true, true), "admitted");
    let events = restored_events(&pool, s).await;
    assert_eq!(events.len(), 1, "the root's re-attach audited: {events:?}");
    assert_eq!(events[0]["outcome"], "successor_unchanged");
    assert_eq!(events[0]["root_attached_now"], true);
    assert_eq!(
        events[0]["root_attachment"],
        out[0].2.expect("id").to_string()
    );

    // The same when the successor already holds a live row made by name.
    let root2 = register_in(&pool, &identity_key(), None, "g-job-2").await;
    link_to(&pool, root2, h).await;
    attach_to_role(&pool, root2).await;
    assert_eq!(detach_from_role(&pool, root2).await, 1, "root2 detached");
    let s2 = register_in(&pool, &identity_key(), Some(root2), "g-job-2").await;
    let s2_row = attach_to_role(&pool, s2).await;
    let out = restore(&pool, root2, s2).await.expect("the second call");
    assert_eq!(
        steps(&out),
        vec![("root_attached", root2), ("successor_already_attached", s2)],
        "{out:?}"
    );
    assert_eq!(out[1].2, Some(s2_row), "its own row reported");
    let events = restored_events(&pool, s2).await;
    assert_eq!(events.len(), 1, "the root's re-attach audited: {events:?}");
    assert_eq!(events[0]["outcome"], "successor_already_attached");
    assert_eq!(events[0]["root_attached_now"], true);
}

/// A `valid_to` THAT WOULD NOT APPLY IS REFUSED. With the root's live row
/// made by name kept, a `valid_to` other than NULL or that row's end is
/// refused 22023, nothing written. CONTROL: NULL restores.
#[sqlx::test(migrations = "../../migrations")]
async fn a_valid_to_other_than_the_kept_roots_end_is_refused(pool: PgPool) {
    let (h, group) = attached_group_held(&pool, "Synthetic Restore Window Team").await;
    let [root, _, newest] = lineage(&pool, h, group, "g-job").await;
    assert_eq!(detach_from_role(&pool, root).await, 1, "root detached");
    attach_to_role(&pool, root).await;

    let before = footprint(&pool).await;
    assert_refused(
        &restore_until(&pool, "epigraph_maintenance", root, newest, Some("1 hour")).await,
        "22023",
        "would not apply",
        "a valid_to the kept root row does not end at",
    );
    assert_eq!(footprint(&pool).await, before, "nothing written");
    restore(&pool, root, newest).await.expect("CONTROL: NULL");
    assert_eq!(
        resolves(&pool, newest, group).await,
        (true, true),
        "CONTROL"
    );
}

/// A FINITE WINDOW ENDS THE SUCCESSOR WITH THE ROOT (264's documented
/// consequence). The verb attaches the root until `valid_to` and the
/// successor until the same instant; past it the successor is judged
/// exactly as the root is (`epigraph_role_agent_gate`), and inside it both
/// are members.
#[sqlx::test(migrations = "../../migrations")]
async fn a_finite_window_ends_the_successor_with_the_root(pool: PgPool) {
    let (h, group) = attached_group_held(&pool, "Synthetic Restore Finite Team").await;
    let [root, _, newest] = lineage(&pool, h, group, "g-job").await;
    assert_eq!(detach_from_role(&pool, root).await, 1, "root detached");

    let out = restore_until(&pool, "epigraph_maintenance", root, newest, Some("1 hour"))
        .await
        .expect("the restore");
    let names: Vec<&str> = out.iter().map(|(s, _, _)| s.as_str()).collect();
    assert_eq!(names.first(), Some(&"root_attached"), "{out:?}");
    assert_eq!(names.last(), Some(&"successor_attached"), "{out:?}");
    let root_row = out[0].2.expect("root row");
    let succ_row = out.last().expect("step").2.expect("successor row");
    let ends: (
        Option<chrono::DateTime<chrono::Utc>>,
        Option<chrono::DateTime<chrono::Utc>>,
    ) = sqlx::query_as(
        "SELECT (SELECT valid_to FROM role_agents WHERE id = $1), \
                    (SELECT valid_to FROM role_agents WHERE id = $2)",
    )
    .bind(root_row)
    .bind(succ_row)
    .fetch_one(&pool)
    .await
    .expect("ends");
    assert!(ends.0.is_some(), "the root's row is finite: {ends:?}");
    assert_eq!(ends.1, ends.0, "the successor's row ends with the root's");
    assert_eq!(resolves(&pool, newest, group).await, (true, true), "inside");

    let gate = |agent: Uuid| {
        let pool = pool.clone();
        async move {
            sqlx::query_as::<_, (bool, Option<String>, Option<String>)>(
                "SELECT may_run, role, reason \
                   FROM public.epigraph_role_agent_gate($1, now() + interval '2 hours')",
            )
            .bind(agent)
            .fetch_one(&pool)
            .await
            .expect("gate")
        }
    };
    assert_eq!(
        gate(newest).await,
        gate(root).await,
        "past the window the successor is judged as the root is"
    );
}
