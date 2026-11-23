//! Migration 267 (backlog 1777638e): edge, evidence and assessment BBAs move
//! from a `perspectives` pseudo-row onto `mass_functions`' own slot
//! (`slot_kind`, `slot_id`), the slot rows of `perspectives` are deleted and
//! `perspectives_not_bba_slot` keeps them gone. `docs/runbooks/267-undo.sql`
//! takes it back out.
//!
//! A fresh database has no legacy rows, so these tests migrate to the last
//! migration below 267 in the tree, seed the shapes the pre-267 writers left,
//! then apply 267:
//!
//! * `legacy_slot_rows_move_onto_the_slot_and_the_slot_perspectives_go`: each
//!   shape lands on the slot it names, a genuine perspective's BBA is left
//!   alone, and no slot-shaped perspective remains;
//! * the three fail-closed refusals (A1, A2, A3) and the body precondition,
//!   each of which changes nothing;
//! * `the_267_undo_returns_the_catalog_and_the_rows_below_267`: the undo
//!   restores the catalog below 267 exactly, puts the rows back on their
//!   re-created perspectives, and is idempotent.
//!
//! On the code before 267 every test fails: there `up_to(267)` is the head
//! below it, so the slot columns the assertions read do not exist.

#[path = "viewer_fixture.rs"]
mod fixture;

use sqlx::PgPool;
use std::collections::BTreeSet;
use uuid::Uuid;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

/// The last migration below 267 in this tree (computed, so a migration merged
/// below 267 later is part of "below" for the undo's catalog comparison).
fn below() -> i64 {
    MIGRATOR
        .migrations
        .iter()
        .map(|m| m.version)
        .filter(|v| *v < 267)
        .max()
        .expect("migrations below 267")
}

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
async fn try_migrate(
    pool: &PgPool,
    migrator: &sqlx::migrate::Migrator,
) -> Result<(), sqlx::migrate::MigrateError> {
    let mut conn = pool.acquire().await.expect("acquire");
    let out = migrator.run(&mut *conn).await;
    sqlx::query("RESET ALL")
        .execute(&mut *conn)
        .await
        .expect("RESET ALL");
    out
}

async fn migrate(pool: &PgPool, migrator: &sqlx::migrate::Migrator) {
    try_migrate(pool, migrator).await.expect("migrate");
}

async fn has_slot_columns(pool: &PgPool) -> bool {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.columns \
                         WHERE table_schema = 'public' AND table_name = 'mass_functions' \
                           AND column_name = 'slot_id')",
    )
    .fetch_one(pool)
    .await
    .expect("read the columns")
}

/// A perspective row as a pre-267 writer left it.
async fn perspective(pool: &PgPool, id: Uuid, name: &str, kind: Option<&str>, owner: Uuid) {
    sqlx::query(
        "INSERT INTO perspectives (id, name, perspective_type, owner_agent_id) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(id)
    .bind(name)
    .bind(kind)
    .bind(owner)
    .execute(pool)
    .await
    .expect("seed a perspective");
}

/// A BBA keyed `perspective_id = key`, as a pre-267 writer stored it.
async fn bba(
    pool: &PgPool,
    claim: Uuid,
    frame: Uuid,
    agent: Uuid,
    key: Option<Uuid>,
    method: &str,
    evidence: Option<Uuid>,
) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO mass_functions (claim_id, frame_id, source_agent_id, perspective_id, \
                                     masses, combination_method, evidence_id) \
         VALUES ($1, $2, $3, $4, '{\"0\": 0.6, \"0,1\": 0.4}'::jsonb, $5, $6) RETURNING id",
    )
    .bind(claim)
    .bind(frame)
    .bind(agent)
    .bind(key)
    .bind(method)
    .bind(evidence)
    .fetch_one(pool)
    .await
    .expect("seed a BBA")
}

async fn frame(pool: &PgPool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses) VALUES ($1, ARRAY['TRUE','FALSE']::text[]) \
         RETURNING id",
    )
    .bind(format!("m267-{}", Uuid::new_v4()))
    .fetch_one(pool)
    .await
    .expect("seed a frame")
}

/// Everything a legacy database below 267 can hold, by row.
struct Legacy {
    agent: Uuid,
    target: Uuid,
    edge: Uuid,
    legacy_edge: Uuid,
    ev1: Uuid,
    ev2: Uuid,
    assess_slot: Uuid,
    genuine: Uuid,
    orphan: Uuid,
    edge_row: Uuid,
    legacy_edge_row: Uuid,
    ev1_row: Uuid,
    ev2_row: Uuid,
    rest_row: Uuid,
    assess_row: Uuid,
    genuine_row: Uuid,
    unscoped_row: Uuid,
}

async fn seed_legacy(pool: &PgPool) -> Legacy {
    let (agent, _group) = fixture::seed_agent_with_group(pool, "m267").await;
    let source = fixture::seed_public_claim(pool, agent, "m267 source").await;
    let target = fixture::seed_public_claim(pool, agent, "m267 target").await;
    let f = frame(pool).await;
    let edge = fixture::seed_edge(pool, source, target).await;
    let legacy_edge = fixture::seed_edge(pool, target, source).await;
    let ev1 = fixture::seed_evidence(pool, target, "observation").await;
    let ev2 = fixture::seed_evidence(pool, target, "document").await;
    let assess_slot = Uuid::new_v4();
    let genuine = Uuid::new_v4();
    let orphan = Uuid::new_v4();

    // The edge factor's row (typed `edge`, id = the edge).
    perspective(pool, edge, "edge_factor", Some("edge"), agent).await;
    let edge_row = bba(pool, target, f, agent, Some(edge), "edge_factor", None).await;
    // A legacy edge row whose perspective carries another type (the edge
    // factor kept an existing row's type): keyed by the edge's id.
    perspective(
        pool,
        legacy_edge,
        "lens-that-was-there",
        Some("analytical"),
        agent,
    )
    .await;
    let legacy_edge_row = bba(
        pool,
        source,
        f,
        agent,
        Some(legacy_edge),
        "edge_factor",
        None,
    )
    .await;
    // Two evidence rows of ONE agent on one (claim, frame): they collide on
    // the old unique key once their perspective is NULL, so 267 must drop it
    // before it moves them.
    perspective(pool, ev1, "evidence_grounded", Some("evidence"), agent).await;
    perspective(pool, ev2, "evidence_grounded", Some("evidence"), agent).await;
    let ev1_row = bba(pool, target, f, agent, Some(ev1), "auto_wire", Some(ev1)).await;
    let ev2_row = bba(pool, target, f, agent, Some(ev2), "auto_wire", Some(ev2)).await;
    // A REST `/frames/:id/evidence` row another agent filed on ev1's slot
    // perspective: a `discount` label, but its key is an evidence row's id.
    let (other, _) = fixture::seed_agent_with_group(pool, "m267-rest").await;
    let rest_row = bba(pool, target, f, other, Some(ev1), "discount", None).await;
    // The assess route's slot (typed `evidence`, `discount`).
    perspective(
        pool,
        assess_slot,
        "evidence_grounded",
        Some("evidence"),
        agent,
    )
    .await;
    let assess_row = bba(pool, target, f, agent, Some(assess_slot), "discount", None).await;
    // A genuine perspective's BBA, and the agent's unscoped one: untouched.
    perspective(pool, genuine, "a lens", Some("analytical"), agent).await;
    let genuine_row = bba(pool, target, f, agent, Some(genuine), "Dempster", None).await;
    let unscoped_row = bba(pool, target, f, agent, None, "auto_wire", None).await;
    // A slot row whose BBAs are gone.
    perspective(pool, orphan, "edge_factor", Some("edge"), agent).await;

    Legacy {
        agent,
        target,
        edge,
        legacy_edge,
        ev1,
        ev2,
        assess_slot,
        genuine,
        orphan,
        edge_row,
        legacy_edge_row,
        ev1_row,
        ev2_row,
        rest_row,
        assess_row,
        genuine_row,
        unscoped_row,
    }
}

type Key = (Option<Uuid>, Option<String>, Option<Uuid>);

async fn key_of(pool: &PgPool, row: Uuid) -> Key {
    sqlx::query_as("SELECT perspective_id, slot_kind, slot_id FROM mass_functions WHERE id = $1")
        .bind(row)
        .fetch_one(pool)
        .await
        .expect("read a row's key")
}

fn slot(kind: &str, id: Uuid) -> Key {
    (None, Some(kind.to_string()), Some(id))
}

async fn perspective_ids(pool: &PgPool) -> BTreeSet<Uuid> {
    sqlx::query_scalar::<_, Uuid>("SELECT id FROM perspectives")
        .fetch_all(pool)
        .await
        .expect("read perspectives")
        .into_iter()
        .collect()
}

/// Every legacy shape lands on the slot it names; a genuine perspective's BBA
/// and the agent's unscoped BBA are untouched; every slot-shaped perspective
/// (the orphan included) is deleted and a new one is refused.
/// Mutations: dropping the old unique key AFTER the move instead of before
/// fails the migration (the two evidence rows collide); classifying by
/// `perspective_type` alone leaves `legacy_edge_row` on its perspective.
#[sqlx::test(migrations = false)]
async fn legacy_slot_rows_move_onto_the_slot_and_the_slot_perspectives_go(pool: PgPool) {
    migrate(&pool, &up_to(below())).await;
    let l = seed_legacy(&pool).await;
    migrate(&pool, &up_to(267)).await;
    assert!(has_slot_columns(&pool).await, "267 adds the slot columns");

    assert_eq!(key_of(&pool, l.edge_row).await, slot("edge", l.edge));
    assert_eq!(
        key_of(&pool, l.legacy_edge_row).await,
        slot("edge", l.legacy_edge),
        "keyed by the edge's id whatever its perspective's type"
    );
    assert_eq!(key_of(&pool, l.ev1_row).await, slot("evidence", l.ev1));
    assert_eq!(key_of(&pool, l.ev2_row).await, slot("evidence", l.ev2));
    assert_eq!(
        key_of(&pool, l.rest_row).await,
        slot("evidence", l.ev1),
        "an evidence row's id is an evidence slot whatever the label"
    );
    assert_eq!(
        key_of(&pool, l.assess_row).await,
        slot("assessment", l.assess_slot)
    );
    assert_eq!(
        key_of(&pool, l.genuine_row).await,
        (Some(l.genuine), None, None),
        "a genuine perspective's BBA stays on it"
    );
    assert_eq!(key_of(&pool, l.unscoped_row).await, (None, None, None));

    let left = perspective_ids(&pool).await;
    assert!(left.contains(&l.genuine), "the genuine perspective stays");
    for (what, id) in [
        ("edge", l.edge),
        ("legacy edge", l.legacy_edge),
        ("ev1", l.ev1),
        ("ev2", l.ev2),
        ("assessment", l.assess_slot),
        ("orphan", l.orphan),
    ] {
        assert!(!left.contains(&id), "the {what} slot row is deleted");
    }
    let typed: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM perspectives WHERE perspective_type IN ('edge', 'evidence')",
    )
    .fetch_one(&pool)
    .await
    .expect("count typed slot rows");
    assert_eq!(typed, 0, "no perspective row is typed edge or evidence");
    let refused = sqlx::query(
        "INSERT INTO perspectives (id, name, perspective_type, owner_agent_id) \
         VALUES ($1, 'edge_factor', 'edge', $2)",
    )
    .bind(Uuid::new_v4())
    .bind(l.agent)
    .execute(&pool)
    .await
    .expect_err("a new slot row is refused");
    assert!(
        refused.to_string().contains("perspectives_not_bba_slot"),
        "{refused}"
    );
    let on_target: i64 =
        sqlx::query_scalar("SELECT count(*) FROM mass_functions WHERE claim_id = $1")
            .bind(l.target)
            .fetch_one(&pool)
            .await
            .expect("count");
    assert_eq!(on_target, 7, "no BBA was lost or added");
}

/// `267` refused: the error names it, and nothing changed (no slot column,
/// the rows and perspectives as seeded).
async fn assert_refused(pool: &PgPool, needle: &str) {
    let before = perspective_ids(pool).await;
    let err = try_migrate(pool, &up_to(267))
        .await
        .expect_err("267 refuses");
    let text = format!("{err:?}");
    assert!(text.contains(needle), "refused for `{needle}`: {text}");
    assert!(
        !has_slot_columns(pool).await,
        "nothing changed: no slot column"
    );
    assert_eq!(
        perspective_ids(pool).await,
        before,
        "nothing changed: perspectives"
    );
}

/// A1: a BBA on an evidence-typed perspective with a label no evidence writer
/// stores is not guessed at.
#[sqlx::test(migrations = false)]
async fn an_unclassifiable_evidence_slot_row_refuses_267(pool: PgPool) {
    migrate(&pool, &up_to(below())).await;
    let l = seed_legacy(&pool).await;
    let f = frame(&pool).await;
    bba(&pool, l.target, f, l.agent, Some(l.ev1), "Dempster", None).await;
    assert_refused(&pool, "cannot be classified").await;
}

/// A2: a community membership names a slot row, which the DELETE would
/// cascade away.
#[sqlx::test(migrations = false)]
async fn a_community_membership_of_a_slot_row_refuses_267(pool: PgPool) {
    migrate(&pool, &up_to(below())).await;
    let l = seed_legacy(&pool).await;
    let community: Uuid =
        sqlx::query_scalar("INSERT INTO communities (name) VALUES ('m267') RETURNING id")
            .fetch_one(&pool)
            .await
            .expect("seed a community");
    sqlx::query("INSERT INTO community_members (community_id, perspective_id) VALUES ($1, $2)")
        .bind(community)
        .bind(l.orphan)
        .execute(&pool)
        .await
        .expect("seed a membership");
    assert_refused(&pool, "community membership").await;
}

/// A3: a BBA left on a perspective that still looks like a slot (keyed on an
/// edge's id with a label no edge writer stores).
#[sqlx::test(migrations = false)]
async fn a_slot_shaped_row_267_would_leave_behind_refuses_267(pool: PgPool) {
    migrate(&pool, &up_to(below())).await;
    let l = seed_legacy(&pool).await;
    let f = frame(&pool).await;
    bba(
        &pool,
        l.target,
        f,
        l.agent,
        Some(l.legacy_edge),
        "Dempster",
        None,
    )
    .await;
    assert_refused(&pool, "cannot be classified").await;
}

/// A4: an edge naming a slot row as a `perspective` endpoint (what a past
/// `dekg migrate` wrote from every BBA's perspective) would dangle.
#[sqlx::test(migrations = false)]
async fn an_edge_from_a_slot_row_refuses_267(pool: PgPool) {
    migrate(&pool, &up_to(below())).await;
    let l = seed_legacy(&pool).await;
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'perspective', $2, 'claim', 'CONTRIBUTES_TO')",
    )
    .bind(l.edge)
    .bind(l.target)
    .execute(&pool)
    .await
    .expect("seed a CONTRIBUTES_TO edge from the edge's slot row");
    assert_refused(&pool, "name a BBA slot perspective as an endpoint").await;
}

/// A5: a viewpoint somebody typed `edge` (`create_perspective` never checked
/// the type) is neither kept nor deleted.
#[sqlx::test(migrations = false)]
async fn a_viewpoint_typed_edge_refuses_267(pool: PgPool) {
    migrate(&pool, &up_to(below())).await;
    let l = seed_legacy(&pool).await;
    perspective(&pool, Uuid::new_v4(), "my edge lens", Some("edge"), l.agent).await;
    assert_refused(&pool, "are not BBA slot rows").await;
}

/// The body precondition: a re-bodied definer refuses 267.
#[sqlx::test(migrations = false)]
async fn a_re_bodied_definer_refuses_267(pool: PgPool) {
    migrate(&pool, &up_to(below())).await;
    let src: String = sqlx::query_scalar(
        "SELECT pg_get_functiondef('public.epigraph_cascade_delete_edge_bbas(uuid[], text)'\
         ::regprocedure)",
    )
    .fetch_one(&pool)
    .await
    .expect("read the body");
    let edited = src.replacen("BEGIN", "BEGIN\n    -- another migration's delta", 1);
    sqlx::raw_sql(&edited)
        .execute(&pool)
        .await
        .expect("re-body the definer");
    assert_refused(&pool, "epigraph_cascade_delete_edge_bbas is not the body").await;
}

fn repo_file(rel: &str) -> String {
    std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(rel),
    )
    .unwrap_or_else(|e| panic!("{rel}: {e}"))
}

/// The `public` catalog: relations, the two tables' columns, functions (whole
/// definition, owner and ACL), policies, triggers and constraints.
async fn catalog(pool: &PgPool) -> BTreeSet<String> {
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT 'rel ' || c.relname || ' ' || c.relkind::text \
           FROM pg_class c WHERE c.relnamespace = 'public'::regnamespace \
         UNION ALL \
         SELECT 'col ' || a.attrelid::regclass::text || '.' || a.attname || ' ' \
                || format_type(a.atttypid, a.atttypmod) \
           FROM pg_attribute a \
          WHERE a.attrelid IN ('public.mass_functions'::regclass, 'public.perspectives'::regclass) \
            AND a.attnum > 0 AND NOT a.attisdropped \
         UNION ALL \
         SELECT 'fn ' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ') ' \
                || CASE WHEN p.prokind IN ('f', 'p') THEN md5(pg_get_functiondef(p.oid)) \
                        ELSE md5(p.prosrc) END \
                || ' ' || p.proowner::regrole::text || ' ' \
                || COALESCE(p.proacl::text, '-') \
           FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace \
         UNION ALL \
         SELECT 'pol ' || c.relname || '.' || pol.polname \
           FROM pg_policy pol JOIN pg_class c ON c.oid = pol.polrelid \
          WHERE c.relnamespace = 'public'::regnamespace \
         UNION ALL \
         SELECT 'trg ' || c.relname || '.' || t.tgname \
           FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid \
          WHERE NOT t.tgisinternal AND c.relnamespace = 'public'::regnamespace \
         UNION ALL \
         SELECT 'con ' || c.relname || '.' || k.conname || ' ' || pg_get_constraintdef(k.oid) \
           FROM pg_constraint k JOIN pg_class c ON c.oid = k.conrelid \
          WHERE c.relnamespace = 'public'::regnamespace",
    )
    .fetch_all(pool)
    .await
    .expect("catalog");
    rows.into_iter().collect()
}

/// The undo restores the catalog below 267 exactly (the three definer bodies
/// byte for byte, the old unique key, no slot column, no CHECK, no new
/// definer), puts every moved row back on a re-created slot perspective of
/// the old type, and a second run changes nothing.
/// Mutation: an undo that leaves one predecessor body out, or re-adds the
/// unique key under another definition, shows in the catalog diff.
#[sqlx::test(migrations = false)]
async fn the_267_undo_returns_the_catalog_and_the_rows_below_267(pool: PgPool) {
    migrate(&pool, &up_to(below())).await;
    let before = catalog(&pool).await;
    let l = seed_legacy(&pool).await;
    migrate(&pool, &up_to(267)).await;
    let through = catalog(&pool).await;
    assert!(
        through
            .iter()
            .any(|e| e.starts_with("fn epigraph_edge_bbas_keyed(p_edge uuid)")),
        "CALIBRATION: 267 adds its definer"
    );

    let undo = repo_file("docs/runbooks/267-undo.sql");
    for run in ["first", "second"] {
        sqlx::raw_sql(&undo)
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("the {run} run of the undo applies: {e}"));
        let after = catalog(&pool).await;
        assert_eq!(
            after.symmetric_difference(&before).collect::<Vec<_>>(),
            Vec::<&String>::new(),
            "after the {run} run the catalog is exactly the one below 267"
        );
    }

    let keyed: Vec<(Uuid, Option<Uuid>, Option<String>)> = sqlx::query_as(
        "SELECT m.id, m.perspective_id, p.perspective_type \
           FROM mass_functions m LEFT JOIN perspectives p ON p.id = m.perspective_id \
          WHERE m.id = ANY($1) ORDER BY m.id",
    )
    .bind(vec![
        l.edge_row,
        l.legacy_edge_row,
        l.ev1_row,
        l.ev2_row,
        l.rest_row,
        l.assess_row,
        l.genuine_row,
    ])
    .fetch_all(&pool)
    .await
    .expect("read the restored keys");
    let mut expected = vec![
        (l.edge_row, Some(l.edge), Some("edge".to_string())),
        (
            l.legacy_edge_row,
            Some(l.legacy_edge),
            Some("edge".to_string()),
        ),
        (l.ev1_row, Some(l.ev1), Some("evidence".to_string())),
        (l.ev2_row, Some(l.ev2), Some("evidence".to_string())),
        (l.rest_row, Some(l.ev1), Some("evidence".to_string())),
        (
            l.assess_row,
            Some(l.assess_slot),
            Some("evidence".to_string()),
        ),
        (
            l.genuine_row,
            Some(l.genuine),
            Some("analytical".to_string()),
        ),
    ];
    expected.sort_by_key(|r| r.0);
    assert_eq!(
        keyed, expected,
        "every moved row is back on a perspective of its old type"
    );
}
