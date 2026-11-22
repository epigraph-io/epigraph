//! `docs/runbooks/263-undo.sql`, the rollback of migration 263 (person-facing
//! keyless team groups and consented invitations).
//!
//! [`the_263_undo_returns_the_catalog_below_263`]: on a database migrated
//! through 263, the undo leaves the `public` catalog (relations, functions
//! with body, owner and ACL, policies, triggers, constraints) exactly as it
//! was below 263, and a second run changes nothing. The catalog compares
//! whole function definitions by md5, so this also pins that the undo
//! restores 176's two team-group guards byte for byte, which 263 re-states.
//! [`the_263_undo_keeps_the_groups_and_memberships_it_made`]: what the undo
//! leaves behind is ordinary verb-made state the 164 verbs still manage.
//! [`the_263_undo_refuses_over_a_later_guard_body`]: the undo does not
//! silently revert a guard that a later migration re-bodied.

#[path = "viewer_fixture.rs"]
mod fixture;

use sqlx::PgPool;
use std::collections::BTreeSet;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

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

/// The `public` catalog by name: relations, `agents` columns, functions (body,
/// owner and ACL), policies, triggers and constraints. A function is hashed
/// by its whole definition (`pg_get_functiondef`: SECURITY DEFINER, the pinned
/// `search_path`, volatility and body), not its body alone, so an undo that
/// restored 206's body without its definer attributes would be caught.
async fn catalog(pool: &PgPool) -> BTreeSet<String> {
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT 'rel ' || c.relname || ' ' || c.relkind::text \
           FROM pg_class c WHERE c.relnamespace = 'public'::regnamespace \
         UNION ALL \
         SELECT 'col agents.' || a.attname || ' ' || format_type(a.atttypid, a.atttypmod) \
           FROM pg_attribute a \
          WHERE a.attrelid = 'public.agents'::regclass AND a.attnum > 0 AND NOT a.attisdropped \
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
         SELECT 'con ' || c.relname || '.' || k.conname \
           FROM pg_constraint k JOIN pg_class c ON c.oid = k.conrelid \
          WHERE c.relnamespace = 'public'::regnamespace",
    )
    .fetch_all(pool)
    .await
    .expect("catalog");
    rows.into_iter().collect()
}

fn repo_file(rel: &str) -> String {
    std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(rel),
    )
    .unwrap_or_else(|e| panic!("{rel}: {e}"))
}

/// The undo returns the catalog to what it was below 263, and is idempotent.
/// Mutation: the undo's re-statement of either 176 guard dropped, or edited
/// by one character -> that guard's md5 differs from the one below 263 and is
/// named in the diff.
#[sqlx::test(migrations = false)]
async fn the_263_undo_returns_the_catalog_below_263(pool: PgPool) {
    migrate(&pool, &up_to(262)).await;
    let before = catalog(&pool).await;
    migrate(&pool, &up_to(263)).await;
    let through = catalog(&pool).await;
    let added: BTreeSet<&String> = through.difference(&before).collect();
    let removed: BTreeSet<&String> = before.difference(&through).collect();
    for guard in [
        "fn epigraph_team_group_roster_verbs_only()",
        "fn epigraph_team_group_row_verbs_only()",
    ] {
        assert!(
            added.iter().any(|e| e.starts_with(guard))
                && removed.iter().any(|e| e.starts_with(guard)),
            "CALIBRATION: 263 re-states {guard}: added {added:?} removed {removed:?}"
        );
    }
    assert_eq!(
        removed.len(),
        2,
        "CALIBRATION: the only entries 263 changes are the two guard bodies: {removed:?}"
    );
    for new in [
        "rel group_invitations r",
        "rel team_group_roster_grants r",
        "rel person_team_groups r",
        "fn epigraph_accept_group_invitation(p_invitation uuid)",
        "pol group_invitations.group_invitations_privileged_read",
    ] {
        assert!(
            added.iter().any(|e| e.starts_with(new)),
            "CALIBRATION: 263 adds {new}: {added:?}"
        );
    }

    let undo = repo_file("docs/runbooks/263-undo.sql");
    for run in ["first", "second"] {
        sqlx::raw_sql(&undo)
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("the {run} run of the undo applies: {e}"));
        let after = catalog(&pool).await;
        assert_eq!(
            after.symmetric_difference(&before).collect::<Vec<_>>(),
            Vec::<&String>::new(),
            "the {run} run of the undo returns the catalog to below 263"
        );
    }
}

/// One statement on an application-role transaction stamped as `who`,
/// committed; the uuid it returns.
async fn as_app(pool: &PgPool, who: uuid::Uuid, sql: &str, arg: Option<uuid::Uuid>) -> uuid::Uuid {
    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("SET LOCAL SESSION AUTHORIZATION epigraph_app")
        .execute(&mut *tx)
        .await
        .expect("app role");
    sqlx::query("SELECT set_config('epigraph.principal_id', $1, true)")
        .bind(who.to_string())
        .execute(&mut *tx)
        .await
        .expect("stamp");
    let mut q = sqlx::query_scalar::<_, uuid::Uuid>(sql);
    if let Some(x) = arg {
        q = q.bind(x);
    }
    let id = q
        .fetch_one(&mut *tx)
        .await
        .unwrap_or_else(|e| panic!("{sql}: {e}"));
    tx.commit().await.expect("commit");
    id
}

/// After the undo, a group a Person made and the membership an acceptance
/// wrote are still there, and the operator's verb still removes the member.
#[sqlx::test(migrations = "../../migrations")]
async fn the_263_undo_keeps_the_groups_and_memberships_it_made(pool: PgPool) {
    let a = fixture::seed_human_operator(&pool, "undo-a").await.0;
    let b = fixture::seed_human_operator(&pool, "undo-b").await.0;
    let group = as_app(
        &pool,
        a,
        "SELECT public.epigraph_person_create_team_group('Synthetic Undo Team', 'undo')",
        None,
    )
    .await;
    // The invite binds two ids; written out rather than widening `as_app`.
    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("SET LOCAL SESSION AUTHORIZATION epigraph_app")
        .execute(&mut *tx)
        .await
        .expect("app role");
    sqlx::query("SELECT set_config('epigraph.principal_id', $1, true)")
        .bind(a.to_string())
        .execute(&mut *tx)
        .await
        .expect("stamp");
    let invitation: uuid::Uuid =
        sqlx::query_scalar("SELECT public.epigraph_invite_to_team_group($1, $2, 'writer', NULL)")
            .bind(group)
            .bind(b)
            .fetch_one(&mut *tx)
            .await
            .expect("invite");
    tx.commit().await.expect("commit");
    as_app(
        &pool,
        b,
        "SELECT out_membership_id FROM public.epigraph_accept_group_invitation($1)",
        Some(invitation),
    )
    .await;

    sqlx::raw_sql(&repo_file("docs/runbooks/263-undo.sql"))
        .execute(&pool)
        .await
        .expect("undo");

    let mut live: Vec<(uuid::Uuid, String)> = sqlx::query_as(
        "SELECT agent_id, role::text FROM group_memberships \
          WHERE group_id = $1 AND revoked_at IS NULL",
    )
    .bind(group)
    .fetch_all(&pool)
    .await
    .expect("rows");
    live.sort_by(|x, y| x.1.cmp(&y.1));
    assert_eq!(
        live,
        vec![(a, "admin".to_string()), (b, "writer".to_string())]
    );
    let mut m = pool.acquire().await.expect("acquire");
    sqlx::query("SET SESSION AUTHORIZATION epigraph_maintenance")
        .execute(&mut *m)
        .await
        .expect("maintenance");
    let applied: bool = sqlx::query_scalar(
        "SELECT out_applied FROM public.epigraph_team_group_remove_member($1, $2, 'undo test')",
    )
    .bind(group)
    .bind(b)
    .fetch_one(&mut *m)
    .await
    .expect("the 164 verb still manages the group");
    sqlx::query("RESET SESSION AUTHORIZATION")
        .execute(&mut *m)
        .await
        .expect("reset");
    assert!(applied);
}

/// The undo refuses (55000, nothing changed) when either guard carries a body
/// that is neither 263's nor 176's, as after a later migration re-bodied it;
/// re-stating 176's text over it would silently drop that migration's change.
/// Mutation: the undo's precondition block deleted -> the undo applies and
/// this test fails on the first assertion.
#[sqlx::test(migrations = false)]
async fn the_263_undo_refuses_over_a_later_guard_body(pool: PgPool) {
    migrate(&pool, &up_to(263)).await;
    // A "later migration" re-bodies the group-row guard: 263's body with one
    // added comment line, which changes the md5 and nothing else.
    let later_src: String = sqlx::query_scalar(
        "SELECT prosrc FROM pg_proc \
          WHERE oid = 'public.epigraph_team_group_row_verbs_only()'::regprocedure",
    )
    .fetch_one(&pool)
    .await
    .expect("263's group-row guard body");
    let later_src = format!("{later_src}-- a later migration's change\n");
    sqlx::raw_sql(&format!(
        "CREATE OR REPLACE FUNCTION public.epigraph_team_group_row_verbs_only() \
         RETURNS trigger LANGUAGE plpgsql SET search_path = public, pg_temp \
         AS $later${later_src}$later$"
    ))
    .execute(&pool)
    .await
    .expect("re-body the guard");
    let before = catalog(&pool).await;

    let mut conn = pool.acquire().await.expect("acquire");
    let r = sqlx::raw_sql(&repo_file("docs/runbooks/263-undo.sql"))
        .execute(&mut *conn)
        .await;
    // The undo's BEGIN is left aborted on this connection; end it.
    sqlx::query("ROLLBACK")
        .execute(&mut *conn)
        .await
        .expect("end the aborted undo transaction");
    drop(conn);
    let code = r.as_ref().err().and_then(|e| {
        e.as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .map(|c| c.to_string())
    });
    assert_eq!(code.as_deref(), Some("55000"), "{r:?}");
    assert!(
        format!("{r:?}").contains("epigraph_team_group_row_verbs_only is neither 263's body"),
        "{r:?}"
    );
    // The catalog is exactly what it was before the undo ran.
    let after = catalog(&pool).await;
    assert_eq!(
        after.symmetric_difference(&before).collect::<Vec<_>>(),
        Vec::<&String>::new(),
        "the refused undo changed nothing"
    );
}
