//! `epigraph-operator`: the reviewed, in-repo tool for the one-time operator
//! ownership backfill that migration 102 left out of scope.
//!
//! Three subcommands, each dry-run by default:
//!
//! * `link-retired` — call `epigraph_link_retired_agent` for a list of
//!   historical agent identities, so the operator OWNS their claims while the
//!   identities gain zero write authority (102 section 7).
//! * `reown-claims` — move an explicit list of claims (and every row the
//!   tenancy trigger cascades from them) into the operator's personal group,
//!   under a manifest written and fsynced BEFORE the first write.
//! * `reown-reverse` — restore every row a manifest names to the owner it
//!   recorded.
//!
//! It follows the `retire_match_candidates` precedent: production graph writes
//! go through reviewed code, not ad-hoc SQL, and the operator runs it, never an
//! agent.
//!
//! # The connection is a maintenance DSN, named explicitly
//!
//! [`connect`] reads [`DSN_ENV`] and nothing else. It never falls back to
//! `DATABASE_URL` or `MAINTENANCE_DATABASE_URL`: an inherited application DSN
//! is exactly how a corpus-wide write ends up on a connection that RLS filters
//! to nothing and exits 0. Having connected, it REFUSES unless
//! `pg_has_role(session_user, 'epigraph_maintenance', 'MEMBER')` is true.
//! `session_user`, not `current_user`, because that is what
//! `epigraph_bypass()` reads.
//!
//! # Why the pool is built by `ScopedPool::connect_with_options`
//!
//! `crates/epigraph-db/tests/no_unmaintained_dsn.rs` keys on pool construction
//! spellings. This module builds through a spelling that lint recognises as a
//! maintenance constructor rather than a bare `PgPool`, so the ratchet keeps
//! seeing it. The privilege check here is stricter than
//! `epigraph_db::assert_maintenance_privilege` (which is conditioned on row
//! security being active): it is unconditional.

pub mod link;
pub mod manifest;
pub mod reown;
pub mod reverse;
pub mod tables;

use anyhow::{anyhow, bail, Context};
use sqlx::PgConnection;
use std::path::Path;
use uuid::Uuid;

/// The environment variable that carries this tool's maintenance DSN.
///
/// Its own name, on purpose: nothing else in the tree reads it, so an
/// environment that merely inherited an application or maintenance DSN from a
/// sibling job cannot point this tool at a database by accident.
pub const DSN_ENV: &str = "EPIGRAPH_OPERATOR_MAINTENANCE_DSN";

/// The world group: public, owned by no one.
pub const WORLD: Uuid = Uuid::nil();

/// Migration 074's seed group (`00000000-0000-0000-0000-00000000dead`).
pub const SEED: Uuid = Uuid::from_u128(0xdead);

/// A maintenance pool, held for the life of the process.
pub struct OperatorDb {
    scoped: epigraph_db::ScopedPool,
    /// `session_user` as the server reported it at connect time.
    pub session_user: String,
}

impl OperatorDb {
    /// The pool every statement runs on.
    #[must_use]
    pub const fn pool(&self) -> &sqlx::PgPool {
        self.scoped.inner()
    }
}

/// Connect on [`DSN_ENV`] and refuse a non-maintenance role.
///
/// # Errors
/// [`DSN_ENV`] unset or empty; the connection fails; or `session_user` is not a
/// member of `epigraph_maintenance`.
pub async fn connect() -> anyhow::Result<OperatorDb> {
    let url = std::env::var(DSN_ENV)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .ok_or_else(|| {
            anyhow!(
                "{DSN_ENV} is not set. epigraph-operator writes ownership across the corpus and \
                 needs an explicit maintenance DSN in that variable. It never falls back to \
                 DATABASE_URL or MAINTENANCE_DATABASE_URL."
            )
        })?;
    let scoped = epigraph_db::ScopedPool::connect_with_options(
        &url,
        epigraph_db::SessionGucMode::Session,
        epigraph_db::ScopedPoolOptions {
            max_connections: 2,
            ..Default::default()
        },
    )
    .await
    .map_err(|e| anyhow!("connecting on {DSN_ENV}: {e}"))?;
    let mut conn = scoped.inner().acquire().await?;
    let session_user = refuse_non_maintenance(&mut conn).await?;
    drop(conn);
    Ok(OperatorDb {
        scoped,
        session_user,
    })
}

/// Refuse unless `session_user` is a member of `epigraph_maintenance`.
///
/// Returns the session user's name.
///
/// # Errors
/// The role is not a member, the role `epigraph_maintenance` does not exist, or
/// the query fails.
pub async fn refuse_non_maintenance(conn: &mut PgConnection) -> anyhow::Result<String> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance')",
    )
    .fetch_one(&mut *conn)
    .await?;
    if !exists {
        bail!(
            "role epigraph_maintenance does not exist on this cluster; refusing. \
             epigraph-operator runs only as a member of that role."
        );
    }
    let (user, member): (String, bool) = sqlx::query_as(
        "SELECT session_user::text, pg_has_role(session_user, 'epigraph_maintenance', 'MEMBER')",
    )
    .fetch_one(&mut *conn)
    .await?;
    if !member {
        bail!(
            "session_user {user} is not a member of epigraph_maintenance; refusing. \
             {DSN_ENV} must name a maintenance login. On an application role every read here \
             is filtered by row security and every write matches nothing."
        );
    }
    Ok(user)
}

/// One UUID per line; blank lines and `#` comments ignored; duplicates dropped
/// with order kept.
///
/// # Errors
/// The file cannot be read, or a line is not a UUID.
pub fn read_ids_file(path: &Path) -> anyhow::Result<Vec<Uuid>> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let id = Uuid::parse_str(line)
            .with_context(|| format!("{}:{}: not a UUID: {line:?}", path.display(), n + 1))?;
        if seen.insert(id) {
            out.push(id);
        }
    }
    Ok(out)
}

/// The operator's personal group, refusing anything that is not one the
/// operator itself created.
///
/// The same test `epigraph_operator_actor` and the two link functions apply
/// (migration 102 section 3): a group carrying the operator's `did_key` that
/// someone else created is a squat, not the operator's group.
///
/// # Errors
/// No such group, or the group is not `kind = 'personal'` created by the
/// operator.
pub async fn operator_group(conn: &mut PgConnection, operator: Uuid) -> anyhow::Result<Uuid> {
    let row: Option<(Uuid, String, Option<Uuid>)> = sqlx::query_as(
        "SELECT id, kind::text, created_by_agent_id FROM groups \
          WHERE did_key = 'did:epigraph:personal:' || $1::text",
    )
    .bind(operator)
    .fetch_optional(&mut *conn)
    .await?;
    let Some((id, kind, creator)) = row else {
        bail!(
            "operator {operator} has no personal group (did:epigraph:personal:{operator}); \
             link an agent to it first, which creates it"
        );
    };
    if kind != "personal" || creator != Some(operator) {
        bail!(
            "the group {id} carrying did:epigraph:personal:{operator} is kind={kind} created by \
             {creator:?}, not a personal group created by the operator; refusing to use it as \
             the target"
        );
    }
    Ok(id)
}

/// The author's OWN personal group, by the same creator test, if it has one.
///
/// # Errors
/// The query fails.
pub async fn authors_personal_group(
    conn: &mut PgConnection,
    author: Uuid,
) -> anyhow::Result<Option<Uuid>> {
    Ok(sqlx::query_scalar(
        "SELECT id FROM groups \
          WHERE did_key = 'did:epigraph:personal:' || $1::text \
            AND kind = 'personal' AND created_by_agent_id = $1",
    )
    .bind(author)
    .fetch_optional(&mut *conn)
    .await?)
}

/// The operator an agent's `operator_links` row names, retired or not.
///
/// Read through `epigraph_operator_of_author`, the same definer read the
/// ownership gate's TARGET side uses, so this tool and the gate cannot disagree
/// about who owns an author's claims.
///
/// # Errors
/// The query fails.
pub async fn operator_of_author(
    conn: &mut PgConnection,
    agent: Uuid,
) -> anyhow::Result<Option<Uuid>> {
    Ok(
        sqlx::query_scalar("SELECT operator_id FROM public.epigraph_operator_of_author($1)")
            .bind(agent)
            .fetch_optional(&mut *conn)
            .await?,
    )
}
