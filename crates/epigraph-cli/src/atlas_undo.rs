//! The operator undo of one Atlas apply run (backlog b3e39c55):
//! `atlas_meaning reverse` and `atlas_links reverse`.
//!
//! An `apply --apply` of either binary writes one `atlas_map_runs` row and its
//! levels and nothing else, so deleting that row (its levels go by migration
//! 210's `ON DELETE CASCADE`) is a complete undo, and the map's previous
//! finished run is served again. [`reverse_run`] does that delete the way the
//! other operator tools undo their writes, instead of a hand-run DELETE:
//!
//! * **One transaction, under the map's publish lock**
//!   (`AtlasMapRepository::lock_map_for_publish`, the key the nightly and the
//!   naming step publish under and the operator builds hold for their whole
//!   build), so no publish of the map interleaves with the checks and the
//!   delete. A nightly or naming pass that built from the reversed run then
//!   finds a different latest run when it publishes, and writes nothing.
//! * **Refusals** (nothing deleted): the map has no such run (another map's
//!   run included); the run is unfinished (a build is writing it); the run is
//!   not one this binary's `apply` writes (its `algo`, its `params` and the
//!   hierarchies of its stored levels must all be the binary's, and a run a
//!   nightly or naming pass derived from another run is refused); or a later
//!   run of the map names it as its source (`nightly_from_run`,
//!   `named_from_run`), so deleting it would not undo what that run carries
//!   forward.
//! * **Dry run by default.** Without `apply` the report says what the cascade
//!   deletes (the run's levels per hierarchy) and which run is served after,
//!   and nothing is written. With `apply` the delete and one `security_events`
//!   audit row ([`REVERSE_EVENT`]) commit together.

use anyhow::{bail, Context};
use chrono::Utc;
use epigraph_db::repos::atlas_map::{AtlasMap, MapRunForUndo};
use epigraph_db::{AtlasMapRepository, SecurityEventRepository, SecurityEventRow, Viewer};
use serde_json::{json, Value};
use sqlx::{Connection, PgConnection};
use uuid::Uuid;

use crate::atlas_links::build::HIERARCHIES_ALGO;
use crate::atlas_meaning::build::MEANING_ALGO;
use crate::atlas_meaning::tree::map_key;
use crate::operator::client_scope::Operator;

/// The `security_events.event_type` of an applied reverse.
pub const REVERSE_EVENT: &str = "atlas.map_run_reversed";

/// The `params` keys a run derived from another run carries (the nightly's
/// and the naming step's), naming its source run.
const SOURCE_KEYS: [&str; 2] = ["nightly_from_run", "named_from_run"];

/// Which binary's apply runs a reverse may delete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyKind {
    /// `atlas_meaning apply`: one run holding the meaning hierarchy only.
    Meaning,
    /// `atlas_links apply`: one run holding both hierarchies.
    Links,
}

impl ApplyKind {
    /// The binary's name.
    #[must_use]
    pub fn tool(self) -> &'static str {
        match self {
            Self::Meaning => "atlas_meaning",
            Self::Links => "atlas_links",
        }
    }

    /// The `atlas_map_runs.algo` the binary's apply writes.
    #[must_use]
    pub fn algo(self) -> &'static str {
        match self {
            Self::Meaning => MEANING_ALGO,
            Self::Links => HIERARCHIES_ALGO,
        }
    }

    /// Why `run` is not a run this binary's apply wrote, or `None` when it is.
    #[must_use]
    pub fn mismatch(self, run: &MapRunForUndo) -> Option<String> {
        if run.algo != self.algo() {
            return Some(format!(
                "its algo is {:?}, not {:?} (the run {} apply writes)",
                run.algo,
                self.algo(),
                self.tool()
            ));
        }
        if let Some(k) = SOURCE_KEYS.iter().find(|k| run.params.get(**k).is_some()) {
            return Some(format!(
                "its params name a source run ({k}): a nightly or naming pass derived it from \
                 another run, it is not an apply"
            ));
        }
        let shape_ok = match self {
            Self::Meaning => {
                run.params.get("hierarchy") == Some(&json!("meaning")) && run.links_levels == 0
            }
            Self::Links => run.params.get("hierarchies") == Some(&json!(["meaning", "links"])),
        };
        if !shape_ok || run.meaning_levels == 0 {
            return Some(format!(
                "its params and stored levels (meaning {}, links {}) are not those of an {} apply",
                run.meaning_levels,
                run.links_levels,
                self.tool()
            ));
        }
        None
    }
}

/// Undo one apply run of `map` (see the module documentation). `conn` is the
/// maintenance connection and `viewer` its bypass viewer. With `apply`
/// false, nothing is written.
///
/// Returns the report: the run, what the cascade deletes, the run served
/// after, and (applied) the audit row's id.
///
/// # Errors
/// Every refusal in the module documentation, or a database error; nothing
/// is deleted.
pub async fn reverse_run(
    conn: &mut PgConnection,
    viewer: &Viewer,
    map: AtlasMap,
    run_id: Uuid,
    kind: ApplyKind,
    apply: bool,
) -> anyhow::Result<Value> {
    let key = map_key(map);
    let mut tx = conn
        .begin()
        .await
        .context("begin the reverse transaction")?;
    AtlasMapRepository::lock_map_for_publish(&mut tx, map).await?;
    let Some(run) = AtlasMapRepository::run_for_undo(&mut tx, viewer, map, run_id).await? else {
        bail!(
            "map {key} has no run {run_id} (it may be another map's run, or already deleted); \
             nothing was deleted"
        );
    };
    let Some(finished_at) = run.finished_at else {
        bail!(
            "run {run_id} of map {key} is unfinished (a build is writing it); nothing was deleted"
        );
    };
    if let Some(why) = kind.mismatch(&run) {
        bail!(
            "run {run_id} of map {key} is not one `{} apply` wrote: {why}; nothing was deleted",
            kind.tool()
        );
    }
    if !run.dependents.is_empty() {
        bail!(
            "later runs of map {key} were built from run {run_id} (a nightly refresh or a naming \
             pass): {:?}; deleting it would not undo what they carry forward. Nothing was deleted",
            run.dependents
        );
    }

    let served_now = run.served_now == Some(run_id);
    let snapshot = json!({
        "run_id": run_id,
        "algo": run.algo,
        "created_at": run.created_at,
        "finished_at": finished_at,
        "level_count": run.level_count,
        "levels": {"meaning": run.meaning_levels, "links": run.links_levels},
        "params": run.params,
    });
    let mut report = json!({
        "map": key,
        "run_id": run_id,
        "applied": false,
        "run": snapshot,
        "deletes": {
            "runs": 1,
            "levels": run.meaning_levels + run.links_levels,
        },
        "served_now": served_now,
        "served_after": if served_now { json!(run.served_after) } else { json!(run.served_now) },
    });
    if served_now && run.served_after.is_none() {
        report["note"] = json!(
            "the map has no other finished run: once this one is deleted the Atlas serves nothing \
             for it, and the nightly does not refresh it until an operator build writes a run"
        );
    }
    if !apply {
        tx.rollback().await.context("roll back the dry run")?;
        return Ok(report);
    }

    let deleted = AtlasMapRepository::delete_run(&mut tx, map, run_id).await?;
    if deleted != 1 {
        bail!("deleted {deleted} runs, not 1; rolled back");
    }
    let session_user: String = sqlx::query_scalar("SELECT session_user::text")
        .fetch_one(&mut *tx)
        .await
        .context("read the session user")?;
    let op = Operator::of_this_process(session_user);
    let audit_event_id = Uuid::new_v4();
    // Agent-less: readable by privileged and admin sessions only. The row
    // names a team map's run; the operator is in `details`.
    SecurityEventRepository::log_conn(
        &mut tx,
        &SecurityEventRow {
            id: audit_event_id,
            event_type: REVERSE_EVENT.to_string(),
            agent_id: None,
            success: Some(true),
            details: json!({
                "tool": kind.tool(),
                "command": "reverse",
                "cli_version": env!("CARGO_PKG_VERSION"),
                "operator": {
                    "session_user": op.session_user,
                    "os_user": op.os_user,
                    "os_user_source": "environment (SUDO_USER, USER, LOGNAME): advisory, \
                                       settable by the caller",
                    "process_uid": op.process_uid,
                    "process_user": op.process_user,
                    "login_uid": op.login_uid,
                    "login_user": op.login_user,
                },
                "map": report["map"],
                "run": report["run"],
                "deletes": report["deletes"],
                "served_now": served_now,
                "served_after": report["served_after"],
            }),
            ip_address: None,
            user_agent: None,
            correlation_id: None,
            created_at: Utc::now(),
        },
    )
    .await
    .context("write the audit row")?;
    tx.commit().await.context("commit the reverse")?;
    report["applied"] = json!(true);
    report["audit_event_id"] = json!(audit_event_id);
    Ok(report)
}
