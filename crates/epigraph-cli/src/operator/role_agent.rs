//! `role-attach` and `role-detach`: attach an agent identity to a platform
//! role (migration 166's `role_agents`) or detach it, on the maintenance DSN,
//! through the two maintenance-only definers
//! `epigraph_attach_agent_to_role(text, uuid, timestamptz, timestamptz, text)`
//! and `epigraph_detach_agent_from_role(text, uuid, text)`.
//!
//! Both are security acts. An attachment RESTRICTS the agent (166: it writes
//! nothing while its own human does not hold the role, `ROL01`), and, where
//! the role is bound to a group in 179's `attached_agents` mode, GRANTS it the
//! group. An attach also FOLLOWS THE LINEAGE: the table's trigger attaches
//! every registered successor of the identity (`agent_succession`), each copy
//! naming the row of the identity it succeeded (195). A detach is the
//! operator's cut-off: it is final per row, STICKY PER IDENTITY (195: no
//! succession copy admits a detached identity again, only an attachment made
//! by name), and it cuts off the copies chained through it and the
//! successors below it that hold no live attachment made by name.
//!
//! What this module adds to a hand-run `SELECT` of the definer:
//!
//! * a DRY RUN by default: the definer runs in one transaction that is rolled
//!   back (its `role_agents` rows and its `platform.role_agent_*` audit rows
//!   with it) unless `--apply` is given, so a dry run prints exactly what the
//!   database decided;
//! * the lineage effect, read inside that transaction: every succession copy
//!   the attach wrote (`COPY` lines, the whole `inherited_from` chain, not
//!   only the copies naming the new row), or every row the detach ended
//!   (`DETACHED` lines);
//! * the role-derived memberships (`epigraph_role_derived_memberships`, the
//!   viewer's own rule) of every identity the act can change, read before and
//!   after it in the same transaction: the agent, every registered successor
//!   of it (transitively), and every holder of a copy chained from one of its
//!   rows for the role. Each is printed `GAINED`, `LOST` or `KEPT`.
//! * checks that can be made before connecting: the role key's shape, a
//!   non-blank reason, and a window that ends after it starts.
//!
//! Every rule stays in the database (`ROL02`: no human or role node, no
//! overlapping window, no back-dating; the definer's own `22004`), and the
//! table's trigger writes the audit rows: one `platform.role_agent_attached`
//! per row an attach writes (copies included) and one
//! `platform.role_agent_detached` per row a detach ends, each naming the
//! writing login (`attached_by` / `detached_by`) and the reason. The
//! transaction also carries this process's identity in
//! `epigraph.operator_actor`, as the group verbs' does
//! (`team_group::begin_audited`); 166's audit trigger does not read it.

use anyhow::bail;
use chrono::{DateTime, Utc};
use sqlx::PgConnection;
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

/// Refuse a role key that is not `role:<lowercase-key>`, a blank reason, and
/// a window that does not end after it starts, before any connection.
///
/// # Errors
/// Any of the three.
pub fn validate(
    role: &str,
    reason: &str,
    valid_from: Option<DateTime<Utc>>,
    valid_to: Option<DateTime<Utc>>,
) -> anyhow::Result<()> {
    if !super::custodian::is_role_key(role) {
        bail!("--role {role:?} is not a role key (role:<lowercase-key>); nothing was done");
    }
    if reason.trim().is_empty() {
        bail!("--reason must say why (it is recorded in the audit row); nothing was done");
    }
    if let (Some(from), Some(to)) = (valid_from, valid_to) {
        if to <= from {
            bail!("--valid-to {to} is not after --valid-from {from}; nothing was done");
        }
    }
    Ok(())
}

/// One `role_agents` row, as printed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentRow {
    pub id: Uuid,
    pub agent: Uuid,
    /// The row this one was copied through (`None`: made by name).
    pub inherited_from: Option<Uuid>,
    pub valid_from: String,
    /// `None`: open-ended.
    pub valid_to: Option<String>,
}

/// How one derived membership changed across the act.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Change {
    Gained,
    Lost,
    Kept,
}

impl Change {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Change::Gained => "GAINED",
            Change::Lost => "LOST",
            Change::Kept => "KEPT",
        }
    }
}

/// One role-derived membership of an affected identity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct MembershipChange {
    pub agent: Uuid,
    pub group: Uuid,
    /// `reader` or `writer`.
    pub role: String,
    pub change: Change,
}

/// What an attach or a detach did (rolled back unless `applied`).
#[derive(Debug, Clone, Default)]
pub struct Outcome {
    /// Attach: the row made by name. Detach: unused.
    pub attachment: Option<Uuid>,
    /// Attach: every succession copy the follow wrote, chained. Detach:
    /// every row the detach ended.
    pub rows: Vec<AttachmentRow>,
    /// The derived memberships of every affected identity, before vs after.
    pub memberships: Vec<MembershipChange>,
    /// `false` for a dry run: nothing was committed.
    pub applied: bool,
}

/// The identities an act on `(role, agent)` can change: the agent, every
/// registered successor of it (`agent_succession`, transitively: a detach
/// cuts off successors with no live attachment made by name, and an attach
/// copies onto every one of them), and every holder of a copy chained from
/// one of the agent's rows for `role`. Read on a maintenance session
/// (`agent_succession` and `role_agents` are FORCE RLS; any other session
/// reads no row).
async fn affected_agents(
    conn: &mut PgConnection,
    role: &str,
    agent: Uuid,
) -> anyhow::Result<Vec<Uuid>> {
    let rows: Vec<Uuid> = sqlx::query_scalar(
        "WITH RECURSIVE successors(agent_id) AS ( \
             SELECT $2::uuid \
             UNION \
             SELECT s.child_agent_id FROM public.agent_succession s \
               JOIN successors p ON s.parent_agent_id = p.agent_id \
         ), \
         copies(id, agent_id) AS ( \
             SELECT r.id, r.agent_id FROM public.role_agents r \
              WHERE r.role = $1 AND r.agent_id = $2 \
             UNION \
             SELECT r.id, r.agent_id FROM public.role_agents r \
               JOIN copies c ON r.inherited_from = c.id \
         ) \
         SELECT agent_id FROM successors \
         UNION \
         SELECT agent_id FROM copies \
         ORDER BY 1",
    )
    .bind(role)
    .bind(agent)
    .fetch_all(&mut *conn)
    .await?;
    Ok(rows)
}

/// `(agent, group, role)` of every role-derived membership of `agents` at
/// this statement's clock (the viewer's rule; a membership the act
/// started or ended at the transaction's `now()` is counted).
async fn derived(
    conn: &mut PgConnection,
    agents: &[Uuid],
) -> anyhow::Result<BTreeSet<(Uuid, Uuid, String)>> {
    let rows: Vec<(Uuid, Uuid, String)> = sqlx::query_as(
        "SELECT a.agent_id, d.group_id, d.role \
           FROM unnest($1::uuid[]) AS a(agent_id) \
          CROSS JOIN LATERAL public.epigraph_role_derived_memberships( \
                   a.agent_id, clock_timestamp()) d",
    )
    .bind(agents)
    .fetch_all(&mut *conn)
    .await?;
    Ok(rows.into_iter().collect())
}

fn diff(
    before: &BTreeSet<(Uuid, Uuid, String)>,
    after: &BTreeSet<(Uuid, Uuid, String)>,
) -> Vec<MembershipChange> {
    let mut out: BTreeMap<(Uuid, Uuid, String), Change> = BTreeMap::new();
    for k in before.union(after) {
        let change = match (before.contains(k), after.contains(k)) {
            (false, true) => Change::Gained,
            (true, false) => Change::Lost,
            _ => Change::Kept,
        };
        out.insert(k.clone(), change);
    }
    out.into_iter()
        .map(|((agent, group, role), change)| MembershipChange {
            agent,
            group,
            role,
            change,
        })
        .collect()
}

type RawRow = (Uuid, Uuid, Option<Uuid>, String, Option<String>);

fn rows_of(raw: Vec<RawRow>) -> Vec<AttachmentRow> {
    raw.into_iter()
        .map(
            |(id, agent, inherited_from, valid_from, valid_to)| AttachmentRow {
                id,
                agent,
                inherited_from,
                valid_from,
                valid_to,
            },
        )
        .collect()
}

async fn finish(tx: sqlx::Transaction<'_, sqlx::Postgres>, apply: bool) -> anyhow::Result<()> {
    if apply {
        tx.commit().await?;
    } else {
        tx.rollback().await?;
    }
    Ok(())
}

/// Attach `agent` to `role` over `[valid_from (default now), valid_to)`, in
/// one transaction committed only under `apply`, and report the succession
/// copies the attach wrote and the derived memberships it changed.
///
/// # Errors
/// A pre-connection check ([`validate`]); the definer or the table's guard
/// refused (`ROL02`: a human or role node, an overlapping window, a
/// back-dated start; `22004`; an unknown role or agent, `23503`); a statement
/// failed. Nothing is committed on an error.
pub async fn attach(
    conn: &mut PgConnection,
    role: &str,
    agent: Uuid,
    valid_from: Option<DateTime<Utc>>,
    valid_to: Option<DateTime<Utc>>,
    reason: &str,
    apply: bool,
) -> anyhow::Result<Outcome> {
    validate(role, reason, valid_from, valid_to)?;
    let mut tx = super::team_group::begin_audited(conn, "role-attach").await?;
    let agents = affected_agents(&mut tx, role, agent).await?;
    let before = derived(&mut tx, &agents).await?;
    let id: Uuid =
        sqlx::query_scalar("SELECT public.epigraph_attach_agent_to_role($1, $2, $3, $4, $5)")
            .bind(role)
            .bind(agent)
            .bind(valid_from)
            .bind(valid_to)
            .bind(reason)
            .fetch_one(&mut *tx)
            .await?;
    // The follow chains its copies (195): a successor's copy names its
    // predecessor's copy, so only the first level names `id`. Walk the chain.
    let raw: Vec<RawRow> = sqlx::query_as(
        "WITH RECURSIVE chain(id, depth) AS ( \
             SELECT r.id, 1 FROM public.role_agents r WHERE r.inherited_from = $1 \
             UNION \
             SELECT r.id, c.depth + 1 FROM public.role_agents r \
               JOIN chain c ON r.inherited_from = c.id \
         ) \
         SELECT r.id, r.agent_id, r.inherited_from, r.valid_from::text, r.valid_to::text \
           FROM public.role_agents r JOIN chain c ON c.id = r.id \
          ORDER BY c.depth, r.agent_id, r.valid_from, r.id",
    )
    .bind(id)
    .fetch_all(&mut *tx)
    .await?;
    let after = derived(&mut tx, &agents).await?;
    finish(tx, apply).await?;
    Ok(Outcome {
        attachment: Some(id),
        rows: rows_of(raw),
        memberships: diff(&before, &after),
        applied: apply,
    })
}

/// Detach every un-detached attachment of `agent` to `role`, now, in one
/// transaction committed only under `apply`, and report the rows it ended
/// and the derived memberships it changed (the agent's, its successors' and
/// its copies' holders').
///
/// # Errors
/// A pre-connection check ([`validate`]); the definer refused; a statement
/// failed. Nothing is committed on an error.
pub async fn detach(
    conn: &mut PgConnection,
    role: &str,
    agent: Uuid,
    reason: &str,
    apply: bool,
) -> anyhow::Result<Outcome> {
    validate(role, reason, None, None)?;
    let mut tx = super::team_group::begin_audited(conn, "role-detach").await?;
    let agents = affected_agents(&mut tx, role, agent).await?;
    let before = derived(&mut tx, &agents).await?;
    let open: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM public.role_agents \
          WHERE role = $1 AND agent_id = $2 AND detached_at IS NULL ORDER BY valid_from, id",
    )
    .bind(role)
    .bind(agent)
    .fetch_all(&mut *tx)
    .await?;
    let n: i32 = sqlx::query_scalar("SELECT public.epigraph_detach_agent_from_role($1, $2, $3)")
        .bind(role)
        .bind(agent)
        .bind(reason)
        .fetch_one(&mut *tx)
        .await?;
    if usize::try_from(n).ok() != Some(open.len()) {
        tx.rollback().await?;
        bail!(
            "the detach definer ended {n} row(s), {} were un-detached before it; rolled back, \
             nothing was changed",
            open.len()
        );
    }
    let raw: Vec<RawRow> = sqlx::query_as(
        "SELECT id, agent_id, inherited_from, valid_from::text, valid_to::text \
           FROM public.role_agents WHERE id = ANY($1) AND detached_at IS NOT NULL \
          ORDER BY valid_from, id",
    )
    .bind(&open)
    .fetch_all(&mut *tx)
    .await?;
    let after = derived(&mut tx, &agents).await?;
    finish(tx, apply).await?;
    Ok(Outcome {
        attachment: None,
        rows: rows_of(raw),
        memberships: diff(&before, &after),
        applied: apply,
    })
}

fn row_line(kind: &str, r: &AttachmentRow) -> String {
    format!(
        "{kind}\t{}\tagent={}\tinherited_from={}\tvalid_from={}\tvalid_to={}",
        r.id,
        r.agent,
        r.inherited_from
            .map_or_else(|| "-".to_string(), |i| i.to_string()),
        r.valid_from,
        r.valid_to.as_deref().unwrap_or("open")
    )
}

fn membership_lines(o: &Outcome) -> Vec<String> {
    let mut out: Vec<String> = o
        .memberships
        .iter()
        .map(|m| {
            format!(
                "MEMBERSHIP\t{}\tagent={}\tgroup={}\trole={}",
                m.change.label(),
                m.agent,
                m.group,
                m.role
            )
        })
        .collect();
    out.push(format!(
        "MEMBERSHIPS: {} gained, {} lost, {} kept (role-derived, every identity the act can \
         change)",
        o.memberships
            .iter()
            .filter(|m| m.change == Change::Gained)
            .count(),
        o.memberships
            .iter()
            .filter(|m| m.change == Change::Lost)
            .count(),
        o.memberships
            .iter()
            .filter(|m| m.change == Change::Kept)
            .count()
    ));
    out
}

/// The lines `role-attach` prints for `o`.
#[must_use]
pub fn describe_attach(role: &str, agent: Uuid, o: &Outcome) -> Vec<String> {
    let would = if o.applied { "" } else { "WOULD BE " };
    let mut out = vec![format!(
        "{would}ATTACHED\tattachment={}\trole={role}\tagent={agent}",
        o.attachment.map_or_else(String::new, |i| i.to_string())
    )];
    out.extend(o.rows.iter().map(|r| row_line("COPY", r)));
    out.push(format!(
        "COPIES: {} (the attach follows the identity's registered successors)",
        o.rows.len()
    ));
    out.extend(membership_lines(o));
    if !o.applied {
        out.push(
            "DRY RUN: the attachment, its copies and their audit rows were rolled back. Re-run \
             with --apply to attach."
                .to_string(),
        );
    }
    out
}

/// The lines `role-detach` prints for `o`.
#[must_use]
pub fn describe_detach(role: &str, agent: Uuid, o: &Outcome) -> Vec<String> {
    let would = if o.applied { "" } else { "WOULD BE " };
    let mut out: Vec<String> = o
        .rows
        .iter()
        .map(|r| format!("{would}{}", row_line("DETACHED", r)))
        .collect();
    if o.rows.is_empty() {
        out.push(format!(
            "NOTHING-TO-DETACH\trole={role}\tagent={agent}\t(no un-detached attachment; nothing \
             was changed)"
        ));
    } else {
        out.push(format!(
            "DETACHED: {} row(s) of agent {agent} for {role} (sticky per identity: only an \
             attachment by name admits it again)",
            o.rows.len()
        ));
    }
    out.extend(membership_lines(o));
    if !o.applied && !o.rows.is_empty() {
        out.push(
            "DRY RUN: the detach and its audit rows were rolled back. Re-run with --apply to \
             detach."
                .to_string(),
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_refuses_a_bad_key_a_blank_reason_and_an_empty_window() {
        let t = |s: &str| s.parse::<DateTime<Utc>>().unwrap();
        assert!(validate("role:ops", "why", None, None).is_ok());
        assert!(validate("ops", "why", None, None).is_err());
        assert!(validate("role:Ops", "why", None, None).is_err());
        assert!(validate("role:ops", "  ", None, None).is_err());
        let a = t("2026-01-01T00:00:00Z");
        let b = t("2026-01-02T00:00:00Z");
        assert!(validate("role:ops", "why", Some(a), Some(b)).is_ok());
        assert!(validate("role:ops", "why", Some(b), Some(a)).is_err());
        assert!(validate("role:ops", "why", Some(a), Some(a)).is_err());
    }

    #[test]
    fn diff_labels_gained_lost_and_kept() {
        let (a, g1, g2) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let before: BTreeSet<_> = [(a, g1, "writer".to_string()), (a, g2, "reader".to_string())]
            .into_iter()
            .collect();
        let after: BTreeSet<_> = [(a, g1, "writer".to_string()), (a, g2, "writer".to_string())]
            .into_iter()
            .collect();
        let d = diff(&before, &after);
        let got: Vec<(Uuid, &str, Change)> = d
            .iter()
            .map(|m| (m.group, m.role.as_str(), m.change))
            .collect();
        assert!(got.contains(&(g1, "writer", Change::Kept)));
        assert!(got.contains(&(g2, "reader", Change::Lost)));
        assert!(got.contains(&(g2, "writer", Change::Gained)));
        assert_eq!(got.len(), 3);
    }
}
