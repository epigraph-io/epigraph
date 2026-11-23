//! `EPIGRAPH_COMPOUND_WRITE_GUARD` on the textless BBA writers (SPEC §4.1,
//! writer W3): what a BBA written straight onto a **compound** does.
//!
//! A compound's belief is a query over its leaves, so evidence belongs on its
//! atoms. A textless writer (one that stores masses with no evidence row, so
//! nothing could attribute the write to an atom later) that names a compound
//! is guarded here:
//!
//! - MCP `submit_ds_evidence`;
//! - REST `POST /api/v1/frames/:id/evidence`;
//! - REST `POST /api/v1/claims/:id/assess`.
//!
//! Under [`CompoundWriteGuard::Warn`] (the default) the write goes ahead and
//! stays inert on the compound: a compound has no cache-owner frame
//! (`MassFunctionRepository::cache_owner_frame_for_claim`), so neither the
//! write nor any later owner-rule recompute folds the row into the
//! compound's cached belief. (The derived compound view, SPEC §3.6, reads the
//! refutation mass of a compound's own rows by design, this one included.)
//! The caller gets a `deprecated_compound_target`
//! field naming the atoms it can see, and the write is logged under
//! [`LOG_TARGET`] with the writer and the caller's agent id (never the
//! claim's content), so the callers to fix before a flip to `refuse` can be
//! read from the journal.
//!
//! Under [`CompoundWriteGuard::Refuse`] the write is refused before anything
//! is written, with the visible atoms in the refusal ([`REFUSAL_CODE`]: MCP
//! `invalid_params`, REST `422`).
//!
//! **Role is structure.** Whether the target is a compound is decided by
//! migration 193's definer `public.epigraph_claim_is_compound`
//! (`claim_role::is_compound_by_definer`), on the
//! whole graph whatever the caller's row security lets it see. A caller that
//! cannot see any of a compound's decomposition is still guarded (and is
//! listed no atoms): the inline predicate read on the caller's application
//! session would find no compound there and let the write through.
//!
//! **The atoms are the caller's.** [`visible_atoms`] lists only the leaves
//! the caller can read (the viewer-spliced leaf closure,
//! `claim_role::leaf_closure_batch`), minus any visible leaf that is itself a
//! compound whose decomposition the caller cannot see: naming one would send
//! the caller to another guarded target.
//!
//! The update writer `update_with_evidence` is not guarded here: it carries an
//! evidence row (it is text-bearing), and SPEC §4.1 routes such writes (W1)
//! rather than refusing them.

use serde::Serialize;
use uuid::Uuid;

use epigraph_db::repos::claim_role;
use epigraph_db::visibility::Viewer;
use epigraph_db::DbError;

use crate::belief_modes::CompoundWriteGuard;

/// The `tracing` target every guarded compound write is logged under.
pub const LOG_TARGET: &str = "epigraph::compound_write_guard";

/// The machine-readable code of a refusal (MCP `data.error`, REST `error`).
pub const REFUSAL_CODE: &str = "compound_target";

/// At most this many visible atoms are listed; `visible_atom_count` carries
/// the full count.
pub const VISIBLE_ATOMS_CAP: usize = 50;

/// One atom of a compound the caller can read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VisibleAtom {
    pub id: Uuid,
    pub content: String,
}

/// A guarded write's compound target, as the caller may see it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CompoundTarget {
    /// The compound the write named.
    pub claim_id: Uuid,
    /// The compound's leaves the caller can read that are not themselves
    /// compounds, ordered by id, at most [`VISIBLE_ATOMS_CAP`]. Empty when the
    /// caller can see none.
    pub visible_atoms: Vec<VisibleAtom>,
    /// How many such atoms there are (`visible_atoms` may be capped).
    pub visible_atom_count: usize,
    /// The guard mode that decided the write (`warn` or `refuse`).
    pub guard: CompoundWriteGuard,
}

impl CompoundTarget {
    /// The sentence a `warn`-mode write adds to the response's warnings.
    #[must_use]
    pub fn warning(&self) -> String {
        format!(
            "claim {} is a compound: its belief is derived from the atoms it decomposes into, \
             so this BBA was stored but is never folded into the compound's cached belief, now \
             or by a later recompute (the derived compound view reads only its refutation \
             mass, as for every row on a compound). Write it on the atoms instead ({}). Textless \
             BBA writes on compounds are deprecated and will be refused \
             (EPIGRAPH_COMPOUND_WRITE_GUARD=refuse).",
            self.claim_id,
            self.atoms_phrase()
        )
    }

    /// The message of a `refuse`-mode refusal.
    #[must_use]
    pub fn refusal(&self) -> String {
        format!(
            "claim {} is a compound: a BBA with no evidence text is not accepted on a compound \
             (EPIGRAPH_COMPOUND_WRITE_GUARD=refuse); nothing was written. Write it on the atoms \
             instead ({}).",
            self.claim_id,
            self.atoms_phrase()
        )
    }

    /// The machine-readable body of a refusal, shared by both transports:
    /// `{"error": "compound_target", "claim_id", "visible_atoms",
    /// "visible_atom_count", "flag", "retryable": false}`.
    #[must_use]
    pub fn refusal_data(&self) -> serde_json::Value {
        serde_json::json!({
            "error": REFUSAL_CODE,
            "claim_id": self.claim_id,
            "visible_atoms": self.visible_atoms,
            "visible_atom_count": self.visible_atom_count,
            "flag": CompoundWriteGuard::ENV,
            "retryable": false,
        })
    }

    fn atoms_phrase(&self) -> String {
        match self.visible_atom_count {
            0 => "none of its atoms is visible to this caller".to_string(),
            n => format!("{n} visible atom(s), listed in visible_atoms"),
        }
    }
}

/// What the guard decided for one write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardDecision {
    /// The target is not a compound: the write is unchanged.
    NotCompound,
    /// `warn`: the write goes ahead, inert on the compound, and the caller is
    /// told.
    Accept(CompoundTarget),
    /// `refuse`: nothing may be written.
    Refuse(CompoundTarget),
}

/// Whether `claim_id` is currently a compound, decided with definer rights on
/// the whole graph (migration 193), whatever `conn`'s row security admits.
///
/// # Errors
/// [`DbError`] when the query fails.
pub async fn is_compound(conn: &mut sqlx::PgConnection, claim_id: Uuid) -> Result<bool, DbError> {
    claim_role::is_compound_by_definer(conn, claim_id).await
}

/// The compound's atoms `viewer` can read: its visible leaf closure, minus a
/// leaf that is itself a compound (its decomposition hidden from `viewer`),
/// ordered by id. Returns at most [`VISIBLE_ATOMS_CAP`] atoms and the full
/// count.
///
/// # Errors
/// [`DbError`] when a query fails.
pub async fn visible_atoms(
    conn: &mut sqlx::PgConnection,
    viewer: &Viewer,
    claim_id: Uuid,
) -> Result<(Vec<VisibleAtom>, usize), DbError> {
    let leaves = claim_role::leaf_closure_batch(&mut *conn, viewer, &[claim_id])
        .await?
        .remove(&claim_id)
        .unwrap_or_default();
    let rows = claim_role::visible_non_compounds(&mut *conn, viewer, &leaves).await?;
    let count = rows.len();
    let atoms = rows
        .into_iter()
        .take(VISIBLE_ATOMS_CAP)
        .map(|(id, content)| VisibleAtom { id, content })
        .collect();
    Ok((atoms, count))
}

/// Decide a textless BBA write by `caller` through `writer` onto `claim_id`
/// under `mode`, before anything is written. A compound target is logged
/// under [`LOG_TARGET`] (writer, claim id, caller, mode; never content).
///
/// `conn` should carry the caller's tenancy stamp, so the listed atoms are
/// the ones the caller can read; the compound test itself ignores it. A
/// claim `viewer` cannot read is [`GuardDecision::NotCompound`]: the writer's
/// own not-found check answers it, exactly as for a missing id.
///
/// # Errors
/// [`DbError`] when a query fails.
pub async fn decide(
    conn: &mut sqlx::PgConnection,
    viewer: &Viewer,
    claim_id: Uuid,
    mode: CompoundWriteGuard,
    writer: &'static str,
    caller: Option<Uuid>,
) -> Result<GuardDecision, DbError> {
    // A claim the caller cannot read is left to the writer's own not-found
    // answer, so the guard is no existence oracle: deciding it here would
    // answer "a compound" for a claim the writer then reports as missing.
    if !epigraph_db::ClaimRepository::visible_claim_ids(&mut *conn, viewer, &[claim_id])
        .await?
        .contains(&claim_id)
    {
        return Ok(GuardDecision::NotCompound);
    }
    if !is_compound(&mut *conn, claim_id).await? {
        return Ok(GuardDecision::NotCompound);
    }
    let (visible_atoms, visible_atom_count) = visible_atoms(&mut *conn, viewer, claim_id).await?;
    let target = CompoundTarget {
        claim_id,
        visible_atoms,
        visible_atom_count,
        guard: mode,
    };
    let caller = caller.map(|c| c.to_string());
    match mode {
        CompoundWriteGuard::Warn => {
            tracing::warn!(
                target: LOG_TARGET,
                writer,
                %claim_id,
                caller = caller.as_deref().unwrap_or("anonymous"),
                guard = mode.as_str(),
                "textless BBA write on a compound accepted (inert); the caller should write \
                 on the compound's atoms"
            );
            Ok(GuardDecision::Accept(target))
        }
        CompoundWriteGuard::Refuse => {
            tracing::info!(
                target: LOG_TARGET,
                writer,
                %claim_id,
                caller = caller.as_deref().unwrap_or("anonymous"),
                guard = mode.as_str(),
                "textless BBA write on a compound refused"
            );
            Ok(GuardDecision::Refuse(target))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(n: usize) -> CompoundTarget {
        CompoundTarget {
            claim_id: Uuid::nil(),
            visible_atoms: (0..n.min(VISIBLE_ATOMS_CAP))
                .map(|i| VisibleAtom {
                    id: Uuid::from_u128(i as u128 + 1),
                    content: format!("atom {i}"),
                })
                .collect(),
            visible_atom_count: n,
            guard: CompoundWriteGuard::Refuse,
        }
    }

    #[test]
    fn the_refusal_body_is_machine_keyed_and_names_the_flag() {
        let data = target(2).refusal_data();
        assert_eq!(data["error"], REFUSAL_CODE);
        assert_eq!(data["flag"], "EPIGRAPH_COMPOUND_WRITE_GUARD");
        assert_eq!(data["retryable"], false);
        assert_eq!(data["visible_atom_count"], 2);
        assert_eq!(data["visible_atoms"][1]["content"], "atom 1");
    }

    #[test]
    fn the_texts_say_what_happened_and_where_to_write() {
        let none = target(0);
        assert!(none.refusal().contains("nothing was written"));
        assert!(none.refusal().contains("none of its atoms is visible"));
        let some = target(3);
        assert!(some
            .warning()
            .contains("never folded into the compound's cached belief"));
        assert!(some.warning().contains("3 visible atom(s)"));
    }

    #[test]
    fn the_wire_shape_of_a_target_carries_the_guard_spelling() {
        let v = serde_json::to_value(target(1)).unwrap();
        assert_eq!(v["guard"], "refuse");
        assert_eq!(v["visible_atoms"][0]["id"], Uuid::from_u128(1).to_string());
    }
}
