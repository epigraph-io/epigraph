//! The compound-atom sweep (backlog `72850d43`): label every current atom
//! that still asserts several independent things, so it can be found and
//! re-decomposed, and take the label off every claim that no longer
//! qualifies.
//!
//! A claim QUALIFIES when it is current, is the target of at least one
//! in-force `decomposes_to` edge from a current parent (it is an atom of some
//! decomposition), has no in-force `decomposes_to` children of its own (no
//! one has split it yet), and `epigraph_core::atomicity::conjunct_screen`
//! calls it compound. The label is
//! [`epigraph_core::atomicity::COMPOUND_ATOM_LABEL`].
//!
//! # The label is derived only from what its readers can see
//!
//! The sweep reads as the maintenance bypass viewer, so it sees every edge.
//! The label it writes is visible to every reader of the claim. Deciding it
//! from all edges would disclose hidden structure: a public atom whose only
//! parent is group-private would carry a public `compound-atom` label while
//! a stranger is told it has no parent, and a private child under a public
//! compound atom would keep (or take away) the label. So both edge counts
//! [`qualifies`] reads are the AUDIENCE counts
//! (`ScreenRow::audience_parents` / `audience_children`): edges and
//! neighbours that every reader of the claim can see. `claim_role.rs`'s
//! "structure, no viewer filter" rule is for internal decisions; a label is
//! a disclosure.
//!
//! The sweep is idempotent and self-cleaning: a second run over an unchanged
//! graph changes nothing, and a labelled atom that is re-decomposed
//! (`decompose_claims --redecompose`) loses the label on the next run. Labels
//! are written through `ClaimRepository::update_labels_conn`, the label
//! chokepoint, one transaction per page; no other column is touched.

use chrono::{DateTime, Utc};
use epigraph_core::atomicity::{conjunct_screen, COMPOUND_ATOM_LABEL};
use epigraph_db::{AtomicityScreenRepository, ClaimRepository, ScreenPopulation, ScreenRow};
use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;

/// Rows read per statement.
const PAGE: i64 = 500;

/// What one sweep found and (with `apply`) changed.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct SweepReport {
    /// Whether labels were written.
    pub applied: bool,
    /// Atoms read and screened.
    pub atoms_scanned: usize,
    /// Atoms that qualify (labelled already or not).
    pub compound_atoms: usize,
    /// Qualifying atoms that lacked the label: labelled by this run, or
    /// would be on a dry run.
    pub labelled: Vec<Uuid>,
    /// Claims carrying the label that no longer qualify: unlabelled by this
    /// run, or would be on a dry run.
    pub unlabelled: Vec<Uuid>,
    /// True when `max_scan` stopped the atom walk before the population
    /// ran out; the counts then cover only the rows read, and nothing is
    /// unlabelled (a claim past the cap could still qualify).
    pub scan_capped: bool,
}

/// Whether `row` qualifies for the compound-atom label (see the module docs):
/// decided from the AUDIENCE edge counts only, never from structure some
/// reader of the claim cannot see.
#[must_use]
pub fn qualifies(row: &ScreenRow) -> bool {
    row.is_current
        && row.audience_parents > 0
        && row.audience_children == 0
        && conjunct_screen(&row.content).is_compound()
}

fn has_label(row: &ScreenRow) -> bool {
    row.labels.iter().any(|l| l == COMPOUND_ATOM_LABEL)
}

async fn relabel(pool: &PgPool, ids: &[Uuid], add: bool) -> Result<(), Box<dyn std::error::Error>> {
    if ids.is_empty() {
        return Ok(());
    }
    let label = vec![COMPOUND_ATOM_LABEL.to_string()];
    let none: Vec<String> = Vec::new();
    let mut tx = pool.begin().await?;
    for &id in ids {
        if add {
            ClaimRepository::update_labels_conn(&mut tx, id, &label, &none).await?;
        } else {
            ClaimRepository::update_labels_conn(&mut tx, id, &none, &label).await?;
        }
    }
    tx.commit().await?;
    Ok(())
}

/// Run the sweep on `pool` as `viewer` (the maintenance bypass viewer in the
/// binary). Reads at most `max_scan` atoms. With `apply = false` nothing is
/// written and the report says what would change.
///
/// # Errors
/// Database failure. Pages already applied stay applied; a re-run converges.
pub async fn sweep(
    pool: &PgPool,
    viewer: &epigraph_db::visibility::Viewer,
    apply: bool,
    max_scan: usize,
) -> Result<SweepReport, Box<dyn std::error::Error>> {
    let mut report = SweepReport {
        applied: apply,
        ..SweepReport::default()
    };

    // Phase 1: label every qualifying atom that lacks the label.
    let mut after: Option<(DateTime<Utc>, Uuid)> = None;
    loop {
        if report.atoms_scanned >= max_scan {
            report.scan_capped = true;
            break;
        }
        let want = PAGE.min((max_scan - report.atoms_scanned) as i64);
        let page = AtomicityScreenRepository::page(
            &mut *pool.acquire().await?,
            viewer,
            ScreenPopulation::Atoms,
            after,
            want,
        )
        .await?;
        let n = page.len();
        let mut add = Vec::new();
        for row in &page {
            report.atoms_scanned += 1;
            after = Some((row.created_at, row.id));
            if qualifies(row) {
                report.compound_atoms += 1;
                if !has_label(row) {
                    add.push(row.id);
                }
            }
        }
        if apply {
            relabel(pool, &add, true).await?;
        }
        report.labelled.extend(add);
        if (n as i64) < want {
            break;
        }
    }

    // Phase 2: unlabel every labelled claim that no longer qualifies. Skipped
    // when the walk above was capped: it did not see the whole population,
    // so it cannot tell a stale label from one past the cap.
    if !report.scan_capped {
        let mut after: Option<(DateTime<Utc>, Uuid)> = None;
        loop {
            let page = AtomicityScreenRepository::labelled_page(
                pool,
                viewer,
                COMPOUND_ATOM_LABEL,
                after,
                PAGE,
            )
            .await?;
            let n = page.len();
            let mut remove = Vec::new();
            for row in &page {
                after = Some((row.created_at, row.id));
                if !qualifies(row) {
                    remove.push(row.id);
                }
            }
            if apply {
                relabel(pool, &remove, false).await?;
            }
            report.unlabelled.extend(remove);
            if (n as i64) < PAGE {
                break;
            }
        }
    }
    Ok(report)
}
