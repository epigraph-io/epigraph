//! Opt-in evidence hiding (operator directive 2026-09-23, Amendment 2): the
//! selectors, the preview, and every refusal that stands between them and a
//! write.
//!
//! # What is built here, and what is not
//!
//! Built: the three selectors (`--hide-evidence-ids`, `--hide-evidence-type`,
//! `--hide-evidence-label`), the dry-run report (per-type and per-claim counts
//! and an 80-character content preview of every selected row), and the
//! refusals `--apply` must pass: the `--confirm-hide <N>` count, the
//! unenforced-hide detection, and the kernel-guard check.
//!
//! NOT built: the write that hides a row, its pin, and the manifest's
//! hidden-row reversal. The write is useless without the kernel guard the brief
//! calls B-H2 — migration 070's insert arm re-syncs EVERY evidence row of a
//! claim to the claim on the next evidence INSERT for it, and 072's update arm
//! does the same on the next claim owner or visibility change, so an unpinned
//! hidden row is re-published by ordinary application writes. The guard (a
//! definer-only pin table plus pin-aware arms (c) and (d), as migration 104)
//! was not written in this branch. So `--apply` with any hide selector REFUSES
//! on a schema without that guard, keyed on the live catalog
//! ([`guard_status`]), and refuses again, with its own message, on a schema
//! WITH it, because this build has no write path to run. A dry run is always
//! available.
//!
//! # Selectors are a union
//!
//! A row is selected when it matches ANY selector: its id is in the ids file,
//! OR its `evidence_type` is one of the `--hide-evidence-type` values, OR one
//! of its `labels` is one of the `--hide-evidence-label` values. Each selector
//! is an explicit request to hide; widening one never narrows another. Only
//! evidence attached to claims in scope is ever selected; an id in the ids file
//! that is not is REPORTED as out of scope, never hidden.
//!
//! # Unenforced hiding (B-H4)
//!
//! Permissive policies are OR'ed. Production carries orphan PERMISSIVE policies
//! (`claims_privacy`, `evidence_privacy`, `edges_privacy`) that exist in no
//! migration and whose USING is effectively TRUE, so while `evidence_privacy`
//! exists any application session reads a `group` evidence row and hiding has
//! NO effect. [`extra_evidence_policies`] finds every permissive SELECT-capable
//! policy on `evidence` other than `evidence_tenancy`. A dry run prints a loud
//! warning; `--apply` refuses unless `--accept-unenforced-hide` is given.
//!
//! Independently of any policy, a BYPASSRLS or superuser connection reads every
//! row regardless, and hiding is forward-only: content already emitted in
//! events, caches, exports or search results is not retracted.

use super::tables::{Attached, Snapshot};
use anyhow::{bail, Context};
use sqlx::PgConnection;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use uuid::Uuid;

/// `evidence_type_valid`'s seven values (migration 001's CHECK).
pub const EVIDENCE_TYPES: &[&str] = &[
    "document",
    "observation",
    "testimony",
    "computation",
    "reference",
    "figure",
    "conversational",
];

/// The hide flags, shared by `reown-claims` and `hide-evidence`.
#[derive(Clone, Debug, Default, clap::Args)]
pub struct HideArgs {
    /// File of evidence UUIDs to hide (one per line).
    #[arg(long)]
    pub hide_evidence_ids: Option<PathBuf>,
    /// Hide every in-scope evidence row of this `evidence_type`. Repeatable.
    #[arg(long)]
    pub hide_evidence_type: Vec<String>,
    /// Hide every in-scope evidence row carrying this label. Repeatable.
    #[arg(long)]
    pub hide_evidence_label: Vec<String>,
    /// Under `--apply`, the planned hidden-row count, repeated back.
    #[arg(long)]
    pub confirm_hide: Option<usize>,
    /// Proceed although a permissive policy on `evidence` other than
    /// `evidence_tenancy` means hiding would not be enforced.
    #[arg(long)]
    pub accept_unenforced_hide: bool,
}

/// The parsed selectors.
#[derive(Clone, Debug, Default)]
pub struct Selector {
    pub ids: BTreeSet<Uuid>,
    pub types: BTreeSet<String>,
    pub labels: BTreeSet<String>,
}

impl Selector {
    /// # Errors
    /// The ids file is unreadable or malformed, or a type is not one of
    /// [`EVIDENCE_TYPES`].
    pub fn from_args(a: &HideArgs) -> anyhow::Result<Self> {
        let ids = match &a.hide_evidence_ids {
            Some(p) => super::read_ids_file(p)?.into_iter().collect(),
            None => BTreeSet::new(),
        };
        for t in &a.hide_evidence_type {
            if !EVIDENCE_TYPES.contains(&t.as_str()) {
                bail!(
                    "--hide-evidence-type {t:?} is not an evidence_type; expected one of {}",
                    EVIDENCE_TYPES.join(", ")
                );
            }
        }
        Ok(Self {
            ids,
            types: a.hide_evidence_type.iter().cloned().collect(),
            labels: a.hide_evidence_label.iter().cloned().collect(),
        })
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ids.is_empty() && self.types.is_empty() && self.labels.is_empty()
    }

    /// Whether an attached row is selected. Only `evidence` rows ever are.
    #[must_use]
    pub fn matches(&self, a: &Attached) -> bool {
        if a.table != "evidence" {
            return false;
        }
        Uuid::parse_str(&a.pk).is_ok_and(|id| self.ids.contains(&id))
            || a.evidence_type
                .as_ref()
                .is_some_and(|t| self.types.contains(t))
            || a.labels.iter().any(|l| self.labels.contains(l))
    }
}

/// The rows a selector picks out of a snapshot.
#[derive(Debug, Default)]
pub struct Plan {
    /// Selected, currently public: these would be hidden.
    pub rows: Vec<Attached>,
    /// Selected but already not public: left exactly as they are.
    pub already_private: usize,
    /// Ids from the ids file that are not evidence of any claim in scope.
    pub out_of_scope: Vec<Uuid>,
}

impl Plan {
    #[must_use]
    pub fn by_type(&self) -> BTreeMap<String, usize> {
        let mut m = BTreeMap::new();
        for r in &self.rows {
            *m.entry(r.evidence_type.clone().unwrap_or_default())
                .or_default() += 1;
        }
        m
    }

    #[must_use]
    pub fn by_claim(&self) -> BTreeMap<Uuid, usize> {
        let mut m = BTreeMap::new();
        for r in &self.rows {
            *m.entry(r.claim).or_default() += 1;
        }
        m
    }
}

/// Select from `attached` (the evidence of the claims in scope).
#[must_use]
pub fn plan(sel: &Selector, attached: &Snapshot) -> Plan {
    let mut p = Plan::default();
    let mut seen_ids = BTreeSet::new();
    for a in attached.values() {
        if a.table == "evidence" {
            if let Ok(id) = Uuid::parse_str(&a.pk) {
                seen_ids.insert(id);
            }
        }
        if !sel.matches(a) {
            continue;
        }
        if a.tenancy.visibility == "public" {
            p.rows.push(a.clone());
        } else {
            p.already_private += 1;
        }
    }
    p.out_of_scope = sel.ids.difference(&seen_ids).copied().collect();
    p
}

fn preview(s: Option<&str>) -> String {
    match s {
        None => "(no raw_content)".to_string(),
        Some(t) => t
            .chars()
            .take(80)
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect(),
    }
}

/// The dry-run report: counts per type and per claim, then one preview line
/// per row.
///
/// # Errors
/// Writing to `out` fails.
pub fn print(out: &mut dyn std::io::Write, p: &Plan) -> anyhow::Result<()> {
    writeln!(
        out,
        "HIDE-PLAN: {} evidence row(s) would become visibility=group, owned by the operator's \
         personal group ({} selected row(s) already not public are left as they are)",
        p.rows.len(),
        p.already_private
    )?;
    for (t, n) in p.by_type() {
        writeln!(out, "HIDE-TYPE\t{t}\t{n}")?;
    }
    for (c, n) in p.by_claim() {
        writeln!(out, "HIDE-CLAIM\t{c}\t{n}")?;
    }
    let mut rows: Vec<&Attached> = p.rows.iter().collect();
    rows.sort_by(|a, b| (a.claim, &a.pk).cmp(&(b.claim, &b.pk)));
    for r in rows {
        writeln!(
            out,
            "HIDE\t{}\t{}\t{}\t{}",
            r.pk,
            r.claim,
            r.evidence_type.as_deref().unwrap_or(""),
            preview(r.preview.as_deref())
        )?;
    }
    for id in &p.out_of_scope {
        writeln!(
            out,
            "HIDE-OUT-OF-SCOPE\t{id}\tnot evidence of any claim in scope; never hidden"
        )?;
    }
    Ok(())
}

/// Whether the kernel guard (B-H2) that stops propagation re-publishing a
/// hidden row is present in the live schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuardStatus {
    pub pin_table: bool,
    pub propagate_arm_pinned: bool,
    pub inherit_arm_pinned: bool,
}

impl GuardStatus {
    #[must_use]
    pub const fn complete(self) -> bool {
        self.pin_table && self.propagate_arm_pinned && self.inherit_arm_pinned
    }
}

/// Read the guard's presence from the catalog: the pin table exists, and BOTH
/// tenancy trigger bodies consult it.
///
/// # Errors
/// A catalog read fails.
pub async fn guard_status(conn: &mut PgConnection) -> anyhow::Result<GuardStatus> {
    let (pin_table, propagate_arm_pinned, inherit_arm_pinned): (bool, bool, bool) =
        sqlx::query_as(
            "SELECT to_regclass('public.evidence_visibility_pins') IS NOT NULL, \
                    COALESCE((SELECT prosrc LIKE '%evidence_visibility_pins%' FROM pg_proc \
                               WHERE oid = to_regprocedure('public.epigraph_propagate_tenancy()')), \
                             false), \
                    COALESCE((SELECT prosrc LIKE '%evidence_visibility_pins%' FROM pg_proc \
                               WHERE oid = to_regprocedure('public.epigraph_inherit_tenancy_stmt()')), \
                             false)",
        )
        .fetch_one(&mut *conn)
        .await
        .context("reading the evidence pin guard from the catalog")?;
    Ok(GuardStatus {
        pin_table,
        propagate_arm_pinned,
        inherit_arm_pinned,
    })
}

/// Permissive policies on `evidence`, other than `evidence_tenancy`, that
/// apply to reads (`cmd` ALL or SELECT). Each is OR'ed with the tenancy policy,
/// so any one whose USING admits a `group` row defeats hiding.
///
/// # Errors
/// The catalog read fails.
pub async fn extra_evidence_policies(conn: &mut PgConnection) -> anyhow::Result<Vec<String>> {
    Ok(sqlx::query_scalar(
        "SELECT policyname::text FROM pg_policies \
          WHERE schemaname = 'public' AND tablename = 'evidence' \
            AND permissive = 'PERMISSIVE' AND cmd IN ('ALL', 'SELECT') \
            AND policyname <> 'evidence_tenancy' \
          ORDER BY 1",
    )
    .fetch_all(&mut *conn)
    .await?)
}

/// The loud warning a dry run prints when hiding would not be enforced.
///
/// # Errors
/// Writing to `out` fails.
pub fn warn_unenforced(out: &mut dyn std::io::Write, policies: &[String]) -> anyhow::Result<()> {
    if policies.is_empty() {
        return Ok(());
    }
    writeln!(
        out,
        "WARNING: HIDING WILL NOT BE ENFORCED. Permissive polic{} on evidence other than \
         evidence_tenancy: {}. Permissive policies are OR'ed, so an application session can \
         still read a visibility=group evidence row. --apply refuses unless \
         --accept-unenforced-hide is given.",
        if policies.len() == 1 { "y" } else { "ies" },
        policies.join(", ")
    )?;
    Ok(())
}

/// Every refusal between a hide plan and `--apply`, in order: the count
/// confirmation, the unenforced-hide policy check, the kernel guard, and the
/// missing write path.
///
/// # Errors
/// Always, in this build, once the first three pass: see the module doc.
pub fn refuse_apply(
    p: &Plan,
    args: &HideArgs,
    policies: &[String],
    guard: GuardStatus,
) -> anyhow::Result<()> {
    match args.confirm_hide {
        Some(n) if n == p.rows.len() => {}
        Some(n) => bail!(
            "--confirm-hide {n} does not match the planned hidden-row count {}; refusing",
            p.rows.len()
        ),
        None => bail!(
            "--apply with a hide selector requires --confirm-hide {} (the planned hidden-row \
             count, repeated back); refusing",
            p.rows.len()
        ),
    }
    if !policies.is_empty() && !args.accept_unenforced_hide {
        bail!(
            "hiding would NOT be enforced: permissive polic{} {} on evidence admit group rows \
             to every application session. Drop {} first, or pass --accept-unenforced-hide; \
             refusing",
            if policies.len() == 1 { "y" } else { "ies" },
            policies.join(", "),
            if policies.len() == 1 { "it" } else { "them" }
        );
    }
    if !guard.complete() {
        bail!(
            "the kernel guard that keeps a hidden row hidden is not in this schema (pin table: \
             {}, update arm pinned: {}, insert arm pinned: {}). Without it the next claim \
             update, or the next evidence insert for the same claim, re-publishes every hidden \
             row (migrations 070/072), so a hide would not hold. It is the evidence pin \
             migration (planned as 104); refusing",
            guard.pin_table,
            guard.propagate_arm_pinned,
            guard.inherit_arm_pinned
        );
    }
    bail!(
        "this build of epigraph-operator has no hide write path (it ships with the evidence \
         pin guard); refusing"
    )
}

/// `hide-evidence`: the same selectors over the evidence of claims that are
/// NOT moving.
///
/// A listed claim is in scope only if it is already the operator's: owned by
/// the operator's personal group, or authored by the operator or by an agent
/// linked to it (retired or actor). Any other listed claim is HELD — hiding
/// moves a row into the operator's group, and taking a row away from a group
/// the operator has no claim on is not this tool's call.
///
/// # Errors
/// A refusal (see [`refuse_apply`]) or a database error.
pub async fn run_standalone(
    conn: &mut PgConnection,
    operator: Uuid,
    claims: &[Uuid],
    args: &HideArgs,
    apply: bool,
    out: &mut dyn std::io::Write,
) -> anyhow::Result<()> {
    let sel = Selector::from_args(args)?;
    if sel.is_empty() {
        bail!(
            "hide-evidence needs at least one selector: --hide-evidence-ids, \
             --hide-evidence-type or --hide-evidence-label"
        );
    }
    let target = super::operator_group(conn, operator).await?;
    let specs = super::tables::propagated_tables(conn).await?;
    let evidence_spec: Vec<_> = specs
        .iter()
        .filter(|s| s.name == "evidence")
        .cloned()
        .collect();
    if evidence_spec.is_empty() {
        bail!("epigraph_propagate_tenancy no longer cascades to evidence; refusing");
    }
    let rows = super::tables::fetch_claims(conn, claims, false).await?;
    let by_id: BTreeMap<Uuid, _> = rows.iter().map(|r| (r.id, r)).collect();
    let mut in_scope = Vec::new();
    writeln!(
        out,
        "hide-evidence: operator={operator} target_group={target} claims={} mode={}",
        claims.len(),
        if apply { "APPLY" } else { "DRY-RUN" }
    )?;
    for id in claims {
        let Some(c) = by_id.get(id) else {
            writeln!(out, "HELD\t{id}\tnot found")?;
            continue;
        };
        let linked = c.author == operator
            || super::operator_of_author(conn, c.author).await? == Some(operator);
        if c.owner == target || linked {
            in_scope.push(c.id);
        } else {
            writeln!(
                out,
                "HELD\t{id}\tneither owned by the operator's group nor authored by the operator \
                 or an agent linked to it"
            )?;
        }
    }
    let attached = super::tables::fetch_attached(conn, &evidence_spec, &in_scope).await?;
    let p = plan(&sel, &attached);
    print(out, &p)?;
    let policies = extra_evidence_policies(conn).await?;
    warn_unenforced(out, &policies)?;
    let guard = guard_status(conn).await?;
    if apply {
        refuse_apply(&p, args, &policies, guard)?;
    }
    writeln!(
        out,
        "DRY RUN: nothing was written.{}",
        if guard.complete() {
            ""
        } else {
            " --apply refuses on this schema: the kernel pin guard is absent."
        }
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operator::tables::Tenancy;

    fn ev(pk: Uuid, t: &str, labels: &[&str], vis: &str) -> Attached {
        Attached {
            table: "evidence".into(),
            pk: pk.to_string(),
            claim: Uuid::nil(),
            claims: BTreeSet::new(),
            tenancy: Tenancy {
                owner: Uuid::nil(),
                visibility: vis.into(),
                co_owner: None,
            },
            writer: None,
            endpoints_public: None,
            shared_outside: false,
            evidence_type: Some(t.into()),
            labels: labels.iter().map(|s| (*s).to_string()).collect(),
            preview: Some("line one\nline two".into()),
        }
    }

    #[test]
    fn selectors_are_a_union_and_only_select_evidence() {
        let (a, b, c) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let sel = Selector {
            ids: [a].into(),
            types: ["testimony".to_string()].into(),
            labels: ["private".to_string()].into(),
        };
        assert!(sel.matches(&ev(a, "document", &[], "public")));
        assert!(sel.matches(&ev(b, "testimony", &[], "public")));
        assert!(sel.matches(&ev(c, "document", &["x", "private"], "public")));
        assert!(!sel.matches(&ev(c, "document", &["x"], "public")));
        let mut not_ev = ev(a, "document", &[], "public");
        not_ev.table = "triples".into();
        assert!(!sel.matches(&not_ev));
    }

    #[test]
    fn an_unknown_type_is_refused() {
        let args = HideArgs {
            hide_evidence_type: vec!["rumour".into()],
            ..Default::default()
        };
        assert!(Selector::from_args(&args).is_err());
    }

    #[test]
    fn the_confirm_count_policy_and_guard_refusals_come_in_order() {
        let p = Plan {
            rows: vec![ev(Uuid::new_v4(), "document", &[], "public")],
            ..Default::default()
        };
        let none = GuardStatus {
            pin_table: false,
            propagate_arm_pinned: false,
            inherit_arm_pinned: false,
        };
        let mut a = HideArgs::default();
        let e = refuse_apply(&p, &a, &[], none).unwrap_err().to_string();
        assert!(e.contains("requires --confirm-hide 1"), "{e}");
        a.confirm_hide = Some(2);
        let e = refuse_apply(&p, &a, &[], none).unwrap_err().to_string();
        assert!(e.contains("does not match"), "{e}");
        a.confirm_hide = Some(1);
        let pol = vec!["evidence_privacy".to_string()];
        let e = refuse_apply(&p, &a, &pol, none).unwrap_err().to_string();
        assert!(e.contains("--accept-unenforced-hide"), "{e}");
        a.accept_unenforced_hide = true;
        let e = refuse_apply(&p, &a, &pol, none).unwrap_err().to_string();
        assert!(e.contains("kernel guard"), "{e}");
        let full = GuardStatus {
            pin_table: true,
            propagate_arm_pinned: true,
            inherit_arm_pinned: true,
        };
        let e = refuse_apply(&p, &a, &pol, full).unwrap_err().to_string();
        assert!(e.contains("no hide write path"), "{e}");
    }

    #[test]
    fn the_preview_is_eighty_characters_on_one_line() {
        assert_eq!(preview(Some("a\nb")), "a b");
        assert_eq!(preview(Some(&"x".repeat(200))).chars().count(), 80);
        assert_eq!(preview(None), "(no raw_content)");
    }
}
