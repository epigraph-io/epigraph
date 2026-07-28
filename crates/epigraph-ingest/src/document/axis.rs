//! Validation and resolution of declared labeled axes (issue #222).
//!
//! `ingest_document`'s DS-wiring used to hardcode a single binary frame
//! (`binary_truth` over `{TRUE, FALSE}`) for every claim, even though the
//! kernel is frame-generic: `FrameRepository::create` accepts arbitrary labeled
//! hypotheses and the combination/measures layer works over any frame. What was
//! missing was a way for *ingestion* to place a claim on a declared axis.
//!
//! An [`AxisDeclaration`] on a paragraph (or inherited from its section)
//! resolves to a [`PlannedAxis`] carrying the frame name, its hypotheses, and
//! the index the claim asserts. Absent declaration ⇒ `None` ⇒ the binary
//! default, unchanged.
//!
//! Validation is **fail-closed and up front**: a malformed axis is an error, not
//! a silent downgrade to `binary_truth`. Downgrading would record a belief about
//! `TRUE` for a claim the caller placed on `moderate`, which is worse than a
//! rejected ingest.

use crate::common::plan::PlannedAxis;
use crate::document::schema::{AxisDeclaration, DocumentExtraction, Paragraph, Section};

/// Reserved name of the default binary frame. An axis may not redeclare it —
/// its hypotheses are fixed and every non-axis claim shares it.
pub const BINARY_FRAME_NAME: &str = "binary_truth";

/// Why an axis declaration was rejected. Stringified into the caller-facing
/// `INVALID_PARAMS` message, prefixed with the offending node's path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AxisError {
    /// Fewer than 2 hypotheses — a frame needs at least a binary partition.
    TooFewHypotheses { frame: String, count: usize },
    /// `hypotheses` contains a repeat, so an index would be ambiguous.
    DuplicateHypothesis { frame: String, label: String },
    /// `label` is not one of `hypotheses`.
    LabelNotInFrame {
        frame: String,
        label: String,
        hypotheses: Vec<String>,
    },
    /// Frame name is empty/whitespace, or a hypothesis is.
    EmptyName { frame: String },
    /// Tried to redeclare the reserved binary frame.
    ReservedFrameName { frame: String },
    /// Two paragraphs (or a section and its paragraph) declared the same frame
    /// name with different hypotheses. Frames dedupe by name, so this would
    /// silently place claims on two incompatible readings of one axis.
    InconsistentHypotheses {
        frame: String,
        first: Vec<String>,
        second: Vec<String>,
    },
    /// A per-atom `axis_labels` entry names a label outside the axis.
    AtomLabelNotInFrame {
        frame: String,
        label: String,
        atom_index: usize,
    },
    /// `axis_labels` is longer than `atoms`, so entries would be dropped —
    /// almost always an off-by-one in the caller's arrays.
    MoreLabelsThanAtoms { labels: usize, atoms: usize },
}

impl std::fmt::Display for AxisError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooFewHypotheses { frame, count } => write!(
                f,
                "axis {frame:?} declares {count} hypothes(es); an axis needs at least 2 \
                 (a single-valued axis carries no information — use the default binary frame)"
            ),
            Self::DuplicateHypothesis { frame, label } => write!(
                f,
                "axis {frame:?} lists hypothesis {label:?} more than once; hypotheses must be distinct"
            ),
            Self::LabelNotInFrame {
                frame,
                label,
                hypotheses,
            } => write!(
                f,
                "axis {frame:?} label {label:?} is not one of its hypotheses {hypotheses:?}"
            ),
            Self::EmptyName { frame } => write!(
                f,
                "axis {frame:?} has an empty frame name or hypothesis label"
            ),
            Self::ReservedFrameName { frame } => write!(
                f,
                "{frame:?} is the reserved default frame and cannot be redeclared as an axis; \
                 omit `axis` to use it, or pick another frame name"
            ),
            Self::InconsistentHypotheses {
                frame,
                first,
                second,
            } => write!(
                f,
                "axis {frame:?} is declared twice with different hypotheses ({first:?} vs \
                 {second:?}); frames dedupe by name, so one name must mean one ordered axis"
            ),
            Self::AtomLabelNotInFrame {
                frame,
                label,
                atom_index,
            } => write!(
                f,
                "axis_labels[{atom_index}] = {label:?} is not a hypothesis of axis {frame:?}"
            ),
            Self::MoreLabelsThanAtoms { labels, atoms } => write!(
                f,
                "axis_labels has {labels} entries but there are only {atoms} atoms; \
                 extra labels would be silently dropped"
            ),
        }
    }
}

/// Validate one declaration in isolation and resolve its own `label` to an index.
fn resolve_declaration(decl: &AxisDeclaration) -> Result<PlannedAxis, AxisError> {
    let frame = decl.frame.trim().to_string();
    if frame.is_empty() || decl.hypotheses.iter().any(|h| h.trim().is_empty()) {
        return Err(AxisError::EmptyName { frame });
    }
    if frame == BINARY_FRAME_NAME {
        return Err(AxisError::ReservedFrameName { frame });
    }
    let hypotheses: Vec<String> = decl
        .hypotheses
        .iter()
        .map(|h| h.trim().to_string())
        .collect();
    if hypotheses.len() < 2 {
        return Err(AxisError::TooFewHypotheses {
            frame,
            count: hypotheses.len(),
        });
    }
    for (i, h) in hypotheses.iter().enumerate() {
        if hypotheses[..i].contains(h) {
            return Err(AxisError::DuplicateHypothesis {
                frame,
                label: h.clone(),
            });
        }
    }
    let label = decl.label.trim();
    let hypothesis_index =
        hypotheses
            .iter()
            .position(|h| h == label)
            .ok_or_else(|| AxisError::LabelNotInFrame {
                frame: frame.clone(),
                label: label.to_string(),
                hypotheses: hypotheses.clone(),
            })?;
    Ok(PlannedAxis {
        frame,
        hypotheses,
        hypothesis_index,
    })
}

/// The axis in effect for a paragraph: its own declaration, else its section's.
#[must_use]
pub fn effective_declaration<'a>(
    paragraph: &'a Paragraph,
    section: &'a Section,
) -> Option<&'a AxisDeclaration> {
    paragraph.axis.as_ref().or(section.axis.as_ref())
}

/// Resolve the axis for a paragraph, and for each of its atoms.
///
/// Returns `(paragraph_axis, atom_axes)` where `atom_axes[i]` is the axis for
/// `paragraph.atoms[i]` — the paragraph's axis with `hypothesis_index` swapped
/// to the atom's `axis_labels[i]` override when one is present and non-empty.
/// Both are `None` when no axis is in effect.
///
/// # Errors
/// [`AxisError`] when the declaration is malformed or an override names a label
/// outside the axis.
pub fn resolve_paragraph_axes(
    paragraph: &Paragraph,
    section: &Section,
) -> Result<(Option<PlannedAxis>, Vec<Option<PlannedAxis>>), AxisError> {
    let Some(decl) = effective_declaration(paragraph, section) else {
        // No axis in effect: per-atom labels are meaningless, and silently
        // ignoring them would hide a caller that forgot the declaration.
        return Ok((None, vec![None; paragraph.atoms.len()]));
    };
    let base = resolve_declaration(decl)?;

    if paragraph.axis_labels.len() > paragraph.atoms.len() {
        return Err(AxisError::MoreLabelsThanAtoms {
            labels: paragraph.axis_labels.len(),
            atoms: paragraph.atoms.len(),
        });
    }

    let mut atom_axes = Vec::with_capacity(paragraph.atoms.len());
    for i in 0..paragraph.atoms.len() {
        let override_label = paragraph
            .axis_labels
            .get(i)
            .map(|s| s.trim())
            .filter(|s| !s.is_empty());
        match override_label {
            None => atom_axes.push(Some(base.clone())),
            Some(label) => {
                let idx = base
                    .hypotheses
                    .iter()
                    .position(|h| h == label)
                    .ok_or_else(|| AxisError::AtomLabelNotInFrame {
                        frame: base.frame.clone(),
                        label: label.to_string(),
                        atom_index: i,
                    })?;
                atom_axes.push(Some(PlannedAxis {
                    hypothesis_index: idx,
                    ..base.clone()
                }));
            }
        }
    }
    Ok((Some(base), atom_axes))
}

/// Validate every axis declaration in an extraction before any DB write, and
/// check cross-node consistency: one frame name must mean one ordered
/// hypothesis list across the whole document.
///
/// Call this ahead of plan building so a malformed axis fails the ingest with a
/// path-qualified message instead of half-writing a document.
///
/// # Errors
/// A human-readable message naming the offending node's path.
pub fn validate_axes(extraction: &DocumentExtraction) -> Result<(), String> {
    let mut seen: Vec<(String, Vec<String>)> = Vec::new();

    let mut check = |axis: &PlannedAxis, path: &str| -> Result<(), String> {
        if let Some((_, first)) = seen.iter().find(|(name, _)| *name == axis.frame) {
            if *first != axis.hypotheses {
                return Err(format!(
                    "{path}: {}",
                    AxisError::InconsistentHypotheses {
                        frame: axis.frame.clone(),
                        first: first.clone(),
                        second: axis.hypotheses.clone(),
                    }
                ));
            }
        } else {
            seen.push((axis.frame.clone(), axis.hypotheses.clone()));
        }
        Ok(())
    };

    for (si, section) in extraction.sections.iter().enumerate() {
        let section_path = format!("sections[{si}]");
        if let Some(decl) = &section.axis {
            let resolved =
                resolve_declaration(decl).map_err(|e| format!("{section_path}.axis: {e}"))?;
            check(&resolved, &format!("{section_path}.axis"))?;
        }
        for (pi, paragraph) in section.paragraphs.iter().enumerate() {
            let para_path = format!("{section_path}.paragraphs[{pi}]");
            let (para_axis, _atoms) = resolve_paragraph_axes(paragraph, section)
                .map_err(|e| format!("{para_path}.axis: {e}"))?;
            if let Some(axis) = para_axis {
                check(&axis, &format!("{para_path}.axis"))?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::document::schema::{DocumentSource, SourceType};

    fn decl(frame: &str, hyps: &[&str], label: &str) -> AxisDeclaration {
        AxisDeclaration {
            frame: frame.to_string(),
            hypotheses: hyps.iter().map(|s| (*s).to_string()).collect(),
            label: label.to_string(),
        }
    }

    fn potency(label: &str) -> AxisDeclaration {
        decl(
            "anxiolytic_potency",
            &["ineffective", "mild", "moderate", "strong"],
            label,
        )
    }

    fn para(atoms: &[&str]) -> Paragraph {
        Paragraph {
            text: "p".to_string(),
            span: None,
            atoms: atoms.iter().map(|s| (*s).to_string()).collect(),
            generality: Vec::new(),
            confidence: 0.8,
            methodology: None,
            evidence_type: None,
            axis: None,
            axis_labels: Vec::new(),
            page: None,
            instruments_used: Vec::new(),
            reagents_involved: Vec::new(),
            conditions: Vec::new(),
        }
    }

    fn section(paragraphs: Vec<Paragraph>) -> Section {
        Section {
            title: "s".to_string(),
            heading_span: None,
            axis: None,
            paragraphs,
        }
    }

    fn extraction(sections: Vec<Section>) -> DocumentExtraction {
        DocumentExtraction {
            source: DocumentSource {
                title: "t".to_string(),
                doi: None,
                external_id: None,
                uri: None,
                source_type: SourceType::Paper,
                authors: Vec::new(),
                journal: None,
                year: None,
                metadata: serde_json::Value::Null,
            },
            thesis: None,
            thesis_derivation: Default::default(),
            sections,
            relationships: Vec::new(),
            source_text: None,
        }
    }

    #[test]
    fn label_resolves_to_its_index() {
        let a = resolve_declaration(&potency("moderate")).expect("valid");
        assert_eq!(a.frame, "anxiolytic_potency");
        assert_eq!(a.hypothesis_index, 2);
        assert_eq!(a.hypotheses.len(), 4);
    }

    #[test]
    fn first_and_last_labels_resolve() {
        assert_eq!(
            resolve_declaration(&potency("ineffective"))
                .expect("valid")
                .hypothesis_index,
            0
        );
        assert_eq!(
            resolve_declaration(&potency("strong"))
                .expect("valid")
                .hypothesis_index,
            3
        );
    }

    #[test]
    fn whitespace_is_trimmed_on_frame_label_and_hypotheses() {
        let a = resolve_declaration(&decl("  potency ", &[" low", "high "], " high "))
            .expect("valid after trim");
        assert_eq!(a.frame, "potency");
        assert_eq!(a.hypotheses, vec!["low", "high"]);
        assert_eq!(a.hypothesis_index, 1);
    }

    #[test]
    fn label_outside_frame_is_rejected() {
        let err = resolve_declaration(&potency("very strong")).expect_err("must reject");
        assert!(matches!(err, AxisError::LabelNotInFrame { .. }), "{err:?}");
    }

    #[test]
    fn single_hypothesis_axis_is_rejected() {
        let err = resolve_declaration(&decl("solo", &["only"], "only")).expect_err("must reject");
        assert!(
            matches!(err, AxisError::TooFewHypotheses { count: 1, .. }),
            "{err:?}"
        );
    }

    #[test]
    fn duplicate_hypotheses_are_rejected() {
        let err =
            resolve_declaration(&decl("dup", &["a", "b", "a"], "b")).expect_err("must reject");
        assert!(
            matches!(err, AxisError::DuplicateHypothesis { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn redeclaring_the_binary_frame_is_rejected() {
        let err = resolve_declaration(&decl(BINARY_FRAME_NAME, &["TRUE", "FALSE"], "TRUE"))
            .expect_err("must reject");
        assert!(
            matches!(err, AxisError::ReservedFrameName { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn empty_frame_or_hypothesis_is_rejected() {
        assert!(matches!(
            resolve_declaration(&decl("  ", &["a", "b"], "a")).expect_err("must reject"),
            AxisError::EmptyName { .. }
        ));
        assert!(matches!(
            resolve_declaration(&decl("f", &["a", " "], "a")).expect_err("must reject"),
            AxisError::EmptyName { .. }
        ));
    }

    #[test]
    fn no_axis_yields_none_per_atom() {
        let p = para(&["x", "y"]);
        let (pa, atoms) = resolve_paragraph_axes(&p, &section(vec![])).expect("no axis is fine");
        assert!(pa.is_none());
        assert_eq!(atoms, vec![None, None]);
    }

    #[test]
    fn atoms_inherit_the_paragraph_label_by_default() {
        let mut p = para(&["x", "y"]);
        p.axis = Some(potency("mild"));
        let (pa, atoms) = resolve_paragraph_axes(&p, &section(vec![])).expect("valid");
        assert_eq!(pa.expect("axis").hypothesis_index, 1);
        for a in atoms {
            assert_eq!(a.expect("atom axis").hypothesis_index, 1);
        }
    }

    #[test]
    fn per_atom_labels_override_the_index_on_the_same_frame() {
        let mut p = para(&["x", "y", "z"]);
        p.axis = Some(potency("mild"));
        p.axis_labels = vec![
            "strong".to_string(),
            String::new(),
            "ineffective".to_string(),
        ];
        let (_, atoms) = resolve_paragraph_axes(&p, &section(vec![])).expect("valid");
        let idx: Vec<usize> = atoms
            .iter()
            .map(|a| a.as_ref().expect("axis").hypothesis_index)
            .collect();
        // "" falls back to the paragraph's own label (mild = 1).
        assert_eq!(idx, vec![3, 1, 0]);
        // The frame itself is shared — one axis, different placements.
        assert!(atoms
            .iter()
            .all(|a| a.as_ref().expect("axis").frame == "anxiolytic_potency"));
    }

    #[test]
    fn short_axis_labels_array_leaves_remaining_atoms_on_the_paragraph_label() {
        let mut p = para(&["x", "y", "z"]);
        p.axis = Some(potency("moderate"));
        p.axis_labels = vec!["strong".to_string()];
        let (_, atoms) = resolve_paragraph_axes(&p, &section(vec![])).expect("valid");
        let idx: Vec<usize> = atoms
            .iter()
            .map(|a| a.as_ref().expect("axis").hypothesis_index)
            .collect();
        assert_eq!(idx, vec![3, 2, 2]);
    }

    #[test]
    fn more_labels_than_atoms_is_rejected() {
        let mut p = para(&["x"]);
        p.axis = Some(potency("mild"));
        p.axis_labels = vec!["mild".to_string(), "strong".to_string()];
        let err = resolve_paragraph_axes(&p, &section(vec![])).expect_err("must reject");
        assert!(
            matches!(
                err,
                AxisError::MoreLabelsThanAtoms {
                    labels: 2,
                    atoms: 1
                }
            ),
            "{err:?}"
        );
    }

    #[test]
    fn unknown_per_atom_label_is_rejected_with_its_index() {
        let mut p = para(&["x", "y"]);
        p.axis = Some(potency("mild"));
        p.axis_labels = vec![String::new(), "vigorous".to_string()];
        let err = resolve_paragraph_axes(&p, &section(vec![])).expect_err("must reject");
        assert!(
            matches!(err, AxisError::AtomLabelNotInFrame { atom_index: 1, .. }),
            "{err:?}"
        );
    }

    #[test]
    fn paragraph_inherits_the_section_axis() {
        let p = para(&["x"]);
        let mut s = section(vec![]);
        s.axis = Some(potency("strong"));
        let (pa, atoms) = resolve_paragraph_axes(&p, &s).expect("valid");
        assert_eq!(pa.expect("axis").hypothesis_index, 3);
        assert_eq!(atoms[0].as_ref().expect("axis").hypothesis_index, 3);
    }

    #[test]
    fn paragraph_axis_overrides_the_section_axis() {
        let mut p = para(&["x"]);
        p.axis = Some(decl("grade", &["A", "B"], "B"));
        let mut s = section(vec![]);
        s.axis = Some(potency("strong"));
        let (pa, _) = resolve_paragraph_axes(&p, &s).expect("valid");
        let pa = pa.expect("axis");
        assert_eq!(pa.frame, "grade");
        assert_eq!(pa.hypothesis_index, 1);
    }

    #[test]
    fn validate_accepts_an_axis_free_extraction() {
        validate_axes(&extraction(vec![section(vec![para(&["x"])])])).expect("no axes is valid");
    }

    #[test]
    fn validate_reports_the_offending_path() {
        let mut p = para(&["x"]);
        p.axis = Some(potency("nonexistent"));
        let err = validate_axes(&extraction(vec![
            section(vec![para(&["ok"])]),
            section(vec![para(&["ok"]), p]),
        ]))
        .expect_err("must reject");
        assert!(
            err.starts_with("sections[1].paragraphs[1].axis:"),
            "path not reported: {err}"
        );
    }

    /// One frame name must mean one ordered axis: frames dedupe by name, so two
    /// different hypothesis lists under one name would place claims on
    /// incompatible readings of the "same" axis.
    #[test]
    fn same_frame_name_with_different_hypotheses_is_rejected() {
        let mut p1 = para(&["x"]);
        p1.axis = Some(decl("potency", &["low", "high"], "low"));
        let mut p2 = para(&["y"]);
        p2.axis = Some(decl("potency", &["low", "mid", "high"], "mid"));
        let err = validate_axes(&extraction(vec![section(vec![p1, p2])])).expect_err("must reject");
        assert!(
            err.contains("declared twice with different hypotheses"),
            "{err}"
        );
    }

    #[test]
    fn same_frame_name_with_identical_hypotheses_is_accepted() {
        let mut p1 = para(&["x"]);
        p1.axis = Some(potency("mild"));
        let mut p2 = para(&["y"]);
        p2.axis = Some(potency("strong"));
        validate_axes(&extraction(vec![section(vec![p1, p2])]))
            .expect("one axis, two placements is the point");
    }

    /// Ordering counts: `["low","high"]` and `["high","low"]` assign different
    /// indices to the same label, so they are not the same axis.
    #[test]
    fn hypothesis_order_is_part_of_axis_identity() {
        let mut p1 = para(&["x"]);
        p1.axis = Some(decl("potency", &["low", "high"], "low"));
        let mut p2 = para(&["y"]);
        p2.axis = Some(decl("potency", &["high", "low"], "low"));
        assert!(validate_axes(&extraction(vec![section(vec![p1, p2])])).is_err());
    }

    #[test]
    fn section_and_paragraph_declarations_are_checked_for_consistency() {
        let mut p = para(&["x"]);
        p.axis = Some(decl("potency", &["low", "mid", "high"], "mid"));
        let mut s = section(vec![p]);
        s.axis = Some(decl("potency", &["low", "high"], "low"));
        assert!(validate_axes(&extraction(vec![s])).is_err());
    }
}
