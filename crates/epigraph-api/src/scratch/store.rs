//! The in-memory scratch graph: atoms, edges and the set of applied turns.
//!
//! Everything here is plain data. There is no I/O, no clock read and no
//! environment read: every mutating method takes `now` from its caller, so a
//! test can pin the bytes a snapshot of the store will have.
//!
//! # Idempotence
//!
//! The runner may replay any write after a reap (DESIGN §8), so every write is
//! keyed by a caller-chosen id and a second application is a no-op:
//!
//! * `put_atoms` is keyed by atom id. An id that exists is counted `existing`
//!   and its stored content is left as it was, even when the replayed copy
//!   differs.
//! * `corroborate` is keyed by the corroboration id (the id the restating atom
//!   would have had). Without that key a replay would combine the same BBA onto
//!   its target twice and raise its belief for no new evidence.
//! * `add_edges` is keyed by edge id; `supersede` and `mark_applied` are
//!   naturally idempotent.
//!
//! A batch (`put_atoms`, `add_edges`) is validated whole before any item is
//! applied, so a rejected batch changes nothing.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::bm25;

/// What an atom asserts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AtomKind {
    Fact,
    Decision,
    Preference,
    Instruction,
    Commitment,
    Question,
    Correction,
    Observation,
    /// The placeholder written for a turn whose extraction failed (DESIGN
    /// §3.3), so its content never silently disappears.
    TurnStub,
}

/// Who an atom is attributed to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Speaker {
    User,
    Assistant,
    Tool,
}

/// Edge vocabulary: EpiGraph's own relationship names (DESIGN §4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Relationship {
    Supports,
    Corroborates,
    Elaborates,
    Contradicts,
    Refutes,
    Supersedes,
}

/// A pointer into the runner's evidence files. The graph never reads the
/// file; it only carries the pointer and the hash the runner recorded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    /// Path relative to the belief-context directory, e.g. `turns/12.json`.
    pub path: String,
    /// Lower-case hex SHA-256 of that file when the atom was extracted.
    pub sha256: String,
    /// Opaque locator inside the file (the runner's format, e.g. `tool:2`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub span: Option<String>,
    /// Verbatim anchor text to search the file for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quote: Option<String>,
}

/// The seed mass a caller supplies with an atom or a corroboration.
///
/// Slice 1 meaning: `supported` is the mass on `{supported}` exactly as the
/// runner computed it; the rest is on Θ. The store applies no discount of its
/// own. How that mass becomes an epigraph-ds `MassFunction` (and whether the
/// speaker reliability is folded in here or applied as a source strength,
/// critic finding X6) is decided in E2, which then changes this contract
/// explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Seed {
    pub supported: f64,
}

/// One stored seed BBA and the write that contributed it.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeedBba {
    /// The atom id for the atom's own seed, or the corroboration id.
    pub source: Uuid,
    /// Mass on `{supported}`, quantized to 1e-6 (see [`quantize_mass`]).
    pub supported: f64,
}

/// A stored atom (DESIGN §4.3 `ScratchAtom`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScratchAtom {
    pub id: Uuid,
    pub text: String,
    pub kind: AtomKind,
    pub speaker: Speaker,
    pub turn: u64,
    pub epoch: u64,
    pub created_at: String,
    pub is_current: bool,
    pub superseded_by: Option<Uuid>,
    pub evidence: Vec<Evidence>,
    pub bbas: Vec<SeedBba>,
}

/// A stored edge (DESIGN §4.3 `ScratchEdge`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScratchEdge {
    pub id: Uuid,
    pub source: Uuid,
    pub target: Uuid,
    pub relationship: Relationship,
}

/// An atom as the runner sends it in `put_atoms`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewAtom {
    pub id: Uuid,
    pub text: String,
    pub kind: AtomKind,
    pub speaker: Speaker,
    pub turn: u64,
    pub epoch: u64,
    /// Copied into every evidence entry that has no quote of its own.
    #[serde(default)]
    pub quote: Option<String>,
    #[serde(default)]
    pub evidence: Vec<Evidence>,
    pub seed: Seed,
}

/// An edge as the runner sends it in `add_edges`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewEdge {
    pub id: Uuid,
    pub source: Uuid,
    pub target: Uuid,
    pub rel: Relationship,
}

/// Why a write was refused. Every variant renders without any atom text, so a
/// caller may log it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// An id the operation needs does not name a stored atom.
    UnknownAtom(Uuid),
    /// An atom carried an epoch other than the store's.
    EpochMismatch { expected: u64, got: u64 },
    /// A field failed validation; the payload names the field.
    InvalidValue(&'static str),
    /// The write contradicts the stored graph; the payload names the rule.
    Conflict(&'static str),
}

impl StoreError {
    /// Stable machine-readable code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::UnknownAtom(_) => "unknown_atom",
            Self::EpochMismatch { .. } => "epoch_mismatch",
            Self::InvalidValue(_) => "invalid_value",
            Self::Conflict(_) => "conflict",
        }
    }

    /// Detail without any atom text: ids, numbers and field names only.
    pub fn detail(&self) -> String {
        match self {
            Self::UnknownAtom(id) => format!("no atom {id}"),
            Self::EpochMismatch { expected, got } => {
                format!("store epoch is {expected}, atom epoch is {got}")
            }
            Self::InvalidValue(field) => format!("invalid {field}"),
            Self::Conflict(rule) => (*rule).to_string(),
        }
    }
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code(), self.detail())
    }
}

impl std::error::Error for StoreError {}

/// Counts returned by the batch writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BatchOutcome {
    pub inserted: usize,
    pub existing: usize,
}

/// How a candidate was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CandidateVia {
    Bm25,
    Recent,
}

/// One candidate atom for the extractor.
#[derive(Debug, Clone, PartialEq)]
pub struct Candidate<'a> {
    pub atom: &'a ScratchAtom,
    pub via: CandidateVia,
    /// BM25 score; `None` for a `recent` candidate.
    pub score: Option<f64>,
}

/// Direction of an edge relative to the atom `neighbors` was asked about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Out,
    In,
}

/// Counts for `stats`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Stats {
    pub atoms: usize,
    pub current_atoms: usize,
    pub edges: usize,
    pub applied_turns: usize,
    pub max_applied_turn: Option<u64>,
}

/// Quantize a mass to the 1e-6 grid.
///
/// A snapshot must survive write → restore → write byte for byte, and its
/// hash is checked on restore. A value `k / 1e6` is printed as at most six
/// decimals and parses back with one correctly rounded division, so it
/// round-trips through serde_json's default (not `float_roundtrip`) parser
/// exactly. An arbitrary `f64` is not guaranteed to.
pub fn quantize_mass(value: f64) -> f64 {
    (value * 1e6).round() / 1e6
}

/// The timestamp format stored in `created_at` and `built_at`.
pub fn timestamp(now: DateTime<Utc>) -> String {
    now.to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn validate_evidence(evidence: &[Evidence]) -> Result<(), StoreError> {
    for ev in evidence {
        if ev.path.trim().is_empty() {
            return Err(StoreError::InvalidValue("evidence.path"));
        }
        if !is_sha256_hex(&ev.sha256) {
            return Err(StoreError::InvalidValue("evidence.sha256"));
        }
    }
    Ok(())
}

fn validate_seed(seed: Seed) -> Result<f64, StoreError> {
    if !seed.supported.is_finite() || !(0.0..=1.0).contains(&seed.supported) {
        return Err(StoreError::InvalidValue("seed.supported"));
    }
    Ok(quantize_mass(seed.supported))
}

/// The scratch graph of one chat, for one epoch.
#[derive(Debug, Clone, PartialEq)]
pub struct ScratchStore {
    scope: String,
    epoch: u64,
    atoms: BTreeMap<Uuid, ScratchAtom>,
    edges: BTreeMap<Uuid, ScratchEdge>,
    applied_turns: BTreeSet<u64>,
    built_at: String,
}

impl ScratchStore {
    /// An empty graph.
    pub fn new(scope: impl Into<String>, epoch: u64, now: DateTime<Utc>) -> Self {
        Self {
            scope: scope.into(),
            epoch,
            atoms: BTreeMap::new(),
            edges: BTreeMap::new(),
            applied_turns: BTreeSet::new(),
            built_at: timestamp(now),
        }
    }

    /// Rebuild a graph from snapshot parts, checking the invariants a
    /// well-formed snapshot holds. Used by restore only.
    pub(crate) fn from_parts(
        scope: String,
        epoch: u64,
        applied_turns: Vec<u64>,
        atoms: Vec<ScratchAtom>,
        edges: Vec<ScratchEdge>,
        built_at: String,
    ) -> Result<Self, &'static str> {
        let mut atom_map = BTreeMap::new();
        for atom in atoms {
            if atom.epoch != epoch {
                return Err("atom epoch differs from snapshot epoch");
            }
            if atom.is_current == atom.superseded_by.is_some() {
                return Err("atom is_current disagrees with superseded_by");
            }
            if atom_map.insert(atom.id, atom).is_some() {
                return Err("duplicate atom id");
            }
        }
        for atom in atom_map.values() {
            if let Some(by) = atom.superseded_by {
                if !atom_map.contains_key(&by) {
                    return Err("superseded_by names a missing atom");
                }
            }
        }
        let mut edge_map = BTreeMap::new();
        for edge in edges {
            if !atom_map.contains_key(&edge.source) || !atom_map.contains_key(&edge.target) {
                return Err("edge endpoint names a missing atom");
            }
            if edge_map.insert(edge.id, edge).is_some() {
                return Err("duplicate edge id");
            }
        }
        let turn_count = applied_turns.len();
        let applied: BTreeSet<u64> = applied_turns.into_iter().collect();
        if applied.len() != turn_count {
            return Err("duplicate applied turn");
        }
        Ok(Self {
            scope,
            epoch,
            atoms: atom_map,
            edges: edge_map,
            applied_turns: applied,
            built_at,
        })
    }

    pub fn scope(&self) -> &str {
        &self.scope
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// When the graph's content last changed.
    pub fn built_at(&self) -> &str {
        &self.built_at
    }

    /// Every atom, current or not, in id order.
    pub fn atoms(&self) -> impl Iterator<Item = &ScratchAtom> {
        self.atoms.values()
    }

    /// Every edge, in id order.
    pub fn edges(&self) -> impl Iterator<Item = &ScratchEdge> {
        self.edges.values()
    }

    /// Applied turns, ascending.
    pub fn applied_turns(&self) -> impl Iterator<Item = u64> + '_ {
        self.applied_turns.iter().copied()
    }

    pub fn atom(&self, id: &Uuid) -> Option<&ScratchAtom> {
        self.atoms.get(id)
    }

    pub fn stats(&self) -> Stats {
        Stats {
            atoms: self.atoms.len(),
            current_atoms: self.atoms.values().filter(|a| a.is_current).count(),
            edges: self.edges.len(),
            applied_turns: self.applied_turns.len(),
            max_applied_turn: self.applied_turns.iter().next_back().copied(),
        }
    }

    fn touch(&mut self, now: DateTime<Utc>) {
        self.built_at = timestamp(now);
    }

    /// Insert atoms; an id already stored is counted `existing` and left
    /// unchanged. The whole batch is validated first.
    pub fn put_atoms(
        &mut self,
        atoms: Vec<NewAtom>,
        now: DateTime<Utc>,
    ) -> Result<BatchOutcome, StoreError> {
        let mut seeds = Vec::with_capacity(atoms.len());
        for atom in &atoms {
            if atom.epoch != self.epoch {
                return Err(StoreError::EpochMismatch {
                    expected: self.epoch,
                    got: atom.epoch,
                });
            }
            if atom.text.trim().is_empty() {
                return Err(StoreError::InvalidValue("text"));
            }
            validate_evidence(&atom.evidence)?;
            seeds.push(validate_seed(atom.seed)?);
        }
        let mut outcome = BatchOutcome::default();
        let created_at = timestamp(now);
        for (atom, supported) in atoms.into_iter().zip(seeds) {
            if self.atoms.contains_key(&atom.id) {
                outcome.existing += 1;
                continue;
            }
            let quote = atom.quote;
            let evidence = atom
                .evidence
                .into_iter()
                .map(|mut ev| {
                    if ev.quote.is_none() {
                        ev.quote.clone_from(&quote);
                    }
                    ev
                })
                .collect();
            self.atoms.insert(
                atom.id,
                ScratchAtom {
                    id: atom.id,
                    text: atom.text,
                    kind: atom.kind,
                    speaker: atom.speaker,
                    turn: atom.turn,
                    epoch: atom.epoch,
                    created_at: created_at.clone(),
                    is_current: true,
                    superseded_by: None,
                    evidence,
                    bbas: vec![SeedBba {
                        source: atom.id,
                        supported,
                    }],
                },
            );
            outcome.inserted += 1;
        }
        if outcome.inserted > 0 {
            self.touch(now);
        }
        Ok(outcome)
    }

    /// Combine a second seed onto `target` and append its evidence (the
    /// `restates` relation). Returns `false` when corroboration `id` was
    /// already applied to `target`.
    pub fn corroborate(
        &mut self,
        id: Uuid,
        target: Uuid,
        seed: Seed,
        evidence: Vec<Evidence>,
        now: DateTime<Utc>,
    ) -> Result<bool, StoreError> {
        let supported = validate_seed(seed)?;
        validate_evidence(&evidence)?;
        if id == target {
            return Err(StoreError::Conflict(
                "a corroboration id cannot be its target's id",
            ));
        }
        let atom = self
            .atoms
            .get_mut(&target)
            .ok_or(StoreError::UnknownAtom(target))?;
        if atom.bbas.iter().any(|b| b.source == id) {
            return Ok(false);
        }
        atom.bbas.push(SeedBba {
            source: id,
            supported,
        });
        atom.evidence.extend(evidence);
        self.touch(now);
        Ok(true)
    }

    /// Insert edges; an id already stored is counted `existing`. The whole
    /// batch is validated first.
    pub fn add_edges(
        &mut self,
        edges: Vec<NewEdge>,
        now: DateTime<Utc>,
    ) -> Result<BatchOutcome, StoreError> {
        for edge in &edges {
            for end in [edge.source, edge.target] {
                if !self.atoms.contains_key(&end) {
                    return Err(StoreError::UnknownAtom(end));
                }
            }
            if edge.source == edge.target {
                return Err(StoreError::Conflict(
                    "an edge cannot join an atom to itself",
                ));
            }
        }
        let mut outcome = BatchOutcome::default();
        for edge in edges {
            if self.edges.contains_key(&edge.id) {
                outcome.existing += 1;
                continue;
            }
            self.edges.insert(
                edge.id,
                ScratchEdge {
                    id: edge.id,
                    source: edge.source,
                    target: edge.target,
                    relationship: edge.rel,
                },
            );
            outcome.inserted += 1;
        }
        if outcome.inserted > 0 {
            self.touch(now);
        }
        Ok(outcome)
    }

    /// Hide `old` behind `new` (the `corrects` relation). Returns `false`
    /// when `old` is already superseded; the first superseder is kept.
    pub fn supersede(
        &mut self,
        old: Uuid,
        new: Uuid,
        now: DateTime<Utc>,
    ) -> Result<bool, StoreError> {
        if old == new {
            return Err(StoreError::Conflict("an atom cannot supersede itself"));
        }
        let replacement = self.atoms.get(&new).ok_or(StoreError::UnknownAtom(new))?;
        let replacement_current = replacement.is_current;
        let target = self.atoms.get(&old).ok_or(StoreError::UnknownAtom(old))?;
        if !target.is_current {
            return Ok(false);
        }
        if !replacement_current {
            return Err(StoreError::Conflict(
                "the superseding atom is itself superseded",
            ));
        }
        if let Some(atom) = self.atoms.get_mut(&old) {
            atom.is_current = false;
            atom.superseded_by = Some(new);
        }
        self.touch(now);
        Ok(true)
    }

    /// Record that turn `turn` is fully written. Returns `false` when it
    /// already was.
    pub fn mark_applied(&mut self, turn: u64, now: DateTime<Utc>) -> bool {
        let changed = self.applied_turns.insert(turn);
        if changed {
            self.touch(now);
        }
        changed
    }

    /// Candidate atoms for the extractor: the BM25 top `k` current atoms for
    /// `text`, then up to `recent` of the most recent current atoms not
    /// already listed. Superseded atoms are never candidates.
    pub fn candidates(&self, text: &str, k: usize, recent: usize) -> Vec<Candidate<'_>> {
        // Most recent first, so BM25 ties go to the newer atom.
        let mut current: Vec<&ScratchAtom> = self.atoms.values().filter(|a| a.is_current).collect();
        current.sort_by(|a, b| {
            b.turn
                .cmp(&a.turn)
                .then_with(|| b.created_at.cmp(&a.created_at))
                .then_with(|| a.id.cmp(&b.id))
        });
        let docs: Vec<&str> = current.iter().map(|a| a.text.as_str()).collect();
        let mut out: Vec<Candidate<'_>> = bm25::rank(&docs, text, k)
            .into_iter()
            .map(|(i, score)| Candidate {
                atom: current[i],
                via: CandidateVia::Bm25,
                score: Some(score),
            })
            .collect();
        let listed: BTreeSet<Uuid> = out.iter().map(|c| c.atom.id).collect();
        out.extend(
            current
                .iter()
                .filter(|a| !listed.contains(&a.id))
                .take(recent)
                .map(|a| Candidate {
                    atom: a,
                    via: CandidateVia::Recent,
                    score: None,
                }),
        );
        out
    }

    /// Every edge touching `id`, with its direction, in edge-id order.
    pub fn neighbors(&self, id: &Uuid) -> Result<Vec<(&ScratchEdge, Direction)>, StoreError> {
        if !self.atoms.contains_key(id) {
            return Err(StoreError::UnknownAtom(*id));
        }
        Ok(self
            .edges
            .values()
            .filter_map(|e| {
                if e.source == *id {
                    Some((e, Direction::Out))
                } else if e.target == *id {
                    Some((e, Direction::In))
                } else {
                    None
                }
            })
            .collect())
    }
}
