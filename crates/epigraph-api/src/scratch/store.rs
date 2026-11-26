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
//! * `put_agents` is keyed by agent id. A known id only gains the aliases it
//!   did not have (a set union), so a replay changes nothing.
//! * `relate` is keyed by relation id.
//!
//! # Agents (slice 1b, operator ruling R1)
//!
//! An atom is attributed to a named [`ScratchAgent`] (`speaker_agent`, the
//! agent that said it in the chat) and may be about other agents (`about`).
//! These are the agent→atom edges of EpiGraph's vocabulary, kept as atom
//! fields so they cannot dangle: `speaker_agent` is the `asserts` edge
//! (`epigraph-db` `AGENT_SOURCE_AUTHORSHIP`) and `about` is an `about` edge.
//! Agent↔agent relationships are [`AgentRelation`]s.
//!
//! Agent ids are UUIDv5 of the scope and the normalised display name
//! ([`agent_id`]), computed by the CALLER (the runner), as atom ids are: the
//! runner stores them in its atoms file, so a replay never recomputes one.
//! The store checks every reference: an atom naming an unknown agent is
//! refused. Agent names are chat text: no error detail ever carries one.
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

/// What part an agent plays in the chat.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AgentRole {
    /// The person the chat's user texts come from.
    User,
    /// The agent itself (the chat's assistant texts).
    Assistant,
    /// Any other named person: a speaker of a recorded conversation, or
    /// someone the speakers talk about.
    Participant,
    /// A tool whose output the turn shows.
    Tool,
}

/// The namespace of every belief-context UUIDv5, shared with the runner
/// (`agent-runner/src/belief-context/writer.ts::BELIEF_ID_NAMESPACE`).
pub const BELIEF_ID_NAMESPACE: Uuid = Uuid::from_u128(0x1302_a2e6_3c62_4987_8fdb_9f54_47f0_2187);

/// The comparison form of an agent name: lower-cased, every run of
/// whitespace one space, trimmed. The runner applies NFKC and drops format
/// characters before this; for the plain names this crate itself names
/// (the format-1 reader's role agents) the two agree.
pub fn normalise_name(name: &str) -> String {
    name.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

/// UUIDv5 of `agent/<scope>/<normalised name>` in [`BELIEF_ID_NAMESPACE`].
pub fn agent_id(scope: &str, name: &str) -> Uuid {
    Uuid::new_v5(
        &BELIEF_ID_NAMESPACE,
        format!("agent/{scope}/{}", normalise_name(name)).as_bytes(),
    )
}

/// A named agent of the chat (operator ruling R1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScratchAgent {
    pub id: Uuid,
    pub display_name: String,
    pub role: AgentRole,
    /// Other names the chat uses for this agent, in the order first seen.
    #[serde(default)]
    pub aliases: Vec<String>,
}

/// An agent as the runner sends it in `put_agents`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewAgent {
    pub id: Uuid,
    pub display_name: String,
    pub role: AgentRole,
    #[serde(default)]
    pub aliases: Vec<String>,
}

/// An agent↔agent relationship (`friend_of`, `family_of`, `works_with`, ...).
///
/// `kind` is free text in a fixed shape ([`valid_relation_kind`]); the runner
/// offers the model [`RELATION_KINDS`] first. `turn` is the turn that stated
/// it: the digest lists a relation only once that turn has left the window
/// and is applied, as it does atoms.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentRelation {
    pub id: Uuid,
    pub source: Uuid,
    pub target: Uuid,
    pub kind: String,
    pub turn: u64,
}

/// A relation as the runner sends it in `relate`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewRelation {
    pub id: Uuid,
    pub source: Uuid,
    pub target: Uuid,
    pub kind: String,
    pub turn: u64,
}

/// The relation kinds offered first. EpiGraph's `affiliated_with` is kept
/// as it is spelled there (lower case, as every scratch relationship is).
pub const RELATION_KINDS: [&str; 9] = [
    "friend_of",
    "family_of",
    "partner_of",
    "parent_of",
    "child_of",
    "sibling_of",
    "works_with",
    "affiliated_with",
    "knows",
];

/// A relation kind is 1 to 40 characters: a lower-case ASCII letter, then
/// lower-case letters, digits and `_`. Free text beyond the offered list is
/// allowed in that shape; nothing else, so a kind can never carry markup.
pub fn valid_relation_kind(kind: &str) -> bool {
    let bytes = kind.as_bytes();
    (1..=MAX_RELATION_KIND_CHARS).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_')
}

/// Longest relation kind.
pub const MAX_RELATION_KIND_CHARS: usize = 40;
/// Longest agent name or alias, in characters.
pub const MAX_AGENT_NAME_CHARS: usize = 80;
/// Most aliases one agent keeps.
pub const MAX_AGENT_ALIASES: usize = 16;
/// Most agents one atom is about.
pub const MAX_ABOUT: usize = 8;

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

/// The seed a caller supplies with an atom or a corroboration: the
/// extractor's confidence and the speaker's reliability, kept apart.
///
/// The undiscounted mass is `m({supported}) = confidence`, the rest on Θ.
/// `reliability` (the runner's speaker table, DESIGN §3.4) is applied ONCE,
/// as the BBA's source strength, when the `belief` module seeds it through
/// `epigraph_engine::cdst_bp::seed_mass`. The resulting
/// `m({supported}) = confidence × reliability` is what DESIGN §3.4 asks for.
///
/// The two factors are separate fields with these names, not a single
/// pre-multiplied `supported` mass (DESIGN §4.2's sketch), on purpose (critic
/// finding X6): a caller that multiplied `confidence × reliability` itself
/// and ALSO passed the reliability would discount twice, and the child could
/// not tell. A caller still sending the old `supported` key is refused
/// (`deny_unknown_fields`), never silently mis-weighted.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Seed {
    /// Extractor confidence in the atom, in `[0, 1]`, NOT yet multiplied by
    /// the speaker reliability.
    pub confidence: f64,
    /// Speaker reliability in `[0, 1]`, applied by belief as the source
    /// strength.
    pub reliability: f64,
}

/// One stored seed BBA and the write that contributed it.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeedBba {
    /// The atom id for the atom's own seed, or the corroboration id.
    pub source: Uuid,
    /// Undiscounted mass on `{supported}`, quantized to 1e-6 (see
    /// [`quantize_mass`]).
    pub confidence: f64,
    /// Source strength, quantized to 1e-6.
    pub reliability: f64,
}

/// A stored atom (DESIGN §4.3 `ScratchAtom`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScratchAtom {
    pub id: Uuid,
    pub text: String,
    pub kind: AtomKind,
    /// The agent that said it in the chat (EpiGraph's `asserts`).
    pub speaker_agent: Uuid,
    /// The agents it is about, in the order given, no repeats.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub about: Vec<Uuid>,
    pub turn: u64,
    pub epoch: u64,
    /// When the turn happened in the conversation (RFC 3339, UTC,
    /// milliseconds), as the runner's turn record says; absent when unknown.
    /// `created_at` is when the graph stored the atom, which for a replayed
    /// or lazily extracted turn can be much later.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
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
    /// A stored agent's id.
    pub speaker_agent: Uuid,
    /// Stored agents' ids, at most [`MAX_ABOUT`]; repeats are dropped.
    #[serde(default)]
    pub about: Vec<Uuid>,
    pub turn: u64,
    pub epoch: u64,
    /// RFC 3339 time of the turn; stored normalised to UTC milliseconds.
    #[serde(default)]
    pub at: Option<String>,
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
    /// An id the operation needs does not name a stored agent.
    UnknownAgent(Uuid),
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
            Self::UnknownAgent(_) => "unknown_agent",
            Self::EpochMismatch { .. } => "epoch_mismatch",
            Self::InvalidValue(_) => "invalid_value",
            Self::Conflict(_) => "conflict",
        }
    }

    /// Detail without any atom text: ids, numbers and field names only.
    pub fn detail(&self) -> String {
        match self {
            Self::UnknownAtom(id) => format!("no atom {id}"),
            Self::UnknownAgent(id) => format!("no agent {id}"),
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
    pub agents: usize,
    pub relations: usize,
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

/// Normalise an RFC 3339 time to the stored form (UTC, milliseconds).
fn normalise_at(at: &str) -> Result<String, StoreError> {
    DateTime::parse_from_rfc3339(at.trim())
        .map(|t| timestamp(t.with_timezone(&Utc)))
        .map_err(|_| StoreError::InvalidValue("at"))
}

fn valid_name(name: &str) -> bool {
    !name.trim().is_empty() && name.chars().count() <= MAX_AGENT_NAME_CHARS
}

/// `ids` without repeats, first occurrence kept.
fn dedup_ids(ids: Vec<Uuid>) -> Vec<Uuid> {
    let mut seen = BTreeSet::new();
    ids.into_iter().filter(|id| seen.insert(*id)).collect()
}

fn unit_interval(value: f64) -> bool {
    value.is_finite() && (0.0..=1.0).contains(&value)
}

/// Validate a seed and put both factors on the 1e-6 grid.
fn validate_seed(seed: Seed) -> Result<(f64, f64), StoreError> {
    if !unit_interval(seed.confidence) {
        return Err(StoreError::InvalidValue("seed.confidence"));
    }
    if !unit_interval(seed.reliability) {
        return Err(StoreError::InvalidValue("seed.reliability"));
    }
    Ok((
        quantize_mass(seed.confidence),
        quantize_mass(seed.reliability),
    ))
}

/// The scratch graph of one chat, for one epoch.
#[derive(Debug, Clone, PartialEq)]
pub struct ScratchStore {
    scope: String,
    epoch: u64,
    agents: BTreeMap<Uuid, ScratchAgent>,
    relations: BTreeMap<Uuid, AgentRelation>,
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
            agents: BTreeMap::new(),
            relations: BTreeMap::new(),
            atoms: BTreeMap::new(),
            edges: BTreeMap::new(),
            applied_turns: BTreeSet::new(),
            built_at: timestamp(now),
        }
    }

    /// Rebuild a graph from snapshot parts, checking the invariants a
    /// well-formed snapshot holds. Used by restore only.
    // One argument per snapshot member, so a member cannot be forgotten.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_parts(
        scope: String,
        epoch: u64,
        applied_turns: Vec<u64>,
        agents: Vec<ScratchAgent>,
        relations: Vec<AgentRelation>,
        atoms: Vec<ScratchAtom>,
        edges: Vec<ScratchEdge>,
        built_at: String,
    ) -> Result<Self, &'static str> {
        let mut agent_map = BTreeMap::new();
        for agent in agents {
            if agent_map.insert(agent.id, agent).is_some() {
                return Err("duplicate agent id");
            }
        }
        let mut relation_map = BTreeMap::new();
        for relation in relations {
            if !agent_map.contains_key(&relation.source)
                || !agent_map.contains_key(&relation.target)
            {
                return Err("relation endpoint names a missing agent");
            }
            if relation_map.insert(relation.id, relation).is_some() {
                return Err("duplicate relation id");
            }
        }
        let mut atom_map = BTreeMap::new();
        for atom in atoms {
            if atom.epoch != epoch {
                return Err("atom epoch differs from snapshot epoch");
            }
            if !agent_map.contains_key(&atom.speaker_agent)
                || atom.about.iter().any(|a| !agent_map.contains_key(a))
            {
                return Err("atom names a missing agent");
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
            agents: agent_map,
            relations: relation_map,
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

    /// Every agent, in id order.
    pub fn agents(&self) -> impl Iterator<Item = &ScratchAgent> {
        self.agents.values()
    }

    pub fn agent(&self, id: &Uuid) -> Option<&ScratchAgent> {
        self.agents.get(id)
    }

    /// Every agent↔agent relation, in id order.
    pub fn relations(&self) -> impl Iterator<Item = &AgentRelation> {
        self.relations.values()
    }

    /// Add agents; a known id only gains the aliases it lacks. The whole
    /// batch is validated first. `inserted` counts new agents, `existing`
    /// known ones (with or without new aliases); `updated` counts those that
    /// gained an alias.
    pub fn put_agents(
        &mut self,
        agents: Vec<NewAgent>,
        now: DateTime<Utc>,
    ) -> Result<(BatchOutcome, usize), StoreError> {
        for agent in &agents {
            if !valid_name(&agent.display_name) {
                return Err(StoreError::InvalidValue("agent.display_name"));
            }
            if agent.aliases.len() > MAX_AGENT_ALIASES
                || !agent.aliases.iter().all(|a| valid_name(a))
            {
                return Err(StoreError::InvalidValue("agent.aliases"));
            }
            if let Some(known) = self.agents.get(&agent.id) {
                if known.role != agent.role {
                    return Err(StoreError::Conflict("an agent's role cannot change"));
                }
            }
        }
        let mut outcome = BatchOutcome::default();
        let mut updated = 0;
        for agent in agents {
            match self.agents.get_mut(&agent.id) {
                Some(known) => {
                    outcome.existing += 1;
                    let mut gained = false;
                    for alias in agent.aliases.iter().chain([&agent.display_name]) {
                        let key = normalise_name(alias);
                        let have = std::iter::once(&known.display_name)
                            .chain(known.aliases.iter())
                            .any(|n| normalise_name(n) == key);
                        if !have && known.aliases.len() < MAX_AGENT_ALIASES {
                            known.aliases.push(alias.trim().to_string());
                            gained = true;
                        }
                    }
                    if gained {
                        updated += 1;
                    }
                }
                None => {
                    let display_name = agent.display_name.trim().to_string();
                    let mut aliases: Vec<String> = Vec::new();
                    for alias in agent.aliases {
                        let key = normalise_name(&alias);
                        let have = std::iter::once(&display_name)
                            .chain(aliases.iter())
                            .any(|n| normalise_name(n) == key);
                        if !have {
                            aliases.push(alias.trim().to_string());
                        }
                    }
                    self.agents.insert(
                        agent.id,
                        ScratchAgent {
                            id: agent.id,
                            display_name,
                            role: agent.role,
                            aliases,
                        },
                    );
                    outcome.inserted += 1;
                }
            }
        }
        if outcome.inserted > 0 || updated > 0 {
            self.touch(now);
        }
        Ok((outcome, updated))
    }

    /// Add agent↔agent relations; an id already stored is counted
    /// `existing`. The whole batch is validated first.
    pub fn relate(
        &mut self,
        relations: Vec<NewRelation>,
        now: DateTime<Utc>,
    ) -> Result<BatchOutcome, StoreError> {
        for r in &relations {
            for end in [r.source, r.target] {
                if !self.agents.contains_key(&end) {
                    return Err(StoreError::UnknownAgent(end));
                }
            }
            if r.source == r.target {
                return Err(StoreError::Conflict(
                    "a relation cannot join an agent to itself",
                ));
            }
            if !valid_relation_kind(&r.kind) {
                return Err(StoreError::InvalidValue("relation.kind"));
            }
        }
        let mut outcome = BatchOutcome::default();
        for r in relations {
            if self.relations.contains_key(&r.id) {
                outcome.existing += 1;
                continue;
            }
            self.relations.insert(
                r.id,
                AgentRelation {
                    id: r.id,
                    source: r.source,
                    target: r.target,
                    kind: r.kind,
                    turn: r.turn,
                },
            );
            outcome.inserted += 1;
        }
        if outcome.inserted > 0 {
            self.touch(now);
        }
        Ok(outcome)
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
            agents: self.agents.len(),
            relations: self.relations.len(),
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
        let mut checked = Vec::with_capacity(atoms.len());
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
            for agent in std::iter::once(&atom.speaker_agent).chain(atom.about.iter()) {
                if !self.agents.contains_key(agent) {
                    return Err(StoreError::UnknownAgent(*agent));
                }
            }
            if atom.about.len() > MAX_ABOUT {
                return Err(StoreError::InvalidValue("about"));
            }
            validate_evidence(&atom.evidence)?;
            let at = atom.at.as_deref().map(normalise_at).transpose()?;
            checked.push((validate_seed(atom.seed)?, at));
        }
        let mut outcome = BatchOutcome::default();
        let created_at = timestamp(now);
        for (atom, ((confidence, reliability), at)) in atoms.into_iter().zip(checked) {
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
                    speaker_agent: atom.speaker_agent,
                    about: dedup_ids(atom.about),
                    turn: atom.turn,
                    epoch: atom.epoch,
                    at,
                    created_at: created_at.clone(),
                    is_current: true,
                    superseded_by: None,
                    evidence,
                    bbas: vec![SeedBba {
                        source: atom.id,
                        confidence,
                        reliability,
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
        let (confidence, reliability) = validate_seed(seed)?;
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
            confidence,
            reliability,
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
