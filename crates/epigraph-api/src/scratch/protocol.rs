//! The JSON-lines protocol `epigraph-scratch` speaks on stdin/stdout
//! (DESIGN §4.2).
//!
//! # Envelope
//!
//! Each request is one JSON object on one line: `{"id": <any JSON>, "op":
//! "<name>", ...params}`. Each request gets exactly one response line, in
//! order, echoing `id`:
//!
//! ```text
//! {"id":7,"ok":true, ...result}
//! {"id":7,"ok":false,"error":"<code>","detail":"<text-free detail>"}
//! ```
//!
//! A line that is not JSON gets `{"id":null,"ok":false,"error":"bad_json"}`,
//! and the child keeps serving. Blank lines are ignored. Unknown parameters
//! are refused (`bad_request`), so a misspelt or mis-cased key fails loudly
//! instead of being dropped.
//!
//! `detail` never contains atom or query text: only ids, numbers, field names
//! and fixed phrases. A runner may log it.
//!
//! # Operations
//!
//! | op | params | result |
//! |---|---|---|
//! | `health` | — | `status`, `format`, `scope`, `epoch`, `restored_from`, `restore_degraded`, `version` |
//! | `stats` | — | `agents`, `relations`, `atoms`, `current_atoms`, `edges`, `applied_turns`, `max_applied_turn` |
//! | `candidates` | `text`, `k`? (10), `recent`? (10) | `candidates: [{id,text,kind,speaker,speaker_agent,role,turn,via,score}]` |
//! | `put_agents` | `agents: [{id,display_name,role,aliases?}]` | `inserted`, `existing`, `updated` |
//! | `relate` | `relations: [{id,source,target,kind,turn}]` | `inserted`, `existing` |
//! | `agents` | — | `agents: [{id,display_name,role,aliases}]` |
//! | `put_atoms` | `atoms: [{id,text,kind,speaker_agent,about?,turn,epoch,at?,quote?,evidence?,seed:{confidence,reliability}}]` | `inserted`, `existing` |
//! | `corroborate` | `corroboration_id`, `target`, `seed`, `evidence`? | `applied` |
//! | `add_edges` | `edges: [{id,source,target,rel}]` | `inserted`, `existing` |
//! | `supersede` | `old`, `new`, `reason`? | `changed` |
//! | `mark_applied` | `turn` | `changed` |
//! | `update_belief` | — | `current_atoms`, `contested`, `seeds` |
//! | `atom` | `atom_id` | `atom`, `belief: {bel,pl,betp,contested,contested_with}` |
//! | `neighbors` | `atom_id` | `neighbors: [{edge,relationship,direction,atom:{id,text,kind,speaker_agent,turn,is_current}}]` |
//! | `snapshot` | — | `bytes` |
//! | `digest` | `query`, `exclude_turns_from` (the first turn of the verbatim window), `k_per_slice`? (20, at most 200) | `atoms_total`, `eligible`, `turns_archived`, `standing`, `relevant`, `recent`, `recent_corrections`, `open`, `people` (see [`super::rank`]) |
//!
//! Three departures from DESIGN §4.2's sketch:
//!
//! * `seed` is `{confidence, reliability}`, not a pre-multiplied
//!   `{supported}` (critic finding X6): the child applies the reliability
//!   once, as the source strength, so a caller never multiplies it in itself
//!   (see [`super::store::Seed`]). The old key is refused.
//! * `corroborate` takes a `corroboration_id` the sketch does not list: the
//!   id the restating atom would have had (its UUIDv5). It makes a replayed
//!   corroboration a no-op; without it a replay double-counts the BBA.
//! * The sketch writes `atom{id}` and `neighbors{id}`, but `id` is already
//!   the envelope's request id, and a JSON object holds a key once. Those
//!   parameters are `atom_id`.
//!
//! `supersede`'s `reason` is accepted and not stored in slice 1.
//!
//! Agents (slice 1b): a role is `user`, `assistant`, `participant` or
//! `tool`. `put_agents` refuses a known id with another role (`conflict`).
//! An atom's `speaker_agent` and `about` must name stored agents
//! (`unknown_agent`), so the runner sends `put_agents` before `put_atoms`.
//! `speaker` in a `candidates` or `digest` item is the speaker agent's display
//! name, which is chat text like the atom's own.
//!
//! `candidates` and the digest's `relevant` slice index each atom's text
//! together with the names and aliases of its speaker and of the agents it
//! is about, so a query naming a person retrieves that person's atoms.
//!
//! An atom's `at` is the conversation time of its turn (RFC 3339; stored in
//! UTC with milliseconds), carried into every `digest` item, so a question
//! about when something happened does not depend on the extractor having
//! written the date into the text. An unparsable `at` is `invalid_value`.
//!
//! Belief ([`super::belief`]) is derived from the stored graph on every read
//! and never stored, so `update_belief` writes nothing: it recomputes belief
//! for the whole graph, which surfaces a seed that cannot be combined
//! (`belief_failed`), and reports counts. DESIGN §3.4 calls it after each
//! turn's batch; the snapshot that batch's writes took is already the
//! complete state.
//!
//! # Durability
//!
//! A mutating op that changed the graph is followed by a snapshot before its
//! response is written, so `ok:true` means the change is on disk. When the
//! snapshot fails the response is `snapshot_failed`; the change stays in
//! memory and the next mutating op (or `snapshot`) retries the write. Every
//! write is idempotent, so the runner's replay is safe either way.
//!
//! After a restore from `.prev`, the first successful write replaces
//! `graph.json` without rotating it over `.prev`, so the damaged file never
//! displaces the only good copy.
//!
//! `restore_degraded: false` does not prove the graph holds every
//! acknowledged write (a deleted `graph.json` restores an older `.prev`; two
//! deleted files restore empty). The runner compares its ledger's written
//! turns with `stats.applied_turns` on every spawn and replays the gap.

use std::io::{self, BufRead, Write};
use std::path::PathBuf;

use chrono::Utc;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use uuid::Uuid;

use super::belief::{BeliefError, BeliefView};
use super::rank::{self, DEFAULT_K_PER_SLICE, MAX_K_PER_SLICE};
use super::snapshot::{self, RestoreError, RestoreReport, RestoredFrom};
use super::store::{
    AgentRole, Evidence, NewAgent, NewAtom, NewEdge, NewRelation, ScratchAtom, ScratchStore, Seed,
    StoreError,
};

/// Default BM25 hits for `candidates`.
pub const DEFAULT_CANDIDATES_K: usize = 10;
/// Default recent atoms for `candidates` (DESIGN §3.2: "the 10 most recent").
pub const DEFAULT_CANDIDATES_RECENT: usize = 10;
/// Upper bound on either `candidates` count.
pub const MAX_CANDIDATES: usize = 100;

/// A failed request, rendered as `ok:false`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpError {
    pub code: &'static str,
    pub detail: String,
}

impl OpError {
    fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

impl From<BeliefError> for OpError {
    fn from(e: BeliefError) -> Self {
        Self::new("belief_failed", e.to_string())
    }
}

impl From<StoreError> for OpError {
    fn from(e: StoreError) -> Self {
        Self::new(e.code(), e.detail())
    }
}

/// A text-free rendering of a parameter error. serde's messages for a wrong
/// type or value quote the offending value, which may be chat text, so only
/// the missing/unknown-field forms (which name a key) are passed through.
fn param_error(e: &serde_json::Error) -> OpError {
    let msg = e.to_string();
    let detail = if msg.starts_with("missing field") || msg.starts_with("unknown field") {
        msg.split(", expected")
            .next()
            .unwrap_or("bad parameters")
            .to_string()
    } else {
        "a parameter has the wrong type or value".to_string()
    };
    OpError::new("bad_request", detail)
}

fn params<T: DeserializeOwned>(rest: Map<String, Value>) -> Result<T, OpError> {
    serde_json::from_value(Value::Object(rest)).map_err(|e| param_error(&e))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NoParams {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidatesParams {
    text: String,
    #[serde(default)]
    k: Option<usize>,
    #[serde(default)]
    recent: Option<usize>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PutAtomsParams {
    atoms: Vec<NewAtom>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PutAgentsParams {
    agents: Vec<NewAgent>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RelateParams {
    relations: Vec<NewRelation>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CorroborateParams {
    corroboration_id: Uuid,
    target: Uuid,
    seed: Seed,
    #[serde(default)]
    evidence: Vec<Evidence>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AddEdgesParams {
    edges: Vec<NewEdge>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SupersedeParams {
    old: Uuid,
    new: Uuid,
    #[serde(default)]
    #[allow(dead_code)] // accepted for the protocol; not stored in slice 1
    reason: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TurnParams {
    turn: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DigestParams {
    query: String,
    /// The first turn of the verbatim window; pending turns below it are
    /// excluded because they are not applied (see [`super::rank`]).
    exclude_turns_from: u64,
    #[serde(default)]
    k_per_slice: Option<usize>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AtomIdParams {
    atom_id: Uuid,
}

fn atom_summary(atom: &ScratchAtom) -> Value {
    json!({
        "id": atom.id,
        "text": atom.text,
        "kind": atom.kind,
        "speaker_agent": atom.speaker_agent,
        "turn": atom.turn,
        "is_current": atom.is_current,
    })
}

/// The speaker agent's display name and role; an atom always names a stored
/// agent (checked on write and on restore).
fn speaker_of<'s>(store: &'s ScratchStore, atom: &ScratchAtom) -> (&'s str, AgentRole) {
    store
        .agent(&atom.speaker_agent)
        .map_or(("", AgentRole::Participant), |a| {
            (a.display_name.as_str(), a.role)
        })
}

/// One running scratch graph bound to its snapshot file.
#[derive(Debug)]
pub struct Session {
    store: ScratchStore,
    snapshot_path: PathBuf,
    restore: RestoreReport,
    /// The in-memory graph has changes no snapshot holds yet.
    dirty: bool,
    /// The graph came from `.prev`: the next successful write must not
    /// rotate the (damaged or missing) `graph.json` over that good `.prev`.
    keep_prev_once: bool,
}

impl Session {
    /// Restore the graph for `scope`/`epoch` from `snapshot_path` (see
    /// [`snapshot::restore`]).
    pub fn open(snapshot_path: PathBuf, scope: &str, epoch: u64) -> Result<Self, RestoreError> {
        let (store, restore) = snapshot::restore(&snapshot_path, scope, epoch, Utc::now())?;
        let keep_prev_once = restore.from == RestoredFrom::Prev;
        Ok(Self {
            store,
            snapshot_path,
            restore,
            dirty: false,
            keep_prev_once,
        })
    }

    pub fn store(&self) -> &ScratchStore {
        &self.store
    }

    pub fn restore_report(&self) -> &RestoreReport {
        &self.restore
    }

    fn persist(&mut self) -> Result<usize, OpError> {
        let bytes = snapshot::encode(&self.store);
        let write = if self.keep_prev_once {
            snapshot::write_atomic_keeping_prev
        } else {
            snapshot::write_atomic
        };
        write(&self.snapshot_path, &bytes).map_err(|e| {
            OpError::new(
                "snapshot_failed",
                format!("snapshot write failed: {:?}", e.kind()),
            )
        })?;
        // Cleared only on success: a failed write retries without rotating.
        self.keep_prev_once = false;
        self.dirty = false;
        Ok(bytes.len())
    }

    /// After a mutating op: snapshot if anything is unsaved, then answer.
    fn commit(&mut self, changed: bool, result: Value) -> Result<Value, OpError> {
        self.dirty |= changed;
        if self.dirty {
            self.persist()?;
        }
        Ok(result)
    }

    /// Handle one request line and return its response object.
    pub fn handle_line(&mut self, line: &[u8]) -> Value {
        let request: Value = match serde_json::from_slice(line) {
            Ok(v) => v,
            Err(e) => {
                return json!({
                    "id": Value::Null,
                    "ok": false,
                    "error": "bad_json",
                    "detail": format!("not JSON at column {}", e.column()),
                })
            }
        };
        let Value::Object(mut fields) = request else {
            return json!({
                "id": Value::Null,
                "ok": false,
                "error": "bad_request",
                "detail": "a request must be a JSON object",
            });
        };
        let id = fields.remove("id").unwrap_or(Value::Null);
        let result = match fields.remove("op") {
            Some(Value::String(op)) => self.dispatch(&op, fields),
            Some(_) => Err(OpError::new("bad_request", "op must be a string")),
            None => Err(OpError::new("bad_request", "missing field `op`")),
        };
        match result {
            Ok(Value::Object(body)) => {
                let mut out = Map::new();
                out.insert("id".into(), id);
                out.insert("ok".into(), Value::Bool(true));
                out.extend(body);
                Value::Object(out)
            }
            Ok(other) => json!({ "id": id, "ok": true, "result": other }),
            Err(e) => json!({ "id": id, "ok": false, "error": e.code, "detail": e.detail }),
        }
    }

    fn dispatch(&mut self, op: &str, rest: Map<String, Value>) -> Result<Value, OpError> {
        let now = Utc::now();
        match op {
            "health" => {
                params::<NoParams>(rest)?;
                Ok(json!({
                    "status": "ok",
                    "format": snapshot::FORMAT,
                    "scope": self.store.scope(),
                    "epoch": self.store.epoch(),
                    "restored_from": self.restore.from.as_str(),
                    "restore_degraded": self.restore.degraded(),
                    "version": env!("CARGO_PKG_VERSION"),
                }))
            }
            "stats" => {
                params::<NoParams>(rest)?;
                let s = self.store.stats();
                Ok(json!({
                    "agents": s.agents,
                    "relations": s.relations,
                    "atoms": s.atoms,
                    "current_atoms": s.current_atoms,
                    "edges": s.edges,
                    "applied_turns": s.applied_turns,
                    "max_applied_turn": s.max_applied_turn,
                }))
            }
            "candidates" => {
                let p: CandidatesParams = params(rest)?;
                let k = p.k.unwrap_or(DEFAULT_CANDIDATES_K);
                let recent = p.recent.unwrap_or(DEFAULT_CANDIDATES_RECENT);
                if k > MAX_CANDIDATES || recent > MAX_CANDIDATES {
                    return Err(OpError::new(
                        "bad_request",
                        format!("k and recent are at most {MAX_CANDIDATES}"),
                    ));
                }
                let list: Vec<Value> = self
                    .store
                    .candidates(&p.text, k, recent)
                    .into_iter()
                    .map(|c| {
                        let (speaker, role) = speaker_of(&self.store, c.atom);
                        json!({
                            "id": c.atom.id,
                            "text": c.atom.text,
                            "kind": c.atom.kind,
                            "speaker": speaker,
                            "speaker_agent": c.atom.speaker_agent,
                            "role": role,
                            "turn": c.atom.turn,
                            "via": c.via,
                            "score": c.score,
                        })
                    })
                    .collect();
                Ok(json!({ "candidates": list }))
            }
            "put_agents" => {
                let p: PutAgentsParams = params(rest)?;
                let (out, updated) = self.store.put_agents(p.agents, now)?;
                self.commit(
                    out.inserted > 0 || updated > 0,
                    json!({ "inserted": out.inserted, "existing": out.existing, "updated": updated }),
                )
            }
            "relate" => {
                let p: RelateParams = params(rest)?;
                let out = self.store.relate(p.relations, now)?;
                self.commit(
                    out.inserted > 0,
                    json!({ "inserted": out.inserted, "existing": out.existing }),
                )
            }
            "agents" => {
                params::<NoParams>(rest)?;
                let list: Vec<&super::store::ScratchAgent> = self.store.agents().collect();
                Ok(json!({ "agents": list }))
            }
            "put_atoms" => {
                let p: PutAtomsParams = params(rest)?;
                let out = self.store.put_atoms(p.atoms, now)?;
                self.commit(
                    out.inserted > 0,
                    json!({ "inserted": out.inserted, "existing": out.existing }),
                )
            }
            "corroborate" => {
                let p: CorroborateParams = params(rest)?;
                let applied = self.store.corroborate(
                    p.corroboration_id,
                    p.target,
                    p.seed,
                    p.evidence,
                    now,
                )?;
                self.commit(applied, json!({ "applied": applied }))
            }
            "add_edges" => {
                let p: AddEdgesParams = params(rest)?;
                let out = self.store.add_edges(p.edges, now)?;
                self.commit(
                    out.inserted > 0,
                    json!({ "inserted": out.inserted, "existing": out.existing }),
                )
            }
            "supersede" => {
                let p: SupersedeParams = params(rest)?;
                let changed = self.store.supersede(p.old, p.new, now)?;
                self.commit(changed, json!({ "changed": changed }))
            }
            "mark_applied" => {
                let p: TurnParams = params(rest)?;
                let changed = self.store.mark_applied(p.turn, now);
                self.commit(changed, json!({ "changed": changed }))
            }
            "update_belief" => {
                params::<NoParams>(rest)?;
                let view = BeliefView::compute(&self.store)?;
                Ok(serde_json::to_value(view.summary(&self.store))
                    .expect("belief summary serializes"))
            }
            "atom" => {
                let p: AtomIdParams = params(rest)?;
                let atom = self
                    .store
                    .atom(&p.atom_id)
                    .ok_or(StoreError::UnknownAtom(p.atom_id))?;
                let view = BeliefView::compute(&self.store)?;
                Ok(json!({ "atom": atom, "belief": view.get(&p.atom_id) }))
            }
            "neighbors" => {
                let p: AtomIdParams = params(rest)?;
                let list: Vec<Value> = self
                    .store
                    .neighbors(&p.atom_id)?
                    .into_iter()
                    .filter_map(|(edge, direction)| {
                        let other = match direction {
                            super::store::Direction::Out => edge.target,
                            super::store::Direction::In => edge.source,
                        };
                        self.store.atom(&other).map(|atom| {
                            json!({
                                "edge": edge.id,
                                "relationship": edge.relationship,
                                "direction": direction,
                                "atom": atom_summary(atom),
                            })
                        })
                    })
                    .collect();
                Ok(json!({ "neighbors": list }))
            }
            "snapshot" => {
                params::<NoParams>(rest)?;
                let bytes = self.persist()?;
                Ok(json!({ "bytes": bytes }))
            }
            "digest" => {
                let p: DigestParams = params(rest)?;
                let k = p.k_per_slice.unwrap_or(DEFAULT_K_PER_SLICE);
                if k > MAX_K_PER_SLICE {
                    return Err(OpError::new(
                        "bad_request",
                        format!("k_per_slice is at most {MAX_K_PER_SLICE}"),
                    ));
                }
                let view = BeliefView::compute(&self.store)?;
                let digest = rank::digest(&self.store, &view, &p.query, p.exclude_turns_from, k);
                Ok(serde_json::to_value(digest).expect("digest serializes"))
            }
            _ => Err(OpError::new("unknown_op", "no such op")),
        }
    }
}

/// Serve requests from `input` until end of input, one response line per
/// request line, flushing after each.
pub fn serve<R: BufRead, W: Write>(
    session: &mut Session,
    mut input: R,
    mut output: W,
) -> io::Result<()> {
    let mut line = Vec::new();
    loop {
        line.clear();
        if input.read_until(b'\n', &mut line)? == 0 {
            return Ok(());
        }
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let response = session.handle_line(&line);
        serde_json::to_writer(&mut output, &response)?;
        output.write_all(b"\n")?;
        output.flush()?;
    }
}
