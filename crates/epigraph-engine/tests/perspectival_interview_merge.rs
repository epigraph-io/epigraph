//! #2 MERGE-AND-RECOMPUTE harness for the perspectival demo.
//!
//! Builds the condition-cluster discovery cluster into a fresh dev DB EXACTLY as
//! `perspectival_discover_load.rs::discover_to_snapshot` does (same repo-layer
//! calls, same open-world BBA recording), snapshots the BEFORE per-perspective
//! BetP for every claim, THEN merges a single practitioner's extracted
//! efficacy/safety BBAs (from the interview-extracted JSON) onto the matching
//! existing claims — attaching new BBAs, never duplicating claims, creating a
//! claim only when no matching efficacy/safety claim exists — and recomputes
//! the AFTER per-perspective BetP via the real engine
//! (`get_perspective_belief`, compute-on-read). It then writes an updated
//! snapshot (same shape as the GUI snapshot JSON) and a compact per-treatment,
//! per-perspective before/after belief-delta report.
//!
//! IMPORTANT: this builds the graph from scratch and assumes an EMPTY,
//! disposable DB (`insert_claim` does no dedup; pointing it at a DB that
//! already holds discovery claims would duplicate them and make attachment
//! ambiguous). Use a dedicated DB, e.g. `epigraph_interview_dev`.
//!
//! Run (all paths supplied via env vars; no hardcoded defaults):
//!   DISCOVERY_IN=$SEED_DIR/data/discovery.json \
//!   INTERVIEW_IN=$SEED_DIR/data/interview-extracted.json \
//!   DATABASE_URL=postgres://epigraph:epigraph@localhost/epigraph_interview_dev \
//!   SEED_DIR=$SEED_DIR \
//!   SNAPSHOT_OUT=$SEED_DIR/gui/data/snapshot-with-interview.json \
//!   DELTA_OUT=$SEED_DIR/data/interview-belief-delta.json \
//!   SQLX_OFFLINE=true cargo test -p epigraph-engine --test perspectival_interview_merge -- --nocapture

use std::collections::{BTreeMap, BTreeSet, HashMap};

use epigraph_db::{EntityRepository, FrameRepository, MassFunctionRepository, PerspectiveRepository, PgPool};
use epigraph_ds::{FocalElement, FrameOfDiscernment, MassFunction};
use serde_json::{json, Map, Value};
use uuid::Uuid;

const OPEN_WORLD_FRACTION: f64 = 0.08;
const PRACTITIONER_SOURCE_TYPE: &str = "source_practitioner";

fn read(path: &str) -> Value {
    let s = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    serde_json::from_str(&s).unwrap_or_else(|e| panic!("parse {path}: {e}"))
}
fn arr<'a>(v: &'a Value, key: &str) -> &'a Vec<Value> {
    v.get(key).and_then(|x| x.as_array()).map(|a| a).unwrap_or_else(|| panic!("missing array {key}"))
}
fn s(v: &Value, key: &str) -> String {
    v.get(key).and_then(|x| x.as_str()).unwrap_or_default().to_string()
}

async fn insert_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key, created_at, updated_at) VALUES ($1, sha256($1::text::bytea), NOW(), NOW())")
        .bind(id).execute(pool).await.expect("agent");
    id
}
async fn insert_claim(pool: &PgPool, author: Uuid, content: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO claims (id, content, content_hash, truth_value, agent_id) VALUES ($1, $2, sha256($1::text::bytea), 0.5, $3)")
        .bind(id).bind(content).bind(author).execute(pool).await.expect("claim");
    id
}
async fn assign(pool: &PgPool, claim: Uuid, frame: Uuid) {
    sqlx::query("INSERT INTO claim_frames (claim_id, frame_id, hypothesis_index) VALUES ($1, $2, 0) ON CONFLICT DO NOTHING")
        .bind(claim).bind(frame).execute(pool).await.expect("assign");
}
async fn betp0(pool: &PgPool, claim: Uuid, frame: Uuid, persp: Uuid) -> f64 {
    epigraph_engine::belief_query::get_perspective_belief(pool, claim, frame, persp)
        .await.expect("belief").pignistic_prob
}

/// Open-world BBA from an arbitrary masses map (hypothesis names + "theta");
/// reserves OPEN_WORLD_FRACTION of theta onto the missing element and
/// normalizes to sum 1. COPIED VERBATIM from perspectival_discover_load.rs (it is
/// private to that test crate). The interview 3-key masses
/// (efficacious/no_effect/theta and safe/harmful/theta) map cleanly onto the
/// frame hypotheses + literal "theta", so they pass through with no fourth
/// open-world key and no renormalize distortion.
fn ow_bba_json(frame: &FrameOfDiscernment, hyps: &[String], masses: &Map<String, Value>) -> Value {
    let mut m: BTreeMap<FocalElement, f64> = BTreeMap::new();
    let mut theta_mass = 0.0;
    for (k, v) in masses {
        let val = v.as_f64().unwrap_or(0.0);
        if k == "theta" {
            theta_mass = val;
        } else if let Some(idx) = hyps.iter().position(|h| h == k) {
            if val > 0.0 {
                *m.entry(FocalElement::positive(BTreeSet::from([idx]))).or_insert(0.0) += val;
            }
        }
    }
    let ow = OPEN_WORLD_FRACTION.min(theta_mass.max(0.0));
    let theta_rem = (theta_mass - ow).max(0.0);
    if theta_rem > 1e-9 {
        m.insert(FocalElement::theta(frame), theta_rem);
    }
    m.insert(FocalElement::missing(frame), ow);
    let sum: f64 = m.values().sum();
    if sum > 0.0 && (sum - 1.0).abs() > 1e-6 {
        for v in m.values_mut() {
            *v /= sum;
        }
    }
    MassFunction::new(frame.clone(), m).expect("ow bba").masses_to_json()
}

/// Match a (possibly latin-suffixed) evidence treatment_key back onto a clean
/// treatment key. COPIED from the converter's inline fuzzy-match logic.
fn match_treatment<'a>(pkg: &'a Value, raw_tk: &str) -> (String, String) {
    let matched = arr(pkg, "treatments").iter().find(|t| {
        let k = s(t, "key");
        !k.is_empty() && (raw_tk == k || raw_tk.starts_with(&k) || raw_tk.contains(&k) || k.contains(raw_tk))
    });
    let tk = matched.map(|t| s(t, "key")).unwrap_or_else(|| raw_tk.to_string());
    let tname = matched.map(|t| s(t, "name")).unwrap_or_else(|| raw_tk.to_string());
    (tk, tname)
}

struct ClaimMeta {
    key: String,
    kind: String,
    frame_key: String,
    target: String,
    content: String,
    treatment: Option<String>,
    symptom: Option<String>,
    dimension: Option<String>,
    evidence: Vec<Value>,
    uuid: Uuid,
    frame_uuid: Uuid,
    /// per-perspective BetP before the practitioner merge
    before: Map<String, Value>,
    /// per-perspective BetP after the practitioner merge
    after: Map<String, Value>,
    /// true if this claim was newly created to host a practitioner BBA (no
    /// prior discovery evidence; its "before" BetP is the vacuous ~0.5 of an
    /// empty/uninformative 2-hyp frame)
    created_for_interview: bool,
    /// true if a practitioner BBA was attached to (or created on) this claim
    touched: bool,
}

#[tokio::test]
async fn merge_interview_and_recompute() {
    let Ok(url) = std::env::var("DATABASE_URL") else { eprintln!("SKIP: DATABASE_URL not set"); return; };
    let pkg_path = std::env::var("DISCOVERY_IN").expect("set DISCOVERY_IN");
    let interview_path = std::env::var("INTERVIEW_IN").expect("set INTERVIEW_IN");
    let dir = std::env::var("SEED_DIR").expect("set SEED_DIR");
    let out = std::env::var("SNAPSHOT_OUT").expect("set SNAPSHOT_OUT");
    let delta_out = std::env::var("DELTA_OUT").expect("set DELTA_OUT");
    let pool = PgPool::connect(&url).await.expect("connect");
    sqlx::migrate!("../../migrations").run(&pool).await.ok();

    let pkg = read(&pkg_path);
    let cluster = pkg.get("cluster").expect("cluster");
    let disease = s(cluster, "disease_state");
    let frames_j = read(&format!("{dir}/seeds/frames.json"));
    let obs_j = read(&format!("{dir}/perspectives/observers.json"));

    // ---- frames (fixed 4) ----
    let mut frame_of: HashMap<String, (Uuid, Vec<String>)> = HashMap::new();
    for f in arr(&frames_j, "frames") {
        let hyps: Vec<String> = arr(f, "hypotheses").iter().map(|h| h.as_str().unwrap().to_string()).collect();
        let row = FrameRepository::create(&pool, &s(f, "name"), None, &hyps).await.expect("frame");
        frame_of.insert(s(f, "key"), (row.id, hyps));
    }
    // ---- perspectives (fixed 4) ----
    let author = insert_agent(&pool).await;
    let mut persp: Vec<(String, String, Uuid, Value)> = Vec::new();
    for p in arr(&obs_j, "perspectives") {
        let row = PerspectiveRepository::create(&pool, &s(p, "name"), None, None,
            p.get("perspective_type").and_then(|x| x.as_str()), &[], None, None).await.expect("persp");
        let map: HashMap<String, f64> = p.get("source_reliability").and_then(|x| x.as_object()).unwrap()
            .iter().map(|(k, v)| (k.clone(), v.as_f64().unwrap())).collect();
        PerspectiveRepository::set_source_reliability(&pool, row.id, &map).await.expect("rel");
        persp.push((s(p, "key"), s(p, "name"), row.id, p.get("source_reliability").cloned().unwrap()));
    }

    // ---- entities: condition-cluster anchor + treatment organisms ----
    let mut entities_out: Vec<Value> = vec![json!({ "key": "disease-state", "name": disease, "type_top": "Condition", "type_sub": "DiseaseState" })];
    EntityRepository::upsert(&pool, &disease, "Condition", Some("DiseaseState"), None, json!({})).await.expect("disease entity");
    let symptom_name: HashMap<String, String> =
        arr(cluster, "symptoms").iter().map(|s_| (s(s_, "key"), s(s_, "name"))).collect();
    for t in arr(&pkg, "treatments") {
        let name = if s(t, "latin").is_empty() { s(t, "name") } else { format!("{} ({})", s(t, "name"), s(t, "latin")) };
        EntityRepository::upsert(&pool, &name, "Organism", Some("Botanical"), None, json!({})).await.expect("treatment entity");
        entities_out.push(json!({ "key": s(t, "key"), "name": name, "type_top": "Organism", "type_sub": "Botanical" }));
    }

    // clean treatment key -> display name (for content of newly-created claims)
    let treat_name: HashMap<String, String> =
        arr(&pkg, "treatments").iter().map(|t| (s(t, "key"), s(t, "name"))).collect();

    // ============================================================
    // STAGE A: build the discovery cluster exactly as the converter
    // ============================================================
    let mut metas: Vec<ClaimMeta> = Vec::new();
    let mut push_claim = |metas: &mut Vec<ClaimMeta>, key: String, kind: &str, frame_key: &str, content: String,
                          treatment: Option<String>, symptom: Option<String>, dimension: Option<String>, evidence: Vec<Value>| {
        let (fu, hyps) = frame_of.get(frame_key).expect("frame").clone();
        metas.push(ClaimMeta {
            key, kind: kind.to_string(), frame_key: frame_key.to_string(), target: hyps[0].clone(),
            content, treatment, symptom, dimension, evidence, uuid: Uuid::nil(), frame_uuid: fu,
            before: Map::new(), after: Map::new(), created_for_interview: false, touched: false,
        });
    };

    // symptom-membership claims
    for sy in arr(cluster, "symptoms") {
        let ev: Vec<Value> = sy.get("membership").and_then(|x| x.as_array()).map(|a| a.iter().map(|m| {
            json!({ "source_type": s(m, "source_type"),
                    "masses": { "holds": m.get("holds").and_then(|x| x.as_f64()).unwrap_or(0.4),
                                "theta": 1.0 - m.get("holds").and_then(|x| x.as_f64()).unwrap_or(0.4) } })
        }).collect()).unwrap_or_default();
        push_claim(&mut metas, s(sy, "key"), "symptom", "symptom_membership", s(sy, "name"),
            None, None, sy.get("dimension").and_then(|x| x.as_str()).map(String::from), ev);
    }
    // diagnostic-label claims
    for (i, lbl) in arr(cluster, "western_labels").iter().enumerate() {
        let lbl = lbl.as_str().unwrap_or("clinical diagnosis").to_string();
        let ev = vec![json!({ "source_type": "source_clinical", "masses": { "holds": 0.85, "theta": 0.15 } })];
        push_claim(&mut metas, format!("label-{i}"), "label", "diagnostic_label",
            format!("This state is correctly labeled {lbl}."), None, None, None, ev);
    }
    // treatment efficacy + safety claims
    for tev in arr(&pkg, "evidence") {
        let raw_tk = s(tev, "treatment_key");
        let (tk, tname) = match_treatment(&pkg, &raw_tk);
        for eff in tev.get("efficacy").and_then(|x| x.as_array()).map(|a| a.clone()).unwrap_or_default() {
            let sk = s(&eff, "symptom_key");
            let sname = symptom_name.get(&sk).cloned().unwrap_or(sk.clone());
            let ev: Vec<Value> = eff.get("sources").and_then(|x| x.as_array()).map(|a| a.iter().map(|sc| {
                json!({ "source_type": s(sc, "source_type"), "masses": sc.get("masses").cloned().unwrap_or(json!({})) })
            }).collect()).unwrap_or_default();
            push_claim(&mut metas, format!("eff-{tk}-{sk}"), "treatment_effect", "treatment_efficacy",
                format!("{tname} is efficacious for {sname}."), Some(tk.clone()), Some(sk), None, ev);
        }
        if let Some(saf) = tev.get("safety").and_then(|x| x.get("sources")).and_then(|x| x.as_array()) {
            let ev: Vec<Value> = saf.iter().map(|sc| json!({ "source_type": s(sc, "source_type"), "masses": sc.get("masses").cloned().unwrap_or(json!({})) })).collect();
            push_claim(&mut metas, format!("saf-{tk}"), "treatment_safety", "treatment_safety",
                format!("{tname} is safe at therapeutic dose for chronic use."), Some(tk.clone()), None, None, ev);
        }
    }

    // insert claims + discovery BBAs (fresh agent per BBA — correct for the
    // discovery sources, which are distinct evidence streams)
    for cm in metas.iter_mut() {
        let cu = insert_claim(&pool, author, &cm.content).await;
        assign(&pool, cu, cm.frame_uuid).await;
        cm.uuid = cu;
        let hyps = frame_of.get(&cm.frame_key).unwrap().1.clone();
        let frame = FrameOfDiscernment::new(cm.frame_key.clone(), hyps.clone()).unwrap();
        for ev in &cm.evidence {
            let st = s(ev, "source_type");
            let masses = ev.get("masses").and_then(|x| x.as_object()).cloned().unwrap_or_default();
            if masses.is_empty() { continue; }
            let bba = ow_bba_json(&frame, &hyps, &masses);
            let src = insert_agent(&pool).await;
            MassFunctionRepository::store_with_perspective(&pool, cu, cm.frame_uuid, Some(src),
                None, &bba, None, Some("discount"), Some(1.0), Some(&st), "cross", None).await.expect("bba");
        }
    }

    // ============================================================
    // STAGE B: snapshot BEFORE beliefs (real engine, compute-on-read)
    // ============================================================
    for cm in metas.iter_mut() {
        let mut betp = Map::new();
        for (pk, _pn, pid, _sr) in &persp {
            betp.insert(pk.clone(), json!(betp0(&pool, cm.uuid, cm.frame_uuid, *pid).await));
        }
        cm.before = betp;
    }

    // ============================================================
    // STAGE C: merge the practitioner interview BBAs
    //   - single practitioner agent (note #2)
    //   - attach to existing efficacy/safety claim by treatment+symptom key
    //   - create a claim only if none exists
    //   - source_type = "source_practitioner" on every entry
    // ============================================================
    let interview = read(&interview_path);
    // (key, id) for each perspective — used to materialize a created claim's
    // baseline "before" BetP inside ensure_meta.
    let persp_ids: Vec<(String, Uuid)> = persp.iter().map(|(k, _, id, _)| (k.clone(), *id)).collect();
    let practitioner = insert_agent(&pool).await;
    let practitioner_did = interview.get("agent").and_then(|a| a.get("did"))
        .and_then(|x| x.as_str()).unwrap_or("did:perspectival:practitioner:unknown").to_string();

    // index existing metas by key for precise attachment (claims live in the DB
    // by content/hash, so the key->uuid map is the only reliable lookup)
    let mut key_index: HashMap<String, usize> =
        metas.iter().enumerate().map(|(i, cm)| (cm.key.clone(), i)).collect();

    // collect (meta_index, frame_key, raw_masses_value, source_type) merges to
    // apply after we finish mutating `metas`, to keep the borrow checker happy.
    struct Merge { idx: usize, masses: Map<String, Value> }
    let mut merges: Vec<Merge> = Vec::new();

    for tev in arr(&interview, "evidence") {
        let raw_tk = s(tev, "treatment_key");
        let (tk, _tname_disc) = match_treatment(&pkg, &raw_tk);
        let tname = treat_name.get(&tk).cloned().unwrap_or_else(|| tk.clone());

        // efficacy entries: one practitioner BBA per (treatment, symptom)
        for eff in tev.get("efficacy").and_then(|x| x.as_array()).map(|a| a.clone()).unwrap_or_default() {
            let sk = s(&eff, "symptom_key");
            let sname = symptom_name.get(&sk).cloned().unwrap_or(sk.clone());
            // the interview provides a single practitioner source per symptom;
            // take its masses (raw 3-key)
            let masses = eff.get("sources").and_then(|x| x.as_array())
                .and_then(|a| a.first())
                .and_then(|sc| sc.get("masses")).and_then(|x| x.as_object()).cloned()
                .unwrap_or_default();
            if masses.is_empty() { continue; }
            let key = format!("eff-{tk}-{sk}");
            let idx = ensure_meta(&pool, &mut metas, &mut key_index, &frame_of, &persp_ids, author,
                &key, "treatment_effect", "treatment_efficacy",
                format!("{tname} is efficacious for {sname}."),
                Some(tk.clone()), Some(sk.clone()), None).await;
            merges.push(Merge { idx, masses });
        }

        // safety entry: one practitioner BBA per treatment
        if let Some(saf_sources) = tev.get("safety").and_then(|x| x.get("sources")).and_then(|x| x.as_array()) {
            let masses = saf_sources.first()
                .and_then(|sc| sc.get("masses")).and_then(|x| x.as_object()).cloned()
                .unwrap_or_default();
            if !masses.is_empty() {
                let key = format!("saf-{tk}");
                let idx = ensure_meta(&pool, &mut metas, &mut key_index, &frame_of, &persp_ids, author,
                    &key, "treatment_safety", "treatment_safety",
                    format!("{tname} is safe at therapeutic dose for chronic use."),
                    Some(tk.clone()), None, None).await;
                merges.push(Merge { idx, masses });
            }
        }
    }

    // apply the practitioner BBAs. A single practitioner agent is used for all;
    // because every merge targets a DISTINCT (claim, frame) — distinct
    // treatment×symptom efficacy claims and one safety claim per treatment —
    // none collide on mass_functions_unique_per_perspective
    // (claim, frame, source_agent, perspective).
    for m in &merges {
        let cm = &mut metas[m.idx];
        cm.touched = true;
        let hyps = frame_of.get(&cm.frame_key).unwrap().1.clone();
        let frame = FrameOfDiscernment::new(cm.frame_key.clone(), hyps.clone()).unwrap();
        let bba = ow_bba_json(&frame, &hyps, &m.masses);
        MassFunctionRepository::store_with_perspective(&pool, cm.uuid, cm.frame_uuid, Some(practitioner),
            None, &bba, None, Some("discount"), Some(1.0), Some(PRACTITIONER_SOURCE_TYPE), "cross", None)
            .await.expect("practitioner bba");
        // append raw-masses practitioner entry to the snapshot evidence list
        // (the snapshot stores RAW masses; ow is applied only to the DB BBA)
        cm.evidence.push(json!({
            "source_type": PRACTITIONER_SOURCE_TYPE,
            "source_agent": practitioner_did,
            "masses": Value::Object(m.masses.clone()),
        }));
    }

    // ============================================================
    // STAGE D: recompute AFTER beliefs (real engine)
    // ============================================================
    for cm in metas.iter_mut() {
        let mut betp = Map::new();
        for (pk, _pn, pid, _sr) in &persp {
            betp.insert(pk.clone(), json!(betp0(&pool, cm.uuid, cm.frame_uuid, *pid).await));
        }
        cm.after = betp;
    }

    // ============================================================
    // STAGE E: write updated snapshot (same shape as the GUI snapshot JSON)
    // ============================================================
    let mut claims_json = Vec::new();
    for cm in &metas {
        claims_json.push(json!({
            "key": cm.key, "kind": cm.kind, "frame": cm.frame_key, "target": cm.target, "content": cm.content,
            "treatment": cm.treatment, "symptom": cm.symptom, "dimension": cm.dimension, "archetype": Value::Null,
            "betp": Value::Object(cm.after.clone()), "evidence": cm.evidence,
        }));
    }
    let persp_out: Vec<Value> = persp.iter().map(|(k, n, _, sr)| json!({ "key": k, "name": n, "source_reliability": sr })).collect();
    let snapshot = json!({
        "generated_from": "agentic discovery + practitioner interview merge → epigraph engine (get_perspective_belief), open-world BBAs",
        "disease": disease,
        "open_world_fraction": OPEN_WORLD_FRACTION,
        "perspectives": persp_out,
        "entities": entities_out,
        "claims": claims_json,
    });
    if let Some(p) = std::path::Path::new(&out).parent() { std::fs::create_dir_all(p).ok(); }
    std::fs::write(&out, serde_json::to_string_pretty(&snapshot).unwrap()).expect("write snapshot");

    // ============================================================
    // STAGE F: write the belief-delta report (touched claims only).
    //   Granularity: efficacy broken out per symptom (the claim granularity);
    //   safety once per treatment. Each entry has before/after BetP per
    //   perspective + delta, and a `created_for_interview` flag so a reader is
    //   not misled by the vacuous (~0.5) "before" of a newly-created claim.
    // ============================================================
    let mut deltas: Vec<Value> = Vec::new();
    for cm in &metas {
        if !cm.touched { continue; }
        let mut per_persp = Map::new();
        for (pk, _pn, _pid, _sr) in &persp {
            let b = cm.before.get(pk).and_then(|v| v.as_f64()).unwrap_or(f64::NAN);
            let a = cm.after.get(pk).and_then(|v| v.as_f64()).unwrap_or(f64::NAN);
            per_persp.insert(pk.clone(), json!({ "before": b, "after": a, "delta": a - b }));
        }
        deltas.push(json!({
            "claim_key": cm.key,
            "kind": cm.kind,
            "dimension": if cm.kind == "treatment_safety" { "safety" } else { "efficacy" },
            "treatment": cm.treatment,
            "symptom": cm.symptom,
            "content": cm.content,
            "created_for_interview": cm.created_for_interview,
            "by_perspective": Value::Object(per_persp),
        }));
    }
    // sort by treatment then kind for a stable, human-readable report
    deltas.sort_by(|x, y| {
        let tx = x.get("treatment").and_then(|v| v.as_str()).unwrap_or("");
        let ty = y.get("treatment").and_then(|v| v.as_str()).unwrap_or("");
        tx.cmp(ty).then(x.get("kind").and_then(|v| v.as_str()).unwrap_or("")
            .cmp(y.get("kind").and_then(|v| v.as_str()).unwrap_or("")))
    });
    let delta_report = json!({
        "generated_from": "perspectival_interview_merge: before vs after per-perspective BetP for claims touched by the practitioner interview",
        "disease": disease,
        "practitioner_agent": practitioner_did,
        "practitioner_source_type": PRACTITIONER_SOURCE_TYPE,
        "open_world_fraction": OPEN_WORLD_FRACTION,
        "perspectives": persp.iter().map(|(k, _, _, _)| json!(k)).collect::<Vec<_>>(),
        "touched_claim_count": deltas.len(),
        "deltas": deltas,
    });
    if let Some(p) = std::path::Path::new(&delta_out).parent() { std::fs::create_dir_all(p).ok(); }
    std::fs::write(&delta_out, serde_json::to_string_pretty(&delta_report).unwrap()).expect("write delta");

    let touched = metas.iter().filter(|c| c.touched).count();
    let created = metas.iter().filter(|c| c.created_for_interview).count();
    eprintln!(
        "INTERVIEW MERGE → {out}  ({} claims × {} perspectives); delta → {delta_out} ({} touched, {} newly-created)",
        metas.len(), persp.len(), touched, created
    );
}

/// Find the meta for `key`, or create the claim + assignment + meta if absent.
/// Returns the index into `metas`. Marks a freshly-created meta with
/// `created_for_interview = true` and materializes its baseline (pre-merge,
/// no-evidence) `before` BetP per perspective from the engine so the delta
/// report shows an honest baseline.
#[allow(clippy::too_many_arguments)]
async fn ensure_meta(
    pool: &PgPool,
    metas: &mut Vec<ClaimMeta>,
    key_index: &mut HashMap<String, usize>,
    frame_of: &HashMap<String, (Uuid, Vec<String>)>,
    persp_ids: &[(String, Uuid)],
    author: Uuid,
    key: &str,
    kind: &str,
    frame_key: &str,
    content: String,
    treatment: Option<String>,
    symptom: Option<String>,
    dimension: Option<String>,
) -> usize {
    if let Some(&i) = key_index.get(key) {
        return i;
    }
    let (fu, hyps) = frame_of.get(frame_key).expect("frame").clone();
    let cu = insert_claim(pool, author, &content).await;
    assign(pool, cu, fu).await;
    // "before" for a created claim: no prior evidence yet, so its
    // get_perspective_belief is the empty-frame BetP (~0.5 on a 2-hyp frame),
    // identical across perspectives. Compute it from the engine NOW (before the
    // practitioner BBA lands) so the delta report shows an honest baseline
    // rather than NaN.
    let mut before: Map<String, Value> = Map::new();
    for (pk, pid) in persp_ids {
        before.insert(pk.clone(), json!(betp0(pool, cu, fu, *pid).await));
    }
    let idx = metas.len();
    metas.push(ClaimMeta {
        key: key.to_string(), kind: kind.to_string(), frame_key: frame_key.to_string(),
        target: hyps[0].clone(), content, treatment, symptom, dimension,
        evidence: Vec::new(), uuid: cu, frame_uuid: fu,
        before, after: Map::new(), created_for_interview: true, touched: false,
    });
    key_index.insert(key.to_string(), idx);
    idx
}
