//! Converts an agentic DISCOVERY PACKAGE (the perspectival-discover workflow's output) into a
//! real-CDST-engine snapshot for the GUI: builds the cluster's claims + per-source BBAs
//! (open-world), loads them into a fresh dev DB, and computes get_perspective_belief for
//! every claim × perspective.
//!
//! Run (all paths supplied via env vars; no hardcoded defaults):
//!   DISCOVERY_IN=$SEED_DIR/data/discovery.json \
//!   DATABASE_URL=postgres://epigraph:epigraph@localhost/epigraph_cluster_dev \
//!   SEED_DIR=$SEED_DIR SNAPSHOT_OUT=$SEED_DIR/data/snapshot.json \
//!   SQLX_OFFLINE=true cargo test -p epigraph-engine --test perspectival_discover_load -- --nocapture

use std::collections::{BTreeMap, BTreeSet, HashMap};

use epigraph_db::{EntityRepository, FrameRepository, MassFunctionRepository, PerspectiveRepository, PgPool};
use epigraph_ds::{FocalElement, FrameOfDiscernment, MassFunction};
use serde_json::{json, Map, Value};
use uuid::Uuid;

const OPEN_WORLD_FRACTION: f64 = 0.08;

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

/// Open-world BBA from an arbitrary masses map (hypothesis names + "theta"); reserves
/// OPEN_WORLD_FRACTION of theta onto the missing element and normalizes to sum 1.
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
    // tolerate agent masses that don't sum to exactly 1
    let sum: f64 = m.values().sum();
    if sum > 0.0 && (sum - 1.0).abs() > 1e-6 {
        for v in m.values_mut() {
            *v /= sum;
        }
    }
    MassFunction::new(frame.clone(), m).expect("ow bba").masses_to_json()
}

struct ClaimMeta {
    key: String, kind: String, frame_key: String, target: String, content: String,
    treatment: Option<String>, symptom: Option<String>, dimension: Option<String>,
    evidence: Vec<Value>, uuid: Uuid, frame_uuid: Uuid,
}

#[tokio::test]
async fn discover_to_snapshot() {
    let Ok(url) = std::env::var("DATABASE_URL") else { eprintln!("SKIP: DATABASE_URL not set"); return; };
    let pkg_path = std::env::var("DISCOVERY_IN").expect("set DISCOVERY_IN");
    let dir = std::env::var("SEED_DIR").expect("set SEED_DIR");
    let out = std::env::var("SNAPSHOT_OUT").expect("set SNAPSHOT_OUT");
    let pool = PgPool::connect(&url).await.expect("connect");
    sqlx::migrate!("../../migrations").run(&pool).await.ok();

    let pkg = read(&pkg_path);
    let cluster = pkg.get("cluster").expect("cluster");
    let disease = s(cluster, "disease_state");
    let frames_j = read(&format!("{dir}/seeds/frames.json"));
    let obs_j = read(&format!("{dir}/perspectives/observers.json"));

    // frames (fixed 4)
    let mut frame_of: HashMap<String, (Uuid, Vec<String>)> = HashMap::new();
    for f in arr(&frames_j, "frames") {
        let hyps: Vec<String> = arr(f, "hypotheses").iter().map(|h| h.as_str().unwrap().to_string()).collect();
        let row = FrameRepository::create(&pool, &s(f, "name"), None, &hyps).await.expect("frame");
        frame_of.insert(s(f, "key"), (row.id, hyps));
    }
    // perspectives (fixed 4)
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

    // entities: condition-cluster anchor + treatment organisms
    let mut entities_out: Vec<Value> = vec![json!({ "key": "disease-state", "name": disease, "type_top": "Condition", "type_sub": "DiseaseState" })];
    EntityRepository::upsert(&pool, &disease, "Condition", Some("DiseaseState"), None, json!({})).await.expect("condition entity");
    let symptom_name: HashMap<String, String> =
        arr(cluster, "symptoms").iter().map(|s_| (s(s_, "key"), s(s_, "name"))).collect();
    for t in arr(&pkg, "treatments") {
        let name = if s(t, "latin").is_empty() { s(t, "name") } else { format!("{} ({})", s(t, "name"), s(t, "latin")) };
        EntityRepository::upsert(&pool, &name, "Organism", Some("Botanical"), None, json!({})).await.expect("treatment entity");
        entities_out.push(json!({ "key": s(t, "key"), "name": name, "type_top": "Organism", "type_sub": "Botanical" }));
    }

    let mut metas: Vec<ClaimMeta> = Vec::new();
    let mut push_claim = |metas: &mut Vec<ClaimMeta>, key: String, kind: &str, frame_key: &str, content: String,
                          treatment: Option<String>, symptom: Option<String>, dimension: Option<String>, evidence: Vec<Value>| {
        let (fu, hyps) = frame_of.get(frame_key).expect("frame").clone();
        metas.push(ClaimMeta {
            key, kind: kind.to_string(), frame_key: frame_key.to_string(), target: hyps[0].clone(),
            content, treatment, symptom, dimension, evidence, uuid: Uuid::nil(), frame_uuid: fu,
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
    // diagnostic-label claims (clinical artifact; perspectives differentiate by α)
    for (i, lbl) in arr(cluster, "western_labels").iter().enumerate() {
        let lbl = lbl.as_str().unwrap_or("clinical diagnosis").to_string();
        let ev = vec![json!({ "source_type": "source_clinical", "masses": { "holds": 0.85, "theta": 0.15 } })];
        push_claim(&mut metas, format!("label-{i}"), "label", "diagnostic_label",
            format!("This state is correctly labeled {lbl}."), None, None, None, ev);
    }
    // treatment efficacy + safety claims
    for tev in arr(&pkg, "evidence") {
        let raw_tk = s(tev, "treatment_key");
        // evidence treatment_key may be the long form ("treatment-e-binomial-treatment-e");
        // match it back to the clean treatment key so claim keys + entity links line up.
        let matched = arr(&pkg, "treatments").iter().find(|t| {
            let k = s(t, "key");
            !k.is_empty() && (raw_tk == k || raw_tk.starts_with(&k) || raw_tk.contains(&k) || k.contains(&raw_tk))
        });
        let tk = matched.map(|t| s(t, "key")).unwrap_or_else(|| raw_tk.clone());
        let tname = matched.map(|t| s(t, "name")).unwrap_or_else(|| raw_tk.clone());
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

    // insert claims + BBAs
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
            // fresh agent per BBA so repeated source_types on one claim don't collide on
            // mass_functions_unique_per_perspective (claim, frame, source_agent, perspective)
            let src = insert_agent(&pool).await;
            MassFunctionRepository::store_with_perspective(&pool, cu, cm.frame_uuid, Some(src),
                None, &bba, None, Some("discount"), Some(1.0), Some(&st), "cross", None).await.expect("bba");
        }
    }

    // compute beliefs + assemble snapshot (same shape as perspectival_snapshot)
    let mut claims_json = Vec::new();
    for cm in &metas {
        let mut betp = Map::new();
        for (pk, _pn, pid, _sr) in &persp {
            betp.insert(pk.clone(), json!(betp0(&pool, cm.uuid, cm.frame_uuid, *pid).await));
        }
        claims_json.push(json!({
            "key": cm.key, "kind": cm.kind, "frame": cm.frame_key, "target": cm.target, "content": cm.content,
            "treatment": cm.treatment, "symptom": cm.symptom, "dimension": cm.dimension, "archetype": Value::Null,
            "betp": Value::Object(betp), "evidence": cm.evidence,
        }));
    }
    let persp_out: Vec<Value> = persp.iter().map(|(k, n, _, sr)| json!({ "key": k, "name": n, "source_reliability": sr })).collect();
    let snapshot = json!({
        "generated_from": "agentic discovery → epigraph engine (get_perspective_belief), open-world BBAs",
        "disease": disease,
        "open_world_fraction": OPEN_WORLD_FRACTION,
        "perspectives": persp_out,
        "entities": entities_out,
        "claims": claims_json,
    });
    if let Some(p) = std::path::Path::new(&out).parent() { std::fs::create_dir_all(p).ok(); }
    std::fs::write(&out, serde_json::to_string_pretty(&snapshot).unwrap()).expect("write");
    eprintln!("CONDITION-CLUSTER SNAPSHOT → {out}  ({} claims × {} perspectives)", metas.len(), persp.len());
}
