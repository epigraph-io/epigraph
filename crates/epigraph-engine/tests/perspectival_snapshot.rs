//! Generates a real-CDST-engine snapshot of the perspectival-demo cluster for the GUI.
//!
//! Loads the seed into a FRESH dev DB (open-world BBAs), then computes the REAL
//! `get_perspective_belief` for every claim × every perspective and dumps a JSON
//! the Next.js frontend consumes. Numbers are the engine's, not a reimplementation.
//!
//! Run (against a freshly (re)created DB; paths supplied via env vars, no defaults):
//!   DATABASE_URL=postgres://epigraph:epigraph@localhost/epigraph_demo_dev \
//!   SEED_DIR=$SEED_DIR SNAPSHOT_OUT=$SEED_DIR/data/snapshot.json \
//!   SQLX_OFFLINE=true cargo test -p epigraph-engine --test perspectival_snapshot -- --nocapture

use std::collections::{BTreeMap, BTreeSet, HashMap};

use epigraph_db::{EntityRepository, FrameRepository, MassFunctionRepository, PerspectiveRepository, PgPool};
use epigraph_ds::{FocalElement, FrameOfDiscernment, MassFunction};
use serde_json::{json, Value};
use uuid::Uuid;

const OPEN_WORLD_FRACTION: f64 = 0.08;

fn read(dir: &str, file: &str) -> Value {
    let path = format!("{dir}/{file}");
    let s = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    serde_json::from_str(&s).unwrap_or_else(|e| panic!("parse {path}: {e}"))
}
fn arr<'a>(v: &'a Value, key: &str) -> &'a Vec<Value> {
    v.get(key).and_then(|x| x.as_array()).unwrap_or_else(|| panic!("missing array {key}"))
}
fn s(v: &Value, key: &str) -> String {
    v.get(key).and_then(|x| x.as_str()).unwrap_or_else(|| panic!("missing str {key}")).to_string()
}
fn s_opt(v: &Value, key: &str) -> Option<String> {
    v.get(key).and_then(|x| x.as_str()).map(String::from)
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
fn ow_bba_json(frame: &FrameOfDiscernment, hyps: &[String], masses: &Value) -> Value {
    let obj = masses.as_object().expect("masses obj");
    let (mut hyp_idx, mut hyp_mass, mut theta_mass) = (None, 0.0, 0.0);
    for (k, v) in obj {
        let val = v.as_f64().expect("mass f64");
        if k == "theta" { theta_mass = val; }
        else { hyp_idx = Some(hyps.iter().position(|h| h == k).unwrap_or_else(|| panic!("hyp {k}"))); hyp_mass = val; }
    }
    let idx = hyp_idx.expect("hyp");
    let ow = OPEN_WORLD_FRACTION.min(theta_mass);
    let theta_rem = (theta_mass - ow).max(0.0);
    let mut m: BTreeMap<FocalElement, f64> = BTreeMap::new();
    m.insert(FocalElement::positive(BTreeSet::from([idx])), hyp_mass);
    if theta_rem > 1e-9 { m.insert(FocalElement::theta(frame), theta_rem); }
    m.insert(FocalElement::missing(frame), ow);
    MassFunction::new(frame.clone(), m).expect("ow bba").masses_to_json()
}

struct ClaimMeta {
    key: String, kind: String, frame: String, target: String, content: String,
    treatment: Option<String>, symptom: Option<String>, dimension: Option<String>, archetype: Option<String>,
    evidence: Vec<Value>, uuid: Uuid, frame_uuid: Uuid,
}

#[tokio::test]
#[ignore = "requires SEED_DIR + dedicated dev DB; run manually with --ignored"]
async fn generate_snapshot() {
    let Ok(url) = std::env::var("DATABASE_URL") else { eprintln!("SKIP: DATABASE_URL not set"); return; };
    let dir = std::env::var("SEED_DIR").expect("set SEED_DIR");
    let out = std::env::var("SNAPSHOT_OUT").expect("set SNAPSHOT_OUT");
    let pool = PgPool::connect(&url).await.expect("connect");
    sqlx::migrate!("../../migrations").run(&pool).await.ok();

    let frames_j = read(&dir, "seeds/frames.json");
    let entities_j = read(&dir, "seeds/entities.json");
    let agents_j = read(&dir, "seeds/agents.json");
    let claims_j = read(&dir, "seeds/claims.json");
    let obs_j = read(&dir, "perspectives/observers.json");

    let author = insert_agent(&pool).await;
    let mut agent_id: HashMap<String, Uuid> = HashMap::new();
    let mut persp: Vec<(String, String, Uuid, Value)> = Vec::new();
    let mut frame_of: HashMap<String, (Uuid, Vec<String>)> = HashMap::new();

    for f in arr(&frames_j, "frames") {
        let hyps: Vec<String> = arr(f, "hypotheses").iter().map(|h| h.as_str().unwrap().to_string()).collect();
        let row = FrameRepository::create(&pool, &s(f, "name"), None, &hyps).await.expect("frame");
        frame_of.insert(s(f, "key"), (row.id, hyps));
    }
    for grp in ["source_agents", "observer_agents"] {
        if let Some(list) = agents_j.get(grp).and_then(|x| x.as_array()) {
            for a in list { agent_id.insert(s(a, "key"), insert_agent(&pool).await); }
        }
    }
    for e in arr(&entities_j, "entities") {
        EntityRepository::upsert(&pool, &s(e, "canonical_name"), &s(e, "type_top"),
            e.get("type_sub").and_then(|x| x.as_str()), None,
            e.get("properties").cloned().unwrap_or_else(|| json!({}))).await.expect("entity");
    }
    for p in arr(&obs_j, "perspectives") {
        let row = PerspectiveRepository::create(&pool, &s(p, "name"), None, None,
            p.get("perspective_type").and_then(|x| x.as_str()), &[], None, None).await.expect("persp");
        let map: HashMap<String, f64> = p.get("source_reliability").and_then(|x| x.as_object()).unwrap()
            .iter().map(|(k, v)| (k.clone(), v.as_f64().unwrap())).collect();
        PerspectiveRepository::set_source_reliability(&pool, row.id, &map).await.expect("rel");
        persp.push((s(p, "key"), s(p, "name"), row.id, p.get("source_reliability").cloned().unwrap()));
    }

    let mut claims: Vec<ClaimMeta> = Vec::new();
    for c in arr(&claims_j, "claims") {
        let fk = s(c, "frame");
        let (frame_uuid, hyps) = frame_of.get(&fk).expect("frame").clone();
        let cu = insert_claim(&pool, author, &s(c, "content")).await;
        assign(&pool, cu, frame_uuid).await;
        let frame = FrameOfDiscernment::new(fk.clone(), hyps.clone()).unwrap();
        let mut ev_out = Vec::new();
        for ev in arr(c, "evidence") {
            let etype = s(ev, "evidence_type");
            let masses = ev.get("masses").expect("masses");
            let bba = ow_bba_json(&frame, &hyps, masses);
            MassFunctionRepository::store_with_perspective(&pool, cu, frame_uuid,
                agent_id.get(&s(ev, "source_agent")).copied(), None, &bba, None,
                Some("discount"), Some(1.0), Some(&etype), "cross", None).await.expect("bba");
            ev_out.push(json!({ "source_type": etype, "source_agent": s(ev, "source_agent"), "masses": masses }));
        }
        claims.push(ClaimMeta {
            key: s(c, "key"), kind: s(c, "claim_kind"), frame: fk, target: hyps[0].clone(), content: s(c, "content"),
            treatment: s_opt(c, "treatment"), symptom: s_opt(c, "symptom"), dimension: s_opt(c, "dimension"),
            archetype: s_opt(c, "archetype"), evidence: ev_out, uuid: cu, frame_uuid,
        });
    }

    let mut claims_json = Vec::new();
    for cm in &claims {
        let mut betp = serde_json::Map::new();
        for (pk, _pn, pid, _sr) in &persp {
            betp.insert(pk.clone(), json!(betp0(&pool, cm.uuid, cm.frame_uuid, *pid).await));
        }
        claims_json.push(json!({
            "key": cm.key, "kind": cm.kind, "frame": cm.frame, "target": cm.target, "content": cm.content,
            "treatment": cm.treatment, "symptom": cm.symptom, "dimension": cm.dimension, "archetype": cm.archetype,
            "betp": Value::Object(betp), "evidence": cm.evidence,
        }));
    }

    let entities_out: Vec<Value> = arr(&entities_j, "entities").iter().map(|e| json!({
        "key": s(e, "key"), "name": s(e, "canonical_name"), "type_top": s(e, "type_top"),
        "type_sub": e.get("type_sub").and_then(|x| x.as_str()),
    })).collect();
    let disease = entities_out.iter()
        .find(|e| e["type_sub"].as_str() == Some("DiseaseState"))
        .and_then(|e| e["name"].as_str()).unwrap_or("condition cluster").to_string();
    let persp_out: Vec<Value> = persp.iter().map(|(k, n, _, sr)| json!({
        "key": k, "name": n, "source_reliability": sr,
    })).collect();

    let snapshot = json!({
        "generated_from": "epigraph_demo_dev — real CDST engine (get_perspective_belief), open-world BBAs",
        "disease": disease,
        "open_world_fraction": OPEN_WORLD_FRACTION,
        "perspectives": persp_out,
        "entities": entities_out,
        "claims": claims_json,
    });

    if let Some(parent) = std::path::Path::new(&out).parent() { std::fs::create_dir_all(parent).ok(); }
    std::fs::write(&out, serde_json::to_string_pretty(&snapshot).unwrap()).expect("write snapshot");
    eprintln!("SNAPSHOT → {out}  ({} claims × {} perspectives)", claims.len(), persp.len());
}
