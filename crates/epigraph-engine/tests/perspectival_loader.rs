//! perspectival-demo seed loader + T2-full validation (OPEN-WORLD).
//!
//! Reads the demo's seeds + perspectives JSON and loads the FULL cluster
//! (entities, all claims, evidence BBAs, edges, perspectives) into a dev epigraph
//! DB via the repo layer. Every BBA reserves OPEN-WORLD mass (a `~`/missing
//! element) so the frame is not treated as exhaustive — genuine open-world CDST.
//! Then validates the directional archetypes via the REAL `get_perspective_belief`,
//! and proves the open-world `YagerOpen` rule actually fires at high conflict.
//!
//! Run (SEED_DIR supplied via env var; no hardcoded default):
//!   DATABASE_URL=postgres://epigraph:epigraph@localhost/epigraph_demo_dev \
//!   SEED_DIR=$SEED_DIR SQLX_OFFLINE=true \
//!   cargo test -p epigraph-engine --test perspectival_loader -- --nocapture

use std::collections::{BTreeMap, BTreeSet, HashMap};

use epigraph_db::{EntityRepository, FrameRepository, MassFunctionRepository, PerspectiveRepository, PgPool};
use epigraph_ds::{combination, FocalElement, FrameOfDiscernment, MassFunction};
use serde_json::Value;
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

/// BetP for hypothesis index 0 (the target: efficacious / safe / holds) under a perspective.
async fn betp0(pool: &PgPool, claim: Uuid, frame: Uuid, persp: Uuid) -> f64 {
    epigraph_engine::belief_query::get_perspective_belief(pool, claim, frame, persp)
        .await.expect("belief").pignistic_prob
}

/// Build an open-world BBA json: mass on the named hypothesis (its frame index),
/// `OPEN_WORLD_FRACTION` on the `~` (missing) element, remainder on Θ.
fn ow_bba_json(frame: &FrameOfDiscernment, hyps: &[String], masses: &Value) -> Value {
    // seed masses are {<hypothesis>: m, "theta": t}; find the single hypothesis key.
    let obj = masses.as_object().expect("masses obj");
    let mut hyp_idx = None;
    let mut hyp_mass = 0.0;
    let mut theta_mass = 0.0;
    for (k, v) in obj {
        let val = v.as_f64().expect("mass f64");
        if k == "theta" {
            theta_mass = val;
        } else {
            let idx = hyps.iter().position(|h| h == k).unwrap_or_else(|| panic!("hyp {k} not in frame"));
            hyp_idx = Some(idx);
            hyp_mass = val;
        }
    }
    let idx = hyp_idx.expect("a hypothesis mass");
    let ow = OPEN_WORLD_FRACTION.min(theta_mass);
    let theta_rem = (theta_mass - ow).max(0.0);

    let mut m: BTreeMap<FocalElement, f64> = BTreeMap::new();
    m.insert(FocalElement::positive(BTreeSet::from([idx])), hyp_mass);
    if theta_rem > 1e-9 {
        m.insert(FocalElement::theta(frame), theta_rem);
    }
    m.insert(FocalElement::missing(frame), ow);
    MassFunction::new(frame.clone(), m).expect("ow bba").masses_to_json()
}

#[tokio::test]
#[ignore = "requires SEED_DIR + dedicated dev DB; run manually with --ignored"]
async fn load_and_validate_open_world() {
    let Ok(url) = std::env::var("DATABASE_URL") else { eprintln!("SKIP: DATABASE_URL not set"); return; };
    let dir = std::env::var("SEED_DIR").expect("set SEED_DIR");
    let pool = PgPool::connect(&url).await.expect("connect");
    sqlx::migrate!("../../migrations").run(&pool).await.ok();

    // ---- parse seed ----
    let frames_j = read(&dir, "seeds/frames.json");
    let entities_j = read(&dir, "seeds/entities.json");
    let agents_j = read(&dir, "seeds/agents.json");
    let claims_j = read(&dir, "seeds/claims.json");
    let edges_j = read(&dir, "seeds/edges.json");
    let obs_j = read(&dir, "perspectives/observers.json");

    let author = insert_agent(&pool).await;
    let mut key_id: HashMap<String, Uuid> = HashMap::new(); // entity/claim keys
    let mut agent_id: HashMap<String, Uuid> = HashMap::new();
    let mut persp_id: HashMap<String, Uuid> = HashMap::new();
    let mut frame_of: HashMap<String, (Uuid, Vec<String>)> = HashMap::new();

    // ---- frames ----
    for f in arr(&frames_j, "frames") {
        let name = s(f, "name");
        let hyps: Vec<String> = arr(f, "hypotheses").iter().map(|h| h.as_str().unwrap().to_string()).collect();
        let row = FrameRepository::create(&pool, &name, None, &hyps).await.expect("frame");
        frame_of.insert(s(f, "key"), (row.id, hyps));
    }
    // ---- agents (source + observer) ----
    for grp in ["source_agents", "observer_agents"] {
        if let Some(list) = agents_j.get(grp).and_then(|x| x.as_array()) {
            for a in list {
                agent_id.insert(s(a, "key"), insert_agent(&pool).await);
            }
        }
    }
    // ---- entities ----
    for e in arr(&entities_j, "entities") {
        let type_sub = e.get("type_sub").and_then(|x| x.as_str());
        let props = e.get("properties").cloned().unwrap_or_else(|| serde_json::json!({}));
        let row = EntityRepository::upsert(&pool, &s(e, "canonical_name"), &s(e, "type_top"), type_sub, None, props)
            .await.expect("entity");
        key_id.insert(s(e, "key"), row.id);
    }
    // ---- perspectives + source_reliability ----
    for p in arr(&obs_j, "perspectives") {
        let ptype = p.get("perspective_type").and_then(|x| x.as_str());
        let row = PerspectiveRepository::create(&pool, &s(p, "name"), None, None, ptype, &[], None, None)
            .await.expect("perspective");
        let map: HashMap<String, f64> = p.get("source_reliability").and_then(|x| x.as_object()).unwrap()
            .iter().map(|(k, v)| (k.clone(), v.as_f64().unwrap())).collect();
        PerspectiveRepository::set_source_reliability(&pool, row.id, &map).await.expect("rel");
        persp_id.insert(s(p, "key"), row.id);
    }
    // ---- claims + BBAs (open-world) ----
    let mut n_bba = 0;
    for c in arr(&claims_j, "claims") {
        let key = s(c, "key");
        let frame_key = s(c, "frame");
        let (frame_uuid, hyps) = frame_of.get(&frame_key).expect("claim frame").clone();
        let claim_uuid = insert_claim(&pool, author, &s(c, "content")).await;
        assign(&pool, claim_uuid, frame_uuid).await;
        key_id.insert(key.clone(), claim_uuid);
        let frame = FrameOfDiscernment::new(frame_key.clone(), hyps.clone()).unwrap();
        for ev in arr(c, "evidence") {
            let src = agent_id.get(&s(ev, "source_agent")).copied();
            let etype = s(ev, "evidence_type");
            let masses = ev.get("masses").expect("masses");
            let bba = ow_bba_json(&frame, &hyps, masses);
            MassFunctionRepository::store_with_perspective(
                &pool, claim_uuid, frame_uuid, src, None, &bba, None,
                Some("discount"), Some(1.0), Some(&etype), "cross", None,
            ).await.expect("store bba");
            n_bba += 1;
        }
    }
    // ---- edges ----
    let mut n_edge = 0;
    for e in arr(&edges_j, "edges") {
        let src = key_id.get(&s(e, "source")).copied().expect("edge source");
        let tgt = key_id.get(&s(e, "target")).copied().expect("edge target");
        EdgeRepositoryCreate(&pool, src, &s(e, "source_type"), tgt, &s(e, "target_type"), &s(e, "relationship")).await;
        n_edge += 1;
    }
    eprintln!("LOADED: {} frames, {} entities, {} claims, {} BBAs (open-world), {} perspectives, {} edges",
        frame_of.len(), arr(&entities_j, "entities").len(), arr(&claims_j, "claims").len(), n_bba, persp_id.len(), n_edge);

    // ---- T2-full validation: directional archetypes via the REAL engine ----
    let cid = |k: &str| *key_id.get(k).expect(k);
    let pid = |k: &str| *persp_id.get(k).expect(k);
    let eff_frame = frame_of.get("treatment_efficacy").unwrap().0;
    let saf_frame = frame_of.get("treatment_safety").unwrap().0;
    let persps = ["clinical_observer", "tradition_observer", "regulatory_observer", "skeptic_observer"];

    eprintln!("\nEFFICACY BetP(efficacious) — open-world, real engine  [clin  trad  regul  skept]:");
    for claim in ["eff-treatment-a-symptom-1", "eff-treatment-b-symptom-3", "eff-treatment-e-symptom-4", "eff-treatment-c-symptom-2"] {
        let mut v = vec![];
        for p in persps { v.push(betp0(&pool, cid(claim), eff_frame, pid(p)).await); }
        eprintln!("  {claim:<26} {:.3} {:.3} {:.3} {:.3}", v[0], v[1], v[2], v[3]);
    }
    eprintln!("SAFETY BetP(safe):");
    for claim in ["saf-treatment-a", "saf-treatment-c"] {
        let mut v = vec![];
        for p in persps { v.push(betp0(&pool, cid(claim), saf_frame, pid(p)).await); }
        eprintln!("  {claim:<26} {:.3} {:.3} {:.3} {:.3}", v[0], v[1], v[2], v[3]);
    }

    // Directional assertions (open-world shifts magnitudes; directions hold).
    for p in persps {
        assert!(betp0(&pool, cid("eff-treatment-a-symptom-1"), eff_frame, pid(p)).await > 0.5, "consensus eff {p}");
    }
    let bv = betp0(&pool, cid("eff-treatment-b-symptom-3"), eff_frame, pid("tradition_observer")).await;
    let bc = betp0(&pool, cid("eff-treatment-b-symptom-3"), eff_frame, pid("clinical_observer")).await;
    assert!(bv > bc + 0.15, "tradition-only gap: tradition {bv} vs clinical {bc}");
    let jv = betp0(&pool, cid("eff-treatment-e-symptom-4"), eff_frame, pid("tradition_observer")).await;
    let jc = betp0(&pool, cid("eff-treatment-e-symptom-4"), eff_frame, pid("clinical_observer")).await;
    assert!(jv > jc && jc < 0.5, "conflict: tradition {jv} vs clinical {jc}");
    let sv = betp0(&pool, cid("saf-treatment-c"), saf_frame, pid("tradition_observer")).await;
    let sc = betp0(&pool, cid("saf-treatment-c"), saf_frame, pid("clinical_observer")).await;
    assert!(sv > sc + 0.25 && sc < 0.5, "safety divergence: tradition {sv} vs clinical {sc}");

    // ---- OPEN-WORLD PROOF ----
    // The engine implements the YagerOpen rule as inagaki_combine(gamma=1.0) (routes ALL
    // conflict to the open-world/missing element), and the closed high-conflict rule as
    // inagaki_combine(gamma=0.5). Both report method_used=Inagaki, so we discriminate via
    // mass_on_missing: at K>=0.5, reserving open-world mass (owf>0.03) selects YagerOpen and
    // sends the conflict to the open-world element; with no open-world mass it stays closed
    // and routes only ~half there. More mass-on-missing == the open-world branch genuinely fired.
    let bf = FrameOfDiscernment::new("ow_proof", vec!["a".into(), "b".into()]).unwrap();
    let mk = |idx: usize, ow: f64| {
        let mut m = BTreeMap::new();
        m.insert(FocalElement::positive(BTreeSet::from([idx])), 0.80); // K = 0.80*0.80 = 0.64 >= 0.5
        if ow > 0.0 { m.insert(FocalElement::missing(&bf), ow); }
        m.insert(FocalElement::theta(&bf), 0.20 - ow);
        MassFunction::new(bf.clone(), m).unwrap()
    };
    let (_co, rep_ow) = combination::combine_multiple(&[mk(0, 0.08), mk(1, 0.08)], 0.1).unwrap();
    let (_cc, rep_cl) = combination::combine_multiple(&[mk(0, 0.0), mk(1, 0.0)], 0.1).unwrap();
    let (miss_ow, miss_cl) = (rep_ow[0].mass_on_missing, rep_cl[0].mass_on_missing);
    eprintln!("\nOPEN-WORLD PROOF (K={:.2}): open-world inputs -> mass_on_missing={:.3} ({:?});  closed inputs -> mass_on_missing={:.3} ({:?})",
        rep_ow[0].conflict_k, miss_ow, rep_ow[0].method_used, miss_cl, rep_cl[0].method_used);
    assert!(miss_ow > miss_cl + 0.10,
        "open-world reservation should route MORE conflict to the open-world element (YagerOpen, gamma=1.0) than the closed rule: ow={miss_ow} closed={miss_cl}");

    eprintln!("\nALL OPEN-WORLD VALIDATION CHECKS PASS");
}

// Thin wrapper so the long edge create call reads cleanly above.
#[allow(non_snake_case)]
async fn EdgeRepositoryCreate(pool: &PgPool, src: Uuid, st: &str, tgt: Uuid, tt: &str, rel: &str) {
    epigraph_db::EdgeRepository::create(pool, src, st, tgt, tt, rel, None, None, None)
        .await
        .expect("edge");
}
