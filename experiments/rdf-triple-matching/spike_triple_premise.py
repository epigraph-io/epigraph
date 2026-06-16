#!/usr/bin/env python3
"""
Phase-0 premise spike for the RDF-triple → cross-source matching experiment.

Question (kill-switch): if we LLM-extract triples for one duplicate-paper twin
(Mechanical Frustration DNA Origami: bioRxiv preprint + NatComm journal) and
canonicalize entities by name+type, do cross-source claim pairs end up sharing
(subject, predicate) — i.e. does `triple_overlap` fire — AND does it fire for
pairs embedding alone does NOT already nail (marginal value, embed_cosine < 0.85)?

No DB clone, no API: entities/triples aren't in the no-raw-SQL protected list and
the premise is about extraction+canonicalization producing overlap, which is
computable in-memory. Reads are prod read-only.

Usage:
  python3 spike_triple_premise.py --limit-per-source 5   # smoke (10 claims)
  python3 spike_triple_premise.py                        # full twin (111 claims)
"""
from __future__ import annotations
import sys, json, math, argparse, itertools, re
sys.path.insert(0, "/home/jeremy/EpigraphV2/scripts/lib")
import psycopg2, psycopg2.extras
from triple_extractor import ClaimText, validate_result
from llm_extractor import LLMExtractor
import time


import subprocess, random


class RobustLLMExtractor(LLMExtractor):
    """Retries a batch that comes back fully empty (the failure signature when a
    concurrent `claude -p` collides / rate-limits). Also raises the per-call timeout
    from the parent's hardcoded 120s to 300s (this box runs concurrent EpiClaw
    `claude -p` automation, so OAuth calls queue and are slow under contention)."""

    def _extract_batch(self, claims):
        orig_run = subprocess.run

        def patched_run(*a, **k):
            k["timeout"] = 300  # generous under concurrent claude load
            return orig_run(*a, **k)

        subprocess.run = patched_run
        try:
            last = None
            for attempt in range(4):
                last = super()._extract_batch(claims)
                if any(r.entities for r in last):
                    return last
                time.sleep(3 * (attempt + 1) + random.random() * 2)  # backoff + jitter
            return last
        finally:
            subprocess.run = orig_run

SOURCES = {
    "natcomm": "journal/NatComm_2025_Mechanical_Frustration_DNA_Origami",
    "biorxiv": "bioRxiv/bioRxiv_2024_Mechanical_Frustration_DNA_Origami_preprint",
}
DB = "dbname=epigraph user=epigraph password=epigraph host=localhost port=5432"


def parse_emb(s):
    if not s:
        return None
    return [float(x) for x in s.strip("[]").split(",")]


def cosine(a, b):
    if a is None or b is None:
        return None
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(x * x for x in b))
    return dot / (na * nb) if na and nb else 0.0


def jaccard(a: set, b: set):
    if not a and not b:
        return None  # mirror scorer.rs: empty/empty -> None (excluded)
    u = a | b
    return len(a & b) / len(u) if u else None


def canon_exact(name, type_top):
    return (name.strip().lower(), type_top)


def canon_norm(name, type_top):
    # strip all non-alphanumerics: "DNA origami"/"DNA-origami"/"dna  origami" -> "dnaorigami"
    return (re.sub(r"[^a-z0-9]+", "", name.lower()), type_top)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit-per-source", type=int, default=0)
    ap.add_argument("--out", default="/home/jeremy/epigraph-wt-triples-exp/experiments/rdf-triple-matching/spike_results.json")
    args = ap.parse_args()

    conn = psycopg2.connect(DB)
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    lim = "" if args.limit_per_source <= 0 else f"LIMIT {args.limit_per_source}"
    claims = []
    for tag, doi in SOURCES.items():
        cur.execute(
            f"""SELECT id::text AS id, content, embedding::text AS emb
                FROM claims WHERE is_current AND properties->>'source_doi'=%s
                AND length(content) > 40 ORDER BY created_at {lim}""",
            (doi,),
        )
        for r in cur.fetchall():
            r["src"] = tag
            r["embv"] = parse_emb(r["emb"])
            claims.append(r)
    by_src = {"natcomm": [c for c in claims if c["src"] == "natcomm"],
              "biorxiv": [c for c in claims if c["src"] == "biorxiv"]}
    print(f"[spike] fetched {len(by_src['natcomm'])} natcomm + {len(by_src['biorxiv'])} biorxiv = {len(claims)} claims", flush=True)

    # ---- extract ----
    ext = RobustLLMExtractor(batch_size=5)
    results = ext.extract([ClaimText(c["id"], c["content"]) for c in claims])
    res_by_id = {r.claim_id: r for r in results}
    n_with_ent = sum(1 for r in results if r.entities)
    n_with_tri = sum(1 for r in results if r.triples)
    print(f"[spike] extracted: {n_with_ent}/{len(results)} claims got entities, {n_with_tri} got triples", flush=True)

    # precompute cross-source embedding cosine once (canon-independent)
    embc = {}
    for a, b in itertools.product(by_src["natcomm"], by_src["biorxiv"]):
        embc[(a["id"], b["id"])] = cosine(a["embv"], b["embv"])

    def analyze(canon_fn, label):
        canon_entities = {}   # canon_key -> set(src)
        sp_set, ent_set = {}, {}
        for c in claims:
            r = res_by_id.get(c["id"])
            sp, es = set(), set()
            if r:
                name_type = {e.name: e.type_top for e in r.entities}
                for e in r.entities:
                    ck = canon_fn(e.name, e.type_top)
                    es.add(ck)
                    canon_entities.setdefault(ck, set()).add(c["src"])
                for t in r.triples:
                    st = name_type.get(t.subject)
                    if st is None:
                        continue
                    sp.add((canon_fn(t.subject, st), t.predicate))
            sp_set[c["id"]], ent_set[c["id"]] = sp, es
        cross_entities = {k: v for k, v in canon_entities.items() if len(v) == 2}
        pairs = []
        for a, b in itertools.product(by_src["natcomm"], by_src["biorxiv"]):
            to = jaccard(sp_set[a["id"]], sp_set[b["id"]])
            ej = jaccard(ent_set[a["id"]], ent_set[b["id"]])
            ec = embc[(a["id"], b["id"])]
            shared = sp_set[a["id"]] & sp_set[b["id"]]
            pairs.append({"a": a["id"], "b": b["id"], "embed_cosine": ec,
                          "triple_overlap": to, "entity_jaccard": ej,
                          "shared_sp": sorted(f"{s[0][0]}|{s[1]}" for s in shared),
                          "a_text": a["content"][:140], "b_text": b["content"][:140]})
        tri_fire = [p for p in pairs if p["triple_overlap"] and p["triple_overlap"] > 0]
        tri_hard = [p for p in tri_fire if p["embed_cosine"] is not None and p["embed_cosine"] < 0.85]
        ent_fire = [p for p in pairs if p["entity_jaccard"] and p["entity_jaccard"] > 0]
        summ = {
            "canon_mode": label,
            "canonical_entities_total": len(canon_entities),
            "canonical_entities_cross_source": len(cross_entities),
            "cross_source_pairs": len(pairs),
            "pairs_triple_overlap_gt0": len(tri_fire),
            "pairs_triple_overlap_gt0_embed_hard(<0.85)": len(tri_hard),
            "pairs_entity_jaccard_gt0": len(ent_fire),
            "max_triple_overlap": round(max([p["triple_overlap"] for p in tri_fire], default=0.0), 3),
            "example_cross_entities": sorted(f"{k[0]} [{k[1]}]" for k in list(cross_entities))[:25],
        }
        return summ, pairs, tri_hard

    print(f"\n[spike] {n_with_ent}/{len(results)} claims w/ entities, {n_with_tri} w/ triples", flush=True)
    out = {"claims_total": len(claims), "claims_with_entities": n_with_ent,
           "claims_with_triples": n_with_tri, "modes": {}}
    gate_norm = None
    for fn, label in [(canon_exact, "exact"), (canon_norm, "normalized")]:
        summ, pairs, tri_hard = analyze(fn, label)
        out["modes"][label] = {"summary": summ, "pairs": pairs}
        print(f"\n==== SUMMARY [{label}] ====", flush=True)
        print(json.dumps(summ, indent=2), flush=True)
        tri_hard.sort(key=lambda p: (-p["triple_overlap"], p["embed_cosine"]))
        if tri_hard:
            print(f"-- top embed-HARD pairs where triples fire ({label}, marginal value) --", flush=True)
            for p in tri_hard[:6]:
                print(f"  embed={p['embed_cosine']:.3f} triple_overlap={p['triple_overlap']:.3f} shared={p['shared_sp']}", flush=True)
                print(f"    A: {p['a_text']}\n    B: {p['b_text']}", flush=True)
        if label == "normalized":
            gate_norm = summ

    with open(args.out, "w") as f:
        json.dump(out, f, indent=2)
    print(f"\n[spike] wrote {args.out}", flush=True)

    # gate on the realistic (normalized) canonicalization
    ok = (gate_norm["canonical_entities_cross_source"] >= 3
          and gate_norm["pairs_triple_overlap_gt0"] >= 1)
    print(f"\n==== GATE (normalized canon): {'PASS' if ok else 'FAIL'} ====", flush=True)
    print("PASS = >=3 cross-source entity merges AND >=1 cross-source pair with triple_overlap>0", flush=True)
    sys.exit(0 if ok else 2)


if __name__ == "__main__":
    main()
