#!/usr/bin/env python3
"""
Phase-0b: DISCRIMINATION (not firing rate) + mechanism, on the already-extracted twin.

Firing rate != signal. This checks whether entity_jaccard / subject_jaccard /
triple_overlap are actually HIGHER for verifier-confirmed matches than for non-matches,
specifically in the embed-MID band (0.50-0.80) where embedding is ambiguous — the only
band where a structural signal can add marginal value.

Ground truth = LLM verifier on each sampled pair (NOT embed_cosine; same-paper twins are
near-duplicate text so labeling-by-embedding would be circular).

Mechanism (no labels needed): of pairs that share any entity, how many share a SUBJECT
entity (so triple_overlap *can* fire) vs only object/modifier? Distinguishes
"predicate variance" from "shared entities aren't subjects".
"""
from __future__ import annotations
import sys, json, math, itertools, subprocess, time, random, os
sys.path.insert(0, "/home/jeremy/EpigraphV2/scripts/lib")
import psycopg2, psycopg2.extras
from triple_extractor import ClaimText
from llm_extractor import LLMExtractor

HERE = os.path.dirname(os.path.abspath(__file__))
SOURCES = {"natcomm": "journal/NatComm_2025_Mechanical_Frustration_DNA_Origami",
           "biorxiv": "bioRxiv/bioRxiv_2024_Mechanical_Frustration_DNA_Origami_preprint"}
DB = "dbname=epigraph user=epigraph password=epigraph host=localhost port=5432"
CACHE = os.path.join(HERE, "extractions_cache.json")


def claude(prompt, timeout=300, tries=4):
    for a in range(tries):
        try:
            r = subprocess.run(["claude", "-p", "--output-format", "text", "--max-turns", "1"],
                               input=prompt, capture_output=True, text=True, timeout=timeout)
            if r.returncode == 0 and r.stdout.strip():
                return r.stdout.strip()
        except subprocess.TimeoutExpired:
            pass
        time.sleep(3 * (a + 1) + random.random() * 2)
    return None


class RobustLLM(LLMExtractor):
    def _extract_batch(self, claims):
        orig = subprocess.run
        def patched(*a, **k):
            k["timeout"] = 300
            return orig(*a, **k)
        subprocess.run = patched
        try:
            last = None
            for attempt in range(4):
                last = super()._extract_batch(claims)
                if any(r.entities for r in last):
                    return last
                time.sleep(3 * (attempt + 1) + random.random() * 2)
            return last
        finally:
            subprocess.run = orig


def parse_emb(s):
    return [float(x) for x in s.strip("[]").split(",")] if s else None


def cosine(a, b):
    if a is None or b is None:
        return None
    d = sum(x * y for x, y in zip(a, b)); na = math.sqrt(sum(x * x for x in a)); nb = math.sqrt(sum(x * x for x in b))
    return d / (na * nb) if na and nb else 0.0


def jacc(a, b):
    if not a and not b:
        return 0.0
    u = a | b
    return len(a & b) / len(u) if u else 0.0


def norm(name):
    import re
    return re.sub(r"[^a-z0-9]+", "", name.lower())


def auc(pos, neg):
    """rank-based AUC of a feature given its values on positives vs negatives."""
    if not pos or not neg:
        return None
    wins = ties = 0
    for p in pos:
        for n in neg:
            if p > n: wins += 1
            elif p == n: ties += 1
    return (wins + 0.5 * ties) / (len(pos) * len(neg))


def main():
    conn = psycopg2.connect(DB)
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    claims = []
    for tag, doi in SOURCES.items():
        cur.execute("""SELECT id::text AS id, content, embedding::text AS emb FROM claims
                       WHERE is_current AND properties->>'source_doi'=%s AND length(content)>40
                       ORDER BY created_at""", (doi,))
        for r in cur.fetchall():
            r["src"] = tag; r["embv"] = parse_emb(r["emb"]); claims.append(r)
    nc = [c for c in claims if c["src"] == "natcomm"]; bx = [c for c in claims if c["src"] == "biorxiv"]
    print(f"[disc] {len(nc)} natcomm + {len(bx)} biorxiv", flush=True)

    # ---- extraction with cache ----
    if os.path.exists(CACHE):
        cache = json.load(open(CACHE)); print(f"[disc] loaded {len(cache)} cached extractions", flush=True)
    else:
        cache = {}
    todo = [c for c in claims if c["id"] not in cache]
    if todo:
        print(f"[disc] extracting {len(todo)} claims (cached {len(cache)})...", flush=True)
        res = RobustLLM(batch_size=5).extract([ClaimText(c["id"], c["content"]) for c in todo])
        for r in res:
            cache[r.claim_id] = {
                "entities": [{"name": e.name, "type": e.type_top, "role": e.role} for e in r.entities],
                "triples": [{"subject": t.subject, "predicate": t.predicate} for t in r.triples],
            }
        json.dump(cache, open(CACHE, "w"), indent=1); print(f"[disc] cached -> {CACHE}", flush=True)

    # ---- per-claim signal sets ----
    allent, subjent, sp = {}, {}, {}
    for c in claims:
        e = cache.get(c["id"], {"entities": [], "triples": []})
        nt = {x["name"]: x["type"] for x in e["entities"]}
        allent[c["id"]] = {(norm(x["name"]), x["type"]) for x in e["entities"]}
        subs = set(); spp = set()
        for t in e["triples"]:
            st = nt.get(t["subject"])
            if st is None:
                continue
            subs.add((norm(t["subject"]), st)); spp.add(((norm(t["subject"]), st), t["predicate"]))
        subjent[c["id"]] = subs; sp[c["id"]] = spp

    # ---- all cross-source pairs ----
    pairs = []
    for a, b in itertools.product(nc, bx):
        ej = jacc(allent[a["id"]], allent[b["id"]])
        sj = jacc(subjent[a["id"]], subjent[b["id"]])
        to = jacc(sp[a["id"]], sp[b["id"]])
        ec = cosine(a["embv"], b["embv"])
        pairs.append({"a": a["id"], "b": b["id"], "ec": ec, "ej": ej, "sj": sj, "to": to,
                      "at": a["content"], "bt": b["content"]})

    # ---- MECHANISM: of entity-sharing pairs, how many share a SUBJECT? ----
    share_ent = [p for p in pairs if p["ej"] > 0]
    share_subj = [p for p in share_ent if p["sj"] > 0]
    share_sp = [p for p in share_ent if p["to"] > 0]
    print("\n==== MECHANISM ====", flush=True)
    print(f"pairs sharing any entity: {len(share_ent)}", flush=True)
    print(f"  ...of which share a SUBJECT entity: {len(share_subj)}", flush=True)
    print(f"  ...of which share a (subject,predicate): {len(share_sp)}", flush=True)
    print("  -> if share_subj >> share_sp: predicate variance is the bottleneck", flush=True)
    print("  -> if share_subj ~ share_sp but << share_ent: shared entities are objects/modifiers, not subjects", flush=True)

    # ---- DISCRIMINATION: verifier-label a mid-band sample ----
    mid = [p for p in pairs if p["ec"] is not None and 0.50 <= p["ec"] < 0.80]
    print(f"\n[disc] {len(mid)} pairs in embed-mid band (0.50-0.80)", flush=True)
    random.seed(42)
    hi = [p for p in mid if p["ej"] > 0]; lo = [p for p in mid if p["ej"] == 0]
    random.shuffle(hi); random.shuffle(lo)
    sample = hi[:25] + lo[:25]
    print(f"[disc] labeling {len(sample)} mid-band pairs ({min(25,len(hi))} ej>0, {min(25,len(lo))} ej=0) via verifier...", flush=True)

    VP = ("Two atomic claims, possibly from different papers about the same research. Do they assert the "
          "SAME specific finding/result (such that one corroborates the other) — NOT merely the same topic? "
          'Answer with JSON only: {"match": true|false}.\n\nCLAIM A: {a}\n\nCLAIM B: {b}')
    for i, p in enumerate(sample):
        out = claude(VP.replace("{a}", p["at"][:600]).replace("{b}", p["bt"][:600]))
        m = None
        if out:
            raw = out.strip()
            if raw.startswith("```"):
                raw = raw.split("\n", 1)[-1].rsplit("```", 1)[0]
            try:
                m = bool(json.loads(raw).get("match"))
            except Exception:
                m = "true" in raw.lower()[:40]
        p["match"] = m
        if (i + 1) % 10 == 0:
            print(f"  labeled {i+1}/{len(sample)}", flush=True)

    labeled = [p for p in sample if p["match"] is not None]
    matches = [p for p in labeled if p["match"]]; nonm = [p for p in labeled if not p["match"]]
    print(f"\n==== DISCRIMINATION (embed-mid band, n={len(labeled)}: {len(matches)} match / {len(nonm)} non-match) ====", flush=True)

    def stat(key):
        mv = [p[key] for p in matches]; nv = [p[key] for p in nonm]
        am = sum(mv) / len(mv) if mv else 0; an = sum(nv) / len(nv) if nv else 0
        return am, an, auc(mv, nv)

    out = {"mechanism": {"share_entity": len(share_ent), "share_subject": len(share_subj),
                         "share_subject_predicate": len(share_sp)},
           "discrimination": {"n_labeled": len(labeled), "n_match": len(matches), "n_nonmatch": len(nonm)},
           "samples": [{k: p[k] for k in ("ec", "ej", "sj", "to", "match")} for p in labeled]}
    for key, lab in [("ej", "entity_jaccard"), ("sj", "subject_jaccard"), ("to", "triple_overlap"), ("ec", "embed_cosine")]:
        am, an, a = stat(key)
        out["discrimination"][lab] = {"mean_match": round(am, 4), "mean_nonmatch": round(an, 4), "auc": None if a is None else round(a, 3)}
        print(f"  {lab:16s} mean(match)={am:.4f} mean(nonmatch)={an:.4f} AUC={a if a is None else round(a,3)}", flush=True)

    json.dump(out, open(os.path.join(HERE, "discriminate_results.json"), "w"), indent=2)
    print("\n[disc] wrote discriminate_results.json", flush=True)
    print("\n==== READ: AUC>0.5 means the feature ranks matches above non-matches in the band where embedding can't decide. ====", flush=True)


if __name__ == "__main__":
    main()
