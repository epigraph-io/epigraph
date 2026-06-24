#!/usr/bin/env python3
"""Deterministically recover the exact 50 mid-band pairs discriminate.py sampled
(seed 42, same created_at ordering, cached extractions) and print their texts +
structural metrics so the labels can be human-audited. No claude calls."""
import sys, json, math, itertools, random, os, re
sys.path.insert(0, "/home/jeremy/EpigraphV2/scripts/lib")
import psycopg2, psycopg2.extras

HERE = os.path.dirname(os.path.abspath(__file__))
SOURCES = {"natcomm": "journal/NatComm_2025_Mechanical_Frustration_DNA_Origami",
           "biorxiv": "bioRxiv/bioRxiv_2024_Mechanical_Frustration_DNA_Origami_preprint"}
DB = "dbname=epigraph user=epigraph password=epigraph host=localhost port=5432"
cache = json.load(open(os.path.join(HERE, "extractions_cache.json")))


def emb(s): return [float(x) for x in s.strip("[]").split(",")] if s else None
def cos(a, b):
    d = sum(x*y for x, y in zip(a, b)); na = math.sqrt(sum(x*x for x in a)); nb = math.sqrt(sum(x*x for x in b))
    return d/(na*nb) if na and nb else 0.0
def jacc(a, b):
    if not a and not b: return 0.0
    u = a | b; return len(a & b)/len(u) if u else 0.0
def norm(n): return re.sub(r"[^a-z0-9]+", "", n.lower())

conn = psycopg2.connect(DB); cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
claims = []
for tag, doi in SOURCES.items():
    cur.execute("""SELECT id::text AS id, content, embedding::text AS emb FROM claims
                   WHERE is_current AND properties->>'source_doi'=%s AND length(content)>40
                   ORDER BY created_at""", (doi,))
    for r in cur.fetchall():
        r["src"] = tag; r["embv"] = emb(r["emb"]); claims.append(r)
nc = [c for c in claims if c["src"] == "natcomm"]; bx = [c for c in claims if c["src"] == "biorxiv"]

allent, subjent, sp = {}, {}, {}
for c in claims:
    e = cache.get(c["id"], {"entities": [], "triples": []})
    nt = {x["name"]: x["type"] for x in e["entities"]}
    allent[c["id"]] = {(norm(x["name"]), x["type"]) for x in e["entities"]}
    subs, spp = set(), set()
    for t in e["triples"]:
        st = nt.get(t["subject"])
        if st is None: continue
        subs.add((norm(t["subject"]), st)); spp.add(((norm(t["subject"]), st), t["predicate"]))
    subjent[c["id"]], sp[c["id"]] = subs, spp

pairs = []
for a, b in itertools.product(nc, bx):
    pairs.append({"a": a["id"], "b": b["id"], "ec": cos(a["embv"], b["embv"]),
                  "ej": jacc(allent[a["id"]], allent[b["id"]]), "sj": jacc(subjent[a["id"]], subjent[b["id"]]),
                  "to": jacc(sp[a["id"]], sp[b["id"]]), "at": a["content"], "bt": b["content"]})
mid = [p for p in pairs if p["ec"] is not None and 0.50 <= p["ec"] < 0.80]
random.seed(42)
hi = [p for p in mid if p["ej"] > 0]; lo = [p for p in mid if p["ej"] == 0]
random.shuffle(hi); random.shuffle(lo)
sample = hi[:25] + lo[:25]
for i, p in enumerate(sample):
    print(f"\n### PAIR {i:02d}  ec={p['ec']:.3f} ej={p['ej']:.3f} sj={p['sj']:.3f} to={p['to']:.3f}")
    print(f"A: {p['at'][:300]}")
    print(f"B: {p['bt'][:300]}")
