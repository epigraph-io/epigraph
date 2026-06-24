#!/usr/bin/env python3
"""
Pivot pre-gate: SURFACE-VARIANT CENSUS (zero claude calls).

The binding baseline for entity-centric retrieval is LEXICAL (grep/ILIKE/BM25), not
embedding. The entity layer's only wedge over lexical search is mentions whose claim text
does NOT contain the canonical entity name as a substring (claim says "the origami lattice",
entity is "DNA origami"; abbreviations; pronouns). If every mention's name is already a
literal substring, the entity layer just recovers what grep finds → no value over lexical.

This measures that wedge directly from the cached extractions + claim texts.

Two cuts:
  (1) per-mention literalness: of all (extracted-name, claim) pairs, what fraction have the
      extracted name NOT as a case-insensitive substring of the source claim?
  (2) cross-claim retrieval wedge: for each canonical entity (normalized name) with >=3
      mention-claims, pick its most common surface form as the lexical query; what fraction
      of its mention-claims do NOT contain that query string (i.e. grep for the canonical
      name would miss them, but the entity layer links them)?
"""
import sys, json, os, re, collections
sys.path.insert(0, "/home/jeremy/EpigraphV2/scripts/lib")
import psycopg2, psycopg2.extras

HERE = os.path.dirname(os.path.abspath(__file__))
SOURCES = ["journal/NatComm_2025_Mechanical_Frustration_DNA_Origami",
           "bioRxiv/bioRxiv_2024_Mechanical_Frustration_DNA_Origami_preprint"]
DB = "dbname=epigraph user=epigraph password=epigraph host=localhost port=5432"
cache = json.load(open(os.path.join(HERE, "extractions_cache.json")))


def norm(n):
    return re.sub(r"[^a-z0-9]+", " ", n.lower()).strip()


def main():
    conn = psycopg2.connect(DB); cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""SELECT id::text AS id, lower(content) AS content FROM claims
                   WHERE is_current AND properties->>'source_doi'=ANY(%s) AND length(content)>40""", (SOURCES,))
    text = {r["id"]: r["content"] for r in cur.fetchall()}

    # ---- cut 1: per-mention literalness ----
    total, substr_hit = 0, 0
    miss_examples = []
    canon = collections.defaultdict(lambda: {"claims": set(), "forms": collections.Counter()})
    for cid, ext in cache.items():
        if cid not in text:
            continue
        t = text[cid]
        for e in ext.get("entities", []):
            name = e["name"].strip()
            if not name:
                continue
            total += 1
            hit = name.lower() in t
            if hit:
                substr_hit += 1
            elif len(miss_examples) < 25:
                miss_examples.append((name, e["type"], t[:90]))
            key = (norm(name), e["type"])
            canon[key]["claims"].add(cid)
            canon[key]["forms"][name] += 1

    print("==== CUT 1: per-mention literalness ====", flush=True)
    print(f"total (entity,claim) mentions: {total}", flush=True)
    print(f"  name IS a substring of claim text (lexical would find): {substr_hit} ({100*substr_hit/total:.1f}%)", flush=True)
    print(f"  name NOT a substring (entity-layer wedge): {total-substr_hit} ({100*(total-substr_hit)/total:.1f}%)", flush=True)
    print("  sample non-literal mentions (name :: claim snippet):", flush=True)
    for n, ty, sn in miss_examples[:12]:
        print(f"    '{n}' [{ty}] :: {sn}", flush=True)

    # ---- cut 2: cross-claim retrieval wedge (canonical entities w/ >=3 mention-claims) ----
    print("\n==== CUT 2: cross-claim retrieval wedge (entities with >=3 mention-claims) ====", flush=True)
    rows = []
    for key, d in canon.items():
        claims = d["claims"]
        if len(claims) < 3:
            continue
        query = d["forms"].most_common(1)[0][0]  # most common surface form = lexical query
        ql = query.lower()
        contain = sum(1 for c in claims if ql in text[c])
        miss = len(claims) - contain
        rows.append((query, key[1], len(claims), contain, miss))
    rows.sort(key=lambda r: (-r[4], -r[2]))
    tot_m = sum(r[2] for r in rows); tot_miss = sum(r[4] for r in rows)
    print(f"{'entity':32s} {'type':10s} {'mentions':>8s} {'lex_hit':>7s} {'wedge':>5s}", flush=True)
    for q, ty, m, c, miss in rows[:25]:
        print(f"  {q[:30]:30s} {ty[:10]:10s} {m:8d} {c:7d} {miss:5d}", flush=True)
    if tot_m:
        print(f"\nacross {len(rows)} multi-claim entities: {tot_m} mention-claims, "
              f"{tot_miss} are lexical-misses (cross-claim wedge) = {100*tot_miss/tot_m:.1f}%", flush=True)

    verdict = "WEDGE EXISTS" if (total and (total - substr_hit) / total >= 0.15) else "NO MEANINGFUL WEDGE"
    print(f"\n==== PRE-GATE: {verdict} ====", flush=True)
    print("WEDGE EXISTS (>=15% non-literal mentions) => entity layer can beat lexical; proceed to retrieval-precision check.", flush=True)
    print("NO WEDGE (<15%) => entity retrieval just recovers what grep finds; query value over lexical is structurally thin.", flush=True)

    json.dump({"total_mentions": total, "substring_hit": substr_hit,
               "nonliteral_frac": round((total - substr_hit) / total, 4) if total else None,
               "crossclaim_entities": len(rows), "crossclaim_wedge_frac": round(tot_miss / tot_m, 4) if tot_m else None},
              open(os.path.join(HERE, "census_results.json"), "w"), indent=2)


if __name__ == "__main__":
    main()
