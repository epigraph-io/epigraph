#!/usr/bin/env python3
"""Independent (non-Rust) derivation of scoped-id-vectors.json.

Derives the ids and stored hashes a DOCUMENT ingest plan carries, public and
scope-derived, from their written definitions (epigraph-ingest
`common/ids.rs`, module doc "Scope-derived ids"), NOT from the Rust code under
test: blake3 from the `blake3` package, UUIDv5 hand-rolled over hashlib.sha1
because uuid.uuid5 only takes str names and these names are raw bytes.

The "public" half pins the ids every public ingest has always derived; the
"scoped" half pins the scheme a client recomputing a non-public ingest's ids
must follow. Run by hand, never by the test suite (which compares, and never
regenerates):

    pip install blake3
    python3 gen_scoped_id_vectors.py > scoped-id-vectors.json
"""
import hashlib
import json
import uuid

import blake3

ATOM_NS = uuid.UUID(bytes=bytes([0xa1,0xb2,0xc3,0xd4,0xe5,0xf6,0x47,0x89,0x9a,0xbc,0xde,0xf0,0x12,0x34,0x56,0x78]))
COMPOUND_NS = uuid.UUID(bytes=bytes([0xc0,0x4d,0x90,0xd1,0xe2,0xf3,0x44,0x56,0x78,0x9a,0xbc,0xde,0xf0,0x12,0x34,0xa5]))
def uuid5(ns, name):
    d=bytearray(hashlib.sha1(ns.bytes+name).digest()[:16]); d[6]=(d[6]&0x0F)|0x50; d[8]=(d[8]&0x3F)|0x80
    return str(uuid.UUID(bytes=bytes(d)))
def h(t): return blake3.blake3(t.encode()).digest()
GROUP = uuid.UUID("5c0be1d2-7a41-4f6e-9b3a-2d8e6f1a0c47")
title = "Scoped Id Golden Paper — résumé"
ex = {
 "source": {"title": title, "source_type": "Paper", "authors": []},
 "thesis": "Golden thesis: ids stay put",
 "thesis_derivation": "TopDown",
 "sections": [
  {"title": "Introduction", "paragraphs": [
    {"text": "First paragraph text.", "atoms": ["Atom one is plain.", "Atom zwölf has umlauts."], "generality": [1,2], "confidence": 0.8}]},
  {"title": "Results", "paragraphs": [
    {"text": "Second paragraph text.", "atoms": ["Atom one is plain."], "generality": [1], "confidence": 0.7},
    {"text": "Third paragraph text.", "atoms": [], "generality": [], "confidence": 0.6}]}
 ],
 "relationships": []
}
def plan(scope):
    out=[]
    sfx = "" if scope is None else ":"+str(scope)
    def comp(level, text, path):
        seed = f"{title}\x1f{path}"+sfx
        out.append({"level":level,"content":text,"claim_id":uuid5(COMPOUND_NS,h(text)+seed.encode()),
                    "content_hash":blake3.blake3(h(text)+seed.encode()).hexdigest()})
    def atom(text):
        if scope is None:
            out.append({"level":3,"content":text,"claim_id":uuid5(ATOM_NS,h(text)),"content_hash":h(text).hex()})
        else:
            out.append({"level":3,"content":text,"claim_id":uuid5(ATOM_NS,h(text)+scope.bytes),
                        "content_hash":blake3.blake3(h(text)+scope.bytes).hexdigest()})
    comp(0, ex["thesis"], "thesis")
    for si,s in enumerate(ex["sections"]):
        comp(1, s["title"], f"sections[{si}]")
        for pi,p in enumerate(s["paragraphs"]):
            comp(2, p["text"], f"sections[{si}].paragraphs[{pi}]")
            for a in p["atoms"]: atom(a)
    return out
print(json.dumps({"schema":"scoped-ids-v1","about":"Independent (Python) derivation of document ingest ids; see gen_scoped_id_vectors.py.",
  "group": str(GROUP), "extraction": ex, "public": plan(None), "scoped": plan(GROUP)}, indent=1, ensure_ascii=False))
