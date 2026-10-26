#!/usr/bin/env python3
"""Independent (non-Rust) derivation of workflow-ids-vectors.json.

Implements epigraph-ingest/src/common/ids.rs from its written definition (the
"definitions" block of the JSON): blake3 from the `blake3` package, UUIDv5
hand-rolled over hashlib.sha1, because uuid.uuid5 only takes str names and the
Rust names are raw bytes.

Run by hand, never by the test suite (which compares, and never regenerates):

    pip install blake3
    python3 gen_workflow_ids_vectors.py > workflow-ids-vectors.json

A changed output is a changed id derivation: every stored workflow id moves.
"""
import hashlib, json, sys, uuid
import blake3

ATOM_NS = uuid.UUID(bytes=bytes([0xa1,0xb2,0xc3,0xd4,0xe5,0xf6,0x47,0x89,0x9a,0xbc,0xde,0xf0,0x12,0x34,0x56,0x78]))
COMPOUND_NS = uuid.UUID(bytes=bytes([0xc0,0x4d,0x90,0xd1,0xe2,0xf3,0x44,0x56,0x78,0x9a,0xbc,0xde,0xf0,0x12,0x34,0xa5]))
WORKFLOW_NS = uuid.UUID(bytes=bytes([0xf1,0x0e,0x55,0xa5,0x37,0x42,0x4b,0xc0,0x9d,0x21,0x8e,0xa6,0xf3,0x12,0x6c,0x88]))

def uuid5(ns: uuid.UUID, name: bytes) -> str:
    d = bytearray(hashlib.sha1(ns.bytes + name).digest()[:16])
    d[6] = (d[6] & 0x0F) | 0x50
    d[8] = (d[8] & 0x3F) | 0x80
    return str(uuid.UUID(bytes=bytes(d)))

def h(text: str) -> bytes:
    return blake3.blake3(text.encode("utf-8")).digest()

def root(name: str, gen: int) -> str:
    return uuid5(WORKFLOW_NS, blake3.blake3(f"{name}:{gen}".encode("utf-8")).digest())

def compound_id(content: str, seed: str) -> str:
    return uuid5(COMPOUND_NS, h(content) + seed.encode("utf-8"))

def compound_hash(content: str, seed: str) -> str:
    return blake3.blake3(h(content) + seed.encode("utf-8")).hexdigest()

def atom(content: str) -> str:
    return uuid5(ATOM_NS, h(content))

NAME = "acme-workflow-plan"
extraction = {
    "source": {
        "canonical_name": NAME,
        "goal": "ACME-123456 workflow-plan: produce the weekly summary",
        "generation": 0,
        "parent_canonical_name": None,
        "authors": [],
        "expected_outcome": None,
        "tags": [],
        "metadata": {},
    },
    "thesis": "ACME-123456 workflow-plan thesis: the weekly summary is built from a complete input list.",
    "thesis_derivation": "TopDown",
    "phases": [
        {
            "title": "Collect",
            "summary": "Collect the inputs for ACME-123456.",
            "steps": [
                {"compound": "Read the input list for ACME-123456.",
                 "rationale": "the list drives every later step",
                 "operations": ["open the ACME-123456 input list"],
                 "generality": [2], "confidence": 0.8, "evidence_type": None},
                {"compound": "Check that the ACME-123456 input list is complete.",
                 "rationale": "a partial list gives a partial summary",
                 "operations": [], "generality": [], "confidence": 0.7, "evidence_type": None},
            ],
        },
        {
            "title": "Report",
            "summary": "",
            "steps": [
                {"compound": "Write the summary for ACME-123456.",
                 "rationale": "the summary is the deliverable",
                 "operations": ["write the ACME-123456 summary file"],
                 "generality": [1], "confidence": 0.9, "evidence_type": None},
            ],
        },
    ],
    "relationships": [],
}

# The plan, in builder order: thesis, then per phase: phase, then per step: step, its atoms.
plan = []
def item(level, content):
    if level <= 2:
        cid, ch = compound_id(content, NAME), compound_hash(content, NAME)
    else:
        cid, ch = atom(content), h(content).hex()
    plan.append({"plan_index": len(plan), "level": level, "content": content,
                 "claim_id": cid, "content_hash": ch, "plain_content_hash": h(content).hex()})
item(0, extraction["thesis"])
for ph in extraction["phases"]:
    item(1, ph["summary"] if ph["summary"].strip() else ph["title"])
    for st in ph["steps"]:
        item(2, st["compound"])
        for op in st["operations"]:
            item(3, op)

roots = [{"canonical_name": n, "generation": g, "workflow_id": root(n, g)} for n, g in [
    (NAME, 0), (NAME, 1), (NAME, 12), ("acme-workflow-plan-üß", 3), ("ACME-123456", 4294967295)]]

compounds = [{"content": c, "seed": s, "claim_id": compound_id(c, s), "content_hash": compound_hash(c, s),
              "plain_content_hash": h(c).hex()} for c, s in [
    ("Read the input list for ACME-123456.", NAME),
    ("Read the input list for ACME-123456.", "acme-other-plan"),
    ("Prüfe die Eingabeliste.", "acme-workflow-plan-üß"),
]]
atoms = [{"content": c, "claim_id": atom(c), "content_hash": h(c).hex()} for c in [
    "open the ACME-123456 input list"]]

out = {
    "schema": "workflow-ids-vectors/v1",
    "about": ("Frozen expected values for epigraph-ingest/src/common/ids.rs and the workflow ingest plan "
              "order. Computed by an implementation independent of the Rust crate "
              "(gen_workflow_ids_vectors.py, beside this file, run by hand); the Rust test "
              "compares, it never regenerates. A change here is a change to every stored workflow id."),
    "namespaces": {"workflow": str(WORKFLOW_NS), "compound": str(COMPOUND_NS), "atom": str(ATOM_NS)},
    "definitions": {
        "blake3": "BLAKE3-256 of the UTF-8 bytes",
        "uuid5": "RFC 4122 UUIDv5: SHA-1(namespace bytes || name bytes)[0..16], version 5, variant 10; name is raw bytes",
        "workflow_root_id": "uuid5(workflow, blake3(canonical_name || ':' || decimal(generation)))",
        "compound_claim_id": "uuid5(compound, blake3(content) || canonical_name), levels 0-2",
        "compound_content_hash": "blake3(blake3(content) || canonical_name), the stored content_hash of levels 0-2",
        "atom_id": "uuid5(atom, blake3(content)), level 3; its stored content_hash is blake3(content)",
        "plan_order": "thesis (level 0); then per phase: the phase (level 1, summary or the title when the summary is blank), then per step: the step (level 2) followed by its operations (level 3)",
    },
    "workflow_root_ids": roots,
    "compound_claims": compounds,
    "atoms": atoms,
    "extraction": extraction,
    "workflow_id": root(NAME, 0),
    "plan": plan,
}
json.dump(out, sys.stdout, indent=2, ensure_ascii=False)
sys.stdout.write("\n")
