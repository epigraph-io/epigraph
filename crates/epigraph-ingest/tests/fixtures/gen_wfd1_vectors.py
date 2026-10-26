#!/usr/bin/env python3
"""Independent (non-Rust) derivation of wfd1-vectors.json.

Implements the frozen-plan digest `wfd1`, the deterministic workflow ids and
the plan the workflow ingest writes, from their written definitions (the
"definitions" block of the output), NOT from the Rust code under test: blake3
from the `blake3` package, UUIDv5 hand-rolled over hashlib.sha1 because
uuid.uuid5 only takes str names and these names are raw bytes.

Run by hand, never by the test suite (which compares, and never regenerates):

    pip install blake3
    python3 gen_wfd1_vectors.py > wfd1-vectors.json

A changed output is a changed digest or id definition: every pin moves.
"""
import hashlib
import json
import sys
import uuid

import blake3

# The three namespaces of epigraph-ingest's common/ids.rs, as raw bytes.
ATOM_NS = uuid.UUID(bytes=bytes([0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x47, 0x89,
                                 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78]))
COMPOUND_NS = uuid.UUID(bytes=bytes([0xc0, 0x4d, 0x90, 0xd1, 0xe2, 0xf3, 0x44, 0x56,
                                     0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0xa5]))
WORKFLOW_NS = uuid.UUID(bytes=bytes([0xf1, 0x0e, 0x55, 0xa5, 0x37, 0x42, 0x4b, 0xc0,
                                     0x9d, 0x21, 0x8e, 0xa6, 0xf3, 0x12, 0x6c, 0x88]))


def uuid5(ns: uuid.UUID, name: bytes) -> str:
    d = bytearray(hashlib.sha1(ns.bytes + name).digest()[:16])
    d[6] = (d[6] & 0x0F) | 0x50
    d[8] = (d[8] & 0x3F) | 0x80
    return str(uuid.UUID(bytes=bytes(d)))


def h(text: str) -> bytes:
    return blake3.blake3(text.encode("utf-8")).digest()


def root_id(name: str, gen: int) -> str:
    return uuid5(WORKFLOW_NS, blake3.blake3(f"{name}:{gen}".encode("utf-8")).digest())


def compound_id(content: str, seed: str) -> str:
    return uuid5(COMPOUND_NS, h(content) + seed.encode("utf-8"))


def compound_hash(content: str, seed: str) -> str:
    return blake3.blake3(h(content) + seed.encode("utf-8")).hexdigest()


def atom_id(content: str) -> str:
    return uuid5(ATOM_NS, h(content))


def wfd1(name: str, gen: int, items) -> str:
    m = bytearray()
    m += b"epigraph-wf-v1\n"
    m += name.encode("utf-8") + b"\n" + str(gen).encode("ascii") + b"\n"
    for it in sorted(items, key=lambda i: i["plan_index"]):
        c = it["content"].encode("utf-8")
        m += f"{it['level']}\t{it['claim_id']}\t{len(c)}\n".encode("ascii") + c + b"\n"
    return "wfd1:" + blake3.blake3(bytes(m)).hexdigest()


def item(plan_index: int, level: int, content: str, name: str) -> dict:
    if level <= 2:
        return {"plan_index": plan_index, "level": level, "content": content,
                "claim_id": compound_id(content, name),
                "content_hash": compound_hash(content, name)}
    return {"plan_index": plan_index, "level": level, "content": content,
            "claim_id": atom_id(content), "content_hash": h(content).hex()}


def ingest_plan(extraction: dict) -> list:
    """The plan order the workflow ingest records as `plan_index`: the thesis,
    then per phase the phase node (its summary, or its title when the summary
    is blank), then per step the step node followed by its operation atoms."""
    name = extraction["source"]["canonical_name"]
    texts = []
    if extraction.get("thesis") is not None:
        texts.append((0, extraction["thesis"]))
    for phase in extraction["phases"]:
        summary = phase.get("summary", "")
        texts.append((1, summary if summary.strip() else phase["title"]))
        for step in phase["steps"]:
            texts.append((2, step["compound"]))
            for op in step.get("operations", []):
                texts.append((3, op))
    return [item(i, level, content, name) for i, (level, content) in enumerate(texts)]


# --- case 1: an ingest whose frozen plan the server reads back ----------------
NAME = "acme-frozen-plan"
extraction = {
    "source": {"canonical_name": NAME, "generation": 0,
               "goal": "Read the ACME-123456 queue once and summarise it.",
               "metadata": {}},
    "thesis": f"{NAME} \u2014 thesis: read the ACME-123456 queue once",
    "thesis_derivation": "TopDown",
    "phases": [
        {"title": "Collect", "summary": f"{NAME} \u2014 phase 1: collect the rows",
         "steps": [
             {"compound": f"{NAME} \u2014 step 1.1: read the queue",
              "rationale": "ordered", "confidence": 0.8,
              "operations": ["open the ACME-123456 queue",
                             "pr\u00fcfe jede Zeile \u2014 h\u00f6chstens 40"],
              "generality": [1, 2]},
             {"compound": f"{NAME} \u2014 step 1.2: keep the new rows",
              "rationale": "ordered", "confidence": 0.8,
              "operations": [], "generality": []},
         ]},
        {"title": f"{NAME} \u2014 phase 2: report", "summary": "",
         "steps": [
             {"compound": f"{NAME} \u2014 step 2.1: write the summary \u2713",
              "rationale": "ordered", "confidence": 0.8,
              "operations": ["write one line per new row"],
              "generality": [1]},
         ]},
    ],
    "relationships": [],
}
plan = ingest_plan(extraction)

# The same items with the plan_index values of items 1 and 2 exchanged: what a
# group writer's two `patch_edge` calls produce. Every id and every content is
# unchanged; only the order the digest walks moves.
swapped = [dict(i) for i in plan]
swapped[1]["plan_index"], swapped[2]["plan_index"] = 2, 1

ingest_case = {
    "canonical_name": NAME,
    "generation": 0,
    "workflow_id": root_id(NAME, 0),
    "extraction": extraction,
    "plan": plan,
    "wfd1": wfd1(NAME, 0, plan),
    "wfd1_with_plan_index_1_and_2_swapped": wfd1(NAME, 0, swapped),
}

# --- case 2: the synthetic child the pinned-workflow resolver tests use -------
# Byte-for-byte the child case of the resolver's own wfd1 vectors, so the two
# repositories are checked against one value: a server echo and a host digest
# of the same items must agree.
CHILD = "acme-ops-sched-a-rules"


def slice_step(anchor: str, text: str) -> str:
    return f"\u27e6wfs1 {anchor}\u27e7\n" + text


child_texts = [
    (0, f"{CHILD} \u2014 thesis"),
    (1, f"{CHILD} \u2014 phase 1: RULES"),
    (2, slice_step("RULES", "# RULES\n\nEvery ACME-123456 row is read once.\n")),
    (2, slice_step("RULES/LIMITS",
                   "## LIMITS\n\nPr\u00fcfe die Eingabeliste \u2014 h\u00f6chstens 40 Zeilen.\n")),
]
child_items = [item(i, level, content, CHILD) for i, (level, content) in enumerate(child_texts)]
child_case = {
    "canonical_name": CHILD,
    "generation": 0,
    "workflow_id": root_id(CHILD, 0),
    "items": child_items,
    "wfd1": wfd1(CHILD, 0, child_items),
}

out = {
    "schema": "wfd1-vectors/v1",
    "about": ("Frozen expected values for the frozen-plan digest wfd1 and the ids and stored "
              "hashes a workflow ingest writes. Computed by an implementation independent of the "
              "Rust crates (gen_wfd1_vectors.py, beside this file, run by hand); the Rust tests "
              "compare, they never regenerate. The server's digest_echo must equal these values."),
    "definitions": {
        "wfd1": ("\"wfd1:\" + lowercase hex BLAKE3-256 of: \"epigraph-wf-v1\\n\" || canonical_name || \"\\n\" "
                 "|| decimal(generation) || \"\\n\" || for each item in plan_index order 0..n-1: "
                 "decimal(level) || \"\\t\" || claim_id || \"\\t\" || decimal(byte_len(content)) || \"\\n\" "
                 "|| content || \"\\n\""),
        "claim_id_text": "lowercase hyphenated UUID (8-4-4-4-12)",
        "byte_len": "number of UTF-8 bytes of content, not characters",
        "strings": "UTF-8, no normalization, no trimming",
        "workflow_root_id": "uuid5(workflow, blake3(canonical_name || ':' || decimal(generation)))",
        "compound_claim_id": "uuid5(compound, blake3(content) || canonical_name), levels 0-2",
        "compound_content_hash": "blake3(blake3(content) || canonical_name), the stored hash of levels 0-2",
        "atom_id": "uuid5(atom, blake3(content)), level 3",
        "atom_content_hash": "blake3(content), the stored hash of level 3",
        "plan_order": ("the thesis; then per phase its node (summary, or title when the summary is "
                       "blank); then per step its node followed by its operation atoms"),
    },
    "ingest": ingest_case,
    "resolver_child": child_case,
}
json.dump(out, sys.stdout, indent=2, ensure_ascii=False)
sys.stdout.write("\n")
