/**
 * End-to-end exercise of the compaction cycle the extension drives.
 *
 * This is the behaviour the whole design rests on: a second compaction merges
 * deltas into the graph the first one left behind, instead of asking a model to
 * rewrite a summary it can only half remember. The round trip through JSON is
 * the real one — `details` on a Pi `CompactionEntry` is exactly this payload.
 */

import { describe, expect, it } from "vitest";
import { betp } from "../src/belief.ts";
import { type Extraction, parseExtraction } from "../src/extract.ts";
import { BeliefGraph, GRAPH_KIND, type SerializedGraph } from "../src/graph.ts";
import { render } from "../src/render.ts";

/** Mirrors the merge the extension performs in session_before_compact. */
function applyExtraction(graph: BeliefGraph, extraction: Extraction, turn: number): void {
	const ids = extraction.claims.map(
		(claim) =>
			graph.upsertClaim({
				kind: claim.kind,
				content: claim.content,
				properties: claim.properties,
				strength: claim.strength,
				turn,
			}).id,
	);
	for (const edge of extraction.edges) {
		const source = ids[edge.source];
		const target = ids[edge.target];
		if (source && target) {
			graph.addEdge({ source, target, relation: edge.relation, strength: edge.strength, turn });
		}
	}
	for (const { old, by } of extraction.superseded) {
		const retired = graph.findByContent(old);
		const replacement = ids[by];
		if (retired && replacement) graph.supersede(retired.id, replacement);
	}
	for (const path of extraction.files.read) graph.recordFile(path, "read");
	for (const path of extraction.files.edited) graph.recordFile(path, "edited");
}

/** Round-trip through JSON exactly as Pi persists and reloads `details`. */
function persistAndRestore(graph: BeliefGraph): BeliefGraph {
	const details = JSON.parse(JSON.stringify(graph.toJSON())) as SerializedGraph;
	expect(details.kind).toBe(GRAPH_KIND);
	return BeliefGraph.from(details);
}

const FIRST_COMPACTION = `\`\`\`json
{
  "claims": [
    { "kind": "goal", "content": "Make the migration test suite pass", "strength": 0.95, "properties": {} },
    { "kind": "hypothesis", "content": "the failure is a stale sqlx offline cache", "strength": 0.6, "properties": {} },
    { "kind": "observation", "content": "cargo test reported error[E0308] in claim.rs", "strength": 0.95, "properties": { "error": "error[E0308]: mismatched types", "path": "crates/epigraph-db/src/repos/claim.rs" } }
  ],
  "edges": [ { "source": 2, "target": 1, "relation": "supports", "strength": 0.6 } ],
  "superseded": [],
  "files": { "read": ["crates/epigraph-db/src/repos/claim.rs"], "edited": [] }
}
\`\`\``;

const SECOND_COMPACTION = `\`\`\`json
{
  "claims": [
    { "kind": "observation", "content": "cargo sqlx prepare left the same E0308 failure", "strength": 0.95, "properties": {} },
    { "kind": "hypothesis", "content": "the SELECT in list_by_labels is missing a column", "strength": 0.7, "properties": {} },
    { "kind": "decision", "content": "extend the SELECT in list_by_labels rather than widening claim_from_row", "strength": 0.9, "properties": {} }
  ],
  "edges": [
    { "source": 0, "target": 1, "relation": "supports", "strength": 0.8 }
  ],
  "superseded": [],
  "files": { "read": [], "edited": ["crates/epigraph-db/src/repos/claim.rs"] }
}
\`\`\``;

describe("compaction cycle", () => {
	it("merges a second compaction into the graph the first one persisted", () => {
		const first = new BeliefGraph();
		applyExtraction(first, parseExtraction(FIRST_COMPACTION)!, 4);
		expect(first.size.claims).toBe(3);

		// Pi persists `details`, the session is compacted again later, and the
		// extension restores from the entry rather than from prose.
		const restored = persistAndRestore(first);
		expect(restored.size.claims).toBe(3);

		applyExtraction(restored, parseExtraction(SECOND_COMPACTION)!, 9);

		// Six distinct claims, not two rival summaries.
		expect(restored.size.claims).toBe(6);
		// The original goal survived a round trip and a merge untouched.
		expect(restored.findByContent("Make the migration test suite pass")?.kind).toBe("goal");
		// File tracking accumulates across both spans.
		expect(restored.files().read).toContain("crates/epigraph-db/src/repos/claim.rs");
		expect(restored.files().edited).toContain("crates/epigraph-db/src/repos/claim.rs");
	});

	it("retires a hypothesis the later span refutes, and keeps it visible as a dead end", () => {
		const graph = new BeliefGraph();
		applyExtraction(graph, parseExtraction(FIRST_COMPACTION)!, 4);
		const stale = graph.findByContent("the failure is a stale sqlx offline cache")!;
		expect(betp(stale.belief)).toBeGreaterThan(0.5);

		const refutation = parseExtraction(`\`\`\`json
{
  "claims": [
    { "kind": "observation", "content": "regenerating .sqlx changed nothing; the error persisted", "strength": 0.95, "properties": {} },
    { "kind": "hypothesis", "content": "the failure is a stale sqlx offline cache", "strength": 0.1, "properties": {} }
  ],
  "edges": [ { "source": 0, "target": 1, "relation": "contradicts", "strength": 0.95 } ],
  "superseded": [],
  "files": { "read": [], "edited": [] }
}
\`\`\``)!;
		// Applying the same refutation to a persisted copy must reach the same
		// belief — the round trip is lossless, not merely non-crashing.
		const viaDisk = persistAndRestore(graph);
		applyExtraction(viaDisk, refutation, 9);
		applyExtraction(graph, refutation, 9);

		const killed = graph.findByContent("the failure is a stale sqlx offline cache")!;
		const killedViaDisk = viaDisk.findByContent("the failure is a stale sqlx offline cache")!;
		expect(betp(killedViaDisk.belief)).toBeCloseTo(betp(killed.belief), 10);
		expect(killed.belief.refute).toBeGreaterThan(killed.belief.support);

		// And the render says so out loud, which is the point — a prose summary
		// would have dropped the dead end entirely by the second compaction.
		const { text } = render(graph, { budgetTokens: 4000 });
		expect(text).toContain("Refuted — do not retry");
		expect(text).toContain("stale sqlx offline cache");
	});

	it("drops a superseded fact from the render instead of asserting both versions", () => {
		const graph = new BeliefGraph();
		graph.upsertClaim({ kind: "fact", content: "the migration test suite fails", strength: 0.9, turn: 1 });

		applyExtraction(
			graph,
			parseExtraction(`\`\`\`json
{
  "claims": [ { "kind": "fact", "content": "the migration test suite passes as of abc1234", "strength": 0.95, "properties": { "sha": "abc1234" } } ],
  "edges": [],
  "superseded": [ { "old": "the migration test suite fails", "by": 0 } ],
  "files": { "read": [], "edited": [] }
}
\`\`\``)!,
			9,
		);

		const { text } = render(graph, { budgetTokens: 4000 });
		expect(text).toContain("passes as of abc1234");
		expect(text).not.toContain("the migration test suite fails");
		expect(text).toContain("sha=abc1234");
	});

	it("keeps the rendered block inside budget as the graph grows over many cycles", () => {
		const graph = new BeliefGraph();
		for (let cycle = 1; cycle <= 25; cycle++) {
			applyExtraction(
				graph,
				{
					claims: [
						{ kind: "fact", content: `cycle ${cycle} established something worth remembering here`, strength: 0.85, properties: {} },
						{ kind: "observation", content: `cycle ${cycle} observed a concrete command result`, strength: 0.9, properties: {} },
					],
					edges: [{ source: 1, target: 0, relation: "supports", strength: 0.8 }],
					superseded: [],
					files: { read: [], edited: [] },
				},
				cycle * 3,
			);
			graph.prune(160);
		}

		const budgetTokens = 1500;
		const result = render(graph, { budgetTokens });
		expect(result.tokens).toBeLessThan(budgetTokens + 200);
		expect(result.rendered).toBeGreaterThan(0);
	});
});
