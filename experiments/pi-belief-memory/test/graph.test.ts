import { describe, expect, it } from "vitest";
import { betp } from "../src/belief.ts";
import { BeliefGraph, claimId } from "../src/graph.ts";

function graphWith(...contents: string[]): { graph: BeliefGraph; ids: string[] } {
	const graph = new BeliefGraph();
	const ids = contents.map((content, index) => graph.upsertClaim({ kind: "fact", content, turn: index + 1 }).id);
	return { graph, ids };
}

describe("BeliefGraph claims", () => {
	it("keys claims by normalized content so restatements merge", () => {
		const graph = new BeliefGraph();
		const first = graph.upsertClaim({ kind: "fact", content: "The build is green", turn: 1 });
		const second = graph.upsertClaim({ kind: "fact", content: "  the   BUILD is green  ", turn: 2 });
		expect(second.id).toBe(first.id);
		expect(graph.size.claims).toBe(1);
	});

	it("raises belief when a claim is re-observed rather than replacing it", () => {
		const graph = new BeliefGraph();
		const once = graph.upsertClaim({ kind: "fact", content: "x", strength: 0.6, turn: 1 });
		const before = betp(once.belief);
		const twice = graph.upsertClaim({ kind: "fact", content: "x", strength: 0.6, turn: 2 });
		expect(betp(twice.belief)).toBeGreaterThan(before);
		expect(twice.firstSeenTurn).toBe(1);
		expect(twice.lastSeenTurn).toBe(2);
	});

	it("separates claims that share content but differ in kind", () => {
		const graph = new BeliefGraph();
		graph.upsertClaim({ kind: "hypothesis", content: "the cache is stale", turn: 1 });
		graph.upsertClaim({ kind: "observation", content: "the cache is stale", turn: 1 });
		expect(graph.size.claims).toBe(2);
	});

	it("finds a live claim by content regardless of kind", () => {
		const graph = new BeliefGraph();
		graph.upsertClaim({ kind: "hypothesis", content: "Approach A works", turn: 1 });
		expect(graph.findByContent("approach a works")?.kind).toBe("hypothesis");
		expect(graph.findByContent("nothing like this")).toBeUndefined();
	});

	it("exposes a stable claim id helper", () => {
		expect(claimId("fact", "A")).toBe(claimId("fact", " a "));
		expect(claimId("fact", "A")).not.toBe(claimId("goal", "A"));
	});
});

describe("BeliefGraph edges", () => {
	it("drops edges whose endpoints are unknown", () => {
		const { graph, ids } = graphWith("a");
		expect(graph.addEdge({ source: ids[0], target: "missing", relation: "supports", turn: 1 })).toBeUndefined();
		expect(graph.size.edges).toBe(0);
	});

	it("rejects self-loops", () => {
		const { graph, ids } = graphWith("a");
		expect(graph.addEdge({ source: ids[0], target: ids[0], relation: "supports", turn: 1 })).toBeUndefined();
	});

	it("keeps re-occurrence as separate events rather than one merged edge", () => {
		// Noun/verb split: the fact is one claim, each run of the command is
		// its own timestamped edge.
		const { graph, ids } = graphWith("test suite exists", "the suite passes");
		graph.addEdge({ source: ids[0], target: ids[1], relation: "ran", turn: 1 });
		graph.addEdge({ source: ids[0], target: ids[1], relation: "ran", turn: 2 });
		expect(graph.size.edges).toBe(2);
	});

	it("moves mass into the target along a supports edge", () => {
		const { graph, ids } = graphWith("observed: exit code 0", "the fix worked");
		const before = betp(graph.getClaim(ids[1])!.belief);
		graph.addEdge({ source: ids[0], target: ids[1], relation: "supports", strength: 0.9, turn: 2 });
		expect(betp(graph.getClaim(ids[1])!.belief)).toBeGreaterThan(before);
	});

	it("drives a hypothesis down along a contradicts edge", () => {
		const graph = new BeliefGraph();
		const hypothesis = graph.upsertClaim({ kind: "hypothesis", content: "approach A works", strength: 0.7, turn: 1 }).id;
		const observation = graph.upsertClaim({
			kind: "observation",
			content: "approach A raised TypeError",
			strength: 0.95,
			turn: 2,
		}).id;
		graph.addEdge({ source: observation, target: hypothesis, relation: "contradicts", strength: 0.9, turn: 2 });

		const killed = graph.getClaim(hypothesis)!.belief;
		// Refuting mass now outweighs supporting mass — the signal the renderer
		// files under "do not retry". BetP lands near 0.4 rather than near 0
		// because Dempster's rule normalizes conflict away; see belief.test.ts.
		expect(killed.refute).toBeGreaterThan(killed.support);
		expect(killed.conflict).toBeGreaterThan(0.3);
		expect(betp(killed)).toBeLessThan(0.5);
	});

	it("discounts evidence by the source claim's own belief", () => {
		const graph = new BeliefGraph();
		const strongSource = graph.upsertClaim({ kind: "observation", content: "solid", strength: 0.95, turn: 1 }).id;
		const weakSource = graph.upsertClaim({ kind: "hypothesis", content: "shaky", strength: 0.05, turn: 1 }).id;
		const targetA = graph.upsertClaim({ kind: "fact", content: "target a", strength: 0.5, turn: 1 }).id;
		const targetB = graph.upsertClaim({ kind: "fact", content: "target b", strength: 0.5, turn: 1 }).id;

		graph.addEdge({ source: strongSource, target: targetA, relation: "supports", strength: 0.8, turn: 2 });
		graph.addEdge({ source: weakSource, target: targetB, relation: "supports", strength: 0.8, turn: 2 });

		expect(betp(graph.getClaim(targetA)!.belief)).toBeGreaterThan(betp(graph.getClaim(targetB)!.belief));
	});

	it("skips evidence application when the caller opts out", () => {
		// Hydrated edges: the kernel already folded them into its reported
		// belief, so re-applying would double-count.
		const { graph, ids } = graphWith("a", "b");
		const before = betp(graph.getClaim(ids[1])!.belief);
		graph.addEdge({
			source: ids[0],
			target: ids[1],
			relation: "supports",
			strength: 0.9,
			turn: 2,
			applyEvidence: false,
		});
		expect(betp(graph.getClaim(ids[1])!.belief)).toBe(before);
		expect(graph.size.edges).toBe(1);
	});
});

describe("BeliefGraph supersession", () => {
	it("retires the old claim and keeps it out of the current set", () => {
		const { graph, ids } = graphWith("bug B is open", "bug B is fixed in abc123");
		graph.supersede(ids[0], ids[1]);
		expect(graph.getClaim(ids[0])!.isCurrent).toBe(false);
		expect(graph.getClaim(ids[0])!.supersededBy).toBe(ids[1]);
		expect(graph.currentClaims().map((claim) => claim.id)).toEqual([ids[1]]);
	});

	it("supersedes via a supersedes edge", () => {
		const { graph, ids } = graphWith("old", "new");
		graph.addEdge({ source: ids[1], target: ids[0], relation: "supersedes", turn: 2 });
		expect(graph.getClaim(ids[0])!.isCurrent).toBe(false);
	});

	it("ignores a self-supersede", () => {
		const { graph, ids } = graphWith("a");
		graph.supersede(ids[0], ids[0]);
		expect(graph.getClaim(ids[0])!.isCurrent).toBe(true);
	});
});

describe("BeliefGraph serialization", () => {
	it("round-trips through JSON with beliefs and edges intact", () => {
		const graph = new BeliefGraph();
		const a = graph.upsertClaim({ kind: "goal", content: "ship it", turn: 1 }).id;
		const b = graph.upsertClaim({ kind: "observation", content: "tests pass", turn: 2 }).id;
		graph.addEdge({ source: b, target: a, relation: "supports", strength: 0.9, turn: 2 });
		graph.recordFile("src/foo.ts", "edited");

		const restored = BeliefGraph.from(JSON.parse(JSON.stringify(graph.toJSON())));
		expect(restored.size).toEqual(graph.size);
		expect(restored.turn).toBe(graph.turn);
		expect(betp(restored.getClaim(a)!.belief)).toBeCloseTo(betp(graph.getClaim(a)!.belief), 10);
		expect(restored.files().edited).toEqual(["src/foo.ts"]);
	});

	it("restores from an empty payload without throwing", () => {
		const restored = BeliefGraph.from({ kind: "belief-graph/v1", turn: 0, claims: [], edges: [], files: { read: [], edited: [] } });
		expect(restored.size.claims).toBe(0);
	});
});

describe("BeliefGraph pruning", () => {
	it("never evicts goals or constraints", () => {
		const graph = new BeliefGraph();
		graph.upsertClaim({ kind: "goal", content: "the goal", turn: 1 });
		graph.upsertClaim({ kind: "constraint", content: "the constraint", turn: 1 });
		for (let i = 0; i < 30; i++) {
			graph.upsertClaim({ kind: "fact", content: `filler ${i}`, turn: 2 });
		}
		graph.prune(5);
		const kinds = graph.allClaims().map((claim) => claim.kind);
		expect(kinds).toContain("goal");
		expect(kinds).toContain("constraint");
		expect(graph.size.claims).toBeLessThanOrEqual(5 + 2);
	});

	it("keeps decisive claims over undecided ones", () => {
		const graph = new BeliefGraph();
		const refuted = graph.upsertClaim({ kind: "hypothesis", content: "refuted approach", belief: { support: 0, refute: 0.95, conflict: 0 }, turn: 5 }).id;
		const established = graph.upsertClaim({ kind: "fact", content: "established fact", belief: { support: 0.95, refute: 0, conflict: 0 }, turn: 5 }).id;
		for (let i = 0; i < 10; i++) {
			graph.upsertClaim({ kind: "fact", content: `undecided ${i}`, belief: { support: 0, refute: 0, conflict: 0 }, turn: 5 });
		}
		graph.prune(2);
		const remaining = graph.allClaims().map((claim) => claim.id);
		expect(remaining).toContain(refuted);
		expect(remaining).toContain(established);
	});

	it("drops edges left dangling by pruning", () => {
		const graph = new BeliefGraph();
		const keep = graph.upsertClaim({ kind: "goal", content: "keep me", turn: 1 }).id;
		const drop = graph.upsertClaim({ kind: "fact", content: "drop me", turn: 1 }).id;
		graph.addEdge({ source: drop, target: keep, relation: "supports", turn: 1 });
		graph.prune(1);
		expect(graph.getClaim(drop)).toBeUndefined();
		expect(graph.allEdges()).toHaveLength(0);
	});

	it("is a no-op below the cap", () => {
		const { graph } = graphWith("a", "b");
		expect(graph.prune(10)).toBe(0);
	});
});
