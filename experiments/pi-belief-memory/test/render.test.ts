import { describe, expect, it } from "vitest";
import { BeliefGraph } from "../src/graph.ts";
import { estimateTokens, render } from "../src/render.ts";

function sessionGraph(): BeliefGraph {
	const graph = new BeliefGraph();
	graph.upsertClaim({ kind: "goal", content: "Add belief-graph memory to Pi", strength: 0.95, turn: 1 });
	graph.upsertClaim({ kind: "constraint", content: "No fork of upstream Pi", strength: 0.95, turn: 1 });
	graph.upsertClaim({
		kind: "fact",
		content: "session_before_compact accepts a details field",
		strength: 0.9,
		properties: { path: "core/extensions/types.ts", line: 595 },
		turn: 2,
	});
	const hypothesis = graph.upsertClaim({ kind: "hypothesis", content: "epigraph-tools is the MCP extension point", strength: 0.7, turn: 3 }).id;
	const observation = graph.upsertClaim({
		kind: "observation",
		content: "CLAUDE.md states epigraph-tools is not how tools reach the MCP server",
		strength: 0.95,
		turn: 3,
	}).id;
	graph.addEdge({ source: observation, target: hypothesis, relation: "contradicts", strength: 0.95, turn: 3 });
	return graph;
}

describe("render", () => {
	it("puts goals and constraints in their own sections", () => {
		const { text } = render(sessionGraph(), { budgetTokens: 4000 });
		expect(text).toContain("## Goals");
		expect(text).toContain("Add belief-graph memory to Pi");
		expect(text).toContain("## Constraints");
		expect(text).toContain("No fork of upstream Pi");
	});

	it("renders a refuted hypothesis under do-not-retry with its counter-evidence", () => {
		// The whole point: the failed approach stays visible instead of being
		// summarized away, so the agent does not propose it again.
		const { text } = render(sessionGraph(), { budgetTokens: 4000 });
		expect(text).toContain("Refuted — do not retry");
		expect(text).toContain("epigraph-tools is the MCP extension point");
		expect(text).toContain("⊣ CLAUDE.md states epigraph-tools is not how tools reach the MCP server");
	});

	it("carries verbatim properties through to the render", () => {
		const { text } = render(sessionGraph(), { budgetTokens: 4000 });
		expect(text).toContain("path=core/extensions/types.ts");
	});

	it("omits superseded claims", () => {
		const graph = new BeliefGraph();
		const old = graph.upsertClaim({ kind: "fact", content: "bug B is open", strength: 0.9, turn: 1 }).id;
		const fresh = graph.upsertClaim({ kind: "fact", content: "bug B is fixed", strength: 0.9, turn: 2 }).id;
		graph.supersede(old, fresh);
		const { text } = render(graph, { budgetTokens: 4000 });
		expect(text).toContain("bug B is fixed");
		expect(text).not.toContain("bug B is open");
	});

	it("marks high-ignorance claims so BetP 0.5 is not read as a coin flip", () => {
		const graph = new BeliefGraph();
		graph.upsertClaim({ kind: "fact", content: "never actually checked", belief: { support: 0, refute: 0, conflict: 0 }, turn: 1 });
		const { text } = render(graph, { budgetTokens: 4000 });
		expect(text).toMatch(/\[0\.50 \?\]/);
	});

	it("marks claims carrying accumulated conflict", () => {
		const graph = new BeliefGraph();
		graph.upsertClaim({ kind: "fact", content: "argued both ways", belief: { support: 0.5, refute: 0.4, conflict: 0.6 }, turn: 1 });
		const { text } = render(graph, { budgetTokens: 4000 });
		expect(text).toContain("!]");
	});

	it("stays within its token budget and reports what it dropped", () => {
		const graph = new BeliefGraph();
		for (let i = 0; i < 400; i++) {
			graph.upsertClaim({
				kind: "fact",
				content: `established fact number ${i} with enough text to occupy a meaningful number of tokens`,
				strength: 0.9,
				turn: i + 1,
			});
		}
		const budgetTokens = 600;
		const result = render(graph, { budgetTokens });
		// Header, section titles and the closing tag sit outside the per-claim
		// budget, so allow a small fixed overhead.
		expect(result.tokens).toBeLessThan(budgetTokens + 200);
		expect(result.dropped).toBeGreaterThan(0);
		expect(result.rendered).toBeGreaterThan(0);
		expect(result.rendered + result.dropped).toBe(400);
	});

	it("preserves refuted claims under budget pressure from established ones", () => {
		const graph = new BeliefGraph();
		for (let i = 0; i < 300; i++) {
			graph.upsertClaim({
				kind: "fact",
				content: `established filler ${i} padded out so it consumes real budget in the render`,
				belief: { support: 0.95, refute: 0, conflict: 0 },
				turn: i + 1,
			});
		}
		graph.upsertClaim({
			kind: "hypothesis",
			content: "the approach that failed",
			belief: { support: 0, refute: 0.95, conflict: 0 },
			turn: 301,
		});
		const { text } = render(graph, { budgetTokens: 500 });
		expect(text).toContain("the approach that failed");
	});

	it("names the kernel pointer only when something was hydrated", () => {
		const plain = render(sessionGraph(), { budgetTokens: 4000 });
		expect(plain.text).not.toContain("⟨epigraph:");

		const graph = sessionGraph();
		graph.upsertClaim({
			kind: "fact",
			content: "a long-term memory claim",
			strength: 0.8,
			turn: 4,
			origin: "epigraph",
			provenance: { id: "a4aaa487-0000-0000-0000-000000000000", source: "http://localhost:8080" },
		});
		const hydrated = render(graph, { budgetTokens: 4000, epigraphSource: "http://localhost:8080" });
		expect(hydrated.text).toContain("⟨epigraph:a4aaa487-0000-0000-0000-000000000000⟩");
		expect(hydrated.text).toContain("get_claim");
	});

	it("renders an empty graph without crashing", () => {
		const result = render(new BeliefGraph(), { budgetTokens: 1000 });
		expect(result.rendered).toBe(0);
		expect(result.text).toContain("<belief-graph");
		expect(result.text).toContain("</belief-graph>");
	});

	it("estimates tokens with the same heuristic Pi uses", () => {
		expect(estimateTokens("a".repeat(400))).toBe(100);
	});
});
