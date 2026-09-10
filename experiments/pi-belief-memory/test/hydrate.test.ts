import { describe, expect, it, vi } from "vitest";
import { betp } from "../src/belief.ts";
import { BeliefGraph } from "../src/graph.ts";
import { epigraphConfigFromEnv, hydrate } from "../src/hydrate.ts";

const SEED_ID = "11111111-1111-1111-1111-111111111111";
const NEIGHBOUR_ID = "22222222-2222-2222-2222-222222222222";
const EDGE_ID = "33333333-3333-3333-3333-333333333333";

function json(body: unknown): Response {
	return new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
}

/** A kernel that returns one seed, one neighbour, and one edge between them. */
function fakeKernel(overrides: Record<string, () => Response> = {}): typeof fetch {
	return vi.fn(async (input: RequestInfo | URL) => {
		const url = String(input);
		for (const [fragment, handler] of Object.entries(overrides)) {
			if (url.includes(fragment)) return handler();
		}
		if (url.includes("/search/semantic")) {
			return json({
				results: [
					{
						claim_id: SEED_ID,
						statement: "sqlx offline cache must be regenerated after query changes",
						similarity: 0.82,
						epistemic: { belief: 0.7, plausibility: 0.9 },
						agent_id: "aaaa",
						labels: ["kind:constraint"],
					},
				],
			});
		}
		if (url.includes(`/claims/${SEED_ID}/neighborhood`)) {
			return json({
				center_id: SEED_ID,
				depth: 1,
				connected_entity_ids: [NEIGHBOUR_ID],
				edges: [
					{
						id: EDGE_ID,
						source_id: NEIGHBOUR_ID,
						target_id: SEED_ID,
						source_type: "claim",
						target_type: "claim",
						relationship: "supports",
						properties: {},
					},
				],
			});
		}
		if (url.includes(`/claims/${NEIGHBOUR_ID}/neighborhood`)) {
			return json({ center_id: NEIGHBOUR_ID, depth: 1, connected_entity_ids: [], edges: [] });
		}
		if (url.includes(`/claims/${NEIGHBOUR_ID}`)) {
			return json({ id: NEIGHBOUR_ID, content: "CI runs with SQLX_OFFLINE=true", truth_value: 0.9, labels: [] });
		}
		return new Response("not found", { status: 404 });
	}) as unknown as typeof fetch;
}

const options = { apiUrl: "http://localhost:8080", turn: 3 };

describe("hydrate", () => {
	it("pulls seeds, neighbours, and the edges between them", async () => {
		const graph = new BeliefGraph();
		const result = await hydrate(graph, "sqlx cache", { ...options, fetchImpl: fakeKernel() });

		expect(result.seeds).toBe(1);
		expect(result.claimsAdded).toBe(2);
		expect(result.edgesAdded).toBe(1);
		expect(result.errors).toEqual([]);
		expect(graph.size.claims).toBe(2);
		expect(graph.allEdges()[0].relation).toBe("supports");
	});

	it("attaches a resolvable provenance pointer to every hydrated claim", async () => {
		const graph = new BeliefGraph();
		await hydrate(graph, "sqlx cache", { ...options, fetchImpl: fakeKernel() });

		for (const claim of graph.allClaims()) {
			expect(claim.origin).toBe("epigraph");
			expect(claim.provenance?.source).toBe("http://localhost:8080");
		}
		const seed = graph.allClaims().find((claim) => claim.provenance?.id === SEED_ID);
		expect(seed?.provenance?.agentId).toBe("aaaa");
	});

	it("carries the kernel belief interval across rather than re-deriving it", async () => {
		const graph = new BeliefGraph();
		await hydrate(graph, "sqlx cache", { ...options, fetchImpl: fakeKernel() });

		const seed = graph.allClaims().find((claim) => claim.provenance?.id === SEED_ID)!;
		// [Bel, Pl] = [0.7, 0.9] → support 0.7, refute 0.1, ignorance 0.2 → BetP 0.8
		expect(seed.belief.support).toBeCloseTo(0.7, 10);
		expect(seed.belief.refute).toBeCloseTo(0.1, 10);
		expect(betp(seed.belief)).toBeCloseTo(0.8, 10);
	});

	it("does not double-count a hydrated supports edge", async () => {
		const graph = new BeliefGraph();
		await hydrate(graph, "sqlx cache", { ...options, fetchImpl: fakeKernel() });
		const seed = graph.allClaims().find((claim) => claim.provenance?.id === SEED_ID)!;
		// The kernel already folded the supporting edge into [0.7, 0.9]; if the
		// edge were applied again BetP would drift above 0.8.
		expect(betp(seed.belief)).toBeCloseTo(0.8, 10);
	});

	it("reads the claim kind from a kernel label", async () => {
		const graph = new BeliefGraph();
		await hydrate(graph, "sqlx cache", { ...options, fetchImpl: fakeKernel() });
		const seed = graph.allClaims().find((claim) => claim.provenance?.id === SEED_ID)!;
		expect(seed.kind).toBe("constraint");
	});

	it("starts a neighbour without an interval as vacuous rather than borrowing the seed's belief", async () => {
		const graph = new BeliefGraph();
		await hydrate(graph, "sqlx cache", { ...options, fetchImpl: fakeKernel() });
		const neighbour = graph.allClaims().find((claim) => claim.provenance?.id === NEIGHBOUR_ID)!;
		expect(betp(neighbour.belief)).toBe(0.5);
		expect(neighbour.belief.support).toBe(0);
	});

	it("degrades to an empty result when the kernel is unreachable", async () => {
		const graph = new BeliefGraph();
		const failing = vi.fn(async () => {
			throw new Error("ECONNREFUSED");
		}) as unknown as typeof fetch;

		const result = await hydrate(graph, "anything", { ...options, fetchImpl: failing });
		expect(result.claimsAdded).toBe(0);
		expect(result.errors[0]).toContain("semantic search failed");
		expect(graph.size.claims).toBe(0);
	});

	it("keeps the seeds when a neighbourhood call fails", async () => {
		const graph = new BeliefGraph();
		const result = await hydrate(graph, "sqlx cache", {
			...options,
			fetchImpl: fakeKernel({ neighborhood: () => new Response("boom", { status: 500 }) }),
		});
		expect(result.seeds).toBe(1);
		expect(result.claimsAdded).toBe(1);
		expect(result.errors).toHaveLength(1);
	});

	it("respects the claim cap", async () => {
		const graph = new BeliefGraph();
		const result = await hydrate(graph, "sqlx cache", { ...options, maxClaims: 1, fetchImpl: fakeKernel() });
		expect(result.claimsAdded).toBe(1);
	});

	it("merges a hydrated claim into an identical session claim", async () => {
		const graph = new BeliefGraph();
		graph.upsertClaim({
			kind: "constraint",
			content: "sqlx offline cache must be regenerated after query changes",
			strength: 0.5,
			turn: 1,
		});
		await hydrate(graph, "sqlx cache", { ...options, fetchImpl: fakeKernel() });

		const merged = graph.findByContent("sqlx offline cache must be regenerated after query changes")!;
		// One row, not two — and it gains the pointer back to long-term memory.
		expect(graph.allClaims().filter((c) => c.kind === "constraint")).toHaveLength(1);
		expect(merged.provenance?.id).toBe(SEED_ID);
		expect(betp(merged.belief)).toBeGreaterThan(0.5);
	});

	it("sends the bearer token when one is configured", async () => {
		const impl = fakeKernel();
		await hydrate(new BeliefGraph(), "q", { ...options, token: "secret", fetchImpl: impl });
		const init = (impl as unknown as { mock: { calls: [unknown, RequestInit][] } }).mock.calls[0][1];
		expect((init.headers as Record<string, string>).authorization).toBe("Bearer secret");
	});

	it("tolerates a trailing slash on the API url", async () => {
		const impl = fakeKernel();
		await hydrate(new BeliefGraph(), "q", { ...options, apiUrl: "http://localhost:8080/", fetchImpl: impl });
		const url = String((impl as unknown as { mock: { calls: [string, unknown][] } }).mock.calls[0][0]);
		expect(url).toBe("http://localhost:8080/api/v1/search/semantic");
	});
});

describe("epigraphConfigFromEnv", () => {
	it("returns undefined without an API url", () => {
		expect(epigraphConfigFromEnv({})).toBeUndefined();
	});

	it("reads url and token", () => {
		expect(epigraphConfigFromEnv({ EPIGRAPH_API_URL: "http://x", EPIGRAPH_TOKEN: "t" })).toEqual({
			apiUrl: "http://x",
			token: "t",
		});
	});

	it("omits the token when unset", () => {
		expect(epigraphConfigFromEnv({ EPIGRAPH_API_URL: "http://x" })).toEqual({ apiUrl: "http://x" });
	});
});
