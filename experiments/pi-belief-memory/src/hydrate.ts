/**
 * Seed the session graph from EpiGraph long-term memory.
 *
 * This is the payoff of using the same representation on both sides. Recall
 * against the kernel returns claims that already carry beliefs and already sit
 * in a web of epistemic edges, so hydration is a graph-into-graph merge rather
 * than a text splice: the supports/contradicts structure arrives intact, and
 * every hydrated node keeps a pointer to its kernel row.
 *
 * That pointer is what keeps the block honest about its own lossiness. The
 * rendered one-liner is a summary of a claim that has a full record — evidence,
 * provenance chain, mass function, challenges — sitting behind it. An agent
 * that needs the real thing calls `get_claim` with the UUID instead of
 * treating the summary as the whole story.
 *
 * Fetches go over the HTTP API rather than MCP because an extension runs in
 * Pi's process, not the model's tool loop. Set EPIGRAPH_API_URL and
 * EPIGRAPH_TOKEN, or pass them explicitly.
 */

import { fromInterval } from "./belief.ts";
import { type BeliefGraph, type ClaimKind, CLAIM_KINDS, type JsonValue, type Relation, RELATIONS } from "./graph.ts";

export interface HydrateOptions {
	/** Kernel base URL, e.g. http://localhost:8080 */
	apiUrl: string;
	/** Bearer token for the API. */
	token?: string;
	/** Max seed claims from semantic search. */
	limit?: number;
	/** Minimum cosine similarity for a seed to be worth pulling. */
	minSimilarity?: number;
	/** Hard cap on total claims added, including neighbours. */
	maxClaims?: number;
	/** Turn index to attribute the hydrated rows to. */
	turn: number;
	signal?: AbortSignal;
	fetchImpl?: typeof fetch;
}

export interface HydrateResult {
	seeds: number;
	claimsAdded: number;
	edgesAdded: number;
	errors: string[];
}

interface EpistemicState {
	belief?: number | null;
	plausibility?: number | null;
	ignorance?: number | null;
	truth_value?: number;
}

interface SemanticSearchResult {
	claim_id: string;
	statement: string;
	similarity: number;
	epistemic?: EpistemicState;
	agent_id?: string;
	labels?: string[];
}

interface NeighborhoodEdge {
	id: string;
	source_id: string;
	target_id: string;
	source_type: string;
	target_type: string;
	relationship: string;
	properties?: unknown;
}

interface NeighborhoodResponse {
	center_id: string;
	edges: NeighborhoodEdge[];
	connected_entity_ids: string[];
	depth: number;
}

interface ClaimResponse {
	id: string;
	content: string;
	truth_value: number;
	agent_id?: string;
	labels?: string[];
}

const DEFAULTS = { limit: 12, minSimilarity: 0.35, maxClaims: 40 };

/**
 * Kernel relationship strings that mean the same thing our graph does.
 * Anything else becomes `relates_to` — the edge is still worth keeping as
 * structure even when we cannot interpret its verb.
 */
const RELATION_ALIASES: Record<string, Relation> = {
	supports: "supports",
	contradicts: "contradicts",
	refutes: "contradicts",
	supersedes: "supersedes",
	depends_on: "depends_on",
	derived_from: "depends_on",
	asserts: "supports",
};

function mapRelation(relationship: string): Relation {
	const normalized = relationship.toLowerCase();
	if (RELATION_ALIASES[normalized]) return RELATION_ALIASES[normalized];
	return (RELATIONS as readonly string[]).includes(normalized) ? (normalized as Relation) : "relates_to";
}

/**
 * Infer a claim kind from kernel labels.
 *
 * The kernel's label vocabulary is open, so this is a best-effort read of a
 * `kind:` prefix or a bare label that happens to match. Everything else lands
 * on "fact", which is the honest default for a claim we pulled out of
 * long-term memory without knowing why it was filed.
 */
function inferKind(labels: string[] | undefined): ClaimKind {
	if (!labels) return "fact";
	const kinds = new Set<string>(CLAIM_KINDS);
	for (const label of labels) {
		const bare = label.includes(":") ? label.slice(label.indexOf(":") + 1) : label;
		if (kinds.has(bare)) return bare as ClaimKind;
	}
	return "fact";
}

class ApiClient {
	constructor(
		private readonly base: string,
		private readonly token: string | undefined,
		private readonly signal: AbortSignal | undefined,
		private readonly doFetch: typeof fetch,
	) {}

	private headers(): Record<string, string> {
		const headers: Record<string, string> = { "content-type": "application/json" };
		if (this.token) headers.authorization = `Bearer ${this.token}`;
		return headers;
	}

	async post<T>(path: string, body: unknown): Promise<T> {
		const response = await this.doFetch(`${this.base}${path}`, {
			method: "POST",
			headers: this.headers(),
			body: JSON.stringify(body),
			signal: this.signal,
		});
		if (!response.ok) throw new Error(`POST ${path} → ${response.status}`);
		return (await response.json()) as T;
	}

	async get<T>(path: string): Promise<T> {
		const response = await this.doFetch(`${this.base}${path}`, {
			method: "GET",
			headers: this.headers(),
			signal: this.signal,
		});
		if (!response.ok) throw new Error(`GET ${path} → ${response.status}`);
		return (await response.json()) as T;
	}
}

/**
 * Pull the subgraph relevant to `query` into `graph`.
 *
 * Three round trips per seed at most: semantic search for the seeds, one
 * neighbourhood call each, and a claim fetch for neighbours we do not already
 * hold. Failures are collected rather than thrown — hydration is an
 * enhancement, and a kernel that is down should degrade to a session-only
 * graph rather than break compaction.
 */
export async function hydrate(graph: BeliefGraph, query: string, options: HydrateOptions): Promise<HydrateResult> {
	const limit = options.limit ?? DEFAULTS.limit;
	const minSimilarity = options.minSimilarity ?? DEFAULTS.minSimilarity;
	const maxClaims = options.maxClaims ?? DEFAULTS.maxClaims;
	const base = options.apiUrl.replace(/\/+$/, "");
	const api = new ApiClient(base, options.token, options.signal, options.fetchImpl ?? fetch);
	const result: HydrateResult = { seeds: 0, claimsAdded: 0, edgesAdded: 0, errors: [] };

	let search: { results?: SemanticSearchResult[] };
	try {
		search = await api.post<{ results?: SemanticSearchResult[] }>("/api/v1/search/semantic", {
			query,
			limit,
			min_similarity: minSimilarity,
		});
	} catch (error) {
		result.errors.push(`semantic search failed: ${message(error)}`);
		return result;
	}

	/** Kernel claim UUID → local claim id. */
	const byKernelId = new Map<string, string>();

	const addKernelClaim = (
		kernelId: string,
		content: string,
		labels: string[] | undefined,
		epistemic: EpistemicState | undefined,
		agentId: string | undefined,
	): string | undefined => {
		if (byKernelId.has(kernelId)) return byKernelId.get(kernelId);
		if (result.claimsAdded >= maxClaims) return undefined;
		const claim = graph.upsertClaim({
			kind: inferKind(labels),
			content,
			turn: options.turn,
			origin: "epigraph",
			belief: fromInterval(epistemic?.belief, epistemic?.plausibility),
			properties: labels && labels.length > 0 ? { labels: labels as JsonValue } : {},
			provenance: { id: kernelId, source: base, ...(agentId ? { agentId } : {}) },
		});
		byKernelId.set(kernelId, claim.id);
		result.claimsAdded += 1;
		return claim.id;
	};

	for (const seed of search.results ?? []) {
		if (!seed?.claim_id || typeof seed.statement !== "string") continue;
		addKernelClaim(seed.claim_id, seed.statement, seed.labels, seed.epistemic, seed.agent_id);
		result.seeds += 1;
	}

	// Second pass: the edges. Done after every seed is present so an edge
	// between two seeds does not trigger a redundant claim fetch.
	for (const kernelId of [...byKernelId.keys()]) {
		if (result.claimsAdded >= maxClaims) break;
		let neighborhood: NeighborhoodResponse;
		try {
			neighborhood = await api.get<NeighborhoodResponse>(`/api/v1/claims/${kernelId}/neighborhood?depth=1`);
		} catch (error) {
			result.errors.push(`neighborhood ${kernelId}: ${message(error)}`);
			continue;
		}

		for (const edge of neighborhood.edges ?? []) {
			if (edge.source_type !== "claim" || edge.target_type !== "claim") continue;

			for (const endpoint of [edge.source_id, edge.target_id]) {
				if (byKernelId.has(endpoint) || result.claimsAdded >= maxClaims) continue;
				try {
					const claim = await api.get<ClaimResponse>(`/api/v1/claims/${endpoint}`);
					// A neighbour arrives without an epistemic interval, so it
					// starts vacuous rather than borrowing the seed's belief.
					addKernelClaim(endpoint, claim.content, claim.labels, undefined, claim.agent_id);
				} catch (error) {
					result.errors.push(`claim ${endpoint}: ${message(error)}`);
				}
			}

			const source = byKernelId.get(edge.source_id);
			const target = byKernelId.get(edge.target_id);
			if (!source || !target) continue;

			const added = graph.addEdge({
				source,
				target,
				relation: mapRelation(edge.relationship),
				turn: options.turn,
				origin: "epigraph",
				// The kernel already folded this edge into the beliefs it
				// reported; applying it again would double-count.
				applyEvidence: false,
				provenance: { id: edge.id, source: base },
				properties: { relationship: edge.relationship },
			});
			if (added) result.edgesAdded += 1;
		}
	}

	return result;
}

function message(error: unknown): string {
	return error instanceof Error ? error.message : String(error);
}

/** Read kernel connection settings from the environment. */
export function epigraphConfigFromEnv(env: Record<string, string | undefined>): { apiUrl: string; token?: string } | undefined {
	const apiUrl = env.EPIGRAPH_API_URL;
	if (!apiUrl) return undefined;
	return { apiUrl, ...(env.EPIGRAPH_TOKEN ? { token: env.EPIGRAPH_TOKEN } : {}) };
}
