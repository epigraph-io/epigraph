/**
 * pi-belief-memory — belief-graph short-term memory for the Pi coding agent.
 *
 * Pi's default compaction replaces older context with a prose checkpoint. This
 * extension replaces it with a rendered belief graph instead, while leaving the
 * verbatim recent tail exactly as Pi manages it — `firstKeptEntryId` passes
 * through untouched, so the "keep the last few turns" half needs no change.
 *
 * What that buys, concretely: approaches that were tried and failed stay in
 * context at low belief instead of vanishing, superseded facts drop out instead
 * of sitting next to their replacements, and each compaction merges deltas into
 * a graph rather than asking a model to rewrite a document it half remembers.
 *
 * Store is session-local: the graph lives in the compaction entry's `details`,
 * so it survives /resume with no external dependency. Set EPIGRAPH_API_URL to
 * additionally seed it from long-term memory (see hydrate.ts).
 *
 * Install:  cp -r . ~/.pi/agent/extensions/belief-memory
 * Or test:  pi -e ./src/index.ts
 */

import { type Usage, uuidv7 } from "@earendil-works/pi-ai";
import { convertToLlm, type ExtensionAPI, serializeConversation } from "@earendil-works/pi-coding-agent";
import { BeliefGraph, betp, GRAPH_KIND, type SerializedGraph } from "./graph.ts";
import { buildExtractionPrompt, EXTRACTION_SYSTEM_PROMPT, parseExtraction } from "./extract.ts";
import { epigraphConfigFromEnv, hydrate } from "./hydrate.ts";
import { render } from "./render.ts";

/** Claim contents shown to the extractor as "already known", to steer merges. */
const PRIOR_CLAIM_HINT_LIMIT = 40;
/** Upper bound on graph size before low-value claims are evicted. */
const MAX_CLAIMS = 160;
/** Fallback render budget when nothing better can be derived. */
const DEFAULT_BUDGET_TOKENS = 6000;

interface SessionEntryLike {
	type: string;
	details?: unknown;
}

/** Recover the graph from the most recent compaction entry we wrote. */
function restoreGraph(entries: readonly SessionEntryLike[]): BeliefGraph {
	for (let i = entries.length - 1; i >= 0; i--) {
		const entry = entries[i];
		if (entry?.type !== "compaction") continue;
		const details = entry.details as Partial<SerializedGraph> | undefined;
		if (details?.kind !== GRAPH_KIND) continue;
		try {
			return BeliefGraph.from(details as SerializedGraph);
		} catch {
			// A malformed graph is not worth failing compaction over; start fresh.
			return new BeliefGraph();
		}
	}
	return new BeliefGraph();
}

function budgetFor(keepRecentTokens: number | undefined, env: Record<string, string | undefined>): number {
	const configured = Number.parseInt(env.PI_BELIEF_BUDGET ?? "", 10);
	if (Number.isFinite(configured) && configured > 0) return configured;
	if (keepRecentTokens && keepRecentTokens > 0) {
		return Math.max(1500, Math.min(DEFAULT_BUDGET_TOKENS, Math.floor(keepRecentTokens * 0.3)));
	}
	return DEFAULT_BUDGET_TOKENS;
}

export default function beliefMemory(pi: ExtensionAPI) {
	const env = process.env;
	let turn = 0;
	/** Cached between commands so /beliefs does not re-parse on every call. */
	let lastGraph: BeliefGraph | undefined;

	pi.on("turn_start", async () => {
		turn += 1;
	});

	pi.on("session_before_compact", async (event, ctx) => {
		const { preparation, branchEntries, customInstructions, signal } = event;
		const { messagesToSummarize, turnPrefixMessages, tokensBefore, firstKeptEntryId, settings } = preparation;

		const model = ctx.model;
		if (!model) return; // No model to extract with — let Pi's default run.

		const graph = restoreGraph(branchEntries as unknown as SessionEntryLike[]);
		graph.turn = Math.max(graph.turn, turn);

		const span = [...messagesToSummarize, ...turnPrefixMessages];
		if (span.length === 0) return;

		const conversationText = serializeConversation(convertToLlm(span));
		const priorClaims = graph
			.currentClaims()
			.sort((a, b) => b.lastSeenTurn - a.lastSeenTurn)
			.slice(0, PRIOR_CLAIM_HINT_LIMIT)
			.map((claim) => claim.content);

		const prompt = buildExtractionPrompt(conversationText, priorClaims, customInstructions);
		const maxTokens = Math.max(2048, Math.floor(0.8 * (settings?.reserveTokens ?? 16384)));

		let extraction: ReturnType<typeof parseExtraction>;
		let usage: Usage | undefined;
		try {
			const response = await ctx.modelRegistry.complete(
				model,
				{
					systemPrompt: EXTRACTION_SYSTEM_PROMPT,
					messages: [{ role: "user", content: [{ type: "text", text: prompt }], timestamp: Date.now() }],
				},
				{ maxTokens, signal, cacheRetention: "none", sessionId: uuidv7() },
			);
			usage = response.usage;
			const text = response.content
				.filter((block): block is { type: "text"; text: string } => block.type === "text")
				.map((block) => block.text)
				.join("\n");
			extraction = parseExtraction(text);
		} catch (error) {
			if (!signal.aborted) {
				ctx.ui.notify(`belief-memory: extraction failed (${message(error)}); using default compaction`, "warning");
			}
			return;
		}

		if (!extraction) {
			ctx.ui.notify("belief-memory: could not parse extraction; using default compaction", "warning");
			return;
		}

		// Merge deltas. Claims first, so edges have endpoints to attach to.
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
			if (!source || !target) continue;
			graph.addEdge({ source, target, relation: edge.relation, strength: edge.strength, turn });
		}

		for (const { old, by } of extraction.superseded) {
			const retired = graph.findByContent(old);
			const replacement = ids[by];
			if (retired && replacement) graph.supersede(retired.id, replacement);
		}

		for (const path of extraction.files.read) graph.recordFile(path, "read");
		for (const path of extraction.files.edited) graph.recordFile(path, "edited");

		// Optional: pull the relevant slice of long-term memory in alongside it.
		// Seeded from the live goals, which is the best available description of
		// what this session is about.
		const epigraph = epigraphConfigFromEnv(env);
		if (epigraph && env.PI_BELIEF_HYDRATE !== "0") {
			const goals = graph
				.currentClaims()
				.filter((claim) => claim.kind === "goal")
				.map((claim) => claim.content)
				.join("; ");
			if (goals) {
				const hydrated = await hydrate(graph, goals, { ...epigraph, turn, signal });
				if (hydrated.claimsAdded > 0) {
					ctx.ui.notify(
						`belief-memory: hydrated ${hydrated.claimsAdded} claims / ${hydrated.edgesAdded} edges from EpiGraph`,
						"info",
					);
				}
				for (const error of hydrated.errors.slice(0, 2)) {
					ctx.ui.notify(`belief-memory: ${error}`, "warning");
				}
			}
		}

		graph.prune(MAX_CLAIMS);
		lastGraph = graph;

		const rendered = render(graph, {
			budgetTokens: budgetFor(settings?.keepRecentTokens, env),
			turnRange: { from: 1, to: turn },
			epigraphSource: epigraph?.apiUrl,
		});

		ctx.ui.notify(
			`belief-memory: ${graph.size.claims} claims, ${graph.size.edges} edges → ${rendered.tokens} tokens` +
				(rendered.dropped > 0 ? ` (${rendered.dropped} dropped for budget)` : ""),
			"info",
		);

		return {
			compaction: {
				summary: rendered.text,
				firstKeptEntryId,
				tokensBefore,
				...(usage ? { usage } : {}),
				details: graph.toJSON(),
			},
		};
	});

	pi.registerCommand("beliefs", {
		description: "Show the current belief graph",
		handler: async (_args, ctx) => {
			const graph = lastGraph ?? restoreGraph(ctx.sessionManager.getEntries() as unknown as SessionEntryLike[]);
			if (graph.size.claims === 0) {
				ctx.ui.notify("belief-memory: graph is empty (nothing compacted yet)", "info");
				return;
			}
			const rendered = render(graph, { budgetTokens: budgetFor(undefined, env) });
			ctx.ui.notify(rendered.text, "info");
		},
	});

	pi.registerCommand("beliefs-hydrate", {
		description: "Seed the belief graph from EpiGraph long-term memory: /beliefs-hydrate <query>",
		handler: async (args, ctx) => {
			const query = args.trim();
			if (!query) {
				ctx.ui.notify("belief-memory: usage /beliefs-hydrate <query>", "warning");
				return;
			}
			const epigraph = epigraphConfigFromEnv(env);
			if (!epigraph) {
				ctx.ui.notify("belief-memory: set EPIGRAPH_API_URL to hydrate from long-term memory", "warning");
				return;
			}
			const graph = lastGraph ?? restoreGraph(ctx.sessionManager.getEntries() as unknown as SessionEntryLike[]);
			const result = await hydrate(graph, query, { ...epigraph, turn });
			lastGraph = graph;
			ctx.ui.notify(
				`belief-memory: +${result.claimsAdded} claims, +${result.edgesAdded} edges from ${result.seeds} seeds` +
					(result.errors.length > 0 ? ` (${result.errors.length} errors)` : ""),
				result.errors.length > 0 ? "warning" : "info",
			);
		},
	});
}

function message(error: unknown): string {
	return error instanceof Error ? error.message : String(error);
}

export { BeliefGraph, betp, render, hydrate };
