/**
 * Render a belief graph into the text block that replaces older context.
 *
 * The output is what the model actually reads, so it is optimized for reading
 * rather than for round-tripping — the authoritative graph is the JSON stored
 * alongside it. Two properties matter more than compactness:
 *
 *  - Refuted claims are rendered, loudly. A prose summary drops the approach
 *    that failed, and the agent proposes it again two compactions later. The
 *    "do not retry" section gets a reserved share of the budget so it survives
 *    even when the graph is much larger than the budget.
 *  - Hydrated claims render their kernel UUID, so an agent that needs the full
 *    record can fetch it instead of working from the one-line summary.
 */

import { ignorance as massIgnorance } from "./belief.ts";
import { type BeliefGraph, betp, type Claim, type Edge } from "./graph.ts";

export interface RenderOptions {
	/** Approximate token budget for the whole block. */
	budgetTokens: number;
	/** Fraction of the budget reserved for refuted claims. */
	refutedReserve?: number;
	/** Turn range the graph covers, for the block header. */
	turnRange?: { from: number; to: number };
	/** Kernel base URL to name in the expansion hint. */
	epigraphSource?: string;
}

const DEFAULTS = { refutedReserve: 0.15 };

/** Pi's own heuristic: ~4 characters per token. */
export function estimateTokens(text: string): number {
	return Math.ceil(text.length / 4);
}

/** BetP below this reads as refuted even without a mass imbalance. */
const REFUTED_MAX = 0.25;
/** Refute mass at or above this is a real refutation rather than a doubt. */
const REFUTED_MASS_MIN = 0.3;
/** BetP at or above this reads as established. */
const ESTABLISHED_MIN = 0.6;
/** Ignorance above this means "we never actually checked". */
const UNKNOWN_IGNORANCE = 0.7;

type Section = "goals" | "constraints" | "established" | "open" | "refuted";

/**
 * Which section a claim belongs in.
 *
 * The refuted test reads the *mass balance*, not BetP. Dempster's rule
 * normalizes conflict away by dividing through by (1 - K), which drags two
 * strongly disagreeing sources back toward the middle: a hypothesis held at
 * 0.7 and then killed by a direct observation lands near BetP 0.4, not near 0.
 * Its refute mass still outweighs its support mass roughly two to one, and
 * that imbalance — not the point estimate — is what "we tried this and it
 * failed" actually looks like in the mass function.
 *
 * Ranking by BetP alone here would file every refuted approach under "open"
 * and lose the one signal this whole block exists to carry.
 */
function sectionFor(claim: Claim): Section {
	if (claim.kind === "goal") return "goals";
	if (claim.kind === "constraint") return "constraints";
	const { support, refute } = claim.belief;
	if (refute > support && refute >= REFUTED_MASS_MIN) return "refuted";
	const score = betp(claim.belief);
	if (score < REFUTED_MAX) return "refuted";
	if (score >= ESTABLISHED_MIN && massIgnorance(claim.belief) < UNKNOWN_IGNORANCE) return "established";
	return "open";
}

const SECTION_TITLES: Record<Section, string> = {
	goals: "Goals",
	constraints: "Constraints",
	established: "Established",
	open: "Open / contested",
	refuted: "Refuted — do not retry",
};

/**
 * Ranking score within a section.
 *
 * Decisiveness dominates: a claim at BetP 0.95 or 0.05 has told us something,
 * a claim at 0.5 has not. Recency breaks ties, and connectedness rescues
 * load-bearing claims that have not been mentioned lately.
 */
function score(claim: Claim, graph: BeliefGraph, degree: Map<string, number>): number {
	const decisiveness = Math.abs(betp(claim.belief) - 0.5) * 2;
	const recency = graph.turn > 0 ? claim.lastSeenTurn / graph.turn : 1;
	const connectedness = Math.min(1, (degree.get(claim.id) ?? 0) / 4);
	return decisiveness * 2 + recency + connectedness;
}

function formatBelief(claim: Claim, section: Section): string {
	const ign = massIgnorance(claim.belief);
	// Flag claims whose score is an artifact of never having looked.
	const marker = ign > UNKNOWN_IGNORANCE ? " ?" : claim.belief.conflict > 0.3 ? " !" : "";
	// In the refuted section, report the refuting mass rather than BetP.
	// Printing "[0.40]" under "do not retry" invites exactly the misreading the
	// section exists to prevent.
	if (section === "refuted") return `[refuted ${claim.belief.refute.toFixed(2)}${marker}]`;
	return `[${betp(claim.belief).toFixed(2)}${marker}]`;
}

const EDGE_GLYPH: Record<string, string> = {
	supports: "⊢",
	contradicts: "⊣",
	supersedes: "↦",
	depends_on: "→",
	read: "·",
	edited: "·",
	ran: "·",
	observed: "·",
	decided: "·",
	relates_to: "·",
};

/** The most informative edge attached to a claim, if any. */
function evidenceLine(claim: Claim, graph: BeliefGraph): string | undefined {
	const edges = graph
		.edgesFor(claim.id)
		.filter((edge) => edge.target === claim.id && (edge.relation === "supports" || edge.relation === "contradicts"));
	if (edges.length === 0) return undefined;
	const edge: Edge = edges[0];
	const source = graph.getClaim(edge.source);
	if (!source) return undefined;
	const glyph = EDGE_GLYPH[edge.relation] ?? "·";
	return `${glyph} ${truncate(source.content, 96)}`;
}

function truncate(text: string, max: number): string {
	const collapsed = text.replace(/\s+/g, " ").trim();
	return collapsed.length <= max ? collapsed : `${collapsed.slice(0, max - 1)}…`;
}

/** Verbatim properties worth carrying into the render, shortest first. */
function propertyLine(claim: Claim): string | undefined {
	const keys = Object.keys(claim.properties).filter((key) => {
		const value = claim.properties[key];
		return typeof value === "string" || typeof value === "number";
	});
	if (keys.length === 0) return undefined;
	const parts = keys.slice(0, 3).map((key) => `${key}=${truncate(String(claim.properties[key]), 60)}`);
	return parts.join(" ");
}

function renderClaim(claim: Claim, graph: BeliefGraph, section: Section): string {
	const lines = [`- ${formatBelief(claim, section)} ${truncate(claim.content, 160)}`];
	const props = propertyLine(claim);
	if (props) lines.push(`      ${props}`);
	const evidence = evidenceLine(claim, graph);
	if (evidence) lines.push(`      ${evidence}`);
	if (claim.provenance) lines.push(`      ⟨epigraph:${claim.provenance.id}⟩`);
	return lines.join("\n");
}

interface Budgeted {
	section: Section;
	text: string;
	tokens: number;
}

function buildEntries(claims: Claim[], graph: BeliefGraph): Budgeted[] {
	return claims.map((claim) => {
		const section = sectionFor(claim);
		const text = renderClaim(claim, graph, section);
		return { section, text, tokens: estimateTokens(text) };
	});
}

export interface RenderResult {
	text: string;
	tokens: number;
	/** Claims that fit in the budget. */
	rendered: number;
	/** Claims dropped for budget. */
	dropped: number;
}

/**
 * Render the graph to a budgeted block.
 *
 * Fill order is: goals and constraints first (they are small and frame
 * everything else), then the refuted reserve, then established and open
 * claims by score until the budget runs out.
 */
export function render(graph: BeliefGraph, options: RenderOptions): RenderResult {
	const { budgetTokens } = options;
	const refutedReserve = options.refutedReserve ?? DEFAULTS.refutedReserve;

	const degree = new Map<string, number>();
	for (const edge of graph.allEdges()) {
		degree.set(edge.source, (degree.get(edge.source) ?? 0) + 1);
		degree.set(edge.target, (degree.get(edge.target) ?? 0) + 1);
	}

	const current = graph.currentClaims().sort((a, b) => score(b, graph, degree) - score(a, graph, degree));
	const entries = buildEntries(current, graph);

	const bySection = new Map<Section, Budgeted[]>();
	for (const entry of entries) {
		const list = bySection.get(entry.section) ?? [];
		list.push(entry);
		bySection.set(entry.section, list);
	}

	const chosen = new Map<Section, string[]>();
	let used = 0;
	let rendered = 0;

	const take = (section: Section, limit: number): void => {
		const list = bySection.get(section) ?? [];
		const out = chosen.get(section) ?? [];
		for (const entry of list) {
			if (used + entry.tokens > limit) continue;
			out.push(entry.text);
			used += entry.tokens;
			rendered += 1;
		}
		if (out.length > 0) chosen.set(section, out);
	};

	// Goals and constraints are the frame; they get the whole budget to draw on
	// because there are never many of them.
	take("goals", budgetTokens);
	take("constraints", budgetTokens);

	// Reserve the refuted share before the bulk sections can spend it.
	const bulkLimit = Math.max(0, budgetTokens - Math.floor(budgetTokens * refutedReserve));
	take("established", bulkLimit);
	take("open", bulkLimit);
	take("refuted", budgetTokens);

	const totalCandidates = entries.length;
	const files = graph.files();

	const header = renderHeader(graph, options, rendered, totalCandidates, used, budgetTokens);
	const body: string[] = [header];

	for (const section of ["goals", "constraints", "established", "open", "refuted"] as Section[]) {
		const lines = chosen.get(section);
		if (!lines || lines.length === 0) continue;
		body.push("", `## ${SECTION_TITLES[section]}`, ...lines);
	}

	if (files.read.length > 0 || files.edited.length > 0) {
		body.push("", "## Files");
		if (files.read.length > 0) body.push(`read: ${files.read.join(", ")}`);
		if (files.edited.length > 0) body.push(`edited: ${files.edited.join(", ")}`);
	}

	body.push("</belief-graph>");

	const text = body.join("\n");
	return { text, tokens: estimateTokens(text), rendered, dropped: totalCandidates - rendered };
}

function renderHeader(
	graph: BeliefGraph,
	options: RenderOptions,
	rendered: number,
	total: number,
	used: number,
	budget: number,
): string {
	const range = options.turnRange ? ` turns="${options.turnRange.from}-${options.turnRange.to}"` : "";
	const lines = [
		`<belief-graph${range} claims="${rendered}/${total}" budget="${used}/${budget}">`,
		"This replaces the older conversation. Scores are pignistic probability (BetP):",
		"1.00 = established, 0.00 = doubted. `?` marks high ignorance (never actually",
		"checked, not evidence of a coin flip); `!` marks accumulated conflict.",
		"Refuted entries show refuting mass instead — treat them as settled dead ends",
		"and do not re-propose them without new evidence.",
	];
	const hydrated = graph.currentClaims().some((claim) => claim.provenance);
	if (hydrated) {
		const source = options.epigraphSource ? ` (${options.epigraphSource})` : "";
		lines.push(
			`Claims tagged ⟨epigraph:ID⟩ come from long-term memory${source}; fetch the full`,
			"record with the EpiGraph `get_claim` tool if the summary line is not enough.",
		);
	}
	return lines.join("\n");
}
