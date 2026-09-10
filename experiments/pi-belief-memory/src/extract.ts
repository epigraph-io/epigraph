/**
 * Turn a span of conversation into graph deltas.
 *
 * This replaces Pi's summarization call rather than adding to it, so the cost
 * is the same call it was already going to make. The ask is different, though:
 * instead of "rewrite this document, preserving the old one", it is "emit the
 * claims and edges this span establishes". Deltas merge; documents drift.
 *
 * Extraction is the one step that can fail in ways we cannot repair — a model
 * that returns prose instead of JSON leaves us with nothing. Every failure
 * path here returns `undefined`, which the caller turns into "fall back to
 * Pi's default compaction". A degraded prose summary beats a lost turn.
 */

import { CLAIM_KINDS, type ClaimKind, type JsonValue, RELATIONS, type Relation } from "./graph.ts";

export interface ExtractedClaim {
	kind: ClaimKind;
	content: string;
	strength: number;
	properties: Record<string, JsonValue>;
}

export interface ExtractedEdge {
	/** Index into the claims array. */
	source: number;
	target: number;
	relation: Relation;
	strength: number;
}

export interface Extraction {
	claims: ExtractedClaim[];
	edges: ExtractedEdge[];
	/** Contents of claims this span superseded, matched against the live graph. */
	superseded: { old: string; by: number }[];
	files: { read: string[]; edited: string[] };
}

export const EXTRACTION_SYSTEM_PROMPT = `You are a context extraction assistant. You read a span of conversation between a user and a coding agent, and emit a structured belief graph describing what that span established.

Do NOT continue the conversation. Do NOT answer questions in it. Output ONLY a single JSON object in a \`\`\`json fenced block.`;

export function buildExtractionPrompt(conversationText: string, priorClaims: string[], customInstructions?: string): string {
	const prior =
		priorClaims.length > 0
			? `\n<already-known>\n${priorClaims.map((c) => `- ${c}`).join("\n")}\n</already-known>\n\nDo not re-emit claims from <already-known> unless this span adds evidence for or against them. If it does, emit the claim with the SAME wording so it merges, and attach the new evidence as an edge.\n`
			: "";

	const focus = customInstructions ? `\n\nAdditional focus: ${customInstructions}` : "";

	return `<conversation>
${conversationText}
</conversation>
${prior}
Extract the belief graph this span establishes. Emit a single JSON object:

\`\`\`json
{
  "claims": [
    {
      "kind": "goal" | "constraint" | "fact" | "decision" | "hypothesis" | "observation" | "artifact",
      "content": "the assertion, one sentence",
      "strength": 0.0-1.0,
      "properties": { "path": "src/foo.ts", "error": "exact error text" }
    }
  ],
  "edges": [
    { "source": 0, "target": 1, "relation": "supports" | "contradicts" | "supersedes" | "depends_on" | "read" | "edited" | "ran" | "observed" | "decided" | "relates_to", "strength": 0.0-1.0 }
  ],
  "superseded": [ { "old": "exact content of a previously known claim that is no longer true", "by": 0 } ],
  "files": { "read": ["path"], "edited": ["path"] }
}
\`\`\`

Rules:
- "content" is the ASSERTION in prose. Exact file paths, error strings, commit SHAs, and command output go in "properties", VERBATIM — never paraphrase them into content.
- "strength" is how strongly this span establishes the claim. Direct observation (a command's actual output) is 0.9+. An inference is 0.5-0.7. A guess is 0.2-0.4.
- Emit an "observation" claim for what was actually seen (test output, error text), and a separate "hypothesis" claim for what it was taken to mean. Link them with supports/contradicts. This pairing is the most valuable thing you can extract.
- When the span shows an approach was TRIED AND FAILED, emit the approach as a "hypothesis" claim and a "contradicts" edge from the observation that killed it. Do not omit failed approaches — they are what stops the agent retrying them.
- "source" and "target" are integer indices into YOUR claims array.
- Prefer few sharp claims over many vague ones. Do not emit claims about the conversation itself ("the user asked X"); emit what was established.${focus}

Output only the JSON block.`;
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
	return typeof value === "object" && value !== null && !Array.isArray(value)
		? (value as Record<string, unknown>)
		: undefined;
}

function asStrength(value: unknown, fallback: number): number {
	const n = typeof value === "number" ? value : Number.parseFloat(String(value));
	if (!Number.isFinite(n)) return fallback;
	return n < 0 ? 0 : n > 1 ? 1 : n;
}

function asStringArray(value: unknown): string[] {
	if (!Array.isArray(value)) return [];
	return value.filter((item): item is string => typeof item === "string" && item.trim().length > 0);
}

/** Keep only JSON-safe scalars and shallow arrays; drop anything exotic. */
function sanitizeProperties(value: unknown): Record<string, JsonValue> {
	const record = asRecord(value);
	if (!record) return {};
	const out: Record<string, JsonValue> = {};
	for (const [key, raw] of Object.entries(record)) {
		if (typeof raw === "string" || typeof raw === "number" || typeof raw === "boolean") {
			out[key] = raw;
		} else if (Array.isArray(raw)) {
			const items = raw.filter(
				(item): item is string | number | boolean =>
					typeof item === "string" || typeof item === "number" || typeof item === "boolean",
			);
			if (items.length > 0) out[key] = items;
		}
	}
	return out;
}

/**
 * Pull the JSON object out of a model response.
 *
 * Models wrap JSON in fences, prose, or both, and sometimes emit a bare object.
 * Try the fence first, then the widest brace span, and give up rather than
 * guessing further.
 */
export function parseExtraction(text: string): Extraction | undefined {
	const fenced = /```(?:json)?\s*\n([\s\S]*?)\n?```/.exec(text);
	const candidates = [fenced?.[1], text];

	for (const candidate of candidates) {
		if (!candidate) continue;
		const start = candidate.indexOf("{");
		const end = candidate.lastIndexOf("}");
		if (start === -1 || end <= start) continue;
		let parsed: unknown;
		try {
			parsed = JSON.parse(candidate.slice(start, end + 1));
		} catch {
			continue;
		}
		const validated = validate(parsed);
		if (validated) return validated;
	}
	return undefined;
}

function validate(parsed: unknown): Extraction | undefined {
	const root = asRecord(parsed);
	if (!root) return undefined;

	const claimKinds = new Set<string>(CLAIM_KINDS);
	const relations = new Set<string>(RELATIONS);

	const rawClaims = Array.isArray(root.claims) ? root.claims : [];
	const claims: ExtractedClaim[] = [];
	// Index remap: dropping a malformed claim must not silently re-point the
	// edges that referenced the ones after it.
	const indexMap = new Map<number, number>();

	rawClaims.forEach((raw, originalIndex) => {
		const record = asRecord(raw);
		if (!record) return;
		const content = typeof record.content === "string" ? record.content.trim() : "";
		if (content.length === 0) return;
		const kind = typeof record.kind === "string" && claimKinds.has(record.kind) ? (record.kind as ClaimKind) : "fact";
		indexMap.set(originalIndex, claims.length);
		claims.push({
			kind,
			content,
			strength: asStrength(record.strength, 0.6),
			properties: sanitizeProperties(record.properties),
		});
	});

	if (claims.length === 0) return undefined;

	const rawEdges = Array.isArray(root.edges) ? root.edges : [];
	const edges: ExtractedEdge[] = [];
	for (const raw of rawEdges) {
		const record = asRecord(raw);
		if (!record) continue;
		const source = indexMap.get(Number(record.source));
		const target = indexMap.get(Number(record.target));
		if (source === undefined || target === undefined || source === target) continue;
		const relation =
			typeof record.relation === "string" && relations.has(record.relation)
				? (record.relation as Relation)
				: "relates_to";
		edges.push({ source, target, relation, strength: asStrength(record.strength, 0.6) });
	}

	const rawSuperseded = Array.isArray(root.superseded) ? root.superseded : [];
	const superseded: { old: string; by: number }[] = [];
	for (const raw of rawSuperseded) {
		const record = asRecord(raw);
		if (!record) continue;
		const old = typeof record.old === "string" ? record.old.trim() : "";
		const by = indexMap.get(Number(record.by));
		if (old.length === 0 || by === undefined) continue;
		superseded.push({ old, by });
	}

	const files = asRecord(root.files) ?? {};
	return {
		claims,
		edges,
		superseded,
		files: { read: asStringArray(files.read), edited: asStringArray(files.edited) },
	};
}
