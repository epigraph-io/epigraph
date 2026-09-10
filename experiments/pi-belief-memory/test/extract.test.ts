import { describe, expect, it } from "vitest";
import { buildExtractionPrompt, parseExtraction } from "../src/extract.ts";

const WELL_FORMED = `Here is the graph:

\`\`\`json
{
  "claims": [
    { "kind": "observation", "content": "cargo test failed", "strength": 0.95, "properties": { "error": "error[E0308]: mismatched types" } },
    { "kind": "hypothesis", "content": "the sqlx cache is stale", "strength": 0.6, "properties": {} }
  ],
  "edges": [ { "source": 0, "target": 1, "relation": "supports", "strength": 0.7 } ],
  "superseded": [ { "old": "the build is green", "by": 0 } ],
  "files": { "read": ["src/lib.rs"], "edited": [] }
}
\`\`\`
`;

describe("parseExtraction", () => {
	it("parses a fenced JSON block", () => {
		const result = parseExtraction(WELL_FORMED);
		expect(result?.claims).toHaveLength(2);
		expect(result?.claims[0].kind).toBe("observation");
		expect(result?.claims[0].properties.error).toBe("error[E0308]: mismatched types");
		expect(result?.edges).toEqual([{ source: 0, target: 1, relation: "supports", strength: 0.7 }]);
		expect(result?.superseded).toEqual([{ old: "the build is green", by: 0 }]);
		expect(result?.files.read).toEqual(["src/lib.rs"]);
	});

	it("parses a bare object with no fence", () => {
		const result = parseExtraction('{"claims":[{"kind":"fact","content":"x","strength":0.5}]}');
		expect(result?.claims).toHaveLength(1);
	});

	it("parses an object surrounded by prose", () => {
		const result = parseExtraction('Sure! {"claims":[{"kind":"fact","content":"x"}]} Hope that helps.');
		expect(result?.claims[0].content).toBe("x");
	});

	it("returns undefined for prose with no JSON", () => {
		expect(parseExtraction("I think the main goal was to fix the build.")).toBeUndefined();
	});

	it("returns undefined for malformed JSON", () => {
		expect(parseExtraction('```json\n{"claims": [oops]}\n```')).toBeUndefined();
	});

	it("returns undefined when no claim survives validation", () => {
		expect(parseExtraction('{"claims":[{"kind":"fact","content":"   "}]}')).toBeUndefined();
	});

	it("falls back to `fact` for an unknown claim kind", () => {
		const result = parseExtraction('{"claims":[{"kind":"nonsense","content":"x"}]}');
		expect(result?.claims[0].kind).toBe("fact");
	});

	it("falls back to `relates_to` for an unknown relation", () => {
		const result = parseExtraction('{"claims":[{"kind":"fact","content":"a"},{"kind":"fact","content":"b"}],"edges":[{"source":0,"target":1,"relation":"vibes"}]}');
		expect(result?.edges[0].relation).toBe("relates_to");
	});

	it("remaps edge indices when a malformed claim is dropped", () => {
		// Claim 1 is invalid and dropped. The edge referencing claim 2 must
		// follow it to its new index, not silently re-point at another claim.
		const result = parseExtraction(
			'{"claims":[{"kind":"fact","content":"first"},{"kind":"fact","content":""},{"kind":"fact","content":"third"}],"edges":[{"source":0,"target":2,"relation":"supports"}]}',
		);
		expect(result?.claims.map((c) => c.content)).toEqual(["first", "third"]);
		expect(result?.edges).toEqual([{ source: 0, target: 1, relation: "supports", strength: 0.6 }]);
	});

	it("drops edges pointing at claims that did not survive", () => {
		const result = parseExtraction(
			'{"claims":[{"kind":"fact","content":"first"},{"kind":"fact","content":""}],"edges":[{"source":0,"target":1,"relation":"supports"}]}',
		);
		expect(result?.edges).toEqual([]);
	});

	it("drops self-referential edges", () => {
		const result = parseExtraction('{"claims":[{"kind":"fact","content":"a"}],"edges":[{"source":0,"target":0,"relation":"supports"}]}');
		expect(result?.edges).toEqual([]);
	});

	it("clamps out-of-range strengths", () => {
		const result = parseExtraction('{"claims":[{"kind":"fact","content":"a","strength":7},{"kind":"fact","content":"b","strength":-3}]}');
		expect(result?.claims[0].strength).toBe(1);
		expect(result?.claims[1].strength).toBe(0);
	});

	it("keeps only JSON-safe property values", () => {
		const result = parseExtraction(
			'{"claims":[{"kind":"fact","content":"a","properties":{"path":"x.ts","line":3,"ok":true,"tags":["a","b"],"nested":{"deep":1}}}]}',
		);
		expect(result?.claims[0].properties).toEqual({ path: "x.ts", line: 3, ok: true, tags: ["a", "b"] });
	});

	it("tolerates missing optional sections", () => {
		const result = parseExtraction('{"claims":[{"kind":"fact","content":"a"}]}');
		expect(result?.edges).toEqual([]);
		expect(result?.superseded).toEqual([]);
		expect(result?.files).toEqual({ read: [], edited: [] });
	});
});

describe("buildExtractionPrompt", () => {
	it("embeds the conversation and omits the known block when there is none", () => {
		const prompt = buildExtractionPrompt("USER: hi", []);
		expect(prompt).toContain("<conversation>\nUSER: hi\n</conversation>");
		expect(prompt).not.toContain("<already-known>");
	});

	it("lists prior claims so the model reuses their wording", () => {
		const prompt = buildExtractionPrompt("USER: hi", ["the build is green"]);
		expect(prompt).toContain("<already-known>");
		expect(prompt).toContain("- the build is green");
		expect(prompt).toContain("SAME wording");
	});

	it("appends custom instructions", () => {
		expect(buildExtractionPrompt("x", [], "focus on the migration")).toContain("Additional focus: focus on the migration");
	});
});
