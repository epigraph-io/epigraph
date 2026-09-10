import { describe, expect, it } from "vitest";
import { belief, betp, combine, discount, fromInterval, ignorance, interval, refuting, supporting, VACUOUS } from "../src/belief.ts";

describe("belief", () => {
	it("reports total ignorance as BetP 0.5 with a full-width interval", () => {
		// The distinction a scalar confidence cannot make: this is "we never
		// checked", not "we checked and it is a coin flip".
		expect(betp(VACUOUS)).toBe(0.5);
		expect(ignorance(VACUOUS)).toBe(1);
		expect(interval(VACUOUS)).toEqual({ bel: 0, pl: 1 });
	});

	it("reports a genuine coin flip as BetP 0.5 with a zero-width interval", () => {
		const flip = belief(0.5, 0.5);
		expect(betp(flip)).toBe(0.5);
		expect(ignorance(flip)).toBe(0);
		expect(interval(flip)).toEqual({ bel: 0.5, pl: 0.5 });
	});

	it("raises belief when two supporting sources combine", () => {
		const once = supporting(0.6);
		const twice = combine(once, supporting(0.6));
		expect(betp(twice)).toBeGreaterThan(betp(once));
		expect(ignorance(twice)).toBeLessThan(ignorance(once));
	});

	it("swings the mass balance when refuting evidence lands on a supported claim", () => {
		const supported = supporting(0.8);
		const contested = combine(supported, refuting(0.9));

		// The mass balance flips decisively: refute ≈ 0.64 against support ≈ 0.29.
		expect(contested.refute).toBeGreaterThan(contested.support * 2);

		// But BetP only falls to ≈ 0.32, not below 0.25 — Dempster's rule
		// normalizes the conflict away by dividing through by (1 - K), which
		// drags two disagreeing sources back toward the middle. Anything
		// deciding "is this refuted?" must read the masses, not this number.
		expect(betp(contested)).toBeCloseTo(0.32, 2);
		expect(betp(contested)).toBeLessThan(betp(supported));
	});

	it("records conflict when sources disagree", () => {
		const conflicted = combine(supporting(0.8), refuting(0.8));
		expect(conflicted.conflict).toBeGreaterThan(0);
	});

	it("does not manufacture conflict when sources agree", () => {
		expect(combine(supporting(0.8), supporting(0.7)).conflict).toBe(0);
	});

	it("survives total conflict without producing NaN", () => {
		const total = combine(belief(1, 0), belief(0, 1));
		expect(total.conflict).toBe(1);
		expect(Number.isFinite(betp(total))).toBe(true);
		expect(betp(total)).toBe(0.5);
	});

	it("is commutative", () => {
		const a = supporting(0.7);
		const b = refuting(0.3);
		expect(betp(combine(a, b))).toBeCloseTo(betp(combine(b, a)), 10);
	});

	it("leaves a belief unchanged when combined with the vacuous one", () => {
		const b = belief(0.6, 0.1);
		const combined = combine(b, VACUOUS);
		expect(combined.support).toBeCloseTo(b.support, 10);
		expect(combined.refute).toBeCloseTo(b.refute, 10);
	});

	it("moves discounted mass into ignorance, not into the opposite hypothesis", () => {
		const strong = supporting(0.9);
		const halved = discount(strong, 0.5);
		expect(halved.support).toBeCloseTo(0.45, 10);
		expect(halved.refute).toBe(0);
		expect(ignorance(halved)).toBeGreaterThan(ignorance(strong));
	});

	it("round-trips an EpiGraph belief interval", () => {
		const b = fromInterval(0.3, 0.8);
		expect(b.support).toBeCloseTo(0.3, 10);
		expect(b.refute).toBeCloseTo(0.2, 10);
		expect(ignorance(b)).toBeCloseTo(0.5, 10);
	});

	it("treats a missing interval as vacuous", () => {
		expect(fromInterval(null, null)).toEqual(VACUOUS);
		expect(fromInterval(undefined, 0.5)).toEqual(VACUOUS);
	});

	it("normalizes masses that would otherwise exceed 1", () => {
		const b = belief(0.8, 0.8);
		expect(b.support + b.refute).toBeCloseTo(1, 10);
	});
});
