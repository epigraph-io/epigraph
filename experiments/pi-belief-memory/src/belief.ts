/**
 * Dempster-Shafer belief over a binary frame Θ = {H, ¬H}.
 *
 * A mass function assigns mass to subsets of Θ. On a binary frame there are
 * exactly three focal elements worth tracking:
 *
 *   support  = m({H})    evidence for the claim
 *   refute   = m({¬H})   evidence against the claim
 *   ignorance = m(Θ)     mass we cannot attribute either way
 *
 * The three sum to 1, so `ignorance` is derived rather than stored. Keeping
 * ignorance as a first-class quantity is the point: it distinguishes "we
 * looked and it is a coin flip" (support 0.5, refute 0.5, ignorance 0) from
 * "we never checked" (support 0, refute 0, ignorance 1). A scalar confidence
 * reports 0.5 for both.
 *
 * See docs/intro/02-concepts.md §3 for the kernel's full multi-hypothesis
 * treatment; this module is the binary-frame reduction used for session-local
 * short-term memory.
 */

/** A mass function over {H, ¬H}, with m(Θ) implied by the remainder. */
export interface Belief {
	/** m({H}) — mass committed to the claim being true. */
	support: number;
	/** m({¬H}) — mass committed to the claim being false. */
	refute: number;
	/** Cumulative Dempster conflict K accumulated across combinations. */
	conflict: number;
}

/** Total ignorance: no evidence in either direction. */
export const VACUOUS: Belief = { support: 0, refute: 0, conflict: 0 };

function clamp01(value: number): number {
	if (!Number.isFinite(value)) return 0;
	return value < 0 ? 0 : value > 1 ? 1 : value;
}

/** Build a normalized belief, forcing support + refute <= 1. */
export function belief(support: number, refute: number, conflict = 0): Belief {
	let s = clamp01(support);
	let r = clamp01(refute);
	const total = s + r;
	if (total > 1) {
		s /= total;
		r /= total;
	}
	return { support: s, refute: r, conflict: clamp01(conflict) };
}

/** m(Θ) — the mass that could not be attributed to either hypothesis. */
export function ignorance(b: Belief): number {
	return clamp01(1 - b.support - b.refute);
}

/**
 * Pignistic probability. Distributes the ignorance mass uniformly over the
 * frame's singletons, which on a binary frame means splitting it in half.
 *
 * BetP is the scalar to rank by; read the mass function itself when you need
 * to know how much that rank is worth.
 */
export function betp(b: Belief): number {
	return clamp01(b.support + ignorance(b) / 2);
}

/** The belief interval [Bel, Pl]. Its width is the ignorance. */
export function interval(b: Belief): { bel: number; pl: number } {
	return { bel: b.support, pl: clamp01(1 - b.refute) };
}

/**
 * Dempster's rule of combination on a binary frame.
 *
 * Conflict K is the mass that two sources commit to disjoint hypotheses. The
 * classical rule normalizes it away by dividing through by (1 - K), which is
 * what makes Dempster combination notorious for producing confident nonsense
 * from two sources that flatly disagree. We keep K rather than discarding it,
 * so a claim that has been argued both ways carries a visible conflict score
 * even after its BetP settles.
 *
 * Total conflict (K = 1) cannot be normalized. We fall back to the vacuous
 * belief with conflict pinned at 1 — "these sources cancel; we know nothing,
 * and that is itself worth reporting".
 */
export function combine(a: Belief, b: Belief): Belief {
	const aTheta = ignorance(a);
	const bTheta = ignorance(b);

	const k = a.support * b.refute + a.refute * b.support;
	if (k >= 1) return { support: 0, refute: 0, conflict: 1 };

	const norm = 1 - k;
	const support = (a.support * b.support + a.support * bTheta + aTheta * b.support) / norm;
	const refute = (a.refute * b.refute + a.refute * bTheta + aTheta * b.refute) / norm;

	// Conflict is cumulative and saturating: once two sources have disagreed,
	// later agreement does not un-disagree them.
	const conflict = clamp01(a.conflict + b.conflict + k - a.conflict * b.conflict);
	return belief(support, refute, conflict);
}

/**
 * Discount a belief by a source's own reliability (Shafer discounting).
 *
 * A claim asserted by a source we only half believe should not transfer its
 * full mass. Discounting moves the shortfall into ignorance rather than into
 * the opposing hypothesis — an unreliable witness makes us less certain, not
 * certain of the opposite.
 */
export function discount(b: Belief, reliability: number): Belief {
	const r = clamp01(reliability);
	return belief(b.support * r, b.refute * r, b.conflict);
}

/** Evidence for a claim at the given strength. */
export function supporting(strength: number): Belief {
	return belief(clamp01(strength), 0);
}

/** Evidence against a claim at the given strength. */
export function refuting(strength: number): Belief {
	return belief(0, clamp01(strength));
}

/**
 * Map an EpiGraph belief interval [Bel, Pl] back onto a mass function.
 *
 * The kernel's `EpistemicState` reports the interval rather than the masses,
 * but on a binary frame the inverse is exact: support = Bel, refute = 1 - Pl,
 * and the interval width is the ignorance.
 */
export function fromInterval(bel: number | null | undefined, pl: number | null | undefined): Belief {
	if (bel === null || bel === undefined || pl === null || pl === undefined) return { ...VACUOUS };
	return belief(bel, 1 - pl);
}
