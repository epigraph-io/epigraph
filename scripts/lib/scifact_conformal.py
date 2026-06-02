"""BetP / BBA reference for the offline split-conformal calibrator.

Harvested verbatim from EpigraphV2 ``scripts/lib/cdst_bba.py`` (the
SciFact-calibrated 0.948 F1 directed-BBA model). The live ``epigraph`` tree has
no ``cdst_bba.py`` (only ``scripts/lib/{claude_cli,tiered_enrichment}.py``
exist), so the offline calibrator vendors the exact symbols it needs here.

This module is the **source of truth for the OFFLINE BetP** used to fit the
conformal quantiles. The live Rust engine computes BetP via
``epigraph-ds::measures::pignistic_probability``.

CAVEAT — offline vs. runtime BetP are NOT identical under open-world mass:
``compute_betp`` below follows Smets' TBM and simply EXCLUDES open-world mass
``m('~')`` from the binary BetP (``betp_sup = m('0') + m('0,1')/2``), without
renormalizing. The runtime ``measures::pignistic_probability`` instead
RENORMALIZES the closed-world masses by ``1 / (1 - m_open)``. The two agree
*up to the open-world renormalization factor* ``1/(1 - m_open)`` and are
identical ONLY when ``m_open == 0``. Under the SciFact open-world fraction
``owf = 0.03`` they diverge by ~0.022 (e.g. runtime betp_sup 0.7264 vs
compute_betp 0.7046). The conformal quantiles fit here are therefore
self-consistent on ``compute_betp`` and DO NOT transfer one-for-one to the live
engine unless the runtime path drops the open-world renormalization or the
offline score adds it (see the deferred-persistence risk in the PR).

``compute_betp`` MUST be used as-is rather than the EpigraphV2
``threshold_sweep_holdout.py`` ``classify()`` shortcut
``betp_unsup = 1 - betp_sup - theta``: under ``open_world_fraction = 0.03`` the
shortcut yields ``betp_unsup = -0.157`` while ``compute_betp`` yields ``0.265``
(0.42 divergence) because the shortcut double-counts theta and ignores
``m('~')``. Pure stdlib — no numpy / sklearn / MAPIE.
"""

# ── Methodology Profiles (SciFact-calibrated) ────────────────────────────────
# (base_support, base_against, base_ignorance)
#
# base_support:   mass assigned to the supported hypothesis
# base_against:   mass assigned to the counter-hypothesis
# base_ignorance: residual frame-level ignorance

METHODOLOGY_PROFILES = {
    "deductive_logic":          (0.85, 0.05, 0.10),
    "deductive":                (0.85, 0.05, 0.10),
    "deductive_reasoning":      (0.85, 0.05, 0.10),
    "meta_analysis":            (0.80, 0.05, 0.15),
    "meta-analysis":            (0.80, 0.05, 0.15),
    "theoretical_derivation":   (0.80, 0.05, 0.15),
    "statistical_analysis":     (0.75, 0.05, 0.20),
    "statistical":              (0.75, 0.05, 0.20),
    "statistical_inference":    (0.75, 0.05, 0.20),
    "bayesian_inference":       (0.70, 0.05, 0.25),
    "bayesian":                 (0.70, 0.05, 0.25),
    "computational":            (0.72, 0.05, 0.23),
    "computational_simulation": (0.72, 0.05, 0.23),
    "instrumental":             (0.80, 0.05, 0.15),
    "instrumental_measurement": (0.80, 0.05, 0.15),
    "experimental_observation": (0.80, 0.05, 0.15),
    "inductive_generalization": (0.60, 0.08, 0.32),
    "inductive":                (0.60, 0.08, 0.32),
    "visual_inspection":        (0.55, 0.08, 0.37),
    "observational":            (0.60, 0.08, 0.32),
    "expert_elicitation":       (0.45, 0.10, 0.45),
    "expert":                   (0.45, 0.10, 0.45),
    "testimonial":              (0.45, 0.10, 0.45),
    "extraction":               (0.58, 0.07, 0.35),
    "llm_extraction":           (0.58, 0.07, 0.35),
    "literature_synthesis":     (0.58, 0.07, 0.35),
    "textbook_assertion":       (0.78, 0.04, 0.18),
    "negative_result":          (0.70, 0.05, 0.25),

    # Placeholder values — overwritten by cdst_joint_sweep.py (Stage 2b).
    # See docs/superpowers/specs/2026-04-19-scifact-threshold-tuning-design.md.
    # Column-aligned at 42 (matches what _overwrite_cdst_bba_profiles emits).
    "similarity_band_high":                (0.50, 0.08, 0.42),
    "similarity_band_mid_llm_support":     (0.50, 0.08, 0.42),
    "similarity_band_mid_llm_contradict":  (0.08, 0.50, 0.42),
    "similarity_band_mid_llm_nei":         (0.20, 0.08, 0.72),
}
DEFAULT_PROFILE = (0.50, 0.08, 0.42)


# ── Evidence Type Weights ────────────────────────────────────────────────────

EVIDENCE_TYPE_WEIGHTS = {
    "empirical":       1.0,
    "statistical":     0.9,
    "logical":         0.85,
    "testimonial":     0.6,
    "circumstantial":  0.4,
    "conversational":  0.3,
}


# ── Section Tier Weights ─────────────────────────────────────────────────────
# Fraction of informative mass retained (rest shifted to theta)

SECTION_WEIGHTS = {
    "results":      1.0,
    "methods":      0.90,
    "discussion":   0.70,
    "conclusion":   0.65,
    "introduction": 0.50,
    "abstract":     0.80,
    "other":        0.75,
}


# ── Open-World Fractions ─────────────────────────────────────────────────────
# Fraction of total mass allocated to m(~) — unknown unknowns outside the frame

OPEN_WORLD_FRACTIONS = {
    "peer_reviewed":  0.03,
    "preprint":       0.07,
    "textbook":       0.02,
    "conversational": 0.20,
    "default":        0.05,
}

# Map journal names to source types for open-world lookup
_PREPRINT_JOURNALS = {"arXiv preprint", "bioRxiv", "chemRxiv", "medRxiv"}


# ── Core BBA Builder ─────────────────────────────────────────────────────────

def build_bba_directed(
    evidence_type: str,
    methodology: str,
    confidence: float,
    supports: bool,
    *,
    section_tier: str | None = None,
    journal_reliability: float | None = None,
    open_world_fraction: float = 0.0,
    uncertainty: float | None = None,
) -> dict[str, float]:
    """Build a directed mass function matching the SciFact-calibrated model.

    Produces masses in epigraph-ds format:
        "0"   → m({supported})
        "1"   → m({unsupported})
        "0,1" → m(Θ) closed-world ignorance
        "~"   → m(~∅) open-world ignorance (if fraction > 0)

    Args:
        evidence_type: One of EVIDENCE_TYPE_WEIGHTS keys.
        methodology: One of METHODOLOGY_PROFILES keys.
        confidence: Extraction/evidence confidence in [0, 1].
        supports: True if evidence supports the claim, False if it contradicts.
        section_tier: Optional section tier for discount (results, methods, etc.).
        journal_reliability: Optional journal reliability in [0, 1].
        open_world_fraction: Fraction of total mass allocated to m(~).
        uncertainty: Optional parsed uncertainty from error bars in [0, 1].
            0 = precise (no mass shifted), 1 = total ignorance (all mass → theta).
            When None, no discount applied (backward compatible).

    Returns:
        Dict of focal element → mass, summing to 1.0.
    """
    confidence = max(0.0, min(1.0, confidence))
    open_world_fraction = max(0.0, min(0.5, open_world_fraction))

    base_support, base_against, _base_ign = METHODOLOGY_PROFILES.get(
        methodology.lower() if methodology else "extraction",
        DEFAULT_PROFILE,
    )
    type_weight = EVIDENCE_TYPE_WEIGHTS.get(
        evidence_type.lower() if evidence_type else "circumstantial",
        0.5,
    )

    if supports:
        m_supported = min(base_support * type_weight * confidence, 0.95)
        m_unsupported = min(base_against * (1.0 - confidence * 0.5), 0.3)
    else:
        m_unsupported = min(base_support * type_weight * confidence, 0.95)
        m_supported = min(base_against * (1.0 - confidence * 0.5), 0.3)

    m_theta = max(1.0 - m_supported - m_unsupported, 0.0)

    # Apply section tier discount (shifts informative mass → theta)
    if section_tier and section_tier in SECTION_WEIGHTS:
        retention = SECTION_WEIGHTS[section_tier]
        if retention < 1.0:
            # Discount the primary informative mass (whichever side is larger)
            if supports:
                shift = m_supported * (1.0 - retention)
                m_supported -= shift
            else:
                shift = m_unsupported * (1.0 - retention)
                m_unsupported -= shift
            m_theta += shift

    # Apply journal reliability discount
    if journal_reliability is not None and journal_reliability < 1.0:
        unreliable = 1.0 - journal_reliability
        if supports:
            shift = m_supported * unreliable
            m_supported -= shift
        else:
            shift = m_unsupported * unreliable
            m_unsupported -= shift
        m_theta += shift

    # Apply parsed uncertainty discount (shifts informative mass → theta)
    if uncertainty is not None:
        uncertainty = max(0.0, min(1.0, uncertainty))
        if supports:
            shift = m_supported * uncertainty
            m_supported -= shift
        else:
            shift = m_unsupported * uncertainty
            m_unsupported -= shift
        m_theta += shift

    # Normalize closed-world portion
    total = m_supported + m_unsupported + m_theta
    if total <= 0:
        total = 1.0

    # Redistribute open-world fraction
    m_open = 0.0
    if open_world_fraction > 0:
        m_open = open_world_fraction
        closed_scale = (1.0 - m_open) / total
    else:
        closed_scale = 1.0 / total

    m_supported *= closed_scale
    m_unsupported *= closed_scale
    m_theta *= closed_scale

    # Assemble masses dict (omit near-zero entries)
    masses = {}
    if m_supported > 1e-10:
        masses["0"] = m_supported
    if m_unsupported > 1e-10:
        masses["1"] = m_unsupported
    if m_theta > 1e-10:
        masses["0,1"] = m_theta
    if m_open > 1e-10:
        masses["~"] = m_open

    # Fix floating-point drift
    s = sum(masses.values())
    if masses and abs(s - 1.0) > 1e-9:
        largest = max(masses, key=masses.__getitem__)
        masses[largest] += 1.0 - s

    return masses


# ── Legacy Field Mapper ──────────────────────────────────────────────────────

# Methodology → (evidence_type, supports, confidence_adjustment)
_METHODOLOGY_TO_EVIDENCE = {
    "instrumental":             ("empirical",      True,  1.0),
    "instrumental_measurement": ("empirical",      True,  1.0),
    "experimental_observation": ("empirical",      True,  1.0),
    "visual_inspection":        ("empirical",      True,  0.8),
    "observational":            ("empirical",      True,  0.9),
    "computational":            ("logical",        True,  1.0),
    "computational_simulation": ("logical",        True,  1.0),
    "statistical_analysis":     ("statistical",    True,  1.0),
    "statistical_inference":    ("statistical",    True,  1.0),
    "statistical":              ("statistical",    True,  1.0),
    "deductive":                ("logical",        True,  1.0),
    "deductive_logic":          ("logical",        True,  1.0),
    "deductive_reasoning":      ("logical",        True,  1.0),
    "theoretical_derivation":   ("logical",        True,  1.0),
    "meta_analysis":            ("statistical",    True,  1.0),
    "bayesian_inference":       ("statistical",    True,  1.0),
    "bayesian":                 ("statistical",    True,  1.0),
    "inductive":                ("testimonial",    True,  0.9),
    "inductive_generalization": ("testimonial",    True,  0.9),
    "expert_elicitation":       ("testimonial",    True,  0.8),
    "expert":                   ("testimonial",    True,  0.8),
    "testimonial":              ("testimonial",    True,  0.8),
    "extraction":               ("circumstantial", True,  1.0),
    "llm_extraction":           ("circumstantial", True,  1.0),
    "literature_synthesis":     ("testimonial",    True,  0.9),
    "textbook_assertion":       ("logical",        True,  1.0),
    "negative_result":          ("empirical",      False, 1.0),
}

# Textbook content_type → (evidence_type, supports, confidence_adjustment)
_CONTENT_TYPE_TO_EVIDENCE = {
    "definition":  ("logical",       True, 1.0),
    "paragraph":   ("testimonial",   True, 1.0),
    "table":       ("statistical",   True, 1.0),
    "note":        ("testimonial",   True, 0.85),
    "figure":      ("empirical",     True, 0.9),
}


def map_legacy_fields(
    methodology: str | None = None,
    content_type: str | None = None,
) -> tuple[str, bool, float]:
    """Map legacy claim fields to (evidence_type, supports, confidence_adjustment).

    For claims that lack explicit evidence_type and supports fields.

    Args:
        methodology: Methodology string from enriched JSON.
        content_type: Content type string from textbook enriched JSON.

    Returns:
        (evidence_type, supports, confidence_adjustment) tuple.
        confidence_adjustment is a multiplier on the claim's raw confidence.
    """
    if content_type and content_type in _CONTENT_TYPE_TO_EVIDENCE:
        return _CONTENT_TYPE_TO_EVIDENCE[content_type]

    if methodology and methodology.lower() in _METHODOLOGY_TO_EVIDENCE:
        return _METHODOLOGY_TO_EVIDENCE[methodology.lower()]

    # Default: treat as circumstantial support
    return ("circumstantial", True, 1.0)


# ── BetP Calculation ─────────────────────────────────────────────────────────

def compute_betp(masses: dict) -> tuple[float, float, float]:
    """Compute pignistic probabilities and theta from a mass function.

    Handles open-world mass m(~) using Smets' transferable belief model:
    open-world mass is excluded from BetP redistribution (it represents
    hypotheses outside the frame and cannot inform the closed-world decision).

    NOTE (see module docstring): this EXCLUDES m(~) but does NOT renormalize by
    1/(1 - m_open). The runtime measures::pignistic_probability renormalizes, so
    the two agree only when m_open == 0; under owf=0.03 they diverge by ~0.022.

    Returns (betp_supported, betp_unsupported, theta).
    """
    m_sup = masses.get("0", 0.0)
    m_unsup = masses.get("1", 0.0)
    m_theta = masses.get("0,1", 0.0)
    # m_open = masses.get("~", 0.0)  — excluded from BetP per Smets

    # BetP redistributes theta equally across hypotheses in the binary frame
    betp_sup = m_sup + m_theta / 2
    betp_unsup = m_unsup + m_theta / 2

    return betp_sup, betp_unsup, m_theta
