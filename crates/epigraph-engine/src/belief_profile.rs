//! The belief profile: every parameter of the belief fold in one object.
//!
//! A [`BeliefProfile`] holds every number (and every policy switch) that
//! shapes a belief value: the evidence-type weights and aliases, the locality
//! factors, the unknown-type fallback, the methodology and journal tables, the
//! combination and classifier thresholds, the edge-factor open-world default,
//! the gate constants, and the parameters later slices of the atom-level
//! belief program will consume (class weights, the testimonial ceiling and
//! its policies, forecasts, necessity, test-selection interest).
//!
//! # Resolution
//!
//! Each parameter is resolved through the same tier chain the per-BBA
//! reliability already used (see
//! [`crate::edge_factor::effective_source_strength_with_perspective`]):
//!
//! **perspective override → per-frame override → named global profile → built-in default.**
//!
//! - *Built-in default*: [`BeliefProfile::builtin`], the defaults table below.
//!   Its tables (weights, aliases, methodology, journals) are EMPTY: today's
//!   code gets them from `calibration.toml`, and when that file cannot be
//!   loaded the process runs with empty tables
//!   ([`CalibrationConfig::default_for_phase2_fallback`]). Keeping the
//!   built-in tables empty keeps that behaviour exact.
//! - *Named global profile*: `calibration.toml`. Its existing sections
//!   (`[evidence_type_weights]`, `[evidence_locality]`, ...) fill the tables
//!   and scalars they always filled, then an optional
//!   `[belief_profiles.<name>]` table for [`DEFAULT_PROFILE_NAME`] overrides
//!   any parameter by name ([`BeliefProfile::from_calibration`]).
//! - *Per-frame override*: a `belief_profile` object in `frames.properties`
//!   ([`PROFILE_PROPERTY_KEY`]), then the two per-frame keys that predate the
//!   profile (`intra_evidence_locality_factor`, `evidence_type_weights`). At
//!   the frame tier the dedicated older keys win over the generic object.
//! - *Perspective override*: a `belief_profile` object in
//!   `perspectives.properties`, then the perspective's `source_reliability` /
//!   `locality_reliability` maps. The perspective tier sits above the whole
//!   frame tier, map entries included: an evidence type the perspective's
//!   `reliability.evidence_type_weights` names (set, or removed with `null`)
//!   is answered by the perspective, not by the frame's dedicated
//!   `evidence_type_weights` key.
//!
//! Override objects are JSON merge patches (RFC 7386) over the serialized
//! profile: objects merge key by key, any other value replaces, `null`
//! removes a map entry. An override that names an unknown parameter, has the
//! wrong type, or carries a number outside its range is REJECTED as a whole
//! tier (with a warning) and the tier below stands; it never fails a read.
//!
//! # Where it applies
//!
//! The lens tiers (frame, perspective) apply at fold time only. The
//! write-time construction constants (the edge-factor parameters and the DS
//! write path's simple-support and truth-seed bounds) are read from the served
//! (default) profile when a row is written, so a stored row carries the
//! default profile's construction and never a lens's. The served cache is the
//! anonymous viewer under the default profile ([`BeliefProfile::served`]) with
//! the frame's overrides; lens reads resolve the perspective tier on top and
//! never write the cache.
//!
//! # Hash
//!
//! [`BeliefProfile::profile_hash`] is BLAKE3 over a canonical encoding of the
//! RESOLVED parameters (map keys sorted, `-0.0` read as `0.0`), so a served
//! value can be recomputed from (rows, profile hash). The profile's name is not
//! a parameter and is not hashed.

use std::collections::{BTreeMap, HashMap};
use std::sync::LazyLock;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::calibration::CalibrationConfig;
use crate::edge_factor::PerspectiveReliability;

/// Name of the default ("opinionated-v1") profile: the
/// `[belief_profiles.<name>]` table in `calibration.toml` that the served
/// profile reads.
pub const DEFAULT_PROFILE_NAME: &str = "opinionated-v1";

/// Key of the override object in `frames.properties` and
/// `perspectives.properties`.
pub const PROFILE_PROPERTY_KEY: &str = "belief_profile";

/// Domain separator for the profile hash; bump the version when the
/// canonical encoding changes.
const HASH_DOMAIN: &[u8] = b"epigraph.belief_profile.v1\n";

// belief-profile: defaults-table-begin
/// The built-in defaults: every belief constant the fold paths used as a
/// literal before the profile existed, with its value unchanged, plus the
/// typed defaults of the parameters later slices consume.
pub mod defaults {
    /// Weight of a BBA whose evidence type resolves nowhere and that carries
    /// no stored `source_strength`.
    pub const UNKNOWN_EVIDENCE_TYPE_WEIGHT: f64 = 0.5;
    /// Locality factor for a BBA that is not intra-source.
    pub const CROSS_LOCALITY_FACTOR: f64 = 1.0;
    /// Locality factor for an intra-source BBA (`locality_tag` `intra*`).
    pub const INTRA_EVIDENCE_LOCALITY_FACTOR: f64 = 0.3;
    /// Conflict threshold handed to the Dempster fold (not consumed: see
    /// [`super::CombinationParams::conflict_threshold`]).
    pub const CONFLICT_THRESHOLD: f64 = 0.9;
    /// Journal reliability when no journal entry matches.
    pub const DEFAULT_JOURNAL_RELIABILITY: f64 = 0.78;
    /// Methodology profile `[support, against, ignorance]` when neither the
    /// methodology, its alias, nor a `default` row is in the table.
    pub const METHODOLOGY_FALLBACK: [f64; 3] = [0.50, 0.08, 0.42];
    /// Fraction of a source's `Pl − Bel` taken as open-world mass when the
    /// source row has no stored `open_world_mass`.
    pub const OPEN_WORLD_FRACTION_DEFAULT: f64 = 0.5;
    /// An edge factor whose restricted interval is at least this wide ...
    pub const VACUOUS_WIDTH: f64 = 0.999;
    /// ... and whose belief is below this is vacuous and not written.
    pub const VACUOUS_BELIEF: f64 = 0.01;
    /// Bounds on a written simple-support BBA's committed mass
    /// (`confidence × weight`): never vacuous, never categorical.
    pub const SIMPLE_SUPPORT_MASS_MIN: f64 = 0.01;
    pub const SIMPLE_SUPPORT_MASS_MAX: f64 = 0.99;
    /// Bounds a claim's `truth_value` is capped to before it seeds a BBA, so
    /// the seed is never categorical (a categorical BBA absorbs every later
    /// one under Dempster's rule).
    pub const TRUTH_SEED_MIN: f64 = 0.005;
    pub const TRUTH_SEED_MAX: f64 = 0.995;
    /// Classifier thresholds (the BetP cascade on the binary frame).
    pub const CLASSIFIER_NEI_THRESHOLD: f64 = 0.85;
    pub const CLASSIFIER_SUPPORT_THRESHOLD: f64 = 0.15;
    pub const CLASSIFIER_CONFLICT_THRESHOLD: f64 = 0.05;
    pub const CLASSIFIER_HAS_OPPOSING_THRESHOLD: f64 = 0.1;
    /// Score at or above which an uncontested result is `confirmed`.
    pub const CONFIRMED_SCORE: f64 = 0.75;
    /// Width above which a `[max, Dempster]` band is reported.
    pub const BAND_REPORT_WIDTH: f64 = 0.01;
    /// Attribution strengths k (full / partial / weak).
    pub const ATTRIBUTION_K_FULL: f64 = 1.0;
    pub const ATTRIBUTION_K_PARTIAL: f64 = 0.6;
    pub const ATTRIBUTION_K_WEAK: f64 = 0.3;
    /// Evidence-class weights.
    pub const CLASS_WEIGHT_PRIMARY: f64 = 1.0;
    pub const CLASS_WEIGHT_REPORTED: f64 = 0.6;
    pub const CLASS_WEIGHT_TESTIMONIAL: f64 = 1.0;
    pub const METHODS_DETAIL_FACTOR: f64 = 1.0;
    /// Cap on the testimonial group's m(T) and m(F).
    pub const TESTIMONIAL_CEILING: f64 = 0.1;
    /// Forecast parameters.
    pub const FORECAST_PRE_RESOLUTION_CEILING: f64 = 0.1;
    pub const FORECAST_MODEL_WEIGHT: f64 = 0.5;
    pub const FORECAST_OVERDUE_GRACE_DAYS: u32 = 30;
    /// Necessity strength when none is asserted.
    pub const NECESSITY_DEFAULT_STRENGTH: f64 = 0.0;
    /// Weight of testimonial mass and disagreement in test selection.
    pub const TEST_SELECTION_TESTIMONY_INTEREST: f64 = 1.0;
}
// belief-profile: defaults-table-end

// ── Parameter groups ────────────────────────────────────────────────────────

/// Per-BBA reliability parameters: what `effective_source_strength`
/// discounts each stored BBA by before the fold.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReliabilityParams {
    /// Weight for an evidence type that resolves nowhere and has no stored
    /// strength.
    pub unknown_evidence_type_weight: f64,
    /// Locality factor for a non-intra BBA.
    pub cross_locality_factor: f64,
    /// Locality factor for an intra-source BBA.
    pub intra_evidence_locality_factor: f64,
    /// Canonical evidence type → weight (`[evidence_type_weights]`).
    pub evidence_type_weights: BTreeMap<String, f64>,
    /// Alias → canonical evidence type (`[evidence_type_aliases]`).
    pub evidence_type_aliases: BTreeMap<String, String>,
}

/// Parameters of the combination itself.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CombinationParams {
    /// Conflict threshold handed to `combine_multiple` (the Dempster fold).
    ///
    /// **Not consumed.** `epigraph_ds::combination::combine_multiple` ignores
    /// its threshold argument (every fold step is Dempster), so overriding
    /// this moves no served value. It is still threaded to every fold and
    /// hashed, like the other not-yet-consumed parameters, so a fold that
    /// honours it later needs no profile change; that change is pinned by the
    /// golden test `the_combination_conflict_threshold_is_not_consumed_today`,
    /// which must then be updated on purpose. Until then an override of it
    /// changes the profile hash without changing any value.
    pub conflict_threshold: f64,
}

/// The calibration tables BBA construction reads: methodology profiles,
/// journal reliability. Carried and hashed here so a later slice can apply
/// them at fold time (the reported class weighting).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalibrationTables {
    pub default_journal_reliability: f64,
    pub journal_reliability: BTreeMap<String, f64>,
    /// Methodology → `[support, against, ignorance]`.
    // belief-profile: allow-literal (array length of a mass triplet)
    pub methodology_profiles: BTreeMap<String, [f64; 3]>,
    pub methodology_aliases: BTreeMap<String, String>,
    /// Profile used when no methodology row (nor `default`) matches.
    // belief-profile: allow-literal (array length of a mass triplet)
    pub methodology_fallback: [f64; 3],
}

/// Edge-factor (epistemic edge → BBA) write parameters.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeFactorParams {
    /// Fraction of `Pl − Bel` taken as open-world mass when the source claim
    /// has no stored `open_world_mass`.
    pub open_world_fraction_default: f64,
    /// A restricted interval at least this wide ...
    pub vacuous_width: f64,
    /// ... with belief below this is vacuous and not written.
    pub vacuous_belief: f64,
}

/// Write-time BBA construction bounds of the DS write path
/// (`epigraph_mcp::tools::ds_auto`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConstructionParams {
    /// Lower bound on a written simple-support BBA's committed mass.
    pub simple_support_mass_min: f64,
    /// Upper bound on a written simple-support BBA's committed mass.
    pub simple_support_mass_max: f64,
    /// Lower bound a `truth_value` is capped to before it seeds a BBA.
    pub truth_seed_min: f64,
    /// Upper bound a `truth_value` is capped to before it seeds a BBA.
    pub truth_seed_max: f64,
}

/// The BetP classifier cascade's thresholds.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClassifierParams {
    pub nei_threshold: f64,
    pub support_threshold: f64,
    pub conflict_threshold: f64,
    pub has_opposing_threshold: f64,
}

impl ClassifierParams {
    /// The thresholds in the shape the classifier takes.
    #[must_use]
    pub fn thresholds(&self) -> crate::calibration::ClassifierThresholds {
        crate::calibration::ClassifierThresholds {
            nei_threshold: self.nei_threshold,
            support_threshold: self.support_threshold,
            conflict_threshold: self.conflict_threshold,
            has_opposing_threshold: self.has_opposing_threshold,
        }
    }
}

/// Read-side gate constants.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GateParams {
    /// Score at or above which an uncontested recall hit is `confirmed`.
    pub confirmed_score: f64,
    /// Width above which a `[max, Dempster]` band is reported (not yet
    /// consumed).
    pub band_report_width: f64,
}

/// Attribution strengths k for atom attributions (not yet consumed).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttributionK {
    pub full: f64,
    pub partial: f64,
    pub weak: f64,
}

/// Evidence-class weights (not yet consumed). `reported` is multiplied by
/// journal reliability, the methodology profile and `methods_detail_factor`;
/// `testimonial` applies inside the testimonial group, which the ceiling then
/// bounds.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClassWeights {
    pub primary: f64,
    pub reported: f64,
    pub testimonial: f64,
    /// Hook for a future methods-completeness score.
    pub methods_detail_factor: f64,
}

/// What testimony contributes once a primary or reported item exists
/// (not yet consumed).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TestimonialWhenEvidenced {
    /// Testimony contributes nothing.
    Suppress,
    /// Testimony stays, capped by the ceiling.
    Ceiling,
    /// Testimony stays at this weight.
    Weight(f64),
}

/// How testimony on one atom is grouped (not yet consumed).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TestimonialGrouping {
    /// All testimony on an atom is one group, whatever its source.
    Class,
    /// One group per owning human.
    Owner,
}

/// Combination rule inside one item group (not yet consumed).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WithinGroupRule {
    /// Same literal → max; opposite literals → Dempster.
    MaxSameDempsterOpposite,
    /// Plain Dempster across the group (research lenses only).
    Dempster,
}

/// Forecast parameters (not yet consumed).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForecastParams {
    /// Cap on a forecast atom's belief before it resolves.
    pub pre_resolution_ceiling: f64,
    /// Discount on model / base-rate evidence about the future.
    pub model_weight: f64,
    /// Days after `resolves_at` before an unresolved forecast is overdue.
    pub overdue_grace_days: u32,
}

/// Where necessity assertions may come from (not yet consumed).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NecessitySource {
    /// Explicit assertions only.
    Explicit,
    /// A model proposing necessities (the hook).
    Model,
}

/// Necessity (back-propagation) parameters (not yet consumed).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NecessityParams {
    pub sources: Vec<NecessitySource>,
    /// Strength of a necessity nobody asserted.
    pub default_strength: f64,
}

/// Test-selection parameters (not yet consumed).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestSelectionParams {
    /// Weight of testimonial mass and disagreement in the candidate score.
    pub testimony_interest: f64,
}

/// The lens's per-tag reliability maps, filled by the frame and perspective
/// tiers from the keys that predate the profile. Not settable through an
/// override object; part of the hash because they shape lensed values.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LensReliability {
    /// The frame's strict-key `evidence_type_weights` override.
    pub frame_evidence_type_weights: BTreeMap<String, f64>,
    /// The perspective's `source_reliability` map.
    pub perspective_source_reliability: BTreeMap<String, f64>,
    /// The perspective's `locality_reliability` map.
    pub perspective_locality_reliability: BTreeMap<String, f64>,
}

impl LensReliability {
    /// `true` when the perspective expresses no reliability opinion.
    #[must_use]
    pub fn perspective_is_empty(&self) -> bool {
        self.perspective_source_reliability.is_empty()
            && self.perspective_locality_reliability.is_empty()
    }
}

/// Every belief parameter, resolved. See the module docs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BeliefProfile {
    pub reliability: ReliabilityParams,
    pub combination: CombinationParams,
    pub tables: CalibrationTables,
    pub edge_factor: EdgeFactorParams,
    pub construction: ConstructionParams,
    pub classifier: ClassifierParams,
    pub gates: GateParams,
    pub attribution_k: AttributionK,
    pub class_weight: ClassWeights,
    /// Cap on the testimonial group's m(T) and m(F) (not yet consumed).
    pub testimonial_ceiling: f64,
    pub testimonial_when_evidenced: TestimonialWhenEvidenced,
    pub testimonial_grouping: TestimonialGrouping,
    pub within_group_rule: WithinGroupRule,
    pub forecast: ForecastParams,
    pub necessity: NecessityParams,
    pub test_selection: TestSelectionParams,
    pub lens: LensReliability,
}

/// A belief read's profile identity (addendum §3.1, SPEC §3.5
/// `BeliefView.profile`): the named global profile the lens was resolved over,
/// and [`BeliefProfile::profile_hash`] of the RESOLVED parameters. The name is
/// provenance, not a parameter, so it is not hashed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileIdentity {
    pub name: String,
    pub hash: String,
}

/// Why an override object was rejected.
#[derive(Debug, thiserror::Error)]
pub enum ProfileError {
    #[error("a belief_profile override must be a JSON object")]
    NotAnObject,
    #[error("`lens` is filled from the frame/perspective reliability keys, not overridable")]
    LensNotOverridable,
    #[error("override does not fit the profile: {0}")]
    Shape(#[from] serde_json::Error),
    #[error("parameter `{path}` = {value} is out of range ({range})")]
    OutOfRange {
        path: String,
        value: f64,
        range: &'static str,
    },
}

/// The frame tier's inputs: the generic override object and the two
/// per-frame keys that predate it.
#[derive(Debug, Clone, Copy, Default)]
pub struct FrameTier<'a> {
    /// `frames.properties.belief_profile`.
    pub overrides: Option<&'a Value>,
    /// `frames.properties.intra_evidence_locality_factor`.
    pub intra_evidence_locality_factor: Option<f64>,
    /// `frames.properties.evidence_type_weights` (lowercased keys).
    pub evidence_type_weights: Option<&'a HashMap<String, f64>>,
}

/// The perspective tier's inputs.
#[derive(Debug, Clone, Copy, Default)]
pub struct PerspectiveTier<'a> {
    /// `perspectives.properties.belief_profile`.
    pub overrides: Option<&'a Value>,
    /// The perspective's `source_reliability` / `locality_reliability`.
    pub reliability: Option<&'a PerspectiveReliability>,
}

/// The `belief_profile` override object in a frame's or perspective's
/// `properties`, if any.
#[must_use]
pub fn overrides_in(properties: &Value) -> Option<&Value> {
    properties.get(PROFILE_PROPERTY_KEY)
}

fn to_btree<V: Clone>(m: &HashMap<String, V>) -> BTreeMap<String, V> {
    m.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
}

impl BeliefProfile {
    /// The built-in default profile: the defaults table, with empty
    /// calibration tables (see the module docs for why they are empty).
    #[must_use]
    pub fn builtin() -> Self {
        use defaults as d;
        Self {
            reliability: ReliabilityParams {
                unknown_evidence_type_weight: d::UNKNOWN_EVIDENCE_TYPE_WEIGHT,
                cross_locality_factor: d::CROSS_LOCALITY_FACTOR,
                intra_evidence_locality_factor: d::INTRA_EVIDENCE_LOCALITY_FACTOR,
                evidence_type_weights: BTreeMap::new(),
                evidence_type_aliases: BTreeMap::new(),
            },
            combination: CombinationParams {
                conflict_threshold: d::CONFLICT_THRESHOLD,
            },
            tables: CalibrationTables {
                default_journal_reliability: d::DEFAULT_JOURNAL_RELIABILITY,
                journal_reliability: BTreeMap::new(),
                methodology_profiles: BTreeMap::new(),
                methodology_aliases: BTreeMap::new(),
                methodology_fallback: d::METHODOLOGY_FALLBACK,
            },
            edge_factor: EdgeFactorParams {
                open_world_fraction_default: d::OPEN_WORLD_FRACTION_DEFAULT,
                vacuous_width: d::VACUOUS_WIDTH,
                vacuous_belief: d::VACUOUS_BELIEF,
            },
            construction: ConstructionParams {
                simple_support_mass_min: d::SIMPLE_SUPPORT_MASS_MIN,
                simple_support_mass_max: d::SIMPLE_SUPPORT_MASS_MAX,
                truth_seed_min: d::TRUTH_SEED_MIN,
                truth_seed_max: d::TRUTH_SEED_MAX,
            },
            classifier: ClassifierParams {
                nei_threshold: d::CLASSIFIER_NEI_THRESHOLD,
                support_threshold: d::CLASSIFIER_SUPPORT_THRESHOLD,
                conflict_threshold: d::CLASSIFIER_CONFLICT_THRESHOLD,
                has_opposing_threshold: d::CLASSIFIER_HAS_OPPOSING_THRESHOLD,
            },
            gates: GateParams {
                confirmed_score: d::CONFIRMED_SCORE,
                band_report_width: d::BAND_REPORT_WIDTH,
            },
            attribution_k: AttributionK {
                full: d::ATTRIBUTION_K_FULL,
                partial: d::ATTRIBUTION_K_PARTIAL,
                weak: d::ATTRIBUTION_K_WEAK,
            },
            class_weight: ClassWeights {
                primary: d::CLASS_WEIGHT_PRIMARY,
                reported: d::CLASS_WEIGHT_REPORTED,
                testimonial: d::CLASS_WEIGHT_TESTIMONIAL,
                methods_detail_factor: d::METHODS_DETAIL_FACTOR,
            },
            testimonial_ceiling: d::TESTIMONIAL_CEILING,
            testimonial_when_evidenced: TestimonialWhenEvidenced::Suppress,
            testimonial_grouping: TestimonialGrouping::Class,
            within_group_rule: WithinGroupRule::MaxSameDempsterOpposite,
            forecast: ForecastParams {
                pre_resolution_ceiling: d::FORECAST_PRE_RESOLUTION_CEILING,
                model_weight: d::FORECAST_MODEL_WEIGHT,
                overdue_grace_days: d::FORECAST_OVERDUE_GRACE_DAYS,
            },
            necessity: NecessityParams {
                sources: vec![NecessitySource::Explicit],
                default_strength: d::NECESSITY_DEFAULT_STRENGTH,
            },
            test_selection: TestSelectionParams {
                testimony_interest: d::TEST_SELECTION_TESTIMONY_INTEREST,
            },
            lens: LensReliability::default(),
        }
    }

    /// The global profile for a calibration: the built-in defaults, then the
    /// calibration's sections, then its `[belief_profiles.<default name>]`
    /// table (rejected as a whole, with a warning, if invalid).
    #[must_use]
    pub fn from_calibration(cal: &CalibrationConfig) -> Self {
        let mut p = Self::builtin();
        p.reliability.intra_evidence_locality_factor =
            cal.evidence_locality.intra_evidence_locality_factor;
        p.reliability.evidence_type_weights = to_btree(&cal.evidence_type_weights);
        p.reliability.evidence_type_aliases = to_btree(&cal.evidence_type_aliases);
        p.tables.default_journal_reliability = cal.default_journal_reliability;
        p.tables.journal_reliability = to_btree(&cal.journal_reliability);
        p.tables.methodology_profiles = to_btree(&cal.methodology_profiles);
        p.tables.methodology_aliases = to_btree(&cal.methodology_aliases);
        p.classifier = ClassifierParams {
            nei_threshold: cal.classifier_thresholds.nei_threshold,
            support_threshold: cal.classifier_thresholds.support_threshold,
            conflict_threshold: cal.classifier_thresholds.conflict_threshold,
            has_opposing_threshold: cal.classifier_thresholds.has_opposing_threshold,
        };
        match cal.belief_profiles.get(DEFAULT_PROFILE_NAME) {
            Some(over) => p.overlaid("calibration.toml", over),
            None => p,
        }
    }

    /// The served (default) profile: [`Self::from_calibration`] over the
    /// process-wide calibration, built once.
    #[must_use]
    pub fn served() -> &'static Self {
        static SERVED: LazyLock<BeliefProfile> =
            LazyLock::new(|| BeliefProfile::from_calibration(CalibrationConfig::cached()));
        &SERVED
    }

    /// Layer the frame tier, then the perspective tier, over `self` (the
    /// global profile). Invalid override objects are skipped with a warning.
    #[must_use]
    pub fn resolve(&self, frame: FrameTier<'_>, perspective: PerspectiveTier<'_>) -> Self {
        let mut p = match frame.overrides {
            Some(o) => self.overlaid("frame", o),
            None => self.clone(),
        };
        // The dedicated per-frame keys win over the generic frame object.
        if let Some(f) = frame.intra_evidence_locality_factor {
            p.reliability.intra_evidence_locality_factor = f;
        }
        if let Some(w) = frame.evidence_type_weights {
            p.lens.frame_evidence_type_weights = to_btree(w);
        }
        if let Some(o) = perspective.overrides {
            if let Some(mut q) = p.try_overlaid("perspective", o) {
                // The perspective tier sits above the WHOLE frame tier,
                // including the frame's dedicated weight map, which both
                // reliability branches consult before the profile table. So
                // every evidence type the perspective names (a weight, or
                // `null` to remove one) leaves that map and is answered by
                // the merged table. Only on success: a rejected tier changes
                // nothing. Exact key match: the frame map's keys are
                // lowercase and the fold looks the table up lowercased, so a
                // mis-cased perspective key is inert in both places.
                for key in named_evidence_type_weights(o) {
                    q.lens.frame_evidence_type_weights.remove(key);
                }
                p = q;
            }
        }
        if let Some(r) = perspective.reliability {
            p.lens.perspective_source_reliability = to_btree(&r.source_reliability);
            p.lens.perspective_locality_reliability = to_btree(&r.locality_reliability);
        }
        p
    }

    fn overlaid(&self, tier: &'static str, overrides: &Value) -> Self {
        self.try_overlaid(tier, overrides)
            .unwrap_or_else(|| self.clone())
    }

    /// [`Self::with_overrides`], with a rejection logged and returned as
    /// `None` (the tier below stands).
    fn try_overlaid(&self, tier: &'static str, overrides: &Value) -> Option<Self> {
        match self.with_overrides(overrides) {
            Ok(p) => Some(p),
            Err(e) => {
                tracing::warn!(tier, error = %e, "belief_profile override rejected; tier ignored");
                None
            }
        }
    }

    /// Apply one override object (a JSON merge patch over the serialized
    /// profile).
    ///
    /// # Errors
    /// [`ProfileError`] when the object is not an object, names `lens`, does
    /// not deserialize into the profile (unknown parameter, wrong type), or
    /// carries a number outside its parameter's range.
    pub fn with_overrides(&self, overrides: &Value) -> Result<Self, ProfileError> {
        let Value::Object(obj) = overrides else {
            return Err(ProfileError::NotAnObject);
        };
        if obj.contains_key("lens") {
            return Err(ProfileError::LensNotOverridable);
        }
        check_ranges(overrides, &mut Vec::new())?;
        let mut merged = serde_json::to_value(self)?;
        merge_patch(&mut merged, overrides);
        Ok(serde_json::from_value(merged)?)
    }

    /// BLAKE3 hex digest over the canonical encoding of every resolved
    /// parameter. See the module docs.
    ///
    /// # Panics
    /// Never in practice: every field serializes to JSON.
    #[must_use]
    pub fn profile_hash(&self) -> String {
        let v = serde_json::to_value(self).expect("a belief profile always serializes");
        let mut buf = Vec::from(HASH_DOMAIN);
        canonical_encode(&v, &mut buf);
        epigraph_crypto::ContentHasher::to_hex(&epigraph_crypto::ContentHasher::hash(&buf))
    }

    /// True iff `evidence_type` resolves to a calibrated weight, directly or
    /// through an alias. Same rule as
    /// [`CalibrationConfig::evidence_type_weight_present`].
    #[must_use]
    pub fn evidence_type_weight_present(&self, evidence_type: &str) -> bool {
        let key = evidence_type.to_lowercase();
        let r = &self.reliability;
        r.evidence_type_weights.contains_key(&key)
            || r.evidence_type_aliases
                .get(&key)
                .is_some_and(|c| r.evidence_type_weights.contains_key(c))
    }

    /// The calibrated weight for `evidence_type` (direct, then alias), else
    /// the unknown-type weight. Same rule as
    /// [`CalibrationConfig::get_evidence_type_weight`].
    #[must_use]
    pub fn evidence_type_weight(&self, evidence_type: &str) -> f64 {
        let key = evidence_type.to_lowercase();
        let r = &self.reliability;
        if let Some(&w) = r.evidence_type_weights.get(&key) {
            return w;
        }
        if let Some(&w) = r
            .evidence_type_aliases
            .get(&key)
            .and_then(|c| r.evidence_type_weights.get(c))
        {
            return w;
        }
        r.unknown_evidence_type_weight
    }

    /// Methodology profile `(support, against, ignorance)`: direct, alias,
    /// the `default` row, then the fallback. Same rule as
    /// [`CalibrationConfig::get_methodology_profile`].
    #[must_use]
    pub fn methodology_profile(&self, methodology: &str) -> (f64, f64, f64) {
        let t = &self.tables;
        let key = methodology.to_lowercase();
        let p = t
            .methodology_profiles
            .get(&key)
            .or_else(|| {
                t.methodology_aliases
                    .get(&key)
                    .and_then(|c| t.methodology_profiles.get(c))
            })
            .or_else(|| t.methodology_profiles.get("default"))
            .unwrap_or(&t.methodology_fallback);
        let [support, against, ignorance] = *p;
        (support, against, ignorance)
    }
}

/// The evidence types an override object names under
/// `reliability.evidence_type_weights` (set or removed).
fn named_evidence_type_weights(overrides: &Value) -> impl Iterator<Item = &String> {
    overrides
        .get("reliability")
        .and_then(|r| r.get("evidence_type_weights"))
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(Map::keys)
}

/// RFC 7386 merge patch.
fn merge_patch(target: &mut Value, patch: &Value) {
    if let Value::Object(p) = patch {
        if !target.is_object() {
            *target = Value::Object(Map::new());
        }
        let t = target.as_object_mut().expect("just made an object");
        for (k, v) in p {
            if v.is_null() {
                t.remove(k);
            } else {
                merge_patch(t.entry(k.clone()).or_insert(Value::Null), v);
            }
        }
    } else {
        *target = patch.clone();
    }
}

/// Parameters whose range is not `[0, 1]`.
fn range_of(path: &str) -> (&'static str, fn(f64) -> bool) {
    match path {
        "forecast.overdue_grace_days" => {
            ("a whole number of days", |x| x >= 0.0 && x.fract() == 0.0)
        }
        "test_selection.testimony_interest" => ("a finite weight >= 0", |x| x >= 0.0),
        _ => ("[0, 1]", |x| (0.0..=1.0).contains(&x)),
    }
}

/// Every number in an override object must be finite and in its parameter's
/// range. Map keys are part of the path, so a weight inside a map is checked
/// like any other weight.
fn check_ranges(v: &Value, path: &mut Vec<String>) -> Result<(), ProfileError> {
    match v {
        Value::Object(m) => {
            for (k, child) in m {
                path.push(k.clone());
                check_ranges(child, path)?;
                path.pop();
            }
        }
        Value::Array(a) => {
            for child in a {
                check_ranges(child, path)?;
            }
        }
        Value::Number(n) => {
            let x = n.as_f64().unwrap_or(f64::NAN);
            let joined = path.join(".");
            let (range, ok) = range_of(&joined);
            if !x.is_finite() || !ok(x) {
                return Err(ProfileError::OutOfRange {
                    path: joined,
                    value: x,
                    range,
                });
            }
        }
        _ => {}
    }
    Ok(())
}

/// Canonical, self-delimiting byte encoding of a JSON value: object keys
/// sorted, every string and container length-prefixed, floats as their bit
/// pattern with `-0.0` read as `0.0`. Independent of `serde_json`'s map
/// ordering feature.
fn canonical_encode(v: &Value, out: &mut Vec<u8>) {
    fn len(n: usize, out: &mut Vec<u8>) {
        out.extend_from_slice(&(n as u64).to_le_bytes());
    }
    match v {
        Value::Null => out.push(b'n'),
        Value::Bool(b) => out.push(if *b { b't' } else { b'f' }),
        Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                out.push(b'u');
                out.extend_from_slice(&u.to_le_bytes());
            } else if let Some(i) = n.as_i64() {
                out.push(b'i');
                out.extend_from_slice(&i.to_le_bytes());
            } else {
                let x = n.as_f64().unwrap_or(f64::NAN);
                // belief-profile: allow-literal (reads -0.0 as 0.0 in the hash encoding)
                let x = if x == 0.0 { 0.0 } else { x };
                out.push(b'd');
                out.extend_from_slice(&x.to_bits().to_le_bytes());
            }
        }
        Value::String(s) => {
            out.push(b's');
            len(s.len(), out);
            out.extend_from_slice(s.as_bytes());
        }
        Value::Array(a) => {
            out.push(b'[');
            len(a.len(), out);
            for x in a {
                canonical_encode(x, out);
            }
        }
        Value::Object(m) => {
            out.push(b'{');
            len(m.len(), out);
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            for k in keys {
                out.push(b's');
                len(k.len(), out);
                out.extend_from_slice(k.as_bytes());
                canonical_encode(&m[k], out);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_scalars_equal_the_constants_they_replace() {
        // The values the fold paths carried as literals before the profile.
        let p = BeliefProfile::builtin();
        assert_eq!(p.reliability.unknown_evidence_type_weight, 0.5);
        assert_eq!(p.reliability.cross_locality_factor, 1.0);
        assert_eq!(p.reliability.intra_evidence_locality_factor, 0.3);
        assert_eq!(p.combination.conflict_threshold, 0.9);
        assert_eq!(p.edge_factor.open_world_fraction_default, 0.5);
        assert_eq!(p.edge_factor.vacuous_width, 0.999);
        assert_eq!(p.edge_factor.vacuous_belief, 0.01);
        assert_eq!(p.gates.confirmed_score, 0.75);
        assert_eq!(p.tables.methodology_fallback, [0.50, 0.08, 0.42]);
        assert_eq!(p.tables.default_journal_reliability, 0.78);
        assert_eq!(p.construction.simple_support_mass_min, 0.01);
        assert_eq!(p.construction.simple_support_mass_max, 0.99);
        assert_eq!(p.construction.truth_seed_min, 0.005);
        assert_eq!(p.construction.truth_seed_max, 0.995);
    }

    #[test]
    fn new_parameters_carry_the_addendum_defaults() {
        let p = BeliefProfile::builtin();
        assert_eq!(p.testimonial_ceiling, 0.1);
        assert_eq!(
            p.testimonial_when_evidenced,
            TestimonialWhenEvidenced::Suppress
        );
        assert_eq!(p.testimonial_grouping, TestimonialGrouping::Class);
        assert_eq!(
            p.within_group_rule,
            WithinGroupRule::MaxSameDempsterOpposite
        );
        assert_eq!(p.forecast.pre_resolution_ceiling, 0.1);
        assert_eq!(p.forecast.model_weight, 0.5);
        assert_eq!(p.forecast.overdue_grace_days, 30);
        assert_eq!(p.necessity.sources, vec![NecessitySource::Explicit]);
        assert_eq!(p.necessity.default_strength, 0.0);
        assert_eq!(p.test_selection.testimony_interest, 1.0);
        assert_eq!(p.class_weight.primary, 1.0);
        assert_eq!(p.class_weight.reported, 0.6);
    }

    #[test]
    fn an_invalid_override_is_rejected_whole_and_the_tier_below_stands() {
        let base = BeliefProfile::builtin();
        // Out of range.
        let e = base
            .with_overrides(&serde_json::json!({"testimonial_ceiling": 1.5}))
            .unwrap_err();
        assert!(matches!(e, ProfileError::OutOfRange { .. }), "{e}");
        // Unknown parameter.
        assert!(base
            .with_overrides(&serde_json::json!({"testimonial_cieling": 0.2}))
            .is_err());
        // Lens is not overridable.
        assert!(matches!(
            base.with_overrides(&serde_json::json!({"lens": {}})),
            Err(ProfileError::LensNotOverridable)
        ));
        // A bad override inside resolve leaves the profile unchanged, and a
        // valid half of a mixed object is NOT applied (whole-tier rejection).
        let bad =
            serde_json::json!({"testimonial_ceiling": 0.2, "forecast": {"model_weight": 7.0}});
        let resolved = base.resolve(
            FrameTier::default(),
            PerspectiveTier {
                overrides: Some(&bad),
                reliability: None,
            },
        );
        assert_eq!(resolved, base);
    }

    #[test]
    fn overrides_merge_maps_by_key_and_null_removes_an_entry() {
        let mut base = BeliefProfile::builtin();
        base.reliability
            .evidence_type_weights
            .insert("empirical".into(), 1.0);
        base.reliability
            .evidence_type_weights
            .insert("logical".into(), 0.85);
        let p = base
            .with_overrides(&serde_json::json!({
                "reliability": {"evidence_type_weights": {"logical": 0.5, "empirical": null}},
                "testimonial_when_evidenced": {"weight": 0.25}
            }))
            .unwrap();
        assert_eq!(
            p.reliability.evidence_type_weights,
            BTreeMap::from([("logical".to_string(), 0.5)])
        );
        assert_eq!(
            p.testimonial_when_evidenced,
            TestimonialWhenEvidenced::Weight(0.25)
        );
        // Everything not named is untouched.
        assert_eq!(p.reliability.intra_evidence_locality_factor, 0.3);
    }

    #[test]
    fn the_dedicated_frame_key_wins_over_the_generic_frame_object() {
        let base = BeliefProfile::builtin();
        let generic = serde_json::json!({"reliability": {"intra_evidence_locality_factor": 0.8}});
        let p = base.resolve(
            FrameTier {
                overrides: Some(&generic),
                intra_evidence_locality_factor: Some(0.45),
                evidence_type_weights: None,
            },
            PerspectiveTier::default(),
        );
        assert_eq!(p.reliability.intra_evidence_locality_factor, 0.45);
        // And the perspective tier sits above both.
        let persp = serde_json::json!({"reliability": {"intra_evidence_locality_factor": 0.2}});
        let q = base.resolve(
            FrameTier {
                overrides: Some(&generic),
                intra_evidence_locality_factor: Some(0.45),
                evidence_type_weights: None,
            },
            PerspectiveTier {
                overrides: Some(&persp),
                reliability: None,
            },
        );
        assert_eq!(q.reliability.intra_evidence_locality_factor, 0.2);
    }

    #[test]
    fn profile_lookups_agree_with_the_calibration_lookups_they_mirror() {
        let cal = CalibrationConfig::cached();
        let p = BeliefProfile::from_calibration(cal);
        for key in [
            "empirical",
            "EMPIRICAL",
            "testimony",
            "supports",
            "derived_support",
            "corroborates",
            "mystery",
            "",
        ] {
            assert_eq!(
                p.evidence_type_weight_present(key),
                cal.evidence_type_weight_present(key),
                "{key}"
            );
            assert_eq!(
                p.evidence_type_weight(key).to_bits(),
                cal.get_evidence_type_weight(key).to_bits(),
                "{key}"
            );
        }
        for m in [
            "deductive",
            "Meta-Analysis",
            "statistical_analysis",
            "nonsense",
        ] {
            assert_eq!(
                p.methodology_profile(m),
                cal.get_methodology_profile(m),
                "{m}"
            );
        }
    }
}
