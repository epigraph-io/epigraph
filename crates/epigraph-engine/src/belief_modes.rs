//! The belief-mode switches this process runs under, read once at startup
//! (SPEC §10.2).
//!
//! Atom-level belief is rolled out behind seven environment flags. Because a
//! process reads them **once, at startup**, a flag flip is a restart window
//! over N processes, not an atomic switch, and a process that was never
//! restarted keeps running the old mode.
//!
//! This module is the one place the flags are parsed, so every process
//! derives the same [`BeliefModes`] from the same environment. In this build
//! they are read by:
//!
//! - the API server and the HTTP and stdio MCP servers, which journal them at
//!   boot and report [`current`] on `/health` → `belief_modes` and
//!   `system_stats` → `belief_modes`; the pre-flip mode check (SPEC §10.4)
//!   compares those reports across live processes;
//! - the CLI wave bins `recompute_betp`, `backfill_factors` and
//!   `decompose_claims --retarget`, which compare their own [`current`] with
//!   the API's report before a writing run ([`BeliefModes::skew`]).
//!
//! No other process reads them yet: the job runner (`drain_jobs`),
//! `recompute_claim_belief` and the other belief writers act on no flag in
//! this build. Each starts reading [`current`], and journals it at boot, in
//! the change that makes it act on one.
//!
//! # Defaults, and what this build acts on
//!
//! Every default is the mode the rollout starts from. With every flag unset
//! this build behaves exactly as the build before it did: reading and
//! reporting a flag changes nothing by itself.
//!
//! | flag | values | default | acted on in this build |
//! |---|---|---|---|
//! | `EPIGRAPH_ATOM_FOLD` | `legacy`, `aef_standalone`, `aef` | `legacy` | only by the CLI wave bins that fold caches, which refuse a writing run under any fold but `legacy` |
//! | `EPIGRAPH_COMPOUND_BELIEF` | `legacy`, `shadow`, `progressive`, `strict` | `legacy` | no |
//! | `EPIGRAPH_COMPOUND_WRITE_GUARD` | `warn`, `refuse` | `warn` | no: a textless BBA write on a compound is neither kept inert nor logged yet |
//! | `EPIGRAPH_COMPOUND_SOURCE_EDGES` | `frozen`, `excluded` | `frozen` | no |
//! | `EPIGRAPH_ATOM_CACHE_MODE` | `display`, `pure` | `display` | no |
//! | `EPIGRAPH_INFERENCE` | `off`, `shadow`, `on` | `off` | no |
//! | `EPIGRAPH_BP_APPLY` | `off`, `on` | `off` | no: a BP request with `apply_updates: true` still writes its results |
//!
//! The value docs below say what each mode means once the change that acts on
//! it lands. Until then a reported mode is configuration, not behaviour:
//! `bp_apply: off` on `/health` does not mean BP apply is refused. Each flag is
//! wired into its code path by the change that introduces the behaviour, which
//! reads [`current`] rather than parsing the environment again; this module
//! only guarantees that every process reads and reports the flags alike.
//!
//! # Parsing
//!
//! A value is matched trimmed and case-insensitively against the spellings
//! above. Unset or blank is the default. Anything else also reads as the
//! default, and is returned in [`ModeRead::unrecognised`] (for this process,
//! [`unrecognised`]) so the process can warn at boot: a typo must not
//! silently enable a mode, and the report on `/health` then shows the mode
//! the process actually runs, which is what the pre-flip check compares.

use std::fmt;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

/// Defines one flag's enum: its wire spellings (also its serde form), its
/// environment variable and its default.
macro_rules! belief_mode {
    (
        $(#[$meta:meta])*
        $name:ident, env = $env:literal, default = $default:ident,
        { $( $(#[$vmeta:meta])* $variant:ident => $wire:literal ),+ $(,)? }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        pub enum $name {
            $( $(#[$vmeta])* #[serde(rename = $wire)] $variant, )+
        }

        impl $name {
            /// The environment variable this flag is read from.
            pub const ENV: &'static str = $env;
            /// Every value, in declaration order.
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];

            /// The wire spelling, as `/health` reports it.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $wire,)+
                }
            }

            /// Parse one value: trimmed, case-insensitive, `None` when it is
            /// none of this flag's spellings.
            #[must_use]
            pub fn parse_value(raw: &str) -> Option<Self> {
                let value = raw.trim();
                Self::ALL
                    .iter()
                    .copied()
                    .find(|mode| value.eq_ignore_ascii_case(mode.as_str()))
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::$default
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }
    };
}

belief_mode! {
    /// Which fold writes an atom's cache: today's per-site folds, the atom
    /// evidence fold (AEF) for standalone atoms only, or AEF for every atom.
    AtomFold, env = "EPIGRAPH_ATOM_FOLD", default = Legacy, {
        /// Today's per-site folds.
        Legacy => "legacy",
        /// AEF for standalones; leaves keep the legacy fold.
        AefStandalone => "aef_standalone",
        /// AEF for every atom.
        Aef => "aef",
    }
}

belief_mode! {
    /// How a compound's belief is served.
    CompoundBelief, env = "EPIGRAPH_COMPOUND_BELIEF", default = Legacy, {
        /// Today's own-fold value.
        Legacy => "legacy",
        /// Legacy value served; the derived value is computed alongside.
        Shadow => "shadow",
        /// Derived where its leaves are ready, legacy otherwise.
        Progressive => "progressive",
        /// Derived only.
        Strict => "strict",
    }
}

belief_mode! {
    /// What a textless BBA write aimed at a compound does. Reported only in
    /// this build (see the module doc); the variants describe the enforced
    /// meaning.
    CompoundWriteGuard, env = "EPIGRAPH_COMPOUND_WRITE_GUARD", default = Warn, {
        /// Accepted, kept inert, the caller warned and logged.
        Warn => "warn",
        /// Refused.
        Refuse => "refuse",
    }
}

belief_mode! {
    /// How an atom's display fold reads edge-factor BBAs whose source is a
    /// compound.
    CompoundSourceEdges, env = "EPIGRAPH_COMPOUND_SOURCE_EDGES", default = Frozen, {
        /// Read, one-sided.
        Frozen => "frozen",
        /// Left out.
        Excluded => "excluded",
    }
}

belief_mode! {
    /// What an atom's cache holds.
    AtomCacheMode, env = "EPIGRAPH_ATOM_CACHE_MODE", default = Display, {
        /// Axioms plus atom-to-atom edge factors.
        Display => "display",
        /// Axioms only.
        Pure => "pure",
    }
}

belief_mode! {
    /// The forward-inference layer.
    Inference, env = "EPIGRAPH_INFERENCE", default = Off, {
        /// Not run.
        Off => "off",
        /// Run and stored, not served.
        Shadow => "shadow",
        /// Served.
        On => "on",
    }
}

belief_mode! {
    /// Whether a belief-propagation run may write its results to claims.
    /// Reported only in this build (see the module doc); the variants describe
    /// the enforced meaning.
    BpApply, env = "EPIGRAPH_BP_APPLY", default = Off, {
        /// BP results are not written.
        Off => "off",
        /// BP results may be written to atoms.
        On => "on",
    }
}

/// The seven belief modes of one process, as `/health` and `system_stats`
/// report them.
///
/// Deserialising refuses an unknown field as well as a missing one: a report
/// carrying a mode this build does not know cannot be compared with this
/// build's modes, and a caller comparing them must treat that as a mismatch,
/// not as agreement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BeliefModes {
    pub atom_fold: AtomFold,
    pub compound_belief: CompoundBelief,
    pub compound_write_guard: CompoundWriteGuard,
    pub compound_source_edges: CompoundSourceEdges,
    pub atom_cache_mode: AtomCacheMode,
    pub inference: Inference,
    pub bp_apply: BpApply,
}

/// One flag's place in a [`BeliefModes`]: its report key, its environment
/// variable and its value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModeField {
    /// The key under `belief_modes`.
    pub key: &'static str,
    /// The environment variable.
    pub env: &'static str,
    /// The value's wire spelling.
    pub value: &'static str,
}

/// A flag set to a value none of its spellings match. The process runs the
/// flag's default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnrecognisedFlag {
    /// The environment variable.
    pub env: &'static str,
    /// What it was set to.
    pub value: String,
    /// The default the process runs instead.
    pub running: &'static str,
}

/// What [`BeliefModes::from_lookup`] read: the modes, and every flag whose
/// value was not recognised.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModeRead {
    pub modes: BeliefModes,
    pub unrecognised: Vec<UnrecognisedFlag>,
}

/// One mode on which two processes differ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModeSkew {
    /// The key under `belief_modes`.
    pub key: &'static str,
    /// The environment variable that sets it.
    pub env: &'static str,
    /// This side's value.
    pub ours: &'static str,
    /// The other side's value.
    pub theirs: &'static str,
}

impl fmt::Display for ModeSkew {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: this process runs {}, the server runs {} (set by {})",
            self.key, self.ours, self.theirs, self.env
        )
    }
}

/// Read one flag through `lookup`, recording an unrecognised value.
fn read_flag<T: Copy + Default>(
    lookup: &impl Fn(&str) -> Option<String>,
    env: &'static str,
    parse: fn(&str) -> Option<T>,
    as_str: fn(T) -> &'static str,
    unrecognised: &mut Vec<UnrecognisedFlag>,
) -> T {
    let Some(raw) = lookup(env) else {
        return T::default();
    };
    if raw.trim().is_empty() {
        return T::default();
    }
    parse(&raw).unwrap_or_else(|| {
        let running = T::default();
        unrecognised.push(UnrecognisedFlag {
            env,
            value: raw,
            running: as_str(running),
        });
        running
    })
}

impl BeliefModes {
    /// The modes `lookup` (an environment) describes. Pure: [`Self::from_env`]
    /// is this over the process environment.
    #[must_use]
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> ModeRead {
        let mut unrecognised = Vec::new();
        let modes = Self {
            atom_fold: read_flag(
                &lookup,
                AtomFold::ENV,
                AtomFold::parse_value,
                AtomFold::as_str,
                &mut unrecognised,
            ),
            compound_belief: read_flag(
                &lookup,
                CompoundBelief::ENV,
                CompoundBelief::parse_value,
                CompoundBelief::as_str,
                &mut unrecognised,
            ),
            compound_write_guard: read_flag(
                &lookup,
                CompoundWriteGuard::ENV,
                CompoundWriteGuard::parse_value,
                CompoundWriteGuard::as_str,
                &mut unrecognised,
            ),
            compound_source_edges: read_flag(
                &lookup,
                CompoundSourceEdges::ENV,
                CompoundSourceEdges::parse_value,
                CompoundSourceEdges::as_str,
                &mut unrecognised,
            ),
            atom_cache_mode: read_flag(
                &lookup,
                AtomCacheMode::ENV,
                AtomCacheMode::parse_value,
                AtomCacheMode::as_str,
                &mut unrecognised,
            ),
            inference: read_flag(
                &lookup,
                Inference::ENV,
                Inference::parse_value,
                Inference::as_str,
                &mut unrecognised,
            ),
            bp_apply: read_flag(
                &lookup,
                BpApply::ENV,
                BpApply::parse_value,
                BpApply::as_str,
                &mut unrecognised,
            ),
        };
        ModeRead {
            modes,
            unrecognised,
        }
    }

    /// The modes the process environment describes, read now. Processes use
    /// [`current`], which reads this once.
    #[must_use]
    pub fn from_env() -> ModeRead {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    /// Every flag, in report order.
    #[must_use]
    pub const fn fields(&self) -> [ModeField; 7] {
        [
            ModeField {
                key: "atom_fold",
                env: AtomFold::ENV,
                value: self.atom_fold.as_str(),
            },
            ModeField {
                key: "compound_belief",
                env: CompoundBelief::ENV,
                value: self.compound_belief.as_str(),
            },
            ModeField {
                key: "compound_write_guard",
                env: CompoundWriteGuard::ENV,
                value: self.compound_write_guard.as_str(),
            },
            ModeField {
                key: "compound_source_edges",
                env: CompoundSourceEdges::ENV,
                value: self.compound_source_edges.as_str(),
            },
            ModeField {
                key: "atom_cache_mode",
                env: AtomCacheMode::ENV,
                value: self.atom_cache_mode.as_str(),
            },
            ModeField {
                key: "inference",
                env: Inference::ENV,
                value: self.inference.as_str(),
            },
            ModeField {
                key: "bp_apply",
                env: BpApply::ENV,
                value: self.bp_apply.as_str(),
            },
        ]
    }

    /// Every mode on which `self` (this process) and `theirs` (another
    /// process, typically the API server) differ, in report order. Empty
    /// exactly when the two are equal.
    #[must_use]
    pub fn skew(&self, theirs: &Self) -> Vec<ModeSkew> {
        self.fields()
            .into_iter()
            .zip(theirs.fields())
            .filter(|(ours, other)| ours.value != other.value)
            .map(|(ours, other)| ModeSkew {
                key: ours.key,
                env: ours.env,
                ours: ours.value,
                theirs: other.value,
            })
            .collect()
    }

    /// One line naming every mode, for a boot log.
    #[must_use]
    pub fn summary(&self) -> String {
        self.fields()
            .iter()
            .map(|f| format!("{}={}", f.key, f.value))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

impl fmt::Display for UnrecognisedFlag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}={:?} is not a recognised value; this process runs {}",
            self.env, self.value, self.running
        )
    }
}

static CURRENT: OnceLock<ModeRead> = OnceLock::new();

/// The one read of the process environment, made on first use.
fn read_once() -> &'static ModeRead {
    CURRENT.get_or_init(BeliefModes::from_env)
}

/// This process's belief modes, read from the environment the first time it
/// (or [`unrecognised`]) is called and never again (SPEC §10.2: flags are read
/// at startup; a flip takes a restart).
///
/// A process should call this early in `main` and log [`BeliefModes::summary`]
/// and every [`unrecognised`] flag under its OWN log target, so the modes are
/// fixed and journalled at boot rather than at the first request that happens
/// to read them. This module logs nothing itself: a process's default log
/// filter keeps its own target, not necessarily this crate's, and a typo the
/// filter drops is a typo nobody sees.
pub fn current() -> &'static BeliefModes {
    &read_once().modes
}

/// The flags of the same read as [`current`] whose values none of their
/// spellings match. Each runs its default; the process reports them at boot.
pub fn unrecognised() -> &'static [UnrecognisedFlag] {
    &read_once().unrecognised
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn lookup(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        move |key| map.get(key).cloned()
    }

    /// Every value of every flag, as (env, wire spelling) pairs.
    fn every_value() -> Vec<(&'static str, &'static str)> {
        let mut out = Vec::new();
        out.extend(AtomFold::ALL.iter().map(|m| (AtomFold::ENV, m.as_str())));
        out.extend(
            CompoundBelief::ALL
                .iter()
                .map(|m| (CompoundBelief::ENV, m.as_str())),
        );
        out.extend(
            CompoundWriteGuard::ALL
                .iter()
                .map(|m| (CompoundWriteGuard::ENV, m.as_str())),
        );
        out.extend(
            CompoundSourceEdges::ALL
                .iter()
                .map(|m| (CompoundSourceEdges::ENV, m.as_str())),
        );
        out.extend(
            AtomCacheMode::ALL
                .iter()
                .map(|m| (AtomCacheMode::ENV, m.as_str())),
        );
        out.extend(Inference::ALL.iter().map(|m| (Inference::ENV, m.as_str())));
        out.extend(BpApply::ALL.iter().map(|m| (BpApply::ENV, m.as_str())));
        out
    }

    fn value_of(modes: &BeliefModes, env: &str) -> &'static str {
        modes
            .fields()
            .into_iter()
            .find(|f| f.env == env)
            .map(|f| f.value)
            .expect("a known flag")
    }

    /// Unset flags are today's behaviour (SPEC §10.2): this is the table the
    /// rollout's "no flag, no change" guarantee rests on, spelled out.
    #[test]
    fn an_empty_environment_reads_as_todays_behaviour() {
        let read = BeliefModes::from_lookup(|_| None);
        assert!(read.unrecognised.is_empty());
        assert_eq!(read.modes, BeliefModes::default());
        assert_eq!(
            serde_json::to_value(read.modes).unwrap(),
            serde_json::json!({
                "atom_fold": "legacy",
                "compound_belief": "legacy",
                "compound_write_guard": "warn",
                "compound_source_edges": "frozen",
                "atom_cache_mode": "display",
                "inference": "off",
                "bp_apply": "off",
            })
        );
    }

    /// Every (variable, value, report key) of the SPEC §10.2 flag table, typed
    /// out here as literals rather than taken from the enums: a spelling the
    /// macro got wrong must not be able to agree with itself. Each value set
    /// in the environment is recognised and reported under its key as the
    /// same spelling, and the table covers every flag the report carries.
    #[test]
    fn every_spec_spelling_is_recognised_and_reported_as_spelled() {
        const TABLE: &[(&str, &str, &[&str])] = &[
            (
                "EPIGRAPH_ATOM_FOLD",
                "atom_fold",
                &["legacy", "aef_standalone", "aef"],
            ),
            (
                "EPIGRAPH_COMPOUND_BELIEF",
                "compound_belief",
                &["legacy", "shadow", "progressive", "strict"],
            ),
            (
                "EPIGRAPH_COMPOUND_WRITE_GUARD",
                "compound_write_guard",
                &["warn", "refuse"],
            ),
            (
                "EPIGRAPH_COMPOUND_SOURCE_EDGES",
                "compound_source_edges",
                &["frozen", "excluded"],
            ),
            (
                "EPIGRAPH_ATOM_CACHE_MODE",
                "atom_cache_mode",
                &["display", "pure"],
            ),
            ("EPIGRAPH_INFERENCE", "inference", &["off", "shadow", "on"]),
            ("EPIGRAPH_BP_APPLY", "bp_apply", &["off", "on"]),
        ];
        for (env, key, values) in TABLE {
            for value in *values {
                let read = BeliefModes::from_lookup(lookup(&[(env, value)]));
                assert!(read.unrecognised.is_empty(), "{env}={value} not recognised");
                let report = serde_json::to_value(read.modes).unwrap();
                assert_eq!(report[*key], *value, "{env}={value} reported as {report}");
            }
        }
        let report = serde_json::to_value(BeliefModes::default()).unwrap();
        let mut keys: Vec<&str> = report
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        let mut table_keys: Vec<&str> = TABLE.iter().map(|(_, key, _)| *key).collect();
        keys.sort_unstable();
        table_keys.sort_unstable();
        assert_eq!(
            keys, table_keys,
            "the report carries exactly the SPEC's flags"
        );
    }

    /// Every spelling of every flag is read back as itself whatever its case
    /// and padding, and moves only its own flag.
    #[test]
    fn every_value_is_read_case_insensitively_and_moves_only_its_own_flag() {
        let defaults = BeliefModes::default();
        for (env, wire) in every_value() {
            for spelled in [
                wire.to_string(),
                wire.to_uppercase(),
                format!("  {}\t", wire.to_uppercase()),
            ] {
                let read = BeliefModes::from_lookup(lookup(&[(env, &spelled)]));
                assert!(read.unrecognised.is_empty(), "{env}={spelled:?}");
                assert_eq!(value_of(&read.modes, env), wire, "{env}={spelled:?}");
                for other in read.modes.fields() {
                    if other.env != env {
                        assert_eq!(
                            other.value,
                            value_of(&defaults, other.env),
                            "{env}={spelled:?} moved {}",
                            other.env
                        );
                    }
                }
            }
        }
    }

    /// A value that is no spelling of its flag reads as the default, and is
    /// reported so the process can warn. Values an operator might type for
    /// "yes" do not enable anything. Blank is the plain default, not a typo.
    #[test]
    fn an_unrecognised_value_runs_the_default_and_is_reported() {
        let defaults = BeliefModes::default();
        for env in BeliefModes::default().fields().map(|f| f.env) {
            for typo in ["true", "1", "yes", "enabled", "aef-standalone", "o n"] {
                let read = BeliefModes::from_lookup(lookup(&[(env, typo)]));
                assert_eq!(read.modes, defaults, "{env}={typo:?}");
                assert_eq!(
                    read.unrecognised,
                    vec![UnrecognisedFlag {
                        env,
                        value: typo.to_string(),
                        running: value_of(&defaults, env),
                    }],
                    "{env}={typo:?}"
                );
            }
            for blank in ["", "   "] {
                let read = BeliefModes::from_lookup(lookup(&[(env, blank)]));
                assert_eq!(read.modes, defaults);
                assert!(read.unrecognised.is_empty(), "{env}={blank:?}");
            }
        }
    }

    /// `base` with exactly field `i` moved to a different value.
    fn with_field_moved(base: BeliefModes, i: usize) -> BeliefModes {
        fn next<T: Copy + PartialEq>(all: &[T], v: T) -> T {
            *all.iter().find(|x| **x != v).expect("two or more values")
        }
        let mut m = base;
        match i {
            0 => m.atom_fold = next(AtomFold::ALL, m.atom_fold),
            1 => m.compound_belief = next(CompoundBelief::ALL, m.compound_belief),
            2 => m.compound_write_guard = next(CompoundWriteGuard::ALL, m.compound_write_guard),
            3 => {
                m.compound_source_edges = next(CompoundSourceEdges::ALL, m.compound_source_edges);
            }
            4 => m.atom_cache_mode = next(AtomCacheMode::ALL, m.atom_cache_mode),
            5 => m.inference = next(Inference::ALL, m.inference),
            6 => m.bp_apply = next(BpApply::ALL, m.bp_apply),
            _ => unreachable!(),
        }
        m
    }

    /// Moving any ONE mode makes `skew` report exactly that mode, with both
    /// values, from either side; moving none reports nothing. A comparison
    /// that skipped a field would let that flag's skew through the mode check.
    #[test]
    fn skew_names_exactly_the_modes_that_differ() {
        let base = BeliefModes::default();
        assert!(base.skew(&base).is_empty());
        let keys = base.fields().map(|f| f.key);
        for (i, key) in keys.iter().enumerate() {
            let moved = with_field_moved(base, i);
            let ours = base.skew(&moved);
            assert_eq!(ours.len(), 1, "moving {key} must give one skew: {ours:?}");
            assert_eq!(ours[0].key, *key);
            assert_ne!(ours[0].ours, ours[0].theirs);
            let theirs = moved.skew(&base);
            assert_eq!(theirs.len(), 1);
            assert_eq!(
                (theirs[0].ours, theirs[0].theirs),
                (ours[0].theirs, ours[0].ours)
            );
        }
        // And all seven at once are all reported, in report order.
        let mut all = base;
        for i in 0..keys.len() {
            all = with_field_moved(all, i);
        }
        let skew = base.skew(&all);
        assert_eq!(skew.iter().map(|s| s.key).collect::<Vec<_>>(), keys);
    }

    /// The report a process publishes is read back as the same modes, and a
    /// report this build cannot fully understand is refused rather than
    /// half-read: a missing mode, an extra mode or an unknown value.
    #[test]
    fn a_report_parses_only_when_it_carries_exactly_the_known_modes() {
        let mut modes = BeliefModes::default();
        for i in 0..7 {
            modes = with_field_moved(modes, i);
        }
        let wire = serde_json::to_value(modes).unwrap();
        assert_eq!(
            serde_json::from_value::<BeliefModes>(wire.clone()).unwrap(),
            modes
        );

        let mut missing = wire.clone();
        missing.as_object_mut().unwrap().remove("inference");
        assert!(serde_json::from_value::<BeliefModes>(missing).is_err());

        let mut extra = wire.clone();
        extra
            .as_object_mut()
            .unwrap()
            .insert("future_mode".into(), serde_json::json!("on"));
        assert!(serde_json::from_value::<BeliefModes>(extra).is_err());

        let mut unknown = wire;
        unknown["atom_fold"] = serde_json::json!("aef_everything");
        assert!(serde_json::from_value::<BeliefModes>(unknown).is_err());
    }
}
