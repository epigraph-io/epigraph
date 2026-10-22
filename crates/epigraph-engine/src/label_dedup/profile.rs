//! The `label-dedup-profile/v2` schema: every piece of deployment data the
//! engine uses, passed by reference and pinned by hash.
//!
//! Every list defaults to empty. The defaults that do exist are generic
//! algorithm knobs: the 0.8 overlap thresholds, the 3-token fuzzy floor, the
//! 6-char / 2-digit strong-id rule, the parser's layout limits and the tier
//! order. Unknown keys are refused, so a misspelt key is an error rather than
//! a silently ignored rule.
//!
//! Write templates may use these placeholders, each only where it has a value:
//! `{run_tag}`, `{family}` (the family label of the pass the write belongs to),
//! and `{target}` (graduation and supersession). `{survivor}` is bound in no
//! write a profile declares (losers are marked, not relabelled) and is refused.

use std::collections::BTreeMap;

use regex::Regex;
use serde::{Deserialize, Serialize};

use super::{LabelDedupError, Section};

/// The only schema id this engine accepts.
pub const PROFILE_SCHEMA: &str = "label-dedup-profile/v2";

/// BLAKE3 of the exact profile bytes, lowercase hex. The pin a workflow step
/// records, and the value `profile_hash` arguments are checked against.
#[must_use]
pub fn profile_hash(bytes: &[u8]) -> String {
    epigraph_crypto::ContentHasher::to_hex(&epigraph_crypto::ContentHasher::hash(bytes))
}

/// A parsed, validated profile.
#[derive(Debug, Clone)]
pub struct LabelDedupProfile {
    pub schema: String,
    /// The main family pass (all top-level pass keys).
    pub pass: PassProfile,
    pub closeout: Option<CloseoutSpec>,
    pub lifecycle: Option<LifecycleSpec>,
    /// A second family deduplicated on its own (its own `family_label`).
    pub signal_dedup: Option<PassProfile>,
    pub signal_superseded_by_member: Option<SupersedeSpec>,
}

/// The keys that configure one dedup pass over one family.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PassProfile {
    /// (required) The index key. Retirement removes it.
    pub family_label: String,
    /// (required) What the family is. Only an [`FamilyKind::Index`] is ever
    /// planned: label-only cleanup is bookkeeping on an operational index (a
    /// lead list, a signal list) and must never be pointed at a family of
    /// knowledge claims ([`LabelDedupError::FamilyNotIndex`](super::LabelDedupError::FamilyNotIndex)).
    pub family_kind: FamilyKind,
    /// Extra labels the member read excludes (the closed label is always
    /// excluded). Partial retirements must NOT be listed here: they have to be
    /// loaded so hygiene can see them.
    #[serde(default)]
    pub index_exclude_labels: Vec<String>,
    /// Members carrying it are closed: never members, never survivors.
    #[serde(default)]
    pub closed_label: Option<String>,
    /// A family member also carrying one of these is a partial retirement.
    #[serde(default)]
    pub retired_labels: Vec<String>,
    /// A leading `[FLAG]` (exact text) that marks retired content.
    #[serde(default)]
    pub content_retired_flags: Vec<String>,
    #[serde(default)]
    pub non_member: NonMemberSpec,
    /// Required when the hygiene section is planned. Must remove `{family}`.
    #[serde(default)]
    pub hygiene_write: Option<WriteTemplate>,
    #[serde(default)]
    pub flag: FlagSpec,
    #[serde(default)]
    pub fields: FieldsSpec,
    #[serde(default)]
    pub unknown: UnknownSpec,
    #[serde(default)]
    pub ids: IdSpec,
    #[serde(default)]
    pub entity_match: EntityMatchSpec,
    #[serde(default)]
    pub title_match: TitleMatchSpec,
    /// Enabled tiers. Their order of evaluation is fixed; omitting one
    /// disables it.
    #[serde(default = "Tier::all")]
    pub tiers: Vec<Tier>,
    /// `<prefix><id-prefix>` on either claim links a revision to its original.
    #[serde(default)]
    pub revision_label_prefix: Option<String>,
    /// `<prefix><id-prefix>` on either claim is a human ruling that the two
    /// are distinct: the pair never merges and is never queued for review.
    /// The id prefix must be at least
    /// [`MIN_DISTINCT_ID_PREFIX`](super::classify::MIN_DISTINCT_ID_PREFIX)
    /// characters; a shorter one is ignored.
    #[serde(default)]
    pub distinct_label_prefix: Option<String>,
    #[serde(default)]
    pub partition: PartitionSpec,
    #[serde(default)]
    pub precedence: PrecedenceSpec,
    /// Required when the dedup section is planned.
    #[serde(default)]
    pub merge: Option<MergeSpec>,
}

/// What a deduplicated family is. Declared by every pass, never inferred.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FamilyKind {
    /// An operational index (a lead list, a signal list): its members are
    /// bookkeeping, and label hygiene on it is allowed.
    Index,
    /// A family of knowledge claims. Refused: duplicates there are marked
    /// one by one through `mark_duplicate`, never by a label pass. It is the
    /// default, so an undeclared kind is never planned.
    #[default]
    Knowledge,
}

/// How a pair of claims was matched, strongest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    /// One claim carries `<revision_label_prefix><prefix of the other's id>`.
    RevisionLabel,
    /// The claims share a strong id.
    StrongId,
    /// The claims share any id and their entities match.
    WeakIdAndEntity,
    /// Identical normalized titles and matching entities.
    TitleAndEntity,
    /// Similar titles and matching entities: queued for a human, never merged.
    FuzzyReview,
}

impl Tier {
    #[must_use]
    pub fn all() -> Vec<Self> {
        vec![
            Self::RevisionLabel,
            Self::StrongId,
            Self::WeakIdAndEntity,
            Self::TitleAndEntity,
            Self::FuzzyReview,
        ]
    }

    /// Whether the tier merges without a human.
    #[must_use]
    pub const fn auto_merge(self) -> bool {
        !matches!(self, Self::FuzzyReview)
    }

    /// Larger is stronger.
    #[must_use]
    pub const fn strength(self) -> u8 {
        match self {
            Self::RevisionLabel => 4,
            Self::StrongId => 3,
            Self::WeakIdAndEntity => 2,
            Self::TitleAndEntity => 1,
            Self::FuzzyReview => 0,
        }
    }
}

/// Bookkeeping that wears the family label.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NonMemberSpec {
    #[serde(default)]
    pub labels_any: Vec<String>,
    /// Matched against the normalized, flag-stripped body.
    #[serde(default)]
    pub body_prefixes: Vec<String>,
    #[serde(default)]
    pub body_contains: Vec<String>,
    #[serde(default)]
    pub completion_report: Option<CompletionReportSpec>,
}

/// `<one of prefixes> … <one of requires_any> …` reads as a status report.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompletionReportSpec {
    #[serde(default)]
    pub prefixes: Vec<String>,
    #[serde(default)]
    pub requires_any: Vec<String>,
}

/// A label write template.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WriteTemplate {
    #[serde(default)]
    pub add: Vec<String>,
    #[serde(default)]
    pub remove: Vec<String>,
}

/// The leading `[FLAG]` of a content body.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlagSpec {
    #[serde(default = "default_flag_max_len")]
    pub max_len: usize,
    #[serde(default = "default_flag_max_words")]
    pub max_words: usize,
    /// Spelling → canonical value, both compared in normalized-dashed form.
    #[serde(default)]
    pub canonical: BTreeMap<String, String>,
}

impl Default for FlagSpec {
    fn default() -> Self {
        Self {
            max_len: default_flag_max_len(),
            max_words: default_flag_max_words(),
            canonical: BTreeMap::new(),
        }
    }
}

const fn default_flag_max_len() -> usize {
    20
}
const fn default_flag_max_words() -> usize {
    3
}

/// The record parser: a pipe layout (`title | entity | key: value | …`) with
/// a prose fallback (`<type>: <title> — <entity>, <marker> <value>, …`).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldsSpec {
    #[serde(default)]
    pub title: TitleSpec,
    #[serde(default)]
    pub entity: FieldSpec,
    #[serde(default)]
    pub deadline: FieldSpec,
    #[serde(default)]
    pub value: FieldSpec,
    #[serde(default)]
    pub class: FieldSpec,
    /// Pipe fields that are neither positional nor parsed.
    #[serde(default)]
    pub ignored_keys: Vec<String>,
    /// Further named fields (label-sourced or keyed).
    #[serde(default)]
    pub extra: BTreeMap<String, FieldSpec>,
}

/// Title extraction and the layout limits of both parsers.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TitleSpec {
    /// Position among the pipe fields left after keyed and ignored fields
    /// (and a leading header) are removed.
    #[serde(default)]
    pub pipe_position: usize,
    /// A pipe title `X: rest` with `X` this short and space-free is `rest`,
    /// and `X` becomes the entity when none is keyed.
    #[serde(default = "default_short_prefix_max")]
    pub strip_short_prefix_max: usize,
    /// A leading pipe field of at most this many words containing a header
    /// token is a header, not the title.
    #[serde(default = "default_pipe_header_words_max")]
    pub header_words_max: usize,
    #[serde(default)]
    pub header_tokens: Vec<String>,
    /// A prose body whose first `:` is within this many bytes has a type
    /// prefix (`Notice:`), which is stripped.
    #[serde(default = "default_short_prefix_max")]
    pub prose_prefix_max: usize,
    /// A prose left side of at most this many words containing a prose
    /// header token (or empty) is a header: the right side is
    /// `<entity>: <title>`.
    #[serde(default = "default_prose_header_words_max")]
    pub prose_header_words_max: usize,
    #[serde(default)]
    pub prose_header_tokens: Vec<String>,
    /// Characters of content used as the title when none is parsed.
    #[serde(default = "default_title_fallback_chars")]
    pub fallback_chars: usize,
}

impl Default for TitleSpec {
    fn default() -> Self {
        Self {
            pipe_position: 0,
            strip_short_prefix_max: default_short_prefix_max(),
            header_words_max: default_pipe_header_words_max(),
            header_tokens: Vec::new(),
            prose_prefix_max: default_short_prefix_max(),
            prose_header_words_max: default_prose_header_words_max(),
            prose_header_tokens: Vec::new(),
            fallback_chars: default_title_fallback_chars(),
        }
    }
}

const fn default_short_prefix_max() -> usize {
    12
}
const fn default_pipe_header_words_max() -> usize {
    4
}
const fn default_prose_header_words_max() -> usize {
    3
}
const fn default_title_fallback_chars() -> usize {
    120
}

/// One parsed field.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldSpec {
    /// Pipe position (see [`TitleSpec::pipe_position`]) used when no keyed
    /// value was found.
    #[serde(default)]
    pub pipe_position: Option<usize>,
    /// Pipe field prefixes (`key:`), matched case-insensitively.
    #[serde(default)]
    pub keys: Vec<String>,
    /// Markers scanned for in the whole body when no keyed value was found.
    #[serde(default)]
    pub prose_markers: Vec<String>,
    /// The suffix of the first label with this prefix.
    #[serde(default)]
    pub from_label_prefix: Option<String>,
    /// Read the label before the content.
    #[serde(default)]
    pub prefer_label: bool,
    /// Take the canonical leading `[FLAG]` as this field's value.
    #[serde(default)]
    pub from_flag: bool,
}

/// What counts as a missing value.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnknownSpec {
    /// Values (compared normalized) that mean "missing".
    #[serde(default)]
    pub tokens: Vec<String>,
    /// Values that are never missing, even when they match a token.
    #[serde(default)]
    pub not_unknown: Vec<String>,
    /// Fields whose missing values count against a survivor candidate.
    #[serde(default)]
    pub count_fields: Vec<String>,
}

/// A built-in token rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectRule {
    /// `YYYY-MM-DD`.
    IsoDate,
    /// `M/D/YY` or `M/D/YYYY`.
    UsDate,
    /// `19xx` / `20xx`.
    BareYear,
    /// `YYYY-YYYY`.
    YearRange,
    /// `2026-27`, `2026/27`, `FY2026-27`, `FY26-27`, `FY25/26`, `FY2026`, `FY26`
    /// (only when the second part is the next year).
    FiscalYear,
    /// Any piece containing `:` (tested before trimming).
    ClockTime,
    /// Any piece containing `$` (tested before trimming).
    Money,
    /// Any piece containing `%` (tested before trimming).
    Percent,
}

/// Id tokenization.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdSpec {
    /// Content after the LAST occurrence of this marker is never scanned.
    #[serde(default)]
    pub scan_cut_at_last: Option<String>,
    #[serde(default = "default_strong_min_len")]
    pub strong_min_len: usize,
    #[serde(default = "default_strong_min_digits")]
    pub strong_min_digits: usize,
    #[serde(default = "default_id_min_len")]
    pub min_len: usize,
    #[serde(default = "default_pure_digit_min_len")]
    pub pure_digit_min_len: usize,
    #[serde(default)]
    pub reject: Vec<RejectRule>,
    /// Regexes on the trimmed token; a match is not an id.
    #[serde(default)]
    pub reject_patterns: Vec<String>,
    /// Regexes on the trimmed token (and on a carried normalized id); a match
    /// is a strong id whatever its length.
    #[serde(default)]
    pub strong_patterns: Vec<String>,
    /// Labels `<prefix><NORM>` add `NORM` to the claim's id set.
    #[serde(default)]
    pub carry_label_prefix: Option<String>,
    #[serde(skip)]
    pub(crate) compiled_reject: Vec<Regex>,
    #[serde(skip)]
    pub(crate) compiled_strong: Vec<Regex>,
}

impl Default for IdSpec {
    fn default() -> Self {
        Self {
            scan_cut_at_last: None,
            strong_min_len: default_strong_min_len(),
            strong_min_digits: default_strong_min_digits(),
            min_len: default_id_min_len(),
            pure_digit_min_len: default_pure_digit_min_len(),
            reject: Vec::new(),
            reject_patterns: Vec::new(),
            strong_patterns: Vec::new(),
            carry_label_prefix: None,
            compiled_reject: Vec::new(),
            compiled_strong: Vec::new(),
        }
    }
}

const fn default_strong_min_len() -> usize {
    6
}
const fn default_strong_min_digits() -> usize {
    2
}
const fn default_id_min_len() -> usize {
    3
}
const fn default_pure_digit_min_len() -> usize {
    4
}

/// Entity comparison.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntityMatchSpec {
    /// `[token, "expansion words"]`: the token is replaced by the words.
    #[serde(default)]
    pub aliases: Vec<(String, String)>,
    #[serde(default)]
    pub stopwords: Vec<String>,
    #[serde(default = "default_threshold")]
    pub threshold: f64,
}

impl Default for EntityMatchSpec {
    fn default() -> Self {
        Self {
            aliases: Vec::new(),
            stopwords: Vec::new(),
            threshold: default_threshold(),
        }
    }
}

/// Title comparison.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TitleMatchSpec {
    #[serde(default)]
    pub stopwords: Vec<String>,
    #[serde(default = "default_threshold")]
    pub fuzzy_threshold: f64,
    #[serde(default = "default_fuzzy_min_tokens")]
    pub fuzzy_min_tokens: usize,
}

impl Default for TitleMatchSpec {
    fn default() -> Self {
        Self {
            stopwords: Vec::new(),
            fuzzy_threshold: default_threshold(),
            fuzzy_min_tokens: default_fuzzy_min_tokens(),
        }
    }
}

const fn default_threshold() -> f64 {
    0.8
}
const fn default_fuzzy_min_tokens() -> usize {
    3
}

/// Label partitions that clustering never crosses.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PartitionSpec {
    /// Two claims whose labels under one of these prefixes are both present
    /// and disjoint never pair, directly or through a chain.
    #[serde(default)]
    pub must_agree_label_prefixes: Vec<String>,
    /// A claim carrying one of these labels pairs with a claim that does not
    /// carry the same label only through a shared strong id.
    #[serde(default)]
    pub no_merge_without_strong_id_label_values: Vec<String>,
}

/// Survivor choice: a total order.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrecedenceSpec {
    /// Rank = index of the first group sharing a label with the claim;
    /// unmatched claims rank last.
    #[serde(default)]
    pub rank_label_groups: Vec<Vec<String>>,
    /// Tie-breaks after the rank. The smallest id always breaks a final tie.
    #[serde(default = "TieBreak::all")]
    pub then: Vec<TieBreak>,
}

impl Default for PrecedenceSpec {
    fn default() -> Self {
        Self {
            rank_label_groups: Vec::new(),
            then: TieBreak::all(),
        }
    }
}

/// A survivor tie-break.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TieBreak {
    FewestUnknown,
    NewestCreatedAt,
    SmallestId,
}

impl TieBreak {
    #[must_use]
    pub fn all() -> Vec<Self> {
        vec![Self::FewestUnknown, Self::NewestCreatedAt, Self::SmallestId]
    }
}

/// Cluster writes.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
///
/// A cluster's losers are not relabelled: each becomes a
/// [`DuplicateMark`](super::DuplicateMark) of the survivor, which the apply
/// tool performs through the graph-native dedup act (the loser leaves the
/// index by becoming non-current). What a loser knew stays on it and is read
/// through the survivor's identity edges, so no later date or missing value is
/// copied onto the survivor as a label. Only ids, which are the index's keys,
/// are still carried.
pub struct MergeSpec {
    #[serde(default)]
    pub survivor_add: Vec<String>,
    /// Carry every loser id the survivor lacks as `<carry_label_prefix><NORM>`.
    #[serde(default)]
    pub carry_ids: bool,
}

/// Past-due close-out of live members.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloseoutSpec {
    pub date_field: String,
    /// Must contain the closed label.
    pub add: Vec<String>,
}

/// Signal lifecycle: graduation into a member, or age-out.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleSpec {
    pub signal_family_label: String,
    /// (required) What the signal family is; lifecycle writes onto it, so it
    /// must be an index family like every family a plan writes.
    pub signal_family_kind: FamilyKind,
    #[serde(default)]
    pub signal_exclude_labels: Vec<String>,
    /// The graduation index read excludes these, but keeps closed members.
    #[serde(default)]
    pub target_exclude_labels: Vec<String>,
    #[serde(default)]
    pub umbrella: UmbrellaSpec,
    #[serde(default)]
    pub age_key: Vec<AgeKey>,
    /// No age-out when absent.
    #[serde(default)]
    pub max_age_days: Option<i64>,
    pub graduate_add: Vec<String>,
    #[serde(default)]
    pub age_out_add: Vec<String>,
}

/// Signals that cover many items never graduate on one shared id.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UmbrellaSpec {
    #[serde(default)]
    pub body_prefixes: Vec<String>,
    #[serde(default)]
    pub tokens: Vec<String>,
    #[serde(default)]
    pub phrases: Vec<String>,
    /// Stripped from the normalized body before the checks.
    #[serde(default)]
    pub strip_prefix: Option<String>,
}

/// One entry of the age-key chain, tried in order.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum AgeKey {
    /// The first date directly after one of these whole-word keywords.
    AfterKeywords { after_keywords: Vec<String> },
    /// `"created_at"`.
    Named(AgeKeyName),
}

/// Named age keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgeKeyName {
    CreatedAt,
}

/// Signals that became a member leave the signal family.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupersedeSpec {
    pub add: Vec<String>,
    #[serde(default)]
    pub remove: Vec<String>,
    /// Accepted matches (any of).
    pub require: Vec<SupersedeMatch>,
}

/// A supersession match kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupersedeMatch {
    StrongId,
    ExactEntityTitle,
}

/// Why a read is needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadPurpose {
    /// The main family, excluding the closed label.
    Members,
    /// The lifecycle signal family.
    LifecycleSignals,
    /// The main family including closed members: the graduation index.
    LifecycleTargets,
    /// The signal-dedup family.
    SignalMembers,
    /// Closed lifecycle signals: the probe's match-only index.
    ClosedSignals,
}

/// One viewer-scoped read: claims carrying ALL of `include` and NONE of
/// `exclude`, ordered by id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadSpec {
    pub purpose: ReadPurpose,
    pub include: Vec<String>,
    pub exclude: Vec<String>,
    pub current_only: bool,
}

impl ReadSpec {
    /// Whether a claim with `labels` is in this read.
    #[must_use]
    pub fn matches(&self, labels: &[String]) -> bool {
        self.include.iter().all(|l| labels.contains(l))
            && !self.exclude.iter().any(|l| labels.contains(l))
    }
}

impl LabelDedupProfile {
    /// Parse and validate profile JSON.
    ///
    /// # Errors
    /// [`LabelDedupError::ProfileSchemaInvalid`] for malformed JSON, an
    /// unknown key, a wrong schema id, a bad regex, a write template that
    /// would not leave the family (so a re-plan would never be empty), or an
    /// unknown placeholder.
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, LabelDedupError> {
        let mut map: serde_json::Map<String, serde_json::Value> = serde_json::from_slice(bytes)
            .map_err(|e| invalid(format!("not a JSON object: {e}")))?;
        let schema = match map.remove("schema") {
            Some(serde_json::Value::String(s)) => s,
            _ => return Err(invalid(format!("`schema` must be \"{PROFILE_SCHEMA}\""))),
        };
        if schema != PROFILE_SCHEMA {
            return Err(invalid(format!(
                "unsupported schema {schema:?}; this engine reads \"{PROFILE_SCHEMA}\""
            )));
        }
        let closeout = section_value(&mut map, "closeout")?;
        let lifecycle = section_value(&mut map, "lifecycle")?;
        let signal_dedup = section_value(&mut map, "signal_dedup")?;
        let signal_superseded_by_member = section_value(&mut map, "signal_superseded_by_member")?;
        let pass: PassProfile = serde_json::from_value(serde_json::Value::Object(map))
            .map_err(|e| invalid(e.to_string()))?;
        let mut profile = Self {
            schema,
            pass,
            closeout,
            lifecycle,
            signal_dedup,
            signal_superseded_by_member,
        };
        profile.validate()?;
        Ok(profile)
    }

    /// Check `bytes` against the pinned `expected_hash` BEFORE parsing, then
    /// parse. Returns the profile and its hash.
    ///
    /// # Errors
    /// [`LabelDedupError::ProfileHashMismatch`] when the bytes do not hash to
    /// the pin; otherwise as [`Self::from_json_bytes`].
    pub fn load_pinned(
        bytes: &[u8],
        expected_hash: &str,
    ) -> Result<(Self, String), LabelDedupError> {
        let actual = profile_hash(bytes);
        if !actual.eq_ignore_ascii_case(expected_hash.trim()) {
            return Err(LabelDedupError::ProfileHashMismatch {
                expected: expected_hash.to_string(),
                actual,
            });
        }
        Ok((Self::from_json_bytes(bytes)?, actual))
    }

    /// The reads a plan over `sections` needs, in a fixed order.
    ///
    /// # Errors
    /// [`LabelDedupError::SectionNotConfigured`] when a requested section has
    /// no configuration.
    pub fn reads(&self, sections: &[Section]) -> Result<Vec<ReadSpec>, LabelDedupError> {
        let sections = Section::normalize(sections);
        for s in &sections {
            self.require_section(*s)?;
        }
        let has = |s: Section| sections.contains(&s);
        let mut out = Vec::new();
        if has(Section::Hygiene)
            || has(Section::Dedup)
            || has(Section::Closeout)
            || has(Section::SignalDedup)
        {
            out.push(self.members_read());
        }
        if let (true, Some(lc)) = (has(Section::Lifecycle), self.lifecycle.as_ref()) {
            out.push(ReadSpec {
                purpose: ReadPurpose::LifecycleSignals,
                include: vec![lc.signal_family_label.clone()],
                exclude: dedup_labels(lc.signal_exclude_labels.iter()),
                current_only: true,
            });
            out.push(ReadSpec {
                purpose: ReadPurpose::LifecycleTargets,
                include: vec![self.pass.family_label.clone()],
                exclude: dedup_labels(lc.target_exclude_labels.iter()),
                current_only: true,
            });
        }
        if let (true, Some(sp)) = (has(Section::SignalDedup), self.signal_dedup.as_ref()) {
            out.push(ReadSpec {
                purpose: ReadPurpose::SignalMembers,
                include: vec![sp.family_label.clone()],
                exclude: dedup_labels(sp.closed_label.iter().chain(&sp.index_exclude_labels)),
                current_only: true,
            });
        }
        Ok(out)
    }

    /// The reads a probe needs: the members, plus the closed lifecycle
    /// signals when `include_closed_signals`.
    ///
    /// # Errors
    /// [`LabelDedupError::SectionNotConfigured`] when closed signals are asked
    /// for and the profile has no lifecycle (or no closed label).
    pub fn probe_reads(
        &self,
        include_closed_signals: bool,
    ) -> Result<Vec<ReadSpec>, LabelDedupError> {
        let mut out = vec![self.members_read()];
        if include_closed_signals {
            let (Some(lc), Some(closed)) =
                (self.lifecycle.as_ref(), self.pass.closed_label.as_ref())
            else {
                return Err(LabelDedupError::SectionNotConfigured {
                    section: Section::Lifecycle,
                });
            };
            out.push(ReadSpec {
                purpose: ReadPurpose::ClosedSignals,
                include: vec![lc.signal_family_label.clone(), closed.clone()],
                exclude: Vec::new(),
                current_only: true,
            });
        }
        Ok(out)
    }

    /// Refuse a section whose configuration (or write template) is absent.
    pub(crate) fn require_section(&self, section: Section) -> Result<(), LabelDedupError> {
        let configured = match section {
            Section::Hygiene => self.pass.hygiene_write.is_some(),
            Section::Dedup => self.pass.merge.is_some(),
            Section::Closeout => self.closeout.is_some(),
            Section::Lifecycle => self.lifecycle.is_some(),
            Section::SignalDedup => self
                .signal_dedup
                .as_ref()
                .is_some_and(|s| s.hygiene_write.is_some() && s.merge.is_some()),
        };
        if configured {
            Ok(())
        } else {
            Err(LabelDedupError::SectionNotConfigured { section })
        }
    }

    fn members_read(&self) -> ReadSpec {
        ReadSpec {
            purpose: ReadPurpose::Members,
            include: vec![self.pass.family_label.clone()],
            exclude: dedup_labels(
                self.pass
                    .closed_label
                    .iter()
                    .chain(&self.pass.index_exclude_labels),
            ),
            current_only: true,
        }
    }

    fn validate(&mut self) -> Result<(), LabelDedupError> {
        validate_pass(&mut self.pass, "")?;
        let family = self.pass.family_label.clone();
        if let Some(c) = &self.closeout {
            check_field_name(&self.pass, &c.date_field, "closeout.date_field")?;
            let Some(closed) = &self.pass.closed_label else {
                return Err(invalid(
                    "closeout needs `closed_label`: a closed member must leave the member read",
                ));
            };
            check_templates(&c.add, &[Var::RunTag, Var::Family], "closeout.add")?;
            if !c.add.contains(closed) {
                return Err(invalid(format!(
                    "closeout.add must add the closed label {closed:?}, or an applied close-out is planned again"
                )));
            }
        }
        if let Some(lc) = &self.lifecycle {
            check_label(&lc.signal_family_label, "lifecycle.signal_family_label")?;
            check_templates(
                &lc.graduate_add,
                &[Var::RunTag, Var::Family, Var::Target],
                "lifecycle.graduate_add",
            )?;
            check_templates(
                &lc.age_out_add,
                &[Var::RunTag, Var::Family],
                "lifecycle.age_out_add",
            )?;
            let exits = |adds: &[String]| adds.iter().any(|a| lc.signal_exclude_labels.contains(a));
            if !exits(&lc.graduate_add) {
                return Err(invalid(
                    "lifecycle.graduate_add must add a label in signal_exclude_labels, or a graduated signal is planned again",
                ));
            }
            if lc.max_age_days.is_some() && !exits(&lc.age_out_add) {
                return Err(invalid(
                    "lifecycle.age_out_add must add a label in signal_exclude_labels, or an aged-out signal is planned again",
                ));
            }
            if lc.max_age_days.is_some_and(|d| d < 0) {
                return Err(invalid("lifecycle.max_age_days must not be negative"));
            }
        }
        if let Some(sp) = &mut self.signal_dedup {
            if sp.family_label == family {
                return Err(invalid(
                    "signal_dedup.family_label must differ from the main family",
                ));
            }
            validate_pass(sp, "signal_dedup.")?;
        }
        if let Some(ss) = &self.signal_superseded_by_member {
            let Some(sp) = &self.signal_dedup else {
                return Err(invalid("signal_superseded_by_member needs signal_dedup"));
            };
            let vars = [Var::RunTag, Var::Family, Var::Target];
            check_templates(&ss.add, &vars, "signal_superseded_by_member.add")?;
            check_templates(&ss.remove, &vars, "signal_superseded_by_member.remove")?;
            if !leaves_family(&ss.remove, &sp.family_label) {
                return Err(invalid(
                    "signal_superseded_by_member.remove must remove {family}, or a superseded signal is planned again",
                ));
            }
            if ss.require.is_empty() {
                return Err(invalid(
                    "signal_superseded_by_member.require must name at least one match",
                ));
            }
        }
        Ok(())
    }
}

/// A placeholder a write template may use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Var {
    RunTag,
    Family,
    Survivor,
    Target,
}

impl Var {
    const fn name(self) -> &'static str {
        match self {
            Self::RunTag => "run_tag",
            Self::Family => "family",
            Self::Survivor => "survivor",
            Self::Target => "target",
        }
    }

    fn parse(name: &str) -> Option<Self> {
        [Self::RunTag, Self::Family, Self::Survivor, Self::Target]
            .into_iter()
            .find(|v| v.name() == name)
    }
}

/// Values bound into a template.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Bindings<'a> {
    pub run_tag: &'a str,
    pub family: &'a str,
    pub survivor: Option<&'a str>,
    pub target: Option<&'a str>,
}

/// Expand one template. Templates were validated at load, so every
/// placeholder is known and bound where it is used.
pub(crate) fn expand(template: &str, b: &Bindings<'_>) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        let Some(close) = after.find('}') else {
            out.push_str(&rest[open..]);
            return out;
        };
        let value = match Var::parse(&after[..close]) {
            Some(Var::RunTag) => Some(b.run_tag),
            Some(Var::Family) => Some(b.family),
            Some(Var::Survivor) => b.survivor,
            Some(Var::Target) => b.target,
            None => None,
        };
        match value {
            Some(v) => out.push_str(v),
            None => out.push_str(&rest[open..=open + 1 + close]),
        }
        rest = &after[close + 1..];
    }
    out.push_str(rest);
    out
}

/// Whether a label is safe to write: not empty, not padded, no control
/// characters, no `$` (the write path refuses it), no braces (an unexpanded
/// template).
pub(crate) fn label_problem(label: &str) -> Option<&'static str> {
    if label.is_empty() {
        Some("empty")
    } else if label.trim() != label {
        Some("leading or trailing whitespace")
    } else if label.chars().any(char::is_control) {
        Some("control character")
    } else if label.contains('$') {
        Some("contains `$`, which the label write path refuses")
    } else if label.contains('{') || label.contains('}') {
        Some("contains a brace (an unexpanded template)")
    } else {
        None
    }
}

fn invalid(msg: impl Into<String>) -> LabelDedupError {
    LabelDedupError::ProfileSchemaInvalid(msg.into())
}

fn section_value<T: serde::de::DeserializeOwned>(
    map: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<Option<T>, LabelDedupError> {
    match map.remove(key) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(v) => serde_json::from_value(v)
            .map(Some)
            .map_err(|e| invalid(format!("{key}: {e}"))),
    }
}

fn dedup_labels<'a>(labels: impl Iterator<Item = &'a String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for l in labels {
        if !out.contains(l) {
            out.push(l.clone());
        }
    }
    out
}

fn check_label(label: &str, at: &str) -> Result<(), LabelDedupError> {
    match label_problem(label) {
        Some(p) => Err(invalid(format!(
            "{at}: label {label:?} is not writable: {p}"
        ))),
        None => Ok(()),
    }
}

fn check_templates(templates: &[String], allowed: &[Var], at: &str) -> Result<(), LabelDedupError> {
    for t in templates {
        let mut literal = String::new();
        let mut rest = t.as_str();
        while let Some(open) = rest.find('{') {
            literal.push_str(&rest[..open]);
            let after = &rest[open + 1..];
            let Some(close) = after.find('}') else {
                return Err(invalid(format!("{at}: unclosed `{{` in {t:?}")));
            };
            let name = &after[..close];
            match Var::parse(name) {
                Some(v) if allowed.contains(&v) => literal.push('x'),
                Some(_) => {
                    return Err(invalid(format!(
                        "{at}: placeholder {{{name}}} is not bound here (allowed: {})",
                        allowed
                            .iter()
                            .map(|v| format!("{{{}}}", v.name()))
                            .collect::<Vec<_>>()
                            .join(", ")
                    )))
                }
                None => {
                    return Err(invalid(format!(
                        "{at}: unknown placeholder {{{name}}} in {t:?}"
                    )))
                }
            }
            rest = &after[close + 1..];
        }
        literal.push_str(rest);
        check_label(&literal, at)?;
    }
    Ok(())
}

fn leaves_family(remove: &[String], family: &str) -> bool {
    remove.iter().any(|r| r == "{family}" || r == family)
}

fn check_field_name(pass: &PassProfile, name: &str, at: &str) -> Result<(), LabelDedupError> {
    let known = matches!(name, "entity" | "deadline" | "value" | "class")
        || pass.fields.extra.contains_key(name);
    if known {
        Ok(())
    } else {
        Err(invalid(format!("{at}: unknown field {name:?}")))
    }
}

fn validate_pass(pass: &mut PassProfile, at: &str) -> Result<(), LabelDedupError> {
    check_label(&pass.family_label, &format!("{at}family_label"))?;
    for name in pass.fields.extra.keys() {
        if matches!(
            name.as_str(),
            "title" | "entity" | "deadline" | "value" | "class"
        ) {
            return Err(invalid(format!(
                "{at}fields.extra: {name:?} shadows a core field"
            )));
        }
    }
    for t in [
        &pass.entity_match.threshold,
        &pass.title_match.fuzzy_threshold,
    ] {
        if t.is_nan() || *t <= 0.0 || *t > 1.0 {
            return Err(invalid(format!(
                "{at}thresholds must be in (0, 1], got {t}"
            )));
        }
    }
    let compile = |pats: &[String], key: &str| -> Result<Vec<Regex>, LabelDedupError> {
        pats.iter()
            .map(|p| Regex::new(p).map_err(|e| invalid(format!("{at}ids.{key}: {e}"))))
            .collect()
    };
    pass.ids.compiled_reject = compile(&pass.ids.reject_patterns, "reject_patterns")?;
    pass.ids.compiled_strong = compile(&pass.ids.strong_patterns, "strong_patterns")?;
    for name in &pass.unknown.count_fields {
        check_field_name(pass, name, &format!("{at}unknown.count_fields"))?;
    }
    if let Some(h) = &pass.hygiene_write {
        check_templates(
            &h.add,
            &[Var::RunTag, Var::Family],
            &format!("{at}hygiene_write.add"),
        )?;
        check_templates(
            &h.remove,
            &[Var::RunTag, Var::Family],
            &format!("{at}hygiene_write.remove"),
        )?;
        if !leaves_family(&h.remove, &pass.family_label) {
            return Err(invalid(format!(
                "{at}hygiene_write.remove must remove {{family}}, or an applied hygiene write is planned again"
            )));
        }
    }
    if let Some(m) = &pass.merge {
        check_templates(
            &m.survivor_add,
            &[Var::RunTag, Var::Family],
            &format!("{at}merge.survivor_add"),
        )?;
        if m.carry_ids && pass.ids.carry_label_prefix.is_none() {
            return Err(invalid(format!(
                "{at}merge.carry_ids needs ids.carry_label_prefix"
            )));
        }
    }
    for prefix in pass
        .ids
        .carry_label_prefix
        .iter()
        .chain(&pass.revision_label_prefix)
        .chain(&pass.distinct_label_prefix)
    {
        if prefix.is_empty() {
            return Err(invalid(format!("{at}label prefixes must not be empty")));
        }
    }
    Ok(())
}
