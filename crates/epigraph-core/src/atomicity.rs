//! The atomicity heuristic: is a claim already one atomic proposition?
//!
//! `decompose_claims` (epigraph-cli) skips claims this accepts, so they never
//! get a `decomposes_to` edge and stay in the undecomposed population. The
//! operator ruled (2026-10-14, backlog `5e1debbc`) that such claims are
//! TERMINAL by policy: not a backlog and not a defect. The MCP tool
//! `query_undecomposed_claims` flags them with the same function, so the two
//! surfaces cannot disagree about which rows are atomic.
//!
//! [`conjunct_screen`] is the finer, warn-only measure: an estimated count of
//! independent assertions per claim. `looks_atomic` decides what
//! `decompose_claims` skips by default; the screen decides what is reported as
//! compound (the `submit_claim` and `ingest_document` warnings, the
//! `screen_claim_atomicity` and `query_compound_claims` MCP tools, the
//! `atomicity_sweep` label and `decompose_claims --redecompose`). A claim can
//! look atomic and still screen compound ("X rose, but Y fell.").
//!
//! [`conjunct_estimate`] (backlog `72850d43`) is a second, independent count
//! with its own rules (finite-verb coordination, enumerations,
//! `respectively`); it feeds only `query_undecomposed_claims`'
//! `conjunct_estimate` / `conjunct_signals` fields. The two counters can
//! disagree on the same text; neither changes what [`looks_atomic`] decides.

/// Longest claim, in Unicode scalar values, that [`looks_atomic`] may call
/// atomic. Chosen by the operator brief (2026-09-24): "one sentence and ≤ 160
/// chars".
pub const ATOMIC_MAX_CHARS: usize = 160;

/// Number of sentences in `text`, by a deliberately simple rule.
///
/// A boundary is either
/// * a run of `.` `!` `?` (plus any closing quote/bracket), followed by
///   whitespace, followed by an uppercase letter, a digit, or an opening
///   quote/bracket; or
/// * a line break between two non-blank lines (bullet lists, pasted notes).
///
/// It errs toward COUNTING a boundary: `"Dr. Smith"` and `"e.g. The"` read as
/// two sentences. That direction only sends a claim to the LLM that could have
/// been skipped; the opposite error would silently skip a compound claim.
/// Decimals (`3.5`) and dotted identifiers (`epigraph.io`) never count, because
/// no whitespace follows the dot.
pub fn sentence_count(text: &str) -> usize {
    count_sentences(text, false)
}

/// Abbreviations after which the screen does not cut a sentence, lower-cased
/// and with their dots. Kept to words that rarely end a sentence: `etc.` and
/// single initials are left out on purpose. `al.` counts only after `et`.
const SCREEN_ABBREVIATIONS: [&str; 25] = [
    "sec.", "secs.", "fig.", "figs.", "eq.", "eqs.", "eqn.", "eqns.", "ref.", "refs.", "tab.",
    "vol.", "ch.", "e.g.", "i.e.", "al.", "vs.", "approx.", "ca.", "cf.", "resp.", "viz.", "dr.",
    "prof.", "pp.",
];

/// Whether the `.` at `chars[dot]` ends one of [`SCREEN_ABBREVIATIONS`].
fn ends_screen_abbreviation(chars: &[char], dot: usize) -> bool {
    let mut start = dot;
    while start > 0 && (chars[start - 1].is_alphabetic() || chars[start - 1] == '.') {
        start -= 1;
    }
    let word: String = chars[start..=dot].iter().collect::<String>().to_lowercase();
    if !SCREEN_ABBREVIATIONS.contains(&word.as_str()) {
        return false;
    }
    if word != "al." {
        return true;
    }
    // `et al.`: the word before must be `et`.
    let before: String = chars[..start].iter().collect();
    before
        .trim_end()
        .rsplit(|c: char| !c.is_alphabetic())
        .next()
        .is_some_and(|w| w.eq_ignore_ascii_case("et"))
}

/// [`sentence_count`], or with `skip_abbreviations` the screen's count, which
/// does not cut after a [`SCREEN_ABBREVIATIONS`] word.
fn count_sentences(text: &str, skip_abbreviations: bool) -> usize {
    let chars: Vec<char> = text.trim().chars().collect();
    if chars.is_empty() {
        return 0;
    }
    let closing = |c: char| matches!(c, '"' | '\'' | ')' | ']' | '\u{201d}' | '\u{2019}');
    let opening = |c: char| matches!(c, '"' | '\'' | '(' | '[' | '\u{201c}' | '\u{2018}');
    let mut n = 1;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if matches!(c, '.' | '!' | '?') {
            let mut j = i + 1;
            while j < chars.len() && (matches!(chars[j], '.' | '!' | '?') || closing(chars[j])) {
                j += 1;
            }
            let mut k = j;
            while k < chars.len() && chars[k].is_whitespace() {
                k += 1;
            }
            let abbreviation =
                skip_abbreviations && c == '.' && ends_screen_abbreviation(&chars, i);
            if k > j && k < chars.len() && !abbreviation {
                let next = chars[k];
                if next.is_uppercase() || next.is_ascii_digit() || opening(next) {
                    n += 1;
                    // The whitespace run is consumed: a newline inside it must
                    // not count the same boundary twice.
                    i = k;
                    continue;
                }
            }
            i = j;
        } else if c == '\n' {
            // A line break between non-blank lines is a boundary.
            let mut k = i + 1;
            while k < chars.len() && chars[k].is_whitespace() {
                k += 1;
            }
            if k < chars.len() {
                n += 1;
            }
            i = k;
        } else {
            i += 1;
        }
    }
    n
}

/// Whether `content` is already atomic enough that decomposing it would spend
/// an LLM call to get the claim back unchanged: exactly one sentence (see
/// [`sentence_count`]) and at most [`ATOMIC_MAX_CHARS`] characters.
///
/// This is the ONE definition of the heuristic; `decompose_claims`' eligibility
/// filter and its report (`epigraph_cli::decompose`, via a re-export) and the
/// `looks_atomic` flag on `query_undecomposed_claims` all call it.
pub fn looks_atomic(content: &str) -> bool {
    sentence_count(content) <= 1 && content.trim().chars().count() <= ATOMIC_MAX_CHARS
}

/// The label the compound-atom sweep (`epigraph-cli`'s `atomicity_sweep`)
/// puts on a current atom (the target of a `decomposes_to` edge, with no
/// in-force `decomposes_to` children of its own) that [`conjunct_screen`]
/// calls compound, and takes off one that no longer qualifies.
pub const COMPOUND_ATOM_LABEL: &str = "compound-atom";

/// The [`ConjunctScreen::conjunct_count`] at which a claim screens compound.
pub const COMPOUND_MIN_CONJUNCTS: usize = 2;

/// What [`conjunct_screen`] counted in one claim's text.
///
/// The components are reported, not only the total, so a caller can see WHY a
/// claim screened compound: a narrative protocol or postmortem claim is
/// legitimately long, and the screen is a warning and a discovery key, never a
/// rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct ConjunctScreen {
    /// Sentences, by [`sentence_count`]'s boundaries except one right after
    /// a common abbreviation (`Sec.`, `Fig.`, `Eq.`, `Ref.`, `e.g.`, `i.e.`,
    /// `et al.`, `vs.`, `approx.` and a few more): `"As shown in Sec. III, X
    /// holds."` is one sentence here. [`sentence_count`] itself, and so
    /// [`looks_atomic`], still cut there.
    pub sentences: usize,
    /// Joins inside a sentence that start another independent clause: a `;`,
    /// or a comma followed by `and`, `but`, `yet`, `so`, `while`, `whereas`,
    /// `although`, `though` or `which`, or `whereas` alone. A `, and` that
    /// closes a comma list (`A, B, and C`) is not a join.
    pub clause_joins: usize,
    /// Distinct numeric quantities.
    ///
    /// ONE quantity each: a range written with a dash (`3-5 nm`, `3−5 nm`), a
    /// product or dimension (`2×1`, `3 x 4 mm`), scientific notation
    /// (`1.625 × 10^4`, `2.3×10^-9`), and a value with its uncertainty
    /// (`78 ± 14%`, `1.12 +/- 0.02`).
    ///
    /// NONE: a number glued to a letter (`CO2`, `Q3`, `v1.2`, `COVID-19`, the
    /// exponent of `1.6e-4`), an exponent after `^` (`cm^-1`), a bare
    /// four-digit year (1800 to 2199), a figure, equation, section, table or
    /// reference number (`Fig. 3`, `Eq. (4)`), and bracketed notation: surface
    /// and crystallographic names (`Si(100)−2×1`, `c(4×2)`, `(111)`, `[110]`)
    /// and square-bracket citations (`[12, 14]`). A short parenthesised number
    /// that is none of these (`(1)`, `(12)`) still counts.
    pub quantities: usize,
    /// The estimated number of independent assertions:
    /// `max(sentences + clause_joins, ceil(quantities / 2))`. Never below
    /// [`ConjunctScreen::sentences`].
    pub conjunct_count: usize,
}

impl ConjunctScreen {
    /// `conjunct_count >= COMPOUND_MIN_CONJUNCTS`.
    pub fn is_compound(&self) -> bool {
        self.conjunct_count >= COMPOUND_MIN_CONJUNCTS
    }
}

/// Words that, after a comma, start an independent clause.
const CLAUSE_CONNECTORS: [&str; 9] = [
    "and", "but", "yet", "so", "while", "whereas", "although", "though", "which",
];

/// Estimate how many logically independent assertions `text` makes.
///
/// A heuristic with no parser and no database, so the MCP server and the CLI
/// share it. Three signals, each documented on [`ConjunctScreen`]:
///
/// * sentences ([`sentence_count`]'s boundaries, but not right after a common
///   abbreviation);
/// * clause joins inside a sentence;
/// * distinct numeric quantities, halved and rounded up: one fact often
///   carries two numbers (a change from one value to another, a value and its
///   uncertainty, a range written in words), so two quantities alone do not
///   make a claim compound, and three do.
///
/// Its errors run in both directions and are accepted because nothing is
/// refused on it. A noun-phrase `and` ("apples and pears are fruit") is not
/// counted, so "X rose and Y fell" without a comma is missed; a comma list
/// opened by an introductory phrase ("In May, X rose, and Y fell") reads as a
/// list and its join is missed; a non-restrictive `, which` that only
/// describes ("the lab, which is in Oslo") is counted.
pub fn conjunct_screen(text: &str) -> ConjunctScreen {
    let sentences = count_sentences(text, true);
    let clause_joins = clause_join_count(text);
    let quantities = quantity_count(text);
    ConjunctScreen {
        sentences,
        clause_joins,
        quantities,
        conjunct_count: (sentences + clause_joins).max(quantities.div_ceil(2)),
    }
}

/// [`ConjunctScreen::clause_joins`] of `text`.
fn clause_join_count(text: &str) -> usize {
    let chars: Vec<char> = text.trim().chars().collect();
    // The word starting at `i` (letters only, lower-cased) and where it ends.
    let word_at = |i: usize| -> (String, usize) {
        let mut j = i;
        while j < chars.len() && chars[j].is_alphabetic() {
            j += 1;
        }
        (chars[i..j].iter().collect::<String>().to_lowercase(), j)
    };
    let mut joins = 0;
    // Commas since the last sentence or clause boundary: a `, and` after one
    // closes a list rather than joining a clause.
    let mut commas = 0usize;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        match c {
            '.' | '!' | '?' | '\n' => commas = 0,
            ';' => {
                // A semicolon with more text after it joins two clauses.
                if chars[i + 1..].iter().any(|c| c.is_alphanumeric()) {
                    joins += 1;
                }
                commas = 0;
            }
            ',' if chars.get(i + 1).is_some_and(|c| c.is_whitespace()) => {
                let mut k = i + 1;
                while k < chars.len() && chars[k].is_whitespace() {
                    k += 1;
                }
                let (word, end) = word_at(k);
                let followed = chars.get(end).is_some_and(|c| c.is_whitespace());
                if followed && CLAUSE_CONNECTORS.contains(&word.as_str()) {
                    if word == "and" && commas > 0 {
                        // `A, B, and C`: a list tail.
                    } else {
                        joins += 1;
                        commas = 0;
                    }
                    i = end;
                    continue;
                }
                commas += 1;
            }
            _ if c.is_alphabetic() && (i == 0 || !chars[i - 1].is_alphanumeric()) => {
                let (word, end) = word_at(i);
                // `whereas` joins two clauses with or without a comma; the
                // comma form was counted (and skipped past) above.
                if word == "whereas" {
                    joins += 1;
                    commas = 0;
                }
                i = end;
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    joins
}

/// Words whose following number is a label, not a quantity (`Fig. 3`,
/// `Eq. (4)`, `Table 2`), lower-cased and without a trailing dot.
const REFERENCE_WORDS: [&str; 22] = [
    "fig",
    "figs",
    "figure",
    "figures",
    "eq",
    "eqs",
    "eqn",
    "eqns",
    "equation",
    "equations",
    "ref",
    "refs",
    "reference",
    "sec",
    "secs",
    "section",
    "sections",
    "tab",
    "table",
    "tables",
    "ch",
    "chapter",
];

/// A dash or minus as written in ranges and notation: `-`, `–`, `—`, `−`.
fn is_dash(c: char) -> bool {
    matches!(c, '-' | '\u{2013}' | '\u{2014}' | '\u{2212}')
}

/// Whether the digit at `chars[i]` is the label of a [`REFERENCE_WORDS`]
/// word: the word, an optional `.`, spaces and an optional `(` before it.
fn is_reference_label(chars: &[char], i: usize) -> bool {
    let mut k = i;
    if k > 0 && chars[k - 1] == '(' {
        k -= 1;
    }
    while k > 0 && chars[k - 1] == ' ' {
        k -= 1;
    }
    if k > 0 && chars[k - 1] == '.' {
        k -= 1;
    }
    let end = k;
    while k > 0 && chars[k - 1].is_alphabetic() {
        k -= 1;
    }
    // The number must be separated from the word: `Fig3` is glued, not a
    // label, and is handled by the glued rule.
    if k == end || end == i {
        return false;
    }
    let word: String = chars[k..end].iter().collect::<String>().to_lowercase();
    REFERENCE_WORDS.contains(&word.as_str())
}

/// Whether the digit at `chars[i]` is an exponent: right after `^`, with an
/// optional sign and opening brace between (`10^4`, `cm^-1`, `10^{-9}`).
fn is_exponent(chars: &[char], i: usize) -> bool {
    let mut k = i;
    for _ in 0..2 {
        if k > 0 && (is_dash(chars[k - 1]) || matches!(chars[k - 1], '+' | '{' | '(')) {
            k -= 1;
        }
    }
    k > 0 && chars[k - 1] == '^'
}

/// The end (one past the closer) of bracketed notation whose first digit is
/// `chars[i]`, if it is notation rather than a quantity.
///
/// The group holds only digits, spaces, commas, dashes, `×`/`x`, `√` and
/// combining overbars. Square, curly and angle brackets always make notation
/// (Miller directions and families, citations); a parenthesis does when it is
/// glued to a letter (`Si(100)`, `c(4×2)`), holds three or more digits
/// (`(111)`, `(1-10)`) or holds a product, a root or an overbar.
fn bracketed_notation_end(chars: &[char], i: usize) -> Option<usize> {
    let open = *chars.get(i.checked_sub(1)?)?;
    let close = match open {
        '(' => ')',
        '[' => ']',
        '{' => '}',
        '<' => '>',
        _ => return None,
    };
    let mut k = i;
    let (mut digits, mut product) = (0, false);
    while k < chars.len() {
        let c = chars[k];
        if c.is_ascii_digit() {
            digits += 1;
        } else if matches!(c, '\u{d7}' | 'x' | '\u{221a}' | '\u{304}' | '\u{305}') {
            product = true;
        } else if !(c == ' ' || c == ',' || is_dash(c)) {
            break;
        }
        k += 1;
    }
    if chars.get(k) != Some(&close) {
        return None;
    }
    let glued = i >= 2 && chars[i - 2].is_alphabetic();
    let notation = open != '(' || glued || digits >= 3 || product;
    notation.then_some(k + 1)
}

/// From `chars[j]`, just past a number, the first digit of the number a join
/// continues into, if one does: `×` or `x` (a product, or the `× 10` of
/// scientific notation), or `±`, `+/-`, `+-` (an uncertainty), each with
/// optional spaces around it. `x` must stand alone: `3 xenon` joins nothing.
fn joined_number_start(chars: &[char], j: usize) -> Option<usize> {
    let skip_spaces = |mut k: usize| {
        while k < chars.len() && chars[k] == ' ' {
            k += 1;
        }
        k
    };
    let k = skip_spaces(j);
    let after_op = match chars.get(k)? {
        '\u{d7}' | '\u{b1}' => k + 1,
        'x' if !chars.get(k + 1).is_some_and(|c| c.is_alphabetic()) => k + 1,
        '+' if chars.get(k + 1) == Some(&'/') && chars.get(k + 2).is_some_and(|&c| is_dash(c)) => {
            k + 3
        }
        '+' if chars.get(k + 1).is_some_and(|&c| is_dash(c)) => k + 2,
        _ => return None,
    };
    let mut n = skip_spaces(after_op);
    if chars.get(n) == Some(&'\u{221a}') {
        n += 1;
    }
    chars.get(n)?.is_ascii_digit().then_some(n)
}

/// [`ConjunctScreen::quantities`] of `text`.
fn quantity_count(text: &str) -> usize {
    let chars: Vec<char> = text.chars().collect();
    let mut seen = std::collections::BTreeSet::new();
    let mut i = 0;
    while i < chars.len() {
        if !chars[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        if let Some(end) = bracketed_notation_end(&chars, i) {
            i = end;
            continue;
        }
        // Glued to a word on the left (`CO2`, `Q3`, `v1.2`, `COVID-19`), or by
        // a dash to bracketed notation (the `2×1` of `Si(100)−2×1`); an
        // exponent; or a figure/equation/reference label.
        let glued = (i > 0
            && (chars[i - 1].is_alphabetic()
                || chars[i - 1] == '_'
                || (is_dash(chars[i - 1])
                    && i > 1
                    && (chars[i - 2].is_alphabetic() || chars[i - 2] == ')'))))
            || is_exponent(&chars, i)
            || is_reference_label(&chars, i);
        let start = i;
        let mut j = i;
        loop {
            while j < chars.len() && chars[j].is_ascii_digit() {
                j += 1;
            }
            // A decimal point or thousands separator inside the number.
            if j + 1 < chars.len() && matches!(chars[j], '.' | ',') && chars[j + 1].is_ascii_digit()
            {
                j += 1;
                continue;
            }
            // A dash range (`3-5`, `3–5`, `3−5`) is one quantity.
            if j + 1 < chars.len() && is_dash(chars[j]) && chars[j + 1].is_ascii_digit() {
                j += 1;
                continue;
            }
            // An exponent belongs to its number: `10^4`, `10^-9`, `10^{23}`.
            if chars.get(j) == Some(&'^') {
                let mut k = j + 1;
                while k < chars.len() && (matches!(chars[k], '{' | '(' | '+') || is_dash(chars[k]))
                {
                    k += 1;
                }
                if chars.get(k).is_some_and(|c| c.is_ascii_digit()) {
                    while k < chars.len() && chars[k].is_ascii_digit() {
                        k += 1;
                    }
                    if matches!(chars.get(k), Some('}' | ')')) {
                        k += 1;
                    }
                    j = k;
                    continue;
                }
            }
            // A product, scientific notation or an uncertainty is one.
            if let Some(next) = joined_number_start(&chars, j) {
                j = next;
                continue;
            }
            break;
        }
        // Spaces inside a joined quantity (`78 ± 14`) are not part of its
        // identity: `78±14` and `78 ± 14` are the same quantity.
        let literal: String = chars[start..j].iter().filter(|c| **c != ' ').collect();
        i = j;
        if glued {
            continue;
        }
        let year = literal.len() == 4
            && literal
                .parse::<u32>()
                .is_ok_and(|y| (1800..=2199).contains(&y));
        if !year {
            seen.insert(literal);
        }
    }
    seen.len()
}

// =============================================================================
// CONJUNCT ESTIMATE: how many independent assertions does a claim carry?
// =============================================================================

/// Signal name: the text has more than one sentence ([`sentence_count`]'s
/// boundaries).
pub const SIGNAL_SENTENCES: &str = "sentences";
/// Signal name: a sentence has `;` outside parentheses.
pub const SIGNAL_SEMICOLON: &str = "semicolon";
/// Signal name: `and` / `but` / `whereas` / `while` joins two parts that each
/// have a finite verb.
pub const SIGNAL_COORDINATION: &str = "coordination";
/// Signal name: an inline enumeration, `(1) … (2) …`, `1) … 2) …`,
/// `(a) … (b) …` or `(i) … (ii) …`.
pub const SIGNAL_ENUMERATION: &str = "enumeration";
/// Signal name: `respectively`, which binds several values to several
/// referents in one clause.
pub const SIGNAL_RESPECTIVELY: &str = "respectively";

/// An estimated count of at least this many makes a claim compound-suspect.
pub const COMPOUND_SUSPECT_MIN_CONJUNCTS: usize = 2;

/// What [`conjunct_estimate`] found in one claim.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ConjunctEstimate {
    /// Estimated number of independently assertable statements. 0 for blank
    /// text, otherwise at least 1.
    pub count: usize,
    /// The rules that raised `count` above 1, each at most once, in the fixed
    /// order sentences, semicolon, coordination, enumeration, respectively.
    /// Empty when `count <= 1`.
    pub signals: Vec<&'static str>,
}

impl ConjunctEstimate {
    /// Whether the claim probably asserts several independent conjuncts
    /// (`count >= COMPOUND_SUSPECT_MIN_CONJUNCTS`).
    pub fn compound_suspect(&self) -> bool {
        self.count >= COMPOUND_SUSPECT_MIN_CONJUNCTS
    }
}

/// Estimate how many independent assertions `text` makes (backlog `72850d43`).
///
/// A COUNT with the rules that produced it, not a verdict: narrative protocol
/// and postmortem claims are legitimately long, so nothing should reject on
/// it. It is advisory and separate from [`looks_atomic`], which stays the one
/// rule `decompose_claims` skips on. The two can disagree: a short single
/// sentence such as `"The test passed and the build failed."` is
/// `looks_atomic` (terminal by the 2026-10-14 ruling) and has an estimate
/// of 2.
///
/// Deterministic, no model, no lexicon beyond the closed word lists in this
/// file. Per sentence (the boundaries are [`sentence_count`]'s) the estimate
/// is the largest of:
///
/// * the clauses: the sentence is cut at every `;` outside parentheses, and
///   each piece counts once, or once per part when `and` / `but` / `whereas` /
///   `while` separates parts that EACH hold a finite verb and at least two
///   words (`"A binds B and C"` is one; `"A binds B and inhibits C"` is two);
/// * the items of an inline enumeration (`(1) … (2) … (3) …`);
/// * 2, when the sentence says `respectively`.
///
/// The sentence estimates are summed.
///
/// Unlike [`sentence_count`], the coordination rule errs toward NOT counting:
/// finite verbs are recognised from a closed list plus `-ed` forms (not after
/// a determiner or preposition, not before a participial preposition), so
/// `"Yields rose and costs fell"` counts 2 but a sentence whose verbs are
/// outside the list counts 1. A hit is meant to be labelled and sent for
/// re-decomposition, and a wrong label on an atomic claim is noise on every
/// later read, so precision is preferred. Known false positives: parenthesised
/// citation numbers `(1) … (2)` read as an enumeration, and a participle used
/// as an adjective right after a conjunction (`"The kit contains buffer and
/// prepared slides."` counts 2).
/// Several numeric quantities bound to different referents are NOT detected
/// except through `;` and `respectively`.
pub fn conjunct_estimate(text: &str) -> ConjunctEstimate {
    let sentences = split_sentences(text);
    if sentences.is_empty() {
        return ConjunctEstimate::default();
    }
    let mut count = 0;
    let (mut semicolon, mut coordination, mut enumeration, mut respectively) =
        (false, false, false, false);
    for sentence in &sentences {
        let flat = strip_parenthesised(sentence);
        let mut clauses = 0;
        let mut pieces = 0;
        for piece in flat.split(';') {
            let tokens = tokenize(piece);
            if tokens.is_empty() {
                continue;
            }
            pieces += 1;
            let parts = coordinated_clauses(&tokens);
            if parts > 1 {
                coordination = true;
            }
            clauses += parts;
        }
        if pieces > 1 {
            semicolon = true;
        }
        let mut best = clauses.max(1);
        let items = inline_enumeration_items(sentence);
        if items > best {
            best = items;
            enumeration = true;
        }
        if best < 2 && tokenize(&flat).iter().any(|t| t == "respectively") {
            best = 2;
            respectively = true;
        }
        count += best;
    }
    let mut signals = Vec::new();
    if count > 1 {
        for (on, name) in [
            (sentences.len() > 1, SIGNAL_SENTENCES),
            (semicolon, SIGNAL_SEMICOLON),
            (coordination, SIGNAL_COORDINATION),
            (enumeration, SIGNAL_ENUMERATION),
            (respectively, SIGNAL_RESPECTIVELY),
        ] {
            if on {
                signals.push(name);
            }
        }
    }
    ConjunctEstimate { count, signals }
}

/// `text` cut at [`sentence_count`]'s boundaries. The loop is that function's,
/// collecting the pieces instead of counting them; `split_matches_count` in
/// the tests holds the two together.
fn split_sentences(text: &str) -> Vec<String> {
    let chars: Vec<char> = text.trim().chars().collect();
    let mut out = Vec::new();
    if chars.is_empty() {
        return out;
    }
    let closing = |c: char| matches!(c, '"' | '\'' | ')' | ']' | '\u{201d}' | '\u{2019}');
    let opening = |c: char| matches!(c, '"' | '\'' | '(' | '[' | '\u{201c}' | '\u{2018}');
    let mut start = 0;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if matches!(c, '.' | '!' | '?') {
            let mut j = i + 1;
            while j < chars.len() && (matches!(chars[j], '.' | '!' | '?') || closing(chars[j])) {
                j += 1;
            }
            let mut k = j;
            while k < chars.len() && chars[k].is_whitespace() {
                k += 1;
            }
            if k > j && k < chars.len() {
                let next = chars[k];
                if next.is_uppercase() || next.is_ascii_digit() || opening(next) {
                    out.push(chars[start..j].iter().collect());
                    start = k;
                    i = k;
                    continue;
                }
            }
            i = j;
        } else if c == '\n' {
            let mut k = i + 1;
            while k < chars.len() && chars[k].is_whitespace() {
                k += 1;
            }
            if k < chars.len() {
                out.push(chars[start..i].iter().collect());
                start = k;
            }
            i = k;
        } else {
            i += 1;
        }
    }
    out.push(chars[start..].iter().collect());
    out
}

/// `text` without anything inside `(…)` or `[…]`, so `(p < 0.05; n = 12)` and
/// `(mean and SD)` cut nothing. An unmatched closer is dropped.
fn strip_parenthesised(text: &str) -> String {
    let mut depth = 0usize;
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '(' | '[' => depth += 1,
            ')' | ']' => depth = depth.saturating_sub(1),
            _ if depth == 0 => out.push(c),
            _ => {}
        }
    }
    out
}

/// Lower-cased whitespace-separated words, with punctuation trimmed from both
/// ends (an inner apostrophe or hyphen stays). Words that were only
/// punctuation are dropped.
fn tokenize(text: &str) -> Vec<String> {
    text.split_whitespace()
        .map(|w| {
            w.trim_matches(|c: char| !c.is_alphanumeric())
                .to_lowercase()
        })
        .filter(|w| !w.is_empty())
        .collect()
}

/// The conjunctions the coordination rule cuts at. `or` is absent: a
/// disjunction asserts neither side.
const COORDINATORS: [&str; 4] = ["and", "but", "whereas", "while"];

/// Auxiliaries, copulas and modals.
const AUXILIARIES: [&str; 33] = [
    "is", "are", "was", "were", "has", "have", "had", "does", "do", "did", "can", "could", "will",
    "would", "shall", "should", "may", "might", "must", "cannot", "isn't", "aren't", "wasn't",
    "weren't", "hasn't", "haven't", "hadn't", "doesn't", "don't", "didn't", "can't", "won't",
    "couldn't",
];

/// Frequent finite verbs of the corpus that the `-ed` rule cannot see: third
/// person singular presents and irregular pasts.
const FINITE_VERBS: [&str; 64] = [
    "increases",
    "decreases",
    "shows",
    "binds",
    "causes",
    "reduces",
    "requires",
    "uses",
    "returns",
    "fails",
    "passes",
    "holds",
    "gives",
    "takes",
    "makes",
    "yields",
    "produces",
    "contains",
    "remains",
    "becomes",
    "became",
    "exists",
    "needs",
    "runs",
    "ran",
    "writes",
    "wrote",
    "reads",
    "rose",
    "fell",
    "grew",
    "found",
    "led",
    "leads",
    "means",
    "works",
    "breaks",
    "broke",
    "keeps",
    "kept",
    "went",
    "goes",
    "gets",
    "got",
    "depends",
    "supports",
    "contradicts",
    "refutes",
    "implies",
    "predicts",
    "matches",
    "differs",
    "exceeds",
    "drops",
    "rises",
    "falls",
    "appears",
    "occurs",
    "lacks",
    "allows",
    "prevents",
    "enables",
    "skips",
    "stores",
];

/// Words after which an `-ed` form is a modifier, not a finite verb
/// (`the filtered rows`, `of retired edges`).
const MODIFIER_LEADS: [&str; 20] = [
    "the", "a", "an", "this", "that", "these", "those", "its", "their", "each", "every", "any",
    "no", "of", "in", "by", "with", "for", "to", "from",
];

/// Prepositions that, right after an `-ed` form, mark it as a participial
/// modifier (`the arm, measured under two buffers, turns`). `by` and `to` are
/// left out: `increased by 20%` and `dropped to zero` are finite far more
/// often than not.
const PARTICIPLE_TAILS: [&str; 17] = [
    "under", "from", "on", "in", "with", "at", "for", "as", "during", "using", "via", "across",
    "over", "through", "into", "within", "against",
];

/// `-ed` words that are not past forms.
const NOT_PAST_FORMS: [&str; 5] = ["embed", "hundred", "sacred", "naked", "wicked"];

/// Whether `tokens[i]` reads as a finite verb. `first_part` is true for the
/// part before the first coordinator, which must carry its own subject: there
/// an `-ed` form in first position is a modifier (`Retired edges …`), while a
/// later part may open with one (`… and decreased C`, subject shared).
fn is_finite_verb(tokens: &[String], i: usize, first_part: bool) -> bool {
    let t = tokens[i].as_str();
    if AUXILIARIES.contains(&t) || FINITE_VERBS.contains(&t) {
        return true;
    }
    if t.len() < 4 || !t.ends_with("ed") || t.ends_with("eed") || NOT_PAST_FORMS.contains(&t) {
        return false;
    }
    if tokens
        .get(i + 1)
        .is_some_and(|next| PARTICIPLE_TAILS.contains(&next.as_str()))
    {
        return false;
    }
    if i == 0 {
        return !first_part;
    }
    !MODIFIER_LEADS.contains(&tokens[i - 1].as_str())
}

/// Number of coordinated clauses in one `;`-free piece: its parts between
/// coordinators that hold a finite verb and at least two words, and never
/// less than 1. A coordinator between two numbers (`between 3 and 5`) does not
/// cut.
fn coordinated_clauses(tokens: &[String]) -> usize {
    let starts_with_digit = |t: &String| t.chars().next().is_some_and(|c| c.is_ascii_digit());
    let mut clauses = 0;
    let mut part: Vec<String> = Vec::new();
    let mut first_part = true;
    let mut close = |part: &mut Vec<String>, first_part: &mut bool| {
        if part.len() >= 2 && (0..part.len()).any(|i| is_finite_verb(part, i, *first_part)) {
            clauses += 1;
        }
        part.clear();
        *first_part = false;
    };
    for (i, t) in tokens.iter().enumerate() {
        let numeric_range = i > 0
            && i + 1 < tokens.len()
            && starts_with_digit(&tokens[i - 1])
            && starts_with_digit(&tokens[i + 1]);
        if COORDINATORS.contains(&t.as_str()) && !numeric_range {
            close(&mut part, &mut first_part);
        } else {
            part.push(t.clone());
        }
    }
    close(&mut part, &mut first_part);
    clauses.max(1)
}

/// Items of an inline enumeration in `sentence`: the longest of the runs
/// `(1) (2) …` / `1) 2) …`, `(a) (b) …` and `(i) (ii) …` that starts at its
/// first label and keeps order. 0 when no run reaches two items.
fn inline_enumeration_items(sentence: &str) -> usize {
    const ROMAN: [&str; 8] = ["i", "ii", "iii", "iv", "v", "vi", "vii", "viii"];
    let (mut number, mut letter, mut roman) = (0usize, 0u8, 0usize);
    for word in sentence.split_whitespace() {
        let word = word.trim_end_matches([',', ';', ':', '.']);
        let Some(body) = word.strip_suffix(')') else {
            continue;
        };
        let (label, parenthesised) = match body.strip_prefix('(') {
            Some(inner) => (inner, true),
            None => (body, false),
        };
        if label.is_empty() || label.len() > 4 {
            continue;
        }
        if label.chars().all(|c| c.is_ascii_digit()) {
            if label.parse::<usize>().ok() == Some(number + 1) {
                number += 1;
            }
            continue;
        }
        // A bare `a)` is too often the tail of a parenthetical; letters and
        // roman numerals need both brackets.
        if !parenthesised {
            continue;
        }
        if roman < ROMAN.len() && label == ROMAN[roman] {
            roman += 1;
        }
        if label.len() == 1 && label.as_bytes()[0] == b'a' + letter && letter < 26 {
            letter += 1;
        }
    }
    let items = number.max(letter as usize).max(roman);
    if items >= 2 {
        items
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_short_sentence_looks_atomic() {
        assert_eq!(sentence_count("Water boils at 100 C at sea level."), 1);
        assert!(looks_atomic("Water boils at 100 C at sea level."));
        // No terminal punctuation at all is still one sentence.
        assert!(looks_atomic("Gravity bends light"));
    }

    #[test]
    fn two_sentences_are_not_atomic_even_when_short() {
        let t = "Gravity bends light. Time dilates near mass.";
        assert_eq!(sentence_count(t), 2);
        assert!(
            !looks_atomic(t),
            "two sentences are compound regardless of length"
        );
        assert_eq!(sentence_count("Is it true? Yes! It is."), 3);
    }

    #[test]
    fn one_long_sentence_is_not_atomic() {
        let long = format!("The system {} works.", "really ".repeat(30));
        assert_eq!(sentence_count(&long), 1);
        assert!(long.chars().count() > ATOMIC_MAX_CHARS);
        assert!(
            !looks_atomic(&long),
            "over the char cap is compound-suspect"
        );
    }

    #[test]
    fn the_char_cap_is_inclusive_and_counts_chars_not_bytes() {
        let exact = "a".repeat(ATOMIC_MAX_CHARS);
        assert!(looks_atomic(&exact), "exactly the cap is still atomic");
        let over = "a".repeat(ATOMIC_MAX_CHARS + 1);
        assert!(!looks_atomic(&over));
        // 160 two-byte chars: 320 bytes, 160 chars -> atomic.
        let multibyte = "é".repeat(ATOMIC_MAX_CHARS);
        assert!(multibyte.len() > ATOMIC_MAX_CHARS);
        assert!(looks_atomic(&multibyte), "cap is in chars, not bytes");
    }

    #[test]
    fn decimals_and_dotted_names_are_not_boundaries() {
        assert_eq!(sentence_count("Version 3.5 of epigraph.io ships in Q3."), 1);
        assert_eq!(sentence_count("pH was 7.4 in the sample"), 1);
    }

    #[test]
    fn lowercase_after_a_period_is_not_a_boundary() {
        // Conservative in the other direction would be wrong here: "etc. and"
        // continues the sentence.
        assert_eq!(sentence_count("apples, pears, etc. are fruit"), 1);
    }

    #[test]
    fn line_breaks_between_non_blank_lines_are_boundaries() {
        assert_eq!(sentence_count("- first point\n- second point"), 2);
        assert_eq!(sentence_count("First line.\nSecond line."), 2);
        // A trailing newline adds nothing.
        assert_eq!(sentence_count("Only line.\n\n"), 1);
    }

    #[test]
    fn empty_text_has_no_sentences() {
        assert_eq!(sentence_count(""), 0);
        assert_eq!(sentence_count("   "), 0);
    }

    // --- conjunct screen ---

    fn screen(t: &str) -> ConjunctScreen {
        conjunct_screen(t)
    }

    #[test]
    fn a_single_assertion_screens_atomic() {
        let s = screen("Water boils at 100 C at sea level.");
        assert_eq!(
            s,
            ConjunctScreen {
                sentences: 1,
                clause_joins: 0,
                quantities: 1,
                conjunct_count: 1
            }
        );
        assert!(!s.is_compound());
    }

    #[test]
    fn a_noun_phrase_and_is_not_a_conjunct() {
        let s = screen("Apples and pears are fruit.");
        assert_eq!(s.clause_joins, 0);
        assert_eq!(s.conjunct_count, 1);
        assert!(!s.is_compound());
    }

    #[test]
    fn a_comma_list_tail_is_not_a_join() {
        let s = screen("Apples, pears, and plums are fruit.");
        assert_eq!(s.clause_joins, 0, "{s:?}");
        assert!(!s.is_compound());
    }

    #[test]
    fn one_sentence_joining_two_clauses_screens_compound() {
        // `looks_atomic` accepts this: one sentence, under the char cap. The
        // screen is what catches it.
        let t = "The catalyst raised the yield, but it shortened the column life.";
        assert!(looks_atomic(t));
        let s = screen(t);
        assert_eq!(s.sentences, 1);
        assert_eq!(s.clause_joins, 1);
        assert_eq!(s.conjunct_count, 2);
        assert!(s.is_compound());
        let semi = screen("The pump failed; the backup took over within seconds.");
        assert_eq!(semi.clause_joins, 1);
        assert!(semi.is_compound());
        let whereas = screen("Group A improved whereas group B declined.");
        assert_eq!(whereas.clause_joins, 1);
        assert!(whereas.is_compound());
        let comma_whereas = screen("Group A improved, whereas group B declined.");
        assert_eq!(comma_whereas.clause_joins, 1, "counted once, not twice");
    }

    #[test]
    fn a_trailing_semicolon_joins_nothing() {
        assert_eq!(screen("The pump failed;").clause_joins, 0);
    }

    #[test]
    fn several_sentences_screen_compound() {
        let s = screen("Gravity bends light. Time dilates near mass.");
        assert_eq!(s.sentences, 2);
        assert_eq!(s.conjunct_count, 2);
        assert!(s.is_compound());
    }

    #[test]
    fn quantities_count_distinct_numbers_not_identifiers_or_years() {
        // A decimal is one quantity; Q3 and epigraph.io are not quantities.
        assert_eq!(
            screen("Version 3.5 of epigraph.io ships in Q3.").quantities,
            1
        );
        assert_eq!(
            screen("CO2 and H2O levels rose in COVID-19 wards").quantities,
            0
        );
        assert_eq!(
            screen("In 2020 the yield was 40%.").quantities,
            1,
            "a year is context"
        );
        assert_eq!(
            screen("Particles were 3-5 nm wide.").quantities,
            1,
            "a range is one"
        );
        assert_eq!(screen("Particles were 3\u{2013}5 nm wide.").quantities, 1);
        assert_eq!(screen("The run took 1,200 seconds.").quantities, 1);
        assert_eq!(
            screen("Both arms took 12 days and 12 days.").quantities,
            1,
            "distinct"
        );
    }

    #[test]
    fn two_quantities_are_one_fact_three_are_several() {
        let change = screen("Throughput rose from 40 to 55 requests per second.");
        assert_eq!(change.quantities, 2);
        assert_eq!(change.conjunct_count, 1);
        assert!(!change.is_compound(), "a change from one value to another");
        let three = screen("The sample held 12 mg iron with 3 mg zinc at 7.4 pH");
        assert_eq!(three.quantities, 3);
        assert_eq!(three.sentences, 1);
        assert_eq!(three.conjunct_count, 2);
        assert!(
            three.is_compound(),
            "three numbers bound to different referents"
        );
    }

    /// Single assertions in the shapes that made up most of a 50-atom sample
    /// of what the compound-atom sweep flagged (backlog `705e5980`): surface
    /// and crystallographic notation, scientific notation, a value with its
    /// uncertainty, and an abbreviation followed by a capital or a digit.
    /// Each is ONE assertion and must not screen compound.
    const NOTATION_ATOMS: [&str; 24] = [
        "The Si(100)\u{2212}2\u{d7}1 surface reconstructs at 300 K.",
        "Dimers on Si(100)-2x1 buckle below 120 K.",
        "The Ge(001) c(4\u{d7}2) phase is stable at 80 K.",
        "Growth on the (111) facet proceeds layer by layer at 600 C.",
        "The [110] direction has the lowest barrier of 0.3 eV.",
        "The Si(111)-7\u{d7}7 unit cell holds 12 adatoms.",
        "The rate constant is 1.625 \u{d7} 10^4 M^-1 s^-1 at 298 K.",
        "The diffusion coefficient was 2.3\u{d7}10^-9 m^2/s in water.",
        "The tip apex radius is about 3 x 10^-9 m.",
        "Absorption peaks at 1.5e-3 cm^-1 above 400 K.",
        "The binding yield was 78 \u{b1} 14% across 3 runs.",
        "The barrier is 0.82 \u{b1} 0.05 eV on the 2\u{d7}1 surface.",
        "The measured gap is 1.12 +/- 0.02 eV at 300 K.",
        "As shown in Sec. III, the barrier is 0.8 eV.",
        "The tip is stable, as Fig. 2 shows for 5 scans.",
        "Eq. 4 gives a rate of 10 per second.",
        "The dimer, e.g. The one in the corner, is buckled.",
        "Smith et al. Measured a barrier of 0.7 eV.",
        "Hydrogen passivation, i.e. H termination, lowers reactivity.",
        "Approx. 40 percent of sites were occupied.",
        "Ref. 12 reports the same 2.1 eV barrier.",
        "Si vs. Ge surfaces differ in dimer buckling.",
        "Figs. 3 and 4 show the same 7\u{d7}7 pattern.",
        "The cell, cf. Tab. 2, holds 64 atoms.",
    ];

    /// Genuinely compound controls in the same vocabulary: they must stay
    /// compound after the notation rules.
    const COMPOUND_CONTROLS: [&str; 7] = [
        "The Si(100) surface reconstructs at 300 K. The Ge(001) surface does not.",
        "The barrier is 0.8 eV, but the prefactor is unknown.",
        "Dimers buckle below 120 K; adatoms hop above 400 K.",
        "The sample held 12 mg iron with 3 mg zinc at 7.4 pH",
        "As shown in Sec. III, the barrier is 0.8 eV. The rate is 10 per second.",
        "The yield was 78 \u{b1} 14% at 300 K, 55 \u{b1} 9% at 350 K and 20 \u{b1} 4% at 400 K.",
        "Group A improved whereas group B declined.",
    ];

    #[test]
    fn notation_and_abbreviations_do_not_make_a_claim_compound() {
        let flagged: Vec<(&str, ConjunctScreen)> = NOTATION_ATOMS
            .iter()
            .map(|t| (*t, screen(t)))
            .filter(|(_, s)| s.is_compound())
            .collect();
        assert!(
            flagged.is_empty(),
            "{} of {} single assertions screen compound: {flagged:#?}",
            flagged.len(),
            NOTATION_ATOMS.len()
        );
    }

    #[test]
    fn compound_controls_stay_compound_under_the_notation_rules() {
        for t in COMPOUND_CONTROLS {
            assert!(screen(t).is_compound(), "{t:?}: {:?}", screen(t));
        }
    }

    #[test]
    fn notation_counts_as_one_quantity_or_none() {
        // Surface notation is a name, not a measurement.
        assert_eq!(screen("Si(100)\u{2212}2\u{d7}1").quantities, 0);
        assert_eq!(screen("Si(111)-7x7").quantities, 0);
        assert_eq!(screen("the (111) facet").quantities, 0);
        assert_eq!(screen("the [1\u{304}10] direction").quantities, 0);
        // A citation in square brackets is not a quantity.
        assert_eq!(screen("as reported [12, 14]").quantities, 0);
        // A product or dimension is one quantity.
        assert_eq!(screen("a 2\u{d7}1 cell").quantities, 1);
        assert_eq!(screen("a 3 x 4 mm chip").quantities, 1);
        // Scientific notation is one quantity, however it is written.
        assert_eq!(screen("1.625 \u{d7} 10^4").quantities, 1);
        assert_eq!(screen("2.3\u{d7}10^-9").quantities, 1);
        assert_eq!(screen("6 x 10^{23}").quantities, 1);
        assert_eq!(screen("1.6e-4 and 2.5E4").quantities, 2);
        // A unit exponent is not a quantity.
        assert_eq!(screen("400 cm^-1").quantities, 1);
        assert_eq!(screen("9.8 m s^2").quantities, 1);
        // A value and its uncertainty are one quantity.
        assert_eq!(screen("78 \u{b1} 14%").quantities, 1);
        assert_eq!(screen("1.12 +/- 0.02 eV").quantities, 1);
        assert_eq!(screen("0.82\u{b1}0.05").quantities, 1);
        // A unicode minus range is one, like a dash range.
        assert_eq!(screen("3\u{2212}5 nm").quantities, 1);
        // A figure, equation, section or reference number is a label.
        assert_eq!(screen("Fig. 3 shows 5 nm").quantities, 1);
        assert_eq!(screen("Eq. (4) and Table 2 give 7.5 eV").quantities, 1);
        // A short parenthesised number is still a quantity (an enumeration or
        // a bare count), as before.
        assert_eq!(screen("(1) A, (2) B and (3) C").quantities, 3);
    }

    #[test]
    fn the_screen_does_not_split_sentences_at_abbreviations() {
        for t in [
            "As shown in Sec. III, the barrier is 0.8 eV.",
            "Fig. 2 shows the tip.",
            "Eqs. 3 and 4 agree.",
            "Smith et al. Measured it.",
            "A dimer, e.g. The corner one, buckles.",
            "Hydrogen, i.e. H termination, passivates.",
            "Si vs. Ge differ.",
            "Approx. 40 percent remain.",
        ] {
            assert_eq!(screen(t).sentences, 1, "{t:?}");
        }
        // A real boundary after an abbreviated sentence still counts, and so
        // does one after an ordinary word.
        assert_eq!(screen("See Fig. 2. The tip is sharp.").sentences, 2);
        assert_eq!(screen("The tip is sharp. Fig. 2 shows it.").sentences, 2);
        // `etc.` and initials are not on the list: they end sentences too
        // often.
        assert_eq!(screen("A, B, etc. The rest failed.").sentences, 2);
    }

    #[test]
    fn looks_atomic_keeps_counting_abbreviation_boundaries() {
        // The abbreviation rule is the screen's only. `sentence_count` and
        // `looks_atomic` decide what `decompose_claims` skips, and they keep
        // erring toward a boundary (see `sentence_count`).
        assert_eq!(sentence_count("As shown in Sec. III, it holds."), 2);
        assert!(!looks_atomic("As shown in Sec. III, it holds."));
        assert_eq!(sentence_count("Fig. 2 shows the tip."), 2);
    }

    #[test]
    fn the_count_is_never_below_the_sentence_count() {
        for t in [
            "",
            "One.",
            "One. Two. Three.",
            "- a\n- b\n- c",
            "A rose, and B fell; C held at 3, 4, 5 and 6.",
        ] {
            let s = screen(t);
            assert!(s.conjunct_count >= s.sentences, "{t:?}: {s:?}");
        }
        assert_eq!(screen(""), ConjunctScreen::default());
    }

    // ── conjunct_estimate ────────────────────────────────────────────────────

    fn est(text: &str) -> (usize, Vec<&'static str>) {
        let e = conjunct_estimate(text);
        (e.count, e.signals)
    }

    #[test]
    fn split_matches_count() {
        for t in [
            "",
            "   ",
            "Gravity bends light",
            "Gravity bends light. Time dilates near mass.",
            "Is it true? Yes! It is.",
            "Version 3.5 of epigraph.io ships in Q3.",
            "apples, pears, etc. are fruit",
            "- first point\n- second point",
            "First line.\nSecond line.",
            "Only line.\n\n",
            "He said \"stop.\" Then it stopped.\n\nlast line",
        ] {
            assert_eq!(
                split_sentences(t).len(),
                sentence_count(t),
                "split_sentences and sentence_count disagree on {t:?}"
            );
        }
        assert_eq!(
            split_sentences("First line.\nSecond one. Third."),
            vec!["First line.", "Second one.", "Third."]
        );
    }

    #[test]
    fn a_single_assertion_estimates_one_with_no_signal() {
        for t in [
            "Water boils at 100 C at sea level.",
            "The rotor arm friction coefficient is about 4e-22 N m s.",
            // Coordinated NOUN phrases, one predicate.
            "Claims and edges are tenanted by owner group.",
            "Protein A binds B and C.",
            // Coordinated adjectives.
            "The scaffold is longer and stiffer than the staple strands.",
            // A numeric range.
            "The yield was between 3 and 5 percent when the buffer was fresh.",
            // Modifiers ending in -ed are not finite verbs.
            "Retired edges and deprecated claims are hidden from recall.",
            // A disjunction asserts neither side.
            "The run fails or the token is refused.",
            // Punctuation inside parentheses cuts nothing.
            "The effect was significant (p < 0.05; n = 12 and 14).",
            // An imperative protocol step with a compound object.
            "Mix the scaffold and the staples in folding buffer.",
        ] {
            assert_eq!(est(t), (1, vec![]), "{t:?}");
            assert!(!conjunct_estimate(t).compound_suspect(), "{t:?}");
        }
    }

    #[test]
    fn blank_text_estimates_zero() {
        assert_eq!(est(""), (0, vec![]));
        assert_eq!(est("  \n "), (0, vec![]));
    }

    #[test]
    fn sentences_are_summed() {
        assert_eq!(
            est("Gravity bends light. Time dilates near mass."),
            (2, vec![SIGNAL_SENTENCES])
        );
        assert_eq!(
            est("- the sweep is read-only\n- labels are written by the caller\n- nothing is superseded"),
            (3, vec![SIGNAL_SENTENCES])
        );
    }

    #[test]
    fn semicolons_outside_parentheses_cut() {
        assert_eq!(
            est("Folding buffer: Tris 50 mM; NaCl 100 mM; MgCl2 12.5 mM."),
            (3, vec![SIGNAL_SEMICOLON])
        );
        assert_eq!(
            est("The migration adds the column; the backfill fills it."),
            (2, vec![SIGNAL_SEMICOLON])
        );
        // A trailing semicolon adds no empty piece.
        assert_eq!(est("The migration adds the column;"), (1, vec![]));
    }

    #[test]
    fn coordination_counts_only_parts_with_a_finite_verb() {
        // Two full clauses.
        assert_eq!(
            est("The test passed and the build failed."),
            (2, vec![SIGNAL_COORDINATION])
        );
        // Shared subject, two predicates.
        assert_eq!(
            est("The inhibitor increased the folding yield and decreased aggregation."),
            (2, vec![SIGNAL_COORDINATION])
        );
        assert_eq!(
            est("Magnesium stabilises the lattice but EDTA is required for release."),
            // `stabilises` is outside the closed list: one part counts.
            (1, vec![])
        );
        assert_eq!(
            est("Magnesium is needed for folding but EDTA is required for release."),
            (2, vec![SIGNAL_COORDINATION])
        );
        assert_eq!(
            est("Salt and pepper are spices and sugar is sweet, whereas vinegar is sour."),
            (3, vec![SIGNAL_COORDINATION])
        );
        // The estimate and `looks_atomic` are independent rules.
        assert!(looks_atomic("The test passed and the build failed."));
        assert!(conjunct_estimate("The test passed and the build failed.").compound_suspect());
    }

    #[test]
    fn inline_enumerations_count_their_items() {
        assert_eq!(
            est("The screen reports (1) the sentence count, (2) the clause count and (3) the signals."),
            (3, vec![SIGNAL_ENUMERATION])
        );
        assert_eq!(
            est("Three failure modes: (a) no token, (b) wrong scope, (c) expired grant."),
            (3, vec![SIGNAL_ENUMERATION])
        );
        assert_eq!(
            est("Two phases: (i) spine ingest, (ii) atom extraction."),
            (2, vec![SIGNAL_ENUMERATION])
        );
        // One label is a reference, not a list; and a run must start at 1.
        assert_eq!(est("The result of step (2) is reused."), (1, vec![]));
        assert_eq!(est("See equation (1) for the definition."), (1, vec![]));
    }

    /// A participial phrase is not a clause: `measured under …` modifies the
    /// subject, and the coordinated nouns inside it cut nothing.
    #[test]
    fn a_participial_phrase_is_not_a_clause() {
        assert_eq!(
            est(
                "The rotor arm, measured under several buffer conditions and temperatures, \
                 turns with a friction coefficient of about 4e-22 N m s."
            ),
            (1, vec![])
        );
        // `by` stays finite: the common quantitative phrasing must count.
        assert_eq!(
            est("The folding yield increased by 20% and aggregation decreased by half."),
            (2, vec![SIGNAL_COORDINATION])
        );
    }

    /// The documented false positive, pinned so a change to the `-ed` rule
    /// has to update the doc comment with it.
    #[test]
    fn a_participle_after_a_conjunction_is_a_known_false_positive() {
        assert_eq!(
            est("The kit contains buffer and prepared slides."),
            (2, vec![SIGNAL_COORDINATION])
        );
    }

    #[test]
    fn respectively_binds_two_referents() {
        assert_eq!(
            est("The melting points of the two designs were 52 C and 58 C, respectively."),
            (2, vec![SIGNAL_RESPECTIVELY])
        );
    }

    #[test]
    fn signals_combine_in_fixed_order() {
        let e = conjunct_estimate(
            "The first run passed and the second run failed; the cause was a stale token. \
             Retries were disabled.",
        );
        assert_eq!(e.count, 4);
        assert_eq!(
            e.signals,
            vec![SIGNAL_SENTENCES, SIGNAL_SEMICOLON, SIGNAL_COORDINATION]
        );
        assert!(e.compound_suspect());
    }
}
