//! COMPLETION-PLAN §8.4 and §8.5, asserted rather than declared.
//!
//! §8.5's own wording is the reason this file exists:
//!
//! > `open_findings` contains no `FIX-SCHEDULED` entry whose batch has shipped,
//! > and no disposition term outside the declared vocabulary. **Both properties
//! > are asserted by a test, not declared** — each drifted silently during the
//! > cleanup series and nothing failed.
//!
//! and §9 states the general rule: *"A closed vocabulary needs an assertion, not
//! a declaration."* Before this file, `docs/tenancy/progress.json` was cited in
//! 24 test files and parsed by none of them, so both drifts were invisible to
//! the suite. `findings_disposition_2026_09_12.audits.vocabulary_drift_2026_09_13`
//! records that both happened: three findings carried an undeclared term, and
//! two carried `FIX-SCHEDULED` after the batch named in their `fix_batch` had
//! shipped.
//!
//! # Why the vocabulary is READ from the ledger and not listed here
//!
//! A hard-coded copy of the six terms would be a second authority that drifts
//! from the first, which is this series' most-named failure mode. The terms come
//! from `findings_disposition_2026_09_12.vocabulary`'s own KEYS, so adding a
//! term to the ledger is what widens the vocabulary and nothing else can.
//! [`the_vocabulary_block_is_a_non_empty_object_read_from_the_ledger`] is the
//! arm that stops a rename of that block from silently emptying the vocabulary
//! and greening every other assertion here.
//!
//! # Runtime read, not `include_str!` — and the tradeoff, stated
//!
//! The ledger is read at RUN time through `CARGO_MANIFEST_DIR` rather than baked
//! in with `include_str!`. Both were considered:
//!
//! * `include_str!` makes the ledger a compile-time input, so the binary and the
//!   ledger cannot disagree. It costs 1.3 MB of dead weight in the test binary,
//!   and — the deciding reason — it makes every planted mutation a REBUILD. This
//!   series has already paid for that trap: `cp -a` restores a file with the
//!   backup's mtime, cargo then re-runs the stale mutated binary, and the result
//!   is a phantom failure that `sha256sum -c` says cannot exist.
//! * A runtime read decouples mutation from build, at the cost that the test can
//!   in principle read a tree other than the one it was compiled from.
//!
//! The second cost is accepted and named here so a green run is not read as more
//! than it is: **this proves the ledger ON DISK at `../../docs/tenancy/progress.json`
//! satisfies the two properties.** In CI, where the checkout is the tree under
//! test, those are the same file.
//!
//! # Known limits, so nobody over-claims
//!
//! * This is a lint over the ledger's SHAPE. It cannot tell whether a
//!   disposition is the RIGHT one for its entry — only that the term is
//!   declared, that it is not future-tense, and that no obligation is left with
//!   neither a disposition nor an owner.
//! * An entry with no `disposition` key is not a vocabulary violation. On the
//!   tree this landed against, fourteen `closed_findings` and five
//!   `deferred_obligations` entries have no such key; treating absence as an
//!   out-of-vocabulary term would make this file arrive red at nineteen on a
//!   tree whose vocabulary has never drifted. That is also why the `§8.4` arm
//!   below tests absence-of-disposition only in CONJUNCTION with absence of an
//!   owner, and never on its own.

use std::path::{Path, PathBuf};

use serde_json::Value;

/// The three registers §0 of COMPLETION-PLAN defines. Named once so an arm
/// cannot quietly check two of them.
const REGISTERS: &[&str] = &["open_findings", "closed_findings", "deferred_obligations"];

/// The block whose KEYS are the declared vocabulary.
const VOCABULARY_BLOCK: &str = "findings_disposition_2026_09_12";

/// The future-tense term. §8.5 asks for "no `FIX-SCHEDULED` entry whose batch
/// has shipped"; see [`no_entry_carries_the_future_tense_disposition`] for why
/// this file asserts the stronger, decidable property instead.
const FUTURE_TENSE: &str = "FIX-SCHEDULED";

/// The one spelling that means "nobody owns this".
///
/// EXACT match after trimming, and the exactness is load-bearing. A substring
/// test for `unassigned` matches fifteen further entries whose owner NAMES A
/// CONDITION — "unassigned; the next PR that has to explain a non-zero test
/// count should take it", "UNASSIGNED. Whichever slice owns the job runner." —
/// and those are owned, conditionally, which is what §8.4's "unowned" excludes.
/// A `contains("unsch")` variant additionally matches an owner reading
/// "(PR-07/PR-17 per bin/server.rs's own note; unscheduled)". A loose predicate
/// here would arrive red on fifteen correctly-owned entries, and a ratchet that
/// goes red on a working convention gets weakened, which is how ratchets die.
const UNOWNED: &str = "UNASSIGNED";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/epigraph-db has two ancestors")
        .to_path_buf()
}

fn ledger_path() -> PathBuf {
    repo_root().join("docs/tenancy/progress.json")
}

/// The parsed ledger.
///
/// A parse failure surfaces through `expect`, which is correct for the INPUT:
/// a malformed ledger is not a property violation this file has an opinion
/// about, it is a file that cannot be measured at all. Every PROPERTY below
/// fails on its own `assert!`/`assert_eq!` instead — a planted violation that
/// blew up inside an `expect` would prove only that the plant broke the JSON.
fn ledger() -> Value {
    let path = ledger_path();
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read the ledger at {}: {e}", path.display()));
    serde_json::from_str(&raw)
        .unwrap_or_else(|e| panic!("{} is not valid JSON: {e}", path.display()))
}

/// Every `(register, id, disposition)` triple actually present, in ledger order.
///
/// Entries with no `disposition` key are omitted rather than reported as an
/// empty term — see the module doc's second known limit.
///
/// # ABSENT and MALFORMED are different, and only absent is benign
///
/// A `disposition` key whose value is not a JSON string — `["FIX-SCHEDULED"]`,
/// `null`, `1`, a typo'd object — is rendered with `Value::to_string()` and
/// returned as a term rather than skipped. That is deliberate and it is the
/// fail-CLOSED direction: the rendered form (`["FIX-SCHEDULED"]` including its
/// brackets) is not a key of the ledger's vocabulary block, so
/// [`every_disposition_term_is_declared_in_the_ledgers_own_vocabulary`] reports
/// it as undeclared and names the entry.
///
/// The alternative — `and_then(Value::as_str)`, which yields `None` for any
/// non-string — was what this function did first, and it fails OPEN in exactly
/// the direction §8.5 exists to close: a wrong-SHAPED hand edit to a
/// hand-maintained JSON file would vanish from both §8.5 arms while
/// [`some_entry_actually_carries_a_disposition`] stayed green on the other
/// hundred-odd string-valued entries. It would also have read in the OPPOSITE
/// direction from [`no_deferred_obligation_is_both_undischarged_and_unowned`],
/// which treats the same non-string value as undischarged (fail-closed) — one
/// field, two arms, two answers.
///
/// Measured when this was written: zero non-string `disposition` values exist
/// across all three registers, so this closes a latent gap rather than a live
/// one. It is proven non-vacuous by the planted-non-string mutation recorded in
/// this batch's ledger entry.
fn dispositions(ledger: &Value) -> Vec<(&'static str, String, String)> {
    let mut found = Vec::new();
    for register in REGISTERS {
        let entries = ledger[register]
            .as_array()
            .unwrap_or_else(|| panic!("`{register}` is not an array"));
        for entry in entries {
            let id = entry["id"].as_str().unwrap_or("<no id>").to_string();
            match entry.get("disposition") {
                None => {}
                Some(Value::String(term)) => found.push((*register, id, term.clone())),
                Some(malformed) => found.push((*register, id, malformed.to_string())),
            }
        }
    }
    found
}

/// The declared vocabulary: the KEYS of the ledger's own vocabulary block.
fn vocabulary(ledger: &Value) -> Vec<String> {
    ledger[VOCABULARY_BLOCK]["vocabulary"]
        .as_object()
        .map(|o| o.keys().cloned().collect())
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Non-vacuity. Without these three, a moved key or a renamed register turns
// every assertion below into a pass over an empty set — which is precisely the
// failure §8.5 describes: a property that drifted and nothing failed.
// ---------------------------------------------------------------------------

#[test]
fn the_scanner_finds_all_three_registers_and_they_are_populated() {
    let ledger = ledger();
    for register in REGISTERS {
        let entries = ledger[register].as_array();
        assert!(
            entries.is_some_and(|e| !e.is_empty()),
            "register `{register}` is missing or empty in {}; every assertion in \
             this file would pass vacuously over it",
            ledger_path().display()
        );
    }
}

#[test]
fn the_vocabulary_block_is_a_non_empty_object_read_from_the_ledger() {
    let ledger = ledger();
    let terms = vocabulary(&ledger);
    assert!(
        !terms.is_empty(),
        "`{VOCABULARY_BLOCK}.vocabulary` is missing, is not an object, or has no \
         keys. The vocabulary is deliberately NOT hard-coded in this file, so an \
         empty read here would green \
         `every_disposition_term_is_declared_in_the_ledgers_own_vocabulary` \
         against every possible term."
    );
    assert!(
        terms.iter().any(|t| t == FUTURE_TENSE),
        "`{FUTURE_TENSE}` is not among the declared terms {terms:?}. \
         `no_entry_carries_the_future_tense_disposition` asserts a property about \
         that exact spelling; if the ledger has renamed it, that assertion is \
         checking a term nothing can use."
    );
}

#[test]
fn some_entry_actually_carries_a_disposition() {
    let ledger = ledger();
    assert!(
        !dispositions(&ledger).is_empty(),
        "no entry in any register carries a `disposition` key. Either the field \
         was renamed or the registers moved; either way the vocabulary assertion \
         below is measuring nothing."
    );
}

// ---------------------------------------------------------------------------
// §8.5
// ---------------------------------------------------------------------------

/// §8.5, second property: *"no disposition term outside the declared
/// vocabulary"*.
///
/// Checked across all three registers, not just `open_findings`. §8.5 names
/// `open_findings` because that is where the drift was found, but the
/// vocabulary block governs the whole ledger and
/// `disposition_on_obligations` is written register-agnostically. A term is a
/// term wherever it sits, and restricting the scan to one register would leave
/// the other two exactly as unguarded as `open_findings` was.
#[test]
fn every_disposition_term_is_declared_in_the_ledgers_own_vocabulary() {
    let ledger = ledger();
    let terms = vocabulary(&ledger);
    let undeclared: Vec<String> = dispositions(&ledger)
        .into_iter()
        .filter(|(_, _, term)| !terms.contains(term))
        .map(|(register, id, term)| format!("{register}[{id}].disposition = {term:?}"))
        .collect();
    assert!(
        undeclared.is_empty(),
        "{} disposition term(s) are not declared in \
         `{VOCABULARY_BLOCK}.vocabulary` (declared: {terms:?}):\n  {}\n\
         Either the entry is wrong or the vocabulary needs widening IN THE \
         LEDGER — this file has no list of its own to edit.",
        undeclared.len(),
        undeclared.join("\n  ")
    );
}

/// §8.5, first property, asserted in a STRONGER and decidable form: no entry
/// carries the future-tense term at all.
///
/// §8.5 asks for "no `FIX-SCHEDULED` entry **whose batch has shipped**", and
/// that relation is NOT decidable from this ledger. Measured, on the tree this
/// file was written against:
///
/// * `prs.done[].branch` is prose, not a branch name — values run to
///   `"tenancy/conversion-shard-claims-query, based on integration/tenancy at
///   67e1ff1b (the PR-27 merge)"` and one is a multi-sentence note.
/// * Four of the seven `fix_batch`/`batch` values in use name batches that
///   appear in NEITHER registry — neither `prs.done` nor the dated
///   `*_batch_*` blocks — so a shipped-set derived from the ledger is
///   under-inclusive by more than half of its own inputs.
/// * There is no registry of IN-FLIGHT branches, so "has not shipped" cannot be
///   established even where "has shipped" can.
///
/// A parser over those fields would be under-inclusive in exactly the direction
/// that certifies drift as clean, and it would arrive with ZERO live inputs —
/// there is not one `FIX-SCHEDULED` entry in any register today — so nothing
/// but a planted, invented shape would ever exercise it.
///
/// So the term is refused outright, which is the fail-closed reading and
/// implies §8.5's property. `disposition_on_obligations` (b) is the ledger's own
/// statement of the same thing: *"FIX-SCHEDULED is FUTURE TENSE and must not sit
/// beside a status saying the fix has shipped… Once the branch has shipped, the
/// term is CLOSED if the obligation is discharged, or a term naming what still
/// blocks it if it is not."*
///
/// The cost is stated rather than hidden: a future batch that genuinely wants to
/// schedule work cannot use the term until it adds the in-flight registry this
/// assertion would then read. That is the intended friction — the registry is
/// what makes "whose batch has shipped" measurable, and without it the term is
/// a promise nothing can check.
///
/// # This arm is COUPLED to [`the_vocabulary_block_is_a_non_empty_object_read_from_the_ledger`]
///
/// That arm asserts `FIX-SCHEDULED` REMAINS a declared term, while this one
/// forbids any entry from carrying it. The ledger is therefore pinned to
/// declaring a term nothing may use, and that is deliberate rather than an
/// oversight: without the guard, renaming the term in the ledger would leave
/// this assertion checking a dead spelling and silently passing. The
/// consequence to know about is that deleting `FIX-SCHEDULED` from
/// `findings_disposition_2026_09_12.vocabulary` as a tidy-up turns the OTHER
/// arm red — so dropping the term is a deliberate two-arm change here, not a
/// ledger cleanup. Stated in this file because the ledger's vocabulary block is
/// the authority on which terms EXIST and this file is the authority on which
/// of them may be USED.
#[test]
fn no_entry_carries_the_future_tense_disposition() {
    let ledger = ledger();
    let scheduled: Vec<String> = dispositions(&ledger)
        .into_iter()
        .filter(|(_, _, term)| term == FUTURE_TENSE)
        .map(|(register, id, _)| format!("{register}[{id}]"))
        .collect();
    assert!(
        scheduled.is_empty(),
        "{} entr(y/ies) carry the future-tense disposition {FUTURE_TENSE:?}:\n  {}\n\
         This ledger has no registry of in-flight branches, so \"whose batch has \
         shipped\" cannot be decided and the term is refused outright. Use CLOSED \
         if the obligation is discharged, or a term naming what still blocks it.",
        scheduled.len(),
        scheduled.join("\n  ")
    );
}

// ---------------------------------------------------------------------------
// §8.4
// ---------------------------------------------------------------------------

/// §8.4: *"`deferred_obligations` contains no entry that is both undischarged
/// and unowned; every one is discharged, scheduled, or dispositioned with a
/// reason."*
///
/// # Which of the two clauses this asserts, and why not the other
///
/// The two clauses are different predicates and they measure differently. This
/// arm asserts the FIRST — the conjunction, which is §8.4's actual sentence.
///
/// The second clause read as an INDEPENDENT predicate ("every entry has a
/// disposition") is a strictly wider property, and it was considered and
/// rejected on two grounds. It reads naturally as the elaboration of the first
/// sentence rather than a separate requirement — "every one" meaning every one
/// of the entries the first clause is about. And taking it independently would
/// make this file the gatekeeper for four other tracks' bookkeeping: on the tree
/// this was written against, five `deferred_obligations` entries carry no
/// disposition and all five are OWNED, belonging to COMPLETION-PLAN §4.4, to the
/// undelivered 16b write-side gate, and to ops —
///
/// * `D-PR18-stale-cross-group-edges` — owner: PR-18 / §4.4
/// * `D-PR16-reestablish-the-write-gate-call-site-lint` — owner: the 16b gate
/// * `D-PR14-transcription-is-a-deploy-prerequisite` — owner: ops
/// * `D-PR17-request-path-never-stamps-session-gucs` — owner: the route-layer PR
/// * `D-PR17-tenancy-gucs-are-pgc-userset` — owner: the `acquire_as` conversion PR
///
/// — so §4.4's batch would arrive red on an assertion written here and have to
/// edit a register in this crate to land its own work. They are recorded above
/// as a MEASURED NON-VIOLATION of §8.4, not as an exemption list: each satisfies
/// §8.4 because it is owned, and none of them needs an entry anywhere for this
/// file to stay green.
#[test]
fn no_deferred_obligation_is_both_undischarged_and_unowned() {
    let ledger = ledger();
    let entries = ledger["deferred_obligations"]
        .as_array()
        .expect("`deferred_obligations` is an array");
    let orphaned: Vec<String> = entries
        .iter()
        .filter(|entry| {
            let undischarged = entry.get("disposition").and_then(Value::as_str).is_none();
            let owner = entry
                .get("owner")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim();
            let unowned = owner.is_empty() || owner.eq_ignore_ascii_case(UNOWNED);
            undischarged && unowned
        })
        .map(|entry| entry["id"].as_str().unwrap_or("<no id>").to_string())
        .collect();
    assert!(
        orphaned.is_empty(),
        "{} deferred obligation(s) are both undischarged (no `disposition`) and \
         unowned (`owner` is empty or exactly {UNOWNED:?}):\n  {}\n\
         COMPLETION-PLAN §8.4 requires every one to be discharged, scheduled, or \
         dispositioned with a reason. Give it a disposition from \
         `{VOCABULARY_BLOCK}.vocabulary`, or name an owner.",
        orphaned.len(),
        orphaned.join("\n  ")
    );
}
