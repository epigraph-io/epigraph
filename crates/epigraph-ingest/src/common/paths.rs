//! Claim-path normalization shared across hierarchy walkers.
//!
//! Cross-claim relationships in extractions can use either slash-delimited
//! paths (`sections/0/paragraphs/1/atoms/2`) or the bracket-dot form
//! (`sections[0].paragraphs[1].atoms[2]`) that walkers index by. This module
//! folds the slash form into the bracket-dot form so walkers and the path
//! index speak the same dialect.

/// Convert slash-delimited paths from extraction to the bracket-dot notation
/// used by `path_index`. Passes through paths already in bracket-dot form
/// unchanged.
#[must_use]
pub fn normalize_claim_path(path: &str) -> String {
    if path.contains('[') {
        return path.to_string();
    }
    let parts: Vec<&str> = path.split('/').collect();
    let mut result = String::new();
    let mut i = 0;
    while i < parts.len() {
        if i > 0 {
            result.push('.');
        }
        result.push_str(parts[i]);
        if i + 1 < parts.len() && parts[i + 1].parse::<usize>().is_ok() {
            result.push('[');
            result.push_str(parts[i + 1]);
            result.push(']');
            i += 2;
            continue;
        }
        i += 1;
    }
    result
}
