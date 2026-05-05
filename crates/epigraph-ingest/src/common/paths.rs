//! Path-string helpers shared by the document and workflow walkers.
//!
//! `normalize_claim_path` previously lived in `document/builder.rs` and was
//! imported cross-module by `workflow/builder.rs`. It is logic-agnostic to
//! either artifact type, so it belongs here.

/// Convert slash-delimited paths from extraction ("sections/0/paragraphs/1/atoms/2")
/// to the bracket-dot notation used by path_index ("sections[0].paragraphs[1].atoms[2]").
/// Passes through paths that are already in bracket-dot format unchanged.
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
