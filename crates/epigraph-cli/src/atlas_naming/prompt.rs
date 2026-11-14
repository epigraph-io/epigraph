//! The naming prompt, its carry-over key, the sample order and the reply
//! check (pure).

use sha2::{Digest, Sha256};
use uuid::Uuid;

/// The prompt's version. It enters every key, so changing the prompt renames
/// every group once.
pub const PROMPT_VERSION: &str = "atlas-names/1";
/// Member texts in one prompt.
pub const SAMPLE_SIZE: usize = 12;
/// Candidates read per group: the sample is the first [`SAMPLE_SIZE`] of
/// them whose text the map may draw now.
pub const CANDIDATES: usize = 2 * SAMPLE_SIZE;
/// Characters of one member text in the prompt.
pub const TEXT_CHARS: usize = 300;
/// Children's names in an inner group's prompt.
pub const MAX_CHILD_NAMES: usize = 40;
/// The longest name accepted (the contract allows 120).
pub const MAX_NAME_CHARS: usize = 80;
/// The most words accepted in a name (the prompt asks for 2 to 6).
pub const MAX_NAME_WORDS: usize = 8;
/// A name sharing this many consecutive words with a sampled text quotes it
/// instead of naming the group, and is refused.
pub const QUOTE_WORDS: usize = 5;

/// A claim's place in every sample order: SHA-256 of its id. Independent of
/// the group, so a parent's sample overlaps its children's, and a new claim
/// enters a sample only if it ranks in it.
#[must_use]
pub fn rank(id: Uuid) -> [u8; 32] {
    Sha256::digest(id.as_bytes()).into()
}

/// A member text as it goes into a prompt: whitespace collapsed, cut to
/// [`TEXT_CHARS`] characters.
#[must_use]
pub fn clip_text(text: &str) -> String {
    let flat = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() <= TEXT_CHARS {
        return flat;
    }
    let mut out: String = flat.chars().take(TEXT_CHARS - 1).collect();
    out.push('…');
    out
}

/// What one group's prompt is made of.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromptInput {
    /// A theme root (depth 0).
    pub theme_root: bool,
    /// The names of the group's children, in display order.
    pub child_names: Vec<String>,
    /// The sampled member claims: id and clipped text, in sample order.
    pub members: Vec<(Uuid, String)>,
}

impl PromptInput {
    /// Nothing to name the group from.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.child_names.is_empty() && self.members.is_empty()
    }
}

/// The prompt for one group.
#[must_use]
pub fn build_prompt(input: &PromptInput) -> String {
    let what = if input.theme_root {
        "a whole topic (a theme)"
    } else {
        "one group of claims inside a topic"
    };
    let mut p = format!(
        "You are naming {what} in a map of a knowledge graph ({PROMPT_VERSION}).\n\
         Reply with ONLY a JSON object of the form {{\"name\": \"...\"}}.\n\
         The name is a noun phrase of 2 to 6 words that says what the group is about. \
         Summarise; do not copy words from a claim. No quotation marks, no final period.\n"
    );
    if !input.child_names.is_empty() {
        p.push_str("\nIts subgroups are named:\n");
        for n in &input.child_names {
            p.push_str("- ");
            p.push_str(n);
            p.push('\n');
        }
    }
    if !input.members.is_empty() {
        p.push_str("\nA sample of its claims:\n");
        for (i, (_, t)) in input.members.iter().enumerate() {
            p.push_str(&format!("{}. {t}\n", i + 1));
        }
    }
    p
}

/// The carry-over key of one group's name: lower-hex SHA-256 over the prompt
/// version, the map, the theme, the sampled member ids and the whole prompt
/// (its texts and its children's names). A name is copied from an earlier
/// run only under an equal key, so only when the model would see exactly the
/// same input now.
#[must_use]
pub fn naming_key(map_key: &str, theme_id: Uuid, input: &PromptInput, prompt: &str) -> String {
    let mut h = Sha256::new();
    let mut field = |b: &[u8]| {
        h.update((b.len() as u64).to_le_bytes());
        h.update(b);
    };
    field(b"atlas-names");
    field(PROMPT_VERSION.as_bytes());
    field(map_key.as_bytes());
    field(theme_id.as_bytes());
    for (id, _) in &input.members {
        field(id.as_bytes());
    }
    field(prompt.as_bytes());
    hex::encode(h.finalize())
}

/// Lowercase alphanumeric words of `s`.
fn words(s: &str) -> Vec<String> {
    s.split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(str::to_lowercase)
        .collect()
}

/// The JSON object in a reply: a code fence and surrounding prose are
/// tolerated.
fn reply_object(reply: &str) -> Option<serde_json::Value> {
    let start = reply.find('{')?;
    let end = reply.rfind('}')?;
    if end <= start {
        return None;
    }
    serde_json::from_str::<serde_json::Value>(&reply[start..=end]).ok()
}

/// Check a model reply and return the name in it.
///
/// # Errors
/// Why the reply was refused: no JSON object with a string `name`; a name
/// that is empty, holds a control character (a newline included), is over
/// [`MAX_NAME_CHARS`] characters or [`MAX_NAME_WORDS`] words, or shares
/// [`QUOTE_WORDS`] consecutive words with one of `texts`.
pub fn validate_reply(reply: &str, texts: &[&str]) -> Result<String, String> {
    let obj = reply_object(reply).ok_or("the reply holds no JSON object")?;
    let raw = obj
        .get("name")
        .and_then(serde_json::Value::as_str)
        .ok_or("the reply has no string `name`")?;
    if raw.chars().any(char::is_control) {
        return Err("the name holds a control character".into());
    }
    let name =
        raw.trim_matches(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '`' | '“' | '”'));
    let name = name
        .trim_end_matches(|c: char| c == '.' || c.is_whitespace())
        .trim_matches(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '`' | '“' | '”'));
    let name = name
        .split(' ')
        .filter(|w| !w.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    if name.is_empty() {
        return Err("the name is empty".into());
    }
    let chars = name.chars().count();
    if chars > MAX_NAME_CHARS {
        return Err(format!(
            "the name has {chars} characters, over {MAX_NAME_CHARS}"
        ));
    }
    let nw = words(&name);
    if nw.is_empty() {
        return Err("the name holds no word".into());
    }
    if nw.len() > MAX_NAME_WORDS {
        return Err(format!(
            "the name has {} words, over {MAX_NAME_WORDS}",
            nw.len()
        ));
    }
    if nw.len() >= QUOTE_WORDS {
        for t in texts {
            let tw = words(t);
            for window in nw.windows(QUOTE_WORDS) {
                if tw.windows(QUOTE_WORDS).any(|w| w == window) {
                    return Err(format!(
                        "the name quotes {QUOTE_WORDS} consecutive words of a claim"
                    ));
                }
            }
        }
    }
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEXT: &str = "The lattice constant of diamond is 3.567 angstrom at room temperature";

    #[test]
    fn a_plain_reply_is_accepted_and_trimmed() {
        assert_eq!(
            validate_reply(
                "{\"name\": \" \\\"Diamond lattice geometry\\\". \"}",
                &[TEXT]
            ),
            Ok("Diamond lattice geometry".to_string())
        );
        assert_eq!(
            validate_reply(
                "Sure:\n```json\n{\"name\": \"Diamond lattice geometry\"}\n```",
                &[TEXT]
            ),
            Ok("Diamond lattice geometry".to_string())
        );
    }

    #[test]
    fn invalid_replies_are_refused() {
        let long = format!("{{\"name\": \"{}\"}}", "word ".repeat(30).trim());
        let cases = [
            ("not json", "no JSON".to_string()),
            ("{\"label\": \"x\"}", "no name field".to_string()),
            ("{\"name\": \"\"}", "empty".to_string()),
            ("{\"name\": \"Diamond\\nlattice\"}", "newline".to_string()),
            (long.as_str(), "too long".to_string()),
            (
                "{\"name\": \"one two three four five six seven eight nine\"}",
                "too many words".to_string(),
            ),
            (
                "{\"name\": \"constant of diamond is 3\"}",
                "quotes five words".to_string(),
            ),
        ];
        for (reply, why) in cases {
            assert!(validate_reply(reply, &[TEXT]).is_err(), "{why}: {reply}");
        }
        // Four shared words are not a quote.
        assert!(validate_reply("{\"name\": \"Lattice constant of diamond\"}", &[TEXT]).is_ok());
    }

    #[test]
    fn the_key_covers_the_children_names_the_members_and_the_map() {
        let a = Uuid::from_u128(1);
        let theme = Uuid::from_u128(9);
        let input = PromptInput {
            theme_root: false,
            child_names: vec!["Diamond growth".into()],
            members: vec![(a, "text".into())],
        };
        let key = |i: &PromptInput, map: &str| naming_key(map, theme, i, &build_prompt(i));
        let base = key(&input, "public");
        assert_eq!(base, key(&input, "public"));
        let mut renamed = input.clone();
        renamed.child_names[0] = "Diamond etching".into();
        assert_ne!(base, key(&renamed, "public"));
        let mut other = input.clone();
        other.members[0].0 = Uuid::from_u128(2);
        assert_ne!(base, key(&other, "public"));
        assert_ne!(
            base,
            key(&input, "team:00000000-0000-0000-0000-000000000001")
        );
    }

    #[test]
    fn texts_are_clipped_and_flattened() {
        assert_eq!(clip_text("a\n  b\tc"), "a b c");
        let long = "x".repeat(1000);
        assert_eq!(clip_text(&long).chars().count(), TEXT_CHARS);
    }
}
