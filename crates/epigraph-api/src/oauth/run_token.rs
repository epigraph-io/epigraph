//! `grant_type=urn:epigraph:grant:run-token`: a short-lived DELEGATED run
//! token for an operated LLM agent, minted for a host delegator client.
//!
//! See `docs/tenancy.md` ("Delegated run tokens") for the whole contract; this
//! module holds the grant's configuration.

/// The environment variable naming the LLM models a run token may be minted
/// for, read ONCE at boot ([`RunTokenModels::from_env`]).
pub const RUN_TOKEN_MODELS_ENV: &str = "EPIGRAPH_RUN_TOKEN_MODELS";

/// The LLM models (`agents.properties ->> 'llm_model'`) a run token may be
/// minted for. EMPTY in every constructor and when the variable is unset or
/// blank, and an empty list refuses EVERY mint: an operator who arms the
/// grant names the models it serves.
///
/// The list narrows which operator-linked identities a stolen delegator
/// secret could mint for (an operator's own local tooling identity, say). It
/// is not the authority check: that is the delegation's liveness
/// (`AgentRepository::delegated_principal_pool`), re-read on every request.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunTokenModels(Vec<String>);

impl RunTokenModels {
    /// Parse a comma- or whitespace-separated list. Entries are trimmed;
    /// blanks and repeats are dropped; case is kept (model ids are external
    /// identifiers).
    #[must_use]
    pub fn parse(raw: Option<&str>) -> Self {
        let mut out: Vec<String> = Vec::new();
        for entry in raw
            .unwrap_or_default()
            .split(|c: char| c == ',' || c.is_whitespace())
        {
            let entry = entry.trim();
            if !entry.is_empty() && !out.iter().any(|m| m == entry) {
                out.push(entry.to_string());
            }
        }
        Self(out)
    }

    /// [`Self::parse`] of [`RUN_TOKEN_MODELS_ENV`]. For a binary's boot only.
    #[must_use]
    pub fn from_env() -> Self {
        Self::parse(std::env::var(RUN_TOKEN_MODELS_ENV).ok().as_deref())
    }

    /// Whether `model` (trimmed) is listed.
    #[must_use]
    pub fn contains(&self, model: &str) -> bool {
        let model = model.trim();
        self.0.iter().any(|m| m == model)
    }

    /// Whether no model is listed (every mint is refused).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The listed models, in order.
    #[must_use]
    pub fn as_slice(&self) -> &[String] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::RunTokenModels;

    #[test]
    fn unset_or_blank_lists_no_model() {
        for raw in [None, Some(""), Some("  "), Some(" , ,")] {
            let m = RunTokenModels::parse(raw);
            assert!(m.is_empty(), "{raw:?}");
            assert!(!m.contains("claude-sonnet-5"), "{raw:?}");
        }
    }

    #[test]
    fn entries_are_trimmed_deduplicated_and_case_kept() {
        let m = RunTokenModels::parse(Some(" model-a, model-b  model-a\tModel-C "));
        assert_eq!(m.as_slice(), ["model-a", "model-b", "Model-C"]);
        assert!(m.contains(" model-b "));
        assert!(!m.contains("model-c"), "case is significant");
        assert!(!m.contains("model"), "no prefix match");
    }
}
