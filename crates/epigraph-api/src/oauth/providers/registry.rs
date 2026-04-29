//! Provider registry: name and grant_type lookup.

use std::collections::HashMap;
use std::sync::Arc;

use super::traits::{ExternalIdentityProvider, OidcRedirectFlow};

#[derive(Default)]
pub struct ProviderRegistry {
    by_name: HashMap<String, Arc<dyn ExternalIdentityProvider>>,
    by_grant_type: HashMap<String, Arc<dyn ExternalIdentityProvider>>,
    redirect_flows: HashMap<String, Arc<dyn OidcRedirectFlow>>,
}

impl ProviderRegistry {
    pub fn empty() -> Self {
        Self::default()
    }

    /// Register an identity provider. Optionally also a redirect-flow capability.
    pub fn register(
        &mut self,
        provider: Arc<dyn ExternalIdentityProvider>,
        redirect_flow: Option<Arc<dyn OidcRedirectFlow>>,
    ) -> Result<(), String> {
        let name = provider.name().to_string();
        let grant = provider.grant_type().to_string();
        if self.by_name.contains_key(&name) {
            return Err(format!("duplicate provider name: {name}"));
        }
        if self.by_grant_type.contains_key(&grant) {
            return Err(format!("duplicate grant_type: {grant}"));
        }
        self.by_name.insert(name.clone(), provider.clone());
        self.by_grant_type.insert(grant, provider);
        if let Some(rf) = redirect_flow {
            self.redirect_flows.insert(name, rf);
        }
        Ok(())
    }

    pub fn by_name(&self, name: &str) -> Option<Arc<dyn ExternalIdentityProvider>> {
        self.by_name.get(name).cloned()
    }

    pub fn by_grant_type(&self, gt: &str) -> Option<Arc<dyn ExternalIdentityProvider>> {
        self.by_grant_type.get(gt).cloned()
    }

    pub fn redirect_flow(&self, name: &str) -> Option<Arc<dyn OidcRedirectFlow>> {
        self.redirect_flows.get(name).cloned()
    }

    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }

    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.by_name.keys().map(|s| s.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::providers::traits::{
        ExternalIdentity, ExternalIdentityProvider, ProviderError,
    };
    use async_trait::async_trait;

    struct StubProvider {
        name: String,
        grant: String,
    }

    #[async_trait]
    impl ExternalIdentityProvider for StubProvider {
        fn name(&self) -> &str {
            &self.name
        }
        fn grant_type(&self) -> &str {
            &self.grant
        }
        async fn validate(&self, _: &str) -> Result<ExternalIdentity, ProviderError> {
            unimplemented!()
        }
        fn auto_provision(&self) -> bool {
            true
        }
        fn default_scopes(&self) -> &[String] {
            &[]
        }
    }

    fn stub(name: &str, grant: &str) -> Arc<dyn ExternalIdentityProvider> {
        Arc::new(StubProvider {
            name: name.into(),
            grant: grant.into(),
        })
    }

    #[test]
    fn lookup_by_name_and_grant_type() {
        let mut r = ProviderRegistry::empty();
        r.register(stub("google", "google_id_token"), None).unwrap();
        assert!(r.by_name("google").is_some());
        assert!(r.by_grant_type("google_id_token").is_some());
        assert!(r.by_name("missing").is_none());
    }

    #[test]
    fn duplicate_name_rejected() {
        let mut r = ProviderRegistry::empty();
        r.register(stub("google", "google_id_token"), None).unwrap();
        let err = r
            .register(stub("google", "different_grant"), None)
            .unwrap_err();
        assert!(err.contains("duplicate provider name"));
    }

    #[test]
    fn duplicate_grant_type_rejected() {
        let mut r = ProviderRegistry::empty();
        r.register(stub("google", "google_id_token"), None).unwrap();
        let err = r
            .register(stub("other", "google_id_token"), None)
            .unwrap_err();
        assert!(err.contains("duplicate grant_type"));
    }
}
