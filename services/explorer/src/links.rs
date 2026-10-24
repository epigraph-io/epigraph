//! Base-path-aware URL builders for every route in plan §3.4.
//!
//! Behind Caddy `handle_path /explorer*` the prefix is stripped before the
//! request reaches us, so nothing may hard-code `/claim/...`: every link,
//! redirect, `og:url` and form action comes from here. Builders return
//! browser-visible paths (base path included); [`Links::absolute`] adds the
//! public origin for OG tags and OAuth `redirect_uri`.

use std::sync::Arc;

use url::form_urlencoded;
use uuid::Uuid;

use crate::assets;

/// Cheap to clone (two `Arc<str>`s). Held by [`crate::state::AppState`] and
/// by every [`crate::auth::PageCtx`].
#[derive(Clone, Debug)]
pub struct Links {
    origin: Arc<str>,
    base: Arc<str>,
}

/// Search modes accepted by `/search` (plan §3.4).
pub const SEARCH_MODES: &[&str] = &["semantic", "label", "evidence"];

impl Links {
    /// `origin` is scheme+host(+port) without a trailing slash; `base_path`
    /// is `""` or `"/segment[/segment…]"` without a trailing slash (both as
    /// produced by [`crate::config::Config`]).
    pub fn new(origin: &str, base_path: &str) -> Self {
        Self {
            origin: Arc::from(origin.trim_end_matches('/')),
            base: Arc::from(base_path.trim_end_matches('/')),
        }
    }

    pub fn base_path(&self) -> &str {
        &self.base
    }

    /// Base path + a path that starts with `/`.
    pub fn path(&self, p: &str) -> String {
        debug_assert!(p.starts_with('/'), "link paths start with '/': {p}");
        format!("{}{}", self.base, p)
    }

    /// Public origin + a browser-visible path (as returned by any builder).
    pub fn absolute(&self, browser_path: &str) -> String {
        format!("{}{}", self.origin, browser_path)
    }

    /// The browser-visible form of a path+query this service received.
    /// The router answers both with and without the base path (Caddy
    /// `handle_path` strips it, `handle` does not), so a received path that
    /// already starts with the base path is returned unchanged and any other
    /// is prefixed.
    pub fn browser_path(&self, received: &str) -> String {
        let base: &str = &self.base;
        let carries_base = !base.is_empty()
            && received.starts_with(base)
            && matches!(
                received.as_bytes().get(base.len()),
                None | Some(b'/') | Some(b'?')
            );
        if base.is_empty() || carries_base {
            received.to_string()
        } else {
            format!("{base}{received}")
        }
    }

    /// `received` with the base path removed if present — the path the
    /// route table sees. Always starts with `/`.
    pub fn strip_base<'r>(&self, received: &'r str) -> &'r str {
        let base: &str = &self.base;
        if base.is_empty() {
            return received;
        }
        match received.strip_prefix(base) {
            Some("") => "/",
            Some(rest) if rest.starts_with('/') => rest,
            _ => received,
        }
    }

    // ---- pages -----------------------------------------------------------

    /// Landing page. Always ends in `/` (`/explorer/`, or `/` at the root).
    pub fn home(&self) -> String {
        self.path("/")
    }

    /// `/search` with no query (the header search form's action).
    pub fn search_page(&self) -> String {
        self.path("/search")
    }

    /// `/search?q=&mode=&page=`; `mode`/`page` are omitted when `None`.
    pub fn search(&self, q: &str, mode: Option<&str>, page: Option<u32>) -> String {
        let mut qs = form_urlencoded::Serializer::new(String::new());
        qs.append_pair("q", q);
        if let Some(m) = mode {
            qs.append_pair("mode", m);
        }
        if let Some(p) = page {
            qs.append_pair("page", &p.to_string());
        }
        format!("{}?{}", self.path("/search"), qs.finish())
    }

    pub fn claim(&self, id: Uuid) -> String {
        self.path(&format!("/claim/{id}"))
    }

    pub fn claim_history(&self, id: Uuid) -> String {
        self.path(&format!("/claim/{id}/history"))
    }

    pub fn claim_provenance(&self, id: Uuid) -> String {
        self.path(&format!("/claim/{id}/provenance"))
    }

    pub fn claim_graph(&self, id: Uuid) -> String {
        self.path(&format!("/claim/{id}/graph"))
    }

    pub fn theme(&self, id: Uuid) -> String {
        self.path(&format!("/theme/{id}"))
    }

    pub fn community(&self, id: Uuid) -> String {
        self.path(&format!("/community/{id}"))
    }

    /// `/neighborhood/:id`, with `?mode=` when given (`compound`/`atomic`).
    pub fn neighborhood(&self, id: Uuid, mode: Option<&str>) -> String {
        let p = self.path(&format!("/neighborhood/{id}"));
        match mode {
            Some(m) => format!("{p}?{}", query(&[("mode", m)])),
            None => p,
        }
    }

    pub fn agent(&self, id: Uuid) -> String {
        self.path(&format!("/agent/{id}"))
    }

    pub fn frame(&self, id: Uuid) -> String {
        self.path(&format!("/frame/{id}"))
    }

    pub fn evidence(&self, id: Uuid) -> String {
        self.path(&format!("/evidence/{id}"))
    }

    /// The page for an edge endpoint, by its upstream `entity_type`
    /// (case-insensitive). Only `claim`, `agent`, `evidence` and `frame` have
    /// pages (plan §3.4 "Entity links"); every other type — paper, trace,
    /// perspective `community`, … — returns `None` and renders as plain text.
    pub fn entity(&self, entity_type: &str, id: Uuid) -> Option<String> {
        match entity_type.to_ascii_lowercase().as_str() {
            "claim" => Some(self.claim(id)),
            "agent" => Some(self.agent(id)),
            "evidence" => Some(self.evidence(id)),
            "frame" => Some(self.frame(id)),
            _ => None,
        }
    }

    // ---- BFF JSON --------------------------------------------------------

    pub fn bff_claim(&self, id: Uuid) -> String {
        self.path(&format!("/bff/claim/{id}"))
    }

    pub fn bff_search(&self, q: &str, mode: Option<&str>, page: Option<u32>) -> String {
        let mut qs = form_urlencoded::Serializer::new(String::new());
        qs.append_pair("q", q);
        if let Some(m) = mode {
            qs.append_pair("mode", m);
        }
        if let Some(p) = page {
            qs.append_pair("page", &p.to_string());
        }
        format!("{}?{}", self.path("/bff/search"), qs.finish())
    }

    /// `/bff/graph/ego/:id`, with `?max_degree=` when given.
    pub fn bff_graph_ego(&self, id: Uuid, max_degree: Option<u32>) -> String {
        let p = self.path(&format!("/bff/graph/ego/{id}"));
        match max_degree {
            Some(d) => format!("{p}?max_degree={d}"),
            None => p,
        }
    }

    pub fn bff_themes(&self) -> String {
        self.path("/bff/themes")
    }

    pub fn bff_communities(&self) -> String {
        self.path("/bff/communities")
    }

    pub fn bff_neighborhood(&self, id: Uuid, mode: Option<&str>) -> String {
        let p = self.path(&format!("/bff/neighborhood/{id}"));
        match mode {
            Some(m) => format!("{p}?{}", query(&[("mode", m)])),
            None => p,
        }
    }

    // ---- auth, health, static -------------------------------------------

    /// `/auth/login`, with `?return_to=` (a browser-visible local path).
    pub fn login(&self, return_to: Option<&str>) -> String {
        match return_to {
            Some(r) => format!(
                "{}?{}",
                self.path("/auth/login"),
                query(&[("return_to", r)])
            ),
            None => self.path("/auth/login"),
        }
    }

    /// `/auth/login?mode=popup` for the embed sign-in (plan §3.3).
    pub fn login_popup(&self, return_to: Option<&str>) -> String {
        let mut pairs = vec![("mode", "popup")];
        if let Some(r) = return_to {
            pairs.push(("return_to", r));
        }
        format!("{}?{}", self.path("/auth/login"), query(&pairs))
    }

    pub fn auth_callback(&self) -> String {
        self.path("/auth/callback")
    }

    pub fn logout(&self) -> String {
        self.path("/auth/logout")
    }

    pub fn redeem(&self) -> String {
        self.path("/auth/redeem")
    }

    pub fn health(&self) -> String {
        self.path("/health")
    }

    /// `/static/<name>?v=<content hash>`. The hash makes the URL change
    /// whenever the file does, so assets can be served `immutable`. Unknown
    /// names still get a link (without `v`) and 404 when fetched.
    pub fn static_asset(&self, name: &str) -> String {
        let p = self.path(&format!("/static/{name}"));
        match assets::find(name) {
            Some(a) => format!("{p}?v={}", a.hash),
            None => p,
        }
    }
}

/// Tag a theme / community / neighbourhood URL with the claim the viewer
/// arrived from.
///
/// None of those three views is a permalink — every clustering run mints new
/// ids — so the page cannot recover its centre from the path. `?claim=<uuid>`
/// carries it, and the graph pages read it to render the share button (which
/// copies the *claim's* URL, the only durable one) and to highlight the
/// centre. Every builder of those links must go through here; a link without
/// it silently drops the share button.
pub fn with_centre_claim(href: String, claim: Option<Uuid>) -> String {
    match claim {
        Some(c) => {
            let sep = if href.contains('?') { '&' } else { '?' };
            format!("{href}{sep}{}", query(&[("claim", &c.to_string())]))
        }
        None => href,
    }
}

fn query(pairs: &[(&str, &str)]) -> String {
    let mut qs = form_urlencoded::Serializer::new(String::new());
    for (k, v) in pairs {
        qs.append_pair(k, v);
    }
    qs.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id() -> Uuid {
        Uuid::parse_str("0b9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a10").unwrap()
    }

    #[test]
    fn builders_prefix_the_base_path() {
        let l = Links::new("https://explorer.example.com", "/explorer");
        let i = id();
        assert_eq!(l.home(), "/explorer/");
        assert_eq!(l.claim(i), format!("/explorer/claim/{i}"));
        assert_eq!(l.claim_history(i), format!("/explorer/claim/{i}/history"));
        assert_eq!(
            l.claim_provenance(i),
            format!("/explorer/claim/{i}/provenance")
        );
        assert_eq!(l.claim_graph(i), format!("/explorer/claim/{i}/graph"));
        assert_eq!(l.theme(i), format!("/explorer/theme/{i}"));
        assert_eq!(l.community(i), format!("/explorer/community/{i}"));
        assert_eq!(
            l.neighborhood(i, None),
            format!("/explorer/neighborhood/{i}")
        );
        assert_eq!(
            l.neighborhood(i, Some("atomic")),
            format!("/explorer/neighborhood/{i}?mode=atomic")
        );
        assert_eq!(l.agent(i), format!("/explorer/agent/{i}"));
        assert_eq!(l.frame(i), format!("/explorer/frame/{i}"));
        assert_eq!(l.evidence(i), format!("/explorer/evidence/{i}"));
        assert_eq!(l.bff_claim(i), format!("/explorer/bff/claim/{i}"));
        assert_eq!(
            l.bff_graph_ego(i, Some(40)),
            format!("/explorer/bff/graph/ego/{i}?max_degree=40")
        );
        assert_eq!(l.bff_themes(), "/explorer/bff/themes");
        assert_eq!(l.bff_communities(), "/explorer/bff/communities");
        assert_eq!(
            l.bff_neighborhood(i, None),
            format!("/explorer/bff/neighborhood/{i}")
        );
        assert_eq!(l.logout(), "/explorer/auth/logout");
        assert_eq!(l.redeem(), "/explorer/auth/redeem");
        assert_eq!(l.auth_callback(), "/explorer/auth/callback");
        assert_eq!(l.health(), "/explorer/health");
        assert_eq!(
            l.absolute(&l.claim(i)),
            format!("https://explorer.example.com/explorer/claim/{i}")
        );
    }

    #[test]
    fn received_paths_map_to_browser_paths() {
        let l = Links::new("https://explorer.example.com", "/explorer");
        assert_eq!(l.browser_path("/claim/x?y=1"), "/explorer/claim/x?y=1");
        assert_eq!(l.browser_path("/explorer/claim/x"), "/explorer/claim/x");
        assert_eq!(l.browser_path("/explorer"), "/explorer");
        assert_eq!(l.browser_path("/explorer?q=1"), "/explorer?q=1");
        assert_eq!(l.browser_path("/"), "/explorer/");
        // A route that merely shares the prefix is not already based.
        assert_eq!(l.browser_path("/explorers"), "/explorer/explorers");

        assert_eq!(l.strip_base("/explorer/bff/x"), "/bff/x");
        assert_eq!(l.strip_base("/explorer"), "/");
        assert_eq!(l.strip_base("/bff/x"), "/bff/x");
        assert_eq!(l.strip_base("/explorers"), "/explorers");

        let root = Links::new("http://localhost:8096", "");
        assert_eq!(root.browser_path("/claim/x"), "/claim/x");
        assert_eq!(root.strip_base("/bff/x"), "/bff/x");
    }

    #[test]
    fn root_base_path() {
        let l = Links::new("http://localhost:8096", "");
        assert_eq!(l.home(), "/");
        assert_eq!(l.claim(id()), format!("/claim/{}", id()));
        assert_eq!(l.absolute("/"), "http://localhost:8096/");
    }

    #[test]
    fn query_values_are_encoded() {
        let l = Links::new("https://explorer.example.com", "/explorer");
        assert_eq!(
            l.search("a&b=c <d>", Some("label"), Some(2)),
            "/explorer/search?q=a%26b%3Dc+%3Cd%3E&mode=label&page=2"
        );
        assert_eq!(l.search("x", None, None), "/explorer/search?q=x");
        assert_eq!(
            l.login(Some("/explorer/claim/x?y=1")),
            "/explorer/auth/login?return_to=%2Fexplorer%2Fclaim%2Fx%3Fy%3D1"
        );
        assert_eq!(l.login(None), "/explorer/auth/login");
        assert_eq!(
            l.login_popup(Some("/explorer/")),
            "/explorer/auth/login?mode=popup&return_to=%2Fexplorer%2F"
        );
    }

    #[test]
    fn entity_route_map() {
        let l = Links::new("https://explorer.example.com", "/explorer");
        let i = id();
        assert_eq!(l.entity("claim", i), Some(l.claim(i)));
        assert_eq!(l.entity("Agent", i), Some(l.agent(i)));
        assert_eq!(l.entity("EVIDENCE", i), Some(l.evidence(i)));
        assert_eq!(l.entity("frame", i), Some(l.frame(i)));
        for no_page in [
            "paper",
            "trace",
            "node",
            "activity",
            "perspective",
            "community",
            "context",
            "analysis",
            "source_artifact",
            "span",
            "entity",
            "task",
            "event",
            "",
        ] {
            assert_eq!(l.entity(no_page, i), None, "{no_page} has no page");
        }
    }

    #[test]
    fn static_assets_carry_a_content_hash() {
        let l = Links::new("https://explorer.example.com", "/explorer");
        let css = l.static_asset("app.css");
        assert!(css.starts_with("/explorer/static/app.css?v="), "{css}");
        assert_eq!(l.static_asset("nope.css"), "/explorer/static/nope.css");
    }
}
