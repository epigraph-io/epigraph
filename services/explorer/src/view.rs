//! askama → axum glue and the shared page templates.
//!
//! Every page is an askama struct with a `ctx: PageCtx` field whose template
//! `{% extends "base.html" %}`. askama auto-escapes `.html` templates, so
//! claim text (untrusted) is safe in element content AND attribute values;
//! never apply `|safe` to upstream data.

use askama::Template;
use axum::response::Html;

use crate::auth::PageCtx;
use crate::error::AppError;

/// Render a template into an axum `Html` response body.
pub fn render<T: Template>(template: &T) -> Result<Html<String>, AppError> {
    template.render().map(Html).map_err(AppError::from)
}

/// `templates/error.html` — rendered by `error::render_errors`, never
/// directly by handlers (return an `AppError` instead).
#[derive(Template)]
#[template(path = "error.html")]
pub struct ErrorPage {
    pub ctx: PageCtx,
    pub status: u16,
    pub title: String,
    pub message: String,
}

/// `templates/stub.html` — placeholder for routes an area has not built.
#[derive(Template)]
#[template(path = "stub.html")]
pub struct StubPage {
    pub ctx: PageCtx,
    pub title: String,
    pub area: &'static str,
}

/// Render the "not built yet" page for `area` (`core`, `entities`, …).
pub fn stub_page(ctx: PageCtx, title: &str, area: &'static str) -> Result<Html<String>, AppError> {
    render(&StubPage {
        ctx,
        title: title.to_string(),
        area,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::links::Links;
    use crate::upstream::Degraded;

    fn ctx(signed_in: bool) -> PageCtx {
        PageCtx::new(
            Links::new("https://explorer.example.com", "/explorer"),
            "/explorer/claim/x?a=1&b=<2>".into(),
            signed_in,
        )
    }

    #[test]
    fn base_layout_is_base_path_aware_and_escaped() {
        let html = StubPage {
            ctx: ctx(false),
            title: "<script>alert(1)</script>".into(),
            area: "core",
        }
        .render()
        .unwrap();
        assert!(!html.contains("<script>alert"), "title must be escaped");
        assert!(html.contains("href=\"/explorer/\""), "home link");
        assert!(html.contains("action=\"/explorer/search\""), "search form");
        assert!(html.contains("/explorer/static/app.css?v="), "stylesheet");
        assert!(
            html.contains("/explorer/auth/login?return_to="),
            "sign-in link"
        );
        assert!(
            !html.contains("<2>"),
            "the current path is escaped everywhere"
        );
        assert!(html.contains("content=\"https://explorer.example.com/explorer/claim/x?"));
        assert!(!html.contains("style="), "CSP forbids inline styles");
        assert!(!html.contains("<script>"), "CSP forbids inline scripts");
    }

    #[test]
    fn signed_in_layout_has_sign_out_form() {
        let html = StubPage {
            ctx: ctx(true),
            title: "t".into(),
            area: "core",
        }
        .render()
        .unwrap();
        assert!(html.contains("method=\"post\" action=\"/explorer/auth/logout\""));
        assert!(!html.contains("/explorer/auth/login"));
    }

    /// Pins the template syntax area agents use for degraded sections.
    #[derive(Template)]
    #[template(
        ext = "html",
        source = "{% match s %}{% when Degraded::Available { data } %}ok:{{ data }}\
                  {% when Degraded::Unavailable { reason } %}no:{{ reason }}{% endmatch %}|\
                  {% if let Some(v) = s.get() %}{{ v }}{% else %}-{% endif %}"
    )]
    struct SectionProbe {
        s: Degraded<String>,
    }

    #[test]
    fn degraded_template_syntax() {
        let ok = SectionProbe {
            s: Degraded::ok("<a>".into()),
        };
        assert_eq!(ok.render().unwrap(), "ok:&#60;a&#62;|&#60;a&#62;");
        let no = SectionProbe {
            s: Degraded::unavailable("Timed out."),
        };
        assert_eq!(no.render().unwrap(), "no:Timed out.|-");
    }
}
