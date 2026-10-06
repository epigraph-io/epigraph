//! The match-candidates page (J6) against a wiremock upstream: pending
//! candidates by default, a status switcher over the kernel's four statuses,
//! each candidate as a side-by-side pair of claim excerpts linked to the
//! claim reader, and no way to decide one.
//!
//! The mocks follow `routes/cross_source.rs::list_candidates`, not an
//! idealised list: it answers a bare JSON array of `PendingCandidateOut`
//! (`id`, `claim_a`, `claim_a_excerpt`, `claim_b`, `claim_b_excerpt`,
//! `score`, `verifier_verdict`, `verifier_rationale`, `created_at`), ordered
//! by `score DESC`, with no `total` and no `offset`. `limit` is a required
//! query parameter (the kernel's `ListCandidatesQuery.limit` is a plain
//! `i64`, so a request without it is a 400), and an absent `status` means
//! EVERY status, so every mock matches both. A request that matches no mock
//! gets wiremock's 404, which the page renders as an "unavailable" section
//! with a 200; so every test asserts the rows, text or markers it expects,
//! never only the status.

mod common;

use axum::http::StatusCode;
use common::{spawn, BASE};
use serde_json::{json, Value};
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockBuilder, ResponseTemplate};

/// Rows asked for per page (the kernel does not clamp `limit`).
const LIMIT: &str = "100";
const LIMIT_N: u64 = 100;

const EMPTY_MARK: &str = "data-candidates=\"empty\"";
const UNAVAILABLE_MARK: &str = "data-candidates=\"unavailable\"";
const CAPPED_MARK: &str = "data-candidates=\"capped\"";
const NOTICE_MARK: &str = "data-candidates=\"bad-status\"";

/// A synthetic candidate id, `n` in its last group.
fn candidate_id(n: u64) -> String {
    format!("00000000-0000-4000-9000-{n:012x}")
}

/// A synthetic claim id, `n` in its last group.
fn claim_id(n: u64) -> String {
    format!("00000000-0000-4000-8000-{n:012x}")
}

/// One `PendingCandidateOut`, as the kernel serialises it.
fn candidate(n: u64, a: (u64, &str), b: (u64, &str), score: f64) -> Value {
    json!({
        "id": candidate_id(n),
        "claim_a": claim_id(a.0),
        "claim_a_excerpt": a.1,
        "claim_b": claim_id(b.0),
        "claim_b_excerpt": b.1,
        "score": score,
        "verifier_verdict": "same_finding",
        "verifier_rationale": "Both report the same measured value.",
        "created_at": "2026-09-30T08:09:10.123456+00:00"
    })
}

/// `GET /api/v1/match_candidates` with the bearer and every parameter the
/// page must send for `status`.
fn list(status: &str) -> MockBuilder {
    Mock::given(method("GET"))
        .and(path("/api/v1/match_candidates"))
        .and(header("authorization", "Bearer tok"))
        .and(query_param("status", status))
        .and(query_param("limit", LIMIT))
}

/// The candidates section, sliced out of the page by its own markers.
fn section(body: &str) -> &str {
    let start = body
        .find("<section class=\"section candidates\"")
        .unwrap_or_else(|| panic!("no candidates section: {body}"));
    let len = body[start..]
        .find("</section>")
        .unwrap_or_else(|| panic!("candidates section never closes: {body}"));
    &body[start..start + len]
}

/// J6: with no status asked for (or a blank one) the page lists PENDING
/// candidates, and says so; upstream's order (highest score first) is kept.
/// The status is always sent: without it the kernel returns every status.
#[tokio::test]
async fn candidates_default_to_pending() {
    let app = spawn().await;
    list("pending")
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            candidate(1, (11, "Higher scored claim A"), (12, "Higher B"), 0.91),
            candidate(2, (21, "Lower scored claim A"), (22, "Lower B"), 0.42),
        ])))
        .expect(2)
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");

    for uri in [
        format!("{BASE}/candidates"),
        format!("{BASE}/candidates?status=+"),
    ] {
        let res = app.get_as(&uri, &sid).await;
        assert_eq!(res.status, StatusCode::OK, "{uri}: {}", res.body);
        assert!(!res.body.contains("Not yet available"), "still the stub");
        let s = section(&res.body);
        assert!(
            s.contains("data-candidates-status=\"pending\""),
            "{uri}: {s}"
        );
        let higher = s
            .find(&format!("data-candidate=\"{}\"", candidate_id(1)))
            .unwrap_or_else(|| panic!("{uri}: higher-scored pair missing: {s}"));
        let lower = s
            .find(&format!("data-candidate=\"{}\"", candidate_id(2)))
            .unwrap_or_else(|| panic!("{uri}: lower-scored pair missing: {s}"));
        assert!(
            higher < lower,
            "upstream's highest-score-first order is kept"
        );
        assert!(
            s.contains("0.91") && s.contains("0.42"),
            "scores shown: {s}"
        );
        assert!(!s.contains(UNAVAILABLE_MARK) && !s.contains(EMPTY_MARK));
        assert!(
            res.body.contains(&format!(
                "<a href=\"{BASE}/candidates?status=pending\" aria-current=\"page\">pending</a>"
            )),
            "{uri}: pending is the current status in the switcher: {}",
            res.body
        );
    }
    app.upstream.verify().await;
}

/// J6: statuses are the kernel's own four (`pending|promoted|rejected|
/// stale`). Anything else is refused here with a notice and no upstream
/// call, rather than forwarded for the kernel to 400.
#[tokio::test]
async fn candidates_reject_an_unknown_status_without_calling_upstream() {
    let app = spawn().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/match_candidates"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .expect(0)
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");

    for bad in ["accepted", "Pending", "pending,stale", "%3Cscript%3E"] {
        let res = app
            .get_as(&format!("{BASE}/candidates?status={bad}"), &sid)
            .await;
        assert_eq!(res.status, StatusCode::OK, "{bad}: {}", res.body);
        assert!(res.body.contains(NOTICE_MARK), "{bad}: {}", res.body);
        assert!(
            res.body
                .contains("Status must be one of pending, promoted, rejected or stale."),
            "{bad}: {}",
            res.body
        );
        assert!(
            !res.body.contains("<script>"),
            "{bad}: the value is escaped"
        );
        assert!(
            !res.body.contains("<section class=\"section candidates\""),
            "{bad}: no list rendered"
        );
        assert!(
            res.body
                .contains(&format!("href=\"{BASE}/candidates?status=pending\"")),
            "{bad}: the switcher still offers the valid statuses"
        );
    }
    app.upstream.verify().await;
}

/// J6: each candidate is a side-by-side pair, each excerpt inside the link to
/// its own claim (a swapped pair would link A's text to B), with the score,
/// the verifier's verdict and rationale (escaped: it is free text written
/// from both claims) and the date. The page offers no way to decide a
/// candidate: no form or button in the list, and no decide route anywhere.
#[tokio::test]
async fn candidate_pair_links_both_claims() {
    let app = spawn().await;
    let mut row = candidate(
        7,
        (71, "Water boils at 100 C at sea level"),
        (72, "At one atmosphere water boils at 100 C"),
        0.8765,
    );
    row["verifier_rationale"] = json!("Same claim <script>alert(1)</script> & same unit");
    list("pending")
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([row])))
        .expect(1)
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");

    let res = app.get_as(&format!("{BASE}/candidates"), &sid).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    let s = section(&res.body);
    let a = format!(
        "<a href=\"{BASE}/claim/{}\">Water boils at 100 C at sea level</a>",
        claim_id(71)
    );
    let b = format!(
        "<a href=\"{BASE}/claim/{}\">At one atmosphere water boils at 100 C</a>",
        claim_id(72)
    );
    let a_at = s
        .find(&a)
        .unwrap_or_else(|| panic!("claim A not linked: {s}"));
    let b_at = s
        .find(&b)
        .unwrap_or_else(|| panic!("claim B not linked: {s}"));
    assert!(a_at < b_at, "A on the left, B on the right");
    assert!(s.contains("0.88"), "score to two places: {s}");
    assert!(s.contains("same_finding"), "verdict shown: {s}");
    assert!(
        s.contains("Same claim &#60;script&#62;alert(1)&#60;/script&#62; &#38; same unit"),
        "rationale shown, escaped: {s}"
    );
    assert!(!res.body.contains("<script>alert(1)"), "rationale not raw");
    assert!(s.contains("2026-09-30"), "created date shown: {s}");
    assert!(!s.contains("<form") && !s.contains("<button"), "{s}");
    assert!(!res.body.contains("/decide"), "no decide route linked");
    app.upstream.verify().await;
}

/// The switcher asks upstream for the chosen status, labels the list with
/// it, and links every status.
#[tokio::test]
async fn candidates_switcher_asks_upstream_for_the_chosen_status() {
    let app = spawn().await;
    for (n, status) in [(1u64, "promoted"), (2, "rejected"), (3, "stale")] {
        list(status)
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([candidate(
                n,
                (n * 10 + 1, &format!("{status} A")),
                (n * 10 + 2, &format!("{status} B")),
                0.5
            )])))
            .expect(1)
            .mount(&app.upstream)
            .await;
    }
    let sid = app.sign_in("tok");

    for (n, status) in [(1u64, "promoted"), (2, "rejected"), (3, "stale")] {
        let res = app
            .get_as(&format!("{BASE}/candidates?status={status}"), &sid)
            .await;
        assert_eq!(res.status, StatusCode::OK, "{status}: {}", res.body);
        let s = section(&res.body);
        assert!(
            s.contains(&format!("data-candidates-status=\"{status}\"")),
            "{status}: {s}"
        );
        assert!(
            s.contains(&format!("data-candidate=\"{}\"", candidate_id(n))),
            "{status}: row missing: {s}"
        );
        for other in ["pending", "promoted", "rejected", "stale"] {
            let current = if other == status {
                " aria-current=\"page\""
            } else {
                ""
            };
            assert!(
                res.body.contains(&format!(
                    "<a href=\"{BASE}/candidates?status={other}\"{current}>{other}</a>"
                )),
                "{status}: switcher entry {other}: {}",
                res.body
            );
        }
    }
    app.upstream.verify().await;
}

/// An empty list is an answer, not an error; a failed one is "unavailable",
/// not empty. The answer is reported as what the API returned, never as
/// "none you can read": the API's candidate listing does not read with the
/// viewer's own tenancy, so it can leave out pairs the viewer may read.
#[tokio::test]
async fn candidates_empty_state_is_not_an_error() {
    let app = spawn().await;
    list("pending")
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .expect(1)
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");

    let res = app.get_as(&format!("{BASE}/candidates"), &sid).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    let s = section(&res.body);
    assert!(s.contains(EMPTY_MARK), "{s}");
    assert!(
        s.contains("The API returned no pending candidates for you."),
        "{s}"
    );
    assert!(
        !s.contains("that you can read"),
        "an empty answer is not a claim about everything the viewer may read: {s}"
    );
    assert!(!s.contains(UNAVAILABLE_MARK));
    app.upstream.verify().await;
}

#[tokio::test]
async fn candidates_upstream_failure_is_unavailable_not_empty() {
    let app = spawn().await;
    list("stale")
        .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
        .expect(1)
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");

    let res = app
        .get_as(&format!("{BASE}/candidates?status=stale"), &sid)
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    let s = section(&res.body);
    assert!(s.contains(UNAVAILABLE_MARK), "{s}");
    assert!(s.contains("Match candidates are unavailable."), "{s}");
    assert!(!s.contains(EMPTY_MARK), "a failure is not an empty list");
    assert!(!res.body.contains("boom"), "upstream body not shown");
    app.upstream.verify().await;
}

/// Upstream has no total and no paging: a list that fills the page is
/// marked as possibly cut, and a shorter one is not.
#[tokio::test]
async fn candidates_mark_a_full_list_as_possibly_cut() {
    let app = spawn().await;
    let full: Vec<Value> = (1..=LIMIT_N)
        .map(|n| candidate(n, (n * 2, "a"), (n * 2 + 1, "b"), 1.0 - n as f64 / 1000.0))
        .collect();
    list("pending")
        .respond_with(ResponseTemplate::new(200).set_body_json(Value::Array(full)))
        .expect(1)
        .mount(&app.upstream)
        .await;
    list("rejected")
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([candidate(
            1,
            (2, "a"),
            (3, "b"),
            0.5
        )])))
        .expect(1)
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");

    let res = app.get_as(&format!("{BASE}/candidates"), &sid).await;
    let s = section(&res.body);
    assert!(s.contains(CAPPED_MARK), "{s}");
    assert!(
        s.contains("Showing the top 100 by score; there may be more."),
        "{s}"
    );
    assert_eq!(s.matches("data-candidate=\"").count(), 100);

    let res = app
        .get_as(&format!("{BASE}/candidates?status=rejected"), &sid)
        .await;
    let s = section(&res.body);
    assert!(
        s.contains(&format!("data-candidate=\"{}\"", candidate_id(1))),
        "{s}"
    );
    assert!(!s.contains(CAPPED_MARK), "{s}");
    app.upstream.verify().await;
}

#[tokio::test]
async fn candidates_require_sign_in_and_make_no_anonymous_call() {
    let app = spawn().await;
    let res = app.get(&format!("{BASE}/candidates")).await;
    assert_eq!(res.status, StatusCode::SEE_OTHER);
    let calls = app.upstream.received_requests().await.unwrap_or_default();
    assert!(calls.is_empty(), "called upstream: {calls:?}");
}
