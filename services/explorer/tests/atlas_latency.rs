//! The Explorer BFF's share of the Atlas latency budget (backlog W12
//! 824ac5ac, design §6).
//!
//! A level transition is on screen within 200 ms at p95 warm and 500 ms cold.
//! The plan (`docs/superpowers/plans/2026-11-13-atlas-w12-latency-gate-plan.md`)
//! gives 50 ms of that to the browser, 120 ms warm / 420 ms cold to the
//! kernel (gated by `crates/epigraph-api/tests/atlas_latency_gate.rs`) and
//! [`BFF_SHARE`] (30 ms) to this proxy: the kernel call, the mirror decode,
//! the ETag digest and the compression. The Explorer is its own Cargo
//! workspace and cannot link the kernel, so the kernel here is wiremock
//! serving the largest committed level fixtures, and the time measured
//! INCLUDES that stub's own answer: the share is checked conservatively.
//!
//! Each sample is a real HTTP round trip to the app served on a loopback
//! listener, from a `reqwest` client with the session cookie (reqwest is
//! built without decompression, so the bytes are as sent). Outside the
//! timer, every compressed sample must carry the `Content-Encoding` asked
//! for and decode to the fixture, and every 304 must be empty: a proxy that
//! got faster by dropping compression or its revalidation cannot pass.
//!
//! The JSON report goes to `ATLAS_LATENCY_BFF_REPORT` (a path) when it is
//! set, before the gate asserts.

mod common;

use std::collections::BTreeMap;
use std::io::Read as _;
use std::time::{Duration, Instant};

use common::atlas_contract::{fixture_value, FIXTURE_TEAM_GROUP_ID};
use common::{spawn, TestApp};
use serde_json::{json, Value};
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

/// The BFF's share of a warm or cold transition.
const BFF_SHARE: Duration = Duration::from_millis(30);

const TOKEN: &str = "tok-latency";

/// One measured case: a level fixture fetched one way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Way {
    Gzip,
    Br,
    /// `If-None-Match` with the ETag of a 200: a 304.
    NotModified,
}

impl Way {
    fn name(self) -> &'static str {
        match self {
            Way::Gzip => "gzip",
            Way::Br => "br",
            Way::NotModified => "304",
        }
    }
}

const WAYS: [Way; 3] = [Way::Gzip, Way::Br, Way::NotModified];

/// The fixtures served: the dense 100-node leaf and the theme root.
const FIXTURES: [(&str, &str); 2] = [("leaf", "team_leaf_dense"), ("root", "team_theme_root")];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Temp {
    Warm,
    Cold,
}

type Key = (&'static str, Way, Temp);
type Samples = BTreeMap<Key, Vec<Duration>>;

fn quantile(xs: &[Duration], q: f64) -> Option<Duration> {
    if xs.is_empty() {
        return None;
    }
    let mut s = xs.to_vec();
    s.sort();
    let rank = ((q * s.len() as f64).ceil() as usize).clamp(1, s.len());
    Some(s[rank - 1])
}

/// Every expected case whose p95 exceeds `budget`, or that measured nothing.
fn verdict(samples: &Samples, expected: &[Key], budget: Duration) -> Vec<Key> {
    expected
        .iter()
        .copied()
        .filter(|k| {
            samples
                .get(k)
                .and_then(|xs| quantile(xs, 0.95))
                .is_none_or(|p| p > budget)
        })
        .collect()
}

fn all_expected() -> Vec<Key> {
    let mut out = Vec::new();
    for (name, _) in FIXTURES {
        for way in WAYS {
            for temp in [Temp::Warm, Temp::Cold] {
                out.push((name, way, temp));
            }
        }
    }
    out
}

fn ms(d: Duration) -> f64 {
    (d.as_secs_f64() * 1000.0 * 100.0).round() / 100.0
}

#[test]
fn the_bff_verdict_is_p95_and_an_empty_case_fails() {
    let d = Duration::from_millis;
    let mut s: Samples = BTreeMap::new();
    s.insert(
        ("leaf", Way::Gzip, Temp::Warm),
        (0..100).map(|i| d(if i < 95 { 5 } else { 500 })).collect(),
    );
    s.insert(
        ("leaf", Way::Br, Temp::Warm),
        (0..100).map(|i| d(if i < 90 { 5 } else { 31 })).collect(),
    );
    let got = verdict(
        &s,
        &[
            ("leaf", Way::Gzip, Temp::Warm),
            ("leaf", Way::Br, Temp::Warm),
            ("root", Way::Gzip, Temp::Cold),
        ],
        BFF_SHARE,
    );
    assert_eq!(
        got,
        vec![
            ("leaf", Way::Br, Temp::Warm),
            ("root", Way::Gzip, Temp::Cold)
        ]
    );
}

/// A level fixture as the kernel would send it: compact JSON.
struct Level {
    name: &'static str,
    id: Uuid,
    hierarchy: String,
    body: Vec<u8>,
}

fn levels() -> Vec<Level> {
    FIXTURES
        .iter()
        .map(|(name, stem)| {
            let v = fixture_value(stem);
            assert_eq!(v["map_group_id"], FIXTURE_TEAM_GROUP_ID.to_string());
            Level {
                name,
                id: v["level_id"].as_str().unwrap().parse().unwrap(),
                hierarchy: v["hierarchy"].as_str().unwrap().to_string(),
                body: serde_json::to_vec(&v).unwrap(),
            }
        })
        .collect()
}

/// The app on a loopback listener, its kernel stub serving `levels` after
/// `delay`, and a signed-in session.
struct Served {
    _app: TestApp,
    base: String,
    cookie: String,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Served {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve(levels: &[Level], delay: Duration) -> Served {
    let app = spawn().await;
    for l in levels {
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/atlas/maps/{FIXTURE_TEAM_GROUP_ID}/{}/levels/{}",
                l.hierarchy, l.id
            )))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(l.body.clone(), "application/json")
                    .set_delay(delay),
            )
            .mount(&app.upstream)
            .await;
    }
    let sid = app.sign_in(TOKEN);
    let cookie = TestApp::cookie(&sid);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = app.router.clone();
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    Served {
        _app: app,
        base: format!("http://{addr}"),
        cookie,
        task,
    }
}

fn client() -> reqwest::Client {
    reqwest::Client::builder().no_proxy().build().unwrap()
}

fn url(s: &Served, l: &Level) -> String {
    format!(
        "{}/explorer/bff/atlas/maps/team-{}/{}/{}",
        s.base,
        FIXTURE_TEAM_GROUP_ID.simple(),
        l.hierarchy,
        l.id
    )
}

struct Hit {
    status: u16,
    encoding: Option<String>,
    etag: Option<String>,
    body: Vec<u8>,
    took: Duration,
}

async fn hit(c: &reqwest::Client, s: &Served, l: &Level, way: Way, etag: Option<&str>) -> Hit {
    let accept = match way {
        Way::Br => "br",
        Way::Gzip | Way::NotModified => "gzip",
    };
    let mut req = c
        .get(url(s, l))
        .header("cookie", &s.cookie)
        .header("accept-encoding", accept);
    if let (Way::NotModified, Some(e)) = (way, etag) {
        req = req.header("if-none-match", e);
    }
    let started = Instant::now();
    let resp = req.send().await.unwrap();
    let status = resp.status().as_u16();
    let header = |n: &str| {
        resp.headers()
            .get(n)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };
    let (encoding, etag) = (header("content-encoding"), header("etag"));
    let body = resp.bytes().await.unwrap().to_vec();
    Hit {
        status,
        encoding,
        etag,
        body,
        took: started.elapsed(),
    }
}

fn decode(encoding: &str, b: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    match encoding {
        "gzip" => {
            flate2::read::GzDecoder::new(b)
                .read_to_end(&mut out)
                .expect("a gzip body");
        }
        "br" => {
            brotli::Decompressor::new(b, 4096)
                .read_to_end(&mut out)
                .expect("a br body");
        }
        other => panic!("unexpected encoding {other}"),
    }
    out
}

/// Check one answer outside the timer: the encoding asked for and the
/// fixture's bytes, or an empty 304.
fn check(h: &Hit, l: &Level, way: Way) {
    match way {
        Way::NotModified => {
            assert_eq!(h.status, 304, "{} {}", l.name, way.name());
            assert!(h.body.is_empty(), "a 304 has no body");
        }
        Way::Gzip | Way::Br => {
            assert_eq!(h.status, 200, "{} {}", l.name, way.name());
            let want = match way {
                Way::Br => "br",
                _ => "gzip",
            };
            assert_eq!(
                h.encoding.as_deref(),
                Some(want),
                "{} {}: the level must be compressed",
                l.name,
                way.name()
            );
            assert_eq!(
                decode(want, &h.body),
                l.body,
                "{} decodes to the fixture",
                l.name
            );
        }
    }
}

/// Bytes on the wire per fixture and encoding (from the last check).
type Sizes = BTreeMap<(&'static str, &'static str), usize>;

async fn measure(levels: &[Level], delay: Duration, warm: usize, cold: usize) -> (Samples, Sizes) {
    let mut samples: Samples = BTreeMap::new();
    let mut sizes: Sizes = BTreeMap::new();
    {
        let s = serve(levels, delay).await;
        let c = client();
        for l in levels {
            // Untimed: warms the BFF's kernel connection and gives the ETag.
            let first = hit(&c, &s, l, Way::Gzip, None).await;
            check(&first, l, Way::Gzip);
            let etag = first.etag.clone().expect("a level carries an ETag");
            for way in WAYS {
                for _ in 0..warm {
                    let h = hit(&c, &s, l, way, Some(&etag)).await;
                    check(&h, l, way);
                    sizes.insert((l.name, way.name()), h.body.len());
                    samples
                        .entry((l.name, way, Temp::Warm))
                        .or_default()
                        .push(h.took);
                }
            }
        }
    }
    // Cold: a fresh app (its kernel client has no connection yet) and a
    // fresh client per sample. A 304 needs the ETag, which only a 200 gives:
    // that 200 is fetched through ANOTHER app, so the timed 304 is still the
    // new app's first request.
    let etags: BTreeMap<&str, String> = {
        let s = serve(levels, delay).await;
        let c = client();
        let mut m = BTreeMap::new();
        for l in levels {
            let h = hit(&c, &s, l, Way::Gzip, None).await;
            m.insert(l.name, h.etag.expect("an ETag"));
        }
        m
    };
    for l in levels {
        for way in WAYS {
            for _ in 0..cold {
                let s = serve(levels, delay).await;
                let c = client();
                let h = hit(&c, &s, l, way, Some(&etags[l.name])).await;
                check(&h, l, way);
                samples
                    .entry((l.name, way, Temp::Cold))
                    .or_default()
                    .push(h.took);
            }
        }
    }
    (samples, sizes)
}

fn report(samples: &Samples, sizes: &Sizes, levels: &[Level], breaches: &[Key]) -> Value {
    let rows: Vec<Value> = all_expected()
        .into_iter()
        .map(|k| {
            let xs = samples.get(&k).cloned().unwrap_or_default();
            let p95 = quantile(&xs, 0.95);
            json!({
                "level": k.0,
                "way": k.1.name(),
                "temp": match k.2 { Temp::Warm => "warm", Temp::Cold => "cold" },
                "n": xs.len(),
                "p50_ms": quantile(&xs, 0.5).map(ms),
                "p95_ms": p95.map(ms),
                "max_ms": xs.iter().max().copied().map(ms),
                "budget_ms": ms(BFF_SHARE),
                "pass": p95.is_some_and(|p| p <= BFF_SHARE),
            })
        })
        .collect();
    json!({
        "harness": "atlas-latency-bff",
        "backlog": "824ac5ac",
        "profile": if cfg!(debug_assertions) { "debug" } else { "release" },
        "kernel": "wiremock stub (its own answer time is inside every sample)",
        "bytes": levels.iter().map(|l| json!({
            "level": l.name,
            "raw": l.body.len(),
            "gzip": sizes.get(&(l.name, "gzip")),
            "br": sizes.get(&(l.name, "br")),
        })).collect::<Vec<_>>(),
        "results": rows,
        "breaches": breaches.iter().map(|k| format!("{} {} {:?}", k.0, k.1.name(), k.2)).collect::<Vec<_>>(),
    })
}

fn print_table(r: &Value) {
    eprintln!("atlas BFF latency ({}):", r["profile"]);
    for b in r["bytes"].as_array().into_iter().flatten() {
        eprintln!(
            "  {} bytes: raw {} gzip {} br {}",
            b["level"], b["raw"], b["gzip"], b["br"]
        );
    }
    for row in r["results"].as_array().into_iter().flatten() {
        eprintln!(
            "  {:<5} {:<4} {:<5} n={:<3} p50 {:>8} p95 {:>8} max {:>8} budget {} {}",
            row["level"].as_str().unwrap_or(""),
            row["way"].as_str().unwrap_or(""),
            row["temp"].as_str().unwrap_or(""),
            row["n"],
            row["p50_ms"],
            row["p95_ms"],
            row["max_ms"],
            row["budget_ms"],
            if row["pass"] == json!(true) {
                "ok"
            } else {
                "OVER"
            }
        );
    }
}

fn samples_from_env(var: &str, default: usize) -> usize {
    std::env::var(var)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// THE GATE: the BFF's p95 for the largest leaf and the theme root, gzip,
/// br and 304, warm and cold, within its 30 ms share.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_bff_meets_its_share_of_the_latency_budget() {
    let levels = levels();
    let warm = samples_from_env("ATLAS_LATENCY_WARM_SAMPLES", 60);
    let cold = samples_from_env("ATLAS_LATENCY_COLD_SAMPLES", 8);
    let (samples, sizes) = measure(&levels, Duration::ZERO, warm, cold).await;
    let breaches = verdict(&samples, &all_expected(), BFF_SHARE);
    let r = report(&samples, &sizes, &levels, &breaches);
    print_table(&r);
    if let Ok(path) = std::env::var("ATLAS_LATENCY_BFF_REPORT") {
        if !path.is_empty() {
            std::fs::write(&path, serde_json::to_vec_pretty(&r).unwrap())
                .unwrap_or_else(|e| panic!("write the report to {path}: {e}"));
        }
    }
    assert!(
        breaches.is_empty(),
        "the BFF's latency share is exceeded: {}",
        serde_json::to_string(&r["breaches"]).unwrap_or_default()
    );
}

/// A deliberately slow route turns the BFF gate red: the same measurement
/// with the kernel stub answering after twice the BFF's share is red for
/// every case, where the control (no delay) is green.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_slow_kernel_turns_the_bff_gate_red() {
    let levels = levels();
    // 20 warm samples, so the control's p95 is not just its slowest one.
    let (control, _) = measure(&levels, Duration::ZERO, 20, 3).await;
    let green = verdict(&control, &all_expected(), BFF_SHARE);
    assert!(green.is_empty(), "the control run is red: {green:?}");
    let (slow, _) = measure(&levels, 2 * BFF_SHARE, 6, 1).await;
    let red = verdict(&slow, &all_expected(), BFF_SHARE);
    assert_eq!(red, all_expected(), "a slow kernel left a case green");
}
