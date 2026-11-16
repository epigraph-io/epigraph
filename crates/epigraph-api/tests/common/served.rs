//! Boot the compiled `server` binary and talk to it over a real socket.
//!
//! Shared by the boot tests that must see what `main` does (a binary's `main`
//! cannot be called from a test). Include with
//! `#[path = "common/served.rs"] mod served;`.
#![allow(dead_code)]

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Logged once the listener is bound, followed by the bound address.
pub const SERVING: &str = "Server listening on ";

/// The server this test started (and only it). Killed and reaped on drop,
/// including when an assertion panics first, so the per-test database can be
/// dropped.
pub struct Server {
    pub child: Child,
    pub port: u16,
    /// The log up to and including the serving line.
    pub boot_log: String,
    rx: Option<mpsc::Receiver<String>>,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Server {
    /// Send SIGTERM to this server's PID (the one this test spawned) and wait
    /// up to `within` for it to exit. Returns the exit status and every log
    /// line written after the serving line.
    pub fn terminate(&mut self, within: Duration) -> (Option<ExitStatus>, String) {
        let pid = self.child.id().to_string();
        let sent = Command::new("kill")
            .args(["-TERM", &pid])
            .status()
            .expect("run kill");
        assert!(sent.success(), "kill -TERM {pid} failed");
        let rx = self.rx.take().expect("terminate called once");
        let deadline = Instant::now() + within;
        let mut log = String::new();
        loop {
            while let Ok(line) = rx.try_recv() {
                log.push_str(&line);
                log.push('\n');
            }
            if let Some(status) = self.child.try_wait().expect("try_wait") {
                while let Ok(line) = rx.recv_timeout(Duration::from_millis(300)) {
                    log.push_str(&line);
                    log.push('\n');
                }
                return (Some(status), log);
            }
            if Instant::now() >= deadline {
                return (None, log);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

/// How a boot ended.
pub enum Boot {
    /// It bound its listener and is serving.
    Serving(Server),
    /// It exited before serving.
    Exited { status: ExitStatus, log: String },
}

impl Boot {
    pub fn serving(self) -> Server {
        match self {
            Self::Serving(s) => s,
            Self::Exited { status, log } => {
                panic!("the server exited {status} before serving:\n{log}")
            }
        }
    }
}

fn providers_file() -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "served-fixture-providers-{}.toml",
        std::process::id()
    ));
    std::fs::write(&path, "# no external identity providers\n").expect("providers file");
    path
}

/// The environment every boot gets: a clean slate that reaches the serving
/// line on a migrated database, with the rate limiter OFF so a test's own
/// requests are never refused 429.
pub fn base_command(db_url: &str) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_server"));
    cmd.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("EPIGRAPH_ALLOW_INSECURE_SECRET", "1")
        .env("EPIGRAPH_ENV", "test")
        .env("EPIGRAPH_PORT", "0")
        .env("EPIGRAPH_METRICS_ADDR", "127.0.0.1:0")
        .env("EPIGRAPH_PROVIDERS_CONFIG", providers_file())
        .env("EPIGRAPH_RATE_LIMIT", "off")
        .env("RUST_LOG", "info")
        .env("NO_COLOR", "1")
        .env("DATABASE_URL", db_url)
        .current_dir(std::env::temp_dir())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}

/// Spawn `cmd` and wait (up to 90 s) until it serves or exits.
pub fn boot(mut cmd: Command) -> Boot {
    let mut child = cmd.spawn().expect("spawn the server binary");
    let (tx, rx) = mpsc::channel::<String>();
    for pipe in [
        Box::new(child.stdout.take().expect("stdout")) as Box<dyn std::io::Read + Send>,
        Box::new(child.stderr.take().expect("stderr")),
    ] {
        let tx = tx.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(pipe).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
    }
    drop(tx);
    let mut server = Server {
        child,
        port: 0,
        boot_log: String::new(),
        rx: None,
    };

    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        while let Ok(line) = rx.try_recv() {
            server.boot_log.push_str(&line);
            server.boot_log.push('\n');
            if let Some(port) = serving_port(&line) {
                server.port = port;
                server.rx = Some(rx);
                return Boot::Serving(server);
            }
        }
        if let Some(status) = server.child.try_wait().expect("try_wait") {
            let mut log = std::mem::take(&mut server.boot_log);
            while let Ok(line) = rx.recv_timeout(Duration::from_millis(500)) {
                log.push_str(&line);
                log.push('\n');
            }
            return Boot::Exited { status, log };
        }
        assert!(
            Instant::now() < deadline,
            "the server neither served nor exited within 90s:\n{}",
            server.boot_log
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// The port in a `Server listening on <ip>:<port>` line: the run of ASCII
/// digits after the last `:`.
pub fn serving_port(line: &str) -> Option<u16> {
    let rest = &line[line.find(SERVING)? + SERVING.len()..];
    let after_colon = &rest[rest.rfind(':')? + 1..];
    let digits: String = after_colon
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    digits.parse().ok().filter(|p| *p != 0)
}

/// A raw HTTP/1.1 response: status, lower-cased header lines, body.
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl Response {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Send `method path` with `body` to 127.0.0.1:`port`, `Connection: close`.
pub async fn request(
    port: u16,
    method: &str,
    path: &str,
    content_type: &str,
    body: &[u8],
) -> Response {
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect to the server");
    let head = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: {content_type}\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await.expect("write head");
    // The server may answer (413) and close before the whole body is sent.
    let _ = stream.write_all(body).await;
    let mut raw = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(30), stream.read_to_end(&mut raw))
        .await
        .expect("response within 30s");
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((text.as_str(), ""));
    let mut lines = head.lines();
    let status = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("no HTTP status in response: {text:?}"));
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(n, v)| (n.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    Response {
        status,
        headers,
        body: body.to_string(),
    }
}
