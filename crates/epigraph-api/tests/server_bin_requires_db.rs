//! Operator ruling R-39 (backlog ca927c3b): the `not(feature = "db")` build of
//! this crate is CHECK-ONLY.
//!
//! `cargo check -p epigraph-api --no-default-features --locked` stays in CI so
//! the two-build design keeps compiling, but nothing may RUN that build: its
//! route stubs answer 501/503 or fabricate placeholder data through the real
//! response shapes (see the header of `src/routes/mod.rs`), and its split
//! handlers' `#[cfg]` arms are not held to extractor parity. So the `server`
//! binary declares `required-features = ["db"]`: a no-db build skips it rather
//! than producing a runnable server, while the library and the CI check are
//! unaffected.
//!
//! Read as text so the test needs no TOML dependency.

/// The `[[bin]]` block of `Cargo.toml` whose `name` is `bin`, as text.
fn bin_block<'a>(manifest: &'a str, bin: &str) -> Option<&'a str> {
    manifest.split("[[bin]]").skip(1).find_map(|chunk| {
        // A block runs to the next table header.
        let end = chunk.find("\n[").unwrap_or(chunk.len());
        let block = &chunk[..end];
        let named = block.lines().any(|l| {
            let l = l.trim();
            l.starts_with("name")
                && l.split('=').nth(1).map(str::trim) == Some(&format!("\"{bin}\""))
        });
        named.then_some(block)
    })
}

fn requires_db(block: &str) -> bool {
    block.lines().any(|l| {
        let l = l.split('#').next().unwrap_or("").replace(' ', "");
        l.starts_with("required-features=") && l.contains("\"db\"")
    })
}

#[test]
fn the_server_binary_cannot_be_built_without_the_db_feature() {
    let manifest = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"))
        .expect("read epigraph-api/Cargo.toml");

    // Calibration: the parser reads a block that is known to carry the gate.
    let migrate = bin_block(&manifest, "epigraph-migrate").expect("epigraph-migrate bin block");
    assert!(
        requires_db(migrate),
        "parser calibration failed: epigraph-migrate's block reads as ungated:\n{migrate}"
    );

    let server = bin_block(&manifest, "server").expect("server bin block");
    assert!(
        server.contains("src/bin/server.rs"),
        "found the wrong block for `server`:\n{server}"
    );
    assert!(
        requires_db(server),
        "the `server` binary builds without the `db` feature, so a no-db build yields a runnable \
         server whose routes serve stub and placeholder data (ruling R-39: not(db) is \
         check-only). Add `required-features = [\"db\"]` to its [[bin]] block:\n{server}"
    );
}
