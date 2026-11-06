//! Compiles every file under `static/` into the binary.
//!
//! Generates `$OUT_DIR/static_assets.rs`: one `include_bytes!` per file plus a
//! content hash for cache-busting URLs. Dropping a file into `static/` is all
//! it takes to serve it at `/static/<path>` — no shared registry to edit.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::{env, fs};

fn main() {
    let root = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("static");
    println!("cargo:rerun-if-changed=static");

    let mut files = Vec::new();
    if root.is_dir() {
        collect(&root, &mut files);
    }
    files.sort();

    let mut out = String::from("pub static ASSETS: &[Asset] = &[\n");
    for path in &files {
        let rel = path
            .strip_prefix(&root)
            .unwrap()
            .components()
            .map(|c| c.as_os_str().to_str().expect("static/ paths must be UTF-8"))
            .collect::<Vec<_>>()
            .join("/");
        let bytes = fs::read(path).unwrap();
        writeln!(
            out,
            "    Asset {{ path: {rel:?}, bytes: include_bytes!({abs:?}), hash: \"{hash:016x}\" }},",
            abs = path.to_str().expect("static/ paths must be UTF-8"),
            hash = fnv1a64(&bytes),
        )
        .unwrap();
        println!("cargo:rerun-if-changed={}", path.display());
    }
    out.push_str("];\n");

    let dest = PathBuf::from(env::var("OUT_DIR").unwrap()).join("static_assets.rs");
    fs::write(dest, out).unwrap();
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name.starts_with('.') {
            continue;
        }
        if path.is_dir() {
            collect(&path, out);
        } else {
            out.push(path);
        }
    }
}

/// FNV-1a: not cryptographic, only needs to change when the bytes do.
fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}
