//! Plain-text views of the workspace's Rust sources, shared by the source
//! ratchets in this directory (no syn, so they run everywhere the suite runs).

use std::path::{Path, PathBuf};

/// Two views of `src`, char-aligned with it (newlines kept):
/// `.0` with comments blanked (string literals kept), `.1` with comments AND
/// string/char literals blanked (for brace matching).
fn lex(src: &str) -> (Vec<char>, Vec<char>) {
    let b: Vec<char> = src.chars().collect();
    let mut keep = b.clone();
    let mut code = b.clone();
    let blank = |v: &mut Vec<char>, k: usize| {
        if v[k] != '\n' {
            v[k] = ' ';
        }
    };
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        let next = b.get(i + 1).copied();
        if c == '/' && next == Some('/') {
            while i < b.len() && b[i] != '\n' {
                blank(&mut keep, i);
                blank(&mut code, i);
                i += 1;
            }
            continue;
        }
        if c == '/' && next == Some('*') {
            let mut depth = 0;
            while i < b.len() {
                if b[i] == '/' && b.get(i + 1) == Some(&'*') {
                    depth += 1;
                    for k in i..i + 2 {
                        blank(&mut keep, k);
                        blank(&mut code, k);
                    }
                    i += 2;
                    continue;
                }
                if b[i] == '*' && b.get(i + 1) == Some(&'/') {
                    depth -= 1;
                    for k in i..i + 2 {
                        blank(&mut keep, k);
                        blank(&mut code, k);
                    }
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                    continue;
                }
                blank(&mut keep, i);
                blank(&mut code, i);
                i += 1;
            }
            continue;
        }
        // Raw string r"…", r#"…"#, br#"…"#: blanked in `code` only.
        let prev_ident = i > 0 && (b[i - 1].is_alphanumeric() || b[i - 1] == '_');
        if !prev_ident && (c == 'r' || (c == 'b' && next == Some('r'))) {
            let mut j = if c == 'b' { i + 2 } else { i + 1 };
            let mut hashes = 0;
            while b.get(j) == Some(&'#') {
                hashes += 1;
                j += 1;
            }
            if b.get(j) == Some(&'"') {
                let start = i;
                j += 1;
                while j < b.len() {
                    if b[j] == '"' && (0..hashes).all(|k| b.get(j + 1 + k) == Some(&'#')) {
                        j += 1 + hashes;
                        break;
                    }
                    j += 1;
                }
                for k in start..j.min(b.len()) {
                    blank(&mut code, k);
                }
                i = j;
                continue;
            }
        }
        if c == '"' {
            let start = i;
            i += 1;
            while i < b.len() {
                if b[i] == '\\' {
                    i += 2;
                    continue;
                }
                if b[i] == '"' {
                    i += 1;
                    break;
                }
                i += 1;
            }
            for k in start..i.min(b.len()) {
                blank(&mut code, k);
            }
            continue;
        }
        // Char literal 'x' / '\n' (a lifetime has no closing quote).
        if c == '\'' {
            let close = if next == Some('\\') {
                (i + 3..(i + 12).min(b.len())).find(|&k| b[k] == '\'')
            } else if b.get(i + 2) == Some(&'\'') {
                Some(i + 2)
            } else {
                None
            };
            if let Some(end) = close {
                for k in i..=end {
                    blank(&mut code, k);
                }
                i = end + 1;
                continue;
            }
        }
        i += 1;
    }
    (keep, code)
}

/// `src` with comments and every `#[cfg(test)] mod … { … }` block blanked,
/// string literals kept, line structure preserved.
pub fn production_code(src: &str) -> String {
    let (mut keep, code) = lex(src);
    let pat: Vec<char> = "#[cfg(test)]".chars().collect();
    let mut i = 0;
    while i + pat.len() <= code.len() {
        if code[i..i + pat.len()] != pat[..] {
            i += 1;
            continue;
        }
        let mut j = i + pat.len();
        while j < code.len() && code[j].is_whitespace() {
            j += 1;
        }
        let rest: String = code[j..code.len().min(j + 4)].iter().collect();
        if rest != "mod " {
            i += 1;
            continue;
        }
        let Some(open) = (j..code.len()).find(|&k| code[k] == '{' || code[k] == ';') else {
            break;
        };
        if code[open] == ';' {
            i = open + 1;
            continue;
        }
        let mut depth = 0;
        let mut end = code.len() - 1;
        for (k, ch) in code.iter().enumerate().skip(open) {
            if *ch == '{' {
                depth += 1;
            } else if *ch == '}' {
                depth -= 1;
                if depth == 0 {
                    end = k;
                    break;
                }
            }
        }
        for ch in keep.iter_mut().take(end + 1).skip(i) {
            if *ch != '\n' {
                *ch = ' ';
            }
        }
        i = end + 1;
    }
    keep.into_iter().collect()
}

pub fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root")
}

fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            rs_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// Production sources: every `crates/<crate>/src/**/*.rs` and `build.rs`.
pub fn production_sources(root: &Path) -> Vec<(String, String)> {
    let mut files = Vec::new();
    for krate in std::fs::read_dir(root.join("crates"))
        .expect("crates/")
        .flatten()
    {
        rs_files(&krate.path().join("src"), &mut files);
        let build = krate.path().join("build.rs");
        if build.is_file() {
            files.push(build);
        }
    }
    files.sort();
    files
        .into_iter()
        .map(|p| {
            let rel = p
                .strip_prefix(root)
                .expect("under the workspace")
                .to_string_lossy()
                .replace('\\', "/");
            let src = std::fs::read_to_string(&p).expect("read source");
            (rel, src)
        })
        .collect()
}
