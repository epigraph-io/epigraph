//! Shared source walking for the two atom-level belief ratchets,
//! `no_role_blind_belief_reads.rs` and `bba_writer_lint.rs` (SPEC §7.3).
//!
//! Both ratchets measure the same two trees, and both are tested by adding
//! ONE scratch source to the real tree and checking the verdict, so the
//! sources are plain `(path, text)` values a test can extend in memory. No
//! scratch file is ever written to disk.

#![allow(dead_code)] // each ratchet uses a different subset of this module

use std::path::{Path, PathBuf};

/// One scanned file: its path relative to the workspace root, with `/`
/// separators, and its text.
#[derive(Clone, Debug)]
pub struct Source {
    pub path: String,
    pub text: String,
}

impl Source {
    pub fn new(path: &str, text: &str) -> Self {
        Self {
            path: path.to_string(),
            text: text.to_string(),
        }
    }
}

/// The workspace root. `CARGO_MANIFEST_DIR` is `crates/epigraph-db`.
pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/epigraph-db has two ancestors")
        .to_path_buf()
}

fn walk(dir: &Path, keep: &dyn Fn(&Path) -> bool, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            if p.file_name().is_some_and(|n| n == "__pycache__") {
                continue;
            }
            walk(&p, keep, out);
        } else if keep(&p) {
            out.push(p);
        }
    }
}

fn load(paths: Vec<PathBuf>) -> Vec<Source> {
    let root = repo_root();
    let mut out: Vec<Source> = paths
        .into_iter()
        .filter_map(|p| {
            // A non-UTF-8 file (an image, a compiled artifact) carries no SQL
            // a reviewer could read either.
            let text = std::fs::read_to_string(&p).ok()?;
            let rel = p
                .strip_prefix(&root)
                .unwrap_or(&p)
                .to_string_lossy()
                .replace('\\', "/");
            Some(Source { path: rel, text })
        })
        .collect();
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

/// Every `.rs` file under `crates/*/src/`. Tests, benches and examples are
/// out of scope: a fixture's SQL is not a served read or a production write.
pub fn rust_sources() -> Vec<Source> {
    let mut paths = Vec::new();
    let crates = repo_root().join("crates");
    let Ok(entries) = std::fs::read_dir(&crates) else {
        return Vec::new();
    };
    for e in entries.flatten() {
        let src = e.path().join("src");
        if src.is_dir() {
            walk(
                &src,
                &|p: &Path| p.extension().is_some_and(|x| x == "rs"),
                &mut paths,
            );
        }
    }
    load(paths)
}

/// Every text file under `scripts/`, whatever its type.
pub fn script_sources() -> Vec<Source> {
    let mut paths = Vec::new();
    walk(&repo_root().join("scripts"), &|_: &Path| true, &mut paths);
    load(paths)
}

/// `base` plus one scratch source. The ratchets' synthetic tests run the
/// whole pipeline over the real tree and this one addition.
pub fn with_scratch(base: &[Source], path: &str, text: &str) -> Vec<Source> {
    let mut v = base.to_vec();
    v.push(Source::new(path, text));
    v
}

// ---------------------------------------------------------------------------
// Text views
// ---------------------------------------------------------------------------

/// One string literal: the byte offset of its first content byte in the
/// source, and its contents (escapes left as written).
#[derive(Clone, Debug)]
pub struct Lit {
    pub start: usize,
    pub text: String,
}

/// A source split into the two texts the ratchets read.
///
/// * `code` has the source's byte length. Comments, string-literal contents
///   and char-literal contents are blanked to spaces (newlines kept), and so
///   is every non-ASCII byte, so a byte offset means the same thing in
///   `code` and in the source. An identifier, a call or a field access counts
///   only here: written inside a comment or a string, it does nothing.
/// * `literals` are the string literals, in order. SQL counts only here.
#[derive(Clone, Debug)]
pub struct View {
    pub code: String,
    pub literals: Vec<Lit>,
}

fn is_ident(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn blank(out: &mut [u8], from: usize, to: usize) {
    for b in &mut out[from..to] {
        if *b != b'\n' {
            *b = b' ';
        }
    }
}

/// The Rust view of `src`. Nested block comments, raw strings (`r"…"`,
/// `r#"…"#`, `br"…"`), byte strings, escapes and char literals are followed;
/// a lifetime tick is not mistaken for a char literal (the rule of
/// `lint_text::spend_views`). Every item attributed `#[cfg(test)]` is blanked
/// too, with its literals dropped: a unit-test fixture is not a served read
/// or a production write.
pub fn rust_view(src: &str) -> View {
    let b = src.as_bytes();
    let n = b.len();
    let mut out = b.to_vec();
    let mut literals = Vec::new();
    let mut i = 0;
    while i < n {
        let c = b[i];
        let next = b.get(i + 1).copied();
        if c == b'/' && next == Some(b'/') {
            let end = src[i..].find('\n').map_or(n, |e| i + e);
            blank(&mut out, i, end);
            i = end;
            continue;
        }
        if c == b'/' && next == Some(b'*') {
            let mut depth = 0usize;
            let mut j = i;
            while j < n {
                if b[j] == b'/' && b.get(j + 1) == Some(&b'*') {
                    depth += 1;
                    j += 2;
                } else if b[j] == b'*' && b.get(j + 1) == Some(&b'/') {
                    depth -= 1;
                    j += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    j += 1;
                }
            }
            blank(&mut out, i, j.min(n));
            i = j;
            continue;
        }
        // Raw string: `r` (or `br`) not continuing an identifier, then
        // hashes, then a quote.
        if c == b'r' && matches!(next, Some(b'#') | Some(b'"')) {
            let prev_ok = i == 0
                || !is_ident(b[i - 1])
                || (b[i - 1] == b'b' && (i < 2 || !is_ident(b[i - 2])));
            if prev_ok {
                let mut k = i + 1;
                while k < n && b[k] == b'#' {
                    k += 1;
                }
                if k < n && b[k] == b'"' {
                    let hashes = k - (i + 1);
                    let mut term = String::from("\"");
                    term.push_str(&"#".repeat(hashes));
                    let start = k + 1;
                    let end = src[start..].find(&term).map_or(n, |e| start + e);
                    literals.push(Lit {
                        start,
                        text: src[start..end].to_string(),
                    });
                    blank(&mut out, start, end);
                    i = (end + term.len()).min(n);
                    continue;
                }
            }
        }
        if c == b'"' {
            let start = i + 1;
            let mut k = start;
            while k < n {
                if b[k] == b'\\' {
                    k += 2;
                    continue;
                }
                if b[k] == b'"' {
                    break;
                }
                k += 1;
            }
            let end = k.min(n);
            literals.push(Lit {
                start,
                text: src[start..end].to_string(),
            });
            blank(&mut out, start, end);
            i = end + 1;
            continue;
        }
        if c == b'\'' {
            let close = if next == Some(b'\\') {
                (i + 2..(i + 14).min(n)).find(|&k| b[k] == b'\'')
            } else if b.get(i + 2) == Some(&b'\'') {
                Some(i + 2)
            } else {
                None
            };
            if let Some(end) = close {
                blank(&mut out, i + 1, end);
                i = end + 1;
                continue;
            }
        }
        i += 1;
    }
    for byte in &mut out {
        if !byte.is_ascii() {
            *byte = b' ';
        }
    }
    let mut code = String::from_utf8(out).expect("the code view is ASCII");

    // Blank `#[cfg(test)]` items: from the attribute to the end of the item
    // it attributes (its balanced `{…}` block, or its `;`).
    let mut cut: Vec<(usize, usize)> = Vec::new();
    let mut from = 0;
    while let Some(rel) = code[from..].find("#[cfg(test)]") {
        let at = from + rel;
        let cb = code.as_bytes();
        let mut j = at + "#[cfg(test)]".len();
        let mut end = cb.len();
        while j < cb.len() {
            if cb[j] == b';' {
                end = j + 1;
                break;
            }
            if cb[j] == b'{' {
                end = balanced_end(&code, j, b'{', b'}');
                break;
            }
            j += 1;
        }
        cut.push((at, end));
        from = end.max(at + 1);
    }
    if !cut.is_empty() {
        let mut bytes = code.into_bytes();
        for &(a, e) in &cut {
            blank(&mut bytes, a, e);
        }
        code = String::from_utf8(bytes).expect("still ASCII");
        literals.retain(|l| !cut.iter().any(|&(a, e)| l.start >= a && l.start < e));
    }
    View { code, literals }
}

/// The end (exclusive) of the balanced `open … close` region starting at
/// `code[start]`, on a code view (no strings or comments left to confuse it).
pub fn balanced_end(code: &str, start: usize, open: u8, close: u8) -> usize {
    let b = code.as_bytes();
    let mut depth = 0usize;
    for (j, &c) in b.iter().enumerate().skip(start) {
        if c == open {
            depth += 1;
        } else if c == close {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return j + 1;
            }
        }
    }
    b.len()
}

/// The Python view of `src`: `#` comments and string contents blanked (all
/// prefixes and both quote styles, single and triple), with the literals.
pub fn python_view(src: &str) -> View {
    let b = src.as_bytes();
    let n = b.len();
    let mut out = b.to_vec();
    let mut literals = Vec::new();
    let mut i = 0;
    while i < n {
        let c = b[i];
        if c == b'#' {
            let end = src[i..].find('\n').map_or(n, |e| i + e);
            blank(&mut out, i, end);
            i = end;
            continue;
        }
        if c == b'"' || c == b'\'' {
            let triple = b.get(i + 1) == Some(&c) && b.get(i + 2) == Some(&c);
            let qlen = if triple { 3 } else { 1 };
            let start = i + qlen;
            let mut k = start;
            let end = loop {
                if k >= n {
                    break n;
                }
                if b[k] == b'\\' {
                    k += 2;
                    continue;
                }
                if b[k] == c && (!triple || (b.get(k + 1) == Some(&c) && b.get(k + 2) == Some(&c)))
                {
                    break k;
                }
                if !triple && b[k] == b'\n' {
                    break k;
                }
                k += 1;
            };
            // A docstring (a triple-quoted literal that opens its line and
            // follows a `def` / `class` header, or opens the module) is prose,
            // not a statement: it is blanked but not kept as a literal.
            let line_start = src[..i].rfind('\n').map_or(0, |p| p + 1);
            let opens_line = out[line_start..i].iter().all(|c| c.is_ascii_whitespace());
            let prev_code = String::from_utf8_lossy(&out[..line_start]).to_string();
            let prev_line = prev_code.lines().rev().find(|l| !l.trim().is_empty());
            let docstring =
                triple && opens_line && prev_line.is_none_or(|l| l.trim_end().ends_with(':'));
            if !docstring {
                literals.push(Lit {
                    start,
                    text: src[start..end].to_string(),
                });
            }
            blank(&mut out, start, end);
            i = (end + qlen).min(n);
            continue;
        }
        i += 1;
    }
    for byte in &mut out {
        if !byte.is_ascii() {
            *byte = b' ';
        }
    }
    View {
        code: String::from_utf8(out).expect("the code view is ASCII"),
        literals,
    }
}

// ---------------------------------------------------------------------------
// Units: the function (or item) a hit belongs to
// ---------------------------------------------------------------------------

/// A Rust `fn` with a body: its name, the offset of `fn`, and its body's
/// `{`…`}` span. `impl_type` is the type of the innermost `impl` block it
/// sits in, if any.
#[derive(Clone, Debug)]
pub struct RustFn {
    pub name: String,
    pub impl_type: Option<String>,
    pub sig_start: usize,
    pub body_start: usize,
    pub end: usize,
}

impl RustFn {
    /// Signature and body, from the code view.
    pub fn text<'a>(&self, code: &'a str) -> &'a str {
        &code[self.sig_start..self.end]
    }
    /// The return type text, between `->` and the body (empty if none).
    pub fn return_type<'a>(&self, code: &'a str) -> &'a str {
        let sig = &code[self.sig_start..self.body_start];
        let close = sig.rfind(')').unwrap_or(0);
        match sig[close..].find("->") {
            Some(a) => &sig[close + a + 2..],
            None => "",
        }
    }
}

/// Every occurrence of `word` in `hay` with identifier boundaries on both
/// sides.
pub fn find_words(hay: &str, word: &str) -> Vec<usize> {
    let b = hay.as_bytes();
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(rel) = hay[from..].find(word) {
        let at = from + rel;
        let end = at + word.len();
        let before = at == 0 || !is_ident(b[at - 1]);
        let after = end >= b.len() || !is_ident(b[end]);
        if before && after {
            out.push(at);
        }
        from = at + 1;
    }
    out
}

pub fn has_word(hay: &str, word: &str) -> bool {
    !find_words(hay, word).is_empty()
}

fn ident_at(code: &str, at: usize) -> Option<(String, usize)> {
    let b = code.as_bytes();
    let mut j = at;
    while j < b.len() && b[j].is_ascii_whitespace() {
        j += 1;
    }
    let s = j;
    while j < b.len() && is_ident(b[j]) {
        j += 1;
    }
    (j > s && !b[s].is_ascii_digit()).then(|| (code[s..j].to_string(), j))
}

/// The end of a `<…>` generic list starting at `code[start]`. A `>` that
/// closes `->` or `=>` is not a bracket.
fn angle_end(code: &str, start: usize) -> usize {
    let b = code.as_bytes();
    let mut depth = 0usize;
    for j in start..b.len() {
        match b[j] {
            b'<' => depth += 1,
            b'>' if j > 0 && (b[j - 1] == b'-' || b[j - 1] == b'=') => {}
            b'>' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return j + 1;
                }
            }
            b'{' | b';' => return j,
            _ => {}
        }
    }
    b.len()
}

/// `impl` blocks of a code view: (type name, body span).
fn impl_blocks(code: &str) -> Vec<(String, usize, usize)> {
    let b = code.as_bytes();
    let mut out = Vec::new();
    for at in find_words(code, "impl") {
        let mut j = at + 4;
        while j < b.len() && b[j].is_ascii_whitespace() {
            j += 1;
        }
        if j < b.len() && b[j] == b'<' {
            j = angle_end(code, j);
        }
        let Some(brace_rel) = code[j..].find(['{', ';', '(', ')']) else {
            continue;
        };
        if b[j + brace_rel] != b'{' {
            continue; // `impl Trait` in argument or return position
        }
        let head = &code[j..j + brace_rel];
        let head = head.split(" where ").next().unwrap_or(head);
        let head = match head.rfind(" for ") {
            Some(f) => &head[f + 5..],
            None => head,
        };
        let head = head.split('<').next().unwrap_or(head).trim();
        let name = head.rsplit("::").next().unwrap_or(head).trim().to_string();
        if name.is_empty() {
            continue;
        }
        let open = j + brace_rel;
        out.push((name, open, balanced_end(code, open, b'{', b'}')));
    }
    out
}

/// Every Rust `fn` with a body in a code view.
pub fn rust_fns(code: &str) -> Vec<RustFn> {
    let b = code.as_bytes();
    let impls = impl_blocks(code);
    let mut out = Vec::new();
    for at in find_words(code, "fn") {
        let Some((name, mut j)) = ident_at(code, at + 2) else {
            continue; // `fn(` pointer types
        };
        while j < b.len() && b[j].is_ascii_whitespace() {
            j += 1;
        }
        if j < b.len() && b[j] == b'<' {
            j = angle_end(code, j);
            while j < b.len() && b[j].is_ascii_whitespace() {
                j += 1;
            }
        }
        if j >= b.len() || b[j] != b'(' {
            continue;
        }
        j = balanced_end(code, j, b'(', b')');
        // The body is the first `{` before any `;` (a `;` first means a
        // bodiless trait method declaration).
        let Some(rel) = code[j..].find(['{', ';']) else {
            continue;
        };
        if b[j + rel] != b'{' {
            continue;
        }
        let body_start = j + rel;
        let end = balanced_end(code, body_start, b'{', b'}');
        let impl_type = impls
            .iter()
            .filter(|(_, s, e)| *s < at && at < *e)
            .min_by_key(|(_, s, e)| e - s)
            .map(|(n, _, _)| n.clone());
        out.push(RustFn {
            name,
            impl_type,
            sig_start: at,
            body_start,
            end,
        });
    }
    out
}

/// `const NAME: …;` / `static NAME: …;` items outside any fn: (name, span).
fn rust_consts(code: &str) -> Vec<(String, usize, usize)> {
    let b = code.as_bytes();
    let mut out = Vec::new();
    for kw in ["const", "static"] {
        for at in find_words(code, kw) {
            if at > 0 && b[at - 1] == b'\'' {
                continue; // `'static`
            }
            let Some((name, j)) = ident_at(code, at + kw.len()) else {
                continue;
            };
            let rest = code[j..].trim_start();
            if !rest.starts_with(':') {
                continue; // `const fn`, `static ref`, …
            }
            // The item ends at the first `;` outside brackets.
            let mut depth = 0i32;
            let mut end = b.len();
            for (k, &c) in b.iter().enumerate().skip(j) {
                match c {
                    b'(' | b'[' | b'{' => depth += 1,
                    b')' | b']' | b'}' => depth -= 1,
                    b';' if depth <= 0 => {
                        end = k + 1;
                        break;
                    }
                    _ => {}
                }
            }
            out.push((name, at, end));
        }
    }
    out
}

/// The unit names of a Rust code view, resolved by offset.
pub struct RustUnits {
    pub fns: Vec<RustFn>,
    consts: Vec<(String, usize, usize)>,
}

impl RustUnits {
    pub fn new(code: &str) -> Self {
        Self {
            fns: rust_fns(code),
            consts: rust_consts(code),
        }
    }

    /// The innermost fn containing `offset`.
    pub fn fn_at(&self, offset: usize) -> Option<&RustFn> {
        self.fns
            .iter()
            .filter(|f| f.sig_start <= offset && offset < f.end)
            .min_by_key(|f| f.end - f.sig_start)
    }

    /// The unit name of `offset` and the code span it covers: the innermost
    /// fn, else the `const` / `static` item, else `<module>`.
    pub fn unit_at(&self, offset: usize) -> (String, Option<(usize, usize)>) {
        if let Some(f) = self.fn_at(offset) {
            return (f.name.clone(), Some((f.sig_start, f.end)));
        }
        if let Some((name, s, e)) = self
            .consts
            .iter()
            .filter(|(_, s, e)| *s <= offset && offset < *e)
            .min_by_key(|(_, s, e)| e - s)
        {
            return (format!("const {name}"), Some((*s, *e)));
        }
        ("<module>".to_string(), None)
    }
}

/// The enclosing `def` of the line holding `offset` in a Python code view, by
/// indentation, or `<module>`.
pub fn python_unit_at(code: &str, offset: usize) -> String {
    let line_start = code[..offset].rfind('\n').map_or(0, |i| i + 1);
    let indent = |l: &str| l.len() - l.trim_start().len();
    let mut limit = indent(&code[line_start..]);
    for line in code[..line_start].lines().rev() {
        if line.trim().is_empty() {
            continue;
        }
        let ind = indent(line);
        if ind >= limit {
            continue;
        }
        let t = line.trim_start();
        if t.starts_with([')', ']', '}']) {
            continue; // the close of a bracketed continuation, e.g. a long signature
        }
        let def = t
            .strip_prefix("async def ")
            .or_else(|| t.strip_prefix("def "));
        if let Some(rest) = def {
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            return name;
        }
        limit = ind;
        if ind == 0 {
            break;
        }
    }
    "<module>".to_string()
}

// ---------------------------------------------------------------------------
// SQL
// ---------------------------------------------------------------------------

/// Is this literal SQL? Statements in this codebase are written with
/// UPPER-case keywords, so the keywords are matched case-sensitively, as
/// whole words: lower-case prose ("select from the list") and the MCP tool
/// descriptions are not SQL. A literal with no keyword counts when it names a
/// table-qualified column of interest (`c.pignistic_prob`), which is how a
/// statement split across several literals shows up in its middle pieces.
pub fn is_sql(lit: &str) -> bool {
    const KEYWORDS: &[&str] = &[
        "SELECT",
        "FROM",
        "WHERE",
        "UPDATE",
        "INSERT",
        "DELETE",
        "JOIN",
        "RETURNING",
        "SET",
        "VALUES",
    ];
    if KEYWORDS.iter().any(|k| has_word(lit, k))
        || lit.contains("ORDER BY")
        || lit.contains("GROUP BY")
        || ["COALESCE(", "GREATEST(", "LEAST("]
            .iter()
            .any(|f| lit.contains(f))
    {
        return true;
    }
    ["pignistic_prob", "plausibility", "belief", "truth_value"]
        .iter()
        .any(|col| {
            find_words(lit, col).iter().any(|&at| {
                at >= 2 && lit.as_bytes()[at - 1] == b'.' && is_ident(lit.as_bytes()[at - 2])
            })
        })
}

/// `lit` without its SQL comments: `--` to the end of the line (a newline or
/// a `\n` escape) and `/* … */` spans. A `--` inside a quoted SQL literal is
/// read as a comment too; that only hides text.
pub fn sql_without_comments(lit: &str) -> String {
    let b = lit.as_bytes();
    let mut out = String::with_capacity(lit.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'-' && b.get(i + 1) == Some(&b'-') {
            let nl = lit[i..].find('\n').map(|e| i + e);
            let esc = lit[i..].find("\\n").map(|e| i + e);
            i = match (nl, esc) {
                (Some(a), Some(e)) => a.min(e),
                (Some(a), None) => a,
                (None, Some(e)) => e,
                (None, None) => b.len(),
            };
            continue;
        }
        if b[i] == b'/' && b.get(i + 1) == Some(&b'*') {
            i = lit[i + 2..].find("*/").map_or(b.len(), |e| i + 2 + e + 2);
            continue;
        }
        let ch = lit[i..].chars().next().expect("in bounds");
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// Does this SQL literal write (`INSERT INTO`, `UPDATE`, `DELETE FROM`, or a
/// `SET` clause continued from an earlier literal)?
pub fn is_write_sql(sql: &str) -> bool {
    sql.contains("INSERT INTO")
        || has_word(sql, "UPDATE")
        || sql.contains("DELETE FROM")
        || has_word(sql, "SET")
}
