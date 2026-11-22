//! The per-call viewer-spend scanner shared by `visibility_lint.rs` (the repo
//! layer) and `epigraph-mcp/tests/tool_viewer_is_spent.rs` (the MCP tools),
//! backlog ada8ee55.
//!
//! # What it measures
//!
//! For every `fn` that holds a viewer, every database call in its body, and
//! whether that call receives the viewer. The two lints that include this
//! module assert the UNVIEWED calls against an exact per-fn register, the shape
//! `epigraph-api/tests/viewer_spend_lint.rs` gives the route handlers. The
//! fn-level checks those two files already run ("the body spends its viewer at
//! least once") cannot see the defect this exists for: a fn that spends its
//! viewer on one statement while the statement whose rows it returns runs
//! without it.
//!
//! The scanner is a port of `viewer_spend_lint.rs`'s, with two differences, both
//! on purpose:
//!
//! * **The spend rule is the repo and tool layers', not the routes'.** A call is
//!   viewed when it hands the viewer on as a whole value (the bare identifier, or
//!   [`HANDOFF_METHODS`]: a clone, a scoped copy, or a rendered or spliced
//!   predicate), or when its statement text carries the live SQL marker
//!   `visibility = 'public'` IN PREDICATE POSITION ([`predicate_spend`], after
//!   `AND` / `OR` / `WHERE` / `ON`; not in a projection, an `ORDER BY` or a
//!   `CASE WHEN`). Stricter than each lint's fn-level `spends_viewer`, which
//!   also counts `.splice(` on any receiver and the marker anywhere: per call,
//!   a splice counts only on one of the fn's own viewers (a handoff).
//!   `group_bind()` and `writable_bind()`
//!   are NOT a spend here, as they are not in either lint's fn-level check:
//!   binding an array proves a parameter was supplied, not that the SQL reads
//!   it. A three-bind statement is viewed by its SQL text, which is in the
//!   call's region.
//! * **The database handles are named by a [`Surface`]**, so one scanner reads
//!   both the repo layer (pool, connection, transaction and generic-executor
//!   parameters) and the MCP tools (the server handle, its pool fields, its
//!   stamped-connection method, the maintenance sessions).
//!
//! # Regions
//!
//! A call's region is its argument list; for a `sqlx` chain it is the whole
//! chain from `sqlx::` to the terminal's closing parenthesis, plus the `let`
//! right-hand side of the statement or SQL string the chain reads. Structure is
//! read on a length-preserving view with comments and string contents blanked,
//! so offsets agree with the raw source; the marker check then reads the RAW
//! slices at those offsets, which always start at a code token.
//!
//! # Labels
//!
//! As in the route lint: a repo or helper call by its last two path segments
//! (`ClaimRepository::get_by_id`); a `sqlx` chain by its head, the first word of
//! its SQL and its terminal (`sqlx::query_as(SELECT).fetch_one`); a method on a
//! pool handle as `<handle>.<method>`.

#![allow(dead_code)]

use std::collections::BTreeMap;

/// The database handles of one scanned layer.
pub struct Surface {
    /// Type fragments marking a parameter as the whole application handle
    /// (`EpiGraphMcpFull`). Passed to a call as an argument, that call is a
    /// database call (the callee can reach the pool), and `<handle>.<field>`
    /// for a field in [`Self::pool_fields`] is a pool.
    pub state_types: &'static [&'static str],
    /// Fields of the application handle that are pools.
    pub pool_fields: &'static [&'static str],
    /// Methods of the application handle that open a connection or run SQL
    /// (`read_as`). A call to one is a database call.
    pub state_db_methods: &'static [&'static str],
    /// Calls whose result is a viewer (`request_viewer(`, `Viewer::resolve(`).
    /// A `let` binding of one is a viewer the fn holds, so a fn that resolves
    /// its own viewer is in the population.
    pub viewer_ctors: &'static [&'static str],
    /// Extra connection constructors, beyond [`CONNECTION_CTORS`], whose `let`
    /// binding is a connection (`admin_cascade_session(`).
    pub conn_ctors: &'static [&'static str],
    /// The per-call marker-spend predicate, run on the RAW text of a call's
    /// region: the lint's `spend_views` (to drop comments) followed by
    /// [`predicate_spend`]. Not the lint's fn-level `spends_viewer`, which
    /// also counts `.splice(` on any receiver and the SQL marker in any
    /// position.
    pub marker_spend: fn(&str) -> bool,
}

// ── source views ────────────────────────────────────────────────────────────

/// Two views of `src`, byte-for-byte the same length as it, so offsets agree:
///
/// * `code`: comments and string/char-literal CONTENTS replaced by spaces (the
///   quotes stay). Everything structural is read here.
/// * `sql`: comments replaced by spaces, string contents kept. Read only for
///   the first word of a statement and for `#[cfg(..)]` predicates.
///
/// A copy of `viewer_spend_lint.rs::views`.
pub fn views(src: &str) -> (String, String) {
    let s = src.as_bytes();
    let n = s.len();
    let mut code = s.to_vec();
    let mut sql = s.to_vec();
    let blank = |code: &mut Vec<u8>, sql: &mut Vec<u8>, a: usize, b: usize, both: bool| {
        for k in a..b.min(n) {
            if s[k] != b'\n' {
                code[k] = b' ';
                if both {
                    sql[k] = b' ';
                }
            }
        }
    };
    let mut i = 0;
    while i < n {
        if s[i..].starts_with(b"//") {
            let j = s[i..].iter().position(|&c| c == b'\n').map_or(n, |p| i + p);
            blank(&mut code, &mut sql, i, j, true);
            i = j;
            continue;
        }
        if s[i..].starts_with(b"/*") {
            let (mut depth, mut j) = (0usize, i);
            while j < n {
                if s[j..].starts_with(b"/*") {
                    depth += 1;
                    j += 2;
                } else if s[j..].starts_with(b"*/") {
                    depth -= 1;
                    j += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    j += 1;
                }
            }
            blank(&mut code, &mut sql, i, j, true);
            i = j;
            continue;
        }
        let prev_is_ident = i > 0 && is_ident(s[i - 1]);
        if !prev_is_ident && (s[i] == b'r' || s[i] == b'b') {
            let mut j = i;
            if s[j] == b'b' {
                j += 1;
            }
            if j < n && s[j] == b'r' {
                let mut k = j + 1;
                while k < n && s[k] == b'#' {
                    k += 1;
                }
                if k < n && s[k] == b'"' {
                    let hashes = k - (j + 1);
                    // `resize`, not `repeat_n`: this file compiles under two
                    // crates' MSRVs, and `repeat_n` is newer than one of them.
                    let mut end = vec![b'"'];
                    end.resize(hashes + 1, b'#');
                    let close = find(s, &end, k + 1).unwrap_or(n);
                    blank(&mut code, &mut sql, k + 1, close, false);
                    i = close + end.len();
                    continue;
                }
            }
            if s[i] == b'b' && i + 1 < n && s[i + 1] == b'"' {
                i += 1;
            }
        }
        if s[i] == b'"' {
            let mut j = i + 1;
            while j < n && s[j] != b'"' {
                if s[j] == b'\\' {
                    j += 1;
                }
                j += 1;
            }
            blank(&mut code, &mut sql, i + 1, j, false);
            i = j + 1;
            continue;
        }
        if s[i] == b'\'' {
            // A char literal ('x', '\n', '\u{..}'); otherwise a lifetime.
            if i + 2 < n && s[i + 1] == b'\\' {
                let j = s[i + 2..]
                    .iter()
                    .position(|&c| c == b'\'')
                    .map_or(n, |p| i + 2 + p);
                blank(&mut code, &mut sql, i + 1, j, false);
                i = j + 1;
                continue;
            }
            if i + 2 < n && s[i + 2] == b'\'' {
                blank(&mut code, &mut sql, i + 1, i + 2, false);
                i += 3;
                continue;
            }
        }
        i += 1;
    }
    (
        String::from_utf8(code).expect("only ASCII spaces were written"),
        String::from_utf8(sql).expect("only ASCII spaces were written"),
    )
}

fn is_ident(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

fn find(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if from > hay.len() {
        return None;
    }
    hay[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| from + p)
}

/// Offsets in `[a, b)` where `word` occurs with no identifier byte on either side.
fn words(code: &str, word: &str, a: usize, b: usize) -> Vec<usize> {
    let s = code.as_bytes();
    let mut out = Vec::new();
    let mut from = a;
    while let Some(p) = find(s, word.as_bytes(), from) {
        if p >= b {
            break;
        }
        let end = p + word.len();
        if (p == 0 || !is_ident(s[p - 1])) && (end >= s.len() || !is_ident(s[end])) {
            out.push(p);
        }
        from = p + 1;
    }
    out
}

fn skip_ws(s: &[u8], mut i: usize) -> usize {
    while i < s.len() && s[i].is_ascii_whitespace() {
        i += 1;
    }
    i
}

fn ident_at(s: &[u8], i: usize) -> &str {
    let mut j = i;
    while j < s.len() && is_ident(s[j]) {
        j += 1;
    }
    std::str::from_utf8(&s[i..j]).expect("ASCII identifier")
}

/// The offset of the bracket closing the one at `open`. For `<`, a `->` arrow
/// inside does not close it.
fn close_of(s: &[u8], open: usize) -> usize {
    let (o, c) = match s[open] {
        b'(' => (b'(', b')'),
        b'[' => (b'[', b']'),
        b'{' => (b'{', b'}'),
        b'<' => (b'<', b'>'),
        other => panic!("close_of on {:?}", other as char),
    };
    let mut depth = 0usize;
    for (j, &ch) in s.iter().enumerate().skip(open) {
        if ch == o {
            depth += 1;
        } else if ch == c && !(c == b'>' && j > 0 && s[j - 1] == b'-') {
            depth -= 1;
            if depth == 0 {
                return j;
            }
        }
    }
    s.len() - 1
}

/// Spans of items under `#[cfg(test)]`, `#[cfg(all(test, ..))]` or
/// `#[cfg(not(feature = "db"))]`: none of them serves a request.
fn excluded_spans(code: &str, sql: &str) -> Vec<(usize, usize)> {
    let (c, q) = (code.as_bytes(), sql.as_bytes());
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(at) = find(c, b"#[cfg(", from) {
        from = at + 1;
        let open = at + 5;
        let close = close_of(c, open);
        let pred: String = std::str::from_utf8(&q[open + 1..close])
            .expect("utf-8")
            .chars()
            .filter(|ch| !ch.is_whitespace())
            .collect();
        if pred == "test" || pred.starts_with("all(test") || pred == "not(feature=\"db\")" {
            let brace = find(c, b"{", close).unwrap_or(c.len() - 1);
            let semi = find(c, b";", close).unwrap_or(c.len() - 1);
            let end = if semi < brace {
                semi
            } else {
                close_of(c, brace)
            };
            out.push((at, end));
        }
    }
    out
}

// ── viewer-holding fns ──────────────────────────────────────────────────────

/// One viewer-holding fn.
pub struct Holder {
    pub name: String,
    /// The viewer variables: its viewer parameter, a viewer field bound by a
    /// struct-pattern `let` (`let Ctx { viewer, .. } = *ctx;`), and every
    /// `let` binding of a viewer constructor or of an `unwrap_or(<viewer>)`
    /// fallback.
    pub viewers: Vec<String>,
    pub body: (usize, usize),
    /// Parameters (or destructured struct fields) typed as a pool (`&PgPool`,
    /// `&ScopedPool`).
    pub pools: Vec<String>,
    /// Parameters (or destructured struct fields) typed as a connection or
    /// executor: any use inside a call is a database call.
    pub conns: Vec<String>,
    /// Parameters (or destructured struct fields) typed as the application
    /// handle.
    pub states: Vec<String>,
}

/// Split `inner` (the text between a pair of brackets) on depth-0 commas.
fn split_top(inner: &[u8]) -> Vec<&[u8]> {
    let mut parts = Vec::new();
    let (mut depth, mut start) = (0i32, 0usize);
    for (i, &c) in inner.iter().enumerate() {
        match c {
            b'>' if i > 0 && inner[i - 1] == b'-' => {}
            b'(' | b'<' | b'[' | b'{' => depth += 1,
            b')' | b'>' | b']' | b'}' => depth -= 1,
            b',' if depth == 0 => {
                parts.push(&inner[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(&inner[start..]);
    parts
}

/// `(name, flattened type)` of each `<ident>: <type>` parameter in `params`
/// (the text between, and including, the parentheses).
fn typed_params(params: &str) -> Vec<(String, String)> {
    let p = params.as_bytes();
    let mut out = Vec::new();
    for part in split_top(&p[1..p.len() - 1]) {
        let part = std::str::from_utf8(part).expect("ASCII params");
        let Some(colon) = part.find(':') else {
            continue;
        };
        let name = part[..colon].trim().trim_start_matches("mut ").trim();
        if name.is_empty() || !name.bytes().all(is_ident) || part[colon..].starts_with("::") {
            continue;
        }
        out.push((name.to_string(), flat_type(&part[colon + 1..])));
    }
    out
}

/// A parameter type with whitespace and lifetimes removed: `&'a mut
/// PgConnection` -> `&mutPgConnection`, `&'_ Viewer` -> `&Viewer`.
fn flat_type(ty: &str) -> String {
    let b = ty.as_bytes();
    let mut out = String::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\'' {
            i += 1;
            while i < b.len() && is_ident(b[i]) {
                i += 1;
            }
            continue;
        }
        if !b[i].is_ascii_whitespace() {
            out.push(b[i] as char);
        }
        i += 1;
    }
    out
}

/// Is `ty` (flattened) a `Viewer`, by reference or by value:
/// `&Viewer`, `&epigraph_db::visibility::Viewer`, `Viewer`?
fn is_viewer_type(ty: &str) -> bool {
    let rest = ty.strip_prefix('&').unwrap_or(ty);
    let rest = rest.trim_start_matches("mut");
    rest == "Viewer"
        || (rest.ends_with("::Viewer") && rest.bytes().all(|c| is_ident(c) || c == b':'))
}

/// The generic type parameters bounded by an executor trait, from the generic
/// list and the `where` clause: `E` in `fn f<'e, E: sqlx::PgExecutor<'e>>` or
/// `fn f<A>(..) where A: sqlx::Acquire<'_, Database = Postgres>`.
fn executor_generics(generics: &str, where_clause: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut read = |text: &str| {
        for part in split_top(text.as_bytes()) {
            let part = std::str::from_utf8(part).expect("ASCII generics");
            let Some(colon) = part.find(':') else {
                continue;
            };
            let name = part[..colon].trim();
            let bounds = &part[colon..];
            if !name.is_empty()
                && name.bytes().all(is_ident)
                && (bounds.contains("Executor") || bounds.contains("Acquire"))
            {
                out.push(name.to_string());
            }
        }
    };
    if generics.len() >= 2 {
        read(&generics[1..generics.len() - 1]);
    }
    read(where_clause);
    out
}

/// The kind of database-relevant value a parameter or field type names.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Viewer,
    Pool,
    Conn,
    State,
    Other,
}

/// Classify a flattened parameter or field type. `exec` holds the fn's
/// executor-bounded generic parameters.
fn classify(ty: &str, surface: &Surface, exec: &[String]) -> Kind {
    if is_viewer_type(ty) {
        return Kind::Viewer;
    }
    if ty.contains("PgPool") || ty.contains("ScopedPool") {
        return Kind::Pool;
    }
    let conn = [
        "PgConnection",
        "ScopedRead",
        "ScopedTx",
        "Transaction<",
        "PgExecutor",
        "Executor<",
        "Acquire<",
    ]
    .iter()
    .any(|t| ty.contains(t))
        || exec.iter().any(|e| {
            let bare = ty.trim_start_matches('&').trim_start_matches("mut");
            bare == e
        });
    if conn {
        return Kind::Conn;
    }
    if surface.state_types.iter().any(|t| ty.contains(t)) {
        return Kind::State;
    }
    Kind::Other
}

/// `struct name -> [(field, flattened type)]` for every braced struct in
/// `code` (the code view). A fn can receive its viewer inside one of these and
/// destructure it (`let UnitContext { server, viewer, .. } = *ctx;`), which a
/// scan of parameter types alone does not see.
pub type Structs = BTreeMap<String, Vec<(String, String)>>;

/// Every braced `struct` in `code` with its named fields.
pub fn struct_fields(code: &str) -> Structs {
    let s = code.as_bytes();
    let mut out = Structs::new();
    for at in words(code, "struct", 0, s.len()) {
        let mut j = skip_ws(s, at + "struct".len());
        let name = ident_at(s, j).to_string();
        if name.is_empty() {
            continue;
        }
        j = skip_ws(s, j + name.len());
        if j < s.len() && s[j] == b'<' {
            j = skip_ws(s, close_of(s, j) + 1);
        }
        // A `where` clause before the body.
        if s[j..].starts_with(b"where") {
            match find(s, b"{", j) {
                Some(b) if !matches!(find(s, b";", j), Some(semi) if semi < b) => j = b,
                _ => continue,
            }
        }
        if j >= s.len() || s[j] != b'{' {
            continue;
        }
        let close = close_of(s, j);
        let mut fields = Vec::new();
        for part in split_top(&s[j + 1..close]) {
            let mut part = std::str::from_utf8(part).expect("ASCII struct body").trim();
            // Attributes on the field (`#[serde(default)]`).
            while part.starts_with("#[") {
                let pb = part.as_bytes();
                let end = close_of(pb, 1);
                part = part[end + 1..].trim_start();
            }
            if let Some(rest) = part.strip_prefix("pub") {
                let rest = rest.trim_start();
                part = if rest.starts_with('(') {
                    rest[close_of(rest.as_bytes(), 0) + 1..].trim_start()
                } else {
                    rest
                };
            }
            let Some(colon) = part.find(':') else {
                continue;
            };
            let fname = part[..colon].trim();
            if fname.is_empty() || !fname.bytes().all(is_ident) || part[colon..].starts_with("::") {
                continue;
            }
            fields.push((fname.to_string(), flat_type(&part[colon + 1..])));
        }
        out.insert(name, fields);
    }
    out
}

/// Every struct in `structs` with a field typed as a `Viewer`: a value that
/// carries a viewer into a fn.
pub fn viewer_carriers(structs: &Structs) -> Vec<String> {
    structs
        .iter()
        .filter(|(_, fields)| fields.iter().any(|(_, ty)| is_viewer_type(ty)))
        .map(|(n, _)| n.clone())
        .collect()
}

/// `let <Path> { f, g: alias, mut h, .. } = <rhs>;` struct-pattern bindings in
/// `[a, b)`, as `(struct name, field, bound name)`.
fn struct_lets(code: &str, a: usize, b: usize) -> Vec<(String, String, String)> {
    let s = code.as_bytes();
    let mut out = Vec::new();
    for at in words(code, "let", a, b) {
        let start = skip_ws(s, at + 3);
        let mut j = start;
        while j < b && (is_ident(s[j]) || s[j] == b':') {
            j += 1;
        }
        let path = &code[start..j];
        let name = path.rsplit("::").next().unwrap_or(path);
        if !name.as_bytes().first().is_some_and(u8::is_ascii_uppercase) {
            continue;
        }
        // Generic arguments on the pattern's path (`Ctx::<'_> { .. }`).
        if j < b && s[j] == b'<' {
            j = close_of(s, j) + 1;
        }
        j = skip_ws(s, j);
        if j >= b || s[j] != b'{' {
            continue;
        }
        let close = close_of(s, j);
        for part in split_top(&s[j + 1..close]) {
            let part = std::str::from_utf8(part).expect("ASCII pattern").trim();
            if part.is_empty() || part == ".." {
                continue;
            }
            let (field, bound) = match part.split_once(':') {
                Some((f, alias)) => (f.trim(), alias.trim()),
                None => (part, part),
            };
            let field = field
                .trim_start_matches("ref ")
                .trim_start_matches("mut ")
                .trim();
            let bound = bound
                .trim_start_matches("ref ")
                .trim_start_matches("mut ")
                .trim();
            if field.bytes().all(is_ident) && !bound.is_empty() && bound.bytes().all(is_ident) {
                out.push((name.to_string(), field.to_string(), bound.to_string()));
            }
        }
    }
    out
}

/// One `fn` item with a body: its name, its typed parameters, its
/// executor-bounded generics and its body span.
pub struct FnHeader {
    pub name: String,
    /// `(name, flattened type)` of each typed parameter.
    pub params: Vec<(String, String)>,
    exec: Vec<String>,
    pub body: (usize, usize),
}

/// Every `fn` with a body in `code`, outside the [`excluded_spans`].
pub fn fn_headers(code: &str, sql: &str) -> Vec<FnHeader> {
    let s = code.as_bytes();
    let excluded = excluded_spans(code, sql);
    let mut out = Vec::new();
    for at in words(code, "fn", 0, s.len()) {
        if excluded.iter().any(|&(a, b)| a <= at && at <= b) {
            continue;
        }
        let mut j = skip_ws(s, at + 2);
        let name = ident_at(s, j).to_string();
        if name.is_empty() {
            continue;
        }
        j = skip_ws(s, j + name.len());
        let mut generics = "";
        if j < s.len() && s[j] == b'<' {
            let g_end = close_of(s, j);
            generics = &code[j..=g_end];
            j = skip_ws(s, g_end + 1);
        }
        if j >= s.len() || s[j] != b'(' {
            continue;
        }
        let params_end = close_of(s, j);
        let params = &code[j..=params_end];
        let (Some(brace), semi) = (find(s, b"{", params_end), find(s, b";", params_end)) else {
            continue;
        };
        if semi.is_some_and(|semi| semi < brace) {
            continue;
        }
        let sig_tail = &code[params_end + 1..brace];
        let where_clause = sig_tail
            .find("where")
            .map_or("", |w| &sig_tail[w + "where".len()..]);
        out.push(FnHeader {
            name,
            params: typed_params(params),
            exec: executor_generics(generics, where_clause),
            body: (brace, close_of(s, brace)),
        });
    }
    out
}

/// Every viewer-holding `fn` in `code`. `structs` are the struct definitions
/// in scope (see [`struct_fields`]); a struct-pattern `let` of one binds each
/// named field by its declared type.
pub fn holders(code: &str, sql: &str, surface: &Surface, structs: &Structs) -> Vec<Holder> {
    let mut out = Vec::new();
    for FnHeader {
        name,
        params,
        exec,
        body,
    } in fn_headers(code, sql)
    {
        // Parameters, then the fields a struct-pattern `let` binds, each
        // classified by its declared type.
        let mut typed: Vec<(String, Kind)> = params
            .into_iter()
            .map(|(n, ty)| {
                let k = classify(&ty, surface, &exec);
                (n, k)
            })
            .collect();
        for (st, field, bound) in struct_lets(code, body.0, body.1) {
            let Some(fields) = structs.get(&st) else {
                continue;
            };
            if let Some((_, ty)) = fields.iter().find(|(f, _)| *f == field) {
                typed.push((bound, classify(ty, surface, &exec)));
            }
        }
        let of = |k: Kind| -> Vec<String> {
            typed
                .iter()
                .filter(|(_, kind)| *kind == k)
                .map(|(n, _)| n.clone())
                .collect()
        };

        let mut viewers = of(Kind::Viewer);
        for (v, _, at, ra, rb) in lets(code, body.0, body.1) {
            let rhs = &code[ra..rb];
            let flat: String = rhs.chars().filter(|c| !c.is_whitespace()).collect();
            let fallback = viewers.iter().any(|old| {
                flat.ends_with(&format!("unwrap_or({old})"))
                    || flat.ends_with(&format!("unwrap_or(&{old})"))
            });
            let ctor = surface.viewer_ctors.iter().any(|c| flat.contains(c));
            if (fallback || ctor) && !viewers.contains(&v) {
                // Only a binding at the fn's own level or in a block it owns;
                // a nested fn's bindings are measured with it.
                let _ = at;
                viewers.push(v);
            }
        }
        if viewers.is_empty() {
            continue;
        }
        out.push(Holder {
            name,
            viewers,
            body,
            pools: of(Kind::Pool),
            conns: of(Kind::Conn),
            states: of(Kind::State),
        });
    }
    out
}

type Lets = Vec<(String, bool, usize, usize, usize)>;

/// `let [mut] <name> [: T] = <rhs>;` bindings in `[a, b)`, as
/// `(name, is_mut, let_offset, rhs_start, rhs_end)`, plus the refutable
/// `if let` / `while let` form [`if_let_binding`] reads.
fn lets(code: &str, a: usize, b: usize) -> Lets {
    let s = code.as_bytes();
    let mut out = Vec::new();
    for at in words(code, "let", a, b) {
        if let Some(binding) = if_let_binding(code, at, b) {
            out.push(binding);
            continue;
        }
        let mut j = skip_ws(s, at + 3);
        // A tuple pattern, `let (mut tx, actor, _) = <rhs>`: each element is a
        // binding of the whole right-hand side (a connection opener returns
        // its connection in such a tuple).
        let mut names: Vec<(String, bool)> = Vec::new();
        if s.get(j) == Some(&b'(') {
            let close = close_of(s, j);
            for part in split_top(&s[j + 1..close]) {
                let part = std::str::from_utf8(part).expect("ASCII pattern").trim();
                let (m, n) = match part.strip_prefix("mut ") {
                    Some(rest) => (true, rest.trim()),
                    None => (false, part),
                };
                if !n.is_empty() && n != "_" && n.bytes().all(is_ident) {
                    names.push((n.to_string(), m));
                }
            }
            j = skip_ws(s, close + 1);
        } else {
            let mut is_mut = false;
            if s[j..].starts_with(b"mut") && !is_ident(s[j + 3]) {
                is_mut = true;
                j = skip_ws(s, j + 3);
            }
            let name = ident_at(s, j).to_string();
            if name.is_empty() {
                continue;
            }
            j = skip_ws(s, j + name.len());
            names.push((name, is_mut));
        }
        if j < b && s[j] == b':' {
            let mut depth = 0i32;
            while j < b {
                match s[j] {
                    b'(' | b'<' | b'[' => depth += 1,
                    b')' | b'>' | b']' => depth -= 1,
                    b'=' if depth <= 0 && s[j + 1] != b'>' => break,
                    b';' => break,
                    _ => {}
                }
                j += 1;
            }
        }
        if j >= b || s[j] != b'=' || matches!(s[j + 1], b'=' | b'>') {
            continue;
        }
        let rhs_start = j + 1;
        let (mut depth, mut k) = (0i32, rhs_start);
        while k < b {
            match s[k] {
                b'(' | b'[' | b'{' => depth += 1,
                b')' | b']' | b'}' => {
                    depth -= 1;
                    if depth < 0 {
                        break;
                    }
                }
                b';' if depth == 0 => break,
                _ => {}
            }
            k += 1;
        }
        for (name, is_mut) in names {
            out.push((name, is_mut, at, rhs_start, k));
        }
    }
    out
}

/// The `let` at `at` as `if let <Ctor>([mut] <name>) = <rhs> {` (or `while
/// let`), `<Ctor>` one of `Ok` / `Some` / `Err`. The right-hand side is the
/// scrutinee, which ends at the `{` that opens the body at bracket depth 0.
fn if_let_binding(code: &str, at: usize, b: usize) -> Option<(String, bool, usize, usize, usize)> {
    let s = code.as_bytes();
    let mut k = at;
    while k > 0 && s[k - 1].is_ascii_whitespace() {
        k -= 1;
    }
    let mut w = k;
    while w > 0 && is_ident(s[w - 1]) {
        w -= 1;
    }
    if !matches!(&code[w..k], "if" | "while") {
        return None;
    }
    let mut j = skip_ws(s, at + 3);
    let ctor = ident_at(s, j);
    if !matches!(ctor, "Ok" | "Some" | "Err") {
        return None;
    }
    j = skip_ws(s, j + ctor.len());
    if j >= b || s[j] != b'(' {
        return None;
    }
    j = skip_ws(s, j + 1);
    let mut is_mut = false;
    if s[j..].starts_with(b"mut") && !is_ident(s[j + 3]) {
        is_mut = true;
        j = skip_ws(s, j + 3);
    }
    let name = ident_at(s, j).to_string();
    if name.is_empty() {
        return None;
    }
    j = skip_ws(s, j + name.len());
    if j >= b || s[j] != b')' {
        return None;
    }
    j = skip_ws(s, j + 1);
    if j >= b || s[j] != b'=' || matches!(s[j + 1], b'=' | b'>') {
        return None;
    }
    let rhs_start = j + 1;
    let (mut depth, mut k) = (0i32, rhs_start);
    while k < b {
        match s[k] {
            b'{' if depth == 0 => break,
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => {
                depth -= 1;
                if depth < 0 {
                    break;
                }
            }
            _ => {}
        }
        k += 1;
    }
    Some((name, is_mut, at, rhs_start, k))
}

/// Does `flat` (whitespace removed) call a fn whose name starts with `begin`
/// (`begin_author_stamped_tx(`, `begin_ingest_tx(`, `begin_claim_act(`)? Every
/// such helper in both layers opens a transaction and returns it.
fn calls_a_begin(flat: &str) -> bool {
    let s = flat.as_bytes();
    words_prefix(flat, "begin").into_iter().any(|p| {
        let mut j = p;
        while j < s.len() && is_ident(s[j]) {
            j += 1;
        }
        s.get(j) == Some(&b'(')
    })
}

/// Offsets where an identifier STARTING with `prefix` begins.
fn words_prefix(code: &str, prefix: &str) -> Vec<usize> {
    let s = code.as_bytes();
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(p) = find(s, prefix.as_bytes(), from) {
        if p == 0 || !is_ident(s[p - 1]) {
            out.push(p);
        }
        from = p + 1;
    }
    out
}

/// Calls whose `let mut` binding is a connection, in every layer.
pub const CONNECTION_CTORS: &[&str] = &[
    "read_as(",
    "write_as(",
    "begin_claim_write(",
    "begin_as(",
    "acquire_as(",
    "maintenance(",
    "Connection::begin(",
    ".begin()",
    ".acquire()",
];
const TERMINALS: &[&str] = &[
    "fetch_one",
    "fetch_all",
    "fetch_optional",
    "fetch",
    "fetch_many",
    "execute",
];
const KEYWORDS: &[&str] = &[
    "if", "match", "while", "for", "return", "in", "loop", "move", "async", "await", "let", "else",
];

/// Methods of a pool handle that run nothing (an `Option` combinator, a
/// clone, a projection to the inner pool): the handle passes through them to
/// whatever call encloses the expression, which is measured instead.
const NON_DB_METHODS: &[&str] = &[
    "clone",
    "as_ref",
    "inner",
    "ok_or",
    "ok_or_else",
    "unwrap",
    "expect",
    "map",
    "is_some",
    "is_none",
];

/// Calls that run no statement of their own and so are not registered:
/// opening a transaction or a connection (every statement then run on it is
/// measured where it runs), and `drop`, which rolls a transaction back.
const NOT_A_STATEMENT: &[&str] = &["begin", "acquire", "drop"];

fn has_word(hay: &str, word: &str) -> bool {
    !words(hay, word, 0, hay.len()).is_empty()
}

/// `Viewer` methods that hand on the WHOLE viewer: a copy of it, or its
/// predicate rendered or spliced into the statement. Unlike the route lint's
/// list, `group_bind` and `writable_bind` are absent: a bind proves a
/// parameter was supplied, not that the SQL reads it.
pub const HANDOFF_METHODS: &[&str] = &[
    "clone",
    "detach_scoped",
    "splice",
    "splice_write",
    "render_predicate",
    "render_edge_predicate",
    "render_writable_predicate",
];

/// Does `region` (code view) hand on one of `viewers` as a whole value: the
/// bare identifier, or one of [`HANDOFF_METHODS`] on it?
fn hands_on_viewer(region: &str, viewers: &[String]) -> bool {
    let s = region.as_bytes();
    viewers.iter().any(|v| {
        words(region, v, 0, s.len()).into_iter().any(|p| {
            // A field of something else (`params.viewer`) is not this viewer.
            let mut b = p;
            while b > 0 && s[b - 1].is_ascii_whitespace() {
                b -= 1;
            }
            if b > 0 && s[b - 1] == b'.' {
                return false;
            }
            let q = skip_ws(s, p + v.len());
            if s.get(q) != Some(&b'.') {
                return true;
            }
            let m_at = skip_ws(s, q + 1);
            HANDOFF_METHODS.contains(&ident_at(s, m_at))
        })
    })
}

/// The SQL-text spend marker, matched only where it filters rows.
pub const PREDICATE_MARKER: &str = "visibility = 'public'";

/// Does `live_sql` (a statement's text with its comments removed, as each
/// lint's `spend_views` returns it) carry [`PREDICATE_MARKER`] as a FILTER: in
/// predicate position, right after `AND`, `OR`, `WHERE` or `ON` (skipping an
/// opening parenthesis, line breaks and the column's table alias, `c.` or a
/// `{mf}.` placeholder)?
///
/// The per-call check reads this instead of the fn-level `spends_viewer`,
/// which counts the marker anywhere in the text. In one call's statement the
/// marker can sit in a projection (`SELECT c.content, c.visibility = 'public'
/// FROM claims c WHERE c.id = $1`), an `ORDER BY` or a `CASE WHEN`, none of
/// which hides a row, and a column named `profile_visibility` is not the
/// marker at all.
pub fn predicate_spend(live_sql: &str) -> bool {
    // `\n`, `\t`, `\r` escapes and line-continuation backslashes are line
    // breaks in the statement; read them as whitespace.
    let mut t = live_sql.as_bytes().to_vec();
    let mut i = 0;
    while i < t.len() {
        if t[i] == b'\\' {
            t[i] = b' ';
            if i + 1 < t.len() && matches!(t[i + 1], b'n' | b't' | b'r') {
                t[i + 1] = b' ';
            }
            i += 1;
        }
        i += 1;
    }
    let mut from = 0;
    while let Some(p) = find(&t, PREDICATE_MARKER.as_bytes(), from) {
        from = p + 1;
        if p > 0 && is_ident(t[p - 1]) {
            // `profile_visibility = 'public'`: another column.
            continue;
        }
        let mut k = p;
        // The table alias: `c.`, `c2.`, `{mf}.`.
        if k > 0 && t[k - 1] == b'.' {
            k -= 1;
            while k > 0 && (is_ident(t[k - 1]) || t[k - 1] == b'{' || t[k - 1] == b'}') {
                k -= 1;
            }
        }
        while k > 0 && (t[k - 1].is_ascii_whitespace() || t[k - 1] == b'(') {
            k -= 1;
        }
        let end = k;
        while k > 0 && is_ident(t[k - 1]) {
            k -= 1;
        }
        let word = std::str::from_utf8(&t[k..end]).expect("ASCII keyword");
        if ["AND", "OR", "WHERE", "ON"]
            .iter()
            .any(|kw| word.eq_ignore_ascii_case(kw))
        {
            return true;
        }
    }
    false
}

/// The path written immediately before the `(` at `open` (a `!` of a macro
/// kept), and where it starts.
fn callee_before(s: &[u8], open: usize) -> (String, usize) {
    let mut j = open as isize - 1;
    while j >= 0 && s[j as usize].is_ascii_whitespace() {
        j -= 1;
    }
    // A turbofish `::<..>` between the path and the call.
    if j >= 0 && s[j as usize] == b'>' {
        let mut depth = 0;
        while j >= 0 {
            match s[j as usize] {
                b'>' => depth += 1,
                b'<' => {
                    depth -= 1;
                    if depth == 0 {
                        j -= 1;
                        break;
                    }
                }
                _ => {}
            }
            j -= 1;
        }
        if j >= 1 && &s[(j - 1) as usize..=j as usize] == b"::" {
            j -= 2;
        }
    }
    let end = (j + 1) as usize;
    if j >= 0 && s[j as usize] == b'!' {
        j -= 1;
    }
    while j >= 0 && (is_ident(s[j as usize]) || s[j as usize] == b':') {
        j -= 1;
    }
    let start = (j + 1) as usize;
    (
        std::str::from_utf8(&s[start..end])
            .expect("ASCII path")
            .to_string(),
        start,
    )
}

/// The innermost function or method call whose argument list contains `p`,
/// skipping tuple-struct constructors (`Some(..)`), keywords, bare tuples and
/// non-SQL macros. `None` when `p` sits in a block or a struct literal first.
fn enclosing_call(s: &[u8], p: usize, lo: usize) -> Option<(String, usize)> {
    let mut i = p;
    let mut depth = 0usize;
    while i > lo {
        i -= 1;
        match s[i] {
            b')' | b']' | b'}' => depth += 1,
            b'(' | b'[' | b'{' => {
                if depth > 0 {
                    depth -= 1;
                    continue;
                }
                if s[i] != b'(' {
                    return None;
                }
                let (callee, _) = callee_before(s, i);
                let last = callee.rsplit("::").next().unwrap_or("");
                let constructor = !callee.contains("::")
                    && callee
                        .as_bytes()
                        .first()
                        .is_some_and(u8::is_ascii_uppercase);
                // A formatting or logging macro names a handle; it runs nothing.
                let non_sql_macro = callee.ends_with('!') && !callee.starts_with("sqlx::");
                if callee.is_empty() || KEYWORDS.contains(&last) || constructor || non_sql_macro {
                    continue;
                }
                return Some((callee, i));
            }
            _ => {}
        }
    }
    None
}

/// The first word of the first string literal in `[a, b)` of the `sql` view.
fn first_literal_word(sql: &str, a: usize, b: usize) -> Option<String> {
    let q = sql.as_bytes();
    let quote = find(q, b"\"", a).filter(|&x| x < b)?;
    let start = skip_ws(q, quote + 1);
    let word: String = q[start..]
        .iter()
        .take_while(|c| c.is_ascii_alphabetic())
        .map(|&c| c as char)
        .collect();
    (!word.is_empty()).then(|| word.to_ascii_uppercase())
}

/// The RHS span of the last `let <name>` before `before`.
fn resolve_let(lets: &Lets, name: &str, before: usize) -> Option<(usize, usize)> {
    lets.iter()
        .filter(|(n, _, at, _, _)| n == name && *at < before)
        .map(|&(_, _, _, a, b)| (a, b))
        .next_back()
}

/// Is `[a, z)` one expression: no `;` outside brackets, never closing more
/// than it opened?
fn same_expression(s: &[u8], a: usize, z: usize) -> bool {
    let mut depth = 0i32;
    for &c in &s[a..z] {
        match c {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => {
                depth -= 1;
                if depth < 0 {
                    return false;
                }
            }
            b';' if depth == 0 => return false,
            _ => {}
        }
    }
    depth == 0
}

/// Label a `sqlx` chain ending in `terminal` (whose name starts at `term_at`),
/// and return the extra spans (bindings it reads) that count toward its spend.
fn chain_label(
    code: &str,
    sql: &str,
    body_start: usize,
    term_at: usize,
    terminal: &str,
    lets: &Lets,
) -> (String, Vec<(usize, usize)>) {
    let s = code.as_bytes();
    let mut extra = Vec::new();
    let mut head = None;
    if let Some(cand) = code[body_start..term_at]
        .rfind("sqlx")
        .map(|p| body_start + p)
    {
        if !words(code, "sqlx", cand, cand + 1).is_empty() && same_expression(s, cand, term_at) {
            head = Some(cand);
        }
    }
    if head.is_none() {
        // `<receiver>.fetch_one(..)`: resolve the receiver's binding.
        let mut k = term_at - 1;
        while s[k].is_ascii_whitespace() {
            k -= 1;
        }
        if s[k] == b'.' {
            let mut j = k - 1;
            while s[j].is_ascii_whitespace() {
                j -= 1;
            }
            let end = j + 1;
            while is_ident(s[j]) {
                j -= 1;
            }
            let receiver = &code[j + 1..end];
            if let Some((a, b)) = resolve_let(lets, receiver, j) {
                extra.push((a, b));
                if let Some(p) = code[a..b].find("sqlx") {
                    head = Some(a + p);
                }
            }
        }
    }
    let Some(head) = head else {
        return (format!("?.{terminal}"), extra);
    };
    let mut op = skip_ws(s, head + 4);
    op = skip_ws(s, op + 2); // `::`
    let mut fun = ident_at(s, op).to_string();
    op = skip_ws(s, op + fun.len());
    if s[op] == b'!' {
        fun.push('!');
        op = skip_ws(s, op + 1);
    }
    if s[op..].starts_with(b"::") {
        op = skip_ws(s, op + 2);
        if s[op] == b'<' {
            op = skip_ws(s, close_of(s, op) + 1);
        }
    }
    if s[op] != b'(' {
        return (format!("sqlx::{fun}(?).{terminal}"), extra);
    }
    let close = close_of(s, op);
    let mut verb = first_literal_word(sql, op, close);
    if verb.is_none() {
        let arg = code[op + 1..close]
            .split(',')
            .next()
            .unwrap_or("")
            .trim()
            .trim_start_matches('&')
            .trim();
        if !arg.is_empty() && arg.bytes().all(is_ident) {
            if let Some((a, b)) = resolve_let(lets, arg, op) {
                extra.push((a, b));
                verb = first_literal_word(sql, a, b);
            }
        }
    }
    (
        format!(
            "sqlx::{fun}({}).{terminal}",
            verb.as_deref().unwrap_or("dynamic")
        ),
        extra,
    )
}

/// Every database call in `h`'s body as `(label, viewed)`, except calls inside
/// the `nested` spans (the bodies of viewer-holding fns declared inside this
/// one, which are measured on their own).
pub fn db_calls(
    src: &str,
    code: &str,
    sql: &str,
    h: &Holder,
    nested: &[(usize, usize)],
    surface: &Surface,
) -> Vec<(String, bool)> {
    let s = code.as_bytes();
    let (b, e) = h.body;
    let bindings: Lets = lets(code, b, e)
        .into_iter()
        .filter(|(_, _, at, _, _)| !nested.iter().any(|&(x, y)| x <= *at && *at <= y))
        .collect();
    let mut pool_aliases: Vec<String> = h.pools.clone();
    let mut conns: Vec<String> = h.conns.clone();
    let mut repos: Vec<(String, String)> = Vec::new();
    let pool_exprs: Vec<String> = h
        .states
        .iter()
        .flat_map(|st| {
            surface.pool_fields.iter().flat_map(move |f| {
                [
                    format!("&{st}.{f}"),
                    format!("{st}.{f}"),
                    format!("{st}.{f}.clone()"),
                    format!("&{st}.{f}.clone()"),
                ]
            })
        })
        .collect();
    for (name, is_mut, _, ra, rb) in &bindings {
        let rhs = &code[*ra..*rb];
        let flat: String = rhs.chars().filter(|c| !c.is_whitespace()).collect();
        let names_pool = h.states.iter().any(|st| has_word(rhs, st))
            || pool_aliases.iter().any(|a| has_word(rhs, a))
            || conns.iter().any(|c| has_word(rhs, c));
        if pool_exprs.contains(&flat) {
            pool_aliases.push(name.clone());
            continue;
        }
        if let Some(new_at) = flat.find("::new(") {
            let path = &flat[..new_at];
            if !path.is_empty() && path.bytes().all(|c| is_ident(c) || c == b':') && names_pool {
                let ty = path.rsplit("::").next().unwrap_or(path).to_string();
                repos.push((name.clone(), ty));
                continue;
            }
        }
        // A connection: opened by a constructor, or a reborrow of one
        // (`&mut *tx`, `&mut tx`, `tx`). A `let mut` whose right-hand side
        // merely RUNS a statement on a connection (`let mut rows =
        // q.fetch_all(&mut *tx)`) binds its result, not a connection.
        let surface_ctor = surface.conn_ctors.iter().any(|c| flat.contains(c));
        let ctor = surface_ctor
            || CONNECTION_CTORS.iter().any(|c| flat.contains(c))
            || calls_a_begin(&flat);
        let reborrow = {
            let r = flat.trim_start_matches("&mut").trim_start_matches('*');
            r.starts_with('*')
                || conns.iter().any(|c| r == c)
                || pool_aliases.iter().any(|a| r == a)
        };
        if (*is_mut || surface_ctor) && (ctor || reborrow) {
            conns.push(name.clone());
        }
    }

    // open-paren offset -> (label, is a plain call whose label needs resolving)
    let mut calls: BTreeMap<usize, (String, bool)> = BTreeMap::new();
    let enclose = |calls: &mut BTreeMap<usize, (String, bool)>, p: usize| {
        if let Some((callee, open)) = enclosing_call(s, p, b) {
            calls.entry(open).or_insert((callee, true));
        }
    };
    // `.<method>(` right after offset `q`: `Some((method, open_paren))`.
    let method_after = |q: usize| -> Option<(String, usize)> {
        let q = skip_ws(s, q);
        if s.get(q) != Some(&b'.') {
            return None;
        }
        let m_at = skip_ws(s, q + 1);
        let m = ident_at(s, m_at).to_string();
        let open = skip_ws(s, m_at + m.len());
        (s.get(open) == Some(&b'(')).then_some((m, open))
    };

    for st in &h.states {
        for p in words(code, st, b, e) {
            let q = skip_ws(s, p + st.len());
            if s.get(q) == Some(&b'.') {
                let f_at = skip_ws(s, q + 1);
                let field = ident_at(s, f_at).to_string();
                let after = skip_ws(s, f_at + field.len());
                if surface.pool_fields.contains(&field.as_str()) {
                    match method_after(after) {
                        Some((m, open)) if !NON_DB_METHODS.contains(&m.as_str()) => {
                            calls.entry(open).or_insert((format!("{field}.{m}"), false));
                        }
                        _ => enclose(&mut calls, p),
                    }
                } else if field == "clone" {
                    // The whole handle, cloned and handed to a helper.
                    enclose(&mut calls, p);
                } else if s.get(after) == Some(&b'(')
                    && surface.state_db_methods.contains(&field.as_str())
                {
                    calls
                        .entry(after)
                        .or_insert((format!("{st}.{field}"), false));
                }
                continue;
            }
            enclose(&mut calls, p);
        }
    }
    for alias in &pool_aliases {
        for p in words(code, alias, b, e) {
            // The binding itself (`let pool = ..` / `let mut pool = ..`).
            if bindings
                .iter()
                .any(|(n, _, at, _, _)| n == alias && *at < p && p < *at + 12)
            {
                continue;
            }
            match method_after(p + alias.len()) {
                Some((m, open)) if !NON_DB_METHODS.contains(&m.as_str()) => {
                    calls.entry(open).or_insert((format!("pool.{m}"), false));
                }
                _ => enclose(&mut calls, p),
            }
        }
    }
    for p in words(code, "mut", b, e) {
        let mut k = p - 1;
        while k > b && s[k].is_ascii_whitespace() {
            k -= 1;
        }
        if s[k] != b'&' {
            continue;
        }
        let q = skip_ws(s, p + 3);
        if s[q] == b'*' || conns.iter().any(|c| c == ident_at(s, q)) {
            enclose(&mut calls, p);
        }
    }
    for (alias, ty) in &repos {
        for p in words(code, alias, b, e) {
            if let Some((m, open)) = method_after(p + alias.len()) {
                calls.entry(open).or_insert((format!("{ty}::{m}"), false));
            }
        }
    }
    // A connection or executor handed on as it is (`Repo::get(conn, id)`,
    // `.fetch_one(executor)`).
    for conn in &conns {
        for p in words(code, conn, b, e) {
            let mut k = p;
            while k > b && s[k - 1].is_ascii_whitespace() {
                k -= 1;
            }
            // `x.conn` is a field, not this binding.
            if k > b && s[k - 1] == b'.' {
                continue;
            }
            enclose(&mut calls, p);
        }
    }
    calls.retain(|&open, _| !nested.iter().any(|&(x, y)| x <= open && open <= y));

    let mut out = Vec::new();
    for (&open, (callee, plain)) in &calls {
        let method = callee.rsplit(['.', ':']).next().unwrap_or(callee);
        if NOT_A_STATEMENT.contains(&method) {
            continue;
        }
        let close = close_of(s, open);
        let mut spans = vec![(open, close + 1)];
        let callee_flat = callee.trim_end_matches('!');
        let last = callee_flat.rsplit("::").next().unwrap_or(callee_flat);
        let label = if *plain && TERMINALS.contains(&last) {
            let (_, term_at) = callee_before(s, open);
            let (label, extra) = chain_label(code, sql, b, term_at, last, &bindings);
            let chain_start = code[b..term_at]
                .rfind("sqlx")
                .map(|x| b + x)
                .filter(|&x| same_expression(s, x, term_at))
                .unwrap_or(term_at);
            spans = extra;
            spans.push((chain_start, close + 1));
            label
        } else if *plain {
            let parts: Vec<&str> = callee.split("::").collect();
            parts[parts.len().saturating_sub(2)..].join("::")
        } else {
            callee.clone()
        };
        let code_region: String = spans
            .iter()
            .map(|&(x, y)| &code[x..y])
            .collect::<Vec<_>>()
            .join("\n");
        let raw_region: String = spans
            .iter()
            .map(|&(x, y)| &src[x..y])
            .collect::<Vec<_>>()
            .join("\n");
        let viewed =
            hands_on_viewer(&code_region, &h.viewers) || (surface.marker_spend)(&raw_region);
        out.push((label, viewed));
    }
    out
}

/// `(file, fn) -> sorted unviewed labels`, for every fn with any.
pub type Measured = BTreeMap<(String, String), Vec<String>>;

/// Every viewer-holding fn measured, as `(file, fn)`.
pub type Population = std::collections::BTreeSet<(String, String)>;

/// Measure one source file into `out` and `pop`; returns `(fns, calls)`.
pub fn measure_source(
    file: &str,
    src: &str,
    surface: &Surface,
    out: &mut Measured,
    pop: &mut Population,
) -> (usize, usize) {
    let (code, sql) = views(src);
    let hs = holders(&code, &sql, surface, &struct_fields(&code));
    let mut n_calls = 0;
    for h in &hs {
        pop.insert((file.to_string(), h.name.clone()));
        let nested: Vec<(usize, usize)> = hs
            .iter()
            .map(|o| o.body)
            .filter(|&(x, y)| h.body.0 < x && y < h.body.1)
            .collect();
        let calls = db_calls(src, &code, &sql, h, &nested, surface);
        n_calls += calls.len();
        let mut unviewed: Vec<String> = calls
            .into_iter()
            .filter(|(_, viewed)| !viewed)
            .map(|(l, _)| l)
            .collect();
        if !unviewed.is_empty() {
            let entry = out.entry((file.to_string(), h.name.clone())).or_default();
            entry.append(&mut unviewed);
            entry.sort();
        }
    }
    (hs.len(), n_calls)
}

/// A register `(file, fn, labels)` as a [`Measured`] map, refusing a
/// duplicated key and an entry with no labels.
pub fn register(entries: &[(&str, &str, &[&str])]) -> Measured {
    let mut out = Measured::new();
    for (file, name, labels) in entries {
        assert!(
            !labels.is_empty(),
            "the register lists {file}::{name} with no calls; remove the entry"
        );
        let mut v: Vec<String> = labels.iter().map(|l| (*l).to_string()).collect();
        v.sort();
        let prev = out.insert(((*file).to_string(), (*name).to_string()), v);
        assert!(prev.is_none(), "the register lists {file}::{name} twice");
    }
    out
}

fn multiset_diff(a: &[String], b: &[String]) -> Vec<String> {
    let mut rest = b.to_vec();
    let mut out = Vec::new();
    for x in a {
        if let Some(i) = rest.iter().position(|y| y == x) {
            rest.remove(i);
        } else {
            out.push(x.clone());
        }
    }
    out
}

/// The drift between `measured` and `want`, empty when they agree exactly.
/// Each drifted fn is followed by its measured entry in register syntax, so a
/// reviewed change can be pasted.
pub fn drift(measured: &Measured, want: &Measured) -> String {
    let mut report = String::new();
    let keys: std::collections::BTreeSet<_> = measured.keys().chain(want.keys()).collect();
    for key in keys {
        let got = measured.get(key).cloned().unwrap_or_default();
        let exp = want.get(key).cloned().unwrap_or_default();
        let new = multiset_diff(&got, &exp);
        let gone = multiset_diff(&exp, &got);
        if !new.is_empty() || !gone.is_empty() {
            report.push_str(&format!(
                "  {}::{}\n    NEW (unreviewed, no viewer in its arguments or statement): \
                 {new:?}\n    GONE (lower the register): {gone:?}\n    measured: \
                 (\"{}\", \"{}\", &{got:?}),\n",
                key.0, key.1, key.0, key.1
            ));
        }
    }
    report
}
