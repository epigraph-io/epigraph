//! The bug-report intake (migration 207).
//!
//! Three calls, each one definer:
//!
//! * [`BugReportRepository::submit_conn`] files a report through
//!   `epigraph_submit_bug_report`, as the session principal, into the intake
//!   group the instance configured (`bug_report_intake_settings`). The caller
//!   need not be a member of that group and learns nothing about its contents:
//!   the answer is a [`BugReportReceipt`] and nothing else.
//! * [`BugReportRepository::list_mine_conn`] reads the caller's own intake
//!   reports through `epigraph_my_bug_reports`.
//! * [`BugReportRepository::preflight_conn`] asks
//!   `epigraph_bug_report_preflight` whether the write would refuse the
//!   caller (not configured, system agent, unbound, a role's agent its
//!   holder does not cover, over its limit) before the server spends an
//!   embedding call on the report.
//!
//! Both run on the caller's STAMPED connection (`ScopedPool::begin_as`): the
//! definers read the principal from the session, never from an argument. The
//! intake group is not an argument either; it is read from the settings row
//! inside the definer.
//!
//! Every refusal the definers raise carries a `BUGnn:` code and is returned
//! as [`DbError::Refused`] with the database's message, so every surface
//! answers it as the caller's error rather than a server fault.

use crate::errors::{DbError, RefusalKind};
use chrono::{DateTime, Utc};
use epigraph_crypto::ContentHasher;
use uuid::Uuid;

/// The longest title the intake accepts, in characters.
pub const MAX_TITLE_CHARS: usize = 200;
/// The longest description (and repro) the intake accepts, in bytes.
pub const MAX_DESCRIPTION_BYTES: usize = 20_480;
/// The longest evidence text the intake accepts, in bytes.
pub const MAX_EVIDENCE_BYTES: usize = 51_200;
/// The severities the intake accepts.
pub const SEVERITIES: &[&str] = &["blocker", "major", "minor"];

/// The characters a reader cannot see, as inclusive code-point ranges: the
/// Unicode White_Space characters, every Cc control (U+0000 cannot reach the
/// database) and every Cf format character, of Unicode 15.0; and the
/// characters that render as nothing although Unicode classes them as
/// letters, marks or symbols: the Hangul fillers (U+115F, U+1160, U+3164,
/// U+FFA0), U+2800 BRAILLE PATTERN BLANK, the combining grapheme joiner
/// U+034F, the Khmer inherent vowels U+17B4-U+17B5, the Mongolian free
/// variation selectors U+180B-U+180D and U+180F, and the variation selectors
/// U+FE00-U+FE0F and U+E0100-U+E01EF. Adjacent ranges merged. A title or
/// description made only of these is blank (BUG04).
/// Migration 207's `c_invisible` bracket is the same list; the definer is the
/// authority, and this copy lets the server refuse before the embedding call.
pub const INVISIBLE: &[(u32, u32)] = &[
    (0x0001, 0x0020),
    (0x007F, 0x00A0),
    (0x00AD, 0x00AD),
    (0x034F, 0x034F),
    (0x0600, 0x0605),
    (0x061C, 0x061C),
    (0x06DD, 0x06DD),
    (0x070F, 0x070F),
    (0x0890, 0x0891),
    (0x08E2, 0x08E2),
    (0x115F, 0x1160),
    (0x1680, 0x1680),
    (0x17B4, 0x17B5),
    (0x180B, 0x180F),
    (0x2000, 0x200F),
    (0x2028, 0x202F),
    (0x205F, 0x2064),
    (0x2066, 0x206F),
    (0x2800, 0x2800),
    (0x3000, 0x3000),
    (0x3164, 0x3164),
    (0xFE00, 0xFE0F),
    (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0),
    (0xFFF9, 0xFFFB),
    (0x110BD, 0x110BD),
    (0x110CD, 0x110CD),
    (0x13430, 0x1343F),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0001, 0xE0001),
    (0xE0020, 0xE007F),
    (0xE0100, 0xE01EF),
];

/// Whether `s` has nothing visible in it: every character is in
/// [`INVISIBLE`] (or is whitespace by Rust's rule, which is the same
/// White_Space set). The empty string is blank.
#[must_use]
pub fn is_blank(s: &str) -> bool {
    s.chars().all(|c| {
        let cp = u32::from(c);
        c.is_whitespace() || INVISIBLE.iter().any(|&(lo, hi)| (lo..=hi).contains(&cp))
    })
}

/// One report, as the caller gave it.
#[derive(Debug, Clone, Default)]
pub struct BugReportInput {
    pub title: String,
    pub description: String,
    pub severity: Option<String>,
    pub component: Option<String>,
    pub repro: Option<String>,
    pub evidence: Option<String>,
    /// The claim's embedding as pgvector text (`[0.1,...]`, 1536 values), when
    /// the server computed one. Stored by the definer for operations search;
    /// the reporter cannot read the claim, so it cannot read this either.
    pub embedding: Option<String>,
}

/// What a submission answers: the new claim's id and when it was filed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BugReportReceipt {
    pub claim_id: Uuid,
    pub submitted_at: DateTime<Utc>,
}

/// One of the caller's own intake reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BugReportRow {
    pub claim_id: Uuid,
    pub title: Option<String>,
    pub submitted_at: DateTime<Utc>,
    /// The claim's labels NOW: triage's changes included.
    pub labels: Vec<String>,
    pub resolved: bool,
    pub is_current: bool,
}

/// `None` for an absent or whitespace-only optional text, else the text as
/// given. The definer applies the same rule, so the content both compose is
/// the same.
fn present(s: Option<&str>) -> Option<&str> {
    s.filter(|t| !t.trim().is_empty())
}

impl BugReportInput {
    /// The claim content the definer composes from the report, byte for byte:
    /// the title, a blank line, the description, and the repro under a
    /// `Repro:` heading when there is one. The definer refuses (BUG05) any
    /// other content, so the digest computed over this is the stored row's.
    #[must_use]
    pub fn content(&self) -> String {
        let mut s = format!("{}\n\n{}", self.title, self.description);
        if let Some(r) = present(self.repro.as_deref()) {
            s.push_str("\n\nRepro:\n");
            s.push_str(r);
        }
        s
    }

    /// The evidence text the definer stores: the caller's evidence, else its
    /// description.
    #[must_use]
    pub fn evidence_text(&self) -> &str {
        present(self.evidence.as_deref()).unwrap_or(&self.description)
    }
}

/// Classify a definer refusal by its code. `None` for anything that is not a
/// `BUGnn:` refusal.
fn refusal_kind(message: &str) -> Option<RefusalKind> {
    let b = message.as_bytes();
    if b.len() < 6
        || !b.starts_with(b"BUG")
        || !b[3].is_ascii_digit()
        || !b[4].is_ascii_digit()
        || b[5] != b':'
    {
        return None;
    }
    Some(match &message[..5] {
        "BUG04" | "BUG05" => RefusalKind::Input,
        "BUG03" | "BUG08" => RefusalKind::State,
        _ => RefusalKind::Authority,
    })
}

/// A `BUGnn:` refusal as [`DbError::Refused`] carrying the database's message;
/// every other error unchanged.
fn map_refusal(e: sqlx::Error) -> DbError {
    if let sqlx::Error::Database(db) = &e {
        if let Some(kind) = refusal_kind(db.message()) {
            return DbError::Refused {
                kind,
                message: db.message().to_string(),
            };
        }
    }
    DbError::from(e)
}

/// The bug-report intake's two definers.
pub struct BugReportRepository;

impl BugReportRepository {
    /// File `report` as the principal `conn` is stamped with.
    ///
    /// # Errors
    /// [`DbError::Refused`] for every `BUGnn:` refusal (not configured, empty
    /// or oversized input, unbound or system caller, rate limit); the claims
    /// trigger's own refusals (OPL01, OPL02, ROL01) as their named variants;
    /// `DbError::QueryFailed` otherwise.
    pub async fn submit_conn(
        conn: &mut sqlx::PgConnection,
        report: &BugReportInput,
    ) -> Result<BugReportReceipt, DbError> {
        let content = report.content();
        let content_hash = ContentHasher::hash(content.as_bytes());
        let evidence_hash = ContentHasher::hash(report.evidence_text().as_bytes());
        let (claim_id, submitted_at): (Uuid, DateTime<Utc>) = sqlx::query_as(
            "SELECT claim_id, submitted_at FROM public.epigraph_submit_bug_report( \
                 $1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(&report.title)
        .bind(&report.description)
        .bind(report.severity.as_deref())
        .bind(report.component.as_deref())
        .bind(present(report.repro.as_deref()))
        .bind(present(report.evidence.as_deref()))
        .bind(&content)
        .bind(content_hash.as_slice())
        .bind(evidence_hash.as_slice())
        .bind(report.embedding.as_deref())
        .fetch_one(&mut *conn)
        .await
        .map_err(map_refusal)?;
        Ok(BugReportReceipt {
            claim_id,
            submitted_at,
        })
    }

    /// Raise the refusal [`submit_conn`](Self::submit_conn) would raise for
    /// the stamped principal before it reads any report (BUG01-03, BUG06-08
    /// and, on a database armed for operator binding, 166's ROL01, exactly
    /// when the write's claims trigger asks it), or return `Ok(())`. Writes nothing. ADVISORY: the write
    /// repeats every check, so a pass here admits nothing by itself; it lets
    /// the caller skip work (the embedding call) for a report the write
    /// would refuse.
    ///
    /// # Errors
    /// [`DbError::Refused`] for each `BUGnn:` refusal;
    /// [`DbError::RoleHolderRequired`] for ROL01, as the write's trigger
    /// raises it; `DbError::QueryFailed` otherwise.
    pub async fn preflight_conn(conn: &mut sqlx::PgConnection) -> Result<(), DbError> {
        sqlx::query("SELECT public.epigraph_bug_report_preflight()")
            .execute(&mut *conn)
            .await
            .map_err(map_refusal)?;
        Ok(())
    }

    /// The stamped principal's own intake reports, newest first, at most
    /// `limit` (clamped to 1..=200 by the definer).
    ///
    /// # Errors
    /// [`DbError::Refused`] when the session has no principal (BUG01) or the
    /// intake is not configured (BUG03); `DbError::QueryFailed` otherwise.
    pub async fn list_mine_conn(
        conn: &mut sqlx::PgConnection,
        limit: i32,
    ) -> Result<Vec<BugReportRow>, DbError> {
        type Row = (Uuid, Option<String>, DateTime<Utc>, Vec<String>, bool, bool);
        let rows: Vec<Row> = sqlx::query_as(
            "SELECT claim_id, title, submitted_at, labels, resolved, is_current \
               FROM public.epigraph_my_bug_reports($1)",
        )
        .bind(limit)
        .fetch_all(&mut *conn)
        .await
        .map_err(map_refusal)?;
        Ok(rows
            .into_iter()
            .map(
                |(claim_id, title, submitted_at, labels, resolved, is_current)| BugReportRow {
                    claim_id,
                    title,
                    submitted_at,
                    labels,
                    resolved,
                    is_current,
                },
            )
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_is_title_blank_line_description_then_the_repro_heading() {
        let mut r = BugReportInput {
            title: "T".into(),
            description: "D".into(),
            ..Default::default()
        };
        assert_eq!(r.content(), "T\n\nD");
        r.repro = Some("   ".into());
        assert_eq!(r.content(), "T\n\nD", "a blank repro is no repro");
        r.repro = Some("step 1".into());
        assert_eq!(r.content(), "T\n\nD\n\nRepro:\nstep 1");
    }

    #[test]
    fn evidence_falls_back_to_the_description() {
        let mut r = BugReportInput {
            title: "T".into(),
            description: "D".into(),
            ..Default::default()
        };
        assert_eq!(r.evidence_text(), "D");
        r.evidence = Some(" \n".into());
        assert_eq!(r.evidence_text(), "D");
        r.evidence = Some("log".into());
        assert_eq!(r.evidence_text(), "log");
    }

    #[test]
    fn blank_means_nothing_visible() {
        for s in [
            "",
            " \t\n",
            "\u{200B}",
            "\u{2060}\u{FEFF}",
            "\u{1C}",
            "\u{AD}\u{3000}",
            "\u{3164}\u{115F}\u{1160}\u{FFA0}",
            "\u{2800}\u{34F}\u{FE0F}\u{E0100}",
        ] {
            assert!(is_blank(s), "{s:?}");
        }
        for s in [
            "a",
            "a\u{200B}",
            "\u{FEFF}x",
            "\u{2065}",
            "\u{E0080}",
            "\u{2801}",
            "\u{3165}",
            "\u{2764}\u{FE0F}",
        ] {
            assert!(!is_blank(s), "{s:?}");
        }
        // The ranges are ordered, disjoint and not adjacent (merged).
        for w in INVISIBLE.windows(2) {
            assert!(w[0].0 <= w[0].1 && w[0].1 + 1 < w[1].0, "{w:?}");
        }
    }

    #[test]
    fn only_bug_codes_are_refusals() {
        assert_eq!(refusal_kind("BUG04: x"), Some(RefusalKind::Input));
        assert_eq!(refusal_kind("BUG03: x"), Some(RefusalKind::State));
        assert_eq!(refusal_kind("BUG08: x"), Some(RefusalKind::State));
        assert_eq!(refusal_kind("BUG07: x"), Some(RefusalKind::Authority));
        assert_eq!(refusal_kind("OPL01: x"), None);
        assert_eq!(refusal_kind("BUG"), None);
        assert_eq!(refusal_kind("BUGGY: x"), None);
    }
}
