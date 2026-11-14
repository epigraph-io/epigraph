//! The pgvector version floor (backlog e30316ae).
//!
//! The HNSW readers in `repos/claim.rs` set `hnsw.iterative_scan`, which
//! pgvector added in 0.8.0. On an older pgvector the `hnsw` GUC prefix is
//! reserved by the loaded extension and the name is unknown, so the
//! `set_config` call fails with SQLSTATE 42602 and every semantic search
//! fails with it. Distribution packages still ship 0.6.
//!
//! Nothing checked the version before this module, so that deployment
//! migrated cleanly, booted cleanly, and failed on its first search. Now
//! `epigraph-migrate` (and the server's migrate-on-boot path) refuse before
//! applying anything, and the server refuses to start, with a message that
//! names the version found and the floor.
//!
//! The comparison is the pure [`check`]; [`read_state`] is the one query, a
//! non-macro `query_as` so the offline `.sqlx/` cache needs no entry.

use std::fmt;

/// The lowest pgvector release the kernel runs on: the one that added
/// `hnsw.iterative_scan`.
pub const PGVECTOR_FLOOR: Version = Version {
    major: 0,
    minor: 8,
    patch: 0,
};

/// A pgvector release number, compared numerically (0.10.0 is above 0.8.0).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl Version {
    /// Parse `major.minor[.patch]`, as `pg_extension.extversion` spells it.
    /// A missing patch is 0. Anything else (a suffix, a fourth component, a
    /// non-number) is `None`: a version this cannot read is not assumed to be
    /// new enough.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        let mut parts = raw.trim().split('.');
        let mut next = |required: bool| match parts.next() {
            Some(p) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => p.parse().ok(),
            None if !required => Some(0),
            _ => None,
        };
        let major = next(true)?;
        let minor = next(true)?;
        let patch = next(false)?;
        if parts.next().is_some() {
            return None;
        }
        Some(Self {
            major,
            minor,
            patch,
        })
    }
}

/// What the database says about pgvector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    /// Installed in this database at this version (`pg_extension.extversion`).
    Installed(String),
    /// Not installed in this database; `CREATE EXTENSION vector` would
    /// install this version (`pg_available_extensions.default_version`).
    NotInstalled { default_version: String },
    /// Not installed, and the server has no pgvector to install.
    Unavailable,
}

/// Who is asking, which decides whether a not-yet-installed extension is a
/// refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Before migrating: migration 001 runs `CREATE EXTENSION`, so an
    /// installable version that meets the floor is fine.
    BeforeMigrating,
    /// A server about to serve: the extension must already be installed.
    Serving,
}

/// Why the database's pgvector cannot run this kernel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// Installed below the floor (or at a version this cannot read).
    InstalledTooOld { found: String, floor: Version },
    /// Not installed, and `CREATE EXTENSION` would install a version below
    /// the floor.
    AvailableTooOld { found: String, floor: Version },
    /// The server has no pgvector at all.
    Unavailable { floor: Version },
    /// Not installed in a database a server is about to serve.
    NotInstalled { floor: Version },
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InstalledTooOld { found, floor } => write!(
                f,
                "REFUSING: pgvector {found} is installed in this database; EpiGraph needs \
                 pgvector >= {floor} (hnsw.iterative_scan), and every semantic search fails \
                 below it (SQLSTATE 42602). Install pgvector >= {floor} on the PostgreSQL \
                 server, then run `ALTER EXTENSION vector UPDATE;` in this database as its \
                 owner or a superuser."
            ),
            Self::AvailableTooOld { found, floor } => write!(
                f,
                "REFUSING: this PostgreSQL server's pgvector is {found} (the version CREATE \
                 EXTENSION would install); EpiGraph needs pgvector >= {floor} \
                 (hnsw.iterative_scan). Install pgvector >= {floor} on the server (the \
                 pgvector/pgvector:pg16 image ships a current one), then migrate again. \
                 Nothing was applied."
            ),
            Self::Unavailable { floor } => write!(
                f,
                "REFUSING: this PostgreSQL server has no pgvector extension; EpiGraph needs \
                 pgvector >= {floor}. Install it (https://github.com/pgvector/pgvector#installation) \
                 and migrate again. Nothing was applied."
            ),
            Self::NotInstalled { floor } => write!(
                f,
                "REFUSING: the pgvector extension is not installed in this database; EpiGraph \
                 needs pgvector >= {floor}. Run `epigraph-migrate` against it first (migration \
                 001 creates the extension)."
            ),
        }
    }
}

impl std::error::Error for Refusal {}

fn meets(raw: &str, floor: Version) -> bool {
    Version::parse(raw).is_some_and(|v| v >= floor)
}

/// The verdict on `state` for `phase` against `floor` (production passes
/// [`PGVECTOR_FLOOR`]).
pub fn check(state: &State, phase: Phase, floor: Version) -> Result<(), Refusal> {
    match state {
        State::Installed(v) if meets(v, floor) => Ok(()),
        State::Installed(v) => Err(Refusal::InstalledTooOld {
            found: v.clone(),
            floor,
        }),
        State::NotInstalled { .. } if phase == Phase::Serving => {
            Err(Refusal::NotInstalled { floor })
        }
        State::NotInstalled { default_version } if meets(default_version, floor) => Ok(()),
        State::NotInstalled { default_version } => Err(Refusal::AvailableTooOld {
            found: default_version.clone(),
            floor,
        }),
        State::Unavailable if phase == Phase::Serving => Err(Refusal::NotInstalled { floor }),
        State::Unavailable => Err(Refusal::Unavailable { floor }),
    }
}

/// Read pgvector's state in the connected database. `pg_extension` and
/// `pg_available_extensions` are readable by every role.
pub async fn read_state<'e, E>(executor: E) -> Result<State, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    let (installed, default_version): (Option<String>, Option<String>) = sqlx::query_as(
        "SELECT (SELECT extversion FROM pg_extension WHERE extname = 'vector'), \
                (SELECT default_version FROM pg_available_extensions WHERE name = 'vector')",
    )
    .fetch_one(executor)
    .await?;
    Ok(match (installed, default_version) {
        (Some(v), _) => State::Installed(v),
        (None, Some(default_version)) => State::NotInstalled { default_version },
        (None, None) => State::Unavailable,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(major: u32, minor: u32, patch: u32) -> Version {
        Version {
            major,
            minor,
            patch,
        }
    }

    #[test]
    fn versions_parse_and_compare_numerically() {
        assert_eq!(Version::parse("0.8.0"), Some(v(0, 8, 0)));
        assert_eq!(Version::parse(" 0.8.7 "), Some(v(0, 8, 7)));
        assert_eq!(Version::parse("0.7"), Some(v(0, 7, 0)));
        assert_eq!(Version::parse("1.0.0"), Some(v(1, 0, 0)));
        // Numeric, not lexical: "0.10.0" < "0.8.0" as strings.
        assert!(Version::parse("0.10.0").unwrap() > PGVECTOR_FLOOR);
        assert!(Version::parse("0.7.4").unwrap() < PGVECTOR_FLOOR);
        assert!(Version::parse("0.6.0").unwrap() < PGVECTOR_FLOOR);
        for unreadable in ["", "0", "0.8.0-dev", "0.8.0.1", "v0.8.0", "0..8", "0.8.x"] {
            assert_eq!(Version::parse(unreadable), None, "{unreadable:?}");
        }
    }

    #[test]
    fn an_installed_extension_is_checked_against_the_floor() {
        for ok in ["0.8.0", "0.8.7", "0.10.0", "1.0.0"] {
            for phase in [Phase::BeforeMigrating, Phase::Serving] {
                check(&State::Installed(ok.into()), phase, PGVECTOR_FLOOR)
                    .unwrap_or_else(|e| panic!("{ok} must pass: {e}"));
            }
        }
        for old in ["0.6.0", "0.7.4", "0.5", "0.8.0-dev"] {
            let err = check(
                &State::Installed(old.into()),
                Phase::Serving,
                PGVECTOR_FLOOR,
            )
            .expect_err(old);
            let msg = err.to_string();
            assert!(msg.contains(old), "the refusal must name {old}: {msg}");
            assert!(
                msg.contains(">= 0.8.0"),
                "the refusal must name the floor: {msg}"
            );
            assert!(
                msg.contains("ALTER EXTENSION vector UPDATE"),
                "an installed extension is updated in place: {msg}"
            );
        }
    }

    #[test]
    fn before_migrating_the_installable_version_is_what_counts() {
        let fresh_ok = State::NotInstalled {
            default_version: "0.8.7".into(),
        };
        check(&fresh_ok, Phase::BeforeMigrating, PGVECTOR_FLOOR).expect("installable 0.8.7");
        let fresh_old = State::NotInstalled {
            default_version: "0.6.0".into(),
        };
        let err = check(&fresh_old, Phase::BeforeMigrating, PGVECTOR_FLOOR).expect_err("0.6.0");
        assert!(matches!(err, Refusal::AvailableTooOld { .. }), "{err:?}");
        assert!(err.to_string().contains("0.6.0"));
        let none = check(&State::Unavailable, Phase::BeforeMigrating, PGVECTOR_FLOOR)
            .expect_err("no pgvector");
        assert!(matches!(none, Refusal::Unavailable { .. }), "{none:?}");
    }

    #[test]
    fn a_server_refuses_a_database_without_the_extension() {
        for state in [
            State::NotInstalled {
                default_version: "0.8.7".into(),
            },
            State::Unavailable,
        ] {
            let err = check(&state, Phase::Serving, PGVECTOR_FLOOR).expect_err("not installed");
            assert!(matches!(err, Refusal::NotInstalled { .. }), "{err:?}");
            assert!(err.to_string().contains("epigraph-migrate"));
        }
    }
}
