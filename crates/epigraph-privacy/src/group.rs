//! The group-membership role vocabulary.

use serde::{Deserialize, Serialize};

/// A member's role in a group.
///
/// # The vocabulary this must agree with
///
/// `reader`, `writer`, `admin` — the three values
/// `group_memberships_role_check` admits, the column `DEFAULT`, and the route
/// that validates `role` on member addition. `member` and `creator` are
/// **rejected**: neither was ever storable, and a client that sent one used to
/// pass route validation and then raise a check-constraint violation.
///
/// # What this type is, and what it is not, today
///
/// It is the typed spelling of that vocabulary, and the client-side onboarding
/// tool parses `--role` through it so an unstorable role is refused before a
/// wrapped key share is ever produced for it.
///
/// It is **not yet** the single spelling: the server still compares role
/// strings in three places, and converging them means editing files this
/// change does not own. That convergence is recorded as an open obligation
/// rather than done halfway here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupRole {
    /// May read the group's rows.
    Reader,
    /// May read and write the group's rows.
    Writer,
    /// May read, write, and manage membership.
    Admin,
}

impl GroupRole {
    /// The stored spelling.
    #[must_use]
    pub const fn as_db_str(self) -> &'static str {
        match self {
            Self::Reader => "reader",
            Self::Writer => "writer",
            Self::Admin => "admin",
        }
    }

    /// Parse a stored role. Returns `None` for anything the column's CHECK
    /// constraint would reject — including the historical `member` and
    /// `creator` spellings.
    #[must_use]
    pub fn from_db_str(s: &str) -> Option<Self> {
        match s {
            "reader" => Some(Self::Reader),
            "writer" => Some(Self::Writer),
            "admin" => Some(Self::Admin),
            _ => None,
        }
    }

    /// Every role, least-privileged first.
    pub const ALL: [Self; 3] = [Self::Reader, Self::Writer, Self::Admin];

    /// May this role add or remove members?
    #[must_use]
    pub const fn can_manage_members(self) -> bool {
        matches!(self, Self::Admin)
    }

    /// May this role write rows owned by the group?
    #[must_use]
    pub const fn can_write(self) -> bool {
        matches!(self, Self::Writer | Self::Admin)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_role_roundtrip() {
        for role in GroupRole::ALL {
            assert_eq!(GroupRole::from_db_str(role.as_db_str()), Some(role));
        }
    }

    #[test]
    fn test_role_permissions() {
        assert!(!GroupRole::Reader.can_manage_members());
        assert!(!GroupRole::Reader.can_write());
        assert!(!GroupRole::Writer.can_manage_members());
        assert!(GroupRole::Writer.can_write());
        assert!(GroupRole::Admin.can_manage_members());
        assert!(GroupRole::Admin.can_write());
    }

    #[test]
    fn the_two_unstorable_spellings_are_refused() {
        // Both would pass a naive non-empty check and then violate
        // `group_memberships_role_check` at INSERT time.
        assert_eq!(GroupRole::from_db_str("member"), None);
        assert_eq!(GroupRole::from_db_str("creator"), None);
        assert_eq!(GroupRole::from_db_str("Admin"), None);
        assert_eq!(GroupRole::from_db_str(""), None);
    }
}
