//! The registry of database refusal codes: the ONE place a code a migration
//! raises is recognised, and where each is given its answer (backlog
//! d9ff9949, split 2/2 of ad2c7b0e).
//!
//! # One lookup
//!
//! [`lookup`] reads a driver error and returns the [`RefusalCode`] it
//! carries, whichever way it carries it ([`Carrier`]):
//!
//! * a custom SQLSTATE that IS the code (`RVK01`, `OPL02`, `TGP04`, `ELV06`);
//! * a message that opens `CODE: ` (`VIS03: ...`), under whatever SQLSTATE the
//!   raise chose, or under one named SQLSTATE (`RT07` only as `42501`).
//!
//! A custom SQLSTATE is read first. The [`Answer`] says what the code becomes
//! and so what each transport answers; [`Answer::kind`] is its
//! [`RefusalKind`] when it has one. Nothing outside this file matches a code
//! (`tests/refusal_code_matches_ratchet.rs`): a repo converts its definers'
//! refusals with `DbError::from_definer`, `From<sqlx::Error>` asks [`lookup`]
//! for the codes it answers for every caller, and a route that answers a code
//! itself compares [`route_code`] with this file's constant. The one
//! exception is `CX03`, recognised in `epigraph-auth` (which does not depend
//! on this crate) and registered here as well; the ratchet names it.
//!
//! # The HTTP-disclosed lists
//!
//! The refusal codes migration 176 gave to designed database refusals that an
//! API or MCP caller can reach (backlog e2c22c7c, ruling R-25) stay database
//! errors ([`Answer::Disclosed`]).
//!
//! A designed refusal's MESSAGE opens with its code (`GRM05: ...`); its
//! SQLSTATE is the one it had before 176, so callers that branch on the
//! SQLSTATE answer as before. The MCP layer sends any message that opens with
//! a code (`epigraph_mcp::errors::internal_error`). The HTTP layer sends the
//! message only for a code listed here, each reviewed for what its text
//! discloses (`From<DbError> for ApiError`): an older coded refusal whose text
//! nobody reviewed for the HTTP body stays the redacted 500.
//!
//! `tests/caller_refusal_codes_restatement.rs` pins that this list is exactly
//! the set of codes 176 introduces.
//!
//! The supersede architecture's refusal codes (`SR01`..`SR13`, SPEC section
//! 7.2) follow 176's pattern but are not 176's, so they live in a second
//! reviewed list, [`SUPERSEDE_REFUSAL_CODES`], each code added by the
//! migration that first raises it. [`caller_refusal_code`] consults both, and
//! only them: a code [`REGISTRY`] answers otherwise is never disclosed by that
//! HTTP arm.

use crate::errors::{DbError, RefusalKind};

/// SQLSTATE `RVK01`: `epigraph_ensure_personal_group` refused because the agent
/// holds only REVOKED membership rows of its personal group (migration 105).
///
/// A custom class on purpose: `RV` is outside the standard's reserved `0-4` /
/// `A-H` classes and outside every class PostgreSQL itself raises, so no
/// server-side error can be mistaken for this refusal.
pub const PERSONAL_MEMBERSHIP_REVOKED: &str = "RVK01";

/// SQLSTATE `RVK02`: `epigraph_ensure_personal_group` refused because the group
/// under the agent's canonical personal did_key is not the agent's own — not
/// `kind = 'personal'`, or created by another agent (a squat). Migration 105.
/// Same class as [`PERSONAL_MEMBERSHIP_REVOKED`], for the same reason.
pub const PERSONAL_GROUP_NOT_OWNED: &str = "RVK02";

/// SQLSTATE `OPL01`: a claim write named an author that is not bound to a human
/// operator (migration 122). Raised by `epigraph_require_bound_author`, which the
/// `claims_require_tenancy_then_operator_binding` trigger and
/// `ClaimRepository::default_decl_for_author` both call, once the database is
/// armed. Same custom-class reasoning as [`PERSONAL_MEMBERSHIP_REVOKED`].
pub const OPERATOR_LINK_REQUIRED: &str = "OPL01";

/// SQLSTATE `OPL02`: a live-linked agent was named on a row owned by a group its
/// OPERATOR holds no writer/admin membership in, or given a writer/admin row in
/// such a group (migration 122 section 1b). Every agent writes only where its
/// own human writes; admin access is the only thing that crosses groups.
pub const OPERATOR_SCOPE_REFUSED: &str = "OPL02";

/// SQLSTATE `ROL01`: a claim was written or attributed by an agent attached to
/// a role (`role_agents`, migration 166) while no human holds that role, or
/// while the agent's linked human is not the holder. Raised by
/// `epigraph_require_role_holder`, which the claims trigger's operator-binding
/// checks call once the database is armed; the valve does not relieve it.
pub const ROLE_HOLDER_REQUIRED: &str = "ROL01";

/// SQLSTATE `ELV01` (migration 124): the principal of an enrollment may no
/// longer hold a passkey.
pub const ELV01: &str = "ELV01";
/// SQLSTATE `ELV02` (migration 125): the ticket definer refuses the elevation.
pub const ELV02: &str = "ELV02";
/// SQLSTATE `ELV03` (migrations 124, 125, 130): the ceremony's subject is not
/// in a state the step admits (the act confirm answers it as not live).
pub const ELV03: &str = "ELV03";
/// SQLSTATE `ELV04` (migration 124): the enrollment ticket is not live.
pub const ELV04: &str = "ELV04";
/// SQLSTATE `ELV06` (migration 125): the elevation ticket is not live, or its
/// refresh family is already elevated.
pub const ELV06: &str = "ELV06";
/// SQLSTATE `ELV07` (migration 130): an admin act proposed by a request that
/// is not elevated.
pub const ELV07: &str = "ELV07";
/// SQLSTATE `ELV08` (migration 130): the admin act is not live and started.
pub const ELV08: &str = "ELV08";
/// SQLSTATE `CUS04` (migration 123): the custodial act's assignment has ended.
pub const CUS04: &str = "CUS04";

/// `ADM02: ` as `42501` (migrations 111, 112, 237, 252): the token carries
/// `claims:admin`, but its client record grants no live `claims:admin` to the
/// principal. The agent-key routes answer it on the admin audit write.
pub const ADM02: &str = "ADM02";
/// `AK02: ` as `42501` (migrations 161, 162, 163, 239): a `signing` (or
/// `identity-legacy`) agent key is attested state, changed only by the host's
/// identity registration or a maintenance session.
pub const AK02: &str = "AK02";
/// `AK03: ` as `42501` (migration 239): the key's agent is not the stamped
/// principal, and the database does not hold the caller to be an admin.
pub const AK03: &str = "AK03";

/// SQLSTATE `AID06` (migrations 161, 268, 276): the prompt history of an
/// agent is readable only by its operator and by an admin. The prompt-history
/// routes answer it as the not-found every other miss gets.
pub const PROMPT_HISTORY_REFUSED: &str = "AID06";

/// How a refusal carries its code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Carrier {
    /// The message opens with `CODE: `. When `sqlstate` is set, the error's
    /// SQLSTATE must also be that one.
    Prefix { sqlstate: Option<&'static str> },
    /// The SQLSTATE is the code itself (a custom class).
    Sqlstate,
}

/// What a coded refusal becomes, and so what each transport answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    /// `DbError::MembershipRevoked`, for every caller (`From<sqlx::Error>`).
    /// HTTP 403, MCP `INVALID_REQUEST`.
    MembershipRevoked,
    /// `DbError::PersonalGroupNotOwned`, for every caller. HTTP 403, MCP
    /// `INVALID_REQUEST`.
    PersonalGroupNotOwned,
    /// `DbError::OperatorLinkRequired`, for every caller. HTTP 403, MCP
    /// `INVALID_REQUEST`.
    OperatorLinkRequired,
    /// `DbError::OperatorScopeRefused`, for every caller. HTTP 403, MCP
    /// `INVALID_REQUEST`.
    OperatorScopeRefused,
    /// `DbError::RoleHolderRequired`, for every caller. HTTP 403, MCP
    /// `INVALID_REQUEST`.
    RoleHolderRequired,
    /// `DbError::Refused` (state) with the text
    /// `errors::retracted_bba_rewrite_message` builds (only the row id is
    /// read from the database, from DETAIL), for every caller. HTTP 409, MCP
    /// the tool error.
    RetractedBbaRewrite,
    /// `DbError::Refused { kind, message }` with the database's text, made by
    /// the repo that calls the family's definer (`DbError::from_definer`);
    /// any other caller gets the ordinary conversion. HTTP by kind (input
    /// 400, authority 403, state 409), MCP the message as written.
    Refused(RefusalKind),
    /// `DbError::NotFound` for the target the calling repo names, so the
    /// refusal reads as a missing row.
    NotFound,
    /// Stays a database error: the route or tool that calls the definer
    /// answers it itself (compare [`route_code`] with the code's constant).
    /// Anywhere else it is the redacted 500.
    Route,
    /// Stays a database error whose message the HTTP layer sends, answered by
    /// its SQLSTATE ([`CALLER_REFUSAL_CODES`], [`SUPERSEDE_REFUSAL_CODES`];
    /// [`caller_refusal_code`]). MCP sends the coded message.
    Disclosed,
}

impl Answer {
    /// The [`RefusalKind`] the answer is, when it is one: the typed denials
    /// are authority refusals, RT07 a state refusal, a site refusal its own
    /// kind. `None` for a not-found, a route's own answer, or a disclosed
    /// database error (answered by its SQLSTATE).
    #[must_use]
    pub const fn kind(self) -> Option<RefusalKind> {
        match self {
            Self::MembershipRevoked
            | Self::PersonalGroupNotOwned
            | Self::OperatorLinkRequired
            | Self::OperatorScopeRefused
            | Self::RoleHolderRequired => Some(RefusalKind::Authority),
            Self::RetractedBbaRewrite => Some(RefusalKind::State),
            Self::Refused(kind) => Some(kind),
            Self::NotFound | Self::Route | Self::Disclosed => None,
        }
    }
}

/// One registered refusal code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefusalCode {
    /// The code, e.g. `VIS03`.
    pub code: &'static str,
    /// How a raised refusal carries it.
    pub carrier: Carrier,
    /// What it becomes.
    pub answer: Answer,
}

const fn prefix(code: &'static str, answer: Answer) -> RefusalCode {
    RefusalCode {
        code,
        carrier: Carrier::Prefix { sqlstate: None },
        answer,
    }
}

const fn sqlstate(code: &'static str, answer: Answer) -> RefusalCode {
    RefusalCode {
        code,
        carrier: Carrier::Sqlstate,
        answer,
    }
}

const fn in_42501(code: &'static str, answer: Answer) -> RefusalCode {
    RefusalCode {
        code,
        carrier: Carrier::Prefix {
            sqlstate: Some("42501"),
        },
        answer,
    }
}

const AUTHORITY: Answer = Answer::Refused(RefusalKind::Authority);
const INPUT: Answer = Answer::Refused(RefusalKind::Input);
const STATE: Answer = Answer::Refused(RefusalKind::State);

/// Every code with an answer of its own. The two HTTP-disclosed lists below
/// are the rest of the registry ([`Answer::Disclosed`]).
#[rustfmt::skip]
pub const REGISTRY: &[RefusalCode] = &[
    // Migration 105: personal-group provisioning.
    sqlstate(PERSONAL_MEMBERSHIP_REVOKED, Answer::MembershipRevoked),
    sqlstate(PERSONAL_GROUP_NOT_OWNED, Answer::PersonalGroupNotOwned),
    // Migration 122: operator binding.
    sqlstate(OPERATOR_LINK_REQUIRED, Answer::OperatorLinkRequired),
    sqlstate(OPERATOR_SCOPE_REFUSED, Answer::OperatorScopeRefused),
    // Migration 166: a role's agent with no live holder of its own.
    sqlstate(ROLE_HOLDER_REQUIRED, Answer::RoleHolderRequired),
    // Migration 184 (operator ruling R-103), re-raised by 251 and 274: a
    // write to the key of a retracted BBA. Only as 42501.
    RefusalCode {
        code: "RT07",
        carrier: Carrier::Prefix { sqlstate: Some("42501") },
        answer: Answer::RetractedBbaRewrite,
    },
    // Migrations 206 and 209: claim visibility acts. VIS04 and VIS06: a
    // claim (or the default's row) changed under the act; nothing was
    // changed and a retry classifies the new state.
    prefix("VIS01", AUTHORITY), prefix("VIS02", AUTHORITY), prefix("VIS03", INPUT),
    prefix("VIS04", STATE), prefix("VIS05", AUTHORITY), prefix("VIS06", STATE),
    // Migration 207: the bug-report intake.
    prefix("BUG01", AUTHORITY), prefix("BUG02", AUTHORITY), prefix("BUG03", STATE),
    prefix("BUG04", INPUT), prefix("BUG05", INPUT), prefix("BUG06", AUTHORITY),
    prefix("BUG07", AUTHORITY), prefix("BUG08", STATE),
    // Migration 208: the authorship countersign.
    prefix("CSG01", AUTHORITY), prefix("CSG02", AUTHORITY),
    // Migration 263: person team groups and invitations. TGP08 reads as a
    // missing target.
    sqlstate("TGP01", AUTHORITY), sqlstate("TGP02", AUTHORITY), sqlstate("TGP03", INPUT),
    sqlstate("TGP04", STATE), sqlstate("TGP05", STATE), sqlstate("TGP06", STATE),
    sqlstate("TGP07", STATE), sqlstate("TGP08", Answer::NotFound), sqlstate("TGP09", INPUT),
    // Migration 310: the profile visibility setter.
    prefix("PVS01", AUTHORITY), prefix("PVS02", INPUT), prefix("PVS04", STATE),
    prefix("PVS05", AUTHORITY),
    // Migrations 124, 125 and 130: the passkey and elevation ceremonies and
    // admin acts, each answered by the route that calls the definer.
    sqlstate(ELV01, Answer::Route), sqlstate(ELV02, Answer::Route),
    sqlstate(ELV03, Answer::Route), sqlstate(ELV04, Answer::Route),
    sqlstate(ELV06, Answer::Route), sqlstate(ELV07, Answer::Route),
    sqlstate(ELV08, Answer::Route),
    // Migration 123: a custodial act's ended assignment.
    sqlstate(CUS04, Answer::Route),
    // The agent-key definers' refusals (migrations 161 to 163 and 239) and
    // the admin grant check (111, 112, 237, 252), all as 42501.
    in_42501(AK02, Answer::Route), in_42501(AK03, Answer::Route),
    in_42501(ADM02, Answer::Route),
    // Migrations 161, 268 and 276: the prompt history's reader.
    sqlstate(PROMPT_HISTORY_REFUSED, Answer::Route),
    // Migration 120's cascade-deferral definer, answered by the supersede
    // route and tool. Recognised by `epigraph_auth::claim_act::
    // is_cascade_deferral_refusal`, which takes a SQLSTATE and a message so
    // that `epigraph-auth` stays free of the database layer; listed here so
    // the registry knows every code a caller answers (the ratchet ties the
    // two: tests/refusal_code_matches_ratchet.rs).
    in_42501("CX03", Answer::Route),
];

/// A family of codes one definer (or one migration's definers) raises, and
/// the repo that calls it converts ([`Answer::Refused`], [`Answer::NotFound`]).
/// A repo converts only its own family, so a code of another family reached
/// through its statement stays the ordinary conversion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    /// `VISnn`, migrations 206 and 209: claim visibility acts.
    Vis,
    /// `PVSnn`, migration 310: the profile visibility setter.
    Pvs,
    /// `CSGnn`, migration 208: the authorship countersign.
    Csg,
    /// `BUGnn`, migration 207: the bug-report intake.
    Bug,
    /// `TGPnn`, migration 263: person team groups and invitations.
    Tgp,
}

impl Family {
    const fn letters(self) -> &'static str {
        match self {
            Self::Vis => "VIS",
            Self::Pvs => "PVS",
            Self::Csg => "CSG",
            Self::Bug => "BUG",
            Self::Tgp => "TGP",
        }
    }

    /// `true` when `code` is this family's: its letters, then digits only.
    #[must_use]
    pub fn holds(self, code: &str) -> bool {
        code.strip_prefix(self.letters())
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
    }
}

/// The code `message` opens with, `"CODE: ..."`.
fn message_code(message: &str) -> Option<&str> {
    message.split_once(": ").map(|(code, _)| code)
}

/// The registered refusal a database error carries: its custom SQLSTATE when
/// that is a registered code, else the code its message opens with when that
/// is registered as a prefix (under the SQLSTATE the entry names, if any),
/// else a code of the two HTTP-disclosed lists.
#[must_use]
pub fn lookup(db: &(dyn sqlx::error::DatabaseError + 'static)) -> Option<RefusalCode> {
    let sqlstate = db.code();
    let sqlstate = sqlstate.as_deref();
    if let Some(found) = REGISTRY
        .iter()
        .find(|c| c.carrier == Carrier::Sqlstate && Some(c.code) == sqlstate)
    {
        return Some(*found);
    }
    let code = message_code(db.message())?;
    REGISTRY
        .iter()
        .find(|c| match c.carrier {
            Carrier::Prefix { sqlstate: want } => {
                c.code == code && want.is_none_or(|w| Some(w) == sqlstate)
            }
            Carrier::Sqlstate => false,
        })
        .copied()
        .or_else(|| caller_refusal_code(db.message()).map(|c| prefix(c, Answer::Disclosed)))
}

/// The registered refusal a message opens with, for a code carried by its
/// prefix under any SQLSTATE (no driver error at hand).
#[must_use]
pub fn lookup_message(message: &str) -> Option<RefusalCode> {
    let code = message_code(message)?;
    REGISTRY
        .iter()
        .find(|c| c.code == code && c.carrier == (Carrier::Prefix { sqlstate: None }))
        .copied()
        .or_else(|| caller_refusal_code(message).map(|c| prefix(c, Answer::Disclosed)))
}

/// The registered refusal of `family` a database error carries ([`lookup`],
/// kept to that family): what a repo that calls the family's definer
/// converts.
#[must_use]
pub fn lookup_in(
    db: &(dyn sqlx::error::DatabaseError + 'static),
    family: Family,
) -> Option<RefusalCode> {
    lookup(db).filter(|c| family.holds(c.code))
}

/// The route-answered code ([`Answer::Route`]) a definer raised, read from a
/// `DbError::QueryFailed`'s driver error: what a route compares with
/// [`ELV04`] and the like to choose its own answer.
#[must_use]
pub fn route_code(e: &DbError) -> Option<&'static str> {
    let DbError::QueryFailed { source } = e else {
        return None;
    };
    lookup(source.as_database_error()?)
        .filter(|c| c.answer == Answer::Route)
        .map(|c| c.code)
}

/// Every refusal code migration 176 introduced.
#[rustfmt::skip]
pub const CALLER_REFUSAL_CODES: &[&str] = &[
    // epigraph_admin_act_args (130): an admin act's kind and arguments.
    "AAR01", "AAR02", "AAR03", "AAR04", "AAR05", "AAR06",
    "AAR07", "AAR08", "AAR09", "AAR10", "AAR11",
    // epigraph_propose_admin_act (130): passkey.register names the proposer.
    "AAR12",
    // epigraph_owner_immutable_guard (115), epigraph_writer_owner_guard (114).
    "TEN01", "TEN02",
    // 108, 109 and 164's guards on groups and group_memberships.
    "GRM01", "GRM02", "GRM03", "GRM04", "GRM05", "GRM06",
    // epigraph_no_public_sealed (081).
    "PRV01",
    // epigraph_agents_refuse_registered_system_key (148).
    "AGK01",
];

/// The supersede architecture's caller-reachable refusal codes (SPEC section
/// 7.2), each reviewed for what its message discloses (row ids go in DETAIL).
/// The SQLSTATE of each is the class its HTTP answer follows: `42501` -> 403,
/// `55000` -> 409.
#[rustfmt::skip]
pub const SUPERSEDE_REFUSAL_CODES: &[&str] = &[
    // Migration 194 (H10): delete a retracted BBA outside the purge definer.
    "SR09",
];

/// The code `message` opens with, `"CODE: ..."`, when `list` names it.
fn listed_code(message: &str, list: &'static [&'static str]) -> Option<&'static str> {
    let (code, _) = message.split_once(": ")?;
    list.iter().copied().find(|c| *c == code)
}

/// The [`CALLER_REFUSAL_CODES`] or [`SUPERSEDE_REFUSAL_CODES`] entry `message`
/// opens with (`"GRM05: ..."` gives `Some("GRM05")`), or `None`.
#[must_use]
pub fn caller_refusal_code(message: &str) -> Option<&'static str> {
    listed_code(message, CALLER_REFUSAL_CODES)
        .or_else(|| listed_code(message, SUPERSEDE_REFUSAL_CODES))
}

/// The [`SUPERSEDE_REFUSAL_CODES`] entry `message` opens with, or `None`.
#[must_use]
pub fn supersede_refusal_code(message: &str) -> Option<&'static str> {
    listed_code(message, SUPERSEDE_REFUSAL_CODES)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::fake_db::error;

    fn db(code: &'static str, message: &str) -> Option<RefusalCode> {
        let e = error(code, message);
        lookup(e.as_database_error().expect("a database error"))
    }

    #[test]
    fn each_code_is_registered_once_and_never_in_a_disclosed_list() {
        let mut seen = std::collections::BTreeSet::new();
        for c in REGISTRY {
            assert!(seen.insert(c.code), "{} registered twice", c.code);
            assert!(!CALLER_REFUSAL_CODES.contains(&c.code), "{}", c.code);
            assert!(!SUPERSEDE_REFUSAL_CODES.contains(&c.code), "{}", c.code);
            // The HTTP arm that sends a QueryFailed message stays exactly the
            // two reviewed lists: a registry code never widens it.
            assert_eq!(
                caller_refusal_code(&format!("{}: x", c.code)),
                None,
                "{}",
                c.code
            );
        }
    }

    #[test]
    fn a_sqlstate_code_is_read_from_the_sqlstate_and_a_prefix_code_from_the_message() {
        let tgp = db("TGP04", "TGP04: x").expect("TGP04");
        assert_eq!(
            (tgp.code, tgp.answer),
            ("TGP04", Answer::Refused(RefusalKind::State))
        );
        // A SQLSTATE-carried code is not recognised by its message alone.
        assert_eq!(db("P0001", "TGP04: x"), None);
        assert_eq!(db("P0001", "ELV04: x"), None);
        // A prefix code under any SQLSTATE, but only as `CODE: ` at the start.
        for state in ["42501", "22023", "P0001"] {
            assert_eq!(
                db(state, "VIS03: x").map(|c| c.answer),
                Some(Answer::Refused(RefusalKind::Input))
            );
        }
        for message in [
            "VIS03 x",
            "VIS03:x",
            "x VIS03: x",
            "vis03: x",
            "VIS07: x",
            "PVS03: x",
        ] {
            assert_eq!(db("42501", message), None, "{message:?}");
        }
        // RT07 only as 42501.
        assert_eq!(
            db("42501", "RT07: m").map(|c| c.answer),
            Some(Answer::RetractedBbaRewrite)
        );
        assert_eq!(db("P0001", "RT07: m"), None);
        // The custom SQLSTATE wins over the message.
        assert_eq!(db("OPL02", "VIS01: x").map(|c| c.code), Some("OPL02"));
        // The reviewed lists are part of the one lookup.
        assert_eq!(
            db("42501", "GRM05: x").map(|c| (c.code, c.answer)),
            Some(("GRM05", Answer::Disclosed))
        );
        assert_eq!(
            db("55000", "SR09: x").map(|c| (c.code, c.answer)),
            Some(("SR09", Answer::Disclosed))
        );
        assert_eq!(
            lookup_message("BUG05: x").map(|c| c.answer),
            Some(Answer::Refused(RefusalKind::Input))
        );
        assert_eq!(lookup_message("RT07: m"), None, "RT07 needs its SQLSTATE");
        assert_eq!(
            lookup_message("OPL01: x"),
            None,
            "OPL01 is carried by its SQLSTATE"
        );
    }

    #[test]
    fn a_family_holds_only_its_own_codes() {
        assert!(Family::Vis.holds("VIS01") && Family::Tgp.holds("TGP08"));
        for (family, code) in [
            (Family::Vis, "PVS01"),
            (Family::Bug, "BUG"),
            (Family::Bug, "BUGGY"),
            (Family::Csg, "CSG0x"),
        ] {
            assert!(!family.holds(code), "{family:?} {code}");
        }
        let e = error("P0001", "PVS01: x");
        let db = e.as_database_error().expect("db");
        assert_eq!(lookup_in(db, Family::Pvs).map(|c| c.code), Some("PVS01"));
        assert_eq!(lookup_in(db, Family::Vis), None);
    }

    #[test]
    fn a_route_code_is_a_registered_route_answer_on_a_query_failure() {
        let q = |code, message| DbError::QueryFailed {
            source: error(code, message),
        };
        assert_eq!(route_code(&q("ELV04", "ELV04: x")), Some(ELV04));
        assert_eq!(route_code(&q("CUS04", "x")), Some(CUS04));
        // Registered, but not a route's; or not registered.
        assert_eq!(route_code(&q("TGP01", "TGP01: x")), None);
        assert_eq!(route_code(&q("ELV05", "x")), None);
        assert_eq!(route_code(&q("22004", "x")), None);
        // Only a QueryFailed carries the driver's SQLSTATE.
        assert_eq!(route_code(&DbError::from(error("RVK01", "x"))), None);
    }

    /// The agent-key, admin-grant, prompt-history and cascade-deferral codes
    /// a route answers itself: each only as its definer raises it.
    #[test]
    fn the_route_answered_key_grant_history_and_deferral_codes() {
        let q = |code, message| DbError::QueryFailed {
            source: error(code, message),
        };
        assert_eq!(route_code(&q("42501", "AK02: x")), Some(AK02));
        assert_eq!(route_code(&q("42501", "AK03: x")), Some(AK03));
        assert_eq!(route_code(&q("42501", "ADM02: x")), Some(ADM02));
        assert_eq!(route_code(&q("42501", "CX03: x")), Some("CX03"));
        assert_eq!(
            route_code(&q("AID06", "AID06: x")),
            Some(PROMPT_HISTORY_REFUSED)
        );
        for (state, message) in [
            // Not 42501: another refusal that happens to open the same way.
            ("P0001", "AK02: x"),
            ("55000", "ADM02: x"),
            ("P0001", "CX03: x"),
            // The code is the SQLSTATE, not the text.
            ("42501", "AID06: x"),
            // Not at the start, or not followed by ": ".
            ("42501", "permission denied: AK02: x"),
            ("42501", "AK02 x"),
            // A plain role-privilege refusal.
            (
                "42501",
                "permission denied for function epigraph_agent_key_rotate",
            ),
        ] {
            assert_eq!(route_code(&q(state, message)), None, "{state} {message:?}");
        }
    }

    #[test]
    fn each_answer_has_the_kind_its_transports_answer_by() {
        assert_eq!(
            Answer::OperatorScopeRefused.kind(),
            Some(RefusalKind::Authority)
        );
        assert_eq!(Answer::RetractedBbaRewrite.kind(), Some(RefusalKind::State));
        assert_eq!(
            Answer::Refused(RefusalKind::Input).kind(),
            Some(RefusalKind::Input)
        );
        for a in [Answer::NotFound, Answer::Route, Answer::Disclosed] {
            assert_eq!(a.kind(), None, "{a:?}");
        }
    }

    #[test]
    fn only_a_listed_code_at_the_start_is_recognised() {
        assert_eq!(caller_refusal_code("GRM05: the roster"), Some("GRM05"));
        assert_eq!(caller_refusal_code("AGK01: agents: x"), Some("AGK01"));
        for other in [
            // An older code no one reviewed for the HTTP body.
            "FA07: duplicate x is bound",
            "CR04: x is not a resolution status",
            // Listed, but not at the start, or not followed by ": ".
            "x GRM05: the roster",
            "GRM05 the roster",
            "GRM05:the roster",
            "grm05: the roster",
            "",
        ] {
            assert_eq!(caller_refusal_code(other), None, "{other:?}");
        }
    }

    #[test]
    fn a_supersede_code_is_recognised_by_both_and_kept_out_of_176s_list() {
        assert_eq!(caller_refusal_code("SR09: a retracted x"), Some("SR09"));
        assert_eq!(supersede_refusal_code("SR09: a retracted x"), Some("SR09"));
        assert!(!CALLER_REFUSAL_CODES.contains(&"SR09"));
        // A 176 code is a caller code but not a supersede code.
        assert_eq!(supersede_refusal_code("GRM05: the roster"), None);
        for other in [
            "SR99: unlisted",
            "SR10: not yet raised",
            "x SR09: y",
            "SR09 y",
            "sr09: y",
        ] {
            assert_eq!(caller_refusal_code(other), None, "{other:?}");
            assert_eq!(supersede_refusal_code(other), None, "{other:?}");
        }
    }
}
