//! Authorization for lore: who may read and write which repository's memory.
//!
//! ## What this crate is, and what it deliberately is not
//!
//! It is **authorization**, not identity. The upstream already authenticates:
//! it hashes a bearer token, resolves a user, and populates an `ActorContext`
//! that crosses every call. What it does not do is ask the next question —
//! *may this user see this repository's memory?* — because it answered it once,
//! globally, with "yes". `V14__users.sql` says so outright:
//!
//! > ai-memory's data model stays single-tenant: every authenticated user sees
//! > the same wiki pages (no RBAC, no per-user data scoping).
//!
//! The only mention of RBAC in the whole schema is the line saying there is
//! none. That gap is what this crate fills, and nothing else: it does not hash
//! tokens, does not talk to a database, and does not know what a request is.
//! Given a set of grants it decides; the store fetches, the middleware acts.
//!
//! ## Why the decision is a type rather than a `bool`
//!
//! Hard rule #3: **E1 and E2 are distinct errors and neither is ever confused
//! with an empty memory.** A missing key is an authentication failure; a
//! missing grant is an authorization failure; finding nothing is a valid,
//! successful, empty answer. Collapsing them into `bool` throws away the
//! difference at the one point that knows it, and journey J1 — a new developer
//! finding out why they see nothing — becomes undebuggable.
//!
//! ## Why grants attach to a person, not to a credential
//!
//! Someone with a laptop, a desktop and a CI runner holds three keys and needs
//! one grant per repository. Revoking a lost laptop must cost them that laptop,
//! not their access. So a key answers *who is this*, and a grant answers *what
//! may they reach*, and revoking one never silently does the other's job.

use ai_memory_core::{ProjectId, UserId};
use serde::{Deserialize, Serialize};

pub mod error;
pub mod grant;

pub use error::{AuthenticationFailure, NotGranted};
pub use grant::{GrantLevel, ProjectGrant};

/// How a repository admits users (#708).
///
/// `Open` is what every repository was before this existed: any authenticated
/// user reaches it, grants or not. `Restricted` admits only holders of a grant
/// — the creator holds one from the moment they create it — and the root
/// operator, who is authorized above per-repository granularity. Open by
/// default, so an upgrade changes nothing until an operator restricts a
/// repository on purpose.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessMode {
    /// Any authenticated user.
    #[default]
    Open,
    /// Grant holders and root only.
    Restricted,
}

impl AccessMode {
    /// The stored spelling, as in `projects.access_mode`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Restricted => "restricted",
        }
    }

    /// Parse the stored spelling. Unknown values are `None`, never a default:
    /// a mode this version cannot read must not quietly become `Open`.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "open" => Some(Self::Open),
            "restricted" => Some(Self::Restricted),
            _ => None,
        }
    }
}

/// [`decide`] for a repository in `mode`: an open repository admits everyone
/// at every level, a restricted one asks the grants.
#[must_use]
pub fn decide_with_mode(
    mode: AccessMode,
    grants: &[ProjectGrant],
    user: UserId,
    repository: ProjectId,
    required: GrantLevel,
) -> Access {
    match mode {
        AccessMode::Open => Access::Granted,
        AccessMode::Restricted => decide(grants, user, repository, required),
    }
}

/// Whether a user may reach a repository's memory, and if not, why.
///
/// `Denied` carries the repository so the message can name it. A denial that
/// cannot say *what* was denied leaves the reader guessing whether they typed
/// something wrong or were never granted anything.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Access {
    /// An active grant exists.
    Granted,
    /// No active grant. The distinction below is what makes the difference
    /// between "ask for access" and "ask why it was taken away".
    Denied(Denial),
}

/// Why access was refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Denial {
    /// This user holds no grant on this project.
    NeverGranted { repository: ProjectId },
    /// A grant exists but does not reach the level this operation needs — a
    /// read grant attempting a write.
    ///
    /// Carries both levels because the useful message names them: "you have
    /// read on this project and this needs write" tells someone exactly what
    /// to ask for, where "denied" starts a conversation.
    InsufficientLevel {
        repository: ProjectId,
        held: GrantLevel,
        required: GrantLevel,
    },
}

impl Access {
    /// Convenience for the call sites that only branch.
    #[must_use]
    pub fn is_granted(&self) -> bool {
        matches!(self, Self::Granted)
    }
}

/// Decide whether `user` may reach `repository`, given every grant the store
/// holds for that pair.
///
/// Takes the grants rather than fetching them so the rule is testable without
/// a database and cannot quietly acquire a second data source.
///
/// **Grants are never inherited.** An autonomous LLM triggered by a person
/// holds its own grants and is decided on its own; if it were handed the
/// caller's access, a leaked automation key would expose everything the most
/// permissive member of the team can read. This function is given one user's
/// grants and has no way to widen that, which is the point.
#[must_use]
pub fn decide(
    grants: &[ProjectGrant],
    user: UserId,
    repository: ProjectId,
    required: GrantLevel,
) -> Access {
    // The strongest grant wins. The primary key keeps this to one row per
    // user and project, but the decision must not depend on that: reading the
    // maximum means a duplicate can only ever be redundant, never a silent
    // downgrade that depends on row order.
    let held = grants
        .iter()
        .filter(|grant| grant.user_id == user && grant.project_id == repository)
        .map(|grant| grant.level)
        .max();
    match held {
        Some(held) if held.covers(required) => Access::Granted,
        // Held something, but not enough. Deliberately its own answer: "you
        // cannot write here" and "you cannot see this at all" send a person to
        // different places, and telling a reader their memory is empty when it
        // is merely read-only is the kind of lie this design exists to avoid.
        Some(held) => Access::Denied(Denial::InsufficientLevel {
            repository,
            held,
            required,
        }),
        None => Access::Denied(Denial::NeverGranted { repository }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ai_memory_core::WorkspaceId;
    use jiff::Timestamp;

    fn grant_as(user: UserId, repository: ProjectId, level: GrantLevel) -> ProjectGrant {
        ProjectGrant {
            workspace_id: WorkspaceId::new(),
            project_id: repository,
            user_id: user,
            level,
            granted_by: Some(user),
            granted_at: Timestamp::UNIX_EPOCH,
        }
    }

    /// The ordering is the whole mechanism, so it is asserted directly rather
    /// than left implicit in the derive.
    #[test]
    fn a_stronger_level_covers_a_weaker_requirement() {
        assert!(GrantLevel::Write.covers(GrantLevel::Read));
        assert!(GrantLevel::Write.covers(GrantLevel::Write));
        assert!(GrantLevel::Read.covers(GrantLevel::Read));
        assert!(!GrantLevel::Read.covers(GrantLevel::Write));
    }

    /// A read grant attempting a write is refused, and the refusal names both
    /// levels.
    #[test]
    fn a_read_grant_cannot_write_and_is_told_why() {
        let (u, r) = (UserId::new(), ProjectId::new());
        let grants = vec![grant_as(u, r, GrantLevel::Read)];
        assert_eq!(decide(&grants, u, r, GrantLevel::Read), Access::Granted);
        assert_eq!(
            decide(&grants, u, r, GrantLevel::Write),
            Access::Denied(Denial::InsufficientLevel {
                repository: r,
                held: GrantLevel::Read,
                required: GrantLevel::Write,
            })
        );
    }

    /// Not enough access and no access at all are different answers. Telling a
    /// reader their memory is empty when it is merely read-only is the class of
    /// lie this design exists to avoid.
    #[test]
    fn insufficient_is_not_the_same_as_never_granted() {
        let (u, other, r) = (UserId::new(), UserId::new(), ProjectId::new());
        let grants = vec![grant_as(u, r, GrantLevel::Read)];
        let insufficient = decide(&grants, u, r, GrantLevel::Write);
        let absent = decide(&grants, other, r, GrantLevel::Read);
        assert!(matches!(
            insufficient,
            Access::Denied(Denial::InsufficientLevel { .. })
        ));
        assert_eq!(
            absent,
            Access::Denied(Denial::NeverGranted { repository: r })
        );
    }

    /// The decision must not depend on row order. A duplicate grant can only
    /// ever be redundant, never a silent downgrade.
    #[test]
    fn the_strongest_grant_wins_whatever_the_order() {
        let (u, r) = (UserId::new(), ProjectId::new());
        for grants in [
            vec![
                grant_as(u, r, GrantLevel::Read),
                grant_as(u, r, GrantLevel::Write),
            ],
            vec![
                grant_as(u, r, GrantLevel::Write),
                grant_as(u, r, GrantLevel::Read),
            ],
        ] {
            assert_eq!(decide(&grants, u, r, GrantLevel::Write), Access::Granted);
        }
    }

    /// A grant belongs to one user on one project and reaches nothing else.
    #[test]
    fn a_grant_reaches_neither_another_user_nor_another_project() {
        let (u, other_user, r, other_project) = (
            UserId::new(),
            UserId::new(),
            ProjectId::new(),
            ProjectId::new(),
        );
        let grants = vec![grant_as(u, r, GrantLevel::Write)];
        assert!(decide(&grants, u, r, GrantLevel::Write).is_granted());
        assert!(!decide(&grants, other_user, r, GrantLevel::Read).is_granted());
        assert!(!decide(&grants, u, other_project, GrantLevel::Read).is_granted());
    }

    /// Round-trips through the stored form, and refuses what it does not know
    /// rather than defaulting.
    #[test]
    fn levels_round_trip_and_unknown_values_are_refused() {
        for level in [GrantLevel::Read, GrantLevel::Write] {
            assert_eq!(GrantLevel::parse(level.as_str()), Ok(level));
        }
        assert!(GrantLevel::parse("owner").is_err());
        assert!(GrantLevel::parse("").is_err());
        assert!(
            GrantLevel::parse("admin").is_err(),
            "there is no per-project admin; administration is root's"
        );
        assert!(
            GrantLevel::parse("Write").is_err(),
            "the stored form is lowercase"
        );
    }

    /// An open project admits everyone at every level; a restricted one asks
    /// the grants.
    #[test]
    fn the_mode_decides_before_the_grants() {
        let (u, r) = (UserId::new(), ProjectId::new());
        assert!(decide_with_mode(AccessMode::Open, &[], u, r, GrantLevel::Write).is_granted());
        assert!(
            !decide_with_mode(AccessMode::Restricted, &[], u, r, GrantLevel::Read).is_granted()
        );
        let grants = vec![grant_as(u, r, GrantLevel::Read)];
        assert!(
            decide_with_mode(AccessMode::Restricted, &grants, u, r, GrantLevel::Read).is_granted()
        );
    }
}
