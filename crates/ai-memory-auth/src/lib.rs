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
pub use grant::{GrantRole, MemoryGrant};

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
    grants: &[MemoryGrant],
    user: UserId,
    repository: ProjectId,
    required: GrantRole,
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
    /// This user was never granted this repository.
    NeverGranted { repository: ProjectId },
    /// A grant existed and was revoked. Worth distinguishing: "you never had
    /// this" and "this was taken from you" send a person to different places,
    /// and only one of them is a surprise worth escalating.
    Revoked { repository: ProjectId },
    /// An active grant exists but does not reach the level this operation
    /// needs — a reader attempting a write.
    ///
    /// Carries both levels because the useful message names them: "you have
    /// reader on this repository and this needs writer" tells someone exactly
    /// what to ask for, where "denied" starts a conversation.
    InsufficientRole {
        repository: ProjectId,
        held: GrantRole,
        required: GrantRole,
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
    grants: &[MemoryGrant],
    user: UserId,
    repository: ProjectId,
    required: GrantRole,
) -> Access {
    let mut saw_revoked = false;
    let mut best_held: Option<GrantRole> = None;

    for grant in grants {
        if grant.user_id != user || grant.repository_id != repository {
            continue;
        }
        if !grant.is_active() {
            saw_revoked = true;
            continue;
        }
        // The strongest active grant wins. A unique index keeps this to one
        // row in practice, but the decision must not depend on that: reading
        // the maximum means a duplicate can only ever be redundant, never a
        // silent downgrade that depends on row order.
        best_held = Some(best_held.map_or(grant.role, |held: GrantRole| held.max(grant.role)));
    }

    match best_held {
        Some(held) if held.covers(required) => Access::Granted,
        // Held something, but not enough. Deliberately its own answer: "you
        // cannot write here" and "you cannot see this at all" send a person to
        // different places, and telling a reader their memory is empty when it
        // is merely read-only is the kind of lie this design exists to avoid.
        Some(held) => Access::Denied(Denial::InsufficientRole {
            repository,
            held,
            required,
        }),
        None if saw_revoked => Access::Denied(Denial::Revoked { repository }),
        None => Access::Denied(Denial::NeverGranted { repository }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jiff::Timestamp;

    fn grant(user: UserId, repository: ProjectId, revoked: bool) -> MemoryGrant {
        grant_as(user, repository, revoked, GrantRole::Writer)
    }

    fn grant_as(
        user: UserId,
        repository: ProjectId,
        revoked: bool,
        role: GrantRole,
    ) -> MemoryGrant {
        MemoryGrant {
            id: ai_memory_core::ids::MemoryGrantId::new(),
            user_id: user,
            repository_id: repository,
            role,
            granted_by_user_id: Some(user),
            granted_at: Timestamp::UNIX_EPOCH,
            revoked_at: revoked.then_some(Timestamp::UNIX_EPOCH),
            revoked_by_user_id: None,
        }
    }

    /// The ordering is the whole mechanism, so it is asserted directly rather
    /// than left implicit in the derive.
    #[test]
    fn a_stronger_role_covers_a_weaker_requirement() {
        assert!(GrantRole::Admin.covers(GrantRole::Writer));
        assert!(GrantRole::Admin.covers(GrantRole::Reader));
        assert!(GrantRole::Writer.covers(GrantRole::Reader));
        assert!(GrantRole::Reader.covers(GrantRole::Reader));

        assert!(!GrantRole::Reader.covers(GrantRole::Writer));
        assert!(!GrantRole::Writer.covers(GrantRole::Admin));
    }

    /// A reader attempting a write is refused, and the refusal names both
    /// levels — "you have reader and this needs writer" tells someone what to
    /// ask for, where a bare denial starts a conversation.
    #[test]
    fn a_reader_cannot_write_and_is_told_why() {
        let (u, r) = (UserId::new(), ProjectId::new());
        let grants = vec![grant_as(u, r, false, GrantRole::Reader)];

        assert_eq!(decide(&grants, u, r, GrantRole::Reader), Access::Granted);
        assert_eq!(
            decide(&grants, u, r, GrantRole::Writer),
            Access::Denied(Denial::InsufficientRole {
                repository: r,
                held: GrantRole::Reader,
                required: GrantRole::Writer,
            })
        );
    }

    /// Not enough access and no access at all are different answers. Telling a
    /// reader their memory is empty when it is merely read-only is the class of
    /// lie this design exists to avoid.
    #[test]
    fn insufficient_is_not_the_same_as_never_granted() {
        let (u, other, r) = (UserId::new(), UserId::new(), ProjectId::new());
        let grants = vec![grant_as(u, r, false, GrantRole::Reader)];

        let insufficient = decide(&grants, u, r, GrantRole::Admin);
        let absent = decide(&grants, other, r, GrantRole::Reader);

        assert!(matches!(
            insufficient,
            Access::Denied(Denial::InsufficientRole { .. })
        ));
        assert!(matches!(
            absent,
            Access::Denied(Denial::NeverGranted { .. })
        ));
        assert_ne!(insufficient, absent);
    }

    /// The decision must not depend on row order. A duplicate grant can only
    /// ever be redundant, never a silent downgrade.
    #[test]
    fn the_strongest_active_grant_wins_whatever_the_order() {
        let (u, r) = (UserId::new(), ProjectId::new());
        let weak_first = vec![
            grant_as(u, r, false, GrantRole::Reader),
            grant_as(u, r, false, GrantRole::Admin),
        ];
        let strong_first = vec![
            grant_as(u, r, false, GrantRole::Admin),
            grant_as(u, r, false, GrantRole::Reader),
        ];

        assert_eq!(decide(&weak_first, u, r, GrantRole::Admin), Access::Granted);
        assert_eq!(
            decide(&strong_first, u, r, GrantRole::Admin),
            Access::Granted
        );
    }

    /// A revoked admin grant does not keep conferring admin, and a revoked
    /// grant beside an active weaker one must not resurrect the stronger.
    #[test]
    fn revoking_the_stronger_grant_leaves_only_the_weaker() {
        let (u, r) = (UserId::new(), ProjectId::new());
        let grants = vec![
            grant_as(u, r, true, GrantRole::Admin),
            grant_as(u, r, false, GrantRole::Reader),
        ];

        assert_eq!(decide(&grants, u, r, GrantRole::Reader), Access::Granted);
        assert!(matches!(
            decide(&grants, u, r, GrantRole::Admin),
            Access::Denied(Denial::InsufficientRole { .. })
        ));
    }

    /// Round-trips through the stored form, and refuses what it does not know
    /// rather than defaulting — a role this build cannot read must not silently
    /// become the weakest one, which would lock a team out of its own project.
    #[test]
    fn roles_round_trip_and_unknown_values_are_refused() {
        for role in [GrantRole::Reader, GrantRole::Writer, GrantRole::Admin] {
            assert_eq!(GrantRole::parse(role.as_str()), Ok(role));
        }
        assert!(GrantRole::parse("owner").is_err());
        assert!(GrantRole::parse("").is_err());
        assert!(
            GrantRole::parse("Admin").is_err(),
            "the stored form is lowercase"
        );
    }

    #[test]
    fn an_active_grant_allows() {
        let (u, r) = (UserId::new(), ProjectId::new());
        assert_eq!(
            decide(&[grant(u, r, false)], u, r, GrantRole::Reader),
            Access::Granted
        );
    }

    #[test]
    fn no_grant_at_all_is_never_granted() {
        let (u, r) = (UserId::new(), ProjectId::new());
        assert_eq!(
            decide(&[], u, r, GrantRole::Reader),
            Access::Denied(Denial::NeverGranted { repository: r })
        );
    }

    /// "You never had this" and "this was taken from you" send a person to
    /// different places. Only one of them is worth escalating.
    #[test]
    fn a_revoked_grant_is_reported_as_revoked() {
        let (u, r) = (UserId::new(), ProjectId::new());
        assert_eq!(
            decide(&[grant(u, r, true)], u, r, GrantRole::Reader),
            Access::Denied(Denial::Revoked { repository: r })
        );
    }

    /// Revoking and re-granting is ordinary. The active row must win whatever
    /// order the store returns them in.
    #[test]
    fn an_active_grant_wins_over_an_older_revoked_one() {
        let (u, r) = (UserId::new(), ProjectId::new());
        let revoked_first = vec![grant(u, r, true), grant(u, r, false)];
        let active_first = vec![grant(u, r, false), grant(u, r, true)];
        assert_eq!(
            decide(&revoked_first, u, r, GrantRole::Reader),
            Access::Granted
        );
        assert_eq!(
            decide(&active_first, u, r, GrantRole::Reader),
            Access::Granted
        );
    }

    /// The isolation this whole crate exists for: one person's grant must not
    /// answer for another's, nor one repository's for another's.
    #[test]
    fn a_grant_reaches_neither_another_user_nor_another_repository() {
        let (ana, bruno) = (UserId::new(), UserId::new());
        let (api, web) = (ProjectId::new(), ProjectId::new());
        let grants = vec![grant(ana, api, false)];

        assert_eq!(
            decide(&grants, ana, api, GrantRole::Reader),
            Access::Granted
        );
        assert_eq!(
            decide(&grants, bruno, api, GrantRole::Reader),
            Access::Denied(Denial::NeverGranted { repository: api })
        );
        assert_eq!(
            decide(&grants, ana, web, GrantRole::Reader),
            Access::Denied(Denial::NeverGranted { repository: web })
        );
    }

    /// Grants are decided per user, so a set containing someone else's revoked
    /// grant must not colour this user's answer.
    #[test]
    fn another_users_revocation_does_not_leak_into_this_decision() {
        let (ana, bruno) = (UserId::new(), UserId::new());
        let api = ProjectId::new();
        let grants = vec![grant(bruno, api, true)];
        assert_eq!(
            decide(&grants, ana, api, GrantRole::Reader),
            Access::Denied(Denial::NeverGranted { repository: api }),
            "Ana never had it; Bruno losing it says nothing about her"
        );
    }
}
