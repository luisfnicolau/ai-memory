//! A grant: permission for one user to reach one repository's memory.

use ai_memory_core::ids::MemoryGrantId;
use ai_memory_core::{ProjectId, UserId};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

/// One user's access to one repository's memory.
///
/// **What is granted is access to the *memory* of a repository, not to the
/// repository.** Code access belongs to GitHub, and lore neither checks it nor
/// claims to. Conflating the two would let this system imply a permission it
/// has no way to verify.
/// What a grant lets its holder do in one project (#708).
///
/// Two levels, and `Write` contains `Read`: a call site names the level an
/// operation needs and the comparison is `held >= required`.
///
/// There is no per-project administrator. Granting and revoking, and every
/// other administrative act, belong to the server's `root` operator, as they
/// always have; delegating them per project is out of scope for v1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantRole {
    /// Query and read the project's pages, observations, status and
    /// briefing. Captures from this user are refused rather than silently
    /// dropped.
    Read,
    /// Everything `Read` allows, plus writing: pages, captures, consolidation,
    /// handoffs, messages, deletion.
    Write,
}

impl GrantRole {
    /// The stored form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
        }
    }

    /// Parse the stored form. Unknown values are refused rather than defaulted:
    /// a level this build does not understand must not silently become one it
    /// does — reading `write` as `read` locks a team out of its own project,
    /// and defaulting the other way widens access nobody granted.
    ///
    /// # Errors
    /// Returns the unrecognised string.
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "read" => Ok(Self::Read),
            "write" => Ok(Self::Write),
            other => Err(other.to_string()),
        }
    }

    /// Whether this role satisfies a requirement.
    #[must_use]
    pub fn covers(self, required: Self) -> bool {
        self >= required
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryGrant {
    pub id: MemoryGrantId,
    /// Who may reach it. A person, not a device: revoking one laptop's key
    /// must not cost them access from another.
    pub user_id: UserId,
    /// Which repository's memory. `projects(id)` in the schema; the data model
    /// calls the entity `repository` (ARD-08 amendment).
    pub repository_id: ProjectId,
    /// What this grant permits. See [`GrantRole`].
    pub role: GrantRole,
    /// The operator who granted it, so "who let them in" has an answer that is
    /// not "the database".
    ///
    /// `None` when there is no `users` row behind the decision: the operator
    /// used the root bearer token, which authenticates from configuration.
    /// Naming a person there would invent a decision that was never made.
    ///
    /// Equal to `user_id` for exactly one kind of grant: the `write` a user
    /// receives with a repository they create, where the act was theirs.
    pub granted_by_user_id: Option<UserId>,
    /// When it was granted, or when it was seeded.
    pub granted_at: Timestamp,
    /// `None` while active. Revocation stamps a time rather than deleting the
    /// row: nothing is deleted, and an audit trail that forgets who lost
    /// access and when is not one.
    pub revoked_at: Option<Timestamp>,
    /// Who revoked it, on the same terms as [`Self::granted_by_user_id`]:
    /// `None` when the operator used the root token. Only
    /// [`Self::revoked_at`] decides whether the grant is in force.
    pub revoked_by_user_id: Option<UserId>,
}

impl MemoryGrant {
    /// Whether this grant currently permits anything.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.revoked_at.is_none()
    }
}
