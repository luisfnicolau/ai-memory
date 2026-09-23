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
/// What a grant lets its holder do.
///
/// Ordered, and each level contains the one below it: an `Admin` can do
/// anything a `Writer` can, and a `Writer` anything a `Reader` can. That
/// ordering is the whole mechanism — a call site names the level an operation
/// needs, and the comparison is `held >= required`.
///
/// Three levels rather than two because the third is what makes a server
/// usable by more than one team. Without `Admin`, every grant on every project
/// has to go through a server-wide `root`, so onboarding a new person to one
/// team's project needs the person who runs the server. `Admin` is deliberately
/// scoped to a single repository: it confers nothing anywhere else.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantRole {
    /// Read this repository's memory. Cannot write pages, and captures from
    /// this user are refused rather than silently dropped.
    Reader,
    /// Read and write. What a developer working in the repository needs, and
    /// the level a grant carries when nobody says otherwise.
    Writer,
    /// Read, write, and grant this repository to other people.
    Admin,
}

impl GrantRole {
    /// The stored form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Reader => "reader",
            Self::Writer => "writer",
            Self::Admin => "admin",
        }
    }

    /// Parse the stored form. Unknown values are refused rather than defaulted:
    /// a role this build does not understand must not silently become the
    /// weakest one, because a downgrade of `admin` to `reader` locks a team out
    /// of its own project, and defaulting the other way is worse.
    ///
    /// # Errors
    /// Returns the unrecognised string.
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "reader" => Ok(Self::Reader),
            "writer" => Ok(Self::Writer),
            "admin" => Ok(Self::Admin),
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
    /// `None` when there is no `users` row behind the decision: the grant was
    /// seeded when authorization was switched on, or the operator used the
    /// root bearer token, which authenticates from configuration. Naming a
    /// person there would invent a decision that was never made.
    ///
    /// Equal to `user_id` for exactly one kind of grant: the `admin` a user
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
