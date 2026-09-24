//! A grant: permission for one user to reach one project's memory (#708).

use ai_memory_core::{ProjectId, UserId, WorkspaceId};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

/// What a grant lets its holder do in one project.
///
/// Two levels, and `Write` contains `Read`: a call site names the level an
/// operation needs and the comparison is `held >= required`.
///
/// There is no per-project administrator. Granting and revoking, and every
/// other administrative act, belong to the server's `root` operator, as they
/// always have; delegating them per project is out of scope for v1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantLevel {
    /// Query and read the project's pages, observations, status and
    /// briefing. Captures from this user are refused rather than silently
    /// dropped.
    Read,
    /// Everything `Read` allows, plus writing: pages, captures, consolidation,
    /// handoffs, messages, deletion.
    Write,
}

impl GrantLevel {
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

/// One user's access to one project's memory — a row of `project_grants`.
///
/// What is granted is access to the project's *memory*, not to the code it
/// may describe: whoever hosts the repository decides that, and ai-memory
/// neither checks nor implies it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectGrant {
    /// The workspace the project lives in.
    pub workspace_id: WorkspaceId,
    /// Which project's memory.
    pub project_id: ProjectId,
    /// Who may reach it. A person, not a device: revoking one laptop's key
    /// must not cost them access from another.
    pub user_id: UserId,
    /// What this grant permits. See [`GrantLevel`].
    pub level: GrantLevel,
    /// Who granted it, so "who let them in" has an answer that is not "the
    /// database".
    ///
    /// `None` when there is no `users` row behind the decision: the operator
    /// used the root bearer token, which authenticates from configuration.
    /// Naming a person there would invent a decision that was never made.
    ///
    /// Equal to `user_id` for exactly one kind of grant: the `write` a user
    /// receives with a project they create, where the act was theirs.
    pub granted_by: Option<UserId>,
    /// When it was granted, or last changed level.
    pub granted_at: Timestamp,
}
