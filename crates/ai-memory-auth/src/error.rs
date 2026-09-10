//! E1 and E2: the two refusals, kept apart.
//!
//! Hard rule #3, and the use cases are blunt about why (E1/E2 in
//! `use-cases.md`): *"a tua chave não vale"* and *"não tens acesso à memória
//! deste repositório"* ask different things of the person reading them. One
//! sends them to rotate a credential, the other to ask a colleague for access.
//! A single "access denied" sends them nowhere.
//!
//! Journey J1 — a developer arriving on their first day — fails here more
//! often than anywhere else in the product. It is also the moment they have
//! the least context to work out what went wrong, which is why these messages
//! carry more than the failure.
//!
//! ## The three things every message here must do
//!
//! From `ui_guidelines.md`:
//!
//! 1. **Say what to do next.** A message that describes without directing
//!    leaves the reader stuck.
//! 2. **Never look like emptiness.** "I found nothing" and "I could not look"
//!    lead to different decisions; confusing them makes a person conclude the
//!    memory is empty when it is merely closed.
//! 3. **A refusal says what it did *not* take.** Revocation removes reach, not
//!    history, and saying so is the difference between a rule and a threat.
//!
//! ## Language
//!
//! English, because product messages default to it and follow
//! `user.default_language` where one is set. That field exists (V49); the
//! message catalogue that would consume it does not yet, so everything here is
//! English for now.

use std::fmt;

use serde::{Deserialize, Serialize};

/// **E1** — the credential itself. An authentication failure.
///
/// Deliberately narrower than "auth failed": which of these it is decides what
/// the reader should do, and the server knows which.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticationFailure {
    /// Nothing was presented. Usually a client that was never configured.
    Missing,
    /// Presented and unknown. Usually a rotated or mistyped key.
    Unrecognised,
    /// Known, and revoked. The distinction from `Unrecognised` matters: a
    /// revoked key means somebody made a decision, and the reader may need to
    /// know whose.
    Revoked,
    /// The user's access was expired rather than the key revoked.
    Expired,
}

impl AuthenticationFailure {
    /// A short machine-readable tag, for logs and for clients that branch.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::Missing => "E1_MISSING",
            Self::Unrecognised => "E1_UNRECOGNISED",
            Self::Revoked => "E1_REVOKED",
            Self::Expired => "E1_EXPIRED",
        }
    }
}

impl fmt::Display for AuthenticationFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing => f.write_str(
                "No credential was presented, so nothing was searched — this is not an \
                 empty memory. Set AI_MEMORY_AUTH_TOKEN for this machine, or ask an \
                 operator to issue a key for it.",
            ),
            Self::Unrecognised => f.write_str(
                "That key is not recognised, so nothing was searched — this is not an \
                 empty memory. It may have been rotated; ask an operator to issue a \
                 new one for this machine.",
            ),
            Self::Revoked => f.write_str(
                "That key was revoked, so nothing was searched — this is not an empty \
                 memory. Your other devices are unaffected, and everything you have \
                 already written is still there. Ask an operator to issue a new key \
                 for this machine.",
            ),
            Self::Expired => f.write_str(
                "Your access has expired, so nothing was searched — this is not an \
                 empty memory. Everything you have already written is still there. \
                 Ask an operator to restore it.",
            ),
        }
    }
}

/// **E2** — the grant. An authorization failure, and never E1.
///
/// Carries the repository *by name* because a refusal the reader cannot
/// identify is one they cannot act on: they do not know what to ask for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotGranted {
    /// The repository as a person would name it — its D1 identity where there
    /// is one, e.g. `github.com/acme/api`.
    pub repository: String,
    /// Whether a grant once existed. "You never had this" and "this was taken
    /// from you" are different problems with different next steps.
    pub was_revoked: bool,
}

impl NotGranted {
    /// A short machine-readable tag, for logs and for clients that branch.
    #[must_use]
    pub fn code(&self) -> &'static str {
        if self.was_revoked {
            "E2_REVOKED"
        } else {
            "E2_NOT_GRANTED"
        }
    }
}

impl fmt::Display for NotGranted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let repository = &self.repository;
        if self.was_revoked {
            write!(
                f,
                "Your access to the memory of {repository} was revoked, so nothing was \
                 searched — this is not an empty memory. Your key is still valid, and \
                 everything you wrote before remains attributed to you. Ask an operator \
                 if this was a mistake. {DISCLAIMER}"
            )
        } else {
            write!(
                f,
                "You do not have access to the memory of {repository}, so nothing was \
                 searched — this is not an empty memory. Your key is valid; what is \
                 missing is the grant. Ask an operator for access to {repository}. \
                 {DISCLAIMER}"
            )
        }
    }
}

/// Said on every E2, because the alternative is implying a permission this
/// system has no way to verify.
///
/// What is granted is access to a repository's *memory*, not to the
/// repository. Code access belongs to GitHub; lore neither checks it nor
/// claims anything about it, and a person refused here should not go looking
/// for a problem with their git credentials.
const DISCLAIMER: &str =
    "This says nothing about your access to the repository itself, which lore does not check.";

#[cfg(test)]
mod tests {
    use super::*;

    /// Words that would make a refusal read as an answer. Pattern 2: a person
    /// who concludes the memory is empty stops looking, and the thing they
    /// needed was there all along.
    const SOUNDS_EMPTY: &[&str] = &["no results", "nothing found", "no memory", "is empty"];

    /// Something the reader can act on. Pattern 1: a message that describes
    /// without directing leaves them stuck.
    const SUGGESTS_AN_ACTION: &[&str] = &["ask an operator", "set ai_memory_auth_token"];

    fn all_e1() -> Vec<AuthenticationFailure> {
        vec![
            AuthenticationFailure::Missing,
            AuthenticationFailure::Unrecognised,
            AuthenticationFailure::Revoked,
            AuthenticationFailure::Expired,
        ]
    }

    fn all_e2() -> Vec<NotGranted> {
        vec![
            NotGranted {
                repository: "github.com/acme/api".into(),
                was_revoked: false,
            },
            NotGranted {
                repository: "github.com/acme/api".into(),
                was_revoked: true,
            },
        ]
    }

    #[test]
    fn every_refusal_tells_the_reader_what_to_do() {
        let messages = all_e1()
            .into_iter()
            .map(|e| e.to_string())
            .chain(all_e2().into_iter().map(|e| e.to_string()));
        for message in messages {
            let lower = message.to_lowercase();
            assert!(
                SUGGESTS_AN_ACTION.iter().any(|hint| lower.contains(hint)),
                "no next step in: {message}"
            );
        }
    }

    #[test]
    fn no_refusal_reads_as_an_empty_memory() {
        let messages = all_e1()
            .into_iter()
            .map(|e| e.to_string())
            .chain(all_e2().into_iter().map(|e| e.to_string()));
        for message in messages {
            let lower = message.to_lowercase();
            for phrase in SOUNDS_EMPTY {
                assert!(
                    !lower.contains(phrase),
                    "{message:?} could be mistaken for an empty result ({phrase:?})"
                );
            }
            assert!(
                lower.contains("not an empty memory"),
                "a refusal must say so outright: {message}"
            );
        }
    }

    /// The distinction E2 exists for. A reader who cannot tell which of the
    /// two they hit does not know whether to fix their key or ask a colleague.
    #[test]
    fn e2_says_the_key_is_fine_and_e1_never_does() {
        for e2 in all_e2() {
            let lower = e2.to_string().to_lowercase();
            assert!(
                lower.contains("key is valid") || lower.contains("key is still valid"),
                "E2 must clear the credential: {e2}"
            );
        }
        for e1 in all_e1() {
            let lower = e1.to_string().to_lowercase();
            assert!(
                !lower.contains("key is valid"),
                "E1 is about the key; it cannot call it valid: {e1}"
            );
        }
    }

    /// A refusal the reader cannot identify is one they cannot act on: they do
    /// not know what to ask for.
    #[test]
    fn e2_names_the_repository() {
        for e2 in all_e2() {
            assert!(
                e2.to_string().contains("github.com/acme/api"),
                "E2 must name what was refused: {e2}"
            );
        }
    }

    /// The system must not imply a permission it cannot verify. Somebody
    /// refused here should not go hunting for a git credentials problem.
    #[test]
    fn e2_disclaims_any_statement_about_the_repository_itself() {
        for e2 in all_e2() {
            assert!(
                e2.to_string().contains(DISCLAIMER),
                "E2 must disclaim repository access: {e2}"
            );
        }
    }

    /// Pattern 3: a refusal says what it did *not* take. Revocation removes
    /// reach, not history.
    #[test]
    fn revocation_says_what_it_did_not_take() {
        let revoked = NotGranted {
            repository: "github.com/acme/api".into(),
            was_revoked: true,
        };
        assert!(revoked.to_string().contains("remains attributed to you"));

        let key_revoked = AuthenticationFailure::Revoked.to_string();
        assert!(key_revoked.contains("other devices are unaffected"));
        assert!(key_revoked.contains("already written is still there"));
    }

    /// Codes are distinct so a client can branch without parsing prose, and
    /// E1 and E2 never share one.
    #[test]
    fn codes_separate_the_two_families() {
        let e1: Vec<_> = all_e1().into_iter().map(|e| e.code()).collect();
        let e2: Vec<_> = all_e2().iter().map(NotGranted::code).collect();
        assert!(e1.iter().all(|c| c.starts_with("E1_")));
        assert!(e2.iter().all(|c| c.starts_with("E2_")));
        let mut unique = e1.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), e1.len(), "E1 codes must be distinct");
        assert_ne!(e2[0], e2[1], "granted-never and revoked are different");
    }
}
