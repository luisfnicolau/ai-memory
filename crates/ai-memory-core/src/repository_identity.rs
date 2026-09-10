//! The D1 identity chain: what names a repository, independent of where it
//! sits on any one disk.
//!
//! ## Why this exists
//!
//! ARD-08 and hard rule #4: **repository identity is never a filesystem
//! path.** A path is per-device by construction, so any identity derived from
//! one splits the same repository into a different project on every machine —
//! which defeats the product's first objective, memory that follows a person
//! across devices and is shared with their team.
//!
//! FR-06 defines the chain, in order:
//!
//! 1. **normalised git remote** — `upstream` when present, else `origin`
//! 2. **manifest** — the `project = "…"` field of `.ai-memory.toml`
//! 3. **folder name**
//!
//! ## The rung above the chain
//!
//! Everything FR-06 describes *infers* an identity, and inference has cases it
//! cannot reach: a directory with no remote at all, two checkouts that should
//! deliberately share one memory, a subdirectory of a monorepo that deserves
//! its own. Guessing serves none of them.
//!
//! So `identity = "…"` in `.ai-memory.toml` — written by hand, or by the
//! `link` command once it exists (Migration 2.1.1 05) — sits
//! above the whole chain. It is the only rung a person states rather than the
//! system deduces, and stating it is precisely the act of overriding what
//! would otherwise be deduced. A declaration that lost to a git remote would
//! be a declaration that does nothing in the case people most want it for.
//!
//! Steps 2 and 3 already existed (`crate::marker` and `derive_project_name`
//! respectively). Step 1 did not: before this module, nothing outside the
//! workstream subsystem ever looked at a remote, so two clones of
//! `github.com/acme/api` under `~/work/api` and `~/dev/acme-api` resolved to
//! two unrelated projects.
//!
//! ## Why the chain stops rather than searching
//!
//! FR-06b: when neither `upstream` nor `origin` exists, we fall to the next
//! step instead of picking some other remote. Remote names are personal —
//! one person's `fork`, another's `mine` — so choosing arbitrarily produces an
//! identity that differs per person, which is worse than falling back to a
//! shared convention.
//!
//! `upstream` wins over `origin` because in fork workflows every contributor's
//! `origin` points at their own fork. Keying on `origin` there would give each
//! contributor a private memory of the same repository.
//!
//! ## Why local-path remotes are rejected
//!
//! A remote can legitimately be a filesystem path — `/srv/git/api.git`,
//! `../sibling`, `file:///srv/git/api.git`, `C:\repos\api`. Those are paths,
//! and hard rule #4 applies to them exactly as it applies to `cwd`. They
//! produce no identity here; the chain moves on to the manifest.
//!
//! This is the failure mode the previous implementation had. The workstream
//! crate's `inspect_repository` falls back to `git-common-dir`, then
//! `git-root`, then `cwd` when it finds no remote — all paths. It reads as a
//! chain but its lower steps re-introduce exactly what the rule forbids.

use serde::{Deserialize, Serialize};

/// The marker filename, matching `crates/ai-memory-cli/src/marker.rs`.
///
/// The fork wrote `.lore.toml` here and kept this one as a fallback. That
/// reasoning inverts on this base: the marker is upstream's, committed into
/// repositories that upstream's own tooling reads, so there is exactly one
/// name and it is theirs.
pub const MARKER_FILENAME: &str = ".ai-memory.toml";

/// Every marker name that is read, highest precedence first.
///
/// One entry today. The list stays because the failure mode it exists to
/// prevent is the worst this system has: dropping a name that is still on
/// somebody's disk sends the identity down to the next rung of the chain —
/// usually the folder name — which **silently re-homes that repository's
/// memory to a different project**. No error, no warning; the previous memory
/// simply stops being found. Any future rename adds a name here rather than
/// replacing one.
pub const MARKER_FILENAMES: &[&str] = &[MARKER_FILENAME];

/// Which rung of the chain produced an identity.
///
/// Stored alongside the identity so an operator can tell a globally unique
/// identity from a merely local one. `FolderName` is not unique across
/// organisations — two companies both having an `api` folder is ordinary —
/// and E6 in the use cases accepts that as a known limitation. Recording the
/// source is what lets a later diagnostic distinguish "shared by design" from
/// "collided by accident".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentitySource {
    /// An `identity = "…"` declaration a person wrote deliberately, normally
    /// by hand in the marker. Outranks everything below it.
    ///
    /// The rungs beneath this one all *infer* an identity. This one is told.
    /// Inference is right by default and wrong in the cases that matter most
    /// to the people hitting them: a directory with no remote, two checkouts
    /// that should share one memory, a subdirectory that deserves its own.
    /// None of those can be guessed, and all of them can be stated.
    Explicit,
    /// A normalised `upstream` or `origin` URL. Globally unique.
    GitRemote,
    /// The `project` field of a `.ai-memory.toml` marker. Unique by agreement.
    Manifest,
    /// The directory's basename. **Not** globally unique.
    FolderName,
}

impl IdentitySource {
    /// The stored spelling, matching the `identity_source` enum in the data
    /// model. Kept explicit rather than derived from the variant name so a
    /// rename in Rust cannot silently rewrite what is already in the database.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Explicit => "explicit",
            Self::GitRemote => "git_remote",
            Self::Manifest => "manifest",
            Self::FolderName => "folder_name",
        }
    }

    /// Parse the stored spelling back. Unknown values are `None` rather than a
    /// default, so a row written by a newer version is visibly unreadable
    /// instead of quietly mis-typed.
    #[must_use]
    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s {
            "explicit" => Some(Self::Explicit),
            "git_remote" => Some(Self::GitRemote),
            "manifest" => Some(Self::Manifest),
            "folder_name" => Some(Self::FolderName),
            _ => None,
        }
    }

    /// Whether an identity from this rung is unique beyond the local machine.
    ///
    /// Used to decide whether to warn the user that their memory may not line
    /// up with a colleague's (FR-06, E6 and the wireframe at S6).
    #[must_use]
    pub fn is_globally_unique(self) -> bool {
        // An explicit declaration is as unique as the person writing it meant
        // it to be — which is the point of writing one. Treat it as settled so
        // the "this folder's memory may not line up with your colleagues'"
        // warning stops nagging someone who has already answered it.
        matches!(self, Self::Explicit | Self::GitRemote)
    }
}

/// A resolved repository identity and the rung it came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepositoryIdentity {
    /// The identity itself, e.g. `github.com/acme/api`.
    pub identity: String,
    /// Which rung produced it.
    pub source: IdentitySource,
}

/// Everything the chain needs, gathered by the caller.
///
/// Taking these as data rather than reading git and the filesystem here keeps
/// this module pure: the whole chain is testable without a repository on disk,
/// and the crate stays free of a git dependency.
#[derive(Debug, Default, Clone)]
pub struct IdentityInputs<'a> {
    /// `identity = "…"` from the nearest `.ai-memory.toml`, written
    /// deliberately by a person. Wins over every inferred rung.
    pub explicit_identity: Option<&'a str>,
    /// URL of the `upstream` remote, if any.
    pub upstream_remote: Option<&'a str>,
    /// URL of the `origin` remote, if any.
    pub origin_remote: Option<&'a str>,
    /// `project = "…"` from the nearest `.ai-memory.toml`.
    pub manifest_name: Option<&'a str>,
    /// Basename of the repository root (or of the cwd when there is no repo).
    pub folder_name: Option<&'a str>,
}

/// Walk the D1 chain and return the first rung that yields an identity.
///
/// Returns `None` only when every rung is empty — a case the caller must
/// surface rather than paper over, because a capture with no repository
/// identity has nowhere correct to land.
#[must_use]
pub fn resolve(inputs: &IdentityInputs<'_>) -> Option<RepositoryIdentity> {
    // Rung 0. Someone decided this. Nothing inferred below overrides it —
    // including a git remote, because the reasons to override a remote are
    // exactly the reasons someone would write this down: two repositories that
    // should share one memory, or a subdirectory that deserves its own.
    if let Some(declared) = inputs.explicit_identity.and_then(non_empty) {
        return Some(RepositoryIdentity {
            identity: declared.trim().to_lowercase(),
            source: IdentitySource::Explicit,
        });
    }

    // Rung 1. `upstream` first (FR-06b). A remote that normalises to nothing
    // — a local path, or a string git accepted but we cannot key on — does not
    // stop the chain; it simply yields nothing and we continue.
    for remote in [inputs.upstream_remote, inputs.origin_remote]
        .into_iter()
        .flatten()
    {
        if let Some(identity) = normalize_remote_url(remote) {
            return Some(RepositoryIdentity {
                identity,
                source: IdentitySource::GitRemote,
            });
        }
    }

    // Rung 2. The manifest is a deliberate declaration, so it is taken as
    // written apart from trimming and case folding.
    if let Some(name) = inputs.manifest_name.and_then(non_empty) {
        return Some(RepositoryIdentity {
            identity: name.trim().to_lowercase(),
            source: IdentitySource::Manifest,
        });
    }

    // Rung 3. The folder name. Not globally unique; see `IdentitySource`.
    if let Some(name) = inputs.folder_name.and_then(non_empty) {
        return Some(RepositoryIdentity {
            identity: name.trim().to_lowercase(),
            source: IdentitySource::FolderName,
        });
    }

    None
}

fn non_empty(s: &str) -> Option<&str> {
    let t = s.trim();
    (!t.is_empty()).then_some(t)
}

/// Normalise a git remote URL to a stable identity, or `None` if the URL does
/// not name a network-reachable repository.
///
/// All of these produce `github.com/acme/api`:
///
/// ```text
/// git@github.com:Acme/API.git
/// https://github.com/acme/api/
/// https://user@github.com:443/Acme/API
/// ssh://git@github.com:22/Acme/API.git
/// git://github.com/acme/api
/// ```
///
/// These produce `None`, because they are filesystem paths (hard rule #4):
///
/// ```text
/// /srv/git/api.git
/// ../sibling
/// file:///srv/git/api.git
/// C:\repos\api
/// ```
#[must_use]
pub fn normalize_remote_url(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }

    // Split off a scheme if there is one. Whether a scheme was present decides
    // how `:` is read further down, which is the subtle part of this function.
    let (scheme, rest) = match raw.find("://") {
        Some(idx) => {
            let scheme = raw[..idx].to_ascii_lowercase();
            (Some(scheme), &raw[idx + 3..])
        }
        None => (None, raw),
    };

    // `file://` names a path however it is dressed up.
    if scheme.as_deref() == Some("file") {
        return None;
    }

    // Credentials: strip up to the last `@` that precedes the path. Splitting
    // on the last one rather than the first keeps passwords containing `@`
    // from leaking a fragment of themselves into the identity.
    let host_and_path = {
        let path_start = rest.find('/').unwrap_or(rest.len());
        match rest[..path_start].rfind('@') {
            Some(at) => &rest[at + 1..],
            None => rest,
        }
    };

    let normalized = if scheme.is_some() {
        // URL form: `host[:port]/path`.
        let (host, path) = split_once_or_all(host_and_path, '/');
        let host = strip_port(host);
        if host.is_empty() || path.is_empty() {
            return None;
        }
        format!("{host}/{path}")
    } else {
        // No scheme. Either scp-like `host:path`, or a filesystem path.
        //
        // `:` before any `/` is what distinguishes them. `/srv/git/api.git`
        // has no `:` at all; `../sibling` likewise. A Windows drive letter
        // (`C:\repos\api`) does have one, hence the single-character guard —
        // no real hostname is one character long.
        let colon = host_and_path.find(':')?;
        let slash = host_and_path.find('/');
        if slash.is_some_and(|s| s < colon) {
            return None;
        }
        let (host, path) = host_and_path.split_at(colon);
        let path = &path[1..];
        if host.len() <= 1 || host.is_empty() || path.is_empty() {
            return None;
        }
        // A scp-like path is never absolute in practice, and a backslash means
        // we are looking at Windows rather than a repository path.
        if path.starts_with('\\') || path.contains('\\') {
            return None;
        }
        format!("{host}/{path}")
    };

    let identity = tidy(&normalized);

    // An identity with no `/` is a bare hostname, not a repository.
    if identity.is_empty() || !identity.contains('/') {
        return None;
    }
    Some(identity)
}

/// Strip a `:port` suffix from a host. Only ever called on the URL form, where
/// `:` unambiguously introduces a port — in scp-like syntax the same character
/// separates host from path.
fn strip_port(host: &str) -> &str {
    match host.rfind(':') {
        Some(idx) if host[idx + 1..].chars().all(|c| c.is_ascii_digit()) => &host[..idx],
        _ => host,
    }
}

fn split_once_or_all(s: &str, sep: char) -> (&str, &str) {
    match s.split_once(sep) {
        Some((a, b)) => (a, b),
        None => (s, ""),
    }
}

/// Case-fold, drop a trailing `.git`, and collapse the slash noise that
/// distinguishes otherwise identical URLs.
fn tidy(s: &str) -> String {
    let mut out = s.to_lowercase();
    while out.ends_with('/') {
        out.pop();
    }
    if let Some(stripped) = out.strip_suffix(".git") {
        out = stripped.to_string();
    }
    while out.ends_with('/') {
        out.pop();
    }
    // `https://host//acme//api` and `https://host/acme/api` are the same
    // repository as far as any server is concerned.
    while out.contains("//") {
        out = out.replace("//", "/");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The property that defines the whole task: every spelling of the same
    /// repository has to land on one identity, or memory fragments per person.
    #[test]
    fn every_spelling_of_one_repository_agrees() {
        let expected = "github.com/acme/api";
        for url in [
            "git@github.com:Acme/API.git",
            "git@github.com:acme/api",
            "https://github.com/acme/api",
            "https://github.com/acme/api/",
            "https://github.com/acme/api.git",
            "https://github.com/Acme/API.git/",
            "https://user@github.com/acme/api",
            "https://user:secret@github.com/acme/api",
            "https://user@github.com:443/Acme/API",
            "ssh://git@github.com:22/Acme/API.git",
            "ssh://git@github.com/acme/api.git",
            "git://github.com/acme/api",
            "  https://github.com/acme/api  ",
            "https://github.com//acme//api",
        ] {
            assert_eq!(
                normalize_remote_url(url).as_deref(),
                Some(expected),
                "normalising {url}"
            );
        }
    }

    /// Hard rule #4. These are all paths, however git dresses them up, and a
    /// path must never become an identity.
    #[test]
    fn filesystem_paths_yield_no_identity() {
        for url in [
            "/srv/git/api.git",
            "../sibling",
            "./api",
            "file:///srv/git/api.git",
            "file://localhost/srv/git/api.git",
            r"C:\repos\api",
            r"c:\repos\api",
            "~/repos/api",
            "",
            "   ",
        ] {
            assert_eq!(normalize_remote_url(url), None, "rejecting {url}");
        }
    }

    #[test]
    fn a_bare_host_is_not_a_repository() {
        assert_eq!(normalize_remote_url("https://github.com"), None);
        assert_eq!(normalize_remote_url("https://github.com/"), None);
    }

    #[test]
    fn self_hosted_forges_and_deep_paths_survive() {
        assert_eq!(
            normalize_remote_url("git@git.internal.acme.dev:platform/tools/api.git").as_deref(),
            Some("git.internal.acme.dev/platform/tools/api")
        );
        assert_eq!(
            normalize_remote_url("https://gitlab.com/acme/group/subgroup/api.git").as_deref(),
            Some("gitlab.com/acme/group/subgroup/api")
        );
        assert_eq!(
            normalize_remote_url("ssh://git@ssh.dev.azure.com:22/v3/acme/proj/api").as_deref(),
            Some("ssh.dev.azure.com/v3/acme/proj/api")
        );
    }

    /// A repository whose name genuinely ends in `.git` would be mangled, but
    /// the suffix is stripped only once, so `api.git.git` keeps one.
    #[test]
    fn dot_git_is_stripped_once() {
        assert_eq!(
            normalize_remote_url("https://github.com/acme/api.git.git").as_deref(),
            Some("github.com/acme/api.git")
        );
    }

    #[test]
    fn upstream_wins_over_origin() {
        let got = resolve(&IdentityInputs {
            upstream_remote: Some("git@github.com:acme/api.git"),
            origin_remote: Some("git@github.com:contributor/api-fork.git"),
            ..Default::default()
        })
        .expect("an identity");
        assert_eq!(got.identity, "github.com/acme/api");
        assert_eq!(got.source, IdentitySource::GitRemote);
    }

    #[test]
    fn origin_is_used_when_there_is_no_upstream() {
        let got = resolve(&IdentityInputs {
            origin_remote: Some("https://github.com/acme/api"),
            ..Default::default()
        })
        .expect("an identity");
        assert_eq!(got.identity, "github.com/acme/api");
    }

    /// FR-06b: an unusable remote does not halt the chain, and no *other*
    /// remote is substituted — the caller never offers one.
    #[test]
    fn a_path_remote_falls_through_to_the_manifest() {
        let got = resolve(&IdentityInputs {
            origin_remote: Some("/srv/git/api.git"),
            manifest_name: Some("acme-api"),
            folder_name: Some("whatever"),
            ..Default::default()
        })
        .expect("an identity");
        assert_eq!(got.identity, "acme-api");
        assert_eq!(got.source, IdentitySource::Manifest);
    }

    #[test]
    fn the_chain_runs_in_order() {
        let manifest_only = resolve(&IdentityInputs {
            manifest_name: Some("Declared"),
            folder_name: Some("on-disk"),
            ..Default::default()
        })
        .expect("an identity");
        assert_eq!(manifest_only.identity, "declared");
        assert_eq!(manifest_only.source, IdentitySource::Manifest);

        let folder_only = resolve(&IdentityInputs {
            folder_name: Some("On-Disk"),
            ..Default::default()
        })
        .expect("an identity");
        assert_eq!(folder_only.identity, "on-disk");
        assert_eq!(folder_only.source, IdentitySource::FolderName);

        assert!(resolve(&IdentityInputs::default()).is_none());
    }

    /// Blank strings are not declarations. A marker with `project = ""` should
    /// behave as if the field were absent rather than pin every repository to
    /// one empty identity.
    #[test]
    fn blank_rungs_are_skipped() {
        let got = resolve(&IdentityInputs {
            origin_remote: Some("   "),
            manifest_name: Some(""),
            folder_name: Some("api"),
            ..Default::default()
        })
        .expect("an identity");
        assert_eq!(got.identity, "api");
        assert_eq!(got.source, IdentitySource::FolderName);
    }

    /// The two clones from the task description: same repository, different
    /// directories, one identity. This is the regression that matters.
    #[test]
    fn two_clones_in_different_directories_share_an_identity() {
        let mac = resolve(&IdentityInputs {
            origin_remote: Some("git@github.com:acme/api.git"),
            folder_name: Some("api"),
            ..Default::default()
        })
        .expect("an identity");
        let linux = resolve(&IdentityInputs {
            origin_remote: Some("https://github.com/Acme/API"),
            folder_name: Some("acme-api"),
            ..Default::default()
        })
        .expect("an identity");
        assert_eq!(mac.identity, linux.identity);
    }

    /// The point of a declaration is to override what would otherwise be
    /// inferred. One that lost to a git remote would be useless in exactly the
    /// case people reach for it: two checkouts that should share one memory.
    #[test]
    fn an_explicit_declaration_beats_every_inferred_rung() {
        let got = resolve(&IdentityInputs {
            explicit_identity: Some("Acme Platform"),
            upstream_remote: Some("git@github.com:acme/api.git"),
            origin_remote: Some("git@github.com:contributor/api.git"),
            manifest_name: Some("declared"),
            folder_name: Some("on-disk"),
        })
        .expect("an identity");
        assert_eq!(got.identity, "acme platform");
        assert_eq!(got.source, IdentitySource::Explicit);
    }

    /// A folder with no git at all is the case the feature exists for: the
    /// chain would otherwise land on a basename that collides with every other
    /// `notes` folder in the world.
    #[test]
    fn a_declaration_rescues_a_folder_with_no_repository() {
        let inferred = resolve(&IdentityInputs {
            folder_name: Some("notes"),
            ..Default::default()
        })
        .expect("an identity");
        assert_eq!(inferred.source, IdentitySource::FolderName);
        assert!(!inferred.source.is_globally_unique());

        let declared = resolve(&IdentityInputs {
            explicit_identity: Some("ana/personal-notes"),
            folder_name: Some("notes"),
            ..Default::default()
        })
        .expect("an identity");
        assert_eq!(declared.identity, "ana/personal-notes");
        assert!(
            declared.source.is_globally_unique(),
            "having answered the question, the operator should stop being asked it"
        );
    }

    /// Two directories pointed at the same declared identity share a project —
    /// which is what "link a folder to a project" means.
    #[test]
    fn two_folders_can_be_linked_to_one_identity() {
        let a = resolve(&IdentityInputs {
            explicit_identity: Some("acme/platform"),
            folder_name: Some("frontend"),
            ..Default::default()
        })
        .unwrap();
        let b = resolve(&IdentityInputs {
            explicit_identity: Some("acme/platform"),
            origin_remote: Some("git@github.com:acme/backend.git"),
            folder_name: Some("backend"),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(a.identity, b.identity);
    }

    /// A blank declaration is not a declaration. An empty `identity = ""` must
    /// fall through rather than pin every folder to one empty identity.
    #[test]
    fn a_blank_declaration_falls_through() {
        let got = resolve(&IdentityInputs {
            explicit_identity: Some("   "),
            origin_remote: Some("https://github.com/acme/api"),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(got.source, IdentitySource::GitRemote);
    }

    #[test]
    fn source_round_trips_through_its_stored_spelling() {
        for source in [
            IdentitySource::Explicit,
            IdentitySource::GitRemote,
            IdentitySource::Manifest,
            IdentitySource::FolderName,
        ] {
            assert_eq!(IdentitySource::from_str_opt(source.as_str()), Some(source));
        }
        assert_eq!(IdentitySource::from_str_opt("something_new"), None);
        assert!(IdentitySource::GitRemote.is_globally_unique());
        assert!(!IdentitySource::Manifest.is_globally_unique());
        assert!(!IdentitySource::FolderName.is_globally_unique());
    }
}
