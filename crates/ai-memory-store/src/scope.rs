//! Shared workspace/project scope resolution.
//!
//! HTTP admin routes, MCP tools, and the read-only web API all need the same
//! boundary rules: explicit read scopes fail closed, write scopes are the only
//! place that may create projects, and current-project defaults must respect the
//! actor-scoped active-project pointer. Keeping those policies here prevents
//! each surface from growing its own subtly different fallback chain.

use std::collections::HashSet;
use std::fmt;

use ai_memory_core::{ActiveProject, ActiveProjectLookup, ActorKey, ProjectId, WorkspaceId};

use crate::error::StoreError;
use crate::{ReaderPool, WriterHandle};

/// Canonical error for partial explicit scope arguments.
pub const WORKSPACE_PROJECT_PAIR_REQUIRED: &str = "workspace and project must be provided together";

/// Message for [`ScopeResolutionError::AmbiguousUnscopedWrite`]. Names both fixes,
/// because the caller cannot tell from the failure alone which one applies to them.
pub const AMBIGUOUS_UNSCOPED_WRITE: &str = "cannot resolve a target for this write: the active-project pointer does not match this \
     caller. Pass an explicit workspace and project, or install the lifecycle hooks so the \
     pointer is populated";

/// Human-readable workspace/project pair supplied by an API caller.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ScopeName {
    /// Workspace name.
    pub workspace: String,
    /// Project name within the workspace.
    pub project: String,
}

impl ScopeName {
    /// Build a scope name from any string-like values.
    #[must_use]
    pub fn new(workspace: impl Into<String>, project: impl Into<String>) -> Self {
        Self {
            workspace: workspace.into(),
            project: project.into(),
        }
    }
}

/// Resolved database ids for a project scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolvedScope {
    /// Owning workspace id.
    pub workspace_id: WorkspaceId,
    /// Project id inside the workspace.
    pub project_id: ProjectId,
}

impl ResolvedScope {
    /// Return the ids as the tuple used by existing reader/writer APIs.
    #[must_use]
    pub fn as_tuple(self) -> (WorkspaceId, ProjectId) {
        (self.workspace_id, self.project_id)
    }
}

/// Scope-resolution failure, independent of HTTP/MCP response types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeResolutionError {
    /// The caller is authenticated but not authorized for this repository, or
    /// not to the level this operation needs (#708).
    ///
    /// Deliberately distinct from `ProjectNotFoundInWorkspace`. Returning
    /// "not found" for a project somebody may not read is a defensible choice
    /// in some systems, but not here: the same error would then mean both "you
    /// cannot see this" and "this does not exist", and a developer whose grant
    /// was never issued would spend the afternoon debugging a typo.
    NotAuthorized {
        /// The repository as a person would name it.
        repository: String,
        /// What the caller holds today, if anything.
        held: Option<ai_memory_auth::GrantRole>,
        /// What the operation needed.
        required: ai_memory_auth::GrantRole,
    },
    /// Only one of workspace/project was provided.
    WorkspaceProjectPairRequired,
    /// A multi-scope entry had an empty workspace.
    ScopeWorkspaceEmpty,
    /// A multi-scope entry had an empty project.
    ScopeProjectEmpty,
    /// The caller supplied more scopes than the surface allows.
    TooManyScopes {
        /// Maximum number of scopes allowed by the caller surface.
        max: usize,
        /// Number of scopes the request supplied.
        actual: usize,
    },
    /// A workspace name did not resolve.
    WorkspaceNotFound {
        /// Workspace name supplied by the caller.
        workspace: String,
    },
    /// A project name did not resolve inside the provided workspace.
    ProjectNotFoundInWorkspace {
        /// Workspace name supplied by the caller.
        workspace: String,
        /// Project name supplied by the caller.
        project: String,
    },
    /// A project-only read did not resolve in either the actor's active
    /// workspace or the server's default workspace.
    ProjectNotFoundInActiveOrDefault {
        /// Project name supplied by the caller.
        project: String,
    },
    /// An unscoped write from a caller whose active-project pointer did not
    /// resolve. Writing it to the server default would silently misfile it.
    AmbiguousUnscopedWrite,
    /// A write-create policy was requested without a writer handle.
    WriterRequired,
    /// Underlying store failure.
    Store(String),
}

impl ScopeResolutionError {
    /// True when the error is caused by malformed caller input rather than a
    /// missing object or an internal store failure.
    #[must_use]
    pub fn is_bad_request(&self) -> bool {
        matches!(
            self,
            ScopeResolutionError::WorkspaceProjectPairRequired
                | ScopeResolutionError::ScopeWorkspaceEmpty
                | ScopeResolutionError::ScopeProjectEmpty
                | ScopeResolutionError::TooManyScopes { .. }
                | ScopeResolutionError::AmbiguousUnscopedWrite
        )
    }

    /// True when the caller is authenticated but not authorized for the
    /// repository (#708).
    ///
    /// Surfaces map this to 403. Before this existed it fell through to their
    /// catch-all 500, which told a user refused by design that the server was
    /// broken — the one reading of a denial more misleading than "not found".
    #[must_use]
    pub fn is_forbidden(&self) -> bool {
        matches!(self, ScopeResolutionError::NotAuthorized { .. })
    }

    /// True when the caller named a scope that does not exist.
    #[must_use]
    pub fn is_not_found(&self) -> bool {
        matches!(
            self,
            ScopeResolutionError::WorkspaceNotFound { .. }
                | ScopeResolutionError::ProjectNotFoundInWorkspace { .. }
                | ScopeResolutionError::ProjectNotFoundInActiveOrDefault { .. }
        )
    }
}

impl fmt::Display for ScopeResolutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScopeResolutionError::NotAuthorized {
                repository,
                held,
                required,
            } => {
                // Name both levels: "you have reader and this needs writer"
                // tells somebody what to ask for, where a bare denial starts a
                // conversation.
                match held {
                    Some(held) => write!(
                        f,
                        "not authorized for {repository}: you have {} and this needs {}. \
                         Ask someone with admin on it to raise your access.",
                        held.as_str(),
                        required.as_str()
                    ),
                    None => write!(
                        f,
                        "not authorized for {repository}. This is an access problem, not an \
                         empty memory — ask an operator to grant you {} on it.",
                        required.as_str()
                    ),
                }
            }
            ScopeResolutionError::WorkspaceProjectPairRequired => {
                f.write_str(WORKSPACE_PROJECT_PAIR_REQUIRED)
            }
            ScopeResolutionError::ScopeWorkspaceEmpty => {
                f.write_str("scope workspace cannot be empty")
            }
            ScopeResolutionError::ScopeProjectEmpty => f.write_str("scope project cannot be empty"),
            ScopeResolutionError::AmbiguousUnscopedWrite => f.write_str(AMBIGUOUS_UNSCOPED_WRITE),
            ScopeResolutionError::TooManyScopes { max, .. } => {
                write!(f, "at most {max} scopes are allowed")
            }
            ScopeResolutionError::WorkspaceNotFound { workspace } => {
                write!(f, "workspace '{workspace}' not found")
            }
            ScopeResolutionError::ProjectNotFoundInWorkspace { workspace, project } => {
                write!(
                    f,
                    "project '{project}' not found in workspace '{workspace}'"
                )
            }
            ScopeResolutionError::ProjectNotFoundInActiveOrDefault { project } => {
                write!(
                    f,
                    "project '{project}' not found in the active or default workspace"
                )
            }
            ScopeResolutionError::WriterRequired => {
                f.write_str("scope resolver requires a writer for create-on-write resolution")
            }
            ScopeResolutionError::Store(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for ScopeResolutionError {}

impl From<StoreError> for ScopeResolutionError {
    fn from(value: StoreError) -> Self {
        ScopeResolutionError::Store(value.to_string())
    }
}

/// Resolves workspace/project names according to the policy requested by the
/// caller. Construct per request; it only borrows existing handles.
pub struct ScopeResolver<'a> {
    reader: &'a ReaderPool,
    writer: Option<&'a WriterHandle>,
    active_project: Option<&'a ActiveProject>,
    default_workspace_id: WorkspaceId,
    default_project_id: ProjectId,
    viewer: Option<ai_memory_core::UserId>,
}

/// Look up an explicit workspace/project pair without creating anything.
///
/// This free function serves surfaces like admin/web routes that do not have a
/// current-project default. [`ScopeResolver::lookup_existing`] delegates here.
///
/// Crate-private on purpose: resolving a repository outside this crate must go
/// through [`lookup_existing_scope_guarded`], so a caller cannot reach a
/// repository without stating which user is asking and what they need (#708).
/// The compiler enforces that; a review convention would not.
pub(crate) async fn lookup_existing_scope(
    reader: &ReaderPool,
    workspace: &str,
    project: &str,
) -> Result<ResolvedScope, ScopeResolutionError> {
    let workspace_id = lookup_existing_workspace(reader, workspace).await?;
    let project_id = reader
        .find_project(workspace_id, project.to_owned())
        .await?
        .ok_or_else(|| ScopeResolutionError::ProjectNotFoundInWorkspace {
            workspace: workspace.to_owned(),
            project: project.to_owned(),
        })?;
    Ok(ResolvedScope {
        workspace_id,
        project_id,
    })
}

/// Look up an explicit workspace by name without creating anything.
///
/// This is for admin/destructive surfaces that operate at workspace granularity
/// and must fail closed on typos instead of auto-creating a scope.
///
/// Deliberately left public and unguarded: a grant is held against a
/// repository, and this returns a workspace id, which is not one. Every path
/// that goes on to touch a project inside the workspace still has to resolve
/// that project through a guarded function, so nothing is reachable from a
/// bare workspace id that the guard would otherwise refuse.
pub async fn lookup_existing_workspace(
    reader: &ReaderPool,
    workspace: &str,
) -> Result<WorkspaceId, ScopeResolutionError> {
    reader
        .find_workspace(workspace.to_owned())
        .await?
        .ok_or_else(|| ScopeResolutionError::WorkspaceNotFound {
            workspace: workspace.to_owned(),
        })
}

/// Authorize a resolved scope, or explain why not (#708).
///
/// `authorized_user` is `None` when authorization is off, or when the caller is
/// the operator's root token — both mean "no per-repository check applies", and
/// both must keep working exactly as before this existed. That is what lets
/// this land without changing the behaviour of every install that has one user.
///
/// # Errors
/// [`ScopeResolutionError::NotAuthorized`] when the user holds nothing on this
/// repository, or holds less than `required`. Propagates store errors.
pub async fn authorize_scope(
    reader: &ReaderPool,
    scope: ResolvedScope,
    authorized_user: Option<ai_memory_core::UserId>,
    required: ai_memory_auth::GrantRole,
    repository_label: &str,
) -> Result<ResolvedScope, ScopeResolutionError> {
    let Some(user) = authorized_user else {
        return Ok(scope);
    };
    let grants = reader.grants_for(user, scope.project_id).await?;
    match ai_memory_auth::decide(&grants, user, scope.project_id, required) {
        ai_memory_auth::Access::Granted => Ok(scope),
        ai_memory_auth::Access::Denied(denial) => {
            let held = match denial {
                ai_memory_auth::Denial::InsufficientRole { held, .. } => Some(held),
                _ => None,
            };
            Err(ScopeResolutionError::NotAuthorized {
                repository: repository_label.to_string(),
                held,
                required,
            })
        }
    }
}

/// [`lookup_existing_scope`] with the authorization check applied.
///
/// # Errors
/// As [`lookup_existing_scope`], plus [`ScopeResolutionError::NotAuthorized`].
pub async fn lookup_existing_scope_guarded(
    reader: &ReaderPool,
    workspace: &str,
    project: &str,
    authorized_user: Option<ai_memory_core::UserId>,
    required: ai_memory_auth::GrantRole,
) -> Result<ResolvedScope, ScopeResolutionError> {
    let scope = lookup_existing_scope(reader, workspace, project).await?;
    authorize_scope(reader, scope, authorized_user, required, project).await
}

/// [`create_explicit_scope`] with the authorization check applied.
///
/// Creating is a two-shape operation and the two shapes authorize differently:
///
/// - The repository already exists: the user must hold `required` on it, the
///   same as any other write. Otherwise "create" would be a way to reach a
///   repository the guard would have refused on the read path.
/// - The repository does not exist yet: there is nothing to hold a grant on,
///   so creation proceeds. Note the creator does not receive a grant here —
///   there is no grant *write* path in the store yet, so on an install with
///   authorization enabled the creator cannot read back what they just made.
///   The enable/grant-admin work closes that; until it lands nobody can be in
///   that state, because nothing can enable authorization.
///
/// # Errors
/// As [`create_explicit_scope`], plus [`ScopeResolutionError::NotAuthorized`].
pub async fn create_explicit_scope_guarded(
    reader: &ReaderPool,
    writer: &WriterHandle,
    workspace: &str,
    project: &str,
    authorized_user: Option<ai_memory_core::UserId>,
    required: ai_memory_auth::GrantRole,
) -> Result<ResolvedScope, ScopeResolutionError> {
    match lookup_existing_scope(reader, workspace, project).await {
        Ok(existing) => {
            authorize_scope(reader, existing, authorized_user, required, project).await?;
        }
        // A repository that is not there yet cannot carry a grant. Any other
        // failure is a real store problem and must not be read as "absent".
        Err(err) if err.is_not_found() => {}
        Err(err) => return Err(err),
    }
    create_explicit_scope(writer, workspace, project).await
}

/// [`resolve_many_existing_scopes`] with the authorization check applied to
/// every scope.
///
/// A denied scope fails the whole call rather than being dropped from the
/// result. Silently returning the permitted subset would answer a
/// cross-repository search with a short list that looks like "nothing was
/// found there" — authorization must never be indistinguishable from empty
/// memory.
///
/// # Errors
/// As [`resolve_many_existing_scopes`], plus
/// [`ScopeResolutionError::NotAuthorized`] naming the first refused repository.
pub async fn resolve_many_existing_scopes_guarded(
    reader: &ReaderPool,
    scopes: &[ScopeName],
    max: usize,
    authorized_user: Option<ai_memory_core::UserId>,
    required: ai_memory_auth::GrantRole,
) -> Result<Vec<ResolvedScope>, ScopeResolutionError> {
    let resolved = resolve_many_existing_scopes_labelled(reader, scopes, max).await?;
    if authorized_user.is_none() {
        return Ok(resolved.into_iter().map(|(_, ids)| ids).collect());
    }
    let mut authorized = Vec::with_capacity(resolved.len());
    for (label, ids) in resolved {
        authorize_scope(reader, ids, authorized_user, required, &label).await?;
        authorized.push(ids);
    }
    Ok(authorized)
}

/// Create or fetch an explicit workspace/project pair.
///
/// This is the only helper that may create a scope, and should only be used by
/// write-style paths whose public contract says they create missing projects.
///
/// Crate-private for the same reason as [`lookup_existing_scope`]: outside this
/// crate the door is [`create_explicit_scope_guarded`].
pub(crate) async fn create_explicit_scope(
    writer: &WriterHandle,
    workspace: &str,
    project: &str,
) -> Result<ResolvedScope, ScopeResolutionError> {
    let workspace_id = writer.get_or_create_workspace(workspace.to_owned()).await?;
    let project_id = writer
        .get_or_create_project(workspace_id, project.to_owned(), None)
        .await?;
    Ok(ResolvedScope {
        workspace_id,
        project_id,
    })
}

/// Look up the reserved global preferences scope
/// ([`ai_memory_core::GLOBAL_SCOPE_PROJECT`] in the default workspace)
/// without creating it. Returns `Ok(None)` when it doesn't exist yet — the
/// scope participates in default reads by existence, so an absent scope
/// means "nothing to union in", never an error (issue #154).
///
/// Deliberately left public and unguarded, together with
/// [`create_global_scope`]: the global scope is the one repository that is
/// shared by construction. It is unioned into everybody's default reads, so
/// requiring a grant on it would mean every user needs an explicit grant to
/// the shared layer before memory works at all. Per-repository authorization
/// is about the project scopes; the global preferences scope is common ground.
///
/// # Errors
/// Propagates store failures only; a missing workspace or project is `None`.
pub async fn lookup_global_scope(
    reader: &ReaderPool,
) -> Result<Option<ResolvedScope>, ScopeResolutionError> {
    let Some(workspace_id) = reader
        .find_workspace(ai_memory_core::DEFAULT_WORKSPACE_NAME.to_owned())
        .await?
    else {
        return Ok(None);
    };
    let Some(project_id) = reader
        .find_project(
            workspace_id,
            ai_memory_core::GLOBAL_SCOPE_PROJECT.to_owned(),
        )
        .await?
    else {
        return Ok(None);
    };
    Ok(Some(ResolvedScope {
        workspace_id,
        project_id,
    }))
}

/// Create or fetch the reserved global preferences scope. Write-path only —
/// the counterpart of [`lookup_global_scope`] for `scope: "global"` writes.
///
/// # Errors
/// Propagates store failures.
pub async fn create_global_scope(
    writer: &WriterHandle,
) -> Result<ResolvedScope, ScopeResolutionError> {
    create_explicit_scope(
        writer,
        ai_memory_core::DEFAULT_WORKSPACE_NAME,
        ai_memory_core::GLOBAL_SCOPE_PROJECT,
    )
    .await
}

/// Resolve and de-duplicate an explicit multi-scope list, keeping the project
/// name each scope was asked for.
///
/// De-duplication drops entries, so the result cannot be zipped back against
/// the input names — an authorization refusal that named the wrong repository
/// would be worse than no name at all. Carrying the label through is the only
/// way to report the refusal against what the caller actually typed.
async fn resolve_many_existing_scopes_labelled(
    reader: &ReaderPool,
    scopes: &[ScopeName],
    max: usize,
) -> Result<Vec<(String, ResolvedScope)>, ScopeResolutionError> {
    if scopes.len() > max {
        return Err(ScopeResolutionError::TooManyScopes {
            max,
            actual: scopes.len(),
        });
    }
    let mut seen = HashSet::new();
    let mut resolved = Vec::new();
    for scope in scopes {
        let workspace =
            trimmed_opt(Some(&scope.workspace)).ok_or(ScopeResolutionError::ScopeWorkspaceEmpty)?;
        let project =
            trimmed_opt(Some(&scope.project)).ok_or(ScopeResolutionError::ScopeProjectEmpty)?;
        let ids = lookup_existing_scope(reader, workspace, project).await?;
        if seen.insert(ids) {
            resolved.push((project.to_owned(), ids));
        }
    }
    Ok(resolved)
}

impl<'a> ScopeResolver<'a> {
    /// Build a resolver for read-only policies, as a given viewer.
    ///
    /// `viewer` is deliberately a constructor argument rather than a
    /// `with_viewer` builder step. A builder step that is forgotten leaves the
    /// resolver silently unauthorized; an argument that is forgotten does not
    /// compile. Every method below authorizes its result against this user
    /// before returning it, including the branches that fall back to the
    /// current or default project without looking anything up — those reach a
    /// repository too.
    ///
    /// `None` means no per-repository check applies: authorization is off, or
    /// the caller is the operator's root token, which authenticates from
    /// configuration rather than a `users` row.
    #[must_use]
    pub fn new(
        reader: &'a ReaderPool,
        default_workspace_id: WorkspaceId,
        default_project_id: ProjectId,
        viewer: Option<ai_memory_core::UserId>,
    ) -> Self {
        Self {
            reader,
            writer: None,
            active_project: None,
            default_workspace_id,
            default_project_id,
            viewer,
        }
    }

    /// Authorize a scope this resolver is about to hand back.
    ///
    /// `label` is the name the caller typed, when there was one. A fallback
    /// resolution has no such name, so the project's own name is fetched to
    /// build the message — on the denial path only, where one more query costs
    /// nothing and an unnameable repository would make the refusal useless.
    async fn guard(
        &self,
        scope: ResolvedScope,
        required: ai_memory_auth::GrantRole,
        label: Option<&str>,
    ) -> Result<ResolvedScope, ScopeResolutionError> {
        if self.viewer.is_none() {
            return Ok(scope);
        }
        let named;
        let label = match label {
            Some(label) => label,
            None => {
                named = self
                    .reader
                    .project_name_by_id(scope.workspace_id, scope.project_id)
                    .await?
                    .unwrap_or_else(|| "the resolved project".to_owned());
                &named
            }
        };
        authorize_scope(self.reader, scope, self.viewer, required, label).await
    }

    /// Attach the writer handle needed by create-on-write resolution.
    #[must_use]
    pub fn with_writer(mut self, writer: &'a WriterHandle) -> Self {
        self.writer = Some(writer);
        self
    }

    /// Attach the active-project map used for current-project defaults.
    #[must_use]
    pub fn with_active_project(mut self, active_project: &'a ActiveProject) -> Self {
        self.active_project = Some(active_project);
        self
    }

    /// Look up an explicit workspace/project pair without creating anything.
    /// Used by read, maintenance, and destructive paths.
    ///
    /// `required` is the role the caller's operation needs — a maintenance or
    /// destructive path asks for more than a read.
    ///
    /// # Errors
    /// As [`lookup_existing_scope`], plus
    /// [`ScopeResolutionError::NotAuthorized`].
    pub async fn lookup_existing(
        &self,
        workspace: &str,
        project: &str,
        required: ai_memory_auth::GrantRole,
    ) -> Result<ResolvedScope, ScopeResolutionError> {
        let scope = lookup_existing_scope(self.reader, workspace, project).await?;
        self.guard(scope, required, Some(project)).await
    }

    /// Resolve MCP-style read arguments: explicit pair if both names are
    /// provided, reject partial pair, otherwise use project-only lookup or the
    /// current-project/default fallback chain.
    pub async fn resolve_read_args(
        &self,
        explicit_workspace: Option<&str>,
        explicit_project: Option<&str>,
        actor: &ActorKey,
    ) -> Result<ResolvedScope, ScopeResolutionError> {
        match (
            trimmed_opt(explicit_workspace),
            trimmed_opt(explicit_project),
        ) {
            (Some(workspace), Some(project)) => {
                self.lookup_existing(workspace, project, ai_memory_auth::GrantRole::Reader)
                    .await
            }
            (Some(_), None) => Err(ScopeResolutionError::WorkspaceProjectPairRequired),
            (None, project) => self.resolve_current_or_project(project, actor).await,
        }
    }

    /// Resolve a project-only read, or the current/default project when no
    /// project was supplied.
    ///
    /// # Errors
    /// As the resolution chain, plus [`ScopeResolutionError::NotAuthorized`].
    pub async fn resolve_current_or_project(
        &self,
        explicit_project: Option<&str>,
        actor: &ActorKey,
    ) -> Result<ResolvedScope, ScopeResolutionError> {
        let scope = self
            .resolve_current_or_project_unguarded(explicit_project, actor)
            .await?;
        // Guarded here rather than at each `return` inside the chain below:
        // that chain has three exits and grows a fourth every time the
        // fallback rules change. One exit is one place to be right.
        self.guard(
            scope,
            ai_memory_auth::GrantRole::Reader,
            trimmed_opt(explicit_project),
        )
        .await
    }

    async fn resolve_current_or_project_unguarded(
        &self,
        explicit_project: Option<&str>,
        actor: &ActorKey,
    ) -> Result<ResolvedScope, ScopeResolutionError> {
        // Read path, so `get_for_read`: it adds the startup seed for a caller
        // the pointer knows nothing about, which is every caller in the window
        // between a restart and the first hook event (#678). `resolve_write_args`
        // below deliberately stays on `get_for` / `lookup_for` — a write must
        // not be attributed to a project reconstructed from history the caller
        // never named.
        let active = self.active_project.and_then(|a| a.get_for_read(actor));
        if let Some(project) = trimmed_opt(explicit_project) {
            if let Some((active_ws, _)) = active
                && let Some(project_id) = self
                    .reader
                    .find_project(active_ws, project.to_owned())
                    .await?
            {
                return Ok(ResolvedScope {
                    workspace_id: active_ws,
                    project_id,
                });
            }
            if active.map(|(ws, _)| ws) != Some(self.default_workspace_id)
                && let Some(project_id) = self
                    .reader
                    .find_project(self.default_workspace_id, project.to_owned())
                    .await?
            {
                return Ok(ResolvedScope {
                    workspace_id: self.default_workspace_id,
                    project_id,
                });
            }
            return Err(ScopeResolutionError::ProjectNotFoundInActiveOrDefault {
                project: project.to_owned(),
            });
        }
        let (workspace_id, project_id) =
            active.unwrap_or((self.default_workspace_id, self.default_project_id));
        Ok(ResolvedScope {
            workspace_id,
            project_id,
        })
    }

    /// Resolve a write target. Explicit names may create the workspace/project;
    /// absence means current-project/default. Partial explicit scopes fail.
    pub async fn resolve_write_args(
        &self,
        explicit_workspace: Option<&str>,
        explicit_project: Option<&str>,
        actor: &ActorKey,
    ) -> Result<ResolvedScope, ScopeResolutionError> {
        let Some(project) = trimmed_opt(explicit_project) else {
            if trimmed_opt(explicit_workspace).is_some() {
                return Err(ScopeResolutionError::WorkspaceProjectPairRequired);
            }
            // #564: a caller carrying a coordinate that resolves to nothing is not
            // asking for the server default — it is a mismatch, and the page it
            // writes would be real, attributed, searchable, and in a project nobody
            // looks in. Refuse and name the two fixes. Callers with no coordinate at
            // all (anonymous/legacy) keep resolving through the default as before.
            let (workspace_id, project_id) = match self.active_project.map(|a| a.lookup_for(actor))
            {
                Some(ActiveProjectLookup::Resolved(workspace_id, project_id)) => {
                    (workspace_id, project_id)
                }
                Some(ActiveProjectLookup::Mismatch) => {
                    return Err(ScopeResolutionError::AmbiguousUnscopedWrite);
                }
                Some(ActiveProjectLookup::Unset) | None => {
                    (self.default_workspace_id, self.default_project_id)
                }
            };
            // A fallback resolution reaches a repository just as an explicit
            // name does, so it is authorized just the same. The label comes
            // from the project row, since the caller never named it.
            return self
                .guard(
                    ResolvedScope {
                        workspace_id,
                        project_id,
                    },
                    ai_memory_auth::GrantRole::Writer,
                    None,
                )
                .await;
        };
        let Some(writer) = self.writer else {
            return Err(ScopeResolutionError::WriterRequired);
        };
        let active = self.active_project.and_then(|a| a.get_for(actor));
        let workspace_id = match trimmed_opt(explicit_workspace) {
            Some(workspace) => writer.get_or_create_workspace(workspace.to_owned()).await?,
            None => active
                .map(|(workspace_id, _)| workspace_id)
                .unwrap_or(self.default_workspace_id),
        };
        // Authorize before creating, and only when there is something to
        // authorize against: a write to an existing repository is checked
        // exactly as a read of it would be, so "create" cannot be a way in.
        // A project that does not exist yet holds no grant — see
        // [`create_explicit_scope_guarded`] for why that is allowed and what
        // still has to close behind it.
        if let Some(existing) = self
            .reader
            .find_project(workspace_id, project.to_owned())
            .await?
        {
            self.guard(
                ResolvedScope {
                    workspace_id,
                    project_id: existing,
                },
                ai_memory_auth::GrantRole::Writer,
                Some(project),
            )
            .await?;
        }
        let project_id = writer
            .get_or_create_project(workspace_id, project.to_owned(), None)
            .await?;
        Ok(ResolvedScope {
            workspace_id,
            project_id,
        })
    }

    /// Resolve and de-duplicate an explicit multi-scope list.
    ///
    /// # Errors
    /// As [`resolve_many_existing_scopes_guarded`] — a scope the viewer cannot
    /// read fails the call rather than being dropped from the result.
    pub async fn resolve_many_existing(
        &self,
        scopes: &[ScopeName],
        max: usize,
    ) -> Result<Vec<ResolvedScope>, ScopeResolutionError> {
        resolve_many_existing_scopes_guarded(
            self.reader,
            scopes,
            max,
            self.viewer,
            ai_memory_auth::GrantRole::Reader,
        )
        .await
    }
}

fn trimmed_opt(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Store;

    use ai_memory_auth::GrantRole;
    use ai_memory_core::NewUser;

    /// Insert a grant row directly.
    ///
    /// The store has no grant *write* path yet — that lands with the admin
    /// grant endpoints — so the guard would otherwise be untestable, and an
    /// untested guard is a claim rather than a control. Writing the row by
    /// hand also keeps these tests honest about the schema: they fail if
    /// V62's shape changes under them.
    fn grant_row(
        db: &std::path::Path,
        user: ai_memory_core::UserId,
        repository: ProjectId,
        role: &str,
        revoked_by: Option<ai_memory_core::UserId>,
    ) {
        let conn = rusqlite::Connection::open(db).unwrap();
        conn.execute(
            "INSERT INTO memory_grant \
             (id, user_id, repository_id, role, granted_by_user_id, granted_at, \
              revoked_at, revoked_by_user_id) \
             VALUES (?1, ?2, ?3, ?4, ?2, 1, ?5, ?6)",
            rusqlite::params![
                ai_memory_core::ids::MemoryGrantId::new()
                    .as_bytes()
                    .to_vec(),
                user.as_bytes().to_vec(),
                repository.as_bytes().to_vec(),
                role,
                revoked_by.map(|_| 2_i64),
                revoked_by.map(|id| id.as_bytes().to_vec()),
            ],
        )
        .unwrap();
    }

    async fn user_named(store: &Store, username: &str, byte: u8) -> ai_memory_core::UserId {
        store
            .writer
            .create_user(
                NewUser {
                    username: username.to_owned(),
                    name: None,
                    email: None,
                },
                [byte; crate::TOKEN_HASH_LEN],
            )
            .await
            .unwrap()
    }

    /// A repository plus two users, one of whom will hold nothing on it.
    async fn guard_fixture(
        store: &Store,
    ) -> (
        WorkspaceId,
        ProjectId,
        ai_memory_core::UserId,
        ai_memory_core::UserId,
    ) {
        let ws = store
            .writer
            .get_or_create_workspace("default")
            .await
            .unwrap();
        let project = store
            .writer
            .get_or_create_project(ws, "client-work", None)
            .await
            .unwrap();
        let alice = user_named(store, "alice", 1).await;
        let bob = user_named(store, "bob", 2).await;
        (ws, project, alice, bob)
    }

    #[tokio::test]
    async fn an_absent_user_is_the_unauthorized_install_and_still_resolves() {
        // Authorization off, and the operator's root token, both arrive here
        // as `None`. Neither may change behaviour, or enabling this crate
        // would break every install that has one user.
        let tmp = tempfile::TempDir::new().unwrap();
        let store = Store::open(tmp.path()).unwrap();
        let (ws, project, _, _) = guard_fixture(&store).await;

        let scope = lookup_existing_scope_guarded(
            &store.reader,
            "default",
            "client-work",
            None,
            GrantRole::Admin,
        )
        .await
        .unwrap();
        assert_eq!(
            scope,
            ResolvedScope {
                workspace_id: ws,
                project_id: project
            }
        );
    }

    #[tokio::test]
    async fn a_user_reaches_only_what_they_were_granted() {
        let tmp = tempfile::TempDir::new().unwrap();
        let store = Store::open(tmp.path()).unwrap();
        let (_, project, alice, bob) = guard_fixture(&store).await;
        grant_row(store.db_path(), alice, project, "writer", None);

        // Alice holds writer: reader and writer pass, admin does not.
        for required in [GrantRole::Reader, GrantRole::Writer] {
            lookup_existing_scope_guarded(
                &store.reader,
                "default",
                "client-work",
                Some(alice),
                required,
            )
            .await
            .unwrap();
        }
        let err = lookup_existing_scope_guarded(
            &store.reader,
            "default",
            "client-work",
            Some(alice),
            GrantRole::Admin,
        )
        .await
        .unwrap_err();
        assert_eq!(
            err,
            ScopeResolutionError::NotAuthorized {
                repository: "client-work".to_owned(),
                held: Some(GrantRole::Writer),
                required: GrantRole::Admin,
            }
        );

        // Bob holds nothing. The refusal must say so — not resolve to an
        // empty repository, which would read as "there is nothing here".
        let err = lookup_existing_scope_guarded(
            &store.reader,
            "default",
            "client-work",
            Some(bob),
            GrantRole::Reader,
        )
        .await
        .unwrap_err();
        assert_eq!(
            err,
            ScopeResolutionError::NotAuthorized {
                repository: "client-work".to_owned(),
                held: None,
                required: GrantRole::Reader,
            }
        );
    }

    #[tokio::test]
    async fn creating_authorizes_against_a_repository_that_already_exists() {
        let tmp = tempfile::TempDir::new().unwrap();
        let store = Store::open(tmp.path()).unwrap();
        let (ws, project, alice, bob) = guard_fixture(&store).await;
        grant_row(store.db_path(), alice, project, "reader", None);

        // "Create" must not be a way around the read guard: the project is
        // already there, so Bob's write is refused exactly as a read would be.
        let err = create_explicit_scope_guarded(
            &store.reader,
            &store.writer,
            "default",
            "client-work",
            Some(bob),
            GrantRole::Writer,
        )
        .await
        .unwrap_err();
        assert!(matches!(
            err,
            ScopeResolutionError::NotAuthorized { held: None, .. }
        ));

        // Alice holds reader, which does not cover a write.
        let err = create_explicit_scope_guarded(
            &store.reader,
            &store.writer,
            "default",
            "client-work",
            Some(alice),
            GrantRole::Writer,
        )
        .await
        .unwrap_err();
        assert!(matches!(
            err,
            ScopeResolutionError::NotAuthorized {
                held: Some(GrantRole::Reader),
                ..
            }
        ));

        // A repository that does not exist yet cannot carry a grant, so
        // creating it proceeds.
        let fresh = create_explicit_scope_guarded(
            &store.reader,
            &store.writer,
            "default",
            "brand-new",
            Some(bob),
            GrantRole::Writer,
        )
        .await
        .unwrap();
        assert_eq!(fresh.workspace_id, ws);
        assert_ne!(fresh.project_id, project);
    }

    #[tokio::test]
    async fn a_refused_scope_fails_the_search_instead_of_shortening_it() {
        let tmp = tempfile::TempDir::new().unwrap();
        let store = Store::open(tmp.path()).unwrap();
        let (ws, granted, alice, _) = guard_fixture(&store).await;
        let refused = store
            .writer
            .get_or_create_project(ws, "other-team", None)
            .await
            .unwrap();
        grant_row(store.db_path(), alice, granted, "reader", None);

        let names = vec![
            ScopeName::new("default", "client-work"),
            ScopeName::new("default", "other-team"),
        ];
        let err = resolve_many_existing_scopes_guarded(
            &store.reader,
            &names,
            25,
            Some(alice),
            GrantRole::Reader,
        )
        .await
        .unwrap_err();
        // Named against what the caller typed, not the id it resolved to.
        assert_eq!(
            err,
            ScopeResolutionError::NotAuthorized {
                repository: "other-team".to_owned(),
                held: None,
                required: GrantRole::Reader,
            }
        );
        assert_ne!(granted, refused);

        // Every scope granted: the call succeeds and de-duplication still
        // applies, so the labels cannot be zipped back positionally.
        grant_row(store.db_path(), alice, refused, "reader", None);
        let resolved = resolve_many_existing_scopes_guarded(
            &store.reader,
            &[
                ScopeName::new("default", "client-work"),
                ScopeName::new("default", "client-work"),
                ScopeName::new("default", "other-team"),
            ],
            25,
            Some(alice),
            GrantRole::Reader,
        )
        .await
        .unwrap();
        assert_eq!(resolved.len(), 2);
    }

    #[tokio::test]
    async fn a_revoked_grant_denies_and_does_not_read_as_never_granted() {
        let tmp = tempfile::TempDir::new().unwrap();
        let store = Store::open(tmp.path()).unwrap();
        let (_, project, alice, bob) = guard_fixture(&store).await;
        grant_row(store.db_path(), alice, project, "admin", Some(bob));

        let err = lookup_existing_scope_guarded(
            &store.reader,
            "default",
            "client-work",
            Some(alice),
            GrantRole::Reader,
        )
        .await
        .unwrap_err();
        assert_eq!(
            err,
            ScopeResolutionError::NotAuthorized {
                repository: "client-work".to_owned(),
                held: None,
                required: GrantRole::Reader,
            }
        );
    }

    /// The global scope is shared ground and stays reachable without a grant.
    #[tokio::test]
    async fn the_global_scope_needs_no_grant() {
        let tmp = tempfile::TempDir::new().unwrap();
        let store = Store::open(tmp.path()).unwrap();
        let (_, _, _, bob) = guard_fixture(&store).await;
        let global = create_global_scope(&store.writer).await.unwrap();
        assert!(
            lookup_global_scope(&store.reader)
                .await
                .unwrap()
                .is_some_and(|found| found == global)
        );
        // Bob holds nothing anywhere, and still shares the global layer.
        let _ = bob;
    }

    #[tokio::test]
    async fn read_args_reject_partial_scope() {
        let tmp = tempfile::TempDir::new().unwrap();
        let store = Store::open(tmp.path()).unwrap();
        let ws = store
            .writer
            .get_or_create_workspace("default")
            .await
            .unwrap();
        let project = store
            .writer
            .get_or_create_project(ws, "scratch", None)
            .await
            .unwrap();
        let resolver = ScopeResolver::new(&store.reader, ws, project, None);
        let err = resolver
            .resolve_read_args(Some("default"), None, &ActorKey::default())
            .await
            .unwrap_err();
        assert_eq!(err, ScopeResolutionError::WorkspaceProjectPairRequired);
        assert_eq!(err.to_string(), WORKSPACE_PROJECT_PAIR_REQUIRED);
    }

    #[tokio::test]
    async fn project_only_read_prefers_active_workspace_then_default() {
        let tmp = tempfile::TempDir::new().unwrap();
        let store = Store::open(tmp.path()).unwrap();
        let default_ws = store
            .writer
            .get_or_create_workspace("default")
            .await
            .unwrap();
        let default_scratch = store
            .writer
            .get_or_create_project(default_ws, "scratch", None)
            .await
            .unwrap();
        let active_ws = store.writer.get_or_create_workspace("team").await.unwrap();
        let active_scratch = store
            .writer
            .get_or_create_project(active_ws, "scratch", None)
            .await
            .unwrap();
        let active_project = ActiveProject::new();
        let actor = ActorKey {
            user: Some("alice".into()),
            session_id: Some("s1".into()),
        };
        active_project.set_for(&actor, active_ws, active_scratch, false);

        let resolver = ScopeResolver::new(&store.reader, default_ws, default_scratch, None)
            .with_active_project(&active_project);
        let scope = resolver
            .resolve_read_args(None, Some("scratch"), &actor)
            .await
            .unwrap();
        assert_eq!(scope.as_tuple(), (active_ws, active_scratch));

        let err = resolver
            .resolve_read_args(None, Some("missing"), &actor)
            .await
            .unwrap_err();
        assert_eq!(
            err,
            ScopeResolutionError::ProjectNotFoundInActiveOrDefault {
                project: "missing".into()
            }
        );
    }

    #[tokio::test]
    async fn write_args_create_project_in_active_workspace() {
        let tmp = tempfile::TempDir::new().unwrap();
        let store = Store::open(tmp.path()).unwrap();
        let default_ws = store
            .writer
            .get_or_create_workspace("default")
            .await
            .unwrap();
        let default_project = store
            .writer
            .get_or_create_project(default_ws, "scratch", None)
            .await
            .unwrap();
        let active_ws = store.writer.get_or_create_workspace("team").await.unwrap();
        let active_project_id = store
            .writer
            .get_or_create_project(active_ws, "current", None)
            .await
            .unwrap();
        let active_project = ActiveProject::new();
        let actor = ActorKey {
            user: None,
            session_id: Some("s1".into()),
        };
        active_project.set_for(&actor, active_ws, active_project_id, false);
        let resolver = ScopeResolver::new(&store.reader, default_ws, default_project, None)
            .with_writer(&store.writer)
            .with_active_project(&active_project);

        let created = resolver
            .resolve_write_args(None, Some("new-project"), &actor)
            .await
            .unwrap();
        assert_eq!(created.workspace_id, active_ws);
        assert!(
            store
                .reader
                .find_project(default_ws, "new-project".into())
                .await
                .unwrap()
                .is_none(),
            "project-only writes must not recreate the baked default workspace"
        );
        assert_eq!(
            store
                .reader
                .find_project(active_ws, "new-project".into())
                .await
                .unwrap(),
            Some(created.project_id)
        );
    }

    #[tokio::test]
    async fn multi_scope_resolution_deduplicates_and_validates() {
        let tmp = tempfile::TempDir::new().unwrap();
        let store = Store::open(tmp.path()).unwrap();
        let ws = store
            .writer
            .get_or_create_workspace("default")
            .await
            .unwrap();
        let project = store
            .writer
            .get_or_create_project(ws, "scratch", None)
            .await
            .unwrap();
        let resolver = ScopeResolver::new(&store.reader, ws, project, None);
        let scopes = vec![
            ScopeName::new("default", "scratch"),
            ScopeName::new(" default ", " scratch "),
        ];
        let resolved = resolver.resolve_many_existing(&scopes, 25).await.unwrap();
        assert_eq!(
            resolved,
            vec![ResolvedScope {
                workspace_id: ws,
                project_id: project
            }]
        );

        let err = resolver
            .resolve_many_existing(&[ScopeName::new("", "scratch")], 25)
            .await
            .unwrap_err();
        assert_eq!(err, ScopeResolutionError::ScopeWorkspaceEmpty);

        let err = resolver
            .resolve_many_existing(
                &[
                    ScopeName::new("default", "scratch"),
                    ScopeName::new("default", "scratch"),
                ],
                1,
            )
            .await
            .unwrap_err();
        assert_eq!(
            err,
            ScopeResolutionError::TooManyScopes { max: 1, actual: 2 }
        );
    }

    #[tokio::test]
    async fn global_scope_lookup_is_none_until_created_then_stable() {
        let tmp = tempfile::TempDir::new().unwrap();
        let store = Store::open(tmp.path()).unwrap();

        // Reads never materialise the reserved scope.
        assert_eq!(lookup_global_scope(&store.reader).await.unwrap(), None);
        assert_eq!(
            lookup_global_scope(&store.reader).await.unwrap(),
            None,
            "lookup must stay a pure read"
        );

        // The write path creates it once; lookup then resolves the same ids.
        let created = create_global_scope(&store.writer).await.unwrap();
        let looked_up = lookup_global_scope(&store.reader).await.unwrap();
        assert_eq!(looked_up, Some(created));

        // Idempotent create.
        let again = create_global_scope(&store.writer).await.unwrap();
        assert_eq!(again, created);
    }

    /// Expected outcome for one table-driven read-resolution row.
    #[derive(Debug)]
    enum Expected {
        Resolved(WorkspaceId, ProjectId),
        Failed(ScopeResolutionError),
    }

    struct ReadCase {
        name: &'static str,
        workspace: Option<&'static str>,
        project: Option<&'static str>,
        active: Option<(WorkspaceId, ProjectId)>,
        expected: Expected,
    }

    /// AGENTS.md mandates a table-driven suite over the scope-resolution
    /// policies: partial scope, missing explicit scope, active-project
    /// precedence, and cross-workspace isolation. One fixture with two
    /// workspaces carrying a same-named project feeds every row.
    #[tokio::test]
    async fn read_resolution_table_driven() {
        let tmp = tempfile::TempDir::new().unwrap();
        let store = Store::open(tmp.path()).unwrap();

        let default_ws = store
            .writer
            .get_or_create_workspace("default")
            .await
            .unwrap();
        let default_scratch = store
            .writer
            .get_or_create_project(default_ws, "scratch", None)
            .await
            .unwrap();
        let alpha_ws = store.writer.get_or_create_workspace("alpha").await.unwrap();
        let alpha_app = store
            .writer
            .get_or_create_project(alpha_ws, "app", None)
            .await
            .unwrap();
        let alpha_shared = store
            .writer
            .get_or_create_project(alpha_ws, "shared", None)
            .await
            .unwrap();
        let beta_ws = store.writer.get_or_create_workspace("beta").await.unwrap();
        let beta_shared = store
            .writer
            .get_or_create_project(beta_ws, "shared", None)
            .await
            .unwrap();
        let beta_other = store
            .writer
            .get_or_create_project(beta_ws, "other", None)
            .await
            .unwrap();
        assert_ne!(
            alpha_shared, beta_shared,
            "same-named projects must get distinct ids per workspace"
        );

        let cases = vec![
            // --- Partial scope fails closed ---
            ReadCase {
                name: "workspace without project is rejected",
                workspace: Some("alpha"),
                project: None,
                active: Some((alpha_ws, alpha_app)),
                expected: Expected::Failed(ScopeResolutionError::WorkspaceProjectPairRequired),
            },
            ReadCase {
                name: "project-only read does not scan every workspace",
                workspace: None,
                project: Some("app"), // exists only in alpha; no active pointer
                active: None,
                expected: Expected::Failed(
                    ScopeResolutionError::ProjectNotFoundInActiveOrDefault {
                        project: "app".into(),
                    },
                ),
            },
            ReadCase {
                name: "project-only read of a missing project fails closed",
                workspace: None,
                project: Some("ghost"),
                active: Some((alpha_ws, alpha_app)),
                expected: Expected::Failed(
                    ScopeResolutionError::ProjectNotFoundInActiveOrDefault {
                        project: "ghost".into(),
                    },
                ),
            },
            // --- Missing explicit scope errors without creating ---
            ReadCase {
                name: "missing workspace errors",
                workspace: Some("ghost"),
                project: Some("app"),
                active: None,
                expected: Expected::Failed(ScopeResolutionError::WorkspaceNotFound {
                    workspace: "ghost".into(),
                }),
            },
            ReadCase {
                name: "missing project in existing workspace errors",
                workspace: Some("alpha"),
                project: Some("ghost"),
                active: Some((alpha_ws, alpha_app)),
                expected: Expected::Failed(ScopeResolutionError::ProjectNotFoundInWorkspace {
                    workspace: "alpha".into(),
                    project: "ghost".into(),
                }),
            },
            // --- Active-project precedence ---
            ReadCase {
                name: "explicit pair beats active project",
                workspace: Some("beta"),
                project: Some("other"),
                active: Some((alpha_ws, alpha_app)),
                expected: Expected::Resolved(beta_ws, beta_other),
            },
            ReadCase {
                name: "no args resolves the active project",
                workspace: None,
                project: None,
                active: Some((alpha_ws, alpha_app)),
                expected: Expected::Resolved(alpha_ws, alpha_app),
            },
            ReadCase {
                name: "no args and no active resolves the default",
                workspace: None,
                project: None,
                active: None,
                expected: Expected::Resolved(default_ws, default_scratch),
            },
            ReadCase {
                name: "whitespace-only args resolve the default",
                workspace: Some("  "),
                project: Some(" "),
                active: None,
                expected: Expected::Resolved(default_ws, default_scratch),
            },
            ReadCase {
                name: "project-only prefers the active workspace",
                workspace: None,
                project: Some("shared"),
                active: Some((alpha_ws, alpha_app)),
                expected: Expected::Resolved(alpha_ws, alpha_shared),
            },
            ReadCase {
                name: "project-only falls back to the default workspace",
                workspace: None,
                project: Some("scratch"), // exists only in default
                active: Some((alpha_ws, alpha_app)),
                expected: Expected::Resolved(default_ws, default_scratch),
            },
            // --- Cross-workspace isolation ---
            ReadCase {
                name: "shared resolves in alpha when alpha is named",
                workspace: Some("alpha"),
                project: Some("shared"),
                active: None,
                expected: Expected::Resolved(alpha_ws, alpha_shared),
            },
            ReadCase {
                name: "shared resolves in beta when beta is named",
                workspace: Some("beta"),
                project: Some("shared"),
                active: None,
                expected: Expected::Resolved(beta_ws, beta_shared),
            },
            ReadCase {
                name: "project-only with beta active stays in beta",
                workspace: None,
                project: Some("shared"),
                active: Some((beta_ws, beta_other)),
                expected: Expected::Resolved(beta_ws, beta_shared),
            },
        ];

        let actor = ActorKey {
            user: Some("alice".into()),
            session_id: Some("s1".into()),
        };
        for case in &cases {
            let active_project = ActiveProject::new();
            if let Some((ws, proj)) = case.active {
                active_project.set_for(&actor, ws, proj, false);
            }
            let resolver = ScopeResolver::new(&store.reader, default_ws, default_scratch, None)
                .with_active_project(&active_project);
            let result = resolver
                .resolve_read_args(case.workspace, case.project, &actor)
                .await;
            match (&result, &case.expected) {
                (Ok(scope), Expected::Resolved(ws, proj)) => {
                    assert_eq!(
                        scope.as_tuple(),
                        (*ws, *proj),
                        "case '{}' resolved the wrong scope",
                        case.name
                    );
                }
                (Err(err), Expected::Failed(expected)) => {
                    assert_eq!(err, expected, "case '{}' failed the wrong way", case.name);
                }
                (result, expected) => panic!(
                    "case '{}': expected {expected:?}, got {result:?}",
                    case.name
                ),
            }
        }

        // The failing read rows must not have auto-created anything.
        assert!(
            store
                .reader
                .find_workspace("ghost".into())
                .await
                .unwrap()
                .is_none(),
            "read resolution must never create workspaces"
        );
        assert!(
            store
                .reader
                .find_project(alpha_ws, "ghost".into())
                .await
                .unwrap()
                .is_none(),
            "read resolution must never create projects"
        );

        // The write-style helper is the only path that may create, and once it
        // does, the no-create lookup resolves the same ids.
        let created = create_explicit_scope(&store.writer, "ghost", "app")
            .await
            .unwrap();
        assert_eq!(
            lookup_existing_scope(&store.reader, "ghost", "app")
                .await
                .unwrap(),
            created
        );

        // Multi-scope resolution keeps same-named projects in their own
        // workspaces and fails closed when one entry is missing.
        let resolver = ScopeResolver::new(&store.reader, default_ws, default_scratch, None);
        let both = resolver
            .resolve_many_existing(
                &[
                    ScopeName::new("alpha", "shared"),
                    ScopeName::new("beta", "shared"),
                ],
                25,
            )
            .await
            .unwrap();
        assert_eq!(
            both,
            vec![
                ResolvedScope {
                    workspace_id: alpha_ws,
                    project_id: alpha_shared
                },
                ResolvedScope {
                    workspace_id: beta_ws,
                    project_id: beta_shared
                },
            ]
        );
        let err = resolver
            .resolve_many_existing(
                &[
                    ScopeName::new("alpha", "shared"),
                    ScopeName::new("beta", "ghost"),
                ],
                25,
            )
            .await
            .unwrap_err();
        assert_eq!(
            err,
            ScopeResolutionError::ProjectNotFoundInWorkspace {
                workspace: "beta".into(),
                project: "ghost".into()
            }
        );
    }

    /// Build a store with a `default/scratch` fallback plus an `ActiveProject`.
    async fn scoped_fixture(
        tmp: &tempfile::TempDir,
    ) -> (Store, WorkspaceId, ProjectId, WorkspaceId, ProjectId) {
        let store = Store::open(tmp.path()).unwrap();
        let default_ws = store
            .writer
            .get_or_create_workspace("default")
            .await
            .unwrap();
        let default_proj = store
            .writer
            .get_or_create_project(default_ws, "scratch", None)
            .await
            .unwrap();
        let team_ws = store.writer.get_or_create_workspace("team").await.unwrap();
        let team_proj = store
            .writer
            .get_or_create_project(team_ws, "real-work", None)
            .await
            .unwrap();
        (store, default_ws, default_proj, team_ws, team_proj)
    }

    #[tokio::test]
    async fn unscoped_write_with_unresolvable_coordinate_errors() {
        // #564: a caller that HAS a coordinate but whose pointer misses used to be
        // written into the server default — a real, attributed, searchable page that
        // nobody goes looking for. Refuse instead.
        let tmp = tempfile::TempDir::new().unwrap();
        let (store, default_ws, default_proj, team_ws, team_proj) = scoped_fixture(&tmp).await;

        let active_project = ActiveProject::new();
        let publisher = ActorKey {
            user: Some("alice".into()),
            session_id: Some("s1".into()),
        };
        active_project.set_for(&publisher, team_ws, team_proj, false);

        // A different operator entirely: carries a coordinate, matches nothing.
        let stranger = ActorKey {
            user: Some("bob".into()),
            session_id: Some("s9".into()),
        };

        let resolver = ScopeResolver::new(&store.reader, default_ws, default_proj, None)
            .with_writer(&store.writer)
            .with_active_project(&active_project);

        let err = resolver
            .resolve_write_args(None, None, &stranger)
            .await
            .unwrap_err();
        assert_eq!(err, ScopeResolutionError::AmbiguousUnscopedWrite);
        assert!(err.is_bad_request());
    }

    #[tokio::test]
    async fn unscoped_write_without_any_coordinate_uses_the_shared_slot() {
        // Anonymous/legacy callers resolve through the shared slot by design and must
        // keep working — the error is only for a caller that HAS a coordinate. Note
        // this resolves to the last published pointer, not the server default:
        // `set_for` writes the shared slot alongside the per-actor entry.
        let tmp = tempfile::TempDir::new().unwrap();
        let (store, default_ws, default_proj, team_ws, team_proj) = scoped_fixture(&tmp).await;

        let active_project = ActiveProject::new();
        let publisher = ActorKey {
            user: Some("alice".into()),
            session_id: Some("s1".into()),
        };
        active_project.set_for(&publisher, team_ws, team_proj, false);

        let resolver = ScopeResolver::new(&store.reader, default_ws, default_proj, None)
            .with_writer(&store.writer)
            .with_active_project(&active_project);

        let scope = resolver
            .resolve_write_args(None, None, &ActorKey::default())
            .await
            .unwrap();
        assert_eq!(scope.as_tuple(), (team_ws, team_proj));
    }

    #[tokio::test]
    async fn unscoped_write_on_an_install_with_no_pointer_uses_the_default() {
        // An install with no lifecycle hooks feeding the pointer has never keyed
        // anything and has an empty shared slot. There is no better information
        // anywhere, so the configured default stays the answer — including for a
        // caller that does carry a coordinate.
        let tmp = tempfile::TempDir::new().unwrap();
        let (store, default_ws, default_proj, _team_ws, _team_proj) = scoped_fixture(&tmp).await;

        let active_project = ActiveProject::new();
        let actor = ActorKey {
            user: Some("alice".into()),
            session_id: Some("s1".into()),
        };

        let resolver = ScopeResolver::new(&store.reader, default_ws, default_proj, None)
            .with_writer(&store.writer)
            .with_active_project(&active_project);

        let scope = resolver
            .resolve_write_args(None, None, &actor)
            .await
            .unwrap();
        assert_eq!(scope.as_tuple(), (default_ws, default_proj));
    }

    #[tokio::test]
    async fn unscoped_write_with_resolving_pointer_uses_it() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (store, default_ws, default_proj, team_ws, team_proj) = scoped_fixture(&tmp).await;

        let active_project = ActiveProject::new();
        let actor = ActorKey {
            user: Some("alice".into()),
            session_id: Some("s1".into()),
        };
        active_project.set_for(&actor, team_ws, team_proj, false);

        let resolver = ScopeResolver::new(&store.reader, default_ws, default_proj, None)
            .with_writer(&store.writer)
            .with_active_project(&active_project);

        let scope = resolver
            .resolve_write_args(None, None, &actor)
            .await
            .unwrap();
        assert_eq!(scope.as_tuple(), (team_ws, team_proj));
    }

    #[tokio::test]
    async fn unscoped_read_with_unresolvable_coordinate_still_falls_back() {
        // Reads keep the fallback: a read answering from the default project is a
        // wrong answer the caller can see; a write is a misfile they cannot.
        let tmp = tempfile::TempDir::new().unwrap();
        let (store, default_ws, default_proj, team_ws, team_proj) = scoped_fixture(&tmp).await;

        let active_project = ActiveProject::new();
        let publisher = ActorKey {
            user: Some("alice".into()),
            session_id: Some("s1".into()),
        };
        active_project.set_for(&publisher, team_ws, team_proj, false);
        let stranger = ActorKey {
            user: Some("bob".into()),
            session_id: Some("s9".into()),
        };

        let resolver = ScopeResolver::new(&store.reader, default_ws, default_proj, None)
            .with_active_project(&active_project);

        let scope = resolver
            .resolve_read_args(None, None, &stranger)
            .await
            .unwrap();
        assert_eq!(scope.as_tuple(), (default_ws, default_proj));
    }

    #[tokio::test]
    async fn the_startup_seed_answers_reads_and_never_retargets_a_write() {
        // #678: after a restart the pointer is empty, so an unscoped read
        // resolved through the baked default and reported an empty project.
        // The seed fixes the read. It must not follow into the write path:
        // `resolve_write_args` still resolves as if nothing were published, so
        // no page is attributed to a project rebuilt from someone else's
        // history.
        let tmp = tempfile::TempDir::new().unwrap();
        let (store, default_ws, default_proj, team_ws, team_proj) = scoped_fixture(&tmp).await;

        let active_project = ActiveProject::new();
        active_project.seed_read_fallback(team_ws, team_proj);

        for actor in [
            // The session that outlived the daemon: coordinate intact, keyed
            // entry gone with the process.
            ActorKey {
                user: Some("alice".into()),
                session_id: Some("s1".into()),
            },
            // And a caller with no coordinate at all.
            ActorKey::default(),
        ] {
            let read = ScopeResolver::new(&store.reader, default_ws, default_proj, None)
                .with_active_project(&active_project)
                .resolve_read_args(None, None, &actor)
                .await
                .unwrap();
            assert_eq!(
                read.as_tuple(),
                (team_ws, team_proj),
                "read must degrade to the seeded scope, not the empty default"
            );

            let write = ScopeResolver::new(&store.reader, default_ws, default_proj, None)
                .with_writer(&store.writer)
                .with_active_project(&active_project)
                .resolve_write_args(None, None, &actor)
                .await
                .unwrap();
            assert_eq!(
                write.as_tuple(),
                (default_ws, default_proj),
                "write target must be exactly what it was before the seed existed"
            );
        }

        // A named project still resolves inside the workspace the seed points
        // at — that is a find-only read, and cross-workspace isolation holds:
        // `real-work` exists only in `team`.
        let named = ScopeResolver::new(&store.reader, default_ws, default_proj, None)
            .with_active_project(&active_project)
            .resolve_read_args(None, Some("real-work"), &ActorKey::default())
            .await
            .unwrap();
        assert_eq!(named.as_tuple(), (team_ws, team_proj));
    }
}
