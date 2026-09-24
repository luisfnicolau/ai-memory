//! Authorizing hook routes that reach a repository through an id (#708).
//!
//! Most routes name a workspace and project and go through the guarded scope
//! resolvers. Some take a managed-run or workstream id in the URL instead,
//! and an id bypasses scope resolution — and the grant check that comes with
//! it — entirely. These resolve the id to its repository first, then ask the
//! same question the resolvers ask.

use ai_memory_auth::GrantRole;
use ai_memory_core::{ProjectId, UserId, WorkspaceId};
use ai_memory_store::{ReaderPool, ResolvedScope, ScopeResolutionError, authorize_scope};

/// Authorize `viewer` for `required` on the repository an id resolved to.
///
/// `scope` is `None` when the id matched nothing. That passes: the caller goes
/// on to report "not found" exactly as it did before, so an unknown id still
/// reads as unknown rather than as a refusal. A known id in a repository the
/// viewer cannot reach is refused with the same `NotAuthorized` the resolvers
/// return — an access problem, never an empty result.
///
/// No viewer — an install with no database users, or root — passes without
/// a lookup.
pub(crate) async fn authorize_resolved(
    reader: &ReaderPool,
    scope: Option<(WorkspaceId, ProjectId)>,
    viewer: Option<UserId>,
    required: GrantRole,
) -> Result<(), ScopeResolutionError> {
    let (Some(viewer), Some((workspace_id, project_id))) = (viewer, scope) else {
        return Ok(());
    };
    let label = reader
        .project_name_by_id(workspace_id, project_id)
        .await?
        .unwrap_or_else(|| "the run's project".to_owned());
    authorize_scope(
        reader,
        ResolvedScope {
            workspace_id,
            project_id,
        },
        Some(viewer),
        required,
        &label,
    )
    .await
    .map(|_| ())
}
