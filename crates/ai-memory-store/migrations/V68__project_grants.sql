-- V68: per-project grants (#708, docs/design-per-project-authz.md).
--
-- Authentication says who is asking; nothing in the schema says what they may
-- reach. `users`, `web_sessions` and `api_credentials` carry no project
-- reference, so every authenticated user reads every project. A grant is the
-- missing piece: one user, one project, one level. It only decides anything in
-- a project whose `access_mode` is `restricted` (V69); an `open` project admits
-- every authenticated user, as every project always has.
--
-- The table is the design's, as specified:
--
--   * one row per (workspace, project, user) — the primary key — so a user
--     holds at most one level on a project, and changing it is an UPDATE;
--   * `read` or `write`, `write` containing `read`. There is no per-project
--     administrator: granting is the server operator's, like every other
--     administrative act;
--   * CASCADE on the project, workspace and user: a grant never outlives what
--     it grants. A revoke is a DELETE. The record of who was granted what,
--     when and by whom lives in `audit_log`, which every grant, revoke and
--     level change writes to;
--   * `granted_by` is the `users` row behind the decision. NULL when there is
--     none — the operator used the root bearer token, which authenticates from
--     configuration, the same model as a root-token page's `author_id`. The one
--     grant that names its own grantee is the creator's: whoever creates a
--     project is granted `write` on it, and the act was theirs.
CREATE TABLE project_grants (
    workspace_id BLOB NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    project_id   BLOB NOT NULL REFERENCES projects(id)   ON DELETE CASCADE,
    user_id      BLOB NOT NULL REFERENCES users(id)      ON DELETE CASCADE,
    level        TEXT NOT NULL CHECK (level IN ('read', 'write')),
    granted_by   BLOB REFERENCES users(id) ON DELETE SET NULL,
    granted_at   INTEGER NOT NULL,
    PRIMARY KEY (workspace_id, project_id, user_id)
) WITHOUT ROWID;

-- Every authorized request asks "what does this user hold on this project";
-- the primary key leads with the workspace, so it cannot answer that alone.
CREATE INDEX idx_project_grants_user ON project_grants(user_id, project_id);
