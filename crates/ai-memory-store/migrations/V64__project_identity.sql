-- V61: give a project an identity that is not its folder name (ARD-08).
--
-- Upstream keys a project by `(workspace_id, name)`, and the name is the
-- basename of whatever directory the agent happened to run in. That is a
-- reasonable default and it fails in three ways that matter here:
--
--   * Two repositories called `api`, in different organisations, collapse into
--     one project and read each other's memory.
--   * Renaming a folder orphans its memory under the old name.
--   * `repo_path` is an absolute path, so it cannot be the thing two people on
--     two machines agree on.
--
-- The third is why this lands before authorization rather than after. A grant
-- is `(user_id, repository_id)`, so whatever resolves a working directory to a
-- `repository_id` decides who can read what. Resolving by folder name means an
-- `api/` checkout from one organisation resolves to the same row — and so the
-- same grant — as an unrelated `api/` from another. That is an access-control
-- hole, not untidiness.
--
-- Additive on purpose. `identity` defaults to empty, existing rows are
-- backfilled from the name they already have, and every existing query keeps
-- working untouched: nothing reads this column until the resolution path is
-- taught to, and the partial index below ignores rows that never are.

ALTER TABLE projects ADD COLUMN identity TEXT NOT NULL DEFAULT '';

-- Which rung of the D1 chain produced it: `explicit`, `git_remote`,
-- `manifest`, or `folder_name`. Kept because the rungs are ranked — a later
-- sighting may only ever upgrade an identity to a more trustworthy source,
-- never downgrade it, and that comparison needs to know where this one came
-- from. An empty string means no rung has claimed the row yet.
ALTER TABLE projects ADD COLUMN identity_source TEXT NOT NULL DEFAULT '';

-- Existing projects keep working under the only identity they can honestly
-- claim: the name they were created with. `folder_name` is the weakest rung,
-- so the first capture that resolves a git remote will upgrade it.
UPDATE projects
   SET identity = lower(name),
       identity_source = 'folder_name'
 WHERE identity = '';

-- Partial, so rows with no identity do not collide with each other on the
-- empty string. Two projects may share a name across workspaces, and within a
-- workspace an identity is the thing that must be unique — that is the point
-- of having it.
CREATE UNIQUE INDEX idx_projects_identity
    ON projects(workspace_id, identity)
 WHERE identity <> '';
