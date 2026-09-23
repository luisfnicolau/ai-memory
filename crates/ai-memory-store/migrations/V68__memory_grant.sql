-- V68: authorize a user against a repository (#708).
--
-- 2.1.1 authenticates and does not authorize. `users`, `web_sessions` and
-- `api_credentials` carry no reference to a project, so any account reads every
-- project on the server. Verified before writing this: two ordinary users, one
-- writes a page, the other reads its full body and finds it by search.
--
-- That is defensible for the single-operator and homelab cases the docs
-- describe. It stops being defensible the moment a server holds work for more
-- than one team, which is what this table is for.

CREATE TABLE memory_grant (
    id                    BLOB PRIMARY KEY NOT NULL,

    -- RESTRICT, not CASCADE: this table's whole purpose is to answer "who could
    -- see this, and for how long", and a cascade answers it by deleting the
    -- evidence. Upstream never deletes a `users` row — accounts are disabled —
    -- so this refuses nothing that exists today, and it makes any future code
    -- that deletes a user decide what happens to that user's access history
    -- instead of erasing it as a side effect.
    user_id               BLOB NOT NULL REFERENCES users(id)    ON DELETE RESTRICT,

    -- References `projects(id)`, the primary key — deliberately not the
    -- project's name or its identity string. Which row a working directory
    -- resolves to is a separate question (see V67); this table only needs the
    -- answer to be stable, so a change to that resolution cannot silently
    -- re-point existing grants.
    --
    -- SET NULL rather than RESTRICT or CASCADE, because upstream genuinely
    -- hard-deletes project rows: `purge-project`, `delete-workspace` (by
    -- cascade), the copy-then-purge leg of a merging `move-project`, and the
    -- scheduled hollow-project sweep. RESTRICT would make every repository
    -- that ever had a grant impossible to purge — including one being purged
    -- because it holds something that must not exist. CASCADE would erase the
    -- access history with it. SET NULL keeps the history row and lets the
    -- repository go; `repository_label` below keeps the row meaningful once
    -- the id no longer resolves.
    --
    -- What SET NULL must never do is quietly orphan access somebody still
    -- holds. The CHECK at the bottom of the table forbids an unrevoked grant
    -- without a repository, and SQLite enforces CHECK on the row the FK action
    -- rewrites — so deleting a project that still has an active grant fails in
    -- the database itself, whichever code path tries it. The operations above
    -- refuse first with a readable error, and revoke properly when the
    -- operator passes `--revoke-grants`.
    repository_id         BLOB REFERENCES projects(id) ON DELETE SET NULL,

    -- `workspace/project`, written when the grant is issued and refreshed to
    -- the name at the moment of deletion by the trigger below. Only read once
    -- `repository_id` is NULL: while the repository exists its current name is
    -- a join away, and a rename must not make an active grant look stale.
    -- When a whole workspace is deleted the workspace row is already gone as
    -- the trigger fires, so the grant-time value is what survives — which is
    -- why it is written at grant time and not only at deletion.
    repository_label      TEXT NOT NULL,

    -- `reader` < `writer` < `admin`, each containing the one below. A call site
    -- names the level an operation needs and the check is `held >= required`.
    --
    -- `admin` is scoped to this repository alone and confers nothing elsewhere.
    -- It exists so that onboarding somebody to one team's project does not
    -- require the person who runs the server; without it, every grant on every
    -- project funnels through a global `root`, which does not survive more than
    -- a handful of teams.
    --
    -- Defaults to `writer`: a grant with nothing said about it means "this
    -- person works here", which is what the common case wants.
    role                  TEXT NOT NULL DEFAULT 'writer'
                              CHECK (role IN ('reader', 'writer', 'admin')),

    -- The `users` row behind the decision, when there is one. NULL when there
    -- is not, which happens in exactly two ways and both are deliberate:
    --
    --   * the grant was seeded when authorization was switched on, preserving
    --     access that already existed rather than issuing it to anyone; and
    --   * the operator acted through the configured root bearer token, which
    --     authenticates from `config.toml` and has no `users` row at all.
    --
    -- The second is upstream's own model, not a new one: a page written with
    -- the root token carries no `author_id` either. Inventing a row, or naming
    -- the grantee as their own granter, would be a plausible-looking lie in
    -- the one table an access review reads.
    granted_by_user_id    BLOB REFERENCES users(id),
    granted_at            INTEGER NOT NULL,

    -- Revocation is a timestamp, not a DELETE. A grant records that somebody
    -- was given access, by whom, and when; deleting the row erases the answer
    -- to "who could see this, and for how long", which is the question a
    -- security review actually asks. A purge keeps its own terminal record for
    -- the same reason (`purged_scopes`); this is the grant-table equivalent.
    revoked_at            INTEGER,

    -- Who revoked it, on the same terms as `granted_by_user_id`: NULL when the
    -- operator used the root token. `revoked_at` alone decides whether a grant
    -- is in force; this column only answers "by whom", and must not be able to
    -- stop the root operator from taking access away.
    revoked_by_user_id    BLOB REFERENCES users(id),

    -- A revoker without a revocation is meaningless; the reverse is the root
    -- token, and is allowed.
    CHECK (revoked_by_user_id IS NULL OR revoked_at IS NOT NULL),

    -- A grant still in force must point at a repository. This is what turns
    -- `ON DELETE SET NULL` from "orphan the access" into "refuse the delete".
    CHECK (repository_id IS NOT NULL OR revoked_at IS NOT NULL)
);

-- Name the repository at the moment it disappears, so the history row of a
-- purged repository still says which one it was. BEFORE DELETE so the row is
-- still readable; the FK action nulls `repository_id` after this has run.
CREATE TRIGGER memory_grant_label_on_project_delete
BEFORE DELETE ON projects
BEGIN
    UPDATE memory_grant
       SET repository_label = COALESCE(
               (SELECT name FROM workspaces WHERE id = OLD.workspace_id) || '/' || OLD.name,
               repository_label)
     WHERE repository_id = OLD.id;
END;

-- Partial: one ACTIVE grant per pair, while the revoked history beside it may
-- be as long as it likes. Re-granting after a revocation is an ordinary thing
-- to do and must not collide with the record of the first grant.
CREATE UNIQUE INDEX idx_memory_grant_active
    ON memory_grant(user_id, repository_id)
 WHERE revoked_at IS NULL;

-- The read path asks "what does this user hold here" on every authorized call.
CREATE INDEX idx_memory_grant_lookup
    ON memory_grant(user_id, repository_id, revoked_at);
