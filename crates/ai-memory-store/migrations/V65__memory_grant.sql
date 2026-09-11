-- V62: authorize a user against a repository (#708).
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
    user_id               BLOB NOT NULL REFERENCES users(id)    ON DELETE CASCADE,

    -- References `projects(id)`, the primary key — deliberately not the
    -- project's name or its identity string. Which row a working directory
    -- resolves to is a separate question (see V61); this table only needs the
    -- answer to be stable, so a change to that resolution cannot silently
    -- re-point existing grants.
    repository_id         BLOB NOT NULL REFERENCES projects(id) ON DELETE CASCADE,

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
    -- security review actually asks. It is the same reasoning the purge design
    -- already applies when it keeps the row and destroys only the content.
    revoked_at            INTEGER,

    -- Who revoked it, on the same terms as `granted_by_user_id`: NULL when the
    -- operator used the root token. `revoked_at` alone decides whether a grant
    -- is in force; this column only answers "by whom", and must not be able to
    -- stop the root operator from taking access away.
    revoked_by_user_id    BLOB REFERENCES users(id),

    -- A revoker without a revocation is meaningless; the reverse is the root
    -- token, and is allowed.
    CHECK (revoked_by_user_id IS NULL OR revoked_at IS NOT NULL)
);

-- Partial: one ACTIVE grant per pair, while the revoked history beside it may
-- be as long as it likes. Re-granting after a revocation is an ordinary thing
-- to do and must not collide with the record of the first grant.
CREATE UNIQUE INDEX idx_memory_grant_active
    ON memory_grant(user_id, repository_id)
 WHERE revoked_at IS NULL;

-- The read path asks "what does this user hold here" on every authorized call.
CREATE INDEX idx_memory_grant_lookup
    ON memory_grant(user_id, repository_id, revoked_at);
