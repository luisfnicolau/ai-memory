-- V69: per-project access mode (#708).
--
-- `open` is what every project was before this existed: any authenticated
-- user reaches it. `restricted` admits only holders of a `memory_grant` and
-- the root operator. Every existing project, and every new one unless the
-- operator sets `[auth] new_projects_restricted`, is `open`, so an upgrade
-- changes nobody's access until an operator restricts a project on purpose.
--
-- A CHECK rather than trusting the application: a mode this version cannot
-- read must never be taken for `open`.
ALTER TABLE projects ADD COLUMN access_mode TEXT NOT NULL DEFAULT 'open'
    CHECK (access_mode IN ('open', 'restricted'));
