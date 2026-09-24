//! Per-project access: grants and access modes (#708).
//!
//! Storage only. The decision itself lives in `ai-memory-auth`, which has no
//! database dependency and can therefore be tested exhaustively without one.

use ai_memory_auth::{GrantLevel, ProjectGrant};
use ai_memory_core::{ProjectId, UserId, WorkspaceId};
use jiff::Timestamp;
use rusqlite::{Connection, OptionalExtension, params};

use crate::error::StoreResult;

fn ts(micros: i64) -> Timestamp {
    Timestamp::from_microsecond(micros).unwrap_or(Timestamp::UNIX_EPOCH)
}

/// The access mode of a repository, or `None` when there is no such project.
///
/// # Errors
/// Propagates SQL errors, and a stored mode this version cannot read.
pub fn access_mode_of(
    conn: &Connection,
    repository_id: ProjectId,
) -> StoreResult<Option<ai_memory_auth::AccessMode>> {
    let stored: Option<String> = conn
        .query_row(
            "SELECT access_mode FROM projects WHERE id = ?1",
            params![repository_id.as_bytes()],
            |row| row.get(0),
        )
        .optional()?;
    stored
        .map(|s| {
            ai_memory_auth::AccessMode::parse(&s).ok_or_else(|| {
                crate::StoreError::MalformedRecord(format!("unknown projects.access_mode {s:?}"))
            })
        })
        .transpose()
}

/// Whether `user` may reach `repository_id` at `required`: an open repository
/// admits everyone, a restricted one asks the grants.
///
/// The one place that combines the mode with the grants, so every entry point
/// — scope resolution, captures, identity claims — answers the same way. A
/// repository that does not exist is treated as restricted: nothing is
/// admitted to what is not there.
///
/// # Errors
/// Propagates SQL errors.
pub fn access(
    conn: &Connection,
    user: UserId,
    repository_id: ProjectId,
    required: ai_memory_auth::GrantLevel,
) -> StoreResult<ai_memory_auth::Access> {
    let mode =
        access_mode_of(conn, repository_id)?.unwrap_or(ai_memory_auth::AccessMode::Restricted);
    let grants = match mode {
        ai_memory_auth::AccessMode::Open => Vec::new(),
        ai_memory_auth::AccessMode::Restricted => grants_for(conn, user, repository_id)?,
    };
    Ok(ai_memory_auth::decide_with_mode(
        mode,
        &grants,
        user,
        repository_id,
        required,
    ))
}

/// Set a repository's access mode, returning the mode it had. `None` when the
/// repository does not exist.
///
/// # Errors
/// Propagates SQL errors.
pub fn set_access_mode(
    conn: &Connection,
    repository_id: ProjectId,
    mode: ai_memory_auth::AccessMode,
) -> StoreResult<Option<ai_memory_auth::AccessMode>> {
    let Some(previous) = access_mode_of(conn, repository_id)? else {
        return Ok(None);
    };
    conn.execute(
        "UPDATE projects SET access_mode = ?1 WHERE id = ?2",
        params![mode.as_str(), repository_id.as_bytes()],
    )?;
    Ok(Some(previous))
}

/// Users who have written to `repository_id` and would not be admitted if it
/// were restricted: enabled, not root, and holding no active grant on it.
///
/// What an operator needs to see when restricting a project — the people who
/// were working in it and are about to be refused — so they can grant the ones
/// who should stay. "Written to" is page authorship, the attribution upstream
/// already records.
///
/// # Errors
/// Propagates SQL errors.
pub fn authors_without_grant(
    conn: &Connection,
    repository_id: ProjectId,
) -> StoreResult<Vec<String>> {
    let mut stmt = conn.prepare(
        "SELECT DISTINCT u.username FROM pages p \
           JOIN users u ON u.id = p.author_id \
          WHERE p.project_id = ?1 \
            AND u.role <> 'root' AND u.disabled_at IS NULL \
            AND NOT EXISTS (SELECT 1 FROM project_grants pg \
                             WHERE pg.user_id = u.id AND pg.project_id = ?1) \
          ORDER BY u.username",
    )?;
    let names = stmt
        .query_map(params![repository_id.as_bytes()], |row| row.get(0))?
        .collect::<Result<Vec<String>, _>>()?;
    Ok(names)
}

/// The grant this user holds on this project, if any — at most one, the
/// table's primary key being `(workspace, project, user)`.
///
/// A row that cannot be parsed is **skipped and logged**, never repaired into
/// something plausible. Fabricating a level for a malformed row in an
/// authorization table risks inventing access that nobody granted; dropping it
/// can only ever deny, which is the safe direction to fail.
///
/// # Errors
/// Propagates any SQL error.
pub fn grants_for(
    conn: &Connection,
    user_id: UserId,
    project_id: ProjectId,
) -> StoreResult<Vec<ProjectGrant>> {
    let mut stmt = conn.prepare(
        "SELECT workspace_id, level, granted_by, granted_at \
           FROM project_grants WHERE user_id = ?1 AND project_id = ?2",
    )?;
    let rows = stmt.query_map(params![user_id.as_bytes(), project_id.as_bytes()], |row| {
        Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Option<Vec<u8>>>(2)?,
            row.get::<_, i64>(3)?,
        ))
    })?;
    let mut grants = Vec::new();
    for row in rows {
        let (workspace, level, by, at) = row?;
        // An ABSENT granter is the root-token case and parses fine. One that
        // is present but unreadable does not: a value we cannot read is never
        // guessed at, and skipping can only ever deny.
        let granter = match &by {
            None => Some(None),
            Some(raw) => UserId::from_slice(raw).ok().map(Some),
        };
        let parsed = WorkspaceId::from_slice(&workspace)
            .ok()
            .zip(granter)
            .zip(GrantLevel::parse(&level).ok());
        let Some(((workspace_id, granted_by), level)) = parsed else {
            tracing::error!(
                %level,
                "skipping a malformed project_grants row; access will be denied \
                 as though it were absent",
            );
            continue;
        };
        grants.push(ProjectGrant {
            workspace_id,
            project_id,
            user_id,
            level,
            granted_by,
            granted_at: ts(at),
        });
    }
    Ok(grants)
}

/// What a call to [`grant`] actually did.
///
/// Returned rather than inferred so an operator's tooling can say "already had
/// that" instead of reporting a change it did not make.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantOutcome {
    /// There was no grant; one was created.
    Granted,
    /// A grant existed at a different level and was changed.
    LevelChanged {
        /// The level held before this call.
        from: GrantLevel,
    },
    /// A grant at exactly this level already existed. Nothing written.
    Unchanged,
}

/// Record a grant change in `audit_log`, the durable answer to "who could
/// reach this, since when, and who decided". The grant table itself only
/// holds what is in force now.
fn audit_grant(
    conn: &Connection,
    op: &str,
    workspace_id: WorkspaceId,
    project_id: ProjectId,
    by: Option<UserId>,
    detail: &serde_json::Value,
    now: i64,
) -> StoreResult<()> {
    conn.execute(
        "INSERT INTO audit_log (at, op, workspace_id, project_id, page_id, author_id, detail) \
         VALUES (?1, ?2, ?3, ?4, NULL, ?5, ?6)",
        params![
            now,
            op,
            workspace_id.as_bytes(),
            project_id.as_bytes(),
            by.map(|by| by.as_bytes().to_vec()),
            detail.to_string(),
        ],
    )?;
    Ok(())
}

/// Grant `user_id` `level` on `project_id`, or change the level they hold.
///
/// `granted_by` is `None` for the root bearer token, and `user_id` itself for
/// the grant a creator receives with the project they create — see V68.
/// Every change is recorded in `audit_log` (`grant_access`, with the previous
/// level when there was one).
///
/// # Errors
/// [`crate::StoreError::NotFound`] when the project does not exist; otherwise
/// propagates any SQL error.
pub fn grant(
    conn: &Connection,
    user_id: UserId,
    project_id: ProjectId,
    level: GrantLevel,
    granted_by: Option<UserId>,
    now: i64,
) -> StoreResult<GrantOutcome> {
    let held = grants_for(conn, user_id, project_id)?.into_iter().next();
    let outcome = match &held {
        Some(held) if held.level == level => return Ok(GrantOutcome::Unchanged),
        Some(held) => GrantOutcome::LevelChanged { from: held.level },
        None => GrantOutcome::Granted,
    };
    let workspace_id: Option<Vec<u8>> = conn
        .query_row(
            "SELECT workspace_id FROM projects WHERE id = ?1",
            params![project_id.as_bytes()],
            |row| row.get(0),
        )
        .optional()?;
    let workspace_id = workspace_id
        .and_then(|bytes| WorkspaceId::from_slice(&bytes).ok())
        .ok_or_else(|| crate::StoreError::NotFound(format!("project {project_id}")))?;
    conn.execute(
        "INSERT INTO project_grants \
         (workspace_id, project_id, user_id, level, granted_by, granted_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
         ON CONFLICT (workspace_id, project_id, user_id) DO UPDATE SET \
           level = excluded.level, granted_by = excluded.granted_by, \
           granted_at = excluded.granted_at",
        params![
            workspace_id.as_bytes(),
            project_id.as_bytes(),
            user_id.as_bytes(),
            level.as_str(),
            granted_by.map(|by| by.as_bytes().to_vec()),
            now,
        ],
    )?;
    let previous = held.map(|held| held.level.as_str());
    audit_grant(
        conn,
        "grant_access",
        workspace_id,
        project_id,
        granted_by,
        &serde_json::json!({
            "user_id": user_id.to_string(),
            "level": level.as_str(),
            "previous": previous,
        }),
        now,
    )?;
    Ok(outcome)
}

/// Take away whatever `user_id` holds on `project_id`.
///
/// Returns whether anything was actually revoked, so revoking twice is
/// harmless and still reports honestly. The revocation is recorded in
/// `audit_log` (`revoke_access`); `revoked_by` is `None` for the root bearer
/// token, and must never be able to prevent a revocation — taking access away
/// is what most needs to work when something has gone wrong.
///
/// # Errors
/// Propagates any SQL error.
pub fn revoke(
    conn: &Connection,
    user_id: UserId,
    project_id: ProjectId,
    revoked_by: Option<UserId>,
    now: i64,
) -> StoreResult<bool> {
    let Some(held) = grants_for(conn, user_id, project_id)?.into_iter().next() else {
        return Ok(false);
    };
    conn.execute(
        "DELETE FROM project_grants WHERE user_id = ?1 AND project_id = ?2",
        params![user_id.as_bytes(), project_id.as_bytes()],
    )?;
    audit_grant(
        conn,
        "revoke_access",
        held.workspace_id,
        project_id,
        revoked_by,
        &serde_json::json!({
            "user_id": user_id.to_string(),
            "level": held.level.as_str(),
        }),
        now,
    )?;
    Ok(true)
}

/// One row of the operator's grant listing, resolved to names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantListing {
    /// Who holds it.
    pub username: String,
    /// The workspace the project lives in.
    pub workspace: String,
    /// The project, by the name an operator would type.
    pub project: String,
    /// What they hold.
    pub level: GrantLevel,
}

/// Every grant on the server, ordered for human reading.
///
/// Names rather than ids: a listing an operator cannot read without three
/// further queries is not a listing.
///
/// # Errors
/// Propagates any SQL error.
pub fn list_grants(conn: &Connection) -> StoreResult<Vec<GrantListing>> {
    let mut stmt = conn.prepare(
        "SELECT users.username, workspaces.name, projects.name, project_grants.level \
           FROM project_grants \
           JOIN users      ON users.id = project_grants.user_id \
           JOIN projects   ON projects.id = project_grants.project_id \
           JOIN workspaces ON workspaces.id = project_grants.workspace_id \
          ORDER BY workspaces.name, projects.name, users.username",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (username, workspace, project, level) = row?;
        let Ok(level) = GrantLevel::parse(&level) else {
            // Same rule as `grants_for`: a row we cannot read is not repaired
            // into something plausible, even for display.
            tracing::error!(%username, %project, "skipping a malformed project_grants row in listing");
            continue;
        };
        out.push(GrantListing {
            username,
            workspace,
            project,
            level,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Store;
    use ai_memory_core::{NewUser, UserRole};

    struct Fixture {
        _tmp: tempfile::TempDir,
        store: Store,
        ws: ai_memory_core::WorkspaceId,
        alice: UserId,
        bob: UserId,
        client: ProjectId,
        personal: ProjectId,
    }

    async fn human(store: &Store, name: &str, role: UserRole) -> UserId {
        store
            .writer
            .create_human_user(
                NewUser {
                    username: name.to_owned(),
                    name: None,
                    email: None,
                },
                role,
                None,
                false,
            )
            .await
            .unwrap()
    }

    async fn fixture() -> Fixture {
        let tmp = tempfile::TempDir::new().unwrap();
        let store = Store::open(tmp.path()).unwrap();
        // Grants only decide anything in a restricted project; every project
        // these tests create starts restricted.
        store
            .writer
            .set_new_project_mode(ai_memory_auth::AccessMode::Restricted)
            .await
            .unwrap();
        let ws = store
            .writer
            .get_or_create_workspace("default")
            .await
            .unwrap();
        let client = store
            .writer
            .get_or_create_project(ws, "client-work", None)
            .await
            .unwrap();
        let personal = store
            .writer
            .get_or_create_project(ws, "personal", None)
            .await
            .unwrap();
        let alice = human(&store, "alice", UserRole::User).await;
        let bob = human(&store, "bob", UserRole::User).await;
        Fixture {
            _tmp: tmp,
            store,
            ws,
            alice,
            bob,
            client,
            personal,
        }
    }

    fn all_rows(store: &Store, user: UserId, project: ProjectId) -> Vec<ProjectGrant> {
        let conn = Connection::open(store.db_path()).unwrap();
        grants_for(&conn, user, project).unwrap()
    }

    /// `(author_id, detail)` of every audit row with this `op`, oldest first.
    fn audit_rows(store: &Store, op: &str) -> Vec<(Option<Vec<u8>>, serde_json::Value)> {
        let conn = Connection::open(store.db_path()).unwrap();
        let mut stmt = conn
            .prepare("SELECT author_id, detail FROM audit_log WHERE op = ?1 ORDER BY id")
            .unwrap();
        stmt.query_map(params![op], |row| {
            let detail: String = row.get(1)?;
            Ok((row.get(0)?, serde_json::from_str(&detail).unwrap()))
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
    }

    /// One row per user and project: a level change updates it, and every
    /// change — not a repeat — lands in the audit log with who made it.
    #[tokio::test]
    async fn granting_reports_what_it_did_and_every_change_is_audited() {
        let f = fixture().await;
        let w = &f.store.writer;

        assert_eq!(
            w.grant_memory(f.alice, f.client, GrantLevel::Read, Some(f.bob))
                .await
                .unwrap(),
            GrantOutcome::Granted
        );
        assert_eq!(
            w.grant_memory(f.alice, f.client, GrantLevel::Read, Some(f.bob))
                .await
                .unwrap(),
            GrantOutcome::Unchanged,
            "the same level again is not a change"
        );
        assert_eq!(
            w.grant_memory(f.alice, f.client, GrantLevel::Write, Some(f.bob))
                .await
                .unwrap(),
            GrantOutcome::LevelChanged {
                from: GrantLevel::Read
            }
        );

        let rows = all_rows(&f.store, f.alice, f.client);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].level, GrantLevel::Write);
        assert_eq!(rows[0].granted_by, Some(f.bob));

        let audit = audit_rows(&f.store, "grant_access");
        assert_eq!(audit.len(), 2, "grant and level change, not the repeat");
        assert_eq!(audit[0].0, Some(f.bob.as_bytes().to_vec()));
        assert_eq!(audit[0].1["level"], "read");
        assert_eq!(audit[1].1["level"], "write");
        assert_eq!(audit[1].1["previous"], "read");
        assert_eq!(audit[1].1["user_id"], f.alice.to_string());
    }

    /// Revoking deletes the grant and records it; revoking again is honest
    /// about there being nothing to take. A revoked user reads exactly like one
    /// never granted.
    #[tokio::test]
    async fn revoking_is_honest_and_audited() {
        let f = fixture().await;
        let w = &f.store.writer;
        w.grant_memory(f.alice, f.client, GrantLevel::Write, Some(f.bob))
            .await
            .unwrap();

        assert!(
            w.revoke_memory(f.alice, f.client, Some(f.bob))
                .await
                .unwrap()
        );
        assert!(
            !w.revoke_memory(f.alice, f.client, Some(f.bob))
                .await
                .unwrap()
        );

        assert!(all_rows(&f.store, f.alice, f.client).is_empty());
        assert_eq!(
            ai_memory_auth::decide(&[], f.alice, f.client, GrantLevel::Read),
            ai_memory_auth::Access::Denied(ai_memory_auth::Denial::NeverGranted {
                repository: f.client
            })
        );
        let audit = audit_rows(&f.store, "revoke_access");
        assert_eq!(audit.len(), 1, "the no-op second revoke writes nothing");
        assert_eq!(audit[0].1["level"], "write");
    }

    #[tokio::test]
    async fn the_root_token_can_grant_and_revoke_without_a_users_row() {
        // The operator on a bearer-token install has no `users` row. They must
        // still be able to take access away — that is the operation that most
        // needs to work when something has gone wrong.
        let f = fixture().await;
        let w = &f.store.writer;
        w.grant_memory(f.alice, f.client, GrantLevel::Write, None)
            .await
            .unwrap();
        assert_eq!(all_rows(&f.store, f.alice, f.client)[0].granted_by, None);
        assert!(w.revoke_memory(f.alice, f.client, None).await.unwrap());
        assert!(all_rows(&f.store, f.alice, f.client).is_empty());
        for op in ["grant_access", "revoke_access"] {
            assert_eq!(
                audit_rows(&f.store, op)[0].0,
                None,
                "{op} by the root token"
            );
        }
    }

    async fn page(store: &Store, repository: ProjectId, path: &str, body: &str) {
        let workspace = store
            .writer
            .get_or_create_workspace("default")
            .await
            .unwrap();
        store
            .writer
            .upsert_page(ai_memory_core::NewPage {
                workspace_id: workspace,
                project_id: repository,
                path: ai_memory_core::PagePath::new(path).unwrap(),
                title: path.to_owned(),
                body: body.to_owned(),
                tier: ai_memory_core::Tier::Semantic,
                frontmatter_json: serde_json::json!({}),
                pinned: false,
                links: Vec::new(),
                author_id: None,
                expires_at: None,
                entities: Vec::new(),
                evidence: Vec::new(),
            })
            .await
            .unwrap();
    }

    fn paths<T>(hits: &[T], path: impl Fn(&T) -> &str) -> Vec<String> {
        let mut out: Vec<String> = hits.iter().map(|h| path(h).to_owned()).collect();
        out.sort();
        out
    }

    /// The search filter is written in SQL as "any active grant"; the guard
    /// on every other path is `decide(.., GrantLevel::Read)`. They agree only
    /// because reader is the lowest level. This pins that, so adding a level
    /// below reader breaks a test rather than quietly widening search.
    #[test]
    fn every_grant_level_can_read_which_is_what_the_search_filter_assumes() {
        for role in [GrantLevel::Read, GrantLevel::Write] {
            assert!(role.covers(GrantLevel::Read), "{role:?}");
        }
    }

    #[tokio::test]
    async fn search_finds_only_what_the_viewer_may_read() {
        let f = fixture().await;
        let r = &f.store.reader;
        page(
            &f.store,
            f.client,
            "secrets/rates.md",
            "confidential day rate",
        )
        .await;
        page(&f.store, f.personal, "notes/rates.md", "personal day rate").await;
        let global = crate::create_global_scope(&f.store.writer).await.unwrap();
        page(
            &f.store,
            global.project_id,
            "prefs/rates.md",
            "shared day rate",
        )
        .await;
        f.store
            .writer
            .grant_memory(f.alice, f.client, GrantLevel::Read, None)
            .await
            .unwrap();

        let as_viewer = |viewer| async move {
            (
                paths(
                    &r.search_pages("rate".into(), 10, viewer).await.unwrap(),
                    |h| h.path.as_str(),
                ),
                paths(
                    &r.search_pages_with_meta("rate".into(), 10, None, viewer)
                        .await
                        .unwrap(),
                    |h| h.path.as_str(),
                ),
                paths(&r.recent_pages_global(10, viewer).await.unwrap(), |h| {
                    h.path.as_str()
                }),
            )
        };

        // Alice holds a grant on the client project: she finds it, plus the
        // shared global scope, and nothing from the project she was never
        // given.
        let alice = vec!["prefs/rates.md".to_owned(), "secrets/rates.md".to_owned()];
        assert_eq!(
            as_viewer(Some(f.alice)).await,
            (alice.clone(), alice.clone(), alice)
        );

        // Bob holds nothing: only the global scope, which is shared by design.
        let bob = vec!["prefs/rates.md".to_owned()];
        assert_eq!(
            as_viewer(Some(f.bob)).await,
            (bob.clone(), bob.clone(), bob)
        );

        // No viewer — an install with no database users, or root — sees everything, as before.
        let all = vec![
            "notes/rates.md".to_owned(),
            "prefs/rates.md".to_owned(),
            "secrets/rates.md".to_owned(),
        ];
        assert_eq!(as_viewer(None).await, (all.clone(), all.clone(), all));

        // A revoked grant hides the repository again.
        f.store
            .writer
            .revoke_memory(f.alice, f.client, None)
            .await
            .unwrap();
        let revoked = vec!["prefs/rates.md".to_owned()];
        assert_eq!(
            as_viewer(Some(f.alice)).await,
            (revoked.clone(), revoked.clone(), revoked)
        );
    }

    #[tokio::test]
    async fn the_limit_counts_only_what_the_viewer_may_see() {
        // Filtering after LIMIT would hand bob a short page: of the first ten
        // matches, most are alice's. Filtering in the query fills his limit
        // from what he can read, and does not tell him how much was hidden.
        //
        // The hidden pages are built to win every ordering these queries use —
        // more of them than the 40 candidates a limit of 10 over-fetches,
        // ranked higher (the needle repeated) and written more recently — so a
        // filter applied after the LIMIT would leave bob with nothing at all.
        let f = fixture().await;
        let r = &f.store.reader;
        for n in 0..12 {
            page(
                &f.store,
                f.personal,
                &format!("visible/{n:02}.md"),
                "needle visible",
            )
            .await;
        }
        for n in 0..60 {
            page(
                &f.store,
                f.client,
                &format!("hidden/{n:02}.md"),
                "needle needle needle needle hidden",
            )
            .await;
        }
        // Without a viewer the hidden pages crowd out every visible one, which
        // is what makes the assertions below mean something.
        let unfiltered = r.search_pages("needle".into(), 10, None).await.unwrap();
        assert!(
            unfiltered
                .iter()
                .all(|h| h.path.as_str().starts_with("hidden/"))
        );
        let unfiltered = r.recent_pages_global(10, None).await.unwrap();
        assert!(unfiltered.iter().all(|h| h.project_name == "client-work"));

        f.store
            .writer
            .grant_memory(f.bob, f.personal, GrantLevel::Read, None)
            .await
            .unwrap();

        let hits = r
            .search_pages("needle".into(), 10, Some(f.bob))
            .await
            .unwrap();
        assert_eq!(hits.len(), 10);
        assert!(hits.iter().all(|h| h.path.as_str().starts_with("visible/")));

        let hits = r
            .search_pages_with_meta("needle".into(), 10, None, Some(f.bob))
            .await
            .unwrap();
        assert_eq!(hits.len(), 10);
        assert!(hits.iter().all(|h| h.project_name == "personal"));

        let hits = r.recent_pages_global(10, Some(f.bob)).await.unwrap();
        assert_eq!(hits.len(), 10);
        assert!(hits.iter().all(|h| h.project_name == "personal"));
    }

    #[tokio::test]
    async fn the_listing_shows_names_and_only_what_is_in_force() {
        let f = fixture().await;
        let w = &f.store.writer;
        w.grant_memory(f.alice, f.client, GrantLevel::Write, None)
            .await
            .unwrap();
        w.grant_memory(f.bob, f.personal, GrantLevel::Read, None)
            .await
            .unwrap();
        w.revoke_memory(f.bob, f.personal, None).await.unwrap();

        let listing = f.store.reader.list_grants().await.unwrap();
        assert_eq!(
            listing,
            vec![GrantListing {
                username: "alice".into(),
                workspace: "default".into(),
                project: "client-work".into(),
                level: GrantLevel::Write,
            }]
        );
    }

    /// A grant never outlives its project: purging it takes the grants too, as
    /// the design's CASCADE says, and the audit log still says who had access.
    #[tokio::test]
    async fn purging_a_project_takes_its_grants_and_keeps_the_audit_trail() {
        let f = fixture().await;
        f.store
            .writer
            .grant_memory(f.alice, f.client, GrantLevel::Write, None)
            .await
            .unwrap();
        f.store
            .writer
            .purge_project(
                f.ws,
                f.client,
                "default/client-work",
                None,
                false,
                crate::Compaction::Skip,
            )
            .await
            .expect("a grant in force does not stand in a purge's way");
        let conn = Connection::open(f.store.db_path()).unwrap();
        let left: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM project_grants WHERE project_id = ?1",
                params![f.client.as_bytes()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(left, 0);
        assert_eq!(audit_rows(&f.store, "grant_access").len(), 1);
    }

    /// Deleting a workspace cascades through its projects to their grants.
    #[tokio::test]
    async fn deleting_a_workspace_takes_its_grants() {
        let f = fixture().await;
        let w = &f.store.writer;
        let team = w.get_or_create_workspace("team-b").await.unwrap();
        let api = w.get_or_create_project(team, "api", None).await.unwrap();
        w.grant_memory(f.alice, api, GrantLevel::Write, None)
            .await
            .unwrap();
        w.delete_workspace(team, true, crate::Compaction::Skip)
            .await
            .unwrap();
        assert!(all_rows(&f.store, f.alice, api).is_empty());
    }

    /// The hollow-project sweep is upstream's, unchanged: an empty project is
    /// swept after its age cutoff whether or not someone holds a grant on it,
    /// and the grant goes with it.
    #[tokio::test]
    async fn an_empty_project_is_swept_even_when_someone_holds_a_grant() {
        let f = fixture().await;
        let w = &f.store.writer;
        let probe = w.get_or_create_project(f.ws, "probe", None).await.unwrap();
        w.grant_memory(f.alice, probe, GrantLevel::Write, None)
            .await
            .unwrap();
        let mut conn = Connection::open(f.store.db_path()).unwrap();
        conn.execute(
            "UPDATE projects SET created_at = 0 WHERE id = ?1",
            params![probe.as_bytes()],
        )
        .unwrap();
        let swept = crate::ops::sweep_hollow_projects(&mut conn, 1).unwrap();
        assert!(swept.contains(&"probe".to_owned()), "{swept:?}");
        assert!(all_rows(&f.store, f.alice, probe).is_empty());
    }

    #[tokio::test]
    async fn rename_and_a_true_move_keep_the_grants_with_the_project() {
        // Both keep the project id, so the grants stay attached to the same
        // content — the id, not the name, is the key. A move to another
        // workspace carries the grant's workspace along with it.
        let f = fixture().await;
        let w = &f.store.writer;
        w.grant_memory(f.alice, f.client, GrantLevel::Write, None)
            .await
            .unwrap();

        w.rename_project(f.ws, f.client, "client-renamed", None)
            .await
            .unwrap();
        let elsewhere = w.get_or_create_workspace("elsewhere").await.unwrap();
        w.move_project_workspace(f.client, f.ws, elsewhere)
            .await
            .unwrap();

        let grants = all_rows(&f.store, f.alice, f.client);
        assert_eq!(grants[0].workspace_id, elsewhere);
        assert_eq!(
            ai_memory_auth::decide(&grants, f.alice, f.client, GrantLevel::Write),
            ai_memory_auth::Access::Granted
        );
        let listing = f.store.reader.list_grants().await.unwrap();
        assert_eq!(listing[0].workspace, "elsewhere");
        assert_eq!(listing[0].project, "client-renamed");

        // And deleting the workspace it left does not take it.
        w.delete_workspace(f.ws, true, crate::Compaction::Skip)
            .await
            .unwrap();
        assert_eq!(all_rows(&f.store, f.alice, f.client).len(), 1);
    }

    /// Both forms of "may read" are built from one SQL template, but they
    /// reach it by different routes — bound parameters and spliced literals —
    /// and a quoting or numbering slip in either would silently widen or
    /// narrow one set of surfaces. This runs both against the same data.
    #[tokio::test]
    async fn the_spliced_predicate_and_the_bound_filter_admit_the_same_repositories() {
        let f = fixture().await;
        let w = &f.store.writer;
        let global = crate::create_global_scope(w).await.unwrap();
        w.grant_memory(f.alice, f.client, GrantLevel::Read, None)
            .await
            .unwrap();
        w.grant_memory(f.bob, f.personal, GrantLevel::Write, None)
            .await
            .unwrap();
        w.revoke_memory(f.bob, f.personal, None).await.unwrap();

        let conn = Connection::open(f.store.db_path()).unwrap();
        let ids = |sql: String, binds: Vec<rusqlite::types::Value>| -> Vec<ProjectId> {
            let mut stmt = conn.prepare(&sql).unwrap();
            let mut out: Vec<ProjectId> = stmt
                .query_map(rusqlite::params_from_iter(binds.iter()), |row| {
                    row.get::<_, Vec<u8>>(0)
                })
                .unwrap()
                .map(|id| ProjectId::from_slice(&id.unwrap()).unwrap())
                .collect();
            out.sort_by_key(|id| *id.as_bytes());
            out
        };
        let sorted = |mut v: Vec<ProjectId>| {
            v.sort_by_key(|id| *id.as_bytes());
            v
        };
        for (viewer, expected) in [
            (f.alice, sorted(vec![f.client, global.project_id])),
            // bob's only grant was revoked: the shared scope is all that is left.
            (f.bob, vec![global.project_id]),
        ] {
            let (bound, binds) =
                crate::reader::readable_repository_filter("projects.id", Some(viewer), 1);
            let spliced = crate::reader::readable_repository_predicate("projects.id", Some(viewer));
            let via_binds = ids(format!("SELECT id FROM projects WHERE 1 = 1{bound}"), binds);
            let via_splice = ids(
                format!("SELECT id FROM projects WHERE 1 = 1{spliced}"),
                Vec::new(),
            );
            assert_eq!(via_binds, expected, "bound filter");
            assert_eq!(via_splice, via_binds, "the two forms disagree");
        }
        assert!(
            crate::reader::readable_repository_predicate("projects.id", None).is_empty(),
            "no viewer must leave the query exactly as it was"
        );
    }

    fn unowned_handoff(
        workspace_id: ai_memory_core::WorkspaceId,
        project_id: ProjectId,
        summary: &str,
    ) -> ai_memory_core::NewHandoff {
        ai_memory_core::NewHandoff {
            workspace_id,
            project_id,
            from_session_id: None,
            from_agent: ai_memory_core::AgentKind::ClaudeCode,
            to_agent: None,
            cwd: None,
            summary: summary.into(),
            open_questions: Vec::new(),
            next_steps: Vec::new(),
            files_touched: Vec::new(),
            owner_user: None,
        }
    }

    /// An unowned handoff is visible to everyone who can see its repository —
    /// which is exactly why it must not reach someone who cannot. The query
    /// keeps its `LIMIT 1`, so a newer handoff in a hidden repository must not
    /// shadow an older one the viewer is entitled to either.
    #[tokio::test]
    async fn the_workspace_handoff_comes_only_from_readable_repositories() {
        let f = fixture().await;
        let w = &f.store.writer;
        w.grant_memory(f.alice, f.client, GrantLevel::Read, None)
            .await
            .unwrap();
        w.grant_memory(f.bob, f.personal, GrantLevel::Read, None)
            .await
            .unwrap();
        w.insert_handoff(unowned_handoff(f.ws, f.personal, "bob's older baton"))
            .await
            .unwrap();
        w.insert_handoff(unowned_handoff(f.ws, f.client, "alice's client baton"))
            .await
            .unwrap();
        let latest = |viewer| {
            let reader = f.store.reader.clone();
            let ws = f.ws;
            async move {
                reader
                    .latest_open_handoff_for_workspace(ws, ai_memory_core::OwnerFilter::Any, viewer)
                    .await
                    .unwrap()
                    .map(|h| h.content.summary)
            }
        };
        assert_eq!(
            latest(Some(f.alice)).await.as_deref(),
            Some("alice's client baton")
        );
        assert_eq!(
            latest(Some(f.bob)).await.as_deref(),
            Some("bob's older baton"),
            "the newer, hidden handoff shadowed the one bob may read"
        );
        assert_eq!(
            latest(None).await.as_deref(),
            Some("alice's client baton"),
            "no viewer is unchanged"
        );
    }

    /// Health's duplicate list compares titles through an inner query. If only
    /// the outer query were filtered, a hidden page sharing a title would still
    /// make the visible one show up as a duplicate — confirming, by its
    /// presence, a page the viewer cannot see.
    #[tokio::test]
    async fn a_hidden_page_does_not_make_a_visible_one_a_duplicate() {
        let f = fixture().await;
        f.store
            .writer
            .grant_memory(f.alice, f.client, GrantLevel::Read, None)
            .await
            .unwrap();
        for repo in [f.client, f.personal] {
            f.store
                .writer
                .upsert_page(ai_memory_core::NewPage {
                    workspace_id: f.ws,
                    project_id: repo,
                    path: ai_memory_core::PagePath::new("notes/plan.md").unwrap(),
                    title: "Plan".into(),
                    body: "same title in two repositories".into(),
                    tier: ai_memory_core::Tier::Semantic,
                    frontmatter_json: serde_json::json!({}),
                    pinned: false,
                    links: Vec::new(),
                    author_id: None,
                    expires_at: None,
                    entities: Vec::new(),
                    evidence: Vec::new(),
                })
                .await
                .unwrap();
        }
        let r = &f.store.reader;
        let (_, dups, _) = r
            .memory_health_for_workspace(f.ws, Some(f.alice))
            .await
            .unwrap();
        assert_eq!(dups, 0, "alice's count includes a page she cannot see");
        let detail = r
            .health_detail_for_workspace(f.ws, 10, Some(f.alice))
            .await
            .unwrap();
        assert!(detail.duplicates.is_empty(), "{:?}", detail.duplicates);

        let (_, dups, _) = r.memory_health_for_workspace(f.ws, None).await.unwrap();
        assert_eq!(dups, 1, "no viewer still sees the pair");
        let detail = r.health_detail_for_workspace(f.ws, 10, None).await.unwrap();
        assert_eq!(detail.duplicates.len(), 2);
    }
}
