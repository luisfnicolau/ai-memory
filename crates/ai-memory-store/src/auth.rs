//! The grants that authorize a user against a repository (#708).
//!
//! Storage only. The decision itself lives in `ai-memory-auth`, which has no
//! database dependency and can therefore be tested exhaustively without one.

use ai_memory_auth::{GrantRole, MemoryGrant};
use ai_memory_core::ids::MemoryGrantId;
use ai_memory_core::{ProjectId, UserId};
use jiff::Timestamp;
use rusqlite::{Connection, params};

use crate::error::StoreResult;

fn ts(micros: i64) -> Timestamp {
    Timestamp::from_microsecond(micros).unwrap_or(Timestamp::UNIX_EPOCH)
}

/// Every grant this user holds on this repository, revoked ones included.
///
/// Revoked rows come back deliberately: the decision distinguishes "you never
/// had this" from "this was taken from you", and only the second is a surprise
/// worth escalating.
///
/// A row that cannot be parsed is **skipped and logged**, never repaired into
/// something plausible. Fabricating an id or a user for a malformed row in an
/// authorization table risks inventing access that nobody granted; dropping it
/// can only ever deny, which is the safe direction to fail.
///
/// # Errors
/// Propagates any SQL error.
pub fn grants_for(
    conn: &Connection,
    user_id: UserId,
    repository_id: ProjectId,
) -> StoreResult<Vec<MemoryGrant>> {
    let mut stmt = conn.prepare(
        "SELECT id, user_id, repository_id, role, granted_by_user_id, granted_at, \
                revoked_at, revoked_by_user_id \
           FROM memory_grant WHERE user_id = ?1 AND repository_id = ?2 \
          ORDER BY granted_at",
    )?;
    let rows = stmt.query_map(
        params![user_id.as_bytes(), repository_id.as_bytes()],
        |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<Vec<u8>>>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, Option<i64>>(6)?,
                row.get::<_, Option<Vec<u8>>>(7)?,
            ))
        },
    )?;

    let mut grants = Vec::new();
    for row in rows {
        let (id, uid, rid, role, by, at, revoked_at, revoked_by) = row?;

        // An ABSENT granter is the documented seeded case and parses fine.
        // A granter that is present but unreadable does not: the rule is that
        // a value we cannot read is never guessed at, and skipping can only
        // ever deny.
        let granter = match &by {
            None => Some(None),
            Some(raw) => UserId::from_slice(raw).ok().map(Some),
        };
        let parsed = MemoryGrantId::from_slice(&id)
            .ok()
            .zip(UserId::from_slice(&uid).ok())
            .zip(ProjectId::from_slice(&rid).ok())
            .zip(granter)
            .zip(GrantRole::parse(&role).ok());

        let Some(((((id, uid), rid), by), role)) = parsed else {
            // Skipping denies; repairing could invent access.
            tracing::error!(
                role = %role,
                "skipping a malformed memory_grant row; access will be denied \
                 as though it were absent",
            );
            continue;
        };

        grants.push(MemoryGrant {
            id,
            user_id: uid,
            repository_id: rid,
            role,
            granted_by_user_id: by,
            granted_at: ts(at),
            revoked_at: revoked_at.map(ts),
            revoked_by_user_id: revoked_by.and_then(|b| UserId::from_slice(&b).ok()),
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
    /// There was no active grant; one was created.
    Granted,
    /// An active grant existed at a different level. It was revoked and a new
    /// one issued, so the change is visible in the history rather than
    /// overwriting it.
    RoleChanged {
        /// The level held before this call.
        from: GrantRole,
    },
    /// An active grant at exactly this level already existed. Nothing written.
    Unchanged,
}

/// Grant `user_id` `role` on `repository_id`.
///
/// Changing an existing grant's level revokes the old row and inserts a new
/// one rather than updating in place. An authorization table whose rows mutate
/// cannot answer "what could they reach last Tuesday", which is the question
/// that matters after an incident. It also keeps the active-pair unique index
/// honest: there is exactly one unrevoked row per pair at every instant.
///
/// `granted_by` is `None` for the root bearer token and for grants seeded
/// when authorization is switched on — see the column comment in V62.
///
/// # Errors
/// Propagates any SQL error.
pub fn grant(
    conn: &Connection,
    user_id: UserId,
    repository_id: ProjectId,
    role: GrantRole,
    granted_by: Option<UserId>,
    now: i64,
) -> StoreResult<GrantOutcome> {
    let active = grants_for(conn, user_id, repository_id)?
        .into_iter()
        .find(MemoryGrant::is_active);

    let outcome = match active {
        Some(held) if held.role == role => return Ok(GrantOutcome::Unchanged),
        Some(held) => {
            // A level change is a revocation plus a new grant. `granted_by` is
            // the revoker too: the person making the change is the person
            // taking the old level away.
            revoke(conn, user_id, repository_id, granted_by, now)?;
            GrantOutcome::RoleChanged { from: held.role }
        }
        None => GrantOutcome::Granted,
    };

    conn.execute(
        "INSERT INTO memory_grant \
         (id, user_id, repository_id, role, granted_by_user_id, granted_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            MemoryGrantId::new().as_bytes(),
            user_id.as_bytes(),
            repository_id.as_bytes(),
            role.as_str(),
            granted_by.map(|by| by.as_bytes().to_vec()),
            now,
        ],
    )?;
    Ok(outcome)
}

/// Revoke whatever `user_id` actively holds on `repository_id`.
///
/// Returns whether anything was actually revoked, so revoking twice is
/// harmless and still reports honestly.
///
/// `revoked_by` is `None` when the operator acts through the root bearer
/// token, which has no `users` row — see the column comment in V62. It must
/// not be able to prevent a revocation: taking access away is the operation
/// that most needs to work when something has gone wrong.
///
/// # Errors
/// Propagates any SQL error.
pub fn revoke(
    conn: &Connection,
    user_id: UserId,
    repository_id: ProjectId,
    revoked_by: Option<UserId>,
    now: i64,
) -> StoreResult<bool> {
    let changed = conn.execute(
        "UPDATE memory_grant SET revoked_at = ?3, revoked_by_user_id = ?4 \
          WHERE user_id = ?1 AND repository_id = ?2 AND revoked_at IS NULL",
        params![
            user_id.as_bytes(),
            repository_id.as_bytes(),
            now,
            revoked_by.map(|by| by.as_bytes().to_vec()),
        ],
    )?;
    Ok(changed > 0)
}

/// One row of the operator's grant listing, resolved to names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantListing {
    /// Who holds it.
    pub username: String,
    /// The workspace the repository lives in.
    pub workspace: String,
    /// The repository, by the name an operator would type.
    pub repository: String,
    /// What they hold.
    pub role: GrantRole,
    /// Whether it is still in force.
    pub active: bool,
}

/// Every active grant on the server, ordered for human reading.
///
/// Names rather than ids: a listing an operator cannot read without three
/// further queries is not a listing.
///
/// # Errors
/// Propagates any SQL error.
pub fn list_active_grants(conn: &Connection) -> StoreResult<Vec<GrantListing>> {
    let mut stmt = conn.prepare(
        "SELECT users.username, workspaces.name, projects.name, memory_grant.role \
           FROM memory_grant \
           JOIN users      ON users.id = memory_grant.user_id \
           JOIN projects   ON projects.id = memory_grant.repository_id \
           JOIN workspaces ON workspaces.id = projects.workspace_id \
          WHERE memory_grant.revoked_at IS NULL \
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
        let (username, workspace, repository, role) = row?;
        let Ok(role) = GrantRole::parse(&role) else {
            // Same rule as `grants_for`: a row we cannot read is not repaired
            // into something plausible. Here it is only a display, but showing
            // an operator a level that is not what the check will use is worse
            // than showing them nothing.
            tracing::error!(%username, %repository, "skipping a malformed memory_grant row in listing");
            continue;
        };
        out.push(GrantListing {
            username,
            workspace,
            repository,
            role,
            active: true,
        });
    }
    Ok(out)
}

/// What switching authorization on did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SeedReport {
    /// Grants written.
    pub granted: usize,
    /// Pairs that already had an active grant and were left alone.
    pub already_held: usize,
    /// Users considered.
    pub users: usize,
    /// Repositories considered.
    pub repositories: usize,
}

/// Give every existing user admin on every existing repository.
///
/// This is the enable path, and it exists because the alternative is a
/// lockout. Authorization enforces against a table that ships empty, so an
/// operator who simply switches it on takes every repository away from every
/// user on the server at once — including, on a team server, work those people
/// were relying on ten seconds earlier. Preserving what people already had and
/// letting the operator narrow it afterwards is the only ordering that is safe
/// to run on a Tuesday afternoon.
///
/// `admin` rather than `writer` for the same reason: the people already using
/// the server must be able to hand out access themselves afterwards, or every
/// subsequent grant funnels through whoever ran this.
///
/// Seeded grants carry no granter — see the column comment in V62. Pairs that
/// already hold something are left exactly as they are, so running this twice
/// changes nothing the second time.
///
/// Root users are skipped: root is authorized above per-repository
/// granularity and never has an `AuthorizedViewer` stamped, so a grant for
/// them would be a row nothing ever reads.
///
/// # Errors
/// Propagates any SQL error.
pub fn seed_admin_grants(conn: &Connection, now: i64) -> StoreResult<SeedReport> {
    let users: Vec<UserId> = {
        let mut stmt = conn.prepare(
            "SELECT id FROM users WHERE role <> 'root' AND disabled_at IS NULL ORDER BY username",
        )?;
        let rows = stmt.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        let mut out = Vec::new();
        for row in rows {
            if let Ok(id) = UserId::from_slice(&row?) {
                out.push(id);
            }
        }
        out
    };
    let repositories: Vec<ProjectId> = {
        let mut stmt = conn.prepare("SELECT id FROM projects ORDER BY name")?;
        let rows = stmt.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        let mut out = Vec::new();
        for row in rows {
            if let Ok(id) = ProjectId::from_slice(&row?) {
                out.push(id);
            }
        }
        out
    };

    let mut report = SeedReport {
        users: users.len(),
        repositories: repositories.len(),
        ..SeedReport::default()
    };
    for user in &users {
        for repository in &repositories {
            // Deliberately not `grant`: that would *change* a pair that
            // already holds a different level, and seeding must only ever add.
            // An operator who narrowed somebody to `reader` before enabling
            // must not have it silently widened back to `admin` by the act of
            // enabling.
            let held = grants_for(conn, *user, *repository)?
                .into_iter()
                .any(|existing| existing.is_active());
            if held {
                report.already_held += 1;
                continue;
            }
            conn.execute(
                "INSERT INTO memory_grant \
                 (id, user_id, repository_id, role, granted_by_user_id, granted_at) \
                 VALUES (?1, ?2, ?3, ?4, NULL, ?5)",
                params![
                    MemoryGrantId::new().as_bytes(),
                    user.as_bytes(),
                    repository.as_bytes(),
                    GrantRole::Admin.as_str(),
                    now,
                ],
            )?;
            report.granted += 1;
        }
    }
    Ok(report)
}

/// Whether any grant has ever been written.
///
/// The startup check uses this to refuse enforcing against an empty table —
/// see `serve`. "Ever", not "currently active", so revoking the last grant is
/// an ordinary operation rather than something that trips a safety net.
///
/// # Errors
/// Propagates any SQL error.
pub fn any_grant_exists(conn: &Connection) -> StoreResult<bool> {
    conn.query_row("SELECT EXISTS(SELECT 1 FROM memory_grant)", [], |row| {
        row.get(0)
    })
    .map_err(crate::StoreError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Store;
    use ai_memory_core::{NewUser, UserRole};

    struct Fixture {
        _tmp: tempfile::TempDir,
        store: Store,
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
            alice,
            bob,
            client,
            personal,
        }
    }

    fn all_rows(store: &Store, user: UserId, repository: ProjectId) -> Vec<MemoryGrant> {
        let conn = Connection::open(store.db_path()).unwrap();
        grants_for(&conn, user, repository).unwrap()
    }

    #[tokio::test]
    async fn granting_reports_what_it_did_and_a_level_change_keeps_history() {
        let f = fixture().await;
        let w = &f.store.writer;

        assert_eq!(
            w.grant_memory(f.alice, f.client, GrantRole::Reader, Some(f.bob))
                .await
                .unwrap(),
            GrantOutcome::Granted
        );
        // The same level again is not reported as a change.
        assert_eq!(
            w.grant_memory(f.alice, f.client, GrantRole::Reader, Some(f.bob))
                .await
                .unwrap(),
            GrantOutcome::Unchanged
        );
        assert_eq!(
            w.grant_memory(f.alice, f.client, GrantRole::Writer, Some(f.bob))
                .await
                .unwrap(),
            GrantOutcome::RoleChanged {
                from: GrantRole::Reader
            }
        );

        // A level change is a revocation plus a new grant, never an UPDATE:
        // both rows survive, exactly one is in force, and the old one records
        // who took it away.
        let rows = all_rows(&f.store, f.alice, f.client);
        assert_eq!(rows.len(), 2);
        let active: Vec<_> = rows.iter().filter(|g| g.is_active()).collect();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].role, GrantRole::Writer);
        let old = rows.iter().find(|g| !g.is_active()).unwrap();
        assert_eq!(old.role, GrantRole::Reader);
        assert_eq!(old.revoked_by_user_id, Some(f.bob));
    }

    #[tokio::test]
    async fn revoking_is_honest_about_whether_anything_was_held() {
        let f = fixture().await;
        let w = &f.store.writer;
        w.grant_memory(f.alice, f.client, GrantRole::Writer, Some(f.bob))
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

        // The decision now reads it as revoked, not as never granted.
        let grants = all_rows(&f.store, f.alice, f.client);
        assert_eq!(
            ai_memory_auth::decide(&grants, f.alice, f.client, GrantRole::Reader),
            ai_memory_auth::Access::Denied(ai_memory_auth::Denial::Revoked {
                repository: f.client
            })
        );
    }

    #[tokio::test]
    async fn the_root_token_can_grant_and_revoke_without_a_users_row() {
        // The operator on a bearer-token install has no `users` row. They must
        // still be able to take access away — that is the operation that most
        // needs to work when something has gone wrong.
        let f = fixture().await;
        let w = &f.store.writer;
        w.grant_memory(f.alice, f.client, GrantRole::Writer, None)
            .await
            .unwrap();
        assert!(w.revoke_memory(f.alice, f.client, None).await.unwrap());

        let rows = all_rows(&f.store, f.alice, f.client);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].granted_by_user_id, None);
        assert_eq!(rows[0].revoked_by_user_id, None);
        assert!(!rows[0].is_active());
    }

    #[tokio::test]
    async fn seeding_preserves_access_and_never_widens_a_narrowed_grant() {
        let f = fixture().await;
        let w = &f.store.writer;
        // Neither root nor a disabled user is something authorization
        // constrains, so neither is seeded.
        human(&f.store, "operator", UserRole::Root).await;
        let gone = human(&f.store, "former", UserRole::User).await;
        w.set_user_disabled(gone, true).await.unwrap();

        // An operator narrowed bob to reader on the client project before
        // enabling. Enabling must not hand him admin back.
        w.grant_memory(f.bob, f.client, GrantRole::Reader, Some(f.alice))
            .await
            .unwrap();

        let report = w.seed_admin_grants().await.unwrap();
        assert_eq!(report.users, 2, "only alice and bob are constrained");
        assert_eq!(report.repositories, 2);
        assert_eq!(report.already_held, 1, "bob's reader grant is left alone");
        assert_eq!(report.granted, 3);

        let bob_client: Vec<_> = all_rows(&f.store, f.bob, f.client)
            .into_iter()
            .filter(MemoryGrant::is_active)
            .collect();
        assert_eq!(bob_client.len(), 1);
        assert_eq!(bob_client[0].role, GrantRole::Reader);

        // Seeded grants say nobody issued them, rather than naming someone.
        let seeded = all_rows(&f.store, f.alice, f.personal);
        assert_eq!(seeded.len(), 1);
        assert_eq!(seeded[0].role, GrantRole::Admin);
        assert_eq!(seeded[0].granted_by_user_id, None);

        // Running it again changes nothing.
        let again = w.seed_admin_grants().await.unwrap();
        assert_eq!(again.granted, 0);
        assert_eq!(again.already_held, 4);
    }

    #[tokio::test]
    async fn any_grant_exists_counts_history_not_just_what_is_in_force() {
        let f = fixture().await;
        let r = &f.store.reader;
        assert!(!r.any_grant_exists().await.unwrap());

        f.store
            .writer
            .grant_memory(f.alice, f.client, GrantRole::Writer, None)
            .await
            .unwrap();
        assert!(r.any_grant_exists().await.unwrap());

        // Revoking the last grant is using the feature, not misconfiguring
        // it: the startup preflight must not start refusing afterwards.
        f.store
            .writer
            .revoke_memory(f.alice, f.client, None)
            .await
            .unwrap();
        assert!(r.any_grant_exists().await.unwrap());
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
    /// on every other path is `decide(.., GrantRole::Reader)`. They agree only
    /// because reader is the lowest level. This pins that, so adding a level
    /// below reader breaks a test rather than quietly widening search.
    #[test]
    fn every_grant_level_can_read_which_is_what_the_search_filter_assumes() {
        for role in [GrantRole::Reader, GrantRole::Writer, GrantRole::Admin] {
            assert!(role.covers(GrantRole::Reader), "{role:?}");
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
            .grant_memory(f.alice, f.client, GrantRole::Reader, None)
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

        // No viewer — authorization off, or root — sees everything, as before.
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
            .grant_memory(f.bob, f.personal, GrantRole::Reader, None)
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
        w.grant_memory(f.alice, f.client, GrantRole::Admin, None)
            .await
            .unwrap();
        w.grant_memory(f.bob, f.personal, GrantRole::Reader, None)
            .await
            .unwrap();
        w.revoke_memory(f.bob, f.personal, None).await.unwrap();

        let listing = f.store.reader.list_active_grants().await.unwrap();
        assert_eq!(
            listing,
            vec![GrantListing {
                username: "alice".into(),
                workspace: "default".into(),
                repository: "client-work".into(),
                role: GrantRole::Admin,
                active: true,
            }]
        );
    }
}
