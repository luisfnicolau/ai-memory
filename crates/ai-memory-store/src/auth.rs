//! Reading the grants that authorize a user against a repository (#708).
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
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, Option<i64>>(6)?,
                row.get::<_, Option<Vec<u8>>>(7)?,
            ))
        },
    )?;

    let mut grants = Vec::new();
    for row in rows {
        let (id, uid, rid, role, by, at, revoked_at, revoked_by) = row?;

        let parsed = MemoryGrantId::from_slice(&id)
            .ok()
            .zip(UserId::from_slice(&uid).ok())
            .zip(ProjectId::from_slice(&rid).ok())
            .zip(UserId::from_slice(&by).ok())
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
