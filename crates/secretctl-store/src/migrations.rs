use crate::error::StoreError;
use rusqlite::Connection;

pub const CURRENT_SCHEMA_VERSION: i32 = 2;

pub fn apply_migrations(conn: &mut Connection) -> Result<(), StoreError> {
    let tx = conn.transaction()?;

    tx.execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL,
            checksum TEXT NOT NULL
        )",
        [],
    )?;

    let current_version: Option<i32> = tx
        .query_row(
            "SELECT MAX(version) FROM schema_migrations",
            [],
            |row| row.get(0),
        )
        .ok()
        .flatten();

    let version = current_version.unwrap_or(0);

    if version < 1 {
        tx.execute(
            "CREATE TABLE IF NOT EXISTS agents (
                agent_id TEXT PRIMARY KEY,
                public_key BLOB NOT NULL,
                executable_hash BLOB,
                display_name TEXT NOT NULL,
                state TEXT NOT NULL,
                created_at TEXT NOT NULL
            )",
            [],
        )?;

        tx.execute(
            "CREATE TABLE IF NOT EXISTS credentials (
                credential_id TEXT PRIMARY KEY,
                name TEXT UNIQUE NOT NULL,
                kind TEXT NOT NULL,
                provider TEXT NOT NULL,
                provider_locator TEXT NOT NULL,
                metadata_json TEXT NOT NULL,
                disabled_at TEXT
            )",
            [],
        )?;

        tx.execute(
            "CREATE TABLE IF NOT EXISTS recipes (
                recipe_id TEXT NOT NULL,
                version INTEGER NOT NULL,
                content_json TEXT NOT NULL,
                content_hash BLOB NOT NULL,
                enabled INTEGER NOT NULL,
                PRIMARY KEY(recipe_id, version)
            )",
            [],
        )?;

        tx.execute(
            "CREATE TABLE IF NOT EXISTS browser_sessions (
                session_id TEXT PRIMARY KEY,
                instance_id TEXT NOT NULL,
                extension_key_id TEXT NOT NULL,
                profile_id TEXT NOT NULL,
                assurance TEXT NOT NULL,
                state TEXT NOT NULL,
                last_heartbeat_at TEXT NOT NULL
            )",
            [],
        )?;

        tx.execute(
            "CREATE TABLE IF NOT EXISTS action_requests (
                request_id TEXT PRIMARY KEY,
                agent_id TEXT NOT NULL,
                credential_id TEXT NOT NULL,
                action TEXT NOT NULL,
                target_origin TEXT NOT NULL,
                browser_session_id TEXT NOT NULL,
                state TEXT NOT NULL,
                policy_hash BLOB,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            )",
            [],
        )?;

        tx.execute(
            "CREATE TABLE IF NOT EXISTS approvals (
                approval_id TEXT PRIMARY KEY,
                request_id TEXT NOT NULL,
                decision TEXT NOT NULL,
                actor TEXT,
                presence TEXT,
                context_digest BLOB NOT NULL,
                decided_at TEXT,
                expires_at TEXT NOT NULL
            )",
            [],
        )?;

        tx.execute(
            "CREATE TABLE IF NOT EXISTS capabilities (
                capability_id TEXT PRIMARY KEY,
                request_id TEXT NOT NULL,
                token_hash BLOB NOT NULL,
                state TEXT NOT NULL,
                max_uses INTEGER NOT NULL,
                used_count INTEGER NOT NULL,
                issued_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                revoked_reason TEXT
            )",
            [],
        )?;

        tx.execute(
            "CREATE TABLE IF NOT EXISTS executions (
                execution_id TEXT PRIMARY KEY,
                capability_id TEXT NOT NULL,
                state TEXT NOT NULL,
                prepared_context_digest BLOB,
                started_at TEXT,
                completed_at TEXT,
                result_code TEXT
            )",
            [],
        )?;

        tx.execute(
            "CREATE TABLE IF NOT EXISTS oauth_grants (
                grant_id TEXT PRIMARY KEY,
                credential_id TEXT NOT NULL,
                provider_locator TEXT NOT NULL,
                scopes_json TEXT NOT NULL,
                subject_hint TEXT,
                created_at TEXT NOT NULL,
                expires_at TEXT
            )",
            [],
        )?;

        tx.execute(
            "CREATE TABLE IF NOT EXISTS audit_events (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT UNIQUE NOT NULL,
                event_type TEXT NOT NULL,
                actor_type TEXT NOT NULL,
                actor_id TEXT,
                event_json TEXT NOT NULL,
                previous_hash BLOB NOT NULL,
                event_hash BLOB NOT NULL,
                created_at TEXT NOT NULL
            )",
            [],
        )?;

        tx.execute(
            "INSERT INTO schema_migrations (version, applied_at, checksum) VALUES (1, datetime('now'), 'v1_initial')",
            [],
        )?;
    }

    if version < 2 {
        tx.execute(
            "ALTER TABLE credentials ADD COLUMN allowed_actions_json TEXT NOT NULL DEFAULT '[]'",
            [],
        )?;
        tx.execute(
            "INSERT INTO schema_migrations (version, applied_at, checksum)
             VALUES (2, datetime('now'), 'v2_credential_allowed_actions')",
            [],
        )?;
    }

    tx.commit()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apply_migrations() {
        let mut conn = Connection::open_in_memory().unwrap();
        apply_migrations(&mut conn).unwrap();

        let table_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
                [],
                |row| row.get(0),
            )
            .unwrap();

        // 10 entity tables + 1 schema_migrations = 11 tables
        assert_eq!(table_count, 11);
    }
}
