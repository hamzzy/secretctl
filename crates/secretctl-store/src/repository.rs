use crate::error::StoreError;
use crate::migrations::apply_migrations;
use rusqlite::{Connection, params};
use secretctl_domain::{
    ActionKind, AgentPrincipal, AuditEvent, CredentialDescriptor, CredentialId, EventId,
};
use std::path::Path;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct SqliteStore {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteStore {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, StoreError> {
        let mut conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        apply_migrations(&mut conn)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    pub fn in_memory() -> Result<Self, StoreError> {
        let mut conn = Connection::open_in_memory()?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        apply_migrations(&mut conn)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    pub fn insert_agent(&self, agent: &AgentPrincipal) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO agents (agent_id, public_key, executable_hash, display_name, state, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                agent.agent_id.as_str(),
                agent.public_key,
                agent.executable_hash,
                agent.display_name,
                agent.state,
                agent.created_at.to_rfc3339()
            ],
        )?;
        Ok(())
    }

    pub fn agent_exists(&self, agent_id_or_name: &str) -> Result<bool, StoreError> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM agents WHERE (agent_id = ?1 OR display_name = ?1) AND state = 'enrolled'",
            [agent_id_or_name],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    pub fn resolve_agent_id(
        &self,
        agent_id_or_name: &str,
    ) -> Result<Option<secretctl_domain::AgentId>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT agent_id FROM agents WHERE (agent_id = ?1 OR display_name = ?1) AND state = 'enrolled' LIMIT 1"
        )?;
        let mut rows = stmt.query([agent_id_or_name])?;
        if let Some(row) = rows.next()? {
            let id_str: String = row.get(0)?;
            Ok(secretctl_domain::AgentId::parse(&id_str).ok())
        } else {
            Ok(None)
        }
    }

    pub fn insert_audit_event(&self, event: &AuditEvent) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO audit_events (event_id, event_type, actor_type, actor_id, event_json, previous_hash, event_hash, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                event.event_id.as_str(),
                event.event_type,
                event.actor_type,
                event.actor_id,
                event.event_json,
                event.previous_hash,
                event.event_hash,
                event.created_at.to_rfc3339()
            ],
        )?;
        Ok(())
    }

    pub fn insert_credential(&self, credential: &CredentialDescriptor) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap();
        let allowed_actions = serde_json::to_string(&credential.allowed_actions)
            .map_err(|e| StoreError::Serialization(e.to_string()))?;
        conn.execute(
            "INSERT INTO credentials
             (credential_id, name, kind, provider, provider_locator, allowed_actions_json, metadata_json, disabled_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                credential.credential_id.as_str(),
                credential.name,
                credential.kind,
                credential.provider,
                credential.provider_locator,
                allowed_actions,
                credential.metadata_json,
                credential.disabled_at.map(|value| value.to_rfc3339()),
            ],
        )?;
        Ok(())
    }

    pub fn get_credential_by_name(&self, name: &str) -> Result<CredentialDescriptor, StoreError> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT credential_id, name, kind, provider, provider_locator,
                    allowed_actions_json, metadata_json, disabled_at
             FROM credentials WHERE name = ?1",
            [name],
            |row| {
                let credential_id: String = row.get(0)?;
                let allowed_actions_json: String = row.get(5)?;
                let disabled_at: Option<String> = row.get(7)?;
                let allowed_actions: Vec<ActionKind> = serde_json::from_str(&allowed_actions_json)
                    .map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            5,
                            rusqlite::types::Type::Text,
                            Box::new(e),
                        )
                    })?;
                let disabled_at = disabled_at
                    .map(|value| {
                        chrono::DateTime::parse_from_rfc3339(&value)
                            .map(|parsed| parsed.with_timezone(&chrono::Utc))
                            .map_err(|e| {
                                rusqlite::Error::FromSqlConversionFailure(
                                    7,
                                    rusqlite::types::Type::Text,
                                    Box::new(e),
                                )
                            })
                    })
                    .transpose()?;
                Ok(CredentialDescriptor {
                    credential_id: CredentialId::parse(&credential_id).map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            0,
                            rusqlite::types::Type::Text,
                            Box::new(e),
                        )
                    })?,
                    name: row.get(1)?,
                    kind: row.get(2)?,
                    provider: row.get(3)?,
                    provider_locator: row.get(4)?,
                    allowed_actions,
                    metadata_json: row.get(6)?,
                    disabled_at,
                })
            },
        )
        .map_err(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => StoreError::NotFound(name.to_string()),
            other => StoreError::Sqlite(other),
        })
    }

    pub fn list_audit_events(&self) -> Result<Vec<AuditEvent>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let mut statement = conn.prepare(
            "SELECT sequence, event_id, event_type, actor_type, actor_id, event_json,
                    previous_hash, event_hash, created_at
             FROM audit_events ORDER BY sequence",
        )?;
        let rows = statement.query_map([], |row| {
            let event_id: String = row.get(1)?;
            let created_at: String = row.get(8)?;
            Ok(AuditEvent {
                sequence: row.get::<_, i64>(0)? as u64,
                event_id: EventId::parse(&event_id).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        1,
                        rusqlite::types::Type::Text,
                        Box::new(e),
                    )
                })?,
                event_type: row.get(2)?,
                actor_type: row.get(3)?,
                actor_id: row.get(4)?,
                event_json: row.get(5)?,
                previous_hash: row.get(6)?,
                event_hash: row.get(7)?,
                created_at: chrono::DateTime::parse_from_rfc3339(&created_at)
                    .map(|parsed| parsed.with_timezone(&chrono::Utc))
                    .map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            8,
                            rusqlite::types::Type::Text,
                            Box::new(e),
                        )
                    })?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    pub fn get_latest_audit_hash(&self) -> Result<Vec<u8>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let result: Option<Vec<u8>> = conn
            .query_row(
                "SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .ok();
        Ok(result.unwrap_or_else(|| secretctl_audit::GENESIS_PREVIOUS_HASH.to_vec()))
    }

    pub fn get_latest_audit_sequence(&self) -> Result<u64, StoreError> {
        let conn = self.conn.lock().unwrap();
        let sequence: i64 = conn.query_row(
            "SELECT COALESCE(MAX(sequence), 0) FROM audit_events",
            [],
            |row| row.get(0),
        )?;
        Ok(sequence as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use secretctl_audit::{AuditContext, GENESIS_PREVIOUS_HASH, create_audit_event};
    use secretctl_domain::AgentId;

    #[test]
    fn test_sqlite_store_agent_and_audit() {
        let store = SqliteStore::in_memory().unwrap();

        let agent = AgentPrincipal {
            agent_id: AgentId::new(),
            public_key: vec![1, 2, 3, 4],
            display_name: "test-agent".to_string(),
            executable_hash: None,
            state: "enrolled".to_string(),
            created_at: Utc::now(),
        };

        store.insert_agent(&agent).unwrap();

        let context = AuditContext {
            request_id: None,
            credential_id: None,
            capability_id: None,
            browser_session_id: None,
            target_origin: None,
            action: None,
            decision: None,
            risk_level: None,
            error_code: None,
        };

        let audit_event = create_audit_event(
            1,
            &GENESIS_PREVIOUS_HASH,
            "agent.enrolled",
            "agent",
            Some(agent.agent_id.to_string()),
            &context,
            Utc::now(),
        )
        .unwrap();

        store.insert_audit_event(&audit_event).unwrap();
        let latest_hash = store.get_latest_audit_hash().unwrap();
        assert_eq!(latest_hash, audit_event.event_hash);
    }
}
