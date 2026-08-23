use crate::error::StoreError;
use crate::migrations::apply_migrations;
use rusqlite::{params, Connection};
use secretctl_domain::{AgentPrincipal, AuditEvent};
use std::path::Path;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct SqliteStore {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteStore {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, StoreError> {
        let mut conn = Connection::open(path)?;
        apply_migrations(&mut conn)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    pub fn in_memory() -> Result<Self, StoreError> {
        let mut conn = Connection::open_in_memory()?;
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use secretctl_audit::{create_audit_event, AuditContext, GENESIS_PREVIOUS_HASH};
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
