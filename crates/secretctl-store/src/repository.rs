use crate::error::StoreError;
use crate::migrations::apply_migrations;
use rusqlite::{Connection, params};
use secretctl_domain::{
    ActionKind, AgentId, AgentPrincipal, Approval, AuditCheckpoint, AuditEvent, CanonicalOrigin,
    Capability, CapabilityId, CapabilitySummary, CredentialDescriptor, CredentialId, EventId,
    Execution, GrantId, OAuthGrant, RequestId, RiskLevel, StandingGrant,
};
use std::path::Path;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

/// Which standing grants a revocation targets. Revoking by agent or by
/// credential is the common case: a human who no longer trusts one agent
/// should not have to enumerate its grants.
#[derive(Debug, Clone)]
pub enum GrantSelector {
    Id(GrantId),
    Agent(String),
    Credential(String),
    All,
}

impl GrantSelector {
    pub fn matches(&self, grant: &StandingGrant) -> bool {
        match self {
            Self::Id(grant_id) => &grant.grant_id == grant_id,
            Self::Agent(name) => &grant.agent_name == name || grant.agent_id.as_str() == name,
            Self::Credential(name) => &grant.credential_name == name,
            Self::All => true,
        }
    }
}

#[derive(Clone)]
pub struct SqliteStore {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteStore {
    pub fn validate_no_prohibited_persisted_keys(&self) -> Result<(), StoreError> {
        fn inspect(value: &serde_json::Value, path: &str) -> Result<(), StoreError> {
            match value {
                serde_json::Value::Object(fields) => {
                    for (key, value) in fields {
                        if secretctl_crypto::contains_prohibited_key_name(key) {
                            return Err(StoreError::StateConflict(format!(
                                "prohibited secret-bearing metadata key at {path}.{key}"
                            )));
                        }
                        inspect(value, &format!("{path}.{key}"))?;
                    }
                }
                serde_json::Value::Array(items) => {
                    for (index, value) in items.iter().enumerate() {
                        inspect(value, &format!("{path}[{index}]"))?;
                    }
                }
                _ => {}
            }
            Ok(())
        }

        let conn = self.conn.lock().unwrap();
        for (table, column) in [
            ("credentials", "metadata_json"),
            ("audit_events", "event_json"),
        ] {
            let mut statement = conn.prepare(&format!("SELECT {column} FROM {table}"))?;
            let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
            for row in rows {
                let document: serde_json::Value = serde_json::from_str(&row?).map_err(|error| {
                    StoreError::Serialization(format!("invalid {table}.{column}: {error}"))
                })?;
                inspect(&document, &format!("{table}.{column}"))?;
            }
        }
        Ok(())
    }

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

    pub fn create_backup<P: AsRef<Path>>(&self, destination_path: P) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap();
        let mut dest_conn = Connection::open(destination_path)?;
        let backup = rusqlite::backup::Backup::new(&conn, &mut dest_conn)?;
        backup.run_to_completion(5, std::time::Duration::from_millis(250), None)?;
        Ok(())
    }

    pub fn restore_from_backup<P: AsRef<Path>>(&self, source_path: P) -> Result<(), StoreError> {
        let mut conn = self.conn.lock().unwrap();
        let src_conn = Connection::open(source_path)?;
        let backup = rusqlite::backup::Backup::new(&src_conn, &mut conn)?;
        backup.run_to_completion(5, std::time::Duration::from_millis(250), None)?;
        Ok(())
    }

    pub fn schema_version(&self) -> Result<i32, StoreError> {
        let conn = self.conn.lock().unwrap();
        let version: Option<i32> = conn
            .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
                row.get(0)
            })
            .ok()
            .flatten();
        Ok(version.unwrap_or(0))
    }

    pub fn insert_agent(&self, agent: &AgentPrincipal) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO agents
             (agent_id, role, public_key, executable_hash, executable_path, peer_uid,
              display_name, state, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                agent.agent_id.as_str(),
                agent.role,
                agent.public_key,
                agent.executable_hash,
                agent.executable_path,
                agent.peer_uid,
                agent.display_name,
                agent.state,
                agent.created_at.to_rfc3339()
            ],
        )?;
        Ok(())
    }

    /// Install-time enrollment for a broker-owned executable. Reinstallation
    /// rotates the public key and executable attestation as one row update.
    pub fn upsert_agent(&self, agent: &AgentPrincipal) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO agents
             (agent_id, role, public_key, executable_hash, executable_path, peer_uid,
              display_name, state, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(agent_id) DO UPDATE SET
               role = excluded.role,
               public_key = excluded.public_key,
               executable_hash = excluded.executable_hash,
               executable_path = excluded.executable_path,
               peer_uid = excluded.peer_uid,
               display_name = excluded.display_name,
               state = excluded.state",
            params![
                agent.agent_id.as_str(),
                agent.role,
                agent.public_key,
                agent.executable_hash,
                agent.executable_path,
                agent.peer_uid,
                agent.display_name,
                agent.state,
                agent.created_at.to_rfc3339()
            ],
        )?;
        Ok(())
    }

    pub fn get_enrolled_agent(&self, agent_id: &str) -> Result<AgentPrincipal, StoreError> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT agent_id, role, public_key, display_name, peer_uid, executable_path,
                    executable_hash, state, created_at
             FROM agents WHERE agent_id = ?1 AND state = 'enrolled'",
            [agent_id],
            |row| {
                let id: String = row.get(0)?;
                let created_at: String = row.get(8)?;
                Ok(AgentPrincipal {
                    agent_id: AgentId::parse(&id).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            0,
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    })?,
                    role: row.get(1)?,
                    public_key: row.get(2)?,
                    display_name: row.get(3)?,
                    peer_uid: row.get::<_, Option<i64>>(4)?.map(|value| value as u32),
                    executable_path: row.get(5)?,
                    executable_hash: row.get(6)?,
                    state: row.get(7)?,
                    created_at: chrono::DateTime::parse_from_rfc3339(&created_at)
                        .map(|value| value.with_timezone(&chrono::Utc))
                        .map_err(|error| {
                            rusqlite::Error::FromSqlConversionFailure(
                                8,
                                rusqlite::types::Type::Text,
                                Box::new(error),
                            )
                        })?,
                })
            },
        )
        .map_err(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => StoreError::NotFound(agent_id.to_string()),
            other => StoreError::Sqlite(other),
        })
    }

    pub fn list_agents(&self) -> Result<Vec<AgentPrincipal>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let mut statement = conn
            .prepare("SELECT agent_id FROM agents WHERE state = 'enrolled' ORDER BY created_at")?;
        let ids = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        drop(conn);
        ids.iter().map(|id| self.get_enrolled_agent(id)).collect()
    }

    pub fn agent_exists(&self, agent_id: &str) -> Result<bool, StoreError> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM agents WHERE agent_id = ?1 AND state = 'enrolled'",
            [agent_id],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    pub fn resolve_agent_id(
        &self,
        agent_id: &str,
    ) -> Result<Option<secretctl_domain::AgentId>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT agent_id FROM agents WHERE agent_id = ?1 AND state = 'enrolled' LIMIT 1",
        )?;
        let mut rows = stmt.query([agent_id])?;
        if let Some(row) = rows.next()? {
            let id_str: String = row.get(0)?;
            Ok(secretctl_domain::AgentId::parse(&id_str).ok())
        } else {
            Ok(None)
        }
    }

    pub fn insert_audit_event(&self, event: &AuditEvent) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap();
        Self::insert_audit_event_tx(&conn, event)?;
        Ok(())
    }

    fn insert_audit_event_tx(conn: &Connection, event: &AuditEvent) -> Result<(), rusqlite::Error> {
        conn.execute(
            "INSERT INTO audit_events
             (sequence, event_id, event_type, actor_type, actor_id, event_json,
              audit_key_version, previous_hash, event_hash, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                event.sequence as i64,
                event.event_id.as_str(),
                event.event_type,
                event.actor_type,
                event.actor_id,
                event.event_json,
                event.audit_key_version,
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

    /// Persist only the opaque provider locator for an OAuth grant. Tokens and
    /// authorization codes must be stored in the provider, never in SQLite.
    pub fn insert_oauth_grant(&self, grant: &OAuthGrant) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap();
        let scopes = serde_json::to_string(&grant.scopes)
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
        conn.execute(
            "INSERT INTO oauth_grants
             (grant_id, credential_id, provider_locator, scopes_json, subject_hint, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                grant.grant_id.as_str(),
                grant.credential_id.as_str(),
                grant.provider_locator,
                scopes,
                grant.subject_hint,
                grant.created_at.to_rfc3339(),
                grant.expires_at.map(|value| value.to_rfc3339()),
            ],
        )?;
        Ok(())
    }

    pub fn get_oauth_grant(&self, grant_id: &GrantId) -> Result<Option<OAuthGrant>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let result = conn.query_row(
            "SELECT grant_id, credential_id, provider_locator, scopes_json, subject_hint, created_at, expires_at
             FROM oauth_grants WHERE grant_id = ?1",
            [grant_id.as_str()],
            |row| {
                let grant_id: String = row.get(0)?;
                let credential_id: String = row.get(1)?;
                let scopes: String = row.get(3)?;
                let created_at: String = row.get(5)?;
                let expires_at: Option<String> = row.get(6)?;
                Ok(OAuthGrant {
                    grant_id: GrantId::parse(&grant_id).map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?,
                    credential_id: CredentialId::parse(&credential_id).map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?,
                    provider_locator: row.get(2)?,
                    scopes: serde_json::from_str(&scopes).map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?,
                    subject_hint: row.get(4)?,
                    created_at: chrono::DateTime::parse_from_rfc3339(&created_at).map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?.with_timezone(&chrono::Utc),
                    expires_at: expires_at.map(|value| chrono::DateTime::parse_from_rfc3339(&value).map(|date| date.with_timezone(&chrono::Utc))).transpose().map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?,
                })
            },
        );
        match result {
            Ok(grant) => Ok(Some(grant)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    pub fn delete_oauth_grant(&self, grant_id: &GrantId) -> Result<bool, StoreError> {
        let conn = self.conn.lock().unwrap();
        Ok(conn.execute(
            "DELETE FROM oauth_grants WHERE grant_id = ?1",
            [grant_id.as_str()],
        )? == 1)
    }

    pub fn insert_approval(&self, approval: &Approval) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO approvals
             (approval_id, request_id, decision, actor, presence, context_digest, decided_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                approval.approval_id.as_str(),
                approval.request_id.as_str(),
                approval.decision,
                approval.actor,
                approval.presence,
                approval.context_digest,
                approval.decided_at.map(|value| value.to_rfc3339()),
                approval.expires_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn insert_approval_with_audit(
        &self,
        approval: &Approval,
        audit_event: &AuditEvent,
    ) -> Result<(), StoreError> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO approvals
             (approval_id, request_id, decision, actor, presence, context_digest, decided_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                approval.approval_id.as_str(),
                approval.request_id.as_str(),
                approval.decision,
                approval.actor,
                approval.presence,
                approval.context_digest,
                approval.decided_at.map(|value| value.to_rfc3339()),
                approval.expires_at.to_rfc3339(),
            ],
        )?;
        Self::insert_audit_event_tx(&tx, audit_event)?;
        tx.commit()?;
        Ok(())
    }

    pub fn update_approval(&self, approval: &Approval) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap();
        let changed = conn.execute(
            "UPDATE approvals
             SET decision = ?2, actor = ?3, presence = ?4, decided_at = ?5
             WHERE approval_id = ?1 AND decision = 'pending'",
            params![
                approval.approval_id.as_str(),
                approval.decision,
                approval.actor,
                approval.presence,
                approval.decided_at.map(|value| value.to_rfc3339()),
            ],
        )?;
        if changed != 1 {
            return Err(StoreError::NotFound(approval.approval_id.to_string()));
        }
        Ok(())
    }

    pub fn update_approval_with_audit(
        &self,
        approval: &Approval,
        audit_event: &AuditEvent,
    ) -> Result<(), StoreError> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let changed = tx.execute(
            "UPDATE approvals
             SET decision = ?2, actor = ?3, presence = ?4, decided_at = ?5
             WHERE approval_id = ?1 AND decision = 'pending'",
            params![
                approval.approval_id.as_str(),
                approval.decision,
                approval.actor,
                approval.presence,
                approval.decided_at.map(|value| value.to_rfc3339()),
            ],
        )?;
        if changed != 1 {
            return Err(StoreError::StateConflict(approval.approval_id.to_string()));
        }
        Self::insert_audit_event_tx(&tx, audit_event)?;
        tx.commit()?;
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

    pub fn delete_credential_by_name(&self, name: &str) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap();
        let changed = conn.execute("DELETE FROM credentials WHERE name = ?1", [name])?;
        if changed != 1 {
            return Err(StoreError::NotFound(name.to_string()));
        }
        Ok(())
    }

    pub fn list_credentials(&self) -> Result<Vec<CredentialDescriptor>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let mut statement = conn.prepare("SELECT name FROM credentials ORDER BY name")?;
        let names = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        drop(conn);
        names
            .iter()
            .map(|name| self.get_credential_by_name(name))
            .collect()
    }

    pub fn insert_capability_with_audit(
        &self,
        capability: &Capability,
        signing_key_id: &str,
        audit_event: &AuditEvent,
    ) -> Result<(), StoreError> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO capabilities
             (capability_id, request_id, token_hash, state, max_uses, used_count,
              issued_at, consume_deadline, execution_deadline, step_deadline,
              flow_id, step_id, revoked_reason, signing_key_id, policy_hash,
              browser_session_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            params![
                capability.capability_id.as_str(),
                capability.request_id.as_str(),
                capability.token_hash,
                capability.state.as_str(),
                capability.max_uses,
                capability.used_count,
                capability.issued_at.to_rfc3339(),
                capability.consume_deadline.to_rfc3339(),
                capability.execution_deadline.to_rfc3339(),
                capability.step_deadline.map(|value| value.to_rfc3339()),
                capability.flow_id.as_ref().map(|id| id.to_string()),
                capability.step_id.as_ref().map(|id| id.to_string()),
                capability.revoked_reason,
                signing_key_id,
                capability.policy_hash,
                capability.browser_session_id.as_str(),
            ],
        )?;
        Self::insert_audit_event_tx(&tx, audit_event)?;
        tx.commit()?;
        Ok(())
    }

    pub fn consume_capability_with_execution_and_audit(
        &self,
        capability_id: &CapabilityId,
        execution: &Execution,
        audit_event: &AuditEvent,
        totp_step: Option<(&CredentialId, u64)>,
    ) -> Result<(), StoreError> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        if let Some((credential_id, time_step)) = totp_step {
            let claimed = tx.execute(
                "INSERT OR IGNORE INTO totp_issuances
                 (credential_id, time_step, execution_id, issued_at)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    credential_id.as_str(),
                    time_step,
                    execution.execution_id.as_str(),
                    execution.started_at.map(|value| value.to_rfc3339()),
                ],
            )?;
            if claimed != 1 {
                return Err(StoreError::StateConflict(format!(
                    "TOTP step already issued for {credential_id}"
                )));
            }
        }
        let changed = tx.execute(
            "UPDATE capabilities
             SET state = 'consumed', used_count = used_count + 1
             WHERE capability_id = ?1
               AND state IN ('issued', 'active')
               AND used_count < max_uses",
            [capability_id.as_str()],
        )?;
        if changed != 1 {
            return Err(StoreError::StateConflict(capability_id.to_string()));
        }
        tx.execute(
            "INSERT INTO executions
             (execution_id, capability_id, state, prepared_context_digest,
              started_at, completed_at, result_code)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                execution.execution_id.as_str(),
                execution.capability_id.as_str(),
                execution.state.as_str(),
                execution.prepared_context_digest,
                execution.started_at.map(|value| value.to_rfc3339()),
                execution.completed_at.map(|value| value.to_rfc3339()),
                execution.result_code,
            ],
        )?;
        Self::insert_audit_event_tx(&tx, audit_event)?;
        tx.commit()?;
        Ok(())
    }

    pub fn finish_execution_with_audit(
        &self,
        execution: &Execution,
        audit_event: &AuditEvent,
    ) -> Result<(), StoreError> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let changed = tx.execute(
            "UPDATE executions
             SET state = ?2, completed_at = ?3, result_code = ?4
             WHERE execution_id = ?1 AND state = 'consuming'",
            params![
                execution.execution_id.as_str(),
                execution.state.as_str(),
                execution.completed_at.map(|value| value.to_rfc3339()),
                execution.result_code,
            ],
        )?;
        if changed != 1 {
            return Err(StoreError::StateConflict(
                execution.execution_id.to_string(),
            ));
        }
        Self::insert_audit_event_tx(&tx, audit_event)?;
        tx.commit()?;
        Ok(())
    }

    pub fn recover_incomplete_state(&self) -> Result<(usize, usize), StoreError> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let expired = tx.execute(
            "UPDATE capabilities SET state = 'expired', revoked_reason = 'broker_restart'
             WHERE state IN ('issued', 'active')",
            [],
        )?;
        let indeterminate = tx.execute(
            "UPDATE executions SET state = 'indeterminate', completed_at = ?1,
             result_code = 'BROKER_RESTART'
             WHERE state IN ('prepared', 'consuming')",
            [chrono::Utc::now().to_rfc3339()],
        )?;
        tx.commit()?;
        Ok((expired, indeterminate))
    }

    pub fn revoke_capability(
        &self,
        capability_id: &CapabilityId,
        reason: &str,
    ) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap();
        let changed = conn.execute(
            "UPDATE capabilities SET state = 'revoked', revoked_reason = ?2
             WHERE capability_id = ?1 AND state IN ('issued', 'active')",
            params![capability_id.as_str(), reason],
        )?;
        if changed != 1 {
            return Err(StoreError::StateConflict(capability_id.to_string()));
        }
        Ok(())
    }

    pub fn consume_oauth_capability(&self, capability_id: &CapabilityId) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap();
        let changed = conn.execute(
            "UPDATE capabilities SET state = 'consumed', used_count = used_count + 1
             WHERE capability_id = ?1 AND state IN ('issued', 'active') AND used_count < max_uses",
            [capability_id.as_str()],
        )?;
        if changed != 1 {
            return Err(StoreError::StateConflict(capability_id.to_string()));
        }
        Ok(())
    }

    pub fn revoke_capability_with_audit(
        &self,
        capability_id: &CapabilityId,
        reason: &str,
        audit_event: &AuditEvent,
    ) -> Result<(), StoreError> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let changed = tx.execute(
            "UPDATE capabilities SET state = 'revoked', revoked_reason = ?2
             WHERE capability_id = ?1 AND state IN ('issued', 'active')",
            params![capability_id.as_str(), reason],
        )?;
        if changed != 1 {
            return Err(StoreError::StateConflict(capability_id.to_string()));
        }
        Self::insert_audit_event_tx(&tx, audit_event)?;
        tx.commit()?;
        Ok(())
    }

    pub fn revoke_capabilities_not_policy_with_audit(
        &self,
        active_policy_hash: &[u8],
        audit_event: &AuditEvent,
    ) -> Result<usize, StoreError> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let changed = tx.execute(
            "UPDATE capabilities SET state = 'revoked', revoked_reason = 'policy_changed'
             WHERE state IN ('issued', 'active') AND policy_hash != ?1",
            [active_policy_hash],
        )?;
        Self::insert_audit_event_tx(&tx, audit_event)?;
        tx.commit()?;
        Ok(changed)
    }

    pub fn revoke_capabilities_for_session(
        &self,
        browser_session_id: &str,
    ) -> Result<usize, StoreError> {
        let conn = self.conn.lock().unwrap();
        let changed = conn.execute(
            "UPDATE capabilities SET state = 'revoked', revoked_reason = 'session_stale'
             WHERE state IN ('issued', 'active') AND browser_session_id = ?1",
            [browser_session_id],
        )?;
        Ok(changed)
    }

    pub fn list_capabilities(
        &self,
        state: Option<&str>,
    ) -> Result<Vec<CapabilitySummary>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let sql = if state.is_some() {
            "SELECT capability_id, request_id, state, max_uses, used_count, issued_at,
                    consume_deadline, revoked_reason, signing_key_id
             FROM capabilities WHERE state = ?1 ORDER BY issued_at DESC"
        } else {
            "SELECT capability_id, request_id, state, max_uses, used_count, issued_at,
                    consume_deadline, revoked_reason, signing_key_id
             FROM capabilities ORDER BY issued_at DESC"
        };
        let mut statement = conn.prepare(sql)?;
        let map_row = |row: &rusqlite::Row<'_>| -> Result<CapabilitySummary, rusqlite::Error> {
            let capability_id: String = row.get(0)?;
            let request_id: String = row.get(1)?;
            let issued_at: String = row.get(5)?;
            let expires_at: String = row.get(6)?;
            let parse_time = |index, value: String| {
                chrono::DateTime::parse_from_rfc3339(&value)
                    .map(|time| time.with_timezone(&chrono::Utc))
                    .map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            index,
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    })
            };
            Ok(CapabilitySummary {
                capability_id: CapabilityId::parse(&capability_id).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })?,
                request_id: RequestId::parse(&request_id).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        1,
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })?,
                state: row.get(2)?,
                max_uses: row.get(3)?,
                used_count: row.get(4)?,
                issued_at: parse_time(5, issued_at)?,
                expires_at: parse_time(6, expires_at)?,
                revoked_reason: row.get(7)?,
                signing_key_id: row.get(8)?,
            })
        };
        let rows = if let Some(state) = state {
            statement.query_map([state], map_row)?
        } else {
            statement.query_map([], map_row)?
        };
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    pub fn capability_state(&self, capability_id: &CapabilityId) -> Result<String, StoreError> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT state FROM capabilities WHERE capability_id = ?1",
            [capability_id.as_str()],
            |row| row.get(0),
        )
        .map_err(StoreError::from)
    }

    pub fn execution_count(&self) -> Result<u64, StoreError> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM executions", [], |row| row.get(0))?;
        Ok(count as u64)
    }

    pub fn execution_state_for_capability(
        &self,
        capability_id: &CapabilityId,
    ) -> Result<String, StoreError> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT state FROM executions WHERE capability_id = ?1 ORDER BY started_at DESC LIMIT 1",
            [capability_id.as_str()],
            |row| row.get(0),
        )
        .map_err(StoreError::from)
    }

    pub fn list_audit_events(&self) -> Result<Vec<AuditEvent>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let mut statement = conn.prepare(
            "SELECT sequence, event_id, event_type, actor_type, actor_id, event_json,
                    audit_key_version, previous_hash, event_hash, created_at
             FROM audit_events ORDER BY sequence",
        )?;
        let rows = statement.query_map([], |row| {
            let event_id: String = row.get(1)?;
            let created_at: String = row.get(9)?;
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
                audit_key_version: row.get::<_, i64>(6)? as u32,
                previous_hash: row.get(7)?,
                event_hash: row.get(8)?,
                created_at: chrono::DateTime::parse_from_rfc3339(&created_at)
                    .map(|parsed| parsed.with_timezone(&chrono::Utc))
                    .map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            9,
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

    pub fn insert_audit_checkpoint(&self, checkpoint: &AuditCheckpoint) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO audit_checkpoints
             (sequence, event_hash, audit_key_version, signing_key_id, signature, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                checkpoint.sequence as i64,
                checkpoint.event_hash,
                checkpoint.audit_key_version,
                checkpoint.signing_key_id,
                checkpoint.signature,
                checkpoint.created_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn list_audit_checkpoints(&self) -> Result<Vec<AuditCheckpoint>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let mut statement = conn.prepare(
            "SELECT sequence, event_hash, audit_key_version, signing_key_id, signature, created_at
             FROM audit_checkpoints ORDER BY sequence",
        )?;
        let rows = statement.query_map([], |row| {
            let created_at: String = row.get(5)?;
            Ok(AuditCheckpoint {
                sequence: row.get::<_, i64>(0)? as u64,
                event_hash: row.get(1)?,
                audit_key_version: row.get::<_, i64>(2)? as u32,
                signing_key_id: row.get(3)?,
                signature: row.get(4)?,
                created_at: chrono::DateTime::parse_from_rfc3339(&created_at)
                    .map(|value| value.with_timezone(&chrono::Utc))
                    .map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            5,
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    })?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    pub fn register_signing_key(
        &self,
        key_id: &str,
        public_key: &[u8],
        state: &str,
    ) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO trusted_signing_keys
             (key_id, public_key, state, created_at, retired_at)
             VALUES (?1, ?2, ?3, ?4, NULL)
             ON CONFLICT(key_id) DO UPDATE SET public_key = excluded.public_key, state = excluded.state",
            params![key_id, public_key, state, chrono::Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn retire_signing_key(&self, key_id: &str) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap();
        let changed = conn.execute(
            "UPDATE trusted_signing_keys SET state = 'retired', retired_at = ?2
             WHERE key_id = ?1 AND state = 'active'",
            params![key_id, chrono::Utc::now().to_rfc3339()],
        )?;
        if changed != 1 {
            return Err(StoreError::NotFound(key_id.to_string()));
        }
        Ok(())
    }

    pub fn trusted_signing_keys(
        &self,
    ) -> Result<std::collections::HashMap<String, Vec<u8>>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let mut statement = conn.prepare(
            "SELECT key_id, public_key FROM trusted_signing_keys
             WHERE state IN ('active', 'retired')",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        rows.collect::<Result<std::collections::HashMap<_, _>, _>>()
            .map_err(StoreError::from)
    }

    pub fn active_signing_key_id(&self) -> Result<Option<String>, StoreError> {
        let conn = self.conn.lock().unwrap();
        Ok(conn
            .query_row(
                "SELECT key_id FROM trusted_signing_keys WHERE state = 'active'
                 ORDER BY created_at DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .ok())
    }

    pub fn register_audit_key_version(
        &self,
        version: u32,
        key_locator: &str,
        state: &str,
    ) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO audit_key_versions (version, key_locator, state, created_at, retired_at)
             VALUES (?1, ?2, ?3, ?4, NULL)
             ON CONFLICT(version) DO UPDATE SET key_locator = excluded.key_locator, state = excluded.state",
            params![version, key_locator, state, chrono::Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn audit_key_versions(&self) -> Result<Vec<(u32, String, String)>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let mut statement = conn.prepare(
            "SELECT version, key_locator, state FROM audit_key_versions ORDER BY version",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)? as u32,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    pub fn retire_audit_key_version(&self, version: u32) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap();
        let changed = conn.execute(
            "UPDATE audit_key_versions SET state = 'retired', retired_at = ?2
             WHERE version = ?1 AND state = 'active'",
            params![version, chrono::Utc::now().to_rfc3339()],
        )?;
        if changed != 1 {
            return Err(StoreError::NotFound(version.to_string()));
        }
        Ok(())
    }

    pub fn active_audit_key_version(&self) -> Result<Option<(u32, String)>, StoreError> {
        Ok(self
            .audit_key_versions()?
            .into_iter()
            .filter(|(_, _, state)| state == "active")
            .max_by_key(|(version, _, _)| *version)
            .map(|(version, locator, _)| (version, locator)))
    }

    /// Persist a standing grant together with the audit event that records its
    /// creation. Creation and audit share one transaction so a grant can never
    /// exist without a trail.
    pub fn insert_standing_grant_with_audit(
        &self,
        grant: &StandingGrant,
        audit_event: &AuditEvent,
    ) -> Result<(), StoreError> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        // Replacing a live grant for the same tuple is an extension, not a
        // second grant: revoke the old row first so the unique index holds.
        tx.execute(
            "UPDATE standing_grants
             SET revoked_at = ?1, revoked_reason = 'superseded'
             WHERE revoked_at IS NULL
               AND agent_id = ?2 AND credential_name = ?3 AND origin = ?4 AND action = ?5",
            params![
                grant.created_at.to_rfc3339(),
                grant.agent_id.as_str(),
                grant.credential_name,
                grant.origin.as_str(),
                grant.action.as_str(),
            ],
        )?;
        tx.execute(
            "INSERT INTO standing_grants
             (grant_id, agent_id, agent_name, credential_id, credential_name, origin, action,
              risk_ceiling, require_presence, created_at, expires_at, revoked_at,
              revoked_reason, last_used_at, use_count)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, NULL, NULL, NULL, 0)",
            params![
                grant.grant_id.as_str(),
                grant.agent_id.as_str(),
                grant.agent_name,
                grant.credential_id.as_str(),
                grant.credential_name,
                grant.origin.as_str(),
                grant.action.as_str(),
                grant.risk_ceiling.as_str(),
                grant.require_presence as i64,
                grant.created_at.to_rfc3339(),
                grant.expires_at.to_rfc3339(),
            ],
        )?;
        Self::insert_audit_event_tx(&tx, audit_event)?;
        tx.commit()?;
        Ok(())
    }

    fn row_to_standing_grant(row: &rusqlite::Row<'_>) -> rusqlite::Result<StandingGrant> {
        fn conversion<E>(index: usize, error: E) -> rusqlite::Error
        where
            E: std::error::Error + Send + Sync + 'static,
        {
            rusqlite::Error::FromSqlConversionFailure(
                index,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        }
        fn timestamp(
            value: Option<String>,
            index: usize,
        ) -> rusqlite::Result<Option<chrono::DateTime<chrono::Utc>>> {
            value
                .map(|raw| {
                    chrono::DateTime::parse_from_rfc3339(&raw)
                        .map(|parsed| parsed.with_timezone(&chrono::Utc))
                        .map_err(|error| conversion(index, error))
                })
                .transpose()
        }

        let grant_id: String = row.get(0)?;
        let agent_id: String = row.get(1)?;
        let credential_id: String = row.get(3)?;
        let origin: String = row.get(5)?;
        let action: String = row.get(6)?;
        let risk_ceiling: String = row.get(7)?;
        let created_at: String = row.get(9)?;
        let expires_at: String = row.get(10)?;

        Ok(StandingGrant {
            grant_id: GrantId::parse(&grant_id).map_err(|error| conversion(0, error))?,
            agent_id: AgentId::parse(&agent_id).map_err(|error| conversion(1, error))?,
            agent_name: row.get(2)?,
            credential_id: CredentialId::parse(&credential_id)
                .map_err(|error| conversion(3, error))?,
            credential_name: row.get(4)?,
            origin: CanonicalOrigin::parse(&origin).map_err(|error| conversion(5, error))?,
            action: ActionKind::from_str(&action).map_err(|error| conversion(6, error))?,
            risk_ceiling: RiskLevel::from_str(&risk_ceiling)
                .map_err(|error| conversion(7, error))?,
            require_presence: row.get::<_, i64>(8)? != 0,
            created_at: timestamp(Some(created_at), 9)?.expect("created_at is non-null"),
            expires_at: timestamp(Some(expires_at), 10)?.expect("expires_at is non-null"),
            revoked_at: timestamp(row.get(11)?, 11)?,
            revoked_reason: row.get(12)?,
            last_used_at: timestamp(row.get(13)?, 13)?,
            use_count: row.get::<_, i64>(14)?.max(0) as u64,
        })
    }

    const GRANT_COLUMNS: &'static str = "grant_id, agent_id, agent_name, credential_id, \
         credential_name, origin, action, risk_ceiling, require_presence, created_at, \
         expires_at, revoked_at, revoked_reason, last_used_at, use_count";

    /// List grants, newest first. `include_revoked` controls whether the
    /// historical rows come back alongside the live ones.
    pub fn list_standing_grants(
        &self,
        include_revoked: bool,
    ) -> Result<Vec<StandingGrant>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let sql = format!(
            "SELECT {} FROM standing_grants {} ORDER BY created_at DESC",
            Self::GRANT_COLUMNS,
            if include_revoked {
                ""
            } else {
                "WHERE revoked_at IS NULL"
            }
        );
        let mut statement = conn.prepare(&sql)?;
        let grants = statement
            .query_map([], Self::row_to_standing_grant)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(grants)
    }

    /// Find the live grant covering exactly this tuple, if one exists.
    ///
    /// The origin and action comparison happens in SQL on canonical strings, so
    /// a grant for `https://github.com:443` can never be retrieved for any
    /// other origin.
    pub fn find_matching_standing_grant(
        &self,
        agent_id: &AgentId,
        credential_name: &str,
        action: ActionKind,
        origin: &CanonicalOrigin,
    ) -> Result<Option<StandingGrant>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let sql = format!(
            "SELECT {} FROM standing_grants
             WHERE revoked_at IS NULL
               AND agent_id = ?1 AND credential_name = ?2 AND action = ?3 AND origin = ?4
             LIMIT 1",
            Self::GRANT_COLUMNS
        );
        let mut statement = conn.prepare(&sql)?;
        let mut rows = statement.query_map(
            params![
                agent_id.as_str(),
                credential_name,
                action.as_str(),
                origin.as_str()
            ],
            Self::row_to_standing_grant,
        )?;
        rows.next().transpose().map_err(StoreError::Sqlite)
    }

    /// Record that a grant authorized a request. Usage counters make
    /// `secretctl grants` show which standing permissions are actually live.
    pub fn touch_standing_grant(
        &self,
        grant_id: &GrantId,
        used_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE standing_grants SET last_used_at = ?1, use_count = use_count + 1
             WHERE grant_id = ?2",
            params![used_at.to_rfc3339(), grant_id.as_str()],
        )?;
        Ok(())
    }

    /// Revoke every live grant matching the selector, returning the revoked
    /// grants so the caller can audit each one individually.
    pub fn revoke_standing_grants(
        &self,
        selector: &GrantSelector,
        reason: &str,
        revoked_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<StandingGrant>, StoreError> {
        let matching: Vec<StandingGrant> = self
            .list_standing_grants(false)?
            .into_iter()
            .filter(|grant| selector.matches(grant))
            .collect();
        if matching.is_empty() {
            return Ok(Vec::new());
        }
        let conn = self.conn.lock().unwrap();
        for grant in &matching {
            conn.execute(
                "UPDATE standing_grants SET revoked_at = ?1, revoked_reason = ?2
                 WHERE grant_id = ?3 AND revoked_at IS NULL",
                params![revoked_at.to_rfc3339(), reason, grant.grant_id.as_str()],
            )?;
        }
        Ok(matching)
    }

    #[doc(hidden)]
    pub fn install_audit_failure_trigger_for_tests(&self) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            "CREATE TEMP TRIGGER secretctl_test_fail_audit
             BEFORE INSERT ON audit_events
             BEGIN SELECT RAISE(ABORT, 'simulated audit storage failure'); END;",
        )?;
        Ok(())
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
            role: "agent".to_string(),
            public_key: vec![1, 2, 3, 4],
            display_name: "test-agent".to_string(),
            peer_uid: Some(501),
            executable_path: None,
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
            1,
            &[9u8; 32],
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

    #[test]
    fn startup_scan_rejects_secret_bearing_metadata_keys() {
        let store = SqliteStore::in_memory().unwrap();
        store
            .insert_credential(&CredentialDescriptor {
                credential_id: CredentialId::new(),
                name: "unsafe-metadata".to_string(),
                kind: "password".to_string(),
                provider: "memory".to_string(),
                provider_locator: "opaque-locator".to_string(),
                allowed_actions: vec![ActionKind::AuthenticatePassword],
                metadata_json: r#"{"password":"must-not-be-persisted"}"#.to_string(),
                disabled_at: None,
            })
            .unwrap();
        assert!(store.validate_no_prohibited_persisted_keys().is_err());
    }
}
