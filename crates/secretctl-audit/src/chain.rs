use crate::error::AuditError;
use crate::events::{validate_audit_payload, AuditContext};
use chrono::{DateTime, Utc};
use secretctl_domain::{AuditEvent, EventId};
use sha2::{Digest, Sha256};

pub const GENESIS_PREVIOUS_HASH: [u8; 32] = [0u8; 32];

pub fn compute_event_hash(
    previous_hash: &[u8],
    sequence: u64,
    event_id: &EventId,
    event_type: &str,
    actor_type: &str,
    actor_id: Option<&str>,
    event_json: &str,
    created_at: &DateTime<Utc>,
) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(previous_hash);
    hasher.update(sequence.to_be_bytes());
    hasher.update(event_id.as_str().as_bytes());
    hasher.update(event_type.as_bytes());
    hasher.update(actor_type.as_bytes());
    if let Some(act_id) = actor_id {
        hasher.update(act_id.as_bytes());
    }
    hasher.update(event_json.as_bytes());
    hasher.update(created_at.to_rfc3339().as_bytes());
    hasher.finalize().to_vec()
}

pub fn create_audit_event(
    sequence: u64,
    previous_hash: &[u8],
    event_type: impl Into<String>,
    actor_type: impl Into<String>,
    actor_id: Option<String>,
    context: &AuditContext,
    created_at: DateTime<Utc>,
) -> Result<AuditEvent, AuditError> {
    let event_type = event_type.into();
    let actor_type = actor_type.into();
    let event_id = EventId::new();

    let event_json = serde_json::to_string(context)
        .map_err(|e| AuditError::Serialization(e.to_string()))?;

    validate_audit_payload(&event_json)?;

    let event_hash = compute_event_hash(
        previous_hash,
        sequence,
        &event_id,
        &event_type,
        &actor_type,
        actor_id.as_deref(),
        &event_json,
        &created_at,
    );

    Ok(AuditEvent {
        sequence,
        event_id,
        event_type,
        actor_type,
        actor_id,
        event_json,
        previous_hash: previous_hash.to_vec(),
        event_hash,
        created_at,
    })
}

pub fn verify_audit_chain(events: &[AuditEvent]) -> Result<(), AuditError> {
    let mut expected_prev_hash = GENESIS_PREVIOUS_HASH.to_vec();

    for (idx, event) in events.iter().enumerate() {
        let expected_seq = (idx + 1) as u64;
        if event.sequence != expected_seq {
            return Err(AuditError::ChainBroken {
                sequence: event.sequence,
            });
        }

        if event.previous_hash != expected_prev_hash {
            return Err(AuditError::ChainBroken {
                sequence: event.sequence,
            });
        }

        let computed_hash = compute_event_hash(
            &event.previous_hash,
            event.sequence,
            &event.event_id,
            &event.event_type,
            &event.actor_type,
            event.actor_id.as_deref(),
            &event.event_json,
            &event.created_at,
        );

        if computed_hash != event.event_hash {
            return Err(AuditError::ChainBroken {
                sequence: event.sequence,
            });
        }

        expected_prev_hash = event.event_hash.clone();
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_hash_chain_verification() {
        let now = Utc::now();
        let context1 = AuditContext {
            request_id: Some("req_1".to_string()),
            credential_id: Some("cred_1".to_string()),
            capability_id: None,
            browser_session_id: None,
            target_origin: Some("https://github.com".to_string()),
            action: Some("authenticate.password".to_string()),
            decision: None,
            risk_level: None,
            error_code: None,
        };

        let event1 = create_audit_event(
            1,
            &GENESIS_PREVIOUS_HASH,
            "action.requested",
            "agent",
            Some("agent_1".to_string()),
            &context1,
            now,
        )
        .unwrap();

        let context2 = AuditContext {
            request_id: Some("req_1".to_string()),
            credential_id: Some("cred_1".to_string()),
            capability_id: Some("cap_1".to_string()),
            browser_session_id: Some("bs_1".to_string()),
            target_origin: Some("https://github.com".to_string()),
            action: Some("authenticate.password".to_string()),
            decision: Some("allow".to_string()),
            risk_level: Some("medium".to_string()),
            error_code: None,
        };

        let event2 = create_audit_event(
            2,
            &event1.event_hash,
            "policy.evaluated",
            "broker",
            None,
            &context2,
            now + chrono::Duration::milliseconds(10),
        )
        .unwrap();

        let events = vec![event1, event2];
        assert!(verify_audit_chain(&events).is_ok());

        // Tampering with sequence breaks chain
        let mut tampered = events.clone();
        tampered[0].event_type = "tampered.type".to_string();
        assert!(verify_audit_chain(&tampered).is_err());
    }
}
