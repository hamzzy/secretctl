use crate::error::AuditError;
use crate::events::{AuditContext, validate_audit_payload};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use secretctl_crypto::{KeyPair, verify_signature};
use secretctl_domain::{AuditCheckpoint, AuditEvent, EventId};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

type HmacSha256 = Hmac<Sha256>;

pub const GENESIS_PREVIOUS_HASH: [u8; 32] = [0u8; 32];
const EVENT_DOMAIN: &[u8] = b"secretctl.audit.event.v1";
const CHECKPOINT_DOMAIN: &[u8] = b"secretctl.audit.checkpoint.v1";

fn update_len_prefixed(mac: &mut HmacSha256, value: &[u8]) {
    mac.update(&(value.len() as u64).to_be_bytes());
    mac.update(value);
}

#[allow(clippy::too_many_arguments)]
pub fn compute_event_hash(
    audit_key_version: u32,
    audit_key: &[u8],
    previous_hash: &[u8],
    sequence: u64,
    event_id: &EventId,
    event_type: &str,
    actor_type: &str,
    actor_id: Option<&str>,
    event_json: &str,
    created_at: &DateTime<Utc>,
) -> Result<Vec<u8>, AuditError> {
    if audit_key_version == 0 || audit_key.len() < 32 {
        return Err(AuditError::Serialization(
            "invalid audit key version or length".to_string(),
        ));
    }
    let mut mac = HmacSha256::new_from_slice(audit_key)
        .map_err(|_| AuditError::Serialization("invalid audit key".to_string()))?;
    mac.update(EVENT_DOMAIN);
    mac.update(&audit_key_version.to_be_bytes());
    update_len_prefixed(&mut mac, previous_hash);
    mac.update(&sequence.to_be_bytes());
    update_len_prefixed(&mut mac, event_id.as_str().as_bytes());
    update_len_prefixed(&mut mac, event_type.as_bytes());
    update_len_prefixed(&mut mac, actor_type.as_bytes());
    update_len_prefixed(&mut mac, actor_id.unwrap_or_default().as_bytes());
    update_len_prefixed(&mut mac, event_json.as_bytes());
    update_len_prefixed(&mut mac, created_at.to_rfc3339().as_bytes());
    Ok(mac.finalize().into_bytes().to_vec())
}

#[allow(clippy::too_many_arguments)]
pub fn create_audit_event(
    sequence: u64,
    previous_hash: &[u8],
    audit_key_version: u32,
    audit_key: &[u8],
    event_type: impl Into<String>,
    actor_type: impl Into<String>,
    actor_id: Option<String>,
    context: &AuditContext,
    created_at: DateTime<Utc>,
) -> Result<AuditEvent, AuditError> {
    let event_type = event_type.into();
    let actor_type = actor_type.into();
    let event_id = EventId::new();
    let event_json =
        serde_json::to_string(context).map_err(|e| AuditError::Serialization(e.to_string()))?;
    validate_audit_payload(&event_json)?;
    let event_hash = compute_event_hash(
        audit_key_version,
        audit_key,
        previous_hash,
        sequence,
        &event_id,
        &event_type,
        &actor_type,
        actor_id.as_deref(),
        &event_json,
        &created_at,
    )?;

    Ok(AuditEvent {
        sequence,
        event_id,
        event_type,
        actor_type,
        actor_id,
        event_json,
        audit_key_version,
        previous_hash: previous_hash.to_vec(),
        event_hash,
        created_at,
    })
}

pub fn verify_audit_chain(
    events: &[AuditEvent],
    audit_keys: &HashMap<u32, Vec<u8>>,
) -> Result<(), AuditError> {
    let mut expected_prev_hash = GENESIS_PREVIOUS_HASH.to_vec();
    for (idx, event) in events.iter().enumerate() {
        let expected_seq = (idx + 1) as u64;
        if event.sequence != expected_seq || event.previous_hash != expected_prev_hash {
            return Err(AuditError::ChainBroken {
                sequence: event.sequence,
            });
        }
        let computed_hash = if event.audit_key_version == 0 {
            // Migration compatibility for pre-M1 records. New records can never
            // use version zero and are always HMAC protected.
            let mut hasher = Sha256::new();
            hasher.update(&event.previous_hash);
            hasher.update(event.sequence.to_be_bytes());
            hasher.update(event.event_id.as_str().as_bytes());
            hasher.update(event.event_type.as_bytes());
            hasher.update(event.actor_type.as_bytes());
            if let Some(actor_id) = event.actor_id.as_deref() {
                hasher.update(actor_id.as_bytes());
            }
            hasher.update(event.event_json.as_bytes());
            hasher.update(event.created_at.to_rfc3339().as_bytes());
            hasher.finalize().to_vec()
        } else {
            let audit_key = audit_keys.get(&event.audit_key_version).ok_or_else(|| {
                AuditError::Serialization(format!(
                    "unknown audit key version {}",
                    event.audit_key_version
                ))
            })?;
            compute_event_hash(
                event.audit_key_version,
                audit_key,
                &event.previous_hash,
                event.sequence,
                &event.event_id,
                &event.event_type,
                &event.actor_type,
                event.actor_id.as_deref(),
                &event.event_json,
                &event.created_at,
            )?
        };
        if computed_hash != event.event_hash {
            return Err(AuditError::ChainBroken {
                sequence: event.sequence,
            });
        }
        expected_prev_hash = event.event_hash.clone();
    }
    Ok(())
}

fn checkpoint_message(checkpoint: &AuditCheckpoint) -> Vec<u8> {
    let mut digest = Sha256::new();
    digest.update(CHECKPOINT_DOMAIN);
    digest.update(checkpoint.sequence.to_be_bytes());
    digest.update((checkpoint.event_hash.len() as u64).to_be_bytes());
    digest.update(&checkpoint.event_hash);
    digest.update(checkpoint.audit_key_version.to_be_bytes());
    digest.update((checkpoint.signing_key_id.len() as u64).to_be_bytes());
    digest.update(checkpoint.signing_key_id.as_bytes());
    digest.update(checkpoint.created_at.to_rfc3339().as_bytes());
    digest.finalize().to_vec()
}

pub fn create_audit_checkpoint(
    sequence: u64,
    event_hash: Vec<u8>,
    audit_key_version: u32,
    signing_key_id: impl Into<String>,
    signing_key: &KeyPair,
    created_at: DateTime<Utc>,
) -> AuditCheckpoint {
    let mut checkpoint = AuditCheckpoint {
        sequence,
        event_hash,
        audit_key_version,
        signing_key_id: signing_key_id.into(),
        signature: Vec::new(),
        created_at,
    };
    checkpoint.signature = signing_key.sign(&checkpoint_message(&checkpoint)).to_vec();
    checkpoint
}

pub fn verify_audit_checkpoints(
    events: &[AuditEvent],
    checkpoints: &[AuditCheckpoint],
    signing_keys: &HashMap<String, Vec<u8>>,
) -> Result<(), AuditError> {
    for checkpoint in checkpoints {
        let event = events
            .iter()
            .find(|event| event.sequence == checkpoint.sequence)
            .ok_or(AuditError::ChainBroken {
                sequence: checkpoint.sequence,
            })?;
        if event.event_hash != checkpoint.event_hash
            || event.audit_key_version != checkpoint.audit_key_version
        {
            return Err(AuditError::ChainBroken {
                sequence: checkpoint.sequence,
            });
        }
        let public_key = signing_keys
            .get(&checkpoint.signing_key_id)
            .ok_or_else(|| {
                AuditError::Serialization(format!(
                    "unknown checkpoint signing key {}",
                    checkpoint.signing_key_id
                ))
            })?;
        verify_signature(
            public_key,
            &checkpoint_message(checkpoint),
            &checkpoint.signature,
        )
        .map_err(|_| AuditError::ChainBroken {
            sequence: checkpoint.sequence,
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> AuditContext {
        AuditContext {
            request_id: Some("req_1".to_string()),
            credential_id: Some("cred_1".to_string()),
            capability_id: None,
            browser_session_id: None,
            target_origin: Some("https://github.com".to_string()),
            action: Some("authenticate.password".to_string()),
            decision: None,
            risk_level: None,
            error_code: None,
        }
    }

    #[test]
    fn keyed_chain_and_signed_checkpoint_detect_tamper_reorder_and_delete() {
        let key_v1 = vec![7u8; 32];
        let key_v2 = vec![8u8; 32];
        let mut audit_keys = HashMap::from([(1, key_v1.clone()), (2, key_v2.clone())]);
        let now = Utc::now();
        let event1 = create_audit_event(
            1,
            &GENESIS_PREVIOUS_HASH,
            1,
            &key_v1,
            "action.requested",
            "agent",
            Some("agent_1".to_string()),
            &context(),
            now,
        )
        .unwrap();
        let event2 = create_audit_event(
            2,
            &event1.event_hash,
            2,
            &key_v2,
            "policy.decided",
            "broker",
            None,
            &context(),
            now + chrono::Duration::milliseconds(1),
        )
        .unwrap();
        let events = vec![event1, event2];
        assert!(verify_audit_chain(&events, &audit_keys).is_ok());

        let signing_key = KeyPair::generate();
        let checkpoint = create_audit_checkpoint(
            2,
            events[1].event_hash.clone(),
            2,
            "signing-v2",
            &signing_key,
            now,
        );
        let signing_keys = HashMap::from([(
            "signing-v2".to_string(),
            signing_key.public_key_bytes().to_vec(),
        )]);
        assert!(verify_audit_checkpoints(&events, &[checkpoint.clone()], &signing_keys).is_ok());

        let mut tampered = events.clone();
        tampered[0].event_type = "tampered".to_string();
        assert!(verify_audit_chain(&tampered, &audit_keys).is_err());
        let reordered = vec![events[1].clone(), events[0].clone()];
        assert!(verify_audit_chain(&reordered, &audit_keys).is_err());
        assert!(verify_audit_checkpoints(&events[..1], &[checkpoint], &signing_keys).is_err());
        audit_keys.remove(&2);
        assert!(verify_audit_chain(&events, &audit_keys).is_err());
    }
}
