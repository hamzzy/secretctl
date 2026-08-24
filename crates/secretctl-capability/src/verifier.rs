use crate::error::CapabilityError;
use crate::token::{parse_and_verify_token, CapabilityClaims};
use chrono::{DateTime, Utc};
use secretctl_domain::{BrowserSessionId, CanonicalOrigin, Capability, CapabilityState};

pub struct ExecutionContextSnapshot<'a> {
    pub top_origin: &'a CanonicalOrigin,
    pub frame_origin: &'a CanonicalOrigin,
    pub browser_session_id: &'a BrowserSessionId,
    pub extension_key_id: &'a str,
    pub tab_id: u32,
    pub frame_id: u32,
    pub document_id: &'a str,
    pub navigation_epoch: u64,
}

pub fn verify_and_consume_capability(
    capability: &mut Capability,
    token: &str,
    broker_public_key: &[u8; 32],
    current_context: &ExecutionContextSnapshot,
    now: DateTime<Utc>,
) -> Result<CapabilityClaims, CapabilityError> {
    // 1. Verify token signature and unpack claims
    let claims = parse_and_verify_token(token, broker_public_key)?;

    if claims.v != 1 || claims.aud != "secretctl:browser-runtime" {
        return Err(CapabilityError::BindingMismatch {
            field: "audience",
            expected: "secretctl:browser-runtime".to_string(),
            actual: claims.aud,
        });
    }

    // 2. Check token ID matches capability ID
    if claims.jti != capability.capability_id {
        return Err(CapabilityError::BindingMismatch {
            field: "capability_id",
            expected: capability.capability_id.to_string(),
            actual: claims.jti.to_string(),
        });
    }

    if claims.req_id != capability.request_id
        || claims.agent_id != capability.agent_id
        || claims.cred_id != capability.credential_id
        || claims.action != capability.action
        || claims.recipe_id != capability.recipe_id
        || claims.recipe_hash != capability.recipe_hash
        || claims.policy_hash != capability.policy_hash
    {
        return Err(CapabilityError::BindingMismatch {
            field: "stored_claims",
            expected: "authoritative capability state".to_string(),
            actual: "signed claims mismatch".to_string(),
        });
    }

    // 3. Check expiration
    if now.timestamp() < claims.nbf {
        return Err(CapabilityError::BindingMismatch {
            field: "not_before",
            expected: claims.nbf.to_string(),
            actual: now.timestamp().to_string(),
        });
    }
    if now.timestamp() >= claims.exp || now >= capability.expires_at {
        capability.state = CapabilityState::Expired;
        return Err(CapabilityError::Expired(format!(
            "Capability expired at {}",
            capability.expires_at
        )));
    }

    // 4. Check state and used count
    if capability.state == CapabilityState::Consumed || capability.used_count >= capability.max_uses {
        return Err(CapabilityError::AlreadyConsumed {
            max: capability.max_uses,
            used: capability.used_count,
        });
    }

    if capability.state != CapabilityState::Issued && capability.state != CapabilityState::Active {
        return Err(CapabilityError::Revoked(format!(
            "Capability in invalid state: {}",
            capability.state.as_str()
        )));
    }

    // 5. Check origin binding
    if !claims.top_origin.matches(current_context.top_origin) {
        return Err(CapabilityError::BindingMismatch {
            field: "top_origin",
            expected: claims.top_origin.to_string(),
            actual: current_context.top_origin.to_string(),
        });
    }

    if !claims.frame_origin.matches(current_context.frame_origin) {
        return Err(CapabilityError::BindingMismatch {
            field: "frame_origin",
            expected: claims.frame_origin.to_string(),
            actual: current_context.frame_origin.to_string(),
        });
    }

    // 6. Check session binding
    if claims.browser_session_id != *current_context.browser_session_id {
        return Err(CapabilityError::BindingMismatch {
            field: "browser_session_id",
            expected: claims.browser_session_id.to_string(),
            actual: current_context.browser_session_id.to_string(),
        });
    }

    if claims.extension_key_id != current_context.extension_key_id
        || claims.tab_id != current_context.tab_id
        || claims.frame_id != current_context.frame_id
        || claims.document_id != current_context.document_id
    {
        return Err(CapabilityError::BindingMismatch {
            field: "executor_context",
            expected: format!(
                "{}/{}/{}/{}",
                claims.extension_key_id, claims.tab_id, claims.frame_id, claims.document_id
            ),
            actual: format!(
                "{}/{}/{}/{}",
                current_context.extension_key_id,
                current_context.tab_id,
                current_context.frame_id,
                current_context.document_id
            ),
        });
    }

    // 7. Check navigation epoch binding
    if claims.navigation_epoch != current_context.navigation_epoch {
        return Err(CapabilityError::EpochMismatch {
            expected: claims.navigation_epoch,
            actual: current_context.navigation_epoch,
        });
    }

    // Atomic consume transition
    capability.used_count += 1;
    if capability.used_count >= capability.max_uses {
        capability.state = CapabilityState::Consumed;
    } else {
        capability.state = CapabilityState::Active;
    }

    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::mint_capability;
    use secretctl_crypto::KeyPair;
    use secretctl_domain::{
        ActionKind, AgentId, BrowserSessionId, CanonicalOrigin, CredentialId, RecipeId, RequestId,
    };

    #[test]
    fn test_verify_and_consume_capability_success() {
        let broker_key = KeyPair::generate();
        let pk = broker_key.public_key_bytes();
        let origin = CanonicalOrigin::parse("https://github.com:443").unwrap();
        let session_id = BrowserSessionId::new();

        let (mut cap, token) = mint_capability(
            &broker_key,
            "key1",
            RequestId::new(),
            AgentId::new(),
            CredentialId::new(),
            ActionKind::AuthenticatePassword,
            origin.clone(),
            origin.clone(),
            session_id.clone(),
            "ext-key-1".to_string(),
            42,
            0,
            "document-1".to_string(),
            5,
            RecipeId::parse("rcp_login").unwrap(),
            vec![1, 2, 3],
            vec![4, 5, 6],
            Utc::now(),
            30,
            1,
        );

        let context = ExecutionContextSnapshot {
            top_origin: &origin,
            frame_origin: &origin,
            browser_session_id: &session_id,
            extension_key_id: "ext-key-1",
            tab_id: 42,
            frame_id: 0,
            document_id: "document-1",
            navigation_epoch: 5,
        };

        let res = verify_and_consume_capability(&mut cap, &token, &pk, &context, Utc::now());
        assert!(res.is_ok());
        assert_eq!(cap.state, CapabilityState::Consumed);
        assert_eq!(cap.used_count, 1);

        // Second consume fails (single use)
        let res2 = verify_and_consume_capability(&mut cap, &token, &pk, &context, Utc::now());
        assert!(res2.is_err());
    }

    #[test]
    fn test_verify_fails_on_epoch_mismatch() {
        let broker_key = KeyPair::generate();
        let pk = broker_key.public_key_bytes();
        let origin = CanonicalOrigin::parse("https://github.com:443").unwrap();
        let session_id = BrowserSessionId::new();

        let (mut cap, token) = mint_capability(
            &broker_key,
            "key1",
            RequestId::new(),
            AgentId::new(),
            CredentialId::new(),
            ActionKind::AuthenticatePassword,
            origin.clone(),
            origin.clone(),
            session_id.clone(),
            "ext-key-1".to_string(),
            42,
            0,
            "document-1".to_string(),
            5,
            RecipeId::parse("rcp_login").unwrap(),
            vec![1, 2, 3],
            vec![4, 5, 6],
            Utc::now(),
            30,
            1,
        );

        let context = ExecutionContextSnapshot {
            top_origin: &origin,
            frame_origin: &origin,
            browser_session_id: &session_id,
            extension_key_id: "ext-key-1",
            tab_id: 42,
            frame_id: 0,
            document_id: "document-1",
            navigation_epoch: 6, // epoch changed
        };

        let res = verify_and_consume_capability(&mut cap, &token, &pk, &context, Utc::now());
        assert!(res.is_err());
    }
}
