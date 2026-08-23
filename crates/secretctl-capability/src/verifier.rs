use crate::error::CapabilityError;
use crate::token::{parse_and_verify_token, CapabilityClaims};
use chrono::{DateTime, Utc};
use secretctl_domain::{BrowserSessionId, CanonicalOrigin, Capability, CapabilityState};

pub struct ExecutionContextSnapshot<'a> {
    pub top_origin: &'a CanonicalOrigin,
    pub frame_origin: &'a CanonicalOrigin,
    pub browser_session_id: &'a BrowserSessionId,
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

    // 2. Check token ID matches capability ID
    if claims.jti != capability.capability_id {
        return Err(CapabilityError::BindingMismatch {
            field: "capability_id",
            expected: capability.capability_id.to_string(),
            actual: claims.jti.to_string(),
        });
    }

    // 3. Check expiration
    if now.timestamp() > claims.exp || now > capability.expires_at {
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
        ActionKind, AgentId, BrowserSessionId, CanonicalOrigin, CredentialId, RequestId,
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
            5,
            Utc::now(),
            30,
            1,
        );

        let context = ExecutionContextSnapshot {
            top_origin: &origin,
            frame_origin: &origin,
            browser_session_id: &session_id,
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
            5,
            Utc::now(),
            30,
            1,
        );

        let context = ExecutionContextSnapshot {
            top_origin: &origin,
            frame_origin: &origin,
            browser_session_id: &session_id,
            navigation_epoch: 6, // epoch changed
        };

        let res = verify_and_consume_capability(&mut cap, &token, &pk, &context, Utc::now());
        assert!(res.is_err());
    }
}
