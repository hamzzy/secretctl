use crate::error::CapabilityError;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use secretctl_crypto::{KeyPair, sha256_digest, verify_signature};
use secretctl_domain::{
    ActionKind, AgentId, BrowserSessionId, CanonicalOrigin, Capability, CapabilityId,
    CapabilityState, CredentialId, RecipeId, RequestId,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityClaims {
    pub v: u8,
    pub aud: String,
    pub jti: CapabilityId,
    pub req_id: RequestId,
    pub agent_id: AgentId,
    pub cred_id: CredentialId,
    pub action: ActionKind,
    pub top_origin: CanonicalOrigin,
    pub frame_origin: CanonicalOrigin,
    pub browser_session_id: BrowserSessionId,
    pub extension_key_id: String,
    pub tab_id: u32,
    pub frame_id: u32,
    pub document_id: String,
    pub navigation_epoch: u64,
    pub recipe_id: RecipeId,
    pub recipe_hash: Vec<u8>,
    pub policy_hash: Vec<u8>,
    pub nbf: i64,
    pub iat: i64,
    pub exp: i64,
    pub max_uses: u32,
    pub issuer_key_id: String,
}

#[allow(clippy::too_many_arguments)]
pub fn mint_capability(
    broker_key: &KeyPair,
    issuer_key_id: &str,
    request_id: RequestId,
    agent_id: AgentId,
    credential_id: CredentialId,
    action: ActionKind,
    top_origin: CanonicalOrigin,
    frame_origin: CanonicalOrigin,
    browser_session_id: BrowserSessionId,
    extension_key_id: String,
    tab_id: u32,
    frame_id: u32,
    document_id: String,
    navigation_epoch: u64,
    recipe_id: RecipeId,
    recipe_hash: Vec<u8>,
    policy_hash: Vec<u8>,
    issued_at: DateTime<Utc>,
    ttl_seconds: u64,
    max_uses: u32,
) -> (Capability, String) {
    let capability_id = CapabilityId::new();
    let expires_at = issued_at + chrono::Duration::seconds(ttl_seconds as i64);

    let claims = CapabilityClaims {
        v: 1,
        aud: "secretctl:browser-runtime".to_string(),
        jti: capability_id.clone(),
        req_id: request_id.clone(),
        agent_id: agent_id.clone(),
        cred_id: credential_id.clone(),
        action,
        top_origin: top_origin.clone(),
        frame_origin: frame_origin.clone(),
        browser_session_id: browser_session_id.clone(),
        extension_key_id: extension_key_id.clone(),
        tab_id,
        frame_id,
        document_id: document_id.clone(),
        navigation_epoch,
        recipe_id: recipe_id.clone(),
        recipe_hash: recipe_hash.clone(),
        policy_hash: policy_hash.clone(),
        nbf: issued_at.timestamp() - 1,
        iat: issued_at.timestamp(),
        exp: expires_at.timestamp(),
        max_uses,
        issuer_key_id: issuer_key_id.to_string(),
    };

    let claims_json = serde_json::to_vec(&claims).expect("valid claims serialization");
    let claims_b64 = URL_SAFE_NO_PAD.encode(&claims_json);
    let signature = broker_key.sign(claims_b64.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(signature);

    let token = format!("{}.{}", claims_b64, sig_b64);
    let token_hash = sha256_digest(token.as_bytes()).to_vec();

    let capability = Capability {
        capability_id,
        request_id,
        agent_id,
        credential_id,
        action,
        top_origin,
        frame_origin,
        browser_session_id,
        extension_key_id,
        tab_id,
        frame_id,
        document_id,
        navigation_epoch,
        recipe_id,
        recipe_hash,
        policy_hash,
        token_hash,
        state: CapabilityState::Issued,
        max_uses,
        used_count: 0,
        issued_at,
        expires_at,
        revoked_reason: None,
    };

    (capability, token)
}

pub fn parse_and_verify_token(
    token: &str,
    broker_public_key: &[u8; 32],
) -> Result<CapabilityClaims, CapabilityError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 2 {
        return Err(CapabilityError::Serialization(
            "Malformed token format".to_string(),
        ));
    }

    let claims_b64 = parts[0];
    let sig_b64 = parts[1];

    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|e| CapabilityError::Serialization(e.to_string()))?;

    verify_signature(broker_public_key, claims_b64.as_bytes(), &sig_bytes)
        .map_err(|_| CapabilityError::InvalidSignature)?;

    let claims_bytes = URL_SAFE_NO_PAD
        .decode(claims_b64)
        .map_err(|e| CapabilityError::Serialization(e.to_string()))?;

    let claims: CapabilityClaims = serde_json::from_slice(&claims_bytes)
        .map_err(|e| CapabilityError::Serialization(e.to_string()))?;

    Ok(claims)
}

pub fn parse_and_verify_token_with_keys(
    token: &str,
    active_keys: &HashMap<String, Vec<u8>>,
) -> Result<CapabilityClaims, CapabilityError> {
    let claims_part = token
        .split('.')
        .next()
        .ok_or_else(|| CapabilityError::Serialization("Malformed token format".to_string()))?;
    let claims_bytes = URL_SAFE_NO_PAD
        .decode(claims_part)
        .map_err(|error| CapabilityError::Serialization(error.to_string()))?;
    let unverified: CapabilityClaims = serde_json::from_slice(&claims_bytes)
        .map_err(|error| CapabilityError::Serialization(error.to_string()))?;
    let public_key = active_keys
        .get(&unverified.issuer_key_id)
        .ok_or(CapabilityError::InvalidSignature)?;
    let public_key: &[u8; 32] = public_key
        .as_slice()
        .try_into()
        .map_err(|_| CapabilityError::InvalidSignature)?;
    let verified = parse_and_verify_token(token, public_key)?;
    if verified.issuer_key_id != unverified.issuer_key_id {
        return Err(CapabilityError::InvalidSignature);
    }
    Ok(verified)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capability_mint_and_verify() {
        let broker_key = KeyPair::generate();
        let pk = broker_key.public_key_bytes();

        let top_origin = CanonicalOrigin::parse("https://github.com:443").unwrap();
        let frame_origin = CanonicalOrigin::parse("https://github.com:443").unwrap();

        let (cap, token) = mint_capability(
            &broker_key,
            "broker-key-1",
            RequestId::new(),
            AgentId::new(),
            CredentialId::new(),
            ActionKind::AuthenticatePassword,
            top_origin.clone(),
            frame_origin.clone(),
            BrowserSessionId::new(),
            "ext-key-1".to_string(),
            42,
            0,
            "document-1".to_string(),
            1,
            RecipeId::parse("rcp_login").unwrap(),
            vec![1, 2, 3],
            vec![4, 5, 6],
            Utc::now(),
            30,
            1,
        );

        assert_eq!(cap.state, CapabilityState::Issued);
        assert_eq!(cap.max_uses, 1);

        let verified_claims = parse_and_verify_token(&token, &pk).expect("should verify token");
        assert_eq!(verified_claims.jti, cap.capability_id);
        assert_eq!(verified_claims.top_origin, top_origin);
    }

    #[test]
    fn key_rotation_rejects_retired_and_unknown_signers() {
        let old_key = KeyPair::generate();
        let new_key = KeyPair::generate();
        let origin = CanonicalOrigin::parse("https://github.com:443").unwrap();
        let (_, old_token) = mint_capability(
            &old_key,
            "old-key",
            RequestId::new(),
            AgentId::new(),
            CredentialId::new(),
            ActionKind::AuthenticatePassword,
            origin.clone(),
            origin,
            BrowserSessionId::new(),
            "ext-key-1".to_string(),
            1,
            0,
            "doc".to_string(),
            1,
            RecipeId::parse("rcp_login").unwrap(),
            vec![1],
            vec![2],
            Utc::now(),
            30,
            1,
        );
        let active_old =
            HashMap::from([("old-key".to_string(), old_key.public_key_bytes().to_vec())]);
        assert!(parse_and_verify_token_with_keys(&old_token, &active_old).is_ok());
        let active_new =
            HashMap::from([("new-key".to_string(), new_key.public_key_bytes().to_vec())]);
        assert!(parse_and_verify_token_with_keys(&old_token, &active_new).is_err());
        assert!(parse_and_verify_token_with_keys(&old_token, &HashMap::new()).is_err());
    }
}
