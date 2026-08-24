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
use std::str::FromStr;

const COSE_ALG_EDDSA: i8 = -8;

#[derive(Debug, Clone, minicbor::Encode, minicbor::Decode)]
#[cbor(array)]
struct CapabilityClaimsWire {
    #[n(0)]
    v: u8,
    #[n(1)]
    aud: String,
    #[n(2)]
    jti: String,
    #[n(3)]
    req_id: String,
    #[n(4)]
    agent_id: String,
    #[n(5)]
    cred_id: String,
    #[n(6)]
    action: String,
    #[n(7)]
    top_origin: String,
    #[n(8)]
    frame_origin: String,
    #[n(9)]
    browser_session_id: String,
    #[n(10)]
    extension_key_id: String,
    #[n(11)]
    tab_id: u32,
    #[n(12)]
    frame_id: u32,
    #[n(13)]
    document_id: String,
    #[n(14)]
    navigation_epoch: u64,
    #[n(15)]
    recipe_id: String,
    #[n(16)]
    recipe_hash: Vec<u8>,
    #[n(17)]
    policy_hash: Vec<u8>,
    #[n(18)]
    nbf: i64,
    #[n(19)]
    iat: i64,
    #[n(20)]
    exp: i64,
    #[n(21)]
    max_uses: u32,
    #[n(22)]
    issuer_key_id: String,
}

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

impl From<&CapabilityClaims> for CapabilityClaimsWire {
    fn from(value: &CapabilityClaims) -> Self {
        Self {
            v: value.v,
            aud: value.aud.clone(),
            jti: value.jti.to_string(),
            req_id: value.req_id.to_string(),
            agent_id: value.agent_id.to_string(),
            cred_id: value.cred_id.to_string(),
            action: value.action.to_string(),
            top_origin: value.top_origin.to_string(),
            frame_origin: value.frame_origin.to_string(),
            browser_session_id: value.browser_session_id.to_string(),
            extension_key_id: value.extension_key_id.clone(),
            tab_id: value.tab_id,
            frame_id: value.frame_id,
            document_id: value.document_id.clone(),
            navigation_epoch: value.navigation_epoch,
            recipe_id: value.recipe_id.to_string(),
            recipe_hash: value.recipe_hash.clone(),
            policy_hash: value.policy_hash.clone(),
            nbf: value.nbf,
            iat: value.iat,
            exp: value.exp,
            max_uses: value.max_uses,
            issuer_key_id: value.issuer_key_id.clone(),
        }
    }
}

impl TryFrom<CapabilityClaimsWire> for CapabilityClaims {
    type Error = CapabilityError;

    fn try_from(value: CapabilityClaimsWire) -> Result<Self, Self::Error> {
        let invalid = |error: secretctl_domain::DomainError| {
            CapabilityError::Serialization(error.to_string())
        };
        Ok(Self {
            v: value.v,
            aud: value.aud,
            jti: CapabilityId::parse(&value.jti).map_err(invalid)?,
            req_id: RequestId::parse(&value.req_id).map_err(invalid)?,
            agent_id: AgentId::parse(&value.agent_id).map_err(invalid)?,
            cred_id: CredentialId::parse(&value.cred_id).map_err(invalid)?,
            action: ActionKind::from_str(&value.action).map_err(invalid)?,
            top_origin: CanonicalOrigin::parse(&value.top_origin).map_err(invalid)?,
            frame_origin: CanonicalOrigin::parse(&value.frame_origin).map_err(invalid)?,
            browser_session_id: BrowserSessionId::parse(&value.browser_session_id)
                .map_err(invalid)?,
            extension_key_id: value.extension_key_id,
            tab_id: value.tab_id,
            frame_id: value.frame_id,
            document_id: value.document_id,
            navigation_epoch: value.navigation_epoch,
            recipe_id: RecipeId::parse(&value.recipe_id).map_err(invalid)?,
            recipe_hash: value.recipe_hash,
            policy_hash: value.policy_hash,
            nbf: value.nbf,
            iat: value.iat,
            exp: value.exp,
            max_uses: value.max_uses,
            issuer_key_id: value.issuer_key_id,
        })
    }
}

fn cbor_error(error: impl std::fmt::Display) -> CapabilityError {
    CapabilityError::Serialization(error.to_string())
}

fn protected_header(key_id: &str) -> Result<Vec<u8>, CapabilityError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .map(2)
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.i8(COSE_ALG_EDDSA))
        .and_then(|encoder| encoder.u8(4))
        .and_then(|encoder| encoder.str(key_id))
        .map_err(cbor_error)?;
    Ok(encoder.into_writer())
}

fn signature_structure(protected: &[u8], payload: &[u8]) -> Result<Vec<u8>, CapabilityError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(4)
        .and_then(|encoder| encoder.str("Signature1"))
        .and_then(|encoder| encoder.bytes(protected))
        .and_then(|encoder| encoder.bytes(&[]))
        .and_then(|encoder| encoder.bytes(payload))
        .map_err(cbor_error)?;
    Ok(encoder.into_writer())
}

fn encode_cose_sign1(
    claims: &CapabilityClaims,
    broker_key: &KeyPair,
) -> Result<Vec<u8>, CapabilityError> {
    let payload = minicbor::to_vec(CapabilityClaimsWire::from(claims)).map_err(cbor_error)?;
    let protected = protected_header(&claims.issuer_key_id)?;
    let signature = broker_key.sign(&signature_structure(&protected, &payload)?);
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(4)
        .and_then(|encoder| encoder.bytes(&protected))
        .and_then(|encoder| encoder.map(0))
        .and_then(|encoder| encoder.bytes(&payload))
        .and_then(|encoder| encoder.bytes(&signature))
        .map_err(cbor_error)?;
    Ok(encoder.into_writer())
}

struct DecodedCoseSign1 {
    claims: CapabilityClaims,
    protected: Vec<u8>,
    payload: Vec<u8>,
    signature: Vec<u8>,
}

fn decode_cose_sign1(token: &str) -> Result<DecodedCoseSign1, CapabilityError> {
    let token_bytes = URL_SAFE_NO_PAD.decode(token).map_err(cbor_error)?;
    let mut decoder = minicbor::Decoder::new(&token_bytes);
    if decoder.array().map_err(cbor_error)? != Some(4) {
        return Err(cbor_error("COSE_Sign1 must be a four-item array"));
    }
    let protected = decoder.bytes().map_err(cbor_error)?.to_vec();
    if decoder.map().map_err(cbor_error)? != Some(0) {
        return Err(cbor_error("COSE unprotected header must be empty"));
    }
    let payload = decoder.bytes().map_err(cbor_error)?.to_vec();
    let signature = decoder.bytes().map_err(cbor_error)?.to_vec();
    if decoder.position() != token_bytes.len() {
        return Err(cbor_error("trailing capability token data"));
    }

    let mut header = minicbor::Decoder::new(&protected);
    if header.map().map_err(cbor_error)? != Some(2)
        || header.u8().map_err(cbor_error)? != 1
        || header.i8().map_err(cbor_error)? != COSE_ALG_EDDSA
        || header.u8().map_err(cbor_error)? != 4
    {
        return Err(cbor_error("unsupported COSE protected header"));
    }
    let key_id = header.str().map_err(cbor_error)?.to_string();
    if header.position() != protected.len() || protected_header(&key_id)? != protected {
        return Err(cbor_error("non-canonical COSE protected header"));
    }

    let wire: CapabilityClaimsWire = minicbor::decode(&payload).map_err(cbor_error)?;
    if minicbor::to_vec(&wire).map_err(cbor_error)? != payload {
        return Err(cbor_error("non-canonical capability payload"));
    }
    let claims = CapabilityClaims::try_from(wire)?;
    if claims.issuer_key_id != key_id {
        return Err(CapabilityError::InvalidSignature);
    }
    Ok(DecodedCoseSign1 {
        claims,
        protected,
        payload,
        signature,
    })
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

    let token = URL_SAFE_NO_PAD.encode(
        encode_cose_sign1(&claims, broker_key).expect("capability claims are CBOR encodable"),
    );
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
    let decoded = decode_cose_sign1(token)?;
    verify_signature(
        broker_public_key,
        &signature_structure(&decoded.protected, &decoded.payload)?,
        &decoded.signature,
    )
    .map_err(|_| CapabilityError::InvalidSignature)?;
    Ok(decoded.claims)
}

pub fn parse_and_verify_token_with_keys(
    token: &str,
    active_keys: &HashMap<String, Vec<u8>>,
) -> Result<CapabilityClaims, CapabilityError> {
    let unverified = decode_cose_sign1(token)?.claims;
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
