//! Broker-owned primitives for the M4 OAuth Authorization Code + PKCE flow.
//!
//! It owns PKCE state, strict callback parsing, token exchange, and opaque
//! provider-backed grants. None of the code or token material crosses the
//! agent boundary.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore;
use secretctl_crypto::{SecretString, sha256_digest};
use secretctl_domain::{CredentialId, GrantId, OAuthGrant};
use secretctl_providers::SecretProvider;
use secretctl_store::SqliteStore;
use uuid::Uuid;

#[derive(Debug)]
pub struct PendingAuthorization {
    pub state: String,
    pub challenge: String,
    verifier: SecretString,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    callback_consumed: bool,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OAuthCallbackError {
    #[error("callback URI does not match the bound redirect")]
    RedirectMismatch,
    #[error("callback state mismatch")]
    StateMismatch,
    #[error("provider returned an OAuth error")]
    ProviderRejected,
    #[error("callback was already consumed")]
    Duplicate,
    #[error("callback did not contain an authorization code")]
    MissingCode,
}

#[derive(Debug)]
pub struct AuthorizationCode(SecretString);

impl AuthorizationCode {
    pub(crate) fn expose_to_token_exchange(&self) -> &str {
        self.0.as_str()
    }
}

pub struct TokenSet {
    pub access_token: SecretString,
    pub refresh_token: Option<SecretString>,
    pub scopes: Vec<String>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, thiserror::Error)]
pub enum OAuthStorageError {
    #[error("token provider unavailable")]
    Provider,
    #[error("opaque grant storage unavailable")]
    Store,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TokenExchangeError {
    #[error("token endpoint must be HTTPS")]
    InsecureEndpoint,
    #[error("token endpoint rejected the authorization")]
    Rejected,
    #[error("token response was invalid")]
    InvalidResponse,
    #[error("token response expanded the approved scopes")]
    ScopeMismatch,
}

#[derive(serde::Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
struct TokenResponseWire {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
}

/// Exchange one authorization code using an HTTPS-only client with redirects
/// disabled. Error bodies are never surfaced or logged.
pub async fn exchange_code(
    token_endpoint: &str,
    client_id: &str,
    pending: &PendingAuthorization,
    code: &AuthorizationCode,
) -> Result<TokenSet, TokenExchangeError> {
    let endpoint =
        url::Url::parse(token_endpoint).map_err(|_| TokenExchangeError::InsecureEndpoint)?;
    if endpoint.scheme() != "https"
        || endpoint.username() != ""
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
    {
        return Err(TokenExchangeError::InsecureEndpoint);
    }
    let client = reqwest::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|_| TokenExchangeError::InvalidResponse)?;
    let response = client
        .post(endpoint)
        .header(reqwest::header::ACCEPT, "application/json")
        .form(&[
            ("grant_type", "authorization_code"),
            ("client_id", client_id),
            ("code", code.expose_to_token_exchange()),
            ("redirect_uri", pending.redirect_uri.as_str()),
            ("code_verifier", pending.verifier_for_token_exchange()),
        ])
        .send()
        .await
        .map_err(|_| TokenExchangeError::Rejected)?;
    validate_token_status(response.status())?;
    let wire: TokenResponseWire = response
        .json()
        .await
        .map_err(|_| TokenExchangeError::InvalidResponse)?;
    if wire.access_token.is_empty() {
        return Err(TokenExchangeError::InvalidResponse);
    }
    let scopes = wire
        .scope
        .as_deref()
        .map(|value| {
            value
                .split_ascii_whitespace()
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|| pending.scopes.clone());
    validate_returned_scopes(&pending.scopes, &scopes)?;
    let expires_at = wire
        .expires_in
        .and_then(|seconds| chrono::Duration::try_seconds(seconds.min(i64::MAX as u64) as i64))
        .map(|duration| chrono::Utc::now() + duration);
    Ok(TokenSet {
        access_token: SecretString::new(wire.access_token.clone()),
        refresh_token: wire.refresh_token.clone().map(SecretString::new),
        scopes,
        expires_at,
    })
}

fn validate_token_status(status: reqwest::StatusCode) -> Result<(), TokenExchangeError> {
    if status.is_redirection() || !status.is_success() {
        Err(TokenExchangeError::Rejected)
    } else {
        Ok(())
    }
}

fn validate_returned_scopes(
    approved: &[String],
    returned: &[String],
) -> Result<(), TokenExchangeError> {
    if returned.iter().any(|scope| !approved.contains(scope)) {
        Err(TokenExchangeError::ScopeMismatch)
    } else {
        Ok(())
    }
}

/// Store token material in the provider and persist only an opaque locator.
/// If metadata persistence fails, the provider item is deleted before return.
pub async fn store_token_grant(
    provider: &dyn SecretProvider,
    store: &SqliteStore,
    credential_id: CredentialId,
    tokens: TokenSet,
) -> Result<OAuthGrant, OAuthStorageError> {
    let grant_id = GrantId::new();
    let locator = format!("oauth-token-{}", grant_id.as_str());
    let access = tokens.access_token.as_str().as_bytes();
    let refresh = tokens
        .refresh_token
        .as_ref()
        .map(|value| value.as_str().as_bytes());
    let mut encoded = zeroize::Zeroizing::new(Vec::with_capacity(
        9 + access.len() + refresh.map_or(0, <[u8]>::len),
    ));
    encoded.push(1);
    encoded.extend_from_slice(&(access.len() as u32).to_be_bytes());
    encoded.extend_from_slice(access);
    encoded.extend_from_slice(&(refresh.map_or(0, <[u8]>::len) as u32).to_be_bytes());
    if let Some(refresh) = refresh {
        encoded.extend_from_slice(refresh);
    }
    provider
        .store_secret(&locator, &encoded)
        .await
        .map_err(|_| OAuthStorageError::Provider)?;
    let grant = OAuthGrant {
        grant_id,
        credential_id,
        provider_locator: locator.clone(),
        scopes: tokens.scopes,
        subject_hint: None,
        created_at: chrono::Utc::now(),
        expires_at: tokens.expires_at,
    };
    if store.insert_oauth_grant(&grant).is_err() {
        let _ = provider.delete_secret(&locator).await;
        return Err(OAuthStorageError::Store);
    }
    Ok(grant)
}

pub async fn revoke_token_grant(
    provider: &dyn SecretProvider,
    store: &SqliteStore,
    grant_id: &GrantId,
) -> Result<bool, OAuthStorageError> {
    let Some(grant) = store
        .get_oauth_grant(grant_id)
        .map_err(|_| OAuthStorageError::Store)?
    else {
        return Ok(false);
    };
    provider
        .delete_secret(&grant.provider_locator)
        .await
        .map_err(|_| OAuthStorageError::Provider)?;
    store
        .delete_oauth_grant(grant_id)
        .map_err(|_| OAuthStorageError::Store)
}

impl PendingAuthorization {
    pub fn new(redirect_uri: impl Into<String>, scopes: Vec<String>) -> Self {
        let mut random = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut random);
        let verifier = URL_SAFE_NO_PAD.encode(random);
        random.fill(0);
        let challenge = URL_SAFE_NO_PAD.encode(sha256_digest(verifier.as_bytes()));
        Self {
            state: Uuid::new_v4().to_string(),
            challenge,
            verifier: SecretString::new(verifier),
            redirect_uri: redirect_uri.into(),
            scopes,
            callback_consumed: false,
        }
    }

    pub fn verifier_for_token_exchange(&self) -> &str {
        self.verifier.as_str()
    }

    pub fn accepts_callback(&self, state: &str, redirect_uri: &str) -> bool {
        self.state == state && self.redirect_uri == redirect_uri
    }

    pub fn authorization_url(
        &self,
        endpoint: &str,
        client_id: &str,
    ) -> Result<String, crate::oauth::OAuthCallbackError> {
        let mut url =
            url::Url::parse(endpoint).map_err(|_| OAuthCallbackError::RedirectMismatch)?;
        if url.scheme() != "https" || url.query().is_some() || url.fragment().is_some() {
            return Err(OAuthCallbackError::RedirectMismatch);
        }
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", client_id)
            .append_pair("redirect_uri", &self.redirect_uri)
            .append_pair("scope", &self.scopes.join(" "))
            .append_pair("state", &self.state)
            .append_pair("code_challenge", &self.challenge)
            .append_pair("code_challenge_method", "S256");
        Ok(url.into())
    }

    /// Parse one exact callback URL. The code is retained in zeroizing memory
    /// and is only exposed to the broker's token exchange implementation.
    pub fn consume_callback(
        &mut self,
        callback_uri: &str,
    ) -> Result<AuthorizationCode, OAuthCallbackError> {
        if self.callback_consumed {
            return Err(OAuthCallbackError::Duplicate);
        }
        let callback =
            url::Url::parse(callback_uri).map_err(|_| OAuthCallbackError::RedirectMismatch)?;
        let bound = url::Url::parse(&self.redirect_uri)
            .map_err(|_| OAuthCallbackError::RedirectMismatch)?;
        if callback.scheme() != bound.scheme()
            || callback.host_str() != bound.host_str()
            || callback.port_or_known_default() != bound.port_or_known_default()
            || callback.path() != bound.path()
            || callback.fragment().is_some()
        {
            return Err(OAuthCallbackError::RedirectMismatch);
        }
        let mut query = std::collections::HashMap::new();
        for (key, value) in callback.query_pairs().into_owned() {
            if query.insert(key, value).is_some() {
                return Err(OAuthCallbackError::StateMismatch);
            }
        }
        if query.get("state").map(String::as_str) != Some(self.state.as_str()) {
            return Err(OAuthCallbackError::StateMismatch);
        }
        if query.contains_key("error") {
            return Err(OAuthCallbackError::ProviderRejected);
        }
        let code = query
            .get("code")
            .ok_or(OAuthCallbackError::MissingCode)?
            .clone();
        if code.is_empty() {
            return Err(OAuthCallbackError::MissingCode);
        }
        self.callback_consumed = true;
        Ok(AuthorizationCode(SecretString::new(code)))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AuthorizationCode, OAuthCallbackError, PendingAuthorization, TokenExchangeError, TokenSet,
        exchange_code, revoke_token_grant, store_token_grant, validate_returned_scopes,
        validate_token_status,
    };
    use secretctl_crypto::SecretString;
    use secretctl_domain::CredentialId;
    use secretctl_providers::{MemorySecretProvider, SecretProvider};
    use secretctl_store::SqliteStore;

    #[test]
    fn pkce_material_is_random_and_callback_bound() {
        let first = PendingAuthorization::new(
            "https://app.example/callback",
            vec!["openid".into(), "profile".into()],
        );
        let second = PendingAuthorization::new("https://app.example/callback", vec![]);
        assert_ne!(first.state, second.state);
        assert_ne!(first.challenge, second.challenge);
        assert!(!first.verifier_for_token_exchange().is_empty());
        assert!(first.accepts_callback(&first.state, "https://app.example/callback"));
        assert!(!first.accepts_callback(&second.state, "https://app.example/callback"));
        assert!(!first.accepts_callback(&first.state, "https://evil.example/callback"));
    }

    #[test]
    fn callback_is_exactly_bound_and_single_use() {
        let mut auth =
            PendingAuthorization::new("https://app.example/oauth/callback", vec!["openid".into()]);
        let callback = format!(
            "https://app.example/oauth/callback?code=opaque-code&state={}",
            auth.state
        );
        let code = auth.consume_callback(&callback).unwrap();
        assert!(!code.expose_to_token_exchange().is_empty());
        assert!(matches!(
            auth.consume_callback(&callback),
            Err(OAuthCallbackError::Duplicate)
        ));
    }

    #[test]
    fn callback_attack_variants_fail_closed() {
        let mut auth = PendingAuthorization::new("https://app.example/oauth/callback", vec![]);
        assert!(matches!(
            auth.consume_callback("https://evil.example/oauth/callback?code=x&state=bad"),
            Err(OAuthCallbackError::RedirectMismatch)
        ));
        let wrong_state = "https://app.example/oauth/callback?code=x&state=bad";
        assert!(matches!(
            auth.consume_callback(wrong_state),
            Err(OAuthCallbackError::StateMismatch)
        ));
    }

    #[tokio::test]
    async fn tokens_live_in_provider_and_agent_gets_only_opaque_grant() {
        let provider = MemorySecretProvider::new();
        let store = SqliteStore::in_memory().unwrap();
        let grant = store_token_grant(
            &provider,
            &store,
            CredentialId::new(),
            TokenSet {
                access_token: SecretString::new("access-canary".into()),
                refresh_token: Some(SecretString::new("refresh-canary".into())),
                scopes: vec!["openid".into()],
                expires_at: None,
            },
        )
        .await
        .unwrap();
        assert!(provider.exists(&grant.provider_locator).await.unwrap());
        let safe = serde_json::to_string(&grant).unwrap();
        assert!(!safe.contains("access-canary"));
        assert!(!safe.contains("refresh-canary"));
        assert!(
            revoke_token_grant(&provider, &store, &grant.grant_id)
                .await
                .unwrap()
        );
        assert!(!provider.exists(&grant.provider_locator).await.unwrap());
    }

    #[tokio::test]
    async fn token_exchange_refuses_non_https_before_network_access() {
        let pending =
            PendingAuthorization::new("https://app.example/callback", vec!["openid".into()]);
        let code = AuthorizationCode(SecretString::new("code-canary".into()));
        assert!(matches!(
            exchange_code("http://idp.example/token", "client", &pending, &code).await,
            Err(TokenExchangeError::InsecureEndpoint)
        ));
    }

    #[test]
    fn token_redirect_and_scope_expansion_are_rejected() {
        assert!(matches!(
            validate_token_status(reqwest::StatusCode::FOUND),
            Err(TokenExchangeError::Rejected)
        ));
        assert!(matches!(
            validate_returned_scopes(&["openid".into()], &["openid".into(), "admin".into()]),
            Err(TokenExchangeError::ScopeMismatch)
        ));
    }
}
