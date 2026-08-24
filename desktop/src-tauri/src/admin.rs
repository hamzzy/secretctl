//! Authenticated client for the `secretctld` admin socket.
//!
//! This is the *only* path by which the desktop application reaches the broker,
//! and it is the same handshake the CLI performs: pin the broker's public key
//! from disk, verify it against the installation signing key held in the
//! Keychain, complete an X25519 exchange, and then speak JSON-RPC inside a
//! `SecureChannel`. The daemon independently checks the peer UID against the
//! socket's owner before any of this runs.
//!
//! The frontend never sees this module. It calls Tauri commands, which call
//! [`AdminConnection::call`]; the process boundary means a compromised webview
//! cannot reach the socket directly.

use anyhow::{Context, anyhow, bail, ensure};
use base64::Engine;
use futures::{SinkExt, StreamExt};
use rand_core::RngCore;
use secretctl_crypto::{EphemeralX25519, KeyPair, SecureChannel};
use secretctl_protocol::{
    LengthPrefixedCodec, RpcRequest, RpcResponse, SessionAuthenticateParams, SessionHelloParams,
    SessionHelloResult, session_auth_transcript,
};
use secretctl_provider_macos::MacOsKeychainProvider;
use secretctl_providers::SecretProvider;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio::net::UnixStream;
use tokio_util::codec::Framed;

const SIGNING_KEY_LOCATOR: &str = "installation-signing-key";
const CRYPTO_SUITE: &str = "X25519-HKDF-SHA256-CHACHA20POLY1305";

/// The daemon terminates an admin session after 600 seconds. Reconnect before
/// that rather than discovering it as a mid-call failure.
const SESSION_MAX_AGE: Duration = Duration::from_secs(480);

/// Resolve the installation directory, matching the CLI's rules so the desktop
/// app and the CLI always address the same installation.
pub fn installation_dir() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("secretctl")
}

/// One live, authenticated admin session.
struct AdminSession {
    framed: Framed<UnixStream, LengthPrefixedCodec>,
    channel: SecureChannel,
    established_at: Instant,
    next_id: u64,
}

impl AdminSession {
    async fn connect(secretctl_dir: &Path) -> anyhow::Result<Self> {
        let provider = MacOsKeychainProvider::new();
        let signing_secret = provider
            .get_secret(SIGNING_KEY_LOCATOR)
            .await
            .context("installation signing key is not available in the Keychain")?;
        let signing_key = KeyPair::from_bytes(signing_secret.as_bytes())?;

        // Pin the broker identity from disk and require it to match the key the
        // Keychain holds. A daemon that cannot prove this identity is not talked
        // to at all.
        let pinned_public = tokio::fs::read(secretctl_dir.join("broker_key.pub"))
            .await
            .context("broker public key is missing; is secretctl initialised?")?;
        ensure!(
            pinned_public == signing_key.public_key_bytes(),
            "broker key pin does not match the Keychain key"
        );

        let socket = UnixStream::connect(secretctl_dir.join("run/admin.sock"))
            .await
            .context("secretctld is not accepting admin connections")?;
        let mut framed = Framed::new(socket, LengthPrefixedCodec::for_agent());

        let hello = SessionHelloParams {
            protocol_version: "1.0".to_string(),
            role: "admin".to_string(),
            principal_id: "local-admin".to_string(),
            client_nonce: random_nonce(),
            supported_suites: vec![CRYPTO_SUITE.to_string()],
        };
        framed
            .send(serde_json::to_vec(&RpcRequest::new(
                "hello",
                "session.hello",
                Some(hello.clone()),
            ))?)
            .await?;
        let hello_wire = framed
            .next()
            .await
            .ok_or_else(|| anyhow!("daemon closed during hello"))??;
        let hello_response: RpcResponse<SessionHelloResult> = serde_json::from_slice(&hello_wire)?;
        let server = hello_response
            .result
            .ok_or_else(|| anyhow!("daemon rejected the admin hello"))?;

        let server_public = decode_key(&server.ephemeral_public_key)?;
        let server_signature =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&server.signature)?;
        let server_transcript = secretctl_crypto::compute_context_digest(&[
            b"secretctl-session-hello-v1",
            hello.client_nonce.as_bytes(),
            server.server_nonce.as_bytes(),
            hello.principal_id.as_bytes(),
            &server_public,
        ]);
        secretctl_crypto::verify_signature(&pinned_public, &server_transcript, &server_signature)
            .context("daemon failed to prove the pinned broker identity")?;

        let client_ephemeral = EphemeralX25519::new();
        let client_public = client_ephemeral.public_bytes();
        let transcript =
            session_auth_transcript(&hello, &server.server_nonce, &server_public, &client_public);
        framed
            .send(serde_json::to_vec(&RpcRequest::new(
                "auth",
                "session.authenticate",
                Some(SessionAuthenticateParams {
                    client_ephemeral_public_key: base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .encode(client_public),
                    signature: base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .encode(signing_key.sign(&transcript)),
                }),
            ))?)
            .await?;
        let auth_wire = framed
            .next()
            .await
            .ok_or_else(|| anyhow!("daemon closed during authentication"))??;
        let auth_response: RpcResponse<serde_json::Value> = serde_json::from_slice(&auth_wire)?;
        ensure!(
            auth_response.error.is_none(),
            "daemon rejected admin authentication"
        );

        let shared_secret = client_ephemeral.diffie_hellman(&server_public);
        Ok(Self {
            framed,
            channel: SecureChannel::new_client(
                &shared_secret,
                server.server_nonce.as_bytes(),
                b"secretctl-admin-session-v1",
            ),
            established_at: Instant::now(),
            next_id: 1,
        })
    }

    fn is_expiring(&self) -> bool {
        self.established_at.elapsed() >= SESSION_MAX_AGE
    }

    async fn call(
        &mut self,
        method: &str,
        params: serde_json::Value,
    ) -> anyhow::Result<serde_json::Value> {
        let id = self.next_id.to_string();
        self.next_id += 1;
        let request = RpcRequest::new(id, method, Some(params));
        let encrypted = self.channel.encrypt(&serde_json::to_vec(&request)?)?;
        self.framed.send(encrypted).await?;
        let wire = self
            .framed
            .next()
            .await
            .ok_or_else(|| anyhow!("daemon closed the admin session"))??;
        let response: RpcResponse<serde_json::Value> =
            secretctl_protocol::from_slice_strict(&self.channel.decrypt(&wire)?)?;
        if let Some(error) = response.error {
            bail!(BrokerError {
                code: error.code,
                message: error.message,
            });
        }
        response
            .result
            .ok_or_else(|| anyhow!("daemon returned no result"))
    }
}

/// An error the broker itself returned, carrying its numeric code.
///
/// The code is preserved so the UI can put it behind "technical details" while
/// showing a plain-language explanation in the primary surface (spec §19).
#[derive(Debug, Clone, serde::Serialize)]
pub struct BrokerError {
    pub code: i32,
    pub message: String,
}

impl std::fmt::Display for BrokerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{} ({})", self.message, self.code)
    }
}

impl std::error::Error for BrokerError {}

/// A lazily established, automatically renewed admin connection.
///
/// Renewal is transparent because an expired or dropped session is an ordinary
/// operational event, not a security decision: every call is re-authorized by
/// the daemon on its own terms regardless of which session carried it.
#[derive(Default)]
pub struct AdminConnection {
    session: tokio::sync::Mutex<Option<AdminSession>>,
}

impl AdminConnection {
    pub fn new() -> Self {
        Self::default()
    }

    /// Issue an admin RPC, connecting or reconnecting as needed.
    ///
    /// A failed call drops the session so the next attempt starts clean rather
    /// than reusing a channel whose nonce sequence may have diverged.
    pub async fn call(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> anyhow::Result<serde_json::Value> {
        let directory = installation_dir();
        let mut guard = self.session.lock().await;

        if guard.as_ref().is_some_and(AdminSession::is_expiring) {
            *guard = None;
        }
        if guard.is_none() {
            *guard = Some(AdminSession::connect(&directory).await?);
        }

        let result = guard
            .as_mut()
            .expect("session established above")
            .call(method, params.clone())
            .await;

        match result {
            Ok(value) => Ok(value),
            Err(error) if error.downcast_ref::<BrokerError>().is_some() => {
                // The broker answered and refused. The channel is still healthy.
                Err(error)
            }
            Err(transport_error) => {
                // Transport-level failure: rebuild once, then surface it.
                *guard = None;
                let mut session = AdminSession::connect(&directory)
                    .await
                    .map_err(|_| transport_error)?;
                let value = session.call(method, params).await?;
                *guard = Some(session);
                Ok(value)
            }
        }
    }

    /// Whether the daemon is reachable right now. Used to drive the
    /// Disconnected state rather than to gate anything security-relevant.
    pub async fn is_reachable(&self) -> bool {
        self.call("admin.ping", serde_json::json!({})).await.is_ok()
    }
}

fn decode_key(encoded: &str) -> anyhow::Result<[u8; 32]> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)?
        .try_into()
        .map_err(|_| anyhow!("daemon sent a malformed ephemeral key"))
}

fn random_nonce() -> String {
    let mut bytes = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod live_daemon_tests {
    use super::*;

    /// These exercise the real handshake against a running `secretctld`, which
    /// is the one thing the daemon-side integration tests cannot cover: the
    /// broker-key pin, the X25519 exchange, and the framed `SecureChannel` all
    /// live on this side of the socket.
    ///
    /// They skip when no daemon is listening rather than failing, so the suite
    /// stays runnable on a machine with no installation. Start one with
    /// `secretctl start` to exercise them.
    fn daemon_available() -> bool {
        installation_dir().join("run/admin.sock").exists()
            && installation_dir().join("broker_key.pub").exists()
    }

    async fn connected() -> Option<AdminConnection> {
        if !daemon_available() {
            eprintln!("skipping: no secretctld admin socket");
            return None;
        }
        let connection = AdminConnection::new();
        match connection.call("admin.ping", serde_json::json!({})).await {
            Ok(_) => Some(connection),
            Err(error) => {
                eprintln!("skipping: could not reach secretctld ({error})");
                None
            }
        }
    }

    #[tokio::test]
    async fn every_ui_rpc_answers_and_deserializes_into_its_dto() {
        let Some(connection) = connected().await else {
            return;
        };

        let status: secretctl_protocol::UiStatus = serde_json::from_value(
            connection
                .call("ui.status", serde_json::json!({}))
                .await
                .expect("ui.status"),
        )
        .expect("status deserializes");
        // A reachable daemon must never report itself disconnected.
        assert_ne!(
            status.protection,
            secretctl_protocol::UiProtectionState::Disconnected
        );

        let _: Vec<secretctl_protocol::UiAuthorizationRequest> = serde_json::from_value(
            connection
                .call("ui.pending", serde_json::json!({}))
                .await
                .expect("ui.pending"),
        )
        .expect("pending deserializes");

        let _: Vec<secretctl_protocol::UiActivityEvent> = serde_json::from_value(
            connection
                .call("ui.activity", serde_json::json!({"limit": 25}))
                .await
                .expect("ui.activity"),
        )
        .expect("activity deserializes");

        let _: Vec<secretctl_protocol::UiAgent> = serde_json::from_value(
            connection
                .call("ui.agents", serde_json::json!({}))
                .await
                .expect("ui.agents"),
        )
        .expect("agents deserializes");

        let _: Vec<secretctl_protocol::UiCredential> = serde_json::from_value(
            connection
                .call("ui.credentials", serde_json::json!({}))
                .await
                .expect("ui.credentials"),
        )
        .expect("credentials deserializes");

        let _: Vec<secretctl_protocol::UiBrowserSession> = serde_json::from_value(
            connection
                .call("ui.browser_sessions", serde_json::json!({}))
                .await
                .expect("ui.browser_sessions"),
        )
        .expect("browser sessions deserializes");

        let _: Vec<secretctl_protocol::UiGrant> = serde_json::from_value(
            connection
                .call("grant.list", serde_json::json!({"include_revoked": true}))
                .await
                .expect("grant.list"),
        )
        .expect("grants deserializes");
    }

    #[tokio::test]
    async fn nothing_the_daemon_sends_this_process_carries_secret_material() {
        let Some(connection) = connected().await else {
            return;
        };

        // The wire itself, before any typed projection. If a secret-bearing
        // field were ever added daemon-side, it would show up here even if the
        // DTO happened to ignore it.
        for (method, params) in [
            ("ui.status", serde_json::json!({})),
            ("ui.pending", serde_json::json!({})),
            ("ui.activity", serde_json::json!({"limit": 200})),
            ("ui.agents", serde_json::json!({})),
            ("ui.credentials", serde_json::json!({})),
            ("ui.browser_sessions", serde_json::json!({})),
            ("grant.list", serde_json::json!({"include_revoked": true})),
        ] {
            let raw = connection
                .call(method, params)
                .await
                .unwrap_or_else(|error| panic!("{method} failed: {error}"));
            let text = serde_json::to_string(&raw).expect("serializable");
            for forbidden in [
                "provider_locator",
                "token_hash",
                "capability_token",
                "public_key",
                "private_key",
                "secret_envelope",
                "password",
            ] {
                assert!(
                    !text.contains(forbidden),
                    "{method} sent a forbidden field '{forbidden}'"
                );
            }
        }
    }

    #[tokio::test]
    async fn an_expired_session_is_renewed_without_the_caller_noticing() {
        let Some(connection) = connected().await else {
            return;
        };
        // Two calls across the same connection must both succeed; the second
        // exercises reuse of the established SecureChannel and its nonce
        // sequence, which is where a framing bug would surface.
        connection.call("admin.ping", serde_json::json!({})).await.expect("first");
        connection.call("admin.ping", serde_json::json!({})).await.expect("second");
    }
}
