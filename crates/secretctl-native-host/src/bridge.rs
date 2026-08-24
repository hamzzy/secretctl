use crate::enrollment::{ExtensionChallenge, ExtensionEnrollment, ExtensionProof};
use crate::framing::ChromeNativeMessagingCodec;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use futures::{SinkExt, StreamExt};
use rand::RngCore;
use secretctl_crypto::{KeyPair, SecureChannel, StaticX25519};
use secretctl_protocol::{
    LengthPrefixedCodec, RpcRequest, RpcResponse, SessionAuthenticateParams,
    SessionAuthenticateResult, SessionHelloParams, SessionHelloResult, session_auth_transcript,
};
use std::path::Path;
use tokio::io::{stdin, stdout};
use tokio::net::UnixStream;
use tokio_util::codec::Framed;
use tracing::info;

const SUITE: &str = "X25519-HKDF-SHA256-CHACHA20POLY1305";

/// Bridge Chrome native messaging to the executor channel only after mutual
/// authentication, broker-key pinning, and channel encryption.
pub async fn run_stdio_bridge(
    executor_sock_path: impl AsRef<Path>,
    principal_id: &str,
    signing_key: &KeyPair,
    broker_public_key: &[u8],
    enrollment_path: impl AsRef<Path>,
) -> anyhow::Result<()> {
    info!(socket = ?executor_sock_path.as_ref(), "connecting native host to broker");
    let socket_stream = UnixStream::connect(executor_sock_path.as_ref()).await?;
    let mut socket = Framed::new(socket_stream, LengthPrefixedCodec::for_executor());

    let hello = SessionHelloParams {
        protocol_version: "1.0".to_string(),
        role: "executor".to_string(),
        principal_id: principal_id.to_string(),
        client_nonce: uuid::Uuid::new_v4().to_string(),
        supported_suites: vec![SUITE.to_string()],
    };
    socket
        .send(serde_json::to_vec(&RpcRequest {
            jsonrpc: "2.0".to_string(),
            id: secretctl_protocol::RpcId::String("native-hello".to_string()),
            method: "session.hello".to_string(),
            params: Some(serde_json::to_value(&hello)?),
        })?)
        .await?;
    let hello_wire = socket
        .next()
        .await
        .ok_or_else(|| anyhow::anyhow!("broker disconnected during hello"))??;
    let hello_response: RpcResponse<SessionHelloResult> =
        secretctl_protocol::from_slice_strict(&hello_wire)?;
    let server = hello_response
        .result
        .ok_or_else(|| anyhow::anyhow!("broker rejected executor hello"))?;
    anyhow::ensure!(
        server.protocol_version == "1.0",
        "protocol downgrade rejected"
    );
    let server_public: [u8; 32] = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&server.ephemeral_public_key)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid broker ephemeral key"))?;
    let server_signature =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&server.signature)?;
    let server_transcript = secretctl_crypto::compute_context_digest(&[
        b"secretctl-session-hello-v1",
        hello.client_nonce.as_bytes(),
        server.server_nonce.as_bytes(),
        hello.principal_id.as_bytes(),
        &server_public,
    ]);
    secretctl_crypto::verify_signature(broker_public_key, &server_transcript, &server_signature)
        .map_err(|_| anyhow::anyhow!("broker identity pin rejected"))?;

    let client_ephemeral = StaticX25519::generate();
    let client_public = client_ephemeral.public_bytes();
    let auth_transcript =
        session_auth_transcript(&hello, &server.server_nonce, &server_public, &client_public);
    socket
        .send(serde_json::to_vec(&RpcRequest {
            jsonrpc: "2.0".to_string(),
            id: secretctl_protocol::RpcId::String("native-auth".to_string()),
            method: "session.authenticate".to_string(),
            params: Some(serde_json::to_value(SessionAuthenticateParams {
                client_ephemeral_public_key: base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(client_public),
                signature: base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(signing_key.sign(&auth_transcript)),
            })?),
        })?)
        .await?;
    let auth_wire = socket
        .next()
        .await
        .ok_or_else(|| anyhow::anyhow!("broker disconnected during authentication"))??;
    let auth_response: RpcResponse<SessionAuthenticateResult> =
        secretctl_protocol::from_slice_strict(&auth_wire)?;
    anyhow::ensure!(
        auth_response
            .result
            .is_some_and(|result| result.authenticated),
        "broker rejected executor authentication"
    );
    let shared_secret = client_ephemeral.diffie_hellman(&server_public);
    let mut channel = SecureChannel::new_client(
        &shared_secret,
        server.server_nonce.as_bytes(),
        b"secretctl-executor-session-v1",
    );
    let mut session_material = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut session_material);
    let envelope_cipher = Aes256Gcm::new_from_slice(&session_material)
        .map_err(|_| anyhow::anyhow!("invalid extension session material"))?;

    let mut chrome_source = Framed::new(stdin(), ChromeNativeMessagingCodec);
    let mut chrome_sink = Framed::new(stdout(), ChromeNativeMessagingCodec);
    let mut executor_session_proof: Option<String> = None;
    let enrollment_path = enrollment_path.as_ref();
    let mut enrollment: ExtensionEnrollment =
        secretctl_protocol::from_slice_strict(&tokio::fs::read(enrollment_path).await?)?;
    let mut extension_challenge: Option<ExtensionChallenge> = None;
    while let Some(frame) = chrome_source.next().await {
        let frame = frame?;
        let mut request: RpcRequest<serde_json::Value> =
            secretctl_protocol::from_slice_strict(&frame)?;
        if request.method == "extension.challenge" {
            let challenge = enrollment.challenge();
            extension_challenge = Some(challenge.clone());
            chrome_sink
                .send(serde_json::to_vec(&RpcResponse::success(
                    request.id,
                    serde_json::to_value(challenge)?,
                ))?)
                .await?;
            continue;
        }
        if request.method == "browser.register" {
            let params = request
                .params
                .as_mut()
                .and_then(serde_json::Value::as_object_mut)
                .ok_or_else(|| anyhow::anyhow!("browser.register parameters missing"))?;
            let instance_id = std::env::var("SECRETCTL_BROWSER_INSTANCE_ID")
                .map_err(|_| anyhow::anyhow!("browser was not launched by secretctl"))?;
            let launcher_nonce = std::env::var("SECRETCTL_BROWSER_LAUNCH_NONCE")
                .map_err(|_| anyhow::anyhow!("browser launch nonce unavailable"))?;
            let profile_id = std::env::var("SECRETCTL_BROWSER_PROFILE_ID")
                .map_err(|_| anyhow::anyhow!("managed profile attestation unavailable"))?;
            params.insert(
                "instance_id".to_string(),
                serde_json::Value::String(instance_id),
            );
            params.insert(
                "launcher_nonce".to_string(),
                serde_json::Value::String(launcher_nonce),
            );
            params.insert(
                "profile_id".to_string(),
                serde_json::Value::String(profile_id),
            );
            let proof: ExtensionProof = serde_json::from_value(
                params
                    .remove("extension_proof")
                    .ok_or_else(|| anyhow::anyhow!("extension proof missing"))?,
            )?;
            let challenge = extension_challenge
                .take()
                .ok_or_else(|| anyhow::anyhow!("extension challenge missing"))?;
            let extension_key_id = enrollment.verify_and_enroll(&challenge.nonce, &proof)?;
            params.insert(
                "extension_key_id".to_string(),
                serde_json::Value::String(extension_key_id),
            );
            tokio::fs::write(enrollment_path, serde_json::to_vec_pretty(&enrollment)?).await?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(enrollment_path, std::fs::Permissions::from_mode(0o600))?;
            }
        } else if request.method == "executor.consume" {
            let params = request
                .params
                .as_mut()
                .and_then(serde_json::Value::as_object_mut)
                .ok_or_else(|| anyhow::anyhow!("executor.consume parameters missing"))?;
            let proof = executor_session_proof
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("browser session is not registered"))?;
            params.insert(
                "session_signature".to_string(),
                serde_json::Value::String(proof.clone()),
            );
        }
        let request_bytes = serde_json::to_vec(&request)?;
        socket.send(channel.encrypt(&request_bytes)?).await?;
        let encrypted = socket
            .next()
            .await
            .ok_or_else(|| anyhow::anyhow!("broker disconnected"))??;
        let response = channel.decrypt(&encrypted)?;
        let mut response: RpcResponse<serde_json::Value> =
            secretctl_protocol::from_slice_strict(&response)?;
        if request.method == "browser.register" {
            if let Some(result) = response
                .result
                .as_mut()
                .and_then(serde_json::Value::as_object_mut)
            {
                executor_session_proof = result
                    .remove("session_proof")
                    .and_then(|value| value.as_str().map(str::to_string));
                anyhow::ensure!(
                    executor_session_proof.is_some(),
                    "browser registration omitted executor session proof"
                );
                result.insert(
                    "session_material".to_string(),
                    serde_json::Value::String(
                        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(session_material),
                    ),
                );
            }
        } else if request.method == "executor.consume" {
            if let Some(result) = response
                .result
                .as_mut()
                .and_then(serde_json::Value::as_object_mut)
            {
                let execution_id = result
                    .get("execution_id")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| anyhow::anyhow!("consume result missing execution ID"))?
                    .to_string();
                let fields = result
                    .remove("fields")
                    .ok_or_else(|| anyhow::anyhow!("consume result missing fields"))?;
                let plaintext = serde_json::to_vec(&serde_json::json!({"fields": fields}))?;
                let mut nonce = [0u8; 12];
                rand::rngs::OsRng.fill_bytes(&mut nonce);
                let ciphertext = envelope_cipher
                    .encrypt(
                        Nonce::from_slice(&nonce),
                        aes_gcm::aead::Payload {
                            msg: &plaintext,
                            aad: execution_id.as_bytes(),
                        },
                    )
                    .map_err(|_| anyhow::anyhow!("extension envelope encryption failed"))?;
                result.insert(
                    "secret_envelope".to_string(),
                    serde_json::json!({
                        "nonce": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce),
                        "ciphertext": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(ciphertext)
                    }),
                );
            }
        }
        chrome_sink.send(serde_json::to_vec(&response)?).await?;
    }
    session_material.fill(0);
    Ok(())
}
