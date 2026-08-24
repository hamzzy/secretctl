use base64::Engine;
use chrono::Utc;
use futures::{SinkExt, StreamExt};
use secretctl_crypto::{EphemeralX25519, KeyPair, SecureChannel};
use secretctl_domain::{AgentId, AgentPrincipal};
use secretctl_policy::{PolicyDocument, PolicyEvaluator};
use secretctl_protocol::{
    LengthPrefixedCodec, RpcRequest, RpcResponse, SessionAuthenticateParams, SessionHelloParams,
    SessionHelloResult, session_auth_transcript,
};
use secretctl_providers::MemorySecretProvider;
use secretctl_store::SqliteStore;
use secretctld::{BrokerServer, BrokerState};
use std::path::Path;
use std::sync::Arc;
use tokio::net::UnixStream;
use tokio_util::codec::Framed;

const SUITE: &str = "X25519-HKDF-SHA256-CHACHA20POLY1305";

fn enrolled(role: &str, key: &KeyPair, uid: u32) -> AgentPrincipal {
    AgentPrincipal {
        agent_id: AgentId::new(),
        role: role.to_string(),
        public_key: key.public_key_bytes().to_vec(),
        display_name: format!("test-{role}"),
        peer_uid: Some(uid),
        executable_path: None,
        executable_hash: None,
        state: "enrolled".to_string(),
        created_at: Utc::now(),
    }
}

async fn authenticate(
    socket: &Path,
    codec: LengthPrefixedCodec,
    role: &str,
    principal: &AgentPrincipal,
    key: &KeyPair,
    broker_public: &[u8; 32],
    channel_info: &[u8],
) -> (Framed<UnixStream, LengthPrefixedCodec>, SecureChannel) {
    let stream = UnixStream::connect(socket).await.unwrap();
    let mut framed = Framed::new(stream, codec);
    let hello = SessionHelloParams {
        protocol_version: "1.0".to_string(),
        role: role.to_string(),
        principal_id: principal.agent_id.to_string(),
        client_nonce: "client-nonce".to_string(),
        supported_suites: vec![SUITE.to_string()],
    };
    framed
        .send(
            serde_json::to_vec(&RpcRequest::new(
                "hello",
                "session.hello",
                Some(hello.clone()),
            ))
            .unwrap(),
        )
        .await
        .unwrap();
    let response: RpcResponse<SessionHelloResult> =
        serde_json::from_slice(&framed.next().await.unwrap().unwrap()).unwrap();
    let server = response.result.unwrap();
    let server_public = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&server.ephemeral_public_key)
        .unwrap();
    let server_public: [u8; 32] = server_public.try_into().unwrap();
    let server_signature = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&server.signature)
        .unwrap();
    let server_transcript = secretctl_crypto::compute_context_digest(&[
        b"secretctl-session-hello-v1",
        hello.client_nonce.as_bytes(),
        server.server_nonce.as_bytes(),
        hello.principal_id.as_bytes(),
        &server_public,
    ]);
    secretctl_crypto::verify_signature(broker_public, &server_transcript, &server_signature)
        .unwrap();

    let ephemeral = EphemeralX25519::new();
    let client_public = ephemeral.public_bytes();
    let transcript =
        session_auth_transcript(&hello, &server.server_nonce, &server_public, &client_public);
    let auth = SessionAuthenticateParams {
        client_ephemeral_public_key: base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(client_public),
        signature: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.sign(&transcript)),
    };
    framed
        .send(
            serde_json::to_vec(&RpcRequest::new("auth", "session.authenticate", Some(auth)))
                .unwrap(),
        )
        .await
        .unwrap();
    let auth_response: RpcResponse<serde_json::Value> =
        serde_json::from_slice(&framed.next().await.unwrap().unwrap()).unwrap();
    assert!(auth_response.error.is_none());
    let shared = ephemeral.diffie_hellman(&server_public);
    (
        framed,
        SecureChannel::new_client(&shared, server.server_nonce.as_bytes(), channel_info),
    )
}

#[tokio::test]
async fn enrolled_roles_require_signatures_and_switch_to_encrypted_transport() {
    let workspace_target = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target");
    let temp = tempfile::tempdir_in(workspace_target).unwrap();
    #[cfg(unix)]
    let uid = {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(temp.path()).unwrap().uid()
    };
    let store = SqliteStore::in_memory().unwrap();
    let agent_key = KeyPair::generate();
    let executor_key = KeyPair::generate();
    let agent = enrolled("agent", &agent_key, uid);
    let executor = enrolled("executor", &executor_key, uid);
    store.insert_agent(&agent).unwrap();
    store.insert_agent(&executor).unwrap();
    let broker_key = KeyPair::generate();
    let broker_public = broker_key.public_key_bytes();
    let state = BrokerState::new_with_audit_key(
        broker_key,
        "test-broker-key",
        secretctl_crypto::SecretBytes::new(vec![9u8; 32]),
        1,
        store,
        Arc::new(MemorySecretProvider::new()),
        PolicyEvaluator::new(PolicyDocument {
            version: "1.0".to_string(),
            rules: vec![],
        }),
    );
    BrokerServer::new(state, temp.path()).start().await.unwrap();

    let (mut agent_framed, mut agent_channel) = authenticate(
        &temp.path().join("agent.sock"),
        LengthPrefixedCodec::for_agent(),
        "agent",
        &agent,
        &agent_key,
        &broker_public,
        b"secretctl-agent-session-v1",
    )
    .await;
    let request = RpcRequest::<serde_json::Value>::new("1", "unknown", None);
    agent_framed
        .send(
            agent_channel
                .encrypt(&serde_json::to_vec(&request).unwrap())
                .unwrap(),
        )
        .await
        .unwrap();
    let response: RpcResponse<serde_json::Value> = serde_json::from_slice(
        &agent_channel
            .decrypt(&agent_framed.next().await.unwrap().unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(response.error.unwrap().code, -32601);

    let (mut executor_framed, mut executor_channel) = authenticate(
        &temp.path().join("executor.sock"),
        LengthPrefixedCodec::for_executor(),
        "executor",
        &executor,
        &executor_key,
        &broker_public,
        b"secretctl-executor-session-v1",
    )
    .await;
    let request = RpcRequest::<serde_json::Value>::new("2", "unknown", None);
    executor_framed
        .send(
            executor_channel
                .encrypt(&serde_json::to_vec(&request).unwrap())
                .unwrap(),
        )
        .await
        .unwrap();
    let response: RpcResponse<serde_json::Value> = serde_json::from_slice(
        &executor_channel
            .decrypt(&executor_framed.next().await.unwrap().unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(response.error.unwrap().code, -32601);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(temp.path()).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(temp.path().join("agent.sock"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}
