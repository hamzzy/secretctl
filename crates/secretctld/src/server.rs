use crate::state::BrokerState;
use base64::Engine;
use futures::{SinkExt, StreamExt};
use secretctl_domain::AgentId;
use secretctl_protocol::{
    ActionCancelParams, ActionRequestParams, ActionStatusParams, AgentDisableParams,
    ApprovalDecideParams, BrowserCloseParams, BrowserLaunchParams, BrowserNavigateParams,
    BrowserOpenTabParams, BrowserRegisterParams, BrowserSessionParams, BrowserTabParams,
    CapabilityListParams, CapabilityRevokeParams, ExecutionNextParams, ExecutorConsumeParams,
    ExecutorHeartbeatParams, ExecutorPrepareParams, ExecutorResultParams, GrantCreateParams,
    GrantListParams, GrantRevokeParams, LengthPrefixedCodec, OAuthCallbackParams,
    PageLocatorParams, PageTypePublicParams, PolicyReloadParams, RpcError, RpcErrorCode,
    RpcRequest, RpcResponse, SessionAuthenticateParams, SessionAuthenticateResult,
    SessionHelloParams, SessionHelloResult, SessionInfoResult, UiActivityParams,
    session_auth_transcript,
};
use std::path::{Path, PathBuf};
use tokio::net::{UnixListener, UnixStream};
use tokio_util::codec::Framed;
use tracing::{error, info, warn};

/// Address one pending approval by id.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovalLookupParams {
    approval_id: secretctl_domain::ApprovalId,
}

pub struct BrokerServer {
    state: BrokerState,
    runtime_dir: PathBuf,
}

impl BrokerServer {
    pub fn new(state: BrokerState, runtime_dir: impl AsRef<Path>) -> Self {
        Self {
            state,
            runtime_dir: runtime_dir.as_ref().to_path_buf(),
        }
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        tokio::fs::create_dir_all(&self.runtime_dir).await?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&self.runtime_dir, std::fs::Permissions::from_mode(0o700))?;
        }

        let endpoint_path =
            |channel| match secretctl_protocol::unix_endpoint(&self.runtime_dir, channel) {
                secretctl_protocol::LocalEndpoint::UnixSocket(path) => path,
                secretctl_protocol::LocalEndpoint::WindowsNamedPipe(_) => unreachable!(),
            };
        let agent_sock_path = endpoint_path(secretctl_protocol::LocalChannel::Agent);
        let executor_sock_path = endpoint_path(secretctl_protocol::LocalChannel::Executor);
        let admin_sock_path = endpoint_path(secretctl_protocol::LocalChannel::Admin);

        let _ = tokio::fs::remove_file(&agent_sock_path).await;
        let _ = tokio::fs::remove_file(&executor_sock_path).await;
        let _ = tokio::fs::remove_file(&admin_sock_path).await;

        let agent_listener = UnixListener::bind(&agent_sock_path)?;
        let executor_listener = UnixListener::bind(&executor_sock_path)?;
        let admin_listener = UnixListener::bind(&admin_sock_path)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let permissions = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&agent_sock_path, permissions.clone())?;
            std::fs::set_permissions(&executor_sock_path, permissions.clone())?;
            std::fs::set_permissions(&admin_sock_path, permissions)?;
        }

        info!(
            "secretctld listening on: agent={:?}, executor={:?}, admin={:?}",
            agent_sock_path, executor_sock_path, admin_sock_path
        );

        let state_agent = self.state.clone();
        tokio::spawn(async move {
            loop {
                match agent_listener.accept().await {
                    Ok((stream, _)) => {
                        let st = state_agent.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_agent_connection(stream, st).await {
                                warn!("Agent connection error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        error!("Agent accept error: {}", e);
                        break;
                    }
                }
            }
        });

        let state_executor = self.state.clone();
        tokio::spawn(async move {
            loop {
                match executor_listener.accept().await {
                    Ok((stream, _)) => {
                        let st = state_executor.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_executor_connection(stream, st).await {
                                warn!("Executor connection error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        error!("Executor accept error: {}", e);
                        break;
                    }
                }
            }
        });

        let state_admin = self.state.clone();
        tokio::spawn(async move {
            loop {
                match admin_listener.accept().await {
                    Ok((stream, _)) => {
                        let st = state_admin.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_admin_connection(stream, st).await {
                                warn!("Admin connection error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        error!("Admin accept error: {}", e);
                        break;
                    }
                }
            }
        });

        let stale_state = self.state.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
            loop {
                interval.tick().await;
                if let Err(error) = stale_state.expire_stale_sessions(chrono::Utc::now()) {
                    error!("Failed to expire stale browser sessions: {}", error.message);
                }
                if let Err(error) = stale_state.expire_pending_approvals(chrono::Utc::now()) {
                    error!("Failed to expire pending approvals: {}", error.message);
                }
            }
        });

        Ok(())
    }
}

async fn handle_agent_connection(stream: UnixStream, state: BrokerState) -> anyhow::Result<()> {
    let peer_cred = stream.peer_cred()?;
    let mut framed = Framed::new(stream, LengthPrefixedCodec::for_agent());
    let mut authenticated_agent: Option<AgentId> = None;
    let mut pending_handshake: Option<(
        SessionHelloParams,
        secretctl_domain::AgentPrincipal,
        String,
        secretctl_crypto::StaticX25519,
    )> = None;
    let mut secure_channel: Option<secretctl_crypto::SecureChannel> = None;
    let mut authenticated_at: Option<std::time::Instant> = None;

    while let Some(msg_res) = framed.next().await {
        let wire_bytes = msg_res?;
        let msg_bytes = if let Some(channel) = secure_channel.as_mut() {
            if authenticated_at.is_some_and(|time| time.elapsed().as_secs() >= 600) {
                anyhow::bail!("agent session rekey required");
            }
            channel.decrypt(&wire_bytes)?
        } else {
            wire_bytes
        };
        let rpc_req: RpcRequest<serde_json::Value> =
            secretctl_protocol::from_slice_strict(&msg_bytes)?;

        let id = rpc_req.id.clone();
        let method = rpc_req.method.as_str();

        let mut activate_channel = None;
        let response: RpcResponse<serde_json::Value> = match method {
            "session.hello" => {
                if secure_channel.is_some() || pending_handshake.is_some() {
                    RpcResponse::error(
                        id,
                        RpcError::new(
                            RpcErrorCode::SECURITY_VIOLATION,
                            "Handshake already started",
                        ),
                    )
                } else {
                    let params: SessionHelloParams =
                        serde_json::from_value(rpc_req.params.unwrap_or_default())?;
                    let enrolled = state.store.get_enrolled_agent(&params.principal_id).ok();
                    if params.protocol_version != "1.0"
                        || params.role != "agent"
                        || !params
                            .supported_suites
                            .iter()
                            .any(|suite| suite == "X25519-HKDF-SHA256-CHACHA20POLY1305")
                        || enrolled.as_ref().is_none_or(|agent| agent.role != "agent")
                    {
                        RpcResponse::error(
                            id,
                            RpcError::new(
                                RpcErrorCode::SECURITY_VIOLATION,
                                "Agent enrollment rejected",
                            ),
                        )
                    } else {
                        let enrolled = enrolled.expect("checked above");
                        if !verify_peer_identity(&enrolled, &peer_cred).await? {
                            return Err(anyhow::anyhow!("agent OS peer identity changed"));
                        }
                        let server_nonce = uuid::Uuid::new_v4().to_string();
                        let ephemeral_key = secretctl_crypto::StaticX25519::generate();
                        let ephemeral_public_key = ephemeral_key.public_bytes();
                        let transcript = secretctl_crypto::compute_context_digest(&[
                            b"secretctl-session-hello-v1",
                            params.client_nonce.as_bytes(),
                            server_nonce.as_bytes(),
                            params.principal_id.as_bytes(),
                            &ephemeral_public_key,
                        ]);
                        let res = SessionHelloResult {
                            protocol_version: "1.0".to_string(),
                            server_nonce: server_nonce.clone(),
                            ephemeral_public_key: base64::engine::general_purpose::URL_SAFE_NO_PAD
                                .encode(ephemeral_public_key),
                            server_key_id: state.key_id.clone(),
                            signature: base64::engine::general_purpose::URL_SAFE_NO_PAD
                                .encode(state.broker_key.sign(&transcript)),
                        };
                        pending_handshake = Some((params, enrolled, server_nonce, ephemeral_key));
                        RpcResponse::success(id, serde_json::to_value(res)?)
                    }
                }
            }
            "session.authenticate" => {
                let params: SessionAuthenticateParams =
                    serde_json::from_value(rpc_req.params.unwrap_or_default())?;
                let Some((hello, enrolled, server_nonce, server_ephemeral)) =
                    pending_handshake.take()
                else {
                    let response: RpcResponse<serde_json::Value> = RpcResponse::error(
                        id,
                        RpcError::new(RpcErrorCode::SECURITY_VIOLATION, "session.hello required"),
                    );
                    let bytes = serde_json::to_vec(&response)?;
                    framed.send(bytes).await?;
                    continue;
                };
                let client_public = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(params.client_ephemeral_public_key)?;
                let client_public: [u8; 32] = client_public
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("invalid client ephemeral key"))?;
                let signature =
                    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(params.signature)?;
                let server_public = server_ephemeral.public_bytes();
                let transcript =
                    session_auth_transcript(&hello, &server_nonce, &server_public, &client_public);
                secretctl_crypto::verify_signature(&enrolled.public_key, &transcript, &signature)
                    .map_err(|_| anyhow::anyhow!("agent handshake signature rejected"))?;
                let shared_secret = server_ephemeral.diffie_hellman(&client_public);
                activate_channel = Some(secretctl_crypto::SecureChannel::new_server(
                    &shared_secret,
                    server_nonce.as_bytes(),
                    b"secretctl-agent-session-v1",
                ));
                authenticated_agent = Some(enrolled.agent_id);
                RpcResponse::success(
                    id,
                    serde_json::to_value(SessionAuthenticateResult {
                        authenticated: true,
                        rekey_after_seconds: 600,
                    })?,
                )
            }
            "action.request" => {
                if let Some(agent_id) = authenticated_agent.clone() {
                    let params: ActionRequestParams =
                        serde_json::from_value(rpc_req.params.unwrap_or_default())?;
                    let should_wait = params.wait;
                    let timeout = std::time::Duration::from_millis(params.timeout_ms);
                    let request_id = params.request_id.clone();
                    match state.handle_action_request(agent_id, params).await {
                        Ok(mut result) => {
                            if should_wait && !result.state.is_terminal() {
                                let deadline = tokio::time::Instant::now() + timeout;
                                loop {
                                    if let Some(current) =
                                        state.requests.read().unwrap().get(&request_id).cloned()
                                    {
                                        result = current;
                                        if result.state.is_terminal() {
                                            break;
                                        }
                                    }
                                    if tokio::time::Instant::now() >= deadline {
                                        break;
                                    }
                                    tokio::time::sleep(std::time::Duration::from_millis(25)).await;
                                }
                            }
                            RpcResponse::success(id, serde_json::to_value(result)?)
                        }
                        Err(err) => RpcResponse::error(id, err),
                    }
                } else {
                    RpcResponse::error(
                        id,
                        RpcError::new(RpcErrorCode::SECURITY_VIOLATION, "session.hello required"),
                    )
                }
            }
            "session.info" => {
                if let Some(agent_id) = authenticated_agent.as_ref() {
                    RpcResponse::success(
                        id,
                        serde_json::to_value(SessionInfoResult {
                            protocol_version: "1.0".to_string(),
                            principal_id: agent_id.to_string(),
                            role: "agent".to_string(),
                            rekey_after_seconds: authenticated_at
                                .map(|started| 600u64.saturating_sub(started.elapsed().as_secs()))
                                .unwrap_or(0),
                        })?,
                    )
                } else {
                    RpcResponse::error(
                        id,
                        RpcError::new(RpcErrorCode::SECURITY_VIOLATION, "session.hello required"),
                    )
                }
            }
            "action.status" => {
                if let Some(agent_id) = authenticated_agent.as_ref() {
                    let params: ActionStatusParams =
                        serde_json::from_value(rpc_req.params.unwrap_or_default())?;
                    match state.handle_action_status(agent_id, params) {
                        Ok(res) => RpcResponse::success(id, serde_json::to_value(res)?),
                        Err(err) => RpcResponse::error(id, err),
                    }
                } else {
                    RpcResponse::error(
                        id,
                        RpcError::new(RpcErrorCode::SECURITY_VIOLATION, "session.hello required"),
                    )
                }
            }
            "action.cancel" => {
                if let Some(agent_id) = authenticated_agent.as_ref() {
                    let params: ActionCancelParams =
                        serde_json::from_value(rpc_req.params.unwrap_or_default())?;
                    match state.handle_action_cancel(agent_id, params) {
                        Ok(res) => RpcResponse::success(id, serde_json::to_value(res)?),
                        Err(err) => RpcResponse::error(id, err),
                    }
                } else {
                    RpcResponse::error(
                        id,
                        RpcError::new(RpcErrorCode::SECURITY_VIOLATION, "session.hello required"),
                    )
                }
            }
            "browser.tabs" if authenticated_agent.is_some() => {
                let params: BrowserSessionParams =
                    serde_json::from_value(rpc_req.params.unwrap_or_default())?;
                match state.handle_browser_tabs(params) {
                    Ok(result) => RpcResponse::success(id, result),
                    Err(error) => RpcResponse::error(id, error),
                }
            }
            "browser.open_tab" if authenticated_agent.is_some() => {
                let params: BrowserOpenTabParams =
                    serde_json::from_value(rpc_req.params.unwrap_or_default())?;
                match state.handle_browser_open_tab(params) {
                    Ok(result) => RpcResponse::success(id, result),
                    Err(error) => RpcResponse::error(id, error),
                }
            }
            "browser.close_tab" if authenticated_agent.is_some() => {
                let params: BrowserTabParams =
                    serde_json::from_value(rpc_req.params.unwrap_or_default())?;
                match state.handle_browser_close_tab(params) {
                    Ok(result) => RpcResponse::success(id, result),
                    Err(error) => RpcResponse::error(id, error),
                }
            }
            "browser.navigate" if authenticated_agent.is_some() => {
                let params: BrowserNavigateParams =
                    serde_json::from_value(rpc_req.params.unwrap_or_default())?;
                match state.handle_browser_navigate(params) {
                    Ok(result) => RpcResponse::success(id, result),
                    Err(error) => RpcResponse::error(id, error),
                }
            }
            "browser.reload" if authenticated_agent.is_some() => {
                let params: BrowserTabParams =
                    serde_json::from_value(rpc_req.params.unwrap_or_default())?;
                match state.handle_browser_reload(params) {
                    Ok(result) => RpcResponse::success(id, result),
                    Err(error) => RpcResponse::error(id, error),
                }
            }
            "page.click" if authenticated_agent.is_some() => {
                let params: PageLocatorParams =
                    serde_json::from_value(rpc_req.params.unwrap_or_default())?;
                match state.handle_page_click(params) {
                    Ok(result) => RpcResponse::success(id, result),
                    Err(error) => RpcResponse::error(id, error),
                }
            }
            "page.type_public" if authenticated_agent.is_some() => {
                let params: PageTypePublicParams =
                    serde_json::from_value(rpc_req.params.unwrap_or_default())?;
                match state.handle_page_type_public(params) {
                    Ok(result) => RpcResponse::success(id, result),
                    Err(error) => RpcResponse::error(id, error),
                }
            }
            _ => RpcResponse::error(
                id,
                RpcError::new(RpcErrorCode::METHOD_NOT_FOUND, "Method not found"),
            ),
        };

        let response_bytes = serde_json::to_vec(&response)?;
        let wire_response = if let Some(channel) = secure_channel.as_mut() {
            channel.encrypt(&response_bytes)?
        } else {
            response_bytes
        };
        framed.send(wire_response).await?;
        if let Some(channel) = activate_channel {
            secure_channel = Some(channel);
            authenticated_at = Some(std::time::Instant::now());
        }
    }

    Ok(())
}

async fn verify_peer_identity(
    principal: &secretctl_domain::AgentPrincipal,
    peer_cred: &tokio::net::unix::UCred,
) -> anyhow::Result<bool> {
    if principal.peer_uid.is_some_and(|uid| uid != peer_cred.uid()) {
        return Ok(false);
    }
    let Some(expected_hash) = principal.executable_hash.as_ref() else {
        return Ok(true);
    };
    let Some(pid) = peer_cred.pid() else {
        return Ok(false);
    };
    let executable_path = tokio::task::spawn_blocking(move || -> anyhow::Result<PathBuf> {
        #[cfg(target_os = "linux")]
        {
            Ok(std::fs::read_link(format!("/proc/{pid}/exe"))?)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let output = std::process::Command::new("/bin/ps")
                .args(["-p", &pid.to_string(), "-o", "comm="])
                .output()?;
            anyhow::ensure!(output.status.success(), "peer executable lookup failed");
            Ok(PathBuf::from(String::from_utf8(output.stdout)?.trim()))
        }
    })
    .await??;
    if principal
        .executable_path
        .as_ref()
        .is_some_and(|path| Path::new(path) != executable_path)
    {
        return Ok(false);
    }
    let bytes = tokio::fs::read(executable_path).await?;
    Ok(secretctl_crypto::sha256_digest(&bytes).as_slice() == expected_hash)
}

async fn handle_executor_connection(stream: UnixStream, state: BrokerState) -> anyhow::Result<()> {
    let peer_cred = stream.peer_cred()?;
    let mut framed = Framed::new(stream, LengthPrefixedCodec::for_executor());
    let hello_bytes = framed
        .next()
        .await
        .ok_or_else(|| anyhow::anyhow!("executor disconnected before handshake"))??;
    let hello_request: RpcRequest<serde_json::Value> =
        secretctl_protocol::from_slice_strict(&hello_bytes)?;
    anyhow::ensure!(
        hello_request.method == "session.hello",
        "session.hello required"
    );
    let hello: SessionHelloParams =
        serde_json::from_value(hello_request.params.unwrap_or_default())?;
    anyhow::ensure!(
        hello.protocol_version == "1.0"
            && hello.role == "executor"
            && hello
                .supported_suites
                .iter()
                .any(|suite| suite == "X25519-HKDF-SHA256-CHACHA20POLY1305"),
        "executor handshake rejected"
    );
    let enrolled = state.store.get_enrolled_agent(&hello.principal_id)?;
    anyhow::ensure!(
        enrolled.role == "executor" && verify_peer_identity(&enrolled, &peer_cred).await?,
        "executor enrollment rejected"
    );
    let server_nonce = uuid::Uuid::new_v4().to_string();
    let server_ephemeral = secretctl_crypto::StaticX25519::generate();
    let server_public = server_ephemeral.public_bytes();
    let server_transcript = secretctl_crypto::compute_context_digest(&[
        b"secretctl-session-hello-v1",
        hello.client_nonce.as_bytes(),
        server_nonce.as_bytes(),
        hello.principal_id.as_bytes(),
        &server_public,
    ]);
    let hello_response = RpcResponse::success(
        hello_request.id,
        serde_json::to_value(SessionHelloResult {
            protocol_version: "1.0".to_string(),
            server_nonce: server_nonce.clone(),
            ephemeral_public_key: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(server_public),
            server_key_id: state.key_id.clone(),
            signature: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(state.broker_key.sign(&server_transcript)),
        })?,
    );
    framed.send(serde_json::to_vec(&hello_response)?).await?;

    let auth_bytes = framed
        .next()
        .await
        .ok_or_else(|| anyhow::anyhow!("executor disconnected during handshake"))??;
    let auth_request: RpcRequest<serde_json::Value> =
        secretctl_protocol::from_slice_strict(&auth_bytes)?;
    anyhow::ensure!(
        auth_request.method == "session.authenticate",
        "session.authenticate required"
    );
    let auth: SessionAuthenticateParams =
        serde_json::from_value(auth_request.params.unwrap_or_default())?;
    let client_public = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(auth.client_ephemeral_public_key)?;
    let client_public: [u8; 32] = client_public
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid executor ephemeral key"))?;
    let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(auth.signature)?;
    let transcript = session_auth_transcript(&hello, &server_nonce, &server_public, &client_public);
    secretctl_crypto::verify_signature(&enrolled.public_key, &transcript, &signature)
        .map_err(|_| anyhow::anyhow!("executor signature rejected"))?;
    let shared_secret = server_ephemeral.diffie_hellman(&client_public);
    let mut secure_channel = secretctl_crypto::SecureChannel::new_server(
        &shared_secret,
        server_nonce.as_bytes(),
        b"secretctl-executor-session-v1",
    );
    let auth_response = RpcResponse::success(
        auth_request.id,
        serde_json::to_value(SessionAuthenticateResult {
            authenticated: true,
            rekey_after_seconds: 600,
        })?,
    );
    framed.send(serde_json::to_vec(&auth_response)?).await?;
    let authenticated_at = std::time::Instant::now();

    while let Some(msg_res) = framed.next().await {
        anyhow::ensure!(
            authenticated_at.elapsed().as_secs() < 600,
            "executor rekey required"
        );
        let msg_bytes = secure_channel.decrypt(&msg_res?)?;
        let rpc_req: RpcRequest<serde_json::Value> =
            secretctl_protocol::from_slice_strict(&msg_bytes)?;

        let id = rpc_req.id.clone();
        let method = rpc_req.method.as_str();

        let response: RpcResponse<serde_json::Value> = match method {
            "browser.register" => {
                let params: BrowserRegisterParams =
                    serde_json::from_value(rpc_req.params.unwrap_or_default())?;
                match state.handle_browser_register(params) {
                    Ok(res) => RpcResponse::success(id, serde_json::to_value(res)?),
                    Err(err) => RpcResponse::error(id, err),
                }
            }
            "execution.next" => {
                let params: ExecutionNextParams =
                    serde_json::from_value(rpc_req.params.unwrap_or_default())?;
                match state.handle_execution_next(params) {
                    Ok(res) => RpcResponse::success(id, serde_json::to_value(res)?),
                    Err(err) => RpcResponse::error(id, err),
                }
            }
            "executor.prepare" => {
                let params: ExecutorPrepareParams =
                    serde_json::from_value(rpc_req.params.unwrap_or_default())?;
                match state.handle_executor_prepare(params).await {
                    Ok(res) => RpcResponse::success(id, serde_json::to_value(res)?),
                    Err(err) => RpcResponse::error(id, err),
                }
            }
            "executor.consume" => {
                let params: ExecutorConsumeParams =
                    serde_json::from_value(rpc_req.params.unwrap_or_default())?;
                match state.handle_executor_consume(params).await {
                    Ok(res) => RpcResponse::success(id, serde_json::to_value(res)?),
                    Err(err) => RpcResponse::error(id, err),
                }
            }
            "oauth.callback" => {
                let params: OAuthCallbackParams =
                    serde_json::from_value(rpc_req.params.unwrap_or_default())?;
                match state.handle_oauth_callback(params).await {
                    Ok(res) => RpcResponse::success(id, serde_json::to_value(res)?),
                    Err(err) => RpcResponse::error(id, err),
                }
            }
            "executor.result" => {
                let params: ExecutorResultParams =
                    serde_json::from_value(rpc_req.params.unwrap_or_default())?;
                match state.handle_executor_result(params).await {
                    Ok(res) => RpcResponse::success(id, serde_json::to_value(res)?),
                    Err(err) => RpcResponse::error(id, err),
                }
            }
            "executor.heartbeat" => {
                let params: ExecutorHeartbeatParams =
                    serde_json::from_value(rpc_req.params.unwrap_or_default())?;
                match state.handle_executor_heartbeat(params).await {
                    Ok(res) => RpcResponse::success(id, serde_json::to_value(res)?),
                    Err(err) => RpcResponse::error(id, err),
                }
            }
            _ => RpcResponse::error(
                id,
                RpcError::new(RpcErrorCode::METHOD_NOT_FOUND, "Method not found"),
            ),
        };

        let resp_bytes = secure_channel.encrypt(&serde_json::to_vec(&response)?)?;
        framed.send(resp_bytes).await?;
    }

    Ok(())
}

async fn handle_admin_connection(stream: UnixStream, state: BrokerState) -> anyhow::Result<()> {
    let peer_cred = stream.peer_cred()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let socket_path = stream
            .local_addr()?
            .as_pathname()
            .ok_or_else(|| anyhow::anyhow!("admin socket has no pathname"))?
            .to_path_buf();
        anyhow::ensure!(
            std::fs::metadata(socket_path)?.uid() == peer_cred.uid(),
            "admin peer UID rejected"
        );
    }
    let mut framed = Framed::new(stream, LengthPrefixedCodec::for_agent());
    let hello_bytes = framed
        .next()
        .await
        .ok_or_else(|| anyhow::anyhow!("admin disconnected before handshake"))??;
    let hello_request: RpcRequest<serde_json::Value> =
        secretctl_protocol::from_slice_strict(&hello_bytes)?;
    anyhow::ensure!(
        hello_request.method == "session.hello",
        "session.hello required"
    );
    let hello: SessionHelloParams =
        serde_json::from_value(hello_request.params.unwrap_or_default())?;
    anyhow::ensure!(
        hello.protocol_version == "1.0"
            && hello.role == "admin"
            && hello.principal_id == "local-admin"
            && hello
                .supported_suites
                .iter()
                .any(|suite| suite == "X25519-HKDF-SHA256-CHACHA20POLY1305"),
        "admin handshake rejected"
    );
    let server_nonce = uuid::Uuid::new_v4().to_string();
    let server_ephemeral = secretctl_crypto::StaticX25519::generate();
    let server_public = server_ephemeral.public_bytes();
    let server_transcript = secretctl_crypto::compute_context_digest(&[
        b"secretctl-session-hello-v1",
        hello.client_nonce.as_bytes(),
        server_nonce.as_bytes(),
        hello.principal_id.as_bytes(),
        &server_public,
    ]);
    let hello_response = RpcResponse::success(
        hello_request.id,
        serde_json::to_value(SessionHelloResult {
            protocol_version: "1.0".to_string(),
            server_nonce: server_nonce.clone(),
            ephemeral_public_key: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(server_public),
            server_key_id: state.key_id.clone(),
            signature: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(state.broker_key.sign(&server_transcript)),
        })?,
    );
    framed.send(serde_json::to_vec(&hello_response)?).await?;
    let auth_bytes = framed
        .next()
        .await
        .ok_or_else(|| anyhow::anyhow!("admin disconnected during handshake"))??;
    let auth_request: RpcRequest<serde_json::Value> =
        secretctl_protocol::from_slice_strict(&auth_bytes)?;
    anyhow::ensure!(
        auth_request.method == "session.authenticate",
        "session.authenticate required"
    );
    let auth: SessionAuthenticateParams =
        serde_json::from_value(auth_request.params.unwrap_or_default())?;
    let client_public = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(auth.client_ephemeral_public_key)?;
    let client_public: [u8; 32] = client_public
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid admin ephemeral key"))?;
    let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(auth.signature)?;
    let transcript = session_auth_transcript(&hello, &server_nonce, &server_public, &client_public);
    secretctl_crypto::verify_signature(
        &state.broker_key.public_key_bytes(),
        &transcript,
        &signature,
    )
    .map_err(|_| anyhow::anyhow!("admin signature rejected"))?;
    let shared_secret = server_ephemeral.diffie_hellman(&client_public);
    let mut secure_channel = secretctl_crypto::SecureChannel::new_server(
        &shared_secret,
        server_nonce.as_bytes(),
        b"secretctl-admin-session-v1",
    );
    let auth_response = RpcResponse::success(
        auth_request.id,
        serde_json::to_value(SessionAuthenticateResult {
            authenticated: true,
            rekey_after_seconds: 600,
        })?,
    );
    framed.send(serde_json::to_vec(&auth_response)?).await?;
    let authenticated_at = std::time::Instant::now();

    while let Some(msg_res) = framed.next().await {
        anyhow::ensure!(
            authenticated_at.elapsed().as_secs() < 600,
            "admin rekey required"
        );
        let msg_bytes = secure_channel.decrypt(&msg_res?)?;
        let rpc_req: RpcRequest<serde_json::Value> =
            secretctl_protocol::from_slice_strict(&msg_bytes)?;
        let id = rpc_req.id.clone();

        let response: RpcResponse<serde_json::Value> = match rpc_req.method.as_str() {
            "admin.ping" => RpcResponse::success(id, serde_json::json!({"status": "ok"})),
            "browser.launch" => {
                let params: BrowserLaunchParams =
                    serde_json::from_value(rpc_req.params.unwrap_or_default())?;
                match state.launch_managed_browser(params) {
                    Ok(result) => RpcResponse::success(id, serde_json::to_value(result)?),
                    Err(error) => RpcResponse::error(id, error),
                }
            }
            "browser.launch_status" => {
                let params: BrowserCloseParams =
                    serde_json::from_value(rpc_req.params.unwrap_or_default())?;
                match state.browser_launch_status(&params.instance_id) {
                    Ok(result) => RpcResponse::success(id, serde_json::to_value(result)?),
                    Err(error) => RpcResponse::error(id, error),
                }
            }
            "browser.close" => {
                let params: BrowserCloseParams =
                    serde_json::from_value(rpc_req.params.unwrap_or_default())?;
                match state.close_managed_browser(params) {
                    Ok(()) => RpcResponse::success(id, serde_json::json!({"closed": true})),
                    Err(error) => RpcResponse::error(id, error),
                }
            }
            "approval.list" => {
                RpcResponse::success(id, serde_json::to_value(state.list_pending_approvals())?)
            }
            "approval.decide" => {
                let params: ApprovalDecideParams =
                    serde_json::from_value(rpc_req.params.unwrap_or_default())?;
                match state.decide_approval(
                    &params.approval_id,
                    params.decision == "approve",
                    &params.context_digest,
                    "local-admin",
                    params.presence_verified,
                ) {
                    Ok(result) => RpcResponse::success(id, serde_json::to_value(result)?),
                    Err(error) => RpcResponse::error(id, error),
                }
            }
            "capability.list" => {
                let params: CapabilityListParams =
                    serde_json::from_value(rpc_req.params.unwrap_or_default())?;
                match state.list_capabilities(params.state.as_deref()) {
                    Ok(result) => RpcResponse::success(id, serde_json::to_value(result)?),
                    Err(error) => RpcResponse::error(id, error),
                }
            }
            "capability.revoke" => {
                let params: CapabilityRevokeParams =
                    serde_json::from_value(rpc_req.params.unwrap_or_default())?;
                match state.revoke_capability_admin(&params.capability_id, &params.reason) {
                    Ok(()) => RpcResponse::success(id, serde_json::json!({"revoked": true})),
                    Err(error) => RpcResponse::error(id, error),
                }
            }
            "ui.status" => match state.ui_status() {
                Ok(status) => RpcResponse::success(id, serde_json::to_value(status)?),
                Err(error) => RpcResponse::error(id, error),
            },
            "ui.pending" => match state.ui_pending_approvals() {
                Ok(pending) => RpcResponse::success(id, serde_json::to_value(pending)?),
                Err(error) => RpcResponse::error(id, error),
            },
            // Re-reads one pending request so the approval window can refresh
            // its context digest immediately before the human commits.
            "ui.pending_one" => {
                let params: ApprovalLookupParams =
                    serde_json::from_value(rpc_req.params.unwrap_or_default())?;
                match state.ui_pending_approval(&params.approval_id) {
                    Ok(request) => RpcResponse::success(id, serde_json::to_value(request)?),
                    Err(error) => RpcResponse::error(id, error),
                }
            }
            "ui.activity" => {
                let params: UiActivityParams =
                    serde_json::from_value(rpc_req.params.unwrap_or_default())?;
                match state.ui_activity(params.limit) {
                    Ok(events) => RpcResponse::success(id, serde_json::to_value(events)?),
                    Err(error) => RpcResponse::error(id, error),
                }
            }
            "ui.agents" => match state.ui_agents() {
                Ok(agents) => RpcResponse::success(id, serde_json::to_value(agents)?),
                Err(error) => RpcResponse::error(id, error),
            },
            "ui.credentials" => match state.ui_credentials() {
                Ok(credentials) => RpcResponse::success(id, serde_json::to_value(credentials)?),
                Err(error) => RpcResponse::error(id, error),
            },
            "ui.browser_sessions" => match state.ui_browser_sessions() {
                Ok(sessions) => RpcResponse::success(id, serde_json::to_value(sessions)?),
                Err(error) => RpcResponse::error(id, error),
            },
            "grant.list" => {
                let params: GrantListParams =
                    serde_json::from_value(rpc_req.params.unwrap_or_default())?;
                match state.ui_grants(params.include_revoked) {
                    Ok(grants) => RpcResponse::success(id, serde_json::to_value(grants)?),
                    Err(error) => RpcResponse::error(id, error),
                }
            }
            "grant.create" => {
                let params: GrantCreateParams =
                    serde_json::from_value(rpc_req.params.unwrap_or_default())?;
                match state.ui_create_grant(params) {
                    Ok(result) => RpcResponse::success(id, serde_json::to_value(result)?),
                    Err(error) => RpcResponse::error(id, error),
                }
            }
            "grant.revoke" => {
                let params: GrantRevokeParams =
                    serde_json::from_value(rpc_req.params.unwrap_or_default())?;
                match state.ui_revoke_grants(&params.selector, &params.reason) {
                    Ok(result) => RpcResponse::success(id, serde_json::to_value(result)?),
                    Err(error) => RpcResponse::error(id, error),
                }
            }
            "agent.disable" => {
                let params: AgentDisableParams =
                    serde_json::from_value(rpc_req.params.unwrap_or_default())?;
                match AgentId::parse(&params.agent_id) {
                    Ok(agent_id) => match state.ui_disable_agent(&agent_id) {
                        Ok(result) => RpcResponse::success(id, serde_json::to_value(result)?),
                        Err(error) => RpcResponse::error(id, error),
                    },
                    Err(_) => RpcResponse::error(
                        id,
                        RpcError::new(RpcErrorCode::INVALID_PARAMS, "Unknown agent"),
                    ),
                }
            }
            "policy.reload" => {
                let params: PolicyReloadParams =
                    serde_json::from_value(rpc_req.params.unwrap_or_default())?;
                let document = secretctl_policy::PolicyDocument::from_yaml(&params.policy_yaml)?;
                let evaluator = secretctl_policy::PolicyEvaluator::new(document);
                let actual_hash = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(evaluator.policy_hash());
                if actual_hash != params.expected_hash {
                    RpcResponse::error(
                        id,
                        RpcError::new(RpcErrorCode::INVALID_PARAMS, "Policy hash mismatch"),
                    )
                } else {
                    match state.replace_policy(evaluator) {
                        Ok(revoked) => RpcResponse::success(
                            id,
                            serde_json::json!({"reloaded": true, "revoked": revoked}),
                        ),
                        Err(error) => RpcResponse::error(id, error),
                    }
                }
            }
            _ => RpcResponse::error(
                id,
                RpcError::new(RpcErrorCode::METHOD_NOT_FOUND, "Method not found"),
            ),
        };

        let resp_bytes = secure_channel.encrypt(&serde_json::to_vec(&response)?)?;
        framed.send(resp_bytes).await?;
    }

    Ok(())
}
