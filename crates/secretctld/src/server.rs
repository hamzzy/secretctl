use crate::state::BrokerState;
use base64::Engine;
use futures::{SinkExt, StreamExt};
use secretctl_domain::{AgentId, ApprovalId};
use secretctl_protocol::{
    ActionCancelParams, ActionRequestParams, ActionStatusParams, ExecutorConsumeParams,
    ExecutorHeartbeatParams, ExecutorPrepareParams, ExecutorResultParams, LengthPrefixedCodec,
    RpcError, RpcErrorCode, RpcRequest, RpcResponse, SessionHelloParams, SessionHelloResult,
};
use std::path::{Path, PathBuf};
use tokio::net::{UnixListener, UnixStream};
use tokio_util::codec::Framed;
use tracing::{error, info, warn};

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovalDecideParams {
    approval_id: ApprovalId,
    decision: String,
    context_digest: Vec<u8>,
    #[serde(default)]
    presence_verified: bool,
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

        let agent_sock_path = self.runtime_dir.join("agent.sock");
        let executor_sock_path = self.runtime_dir.join("executor.sock");
        let admin_sock_path = self.runtime_dir.join("admin.sock");

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
            }
        });

        Ok(())
    }
}

async fn handle_agent_connection(stream: UnixStream, state: BrokerState) -> anyhow::Result<()> {
    let mut framed = Framed::new(stream, LengthPrefixedCodec::for_agent());
    let mut authenticated_agent: Option<AgentId> = None;

    while let Some(msg_res) = framed.next().await {
        let msg_bytes = msg_res?;
        let rpc_req: RpcRequest<serde_json::Value> = serde_json::from_slice(&msg_bytes)?;

        let id = rpc_req.id.clone();
        let method = rpc_req.method.as_str();

        let response: RpcResponse<serde_json::Value> = match method {
            "session.hello" => {
                let params: SessionHelloParams =
                    serde_json::from_value(rpc_req.params.unwrap_or_default())?;
                let resolved_agent = state.store.resolve_agent_id(&params.principal_id)?;
                if params.protocol_version != "1.0"
                    || params.role != "agent"
                    || resolved_agent.is_none()
                {
                    RpcResponse::error(
                        id,
                        RpcError::new(
                            RpcErrorCode::SECURITY_VIOLATION,
                            "Agent enrollment rejected",
                        ),
                    )
                } else {
                    authenticated_agent = resolved_agent;
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
                        server_nonce,
                        ephemeral_public_key: base64::engine::general_purpose::URL_SAFE_NO_PAD
                            .encode(ephemeral_public_key),
                        server_key_id: state.key_id.clone(),
                        signature: base64::engine::general_purpose::URL_SAFE_NO_PAD
                            .encode(state.broker_key.sign(&transcript)),
                    };
                    RpcResponse::success(id, serde_json::to_value(res)?)
                }
            }
            "action.request" => {
                if let Some(agent_id) = authenticated_agent.clone() {
                    let params: ActionRequestParams =
                        serde_json::from_value(rpc_req.params.unwrap_or_default())?;
                    match state.handle_action_request(agent_id, params).await {
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
            _ => RpcResponse::error(
                id,
                RpcError::new(RpcErrorCode::METHOD_NOT_FOUND, "Method not found"),
            ),
        };

        let resp_bytes = serde_json::to_vec(&response)?;
        framed.send(resp_bytes).await?;
    }

    Ok(())
}

async fn handle_executor_connection(stream: UnixStream, state: BrokerState) -> anyhow::Result<()> {
    let mut framed = Framed::new(stream, LengthPrefixedCodec::for_executor());

    while let Some(msg_res) = framed.next().await {
        let msg_bytes = msg_res?;
        let rpc_req: RpcRequest<serde_json::Value> = serde_json::from_slice(&msg_bytes)?;

        let id = rpc_req.id.clone();
        let method = rpc_req.method.as_str();

        let response: RpcResponse<serde_json::Value> = match method {
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

        let resp_bytes = serde_json::to_vec(&response)?;
        framed.send(resp_bytes).await?;
    }

    Ok(())
}

async fn handle_admin_connection(stream: UnixStream, state: BrokerState) -> anyhow::Result<()> {
    let mut framed = Framed::new(stream, LengthPrefixedCodec::for_agent());

    while let Some(msg_res) = framed.next().await {
        let msg_bytes = msg_res?;
        let rpc_req: RpcRequest<serde_json::Value> = serde_json::from_slice(&msg_bytes)?;
        let id = rpc_req.id.clone();

        let response: RpcResponse<serde_json::Value> = match rpc_req.method.as_str() {
            "admin.ping" => RpcResponse::success(id, serde_json::json!({"status": "ok"})),
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
            _ => RpcResponse::error(
                id,
                RpcError::new(RpcErrorCode::METHOD_NOT_FOUND, "Method not found"),
            ),
        };

        let resp_bytes = serde_json::to_vec(&response)?;
        framed.send(resp_bytes).await?;
    }

    Ok(())
}
