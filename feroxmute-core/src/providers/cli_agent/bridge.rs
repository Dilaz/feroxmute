//! Thread-safe bridge to the ACP client.
//!
//! The ACP SDK's `ClientSideConnection` uses `LocalBoxFuture` (requires `spawn_local`
//! / `LocalSet`), but `LlmProvider: Send + Sync` needs `Send` futures. This bridge
//! runs all ACP operations on a dedicated `std::thread` with a `current_thread`
//! tokio runtime + `LocalSet`, communicating via channels.

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use acp::Agent; // Required for initialize, prompt, new_session, cancel
use agent_client_protocol as acp;
use futures::io::AsyncWriteExt;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};

use super::config::{CliAgentConfig, CliAgentType};
use crate::Result;

// ---------------------------------------------------------------------------
// Public event type (forwarded from bridge thread to main runtime)
// ---------------------------------------------------------------------------

/// Events emitted by the CLI agent during prompt processing.
///
/// These are forwarded from the bridge thread via an unbounded channel so that
/// the main runtime can update the TUI / `EventSender`.
#[derive(Debug, Clone)]
pub enum AcpEvent {
    AgentMessage {
        session_id: String,
        text: String,
    },
    AgentThought {
        session_id: String,
        text: String,
    },
    ToolCallStarted {
        session_id: String,
        title: String,
        tool_call_id: String,
    },
    ToolCallCompleted {
        session_id: String,
        tool_call_id: String,
    },
}

// ---------------------------------------------------------------------------
// Commands sent to the bridge thread
// ---------------------------------------------------------------------------

enum AcpCommand {
    Connect {
        working_dir: PathBuf,
        reply: oneshot::Sender<Result<()>>,
    },
    NewSession {
        agent_role: String,
        working_dir: PathBuf,
        mcp_server_url: Option<String>,
        bearer_token: Option<String>,
        reply: oneshot::Sender<Result<acp::SessionId>>,
    },
    Prompt {
        session_id: acp::SessionId,
        message: String,
        reply: oneshot::Sender<Result<String>>,
    },
    Cancel {
        session_id: acp::SessionId,
    },
    Shutdown,
}

// ---------------------------------------------------------------------------
// Response collector (single-threaded, lives inside bridge thread)
// ---------------------------------------------------------------------------

#[derive(Default)]
struct ResponseCollector {
    session_content: HashMap<String, Vec<String>>,
}

impl ResponseCollector {
    fn add_content(&mut self, session_id: &str, text: String) {
        self.session_content
            .entry(session_id.to_string())
            .or_default()
            .push(text);
    }

    fn take_content(&mut self, session_id: &str) -> String {
        self.session_content
            .remove(session_id)
            .unwrap_or_default()
            .join("")
    }
}

/// A custom connection for Gemini CLI which uses a slightly different ACP flavor.
struct GeminiConnection {
    stdin: Arc<Mutex<tokio_util::compat::Compat<tokio::process::ChildStdin>>>,
    pending_requests: Arc<Mutex<HashMap<u64, oneshot::Sender<Result<Value>>>>>,
    next_id: AtomicU64,
}

impl GeminiConnection {
    async fn call(&self, method: &str, params: Value) -> Result<Value> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let request = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params
        });

        let (tx, rx) = oneshot::channel();
        self.pending_requests.lock().await.insert(id, tx);

        tracing::debug!("Gemini call #{id}: sending {method}");
        Self::write_message(&self.stdin, &request).await?;

        // session/prompt can take very long (agent doing work); others should be quick
        let timeout_dur = if method == "session/prompt" {
            Duration::from_secs(600) // 10 min
        } else {
            Duration::from_secs(60) // 1 min
        };

        match tokio::time::timeout(timeout_dur, rx).await {
            Ok(Ok(result)) => {
                tracing::debug!("Gemini call #{id}: {method} completed");
                result
            }
            Ok(Err(_)) => Err(crate::Error::Provider(
                "Gemini connection task dropped".into(),
            )),
            Err(_) => {
                // Remove from pending so stdout reader doesn't try to resolve it
                self.pending_requests.lock().await.remove(&id);
                Err(crate::Error::Provider(format!(
                    "Gemini ACP call '{method}' (id={id}) timed out after {}s. \
                     Check Gemini CLI logs and stderr for errors.",
                    timeout_dur.as_secs()
                )))
            }
        }
    }

    /// Write a JSON-RPC message to the agent's stdin.
    async fn write_message(
        stdin: &Mutex<tokio_util::compat::Compat<tokio::process::ChildStdin>>,
        message: &Value,
    ) -> Result<()> {
        let mut data = serde_json::to_vec(message).map_err(|e| {
            crate::Error::Provider(format!("Failed to serialize Gemini ACP message: {e}"))
        })?;
        data.push(b'\n');

        let mut guard = stdin.lock().await;
        guard.write_all(&data).await.map_err(|e| {
            crate::Error::Provider(format!("Failed to write to Gemini CLI stdin: {e}"))
        })?;
        guard.flush().await.map_err(|e| {
            crate::Error::Provider(format!("Failed to flush Gemini CLI stdin: {e}"))
        })?;

        Ok(())
    }
}

enum Connection {
    Standard(acp::ClientSideConnection),
    Gemini(GeminiConnection),
}

// ---------------------------------------------------------------------------
// AcpBridge (Send + Sync wrapper)
// ---------------------------------------------------------------------------

/// Thread-safe bridge to a CLI agent subprocess via ACP.
///
/// All ACP I/O runs on a dedicated OS thread with its own single-threaded
/// tokio runtime and `LocalSet`. Public methods send commands over an `mpsc`
/// channel and `await` a `oneshot` reply, producing ordinary `Send` futures
/// that satisfy the `LlmProvider` trait bounds.
pub struct AcpBridge {
    cmd_tx: mpsc::Sender<AcpCommand>,
    event_rx: tokio::sync::Mutex<mpsc::UnboundedReceiver<AcpEvent>>,
    thread_handle: std::sync::Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl AcpBridge {
    /// Create a new bridge. Spawns the background thread immediately.
    pub fn new(config: CliAgentConfig) -> Self {
        let (cmd_tx, cmd_rx) = mpsc::channel::<AcpCommand>(32);
        let (event_tx, event_rx) = mpsc::unbounded_channel::<AcpEvent>();

        let handle = std::thread::spawn(move || {
            let rt = build_bridge_runtime();
            let local = tokio::task::LocalSet::new();
            local.block_on(&rt, command_loop(cmd_rx, event_tx, config));
        });

        Self {
            cmd_tx,
            event_rx: tokio::sync::Mutex::new(event_rx),
            thread_handle: std::sync::Mutex::new(Some(handle)),
        }
    }

    // -- public async API (all return Send futures) -------------------------

    /// Spawn the CLI agent subprocess and establish the ACP connection.
    pub async fn connect(&self, working_dir: &Path) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(AcpCommand::Connect {
                working_dir: working_dir.to_path_buf(),
                reply: tx,
            })
            .await
            .map_err(|_| crate::Error::Provider("ACP bridge thread panicked".into()))?;
        rx.await
            .map_err(|_| crate::Error::Provider("ACP bridge thread panicked".into()))?
    }

    /// Create a new ACP session for the given agent role.
    ///
    /// If `mcp_server_url` is provided, it will be passed to the agent as an
    /// HTTP MCP server so that feroxmute tools are available in the session.
    /// If `bearer_token` is also provided, it is sent as an `Authorization`
    /// header so the MCP server can authenticate the CLI agent's requests.
    pub async fn new_session(
        &self,
        agent_role: &str,
        working_dir: &Path,
        mcp_server_url: Option<String>,
        bearer_token: Option<String>,
    ) -> Result<acp::SessionId> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(AcpCommand::NewSession {
                agent_role: agent_role.to_string(),
                working_dir: working_dir.to_path_buf(),
                mcp_server_url,
                bearer_token,
                reply: tx,
            })
            .await
            .map_err(|_| crate::Error::Provider("ACP bridge thread panicked".into()))?;
        rx.await
            .map_err(|_| crate::Error::Provider("ACP bridge thread panicked".into()))?
    }

    /// Send a prompt to a session and wait for the complete response.
    pub async fn prompt(&self, session_id: &acp::SessionId, message: &str) -> Result<String> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(AcpCommand::Prompt {
                session_id: session_id.clone(),
                message: message.to_string(),
                reply: tx,
            })
            .await
            .map_err(|_| crate::Error::Provider("ACP bridge thread panicked".into()))?;
        rx.await
            .map_err(|_| crate::Error::Provider("ACP bridge thread panicked".into()))?
    }

    /// Cancel an active session.
    pub async fn cancel(&self, session_id: &acp::SessionId) {
        let _ = self
            .cmd_tx
            .send(AcpCommand::Cancel {
                session_id: session_id.clone(),
            })
            .await;
    }

    /// Take the event receiver (can only be called once).
    pub async fn take_event_receiver(&self) -> mpsc::UnboundedReceiver<AcpEvent> {
        // Replace with an unbounded channel whose sender is already dropped
        // so the caller owns the original receiver.
        let (_dummy_tx, dummy_rx) = mpsc::unbounded_channel();
        let mut guard = self.event_rx.lock().await;
        std::mem::replace(&mut *guard, dummy_rx)
    }

    /// Shut down the bridge thread gracefully.
    pub async fn shutdown(&self) {
        let _ = self.cmd_tx.send(AcpCommand::Shutdown).await;
    }
}

impl Drop for AcpBridge {
    fn drop(&mut self) {
        let _ = self.cmd_tx.try_send(AcpCommand::Shutdown);
        if let Ok(mut guard) = self.thread_handle.lock()
            && let Some(handle) = guard.take()
        {
            let _ = handle.join();
        }
    }
}

// Silence the `expect` clippy warning for the runtime build in the bridge
// thread. If the current-thread runtime cannot be built something is
// fundamentally wrong and panicking is the only reasonable choice.
#[allow(clippy::expect_used)]
fn build_bridge_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to build bridge tokio runtime")
}

// ---------------------------------------------------------------------------
// Bridge thread internals
// ---------------------------------------------------------------------------

/// Main event loop that runs inside the bridge thread's `LocalSet`.
async fn command_loop(
    mut cmd_rx: mpsc::Receiver<AcpCommand>,
    event_tx: mpsc::UnboundedSender<AcpEvent>,
    config: CliAgentConfig,
) {
    let mut child: Option<Child> = None;
    let mut connection: Option<Connection> = None;
    let collector = Rc::new(RefCell::new(ResponseCollector::default()));

    while let Some(cmd) = cmd_rx.recv().await {
        match cmd {
            AcpCommand::Connect { working_dir, reply } => {
                let result = do_connect(&config, &working_dir, &event_tx, &collector).await;
                match result {
                    Ok((c, conn)) => {
                        child = Some(c);
                        connection = Some(conn);
                        let _ = reply.send(Ok(()));
                    }
                    Err(e) => {
                        let _ = reply.send(Err(e));
                    }
                }
            }

            AcpCommand::NewSession {
                agent_role,
                working_dir,
                mcp_server_url,
                bearer_token,
                reply,
            } => {
                let result = match connection.as_ref() {
                    Some(Connection::Standard(conn)) => {
                        tracing::debug!("Creating standard ACP session for role '{}'", agent_role);
                        let mut request = acp::NewSessionRequest::new(&working_dir);
                        if let Some(url) = mcp_server_url {
                            tracing::debug!("Attaching MCP server at {}", url);
                            let mut mcp_http = acp::McpServerHttp::new("feroxmute", url);
                            if let Some(ref token) = bearer_token {
                                mcp_http = mcp_http.headers(vec![acp::HttpHeader::new(
                                    "Authorization",
                                    format!("Bearer {token}"),
                                )]);
                            }
                            request = request.mcp_servers(vec![acp::McpServer::Http(mcp_http)]);
                        }
                        conn.new_session(request)
                            .await
                            .map(|r| r.session_id)
                            .map_err(|e| {
                                crate::Error::Provider(format!("Failed to create ACP session: {e}"))
                            })
                    }
                    Some(Connection::Gemini(conn)) => {
                        tracing::debug!("Creating Gemini ACP session for role '{}'", agent_role);
                        let mut mcp_servers = Vec::new();
                        if let Some(url) = mcp_server_url {
                            let mut headers = vec![];
                            if let Some(ref token) = bearer_token {
                                headers.push(json!({
                                    "name": "Authorization",
                                    "value": format!("Bearer {token}")
                                }));
                            }
                            mcp_servers.push(json!({
                                "name": "feroxmute",
                                "type": "http",
                                "url": url,
                                "headers": headers
                            }));
                        }

                        tracing::debug!(
                            "Gemini: calling session/new with {} MCP server(s)",
                            mcp_servers.len()
                        );
                        let result = conn
                            .call(
                                "session/new",
                                json!({
                                    "cwd": working_dir.to_string_lossy(),
                                    "mcpServers": mcp_servers
                                }),
                            )
                            .await;

                        match result {
                            Ok(res) => {
                                tracing::debug!("Gemini session/new returned: {res}");
                                if let Some(sid) = res.get("sessionId").and_then(|v| v.as_str()) {
                                    Ok(acp::SessionId::new(sid))
                                } else {
                                    Err(crate::Error::Provider(
                                        "Gemini session/new response missing sessionId".into(),
                                    ))
                                }
                            }
                            Err(e) => {
                                tracing::debug!("Gemini session/new failed: {e}");
                                Err(e)
                            }
                        }
                    }
                    None => Err(crate::Error::Provider(
                        "ACP client not connected".to_string(),
                    )),
                };
                let _ = reply.send(result);
            }

            AcpCommand::Prompt {
                session_id,
                message,
                reply,
            } => {
                let result = match connection.as_ref() {
                    Some(Connection::Standard(conn)) => {
                        let prompt_result = conn
                            .prompt(acp::PromptRequest::new(
                                session_id.clone(),
                                vec![acp::ContentBlock::Text(acp::TextContent::new(&message))],
                            ))
                            .await;
                        match prompt_result {
                            Ok(_) => {
                                let text =
                                    collector.borrow_mut().take_content(session_id.0.as_ref());
                                Ok(text)
                            }
                            Err(e) => {
                                if e.code == acp::ErrorCode::AuthRequired {
                                    Err(crate::Error::Provider(format!(
                                        "{} requires authentication. Run: {}",
                                        config.agent_type.provider_name(),
                                        config.agent_type.auth_hint()
                                    )))
                                } else {
                                    Err(crate::Error::Provider(format!("ACP prompt failed: {e}")))
                                }
                            }
                        }
                    }
                    Some(Connection::Gemini(conn)) => {
                        tracing::debug!(
                            "Gemini: calling session/prompt for session '{}'",
                            session_id.0
                        );
                        let result = conn
                            .call(
                                "session/prompt",
                                json!({
                                    "sessionId": session_id.0,
                                    "prompt": [{"type": "text", "text": message}]
                                }),
                            )
                            .await;

                        match result {
                            Ok(_) => {
                                tracing::debug!(
                                    "Gemini session/prompt completed for session '{}'",
                                    session_id.0
                                );
                                let text =
                                    collector.borrow_mut().take_content(session_id.0.as_ref());
                                Ok(text)
                            }
                            Err(ref e) => {
                                tracing::debug!(
                                    "Gemini session/prompt failed for session '{}': {e}",
                                    session_id.0
                                );
                                result.map(|_| String::new())
                            }
                        }
                    }
                    None => Err(crate::Error::Provider(
                        "ACP client not connected".to_string(),
                    )),
                };
                let _ = reply.send(result);
            }

            AcpCommand::Cancel { session_id } => match connection.as_ref() {
                Some(Connection::Standard(conn)) => {
                    let _ = conn.cancel(acp::CancelNotification::new(session_id)).await;
                }
                Some(Connection::Gemini(conn)) => {
                    let _ = conn
                        .call("session/cancel", json!({ "sessionId": session_id.0 }))
                        .await;
                }
                None => {}
            },

            AcpCommand::Shutdown => {
                if let Some(ref mut c) = child {
                    let _ = c.kill().await;
                }
                break;
            }
        }
    }
}

/// Handle an agent-initiated JSON-RPC request from Gemini CLI.
///
/// The agent may send requests like `request_permission` when it needs approval
/// for tool use. We auto-approve (feroxmute manages permissions via MCP tools).
async fn handle_gemini_request(
    method: &str,
    val: &Value,
    stdin: &Mutex<tokio_util::compat::Compat<tokio::process::ChildStdin>>,
) {
    let id = val.get("id").cloned().unwrap_or(Value::Null);

    let response = match method {
        "request_permission" | "session/request_permission" => {
            // Auto-approve all tool calls — feroxmute handles its own permissions
            // via the MCP tool layer. Mirrors the Standard delegate's behavior.
            //
            // ACP options use `optionId` for the ID and `kind` for the type
            // (allow_always, allow_once, reject_once, etc.). Gemini CLI sends
            // optionId values like "proceed_always", "proceed_once", "cancel".
            // We prefer permanent allow, then temporary allow, then first option.
            let params = val.get("params");
            let option_id = params
                .and_then(|p| p.get("options"))
                .and_then(|o| o.as_array())
                .and_then(|opts| {
                    // Prefer permanent allow by `kind`, then temporary allow, then first
                    opts.iter()
                        .find(|o| o.get("kind").and_then(|v| v.as_str()) == Some("allow_always"))
                        .or_else(|| {
                            opts.iter().find(|o| {
                                o.get("kind").and_then(|v| v.as_str()) == Some("allow_once")
                            })
                        })
                        .or_else(|| opts.first())
                })
                .and_then(|o| o.get("optionId").and_then(|v| v.as_str()))
                .unwrap_or("proceed_always");

            tracing::debug!("Gemini {method} auto-approved with optionId '{option_id}'");
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "outcome": {
                        "outcome": "selected",
                        "optionId": option_id
                    }
                }
            })
        }
        _ => {
            tracing::warn!("Unhandled Gemini agent request: {method}");
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32601,
                    "message": format!("Method not supported: {method}")
                }
            })
        }
    };

    tracing::debug!("Sending Gemini {method} response: {response}");
    if let Err(e) = GeminiConnection::write_message(stdin, &response).await {
        tracing::error!("Failed to send response for Gemini {method}: {e}");
    } else {
        tracing::debug!("Gemini {method} response sent successfully");
    }
}

/// Handle a notification (no `id`) from Gemini CLI.
///
/// Supports two JSON shapes for the `update` field:
///
/// 1. **ACP spec tagged enum** (standard): discriminator in `sessionUpdate` field
///    ```json
///    {"sessionUpdate": "agent_message_chunk", "content": {"type": "text", "text": "..."}}
///    ```
///
/// 2. **Nested object**: variant name is a key wrapping the payload
///    ```json
///    {"agentMessageChunk": {"content": {"text": "..."}}}
///    ```
fn handle_gemini_notification(
    method: &str,
    val: &Value,
    collector: &Rc<RefCell<ResponseCollector>>,
    event_tx: &mpsc::UnboundedSender<AcpEvent>,
) {
    if method != "session/update" && method != "session/notification" {
        tracing::trace!("Gemini notification: {method}");
        return;
    }

    let Some(params) = val.get("params") else {
        return;
    };
    let session_id = params
        .get("sessionId")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let Some(update) = params.get("update") else {
        return;
    };

    // Detect which format: check for `sessionUpdate` tag (ACP spec) or nested keys
    let update_type = update
        .get("sessionUpdate")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    match update_type {
        // ACP spec tagged format: content fields are inline in `update`
        "agent_message_chunk" => {
            if let Some(text_str) = extract_content_text(update) {
                collector
                    .borrow_mut()
                    .add_content(session_id, text_str.to_string());
                let _ = event_tx.send(AcpEvent::AgentMessage {
                    session_id: session_id.to_string(),
                    text: text_str.to_string(),
                });
            }
        }
        "agent_thought_chunk" => {
            if let Some(text_str) = extract_content_text(update) {
                let _ = event_tx.send(AcpEvent::AgentThought {
                    session_id: session_id.to_string(),
                    text: text_str.to_string(),
                });
            }
        }
        "tool_call" => {
            emit_tool_call_started(update, session_id, event_tx);
        }
        "tool_call_update" => {
            emit_tool_call_completed(update, session_id, event_tx);
        }
        _ => {
            // Try nested object format (fallback)
            if let Some(msg) = update.get("agentMessageChunk") {
                if let Some(text_str) = extract_content_text(msg) {
                    collector
                        .borrow_mut()
                        .add_content(session_id, text_str.to_string());
                    let _ = event_tx.send(AcpEvent::AgentMessage {
                        session_id: session_id.to_string(),
                        text: text_str.to_string(),
                    });
                }
            } else if let Some(thought) = update.get("agentThoughtChunk") {
                if let Some(text_str) = extract_content_text(thought) {
                    let _ = event_tx.send(AcpEvent::AgentThought {
                        session_id: session_id.to_string(),
                        text: text_str.to_string(),
                    });
                }
            } else if update.get("toolCall").is_some() {
                emit_tool_call_started(
                    update.get("toolCall").unwrap_or(update),
                    session_id,
                    event_tx,
                );
            } else if update.get("toolCallUpdate").is_some() {
                emit_tool_call_completed(
                    update.get("toolCallUpdate").unwrap_or(update),
                    session_id,
                    event_tx,
                );
            } else {
                tracing::trace!("Unrecognized Gemini update: {update}");
            }
        }
    }
}

/// Extract text from a content chunk (handles both `content.text` and `content.type=text` shapes).
fn extract_content_text(obj: &Value) -> Option<&str> {
    obj.get("content")
        .and_then(|c| c.get("text"))
        .and_then(|t| t.as_str())
}

fn emit_tool_call_started(
    obj: &Value,
    session_id: &str,
    event_tx: &mpsc::UnboundedSender<AcpEvent>,
) {
    let _ = event_tx.send(AcpEvent::ToolCallStarted {
        session_id: session_id.to_string(),
        title: obj
            .get("title")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        tool_call_id: obj
            .get("toolCallId")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
    });
}

fn emit_tool_call_completed(
    obj: &Value,
    session_id: &str,
    event_tx: &mpsc::UnboundedSender<AcpEvent>,
) {
    // For tagged format, status is inline; for nested format, it's in `fields`
    let status = obj
        .get("status")
        .or_else(|| obj.get("fields").and_then(|f| f.get("status")))
        .and_then(|v| v.as_str());

    if status == Some("completed") {
        let _ = event_tx.send(AcpEvent::ToolCallCompleted {
            session_id: session_id.to_string(),
            tool_call_id: obj
                .get("toolCallId")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
        });
    }
}

/// Spawn the CLI subprocess and establish the ACP connection.
///
/// For CLI agents that use ACP adapters (e.g. `claude-code-acp`), the binary
/// speaks ACP natively over stdin/stdout. MCP servers are provided later via
/// `NewSessionRequest.mcp_servers` rather than CLI flags.
async fn do_connect(
    config: &CliAgentConfig,
    working_dir: &Path,
    event_tx: &mpsc::UnboundedSender<AcpEvent>,
    collector: &Rc<RefCell<ResponseCollector>>,
) -> Result<(Child, Connection)> {
    // Check binary availability first
    if which::which(&config.binary_path).is_err() {
        return Err(crate::Error::Provider(format!(
            "{} CLI not found at '{}'. Install it or specify path with --cli-path. Auth hint: {}",
            config.agent_type.provider_name(),
            config.binary_path.display(),
            config.agent_type.auth_hint()
        )));
    }

    let mut cmd = Command::new(&config.binary_path);
    cmd.current_dir(working_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    // Add ACP mode and model for Gemini CLI
    if config.agent_type == CliAgentType::GeminiCli {
        cmd.arg("--experimental-acp");
        cmd.arg("-m").arg(&config.model);
    }

    let mut child = cmd.spawn().map_err(|e| {
        crate::Error::Provider(format!(
            "Failed to spawn {} CLI: {e}",
            config.agent_type.provider_name(),
        ))
    })?;

    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| crate::Error::Provider("Failed to capture CLI stdin".to_string()))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| crate::Error::Provider("Failed to capture CLI stdout".to_string()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| crate::Error::Provider("Failed to capture CLI stderr".to_string()))?;

    // Log stderr in a background task
    tokio::task::spawn_local(async move {
        use tokio::io::AsyncBufReadExt;
        let mut reader = tokio::io::BufReader::new(stderr).lines();
        while let Ok(Some(line)) = reader.next_line().await {
            tracing::warn!("CLI STDERR: {}", line);
        }
    });

    if config.agent_type == CliAgentType::GeminiCli {
        let stdin = Arc::new(Mutex::new(stdin.compat_write()));
        let pending_requests: Arc<Mutex<HashMap<u64, oneshot::Sender<Result<Value>>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let pending_requests_clone = Arc::clone(&pending_requests);
        let event_tx_clone = event_tx.clone();
        let collector_clone = Rc::clone(collector);

        let stdin_clone = Arc::clone(&stdin);
        tokio::task::spawn_local(async move {
            let mut reader = BufReader::new(stdout).lines();
            while let Ok(Some(line)) = reader.next_line().await {
                tracing::debug!("Gemini stdout: {}", line);
                let val: Value = match serde_json::from_str(&line) {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!("Gemini stdout non-JSON: {e}");
                        continue;
                    }
                };

                // Distinguish responses (result/error) from requests/notifications (method).
                // A JSON-RPC response has `result` or `error`; a request has `method`.
                let is_response = val.get("result").is_some() || val.get("error").is_some();
                let has_method = val.get("method").is_some();

                if is_response && !has_method {
                    // Response to one of our pending requests
                    if let Some(id) = val.get("id").and_then(|v| v.as_u64())
                        && let Some(tx) = pending_requests_clone.lock().await.remove(&id)
                    {
                        tracing::debug!("Gemini response matched pending request #{id}");
                        if let Some(error) = val.get("error") {
                            let _ = tx.send(Err(crate::Error::Provider(format!(
                                "Gemini ACP error: {}",
                                error
                            ))));
                        } else {
                            let _ = tx.send(Ok(val.get("result").cloned().unwrap_or(Value::Null)));
                        }
                    } else {
                        tracing::warn!("Gemini response for unknown id: {}", val);
                    }
                } else if let Some(method) = val.get("method").and_then(|v| v.as_str()) {
                    let has_id = val.get("id").is_some();

                    if has_id {
                        // Agent-initiated request — needs a response sent back
                        tracing::debug!("Gemini agent request: {method} body={val}");
                        handle_gemini_request(method, &val, &stdin_clone).await;
                    } else {
                        // Notification — no response needed
                        tracing::debug!("Gemini notification: {method}");
                        handle_gemini_notification(method, &val, &collector_clone, &event_tx_clone);
                    }
                } else {
                    tracing::warn!("Gemini stdout unrecognized message: {}", val);
                }
            }
            // Resolve all pending requests with an error so call() doesn't hang
            let mut pending = pending_requests_clone.lock().await;
            let pending_count = pending.len();
            if pending_count > 0 {
                tracing::warn!(
                    "Gemini stdout reader exited with {pending_count} pending request(s)"
                );
            } else {
                tracing::debug!("Gemini stdout reader exited cleanly");
            }
            for (id, tx) in pending.drain() {
                let _ = tx.send(Err(crate::Error::Provider(format!(
                    "Gemini CLI process exited while request #{id} was pending"
                ))));
            }
        });

        let gemini_conn = GeminiConnection {
            stdin,
            pending_requests,
            next_id: AtomicU64::new(1),
        };

        // Initialize Gemini connection
        gemini_conn
            .call(
                "initialize",
                json!({
                    "protocolVersion": 1,
                    "clientInfo": {
                        "name": "feroxmute",
                        "version": env!("CARGO_PKG_VERSION")
                    }
                }),
            )
            .await?;

        Ok((child, Connection::Gemini(gemini_conn)))
    } else {
        // Build delegate (Rc-based, single-threaded)
        let delegate = AcpClientDelegate {
            event_tx: event_tx.clone(),
            collector: Rc::clone(collector),
        };

        let (conn, io_task) = acp::ClientSideConnection::new(
            delegate,
            stdin.compat_write(),
            stdout.compat(),
            |fut| {
                tokio::task::spawn_local(fut);
            },
        );

        // Spawn IO task on the LocalSet
        tokio::task::spawn_local(async move {
            if let Err(e) = io_task.await {
                tracing::error!("ACP IO task error: {e}");
            }
        });

        // Initialize the connection
        let init_response = conn
            .initialize(
                acp::InitializeRequest::new(acp::ProtocolVersion::V1).client_info(
                    acp::Implementation::new("feroxmute", env!("CARGO_PKG_VERSION")),
                ),
            )
            .await
            .map_err(|e| crate::Error::Provider(format!("ACP initialization failed: {e}")))?;

        tracing::info!(
            "Connected to {} (protocol version: {:?})",
            config.agent_type.provider_name(),
            init_response.protocol_version
        );

        Ok((child, Connection::Standard(conn)))
    }
}

// ---------------------------------------------------------------------------
// ACP Client delegate (lives inside bridge thread, !Send is fine)
// ---------------------------------------------------------------------------

struct AcpClientDelegate {
    event_tx: mpsc::UnboundedSender<AcpEvent>,
    collector: Rc<RefCell<ResponseCollector>>,
}

#[async_trait::async_trait(?Send)]
impl acp::Client for AcpClientDelegate {
    async fn request_permission(
        &self,
        args: acp::RequestPermissionRequest,
    ) -> acp::Result<acp::RequestPermissionResponse> {
        // Auto-approve all tool calls — feroxmute handles its own permissions
        // via the MCP tool layer. Pick the best option from the agent's list:
        // prefer AllowAlways > AllowOnce > first available.
        let option_id = args
            .options
            .iter()
            .find(|o| o.kind == acp::PermissionOptionKind::AllowAlways)
            .or_else(|| {
                args.options
                    .iter()
                    .find(|o| o.kind == acp::PermissionOptionKind::AllowOnce)
            })
            .or_else(|| args.options.first())
            .map(|o| o.option_id.0.to_string())
            .unwrap_or_else(|| "allow_always".to_string());

        tracing::debug!("ACP request_permission auto-approved with '{option_id}'");
        Ok(acp::RequestPermissionResponse::new(
            acp::RequestPermissionOutcome::Selected(acp::SelectedPermissionOutcome::new(option_id)),
        ))
    }

    async fn session_notification(
        &self,
        notification: acp::SessionNotification,
    ) -> acp::Result<()> {
        let session_id = notification.session_id.0.to_string();

        match notification.update {
            acp::SessionUpdate::AgentMessageChunk(chunk) => {
                if let acp::ContentBlock::Text(text_content) = chunk.content {
                    // Accumulate for response collection
                    self.collector
                        .borrow_mut()
                        .add_content(&session_id, text_content.text.clone());

                    // Forward event to main runtime
                    let _ = self.event_tx.send(AcpEvent::AgentMessage {
                        session_id,
                        text: text_content.text,
                    });
                }
            }
            acp::SessionUpdate::AgentThoughtChunk(chunk) => {
                if let acp::ContentBlock::Text(text_content) = chunk.content {
                    let _ = self.event_tx.send(AcpEvent::AgentThought {
                        session_id,
                        text: text_content.text,
                    });
                }
            }
            acp::SessionUpdate::ToolCall(tool_call) => {
                let _ = self.event_tx.send(AcpEvent::ToolCallStarted {
                    session_id,
                    title: tool_call.title,
                    tool_call_id: tool_call.tool_call_id.0.to_string(),
                });
            }
            acp::SessionUpdate::ToolCallUpdate(update) => {
                if let Some(acp::ToolCallStatus::Completed) = update.fields.status {
                    let _ = self.event_tx.send(AcpEvent::ToolCallCompleted {
                        session_id,
                        tool_call_id: update.tool_call_id.0.to_string(),
                    });
                }
            }
            _ => {
                tracing::trace!("ACP session notification: {:?}", notification.update);
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn test_bridge_binary_not_found() {
        let config = CliAgentConfig::new(CliAgentType::ClaudeCode)
            .with_binary_path("/nonexistent/path/claude-code-acp");
        let bridge = AcpBridge::new(config);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(bridge.connect(Path::new("/tmp")));
        assert!(result.is_err());
        if let Err(err) = result {
            assert!(
                err.to_string().contains("not found"),
                "error should mention 'not found': {err}"
            );
        }
    }
}
