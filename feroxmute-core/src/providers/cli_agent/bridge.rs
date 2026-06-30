//! Thread-safe bridge to the ACP client.
//!
//! The ACP SDK drives a connection through actors that run for the lifetime of
//! a single `connect_with` call, and the Gemini flavor uses `spawn_local`. Both
//! need a `current_thread` runtime + `LocalSet`, but `LlmProvider: Send + Sync`
//! needs `Send` futures. This bridge runs all ACP operations on a dedicated
//! `std::thread` with a `current_thread` tokio runtime + `LocalSet`, communicating
//! via channels.

use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use acp::schema::ProtocolVersion;
use acp::schema::v1::{
    CancelNotification, ContentBlock, EnvVariable, HttpHeader, Implementation, InitializeRequest,
    McpCapabilities, McpServer, McpServerHttp, McpServerStdio, NewSessionRequest,
    PermissionOptionKind, PromptRequest, RequestPermissionOutcome, RequestPermissionRequest,
    RequestPermissionResponse, SelectedPermissionOutcome, SessionId, SessionNotification,
    SessionUpdate, TextContent, ToolCallStatus,
};
use acp::{Agent, ByteStreams, Client, ConnectionTo};
use agent_client_protocol as acp;
use futures::io::AsyncWriteExt;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::{Mutex, Notify, mpsc, oneshot};
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};

use super::config::{CliAgentConfig, CliAgentType};
use crate::Result;

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
        reply: oneshot::Sender<Result<SessionId>>,
    },
    Prompt {
        session_id: SessionId,
        message: String,
        reply: oneshot::Sender<Result<String>>,
    },
    Cancel {
        session_id: SessionId,
    },
    Shutdown,
}

// ---------------------------------------------------------------------------
// Response collector
// ---------------------------------------------------------------------------

const ACP_PROMPT_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const ACP_SETUP_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_STDERR_LINES: usize = 20;

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

/// Shared collector used by both the Standard (SDK) and Gemini paths.
///
/// The Standard path's notification callback must be `Send`, so the collector
/// is wrapped in an `Arc<std::sync::Mutex<_>>` rather than `Rc<RefCell<_>>`.
type SharedCollector = Arc<std::sync::Mutex<ResponseCollector>>;

/// Lock the collector, recovering from poisoning rather than panicking.
fn lock_collector(
    collector: &std::sync::Mutex<ResponseCollector>,
) -> std::sync::MutexGuard<'_, ResponseCollector> {
    collector
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// A custom connection for Gemini CLI which uses a slightly different ACP flavor.
struct GeminiConnection {
    stdin: Arc<Mutex<tokio_util::compat::Compat<tokio::process::ChildStdin>>>,
    pending_requests: Arc<Mutex<HashMap<u64, oneshot::Sender<Result<Value>>>>>,
    next_id: AtomicU64,
    /// Signaled by the stdout reader whenever the agent shows activity (notifications,
    /// agent-initiated requests). Used to reset the idle timeout in `call()`.
    activity: Arc<Notify>,
}

#[derive(Default)]
struct CliDiagnostics {
    stderr_lines: VecDeque<String>,
    rpc_events: VecDeque<String>,
}

impl CliDiagnostics {
    fn push_stderr(&mut self, line: String) {
        if self.stderr_lines.len() >= MAX_STDERR_LINES {
            self.stderr_lines.pop_front();
        }
        self.stderr_lines.push_back(line);
    }

    fn push_rpc_event(&mut self, event: String) {
        if self.rpc_events.len() >= MAX_STDERR_LINES {
            self.rpc_events.pop_front();
        }
        self.rpc_events.push_back(event);
    }

    fn recent_summary(&self) -> String {
        let mut sections = Vec::new();
        if !self.stderr_lines.is_empty() {
            sections.push(format!(
                "Recent CLI stderr:\n{}",
                format_diagnostic_lines(&self.stderr_lines)
            ));
        }
        if !self.rpc_events.is_empty() {
            sections.push(format!(
                "Recent ACP RPC activity:\n{}",
                format_diagnostic_lines(&self.rpc_events)
            ));
        }

        if sections.is_empty() {
            String::new()
        } else {
            format!(" {}", sections.join("\n"))
        }
    }
}

fn format_diagnostic_lines(lines: &VecDeque<String>) -> String {
    lines
        .iter()
        .map(|line| format!("  {line}"))
        .collect::<Vec<_>>()
        .join("\n")
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

        if method == "session/prompt" {
            // For session/prompt, use an idle-based timeout that resets whenever the
            // agent shows activity (notifications, tool calls, messages). This prevents
            // premature timeouts when the agent is actively working but hasn't returned
            // the final response yet.
            self.call_with_idle_timeout(id, method, rx).await
        } else {
            // Other methods (initialize, new_session) should be quick.
            match tokio::time::timeout(Duration::from_secs(60), rx).await {
                Ok(Ok(result)) => {
                    tracing::debug!("Gemini call #{id}: {method} completed");
                    result
                }
                Ok(Err(_)) => Err(crate::Error::Provider(
                    "Gemini connection task dropped".into(),
                )),
                Err(_) => {
                    self.pending_requests.lock().await.remove(&id);
                    Err(crate::Error::Provider(format!(
                        "Gemini ACP call '{method}' (id={id}) timed out after 60s. \
                         Check Gemini CLI logs and stderr for errors.",
                    )))
                }
            }
        }
    }

    /// Wait for a `session/prompt` response with an idle timeout that resets on activity.
    ///
    /// The timeout fires only after 10 minutes of *inactivity* (no notifications from
    /// the agent). This allows long-running prompts that involve many tool calls to
    /// complete without hitting a wall-clock timeout.
    async fn call_with_idle_timeout(
        &self,
        id: u64,
        method: &str,
        rx: oneshot::Receiver<Result<Value>>,
    ) -> Result<Value> {
        let idle_duration = Duration::from_secs(600); // 10 min idle
        let deadline = tokio::time::Instant::now() + idle_duration;
        let sleep = tokio::time::sleep_until(deadline);
        tokio::pin!(sleep);
        tokio::pin!(rx);

        loop {
            tokio::select! {
                result = &mut rx => {
                    match result {
                        Ok(result) => {
                            tracing::debug!("Gemini call #{id}: {method} completed");
                            return result;
                        }
                        Err(_) => {
                            return Err(crate::Error::Provider(
                                "Gemini connection task dropped".into(),
                            ));
                        }
                    }
                }
                _ = &mut sleep => {
                    self.pending_requests.lock().await.remove(&id);
                    return Err(crate::Error::Provider(format!(
                        "Gemini ACP call '{method}' (id={id}) timed out after 10 minutes \
                         of inactivity. Check Gemini CLI logs and stderr for errors.",
                    )));
                }
                _ = self.activity.notified() => {
                    // Agent is still working — reset the idle deadline.
                    sleep.as_mut().reset(tokio::time::Instant::now() + idle_duration);
                }
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
    thread_handle: std::sync::Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl AcpBridge {
    /// Create a new bridge. Spawns the background thread immediately.
    pub fn new(config: CliAgentConfig) -> Self {
        let (cmd_tx, cmd_rx) = mpsc::channel::<AcpCommand>(32);

        let handle = std::thread::spawn(move || {
            let rt = build_bridge_runtime();
            let local = tokio::task::LocalSet::new();
            local.block_on(&rt, command_loop(cmd_rx, config));
        });

        Self {
            cmd_tx,
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
    ) -> Result<SessionId> {
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
    pub async fn prompt(&self, session_id: &SessionId, message: &str) -> Result<String> {
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
    pub async fn cancel(&self, session_id: &SessionId) {
        let _ = self
            .cmd_tx
            .send(AcpCommand::Cancel {
                session_id: session_id.clone(),
            })
            .await;
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

fn not_connected() -> crate::Error {
    crate::Error::Provider("ACP client not connected".to_string())
}

/// Main event loop that runs inside the bridge thread's `LocalSet`.
///
/// Waits for the initial `Connect`, then hands control to the per-flavor
/// command loop, which owns the connection for its lifetime. The Standard
/// (SDK) path drives the connection inside an `connect_with` closure; the
/// Gemini path uses a long-lived manual JSON-RPC connection.
async fn command_loop(mut cmd_rx: mpsc::Receiver<AcpCommand>, config: CliAgentConfig) {
    let collector: SharedCollector = Arc::new(std::sync::Mutex::new(ResponseCollector::default()));

    while let Some(cmd) = cmd_rx.recv().await {
        match cmd {
            AcpCommand::Connect { working_dir, reply } => {
                let child_io = match prepare_child(&config, &working_dir) {
                    Ok(io) => io,
                    Err(e) => {
                        let _ = reply.send(Err(e));
                        continue;
                    }
                };

                if config.agent_type == CliAgentType::GeminiCli {
                    match connect_gemini(child_io, &collector).await {
                        Ok((child, conn)) => {
                            let _ = reply.send(Ok(()));
                            gemini_command_loop(&mut cmd_rx, child, conn, &collector).await;
                            return;
                        }
                        Err(e) => {
                            let _ = reply.send(Err(e));
                            continue;
                        }
                    }
                } else {
                    standard_session(&mut cmd_rx, child_io, reply, &collector, &config).await;
                    return;
                }
            }
            AcpCommand::Shutdown => return,
            AcpCommand::NewSession { reply, .. } => {
                let _ = reply.send(Err(not_connected()));
            }
            AcpCommand::Prompt { reply, .. } => {
                let _ = reply.send(Err(not_connected()));
            }
            AcpCommand::Cancel { .. } => {}
        }
    }
}

/// Captured subprocess I/O handles for an established CLI agent process.
struct ChildIo {
    child: Child,
    stdin: ChildStdin,
    stdout: ChildStdout,
    diagnostics: Rc<RefCell<CliDiagnostics>>,
}

/// Spawn the CLI subprocess and capture its stdio.
///
/// For CLI agents that use ACP adapters (e.g. `cc-acp`), the binary
/// speaks ACP natively over stdin/stdout. MCP servers are provided later via
/// `NewSessionRequest.mcp_servers` rather than CLI flags.
fn prepare_child(config: &CliAgentConfig, working_dir: &Path) -> Result<ChildIo> {
    // Resolve the binary to an absolute path. `current_dir` below would
    // otherwise make a relative binary name resolve against `working_dir`
    // instead of `PATH`.
    let binary_path = which::which(&config.binary_path).map_err(|_| {
        crate::Error::Provider(format!(
            "{} CLI not found at '{}'. Install it or specify path with --cli-path. Auth hint: {}",
            config.agent_type.provider_name(),
            config.binary_path.display(),
            config.agent_type.auth_hint()
        ))
    })?;

    let mut cmd = Command::new(&binary_path);
    cmd.current_dir(working_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    match config.agent_type {
        CliAgentType::Codex => {
            cmd.arg("-c")
                .arg(format!("model={}", toml_string_literal(&config.model)));
        }
        CliAgentType::GeminiCli => {
            cmd.arg("--experimental-acp");
            cmd.arg("-m").arg(&config.model);
        }
        CliAgentType::ClaudeCode => {}
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

    let diagnostics = Rc::new(RefCell::new(CliDiagnostics::default()));
    let diagnostics_for_stderr = Rc::clone(&diagnostics);

    // Log stderr in a background task
    tokio::task::spawn_local(async move {
        let mut reader = tokio::io::BufReader::new(stderr).lines();
        while let Ok(Some(line)) = reader.next_line().await {
            diagnostics_for_stderr
                .borrow_mut()
                .push_stderr(line.clone());
            tracing::warn!("CLI STDERR: {}", line);
        }
    });

    Ok(ChildIo {
        child,
        stdin,
        stdout,
        diagnostics,
    })
}

// ---------------------------------------------------------------------------
// Standard ACP path (SDK-driven)
// ---------------------------------------------------------------------------

/// Establish a Standard ACP connection and run the command loop for its lifetime.
///
/// The SDK drives the connection through actors that live only while the
/// `connect_with` closure runs, so the per-session command loop runs *inside*
/// that closure. Permission and notification handling is registered as builder
/// callbacks, which must be `Send` — hence the `Arc`-based shared collector.
async fn standard_session(
    cmd_rx: &mut mpsc::Receiver<AcpCommand>,
    child_io: ChildIo,
    connect_reply: oneshot::Sender<Result<()>>,
    collector: &SharedCollector,
    config: &CliAgentConfig,
) {
    let ChildIo {
        mut child,
        stdin,
        stdout,
        diagnostics,
    } = child_io;

    let activity = Arc::new(Notify::new());
    let transport = ByteStreams::new(stdin.compat_write(), stdout.compat());

    let run = Client
        .builder()
        .on_receive_notification(
            {
                let collector = Arc::clone(collector);
                let activity = Arc::clone(&activity);
                move |notification: SessionNotification, _cx: ConnectionTo<Agent>| {
                    let collector = Arc::clone(&collector);
                    let activity = Arc::clone(&activity);
                    async move {
                        activity.notify_waiters();
                        handle_standard_notification(&collector, notification);
                        Ok(())
                    }
                }
            },
            acp::on_receive_notification!(),
        )
        .on_receive_request(
            {
                let activity = Arc::clone(&activity);
                move |request: RequestPermissionRequest,
                      responder: acp::Responder<RequestPermissionResponse>,
                      _cx: ConnectionTo<Agent>| {
                    let activity = Arc::clone(&activity);
                    async move {
                        activity.notify_waiters();
                        let option_id = pick_permission_option(&request);
                        tracing::debug!("ACP request_permission auto-approved with '{option_id}'");
                        responder.respond(RequestPermissionResponse::new(
                            RequestPermissionOutcome::Selected(SelectedPermissionOutcome::new(
                                option_id,
                            )),
                        ))
                    }
                }
            },
            acp::on_receive_request!(),
        )
        .connect_with(transport, |connection: ConnectionTo<Agent>| async move {
            run_standard_protocol(
                connection,
                cmd_rx,
                collector,
                &activity,
                &diagnostics,
                connect_reply,
                config,
            )
            .await;
            Ok(())
        })
        .await;

    if let Err(e) = run {
        tracing::error!("ACP connection ended with error: {e}");
    }
    let _ = child.kill().await;
}

/// Drive the Standard ACP protocol: initialize, then handle commands until shutdown.
///
/// Runs as the `connect_with` main function, concurrently with the connection's
/// background actors, so `block_task()` resolves normally here.
async fn run_standard_protocol(
    connection: ConnectionTo<Agent>,
    cmd_rx: &mut mpsc::Receiver<AcpCommand>,
    collector: &SharedCollector,
    activity: &Arc<Notify>,
    diagnostics: &Rc<RefCell<CliDiagnostics>>,
    connect_reply: oneshot::Sender<Result<()>>,
    config: &CliAgentConfig,
) {
    let provider_name = config.agent_type.provider_name();

    // Initialize the connection.
    let init = connection
        .send_request(
            InitializeRequest::new(ProtocolVersion::V1)
                .client_info(Implementation::new("feroxmute", env!("CARGO_PKG_VERSION"))),
        )
        .block_task()
        .await;

    let mcp_capabilities: McpCapabilities = match init {
        Ok(response) => {
            let caps = response.agent_capabilities.mcp_capabilities.clone();
            tracing::info!(
                "Connected to {} (protocol version: {:?}, mcp_http: {}, mcp_sse: {})",
                provider_name,
                response.protocol_version,
                caps.http,
                caps.sse
            );
            diagnostics
                .borrow_mut()
                .push_rpc_event("-> initialize ok".to_string());
            let _ = connect_reply.send(Ok(()));
            caps
        }
        Err(e) => {
            let _ = connect_reply.send(Err(crate::Error::Provider(format!(
                "ACP initialization failed: {e}"
            ))));
            return;
        }
    };

    while let Some(cmd) = cmd_rx.recv().await {
        match cmd {
            AcpCommand::Connect { reply, .. } => {
                let _ = reply.send(Ok(()));
            }
            AcpCommand::NewSession {
                agent_role,
                working_dir,
                mcp_server_url,
                bearer_token,
                reply,
            } => {
                tracing::debug!("Creating standard ACP session for role '{agent_role}'");
                let request = NewSessionRequest::new(&working_dir);
                let result = match attach_mcp_server(
                    request,
                    mcp_server_url,
                    bearer_token,
                    &mcp_capabilities,
                    provider_name,
                ) {
                    Ok(request) => {
                        standard_new_session(&connection, request, provider_name, diagnostics).await
                    }
                    Err(e) => Err(e),
                };
                let _ = reply.send(result);
            }
            AcpCommand::Prompt {
                session_id,
                message,
                reply,
            } => {
                let result = match standard_prompt(
                    &connection,
                    &session_id,
                    &message,
                    activity,
                    diagnostics,
                    &config.agent_type,
                )
                .await
                {
                    Ok(()) => Ok(lock_collector(collector).take_content(session_id.0.as_ref())),
                    Err(e) => Err(e),
                };
                let _ = reply.send(result);
            }
            AcpCommand::Cancel { session_id } => {
                let _ = connection.send_notification(CancelNotification::new(session_id));
            }
            AcpCommand::Shutdown => break,
        }
    }
}

fn attach_mcp_server(
    request: NewSessionRequest,
    mcp_server_url: Option<String>,
    bearer_token: Option<String>,
    mcp_capabilities: &McpCapabilities,
    provider_name: &str,
) -> Result<NewSessionRequest> {
    let Some(url) = mcp_server_url else {
        return Ok(request);
    };

    // Prefer HTTP when the agent advertises it; otherwise fall back to a stdio
    // MCP server (which every ACP agent MUST support). The stdio server is
    // feroxmute re-invoked in proxy mode, bridging stdio MCP to this same HTTP
    // server so tools keep executing in the main process.
    let mcp_server = if mcp_capabilities.http {
        tracing::debug!("Attaching HTTP MCP server at {}", url);
        let mut mcp_http = McpServerHttp::new("feroxmute", url);
        if let Some(token) = bearer_token {
            mcp_http = mcp_http.headers(vec![HttpHeader::new(
                "Authorization",
                format!("Bearer {token}"),
            )]);
        }
        McpServer::Http(mcp_http)
    } else {
        tracing::debug!(
            "{provider_name} does not advertise HTTP MCP support; attaching stdio MCP proxy to {}",
            url
        );
        let exe = std::env::current_exe().map_err(|e| {
            crate::Error::Provider(format!(
                "Cannot locate feroxmute executable to launch the stdio MCP proxy for \
                 {provider_name}: {e}"
            ))
        })?;
        let env = match bearer_token {
            Some(token) => vec![EnvVariable::new(
                crate::mcp::stdio_proxy::MCP_TOKEN_ENV,
                token,
            )],
            None => Vec::new(),
        };
        McpServer::Stdio(
            McpServerStdio::new("feroxmute", exe)
                .args(vec![
                    "--mcp-stdio-proxy".to_string(),
                    "--mcp-proxy-url".to_string(),
                    url,
                ])
                .env(env),
        )
    };

    Ok(request.mcp_servers(vec![mcp_server]))
}

async fn standard_new_session(
    connection: &ConnectionTo<Agent>,
    request: NewSessionRequest,
    provider_name: &str,
    diagnostics: &Rc<RefCell<CliDiagnostics>>,
) -> Result<SessionId> {
    match tokio::time::timeout(
        ACP_SETUP_TIMEOUT,
        connection.send_request(request).block_task(),
    )
    .await
    {
        Ok(Ok(response)) => Ok(response.session_id),
        Ok(Err(e)) => Err(crate::Error::Provider(format!(
            "Failed to create ACP session: {e}"
        ))),
        Err(_) => {
            let diagnostics = diagnostics.borrow().recent_summary();
            Err(crate::Error::Provider(format!(
                "{provider_name} ACP session/new timed out after {} seconds. \
                 The CLI connected, but did not create a session with feroxmute's MCP server. \
                 Check authentication, model availability, ACP MCP support, and adapter logs.{}",
                ACP_SETUP_TIMEOUT.as_secs(),
                diagnostics,
            )))
        }
    }
}

async fn standard_prompt(
    connection: &ConnectionTo<Agent>,
    session_id: &SessionId,
    message: &str,
    activity: &Arc<Notify>,
    diagnostics: &Rc<RefCell<CliDiagnostics>>,
    agent_type: &CliAgentType,
) -> Result<()> {
    let prompt_result = connection
        .send_request(PromptRequest::new(
            session_id.clone(),
            vec![ContentBlock::Text(TextContent::new(message))],
        ))
        .block_task();
    tokio::pin!(prompt_result);

    let idle_deadline = tokio::time::Instant::now() + ACP_PROMPT_IDLE_TIMEOUT;
    let idle_sleep = tokio::time::sleep_until(idle_deadline);
    tokio::pin!(idle_sleep);

    loop {
        tokio::select! {
            result = &mut prompt_result => {
                return result.map(|_| ()).map_err(|e| standard_prompt_error(&e, agent_type));
            }
            _ = &mut idle_sleep => {
                let _ = connection.send_notification(CancelNotification::new(session_id.clone()));
                let diagnostics = diagnostics.borrow().recent_summary();
                return Err(crate::Error::Provider(format!(
                    "{} ACP prompt timed out after {} seconds of inactivity. \
                     The CLI connected, but did not return a response or emit ACP activity. \
                     Check authentication, model availability, and the ACP adapter process logs.{}",
                    agent_type.provider_name(),
                    ACP_PROMPT_IDLE_TIMEOUT.as_secs(),
                    diagnostics,
                )));
            }
            _ = activity.notified() => {
                idle_sleep
                    .as_mut()
                    .reset(tokio::time::Instant::now() + ACP_PROMPT_IDLE_TIMEOUT);
            }
        }
    }
}

fn standard_prompt_error(e: &acp::Error, agent_type: &CliAgentType) -> crate::Error {
    if e.code == acp::ErrorCode::AuthRequired {
        crate::Error::Provider(format!(
            "{} requires authentication. Run: {}",
            agent_type.provider_name(),
            agent_type.auth_hint()
        ))
    } else {
        crate::Error::Provider(format!("ACP prompt failed: {e}"))
    }
}

/// Pick the best permission option from the agent's list.
///
/// feroxmute handles its own permissions via the MCP tool layer, so all tool
/// calls are auto-approved: prefer `AllowAlways`, then `AllowOnce`, then first.
fn pick_permission_option(request: &RequestPermissionRequest) -> String {
    request
        .options
        .iter()
        .find(|o| o.kind == PermissionOptionKind::AllowAlways)
        .or_else(|| {
            request
                .options
                .iter()
                .find(|o| o.kind == PermissionOptionKind::AllowOnce)
        })
        .or_else(|| request.options.first())
        .map(|o| o.option_id.0.to_string())
        .unwrap_or_else(|| "allow_always".to_string())
}

/// Handle a session notification from the Standard ACP connection.
fn handle_standard_notification(collector: &SharedCollector, notification: SessionNotification) {
    let session_id = notification.session_id.0.to_string();

    match notification.update {
        SessionUpdate::AgentMessageChunk(chunk) => {
            if let ContentBlock::Text(text_content) = chunk.content {
                lock_collector(collector).add_content(&session_id, text_content.text);
            }
        }
        SessionUpdate::AgentThoughtChunk(_) => {
            tracing::trace!("ACP thought chunk for session '{session_id}'");
        }
        SessionUpdate::ToolCall(tool_call) => {
            tracing::debug!(
                "ACP tool call for session '{}': {} ({})",
                session_id,
                tool_call.title,
                tool_call.tool_call_id.0
            );
        }
        SessionUpdate::ToolCallUpdate(update) => {
            if let Some(ToolCallStatus::Completed) = update.fields.status {
                tracing::debug!(
                    "ACP tool call completed for session '{}': {}",
                    session_id,
                    update.tool_call_id.0
                );
            }
        }
        _ => {
            tracing::trace!("ACP session notification: {:?}", notification.update);
        }
    }
}

// ---------------------------------------------------------------------------
// Gemini ACP path (manual JSON-RPC)
// ---------------------------------------------------------------------------

/// Establish a Gemini CLI connection over manual JSON-RPC and initialize it.
async fn connect_gemini(
    child_io: ChildIo,
    collector: &SharedCollector,
) -> Result<(Child, GeminiConnection)> {
    let ChildIo {
        child,
        stdin,
        stdout,
        diagnostics: _,
    } = child_io;

    let stdin = Arc::new(Mutex::new(stdin.compat_write()));
    let pending_requests: Arc<Mutex<HashMap<u64, oneshot::Sender<Result<Value>>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let pending_requests_clone = Arc::clone(&pending_requests);
    let collector_clone = Arc::clone(collector);
    let activity = Arc::new(Notify::new());
    let activity_clone = Arc::clone(&activity);

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
                            "Gemini ACP error: {error}"
                        ))));
                    } else {
                        let _ = tx.send(Ok(val.get("result").cloned().unwrap_or(Value::Null)));
                    }
                } else {
                    tracing::warn!("Gemini response for unknown id: {}", val);
                }
            } else if let Some(method) = val.get("method").and_then(|v| v.as_str()) {
                let has_id = val.get("id").is_some();

                // Signal activity so idle timeout resets.
                activity_clone.notify_waiters();

                if has_id {
                    // Agent-initiated request — needs a response sent back
                    tracing::debug!("Gemini agent request: {method} body={val}");
                    handle_gemini_request(method, &val, &stdin_clone).await;
                } else {
                    // Notification — no response needed
                    tracing::debug!("Gemini notification: {method}");
                    handle_gemini_notification(method, &val, &collector_clone);
                }
            } else {
                tracing::warn!("Gemini stdout unrecognized message: {}", val);
            }
        }
        // Resolve all pending requests with an error so call() doesn't hang
        let mut pending = pending_requests_clone.lock().await;
        let pending_count = pending.len();
        if pending_count > 0 {
            tracing::warn!("Gemini stdout reader exited with {pending_count} pending request(s)");
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
        activity,
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

    Ok((child, gemini_conn))
}

/// Per-session command loop for the Gemini CLI connection.
async fn gemini_command_loop(
    cmd_rx: &mut mpsc::Receiver<AcpCommand>,
    mut child: Child,
    conn: GeminiConnection,
    collector: &SharedCollector,
) {
    while let Some(cmd) = cmd_rx.recv().await {
        match cmd {
            AcpCommand::Connect { reply, .. } => {
                let _ = reply.send(Ok(()));
            }
            AcpCommand::NewSession {
                agent_role,
                working_dir,
                mcp_server_url,
                bearer_token,
                reply,
            } => {
                tracing::debug!("Creating Gemini ACP session for role '{agent_role}'");
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

                let result = match result {
                    Ok(res) => {
                        tracing::debug!("Gemini session/new returned: {res}");
                        if let Some(sid) = res.get("sessionId").and_then(|v| v.as_str()) {
                            Ok(SessionId::new(sid))
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
                };
                let _ = reply.send(result);
            }
            AcpCommand::Prompt {
                session_id,
                message,
                reply,
            } => {
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

                let result = match result {
                    Ok(_) => {
                        tracing::debug!(
                            "Gemini session/prompt completed for session '{}'",
                            session_id.0
                        );
                        Ok(lock_collector(collector).take_content(session_id.0.as_ref()))
                    }
                    Err(e) => {
                        tracing::debug!(
                            "Gemini session/prompt failed for session '{}': {e}",
                            session_id.0
                        );
                        Err(e)
                    }
                };
                let _ = reply.send(result);
            }
            AcpCommand::Cancel { session_id } => {
                let _ = conn
                    .call("session/cancel", json!({ "sessionId": session_id.0 }))
                    .await;
            }
            AcpCommand::Shutdown => {
                let _ = child.kill().await;
                return;
            }
        }
    }
    let _ = child.kill().await;
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
            // via the MCP tool layer. Mirrors the Standard path's behavior.
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
fn handle_gemini_notification(method: &str, val: &Value, collector: &SharedCollector) {
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
                lock_collector(collector).add_content(session_id, text_str.to_string());
            }
        }
        "agent_thought_chunk" => {
            tracing::trace!("Gemini thought chunk for session '{session_id}'");
        }
        "tool_call" => {
            tracing::debug!("Gemini tool call for session '{session_id}': {update}");
        }
        "tool_call_update" => {
            tracing::debug!("Gemini tool call update for session '{session_id}': {update}");
        }
        _ => {
            // Try nested object format (fallback)
            if let Some(msg) = update.get("agentMessageChunk") {
                if let Some(text_str) = extract_content_text(msg) {
                    lock_collector(collector).add_content(session_id, text_str.to_string());
                }
            } else if let Some(thought) = update.get("agentThoughtChunk") {
                tracing::trace!("Gemini thought chunk for session '{session_id}': {thought}");
            } else if update.get("toolCall").is_some() {
                tracing::debug!("Gemini tool call for session '{session_id}': {update}");
            } else if update.get("toolCallUpdate").is_some() {
                tracing::debug!("Gemini tool call update for session '{session_id}': {update}");
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

// ---------------------------------------------------------------------------
// Codex model TOML quoting
// ---------------------------------------------------------------------------

fn toml_string_literal(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len() + 2);
    escaped.push('"');
    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\u{0008}' => escaped.push_str("\\b"),
            '\t' => escaped.push_str("\\t"),
            '\n' => escaped.push_str("\\n"),
            '\u{000C}' => escaped.push_str("\\f"),
            '\r' => escaped.push_str("\\r"),
            c if c.is_control() => push_toml_unicode_escape(&mut escaped, c),
            _ => escaped.push(ch),
        }
    }
    escaped.push('"');
    escaped
}

fn push_toml_unicode_escape(output: &mut String, ch: char) {
    output.push_str("\\u");
    let code = ch as u32;
    for shift in [12, 8, 4, 0] {
        let nibble = ((code >> shift) & 0xF) as u8;
        output.push(match nibble {
            0 => '0',
            1 => '1',
            2 => '2',
            3 => '3',
            4 => '4',
            5 => '5',
            6 => '6',
            7 => '7',
            8 => '8',
            9 => '9',
            10 => 'A',
            11 => 'B',
            12 => 'C',
            13 => 'D',
            14 => 'E',
            15 => 'F',
            _ => '0',
        });
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
    fn test_response_collector_add_and_take() {
        let mut collector = ResponseCollector::default();
        collector.add_content("s1", "hello ".to_string());
        collector.add_content("s1", "world".to_string());
        assert_eq!(collector.take_content("s1"), "hello world");
        // Second take returns empty (content was consumed)
        assert_eq!(collector.take_content("s1"), "");
    }

    #[test]
    fn test_response_collector_multiple_sessions() {
        let mut collector = ResponseCollector::default();
        collector.add_content("s1", "alpha".to_string());
        collector.add_content("s2", "beta".to_string());
        assert_eq!(collector.take_content("s1"), "alpha");
        assert_eq!(collector.take_content("s2"), "beta");
    }

    #[test]
    fn test_response_collector_take_nonexistent() {
        let mut collector = ResponseCollector::default();
        assert_eq!(collector.take_content("nope"), "");
    }

    #[test]
    fn test_extract_content_text_valid() {
        let obj = serde_json::json!({"content": {"text": "hi"}});
        assert_eq!(extract_content_text(&obj), Some("hi"));
    }

    #[test]
    fn test_extract_content_text_missing_content() {
        let obj = serde_json::json!({"other": "x"});
        assert_eq!(extract_content_text(&obj), None);
    }

    #[test]
    fn test_extract_content_text_missing_text() {
        let obj = serde_json::json!({"content": {"image": "x"}});
        assert_eq!(extract_content_text(&obj), None);
    }

    #[test]
    fn test_toml_string_literal_escapes_codex_model() {
        assert_eq!(toml_string_literal("gpt-5.2"), "\"gpt-5.2\"");
        assert_eq!(
            toml_string_literal("model \"x\"\\next"),
            "\"model \\\"x\\\"\\\\next\""
        );
        assert_eq!(
            toml_string_literal("a\u{0008}\t\n\u{000C}\r\u{0000}\u{007F}z"),
            "\"a\\b\\t\\n\\f\\r\\u0000\\u007Fz\""
        );
    }

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
