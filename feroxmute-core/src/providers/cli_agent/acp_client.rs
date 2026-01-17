//! ACP (Agent Client Protocol) client for communicating with CLI agents

use std::collections::HashMap;
use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;

use acp::Agent; // Required trait for initialize, prompt, new_session, cancel methods
use agent_client_protocol as acp;
use tokio::process::{Child, Command};
use tokio::sync::{Mutex, RwLock};
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};

use crate::Result;
use crate::providers::cli_agent::{CliAgentConfig, CliAgentType};

/// Represents an ACP session with a CLI agent
#[derive(Debug, Clone)]
pub struct AcpSession {
    pub session_id: acp::SessionId,
    pub agent_role: String,
}

/// Shared state for collecting agent responses
#[derive(Default)]
struct ResponseCollector {
    /// Text chunks received for each session
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

/// ACP client that manages connection to a CLI agent subprocess
pub struct AcpClient {
    config: CliAgentConfig,
    child: Option<Child>,
    connection: Option<Arc<acp::ClientSideConnection>>,
    sessions: RwLock<HashMap<String, AcpSession>>,
    response_collector: Arc<Mutex<ResponseCollector>>,
}

impl AcpClient {
    /// Create a new ACP client (not yet connected)
    pub fn new(config: CliAgentConfig) -> Self {
        Self {
            config,
            child: None,
            connection: None,
            sessions: RwLock::new(HashMap::new()),
            response_collector: Arc::new(Mutex::new(ResponseCollector::default())),
        }
    }

    /// Check if the CLI binary is available
    pub fn check_binary(&self) -> Result<()> {
        let binary = &self.config.binary_path;
        if which::which(binary).is_err() {
            return Err(crate::Error::Provider(format!(
                "{} CLI not found at '{}'. Install it or specify path with --cli-path. Auth hint: {}",
                self.config.agent_type.provider_name(),
                binary.display(),
                self.config.agent_type.auth_hint()
            )));
        }
        Ok(())
    }

    /// Spawn the CLI agent subprocess and establish ACP connection
    pub async fn connect(&mut self, working_dir: &Path, mcp_config_path: &Path) -> Result<()> {
        self.check_binary()?;

        let mut cmd = Command::new(&self.config.binary_path);
        cmd.current_dir(working_dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        // Add MCP config argument based on agent type
        match self.config.agent_type {
            CliAgentType::ClaudeCode => {
                cmd.arg("--mcp-config").arg(mcp_config_path);
            }
            CliAgentType::Codex => {
                cmd.arg("--mcp-config").arg(mcp_config_path);
            }
            CliAgentType::GeminiCli => {
                cmd.env("GEMINI_MCP_CONFIG", mcp_config_path);
            }
        }

        let mut child = cmd.spawn().map_err(|e| {
            crate::Error::Provider(format!(
                "Failed to spawn {} CLI: {}",
                self.config.agent_type.provider_name(),
                e
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

        // Create client delegate with shared response collector
        let delegate = AcpClientDelegate {
            response_collector: Arc::clone(&self.response_collector),
        };

        // Create ACP connection
        let (connection, io_task) = acp::ClientSideConnection::new(
            delegate,
            stdin.compat_write(),
            stdout.compat(),
            |fut| {
                tokio::task::spawn_local(fut);
            },
        );

        // Spawn IO task
        tokio::task::spawn_local(async move {
            if let Err(e) = io_task.await {
                tracing::error!("ACP IO task error: {}", e);
            }
        });

        // Initialize connection
        let init_response = connection
            .initialize(
                acp::InitializeRequest::new(acp::ProtocolVersion::V1).client_info(
                    acp::Implementation::new("feroxmute", env!("CARGO_PKG_VERSION")),
                ),
            )
            .await
            .map_err(|e| crate::Error::Provider(format!("ACP initialization failed: {}", e)))?;

        tracing::info!(
            "Connected to {} (protocol version: {:?})",
            self.config.agent_type.provider_name(),
            init_response.protocol_version
        );

        self.child = Some(child);
        self.connection = Some(Arc::new(connection));

        Ok(())
    }

    /// Create a new ACP session for an agent role
    pub async fn new_session(
        &self,
        agent_role: &str,
        working_dir: &Path,
    ) -> Result<acp::SessionId> {
        let connection = self
            .connection
            .as_ref()
            .ok_or_else(|| crate::Error::Provider("ACP client not connected".to_string()))?;

        let response = connection
            .new_session(acp::NewSessionRequest::new(working_dir.to_path_buf()))
            .await
            .map_err(|e| crate::Error::Provider(format!("Failed to create ACP session: {}", e)))?;

        let session = AcpSession {
            session_id: response.session_id.clone(),
            agent_role: agent_role.to_string(),
        };

        self.sessions
            .write()
            .await
            .insert(agent_role.to_string(), session);

        Ok(response.session_id)
    }

    /// Send a prompt to a session and get the response
    pub async fn prompt(&self, session_id: &acp::SessionId, message: &str) -> Result<String> {
        let connection = self
            .connection
            .as_ref()
            .ok_or_else(|| crate::Error::Provider("ACP client not connected".to_string()))?;

        // Send the prompt - response content comes via session_notification
        let _response = connection
            .prompt(acp::PromptRequest::new(
                session_id.clone(),
                vec![acp::ContentBlock::Text(acp::TextContent::new(message))],
            ))
            .await
            .map_err(|e| {
                if e.code == acp::ErrorCode::AuthRequired {
                    crate::Error::Provider(format!(
                        "{} requires authentication. Run: {}",
                        self.config.agent_type.provider_name(),
                        self.config.agent_type.auth_hint()
                    ))
                } else {
                    crate::Error::Provider(format!("ACP prompt failed: {}", e))
                }
            })?;

        // Collect the response content that was accumulated via session_notification
        let text = self
            .response_collector
            .lock()
            .await
            .take_content(session_id.0.as_ref());

        Ok(text)
    }

    /// Cancel an active session
    pub async fn cancel(&self, session_id: &acp::SessionId) {
        if let Some(connection) = &self.connection {
            let _ = connection
                .cancel(acp::CancelNotification::new(session_id.clone()))
                .await;
        }
    }

    /// Get session by agent role
    pub async fn get_session(&self, agent_role: &str) -> Option<AcpSession> {
        self.sessions.read().await.get(agent_role).cloned()
    }

    /// Shutdown the connection and kill the subprocess
    pub async fn shutdown(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill().await;
        }
        self.connection = None;
        self.sessions.write().await.clear();
    }
}

impl Drop for AcpClient {
    fn drop(&mut self) {
        if let Some(ref mut child) = self.child {
            let _ = child.start_kill();
        }
    }
}

/// Delegate for handling ACP client callbacks
struct AcpClientDelegate {
    response_collector: Arc<Mutex<ResponseCollector>>,
}

#[async_trait::async_trait(?Send)]
impl acp::Client for AcpClientDelegate {
    async fn request_permission(
        &self,
        _args: acp::RequestPermissionRequest,
    ) -> acp::Result<acp::RequestPermissionResponse> {
        // Auto-approve tool calls (feroxmute handles its own permissions)
        Ok(acp::RequestPermissionResponse::new(
            acp::RequestPermissionOutcome::Selected(acp::SelectedPermissionOutcome::new(
                "allow_once",
            )),
        ))
    }

    async fn session_notification(
        &self,
        notification: acp::SessionNotification,
    ) -> acp::Result<()> {
        // Handle session updates - extract text content from agent messages
        let session_id = notification.session_id.0.to_string();

        match notification.update {
            acp::SessionUpdate::AgentMessageChunk(chunk) => {
                if let acp::ContentBlock::Text(text) = chunk.content {
                    self.response_collector
                        .lock()
                        .await
                        .add_content(&session_id, text.text);
                }
            }
            acp::SessionUpdate::ToolCall(tool_call) => {
                tracing::debug!("ACP tool call: {:?}", tool_call.tool_call_id);
            }
            acp::SessionUpdate::ToolCallUpdate(update) => {
                tracing::debug!("ACP tool call update: {:?}", update.tool_call_id);
            }
            _ => {
                tracing::trace!("ACP session notification: {:?}", notification.update);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_binary_not_found() {
        let config = CliAgentConfig::new(CliAgentType::ClaudeCode)
            .with_binary_path("/nonexistent/path/claude");
        let client = AcpClient::new(config);
        let result = client.check_binary();
        assert!(result.is_err());
        if let Err(err) = result {
            assert!(
                err.to_string().contains("not found"),
                "error should mention 'not found': {err}"
            );
        }
    }

    #[tokio::test]
    async fn test_prompt_without_connection() {
        let config = CliAgentConfig::new(CliAgentType::ClaudeCode);
        let client = AcpClient::new(config);
        let result = client.prompt(&acp::SessionId::new("test"), "hello").await;
        assert!(result.is_err());
        if let Err(err) = result {
            assert!(
                err.to_string().contains("not connected"),
                "error should mention 'not connected': {err}"
            );
        }
    }
}
