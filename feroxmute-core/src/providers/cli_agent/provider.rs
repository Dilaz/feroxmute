//! CLI Agent Provider implementation
//!
//! Wraps CLI-based coding agents (Claude Code, Codex, Gemini CLI) as LLM providers
//! using the ACP bridge for thread-safe communication and an HTTP MCP server for
//! tool access.

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use tokio::sync::{Mutex, OnceCell};

use crate::Result;
use crate::docker::ContainerManager;
use crate::limitations::EngagementLimitations;
use crate::mcp::McpServer;
use crate::mcp::http::HttpMcpServer;
use crate::mcp::tools::{
    FindingContext, McpAddRecommendationTool, McpCompleteEngagementTool, McpDockerShellTool,
    McpExportHtmlTool, McpExportJsonTool, McpExportMarkdownTool, McpExportPdfTool,
    McpGenerateReportTool, McpListAgentsTool, McpMemoryAddTool, McpMemoryGetTool,
    McpMemoryListTool, McpRecordFindingTool, McpRunScriptTool, McpSpawnAgentTool,
    McpWaitForAgentTool, McpWaitForAnyTool,
};
use crate::providers::traits::{CompletionRequest, CompletionResponse, LlmProvider};
use crate::state::MetricsTracker;
use crate::tools::{EventSender, MemoryContext, OrchestratorContext, ReportContext};

use super::bridge::AcpBridge;
use super::config::CliAgentConfig;

/// CLI Agent Provider that wraps CLI-based coding agents.
///
/// Uses the [`AcpBridge`] for thread-safe ACP communication and an
/// [`HttpMcpServer`] on localhost to expose feroxmute tools via MCP.
pub struct CliAgentProvider {
    config: CliAgentConfig,
    bridge: Arc<AcpBridge>,
    mcp_server: Arc<McpServer>,
    http_server: OnceCell<HttpMcpServer>,
    metrics: MetricsTracker,
    working_dir: PathBuf,
    /// Tracks whether we have already connected the bridge.
    connected: Mutex<bool>,
}

impl CliAgentProvider {
    /// Create a new CLI agent provider.
    ///
    /// Spawns the ACP bridge thread immediately but does **not** connect to the
    /// CLI agent until the first `complete_*` call.
    ///
    /// # Errors
    ///
    /// Returns error if the CLI binary is not found on `$PATH`.
    pub fn new(config: CliAgentConfig, working_dir: PathBuf, metrics: MetricsTracker) -> Self {
        let bridge = Arc::new(AcpBridge::new(config.clone()));
        let mcp_server = Arc::new(McpServer::new("feroxmute", env!("CARGO_PKG_VERSION")));

        Self {
            config,
            bridge,
            mcp_server,
            http_server: OnceCell::new(),
            metrics,
            working_dir,
            connected: Mutex::new(false),
        }
    }

    /// Ensure the HTTP MCP server is running, returning `(url, bearer_token)`.
    async fn ensure_http_server(&self) -> Result<(String, String)> {
        let http = self
            .http_server
            .get_or_try_init(|| async { HttpMcpServer::start(Arc::clone(&self.mcp_server)).await })
            .await?;
        Ok((http.url(), http.token().to_string()))
    }

    /// Connect the bridge if not already connected.
    ///
    /// MCP servers are passed per-session via `NewSessionRequest.mcp_servers`
    /// rather than via CLI args, so connection is independent of MCP config.
    async fn ensure_connected(&self) -> Result<()> {
        let mut connected = self.connected.lock().await;
        if !*connected {
            self.bridge.connect(&self.working_dir).await?;
            *connected = true;
        }
        Ok(())
    }

    /// Register shell tools (docker_shell, memory, finding, script) on the MCP server.
    async fn register_shell_tools(
        &self,
        container: Arc<ContainerManager>,
        events: Arc<dyn EventSender>,
        agent_name: &str,
        limitations: Arc<EngagementLimitations>,
        memory: Arc<MemoryContext>,
    ) {
        self.mcp_server
            .register_tool(Arc::new(McpDockerShellTool::new(
                Arc::clone(&container),
                Arc::clone(&events),
                agent_name.to_string(),
                Arc::clone(&limitations),
            )))
            .await;

        self.mcp_server
            .register_tool(Arc::new(McpMemoryAddTool::new(Arc::clone(&memory))))
            .await;
        self.mcp_server
            .register_tool(Arc::new(McpMemoryGetTool::new(Arc::clone(&memory))))
            .await;
        self.mcp_server
            .register_tool(Arc::new(McpMemoryListTool::new(Arc::clone(&memory))))
            .await;

        let finding_context = Arc::new(FindingContext {
            conn: Arc::clone(&memory.conn),
            events: Arc::clone(&events),
            agent_name: agent_name.to_string(),
        });
        self.mcp_server
            .register_tool(Arc::new(McpRecordFindingTool::new(finding_context)))
            .await;

        self.mcp_server
            .register_tool(Arc::new(McpRunScriptTool::new(
                container,
                events,
                agent_name.to_string(),
            )))
            .await;
    }

    /// Register orchestrator tools on the MCP server.
    async fn register_orchestrator_tools(&self, context: Arc<OrchestratorContext>) {
        self.mcp_server
            .register_tool(Arc::new(McpSpawnAgentTool::new(Arc::clone(&context))))
            .await;
        self.mcp_server
            .register_tool(Arc::new(McpWaitForAgentTool::new(Arc::clone(&context))))
            .await;
        self.mcp_server
            .register_tool(Arc::new(McpWaitForAnyTool::new(Arc::clone(&context))))
            .await;
        self.mcp_server
            .register_tool(Arc::new(McpListAgentsTool::new(Arc::clone(&context))))
            .await;
        self.mcp_server
            .register_tool(Arc::new(McpCompleteEngagementTool::new(context)))
            .await;
    }

    /// Register report tools on the MCP server.
    async fn register_report_tools(&self, context: Arc<ReportContext>) {
        self.mcp_server
            .register_tool(Arc::new(McpGenerateReportTool::new(Arc::clone(&context))))
            .await;
        self.mcp_server
            .register_tool(Arc::new(McpExportJsonTool::new(Arc::clone(&context))))
            .await;
        self.mcp_server
            .register_tool(Arc::new(McpExportMarkdownTool::new(Arc::clone(&context))))
            .await;
        self.mcp_server
            .register_tool(Arc::new(McpExportHtmlTool::new(Arc::clone(&context))))
            .await;
        self.mcp_server
            .register_tool(Arc::new(McpExportPdfTool::new(Arc::clone(&context))))
            .await;
        self.mcp_server
            .register_tool(Arc::new(McpAddRecommendationTool::new(context)))
            .await;
    }
}

#[async_trait]
impl LlmProvider for CliAgentProvider {
    fn name(&self) -> &str {
        self.config.agent_type.provider_name()
    }

    fn supports_tools(&self) -> bool {
        true
    }

    fn metrics(&self) -> &MetricsTracker {
        &self.metrics
    }

    async fn complete(&self, request: CompletionRequest) -> Result<CompletionResponse> {
        // Connect and create session (no MCP tools needed for basic completion)
        self.ensure_connected().await?;

        let session_id = self
            .bridge
            .new_session("completion", &self.working_dir, None, None)
            .await?;

        let combined: String = request
            .messages
            .iter()
            .map(|m| format!("{:?}: {}", m.role, m.content))
            .collect::<Vec<_>>()
            .join("\n\n");

        let response = self.bridge.prompt(&session_id, &combined).await?;

        Ok(CompletionResponse {
            content: Some(response),
            tool_calls: vec![],
            stop_reason: crate::providers::traits::StopReason::EndTurn,
            usage: crate::providers::traits::TokenUsage::default(),
        })
    }

    async fn complete_with_shell(
        &self,
        system_prompt: &str,
        user_prompt: &str,
        container: Arc<ContainerManager>,
        events: Arc<dyn EventSender>,
        agent_name: &str,
        limitations: Arc<EngagementLimitations>,
        memory: Arc<MemoryContext>,
    ) -> Result<String> {
        // 1. Start HTTP MCP server
        let (http_url, token) = self.ensure_http_server().await?;

        // 2. Register shell tools
        self.register_shell_tools(
            container,
            Arc::clone(&events),
            agent_name,
            limitations,
            memory,
        )
        .await;

        // 3. Connect bridge
        self.ensure_connected().await?;

        events.send_feed(
            agent_name,
            &format!(
                "CLI agent '{}' connected with MCP tools at {}",
                self.name(),
                http_url
            ),
            false,
        );

        // 4. Create session with MCP server and prompt
        // ACP sends a single user message, so combine system instructions with the task.
        let session_id = self
            .bridge
            .new_session(agent_name, &self.working_dir, Some(http_url), Some(token))
            .await?;

        let combined_prompt = format!("{system_prompt}\n\n{user_prompt}");
        let response = self.bridge.prompt(&session_id, &combined_prompt).await?;

        Ok(response)
    }

    async fn complete_with_orchestrator(
        &self,
        system_prompt: &str,
        user_prompt: &str,
        context: Arc<OrchestratorContext>,
    ) -> Result<String> {
        // 1. Start HTTP MCP server
        let (http_url, token) = self.ensure_http_server().await?;

        // 2. Register all tools: shell + orchestrator + report
        // For the orchestrator, register shell+memory for the orchestrator's own use,
        // plus orchestrator tools for managing specialist agents.
        let memory = Arc::clone(&context.memory);
        self.register_shell_tools(
            Arc::clone(&context.container),
            Arc::clone(&context.events),
            "orchestrator",
            Arc::clone(&context.limitations),
            memory,
        )
        .await;
        self.register_orchestrator_tools(Arc::clone(&context)).await;

        // Also register report tools so the orchestrator can delegate report generation
        let report_context = Arc::new(ReportContext {
            events: Arc::clone(&context.events),
            target: context.target.clone(),
            session_id: context.session_id.clone(),
            start_time: Utc::now(),
            metrics: MetricsTracker::new(),
            findings: Arc::clone(&context.findings),
            report: Arc::new(Mutex::new(None)),
            reports_dir: context.reports_dir.clone(),
            session_db_path: None,
        });
        self.register_report_tools(report_context).await;

        // 3. Connect bridge
        self.ensure_connected().await?;

        context.events.send_feed(
            "orchestrator",
            &format!(
                "CLI agent '{}' connected for orchestration at {}",
                self.name(),
                http_url
            ),
            false,
        );

        // 4. Create session with MCP server and 30-minute timeout for orchestration
        // ACP sends a single user message, so combine system instructions with the task.
        // The user_prompt contains the actual target URL, engagement limitations, and workflow.
        let session_id = self
            .bridge
            .new_session(
                "orchestrator",
                &self.working_dir,
                Some(http_url),
                Some(token),
            )
            .await?;

        let combined_prompt = format!("{system_prompt}\n\n{user_prompt}");
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(1800),
            self.bridge.prompt(&session_id, &combined_prompt),
        )
        .await
        .map_err(|_| {
            crate::Error::Provider("Orchestrator session timed out after 30 minutes".into())
        })??;

        Ok(response)
    }

    async fn complete_with_report(
        &self,
        system_prompt: &str,
        user_prompt: &str,
        context: Arc<ReportContext>,
    ) -> Result<String> {
        // 1. Start HTTP MCP server
        let (http_url, token) = self.ensure_http_server().await?;

        // 2. Register report + memory tools
        self.register_report_tools(Arc::clone(&context)).await;

        // 3. Connect bridge
        self.ensure_connected().await?;

        context.events.send_feed(
            "report",
            &format!(
                "CLI agent '{}' connected for report generation at {}",
                self.name(),
                http_url
            ),
            false,
        );

        // 4. Create session with MCP server and prompt
        // ACP sends a single user message, so combine system instructions with the task.
        let session_id = self
            .bridge
            .new_session("report", &self.working_dir, Some(http_url), Some(token))
            .await?;

        let combined_prompt = format!("{system_prompt}\n\n{user_prompt}");
        let response = self.bridge.prompt(&session_id, &combined_prompt).await?;

        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::super::CliAgentType;
    use super::*;

    #[test]
    fn test_provider_name() {
        let config = CliAgentConfig::new(CliAgentType::ClaudeCode);
        assert_eq!(config.agent_type.provider_name(), "claude-code");

        let config = CliAgentConfig::new(CliAgentType::Codex);
        assert_eq!(config.agent_type.provider_name(), "codex");

        let config = CliAgentConfig::new(CliAgentType::GeminiCli);
        assert_eq!(config.agent_type.provider_name(), "gemini-cli");
    }

    #[test]
    fn test_provider_creation() {
        let config = CliAgentConfig::new(CliAgentType::ClaudeCode);
        let provider =
            CliAgentProvider::new(config, PathBuf::from("/tmp/test"), MetricsTracker::new());
        assert_eq!(provider.name(), "claude-code");
        assert!(provider.supports_tools());
    }
}
