//! CLI Agent Provider implementation
//!
//! Wraps CLI-based coding agents (Claude Code, Codex, Gemini CLI) as LLM providers
//! using the ACP bridge for thread-safe communication and an HTTP MCP server for
//! tool access.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use agent_client_protocol as acp;
use async_trait::async_trait;
use chrono::Utc;
use tokio::sync::Mutex;
use tracing::Level;

use crate::Result;
use crate::docker::ContainerManager;
use crate::limitations::EngagementLimitations;
use crate::mcp::McpServer;
use crate::mcp::http::HttpMcpServer;
use crate::mcp::tools::{
    FindingContext, McpAddRecommendationTool, McpCompleteEngagementTool,
    McpDeduplicateFindingsTool, McpDockerShellTool, McpExportHtmlTool, McpExportJsonTool,
    McpExportMarkdownTool, McpExportPdfTool, McpGenerateReportTool, McpGetPlaybookTool,
    McpListAgentsTool, McpMemoryAddTool, McpMemoryGetTool, McpMemoryListTool, McpRecordFindingTool,
    McpRunScriptTool, McpSpawnAgentTool, McpWaitForAgentTool, McpWaitForAnyTool,
};
use crate::providers::traits::{CompletionRequest, CompletionResponse, LlmProvider};
use crate::state::MetricsTracker;
use crate::tools::{EventSender, MemoryContext, OrchestratorContext, ReportContext};

use super::bridge::AcpBridge;
use super::config::CliAgentConfig;

const CLI_PROMPT_PROGRESS_INTERVAL: Duration = Duration::from_secs(15);

fn debug_feed_enabled() -> bool {
    tracing::enabled!(Level::DEBUG)
}

fn send_debug_feed(events: &dyn EventSender, agent_name: &str, message: &str) {
    if debug_feed_enabled() {
        events.send_feed(agent_name, message, false);
    }
}

fn send_debug_feed_with_output(
    events: &dyn EventSender,
    agent_name: &str,
    message: &str,
    output: &str,
) {
    if debug_feed_enabled() {
        events.send_feed_with_output(agent_name, message, false, output);
    }
}

fn with_http_mcp_diagnostics(error: crate::Error, http: &HttpMcpServer) -> crate::Error {
    let activity = http.recent_activity_summary();
    if activity.is_empty() {
        error
    } else {
        let message = match error {
            crate::Error::Provider(message) => message,
            other => other.to_string(),
        };
        crate::Error::Provider(format!(
            "{message}\n\nRecent MCP HTTP activity:\n{activity}"
        ))
    }
}

async fn prompt_with_progress(
    bridge: &AcpBridge,
    session_id: &acp::SessionId,
    prompt: &str,
    events: &dyn EventSender,
    agent_name: &str,
    http: &HttpMcpServer,
) -> Result<String> {
    if !debug_feed_enabled() {
        return bridge
            .prompt(session_id, prompt)
            .await
            .map_err(|e| with_http_mcp_diagnostics(e, http));
    }

    send_debug_feed(events, agent_name, "Waiting for CLI agent prompt response");

    let prompt_future = bridge.prompt(session_id, prompt);
    tokio::pin!(prompt_future);

    let progress_sleep = tokio::time::sleep(CLI_PROMPT_PROGRESS_INTERVAL);
    tokio::pin!(progress_sleep);
    let mut last_activity = String::new();

    loop {
        tokio::select! {
            result = &mut prompt_future => {
                return result.map_err(|e| {
                    let error = with_http_mcp_diagnostics(e, http);
                    if debug_feed_enabled() {
                        let error_text = error.to_string();
                        let headline = error_text.lines().next().unwrap_or(&error_text);
                        events.send_feed_with_output(
                            agent_name,
                            &format!("CLI agent prompt failed: {headline}"),
                            true,
                            &http.recent_activity_summary(),
                        );
                    }
                    error
                });
            }
            _ = &mut progress_sleep => {
                let activity = http.recent_activity_summary();
                let latest = http
                    .latest_activity()
                    .unwrap_or_else(|| "no MCP HTTP activity seen yet".to_string());
                if activity.is_empty() {
                    send_debug_feed(
                        events,
                        agent_name,
                        "Still waiting for CLI agent response; no MCP HTTP activity seen yet",
                    );
                } else if activity != last_activity {
                    send_debug_feed_with_output(
                        events,
                        agent_name,
                        &format!("Still waiting for CLI agent response; latest MCP: {latest}"),
                        &activity,
                    );
                    last_activity = activity;
                } else {
                    send_debug_feed(
                        events,
                        agent_name,
                        &format!(
                            "Still waiting for CLI agent response; MCP unchanged: {latest}"
                        ),
                    );
                }

                progress_sleep
                    .as_mut()
                    .reset(tokio::time::Instant::now() + CLI_PROMPT_PROGRESS_INTERVAL);
            }
        }
    }
}

/// CLI Agent Provider that wraps CLI-based coding agents.
///
/// Each `complete_*` call spawns its own CLI subprocess (via [`AcpBridge`]) and
/// [`HttpMcpServer`] so that the orchestrator and subagents run fully
/// independently without deadlocking on a shared bridge.
pub struct CliAgentProvider {
    config: CliAgentConfig,
    metrics: MetricsTracker,
    working_dir: PathBuf,
}

impl CliAgentProvider {
    /// Create a new CLI agent provider.
    ///
    /// The provider is lightweight — each `complete_*` call spawns its own CLI
    /// subprocess and MCP server on demand.
    pub fn new(config: CliAgentConfig, working_dir: PathBuf, metrics: MetricsTracker) -> Self {
        Self {
            config,
            metrics,
            working_dir,
        }
    }

    /// Spin up an isolated CLI subprocess + MCP server for one agent call.
    ///
    /// Returns `(bridge, mcp_server, http_server)`. The HTTP server stays alive
    /// as long as the returned [`HttpMcpServer`] is alive; the bridge `Drop`
    /// kills the subprocess.
    async fn create_agent_env(&self) -> Result<(AcpBridge, Arc<McpServer>, HttpMcpServer)> {
        let bridge = AcpBridge::new(self.config.clone());
        bridge.connect(&self.working_dir).await?;

        let mcp_server = Arc::new(McpServer::new("feroxmute", env!("CARGO_PKG_VERSION")));
        let http = HttpMcpServer::start(Arc::clone(&mcp_server)).await?;

        Ok((bridge, mcp_server, http))
    }

    /// Register shell tools (docker_shell, memory, finding, script) on the given MCP server.
    async fn register_shell_tools(
        mcp_server: &McpServer,
        container: Arc<ContainerManager>,
        events: Arc<dyn EventSender>,
        agent_name: &str,
        limitations: Arc<EngagementLimitations>,
        memory: Arc<MemoryContext>,
    ) {
        mcp_server
            .register_tool(Arc::new(McpDockerShellTool::new(
                Arc::clone(&container),
                Arc::clone(&events),
                agent_name.to_string(),
                Arc::clone(&limitations),
            )))
            .await;

        mcp_server
            .register_tool(Arc::new(McpMemoryAddTool::new(Arc::clone(&memory))))
            .await;
        mcp_server
            .register_tool(Arc::new(McpMemoryGetTool::new(Arc::clone(&memory))))
            .await;
        mcp_server
            .register_tool(Arc::new(McpMemoryListTool::new(Arc::clone(&memory))))
            .await;

        let finding_context = Arc::new(FindingContext {
            conn: Arc::clone(&memory.conn),
            events: Arc::clone(&events),
            agent_name: agent_name.to_string(),
        });
        mcp_server
            .register_tool(Arc::new(McpRecordFindingTool::new(finding_context)))
            .await;

        mcp_server
            .register_tool(Arc::new(McpRunScriptTool::new(
                container,
                events,
                agent_name.to_string(),
            )))
            .await;

        mcp_server
            .register_tool(Arc::new(McpGetPlaybookTool::new()))
            .await;
    }

    /// Register orchestrator tools on the given MCP server.
    async fn register_orchestrator_tools(
        mcp_server: &McpServer,
        context: Arc<OrchestratorContext>,
    ) {
        mcp_server
            .register_tool(Arc::new(McpSpawnAgentTool::new(Arc::clone(&context))))
            .await;
        mcp_server
            .register_tool(Arc::new(McpWaitForAgentTool::new(Arc::clone(&context))))
            .await;
        mcp_server
            .register_tool(Arc::new(McpWaitForAnyTool::new(Arc::clone(&context))))
            .await;
        mcp_server
            .register_tool(Arc::new(McpListAgentsTool::new(Arc::clone(&context))))
            .await;
        mcp_server
            .register_tool(Arc::new(McpCompleteEngagementTool::new(context)))
            .await;
    }

    /// Register report tools on the given MCP server.
    async fn register_report_tools(mcp_server: &McpServer, context: Arc<ReportContext>) {
        mcp_server
            .register_tool(Arc::new(McpDeduplicateFindingsTool::new(Arc::clone(
                &context,
            ))))
            .await;
        mcp_server
            .register_tool(Arc::new(McpGenerateReportTool::new(Arc::clone(&context))))
            .await;
        mcp_server
            .register_tool(Arc::new(McpExportJsonTool::new(Arc::clone(&context))))
            .await;
        mcp_server
            .register_tool(Arc::new(McpExportMarkdownTool::new(Arc::clone(&context))))
            .await;
        mcp_server
            .register_tool(Arc::new(McpExportHtmlTool::new(Arc::clone(&context))))
            .await;
        mcp_server
            .register_tool(Arc::new(McpExportPdfTool::new(Arc::clone(&context))))
            .await;
        mcp_server
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
        // Spawn isolated subprocess (no MCP tools needed for basic completion)
        let bridge = AcpBridge::new(self.config.clone());
        bridge.connect(&self.working_dir).await?;

        let session_id = bridge
            .new_session("completion", &self.working_dir, None, None)
            .await?;

        let combined: String = request
            .messages
            .iter()
            .map(|m| format!("{:?}: {}", m.role, m.content))
            .collect::<Vec<_>>()
            .join("\n\n");

        let response = bridge.prompt(&session_id, &combined).await?;

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
        _agent_type: &str,
        limitations: Arc<EngagementLimitations>,
        memory: Arc<MemoryContext>,
        _event_bus_sender: crate::agents::AgentEventSender,
    ) -> Result<String> {
        // 1. Spawn isolated subprocess + HTTP MCP server
        let (bridge, mcp_server, http) = self.create_agent_env().await?;
        let (http_url, token) = (http.url(), http.token().to_string());

        // 2. Register shell tools on the per-call MCP server
        Self::register_shell_tools(
            &mcp_server,
            container,
            Arc::clone(&events),
            agent_name,
            limitations,
            memory,
        )
        .await;

        events.send_feed(
            agent_name,
            &format!(
                "CLI agent '{}' connected with MCP tools at {}",
                self.name(),
                http_url
            ),
            false,
        );

        // 3. Create session with MCP server and prompt
        send_debug_feed(
            events.as_ref(),
            agent_name,
            "Creating CLI agent ACP session with MCP tools",
        );
        let session_id = bridge
            .new_session(agent_name, &self.working_dir, Some(http_url), Some(token))
            .await
            .map_err(|e| with_http_mcp_diagnostics(e, &http))?;
        send_debug_feed(
            events.as_ref(),
            agent_name,
            "CLI agent ACP session created; sending prompt",
        );

        let combined_prompt = format!("{system_prompt}\n\n{user_prompt}");
        let response = prompt_with_progress(
            &bridge,
            &session_id,
            &combined_prompt,
            events.as_ref(),
            agent_name,
            &http,
        )
        .await?;

        // bridge + http dropped here → subprocess killed, HTTP server shut down
        Ok(response)
    }

    async fn complete_with_orchestrator(
        &self,
        system_prompt: &str,
        user_prompt: &str,
        context: Arc<OrchestratorContext>,
    ) -> Result<String> {
        // 1. Spawn isolated subprocess + HTTP MCP server
        let (bridge, mcp_server, http) = self.create_agent_env().await?;
        let (http_url, token) = (http.url(), http.token().to_string());

        // 2. Register all tools: shell + orchestrator + report
        let memory = Arc::clone(&context.memory);
        Self::register_shell_tools(
            &mcp_server,
            Arc::clone(&context.container),
            Arc::clone(&context.events),
            "orchestrator",
            Arc::clone(&context.limitations),
            memory,
        )
        .await;
        Self::register_orchestrator_tools(&mcp_server, Arc::clone(&context)).await;

        // Also register report tools so the orchestrator can delegate report generation
        let report_context = Arc::new(ReportContext {
            agent_name: "report".to_string(),
            events: Arc::clone(&context.events),
            target: context.target.clone(),
            session_id: context.session_id.clone(),
            start_time: Utc::now(),
            metrics: MetricsTracker::new(),
            findings: Arc::clone(&context.findings),
            report: Arc::new(Mutex::new(None)),
            reports_dir: context.reports_dir.clone(),
            session_db_path: context.session_db_path.clone(),
            deduplicated_findings: Arc::new(Mutex::new(None)),
            provider: None,
        });
        Self::register_report_tools(&mcp_server, report_context).await;

        context.events.send_feed(
            "orchestrator",
            &format!(
                "CLI agent '{}' connected for orchestration at {}",
                self.name(),
                http_url
            ),
            false,
        );

        // 3. Create session with MCP server and prompt
        send_debug_feed(
            context.events.as_ref(),
            "orchestrator",
            "Creating CLI agent ACP session with MCP tools",
        );
        let session_id = bridge
            .new_session(
                "orchestrator",
                &self.working_dir,
                Some(http_url),
                Some(token),
            )
            .await
            .map_err(|e| with_http_mcp_diagnostics(e, &http))?;
        send_debug_feed(
            context.events.as_ref(),
            "orchestrator",
            "CLI agent ACP session created; sending orchestration prompt",
        );

        let combined_prompt = format!("{system_prompt}\n\n{user_prompt}");
        let response = prompt_with_progress(
            &bridge,
            &session_id,
            &combined_prompt,
            context.events.as_ref(),
            "orchestrator",
            &http,
        )
        .await?;

        // bridge + http dropped here → subprocess killed, HTTP server shut down
        Ok(response)
    }

    async fn complete_with_report(
        &self,
        system_prompt: &str,
        user_prompt: &str,
        context: Arc<ReportContext>,
    ) -> Result<String> {
        // 1. Spawn isolated subprocess + HTTP MCP server
        let (bridge, mcp_server, http) = self.create_agent_env().await?;
        let (http_url, token) = (http.url(), http.token().to_string());

        // 2. Register report tools on the per-call MCP server
        Self::register_report_tools(&mcp_server, Arc::clone(&context)).await;

        context.events.send_feed(
            "report",
            &format!(
                "CLI agent '{}' connected for report generation at {}",
                self.name(),
                http_url
            ),
            false,
        );

        // 3. Create session with MCP server and prompt
        send_debug_feed(
            context.events.as_ref(),
            "report",
            "Creating CLI agent ACP session with MCP tools",
        );
        let session_id = bridge
            .new_session("report", &self.working_dir, Some(http_url), Some(token))
            .await
            .map_err(|e| with_http_mcp_diagnostics(e, &http))?;
        send_debug_feed(
            context.events.as_ref(),
            "report",
            "CLI agent ACP session created; sending report prompt",
        );

        let combined_prompt = format!("{system_prompt}\n\n{user_prompt}");
        let response = prompt_with_progress(
            &bridge,
            &session_id,
            &combined_prompt,
            context.events.as_ref(),
            "report",
            &http,
        )
        .await?;

        // bridge + http dropped here → subprocess killed, HTTP server shut down
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
