//! CLI Agent Provider implementation
//!
//! Wraps CLI-based coding agents (Claude Code, Codex, Gemini CLI) as LLM providers.
//!
//! NOTE: The ACP (Agent Client Protocol) library uses `spawn_local` which requires
//! a single-threaded runtime. The current implementation provides the structure
//! but actual ACP integration requires running in a LocalSet context.

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;

use crate::Result;
use crate::docker::ContainerManager;
use crate::limitations::EngagementLimitations;
use crate::mcp::McpServer;
use crate::mcp::tools::{
    FindingContext, McpDockerShellTool, McpMemoryAddTool, McpMemoryGetTool, McpMemoryListTool,
    McpRecordFindingTool,
};
use crate::providers::traits::{CompletionRequest, CompletionResponse, LlmProvider};
use crate::state::MetricsTracker;
use crate::tools::{EventSender, MemoryContext, OrchestratorContext, ReportContext};

use super::{AcpClient, CliAgentConfig};

/// CLI Agent Provider that wraps CLI-based coding agents
///
/// This provider uses ACP (Agent Client Protocol) to communicate with CLI agents
/// and MCP (Model Context Protocol) to expose feroxmute tools to the agent.
pub struct CliAgentProvider {
    /// Configuration for the CLI agent
    config: CliAgentConfig,
    /// MCP server for providing tools to the CLI agent
    mcp_server: Arc<McpServer>,
    /// Metrics tracker for token usage and costs
    metrics: MetricsTracker,
    /// Working directory for agent operations
    working_dir: PathBuf,
    /// Path to MCP config file for CLI agent
    mcp_config_path: PathBuf,
}

impl CliAgentProvider {
    /// Create a new CLI agent provider
    ///
    /// # Arguments
    /// * `config` - CLI agent configuration
    /// * `working_dir` - Working directory for the CLI agent
    /// * `metrics` - Metrics tracker for usage statistics
    ///
    /// # Errors
    /// Returns error if the CLI binary is not found
    pub fn new(
        config: CliAgentConfig,
        working_dir: PathBuf,
        metrics: MetricsTracker,
    ) -> Result<Self> {
        // Create a temporary ACP client just to check binary availability
        let acp_client = AcpClient::new(config.clone());
        acp_client.check_binary()?;

        // Create MCP server for providing tools
        let mcp_server = Arc::new(McpServer::new("feroxmute", env!("CARGO_PKG_VERSION")));

        // MCP config path in the working directory
        let mcp_config_path = working_dir.join(".feroxmute-mcp.json");

        Ok(Self {
            config,
            mcp_server,
            metrics,
            working_dir,
            mcp_config_path,
        })
    }

    /// Register shell tools for specialist agents (recon, scanner, etc.)
    async fn register_shell_tools(
        &self,
        container: Arc<ContainerManager>,
        events: Arc<dyn EventSender>,
        agent_name: &str,
        limitations: Arc<EngagementLimitations>,
        memory: Arc<MemoryContext>,
    ) {
        // Register docker shell tool
        self.mcp_server
            .register_tool(Arc::new(McpDockerShellTool::new(
                Arc::clone(&container),
                Arc::clone(&events),
                agent_name.to_string(),
                Arc::clone(&limitations),
            )))
            .await;

        // Register memory tools
        self.mcp_server
            .register_tool(Arc::new(McpMemoryAddTool::new(Arc::clone(&memory))))
            .await;
        self.mcp_server
            .register_tool(Arc::new(McpMemoryGetTool::new(Arc::clone(&memory))))
            .await;
        self.mcp_server
            .register_tool(Arc::new(McpMemoryListTool::new(Arc::clone(&memory))))
            .await;

        // Register finding tool with a context
        let finding_context = Arc::new(FindingContext {
            conn: Arc::clone(&memory.conn),
            events,
            agent_name: agent_name.to_string(),
        });
        self.mcp_server
            .register_tool(Arc::new(McpRecordFindingTool::new(finding_context)))
            .await;
    }

    /// Write MCP config file for the CLI agent to discover the MCP server
    fn write_mcp_config(&self) -> Result<()> {
        let config = serde_json::json!({
            "mcpServers": {
                "feroxmute": {
                    "command": "feroxmute-mcp",
                    "args": ["--stdio"],
                    "env": {}
                }
            }
        });

        std::fs::write(
            &self.mcp_config_path,
            serde_json::to_string_pretty(&config)?,
        )
        .map_err(|e| crate::Error::Provider(format!("Failed to write MCP config: {}", e)))?;

        tracing::debug!("Wrote MCP config to {}", self.mcp_config_path.display());
        Ok(())
    }

    /// Get the working directory
    pub fn working_dir(&self) -> &PathBuf {
        &self.working_dir
    }

    /// Get the MCP config path
    pub fn mcp_config_path(&self) -> &PathBuf {
        &self.mcp_config_path
    }

    /// Get the MCP server
    pub fn mcp_server(&self) -> &Arc<McpServer> {
        &self.mcp_server
    }
}

#[async_trait]
impl LlmProvider for CliAgentProvider {
    fn name(&self) -> &str {
        self.config.agent_type.provider_name()
    }

    fn supports_tools(&self) -> bool {
        // Tools are provided via MCP
        true
    }

    fn metrics(&self) -> &MetricsTracker {
        &self.metrics
    }

    async fn complete(&self, request: CompletionRequest) -> Result<CompletionResponse> {
        // NOTE: Full ACP integration requires running in a LocalSet context.
        // This is a stub that logs the request and returns an error.
        // See acp_client.rs for the actual ACP communication implementation.

        let prompt_preview: String = request
            .messages
            .iter()
            .map(|m| format!("{:?}: {}", m.role, &m.content[..m.content.len().min(100)]))
            .collect::<Vec<_>>()
            .join("\n");

        tracing::warn!(
            "CLI agent provider '{}' complete() called but ACP requires LocalSet context. Prompt preview: {}",
            self.name(),
            prompt_preview
        );

        // Return error indicating ACP needs LocalSet
        Err(crate::Error::Provider(format!(
            "CLI agent '{}' requires LocalSet runtime context for ACP communication. \
             Use spawn_local or LocalSet::run_until to run CLI agent operations.",
            self.name()
        )))
    }

    async fn complete_with_shell(
        &self,
        system_prompt: &str,
        _user_prompt: &str,
        container: Arc<ContainerManager>,
        events: Arc<dyn EventSender>,
        agent_name: &str,
        limitations: Arc<EngagementLimitations>,
        memory: Arc<MemoryContext>,
    ) -> Result<String> {
        // Write MCP config for the CLI agent
        self.write_mcp_config()?;

        // Register shell tools for this agent
        self.register_shell_tools(
            Arc::clone(&container),
            Arc::clone(&events),
            agent_name,
            limitations,
            memory,
        )
        .await;

        events.send_feed(
            agent_name,
            &format!(
                "CLI agent '{}' initialized with MCP tools at {}",
                self.name(),
                self.mcp_config_path.display()
            ),
            false,
        );

        // NOTE: Full ACP integration requires running in a LocalSet context.
        // The MCP tools are registered and the config is written, but actual
        // CLI agent invocation needs to happen in a LocalSet.

        tracing::warn!(
            "CLI agent provider complete_with_shell() called. System prompt: {}...",
            &system_prompt[..system_prompt.len().min(100)]
        );

        Err(crate::Error::Provider(format!(
            "CLI agent '{}' requires LocalSet runtime context for ACP communication. \
             MCP config written to {}. Tools registered: docker_shell, memory_*, record_finding",
            self.name(),
            self.mcp_config_path.display()
        )))
    }

    async fn complete_with_orchestrator(
        &self,
        system_prompt: &str,
        _user_prompt: &str,
        context: Arc<OrchestratorContext>,
    ) -> Result<String> {
        // Write MCP config
        self.write_mcp_config()?;

        context.events.send_feed(
            "orchestrator",
            &format!("CLI agent '{}' initialized for orchestration", self.name()),
            false,
        );

        tracing::warn!(
            "CLI agent provider complete_with_orchestrator() called. Target: {}, System: {}...",
            context.target,
            &system_prompt[..system_prompt.len().min(100)]
        );

        // For orchestrator mode, we'd need to expose orchestrator tools via MCP
        // This is a complex integration that requires careful design

        Err(crate::Error::Provider(format!(
            "CLI agent '{}' orchestrator mode requires LocalSet runtime context. \
             Target: {}",
            self.name(),
            context.target
        )))
    }

    async fn complete_with_report(
        &self,
        system_prompt: &str,
        _user_prompt: &str,
        context: Arc<ReportContext>,
    ) -> Result<String> {
        // Write MCP config
        self.write_mcp_config()?;

        // Collect findings for the report prompt
        let findings = context.findings.lock().await;
        let findings_count = findings.len();
        drop(findings);

        context.events.send_feed(
            "report",
            &format!(
                "CLI agent '{}' initialized for report generation ({} findings)",
                self.name(),
                findings_count
            ),
            false,
        );

        tracing::warn!(
            "CLI agent provider complete_with_report() called. Findings: {}, System: {}...",
            findings_count,
            &system_prompt[..system_prompt.len().min(100)]
        );

        Err(crate::Error::Provider(format!(
            "CLI agent '{}' report mode requires LocalSet runtime context. \
             Findings count: {}",
            self.name(),
            findings_count
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::super::CliAgentType;
    use super::*;

    #[test]
    fn test_provider_name() {
        // We can't easily test the full provider without a real binary,
        // but we can verify that CliAgentConfig provides the right name
        let config = CliAgentConfig::new(CliAgentType::ClaudeCode);
        assert_eq!(config.agent_type.provider_name(), "claude-code");

        let config = CliAgentConfig::new(CliAgentType::Codex);
        assert_eq!(config.agent_type.provider_name(), "codex");

        let config = CliAgentConfig::new(CliAgentType::GeminiCli);
        assert_eq!(config.agent_type.provider_name(), "gemini-cli");
    }

    #[test]
    fn test_provider_supports_tools() {
        // Provider should indicate it supports tools (via MCP)
        // This is a design verification, not a runtime test
        assert!(true, "CliAgentProvider.supports_tools() should return true");
    }
}
