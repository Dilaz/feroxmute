//! Orchestrator tools for rig-based agent loop
//!
//! These tools allow the orchestrator LLM to spawn and manage specialist agents.

use std::sync::Arc;

use rig::completion::ToolDefinition;
use rig::tool::Tool;
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use crate::agents::{AgentRegistry, AgentResult, AgentStatus, Prompts};
use crate::docker::ContainerManager;
use crate::providers::LlmProvider;

/// Errors from orchestrator tools
#[derive(Debug, Error)]
pub enum OrchestratorToolError {
    #[error("Agent error: {0}")]
    Agent(String),
    #[error("Registry error: {0}")]
    Registry(String),
}

/// Trait for sending events to the UI (implemented by CLI)
pub trait EventSender: Send + Sync {
    /// Send a feed message
    fn send_feed(&self, agent: &str, message: &str, is_error: bool);
    /// Send a status update
    fn send_status(&self, agent: &str, status: AgentStatus);
}

/// Shared context for all orchestrator tools
pub struct OrchestratorContext {
    pub registry: Arc<Mutex<AgentRegistry>>,
    pub provider: Arc<dyn LlmProvider>,
    pub container: Arc<ContainerManager>,
    pub events: Arc<dyn EventSender>,
    pub cancel: CancellationToken,
    pub prompts: Prompts,
    pub target: String,
    pub findings: Arc<Mutex<Vec<String>>>,
}

// ============================================================================
// SpawnAgentTool
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct SpawnAgentArgs {
    pub agent_type: String,
    pub name: String,
    pub instructions: String,
}

#[derive(Debug, Serialize)]
pub struct SpawnAgentOutput {
    pub success: bool,
    pub message: String,
}

pub struct SpawnAgentTool {
    context: Arc<OrchestratorContext>,
}

impl SpawnAgentTool {
    pub fn new(context: Arc<OrchestratorContext>) -> Self {
        Self { context }
    }
}

impl Tool for SpawnAgentTool {
    const NAME: &'static str = "spawn_agent";

    type Error = OrchestratorToolError;
    type Args = SpawnAgentArgs;
    type Output = SpawnAgentOutput;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: "spawn_agent".to_string(),
            description: "Spawn a new agent to run a task in the background. Returns immediately."
                .to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "agent_type": {
                        "type": "string",
                        "enum": ["recon", "scanner", "sast", "report"],
                        "description": "Type of agent to spawn"
                    },
                    "name": {
                        "type": "string",
                        "description": "Unique name for this agent instance (e.g., 'subdomain-enum', 'port-scan')"
                    },
                    "instructions": {
                        "type": "string",
                        "description": "Task-specific instructions for the agent"
                    }
                },
                "required": ["agent_type", "name", "instructions"]
            }),
        }
    }

    async fn call(&self, args: Self::Args) -> Result<Self::Output, Self::Error> {
        let mut registry = self.context.registry.lock().await;

        if registry.has_agent(&args.name) {
            return Ok(SpawnAgentOutput {
                success: false,
                message: format!("Agent '{}' already exists", args.name),
            });
        }

        // Get base prompt for agent type
        let base_prompt = self.context.prompts.get(&args.agent_type).unwrap_or("");
        let full_prompt = format!(
            "{}\n\n---\n\n## Task from Orchestrator\n\nName: {}\nInstructions: {}\nTarget: {}",
            base_prompt, args.name, args.instructions, self.context.target
        );

        self.context.events.send_feed(
            &args.name,
            &format!("Spawned: {}", args.instructions),
            false,
        );
        self.context
            .events
            .send_status(&args.agent_type, AgentStatus::Running);

        // Spawn agent task
        let result_tx = registry.result_sender();
        let agent_name = args.name.clone();
        let agent_type = args.agent_type.clone();
        let target = self.context.target.clone();
        let provider = Arc::clone(&self.context.provider);
        let container = Arc::clone(&self.context.container);
        let events = Arc::clone(&self.context.events);

        let handle = tokio::spawn(async move {
            let start = std::time::Instant::now();

            let output = match provider
                .complete_with_shell(&full_prompt, &target, container, events, &agent_name)
                .await
            {
                Ok(out) => out,
                Err(e) => format!("Error: {}", e),
            };

            let success = !output.starts_with("Error:");

            let _ = result_tx
                .send(AgentResult {
                    name: agent_name.clone(),
                    agent_type,
                    success,
                    output,
                    duration: start.elapsed(),
                })
                .await;
        });

        registry.register(
            args.name.clone(),
            args.agent_type.clone(),
            args.instructions.clone(),
            handle,
        );

        Ok(SpawnAgentOutput {
            success: true,
            message: format!("Spawned agent '{}' ({})", args.name, args.agent_type),
        })
    }
}

// ============================================================================
// WaitForAgentTool
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct WaitForAgentArgs {
    pub name: String,
}

#[derive(Debug, Serialize)]
pub struct WaitForAgentOutput {
    pub found: bool,
    pub success: bool,
    pub output: String,
}

pub struct WaitForAgentTool {
    context: Arc<OrchestratorContext>,
}

impl WaitForAgentTool {
    pub fn new(context: Arc<OrchestratorContext>) -> Self {
        Self { context }
    }
}

impl Tool for WaitForAgentTool {
    const NAME: &'static str = "wait_for_agent";

    type Error = OrchestratorToolError;
    type Args = WaitForAgentArgs;
    type Output = WaitForAgentOutput;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: "wait_for_agent".to_string(),
            description: "Wait for a specific agent to complete and get its results.".to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Name of the agent to wait for"
                    }
                },
                "required": ["name"]
            }),
        }
    }

    async fn call(&self, args: Self::Args) -> Result<Self::Output, Self::Error> {
        self.context.events.send_feed(
            "orchestrator",
            &format!("Waiting for agent '{}'...", args.name),
            false,
        );

        let mut registry = self.context.registry.lock().await;
        match registry.wait_for_agent(&args.name).await {
            Some(result) => {
                self.context.events.send_status(
                    &result.agent_type,
                    if result.success {
                        AgentStatus::Completed
                    } else {
                        AgentStatus::Failed
                    },
                );

                Ok(WaitForAgentOutput {
                    found: true,
                    success: result.success,
                    output: truncate_output(&result.output, 2000),
                })
            }
            None => Ok(WaitForAgentOutput {
                found: false,
                success: false,
                output: format!("Agent '{}' not found", args.name),
            }),
        }
    }
}

// ============================================================================
// WaitForAnyTool
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct WaitForAnyArgs {}

#[derive(Debug, Serialize)]
pub struct WaitForAnyOutput {
    pub found: bool,
    pub name: String,
    pub agent_type: String,
    pub success: bool,
    pub output: String,
}

pub struct WaitForAnyTool {
    context: Arc<OrchestratorContext>,
}

impl WaitForAnyTool {
    pub fn new(context: Arc<OrchestratorContext>) -> Self {
        Self { context }
    }
}

impl Tool for WaitForAnyTool {
    const NAME: &'static str = "wait_for_any";

    type Error = OrchestratorToolError;
    type Args = WaitForAnyArgs;
    type Output = WaitForAnyOutput;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: "wait_for_any".to_string(),
            description: "Wait for any running agent to complete and get its results.".to_string(),
            parameters: json!({
                "type": "object",
                "properties": {}
            }),
        }
    }

    async fn call(&self, _args: Self::Args) -> Result<Self::Output, Self::Error> {
        self.context.events.send_feed(
            "orchestrator",
            "Waiting for any agent to complete...",
            false,
        );

        let mut registry = self.context.registry.lock().await;
        match registry.wait_for_any().await {
            Some(result) => {
                self.context.events.send_status(
                    &result.agent_type,
                    if result.success {
                        AgentStatus::Completed
                    } else {
                        AgentStatus::Failed
                    },
                );

                Ok(WaitForAnyOutput {
                    found: true,
                    name: result.name,
                    agent_type: result.agent_type,
                    success: result.success,
                    output: truncate_output(&result.output, 2000),
                })
            }
            None => Ok(WaitForAnyOutput {
                found: false,
                name: String::new(),
                agent_type: String::new(),
                success: false,
                output: "No running agents".to_string(),
            }),
        }
    }
}

// ============================================================================
// ListAgentsTool
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct ListAgentsArgs {}

#[derive(Debug, Serialize)]
pub struct ListAgentsOutput {
    pub agents: Vec<AgentInfo>,
}

#[derive(Debug, Serialize)]
pub struct AgentInfo {
    pub name: String,
    pub agent_type: String,
    pub status: String,
}

pub struct ListAgentsTool {
    context: Arc<OrchestratorContext>,
}

impl ListAgentsTool {
    pub fn new(context: Arc<OrchestratorContext>) -> Self {
        Self { context }
    }
}

impl Tool for ListAgentsTool {
    const NAME: &'static str = "list_agents";

    type Error = OrchestratorToolError;
    type Args = ListAgentsArgs;
    type Output = ListAgentsOutput;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: "list_agents".to_string(),
            description: "List all spawned agents and their current status.".to_string(),
            parameters: json!({
                "type": "object",
                "properties": {}
            }),
        }
    }

    async fn call(&self, _args: Self::Args) -> Result<Self::Output, Self::Error> {
        let registry = self.context.registry.lock().await;
        let agents = registry
            .list_agents()
            .iter()
            .map(|(name, agent_type, status)| AgentInfo {
                name: name.to_string(),
                agent_type: agent_type.to_string(),
                status: format!("{:?}", status),
            })
            .collect();

        Ok(ListAgentsOutput { agents })
    }
}

// ============================================================================
// RecordFindingTool
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct RecordFindingArgs {
    pub finding: String,
    #[serde(default)]
    pub category: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RecordFindingOutput {
    pub recorded: bool,
    pub message: String,
}

pub struct RecordFindingTool {
    context: Arc<OrchestratorContext>,
}

impl RecordFindingTool {
    pub fn new(context: Arc<OrchestratorContext>) -> Self {
        Self { context }
    }
}

impl Tool for RecordFindingTool {
    const NAME: &'static str = "record_finding";

    type Error = OrchestratorToolError;
    type Args = RecordFindingArgs;
    type Output = RecordFindingOutput;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: "record_finding".to_string(),
            description: "Record an important finding or insight.".to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "finding": {
                        "type": "string",
                        "description": "The finding to record"
                    },
                    "category": {
                        "type": "string",
                        "description": "Category: asset, vulnerability, info, recommendation"
                    }
                },
                "required": ["finding"]
            }),
        }
    }

    async fn call(&self, args: Self::Args) -> Result<Self::Output, Self::Error> {
        let category = args.category.as_deref().unwrap_or("info");
        let formatted = format!("[{}] {}", category.to_uppercase(), args.finding);

        let mut findings = self.context.findings.lock().await;
        findings.push(formatted.clone());

        self.context
            .events
            .send_feed("orchestrator", &format!("Recorded: {}", formatted), false);

        Ok(RecordFindingOutput {
            recorded: true,
            message: format!("Recorded finding: {}", formatted),
        })
    }
}

// ============================================================================
// CompleteEngagementTool
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct CompleteEngagementArgs {
    pub summary: String,
}

#[derive(Debug, Serialize)]
pub struct CompleteEngagementOutput {
    pub completed: bool,
    pub summary: String,
    pub findings_count: usize,
}

pub struct CompleteEngagementTool {
    context: Arc<OrchestratorContext>,
}

impl CompleteEngagementTool {
    pub fn new(context: Arc<OrchestratorContext>) -> Self {
        Self { context }
    }
}

impl Tool for CompleteEngagementTool {
    const NAME: &'static str = "complete_engagement";

    type Error = OrchestratorToolError;
    type Args = CompleteEngagementArgs;
    type Output = CompleteEngagementOutput;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: "complete_engagement".to_string(),
            description: "Mark the engagement as complete and generate summary.".to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "summary": {
                        "type": "string",
                        "description": "Executive summary of the engagement"
                    }
                },
                "required": ["summary"]
            }),
        }
    }

    async fn call(&self, args: Self::Args) -> Result<Self::Output, Self::Error> {
        let findings = self.context.findings.lock().await;
        let findings_count = findings.len();

        self.context.events.send_feed(
            "orchestrator",
            &format!("Engagement complete: {}", args.summary),
            false,
        );

        // Trigger cancellation to stop the agent loop
        self.context.cancel.cancel();

        Ok(CompleteEngagementOutput {
            completed: true,
            summary: args.summary,
            findings_count,
        })
    }
}

// ============================================================================
// Helper functions
// ============================================================================

fn truncate_output(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len])
    }
}
