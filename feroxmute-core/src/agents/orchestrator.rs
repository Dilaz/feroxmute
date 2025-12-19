//! Orchestrator agent for managing engagement phases

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::providers::{CompletionRequest, Message, ToolDefinition};
use crate::Result;

use super::{Agent, AgentContext, AgentStatus, AgentTask, Prompts};

/// Engagement phase
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EngagementPhase {
    /// Initial setup and scope validation
    #[default]
    Setup,
    /// Static analysis of source code
    StaticAnalysis,
    /// Asset discovery and enumeration
    Reconnaissance,
    /// Vulnerability scanning
    Scanning,
    /// Exploitation (if authorized)
    Exploitation,
    /// Report generation
    Reporting,
    /// Engagement complete
    Complete,
}

impl EngagementPhase {
    /// Get the next phase in the engagement workflow
    pub fn next(&self) -> Option<Self> {
        match self {
            Self::Setup => Some(Self::StaticAnalysis),
            Self::StaticAnalysis => Some(Self::Reconnaissance),
            Self::Reconnaissance => Some(Self::Scanning),
            Self::Scanning => Some(Self::Exploitation),
            Self::Exploitation => Some(Self::Reporting),
            Self::Reporting => Some(Self::Complete),
            Self::Complete => None,
        }
    }

    /// Get the next phase, optionally skipping StaticAnalysis if no source target
    pub fn next_with_config(&self, has_source_target: bool) -> Option<Self> {
        match self {
            Self::Setup => {
                if has_source_target {
                    Some(Self::StaticAnalysis)
                } else {
                    Some(Self::Reconnaissance)
                }
            }
            Self::StaticAnalysis => Some(Self::Reconnaissance),
            Self::Reconnaissance => Some(Self::Scanning),
            Self::Scanning => Some(Self::Exploitation),
            Self::Exploitation => Some(Self::Reporting),
            Self::Reporting => Some(Self::Complete),
            Self::Complete => None,
        }
    }
}

/// Orchestrator agent that coordinates the engagement
pub struct OrchestratorAgent {
    status: AgentStatus,
    thinking: Option<String>,
    prompts: Prompts,
    current_phase: EngagementPhase,
    has_source_target: bool,
    findings: Vec<String>,
}

impl OrchestratorAgent {
    /// Create a new orchestrator agent
    pub fn new() -> Self {
        let prompts = Prompts::default();
        Self {
            status: AgentStatus::Idle,
            thinking: None,
            prompts,
            current_phase: EngagementPhase::Setup,
            has_source_target: false,
            findings: Vec::new(),
        }
    }

    /// Create with custom prompts
    pub fn with_prompts(prompts: Prompts) -> Self {
        Self {
            status: AgentStatus::Idle,
            thinking: None,
            prompts,
            current_phase: EngagementPhase::Setup,
            has_source_target: false,
            findings: Vec::new(),
        }
    }

    /// Enable SAST support (source target available)
    pub fn with_source_target(mut self) -> Self {
        self.has_source_target = true;
        self
    }

    /// Get the current engagement phase
    pub fn current_phase(&self) -> EngagementPhase {
        self.current_phase
    }

    /// Get all findings collected
    pub fn findings(&self) -> &[String] {
        &self.findings
    }

    /// Get prompts reference for spawning agents
    pub fn prompts(&self) -> &Prompts {
        &self.prompts
    }

    /// Check if source target is available
    pub fn has_source_target(&self) -> bool {
        self.has_source_target
    }

    /// Build tool definitions for the orchestrator
    fn build_tools(&self) -> Vec<ToolDefinition> {
        let mut tools = vec![
            ToolDefinition {
                name: "spawn_agent".to_string(),
                description:
                    "Spawn a new agent to run a task in the background. Returns immediately."
                        .to_string(),
                parameters: json!({
                    "type": "object",
                    "properties": {
                        "agent_type": {
                            "type": "string",
                            "enum": ["recon", "scanner", "report"],
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
            },
            ToolDefinition {
                name: "wait_for_agent".to_string(),
                description: "Wait for a specific agent to complete and get its results."
                    .to_string(),
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
            },
            ToolDefinition {
                name: "wait_for_any".to_string(),
                description: "Wait for any running agent to complete and get its results."
                    .to_string(),
                parameters: json!({
                    "type": "object",
                    "properties": {}
                }),
            },
            ToolDefinition {
                name: "list_agents".to_string(),
                description: "List all spawned agents and their current status.".to_string(),
                parameters: json!({
                    "type": "object",
                    "properties": {}
                }),
            },
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
            },
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
            },
        ];

        // Add SAST to spawn options if source target available
        if self.has_source_target {
            if let Some(spawn_tool) = tools.iter_mut().find(|t| t.name == "spawn_agent") {
                spawn_tool.parameters = json!({
                    "type": "object",
                    "properties": {
                        "agent_type": {
                            "type": "string",
                            "enum": ["recon", "scanner", "sast", "report"],
                            "description": "Type of agent to spawn"
                        },
                        "name": {
                            "type": "string",
                            "description": "Unique name for this agent instance"
                        },
                        "instructions": {
                            "type": "string",
                            "description": "Task-specific instructions for the agent"
                        }
                    },
                    "required": ["agent_type", "name", "instructions"]
                });
            }
        }

        tools
    }
}

impl Default for OrchestratorAgent {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait(?Send)]
impl Agent for OrchestratorAgent {
    fn name(&self) -> &str {
        "orchestrator"
    }

    fn status(&self) -> AgentStatus {
        self.status
    }

    fn system_prompt(&self) -> &str {
        self.prompts.get("orchestrator").unwrap_or("")
    }

    fn tools(&self) -> Vec<ToolDefinition> {
        self.build_tools()
    }

    async fn execute(&mut self, task: &AgentTask, ctx: &AgentContext<'_>) -> Result<String> {
        self.status = AgentStatus::Running;
        self.thinking = Some(format!(
            "Starting engagement orchestration: {}",
            task.description
        ));

        // Build initial message
        let task_message = format!(
            "Target: {}\nEngagement Task: {}\n\nYou have the following tools:\n\
            - spawn_agent: Spawn agents (recon, scanner{}, report) to run tasks concurrently\n\
            - wait_for_agent: Wait for a specific agent by name\n\
            - wait_for_any: Wait for any agent to complete\n\
            - list_agents: See status of all agents\n\
            - record_finding: Record important findings\n\
            - complete_engagement: Finish the engagement\n\n\
            Start by spawning appropriate agents for reconnaissance.",
            ctx.target,
            task.description,
            if self.has_source_target { ", sast" } else { "" }
        );

        let messages = vec![Message::user(&task_message)];

        // Make single completion request - tool handling done by runner
        let request = CompletionRequest::new(messages)
            .with_system(self.system_prompt())
            .with_tools(self.tools())
            .with_max_tokens(4096);

        let response = ctx.provider.complete(request).await?;

        // Return the response content or tool calls as JSON for runner to handle
        if !response.tool_calls.is_empty() {
            let tool_calls_json: Vec<serde_json::Value> = response
                .tool_calls
                .iter()
                .map(|tc| {
                    json!({
                        "name": tc.name,
                        "arguments": tc.arguments
                    })
                })
                .collect();
            Ok(serde_json::to_string_pretty(&tool_calls_json).unwrap_or_default())
        } else {
            Ok(response.content.unwrap_or_default())
        }
    }

    fn thinking(&self) -> Option<&str> {
        self.thinking.as_deref()
    }

    fn set_status(&mut self, status: AgentStatus) {
        self.status = status;
    }
}

impl OrchestratorAgent {
    /// Handle recording a finding
    pub fn handle_record_finding(&mut self, args: &serde_json::Value) -> String {
        let finding = args
            .get("finding")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown finding");
        let category = args
            .get("category")
            .and_then(|v| v.as_str())
            .unwrap_or("info");

        let formatted = format!("[{}] {}", category.to_uppercase(), finding);
        self.findings.push(formatted.clone());

        format!("Recorded finding: {}", formatted)
    }

    /// Handle engagement completion
    pub fn handle_complete_engagement(&mut self, args: &serde_json::Value) -> String {
        let summary = args
            .get("summary")
            .and_then(|v| v.as_str())
            .unwrap_or("Engagement completed");

        self.current_phase = EngagementPhase::Complete;

        format!(
            "# Engagement Complete\n\n\
            ## Executive Summary\n{}\n\n\
            ## Findings Summary\n\
            Total Findings: {}\n\n\
            {}",
            summary,
            self.findings.len(),
            self.findings.join("\n")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_orchestrator_creation() {
        let agent = OrchestratorAgent::new();
        assert_eq!(agent.name(), "orchestrator");
        assert_eq!(agent.status(), AgentStatus::Idle);
        assert_eq!(agent.current_phase(), EngagementPhase::Setup);
    }

    #[test]
    fn test_phase_progression() {
        assert_eq!(
            EngagementPhase::Setup.next(),
            Some(EngagementPhase::StaticAnalysis)
        );
        assert_eq!(
            EngagementPhase::Reconnaissance.next(),
            Some(EngagementPhase::Scanning)
        );
        assert_eq!(EngagementPhase::Complete.next(), None);
    }

    #[test]
    fn test_orchestrator_tools() {
        let agent = OrchestratorAgent::new();
        let tools = agent.tools();

        assert!(tools.iter().any(|t| t.name == "spawn_agent"));
        assert!(tools.iter().any(|t| t.name == "wait_for_agent"));
        assert!(tools.iter().any(|t| t.name == "wait_for_any"));
        assert!(tools.iter().any(|t| t.name == "list_agents"));
        assert!(tools.iter().any(|t| t.name == "record_finding"));
        assert!(tools.iter().any(|t| t.name == "complete_engagement"));
    }

    #[test]
    fn test_orchestrator_with_source_target() {
        let agent = OrchestratorAgent::new().with_source_target();
        assert!(agent.has_source_target());
    }

    #[test]
    fn test_record_finding() {
        let mut agent = OrchestratorAgent::new();
        assert!(agent.findings().is_empty());

        agent.handle_record_finding(&json!({
            "finding": "Found open port 80",
            "category": "asset"
        }));

        assert_eq!(agent.findings().len(), 1);
        assert!(agent.findings()[0].contains("ASSET"));
    }
}
