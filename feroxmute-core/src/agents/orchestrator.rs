//! Orchestrator agent for managing engagement phases

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::providers::{CompletionRequest, Message, ToolDefinition};
use crate::{Error, Result};

use super::{
    Agent, AgentContext, AgentStatus, AgentTask, Prompts, ReconAgent, SastAgent, ScannerAgent,
};

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
    recon_agent: ReconAgent,
    scanner_agent: ScannerAgent,
    sast_agent: Option<SastAgent>,
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
            prompts: prompts.clone(),
            current_phase: EngagementPhase::Setup,
            recon_agent: ReconAgent::with_prompts(prompts.clone()),
            scanner_agent: ScannerAgent::with_prompts(prompts),
            sast_agent: None,
            has_source_target: false,
            findings: Vec::new(),
        }
    }

    /// Create with custom prompts
    pub fn with_prompts(prompts: Prompts) -> Self {
        Self {
            status: AgentStatus::Idle,
            thinking: None,
            prompts: prompts.clone(),
            current_phase: EngagementPhase::Setup,
            recon_agent: ReconAgent::with_prompts(prompts.clone()),
            scanner_agent: ScannerAgent::with_prompts(prompts),
            sast_agent: None,
            has_source_target: false,
            findings: Vec::new(),
        }
    }

    /// Set the SAST agent for source code analysis
    pub fn with_sast_agent(mut self, sast_agent: SastAgent) -> Self {
        self.sast_agent = Some(sast_agent);
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

    /// Build tool definitions for the orchestrator
    fn build_tools(&self) -> Vec<ToolDefinition> {
        let mut tools = vec![
            ToolDefinition {
                name: "delegate_recon".to_string(),
                description: "Delegate a reconnaissance task to the recon agent".to_string(),
                parameters: json!({
                    "type": "object",
                    "properties": {
                        "task_description": {
                            "type": "string",
                            "description": "Description of the reconnaissance task"
                        },
                        "context": {
                            "type": "string",
                            "description": "Additional context for the task"
                        }
                    },
                    "required": ["task_description"]
                }),
            },
            ToolDefinition {
                name: "delegate_scanner".to_string(),
                description: "Delegate a scanning task to the scanner agent".to_string(),
                parameters: json!({
                    "type": "object",
                    "properties": {
                        "task_description": {
                            "type": "string",
                            "description": "Description of the scanning task"
                        },
                        "context": {
                            "type": "string",
                            "description": "Additional context including targets from recon"
                        }
                    },
                    "required": ["task_description"]
                }),
            },
            ToolDefinition {
                name: "advance_phase".to_string(),
                description: "Move to the next engagement phase".to_string(),
                parameters: json!({
                    "type": "object",
                    "properties": {
                        "reason": {
                            "type": "string",
                            "description": "Reason for advancing to the next phase"
                        }
                    },
                    "required": ["reason"]
                }),
            },
            ToolDefinition {
                name: "get_status".to_string(),
                description: "Get the current engagement status and findings".to_string(),
                parameters: json!({
                    "type": "object",
                    "properties": {}
                }),
            },
            ToolDefinition {
                name: "record_finding".to_string(),
                description: "Record an important finding or insight".to_string(),
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
                description: "Mark the engagement as complete and generate summary".to_string(),
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

        // Add SAST delegation tool if SAST agent is available
        if self.sast_agent.is_some() {
            tools.insert(
                2,
                ToolDefinition {
                    name: "delegate_sast".to_string(),
                    description:
                        "Delegate static analysis task to the SAST agent for source code scanning"
                            .to_string(),
                    parameters: json!({
                        "type": "object",
                        "properties": {
                            "task_description": {
                                "type": "string",
                                "description": "Description of the SAST task"
                            },
                            "context": {
                                "type": "string",
                                "description": "Additional context for the analysis"
                            }
                        },
                        "required": ["task_description"]
                    }),
                },
            );
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
            "Target: {}\nEngagement Task: {}\nCurrent Phase: {:?}\n\nContext: {}",
            ctx.target,
            task.description,
            self.current_phase,
            task.context.as_deref().unwrap_or("None")
        );

        let mut messages = vec![Message::user(&task_message)];
        let mut result = String::new();
        let max_iterations = 20; // Orchestrator may need more iterations

        for iteration in 0..max_iterations {
            self.thinking = Some(format!(
                "Phase: {:?} | Iteration {}: Planning next action...",
                self.current_phase,
                iteration + 1
            ));

            // Make completion request
            let request = CompletionRequest::new(messages.clone())
                .with_system(self.system_prompt())
                .with_tools(self.tools())
                .with_max_tokens(4096);

            let response = ctx.provider.complete(request).await?;

            // Handle response
            if !response.tool_calls.is_empty() {
                for tool_call in &response.tool_calls {
                    self.thinking = Some(format!("Executing: {}", tool_call.name));

                    let args: serde_json::Value = serde_json::from_str(&tool_call.arguments)
                        .map_err(|e| Error::Provider(format!("Invalid tool arguments: {}", e)))?;

                    let tool_result = match tool_call.name.as_str() {
                        "delegate_recon" => self.handle_delegate_recon(&args, task, ctx).await?,
                        "delegate_scanner" => {
                            self.handle_delegate_scanner(&args, task, ctx).await?
                        }
                        "delegate_sast" => self.handle_delegate_sast(&args, task, ctx).await?,
                        "advance_phase" => self.handle_advance_phase(&args),
                        "get_status" => self.handle_get_status(),
                        "record_finding" => self.handle_record_finding(&args),
                        "complete_engagement" => {
                            result.push_str(&self.handle_complete_engagement(&args));
                            self.status = AgentStatus::Completed;
                            break;
                        }
                        _ => "Unknown tool".to_string(),
                    };

                    result.push_str(&format!("\n## {}\n{}\n", tool_call.name, tool_result));
                    messages.push(Message::assistant(format!(
                        "Tool {} result: {}",
                        tool_call.name, tool_result
                    )));
                    messages.push(Message::user("Continue orchestrating the engagement."));
                }
            } else if let Some(content) = response.content {
                self.thinking = Some("Analyzing engagement progress...".to_string());
                result.push_str(&format!("\n## Orchestrator Analysis\n{}\n", content));

                if self.current_phase == EngagementPhase::Complete {
                    break;
                }

                messages.push(Message::assistant(&content));
                messages.push(Message::user("Continue with the engagement."));
            } else {
                break;
            }

            // Check if engagement is complete
            if self.current_phase == EngagementPhase::Complete {
                break;
            }
        }

        if self.status != AgentStatus::Completed {
            self.status = AgentStatus::Completed;
        }
        self.thinking = Some("Engagement orchestration completed".to_string());

        Ok(result)
    }

    fn thinking(&self) -> Option<&str> {
        self.thinking.as_deref()
    }

    fn set_status(&mut self, status: AgentStatus) {
        self.status = status;
    }
}

impl OrchestratorAgent {
    /// Handle delegation to recon agent
    async fn handle_delegate_recon(
        &mut self,
        args: &serde_json::Value,
        parent_task: &AgentTask,
        ctx: &AgentContext<'_>,
    ) -> Result<String> {
        let description = args
            .get("task_description")
            .and_then(|v| v.as_str())
            .unwrap_or("Perform reconnaissance");
        let context = args.get("context").and_then(|v| v.as_str());

        let mut recon_task =
            AgentTask::new(format!("{}-recon", parent_task.id), "recon", description)
                .with_parent(&parent_task.id);

        if let Some(ctx_str) = context {
            recon_task = recon_task.with_context(ctx_str);
        }

        let result = self.recon_agent.execute(&recon_task, ctx).await?;
        self.findings.push(format!("Recon: {}", description));

        Ok(result)
    }

    /// Handle delegation to scanner agent
    async fn handle_delegate_scanner(
        &mut self,
        args: &serde_json::Value,
        parent_task: &AgentTask,
        ctx: &AgentContext<'_>,
    ) -> Result<String> {
        let description = args
            .get("task_description")
            .and_then(|v| v.as_str())
            .unwrap_or("Perform vulnerability scanning");
        let context = args.get("context").and_then(|v| v.as_str());

        let mut scanner_task = AgentTask::new(
            format!("{}-scanner", parent_task.id),
            "scanner",
            description,
        )
        .with_parent(&parent_task.id);

        if let Some(ctx_str) = context {
            scanner_task = scanner_task.with_context(ctx_str);
        }

        let result = self.scanner_agent.execute(&scanner_task, ctx).await?;
        self.findings.push(format!("Scan: {}", description));

        Ok(result)
    }

    /// Handle delegation to SAST agent
    async fn handle_delegate_sast(
        &mut self,
        args: &serde_json::Value,
        parent_task: &AgentTask,
        ctx: &AgentContext<'_>,
    ) -> Result<String> {
        let description = args
            .get("task_description")
            .and_then(|v| v.as_str())
            .unwrap_or("Perform static analysis");
        let context = args.get("context").and_then(|v| v.as_str());

        let mut sast_task = AgentTask::new(format!("{}-sast", parent_task.id), "sast", description)
            .with_parent(&parent_task.id);

        if let Some(ctx_str) = context {
            sast_task = sast_task.with_context(ctx_str);
        }

        // Execute SAST agent if available
        if let Some(ref mut sast_agent) = self.sast_agent {
            let result = sast_agent.execute(&sast_task, ctx).await?;
            self.findings.push(format!("SAST: {}", description));
            Ok(result)
        } else {
            Ok("SAST agent not available (no source target configured)".to_string())
        }
    }

    /// Handle phase advancement
    fn handle_advance_phase(&mut self, args: &serde_json::Value) -> String {
        let reason = args
            .get("reason")
            .and_then(|v| v.as_str())
            .unwrap_or("Phase objectives complete");

        let old_phase = self.current_phase;
        if let Some(next_phase) = self.current_phase.next_with_config(self.has_source_target) {
            self.current_phase = next_phase;
            format!(
                "Advanced from {:?} to {:?}. Reason: {}",
                old_phase, next_phase, reason
            )
        } else {
            "Already at final phase (Complete)".to_string()
        }
    }

    /// Handle status request
    fn handle_get_status(&self) -> String {
        let findings_summary = if self.findings.is_empty() {
            "No findings recorded yet".to_string()
        } else {
            self.findings.join("\n- ")
        };

        format!(
            "Current Phase: {:?}\n\
            Agent Status: {:?}\n\
            Findings Count: {}\n\
            Recent Findings:\n- {}",
            self.current_phase,
            self.status,
            self.findings.len(),
            findings_summary
        )
    }

    /// Handle recording a finding
    fn handle_record_finding(&mut self, args: &serde_json::Value) -> String {
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
    fn handle_complete_engagement(&mut self, args: &serde_json::Value) -> String {
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
            EngagementPhase::StaticAnalysis.next(),
            Some(EngagementPhase::Reconnaissance)
        );
        assert_eq!(
            EngagementPhase::Reconnaissance.next(),
            Some(EngagementPhase::Scanning)
        );
        assert_eq!(
            EngagementPhase::Scanning.next(),
            Some(EngagementPhase::Exploitation)
        );
        assert_eq!(
            EngagementPhase::Exploitation.next(),
            Some(EngagementPhase::Reporting)
        );
        assert_eq!(
            EngagementPhase::Reporting.next(),
            Some(EngagementPhase::Complete)
        );
        assert_eq!(EngagementPhase::Complete.next(), None);
    }

    #[test]
    fn test_phase_progression_with_config() {
        // With source target, should go to StaticAnalysis
        assert_eq!(
            EngagementPhase::Setup.next_with_config(true),
            Some(EngagementPhase::StaticAnalysis)
        );

        // Without source target, should skip to Reconnaissance
        assert_eq!(
            EngagementPhase::Setup.next_with_config(false),
            Some(EngagementPhase::Reconnaissance)
        );

        // Other phases should behave the same
        assert_eq!(
            EngagementPhase::StaticAnalysis.next_with_config(true),
            Some(EngagementPhase::Reconnaissance)
        );
    }

    #[test]
    fn test_orchestrator_tools() {
        let agent = OrchestratorAgent::new();
        let tools = agent.tools();

        assert!(tools.iter().any(|t| t.name == "delegate_recon"));
        assert!(tools.iter().any(|t| t.name == "delegate_scanner"));
        assert!(tools.iter().any(|t| t.name == "advance_phase"));
        assert!(tools.iter().any(|t| t.name == "get_status"));
        assert!(tools.iter().any(|t| t.name == "complete_engagement"));
    }

    #[test]
    fn test_advance_phase_without_sast() {
        let mut agent = OrchestratorAgent::new();
        assert_eq!(agent.current_phase(), EngagementPhase::Setup);
        assert!(!agent.has_source_target);

        // Without source target, should skip StaticAnalysis and go to Reconnaissance
        let result = agent.handle_advance_phase(&json!({"reason": "Setup complete"}));
        assert!(result.contains("Reconnaissance"));
        assert_eq!(agent.current_phase(), EngagementPhase::Reconnaissance);
    }

    #[test]
    fn test_advance_phase_with_sast() {
        use std::path::PathBuf;
        let sast_agent = SastAgent::new(PathBuf::from("/tmp/test"));
        let mut agent = OrchestratorAgent::new().with_sast_agent(sast_agent);
        assert_eq!(agent.current_phase(), EngagementPhase::Setup);
        assert!(agent.has_source_target);

        // With source target, should go to StaticAnalysis
        let result = agent.handle_advance_phase(&json!({"reason": "Setup complete"}));
        assert!(result.contains("StaticAnalysis"));
        assert_eq!(agent.current_phase(), EngagementPhase::StaticAnalysis);

        // Then from StaticAnalysis to Reconnaissance
        let result = agent.handle_advance_phase(&json!({"reason": "SAST complete"}));
        assert!(result.contains("Reconnaissance"));
        assert_eq!(agent.current_phase(), EngagementPhase::Reconnaissance);
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
