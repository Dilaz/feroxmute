//! Orchestrator tools for rig-based agent loop
//!
//! These tools allow the orchestrator LLM to spawn and manage specialist agents.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use rig::completion::ToolDefinition;
use rig::tool::Tool;
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use chrono::Utc;

use crate::agents::{
    AgentRegistry, AgentResult, AgentResultWaiter, AgentStatus, EngagementPhase, Prompts,
};
use crate::docker::ContainerManager;
use crate::limitations::{EngagementLimitations, ToolCategory};
use crate::providers::LlmProvider;
use crate::reports::Report;
use crate::state::models::FindingType;
use crate::state::{MetricsTracker, Severity};
use crate::tools::report::ReportContext;

/// Errors from orchestrator tools
#[derive(Debug, Error)]
pub enum OrchestratorToolError {
    #[error("Agent error: {0}")]
    Agent(String),
    #[error("Registry error: {0}")]
    Registry(String),
}

/// Structured summary of an agent's work
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AgentSummary {
    /// Whether the agent completed successfully
    pub success: bool,
    /// 1-2 sentence overview of what the agent did
    pub summary: String,
    /// Important discoveries or results
    pub key_findings: Vec<String>,
    /// Suggested follow-up actions
    pub next_steps: Vec<String>,
    /// Full raw output from the agent (for debugging)
    #[serde(skip)]
    pub raw_output: Option<String>,
}

/// Summarize agent output using the LLM
async fn summarize_agent_output(
    provider: &dyn crate::providers::LlmProvider,
    agent_name: &str,
    agent_type: &str,
    instructions: &str,
    raw_output: &str,
) -> AgentSummary {
    use crate::providers::{CompletionRequest, Message};

    let prompt = format!(
        r#"You are summarizing agent output for an orchestrator coordinating a penetration test.

Agent: {} ({})
Task: {}

Raw Output:
{}

Respond with JSON only, no markdown formatting:
{{"success": true/false, "summary": "1-2 sentence overview", "key_findings": ["finding 1", "finding 2"], "next_steps": ["action 1", "action 2"]}}"#,
        agent_name, agent_type, instructions, raw_output
    );

    let request = CompletionRequest::new(vec![Message::user(&prompt)])
        .with_system(
            "You extract structured summaries from agent output. Respond with valid JSON only.",
        )
        .with_max_tokens(1024);

    match provider.complete(request).await {
        Ok(response) => {
            if let Some(content) = response.content {
                // Try to parse the JSON response
                if let Ok(summary) = serde_json::from_str::<AgentSummary>(&content) {
                    return summary;
                }
                // Try to extract JSON from markdown code block
                let cleaned = content
                    .trim()
                    .trim_start_matches("```json")
                    .trim_start_matches("```")
                    .trim_end_matches("```")
                    .trim();
                if let Ok(summary) = serde_json::from_str::<AgentSummary>(cleaned) {
                    return summary;
                }
            }
            // Fallback: return a basic summary
            AgentSummary {
                success: !raw_output.to_lowercase().contains("error"),
                summary: "Summarization failed - raw output available".to_string(),
                key_findings: vec![],
                next_steps: vec![],
                raw_output: None,
            }
        }
        Err(_) => AgentSummary {
            success: !raw_output.to_lowercase().contains("error"),
            summary: "Summarization failed - raw output available".to_string(),
            key_findings: vec![],
            next_steps: vec![],
            raw_output: None,
        },
    }
}

/// Trait for sending events to the UI (implemented by CLI)
pub trait EventSender: Send + Sync {
    /// Send a feed message
    fn send_feed(&self, agent: &str, message: &str, is_error: bool);
    /// Send a feed message with tool output attached
    fn send_feed_with_output(&self, agent: &str, message: &str, is_error: bool, output: &str);
    /// Send a status update with optional current tool info
    fn send_status(
        &self,
        agent: &str,
        agent_type: &str,
        status: AgentStatus,
        current_tool: Option<String>,
    );
    /// Send metrics update
    fn send_metrics(
        &self,
        input_tokens: u64,
        output_tokens: u64,
        cache_read_tokens: u64,
        cost_usd: f64,
        tool_calls: u64,
    );
    /// Send vulnerability found
    fn send_vulnerability(&self, severity: Severity, title: &str);
    /// Send thinking update for an agent
    fn send_thinking(&self, agent: &str, content: Option<String>);
    /// Send engagement phase update
    fn send_phase(&self, phase: EngagementPhase);
    /// Send agent summary (when subagent completes)
    fn send_summary(&self, agent: &str, summary: &AgentSummary);
    /// Send memory entries update
    fn send_memory_update(&self, entries: Vec<super::MemoryEntryData>);
    /// Send a code finding from SAST analysis
    #[allow(clippy::too_many_arguments)]
    fn send_code_finding(
        &self,
        agent: &str,
        file_path: &str,
        line_number: Option<u32>,
        severity: Severity,
        finding_type: FindingType,
        title: &str,
        tool: &str,
        cve_id: Option<&str>,
        package_name: Option<&str>,
    );
    /// Notify that a tool was invoked (for tool call counting in TUI)
    fn send_tool_call(&self);
}

/// Shared context for all orchestrator tools
pub struct OrchestratorContext {
    pub registry: Arc<Mutex<AgentRegistry>>,
    pub waiter: Arc<Mutex<AgentResultWaiter>>,
    pub provider: Arc<dyn LlmProvider>,
    pub container: Arc<ContainerManager>,
    pub events: Arc<dyn EventSender>,
    pub cancel: CancellationToken,
    pub prompts: Prompts,
    pub target: String,
    pub findings: Arc<Mutex<Vec<String>>>,
    /// Engagement scope limitations
    pub limitations: Arc<EngagementLimitations>,
    /// Memory/scratch pad context for persistent notes
    pub memory: Arc<super::memory::MemoryContext>,
    /// Flag to distinguish engagement completion from user cancellation
    pub engagement_completed: Arc<AtomicBool>,
    /// Path to source code for SAST analysis (if available)
    pub source_path: Option<String>,
    /// Path to session database for status updates
    pub session_db_path: Option<std::path::PathBuf>,
    /// Session ID for report metadata
    pub session_id: String,
    /// Path to reports directory for saving report files
    pub reports_dir: std::path::PathBuf,
}

// ============================================================================
// SpawnAgentTool
// ============================================================================

/// Get required categories for an agent type
fn agent_required_categories(agent_type: &str) -> Vec<ToolCategory> {
    use ToolCategory::*;
    match agent_type {
        "recon" => vec![SubdomainEnum, AssetDiscovery, PortScan, WebCrawl],
        "scanner" => vec![WebScan, NetworkScan],
        "exploit" => vec![WebExploit, NetworkExploit],
        "sast" => vec![Sast],
        "report" => vec![Report],
        _ => vec![],
    }
}

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
            description: "Spawn a new agent to run a task in the background. Returns immediately. After calling this, you MUST call wait_for_any() to get results - do not stop or complete the engagement without waiting."
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
        // Notify TUI of tool invocation for counting
        self.context.events.send_tool_call();

        // Check if agent type is allowed by limitations
        let required = agent_required_categories(&args.agent_type);
        let has_any_allowed = required
            .iter()
            .any(|c| self.context.limitations.is_allowed(*c));

        if !has_any_allowed && !required.is_empty() {
            let msg = format!(
                "Cannot spawn '{}' agent: no allowed capabilities for current engagement scope",
                args.agent_type
            );
            self.context.events.send_feed("orchestrator", &msg, true);
            return Ok(SpawnAgentOutput {
                success: false,
                message: msg,
            });
        }

        let mut registry = self.context.registry.lock().await;

        if registry.has_agent(&args.name) {
            return Ok(SpawnAgentOutput {
                success: false,
                message: format!("Agent '{}' already exists", args.name),
            });
        }

        // Get base prompt for agent type
        let base_prompt = self.context.prompts.get(&args.agent_type).unwrap_or("");

        // For SAST agents, use source_path; for others, use web target
        let agent_target = if args.agent_type == "sast" {
            self.context
                .source_path
                .clone()
                .unwrap_or_else(|| self.context.target.clone())
        } else {
            self.context.target.clone()
        };

        let full_prompt = format!(
            "{}\n\n---\n\n## Task from Orchestrator\n\nName: {}\nInstructions: {}\nTarget: {}",
            base_prompt, args.name, args.instructions, agent_target
        );

        self.context.events.send_feed(
            &args.name,
            &format!("Spawned: {}", args.instructions),
            false,
        );
        self.context
            .events
            .send_status(&args.name, &args.agent_type, AgentStatus::Streaming, None);

        // Update engagement phase based on agent type
        let phase = match args.agent_type.as_str() {
            "sast" => Some(EngagementPhase::StaticAnalysis),
            "recon" => Some(EngagementPhase::Reconnaissance),
            "scanner" => Some(EngagementPhase::Scanning),
            "report" => Some(EngagementPhase::Reporting),
            _ => None,
        };
        if let Some(p) = phase {
            self.context.events.send_phase(p);
        }

        // Spawn agent task
        let result_tx = registry.result_sender();
        let agent_name = args.name.clone();
        let agent_type = args.agent_type.clone();
        let target = agent_target; // Use source_path for SAST, web target for others
        let provider = Arc::clone(&self.context.provider);
        let container = Arc::clone(&self.context.container);
        let events = Arc::clone(&self.context.events);
        let findings = Arc::clone(&self.context.findings);
        let limitations = Arc::clone(&self.context.limitations);
        let memory = Arc::clone(&self.context.memory);

        let session_id = self.context.session_id.clone();

        let reports_dir = self.context.reports_dir.clone();

        let handle = if agent_type == "report" {
            // Report agents use specialized report tools
            tokio::spawn(async move {
                let start = std::time::Instant::now();

                // Create report context with findings from orchestrator
                let report_context = Arc::new(ReportContext {
                    events: Arc::clone(&events),
                    target: target.clone(),
                    session_id,
                    start_time: Utc::now(),
                    metrics: MetricsTracker::new(),
                    findings,
                    report: Arc::new(Mutex::new(None::<Report>)),
                    reports_dir,
                });

                let output = match provider
                    .complete_with_report(&full_prompt, &target, report_context)
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
            })
        } else {
            // Other agents use shell tool
            tokio::spawn(async move {
                let start = std::time::Instant::now();

                let output = match provider
                    .complete_with_shell(
                        &full_prompt,
                        &target,
                        container,
                        events,
                        &agent_name,
                        limitations,
                        memory,
                    )
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
            })
        };

        registry.register(
            args.name.clone(),
            args.agent_type.clone(),
            args.instructions.clone(),
            handle,
        );

        Ok(SpawnAgentOutput {
            success: true,
            message: format!(
                "Agent '{}' ({}) is now running. YOUR NEXT TOOL CALL MUST BE: wait_for_any()",
                args.name, args.agent_type
            ),
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
    pub summary: AgentSummary,
    /// Raw output truncated for reference (if needed)
    pub raw_output_truncated: String,
    /// Workflow guidance based on current state
    pub workflow_hint: String,
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
        // Notify TUI of tool invocation for counting
        self.context.events.send_tool_call();

        self.context.events.send_feed(
            "orchestrator",
            &format!("Waiting for agent '{}'...", args.name),
            false,
        );

        // Update orchestrator status to Waiting while blocked
        self.context
            .events
            .send_status("orchestrator", "orchestrator", AgentStatus::Waiting, None);

        // Brief lock: check agent status and get instructions
        let (is_running, instructions) = {
            let registry = self.context.registry.lock().await;
            let running = registry.is_agent_running(&args.name);
            let instr = registry
                .get_agent_instructions(&args.name)
                .unwrap_or_default();
            (running, instr)
        };
        // Registry lock released here

        // If agent doesn't exist or already completed, return immediately
        let result = match is_running {
            None | Some(false) => None,
            Some(true) => {
                // Wait on the waiter (no registry lock held)
                let mut waiter = self.context.waiter.lock().await;
                let r = waiter.wait_for_agent(&args.name).await;
                drop(waiter);

                // Brief lock: update agent status
                if let Some(ref res) = r {
                    let mut registry = self.context.registry.lock().await;
                    registry.mark_agent_result(&res.name, res.success);
                }

                r
            }
        };

        // Restore orchestrator status to Running
        self.context.events.send_status(
            "orchestrator",
            "orchestrator",
            AgentStatus::Streaming,
            None,
        );

        match result {
            Some(result) => {
                self.context.events.send_status(
                    &result.name,
                    &result.agent_type,
                    if result.success {
                        AgentStatus::Completed
                    } else {
                        AgentStatus::Failed
                    },
                    None,
                );

                // Summarize the output
                let mut summary = summarize_agent_output(
                    self.context.provider.as_ref(),
                    &result.name,
                    &result.agent_type,
                    &instructions,
                    &result.output,
                )
                .await;

                // Attach raw output for debugging
                summary.raw_output = Some(result.output.clone());

                // Send summary to TUI
                self.context.events.send_summary(&result.name, &summary);

                // Generate workflow hint based on agent type
                let workflow_hint = if result.agent_type == "report" {
                    "REPORT COMPLETED. You may now call complete_engagement with an executive summary.".to_string()
                } else if result.agent_type == "recon" {
                    "RECON COMPLETED. Spawn scanner agent(s) to test discovered endpoints, or wait for other agents.".to_string()
                } else {
                    "Agent completed. Continue with next phase of testing.".to_string()
                };

                Ok(WaitForAgentOutput {
                    found: true,
                    summary,
                    raw_output_truncated: truncate_output(&result.output, 500),
                    workflow_hint,
                })
            }
            None => Ok(WaitForAgentOutput {
                found: false,
                summary: AgentSummary {
                    success: false,
                    summary: format!("Agent '{}' not found", args.name),
                    key_findings: vec![],
                    next_steps: vec![],
                    raw_output: None,
                },
                raw_output_truncated: String::new(),
                workflow_hint: "Agent not found.".to_string(),
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
    pub summary: AgentSummary,
    pub raw_output_truncated: String,
    /// Number of agents still running after this one completed
    pub remaining_running: usize,
    /// Workflow guidance based on current state
    pub workflow_hint: String,
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
            description: "REQUIRED after spawn_agent. Blocks until an agent completes and returns its results. You MUST call this after every spawn to get results and decide next steps. Returns remaining_running count.".to_string(),
            parameters: json!({
                "type": "object",
                "properties": {}
            }),
        }
    }

    async fn call(&self, _args: Self::Args) -> Result<Self::Output, Self::Error> {
        // Notify TUI of tool invocation for counting
        self.context.events.send_tool_call();

        self.context.events.send_feed(
            "orchestrator",
            "Waiting for any agent to complete...",
            false,
        );

        // Update orchestrator status to Waiting while blocked
        self.context
            .events
            .send_status("orchestrator", "orchestrator", AgentStatus::Waiting, None);

        // Brief lock: check if anything is running
        let should_wait = {
            let registry = self.context.registry.lock().await;
            let waiter = self.context.waiter.lock().await;
            registry.running_count() > 0 || waiter.has_pending()
        };
        // Both locks released here

        let result = if should_wait {
            // Wait on the waiter (no registry lock held)
            let mut waiter = self.context.waiter.lock().await;
            let r = waiter.wait_for_any().await;
            drop(waiter);

            // Brief lock: update agent status
            if let Some(ref res) = r {
                let mut registry = self.context.registry.lock().await;
                registry.mark_agent_result(&res.name, res.success);
            }

            r
        } else {
            None
        };

        // Brief lock: get instructions and remaining count
        let (instructions, remaining_running, has_scanner, has_report) = {
            let registry = self.context.registry.lock().await;
            let instr = result
                .as_ref()
                .and_then(|r| registry.get_agent_instructions(&r.name))
                .unwrap_or_default();
            let remaining = registry.running_count();
            let all_agents = registry.list_agents();
            let scanner = all_agents.iter().any(|(_, t, _)| *t == "scanner");
            let report = all_agents.iter().any(|(_, t, _)| *t == "report");
            (instr, remaining, scanner, report)
        };
        // Registry lock released here

        // Restore orchestrator status to Running
        self.context.events.send_status(
            "orchestrator",
            "orchestrator",
            AgentStatus::Streaming,
            None,
        );

        match result {
            Some(result) => {
                self.context.events.send_status(
                    &result.name,
                    &result.agent_type,
                    if result.success {
                        AgentStatus::Completed
                    } else {
                        AgentStatus::Failed
                    },
                    None,
                );

                // Summarize the output
                let mut summary = summarize_agent_output(
                    self.context.provider.as_ref(),
                    &result.name,
                    &result.agent_type,
                    &instructions,
                    &result.output,
                )
                .await;

                // Attach raw output for debugging
                summary.raw_output = Some(result.output.clone());

                // Send summary to TUI
                self.context.events.send_summary(&result.name, &summary);

                // Generate workflow hint based on current state
                let workflow_hint = if result.agent_type == "recon" && !has_scanner {
                    "RECON COMPLETED. You MUST now spawn scanner agent(s) to test the discovered endpoints/services. DO NOT call complete_engagement yet.".to_string()
                } else if result.agent_type == "scanner" && remaining_running == 0 && !has_report {
                    "ALL SCANNERS COMPLETED. You MUST now spawn a report agent to generate findings. DO NOT call complete_engagement yet.".to_string()
                } else if result.agent_type == "report" && remaining_running == 0 {
                    "REPORT COMPLETED. You may now call complete_engagement with an executive summary.".to_string()
                } else if remaining_running > 0 {
                    format!(
                        "{} agent(s) still running. Call wait_for_any again or spawn more agents.",
                        remaining_running
                    )
                } else {
                    "Analyze results and spawn appropriate follow-up agents, or spawn report if all testing is done.".to_string()
                };

                Ok(WaitForAnyOutput {
                    found: true,
                    name: result.name,
                    agent_type: result.agent_type,
                    summary,
                    raw_output_truncated: truncate_output(&result.output, 500),
                    remaining_running,
                    workflow_hint,
                })
            }
            None => Ok(WaitForAnyOutput {
                found: false,
                name: String::new(),
                agent_type: String::new(),
                summary: AgentSummary::default(),
                raw_output_truncated: "No running agents".to_string(),
                remaining_running: 0,
                workflow_hint: "No agents running. Spawn agents to continue the engagement."
                    .to_string(),
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
        // Notify TUI of tool invocation for counting
        self.context.events.send_tool_call();

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
    #[serde(default)]
    pub severity: Option<String>,
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
                    },
                    "severity": {
                        "type": "string",
                        "description": "Severity level for vulnerabilities: critical, high, medium, low, info. Required when category is 'vulnerability'."
                    }
                },
                "required": ["finding"]
            }),
        }
    }

    async fn call(&self, args: Self::Args) -> Result<Self::Output, Self::Error> {
        // Notify TUI of tool invocation for counting
        self.context.events.send_tool_call();

        let category = args.category.as_deref().unwrap_or("info");
        let formatted = format!("[{}] {}", category.to_uppercase(), args.finding);

        let mut findings = self.context.findings.lock().await;
        findings.push(formatted.clone());

        self.context
            .events
            .send_feed("orchestrator", &format!("Recorded: {}", formatted), false);

        // Send vulnerability event to update TUI counts
        if category.eq_ignore_ascii_case("vulnerability") {
            let severity = match args.severity.as_deref().unwrap_or("medium") {
                "critical" | "Critical" | "CRITICAL" => Severity::Critical,
                "high" | "High" | "HIGH" => Severity::High,
                "medium" | "Medium" | "MEDIUM" => Severity::Medium,
                "low" | "Low" | "LOW" => Severity::Low,
                "info" | "Info" | "INFO" | "informational" => Severity::Info,
                _ => Severity::Medium,
            };
            self.context
                .events
                .send_vulnerability(severity, &args.finding);
        }

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
            description: "ONLY call after all work is done: spawn recon -> wait_for_any -> spawn scanners -> wait_for_any (repeat until remaining_running=0) -> spawn report -> wait_for_agent -> THEN complete. Will fail if agents are running.".to_string(),
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
        // Notify TUI of tool invocation for counting
        self.context.events.send_tool_call();

        // Check if there are still running agents (any active state)
        let registry = self.context.registry.lock().await;
        let all_agents: Vec<_> = registry.list_agents();
        let running_agents: Vec<_> = all_agents
            .iter()
            .filter(|(_, _, status)| {
                matches!(
                    status,
                    AgentStatus::Thinking
                        | AgentStatus::Streaming
                        | AgentStatus::Executing
                        | AgentStatus::Processing
                )
            })
            .map(|(name, _, _)| name.to_string())
            .collect();

        drop(registry);

        if !running_agents.is_empty() {
            let msg = format!(
                "Cannot complete: {} agent(s) still running: {}. Use wait_for_any or wait_for_agent first.",
                running_agents.len(),
                running_agents.join(", ")
            );
            self.context.events.send_feed("orchestrator", &msg, true);
            return Ok(CompleteEngagementOutput {
                completed: false,
                summary: msg,
                findings_count: 0,
            });
        }

        let findings = self.context.findings.lock().await;
        let findings_count = findings.len();

        self.context.events.send_feed(
            "orchestrator",
            &format!("Engagement complete: {}", args.summary),
            false,
        );

        // Update phase to Complete
        self.context.events.send_phase(EngagementPhase::Complete);

        // Mark all agents as completed
        let registry = self.context.registry.lock().await;
        for (name, agent_type, _status) in registry.list_agents() {
            self.context
                .events
                .send_status(name, agent_type, AgentStatus::Completed, None);
        }
        drop(registry);

        // Set completion flag BEFORE cancelling so runner knows this was a clean exit
        self.context
            .engagement_completed
            .store(true, Ordering::SeqCst);

        // Mark session as completed
        if let Some(ref db_path) = self.context.session_db_path {
            match rusqlite::Connection::open(db_path) {
                Ok(conn) => {
                    if let Err(e) = conn.execute(
                        "UPDATE session_state SET status = 'completed', last_activity_at = datetime('now') WHERE id = 1",
                        [],
                    ) {
                        self.context.events.send_feed(
                            "orchestrator",
                            &format!("Warning: Failed to persist completion status: {}", e),
                            true,
                        );
                    }
                }
                Err(e) => {
                    self.context.events.send_feed(
                        "orchestrator",
                        &format!("Warning: Failed to open session DB: {}", e),
                        true,
                    );
                }
            }
        }

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
        format!("{}...", &s[..s.floor_char_boundary(max_len)])
    }
}
