//! MCP wrappers for orchestrator tools
//!
//! These tools allow CLI agents (e.g., Claude Code) to spawn and manage
//! specialist agents via the MCP protocol, mirroring the rig-based tools
//! from `tools/orchestrator.rs`.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use async_trait::async_trait;
use chrono::Utc;
use serde::Deserialize;
use serde_json::Value;
use tokio::sync::Mutex;

use crate::Result;
use crate::agents::{AgentResult, AgentStatus, EngagementPhase};
use crate::limitations::ToolCategory;
use crate::mcp::{McpTool, McpToolResult};
use crate::reports::Report;
use crate::state::MetricsTracker;
use crate::tools::OrchestratorContext;
use crate::tools::report::ReportContext;

/// Maximum length (in bytes) for raw output returned to the MCP client.
/// The actual truncation point is adjusted to the nearest char boundary.
const MAX_OUTPUT_LEN: usize = 8_000;

/// Get required tool categories for an agent type
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

/// Truncate a string to at most `max_len` bytes on a valid UTF-8 boundary.
fn truncate_output(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...[truncated]", &s[..s.floor_char_boundary(max_len)])
    }
}

// ============================================================================
// McpSpawnAgentTool
// ============================================================================

/// MCP wrapper for spawning specialist agents.
///
/// Takes an `OrchestratorContext` and delegates to the same logic as the
/// rig-based `SpawnAgentTool`, but returns results via the MCP protocol.
pub struct McpSpawnAgentTool {
    context: Arc<OrchestratorContext>,
}

#[derive(Debug, Deserialize)]
struct SpawnAgentArgs {
    agent_type: String,
    name: String,
    instructions: String,
}

impl McpSpawnAgentTool {
    pub fn new(context: Arc<OrchestratorContext>) -> Self {
        Self { context }
    }
}

#[async_trait]
impl McpTool for McpSpawnAgentTool {
    fn name(&self) -> &str {
        "spawn_agent"
    }

    fn description(&self) -> &str {
        "Spawn a new specialist agent to run a task in the background. Returns immediately. \
         After calling this, you MUST call wait_for_any() to get results - do not stop or \
         complete the engagement without waiting."
    }

    fn input_schema(&self) -> Value {
        serde_json::json!({
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
        })
    }

    async fn execute(&self, arguments: Value) -> Result<McpToolResult> {
        let args: SpawnAgentArgs = serde_json::from_value(arguments)
            .map_err(|e| crate::Error::Provider(format!("Invalid spawn_agent arguments: {e}")))?;

        // Notify TUI of tool invocation
        self.context.events.send_tool_call();

        // Check if agent type is allowed by engagement limitations
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
            return Ok(McpToolResult::error(msg));
        }

        // Check for duplicate agent name
        let mut registry = self.context.registry.lock().await;

        if registry.has_agent(&args.name) {
            return Ok(McpToolResult::error(format!(
                "Agent '{}' already exists",
                args.name
            )));
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

        // Send feed and status events
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

        // Prepare to spawn the agent task
        let result_tx = registry.result_sender();
        let agent_name = args.name.clone();
        let agent_type = args.agent_type.clone();
        let target = agent_target;
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
                    Err(e) => format!("Error: {e}"),
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
                    Err(e) => format!("Error: {e}"),
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

        Ok(McpToolResult::text(
            serde_json::json!({
                "success": true,
                "message": format!(
                    "Agent '{}' ({}) is now running. Call wait_for_any() to get results.",
                    args.name, args.agent_type
                )
            })
            .to_string(),
        ))
    }
}

// ============================================================================
// McpWaitForAgentTool
// ============================================================================

/// MCP wrapper for waiting on a specific agent to complete.
///
/// Unlike the rig-based version, this does NOT perform LLM summarization.
/// The calling CLI agent can interpret the raw output itself.
pub struct McpWaitForAgentTool {
    context: Arc<OrchestratorContext>,
}

#[derive(Debug, Deserialize)]
struct WaitForAgentArgs {
    name: String,
}

impl McpWaitForAgentTool {
    pub fn new(context: Arc<OrchestratorContext>) -> Self {
        Self { context }
    }
}

#[async_trait]
impl McpTool for McpWaitForAgentTool {
    fn name(&self) -> &str {
        "wait_for_agent"
    }

    fn description(&self) -> &str {
        "Wait for a specific agent to complete and get its results."
    }

    fn input_schema(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Name of the agent to wait for"
                }
            },
            "required": ["name"]
        })
    }

    async fn execute(&self, arguments: Value) -> Result<McpToolResult> {
        let args: WaitForAgentArgs = serde_json::from_value(arguments).map_err(|e| {
            crate::Error::Provider(format!("Invalid wait_for_agent arguments: {e}"))
        })?;

        // Notify TUI of tool invocation
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

        // Brief lock: check agent status
        let is_running = {
            let registry = self.context.registry.lock().await;
            registry.is_agent_running(&args.name)
        };

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

        // Restore orchestrator status
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

                let workflow_hint = if result.agent_type == "report" {
                    "REPORT COMPLETED. You may now call complete_engagement with an executive summary."
                } else if result.agent_type == "recon" {
                    "RECON COMPLETED. Spawn scanner agent(s) to test discovered endpoints, or wait for other agents."
                } else {
                    "Agent completed. Continue with next phase of testing."
                };

                Ok(McpToolResult::text(
                    serde_json::json!({
                        "found": true,
                        "name": result.name,
                        "agent_type": result.agent_type,
                        "success": result.success,
                        "duration_secs": result.duration.as_secs(),
                        "output": truncate_output(&result.output, MAX_OUTPUT_LEN),
                        "workflow_hint": workflow_hint
                    })
                    .to_string(),
                ))
            }
            None => Ok(McpToolResult::error(format!(
                "Agent '{}' not found or already completed",
                args.name
            ))),
        }
    }
}

// ============================================================================
// McpWaitForAnyTool
// ============================================================================

/// MCP wrapper for waiting on any agent to complete.
///
/// Blocks until one of the running agents finishes and returns its results.
/// Does NOT perform LLM summarization -- the CLI agent interprets raw output.
pub struct McpWaitForAnyTool {
    context: Arc<OrchestratorContext>,
}

impl McpWaitForAnyTool {
    pub fn new(context: Arc<OrchestratorContext>) -> Self {
        Self { context }
    }
}

#[async_trait]
impl McpTool for McpWaitForAnyTool {
    fn name(&self) -> &str {
        "wait_for_any"
    }

    fn description(&self) -> &str {
        "REQUIRED after spawn_agent. Blocks until an agent completes and returns its results. \
         You MUST call this after every spawn to get results and decide next steps. \
         Returns remaining_running count."
    }

    fn input_schema(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {}
        })
    }

    async fn execute(&self, _arguments: Value) -> Result<McpToolResult> {
        // Notify TUI of tool invocation
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

        // Brief lock: get remaining count and agent state
        let (remaining_running, has_scanner, has_report) = {
            let registry = self.context.registry.lock().await;
            let remaining = registry.running_count();
            let all_agents = registry.list_agents();
            let scanner = all_agents.iter().any(|(_, t, _)| *t == "scanner");
            let report = all_agents.iter().any(|(_, t, _)| *t == "report");
            (remaining, scanner, report)
        };

        // Restore orchestrator status
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

                // Generate workflow hint based on current state
                let workflow_hint = if result.agent_type == "recon" && !has_scanner {
                    "RECON COMPLETED. You MUST now spawn scanner agent(s) to test the discovered endpoints/services. DO NOT call complete_engagement yet."
                } else if result.agent_type == "scanner" && remaining_running == 0 && !has_report {
                    "ALL SCANNERS COMPLETED. You MUST now spawn a report agent to generate findings. DO NOT call complete_engagement yet."
                } else if result.agent_type == "report" && remaining_running == 0 {
                    "REPORT COMPLETED. You may now call complete_engagement with an executive summary."
                } else if remaining_running > 0 {
                    // Can't use format! directly in a match arm returning &str,
                    // so we handle this case after the match.
                    ""
                } else {
                    "Analyze results and spawn appropriate follow-up agents, or spawn report if all testing is done."
                };

                // Build the dynamic hint for the remaining-running case
                let workflow_hint = if workflow_hint.is_empty() {
                    format!(
                        "{} agent(s) still running. Call wait_for_any again or spawn more agents.",
                        remaining_running
                    )
                } else {
                    workflow_hint.to_string()
                };

                Ok(McpToolResult::text(
                    serde_json::json!({
                        "found": true,
                        "name": result.name,
                        "agent_type": result.agent_type,
                        "success": result.success,
                        "duration_secs": result.duration.as_secs(),
                        "output": truncate_output(&result.output, MAX_OUTPUT_LEN),
                        "remaining_running": remaining_running,
                        "workflow_hint": workflow_hint
                    })
                    .to_string(),
                ))
            }
            None => Ok(McpToolResult::text(
                serde_json::json!({
                    "found": false,
                    "name": "",
                    "agent_type": "",
                    "success": false,
                    "output": "No running agents",
                    "remaining_running": 0,
                    "workflow_hint": "No agents running. Spawn agents to continue the engagement."
                })
                .to_string(),
            )),
        }
    }
}

// ============================================================================
// McpListAgentsTool
// ============================================================================

/// MCP wrapper for listing all spawned agents and their status.
pub struct McpListAgentsTool {
    context: Arc<OrchestratorContext>,
}

impl McpListAgentsTool {
    pub fn new(context: Arc<OrchestratorContext>) -> Self {
        Self { context }
    }
}

#[async_trait]
impl McpTool for McpListAgentsTool {
    fn name(&self) -> &str {
        "list_agents"
    }

    fn description(&self) -> &str {
        "List all spawned agents and their current status."
    }

    fn input_schema(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {}
        })
    }

    async fn execute(&self, _arguments: Value) -> Result<McpToolResult> {
        // Notify TUI of tool invocation
        self.context.events.send_tool_call();

        let registry = self.context.registry.lock().await;
        let agents: Vec<Value> = registry
            .list_agents()
            .iter()
            .map(|(name, agent_type, status)| {
                serde_json::json!({
                    "name": name,
                    "agent_type": agent_type,
                    "status": format!("{status:?}")
                })
            })
            .collect();

        Ok(McpToolResult::text(
            serde_json::json!({ "agents": agents }).to_string(),
        ))
    }
}

// ============================================================================
// McpCompleteEngagementTool
// ============================================================================

/// MCP wrapper for completing the engagement.
///
/// Checks that no agents are still running, records the completion, and
/// triggers cancellation to shut down the agent loop.
pub struct McpCompleteEngagementTool {
    context: Arc<OrchestratorContext>,
}

#[derive(Debug, Deserialize)]
struct CompleteEngagementArgs {
    summary: String,
}

impl McpCompleteEngagementTool {
    pub fn new(context: Arc<OrchestratorContext>) -> Self {
        Self { context }
    }
}

#[async_trait]
impl McpTool for McpCompleteEngagementTool {
    fn name(&self) -> &str {
        "complete_engagement"
    }

    fn description(&self) -> &str {
        "ONLY call after all work is done: spawn recon -> wait_for_any -> spawn scanners -> \
         wait_for_any (repeat until remaining_running=0) -> spawn report -> wait_for_agent -> \
         THEN complete. Will fail if agents are running."
    }

    fn input_schema(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "summary": {
                    "type": "string",
                    "description": "Executive summary of the engagement"
                }
            },
            "required": ["summary"]
        })
    }

    async fn execute(&self, arguments: Value) -> Result<McpToolResult> {
        let args: CompleteEngagementArgs = serde_json::from_value(arguments).map_err(|e| {
            crate::Error::Provider(format!("Invalid complete_engagement arguments: {e}"))
        })?;

        // Notify TUI of tool invocation
        self.context.events.send_tool_call();

        // Check if there are still running agents (any active state)
        let registry = self.context.registry.lock().await;
        let all_agents = registry.list_agents();
        let running_agents: Vec<String> = all_agents
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
            return Ok(McpToolResult::error(msg));
        }

        let findings = self.context.findings.lock().await;
        let findings_count = findings.len();
        drop(findings);

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

        // Mark session as completed in the database
        if let Some(ref db_path) = self.context.session_db_path {
            match rusqlite::Connection::open(db_path) {
                Ok(conn) => {
                    if let Err(e) = conn.execute(
                        "UPDATE session_state SET status = 'completed', last_activity_at = datetime('now') WHERE id = 1",
                        [],
                    ) {
                        self.context.events.send_feed(
                            "orchestrator",
                            &format!("Warning: Failed to persist completion status: {e}"),
                            true,
                        );
                    }
                }
                Err(e) => {
                    self.context.events.send_feed(
                        "orchestrator",
                        &format!("Warning: Failed to open session DB: {e}"),
                        true,
                    );
                }
            }
        }

        // Trigger cancellation to stop the agent loop
        self.context.cancel.cancel();

        Ok(McpToolResult::text(
            serde_json::json!({
                "completed": true,
                "summary": args.summary,
                "findings_count": findings_count
            })
            .to_string(),
        ))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn test_truncate_output_short() {
        let s = "hello world";
        assert_eq!(truncate_output(s, 100), "hello world");
    }

    #[test]
    fn test_truncate_output_long() {
        let s = "a".repeat(200);
        let truncated = truncate_output(&s, 50);
        assert!(truncated.ends_with("...[truncated]"));
        // 50 chars of 'a' + "...[truncated]"
        assert!(truncated.len() < 200);
    }

    #[test]
    fn test_truncate_output_multibyte() {
        // Each character is 3 bytes in UTF-8
        let s = "\u{1F600}".repeat(20); // emoji, 4 bytes each
        let truncated = truncate_output(&s, 10);
        // Should not panic and should end with truncation marker
        assert!(truncated.ends_with("...[truncated]"));
    }

    #[test]
    fn test_agent_required_categories() {
        let recon = agent_required_categories("recon");
        assert!(!recon.is_empty());
        assert!(recon.contains(&ToolCategory::SubdomainEnum));

        let unknown = agent_required_categories("unknown");
        assert!(unknown.is_empty());

        let report = agent_required_categories("report");
        assert!(report.contains(&ToolCategory::Report));
    }

    #[test]
    fn test_spawn_agent_schema() {
        let json = serde_json::json!({
            "agent_type": "recon",
            "name": "subdomain-enum",
            "instructions": "Enumerate subdomains for example.com"
        });
        let args: SpawnAgentArgs = serde_json::from_value(json).expect("should parse args");
        assert_eq!(args.agent_type, "recon");
        assert_eq!(args.name, "subdomain-enum");
    }

    #[test]
    fn test_wait_for_agent_schema() {
        let json = serde_json::json!({ "name": "subdomain-enum" });
        let args: WaitForAgentArgs = serde_json::from_value(json).expect("should parse args");
        assert_eq!(args.name, "subdomain-enum");
    }

    #[test]
    fn test_complete_engagement_schema() {
        let json = serde_json::json!({ "summary": "Engagement complete" });
        let args: CompleteEngagementArgs = serde_json::from_value(json).expect("should parse args");
        assert_eq!(args.summary, "Engagement complete");
    }

    #[test]
    fn test_mcp_tool_names() {
        // Verify tool names are correct and unique
        let names = [
            "spawn_agent",
            "wait_for_agent",
            "wait_for_any",
            "list_agents",
            "complete_engagement",
        ];
        let unique: std::collections::HashSet<&str> = names.iter().copied().collect();
        assert_eq!(names.len(), unique.len(), "Tool names must be unique");
    }
}
