//! Agent execution runner

use std::sync::Arc;

use anyhow::Result;
use feroxmute_core::agents::{
    Agent, AgentRegistry, AgentStatus, EngagementPhase, OrchestratorAgent, Prompts,
};
use feroxmute_core::docker::ContainerManager;
use feroxmute_core::limitations::EngagementLimitations;
use feroxmute_core::providers::LlmProvider;
use feroxmute_core::state::models::FindingType;
use feroxmute_core::state::Severity;
use feroxmute_core::tools::{EventSender, MemoryContext, OrchestratorContext};
use tokio::sync::{mpsc, Mutex};
use tokio_util::sync::CancellationToken;

use crate::tui::channel::{CodeFindingEvent, MemoryEntry};
use crate::tui::{AgentEvent, VulnSeverity};

/// Event sender implementation that wraps the TUI channel
struct TuiEventSender {
    tx: mpsc::Sender<AgentEvent>,
}

impl TuiEventSender {
    fn new(tx: mpsc::Sender<AgentEvent>) -> Self {
        Self { tx }
    }
}

impl EventSender for TuiEventSender {
    fn send_feed(&self, agent: &str, message: &str, is_error: bool) {
        let tx = self.tx.clone();
        let agent = agent.to_string();
        let message = message.to_string();
        // Fire and forget - we don't want to block on sending
        tokio::spawn(async move {
            let _ = tx
                .send(AgentEvent::Feed {
                    agent,
                    message,
                    is_error,
                    tool_output: None,
                })
                .await;
        });
    }

    fn send_feed_with_output(&self, agent: &str, message: &str, is_error: bool, output: &str) {
        let tx = self.tx.clone();
        let agent = agent.to_string();
        let message = message.to_string();
        let output = output.to_string();
        tokio::spawn(async move {
            let _ = tx
                .send(AgentEvent::Feed {
                    agent,
                    message,
                    is_error,
                    tool_output: Some(output),
                })
                .await;
        });
    }

    fn send_status(
        &self,
        agent: &str,
        agent_type: &str,
        status: AgentStatus,
        current_tool: Option<String>,
    ) {
        let tx = self.tx.clone();
        let agent = agent.to_string();
        let agent_type = agent_type.to_string();
        tokio::spawn(async move {
            let _ = tx
                .send(AgentEvent::Status {
                    agent,
                    agent_type,
                    status,
                    current_tool,
                })
                .await;
        });
    }

    fn send_metrics(
        &self,
        input: u64,
        output: u64,
        cache_read: u64,
        cost_usd: f64,
        tool_calls: u64,
    ) {
        let tx = self.tx.clone();
        tokio::spawn(async move {
            let _ = tx
                .send(AgentEvent::Metrics {
                    input,
                    output,
                    cache_read,
                    cost_usd,
                    tool_calls,
                })
                .await;
        });
    }

    fn send_vulnerability(&self, severity: Severity, title: &str) {
        let tx = self.tx.clone();
        let vuln_severity = match severity {
            Severity::Critical => VulnSeverity::Critical,
            Severity::High => VulnSeverity::High,
            Severity::Medium => VulnSeverity::Medium,
            Severity::Low => VulnSeverity::Low,
            Severity::Info => VulnSeverity::Info,
        };
        let title = title.to_string();
        tokio::spawn(async move {
            let _ = tx
                .send(AgentEvent::Vulnerability {
                    severity: vuln_severity,
                    title,
                })
                .await;
        });
    }

    fn send_thinking(&self, agent: &str, content: Option<String>) {
        let tx = self.tx.clone();
        let agent = agent.to_string();
        tokio::spawn(async move {
            let _ = tx.send(AgentEvent::Thinking { agent, content }).await;
        });
    }

    fn send_phase(&self, phase: EngagementPhase) {
        let tx = self.tx.clone();
        tokio::spawn(async move {
            let _ = tx.send(AgentEvent::Phase { phase }).await;
        });
    }

    fn send_summary(&self, agent: &str, summary: &feroxmute_core::tools::AgentSummary) {
        let tx = self.tx.clone();
        let agent = agent.to_string();
        let success = summary.success;
        let summary_text = summary.summary.clone();
        let key_findings = summary.key_findings.clone();
        let next_steps = summary.next_steps.clone();
        let raw_output = summary.raw_output.clone();
        tokio::spawn(async move {
            let _ = tx
                .send(AgentEvent::Summary {
                    agent,
                    success,
                    summary: summary_text,
                    key_findings,
                    next_steps,
                    raw_output,
                })
                .await;
        });
    }

    fn send_memory_update(&self, entries: Vec<feroxmute_core::tools::MemoryEntryData>) {
        let tx = self.tx.clone();
        // Convert core MemoryEntryData to TUI MemoryEntry
        let tui_entries: Vec<MemoryEntry> = entries
            .into_iter()
            .map(|e| MemoryEntry {
                key: e.key,
                value: e.value,
                created_at: e.created_at,
                updated_at: e.updated_at,
            })
            .collect();
        tokio::spawn(async move {
            let _ = tx
                .send(AgentEvent::MemoryUpdated {
                    entries: tui_entries,
                })
                .await;
        });
    }

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
    ) {
        let tx = self.tx.clone();
        let agent = agent.to_string();
        let finding = CodeFindingEvent {
            file_path: file_path.to_string(),
            line_number,
            severity,
            finding_type,
            title: title.to_string(),
            tool: tool.to_string(),
            cve_id: cve_id.map(String::from),
            package_name: package_name.map(String::from),
        };
        tokio::spawn(async move {
            let _ = tx.send(AgentEvent::CodeFinding { agent, finding }).await;
        });
    }
}

/// Run the orchestrator agent with TUI feedback
#[allow(clippy::too_many_arguments)]
pub async fn run_orchestrator(
    target: String,
    provider: Arc<dyn LlmProvider>,
    container: Arc<ContainerManager>,
    tx: mpsc::Sender<AgentEvent>,
    cancel: CancellationToken,
    source_path: Option<String>,
    limitations: Arc<EngagementLimitations>,
    instruction: Option<String>,
    session: Arc<feroxmute_core::state::Session>,
) -> Result<()> {
    use std::sync::atomic::{AtomicBool, Ordering};

    // Send initial status
    let _ = tx
        .send(AgentEvent::Status {
            agent: "orchestrator".to_string(),
            agent_type: "orchestrator".to_string(),
            status: AgentStatus::Streaming,
            current_tool: None,
        })
        .await;

    let _ = tx
        .send(AgentEvent::Feed {
            agent: "orchestrator".to_string(),
            message: format!("Starting engagement orchestration for {}", target),
            is_error: false,
            tool_output: None,
        })
        .await;

    // Create orchestrator
    let prompts = Prompts::default();
    let mut orchestrator = OrchestratorAgent::with_prompts(prompts.clone());
    if source_path.is_some() {
        orchestrator = orchestrator.with_source_target();
    }

    // Create flag to distinguish engagement completion from user cancellation
    let engagement_completed = Arc::new(AtomicBool::new(false));

    // Run orchestrator with new provider method
    tokio::select! {
        result = run_orchestrator_with_tools(&orchestrator, &target, &tx, Arc::clone(&provider), Arc::clone(&container), &prompts, cancel.clone(), source_path.clone(), Arc::clone(&limitations), instruction, Arc::clone(&engagement_completed), Arc::clone(&session)) => {
            match result {
                Ok(output) => {
                    // Check if engagement was properly completed via complete_engagement tool
                    let completed = engagement_completed.load(Ordering::SeqCst);

                    if completed {
                        let _ = tx.send(AgentEvent::Status {
                            agent: "orchestrator".to_string(),
                            agent_type: "orchestrator".to_string(),
                            status: AgentStatus::Completed,
                            current_tool: None,
                        }).await;

                        let _ = tx.send(AgentEvent::Finished {
                            success: true,
                            message: format!("Engagement complete.\n{}", output),
                        }).await;
                    } else {
                        // Orchestrator ended without calling complete_engagement
                        let _ = tx.send(AgentEvent::Status {
                            agent: "orchestrator".to_string(),
                            agent_type: "orchestrator".to_string(),
                            status: AgentStatus::Failed,
                            current_tool: None,
                        }).await;

                        let _ = tx.send(AgentEvent::Finished {
                            success: false,
                            message: format!("Engagement ended prematurely - orchestrator stopped without completing the full workflow (recon → scanner → report → complete). Last output:\n{}", output),
                        }).await;
                    }
                }
                Err(e) => {
                    let _ = tx.send(AgentEvent::Status {
                        agent: "orchestrator".to_string(),
                        agent_type: "orchestrator".to_string(),
                        status: AgentStatus::Failed,
                        current_tool: None,
                    }).await;

                    let _ = tx.send(AgentEvent::Finished {
                        success: false,
                        message: format!("Engagement failed: {}", e),
                    }).await;
                }
            }
        }
        _ = cancel.cancelled() => {
            // Check if this was engagement completion or user cancellation
            let completed = engagement_completed.load(Ordering::SeqCst);

            if completed {
                // Engagement completed successfully via complete_engagement tool
                let _ = tx.send(AgentEvent::Status {
                    agent: "orchestrator".to_string(),
                    agent_type: "orchestrator".to_string(),
                    status: AgentStatus::Completed,
                    current_tool: None,
                }).await;

                let _ = tx.send(AgentEvent::Finished {
                    success: true,
                    message: "Engagement completed successfully".to_string(),
                }).await;
            } else {
                // User-initiated cancellation
                let _ = tx.send(AgentEvent::Feed {
                    agent: "orchestrator".to_string(),
                    message: "Cancelled by user".to_string(),
                    is_error: false,
                    tool_output: None,
                }).await;

                let _ = tx.send(AgentEvent::Status {
                    agent: "orchestrator".to_string(),
                    agent_type: "orchestrator".to_string(),
                    status: AgentStatus::Idle,
                    current_tool: None,
                }).await;
            }
        }
    }

    Ok(())
}

/// Run orchestrator using rig's built-in tool loop
#[allow(clippy::too_many_arguments)]
async fn run_orchestrator_with_tools(
    orchestrator: &OrchestratorAgent,
    target: &str,
    tx: &mpsc::Sender<AgentEvent>,
    provider: Arc<dyn LlmProvider>,
    container: Arc<ContainerManager>,
    prompts: &Prompts,
    cancel: CancellationToken,
    source_path: Option<String>,
    limitations: Arc<EngagementLimitations>,
    instruction: Option<String>,
    engagement_completed: Arc<std::sync::atomic::AtomicBool>,
    session: Arc<feroxmute_core::state::Session>,
) -> Result<String> {
    // Create TuiEventSender first so it can be shared
    let events: Arc<dyn feroxmute_core::tools::EventSender> =
        Arc::new(TuiEventSender::new(tx.clone()));

    // Use session DB for persistent storage.
    // We open a separate connection because the MemoryContext wraps it in Arc<Mutex<>>
    // for concurrent access from async tool calls, while Session owns its main connection.
    let memory_conn = session
        .open_connection()
        .map_err(|e| anyhow::anyhow!("Failed to open session DB: {}", e))?;
    let memory_context = Arc::new(MemoryContext {
        conn: Arc::new(Mutex::new(memory_conn)),
        events: Arc::clone(&events),
        agent_name: "orchestrator".to_string(),
    });

    // Create the orchestrator context with all shared state
    let context = Arc::new(OrchestratorContext {
        registry: Arc::new(Mutex::new(AgentRegistry::new())),
        provider: Arc::clone(&provider),
        container,
        events,
        cancel,
        prompts: prompts.clone(),
        target: target.to_string(),
        findings: Arc::new(Mutex::new(Vec::new())),
        limitations: Arc::clone(&limitations),
        memory: memory_context,
        engagement_completed,
        source_path: source_path.clone(),
    });

    let has_source_target = source_path.is_some();

    // Build user prompt with limitations
    let engagement_task = match &instruction {
        Some(instr) => format!(
            "Engagement Task: Perform security assessment\n\nAdditional Objective: {}",
            instr
        ),
        None => "Engagement Task: Perform security assessment".to_string(),
    };

    let source_section = if has_source_target {
        "\n\n## Source Code Available - IMPORTANT\n\
        You have access to the target's SOURCE CODE. This is a significant advantage.\n\n\
        **Your FIRST action must be to spawn BOTH agents in parallel:**\n\
        1. spawn_agent(sast) - Analyze source for vulnerabilities, hardcoded secrets, API keys, and security issues\n\
        2. spawn_agent(recon) - Map the live target's attack surface\n\n\
        Running SAST and recon in parallel is optimal - SAST findings (like hardcoded credentials, \
        API endpoints in code, or vulnerable dependencies) directly inform what the scanner should test."
    } else {
        ""
    };

    let workflow = if has_source_target {
        "WORKFLOW: spawn_agent(sast) AND spawn_agent(recon) IN PARALLEL -> wait_for_any (repeat until both done) -> spawn scanner (informed by both sast and recon findings) -> wait_for_any -> spawn report -> wait_for_agent -> complete_engagement."
    } else {
        "WORKFLOW: spawn_agent(recon) -> wait_for_any -> spawn scanner -> wait_for_any -> spawn report -> wait_for_agent -> complete_engagement."
    };

    let user_prompt = format!(
        "Target: {}\n\n{}\n\n{}{}\n\n\
        Available agent types: recon, scanner{}, report.\n\n\
        {}\n\n\
        CRITICAL: After EVERY spawn_agent call, you MUST call wait_for_any() to get results. Never stop without waiting for spawned agents.\n\n\
        {}",
        target,
        limitations.to_prompt_section(),
        engagement_task,
        source_section,
        if has_source_target { ", sast" } else { "" },
        workflow,
        if has_source_target {
            "START NOW: Spawn both 'sast' and 'recon' agents immediately (two spawn_agent calls), then wait_for_any()."
        } else {
            "Start by spawning a recon agent, then call wait_for_any() to get its results."
        }
    );

    // Use rig's built-in tool loop via the provider
    let result = provider
        .complete_with_orchestrator(orchestrator.system_prompt(), &user_prompt, context)
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    Ok(result)
}
