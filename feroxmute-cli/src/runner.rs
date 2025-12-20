//! Agent execution runner

use std::sync::Arc;

use anyhow::Result;
use feroxmute_core::agents::{Agent, AgentRegistry, AgentStatus, OrchestratorAgent, Prompts};
use feroxmute_core::docker::ContainerManager;
use feroxmute_core::providers::LlmProvider;
use feroxmute_core::tools::{EventSender, OrchestratorContext};
use tokio::sync::{mpsc, Mutex};
use tokio_util::sync::CancellationToken;

use crate::tui::AgentEvent;

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
                })
                .await;
        });
    }

    fn send_status(&self, agent: &str, status: AgentStatus) {
        let tx = self.tx.clone();
        let agent = agent.to_string();
        tokio::spawn(async move {
            let _ = tx.send(AgentEvent::Status { agent, status }).await;
        });
    }
}

/// Run the orchestrator agent with TUI feedback
pub async fn run_orchestrator(
    target: String,
    provider: Arc<dyn LlmProvider>,
    container: Arc<ContainerManager>,
    tx: mpsc::Sender<AgentEvent>,
    cancel: CancellationToken,
    has_source_target: bool,
) -> Result<()> {
    // Send initial status
    let _ = tx
        .send(AgentEvent::Status {
            agent: "orchestrator".to_string(),
            status: AgentStatus::Running,
        })
        .await;

    let _ = tx
        .send(AgentEvent::Feed {
            agent: "orchestrator".to_string(),
            message: format!("Starting engagement orchestration for {}", target),
            is_error: false,
        })
        .await;

    // Create orchestrator
    let prompts = Prompts::default();
    let mut orchestrator = OrchestratorAgent::with_prompts(prompts.clone());
    if has_source_target {
        orchestrator = orchestrator.with_source_target();
    }

    // Run orchestrator with new provider method
    tokio::select! {
        result = run_orchestrator_with_tools(&orchestrator, &target, &tx, Arc::clone(&provider), Arc::clone(&container), &prompts, cancel.clone(), has_source_target) => {
            match result {
                Ok(output) => {
                    let _ = tx.send(AgentEvent::Status {
                        agent: "orchestrator".to_string(),
                        status: AgentStatus::Completed,
                    }).await;

                    let _ = tx.send(AgentEvent::Finished {
                        success: true,
                        message: format!("Engagement complete.\n{}", output),
                    }).await;
                }
                Err(e) => {
                    let _ = tx.send(AgentEvent::Status {
                        agent: "orchestrator".to_string(),
                        status: AgentStatus::Failed,
                    }).await;

                    let _ = tx.send(AgentEvent::Finished {
                        success: false,
                        message: format!("Engagement failed: {}", e),
                    }).await;
                }
            }
        }
        _ = cancel.cancelled() => {
            let _ = tx.send(AgentEvent::Feed {
                agent: "orchestrator".to_string(),
                message: "Cancelled by user".to_string(),
                is_error: false,
            }).await;

            let _ = tx.send(AgentEvent::Status {
                agent: "orchestrator".to_string(),
                status: AgentStatus::Idle,
            }).await;
        }
    }

    Ok(())
}

/// Run orchestrator using rig's built-in tool loop
async fn run_orchestrator_with_tools(
    orchestrator: &OrchestratorAgent,
    target: &str,
    tx: &mpsc::Sender<AgentEvent>,
    provider: Arc<dyn LlmProvider>,
    container: Arc<ContainerManager>,
    prompts: &Prompts,
    cancel: CancellationToken,
    has_source_target: bool,
) -> Result<String> {
    // Create the orchestrator context with all shared state
    let context = Arc::new(OrchestratorContext {
        registry: Arc::new(Mutex::new(AgentRegistry::new())),
        provider: Arc::clone(&provider),
        container,
        events: Arc::new(TuiEventSender::new(tx.clone())),
        cancel,
        prompts: prompts.clone(),
        target: target.to_string(),
        findings: Arc::new(Mutex::new(Vec::new())),
    });

    // Build user prompt
    let user_prompt = format!(
        "Target: {}\nEngagement Task: Perform security assessment\n\n\
        You have tools to spawn agents (recon, scanner{}, report), wait for them, \
        record findings, and complete the engagement.\n\n\
        Start by spawning appropriate agents for reconnaissance.",
        target,
        if has_source_target { ", sast" } else { "" }
    );

    // Use rig's built-in tool loop via the provider
    let result = provider
        .complete_with_orchestrator(orchestrator.system_prompt(), &user_prompt, context)
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    Ok(result)
}
