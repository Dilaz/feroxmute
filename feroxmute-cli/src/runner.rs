//! Agent execution runner

use std::sync::Arc;

use anyhow::Result;
use feroxmute_core::agents::{AgentStatus, Prompts};
use feroxmute_core::docker::ContainerManager;
use feroxmute_core::providers::LlmProvider;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::tui::AgentEvent;

/// Run the recon agent with TUI feedback
pub async fn run_recon_agent(
    target: String,
    provider: Arc<dyn LlmProvider>,
    container: ContainerManager,
    tx: mpsc::Sender<AgentEvent>,
    cancel: CancellationToken,
) -> Result<()> {
    // Send initial status
    let _ = tx
        .send(AgentEvent::Status {
            agent: "recon".to_string(),
            status: AgentStatus::Running,
        })
        .await;

    let _ = tx
        .send(AgentEvent::Feed {
            agent: "recon".to_string(),
            message: format!("Starting reconnaissance on {}", target),
            is_error: false,
        })
        .await;

    // Load prompts and build user prompt
    let prompts = Prompts::default();
    let system_prompt = prompts.get("recon").unwrap_or("");
    let user_prompt = format!("Perform reconnaissance on {}", target);

    // Wrap container in Arc for the shell tool
    let container = Arc::new(container);

    // Run with cancellation support using rig's tool loop
    tokio::select! {
        result = provider.complete_with_shell(system_prompt, &user_prompt, container) => {
            match result {
                Ok(output) => {
                    let _ = tx.send(AgentEvent::Status {
                        agent: "recon".to_string(),
                        status: AgentStatus::Completed,
                    }).await;

                    let _ = tx.send(AgentEvent::Finished {
                        success: true,
                        message: format!("Reconnaissance complete. Output:\n{}", output),
                    }).await;
                }
                Err(e) => {
                    let _ = tx.send(AgentEvent::Status {
                        agent: "recon".to_string(),
                        status: AgentStatus::Failed,
                    }).await;

                    let _ = tx.send(AgentEvent::Finished {
                        success: false,
                        message: format!("Reconnaissance failed: {}", e),
                    }).await;
                }
            }
        }
        _ = cancel.cancelled() => {
            let _ = tx.send(AgentEvent::Feed {
                agent: "recon".to_string(),
                message: "Cancelled by user".to_string(),
                is_error: false,
            }).await;

            let _ = tx.send(AgentEvent::Status {
                agent: "recon".to_string(),
                status: AgentStatus::Idle,
            }).await;
        }
    }

    Ok(())
}
