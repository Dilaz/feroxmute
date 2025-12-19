//! Agent execution runner

use std::sync::Arc;

use anyhow::Result;
use feroxmute_core::agents::{Agent, AgentContext, AgentStatus, AgentTask, ReconAgent};
use feroxmute_core::docker::ContainerManager;
use feroxmute_core::providers::LlmProvider;
use feroxmute_core::state::MetricsTracker;
use feroxmute_core::tools::ToolExecutor;
use rusqlite::Connection;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::tui::AgentEvent;

/// Run the recon agent with TUI feedback
pub async fn run_recon_agent(
    target: String,
    provider: Arc<dyn LlmProvider>,
    container: ContainerManager,
    metrics: MetricsTracker,
    conn: Connection,
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

    // Create agent and executor
    let mut agent = ReconAgent::new();
    let executor = ToolExecutor::new(container, metrics);

    // Create task
    let task = AgentTask::new("recon-main", "recon", format!("Reconnaissance of {}", target));

    // Create context
    let ctx = AgentContext::new(provider.as_ref(), &executor, &conn, &target);

    // Run with cancellation support
    tokio::select! {
        result = agent.execute(&task, &ctx) => {
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
