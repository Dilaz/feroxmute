//! Agent execution runner

use std::sync::Arc;

use anyhow::Result;
use feroxmute_core::agents::{
    Agent, AgentRegistry, AgentResult, AgentStatus, OrchestratorAgent, Prompts,
};
use feroxmute_core::docker::ContainerManager;
use feroxmute_core::providers::{CompletionRequest, LlmProvider, Message};
use serde_json;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::tui::AgentEvent;

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

    // Create agent registry
    let mut registry = AgentRegistry::new();

    // Run orchestrator loop with cancellation support
    tokio::select! {
        result = run_orchestrator_loop(&mut orchestrator, &mut registry, &target, &tx, provider.clone(), container.clone(), &prompts) => {
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

/// Inner orchestrator loop that handles tool calls
async fn run_orchestrator_loop(
    orchestrator: &mut OrchestratorAgent,
    registry: &mut AgentRegistry,
    target: &str,
    tx: &mpsc::Sender<AgentEvent>,
    provider: Arc<dyn LlmProvider>,
    container: Arc<ContainerManager>,
    prompts: &Prompts,
) -> Result<String> {
    let max_iterations = 50;
    let mut result = String::new();
    let mut conversation_history: Vec<Message> = Vec::new();

    // Build initial message
    let initial_message = format!(
        "Target: {}\nEngagement Task: Perform security assessment\n\nYou have the following tools:\n\
        - spawn_agent: Spawn agents (recon, scanner{}, report) to run tasks concurrently\n\
        - wait_for_agent: Wait for a specific agent by name\n\
        - wait_for_any: Wait for any agent to complete\n\
        - list_agents: See status of all agents\n\
        - record_finding: Record important findings\n\
        - complete_engagement: Finish the engagement\n\n\
        Start by spawning appropriate agents for reconnaissance.",
        target,
        if orchestrator.has_source_target() { ", sast" } else { "" }
    );

    conversation_history.push(Message::user(&initial_message));

    for iteration in 0..max_iterations {
        let _ = tx
            .send(AgentEvent::Feed {
                agent: "orchestrator".to_string(),
                message: format!("Iteration {}: thinking...", iteration + 1),
                is_error: false,
            })
            .await;

        // Make completion request
        let request = CompletionRequest::new(conversation_history.clone())
            .with_system(orchestrator.system_prompt())
            .with_tools(orchestrator.tools())
            .with_max_tokens(4096);

        let response = provider.complete(request).await?;

        // Add assistant response to history
        if let Some(ref content) = response.content {
            conversation_history.push(Message::assistant(content));
        }

        // Check if there are tool calls
        if !response.tool_calls.is_empty() {
            let mut tool_results = Vec::new();

            for tool_call in &response.tool_calls {
                let tool_name = &tool_call.name;
                // Parse arguments from JSON string to Value
                let args: serde_json::Value = serde_json::from_str(&tool_call.arguments)
                    .unwrap_or(serde_json::json!({}));

                let tool_result = match tool_name.as_str() {
                    "spawn_agent" => {
                        handle_spawn_agent(
                            &args,
                            registry,
                            tx,
                            provider.clone(),
                            container.clone(),
                            prompts,
                            target,
                        )
                        .await
                    }
                    "wait_for_agent" => handle_wait_for_agent(&args, registry, tx).await,
                    "wait_for_any" => handle_wait_for_any(registry, tx).await,
                    "list_agents" => handle_list_agents(registry),
                    "record_finding" => {
                        let finding_result = orchestrator.handle_record_finding(&args);
                        finding_result
                    }
                    "complete_engagement" => {
                        result = orchestrator.handle_complete_engagement(&args);
                        return Ok(result);
                    }
                    _ => format!("Unknown tool: {}", tool_name),
                };

                let _ = tx
                    .send(AgentEvent::Feed {
                        agent: "orchestrator".to_string(),
                        message: format!("[{}] {}", tool_name, tool_result),
                        is_error: false,
                    })
                    .await;

                tool_results.push((tool_name.clone(), tool_result));
            }

            // Add tool results to conversation as user messages
            for (tool_name, tool_result) in tool_results {
                let result_message = format!("Tool '{}' returned: {}", tool_name, tool_result);
                conversation_history.push(Message::user(&result_message));
            }
        } else if let Some(content) = response.content {
            // No tool calls, just text response
            result.push_str(&content);
            result.push('\n');
        }
    }

    Ok(result)
}

async fn handle_spawn_agent(
    args: &serde_json::Value,
    registry: &mut AgentRegistry,
    tx: &mpsc::Sender<AgentEvent>,
    provider: Arc<dyn LlmProvider>,
    container: Arc<ContainerManager>,
    prompts: &Prompts,
    target: &str,
) -> String {
    let agent_type = args["agent_type"].as_str().unwrap_or("recon");
    let name = args["name"].as_str().unwrap_or("unnamed");
    let instructions = args["instructions"].as_str().unwrap_or("");

    if registry.has_agent(name) {
        return format!("Agent '{}' already exists", name);
    }

    // Get base prompt for agent type
    let base_prompt = prompts.get(agent_type).unwrap_or("");
    let full_prompt = format!(
        "{}\n\n---\n\n## Task from Orchestrator\n\nName: {}\nInstructions: {}\nTarget: {}",
        base_prompt, name, instructions, target
    );

    let _ = tx
        .send(AgentEvent::Feed {
            agent: name.to_string(),
            message: format!("Spawned: {}", instructions),
            is_error: false,
        })
        .await;

    let _ = tx
        .send(AgentEvent::Status {
            agent: agent_type.to_string(),
            status: AgentStatus::Running,
        })
        .await;

    // Spawn agent task
    let result_tx = registry.result_sender();
    let agent_name = name.to_string();
    let agent_type_str = agent_type.to_string();
    let target_owned = target.to_string();

    let handle = tokio::spawn(async move {
        let start = std::time::Instant::now();

        // Run agent with shell tool
        let output = match provider
            .complete_with_shell(&full_prompt, &target_owned, container)
            .await
        {
            Ok(out) => out,
            Err(e) => format!("Error: {}", e),
        };

        let success = !output.starts_with("Error:");

        let _ = result_tx
            .send(AgentResult {
                name: agent_name.clone(),
                agent_type: agent_type_str,
                success,
                output,
                duration: start.elapsed(),
            })
            .await;
    });

    registry.register(
        name.to_string(),
        agent_type.to_string(),
        instructions.to_string(),
        handle,
    );

    format!("Spawned agent '{}' ({})", name, agent_type)
}

async fn handle_wait_for_agent(
    args: &serde_json::Value,
    registry: &mut AgentRegistry,
    tx: &mpsc::Sender<AgentEvent>,
) -> String {
    let name = args["name"].as_str().unwrap_or("");

    let _ = tx
        .send(AgentEvent::Feed {
            agent: "orchestrator".to_string(),
            message: format!("Waiting for agent '{}'...", name),
            is_error: false,
        })
        .await;

    match registry.wait_for_agent(name).await {
        Some(result) => {
            let _ = tx
                .send(AgentEvent::Status {
                    agent: result.agent_type.clone(),
                    status: if result.success {
                        AgentStatus::Completed
                    } else {
                        AgentStatus::Failed
                    },
                })
                .await;

            format!(
                "Agent '{}' completed ({}): {}",
                result.name,
                if result.success { "success" } else { "failed" },
                truncate_output(&result.output, 500)
            )
        }
        None => format!("Agent '{}' not found", name),
    }
}

async fn handle_wait_for_any(
    registry: &mut AgentRegistry,
    tx: &mpsc::Sender<AgentEvent>,
) -> String {
    let _ = tx
        .send(AgentEvent::Feed {
            agent: "orchestrator".to_string(),
            message: "Waiting for any agent to complete...".to_string(),
            is_error: false,
        })
        .await;

    match registry.wait_for_any().await {
        Some(result) => {
            let _ = tx
                .send(AgentEvent::Status {
                    agent: result.agent_type.clone(),
                    status: if result.success {
                        AgentStatus::Completed
                    } else {
                        AgentStatus::Failed
                    },
                })
                .await;

            format!(
                "Agent '{}' completed ({}): {}",
                result.name,
                if result.success { "success" } else { "failed" },
                truncate_output(&result.output, 500)
            )
        }
        None => "No running agents".to_string(),
    }
}

fn handle_list_agents(registry: &AgentRegistry) -> String {
    let agents = registry.list_agents();
    if agents.is_empty() {
        "No agents spawned yet".to_string()
    } else {
        agents
            .iter()
            .map(|(name, agent_type, status)| format!("- {} ({}): {:?}", name, agent_type, status))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

fn truncate_output(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len])
    }
}
