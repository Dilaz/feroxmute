//! Agent registry for managing spawned agents

use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::AgentStatus;

/// Result from a completed agent
#[derive(Debug, Clone)]
pub struct AgentResult {
    pub name: String,
    pub agent_type: String,
    pub success: bool,
    pub output: String,
    pub duration: Duration,
}

/// A spawned agent being tracked by the registry
pub struct SpawnedAgent {
    pub name: String,
    pub agent_type: String,
    pub instructions: String,
    pub status: AgentStatus,
    pub spawned_at: Instant,
    pub handle: Option<JoinHandle<()>>,
}

/// Registry for managing spawned agents
pub struct AgentRegistry {
    agents: HashMap<String, SpawnedAgent>,
    result_tx: mpsc::Sender<AgentResult>,
    result_rx: mpsc::Receiver<AgentResult>,
    pending_results: Vec<AgentResult>,
}

impl AgentRegistry {
    /// Create a new agent registry
    pub fn new() -> Self {
        let (result_tx, result_rx) = mpsc::channel(32);
        Self {
            agents: HashMap::new(),
            result_tx,
            result_rx,
            pending_results: Vec::new(),
        }
    }

    /// Get the sender for agent results
    pub fn result_sender(&self) -> mpsc::Sender<AgentResult> {
        self.result_tx.clone()
    }

    /// Register a spawned agent
    pub fn register(
        &mut self,
        name: String,
        agent_type: String,
        instructions: String,
        handle: JoinHandle<()>,
    ) {
        let agent = SpawnedAgent {
            name: name.clone(),
            agent_type,
            instructions,
            status: AgentStatus::Streaming,
            spawned_at: Instant::now(),
            handle: Some(handle),
        };
        self.agents.insert(name, agent);
    }

    /// Check if an agent with the given name exists
    pub fn has_agent(&self, name: &str) -> bool {
        self.agents.contains_key(name)
    }

    /// Get the status of all agents
    pub fn list_agents(&self) -> Vec<(&str, &str, AgentStatus)> {
        self.agents
            .values()
            .map(|a| (a.name.as_str(), a.agent_type.as_str(), a.status))
            .collect()
    }

    /// Get the instructions for a specific agent
    pub fn get_agent_instructions(&self, name: &str) -> Option<String> {
        self.agents.get(name).map(|a| a.instructions.clone())
    }

    /// Get count of running agents (any active state)
    pub fn running_count(&self) -> usize {
        self.agents
            .values()
            .filter(|a| {
                matches!(
                    a.status,
                    AgentStatus::Thinking
                        | AgentStatus::Streaming
                        | AgentStatus::Executing
                        | AgentStatus::Processing
                )
            })
            .count()
    }

    /// Wait for a specific agent to complete
    /// Returns None if agent doesn't exist or already completed, Some(result) when complete
    pub async fn wait_for_agent(&mut self, name: &str) -> Option<AgentResult> {
        // Check if agent exists and is still running
        match self.agents.get(name) {
            None => return None,
            Some(agent) => {
                // Agent already completed - result was already consumed
                if matches!(agent.status, AgentStatus::Completed | AgentStatus::Failed) {
                    return None;
                }
            }
        }

        // Check pending results first
        if let Some(idx) = self.pending_results.iter().position(|r| r.name == name) {
            let result = self.pending_results.remove(idx);
            if let Some(agent) = self.agents.get_mut(name) {
                agent.status = if result.success {
                    AgentStatus::Completed
                } else {
                    AgentStatus::Failed
                };
            }
            return Some(result);
        }

        // Wait for results from channel
        while let Some(result) = self.result_rx.recv().await {
            if result.name == name {
                if let Some(agent) = self.agents.get_mut(name) {
                    agent.status = if result.success {
                        AgentStatus::Completed
                    } else {
                        AgentStatus::Failed
                    };
                }
                return Some(result);
            } else {
                // Store for later
                self.pending_results.push(result);
            }
        }

        None
    }

    /// Wait for any agent to complete
    /// Returns None if no agents are running
    pub async fn wait_for_any(&mut self) -> Option<AgentResult> {
        if self.running_count() == 0 && self.pending_results.is_empty() {
            return None;
        }

        // Check pending results first
        if !self.pending_results.is_empty() {
            let result = self.pending_results.remove(0);
            if let Some(agent) = self.agents.get_mut(&result.name) {
                agent.status = if result.success {
                    AgentStatus::Completed
                } else {
                    AgentStatus::Failed
                };
            }
            return Some(result);
        }

        // Wait for next result
        if let Some(result) = self.result_rx.recv().await {
            if let Some(agent) = self.agents.get_mut(&result.name) {
                agent.status = if result.success {
                    AgentStatus::Completed
                } else {
                    AgentStatus::Failed
                };
            }
            return Some(result);
        }

        None
    }
}

impl Default for AgentRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_creation() {
        let registry = AgentRegistry::new();
        assert_eq!(registry.running_count(), 0);
        assert!(registry.list_agents().is_empty());
    }

    #[test]
    fn test_has_agent() {
        let registry = AgentRegistry::new();
        assert!(!registry.has_agent("test-agent"));
    }

    #[tokio::test]
    async fn test_wait_for_any_no_agents() {
        let mut registry = AgentRegistry::new();
        let result = registry.wait_for_any().await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_wait_for_agent_not_found() {
        let mut registry = AgentRegistry::new();
        let result = registry.wait_for_agent("nonexistent").await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_get_agent_instructions() {
        let mut registry = AgentRegistry::new();

        // Register a mock agent
        let handle = tokio::spawn(async {});
        registry.register(
            "test-agent".to_string(),
            "recon".to_string(),
            "Enumerate subdomains for example.com".to_string(),
            handle,
        );

        let instructions = registry.get_agent_instructions("test-agent");
        assert_eq!(
            instructions,
            Some("Enumerate subdomains for example.com".to_string())
        );

        let missing = registry.get_agent_instructions("nonexistent");
        assert_eq!(missing, None);
    }
}
