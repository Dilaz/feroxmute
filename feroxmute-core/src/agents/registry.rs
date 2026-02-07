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
}

/// Receives agent results without holding the registry lock.
///
/// This is separated from `AgentRegistry` so that waiting on the channel
/// (an async operation) does not block other registry operations like
/// spawn, list, or status updates.
pub struct AgentResultWaiter {
    result_rx: mpsc::Receiver<AgentResult>,
    pending_results: Vec<AgentResult>,
}

impl AgentRegistry {
    /// Create a new agent registry and its companion result waiter
    pub fn new() -> (Self, AgentResultWaiter) {
        let (result_tx, result_rx) = mpsc::channel(128);
        (
            Self {
                agents: HashMap::new(),
                result_tx,
            },
            AgentResultWaiter {
                result_rx,
                pending_results: Vec::new(),
            },
        )
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

    /// Check if an agent is still running (not completed/failed)
    pub fn is_agent_running(&self, name: &str) -> Option<bool> {
        self.agents
            .get(name)
            .map(|a| !matches!(a.status, AgentStatus::Completed | AgentStatus::Failed))
    }

    /// Update an agent's status based on a result
    pub fn mark_agent_result(&mut self, name: &str, success: bool) {
        if let Some(agent) = self.agents.get_mut(name) {
            agent.status = if success {
                AgentStatus::Completed
            } else {
                AgentStatus::Failed
            };
        }
    }
}

impl AgentResultWaiter {
    /// Wait for a specific agent's result.
    ///
    /// Results for other agents are buffered in `pending_results`.
    /// Returns `None` if the channel is closed before the target agent reports.
    pub async fn wait_for_agent(&mut self, name: &str) -> Option<AgentResult> {
        // Check pending results first
        if let Some(idx) = self.pending_results.iter().position(|r| r.name == name) {
            return Some(self.pending_results.remove(idx));
        }

        // Wait for results from channel
        while let Some(result) = self.result_rx.recv().await {
            if result.name == name {
                return Some(result);
            }
            // Store for later
            self.pending_results.push(result);
        }

        None
    }

    /// Wait for any agent's result.
    ///
    /// Returns a pending result if available, otherwise waits on the channel.
    pub async fn wait_for_any(&mut self) -> Option<AgentResult> {
        // Check pending results first
        if !self.pending_results.is_empty() {
            return Some(self.pending_results.remove(0));
        }

        // Wait for next result
        self.result_rx.recv().await
    }

    /// Check if there are buffered pending results
    pub fn has_pending(&self) -> bool {
        !self.pending_results.is_empty()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_creation() {
        let (registry, _waiter) = AgentRegistry::new();
        assert_eq!(registry.running_count(), 0);
        assert!(registry.list_agents().is_empty());
    }

    #[test]
    fn test_has_agent() {
        let (registry, _waiter) = AgentRegistry::new();
        assert!(!registry.has_agent("test-agent"));
    }

    #[tokio::test]
    async fn test_wait_for_any_no_pending() {
        let (_registry, waiter) = AgentRegistry::new();
        assert!(!waiter.has_pending());
    }

    #[tokio::test]
    async fn test_get_agent_instructions() {
        let (mut registry, _waiter) = AgentRegistry::new();

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

    #[tokio::test]
    async fn test_is_agent_running() {
        let (mut registry, _waiter) = AgentRegistry::new();

        assert_eq!(registry.is_agent_running("nonexistent"), None);

        let handle = tokio::spawn(async {});
        registry.register(
            "agent-1".to_string(),
            "recon".to_string(),
            "test".to_string(),
            handle,
        );

        assert_eq!(registry.is_agent_running("agent-1"), Some(true));

        registry.mark_agent_result("agent-1", true);
        assert_eq!(registry.is_agent_running("agent-1"), Some(false));
    }
}
