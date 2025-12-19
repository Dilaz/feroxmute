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
            status: AgentStatus::Running,
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

    /// Get count of running agents
    pub fn running_count(&self) -> usize {
        self.agents
            .values()
            .filter(|a| a.status == AgentStatus::Running)
            .count()
    }
}

impl Default for AgentRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
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
}
