//! Agent status definitions

use serde::{Deserialize, Serialize};

/// Agent execution status
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AgentStatus {
    /// Agent is idle, waiting for tasks
    #[default]
    Idle,
    /// Agent is in extended thinking (Claude reasoning)
    Thinking,
    /// Agent is streaming response text
    Streaming,
    /// Agent is executing a tool (tool name tracked separately)
    Executing,
    /// Agent is processing tool results
    Processing,
    /// Agent is waiting for external input (e.g., orchestrator waiting for agents)
    Waiting,
    /// Agent encountered a transient error and is retrying
    Retrying,
    /// Agent was cancelled by orchestrator
    Cancelled,
    /// Agent completed successfully
    Completed,
    /// Agent encountered an error
    Failed,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_status_default() {
        let status = AgentStatus::default();
        assert_eq!(status, AgentStatus::Idle);
    }
}
