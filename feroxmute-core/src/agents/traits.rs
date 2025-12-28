//! Agent trait definitions

use async_trait::async_trait;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use crate::providers::{LlmProvider, ToolDefinition};
use crate::tools::ToolExecutor;
use crate::Result;

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
    /// Agent completed successfully
    Completed,
    /// Agent encountered an error
    Failed,
}

/// Task status
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TaskStatus {
    #[default]
    Pending,
    InProgress,
    Completed,
    Failed,
}

/// A task for an agent to execute
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentTask {
    /// Unique task identifier
    pub id: String,
    /// Agent type that should handle this task
    pub agent: String,
    /// Human-readable task description
    pub description: String,
    /// Current task status
    pub status: TaskStatus,
    /// Task priority (higher = more important)
    pub priority: u8,
    /// Parent task ID if this is a subtask
    pub parent_id: Option<String>,
    /// Additional context for the task
    pub context: Option<String>,
}

impl AgentTask {
    /// Create a new task
    pub fn new(
        id: impl Into<String>,
        agent: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            agent: agent.into(),
            description: description.into(),
            status: TaskStatus::Pending,
            priority: 5,
            parent_id: None,
            context: None,
        }
    }

    /// Set task priority
    pub fn with_priority(mut self, priority: u8) -> Self {
        self.priority = priority;
        self
    }

    /// Set parent task ID
    pub fn with_parent(mut self, parent_id: impl Into<String>) -> Self {
        self.parent_id = Some(parent_id.into());
        self
    }

    /// Set task context
    pub fn with_context(mut self, context: impl Into<String>) -> Self {
        self.context = Some(context.into());
        self
    }
}

/// Context provided to agents during execution
pub struct AgentContext<'a> {
    /// LLM provider for completions
    pub provider: &'a dyn LlmProvider,
    /// Tool executor for running security tools
    pub executor: &'a ToolExecutor,
    /// Database connection for persistence
    pub conn: &'a Connection,
    /// Target host being tested
    pub target: &'a str,
}

impl<'a> AgentContext<'a> {
    /// Create a new agent context
    pub fn new(
        provider: &'a dyn LlmProvider,
        executor: &'a ToolExecutor,
        conn: &'a Connection,
        target: &'a str,
    ) -> Self {
        Self {
            provider,
            executor,
            conn,
            target,
        }
    }
}

/// Core trait for all agents
#[async_trait(?Send)]
pub trait Agent: Send + Sync {
    /// Get the agent's name
    fn name(&self) -> &str;

    /// Get the agent's current status
    fn status(&self) -> AgentStatus;

    /// Get the system prompt for this agent
    fn system_prompt(&self) -> &str;

    /// Get the tools available to this agent
    fn tools(&self) -> Vec<ToolDefinition>;

    /// Execute a task and return the result
    async fn execute(&mut self, task: &AgentTask, ctx: &AgentContext<'_>) -> Result<String>;

    /// Get the agent's current thinking/reasoning (if available)
    fn thinking(&self) -> Option<&str> {
        None
    }

    /// Set the agent's status
    fn set_status(&mut self, status: AgentStatus);
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_task_builder() {
        let task = AgentTask::new("task-1", "recon", "Enumerate subdomains")
            .with_priority(10)
            .with_parent("parent-task")
            .with_context("Target: example.com");

        assert_eq!(task.id, "task-1");
        assert_eq!(task.agent, "recon");
        assert_eq!(task.priority, 10);
        assert_eq!(task.parent_id, Some("parent-task".to_string()));
        assert_eq!(task.status, TaskStatus::Pending);
    }

    #[test]
    fn test_agent_status_default() {
        let status = AgentStatus::default();
        assert_eq!(status, AgentStatus::Idle);
    }
}
