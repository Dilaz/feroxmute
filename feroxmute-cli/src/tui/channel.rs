//! Channel communication between agent and TUI

use feroxmute_core::agents::{AgentStatus, EngagementPhase};

/// Vulnerability severity for TUI display
#[derive(Debug, Clone, Copy)]
pub enum VulnSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// Events sent from agent to TUI
#[derive(Debug, Clone)]
pub enum AgentEvent {
    /// Add entry to activity feed
    Feed {
        agent: String,
        message: String,
        is_error: bool,
        tool_output: Option<String>,
    },

    /// Update the thinking panel
    Thinking {
        agent: String,
        content: Option<String>,
    },

    /// Update agent status
    Status {
        agent: String,
        agent_type: String,
        status: AgentStatus,
        /// Current tool being executed (for Executing status)
        current_tool: Option<String>,
    },

    /// Update token metrics
    Metrics {
        input: u64,
        output: u64,
        cache_read: u64,
        cost_usd: f64,
        tool_calls: u64,
    },

    /// Report a vulnerability found
    Vulnerability {
        severity: VulnSeverity,
        title: String,
    },

    /// Update engagement phase
    Phase { phase: EngagementPhase },

    /// Agent finished
    Finished { success: bool, message: String },

    /// Agent summary (sent when subagent completes)
    Summary {
        agent: String,
        success: bool,
        summary: String,
        key_findings: Vec<String>,
        next_steps: Vec<String>,
        /// Full raw output from the agent (for debugging)
        raw_output: Option<String>,
    },

    /// Memory entries updated
    MemoryUpdated { entries: Vec<MemoryEntry> },
}

/// Memory entry for TUI display
#[derive(Debug, Clone)]
pub struct MemoryEntry {
    pub key: String,
    pub value: String,
    pub created_at: String,
    pub updated_at: String,
}
