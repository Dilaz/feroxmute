//! Channel communication between agent and TUI

use feroxmute_core::agents::AgentStatus;

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
    },

    /// Update the thinking panel
    #[allow(dead_code)]
    Thinking(Option<String>),

    /// Update agent status
    Status {
        agent: String,
        agent_type: String,
        status: AgentStatus,
    },

    /// Update token metrics
    Metrics {
        input: u64,
        output: u64,
        cache_read: u64,
        cost_usd: f64,
    },

    /// Report a vulnerability found
    Vulnerability {
        severity: VulnSeverity,
        title: String,
    },

    /// Agent finished
    Finished { success: bool, message: String },
}
