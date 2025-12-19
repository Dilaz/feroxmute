//! Channel communication between agent and TUI

use feroxmute_core::agents::AgentStatus;

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
    Status { agent: String, status: AgentStatus },

    /// Update token metrics
    #[allow(dead_code)]
    Metrics {
        input: u64,
        output: u64,
        cache_read: u64,
    },

    /// Agent finished
    Finished { success: bool, message: String },
}
