//! TUI Application state

use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use feroxmute_core::agents::{AgentStatus, EngagementPhase};
use feroxmute_core::state::models::CodeFinding;
use super::channel::AgentEvent;

/// Active view in the TUI
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum View {
    #[default]
    Dashboard,
    AgentDetail(AgentView),
    Logs,
    Help,
}

/// Agent-specific views
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentView {
    Orchestrator,
    Recon,
    Scanner,
    Sast,
}

/// Metrics display
#[derive(Debug, Clone, Default)]
pub struct Metrics {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_tokens: u64,
    pub tool_calls: u64,
}

/// Vulnerability severity counts
#[derive(Debug, Clone, Default)]
pub struct VulnCounts {
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub info: u32,
}

impl VulnCounts {
    pub fn total(&self) -> u32 {
        self.critical + self.high + self.medium + self.low + self.info
    }
}

/// Code finding counts by type
#[derive(Debug, Clone, Default)]
pub struct CodeFindingCounts {
    pub dependencies: u32,
    pub sast: u32,
    pub secrets: u32,
}

impl CodeFindingCounts {
    pub fn total(&self) -> u32 {
        self.dependencies + self.sast + self.secrets
    }
}

/// Status for each agent
#[derive(Debug, Clone, Default)]
pub struct AgentStatuses {
    pub orchestrator: AgentStatus,
    pub recon: AgentStatus,
    pub scanner: AgentStatus,
    pub sast: Option<String>,
}

/// Activity feed entry
#[derive(Debug, Clone)]
pub struct FeedEntry {
    pub timestamp: Instant,
    pub agent: String,
    pub message: String,
    pub is_error: bool,
}

impl FeedEntry {
    pub fn new(agent: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            timestamp: Instant::now(),
            agent: agent.into(),
            message: message.into(),
            is_error: false,
        }
    }

    pub fn error(agent: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            timestamp: Instant::now(),
            agent: agent.into(),
            message: message.into(),
            is_error: true,
        }
    }
}

/// TUI Application state
pub struct App {
    /// Current view
    pub view: View,
    /// Should quit the application
    pub should_quit: bool,
    /// Show quit confirmation dialog
    pub confirm_quit: bool,
    /// Show agent thinking panel
    pub show_thinking: bool,
    /// Mouse support enabled
    pub mouse_enabled: bool,
    /// Target host
    pub target: String,
    /// Session ID
    pub session_id: String,
    /// Current engagement phase
    pub phase: EngagementPhase,
    /// Time since engagement started
    pub start_time: Instant,
    /// Token metrics
    pub metrics: Metrics,
    /// Vulnerability counts
    pub vuln_counts: VulnCounts,
    /// Agent statuses
    pub agent_statuses: AgentStatuses,
    /// Activity feed
    pub feed: Vec<FeedEntry>,
    /// Current thinking text (from active agent)
    pub current_thinking: Option<String>,
    /// Scroll offset for logs
    pub log_scroll: usize,
    /// Selected feed item
    pub selected_feed: usize,
    /// Source path for SAST analysis
    pub source_path: Option<String>,
    /// Detected programming languages
    pub detected_languages: Vec<String>,
    /// Code findings from SAST
    pub code_findings: Vec<CodeFinding>,
    /// Code finding counts by type
    pub code_finding_counts: CodeFindingCounts,
    /// Channel receiver for agent events
    pub event_rx: Option<mpsc::Receiver<AgentEvent>>,
}

impl App {
    /// Create a new app instance
    pub fn new(
        target: impl Into<String>,
        session_id: impl Into<String>,
        event_rx: Option<mpsc::Receiver<AgentEvent>>,
    ) -> Self {
        Self {
            view: View::Dashboard,
            should_quit: false,
            confirm_quit: false,
            show_thinking: true,
            mouse_enabled: true,
            target: target.into(),
            session_id: session_id.into(),
            phase: EngagementPhase::Setup,
            start_time: Instant::now(),
            metrics: Metrics::default(),
            vuln_counts: VulnCounts::default(),
            agent_statuses: AgentStatuses::default(),
            feed: Vec::new(),
            current_thinking: None,
            log_scroll: 0,
            selected_feed: 0,
            source_path: None,
            detected_languages: Vec::new(),
            code_findings: Vec::new(),
            code_finding_counts: CodeFindingCounts::default(),
            event_rx,
        }
    }

    /// Get elapsed time since start
    pub fn elapsed(&self) -> Duration {
        self.start_time.elapsed()
    }

    /// Format elapsed time for display
    pub fn elapsed_display(&self) -> String {
        let elapsed = self.elapsed();
        let secs = elapsed.as_secs();
        let mins = secs / 60;
        let hours = mins / 60;

        if hours > 0 {
            format!("{}h {:02}m {:02}s", hours, mins % 60, secs % 60)
        } else if mins > 0 {
            format!("{}m {:02}s", mins, secs % 60)
        } else {
            format!("{}s", secs)
        }
    }

    /// Add a feed entry
    pub fn add_feed(&mut self, entry: FeedEntry) {
        self.feed.push(entry);
        // Keep only last 100 entries
        if self.feed.len() > 100 {
            self.feed.remove(0);
        }
    }

    /// Update agent status
    pub fn update_agent_status(&mut self, agent: &str, status: AgentStatus) {
        match agent {
            "orchestrator" => self.agent_statuses.orchestrator = status,
            "recon" => self.agent_statuses.recon = status,
            "scanner" => self.agent_statuses.scanner = status,
            "sast" => self.agent_statuses.sast = Some(format!("{:?}", status)),
            _ => {}
        }
    }

    /// Set current thinking
    pub fn set_thinking(&mut self, thinking: Option<String>) {
        self.current_thinking = thinking;
    }

    /// Update metrics
    pub fn update_metrics(&mut self, input: u64, output: u64, cache_read: u64, tool_calls: u64) {
        self.metrics.input_tokens += input;
        self.metrics.output_tokens += output;
        self.metrics.cache_read_tokens += cache_read;
        self.metrics.tool_calls += tool_calls;
    }

    /// Navigate to view
    pub fn navigate(&mut self, view: View) {
        self.view = view;
    }

    /// Toggle thinking panel
    pub fn toggle_thinking(&mut self) {
        self.show_thinking = !self.show_thinking;
    }

    /// Scroll logs up
    pub fn scroll_up(&mut self) {
        self.log_scroll = self.log_scroll.saturating_sub(1);
    }

    /// Scroll logs down
    pub fn scroll_down(&mut self) {
        self.log_scroll = self.log_scroll.saturating_add(1);
    }

    /// Select next feed item
    pub fn select_next(&mut self) {
        if self.selected_feed < self.feed.len().saturating_sub(1) {
            self.selected_feed += 1;
        }
    }

    /// Select previous feed item
    pub fn select_prev(&mut self) {
        self.selected_feed = self.selected_feed.saturating_sub(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_creation() {
        let app = App::new("example.com", "session-123", None);
        assert_eq!(app.target, "example.com");
        assert_eq!(app.session_id, "session-123");
        assert_eq!(app.view, View::Dashboard);
        assert!(!app.should_quit);
    }

    #[test]
    fn test_vuln_counts() {
        let counts = VulnCounts {
            critical: 1,
            high: 2,
            medium: 3,
            low: 4,
            info: 5,
        };
        assert_eq!(counts.total(), 15);
    }

    #[test]
    fn test_feed_entry() {
        let entry = FeedEntry::new("recon", "Started subdomain enumeration");
        assert_eq!(entry.agent, "recon");
        assert!(!entry.is_error);

        let error = FeedEntry::error("scanner", "Tool execution failed");
        assert!(error.is_error);
    }

    #[test]
    fn test_navigation() {
        let mut app = App::new("test.com", "test-session", None);
        assert_eq!(app.view, View::Dashboard);

        app.navigate(View::Logs);
        assert_eq!(app.view, View::Logs);

        app.navigate(View::AgentDetail(AgentView::Recon));
        assert_eq!(app.view, View::AgentDetail(AgentView::Recon));
    }
}
