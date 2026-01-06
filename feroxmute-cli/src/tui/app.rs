//! TUI Application state

use std::time::{Duration, Instant};

use chrono::{DateTime, Local};

use super::channel::{AgentEvent, MemoryEntry};
use feroxmute_core::agents::{AgentStatus, EngagementPhase};
use feroxmute_core::state::models::{CodeFinding, FindingType};
use tokio::sync::mpsc;

/// Active view in the TUI
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum View {
    #[default]
    Dashboard,
    AgentDetail(String), // Agent name instead of AgentView enum
    Logs,
    Help,
    Memory,
}

/// Metrics display
#[derive(Debug, Clone, Default)]
pub struct Metrics {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_tokens: u64,
    pub tool_calls: u64,
    pub estimated_cost_usd: f64,
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
    #[allow(dead_code)]
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

/// Status for each agent
#[derive(Debug, Clone, Default)]
pub struct AgentStatuses {
    pub orchestrator: AgentStatus,
    pub recon: AgentStatus,
    pub scanner: AgentStatus,
    pub sast: Option<String>,
}

/// Display info for a dynamically spawned agent
#[derive(Debug, Clone, Default)]
pub struct AgentDisplayInfo {
    pub agent_type: String,
    pub status: AgentStatus,
    pub activity: String,
    pub spawn_order: usize,
    pub thinking: Option<String>,
    /// Current tool being executed (for Executing status display)
    pub current_tool: Option<String>,
}

impl AgentDisplayInfo {
    pub fn new_orchestrator() -> Self {
        Self {
            agent_type: "orchestrator".to_string(),
            status: AgentStatus::Idle,
            activity: String::new(),
            spawn_order: 0,
            thinking: None,
            current_tool: None,
        }
    }
}

/// Activity feed entry
#[derive(Debug, Clone)]
pub struct FeedEntry {
    pub timestamp: DateTime<Local>,
    pub agent: String,
    pub message: String,
    pub is_error: bool,
    pub tool_output: Option<String>,
    pub expanded: bool,
}

impl FeedEntry {
    pub fn new(agent: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            timestamp: Local::now(),
            agent: agent.into(),
            message: message.into(),
            is_error: false,
            tool_output: None,
            expanded: false,
        }
    }

    pub fn error(agent: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            timestamp: Local::now(),
            agent: agent.into(),
            message: message.into(),
            is_error: true,
            tool_output: None,
            expanded: false,
        }
    }

    pub fn with_output(mut self, output: String) -> Self {
        self.tool_output = Some(output);
        self
    }
}

/// Maximum number of feed entries to retain
const FEED_MAX_SIZE: usize = 500;

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
    /// Agent statuses (legacy, kept for orchestrator)
    pub agent_statuses: AgentStatuses,
    /// Dynamically spawned agents (name -> info)
    pub agents: std::collections::HashMap<String, AgentDisplayInfo>,
    /// Currently selected agent for thinking display
    pub selected_agent: Option<String>,
    /// Counter for assigning spawn order
    pub agent_spawn_counter: usize,
    /// Activity feed
    pub feed: Vec<FeedEntry>,
    /// Per-agent feed indices for efficient filtering
    pub agent_feed_indices: std::collections::HashMap<String, Vec<usize>>,
    /// Scroll offset for logs
    pub log_scroll: usize,
    /// Selected feed item
    pub selected_feed: usize,
    /// Horizontal scroll offset for feed
    pub feed_scroll_x: u16,
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
    /// Memory entries for display
    pub memory_entries: Vec<MemoryEntry>,
    /// Currently selected memory entry index
    pub selected_memory: usize,
    /// Show memory detail modal
    pub show_memory_modal: bool,
    /// Scroll offset for modal content
    pub memory_modal_scroll: usize,
}

impl App {
    /// Create a new app instance
    pub fn new(
        target: impl Into<String>,
        session_id: impl Into<String>,
        event_rx: Option<mpsc::Receiver<AgentEvent>>,
    ) -> Self {
        let mut agents = std::collections::HashMap::new();
        // Pre-register orchestrator with spawn_order 0
        agents.insert(
            "orchestrator".to_string(),
            AgentDisplayInfo::new_orchestrator(),
        );

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
            agents,
            selected_agent: Some("orchestrator".to_string()),
            agent_spawn_counter: 0,
            feed: Vec::new(),
            agent_feed_indices: std::collections::HashMap::new(),
            log_scroll: 0,
            selected_feed: 0,
            feed_scroll_x: 0,
            source_path: None,
            detected_languages: Vec::new(),
            code_findings: Vec::new(),
            code_finding_counts: CodeFindingCounts::default(),
            event_rx,
            memory_entries: Vec::new(),
            selected_memory: 0,
            show_memory_modal: false,
            memory_modal_scroll: 0,
        }
    }

    /// Get agent name by key number (1-9)
    pub fn get_agent_by_key(&self, key: usize) -> Option<String> {
        if key == 1 {
            return Some("orchestrator".to_string());
        }
        // Find agent with spawn_order == key - 1
        self.agents
            .iter()
            .find(|(name, info)| *name != "orchestrator" && info.spawn_order == key - 1)
            .map(|(name, _)| name.clone())
    }

    /// Get the thinking text for the currently selected agent
    #[allow(dead_code)] // Used in tests
    pub fn get_selected_thinking(&self) -> Option<&str> {
        self.selected_agent
            .as_ref()
            .and_then(|name| self.agents.get(name))
            .and_then(|info| info.thinking.as_deref())
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
        let agent = entry.agent.clone();
        let idx = self.feed.len();
        self.feed.push(entry);

        // Track index for this agent
        self.agent_feed_indices.entry(agent).or_default().push(idx);

        // Keep only last FEED_MAX_SIZE entries
        if self.feed.len() > FEED_MAX_SIZE {
            self.feed.remove(0);
            // Decrement all indices and remove invalid ones
            for indices in self.agent_feed_indices.values_mut() {
                indices.retain_mut(|i| {
                    if *i > 0 {
                        *i -= 1;
                        true
                    } else {
                        false
                    }
                });
            }
        }
    }

    /// Get feed entries for a specific agent
    pub fn get_agent_feed(&self, agent_name: &str) -> Vec<&FeedEntry> {
        if let Some(indices) = self.agent_feed_indices.get(agent_name) {
            indices
                .iter()
                .filter_map(|&idx| self.feed.get(idx))
                .collect()
        } else {
            Vec::new()
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

    /// Update agent activity (from non-indented feed messages)
    pub fn update_agent_activity(&mut self, agent: &str, activity: &str) {
        if let Some(info) = self.agents.get_mut(agent) {
            info.activity = activity.to_string();
        } else if agent != "orchestrator" && agent != "system" {
            // New agent - add it
            self.agent_spawn_counter += 1;
            self.agents.insert(
                agent.to_string(),
                AgentDisplayInfo {
                    agent_type: String::new(), // Will be set from status event
                    status: AgentStatus::Streaming,
                    activity: activity.to_string(),
                    spawn_order: self.agent_spawn_counter,
                    thinking: None,
                    current_tool: None,
                },
            );
        }
    }

    /// Update spawned agent status
    pub fn update_spawned_agent_status(
        &mut self,
        agent: &str,
        agent_type: &str,
        status: AgentStatus,
        current_tool: Option<String>,
    ) {
        if let Some(info) = self.agents.get_mut(agent) {
            info.status = status;
            info.current_tool = current_tool;
            if !agent_type.is_empty() {
                info.agent_type = agent_type.to_string();
            }
        } else if agent != "system" {
            self.agent_spawn_counter += 1;
            self.agents.insert(
                agent.to_string(),
                AgentDisplayInfo {
                    agent_type: agent_type.to_string(),
                    status,
                    activity: String::new(),
                    spawn_order: self.agent_spawn_counter,
                    thinking: None,
                    current_tool,
                },
            );
        }
    }

    /// Update agent thinking
    pub fn update_agent_thinking(&mut self, agent: &str, thinking: Option<String>) {
        if let Some(info) = self.agents.get_mut(agent) {
            info.thinking = thinking;
        }
    }

    /// Add a code finding and update counts
    pub fn add_code_finding(&mut self, finding: CodeFinding) {
        match finding.finding_type {
            FindingType::Dependency => self.code_finding_counts.dependencies += 1,
            FindingType::Sast => self.code_finding_counts.sast += 1,
            FindingType::Secret => self.code_finding_counts.secrets += 1,
        }
        self.code_findings.push(finding);
    }

    /// Navigate to view
    pub fn navigate(&mut self, view: View) {
        self.view = view;
    }

    /// Toggle thinking panel
    pub fn toggle_thinking(&mut self) {
        self.show_thinking = !self.show_thinking;
    }

    /// Toggle output expansion for the currently selected feed entry
    pub fn toggle_output(&mut self, agent_filter: Option<&str>) {
        // Get entries that match the filter and have tool_output
        let matching_indices: Vec<usize> = self
            .feed
            .iter()
            .enumerate()
            .filter(|(_, e)| agent_filter.is_none_or(|a| e.agent == a) && e.tool_output.is_some())
            .map(|(i, _)| i)
            .collect();

        if matching_indices.is_empty() {
            return;
        }

        // Find the entry at the current scroll position
        // log_scroll is offset from bottom, so we need to map it
        let visible_idx = matching_indices
            .iter()
            .rev()
            .nth(self.log_scroll)
            .or_else(|| matching_indices.last());

        if let Some(&idx) = visible_idx
            && let Some(entry) = self.feed.get_mut(idx)
        {
            entry.expanded = !entry.expanded;
        }
    }

    /// Scroll logs up (show older entries by increasing offset from bottom)
    pub fn scroll_up(&mut self) {
        self.log_scroll = self.log_scroll.saturating_add(1);
    }

    /// Scroll logs down (show newer entries by decreasing offset from bottom)
    pub fn scroll_down(&mut self) {
        self.log_scroll = self.log_scroll.saturating_sub(1);
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

    /// Scroll feed left
    pub fn scroll_feed_left(&mut self) {
        self.feed_scroll_x = self.feed_scroll_x.saturating_sub(4);
    }

    /// Scroll feed right
    pub fn scroll_feed_right(&mut self) {
        self.feed_scroll_x = self.feed_scroll_x.saturating_add(4);
    }

    /// Reset feed scroll
    #[allow(dead_code)]
    pub fn reset_feed_scroll(&mut self) {
        self.feed_scroll_x = 0;
    }

    /// Select next memory entry
    pub fn select_next_memory(&mut self) {
        if self.selected_memory < self.memory_entries.len().saturating_sub(1) {
            self.selected_memory += 1;
        }
    }

    /// Select previous memory entry
    pub fn select_prev_memory(&mut self) {
        self.selected_memory = self.selected_memory.saturating_sub(1);
    }

    /// Open memory modal for selected entry
    pub fn open_memory_modal(&mut self) {
        if !self.memory_entries.is_empty() {
            self.show_memory_modal = true;
            self.memory_modal_scroll = 0;
        }
    }

    /// Close memory modal
    pub fn close_memory_modal(&mut self) {
        self.show_memory_modal = false;
        self.memory_modal_scroll = 0;
    }

    /// Scroll memory modal content up
    pub fn scroll_memory_modal_up(&mut self) {
        self.memory_modal_scroll = self.memory_modal_scroll.saturating_add(1);
    }

    /// Scroll memory modal content down
    pub fn scroll_memory_modal_down(&mut self) {
        self.memory_modal_scroll = self.memory_modal_scroll.saturating_sub(1);
    }

    /// Get currently selected memory entry
    pub fn selected_memory_entry(&self) -> Option<&MemoryEntry> {
        self.memory_entries.get(self.selected_memory)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
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

        app.navigate(View::AgentDetail("orchestrator".to_string()));
        assert_eq!(app.view, View::AgentDetail("orchestrator".to_string()));
    }

    #[test]
    fn test_get_agent_by_key() {
        let mut app = App::new("test.com", "test-session", None);
        assert_eq!(app.get_agent_by_key(1), Some("orchestrator".to_string()));
        assert_eq!(app.get_agent_by_key(2), None);

        app.update_spawned_agent_status("recon-1", "recon", AgentStatus::Streaming, None);
        assert_eq!(app.get_agent_by_key(2), Some("recon-1".to_string()));

        app.update_spawned_agent_status("scanner-1", "scanner", AgentStatus::Streaming, None);
        assert_eq!(app.get_agent_by_key(3), Some("scanner-1".to_string()));
    }

    #[test]
    fn test_agent_thinking() {
        let mut app = App::new("test.com", "test-session", None);
        app.update_agent_thinking("orchestrator", Some("Planning...".to_string()));

        let agent = app.agents.get("orchestrator");
        assert!(agent.is_some(), "orchestrator should exist");
        assert_eq!(
            agent.map(|a| a.thinking.clone()),
            Some(Some("Planning...".to_string()))
        );

        app.selected_agent = Some("orchestrator".to_string());
        assert_eq!(app.get_selected_thinking(), Some("Planning..."));
    }

    #[test]
    fn test_feed_scroll() {
        let mut app = App::new("test.com", "test-session", None);
        assert_eq!(app.feed_scroll_x, 0);

        app.scroll_feed_right();
        assert_eq!(app.feed_scroll_x, 4);

        app.scroll_feed_right();
        assert_eq!(app.feed_scroll_x, 8);

        app.scroll_feed_left();
        assert_eq!(app.feed_scroll_x, 4);

        app.reset_feed_scroll();
        assert_eq!(app.feed_scroll_x, 0);
    }

    #[test]
    fn test_toggle_output() {
        let mut app = App::new("test.com", "test-session", None);

        // Add entry without output
        app.add_feed(FeedEntry::new("recon", "Starting scan"));

        // Add entry with output
        let entry_with_output = FeedEntry::new("recon", "  -> exit 0, 5 lines output")
            .with_output("line1\nline2\nline3\nline4\nline5".to_string());
        app.add_feed(entry_with_output);

        // Initially not expanded
        let entry = app.feed.get(1);
        assert!(entry.is_some(), "should have second entry");
        assert!(!entry.map(|e| e.expanded).unwrap_or(true));

        // Toggle should expand
        app.toggle_output(Some("recon"));
        let entry = app.feed.get(1);
        assert!(entry.is_some(), "should have second entry");
        assert!(entry.map(|e| e.expanded).unwrap_or(false));

        // Toggle again should collapse
        app.toggle_output(Some("recon"));
        let entry = app.feed.get(1);
        assert!(entry.is_some(), "should have second entry");
        assert!(!entry.map(|e| e.expanded).unwrap_or(true));
    }

    #[test]
    fn test_memory_selection() {
        let mut app = App::new("test.com", "test-session", None);

        // Empty state - selection stays at 0
        assert_eq!(app.selected_memory, 0);
        app.select_next_memory();
        assert_eq!(app.selected_memory, 0);
        app.select_prev_memory();
        assert_eq!(app.selected_memory, 0);

        // Add entries
        app.memory_entries = vec![
            MemoryEntry {
                key: "k1".into(),
                value: "v1".into(),
                created_at: "".into(),
                updated_at: "".into(),
            },
            MemoryEntry {
                key: "k2".into(),
                value: "v2".into(),
                created_at: "".into(),
                updated_at: "".into(),
            },
            MemoryEntry {
                key: "k3".into(),
                value: "v3".into(),
                created_at: "".into(),
                updated_at: "".into(),
            },
        ];

        // Navigate forward
        assert_eq!(app.selected_memory, 0);
        app.select_next_memory();
        assert_eq!(app.selected_memory, 1);
        app.select_next_memory();
        assert_eq!(app.selected_memory, 2);
        app.select_next_memory();
        assert_eq!(app.selected_memory, 2); // Should not exceed bounds

        // Navigate backward
        app.select_prev_memory();
        assert_eq!(app.selected_memory, 1);
        app.select_prev_memory();
        assert_eq!(app.selected_memory, 0);
        app.select_prev_memory();
        assert_eq!(app.selected_memory, 0); // Should not go below 0
    }

    #[test]
    fn test_memory_modal() {
        let mut app = App::new("test.com", "test-session", None);

        // Cannot open modal with no entries
        app.open_memory_modal();
        assert!(!app.show_memory_modal);

        // Add entry
        app.memory_entries = vec![MemoryEntry {
            key: "test".into(),
            value: "value".into(),
            created_at: "".into(),
            updated_at: "".into(),
        }];

        // Open modal
        app.open_memory_modal();
        assert!(app.show_memory_modal);
        assert_eq!(app.memory_modal_scroll, 0);

        // Scroll
        app.scroll_memory_modal_up();
        assert_eq!(app.memory_modal_scroll, 1);
        app.scroll_memory_modal_up();
        assert_eq!(app.memory_modal_scroll, 2);
        app.scroll_memory_modal_down();
        assert_eq!(app.memory_modal_scroll, 1);

        // Close modal resets scroll
        app.close_memory_modal();
        assert!(!app.show_memory_modal);
        assert_eq!(app.memory_modal_scroll, 0);
    }

    #[test]
    fn test_selected_memory_entry() {
        let mut app = App::new("test.com", "test-session", None);

        // No entries - returns None
        assert!(app.selected_memory_entry().is_none());

        // Add entries
        app.memory_entries = vec![
            MemoryEntry {
                key: "first".into(),
                value: "v1".into(),
                created_at: "".into(),
                updated_at: "".into(),
            },
            MemoryEntry {
                key: "second".into(),
                value: "v2".into(),
                created_at: "".into(),
                updated_at: "".into(),
            },
        ];

        // Get selected entry
        let entry = app.selected_memory_entry();
        assert!(entry.is_some(), "should have selected entry");
        assert_eq!(entry.map(|e| e.key.clone()), Some("first".to_string()));

        app.select_next_memory();
        let entry = app.selected_memory_entry();
        assert!(entry.is_some(), "should have selected entry");
        assert_eq!(entry.map(|e| e.key.clone()), Some("second".to_string()));
    }

    #[test]
    fn test_add_code_finding() {
        use feroxmute_core::state::models::{CodeFinding, FindingType, Severity};

        let mut app = App::new("test.com", "test-session", None);

        // Add dependency finding
        let dep_finding = CodeFinding::new(
            "Cargo.lock",
            Severity::High,
            FindingType::Dependency,
            "CVE-2024-1234 in pkg@1.0",
            "grype",
        );
        app.add_code_finding(dep_finding);
        assert_eq!(app.code_finding_counts.dependencies, 1);
        assert_eq!(app.code_finding_counts.sast, 0);
        assert_eq!(app.code_finding_counts.secrets, 0);

        // Add SAST finding
        let sast_finding = CodeFinding::new(
            "src/main.rs",
            Severity::Medium,
            FindingType::Sast,
            "SQL injection",
            "semgrep",
        );
        app.add_code_finding(sast_finding);
        assert_eq!(app.code_finding_counts.dependencies, 1);
        assert_eq!(app.code_finding_counts.sast, 1);

        // Add secret finding
        let secret_finding = CodeFinding::new(
            ".env",
            Severity::High,
            FindingType::Secret,
            "API key exposed",
            "gitleaks",
        );
        app.add_code_finding(secret_finding);
        assert_eq!(app.code_finding_counts.secrets, 1);

        // Total findings
        assert_eq!(app.code_findings.len(), 3);
    }
}
