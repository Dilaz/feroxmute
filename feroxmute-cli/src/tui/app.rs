//! TUI Application state

use std::time::{Duration, Instant};

use chrono::{DateTime, Local};

use super::channel::{AgentEvent, MemoryEntry};
use super::theme::Theme;
use feroxmute_core::agents::{AgentStatus, EngagementPhase};
use feroxmute_core::state::models::{FindingType, Severity};
use tokio::sync::mpsc;

/// Focusable pane in the unified command center.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Pane {
    #[default]
    Agents,
    Findings,
    Activity,
}

impl Pane {
    /// Next pane in the cycle: Agents → Findings → Activity → Agents.
    pub fn next(self) -> Self {
        match self {
            Pane::Agents => Pane::Findings,
            Pane::Findings => Pane::Activity,
            Pane::Activity => Pane::Agents,
        }
    }

    /// Previous pane in the cycle (reverse of [`Pane::next`]).
    pub fn prev(self) -> Self {
        match self {
            Pane::Agents => Pane::Activity,
            Pane::Findings => Pane::Agents,
            Pane::Activity => Pane::Findings,
        }
    }
}

/// A centered overlay rendered on top of the command center.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Overlay {
    /// Detailed view of a single agent (by name).
    AgentDetail(String),
    /// Detailed view of a finding (index into the sorted findings view).
    FindingDetail(usize),
    /// Orchestrator memory browser.
    Memory,
    /// Full-screen activity log.
    Logs,
    /// Keybinding help.
    Help,
}

/// Source of a finding, shown as a tag in the Findings pane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingSource {
    Net,
    Sast,
    Dep,
    Secret,
}

impl FindingSource {
    /// Short uppercase tag for display.
    pub fn tag(self) -> &'static str {
        match self {
            Self::Net => "NET",
            Self::Sast => "SAST",
            Self::Dep => "DEP",
            Self::Secret => "SECRET",
        }
    }
}

impl From<FindingType> for FindingSource {
    fn from(ft: FindingType) -> Self {
        match ft {
            FindingType::Dependency => Self::Dep,
            FindingType::Sast => Self::Sast,
            FindingType::Secret => Self::Secret,
        }
    }
}

/// A unified finding (network vuln or code/SAST finding) for the Findings pane.
#[derive(Debug, Clone)]
pub struct Finding {
    pub severity: Severity,
    pub title: String,
    pub source: FindingSource,
    pub agent: String,
    /// e.g. "src/foo.rs:42" for code findings; `None` for network vulns.
    pub location: Option<String>,
    pub timestamp: DateTime<Local>,
}

/// Rank for severity ordering (Critical highest, Info lowest).
pub fn severity_rank(s: Severity) -> u8 {
    match s {
        Severity::Critical => 0,
        Severity::High => 1,
        Severity::Medium => 2,
        Severity::Low => 3,
        Severity::Info => 4,
    }
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
    /// Dynamically spawned agents (name -> info), including the orchestrator
    pub agents: std::collections::HashMap<String, AgentDisplayInfo>,
    /// Currently selected agent for thinking display
    pub selected_agent: Option<String>,
    /// Counter for assigning spawn order
    pub agent_spawn_counter: usize,
    /// Activity feed
    pub feed: Vec<FeedEntry>,
    /// Per-agent feed indices for efficient filtering
    pub agent_feed_indices: std::collections::HashMap<String, Vec<usize>>,
    /// Unified findings (network vulns + code findings), insertion order
    pub findings: Vec<Finding>,
    /// Scroll offset for logs / agent detail output
    pub log_scroll: usize,
    /// Source path for SAST analysis
    pub source_path: Option<String>,
    /// Detected programming languages
    pub detected_languages: Vec<String>,
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

    /// Currently focused pane in the command center
    pub focus: Pane,
    /// Active overlay (None = command center focused)
    pub overlay: Option<Overlay>,
    /// Selected index into the ordered agent list
    pub agents_selected: usize,
    /// Selected index into the sorted findings view
    pub findings_selected: usize,
    /// Activity pane scroll (offset from bottom)
    pub activity_scroll: usize,
    /// Resolved theme and capabilities
    pub theme: Theme,
    /// Frame counter for spinner animation
    pub tick: u64,
    /// Sender for operator steering guidance to the orchestrator (None in tests).
    pub steer_tx: Option<mpsc::Sender<String>>,
    /// Active steer input buffer; Some(..) means the input prompt is open.
    pub steer_input: Option<String>,
    /// Wall-clock instant the engagement finished; freezes the elapsed timer.
    /// `None` while the engagement is still running.
    pub finished_at: Option<Instant>,
    /// Whether the finished engagement ended successfully (only meaningful
    /// once `finished_at` is set).
    pub finished_success: bool,
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
            should_quit: false,
            confirm_quit: false,
            show_thinking: true,
            mouse_enabled: true,
            target: target.into(),
            session_id: session_id.into(),
            phase: EngagementPhase::Setup,
            start_time: Instant::now(),
            metrics: Metrics::default(),
            agents,
            selected_agent: Some("orchestrator".to_string()),
            agent_spawn_counter: 0,
            feed: Vec::new(),
            agent_feed_indices: std::collections::HashMap::new(),
            findings: Vec::new(),
            log_scroll: 0,
            source_path: None,
            detected_languages: Vec::new(),
            event_rx,
            memory_entries: Vec::new(),
            selected_memory: 0,
            show_memory_modal: false,
            memory_modal_scroll: 0,
            focus: Pane::default(),
            overlay: None,
            agents_selected: 0,
            findings_selected: 0,
            activity_scroll: 0,
            theme: Theme::detect(false),
            tick: 0,
            steer_tx: None,
            steer_input: None,
            finished_at: None,
            finished_success: false,
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

    /// Agents in display order: orchestrator first, then spawned by spawn order.
    pub fn ordered_agents(&self) -> Vec<(&String, &AgentDisplayInfo)> {
        let mut result = Vec::new();
        if let Some((name, info)) = self.agents.get_key_value("orchestrator") {
            result.push((name, info));
        }
        let mut spawned: Vec<_> = self
            .agents
            .iter()
            .filter(|(name, _)| name.as_str() != "orchestrator")
            .collect();
        spawned.sort_by_key(|(_, info)| info.spawn_order);
        result.extend(spawned);
        result
    }

    /// Findings sorted by severity (Critical→Info), ties most-recent first.
    pub fn sorted_findings(&self) -> Vec<&Finding> {
        let mut v: Vec<&Finding> = self.findings.iter().collect();
        v.sort_by(|a, b| {
            severity_rank(a.severity)
                .cmp(&severity_rank(b.severity))
                .then_with(|| b.timestamp.cmp(&a.timestamp))
        });
        v
    }

    /// Severity counts as `[critical, high, medium, low, info]`.
    pub fn severity_counts(&self) -> [u32; 5] {
        let mut counts = [0u32; 5];
        for finding in &self.findings {
            if let Some(c) = counts.get_mut(severity_rank(finding.severity) as usize) {
                *c += 1;
            }
        }
        counts
    }

    /// Get the thinking text for the currently selected agent
    #[allow(dead_code)] // Used in tests
    pub fn get_selected_thinking(&self) -> Option<&str> {
        self.selected_agent
            .as_ref()
            .and_then(|name| self.agents.get(name))
            .and_then(|info| info.thinking.as_deref())
    }

    /// Get elapsed time since start. Once the engagement has finished the
    /// value is frozen at the finish instant so the header timer stops.
    pub fn elapsed(&self) -> Duration {
        match self.finished_at {
            Some(end) => end.saturating_duration_since(self.start_time),
            None => self.start_time.elapsed(),
        }
    }

    /// Whether the engagement has reached a terminal state.
    pub fn is_finished(&self) -> bool {
        self.finished_at.is_some()
    }

    /// Transition the UI into its terminal state: freeze the elapsed timer and
    /// drive any still-active agents (including the orchestrator) to a terminal
    /// status so nothing keeps rendering as "running". Idempotent.
    pub fn mark_finished(&mut self, success: bool) {
        if self.finished_at.is_some() {
            return;
        }
        self.finished_at = Some(Instant::now());
        self.finished_success = success;
        if success {
            self.phase = EngagementPhase::Complete;
        }
        let terminal = if success {
            AgentStatus::Completed
        } else {
            AgentStatus::Cancelled
        };
        for info in self.agents.values_mut() {
            let still_active = matches!(
                info.status,
                AgentStatus::Idle
                    | AgentStatus::Thinking
                    | AgentStatus::Streaming
                    | AgentStatus::Executing
                    | AgentStatus::Processing
                    | AgentStatus::Waiting
                    | AgentStatus::Retrying
            );
            if still_active {
                info.status = terminal;
                info.current_tool = None;
            }
        }
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

    /// Add a unified finding.
    pub fn add_finding(&mut self, finding: Finding) {
        self.findings.push(finding);
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

    /// Advance focus to the next pane.
    pub fn focus_next(&mut self) {
        self.focus = self.focus.next();
    }

    /// Move focus to the previous pane.
    pub fn focus_prev(&mut self) {
        self.focus = self.focus.prev();
    }

    /// Move selection/scroll up in the focused pane.
    pub fn move_up(&mut self) {
        match self.focus {
            Pane::Agents => {
                self.agents_selected = self.agents_selected.saturating_sub(1);
            }
            Pane::Findings => {
                self.findings_selected = self.findings_selected.saturating_sub(1);
            }
            Pane::Activity => {
                self.activity_scroll = self.activity_scroll.saturating_add(1);
            }
        }
    }

    /// Move selection/scroll down in the focused pane.
    pub fn move_down(&mut self) {
        match self.focus {
            Pane::Agents => {
                let max = self.agents.len().saturating_sub(1);
                if self.agents_selected < max {
                    self.agents_selected += 1;
                }
            }
            Pane::Findings => {
                let max = self.findings.len().saturating_sub(1);
                if self.findings_selected < max {
                    self.findings_selected += 1;
                }
            }
            Pane::Activity => {
                self.activity_scroll = self.activity_scroll.saturating_sub(1);
            }
        }
    }

    /// Open an overlay, resetting overlay scroll state.
    pub fn open_overlay(&mut self, overlay: Overlay) {
        self.log_scroll = 0;
        self.overlay = Some(overlay);
    }

    /// Close any open overlay and reset modal state.
    pub fn close_overlay(&mut self) {
        self.overlay = None;
        self.show_memory_modal = false;
        self.memory_modal_scroll = 0;
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

    fn finding(sev: Severity, title: &str, source: FindingSource) -> Finding {
        Finding {
            severity: sev,
            title: title.to_string(),
            source,
            agent: "test".to_string(),
            location: None,
            timestamp: Local::now(),
        }
    }

    #[test]
    fn mark_finished_freezes_elapsed_timer() {
        let mut app = App::new("example.com", "sess-1", None);
        assert!(!app.is_finished());
        app.mark_finished(true);
        assert!(app.is_finished());
        let first = app.elapsed();
        std::thread::sleep(std::time::Duration::from_millis(20));
        // Timer must not advance once finished.
        assert_eq!(app.elapsed(), first);
    }

    #[test]
    fn mark_finished_terminalizes_active_agents() {
        let mut app = App::new("example.com", "sess-1", None);
        // Orchestrator starts Idle; spawn an executing specialist.
        app.update_spawned_agent_status(
            "recon-1",
            "recon",
            AgentStatus::Executing,
            Some("nmap".into()),
        );
        app.mark_finished(true);
        // Orchestrator (the "main agent") must no longer render as active.
        assert_eq!(app.agents["orchestrator"].status, AgentStatus::Completed);
        let recon = &app.agents["recon-1"];
        assert_eq!(recon.status, AgentStatus::Completed);
        assert!(recon.current_tool.is_none());
        assert_eq!(app.phase, EngagementPhase::Complete);
    }

    #[test]
    fn mark_finished_preserves_completed_status_on_failure() {
        let mut app = App::new("example.com", "sess-1", None);
        app.update_spawned_agent_status("recon-1", "recon", AgentStatus::Completed, None);
        app.update_spawned_agent_status("scanner-1", "scanner", AgentStatus::Executing, None);
        app.mark_finished(false);
        // Already-terminal agents keep their result; still-active ones are cancelled.
        assert_eq!(app.agents["recon-1"].status, AgentStatus::Completed);
        assert_eq!(app.agents["scanner-1"].status, AgentStatus::Cancelled);
        assert!(!app.finished_success);
    }

    #[test]
    fn mark_finished_is_idempotent() {
        let mut app = App::new("example.com", "sess-1", None);
        app.mark_finished(true);
        let frozen = app.finished_at;
        app.mark_finished(false);
        // A second call must not overwrite the recorded finish instant/result.
        assert_eq!(app.finished_at, frozen);
        assert!(app.finished_success);
    }

    #[test]
    fn test_app_creation() {
        let app = App::new("example.com", "session-123", None);
        assert_eq!(app.target, "example.com");
        assert_eq!(app.session_id, "session-123");
        assert_eq!(app.focus, Pane::Agents);
        assert!(app.overlay.is_none());
        assert!(!app.should_quit);
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
    fn test_ordered_agents_orchestrator_first() {
        let mut app = App::new("test.com", "test-session", None);
        app.update_spawned_agent_status("recon-1", "recon", AgentStatus::Streaming, None);
        app.update_spawned_agent_status("scanner-1", "scanner", AgentStatus::Streaming, None);

        let ordered = app.ordered_agents();
        assert_eq!(ordered.len(), 3);
        assert_eq!(ordered[0].0, "orchestrator");
        assert_eq!(ordered[1].0, "recon-1");
        assert_eq!(ordered[2].0, "scanner-1");
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
    fn test_add_finding_and_sorted_order() {
        let mut app = App::new("test.com", "test-session", None);
        app.add_finding(finding(Severity::Low, "low-net", FindingSource::Net));
        app.add_finding(finding(
            Severity::Critical,
            "crit-sast",
            FindingSource::Sast,
        ));
        app.add_finding(finding(Severity::Medium, "med-dep", FindingSource::Dep));
        // Second critical added later must sort before the earlier one (recent-first tie).
        app.add_finding(finding(
            Severity::Critical,
            "crit-later",
            FindingSource::Secret,
        ));

        let sorted = app.sorted_findings();
        assert_eq!(sorted.len(), 4);
        assert_eq!(sorted[0].title, "crit-later");
        assert_eq!(sorted[1].title, "crit-sast");
        assert_eq!(sorted[2].title, "med-dep");
        assert_eq!(sorted[3].title, "low-net");
    }

    #[test]
    fn test_severity_counts_mixed_sources() {
        let mut app = App::new("test.com", "test-session", None);
        app.add_finding(finding(Severity::Critical, "a", FindingSource::Net));
        app.add_finding(finding(Severity::Critical, "b", FindingSource::Sast));
        app.add_finding(finding(Severity::High, "c", FindingSource::Dep));
        app.add_finding(finding(Severity::Medium, "d", FindingSource::Secret));
        app.add_finding(finding(Severity::Info, "e", FindingSource::Net));

        // [critical, high, medium, low, info]
        assert_eq!(app.severity_counts(), [2, 1, 1, 0, 1]);
    }

    #[test]
    fn test_focus_cycle() {
        let mut app = App::new("test.com", "test-session", None);
        assert_eq!(app.focus, Pane::Agents);
        app.focus_next();
        assert_eq!(app.focus, Pane::Findings);
        app.focus_next();
        assert_eq!(app.focus, Pane::Activity);
        app.focus_next();
        assert_eq!(app.focus, Pane::Agents);
        app.focus_prev();
        assert_eq!(app.focus, Pane::Activity);
    }

    #[test]
    fn test_move_down_clamps_on_agents() {
        let mut app = App::new("test.com", "test-session", None);
        app.update_spawned_agent_status("recon-1", "recon", AgentStatus::Streaming, None);
        // 2 agents total (orchestrator + recon-1); max index is 1.
        app.focus = Pane::Agents;
        app.move_down();
        assert_eq!(app.agents_selected, 1);
        app.move_down();
        assert_eq!(app.agents_selected, 1); // clamped
        app.move_up();
        assert_eq!(app.agents_selected, 0);
    }

    #[test]
    fn test_overlay_open_close() {
        let mut app = App::new("test.com", "test-session", None);
        assert!(app.overlay.is_none());
        app.open_overlay(Overlay::Help);
        assert_eq!(app.overlay, Some(Overlay::Help));
        app.close_overlay();
        assert!(app.overlay.is_none());
    }

    #[test]
    fn test_finding_source_tags() {
        assert_eq!(FindingSource::Net.tag(), "NET");
        assert_eq!(
            FindingSource::from(FindingType::Dependency),
            FindingSource::Dep
        );
        assert_eq!(FindingSource::from(FindingType::Sast), FindingSource::Sast);
        assert_eq!(
            FindingSource::from(FindingType::Secret),
            FindingSource::Secret
        );
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
}
