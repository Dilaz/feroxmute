# Dynamic Agent Keys & Streaming Thinking Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix TUI agent navigation (keys 1-9 dynamically map to agents) and add streaming thinking display per agent.

**Architecture:** Update TUI data model to store per-agent thinking with spawn order tracking. Replace rig-core's `.prompt().multi_turn()` with `.stream_prompt().multi_turn()` to capture reasoning blocks in real-time. Route thinking updates through the event channel to per-agent buffers.

**Tech Stack:** Rust, rig-core 0.27 streaming API, ratatui TUI, tokio channels

---

## Task 1: Update AgentDisplayInfo Struct

**Files:**
- Modify: `feroxmute-cli/src/tui/app.rs:82-88`

**Step 1: Add new imports**

At the top of `app.rs`, add `VecDeque`:

```rust
use std::collections::VecDeque;
```

**Step 2: Update AgentDisplayInfo struct**

Replace the existing struct:

```rust
/// Display info for a dynamically spawned agent
#[derive(Debug, Clone, Default)]
pub struct AgentDisplayInfo {
    pub agent_type: String,
    pub status: AgentStatus,
    pub activity: String,
    pub spawn_order: usize,
    pub thinking: Option<String>,
    pub output_buffer: VecDeque<String>,
}

impl AgentDisplayInfo {
    pub fn new_orchestrator() -> Self {
        Self {
            agent_type: "orchestrator".to_string(),
            status: AgentStatus::Idle,
            activity: String::new(),
            spawn_order: 0,
            thinking: None,
            output_buffer: VecDeque::with_capacity(100),
        }
    }

    pub fn push_output(&mut self, line: String) {
        if self.output_buffer.len() >= 100 {
            self.output_buffer.pop_front();
        }
        self.output_buffer.push_back(line);
    }
}
```

**Step 3: Run cargo check**

Run: `cargo check -p feroxmute-cli`
Expected: Errors about missing `spawn_order`, `thinking`, `output_buffer` fields in other code

**Step 4: Commit**

```bash
git add feroxmute-cli/src/tui/app.rs
git commit -m "feat(tui): add spawn_order, thinking, output_buffer to AgentDisplayInfo"
```

---

## Task 2: Update App Struct and View Enum

**Files:**
- Modify: `feroxmute-cli/src/tui/app.rs:14-29` (View enum)
- Modify: `feroxmute-cli/src/tui/app.rs:119-167` (App struct)

**Step 1: Replace View enum**

```rust
/// Active view in the TUI
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum View {
    #[default]
    Dashboard,
    AgentDetail(String),  // Agent name instead of AgentView enum
    Logs,
    Help,
}
```

**Step 2: Remove AgentView enum**

Delete the entire `AgentView` enum (lines 23-29).

**Step 3: Update App struct**

Add new fields and remove `current_thinking`:

```rust
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
}
```

**Step 4: Update App::new()**

```rust
pub fn new(
    target: impl Into<String>,
    session_id: impl Into<String>,
    event_rx: Option<mpsc::Receiver<AgentEvent>>,
) -> Self {
    let mut agents = std::collections::HashMap::new();
    // Pre-register orchestrator with spawn_order 0
    agents.insert("orchestrator".to_string(), AgentDisplayInfo::new_orchestrator());

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
        log_scroll: 0,
        selected_feed: 0,
        feed_scroll_x: 0,
        source_path: None,
        detected_languages: Vec::new(),
        code_findings: Vec::new(),
        code_finding_counts: CodeFindingCounts::default(),
        event_rx,
    }
}
```

**Step 5: Add get_agent_by_key method**

```rust
/// Get agent name by key number (1-9)
pub fn get_agent_by_key(&self, key: usize) -> Option<String> {
    if key == 1 {
        return Some("orchestrator".to_string());
    }
    // Find agent with spawn_order == key - 1
    self.agents.iter()
        .find(|(name, info)| *name != "orchestrator" && info.spawn_order == key - 1)
        .map(|(name, _)| name.clone())
}

/// Get the thinking text for the currently selected agent
pub fn get_selected_thinking(&self) -> Option<&str> {
    self.selected_agent.as_ref()
        .and_then(|name| self.agents.get(name))
        .and_then(|info| info.thinking.as_deref())
}
```

**Step 6: Remove set_thinking method**

Delete the `set_thinking` method (it's now per-agent).

**Step 7: Run cargo check**

Run: `cargo check -p feroxmute-cli`
Expected: Errors about `AgentView` and `current_thinking` not found

**Step 8: Commit**

```bash
git add feroxmute-cli/src/tui/app.rs
git commit -m "feat(tui): update App with dynamic agent support, remove AgentView enum"
```

---

## Task 3: Update Agent Status Methods

**Files:**
- Modify: `feroxmute-cli/src/tui/app.rs:234-284` (update methods)

**Step 1: Update update_spawned_agent_status**

```rust
/// Update spawned agent status with spawn order tracking
pub fn update_spawned_agent_status(
    &mut self,
    agent: &str,
    agent_type: &str,
    status: AgentStatus,
) {
    if let Some(info) = self.agents.get_mut(agent) {
        info.status = status;
        if !agent_type.is_empty() {
            info.agent_type = agent_type.to_string();
        }
    } else if agent != "system" {
        // New agent - assign next spawn_order
        self.agent_spawn_counter += 1;
        self.agents.insert(
            agent.to_string(),
            AgentDisplayInfo {
                agent_type: agent_type.to_string(),
                status,
                activity: String::new(),
                spawn_order: self.agent_spawn_counter,
                thinking: None,
                output_buffer: VecDeque::with_capacity(100),
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
```

**Step 2: Run cargo check**

Run: `cargo check -p feroxmute-cli`
Expected: May still have errors from other files

**Step 3: Commit**

```bash
git add feroxmute-cli/src/tui/app.rs
git commit -m "feat(tui): add spawn order tracking and per-agent thinking"
```

---

## Task 4: Update App Tests

**Files:**
- Modify: `feroxmute-cli/src/tui/app.rs:351-415` (tests)

**Step 1: Update navigation test**

```rust
#[test]
fn test_navigation() {
    let mut app = App::new("test.com", "test-session", None);
    assert_eq!(app.view, View::Dashboard);

    app.navigate(View::Logs);
    assert_eq!(app.view, View::Logs);

    app.navigate(View::AgentDetail("orchestrator".to_string()));
    assert_eq!(app.view, View::AgentDetail("orchestrator".to_string()));
}
```

**Step 2: Add get_agent_by_key test**

```rust
#[test]
fn test_get_agent_by_key() {
    let mut app = App::new("test.com", "test-session", None);

    // Key 1 always returns orchestrator
    assert_eq!(app.get_agent_by_key(1), Some("orchestrator".to_string()));

    // No agent at key 2 yet
    assert_eq!(app.get_agent_by_key(2), None);

    // Spawn an agent
    app.update_spawned_agent_status("recon-1", "recon", AgentStatus::Running);

    // Now key 2 returns recon-1
    assert_eq!(app.get_agent_by_key(2), Some("recon-1".to_string()));

    // Spawn another
    app.update_spawned_agent_status("scanner-1", "scanner", AgentStatus::Running);
    assert_eq!(app.get_agent_by_key(3), Some("scanner-1".to_string()));
}

#[test]
fn test_agent_thinking() {
    let mut app = App::new("test.com", "test-session", None);

    app.update_agent_thinking("orchestrator", Some("Planning attack...".to_string()));

    assert_eq!(
        app.agents.get("orchestrator").unwrap().thinking,
        Some("Planning attack...".to_string())
    );

    app.selected_agent = Some("orchestrator".to_string());
    assert_eq!(app.get_selected_thinking(), Some("Planning attack..."));
}
```

**Step 3: Run tests**

Run: `cargo test -p feroxmute-cli app::tests`
Expected: PASS

**Step 4: Commit**

```bash
git add feroxmute-cli/src/tui/app.rs
git commit -m "test(tui): add tests for dynamic agent keys and thinking"
```

---

## Task 5: Update AgentEvent Enum

**Files:**
- Modify: `feroxmute-cli/src/tui/channel.rs:17-52`

**Step 1: Update Thinking variant**

```rust
/// Events sent from agent to TUI
#[derive(Debug, Clone)]
pub enum AgentEvent {
    /// Add entry to activity feed
    Feed {
        agent: String,
        message: String,
        is_error: bool,
    },

    /// Update the thinking panel for a specific agent
    Thinking {
        agent: String,
        content: Option<String>,
    },

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
```

**Step 2: Run cargo check**

Run: `cargo check -p feroxmute-cli`
Expected: Errors about pattern matching in runner.rs

**Step 3: Commit**

```bash
git add feroxmute-cli/src/tui/channel.rs
git commit -m "feat(tui): update AgentEvent::Thinking to be per-agent"
```

---

## Task 6: Update Runner Event Handling

**Files:**
- Modify: `feroxmute-cli/src/tui/runner.rs:246-248`

**Step 1: Update Thinking event handler**

```rust
AgentEvent::Thinking { agent, content } => {
    app.update_agent_thinking(&agent, content);
}
```

**Step 2: Run cargo check**

Run: `cargo check -p feroxmute-cli`
Expected: Fewer errors

**Step 3: Commit**

```bash
git add feroxmute-cli/src/tui/runner.rs
git commit -m "feat(tui): handle per-agent thinking events"
```

---

## Task 7: Update Event Key Handling

**Files:**
- Modify: `feroxmute-cli/src/tui/events.rs:6` (imports)
- Modify: `feroxmute-cli/src/tui/events.rs:60-71` (key handlers)

**Step 1: Update imports**

```rust
use super::app::{App, View};
```

Remove `AgentView` from the import.

**Step 2: Replace hardcoded key handlers**

Replace lines 60-71:

```rust
// Dynamic agent views (number keys 1-9)
KeyCode::Char(c @ '1'..='9') => {
    let key_num = c.to_digit(10).unwrap() as usize;
    if let Some(agent_name) = app.get_agent_by_key(key_num) {
        app.selected_agent = Some(agent_name.clone());
        app.navigate(View::AgentDetail(agent_name));
    }
}
```

**Step 3: Run cargo check**

Run: `cargo check -p feroxmute-cli`
Expected: Errors in agent_detail.rs about AgentView

**Step 4: Update tests**

```rust
#[test]
fn test_navigation_to_agent_detail() {
    let mut app = App::new("test.com", "test-session", None);

    let key = KeyEvent::new(KeyCode::Char('1'), KeyModifiers::NONE);
    handle_key_event(&mut app, key);
    assert_eq!(app.view, View::AgentDetail("orchestrator".to_string()));

    // Key 2 with no spawned agent does nothing
    let key = KeyEvent::new(KeyCode::Char('2'), KeyModifiers::NONE);
    app.navigate(View::Dashboard);
    handle_key_event(&mut app, key);
    assert_eq!(app.view, View::Dashboard);
}
```

**Step 5: Commit**

```bash
git add feroxmute-cli/src/tui/events.rs
git commit -m "feat(tui): dynamic 1-9 key handling for agent views"
```

---

## Task 8: Update Agent Detail Widget

**Files:**
- Modify: `feroxmute-cli/src/tui/widgets/agent_detail.rs`

**Step 1: Update render function signature**

```rust
/// Render the agent detail view
pub fn render(frame: &mut Frame, app: &App, agent_name: &str) {
    // Delegate to SAST widget for SAST agent type
    if let Some(info) = app.agents.get(agent_name) {
        if info.agent_type == "sast" {
            super::sast::render(frame, app, frame.area());
            return;
        }
    }

    let thinking = app.agents.get(agent_name)
        .and_then(|a| a.thinking.as_ref());
    let show_thinking = app.show_thinking && thinking.is_some();

    let constraints = if show_thinking {
        vec![
            Constraint::Length(3), // Header
            Constraint::Min(10),   // Output
            Constraint::Length(8), // Thinking
            Constraint::Length(1), // Footer
        ]
    } else {
        vec![
            Constraint::Length(3), // Header
            Constraint::Min(10),   // Output
            Constraint::Length(1), // Footer
        ]
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(frame.area());

    render_header(frame, app, agent_name, chunks[0]);
    render_output(frame, app, agent_name, chunks[1]);

    if show_thinking {
        render_thinking(frame, thinking, chunks[2]);
        render_footer(frame, agent_name, app, chunks[3]);
    } else {
        render_footer(frame, agent_name, app, chunks[2]);
    }
}
```

**Step 2: Update render_header**

```rust
fn render_header(frame: &mut Frame, app: &App, agent_name: &str, area: Rect) {
    let (display_name, status) = if let Some(info) = app.agents.get(agent_name) {
        let name = if info.agent_type.is_empty() {
            agent_name.to_string()
        } else {
            format!("{} ({})", agent_name, info.agent_type)
        };
        (name, info.status)
    } else {
        (agent_name.to_string(), AgentStatus::Idle)
    };

    let (status_text, status_style) = format_status(status);

    let header_text = vec![Line::from(vec![
        Span::styled(
            &display_name,
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  |  "),
        Span::styled("Status: ", Style::default().fg(Color::Gray)),
        Span::styled(status_text, status_style),
    ])];

    let header = Paragraph::new(header_text).block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" {} ", display_name)),
    );

    frame.render_widget(header, area);
}
```

**Step 3: Update render_output**

```rust
fn render_output(frame: &mut Frame, app: &App, agent_name: &str, area: Rect) {
    let output_text: Vec<Line> = app
        .feed
        .iter()
        .filter(|entry| entry.agent == agent_name)
        .rev()
        .map(|entry| {
            let style = if entry.is_error {
                Style::default().fg(Color::Red)
            } else {
                Style::default()
            };
            Line::from(Span::styled(&entry.message, style))
        })
        .collect();

    let content = if output_text.is_empty() {
        vec![Line::from(Span::styled(
            "No output yet...",
            Style::default().fg(Color::DarkGray),
        ))]
    } else {
        output_text
    };

    let output = Paragraph::new(content)
        .wrap(Wrap { trim: false })
        .scroll((app.log_scroll as u16, 0))
        .block(Block::default().borders(Borders::ALL).title(" Output "));

    frame.render_widget(output, area);
}
```

**Step 4: Update render_thinking**

```rust
fn render_thinking(frame: &mut Frame, thinking: Option<&String>, area: Rect) {
    let thinking_text = thinking
        .map(|s| s.as_str())
        .unwrap_or("No current thinking...");

    let thinking_widget = Paragraph::new(thinking_text)
        .style(Style::default().fg(Color::Yellow))
        .wrap(Wrap { trim: true })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Thinking ")
                .border_style(Style::default().fg(Color::Yellow)),
        );

    frame.render_widget(thinking_widget, area);
}
```

**Step 5: Update render_footer**

```rust
fn render_footer(frame: &mut Frame, current_agent: &str, app: &App, area: Rect) {
    let current_key = if current_agent == "orchestrator" {
        "1".to_string()
    } else {
        app.agents.get(current_agent)
            .map(|a| (a.spawn_order + 1).to_string())
            .unwrap_or("?".to_string())
    };

    // Count available agents (excluding orchestrator which is always 1)
    let spawned_count = app.agents.len().saturating_sub(1);
    let max_key = (spawned_count + 1).min(9);
    let agents_hint = if max_key > 1 {
        format!("1-{}", max_key)
    } else {
        "1".to_string()
    };

    let help = Line::from(vec![
        Span::styled("h", Style::default().fg(Color::Yellow)),
        Span::raw(" back  "),
        Span::styled("j/k", Style::default().fg(Color::Yellow)),
        Span::raw(" scroll  "),
        Span::styled("t", Style::default().fg(Color::Yellow)),
        Span::raw(" thinking  "),
        Span::styled(&agents_hint, Style::default().fg(Color::Yellow)),
        Span::raw(" agents  "),
        Span::styled(&current_key, Style::default().fg(Color::Cyan)),
        Span::raw(" (current)  "),
        Span::styled("q", Style::default().fg(Color::Yellow)),
        Span::raw(" quit"),
    ]);

    let footer = Paragraph::new(help).style(Style::default().fg(Color::DarkGray));
    frame.render_widget(footer, area);
}
```

**Step 6: Run cargo check**

Run: `cargo check -p feroxmute-cli`
Expected: Errors in runner.rs about View::AgentDetail pattern

**Step 7: Commit**

```bash
git add feroxmute-cli/src/tui/widgets/agent_detail.rs
git commit -m "feat(tui): update agent_detail to use dynamic agent names"
```

---

## Task 9: Update Runner Render Call

**Files:**
- Modify: `feroxmute-cli/src/tui/runner.rs:21-24`

**Step 1: Update render function**

```rust
fn render(frame: &mut Frame, app: &App) {
    match &app.view {
        View::Dashboard => dashboard::render(frame, app),
        View::AgentDetail(agent_name) => agent_detail::render(frame, app, agent_name),
        View::Logs => render_logs(frame, app),
        View::Help => render_help(frame),
    }

    if app.confirm_quit {
        render_quit_dialog(frame);
    }
}
```

**Step 2: Run cargo check**

Run: `cargo check -p feroxmute-cli`
Expected: Should compile now

**Step 3: Commit**

```bash
git add feroxmute-cli/src/tui/runner.rs
git commit -m "feat(tui): update runner for dynamic agent views"
```

---

## Task 10: Update Dashboard Footer

**Files:**
- Modify: `feroxmute-cli/src/tui/widgets/dashboard.rs:300-316`

**Step 1: Update footer to show dynamic agent count**

```rust
fn render_footer(frame: &mut Frame, app: &App, area: Rect) {
    let spawned_count = app.agents.len().saturating_sub(1);
    let max_key = (spawned_count + 1).min(9);
    let agents_hint = if max_key > 1 {
        format!("1-{}", max_key)
    } else {
        "1".to_string()
    };

    let help = Line::from(vec![
        Span::styled("q", Style::default().fg(Color::Yellow)),
        Span::raw(" quit  "),
        Span::styled(&agents_hint, Style::default().fg(Color::Yellow)),
        Span::raw(" agents  "),
        Span::styled("l", Style::default().fg(Color::Yellow)),
        Span::raw(" logs  "),
        Span::styled("t", Style::default().fg(Color::Yellow)),
        Span::raw(" thinking  "),
        Span::styled("?", Style::default().fg(Color::Yellow)),
        Span::raw(" help"),
    ]);

    let footer = Paragraph::new(help).style(Style::default().fg(Color::DarkGray));
    frame.render_widget(footer, area);
}
```

**Step 2: Update render function call**

Change `render_footer(frame, chunks[4]);` to `render_footer(frame, app, chunks[4]);`

**Step 3: Run cargo check**

Run: `cargo check -p feroxmute-cli`
Expected: PASS

**Step 4: Commit**

```bash
git add feroxmute-cli/src/tui/widgets/dashboard.rs
git commit -m "feat(tui): dynamic agent count in dashboard footer"
```

---

## Task 11: Update Help Screen

**Files:**
- Modify: `feroxmute-cli/src/tui/runner.rs:149-183`

**Step 1: Update help text**

```rust
Line::from(vec![
    Span::styled("  1-9        ", Style::default().fg(Color::Yellow)),
    Span::raw("Agent details (1=orchestrator, 2-9=spawned)"),
]),
```

Remove the individual 1, 2, 3, 4 lines and replace with this single line.

**Step 2: Run cargo check**

Run: `cargo check -p feroxmute-cli`
Expected: PASS

**Step 3: Commit**

```bash
git add feroxmute-cli/src/tui/runner.rs
git commit -m "docs(tui): update help screen for dynamic agent keys"
```

---

## Task 12: Add send_thinking to EventSender Trait

**Files:**
- Modify: `feroxmute-core/src/tools/orchestrator.rs:35-44`

**Step 1: Add send_thinking method**

```rust
/// Trait for sending events to the UI (implemented by CLI)
pub trait EventSender: Send + Sync {
    /// Send a feed message
    fn send_feed(&self, agent: &str, message: &str, is_error: bool);
    /// Send a status update
    fn send_status(&self, agent: &str, agent_type: &str, status: AgentStatus);
    /// Send metrics update
    fn send_metrics(&self, input_tokens: u64, output_tokens: u64, cache_read_tokens: u64, cost_usd: f64);
    /// Send vulnerability found
    fn send_vulnerability(&self, severity: Severity, title: &str);
    /// Send thinking update for an agent
    fn send_thinking(&self, agent: &str, content: Option<String>);
}
```

**Step 2: Run cargo check**

Run: `cargo check -p feroxmute-core`
Expected: Errors about missing implementation in CLI

**Step 3: Commit**

```bash
git add feroxmute-core/src/tools/orchestrator.rs
git commit -m "feat(core): add send_thinking to EventSender trait"
```

---

## Task 13: Implement send_thinking in TuiEventSender

**Files:**
- Modify: `feroxmute-cli/src/runner.rs:28-93`

**Step 1: Add send_thinking implementation**

After `send_vulnerability`:

```rust
fn send_thinking(&self, agent: &str, content: Option<String>) {
    let tx = self.tx.clone();
    let agent = agent.to_string();
    tokio::spawn(async move {
        let _ = tx
            .send(AgentEvent::Thinking { agent, content })
            .await;
    });
}
```

**Step 2: Run cargo check**

Run: `cargo check -p feroxmute-cli`
Expected: PASS

**Step 3: Run all tests**

Run: `cargo test -p feroxmute-cli`
Expected: All tests pass

**Step 4: Commit**

```bash
git add feroxmute-cli/src/runner.rs
git commit -m "feat(cli): implement send_thinking for TuiEventSender"
```

---

## Task 14: Update Provider Macro for Streaming (Part 1 - Imports)

**Files:**
- Modify: `feroxmute-core/src/providers/macros.rs:1-10`

**Step 1: Add documentation about streaming**

```rust
//! Macro for generating LLM provider implementations
//!
//! This module provides the `define_provider!` macro which generates complete provider
//! implementations with constructors and LlmProvider trait impl, eliminating 95% code
//! duplication across provider files.
//!
//! ## Streaming Support
//!
//! All provider methods use rig-core's streaming API to capture reasoning/thinking
//! in real-time. The `StreamedAssistantContent::Reasoning` variant contains thinking
//! blocks which are forwarded to the TUI via `EventSender::send_thinking()`.
```

**Step 2: Commit**

```bash
git add feroxmute-core/src/providers/macros.rs
git commit -m "docs(providers): document streaming support in macro"
```

---

## Task 15: Update complete_with_shell for Streaming

**Files:**
- Modify: `feroxmute-core/src/providers/macros.rs:171-223`

**Step 1: Replace complete_with_shell implementation**

```rust
async fn complete_with_shell(
    &self,
    system_prompt: &str,
    user_prompt: &str,
    container: std::sync::Arc<$crate::docker::ContainerManager>,
    events: std::sync::Arc<dyn $crate::tools::EventSender>,
    agent_name: &str,
    limitations: std::sync::Arc<$crate::limitations::EngagementLimitations>,
) -> $crate::Result<String> {
    use futures::StreamExt;
    use rig::streaming::{StreamingPrompt, MultiTurnStreamItem, StreamedAssistantContent};

    let events_clone = std::sync::Arc::clone(&events);
    let agent_name_owned = agent_name.to_string();

    let agent = self
        .client
        .agent(&self.model)
        .preamble(system_prompt)
        .max_tokens(4096)
        .tool($crate::tools::DockerShellTool::new(
            container,
            std::sync::Arc::clone(&events),
            agent_name.to_string(),
            limitations,
        ))
        .build();

    let mut stream = agent.stream_prompt(user_prompt).multi_turn(50);
    let mut final_text = String::new();
    let mut total_input_tokens: u64 = 0;
    let mut total_output_tokens: u64 = 0;

    while let Some(item) = stream.next().await {
        match item {
            Ok(MultiTurnStreamItem::StreamItem(content)) => {
                match content {
                    StreamedAssistantContent::Reasoning(reasoning) => {
                        let text = reasoning.reasoning.join("");
                        events_clone.send_thinking(&agent_name_owned, Some(text));
                    }
                    StreamedAssistantContent::Text(text) => {
                        final_text.push_str(&text.text);
                    }
                    _ => {}
                }
            }
            Ok(MultiTurnStreamItem::FinalResponse(res)) => {
                total_input_tokens = res.usage.input_tokens;
                total_output_tokens = res.usage.output_tokens;
            }
            Err(e) => {
                events_clone.send_thinking(&agent_name_owned, None);
                return Err($crate::Error::Provider(format!("Shell streaming failed: {}", e)));
            }
            _ => {}
        }
    }

    // Clear thinking when done
    events_clone.send_thinking(&agent_name_owned, None);

    // Calculate cost
    let pricing = $crate::pricing::PricingConfig::load();
    let cost = pricing.calculate_cost(
        $provider_name,
        &self.model,
        total_input_tokens,
        total_output_tokens,
    );

    events_clone.send_metrics(
        total_input_tokens,
        total_output_tokens,
        0,
        cost,
    );

    Ok(final_text)
}
```

**Step 2: Run cargo check**

Run: `cargo check -p feroxmute-core`
Expected: May have trait bound errors, we'll fix in next task

**Step 3: Commit**

```bash
git add feroxmute-core/src/providers/macros.rs
git commit -m "feat(providers): add streaming with thinking capture to complete_with_shell"
```

---

## Task 16: Update complete_with_orchestrator for Streaming

**Files:**
- Modify: `feroxmute-core/src/providers/macros.rs:225-280`

**Step 1: Replace complete_with_orchestrator implementation**

```rust
async fn complete_with_orchestrator(
    &self,
    system_prompt: &str,
    user_prompt: &str,
    context: std::sync::Arc<$crate::tools::OrchestratorContext>,
) -> $crate::Result<String> {
    use futures::StreamExt;
    use rig::streaming::{StreamingPrompt, MultiTurnStreamItem, StreamedAssistantContent};

    let events = std::sync::Arc::clone(&context.events);
    let agent_name = "orchestrator".to_string();

    let agent = self
        .client
        .agent(&self.model)
        .preamble(system_prompt)
        .max_tokens(4096)
        .tool($crate::tools::SpawnAgentTool::new(std::sync::Arc::clone(&context)))
        .tool($crate::tools::WaitForAgentTool::new(std::sync::Arc::clone(&context)))
        .tool($crate::tools::WaitForAnyTool::new(std::sync::Arc::clone(&context)))
        .tool($crate::tools::ListAgentsTool::new(std::sync::Arc::clone(&context)))
        .tool($crate::tools::RecordFindingTool::new(std::sync::Arc::clone(&context)))
        .tool($crate::tools::CompleteEngagementTool::new(std::sync::Arc::clone(&context)))
        .build();

    let mut stream = agent.stream_prompt(user_prompt).multi_turn(50);
    let mut final_text = String::new();
    let mut total_input_tokens: u64 = 0;
    let mut total_output_tokens: u64 = 0;

    // Run with cancellation support
    loop {
        tokio::select! {
            item = stream.next() => {
                match item {
                    Some(Ok(MultiTurnStreamItem::StreamItem(content))) => {
                        match content {
                            StreamedAssistantContent::Reasoning(reasoning) => {
                                let text = reasoning.reasoning.join("");
                                events.send_thinking(&agent_name, Some(text));
                            }
                            StreamedAssistantContent::Text(text) => {
                                final_text.push_str(&text.text);
                            }
                            _ => {}
                        }
                    }
                    Some(Ok(MultiTurnStreamItem::FinalResponse(res))) => {
                        total_input_tokens = res.usage.input_tokens;
                        total_output_tokens = res.usage.output_tokens;
                    }
                    Some(Err(e)) => {
                        events.send_thinking(&agent_name, None);
                        return Err($crate::Error::Provider(format!("Orchestrator streaming failed: {}", e)));
                    }
                    None => break,
                    _ => {}
                }
            }
            _ = context.cancel.cancelled() => {
                events.send_thinking(&agent_name, None);
                let findings = context.findings.lock().await;
                return Ok(format!("Engagement completed with {} findings", findings.len()));
            }
        }
    }

    // Clear thinking when done
    events.send_thinking(&agent_name, None);

    // Calculate cost
    let pricing = $crate::pricing::PricingConfig::load();
    let cost = pricing.calculate_cost(
        $provider_name,
        &self.model,
        total_input_tokens,
        total_output_tokens,
    );

    events.send_metrics(
        total_input_tokens,
        total_output_tokens,
        0,
        cost,
    );

    Ok(final_text)
}
```

**Step 2: Run cargo check**

Run: `cargo check -p feroxmute-core`
Expected: Check for errors

**Step 3: Commit**

```bash
git add feroxmute-core/src/providers/macros.rs
git commit -m "feat(providers): add streaming to complete_with_orchestrator"
```

---

## Task 17: Update complete_with_report for Streaming

**Files:**
- Modify: `feroxmute-core/src/providers/macros.rs:282-330`

**Step 1: Replace complete_with_report implementation**

```rust
async fn complete_with_report(
    &self,
    system_prompt: &str,
    user_prompt: &str,
    context: std::sync::Arc<$crate::tools::ReportContext>,
) -> $crate::Result<String> {
    use futures::StreamExt;
    use rig::streaming::{StreamingPrompt, MultiTurnStreamItem, StreamedAssistantContent};

    let events = std::sync::Arc::clone(&context.events);
    let agent_name = "report".to_string();

    let agent = self
        .client
        .agent(&self.model)
        .preamble(system_prompt)
        .max_tokens(4096)
        .tool($crate::tools::GenerateReportTool::new(std::sync::Arc::clone(&context)))
        .tool($crate::tools::ExportJsonTool::new(std::sync::Arc::clone(&context)))
        .tool($crate::tools::ExportMarkdownTool::new(std::sync::Arc::clone(&context)))
        .tool($crate::tools::AddRecommendationTool::new(std::sync::Arc::clone(&context)))
        .build();

    let mut stream = agent.stream_prompt(user_prompt).multi_turn(20);
    let mut final_text = String::new();
    let mut total_input_tokens: u64 = 0;
    let mut total_output_tokens: u64 = 0;

    while let Some(item) = stream.next().await {
        match item {
            Ok(MultiTurnStreamItem::StreamItem(content)) => {
                match content {
                    StreamedAssistantContent::Reasoning(reasoning) => {
                        let text = reasoning.reasoning.join("");
                        events.send_thinking(&agent_name, Some(text));
                    }
                    StreamedAssistantContent::Text(text) => {
                        final_text.push_str(&text.text);
                    }
                    _ => {}
                }
            }
            Ok(MultiTurnStreamItem::FinalResponse(res)) => {
                total_input_tokens = res.usage.input_tokens;
                total_output_tokens = res.usage.output_tokens;
            }
            Err(e) => {
                events.send_thinking(&agent_name, None);
                return Err($crate::Error::Provider(format!("Report streaming failed: {}", e)));
            }
            _ => {}
        }
    }

    // Clear thinking when done
    events.send_thinking(&agent_name, None);

    // Calculate cost
    let pricing = $crate::pricing::PricingConfig::load();
    let cost = pricing.calculate_cost(
        $provider_name,
        &self.model,
        total_input_tokens,
        total_output_tokens,
    );

    events.send_metrics(
        total_input_tokens,
        total_output_tokens,
        0,
        cost,
    );

    Ok(final_text)
}
```

**Step 2: Run cargo check**

Run: `cargo check -p feroxmute-core`
Expected: PASS or minor errors to fix

**Step 3: Commit**

```bash
git add feroxmute-core/src/providers/macros.rs
git commit -m "feat(providers): add streaming to complete_with_report"
```

---

## Task 18: Add futures Dependency

**Files:**
- Modify: `feroxmute-core/Cargo.toml`

**Step 1: Check if futures is already a dependency**

Run: `grep futures feroxmute-core/Cargo.toml`

**Step 2: Add if missing**

```toml
futures = "0.3"
```

**Step 3: Run cargo build**

Run: `cargo build -p feroxmute-core`
Expected: PASS

**Step 4: Commit**

```bash
git add feroxmute-core/Cargo.toml
git commit -m "chore(deps): add futures for streaming support"
```

---

## Task 19: Run Full Test Suite

**Files:** None (testing only)

**Step 1: Run all tests**

Run: `cargo test --workspace`
Expected: All tests pass

**Step 2: Run clippy**

Run: `cargo clippy --workspace -- -D warnings`
Expected: No errors

**Step 3: Run fmt check**

Run: `cargo fmt --check`
Expected: No formatting issues

**Step 4: Final commit if any fixes needed**

```bash
git add -A
git commit -m "fix: address test and lint issues"
```

---

## Task 20: Manual Testing

**Step 1: Build release**

Run: `cargo build --release`

**Step 2: Test key bindings**

1. Start the TUI
2. Press `1` - should show orchestrator view
3. Press `2` - should do nothing (no spawned agents yet)
4. Wait for agents to spawn
5. Press `2`, `3`, etc. - should show spawned agent views
6. Press `h` - should return to dashboard
7. Verify footer shows correct `1-N agents` hint

**Step 3: Test thinking display**

1. Select an agent with `1-9`
2. Verify thinking panel shows that agent's thinking
3. Press `t` to toggle thinking panel
4. Switch agents, verify thinking updates

**Step 4: Document any issues**

Create issues for any bugs found during manual testing.
