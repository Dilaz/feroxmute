# Tool Output Toggle Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add inline expansion of tool outputs in agent detail view using 'o' key.

**Architecture:** Extend the event channel and feed entries to carry optional tool output. Add expansion state to feed entries. Handle 'o' key to toggle expansion and render full output inline with visual grouping.

**Tech Stack:** Rust, ratatui, crossterm, tokio channels

---

### Task 1: Extend AgentEvent::Feed with tool_output

**Files:**
- Modify: `feroxmute-cli/src/tui/channel.rs:17-24`

**Step 1: Add tool_output field to Feed variant**

```rust
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
    // ... rest unchanged
```

**Step 2: Run cargo check**

Run: `cargo check -p feroxmute-cli`
Expected: Errors about missing field in pattern matches - this is expected, we'll fix in later tasks.

---

### Task 2: Extend FeedEntry with tool_output and expanded

**Files:**
- Modify: `feroxmute-cli/src/tui/app.rs:98-125`

**Step 1: Add fields to FeedEntry struct**

```rust
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
```

**Step 2: Run cargo check**

Run: `cargo check -p feroxmute-cli`
Expected: Still has errors (pattern match in drain_events) - will fix next.

---

### Task 3: Update drain_events to handle tool_output

**Files:**
- Modify: `feroxmute-cli/src/tui/runner.rs:227-244`

**Step 1: Update the Feed pattern match**

```rust
AgentEvent::Feed {
    agent,
    message,
    is_error,
    tool_output,
} => {
    // Track activity for non-indented messages
    if !message.starts_with("  ") {
        app.update_agent_activity(&agent, &message);
    }

    let mut entry = if is_error {
        super::app::FeedEntry::error(&agent, &message)
    } else {
        super::app::FeedEntry::new(&agent, &message)
    };

    if let Some(output) = tool_output {
        entry = entry.with_output(output);
    }

    app.add_feed(entry);
}
```

**Step 2: Run cargo check**

Run: `cargo check -p feroxmute-cli`
Expected: PASS (CLI crate compiles)

---

### Task 4: Add send_feed_with_output to EventSender trait

**Files:**
- Modify: `feroxmute-core/src/tools/orchestrator.rs:35-61`

**Step 1: Add new method to EventSender trait**

```rust
/// Trait for sending events to the UI (implemented by CLI)
pub trait EventSender: Send + Sync {
    /// Send a feed message
    fn send_feed(&self, agent: &str, message: &str, is_error: bool);
    /// Send a feed message with tool output attached
    fn send_feed_with_output(&self, agent: &str, message: &str, is_error: bool, output: &str);
    /// Send a status update with optional current tool info
    fn send_status(
        &self,
        agent: &str,
        agent_type: &str,
        status: AgentStatus,
        current_tool: Option<String>,
    );
    // ... rest unchanged
```

**Step 2: Run cargo check**

Run: `cargo check -p feroxmute-core`
Expected: Errors about trait not implemented - we'll fix next.

---

### Task 5: Implement send_feed_with_output in TuiEventSender

**Files:**
- Modify: `feroxmute-cli/src/runner.rs:30-45`

**Step 1: Add implementation after send_feed**

```rust
fn send_feed_with_output(&self, agent: &str, message: &str, is_error: bool, output: &str) {
    let tx = self.tx.clone();
    let agent = agent.to_string();
    let message = message.to_string();
    let output = output.to_string();
    tokio::spawn(async move {
        let _ = tx
            .send(AgentEvent::Feed {
                agent,
                message,
                is_error,
                tool_output: Some(output),
            })
            .await;
    });
}
```

**Step 2: Update existing send_feed to include tool_output: None**

In the existing `send_feed` method, update the `AgentEvent::Feed` construction:

```rust
fn send_feed(&self, agent: &str, message: &str, is_error: bool) {
    let tx = self.tx.clone();
    let agent = agent.to_string();
    let message = message.to_string();
    tokio::spawn(async move {
        let _ = tx
            .send(AgentEvent::Feed {
                agent,
                message,
                is_error,
                tool_output: None,
            })
            .await;
    });
}
```

**Step 3: Run cargo check**

Run: `cargo check`
Expected: PASS (both crates compile)

---

### Task 6: Use send_feed_with_output in shell.rs

**Files:**
- Modify: `feroxmute-core/src/tools/shell.rs:154-163`

**Step 1: Change send_feed to send_feed_with_output for result line**

```rust
// Report result summary (indented)
let line_count = raw_output.lines().count();
self.events.send_feed_with_output(
    &self.agent_name,
    &format!(
        "  -> exit {}, {} lines output",
        result.exit_code, line_count
    ),
    result.exit_code != 0,
    &raw_output,
);
```

**Step 2: Run cargo check**

Run: `cargo check`
Expected: PASS

**Step 3: Commit**

```bash
git add -A
git commit -m "feat(tui): add tool_output field to feed events

Extends AgentEvent::Feed and FeedEntry to carry optional
tool output for inline expansion in agent detail view."
```

---

### Task 7: Add toggle_output method to App

**Files:**
- Modify: `feroxmute-cli/src/tui/app.rs` (after toggle_thinking method, around line 366)

**Step 1: Add method to toggle feed entry expansion**

```rust
/// Toggle output expansion for the currently selected feed entry
pub fn toggle_output(&mut self, agent_filter: Option<&str>) {
    // Get entries that match the filter
    let matching_indices: Vec<usize> = self
        .feed
        .iter()
        .enumerate()
        .filter(|(_, e)| {
            agent_filter.map_or(true, |a| e.agent == a) && e.tool_output.is_some()
        })
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

    if let Some(&idx) = visible_idx {
        if let Some(entry) = self.feed.get_mut(idx) {
            entry.expanded = !entry.expanded;
        }
    }
}
```

**Step 2: Run cargo check**

Run: `cargo check -p feroxmute-cli`
Expected: PASS

---

### Task 8: Handle 'o' key in events.rs

**Files:**
- Modify: `feroxmute-cli/src/tui/events.rs:70-79`

**Step 1: Add key handler for 'o' in AgentDetail view**

After the toggle thinking handler (around line 73), add:

```rust
KeyCode::Char('o') => {
    if let View::AgentDetail(ref agent_name) = app.view {
        app.toggle_output(Some(agent_name));
    }
}
```

**Step 2: Run cargo check**

Run: `cargo check -p feroxmute-cli`
Expected: PASS

---

### Task 9: Update agent_detail render_output for expansion

**Files:**
- Modify: `feroxmute-cli/src/tui/widgets/agent_detail.rs:94-128`

**Step 1: Replace render_output function**

```rust
fn render_output(frame: &mut Frame, app: &App, agent_name: &str, area: Rect) {
    let mut lines: Vec<Line> = Vec::new();

    for entry in app.feed.iter().filter(|e| e.agent == agent_name) {
        let style = if entry.is_error {
            Style::default().fg(Color::Red)
        } else {
            Style::default()
        };
        let time_str = entry.timestamp.format("%H:%M:%S").to_string();

        // Main message line
        lines.push(Line::from(vec![
            Span::styled(time_str, Style::default().fg(Color::DarkGray)),
            Span::raw(" "),
            Span::styled(&entry.message, style),
        ]));

        // If expanded and has output, show it
        if entry.expanded {
            if let Some(ref output) = entry.tool_output {
                for line in output.lines() {
                    lines.push(Line::from(vec![
                        Span::styled("         ", Style::default()),
                        Span::styled("│ ", Style::default().fg(Color::DarkGray)),
                        Span::styled(line, style),
                    ]));
                }
            }
        }
    }

    let content = if lines.is_empty() {
        vec![Line::from(Span::styled(
            "No output yet...",
            Style::default().fg(Color::DarkGray),
        ))]
    } else {
        lines
    };

    let output = Paragraph::new(content)
        .wrap(Wrap { trim: false })
        .scroll((app.log_scroll as u16, 0))
        .block(Block::default().borders(Borders::ALL).title(" Output "));
    frame.render_widget(output, area);
}
```

**Step 2: Run cargo check**

Run: `cargo check -p feroxmute-cli`
Expected: PASS

---

### Task 10: Update footer hint in agent_detail

**Files:**
- Modify: `feroxmute-cli/src/tui/widgets/agent_detail.rs:172-187`

**Step 1: Add 'o' hint to footer**

```rust
let help = Line::from(vec![
    Span::styled("h", Style::default().fg(Color::Yellow)),
    Span::raw(" back  "),
    Span::styled("j/k", Style::default().fg(Color::Yellow)),
    Span::raw(" scroll  "),
    Span::styled("o", Style::default().fg(Color::Yellow)),
    Span::raw(" output  "),
    Span::styled("t", Style::default().fg(Color::Yellow)),
    Span::raw(" thinking "),
    Span::styled(thinking_label, thinking_style),
    Span::raw("  "),
    Span::styled(&agents_hint, Style::default().fg(Color::Yellow)),
    Span::raw(" agents  "),
    Span::styled(&current_key, Style::default().fg(Color::Cyan)),
    Span::raw(" (current)  "),
    Span::styled("q", Style::default().fg(Color::Yellow)),
    Span::raw(" quit"),
]);
```

**Step 2: Run cargo build**

Run: `cargo build`
Expected: PASS

**Step 3: Commit**

```bash
git add -A
git commit -m "feat(tui): add 'o' key to toggle tool output expansion

Press 'o' in agent detail view to expand/collapse the full
output of tool executions inline in the feed."
```

---

### Task 11: Add test for toggle_output

**Files:**
- Modify: `feroxmute-cli/src/tui/app.rs` (in tests module at end)

**Step 1: Add test**

```rust
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
    assert!(!app.feed[1].expanded);

    // Toggle should expand
    app.toggle_output(Some("recon"));
    assert!(app.feed[1].expanded);

    // Toggle again should collapse
    app.toggle_output(Some("recon"));
    assert!(!app.feed[1].expanded);
}
```

**Step 2: Run tests**

Run: `cargo test -p feroxmute-cli toggle_output`
Expected: PASS

**Step 3: Run full test suite**

Run: `cargo test`
Expected: PASS

**Step 4: Final commit**

```bash
git add -A
git commit -m "test(tui): add test for toggle_output functionality"
```

---

## Summary

After completing all tasks:
- Press `o` in agent detail view to expand/collapse tool output
- Full output shown inline with `│` prefix for visual grouping
- Multiple entries can be expanded independently
- Footer shows new `o output` hint
