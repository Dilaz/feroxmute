# Agent Status Visibility Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add real-time status updates from agents to the TUI so users can see what's happening during engagement.

**Architecture:** Add a `reason` field to the shell tool that agents must fill in. The shell tool sends feed events before/after each command. The TUI tracks dynamic agents and displays their current activity.

**Tech Stack:** Rust, ratatui, tokio, chrono

---

## Task 1: Add `reason` Field to Shell Tool Args

**Files:**
- Modify: `feroxmute-core/src/tools/shell.rs:14-18`

**Step 1: Update ShellArgs struct**

In `feroxmute-core/src/tools/shell.rs`, add the `reason` field:

```rust
/// Arguments for the shell tool
#[derive(Debug, Deserialize)]
pub struct ShellArgs {
    /// The shell command to execute
    pub command: String,
    /// Brief explanation shown to user in real-time
    pub reason: String,
}
```

**Step 2: Update tool definition**

In the same file, update the `definition` method (around line 55-69):

```rust
async fn definition(&self, _prompt: String) -> ToolDefinition {
    ToolDefinition {
        name: "shell".to_string(),
        description: "Execute a shell command in a Kali Linux container with pentesting tools installed. Returns combined stdout/stderr and exit code.".to_string(),
        parameters: json!({
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "The shell command to execute (e.g., 'subfinder -d example.com -json')"
                },
                "reason": {
                    "type": "string",
                    "description": "Brief explanation of what this command does and why. This is shown to the user in real-time so they can follow your progress."
                }
            },
            "required": ["command", "reason"]
        }),
    }
}
```

**Step 3: Run cargo check**

Run: `cargo check -p feroxmute-core`
Expected: SUCCESS (reason field added but not yet used)

**Step 4: Commit**

```bash
git add feroxmute-core/src/tools/shell.rs
git commit -m "feat(shell): add required reason field to shell tool args"
```

---

## Task 2: Add EventSender and Agent Name to DockerShellTool

**Files:**
- Modify: `feroxmute-core/src/tools/shell.rs:36-46`
- Modify: `feroxmute-core/src/tools/mod.rs:13`

**Step 1: Import EventSender trait**

At top of `feroxmute-core/src/tools/shell.rs`, add import:

```rust
use crate::tools::EventSender;
```

**Step 2: Update DockerShellTool struct**

Replace the struct (around line 36-39):

```rust
/// Shell tool that executes commands in a Docker container
pub struct DockerShellTool {
    container: Arc<ContainerManager>,
    events: Arc<dyn EventSender>,
    agent_name: String,
}
```

**Step 3: Update constructor**

Replace the `new` method (around line 41-45):

```rust
impl DockerShellTool {
    /// Create a new Docker shell tool
    pub fn new(
        container: Arc<ContainerManager>,
        events: Arc<dyn EventSender>,
        agent_name: String,
    ) -> Self {
        Self {
            container,
            events,
            agent_name,
        }
    }
}
```

**Step 4: Run cargo check**

Run: `cargo check -p feroxmute-core`
Expected: FAIL - providers still calling old constructor

**Step 5: Commit**

```bash
git add feroxmute-core/src/tools/shell.rs
git commit -m "feat(shell): add events and agent_name to DockerShellTool"
```

---

## Task 3: Update Shell Tool to Send Feed Events

**Files:**
- Modify: `feroxmute-core/src/tools/shell.rs:72-86`

**Step 1: Update call method to send events**

Replace the `call` method implementation:

```rust
async fn call(&self, args: Self::Args) -> Result<Self::Output, Self::Error> {
    // Report what we're about to do
    self.events.send_feed(&self.agent_name, &args.reason, false);

    // Report the actual command (indented)
    self.events
        .send_feed(&self.agent_name, &format!("  -> {}", args.command), false);

    // Wrap command to capture both stdout and stderr
    let wrapped_cmd = format!("{} 2>&1", args.command);

    let result = self
        .container
        .exec(vec!["sh", "-c", &wrapped_cmd], None)
        .await
        .map_err(|e| ShellError::Docker(e.to_string()))?;

    // Report result summary (indented)
    let line_count = result.output().lines().count();
    self.events.send_feed(
        &self.agent_name,
        &format!("  -> exit {}, {} lines output", result.exit_code, line_count),
        result.exit_code != 0,
    );

    Ok(ShellOutput {
        output: result.output(),
        exit_code: result.exit_code,
    })
}
```

**Step 2: Run cargo check**

Run: `cargo check -p feroxmute-core`
Expected: FAIL - providers still calling old constructor

**Step 3: Commit**

```bash
git add feroxmute-core/src/tools/shell.rs
git commit -m "feat(shell): send feed events before and after command execution"
```

---

## Task 4: Update Provider Trait Signature

**Files:**
- Modify: `feroxmute-core/src/providers/traits.rs:148-158`

**Step 1: Update complete_with_shell signature**

Replace the default implementation:

```rust
/// Complete with shell tool access (uses rig's built-in tool loop)
async fn complete_with_shell(
    &self,
    _system_prompt: &str,
    _user_prompt: &str,
    _container: Arc<ContainerManager>,
    _events: Arc<dyn crate::tools::EventSender>,
    _agent_name: &str,
) -> Result<String> {
    Err(crate::Error::Provider(
        "Shell tool not supported by this provider".to_string(),
    ))
}
```

**Step 2: Run cargo check**

Run: `cargo check -p feroxmute-core`
Expected: FAIL - provider implementations don't match trait

**Step 3: Commit**

```bash
git add feroxmute-core/src/providers/traits.rs
git commit -m "feat(providers): add events and agent_name params to complete_with_shell"
```

---

## Task 5: Update Anthropic Provider

**Files:**
- Modify: `feroxmute-core/src/providers/anthropic.rs:120-140`

**Step 1: Add import**

At top of file, ensure EventSender is imported:

```rust
use crate::tools::{
    CompleteEngagementTool, DockerShellTool, EventSender, ListAgentsTool, OrchestratorContext,
    RecordFindingTool, SpawnAgentTool, WaitForAgentTool, WaitForAnyTool,
};
```

**Step 2: Update complete_with_shell implementation**

```rust
async fn complete_with_shell(
    &self,
    system_prompt: &str,
    user_prompt: &str,
    container: Arc<ContainerManager>,
    events: Arc<dyn EventSender>,
    agent_name: &str,
) -> Result<String> {
    let agent = self
        .client
        .agent(&self.model)
        .preamble(system_prompt)
        .max_tokens(4096)
        .tool(DockerShellTool::new(container, events, agent_name.to_string()))
        .build();

    // multi_turn enables tool loop with max 50 iterations
    agent
        .prompt(user_prompt)
        .multi_turn(50)
        .await
        .map_err(|e| Error::Provider(format!("Shell completion failed: {}", e)))
}
```

**Step 3: Run cargo check**

Run: `cargo check -p feroxmute-core`
Expected: FAIL - other providers don't match trait

**Step 4: Commit**

```bash
git add feroxmute-core/src/providers/anthropic.rs
git commit -m "feat(anthropic): update complete_with_shell with events param"
```

---

## Task 6: Update Remaining Providers

**Files:**
- Modify: `feroxmute-core/src/providers/openai.rs`
- Modify: `feroxmute-core/src/providers/gemini.rs`
- Modify: `feroxmute-core/src/providers/azure.rs`
- Modify: `feroxmute-core/src/providers/deepseek.rs`
- Modify: `feroxmute-core/src/providers/cohere.rs`
- Modify: `feroxmute-core/src/providers/perplexity.rs`
- Modify: `feroxmute-core/src/providers/mira.rs`
- Modify: `feroxmute-core/src/providers/xai.rs`

**Step 1: Update each provider's complete_with_shell**

For each provider file, update the `complete_with_shell` method signature and implementation. The pattern is identical to Anthropic:

```rust
async fn complete_with_shell(
    &self,
    system_prompt: &str,
    user_prompt: &str,
    container: Arc<ContainerManager>,
    events: Arc<dyn EventSender>,
    agent_name: &str,
) -> Result<String> {
    let agent = self
        .client
        .agent(&self.model)
        .preamble(system_prompt)
        .max_tokens(4096)
        .tool(DockerShellTool::new(container, events, agent_name.to_string()))
        .build();

    agent
        .prompt(user_prompt)
        .multi_turn(50)
        .await
        .map_err(|e| Error::Provider(format!("Shell completion failed: {}", e)))
}
```

Also add `EventSender` to imports in each file.

**Step 2: Run cargo check**

Run: `cargo check -p feroxmute-core`
Expected: FAIL - orchestrator.rs still calling old signature

**Step 3: Commit**

```bash
git add feroxmute-core/src/providers/
git commit -m "feat(providers): update all providers with events param"
```

---

## Task 7: Update SpawnAgentTool to Pass Events

**Files:**
- Modify: `feroxmute-core/src/tools/orchestrator.rs:135-165`

**Step 1: Update the spawned task**

In `SpawnAgentTool::call`, update the spawned task to pass events and agent_name. Find the `tokio::spawn` block and update it:

```rust
// Spawn agent task
let result_tx = registry.result_sender();
let agent_name = args.name.clone();
let agent_type = args.agent_type.clone();
let target = self.context.target.clone();
let provider = Arc::clone(&self.context.provider);
let container = Arc::clone(&self.context.container);
let events = Arc::clone(&self.context.events);

let handle = tokio::spawn(async move {
    let start = std::time::Instant::now();

    let output = match provider
        .complete_with_shell(&full_prompt, &target, container, events, &agent_name)
        .await
    {
        Ok(out) => out,
        Err(e) => format!("Error: {}", e),
    };

    let success = !output.starts_with("Error:");

    let _ = result_tx
        .send(AgentResult {
            name: agent_name.clone(),
            agent_type,
            success,
            output,
            duration: start.elapsed(),
        })
        .await;
});
```

**Step 2: Run cargo check**

Run: `cargo check -p feroxmute-core`
Expected: SUCCESS

**Step 3: Run cargo build**

Run: `cargo build`
Expected: SUCCESS

**Step 4: Commit**

```bash
git add feroxmute-core/src/tools/orchestrator.rs
git commit -m "feat(orchestrator): pass events and agent_name to spawned agents"
```

---

## Task 8: Add Dynamic Agent Tracking to TUI App

**Files:**
- Modify: `feroxmute-cli/src/tui/app.rs:70-78` and `109-155`

**Step 1: Add AgentDisplayInfo struct**

Add after `AgentStatuses` struct (around line 78):

```rust
/// Display info for a dynamically spawned agent
#[derive(Debug, Clone, Default)]
pub struct AgentDisplayInfo {
    pub agent_type: String,
    pub status: AgentStatus,
    pub activity: String,
}
```

**Step 2: Add agents HashMap to App**

In the `App` struct, add after `agent_statuses` field (around line 134):

```rust
/// Dynamically spawned agents (name -> info)
pub agents: std::collections::HashMap<String, AgentDisplayInfo>,
```

**Step 3: Update App::new**

In the `new` constructor, add initialization (after `agent_statuses: AgentStatuses::default()`):

```rust
agents: std::collections::HashMap::new(),
```

**Step 4: Add helper method for activity updates**

Add after `update_agent_status` method:

```rust
/// Update agent activity (from non-indented feed messages)
pub fn update_agent_activity(&mut self, agent: &str, activity: &str) {
    if let Some(info) = self.agents.get_mut(agent) {
        info.activity = activity.to_string();
    } else if agent != "orchestrator" && agent != "system" {
        // New agent - add it
        self.agents.insert(
            agent.to_string(),
            AgentDisplayInfo {
                agent_type: String::new(), // Will be set from status event
                status: AgentStatus::Running,
                activity: activity.to_string(),
            },
        );
    }
}

/// Update spawned agent status
pub fn update_spawned_agent_status(&mut self, agent: &str, status: AgentStatus) {
    if let Some(info) = self.agents.get_mut(agent) {
        info.status = status;
    }
}
```

**Step 5: Run cargo check**

Run: `cargo check -p feroxmute-cli`
Expected: SUCCESS

**Step 6: Commit**

```bash
git add feroxmute-cli/src/tui/app.rs
git commit -m "feat(tui): add dynamic agent tracking to App state"
```

---

## Task 9: Update FeedEntry with Chrono Timestamp

**Files:**
- Modify: `feroxmute-cli/src/tui/app.rs:79-107`

**Step 1: Add chrono import**

At top of file:

```rust
use chrono::{DateTime, Local};
```

**Step 2: Update FeedEntry struct**

Replace the FeedEntry struct:

```rust
/// Activity feed entry
#[derive(Debug, Clone)]
pub struct FeedEntry {
    pub timestamp: DateTime<Local>,
    pub agent: String,
    pub message: String,
    pub is_error: bool,
}

impl FeedEntry {
    pub fn new(agent: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            timestamp: Local::now(),
            agent: agent.into(),
            message: message.into(),
            is_error: false,
        }
    }

    pub fn error(agent: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            timestamp: Local::now(),
            agent: agent.into(),
            message: message.into(),
            is_error: true,
        }
    }
}
```

**Step 3: Run cargo check**

Run: `cargo check -p feroxmute-cli`
Expected: SUCCESS

**Step 4: Commit**

```bash
git add feroxmute-cli/src/tui/app.rs
git commit -m "feat(tui): use chrono timestamp in FeedEntry"
```

---

## Task 10: Update Event Handler for Dynamic Agents

**Files:**
- Modify: `feroxmute-cli/src/tui/runner.rs:216-254`

**Step 1: Update drain_events function**

Replace the event handling in `drain_events`:

```rust
for event in events {
    match event {
        AgentEvent::Feed {
            agent,
            message,
            is_error,
        } => {
            // Track activity for non-indented messages
            if !message.starts_with("  ") {
                app.update_agent_activity(&agent, &message);
            }

            if is_error {
                app.add_feed(super::app::FeedEntry::error(&agent, &message));
            } else {
                app.add_feed(super::app::FeedEntry::new(&agent, &message));
            }
        }
        AgentEvent::Thinking(thinking) => {
            app.current_thinking = thinking;
        }
        AgentEvent::Status { agent, status } => {
            app.update_agent_status(&agent, status);
            app.update_spawned_agent_status(&agent, status);
        }
        AgentEvent::Metrics {
            input,
            output,
            cache_read,
        } => {
            app.metrics.input_tokens += input;
            app.metrics.output_tokens += output;
            app.metrics.cache_read_tokens += cache_read;
        }
        AgentEvent::Finished { success, message } => {
            let agent = "system";
            if success {
                app.add_feed(super::app::FeedEntry::new(agent, &message));
            } else {
                app.add_feed(super::app::FeedEntry::error(agent, &message));
            }
        }
    }
}
```

**Step 2: Run cargo check**

Run: `cargo check -p feroxmute-cli`
Expected: SUCCESS

**Step 3: Commit**

```bash
git add feroxmute-cli/src/tui/runner.rs
git commit -m "feat(tui): update event handler for dynamic agent tracking"
```

---

## Task 11: Update Dashboard to Show Dynamic Agents

**Files:**
- Modify: `feroxmute-cli/src/tui/widgets/dashboard.rs:116-141`

**Step 1: Update render_agents function**

Replace the `render_agents` function:

```rust
/// Render agent status table
fn render_agents(frame: &mut Frame, app: &App, area: Rect) {
    let header = Row::new(vec!["Agent", "Status", "Activity"]).style(
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    );

    // Always show orchestrator first
    let mut rows = vec![agent_row_with_activity(
        "orchestrator",
        "Orchestrator",
        app.agent_statuses.orchestrator,
        app.agents
            .get("orchestrator")
            .map(|a| a.activity.as_str())
            .unwrap_or("-"),
    )];

    // Add dynamically spawned agents
    for (name, info) in &app.agents {
        if name != "orchestrator" {
            rows.push(agent_row_with_activity(
                name,
                name,
                info.status,
                &info.activity,
            ));
        }
    }

    let table = Table::new(
        rows,
        [
            Constraint::Length(20),
            Constraint::Length(12),
            Constraint::Min(20),
        ],
    )
    .header(header)
    .block(Block::default().borders(Borders::ALL).title(" Agents "));

    frame.render_widget(table, area);
}

/// Create a row for an agent with activity
fn agent_row_with_activity<'a>(
    _key: &'a str,
    name: &'a str,
    status: AgentStatus,
    activity: &'a str,
) -> Row<'a> {
    let (status_text, status_style) = match status {
        AgentStatus::Idle => ("Idle", Style::default().fg(Color::Gray)),
        AgentStatus::Planning => ("Planning", Style::default().fg(Color::Blue)),
        AgentStatus::Running => (
            "Running",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        AgentStatus::Waiting => ("Waiting", Style::default().fg(Color::Yellow)),
        AgentStatus::Completed => ("Done", Style::default().fg(Color::Cyan)),
        AgentStatus::Failed => (
            "Failed",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ),
    };

    // Truncate activity to fit
    let activity_display = if activity.len() > 40 {
        format!("{}...", &activity[..37])
    } else {
        activity.to_string()
    };

    Row::new(vec![
        Cell::from(name),
        Cell::from(status_text).style(status_style),
        Cell::from(activity_display).style(Style::default().fg(Color::DarkGray)),
    ])
}
```

**Step 2: Remove old agent_row function**

Delete the old `agent_row` function (was around line 143-167).

**Step 3: Adjust agent table height**

In `render` function, change the agent table constraint from `Constraint::Length(7)` to `Constraint::Min(5)` to allow for more agents:

```rust
let chunks = Layout::default()
    .direction(Direction::Vertical)
    .constraints([
        Constraint::Length(3), // Header
        Constraint::Length(5), // Metrics
        Constraint::Min(5),    // Agent status table (dynamic height)
        Constraint::Min(5),    // Feed
        Constraint::Length(1), // Footer
    ])
    .split(frame.area());
```

**Step 4: Run cargo check**

Run: `cargo check -p feroxmute-cli`
Expected: SUCCESS

**Step 5: Commit**

```bash
git add feroxmute-cli/src/tui/widgets/dashboard.rs
git commit -m "feat(tui): display dynamic agents with activity in dashboard"
```

---

## Task 12: Fix Feed Display Order and Add Timestamps

**Files:**
- Modify: `feroxmute-cli/src/tui/widgets/dashboard.rs:169-241`
- Modify: `feroxmute-cli/src/tui/runner.rs:72-121`

**Step 1: Update render_feed in dashboard.rs**

Replace the `render_feed` function:

```rust
/// Render activity feed with timestamps (newest at bottom)
fn render_feed(frame: &mut Frame, app: &App, area: Rect) {
    let visible_height = area.height.saturating_sub(2) as usize;
    let inner_width = area.width.saturating_sub(2) as usize;
    let scroll_x = app.feed_scroll_x as usize;

    // Take last N entries (newest at bottom)
    let items: Vec<ListItem> = app
        .feed
        .iter()
        .rev()
        .take(visible_height)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .map(|entry| {
            let style = if entry.is_error {
                Style::default().fg(Color::Red)
            } else {
                Style::default()
            };

            let time_str = entry.timestamp.format("%H:%M:%S").to_string();
            let prefix = format!("{} [{}] ", time_str, entry.agent);
            let full_text = format!("{}{}", prefix, entry.message);

            // Apply horizontal scroll
            let full_text_len = full_text.chars().count();
            let display_text: String = if scroll_x < full_text_len {
                let take_count = inner_width.min(full_text_len - scroll_x);
                full_text.chars().skip(scroll_x).take(take_count).collect()
            } else {
                String::new()
            };

            // Color the timestamp and agent prefix
            let time_len = 8; // "HH:MM:SS"
            let prefix_char_len = prefix.chars().count();

            if scroll_x < prefix_char_len {
                let visible_prefix_len = prefix_char_len.saturating_sub(scroll_x);
                let display_char_count = display_text.chars().count();
                let visible_prefix: String = display_text
                    .chars()
                    .take(visible_prefix_len.min(display_char_count))
                    .collect();
                let visible_message: String = if display_char_count > visible_prefix_len {
                    display_text.chars().skip(visible_prefix_len).collect()
                } else {
                    String::new()
                };

                // Split prefix into time and agent parts for coloring
                let time_part: String = visible_prefix.chars().take(time_len.saturating_sub(scroll_x)).collect();
                let agent_part: String = visible_prefix.chars().skip(time_len.saturating_sub(scroll_x)).collect();

                let line = Line::from(vec![
                    Span::styled(time_part, Style::default().fg(Color::DarkGray)),
                    Span::styled(agent_part, Style::default().fg(Color::Cyan)),
                    Span::styled(visible_message, style),
                ]);
                ListItem::new(line)
            } else {
                ListItem::new(Line::from(Span::styled(display_text, style)))
            }
        })
        .collect();

    // Check if content extends beyond visible area
    let has_more_right = app.feed.iter().any(|e| {
        let full_len = format!(
            "{} [{}] {}",
            e.timestamp.format("%H:%M:%S"),
            e.agent,
            e.message
        )
        .chars()
        .count();
        scroll_x + inner_width < full_len
    });
    let has_more_left = scroll_x > 0;

    let title = match (has_more_left, has_more_right) {
        (true, true) => " <- Activity Feed -> ",
        (true, false) => " <- Activity Feed ",
        (false, true) => " Activity Feed -> ",
        (false, false) => " Activity Feed ",
    };

    let feed = List::new(items).block(Block::default().borders(Borders::ALL).title(title));

    frame.render_widget(feed, area);
}
```

**Step 2: Update render_logs in runner.rs**

Replace the `render_logs` function to also use timestamps and correct order:

```rust
/// Render logs view
fn render_logs(frame: &mut Frame, app: &App) {
    use ratatui::{
        layout::{Constraint, Direction, Layout},
        style::{Color, Style},
        text::{Line, Span},
        widgets::{Block, Borders, List, ListItem, Paragraph},
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(1)])
        .split(frame.area());

    let visible_height = chunks[0].height.saturating_sub(2) as usize;

    // Show newest at bottom, apply scroll from bottom
    let items: Vec<ListItem> = app
        .feed
        .iter()
        .rev()
        .skip(app.log_scroll)
        .take(visible_height)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .map(|entry| {
            let style = if entry.is_error {
                Style::default().fg(Color::Red)
            } else {
                Style::default()
            };
            let time_str = entry.timestamp.format("%H:%M:%S").to_string();
            let line = Line::from(vec![
                Span::styled(format!("{} ", time_str), Style::default().fg(Color::DarkGray)),
                Span::styled(
                    format!("[{}] ", entry.agent),
                    Style::default().fg(Color::Cyan),
                ),
                Span::styled(&entry.message, style),
            ]);
            ListItem::new(line)
        })
        .collect();

    let logs = List::new(items).block(Block::default().borders(Borders::ALL).title(" Logs "));

    frame.render_widget(logs, chunks[0]);

    let help = Line::from(vec![
        Span::styled("h", Style::default().fg(Color::Yellow)),
        Span::raw(" back  "),
        Span::styled("j/k", Style::default().fg(Color::Yellow)),
        Span::raw(" scroll  "),
        Span::styled("q", Style::default().fg(Color::Yellow)),
        Span::raw(" quit"),
    ]);
    let footer = Paragraph::new(help).style(Style::default().fg(Color::DarkGray));
    frame.render_widget(footer, chunks[1]);
}
```

**Step 3: Run cargo check**

Run: `cargo check -p feroxmute-cli`
Expected: SUCCESS

**Step 4: Run cargo build**

Run: `cargo build`
Expected: SUCCESS

**Step 5: Commit**

```bash
git add feroxmute-cli/src/tui/widgets/dashboard.rs feroxmute-cli/src/tui/runner.rs
git commit -m "feat(tui): add timestamps and fix feed order (newest at bottom)"
```

---

## Task 13: Run Tests and Final Verification

**Step 1: Run all tests**

Run: `cargo test`
Expected: All tests pass

**Step 2: Run clippy**

Run: `cargo clippy`
Expected: No errors (warnings OK)

**Step 3: Format code**

Run: `cargo fmt`

**Step 4: Final commit if any formatting changes**

```bash
git add -A
git commit -m "chore: format code" || echo "Nothing to commit"
```

---

## Summary

After completing all tasks:

1. Shell tool requires `reason` field - agents explain each command
2. Shell tool sends feed events with reason, command, and result
3. All 9 providers updated with new signature
4. TUI tracks spawned agents dynamically
5. Dashboard shows agents with current activity
6. Feed has timestamps and newest-at-bottom ordering
