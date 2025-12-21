# Dynamic Agent Keys & Streaming Thinking Design

**Goal:** Fix TUI agent navigation (keys 1-9 dynamically map to agents) and add streaming thinking display per agent.

**Tech Stack:** Rust, rig-core streaming API, ratatui TUI

---

## Overview

### Current Problems
- Keys 1-4 hardcoded to fixed `AgentView` enum (Orchestrator, Recon, Scanner, Sast)
- Agents are now dynamically spawned, stored in `HashMap<String, AgentDisplayInfo>`
- `AgentEvent::Thinking` exists but nothing sends it
- Single global `current_thinking` instead of per-agent

### After Implementation
- Key 1 = Orchestrator (fixed), keys 2-9 = spawned agents in spawn order
- Streaming LLM responses capture reasoning/thinking in real-time
- Each agent has its own thinking buffer, displayed when that agent is selected
- Circular buffer (100 entries) per agent for output history

---

## Component 1: Data Model Changes

### File: `feroxmute-cli/src/tui/app.rs`

**Updated `AgentDisplayInfo`:**
```rust
pub struct AgentDisplayInfo {
    pub agent_type: String,
    pub status: AgentStatus,
    pub activity: String,
    pub spawn_order: usize,              // NEW: for key mapping (1-based)
    pub thinking: Option<String>,         // NEW: current thinking text
    pub output_buffer: VecDeque<String>,  // NEW: circular buffer (100 entries)
}
```

**Updated `App`:**
```rust
pub struct App {
    // ... existing fields ...
    pub selected_agent: Option<String>,  // NEW: which agent is focused
    pub agent_spawn_counter: usize,      // NEW: tracks spawn order
    // REMOVE: current_thinking (now per-agent)
}
```

**New method:**
```rust
pub fn get_agent_by_key(&self, key: usize) -> Option<String> {
    if key == 1 {
        return Some("orchestrator".to_string());
    }
    self.agents.iter()
        .find(|(_, info)| info.spawn_order == key - 1)
        .map(|(name, _)| name.clone())
}
```

---

## Component 2: View Enum Change

### File: `feroxmute-cli/src/tui/app.rs`

```rust
pub enum View {
    Dashboard,
    AgentDetail(String),  // Changed from AgentView enum to agent name
    Logs,
    Help,
}
```

Remove the `AgentView` enum entirely.

---

## Component 3: Key Handling

### File: `feroxmute-cli/src/tui/events.rs`

Replace hardcoded agent keys:

```rust
// Remove these:
// KeyCode::Char('1') => View::AgentDetail(AgentView::Orchestrator)
// KeyCode::Char('2') => View::AgentDetail(AgentView::Recon)
// etc.

// Replace with:
KeyCode::Char(c @ '1'..='9') => {
    let key_num = c.to_digit(10).unwrap() as usize;
    if let Some(agent_name) = app.get_agent_by_key(key_num) {
        app.selected_agent = Some(agent_name.clone());
        app.navigate(View::AgentDetail(agent_name));
    }
}
```

---

## Component 4: Event Channel Updates

### File: `feroxmute-cli/src/tui/channel.rs`

```rust
pub enum AgentEvent {
    Feed { agent: String, message: String, is_error: bool },

    // CHANGED: Now per-agent
    Thinking { agent: String, content: Option<String> },

    Status { agent: String, agent_type: String, status: AgentStatus },
    Metrics { input: u64, output: u64, cache_read: u64, cost_usd: f64 },
    Vulnerability { severity: VulnSeverity, title: String },
    Finished { success: bool, message: String },
}
```

---

## Component 5: Streaming Provider Changes

### File: `feroxmute-core/src/providers/macros.rs`

Update `complete_with_shell`, `complete_with_orchestrator`, `complete_with_report` to use streaming:

```rust
async fn complete_with_shell(&self, ...) -> Result<String> {
    use futures::StreamExt;
    use rig::streaming::{MultiTurnStreamItem, StreamedAssistantContent, Reasoning, Text};

    let agent = self.client.agent(&self.model)
        .preamble(system_prompt)
        .tool(DockerShellTool::new(...))
        .build();

    let mut stream = agent.stream_prompt(user_prompt).multi_turn(50);
    let mut final_text = String::new();
    let mut aggregated_usage = Usage::default();

    while let Some(item) = stream.next().await {
        match item {
            Ok(MultiTurnStreamItem::StreamItem(
                StreamedAssistantContent::Reasoning(Reasoning { reasoning, .. })
            )) => {
                let text = reasoning.join("");
                events.send_thinking(agent_name, Some(text));
            }
            Ok(MultiTurnStreamItem::StreamItem(
                StreamedAssistantContent::Text(Text { text })
            )) => {
                final_text.push_str(&text);
            }
            Ok(MultiTurnStreamItem::FinalResponse(res)) => {
                aggregated_usage = res.usage;
            }
            Err(e) => return Err(Error::Provider(e.to_string())),
            _ => {}
        }
    }

    events.send_thinking(agent_name, None); // Clear thinking when done
    events.send_metrics(...);
    Ok(final_text)
}
```

---

## Component 6: EventSender Trait Update

### File: `feroxmute-core/src/tools/mod.rs` (or wherever EventSender is defined)

Add new method:

```rust
pub trait EventSender: Send + Sync {
    fn send_feed(&self, agent: &str, message: &str, is_error: bool);
    fn send_status(&self, agent: &str, agent_type: &str, status: AgentStatus);
    fn send_metrics(&self, input: u64, output: u64, cache_read: u64, cost: f64);
    fn send_thinking(&self, agent: &str, content: Option<String>);  // NEW
}
```

---

## Component 7: Runner Event Handling

### File: `feroxmute-cli/src/tui/runner.rs`

Update `drain_events`:

```rust
AgentEvent::Thinking { agent, content } => {
    if let Some(info) = app.agents.get_mut(&agent) {
        info.thinking = content;
    } else if agent == "orchestrator" {
        app.agents.entry("orchestrator".to_string())
            .or_insert_with(|| AgentDisplayInfo::new_orchestrator())
            .thinking = content;
    }
}
```

Update spawn order assignment:

```rust
pub fn update_spawned_agent_status(&mut self, agent: &str, agent_type: &str, status: AgentStatus) {
    if let Some(info) = self.agents.get_mut(agent) {
        info.status = status;
        if !agent_type.is_empty() {
            info.agent_type = agent_type.to_string();
        }
    } else if agent != "system" {
        self.agent_spawn_counter += 1;
        self.agents.insert(agent.to_string(), AgentDisplayInfo {
            agent_type: agent_type.to_string(),
            status,
            activity: String::new(),
            spawn_order: self.agent_spawn_counter,
            thinking: None,
            output_buffer: VecDeque::with_capacity(100),
        });
    }
}
```

---

## Component 8: Agent Detail Widget

### File: `feroxmute-cli/src/tui/widgets/agent_detail.rs`

Change signature to take agent name:

```rust
pub fn render(frame: &mut Frame, app: &App, agent_name: &str) {
    let agent_info = app.agents.get(agent_name);
    let thinking = agent_info.and_then(|a| a.thinking.as_ref());
    let show_thinking = app.show_thinking && thinking.is_some();

    // ... rest of rendering uses agent_name instead of AgentView ...
}
```

Dynamic footer showing available keys:

```rust
fn render_footer(frame: &mut Frame, current_agent: &str, app: &App, area: Rect) {
    let current_key = if current_agent == "orchestrator" {
        "1".to_string()
    } else {
        app.agents.get(current_agent)
            .map(|a| (a.spawn_order + 1).to_string())
            .unwrap_or("?".to_string())
    };

    let max_key = app.agents.len().min(9);
    // Show "1-N agents" where N is number of spawned agents
}
```

---

## File Changes Summary

| File | Changes |
|------|---------|
| `feroxmute-cli/src/tui/app.rs` | Update `AgentDisplayInfo`, `App`, `View` enum, add `get_agent_by_key()` |
| `feroxmute-cli/src/tui/events.rs` | Dynamic 1-9 key handling |
| `feroxmute-cli/src/tui/channel.rs` | Update `AgentEvent::Thinking` to include agent name |
| `feroxmute-cli/src/tui/runner.rs` | Update `drain_events`, spawn order assignment |
| `feroxmute-cli/src/tui/widgets/agent_detail.rs` | Take `&str` instead of `AgentView`, per-agent thinking |
| `feroxmute-cli/src/tui/widgets/dashboard.rs` | Update footer hints |
| `feroxmute-core/src/providers/macros.rs` | Add streaming with reasoning capture |
| `feroxmute-core/src/tools/mod.rs` | Add `send_thinking()` to `EventSender` trait |

---

## Testing Strategy

1. **Unit tests** - Key mapping logic (`get_agent_by_key`)
2. **Integration test** - Spawn agents, verify keys 2-9 map correctly
3. **Manual test** - Run engagement, verify thinking streams to correct agent panel
4. **Existing tests** - All current TUI tests still pass

---

## Implementation Order

1. Update `AgentDisplayInfo` struct with new fields
2. Update `View` enum (remove `AgentView`)
3. Update `App` with new fields and `get_agent_by_key()`
4. Update `AgentEvent::Thinking` in channel.rs
5. Update `EventSender` trait with `send_thinking()`
6. Update runner.rs event handling
7. Update events.rs key handling (1-9 dynamic)
8. Update agent_detail.rs widget
9. Update dashboard.rs footer
10. Update provider macro with streaming
11. Run tests, verify all pass
