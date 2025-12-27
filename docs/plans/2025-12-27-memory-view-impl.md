# Memory View Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a TUI view showing memory/scratch pad entries with modal popup for details.

**Architecture:** New `Memory` view variant with list widget, modal overlay widget, and event-driven sync from MemoryContext via EventSender trait extension.

**Tech Stack:** Rust, ratatui, tokio mpsc channels, rusqlite

---

### Task 1: Add MemoryEntry and MemoryUpdated Event

**Files:**
- Modify: `feroxmute-cli/src/tui/channel.rs`

**Step 1: Add MemoryEntry struct after AgentEvent enum**

Add at the end of the file, before any closing braces:

```rust
/// Memory entry for TUI display
#[derive(Debug, Clone)]
pub struct MemoryEntry {
    pub key: String,
    pub value: String,
    pub created_at: String,
    pub updated_at: String,
}
```

**Step 2: Add MemoryUpdated variant to AgentEvent**

Add this variant to the `AgentEvent` enum:

```rust
    /// Memory entries updated
    MemoryUpdated {
        entries: Vec<MemoryEntry>,
    },
```

**Step 3: Build to verify**

Run: `cargo build -p feroxmute-cli`
Expected: SUCCESS (unused warning is fine)

**Step 4: Commit**

```bash
git add feroxmute-cli/src/tui/channel.rs
git commit -m "feat(tui): add MemoryEntry struct and MemoryUpdated event"
```

---

### Task 2: Add Memory View and State to App

**Files:**
- Modify: `feroxmute-cli/src/tui/app.rs`

**Step 1: Add Memory variant to View enum**

Find the `View` enum and add `Memory`:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum View {
    #[default]
    Dashboard,
    AgentDetail(String),
    Logs,
    Help,
    Memory,
}
```

**Step 2: Add imports at top of file**

Add to imports:

```rust
use super::channel::{AgentEvent, MemoryEntry};
```

**Step 3: Add memory state fields to App struct**

Add these fields to the `App` struct:

```rust
    /// Memory entries for display
    pub memory_entries: Vec<MemoryEntry>,
    /// Currently selected memory entry index
    pub selected_memory: usize,
    /// Show memory detail modal
    pub show_memory_modal: bool,
    /// Scroll offset for modal content
    pub memory_modal_scroll: usize,
```

**Step 4: Initialize fields in App::new()**

Add to the `Self { ... }` block in `App::new()`:

```rust
            memory_entries: Vec::new(),
            selected_memory: 0,
            show_memory_modal: false,
            memory_modal_scroll: 0,
```

**Step 5: Add memory navigation methods**

Add these methods to the `impl App` block:

```rust
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
```

**Step 6: Build to verify**

Run: `cargo build -p feroxmute-cli`
Expected: SUCCESS (unused warnings are fine)

**Step 7: Commit**

```bash
git add feroxmute-cli/src/tui/app.rs
git commit -m "feat(tui): add Memory view variant and state fields"
```

---

### Task 3: Add send_memory_update to EventSender Trait

**Files:**
- Modify: `feroxmute-core/src/tools/mod.rs`

**Step 1: Add MemoryEntry struct for core crate**

Add this struct (we need it in core since EventSender is in core):

```rust
/// Memory entry for event updates
#[derive(Debug, Clone)]
pub struct MemoryEntryData {
    pub key: String,
    pub value: String,
    pub created_at: String,
    pub updated_at: String,
}
```

**Step 2: Add method to EventSender trait**

Add this method to the `EventSender` trait:

```rust
    /// Send memory entries update
    fn send_memory_update(&self, entries: Vec<MemoryEntryData>);
```

**Step 3: Build to see what needs updating**

Run: `cargo build -p feroxmute-core`
Expected: FAIL - trait not implemented for NoopEventSender in tests

**Step 4: Update NoopEventSender in memory.rs tests**

In `feroxmute-core/src/tools/memory.rs`, find the `NoopEventSender` impl in tests and add:

```rust
        fn send_memory_update(&self, _entries: Vec<crate::tools::MemoryEntryData>) {}
```

**Step 5: Build to verify**

Run: `cargo build -p feroxmute-core`
Expected: SUCCESS

**Step 6: Commit**

```bash
git add feroxmute-core/src/tools/mod.rs feroxmute-core/src/tools/memory.rs
git commit -m "feat(tools): add send_memory_update to EventSender trait"
```

---

### Task 4: Call send_memory_update from Memory Tools

**Files:**
- Modify: `feroxmute-core/src/tools/memory.rs`

**Step 1: Create helper function to query and send all entries**

Add this helper function before the tool implementations:

```rust
/// Query all memory entries and send update event
async fn broadcast_memory_update(context: &MemoryContext) {
    let conn = context.conn.lock().await;
    let mut stmt = match conn.prepare(
        "SELECT key, value, created_at, updated_at FROM scratch_pad ORDER BY key",
    ) {
        Ok(s) => s,
        Err(_) => return,
    };

    let entries: Vec<super::MemoryEntryData> = stmt
        .query_map([], |row| {
            Ok(super::MemoryEntryData {
                key: row.get(0)?,
                value: row.get(1)?,
                created_at: row.get(2)?,
                updated_at: row.get(3)?,
            })
        })
        .ok()
        .map(|rows| rows.filter_map(|r| r.ok()).collect())
        .unwrap_or_default();

    drop(conn); // Release lock before sending
    context.events.send_memory_update(entries);
}
```

**Step 2: Call broadcast after MemoryAddTool::call()**

In `MemoryAddTool::call()`, after the successful `Ok(...)` return, change to:

```rust
    async fn call(&self, args: Self::Args) -> Result<Self::Output, Self::Error> {
        // Log the memory operation
        self.context.events.send_feed(
            &self.context.agent_name,
            &format!("Storing '{}' in memory", args.key),
            false,
        );

        let conn = self.context.conn.lock().await;
        conn.execute(
            "INSERT INTO scratch_pad (key, value, created_at, updated_at)
             VALUES (?1, ?2, datetime('now'), datetime('now'))
             ON CONFLICT(key) DO UPDATE SET value = ?2, updated_at = datetime('now')",
            [&args.key, &args.value],
        )
        .map_err(|e| MemoryToolError::Database(e.to_string()))?;

        drop(conn); // Release lock before broadcast
        broadcast_memory_update(&self.context).await;

        Ok(MemoryAddOutput {
            stored: true,
            key: args.key,
        })
    }
```

**Step 3: Call broadcast after MemoryRemoveTool::call()**

In `MemoryRemoveTool::call()`, update similarly:

```rust
    async fn call(&self, args: Self::Args) -> Result<Self::Output, Self::Error> {
        // Log the memory operation
        self.context.events.send_feed(
            &self.context.agent_name,
            &format!("Removing '{}' from memory", args.key),
            false,
        );

        let conn = self.context.conn.lock().await;
        let rows_affected = conn
            .execute("DELETE FROM scratch_pad WHERE key = ?1", [&args.key])
            .map_err(|e| MemoryToolError::Database(e.to_string()))?;

        drop(conn); // Release lock before broadcast
        broadcast_memory_update(&self.context).await;

        Ok(MemoryRemoveOutput {
            removed: rows_affected > 0,
            key: args.key,
        })
    }
```

**Step 4: Build to verify**

Run: `cargo build -p feroxmute-core`
Expected: SUCCESS

**Step 5: Run tests**

Run: `cargo test -p feroxmute-core memory`
Expected: All tests pass

**Step 6: Commit**

```bash
git add feroxmute-core/src/tools/memory.rs
git commit -m "feat(tools): broadcast memory updates after add/remove"
```

---

### Task 5: Implement send_memory_update in TuiEventSender

**Files:**
- Modify: `feroxmute-cli/src/runner.rs`

**Step 1: Add MemoryEntry import**

Add to imports:

```rust
use crate::tui::channel::MemoryEntry;
```

**Step 2: Implement send_memory_update**

Add this method to the `impl EventSender for TuiEventSender` block:

```rust
    fn send_memory_update(&self, entries: Vec<feroxmute_core::tools::MemoryEntryData>) {
        let tx = self.tx.clone();
        // Convert core MemoryEntryData to TUI MemoryEntry
        let tui_entries: Vec<MemoryEntry> = entries
            .into_iter()
            .map(|e| MemoryEntry {
                key: e.key,
                value: e.value,
                created_at: e.created_at,
                updated_at: e.updated_at,
            })
            .collect();
        tokio::spawn(async move {
            let _ = tx.send(AgentEvent::MemoryUpdated { entries: tui_entries }).await;
        });
    }
```

**Step 3: Build to verify**

Run: `cargo build -p feroxmute-cli`
Expected: SUCCESS

**Step 4: Commit**

```bash
git add feroxmute-cli/src/runner.rs
git commit -m "feat(cli): implement send_memory_update in TuiEventSender"
```

---

### Task 6: Handle MemoryUpdated Event in drain_events

**Files:**
- Modify: `feroxmute-cli/src/tui/runner.rs`

**Step 1: Add handler in drain_events()**

Find the `drain_events()` function and add a new match arm for `MemoryUpdated`:

```rust
            AgentEvent::MemoryUpdated { entries } => {
                app.memory_entries = entries;
                // Clamp selection if entries were removed
                if app.selected_memory >= app.memory_entries.len() {
                    app.selected_memory = app.memory_entries.len().saturating_sub(1);
                }
            }
```

**Step 2: Build to verify**

Run: `cargo build -p feroxmute-cli`
Expected: SUCCESS

**Step 3: Commit**

```bash
git add feroxmute-cli/src/tui/runner.rs
git commit -m "feat(tui): handle MemoryUpdated event in drain_events"
```

---

### Task 7: Add Key Handling for Memory View

**Files:**
- Modify: `feroxmute-cli/src/tui/events.rs`

**Step 1: Add 'p' key to navigate to Memory view**

In `handle_key_event()`, find the main `match key.code` block and add:

```rust
        KeyCode::Char('p') => {
            app.navigate(View::Memory);
        }
```

**Step 2: Add memory-specific key handling**

Add this block before the main navigation keys, after the quit confirmation handling:

```rust
    // Memory view specific handling
    if app.view == View::Memory {
        if app.show_memory_modal {
            // Modal is open
            match key.code {
                KeyCode::Esc | KeyCode::Enter => {
                    app.close_memory_modal();
                    return EventResult::Continue;
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    app.scroll_memory_modal_up();
                    return EventResult::Continue;
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    app.scroll_memory_modal_down();
                    return EventResult::Continue;
                }
                _ => return EventResult::Continue,
            }
        } else {
            // List view
            match key.code {
                KeyCode::Up | KeyCode::Char('k') => {
                    app.select_prev_memory();
                    return EventResult::Continue;
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    app.select_next_memory();
                    return EventResult::Continue;
                }
                KeyCode::Enter => {
                    app.open_memory_modal();
                    return EventResult::Continue;
                }
                _ => {} // Fall through to global keys
            }
        }
    }
```

**Step 3: Build to verify**

Run: `cargo build -p feroxmute-cli`
Expected: SUCCESS

**Step 4: Commit**

```bash
git add feroxmute-cli/src/tui/events.rs
git commit -m "feat(tui): add key handling for Memory view"
```

---

### Task 8: Create Memory List Widget

**Files:**
- Create: `feroxmute-cli/src/tui/widgets/memory.rs`
- Modify: `feroxmute-cli/src/tui/widgets/mod.rs`

**Step 1: Create memory.rs widget file**

Create `feroxmute-cli/src/tui/widgets/memory.rs`:

```rust
//! Memory list widget

use ratatui::{
    layout::{Constraint, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
    Frame,
};

use crate::tui::app::App;

/// Render the memory list view
pub fn render(frame: &mut Frame, app: &App, area: Rect) {
    if app.memory_entries.is_empty() {
        render_empty(frame, area);
        return;
    }

    let header = Row::new(vec!["Key", "Value", "Updated"])
        .style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD));

    // Calculate column widths
    let key_width = (area.width as f32 * 0.3) as u16;
    let updated_width = 10;
    let value_width = area.width.saturating_sub(key_width + updated_width + 6); // 6 for borders/spacing

    let rows: Vec<Row> = app
        .memory_entries
        .iter()
        .enumerate()
        .map(|(i, entry)| {
            let is_selected = i == app.selected_memory;
            let style = if is_selected {
                Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };

            // Truncate key
            let key_display = truncate_str(&entry.key, key_width as usize - 2);
            let key_cell = if is_selected {
                format!("▶ {}", key_display)
            } else {
                format!("  {}", key_display)
            };

            // Truncate value preview
            let value_preview = entry.value.replace('\n', " ");
            let value_display = truncate_str(&value_preview, value_width as usize - 1);

            // Format time (just HH:MM:SS from datetime string)
            let time_display = entry
                .updated_at
                .split(' ')
                .nth(1)
                .unwrap_or(&entry.updated_at)
                .chars()
                .take(8)
                .collect::<String>();

            Row::new(vec![
                Cell::from(key_cell),
                Cell::from(value_display).style(Style::default().fg(Color::DarkGray)),
                Cell::from(time_display).style(Style::default().fg(Color::DarkGray)),
            ])
            .style(style)
        })
        .collect();

    let title = format!(" Memory ({} entries) ", app.memory_entries.len());
    let table = Table::new(
        rows,
        [
            Constraint::Length(key_width),
            Constraint::Min(value_width),
            Constraint::Length(updated_width),
        ],
    )
    .header(header)
    .block(Block::default().borders(Borders::ALL).title(title));

    frame.render_widget(table, area);

    // Render footer
    render_footer(frame, app, area);
}

/// Render empty state
fn render_empty(frame: &mut Frame, area: Rect) {
    let text = Paragraph::new("No memory entries yet")
        .style(Style::default().fg(Color::DarkGray))
        .block(Block::default().borders(Borders::ALL).title(" Memory "));
    frame.render_widget(text, area);
}

/// Render footer with keybindings
fn render_footer(frame: &mut Frame, _app: &App, area: Rect) {
    let footer_area = Rect {
        x: area.x,
        y: area.y + area.height.saturating_sub(1),
        width: area.width,
        height: 1,
    };

    let help = Line::from(vec![
        Span::styled("↑/↓", Style::default().fg(Color::Yellow)),
        Span::raw(" navigate  "),
        Span::styled("Enter", Style::default().fg(Color::Yellow)),
        Span::raw(" view  "),
        Span::styled("h", Style::default().fg(Color::Yellow)),
        Span::raw(" back  "),
        Span::styled("q", Style::default().fg(Color::Yellow)),
        Span::raw(" quit"),
    ]);

    let footer = Paragraph::new(help).style(Style::default().fg(Color::DarkGray));
    frame.render_widget(footer, footer_area);
}

/// Truncate string to max length with ellipsis
fn truncate_str(s: &str, max_len: usize) -> String {
    if s.chars().count() <= max_len {
        s.to_string()
    } else {
        let truncated: String = s.chars().take(max_len.saturating_sub(3)).collect();
        format!("{}...", truncated)
    }
}
```

**Step 2: Export memory module in mod.rs**

Add to `feroxmute-cli/src/tui/widgets/mod.rs`:

```rust
pub mod memory;
```

**Step 3: Build to verify**

Run: `cargo build -p feroxmute-cli`
Expected: SUCCESS (unused warning for memory module is fine)

**Step 4: Commit**

```bash
git add feroxmute-cli/src/tui/widgets/memory.rs feroxmute-cli/src/tui/widgets/mod.rs
git commit -m "feat(tui): add memory list widget"
```

---

### Task 9: Create Memory Modal Widget

**Files:**
- Create: `feroxmute-cli/src/tui/widgets/memory_modal.rs`
- Modify: `feroxmute-cli/src/tui/widgets/mod.rs`

**Step 1: Create memory_modal.rs widget file**

Create `feroxmute-cli/src/tui/widgets/memory_modal.rs`:

```rust
//! Memory modal popup widget

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
    Frame,
};

use crate::tui::app::App;
use crate::tui::channel::MemoryEntry;

/// Render the memory detail modal
pub fn render(frame: &mut Frame, app: &App) {
    let entry = match app.selected_memory_entry() {
        Some(e) => e,
        None => return,
    };

    let area = frame.area();

    // Calculate modal size (80% of screen)
    let modal_width = (area.width as f32 * 0.8) as u16;
    let modal_height = (area.height as f32 * 0.8) as u16;
    let modal_x = (area.width - modal_width) / 2;
    let modal_y = (area.height - modal_height) / 2;

    let modal_area = Rect {
        x: modal_x,
        y: modal_y,
        width: modal_width,
        height: modal_height,
    };

    // Clear the modal area (creates overlay effect)
    frame.render_widget(Clear, modal_area);

    // Render modal content
    render_modal_content(frame, app, entry, modal_area);
}

fn render_modal_content(frame: &mut Frame, app: &App, entry: &MemoryEntry, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(3),    // Content
            Constraint::Length(3), // Timestamps
            Constraint::Length(1), // Footer
        ])
        .split(area);

    // Main content area
    let title = format!(" Memory: {} ", entry.key);
    let content_block = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .border_style(Style::default().fg(Color::Cyan));

    let inner_area = content_block.inner(chunks[0]);
    frame.render_widget(content_block, chunks[0]);

    // Content with word wrap and scroll
    let content_lines: Vec<Line> = entry
        .value
        .lines()
        .skip(app.memory_modal_scroll)
        .map(|line| Line::from(line.to_string()))
        .collect();

    let content = Paragraph::new(content_lines)
        .wrap(Wrap { trim: false })
        .style(Style::default().fg(Color::White));

    frame.render_widget(content, inner_area);

    // Timestamps
    let timestamps = Paragraph::new(vec![
        Line::from(vec![
            Span::styled("Created: ", Style::default().fg(Color::DarkGray)),
            Span::styled(&entry.created_at, Style::default().fg(Color::Gray)),
            Span::raw("  "),
            Span::styled("Updated: ", Style::default().fg(Color::DarkGray)),
            Span::styled(&entry.updated_at, Style::default().fg(Color::Gray)),
        ]),
    ])
    .block(Block::default().borders(Borders::TOP));

    frame.render_widget(timestamps, chunks[1]);

    // Footer
    let footer = Paragraph::new(Line::from(vec![
        Span::styled("Esc/Enter", Style::default().fg(Color::Yellow)),
        Span::raw(" close  "),
        Span::styled("↑/↓", Style::default().fg(Color::Yellow)),
        Span::raw(" scroll"),
    ]))
    .style(Style::default().fg(Color::DarkGray))
    .alignment(ratatui::layout::Alignment::Center);

    frame.render_widget(footer, chunks[2]);
}
```

**Step 2: Export memory_modal module in mod.rs**

Add to `feroxmute-cli/src/tui/widgets/mod.rs`:

```rust
pub mod memory_modal;
```

**Step 3: Build to verify**

Run: `cargo build -p feroxmute-cli`
Expected: SUCCESS

**Step 4: Commit**

```bash
git add feroxmute-cli/src/tui/widgets/memory_modal.rs feroxmute-cli/src/tui/widgets/mod.rs
git commit -m "feat(tui): add memory modal widget"
```

---

### Task 10: Render Memory View in TUI Runner

**Files:**
- Modify: `feroxmute-cli/src/tui/runner.rs`

**Step 1: Add memory widget imports**

Add to imports:

```rust
use super::widgets::{memory, memory_modal};
```

**Step 2: Add Memory view rendering**

Find the `render()` function or the main rendering match statement. Add a case for `View::Memory`:

```rust
        View::Memory => {
            memory::render(frame, app, frame.area());
            if app.show_memory_modal {
                memory_modal::render(frame, app);
            }
        }
```

This should be in the match block that handles different views. Look for existing matches like `View::Dashboard`, `View::Logs`, etc.

**Step 3: Build to verify**

Run: `cargo build -p feroxmute-cli`
Expected: SUCCESS

**Step 4: Run the application to test manually**

Run: `cargo run -- --target example.com --provider anthropic`
Then press `p` to open memory view.

Expected: Memory view renders (empty initially). Press `h` to go back.

**Step 5: Commit**

```bash
git add feroxmute-cli/src/tui/runner.rs
git commit -m "feat(tui): render Memory view in TUI runner"
```

---

### Task 11: Update Footer to Show Memory Keybinding

**Files:**
- Modify: `feroxmute-cli/src/tui/widgets/dashboard.rs`

**Step 1: Add 'p' to footer keybindings**

In the `render_footer()` function, add the memory keybinding hint:

Find the `help` Line and add after the agents hint:

```rust
        Span::styled("p", Style::default().fg(Color::Yellow)),
        Span::raw(" memory  "),
```

**Step 2: Build to verify**

Run: `cargo build -p feroxmute-cli`
Expected: SUCCESS

**Step 3: Commit**

```bash
git add feroxmute-cli/src/tui/widgets/dashboard.rs
git commit -m "feat(tui): add memory keybinding to dashboard footer"
```

---

### Task 12: Final Integration Test

**Step 1: Build everything**

Run: `cargo build`
Expected: SUCCESS

**Step 2: Run all tests**

Run: `cargo test`
Expected: All tests pass

**Step 3: Manual test**

Run: `cargo run -- --target example.com --provider anthropic`

Test sequence:
1. Press `p` - should show empty memory view
2. Press `h` - should return to dashboard
3. Let engagement run until agent stores something in memory
4. Press `p` - should show memory entries
5. Use `j`/`k` to navigate
6. Press `Enter` - should open modal
7. Press `Esc` - should close modal
8. Press `h` - should return to dashboard

**Step 4: Final commit if any fixes needed**

```bash
git status  # Check for any uncommitted changes
```
