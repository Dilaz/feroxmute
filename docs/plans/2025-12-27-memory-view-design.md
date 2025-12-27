# Memory View Design

**Date:** 2025-12-27
**Status:** Approved

## Overview

Add a TUI view to display memory (scratch pad) entries stored by agents, with a modal popup to view full content.

## User Interaction

- **Key:** Press `p` from any view to open Memory view
- **Navigation:** `j`/`k` or `↑`/`↓` to move selection in list
- **View detail:** `Enter` opens modal popup for selected entry
- **Close modal:** `Esc` or `Enter` returns to list
- **Exit view:** `Esc`/`h` returns to Dashboard

## Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Keybinding | `p` for "pad" | Avoids conflicts, intuitive for "scratch pad" |
| Detail view | Modal popup | Quick preview without losing list context |
| List info | Key + truncated value + timestamp | Balance of information at a glance |
| Updates | Auto-refresh | Matches live feed behavior |
| Modal size | 80% screen, word-wrapped | Readable for short strings to multi-line JSON |

## View Structure

### New View Enum Variant

```rust
pub enum View {
    Dashboard,
    AgentDetail(String),
    Logs,
    Help,
    Memory,  // NEW
}
```

### App State Additions

```rust
pub struct App {
    // ... existing fields ...

    /// Memory entries for display
    pub memory_entries: Vec<MemoryEntry>,
    /// Currently selected memory entry index
    pub selected_memory: usize,
    /// Show memory detail modal
    pub show_memory_modal: bool,
    /// Scroll offset for modal content
    pub memory_modal_scroll: usize,
}
```

### MemoryEntry Struct (in channel.rs)

```rust
pub struct MemoryEntry {
    pub key: String,
    pub value: String,
    pub updated_at: String,
}
```

## List View Layout

```
┌─ Memory (3 entries) ──────────────────────────────────────────┐
│  KEY                 VALUE                         UPDATED    │
├───────────────────────────────────────────────────────────────┤
│▶ recon-targets       "api.example.com, admin..."   12:34:56   │
│  recon-technologies  "nginx, php, wordpress..."    12:35:12   │
│  scanner-findings    "[{\"title\":\"XSS in..."     12:36:45   │
│                                                               │
└───────────────────────────────────────────────────────────────┘
 ↑/↓ navigate  Enter view  h back  q quit
```

- Table with 3 columns: Key (30%), Value preview (50%), Updated (20%)
- Value preview truncated with `...`
- Selected row highlighted with `▶` prefix
- Empty state: "No memory entries yet"

## Modal Popup Layout

```
┌─ Memory: recon-targets ───────────────────────────────────────┐
│                                                               │
│  api.example.com                                              │
│  admin.example.com                                            │
│  dev.example.com                                              │
│  staging.example.com                                          │
│                                                               │
│  ─────────────────────────────────────────────────────────    │
│  Created: 2025-12-27 12:34:56                                 │
│  Updated: 2025-12-27 12:34:56                                 │
│                                                               │
└───────────────────────────────────────────────────────────────┘
                        Esc/Enter close
```

- Centered, 80% width × 80% height
- Dimmed background
- Word-wrapped content, scrollable with `j`/`k`
- Footer shows timestamps

## Event System

### New Event Variant

```rust
pub enum AgentEvent {
    // ... existing variants ...

    MemoryUpdated {
        entries: Vec<MemoryEntry>,
    },
}
```

### EventSender Trait Extension

```rust
pub trait EventSender: Send + Sync {
    // ... existing methods ...

    fn send_memory_update(&self, entries: Vec<MemoryEntry>);
}
```

### Trigger Points

After each memory tool call (`memory_add`, `memory_remove`), query all entries:

```sql
SELECT key, value, updated_at FROM scratch_pad ORDER BY key
```

Then send the `MemoryUpdated` event.

## Files to Modify

| File | Changes |
|------|---------|
| `feroxmute-cli/src/tui/app.rs` | Add `Memory` to View enum, add state fields and methods |
| `feroxmute-cli/src/tui/events.rs` | Handle `p` key, Enter/Esc for modal, j/k navigation |
| `feroxmute-cli/src/tui/channel.rs` | Add `MemoryUpdated` event, `MemoryEntry` struct |
| `feroxmute-cli/src/tui/runner.rs` | Render Memory view, handle event in `drain_events()` |
| `feroxmute-cli/src/tui/widgets/mod.rs` | Export memory module |
| `feroxmute-cli/src/tui/widgets/memory.rs` | **NEW** - List view widget |
| `feroxmute-cli/src/tui/widgets/memory_modal.rs` | **NEW** - Modal popup widget |
| `feroxmute-core/src/tools/mod.rs` | Add `send_memory_update()` to EventSender trait |
| `feroxmute-core/src/tools/memory.rs` | Call `send_memory_update()` after operations |
| `feroxmute-cli/src/runner.rs` | Implement `send_memory_update()` in TuiEventSender |

## No Changes Needed

- Provider code
- Agent code
- Database schema (scratch_pad table already exists)
