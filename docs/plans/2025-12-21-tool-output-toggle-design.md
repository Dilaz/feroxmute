# Tool Output Toggle Feature Design

## Overview

Add a toggle key (`o`) to expand/collapse full tool outputs inline in the agent detail view feed. Currently, tool outputs display only a summary like "exit 0, 19 lines output" - this feature allows users to see the actual output without leaving the TUI.

## Design Decisions

- **Inline expansion**: Press `o` on a feed entry to expand/collapse its full output directly in the feed list
- **Key binding**: `o` (mnemonic for "output")
- **Full output display**: All lines shown inline, scroll with `j/k`
- **Multiple expansion**: Each entry remembers its own expand/collapse state independently

## Data Flow Changes

### 1. Extend `AgentEvent::Feed` (channel.rs)

```rust
Feed {
    agent: String,
    message: String,
    is_error: bool,
    tool_output: Option<String>,  // NEW: full output when available
}
```

### 2. Extend `FeedEntry` (app.rs)

```rust
pub struct FeedEntry {
    pub timestamp: DateTime<Local>,
    pub agent: String,
    pub message: String,
    pub is_error: bool,
    pub tool_output: Option<String>,  // NEW: stored full output
    pub expanded: bool,                // NEW: expansion state
}
```

### 3. Add EventSender method (tools/mod.rs)

Add a new method to avoid changing all existing call sites:

```rust
fn send_feed_with_output(&self, agent: &str, message: &str, is_error: bool, output: &str);
```

### 4. Modify shell.rs

Use `send_feed_with_output` for the result summary line to attach the raw output.

## UI Rendering Changes

### Expanded entry display (agent_detail.rs)

```
14:32:05   -> exit 0, 19 lines output
           │ line 1 of actual output
           │ line 2 of actual output
           │ ...
```

- Dim vertical bar `│` prefix groups output lines visually
- Output lines inherit entry style (red if error)

### Key handling (runner.rs)

- `o` key in AgentDetail view toggles `expanded` on selected feed entry
- No-op if entry has no tool_output

### Footer hint update

```
j/k scroll  o output  t thinking [ON]  ...
```

## Files to Modify

| File | Changes |
|------|---------|
| `feroxmute-cli/src/tui/channel.rs` | Add `tool_output: Option<String>` to `Feed` variant |
| `feroxmute-cli/src/tui/app.rs` | Add `tool_output` and `expanded` fields to `FeedEntry` |
| `feroxmute-core/src/tools/mod.rs` | Add `send_feed_with_output` to `EventSender` trait |
| `feroxmute-core/src/tools/shell.rs` | Use `send_feed_with_output` for result line |
| `feroxmute-cli/src/tui/widgets/agent_detail.rs` | Render expanded output, update footer hint |
| `feroxmute-cli/src/tui/runner.rs` | Handle `o` key to toggle expansion |

## Memory Considerations

- Feed capped at 100 entries (existing limit)
- Tool outputs already truncated at 8000 chars in `prepare_output()`
- No additional memory concerns
