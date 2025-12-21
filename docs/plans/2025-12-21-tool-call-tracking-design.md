# Tool Call Tracking Design

## Overview

Hook the TUI "Tool Calls" display to actual LLM tool invocations instead of showing 0.

## Current State

- `App.metrics.tool_calls` exists in TUI but is never populated
- `AgentEvent::Metrics` only sends token counts, not tool calls
- Rig streams `StreamedAssistantContent::ToolCall` events but they're ignored with `_ => {}`

## Design

### Data Flow

```
Stream loop (macros.rs)
    ↓ counts StreamedAssistantContent::ToolCall events
    ↓
AgentEvent::Metrics { input, output, cache_read, cost_usd, tool_calls }
    ↓
TUI runner (runner.rs)
    ↓ app.metrics.tool_calls += tool_calls
    ↓
Dashboard displays updated count
```

### Scope

Counts all LLM tool invocations including:
- `spawn_agent`, `wait_for_agent`, `wait_for_any`, `list_agents`
- `record_finding`, `complete_engagement`
- `shell` (DockerShellTool)
- `generate_report`, `export_json`, `export_markdown`, `add_recommendation`

### Timing

Tool call counts update when an agent completes (batched with token metrics), not on each individual call.

## Changes

### feroxmute-cli/src/tui/channel.rs

Add `tool_calls` field to `Metrics` event:

```rust
Metrics {
    input: u64,
    output: u64,
    cache_read: u64,
    cost_usd: f64,
    tool_calls: u64,  // NEW
}
```

### feroxmute-core/src/tools/orchestrator.rs

Extend `EventSender` trait signature:

```rust
fn send_metrics(&self, input: u64, output: u64, cache_read: u64, cost_usd: f64, tool_calls: u64);
```

### feroxmute-cli/src/runner.rs

1. Update `TuiEventSender::send_metrics` to accept and forward `tool_calls`
2. Update `drain_events` handler to increment `app.metrics.tool_calls`

### feroxmute-core/src/providers/macros.rs

In all three stream loops (`complete_with_shell`, `complete_with_orchestrator`, `complete_with_report`):

1. Add counter: `let mut tool_call_count: u64 = 0;`
2. Add match arm:
   ```rust
   rig::streaming::StreamedAssistantContent::ToolCall(_) => {
       tool_call_count += 1;
   }
   ```
3. Pass count to `send_metrics(..., tool_call_count)`

### feroxmute-core/src/providers/ollama.rs

Same changes as macros.rs for the manual implementation.

### feroxmute-core/src/providers/azure.rs

Same changes as macros.rs for the manual implementation.

## Edge Cases

- **Cancelled engagements**: Tool calls counted up to cancellation are lost (no metrics event sent). Matches current token behavior.
- **Multiple agents**: Each agent sends its own metrics event; TUI accumulates totals.
