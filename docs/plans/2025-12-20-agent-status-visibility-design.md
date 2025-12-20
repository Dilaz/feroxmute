# Agent Status Visibility Design

**Date:** 2025-12-20
**Status:** Approved

## Problem

When agents run, the TUI shows "Waiting for agent 'name'..." but provides no visibility into what the agent is actually doing. The app appears stuck even though agents are working in the background.

Additional issues:
- Feed log has no timestamps
- Feed log ordering is reversed (should be newest at bottom)
- Dashboard shows idle agents that don't exist yet

## Solution

### 1. Shell Tool `reason` Field

Add a required `reason` field to the shell tool so agents must explain each command:

```rust
pub struct ShellArgs {
    pub command: String,
    pub reason: String,  // Required: why this command is being run
}
```

Tool definition:
```json
{
  "properties": {
    "command": {
      "type": "string",
      "description": "Shell command to execute"
    },
    "reason": {
      "type": "string",
      "description": "Brief explanation of what this command does and why. This is shown to the user in real-time so they can follow your progress."
    }
  },
  "required": ["command", "reason"]
}
```

### 2. Shell Tool Event Sending

The `DockerShellTool` gains access to `EventSender` and `agent_name`:

```rust
pub struct DockerShellTool {
    container: Arc<ContainerManager>,
    events: Arc<dyn EventSender>,
    agent_name: String,
}
```

The `call()` method sends events at key points:

```rust
async fn call(&self, args: Self::Args) -> Result<Self::Output, Self::Error> {
    // 1. Report what we're about to do
    self.events.send_feed(&self.agent_name, &args.reason, false);

    // 2. Report the actual command
    self.events.send_feed(&self.agent_name, &format!("  → {}", args.command), false);

    // 3. Execute command
    let result = self.container.exec(...).await?;

    // 4. Report result summary
    let line_count = result.output().lines().count();
    self.events.send_feed(
        &self.agent_name,
        &format!("  → exit {}, {} lines output", result.exit_code, line_count),
        result.exit_code != 0,
    );

    Ok(ShellOutput { ... })
}
```

### 3. Provider Signature Update

Update `complete_with_shell` to accept events and agent name:

```rust
async fn complete_with_shell(
    &self,
    system_prompt: &str,
    user_prompt: &str,
    container: Arc<ContainerManager>,
    events: Arc<dyn EventSender>,   // NEW
    agent_name: &str,                // NEW
) -> Result<String>
```

All 9 providers (anthropic, openai, gemini, azure, deepseek, cohere, perplexity, mira, xai) need this update.

### 4. Orchestrator Tool Update

`SpawnAgentTool` passes events and agent name to the spawned task:

```rust
provider.complete_with_shell(
    &full_prompt,
    &target,
    container,
    Arc::clone(&events),
    &agent_name,
).await
```

### 5. Dynamic Agent List

Only show agents that have been spawned (no idle placeholders):

```rust
pub struct App {
    pub agents: HashMap<String, AgentDisplayInfo>,
}

pub struct AgentDisplayInfo {
    pub agent_type: String,
    pub status: AgentStatus,
    pub activity: String,
}
```

Agents are added to the map when first seen in feed messages.

### 6. Dashboard Activity Display

Show current activity instead of just status:

```
Orchestrator  Running      Waiting for agent 'recon-dns'...
recon-dns     Running      Enumerating DNS records
recon-ports   Completed    Found 5 open ports
```

Activity is updated from non-indented feed messages.

### 7. Feed Log Improvements

Add timestamps and fix ordering:

```rust
pub struct FeedEntry {
    pub timestamp: chrono::DateTime<chrono::Local>,
    pub agent: String,
    pub message: String,
    pub is_error: bool,
}
```

Display format (newest at bottom with auto-scroll):
```
12:34:05  [orchestrator]  Starting engagement...
12:34:07  [recon-dns]     Enumerating DNS records
12:34:07  [recon-dns]       → dig +short example.com
12:34:08  [recon-dns]       → exit 0, 3 lines output
```

## Files to Modify

### Core library (`feroxmute-core/src/`)

| File | Changes |
|------|---------|
| `tools/shell.rs` | Add `reason` field to args, add `events` + `agent_name` fields, send feed events in `call()` |
| `tools/orchestrator.rs` | Pass `events` and `agent_name` to `complete_with_shell()` in spawned task |
| `providers/traits.rs` | Add `events` and `agent_name` params to `complete_with_shell()` signature |
| `providers/anthropic.rs` | Update `complete_with_shell()` implementation |
| `providers/openai.rs` | Update `complete_with_shell()` implementation |
| `providers/gemini.rs` | Update `complete_with_shell()` implementation |
| `providers/azure.rs` | Update `complete_with_shell()` implementation |
| `providers/deepseek.rs` | Update `complete_with_shell()` implementation |
| `providers/cohere.rs` | Update `complete_with_shell()` implementation |
| `providers/perplexity.rs` | Update `complete_with_shell()` implementation |
| `providers/mira.rs` | Update `complete_with_shell()` implementation |
| `providers/xai.rs` | Update `complete_with_shell()` implementation |

### CLI (`feroxmute-cli/src/`)

| File | Changes |
|------|---------|
| `tui/app.rs` | Add `agents: HashMap`, `FeedEntry` with timestamp |
| `tui/runner.rs` | Update event handling for dynamic agents + activity tracking |
| `tui/widgets/dashboard.rs` | Render dynamic agent list with activity, fix feed ordering |
