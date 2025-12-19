# Orchestrator Agent Spawning Design

## Overview

Restructure the agent architecture so the orchestrator is truly in control and dynamically spawns child agents via tool calls, rather than holding them as struct fields.

## Current Problems

1. `main.rs` directly calls `run_recon_agent()`, bypassing the orchestrator entirely
2. `OrchestratorAgent` creates child agents at construction time as struct fields
3. Delegation is synchronous - orchestrator blocks while child agent runs
4. Dashboard feed doesn't wrap or scroll long messages

## Design Decisions

| Decision | Choice |
|----------|--------|
| Agent execution model | Async concurrent - agents run in background, orchestrator continues |
| Spawn parameters | Type + name + instructions (base prompt from prompts.toml) |
| Wait mechanism | Both `wait_for_agent(name)` and `wait_for_any()` available |
| Long feed messages | Horizontal scrolling in dashboard |

## New Startup Flow

```
main.rs → validate docker/provider → start container → spawn OrchestratorAgent only
         ↓
OrchestratorAgent runs in agentic loop
         ↓
Orchestrator uses spawn_agent() tool → creates child agent task
         ↓
Child agent runs async in background (multiple can run concurrently)
         ↓
Orchestrator uses wait_for_agent() or wait_for_any() → gets results
```

## Orchestrator Tools

| Tool | Parameters | Description |
|------|------------|-------------|
| `spawn_agent` | `type`, `name`, `instructions` | Spawns agent in background, returns immediately |
| `wait_for_agent` | `name` | Blocks until named agent completes, returns result |
| `wait_for_any` | (none) | Blocks until any agent completes, returns name + result |
| `list_agents` | (none) | Returns status of all spawned agents |
| `record_finding` | `finding`, `category` | Records a finding (keep existing) |
| `complete_engagement` | `summary` | Ends engagement (keep existing) |

**Removed tools:** `delegate_recon`, `delegate_scanner`, `delegate_sast`, `advance_phase`, `get_status`

**Agent types:** `recon`, `scanner`, `sast` (if source target), `report`

## AgentRegistry

New struct in `feroxmute-core/src/agents/registry.rs`:

```rust
pub struct AgentRegistry {
    agents: HashMap<String, SpawnedAgent>,
    result_rx: mpsc::Receiver<AgentResult>,
    result_tx: mpsc::Sender<AgentResult>,
}

pub struct SpawnedAgent {
    name: String,
    agent_type: String,
    status: AgentStatus,
    spawned_at: Instant,
    handle: JoinHandle<()>,
}

pub struct AgentResult {
    name: String,
    success: bool,
    output: String,
    duration: Duration,
}
```

**Lifecycle:**
1. Spawn: Registry creates agent with combined prompt, spawns as async task
2. Running: Agent sends progress events to TUI via existing channel
3. Complete: Agent sends `AgentResult` through registry's result channel
4. Wait: Orchestrator polls registry for results

## Child Agent Prompt Construction

Combined prompt structure:

```
[Base prompt from prompts.toml for agent type]

---

## Task from Orchestrator

Name: {name}
Instructions: {instructions}
Target: {target}
Context: {any relevant findings so far}
```

Child agents:
- Run the same agentic loop (LLM + shell tool calls)
- Have no knowledge of other agents
- Return a summary when complete

## TUI Horizontal Scrolling

Dashboard feed changes:
- Add `feed_scroll_x: u16` to `App` state
- Keybindings: `←`/`→` or `h`/`l` to scroll horizontally
- Show `→` indicator in title when content extends beyond visible area

## File Changes

### New Files

| File | Purpose |
|------|---------|
| `feroxmute-core/src/agents/registry.rs` | `AgentRegistry`, `SpawnedAgent`, `AgentResult` |

### Modified Files

| File | Changes |
|------|---------|
| `feroxmute-core/src/agents/mod.rs` | Export registry module |
| `feroxmute-core/src/agents/orchestrator.rs` | Remove child agent fields, new tools, use registry |
| `feroxmute-cli/src/runner.rs` | Replace `run_recon_agent()` with `run_orchestrator()` |
| `feroxmute-cli/src/main.rs` | Call `run_orchestrator()` |
| `feroxmute-cli/src/tui/app.rs` | Add `feed_scroll_x` field |
| `feroxmute-cli/src/tui/widgets/dashboard.rs` | Implement horizontal scroll |
| `feroxmute-cli/src/tui/events.rs` | Add scroll key handlers |

### Deleted Code

From `OrchestratorAgent`:
- Fields: `recon_agent`, `scanner_agent`, `sast_agent`
- Tools: `delegate_recon`, `delegate_scanner`, `delegate_sast`, `advance_phase`, `get_status`
- Methods: `handle_delegate_*`, `handle_advance_phase`, `handle_get_status`
