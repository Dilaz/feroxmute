# Orchestrator Rig Tools Design

## Problem

The orchestrator agent gets stuck in an infinite "thinking" loop because:

1. `run_orchestrator_loop` in `runner.rs` manually handles a conversation loop
2. It expects `response.tool_calls` to contain the LLM's tool requests
3. All providers' `complete()` methods always return `tool_calls: vec![]`
4. The providers use rig's `agent.prompt()` which returns a String after rig internally handles any tool loop
5. The tools passed via `request.tools` are completely ignored

## Solution

Replace the manual conversation loop with rig's built-in agentic loop by creating 6 rig `Tool` implementations for orchestrator operations.

## Architecture

```
runner.rs
    │
    ▼
provider.complete_with_orchestrator(context)
    │
    ▼
rig Agent with 6 tools ──► OrchestratorContext (Arc)
    │                            │
    │                            ├─ Arc<Mutex<AgentRegistry>>
    │                            ├─ Arc<dyn LlmProvider>
    │                            ├─ Arc<ContainerManager>
    │                            ├─ mpsc::Sender<AgentEvent>
    │                            ├─ CancellationToken
    │                            ├─ Prompts
    │                            └─ target: String
    ▼
rig handles tool loop internally
    │
    ▼
complete_engagement tool triggers CancellationToken
    │
    ▼
Loop exits, return final summary
```

## Components

### OrchestratorContext

Shared context struct holding all dependencies:

```rust
pub struct OrchestratorContext {
    pub registry: Arc<Mutex<AgentRegistry>>,
    pub provider: Arc<dyn LlmProvider>,
    pub container: Arc<ContainerManager>,
    pub tx: mpsc::Sender<AgentEvent>,
    pub cancel: CancellationToken,
    pub prompts: Prompts,
    pub target: String,
    pub findings: Arc<Mutex<Vec<String>>>,
}
```

### Tool Implementations

| Tool | Args | Behavior |
|------|------|----------|
| `SpawnAgentTool` | agent_type, name, instructions | Spawns agent via `provider.complete_with_shell()`, registers in registry |
| `WaitForAgentTool` | name | Calls `registry.wait_for_agent()`, returns result |
| `WaitForAnyTool` | (none) | Calls `registry.wait_for_any()`, returns result |
| `ListAgentsTool` | (none) | Calls `registry.list_agents()`, formats output |
| `RecordFindingTool` | finding, category | Appends to `findings` vec |
| `CompleteEngagementTool` | summary | Triggers `cancel.cancel()`, returns summary |

Each tool holds `Arc<OrchestratorContext>` and accesses what it needs. The mutex is only held briefly during each operation.

### Provider Changes

New trait method:

```rust
async fn complete_with_orchestrator(
    &self,
    system_prompt: &str,
    user_prompt: &str,
    context: Arc<OrchestratorContext>,
) -> Result<String>;
```

Implementation builds rig agent with all 6 tools and runs with cancellation support.

### Runner Simplification

The current `run_orchestrator_loop` function (~107 lines) gets replaced with ~40 lines that:
1. Build the `OrchestratorContext`
2. Call `provider.complete_with_orchestrator()`
3. Return the result

All manual tool handling functions are removed.

## Files Changed

- `feroxmute-core/src/tools/orchestrator.rs` (new) - 6 tool implementations
- `feroxmute-core/src/tools/mod.rs` - export new module
- `feroxmute-core/src/providers/traits.rs` - add `complete_with_orchestrator` method
- `feroxmute-core/src/providers/anthropic.rs` (and others) - implement new method
- `feroxmute-cli/src/runner.rs` - simplify to use new provider method

## Error Handling

- Tool execution fails → Rig passes error back to LLM, which can retry or adjust
- Agent spawn fails → `SpawnAgentTool` returns error message, LLM decides next step
- LLM never calls `complete_engagement` → Rig's max iterations stops, or add safeguard
- Duplicate agent names → `SpawnAgentTool` checks `registry.has_agent()`, returns error
- External cancel (user presses 'q') → Outer `tokio::select!` handles via cancel token

## Testing

- Unit tests for each tool with mock context
- Integration test with mock provider to verify full loop
