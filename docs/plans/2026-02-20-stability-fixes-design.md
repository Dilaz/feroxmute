# Stability & Quality Fixes Design

**Date**: 2026-02-20

Addresses four issues from `fixes.md`: agent status sync, orchestrator cleanup, tool output truncation, and memory attribution.

## Fix 1: Agent Status Synchronization

**Problem**: All `EventSender` methods in `TuiEventSender` (runner.rs) wrap channel sends in `tokio::spawn`, destroying ordering guarantees. Rapid status transitions arrive out-of-order in the TUI.

**Solution**:
- Remove all `tokio::spawn` wrappers from `TuiEventSender`
- Use `tx.try_send()` (synchronous, non-blocking) for all event sends
- Keep the bounded `mpsc::channel(100)` for backpressure
- On `TrySendError::Full`, log via `tracing::warn!` and drop the event

**Files**: `feroxmute-cli/src/runner.rs`

## Fix 5: Orchestrator Premature Exit — Agent Cleanup

**Problem**: When the orchestrator exits without `complete_engagement`, spawned agent tasks keep running. The TUI shows orchestrator as Failed but agents remain in active states.

**Solution**:
- Add `abort_all(&mut self) -> Vec<(String, String)>` to `AgentRegistry` — aborts `JoinHandle`s, marks agents `Failed`, returns (name, agent_type) list
- After orchestrator loop terminates with failure, call `abort_all` on the registry and send `Failed` status to TUI for each aborted agent
- Return `Arc<OrchestratorContext>` from `run_orchestrator_with_tools` alongside the result so the outer function can access the registry

**Files**: `feroxmute-core/src/agents/registry.rs`, `feroxmute-cli/src/runner.rs`

## Fix 6: Head+Tail Truncation for Tool Output

**Problem**: `prepare_output` in shell.rs truncates from the head only (first 8000 chars). Security tools put key findings at the end, so agents lose valuable data.

**Solution**:
- Split truncation budget: `HEAD_BUDGET = 2000`, `TAIL_BUDGET = 6000`
- Use `char_indices()` for head and `ceil_char_boundary` for tail — both UTF-8 safe
- Insert separator showing bytes omitted between head and tail
- Update existing tests and add head+tail specific test

**Files**: `feroxmute-core/src/tools/shell.rs`

## Fix 2: Memory Attribution

**Problem**: `MemoryContext` is created once with `agent_name: "orchestrator"` and cloned for all subagents. All memory operations are attributed to "orchestrator".

**Solution**:
- Add `MemoryContext::with_agent_name(&Arc<Self>, String) -> Arc<Self>` that shares `conn` and `events` but uses a new agent name
- In `SpawnAgentTool::call`, replace `Arc::clone(&self.context.memory)` with `self.context.memory.with_agent_name(agent_name.clone())` for all three spawn branches

**Files**: `feroxmute-core/src/tools/memory.rs`, `feroxmute-core/src/tools/orchestrator.rs`

## Out of Scope

**Token estimation (#3)**: Filed as GitHub issue. Requires investigating rig-core's response metadata per provider — deeper work than these fixes.

**SQLite connection pooling (#4)**: WAL mode and busy timeout already enabled. `Arc<Mutex<Connection>>` is adequate for ~6 agents.
