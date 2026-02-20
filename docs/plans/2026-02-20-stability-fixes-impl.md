# Stability Fixes Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix agent status synchronization, orchestrator cleanup on premature exit, tool output truncation strategy, and memory attribution for subagents.

**Architecture:** Four independent fixes touching the CLI runner, core agent registry, shell tool output, and memory context. Each fix is self-contained and testable in isolation.

**Tech Stack:** Rust, tokio (mpsc channels, JoinHandle), rusqlite, ratatui TUI

---

### Task 1: Head+Tail Truncation for Tool Output

**Files:**
- Modify: `feroxmute-core/src/tools/shell.rs:28-30` (constants)
- Modify: `feroxmute-core/src/tools/shell.rs:207-229` (`prepare_output` function)
- Modify: `feroxmute-core/src/tools/shell.rs:571-603` (existing tests)

**Step 1: Update existing tests to expect head+tail format**

Replace the truncation tests at the bottom of `shell.rs`. The key changes:
- `test_prepare_output_long_truncated` should verify both head and tail are present
- `test_prepare_output_truncation_suffix` should check for the new `[N bytes omitted]` format
- Add `test_prepare_output_head_tail_split` to verify head/tail content
- Add `test_prepare_output_head_tail_utf8_boundary` for multi-byte chars at tail boundary

```rust
#[test]
fn test_prepare_output_long_truncated() {
    let input = "a".repeat(MAX_OUTPUT_LENGTH + 1000);
    let (output, truncated) = prepare_output(&input);
    assert!(truncated);
    assert!(output.len() < input.len());
    // Should contain both head and tail content
    assert!(output.contains("bytes omitted"));
}

#[test]
fn test_prepare_output_utf8_safe_boundary() {
    // Create a string with multi-byte chars right around the boundary
    let mut input = "a".repeat(MAX_OUTPUT_LENGTH - 2);
    input.push('é'); // 2-byte char at boundary
    input.push_str(&"b".repeat(1000));
    let (_, truncated) = prepare_output(&input);
    assert!(truncated);
}

#[test]
fn test_prepare_output_truncation_suffix() {
    let input = "x".repeat(MAX_OUTPUT_LENGTH + 500);
    let (output, _) = prepare_output(&input);
    assert!(output.contains("bytes omitted"));
}

#[test]
fn test_prepare_output_head_tail_split() {
    // Create input with distinct head and tail content
    let head_content = "HEAD".repeat(500); // 2000 chars
    let middle = "M".repeat(MAX_OUTPUT_LENGTH); // filler
    let tail_content = "TAIL".repeat(1500); // 6000 chars
    let input = format!("{}{}{}", head_content, middle, tail_content);

    let (output, truncated) = prepare_output(&input);
    assert!(truncated);
    // Head should contain beginning of input
    assert!(output.starts_with("HEAD"));
    // Tail should contain end of input
    assert!(output.ends_with("TAIL"));
    // Middle should be omitted
    assert!(output.contains("bytes omitted"));
}

#[test]
fn test_prepare_output_head_tail_utf8_boundary() {
    // Put multi-byte chars where the tail boundary would fall
    let head = "a".repeat(2000);
    let middle = "b".repeat(5000);
    // Place multi-byte chars right where tail_start would land
    let tail_area = "é".repeat(3500); // 2 bytes each = 7000 bytes
    let input = format!("{}{}{}", head, middle, tail_area);

    let (output, truncated) = prepare_output(&input);
    assert!(truncated);
    // Should not panic — UTF-8 safe
    assert!(output.contains("bytes omitted"));
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test -p feroxmute-core test_prepare_output -- --nocapture`
Expected: `test_prepare_output_head_tail_split` and `test_prepare_output_head_tail_utf8_boundary` FAIL (new tests, function doesn't exist yet for the new ones; existing tests fail because format changed)

**Step 3: Add constants and implement head+tail `prepare_output`**

In `shell.rs`, add constants after `MAX_OUTPUT_LENGTH`:

```rust
const MAX_OUTPUT_LENGTH: usize = 8000;
/// Head portion budget for truncated output (command banner, headers)
const HEAD_BUDGET: usize = 2000;
/// Tail portion budget for truncated output (results, summaries)
const TAIL_BUDGET: usize = 6000;
```

Replace the `prepare_output` function:

```rust
fn prepare_output(output: &str) -> (String, bool) {
    let sanitized = sanitize_output(output);

    if sanitized.len() <= MAX_OUTPUT_LENGTH {
        return (sanitized, false);
    }

    // Head: first HEAD_BUDGET bytes (UTF-8 safe)
    let head: String = sanitized
        .char_indices()
        .take_while(|(i, _)| *i < HEAD_BUDGET)
        .map(|(_, c)| c)
        .collect();

    // Tail: last TAIL_BUDGET bytes (UTF-8 safe)
    let tail_start = sanitized.len().saturating_sub(TAIL_BUDGET);
    let tail_start = sanitized.ceil_char_boundary(tail_start);
    let tail = &sanitized[tail_start..];

    let omitted = sanitized.len() - head.len() - tail.len();

    (
        format!(
            "{}\n\n... [{} bytes omitted] ...\n\n{}",
            head, omitted, tail
        ),
        true,
    )
}
```

**Step 4: Run tests to verify they pass**

Run: `cargo test -p feroxmute-core test_prepare_output -- --nocapture`
Expected: All PASS

**Step 5: Run clippy**

Run: `cargo clippy -p feroxmute-core -- -D warnings`
Expected: No warnings

**Step 6: Commit**

```bash
git add feroxmute-core/src/tools/shell.rs
git commit -m "fix: use head+tail truncation for tool output

Keep first 2000 chars (command banners, headers) and last 6000 chars
(results, summaries) instead of truncating from head only. Security
tools typically put key findings at the end of output."
```

---

### Task 2: Memory Attribution for Subagents

**Files:**
- Modify: `feroxmute-core/src/tools/memory.rs:24-29` (add `with_agent_name`)
- Modify: `feroxmute-core/src/tools/orchestrator.rs:396` (use it in SpawnAgentTool)
- Modify: `feroxmute-core/src/tools/memory.rs:447-455` (add test)

**Step 1: Write test for `with_agent_name`**

Add to the `tests` module in `memory.rs`:

```rust
#[test]
fn test_with_agent_name_creates_new_context() {
    let conn = Connection::open_in_memory().expect("should open in-memory db");
    run_migrations(&conn).expect("migrations should succeed");
    let original = Arc::new(MemoryContext {
        conn: Arc::new(Mutex::new(conn)),
        events: Arc::new(NoopEventSender),
        agent_name: "orchestrator".to_string(),
    });

    let renamed = original.with_agent_name("recon-agent".to_string());

    assert_eq!(renamed.agent_name, "recon-agent");
    assert_eq!(original.agent_name, "orchestrator");
    // Should share the same connection (Arc points to same data)
    assert!(Arc::ptr_eq(&original.conn, &renamed.conn));
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p feroxmute-core test_with_agent_name -- --nocapture`
Expected: FAIL — `with_agent_name` method does not exist

**Step 3: Implement `with_agent_name`**

Add an `impl` block for `MemoryContext` in `memory.rs` (after the struct definition, before `broadcast_memory_update`):

```rust
impl MemoryContext {
    /// Create a new context with a different agent name, sharing the DB connection and events
    pub fn with_agent_name(self: &Arc<Self>, agent_name: String) -> Arc<Self> {
        Arc::new(MemoryContext {
            conn: Arc::clone(&self.conn),
            events: Arc::clone(&self.events),
            agent_name,
        })
    }
}
```

**Step 4: Run test to verify it passes**

Run: `cargo test -p feroxmute-core test_with_agent_name -- --nocapture`
Expected: PASS

**Step 5: Update `SpawnAgentTool` to use `with_agent_name`**

In `orchestrator.rs`, find line 396:

```rust
// Before:
let memory = Arc::clone(&self.context.memory);

// After:
let memory = self.context.memory.with_agent_name(agent_name.clone());
```

This single line change applies to all three spawn branches (shell, report, llm_pentest) because they all use `memory` from this same binding.

**Step 6: Run full test suite**

Run: `cargo test -p feroxmute-core`
Expected: All tests pass

**Step 7: Run clippy**

Run: `cargo clippy -p feroxmute-core -- -D warnings`
Expected: No warnings

**Step 8: Commit**

```bash
git add feroxmute-core/src/tools/memory.rs feroxmute-core/src/tools/orchestrator.rs
git commit -m "fix: attribute memory operations to correct agent

Add MemoryContext::with_agent_name() to create per-agent contexts
sharing the same DB connection. SpawnAgentTool now creates a context
with the actual agent name instead of cloning the orchestrator's."
```

---

### Task 3: Agent Status Synchronization

**Files:**
- Modify: `feroxmute-cli/src/runner.rs:22-224` (TuiEventSender impl)

Note: `TuiEventSender` is a private struct in the CLI crate with no direct unit tests. The fix is mechanical — replace `tokio::spawn(async { tx.send(...).await })` with `tx.try_send(...)` for all 11 methods. Testing is done via build + `cargo test -p feroxmute-cli` for compilation, plus manual TUI verification.

**Step 1: Replace all `tokio::spawn` wrappers with `try_send`**

Rewrite the entire `EventSender for TuiEventSender` impl block. The pattern for each method is:

```rust
fn send_status(&self, agent: &str, agent_type: &str, status: AgentStatus, current_tool: Option<String>) {
    if self.tx.try_send(AgentEvent::Status {
        agent: agent.to_string(),
        agent_type: agent_type.to_string(),
        status,
        current_tool,
    }).is_err() {
        tracing::warn!("TUI event channel full, dropping status event for {}", agent);
    }
}
```

Apply this pattern to all 11 methods:
1. `send_feed` — drop `tokio::spawn`, use `try_send` with `AgentEvent::Feed`
2. `send_feed_with_output` — same pattern, includes `tool_output: Some(output)`
3. `send_status` — as shown above
4. `send_metrics` — `try_send` with `AgentEvent::Metrics`
5. `send_vulnerability` — keep the severity mapping, `try_send` with `AgentEvent::Vulnerability`
6. `send_thinking` — `try_send` with `AgentEvent::Thinking`
7. `send_phase` — `try_send` with `AgentEvent::Phase`
8. `send_summary` — keep the field extraction, `try_send` with `AgentEvent::Summary`
9. `send_memory_update` — keep the `MemoryEntry` conversion, `try_send` with `AgentEvent::MemoryUpdated`
10. `send_code_finding` — keep `CodeFindingEvent` construction, `try_send` with `AgentEvent::CodeFinding`
11. `send_tool_call` — `try_send` with `AgentEvent::ToolCall`

For `send_metrics`, `send_vulnerability`, `send_phase`, `send_thinking`, `send_tool_call` — use a generic warning message since there's no agent name:

```rust
tracing::warn!("TUI event channel full, dropping event");
```

**Step 2: Add tracing import if not present**

Check if `tracing` is already a dependency of `feroxmute-cli`. If not:

Run: `cargo add tracing -p feroxmute-cli`

Then add to `runner.rs` if needed — but `tracing::warn!` is typically usable without an explicit import.

**Step 3: Build and test**

Run: `cargo build -p feroxmute-cli && cargo test -p feroxmute-cli`
Expected: Build succeeds, all CLI tests pass

**Step 4: Run clippy**

Run: `cargo clippy -p feroxmute-cli -- -D warnings`
Expected: No warnings

**Step 5: Commit**

```bash
git add feroxmute-cli/src/runner.rs
git commit -m "fix: remove tokio::spawn from TuiEventSender for ordered events

Replace fire-and-forget tokio::spawn with synchronous try_send on the
bounded mpsc channel. This guarantees events from a single agent
arrive at the TUI in the order they were emitted, fixing out-of-order
status display (e.g., stuck on Executing after completion)."
```

---

### Task 4: Orchestrator Premature Exit — Agent Cleanup

**Files:**
- Modify: `feroxmute-core/src/agents/registry.rs` (add `abort_all`)
- Modify: `feroxmute-cli/src/runner.rs:362-501` (return context, add cleanup)

**Step 1: Write test for `abort_all`**

Add to the `tests` module in `registry.rs`:

```rust
#[tokio::test]
async fn test_abort_all_marks_running_agents_failed() {
    let (mut registry, _waiter) = AgentRegistry::new();

    // Register agents in different states
    let handle1 = tokio::spawn(async { tokio::time::sleep(Duration::from_secs(60)).await });
    registry.register(
        "running-agent".to_string(),
        "recon".to_string(),
        "test".to_string(),
        handle1,
    );

    let handle2 = tokio::spawn(async {});
    registry.register(
        "done-agent".to_string(),
        "scanner".to_string(),
        "test".to_string(),
        handle2,
    );
    registry.mark_agent_result("done-agent", true); // Mark as Completed

    let aborted = registry.abort_all();

    // Only the running agent should be aborted
    assert_eq!(aborted.len(), 1);
    assert_eq!(aborted[0].0, "running-agent");
    assert_eq!(aborted[0].1, "recon");

    // All agents should now be in terminal state
    assert_eq!(registry.running_count(), 0);
}

#[tokio::test]
async fn test_abort_all_empty_registry() {
    let (mut registry, _waiter) = AgentRegistry::new();
    let aborted = registry.abort_all();
    assert!(aborted.is_empty());
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test -p feroxmute-core test_abort_all -- --nocapture`
Expected: FAIL — `abort_all` method does not exist

**Step 3: Implement `abort_all`**

Add to the `impl AgentRegistry` block in `registry.rs`, after `mark_agent_result`:

```rust
/// Abort all running agents and return their (name, agent_type) for status notification
pub fn abort_all(&mut self) -> Vec<(String, String)> {
    let mut aborted = Vec::new();
    for agent in self.agents.values_mut() {
        if !matches!(agent.status, AgentStatus::Completed | AgentStatus::Failed) {
            if let Some(handle) = agent.handle.take() {
                handle.abort();
            }
            agent.status = AgentStatus::Failed;
            aborted.push((agent.name.clone(), agent.agent_type.clone()));
        }
    }
    aborted
}
```

**Step 4: Run tests to verify they pass**

Run: `cargo test -p feroxmute-core test_abort_all -- --nocapture`
Expected: Both PASS

**Step 5: Update `run_orchestrator_with_tools` to return context**

In `runner.rs`, change the return type:

```rust
// Before:
async fn run_orchestrator_with_tools(...) -> Result<String> {

// After:
async fn run_orchestrator_with_tools(...) -> Result<(String, Arc<OrchestratorContext>)> {
```

At the end of the function, change:

```rust
// Before:
Ok(result)

// After:
Ok((result, context))
```

**Step 6: Update `run_orchestrator` to destructure and add cleanup**

In `run_orchestrator`, update the `tokio::select!` match arm for the result path. The variable `result` from `run_orchestrator_with_tools` now returns `(String, Arc<OrchestratorContext>)`.

After both the `Ok(output)` non-completed path and the `Err(e)` path, add cleanup. The simplest approach: extract context from the result and run cleanup in both failure branches.

Change the result match in the first `tokio::select!` branch:

```rust
result = run_orchestrator_with_tools(...) => {
    match result {
        Ok((output, context)) => {
            let completed = engagement_completed.load(Ordering::SeqCst);

            if completed {
                // ... existing completed path (unchanged) ...
            } else {
                // ... existing non-completed status sends ...

                // Cleanup: abort still-running agents
                let aborted = {
                    let mut registry = context.registry.lock().await;
                    registry.abort_all()
                };
                for (name, agent_type) in &aborted {
                    let _ = tx.try_send(AgentEvent::Status {
                        agent: name.clone(),
                        agent_type: agent_type.clone(),
                        status: AgentStatus::Failed,
                        current_tool: None,
                    });
                }

                // ... existing Finished event ...
            }
        }
        Err(e) => {
            // ... existing error status sends ...

            // Cleanup: abort still-running agents (need context)
            // Note: on Err, we don't have context from run_orchestrator_with_tools
            // The error case means the function returned Err before creating context
            // or after creating it. We should restructure to always return context.

            // ... existing Finished event ...
        }
    }
}
```

**Important**: The `Err` path doesn't have access to the context. To handle this, restructure `run_orchestrator_with_tools` to return `(Result<String>, Arc<OrchestratorContext>)` instead — always return the context regardless of success/failure. This way both paths can clean up.

Change `run_orchestrator_with_tools` signature and body:

```rust
async fn run_orchestrator_with_tools(...) -> (Result<String>, Option<Arc<OrchestratorContext>>) {
```

Create the context early, store it, and return it in all paths. The context creation happens before the LLM call (lines 380-416), so errors from LLM call (line 495-498) can still return the context. For errors before context creation (line 387-388, DB open), return `None`.

The cleanest approach:

```rust
async fn run_orchestrator_with_tools(...) -> Result<(String, Arc<OrchestratorContext>)> {
    // ... existing context creation (lines 380-416) ...
    // ... existing prompt building ...

    let result = provider
        .complete_with_orchestrator(orchestrator.system_prompt(), &user_prompt, Arc::clone(&context))
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    Ok((result, context))
}
```

Then in `run_orchestrator`, both `Ok` and `Err` need cleanup. For `Err`, we don't have the context — but the only error sources before context creation are DB failures. The `?` propagation means LLM errors are `Err` but context already exists. So we restructure slightly:

Split into: create context first, then run LLM. Return context always:

```rust
async fn run_orchestrator_with_tools(
    ...
) -> (anyhow::Result<String>, Option<Arc<OrchestratorContext>>) {
    // Create context (may fail early)
    let events: Arc<dyn feroxmute_core::tools::EventSender> =
        Arc::new(TuiEventSender::new(tx.clone()));

    let memory_conn = match session.open_connection() {
        Ok(c) => c,
        Err(e) => return (Err(anyhow::anyhow!("Failed to open session DB: {}", e)), None),
    };

    // ... build context, prompts ...
    let context = Arc::new(OrchestratorContext { ... });

    // Run LLM
    let result = provider
        .complete_with_orchestrator(...)
        .await
        .map_err(|e| anyhow::anyhow!("{}", e));

    (result, Some(context))
}
```

In `run_orchestrator`, destructure:

```rust
(result, maybe_context) = run_orchestrator_with_tools(...) => {
    // Cleanup helper
    let cleanup = |ctx: &Option<Arc<OrchestratorContext>>| async {
        if let Some(context) = ctx {
            let aborted = {
                let mut registry = context.registry.lock().await;
                registry.abort_all()
            };
            for (name, agent_type) in &aborted {
                let _ = tx.try_send(AgentEvent::Status {
                    agent: name.clone(),
                    agent_type: agent_type.clone(),
                    status: AgentStatus::Failed,
                    current_tool: None,
                });
            }
        }
    };

    match result {
        Ok(output) => {
            let completed = engagement_completed.load(Ordering::SeqCst);
            if completed {
                // ... existing completed path ...
            } else {
                // ... existing failure status sends ...
                cleanup(&maybe_context).await;
                // ... existing Finished event ...
            }
        }
        Err(e) => {
            // ... existing error status sends ...
            cleanup(&maybe_context).await;
            // ... existing Finished event ...
        }
    }
}
```

**Step 7: Build and test**

Run: `cargo build && cargo test`
Expected: All pass

**Step 8: Run clippy**

Run: `cargo clippy -- -D warnings`
Expected: No warnings

**Step 9: Commit**

```bash
git add feroxmute-core/src/agents/registry.rs feroxmute-cli/src/runner.rs
git commit -m "fix: abort spawned agents on orchestrator premature exit

Add AgentRegistry::abort_all() to abort running agent JoinHandles and
mark them Failed. Called when orchestrator exits without completing
engagement, preventing orphaned agent tasks and Docker exec sessions."
```

---

### Task 5: Final Verification

**Step 1: Run full test suite**

Run: `cargo test`
Expected: All tests pass (240+ tests)

**Step 2: Run strict clippy**

Run: `cargo clippy -- -D warnings`
Expected: No warnings

**Step 3: Format check**

Run: `cargo fmt --check`
Expected: No formatting issues
