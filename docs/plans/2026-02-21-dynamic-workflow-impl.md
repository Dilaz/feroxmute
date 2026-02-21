# Dynamic Event-Driven Workflow Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace the rigid spawn-wait-spawn orchestrator workflow with an event-driven model where agents emit findings/milestones, the orchestrator reviews events in batches, and can cancel or reprioritize running agents.

**Architecture:** Add an event channel (`AgentEventBus`) from subagents to the orchestrator. The orchestrator gains `ReviewEventsTool`, `CancelAgentTool`, and `UpdateAgentTool`. Subagents gain `ReportMilestoneTool`. Workflow hints become informational rather than prescriptive. Tool call limits increase from 50 to 500.

**Tech Stack:** Rust, tokio (mpsc channels, CancellationToken), rig-core (tool trait), ratatui (TUI)

---

### Task 1: Add `Cancelled` to AgentStatus

**Files:**
- Modify: `feroxmute-core/src/agents/traits.rs:14-34`
- Test: `feroxmute-core/src/agents/registry.rs` (existing tests)

**Step 1: Write the failing test**

Add to the test module in `feroxmute-core/src/agents/registry.rs`:

```rust
#[tokio::test]
async fn test_cancelled_is_terminal_state() {
    let (mut registry, _waiter) = AgentRegistry::new();
    let handle = tokio::spawn(async {});
    registry.register(
        "cancel-test".to_string(),
        "recon".to_string(),
        "test".to_string(),
        handle,
    );
    assert_eq!(registry.running_count(), 1);

    registry.update_status("cancel-test", AgentStatus::Cancelled);
    assert_eq!(registry.running_count(), 0);
    assert_eq!(registry.is_agent_running("cancel-test"), Some(false));
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p feroxmute-core test_cancelled_is_terminal_state`
Expected: FAIL — `AgentStatus::Cancelled` doesn't exist yet.

**Step 3: Add `Cancelled` variant**

In `feroxmute-core/src/agents/traits.rs`, add after the `Retrying` variant (line 29):

```rust
    /// Agent was cancelled by orchestrator
    Cancelled,
```

**Step 4: Update `running_count` and `is_agent_running` filters**

In `feroxmute-core/src/agents/registry.rs`, update the filter on line 113:

```rust
.filter(|a| !matches!(a.status, AgentStatus::Completed | AgentStatus::Failed | AgentStatus::Cancelled))
```

And on line 128:

```rust
.map(|a| !matches!(a.status, AgentStatus::Completed | AgentStatus::Failed | AgentStatus::Cancelled))
```

Also update `abort_all` on line 146:

```rust
if !matches!(agent.status, AgentStatus::Completed | AgentStatus::Failed | AgentStatus::Cancelled) {
```

**Step 5: Run tests**

Run: `cargo test -p feroxmute-core test_cancelled_is_terminal_state && cargo test -p feroxmute-core -p feroxmute-cli`
Expected: ALL PASS

**Step 6: Commit**

```bash
git add feroxmute-core/src/agents/traits.rs feroxmute-core/src/agents/registry.rs
git commit -m "feat: add Cancelled variant to AgentStatus"
```

---

### Task 2: Add AgentEventBus for inter-agent events

**Files:**
- Create: `feroxmute-core/src/agents/event_bus.rs`
- Modify: `feroxmute-core/src/agents/mod.rs`
- Test: inline in `event_bus.rs`

**Step 1: Write the failing test**

Create `feroxmute-core/src/agents/event_bus.rs` with:

```rust
//! Event bus for agent-to-orchestrator communication

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

/// Events emitted by agents for the orchestrator to review
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentEvent {
    pub agent_name: String,
    pub agent_type: String,
    pub timestamp: DateTime<Utc>,
    pub event: EventKind,
}

/// The kind of event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventKind {
    /// Agent recorded a finding via RecordFindingTool
    FindingRecorded {
        severity: String,
        title: String,
    },
    /// Agent reached a milestone via ReportMilestoneTool
    MilestoneReached {
        milestone: String,
        details: String,
    },
    /// Agent completed execution
    AgentCompleted {
        success: bool,
        summary: String,
        key_findings: Vec<String>,
        next_steps: Vec<String>,
    },
    /// Agent failed
    AgentFailed {
        error: String,
    },
    /// Agent was cancelled
    AgentCancelled {
        partial_summary: Option<String>,
    },
}

/// Sender half — cloned and given to each agent
pub type AgentEventSender = mpsc::Sender<AgentEvent>;

/// Bus for collecting and draining agent events
pub struct AgentEventBus {
    rx: mpsc::Receiver<AgentEvent>,
    tx: mpsc::Sender<AgentEvent>,
    buffer: Vec<AgentEvent>,
}

impl AgentEventBus {
    /// Create a new event bus with the given channel capacity
    pub fn new(capacity: usize) -> Self {
        let (tx, rx) = mpsc::channel(capacity);
        Self {
            rx,
            tx,
            buffer: Vec::new(),
        }
    }

    /// Get a sender for agents to emit events
    pub fn sender(&self) -> AgentEventSender {
        self.tx.clone()
    }

    /// Drain all pending events from the channel into the buffer, then return them.
    /// Non-blocking — returns immediately with whatever is available.
    pub fn drain(&mut self) -> Vec<AgentEvent> {
        while let Ok(event) = self.rx.try_recv() {
            self.buffer.push(event);
        }
        std::mem::take(&mut self.buffer)
    }

    /// Wait until at least one event is available, then drain all pending events.
    /// Blocks until an event arrives or the timeout expires.
    /// Returns empty vec on timeout.
    pub async fn drain_or_wait(&mut self, timeout: std::time::Duration) -> Vec<AgentEvent> {
        if !self.buffer.is_empty() {
            return std::mem::take(&mut self.buffer);
        }

        // Wait for at least one event
        match tokio::time::timeout(timeout, self.rx.recv()).await {
            Ok(Some(event)) => {
                self.buffer.push(event);
                // Drain any additional events that arrived
                while let Ok(event) = self.rx.try_recv() {
                    self.buffer.push(event);
                }
                std::mem::take(&mut self.buffer)
            }
            _ => Vec::new(), // Timeout or channel closed
        }
    }

    /// Check if there are buffered events without draining
    pub fn has_pending(&self) -> bool {
        !self.buffer.is_empty()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_event_bus_send_and_drain() {
        let mut bus = AgentEventBus::new(32);
        let sender = bus.sender();

        sender
            .send(AgentEvent {
                agent_name: "web-recon".to_string(),
                agent_type: "recon".to_string(),
                timestamp: Utc::now(),
                event: EventKind::MilestoneReached {
                    milestone: "Port scan complete".to_string(),
                    details: "Found 3 open ports".to_string(),
                },
            })
            .await
            .unwrap();

        let events = bus.drain();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].agent_name, "web-recon");
    }

    #[tokio::test]
    async fn test_event_bus_drain_empty() {
        let mut bus = AgentEventBus::new(32);
        let events = bus.drain();
        assert!(events.is_empty());
    }

    #[tokio::test]
    async fn test_event_bus_drain_or_wait_timeout() {
        let mut bus = AgentEventBus::new(32);
        let events = bus
            .drain_or_wait(std::time::Duration::from_millis(50))
            .await;
        assert!(events.is_empty());
    }

    #[tokio::test]
    async fn test_event_bus_drain_or_wait_receives() {
        let mut bus = AgentEventBus::new(32);
        let sender = bus.sender();

        // Send from another task
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            sender
                .send(AgentEvent {
                    agent_name: "scan-1".to_string(),
                    agent_type: "scanner".to_string(),
                    timestamp: Utc::now(),
                    event: EventKind::FindingRecorded {
                        severity: "high".to_string(),
                        title: "SQL injection in /login".to_string(),
                    },
                })
                .await
                .unwrap();
        });

        let events = bus
            .drain_or_wait(std::time::Duration::from_secs(1))
            .await;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].agent_name, "scan-1");
    }

    #[tokio::test]
    async fn test_event_bus_multiple_senders() {
        let mut bus = AgentEventBus::new(32);
        let s1 = bus.sender();
        let s2 = bus.sender();

        s1.send(AgentEvent {
            agent_name: "recon-1".to_string(),
            agent_type: "recon".to_string(),
            timestamp: Utc::now(),
            event: EventKind::MilestoneReached {
                milestone: "done".to_string(),
                details: "".to_string(),
            },
        })
        .await
        .unwrap();

        s2.send(AgentEvent {
            agent_name: "scan-1".to_string(),
            agent_type: "scanner".to_string(),
            timestamp: Utc::now(),
            event: EventKind::FindingRecorded {
                severity: "medium".to_string(),
                title: "XSS".to_string(),
            },
        })
        .await
        .unwrap();

        let events = bus.drain();
        assert_eq!(events.len(), 2);
    }
}
```

**Step 2: Register module**

In `feroxmute-core/src/agents/mod.rs`, add:

```rust
pub mod event_bus;
pub use event_bus::{AgentEvent as OrchestratorEvent, AgentEventBus, AgentEventSender, EventKind};
```

(Note: use `OrchestratorEvent` alias to avoid clash with TUI's `AgentEvent` in `feroxmute-cli`.)

**Step 3: Run tests**

Run: `cargo test -p feroxmute-core event_bus`
Expected: ALL PASS

**Step 4: Commit**

```bash
git add feroxmute-core/src/agents/event_bus.rs feroxmute-core/src/agents/mod.rs
git commit -m "feat: add AgentEventBus for agent-to-orchestrator events"
```

---

### Task 3: Wire event bus into OrchestratorContext

**Files:**
- Modify: `feroxmute-core/src/tools/orchestrator.rs:200-229` (OrchestratorContext)
- Modify: `feroxmute-cli/src/runner.rs` (where OrchestratorContext is constructed)

**Step 1: Add event bus to OrchestratorContext**

In `feroxmute-core/src/tools/orchestrator.rs`, add to the `OrchestratorContext` struct (after line 203):

```rust
pub event_bus: Arc<tokio::sync::Mutex<crate::agents::AgentEventBus>>,
pub event_bus_sender: crate::agents::AgentEventSender,
```

**Step 2: Create event bus in runner.rs**

Find where `OrchestratorContext` is constructed in `feroxmute-cli/src/runner.rs` and add:

```rust
let event_bus = crate::agents::AgentEventBus::new(256);
let event_bus_sender = event_bus.sender();
```

Pass both into the `OrchestratorContext` struct initialization.

**Step 3: Build and fix any compilation errors**

Run: `cargo build`
Expected: Compilation succeeds (may need to update all OrchestratorContext construction sites).

**Step 4: Run tests**

Run: `cargo test -p feroxmute-core -p feroxmute-cli`
Expected: ALL PASS

**Step 5: Commit**

```bash
git add feroxmute-core/src/tools/orchestrator.rs feroxmute-cli/src/runner.rs
git commit -m "feat: wire AgentEventBus into OrchestratorContext"
```

---

### Task 4: Add ReportMilestoneTool for subagents

**Files:**
- Modify: `feroxmute-core/src/tools/orchestrator.rs` (add new tool)
- Modify: `feroxmute-core/src/tools/mod.rs` (re-export)
- Modify: `feroxmute-core/src/providers/macros.rs:207-226` (register tool for shell agents)

**Step 1: Write the failing test**

Add to the test module in `feroxmute-core/src/tools/orchestrator.rs`:

```rust
#[test]
fn test_report_milestone_args_deserialize() {
    let json = r#"{"milestone": "Port scan complete", "details": "Found 3 open ports: 80, 443, 8080"}"#;
    let args: ReportMilestoneArgs = serde_json::from_str(json).unwrap();
    assert_eq!(args.milestone, "Port scan complete");
    assert_eq!(args.details.unwrap(), "Found 3 open ports: 80, 443, 8080");
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p feroxmute-core test_report_milestone_args_deserialize`
Expected: FAIL — `ReportMilestoneArgs` doesn't exist.

**Step 3: Implement ReportMilestoneTool**

Add to `feroxmute-core/src/tools/orchestrator.rs`, before the `CompleteEngagementTool` section:

```rust
// ============================================================================
// ReportMilestoneTool (for subagents)
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct ReportMilestoneArgs {
    pub milestone: String,
    #[serde(default)]
    pub details: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ReportMilestoneOutput {
    pub recorded: bool,
    pub message: String,
}

pub struct ReportMilestoneTool {
    agent_name: String,
    agent_type: String,
    event_bus_sender: crate::agents::AgentEventSender,
    events: Arc<dyn EventSender>,
}

impl ReportMilestoneTool {
    pub fn new(
        agent_name: String,
        agent_type: String,
        event_bus_sender: crate::agents::AgentEventSender,
        events: Arc<dyn EventSender>,
    ) -> Self {
        Self { agent_name, agent_type, event_bus_sender, events }
    }
}

impl Tool for ReportMilestoneTool {
    const NAME: &'static str = "report_milestone";

    type Error = OrchestratorToolError;
    type Args = ReportMilestoneArgs;
    type Output = ReportMilestoneOutput;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: "report_milestone".to_string(),
            description: "Report a significant milestone to the orchestrator. Use this when you reach important checkpoints (e.g., 'port scan complete', 'admin credentials found', 'discovered new subdomain').".to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "milestone": {
                        "type": "string",
                        "description": "Brief description of the milestone reached"
                    },
                    "details": {
                        "type": "string",
                        "description": "Additional details about what was found or accomplished"
                    }
                },
                "required": ["milestone"]
            }),
        }
    }

    async fn call(&self, args: Self::Args) -> Result<Self::Output, Self::Error> {
        let details = args.details.unwrap_or_default();

        // Send to event bus for orchestrator
        let _ = self.event_bus_sender.send(crate::agents::OrchestratorEvent {
            agent_name: self.agent_name.clone(),
            agent_type: self.agent_type.clone(),
            timestamp: Utc::now(),
            event: crate::agents::EventKind::MilestoneReached {
                milestone: args.milestone.clone(),
                details: details.clone(),
            },
        }).await;

        // Also send to TUI feed
        self.events.send_feed(
            &self.agent_name,
            &format!("[MILESTONE] {}: {}", args.milestone, details),
            false,
        );

        Ok(ReportMilestoneOutput {
            recorded: true,
            message: format!("Milestone reported: {}", args.milestone),
        })
    }
}
```

**Step 4: Export from mod.rs**

In `feroxmute-core/src/tools/mod.rs`, add `ReportMilestoneTool` to the orchestrator re-exports.

**Step 5: Register tool for shell agents**

In `feroxmute-core/src/providers/macros.rs`, in the `complete_with_shell` method, after the MemoryListTool registration (line 225), add:

```rust
.tool($crate::tools::ReportMilestoneTool::new(
    agent_name.to_string(),
    agent_type.to_string(),
    event_bus_sender.clone(),
    std::sync::Arc::clone(&events),
))
```

This requires passing `event_bus_sender` and `agent_type` into the `complete_with_shell` method. Update the method signature to accept these new parameters and update all call sites in `SpawnAgentTool::call`.

Similarly add to `complete_with_llm_pentest` method.

**Step 6: Run tests**

Run: `cargo test -p feroxmute-core -p feroxmute-cli`
Expected: ALL PASS

**Step 7: Commit**

```bash
git add feroxmute-core/src/tools/orchestrator.rs feroxmute-core/src/tools/mod.rs feroxmute-core/src/providers/macros.rs
git commit -m "feat: add ReportMilestoneTool for subagent-to-orchestrator events"
```

---

### Task 5: Emit FindingRecorded events from RecordFindingTool

**Files:**
- Modify: `feroxmute-core/src/tools/orchestrator.rs:1024-1100` (RecordFindingTool)

**Step 1: Add event_bus_sender field to RecordFindingTool**

Currently `RecordFindingTool` only has `context: Arc<OrchestratorContext>`. The event bus sender is already in the context (from Task 3). Emit an event after recording the finding.

**Step 2: Implement**

In the `call` method of `RecordFindingTool` (around line 1074, after `findings.push`), add:

```rust
// Emit event to orchestrator event bus
if let Ok(bus) = self.context.event_bus.try_lock() {
    let _ = self.context.event_bus_sender.send(crate::agents::OrchestratorEvent {
        agent_name: "orchestrator".to_string(), // RecordFindingTool is called by orchestrator context
        agent_type: "orchestrator".to_string(),
        timestamp: Utc::now(),
        event: crate::agents::EventKind::FindingRecorded {
            severity: args.severity.clone().unwrap_or_else(|| "info".to_string()),
            title: args.finding.clone(),
        },
    }).await;
}
```

Note: Since `RecordFindingTool` is used by the orchestrator, we need the agent name. Since we're inside orchestrator context, use a sensible default. Alternatively, the `event_bus_sender` on the context is sufficient — no lock needed, just `send` on the sender.

Simplified:

```rust
let _ = self.context.event_bus_sender.send(crate::agents::OrchestratorEvent {
    agent_name: "system".to_string(),
    agent_type: "finding".to_string(),
    timestamp: Utc::now(),
    event: crate::agents::EventKind::FindingRecorded {
        severity: args.severity.clone().unwrap_or_else(|| "info".to_string()),
        title: args.finding.clone(),
    },
}).await;
```

**Step 3: Build and test**

Run: `cargo build && cargo test -p feroxmute-core`
Expected: ALL PASS

**Step 4: Commit**

```bash
git add feroxmute-core/src/tools/orchestrator.rs
git commit -m "feat: emit FindingRecorded events from RecordFindingTool"
```

---

### Task 6: Add ReviewEventsTool for orchestrator

**Files:**
- Modify: `feroxmute-core/src/tools/orchestrator.rs`
- Modify: `feroxmute-core/src/tools/mod.rs`
- Modify: `feroxmute-core/src/providers/macros.rs:315-330` (register for orchestrator)

**Step 1: Write the failing test**

```rust
#[test]
fn test_review_events_args_deserialize() {
    let json = r#"{"timeout_seconds": 30}"#;
    let args: ReviewEventsArgs = serde_json::from_str(json).unwrap();
    assert_eq!(args.timeout_seconds.unwrap(), 30);
}

#[test]
fn test_review_events_args_defaults() {
    let json = r#"{}"#;
    let args: ReviewEventsArgs = serde_json::from_str(json).unwrap();
    assert!(args.timeout_seconds.is_none());
}
```

**Step 2: Implement ReviewEventsTool**

Add to `feroxmute-core/src/tools/orchestrator.rs`:

```rust
// ============================================================================
// ReviewEventsTool
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct ReviewEventsArgs {
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct ReviewEventsOutput {
    pub events: Vec<ReviewEventEntry>,
    pub event_count: usize,
    pub agents_running: usize,
}

#[derive(Debug, Serialize)]
pub struct ReviewEventEntry {
    pub agent_name: String,
    pub agent_type: String,
    pub timestamp: String,
    pub event_type: String,
    pub summary: String,
}

pub struct ReviewEventsTool {
    context: Arc<OrchestratorContext>,
}

impl ReviewEventsTool {
    pub fn new(context: Arc<OrchestratorContext>) -> Self {
        Self { context }
    }
}

impl Tool for ReviewEventsTool {
    const NAME: &'static str = "review_events";

    type Error = OrchestratorToolError;
    type Args = ReviewEventsArgs;
    type Output = ReviewEventsOutput;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: "review_events".to_string(),
            description: "Review events from running agents. Returns findings, milestones, completions, and failures. Blocks until at least one event is available (default 60s timeout). Use this to stay informed about agent progress and decide next actions.".to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "timeout_seconds": {
                        "type": "integer",
                        "description": "How long to wait for events (default: 60 seconds)"
                    }
                }
            }),
        }
    }

    async fn call(&self, args: Self::Args) -> Result<Self::Output, Self::Error> {
        self.context.events.send_tool_call();
        self.context.events.send_feed("orchestrator", "Reviewing agent events...", false);

        let timeout_secs = args.timeout_seconds.unwrap_or(60);
        let timeout = std::time::Duration::from_secs(timeout_secs);

        let events = {
            let mut bus = self.context.event_bus.lock().await;
            bus.drain_or_wait(timeout).await
        };

        let agents_running = {
            let registry = self.context.registry.lock().await;
            registry.running_count()
        };

        let entries: Vec<ReviewEventEntry> = events.iter().map(|e| {
            let (event_type, summary) = match &e.event {
                crate::agents::EventKind::FindingRecorded { severity, title } => {
                    ("finding".to_string(), format!("[{}] {}", severity, title))
                }
                crate::agents::EventKind::MilestoneReached { milestone, details } => {
                    ("milestone".to_string(), format!("{}: {}", milestone, details))
                }
                crate::agents::EventKind::AgentCompleted { success, summary, key_findings, next_steps } => {
                    ("completed".to_string(), format!(
                        "success={}, summary={}, findings=[{}], next_steps=[{}]",
                        success, summary,
                        key_findings.join(", "),
                        next_steps.join(", ")
                    ))
                }
                crate::agents::EventKind::AgentFailed { error } => {
                    ("failed".to_string(), error.clone())
                }
                crate::agents::EventKind::AgentCancelled { partial_summary } => {
                    ("cancelled".to_string(), partial_summary.clone().unwrap_or_else(|| "No summary".to_string()))
                }
            };
            ReviewEventEntry {
                agent_name: e.agent_name.clone(),
                agent_type: e.agent_type.clone(),
                timestamp: e.timestamp.format("%H:%M:%S").to_string(),
                event_type,
                summary,
            }
        }).collect();

        let event_count = entries.len();

        self.context.events.send_feed(
            "orchestrator",
            &format!("Reviewed {} events. {} agents running.", event_count, agents_running),
            false,
        );

        Ok(ReviewEventsOutput {
            events: entries,
            event_count,
            agents_running,
        })
    }
}
```

**Step 3: Export and register**

In `feroxmute-core/src/tools/mod.rs`, add `ReviewEventsTool` to orchestrator re-exports.

In `feroxmute-core/src/providers/macros.rs`, in `complete_with_orchestrator` (around line 325), add:

```rust
.tool($crate::tools::ReviewEventsTool::new(std::sync::Arc::clone(&context)))
```

**Step 4: Run tests**

Run: `cargo test -p feroxmute-core -p feroxmute-cli`
Expected: ALL PASS

**Step 5: Commit**

```bash
git add feroxmute-core/src/tools/orchestrator.rs feroxmute-core/src/tools/mod.rs feroxmute-core/src/providers/macros.rs
git commit -m "feat: add ReviewEventsTool for orchestrator event processing"
```

---

### Task 7: Add CancelAgentTool

**Files:**
- Modify: `feroxmute-core/src/agents/registry.rs` (add CancellationToken tracking)
- Modify: `feroxmute-core/src/tools/orchestrator.rs` (new tool + update SpawnAgentTool)
- Modify: `feroxmute-core/src/tools/mod.rs`
- Modify: `feroxmute-core/src/providers/macros.rs`

**Step 1: Write the failing test**

Add to `feroxmute-core/src/agents/registry.rs` tests:

```rust
#[tokio::test]
async fn test_cancel_agent() {
    let (mut registry, _waiter) = AgentRegistry::new();
    let token = tokio_util::sync::CancellationToken::new();
    let handle = tokio::spawn(async {});
    registry.register_with_cancel(
        "cancel-me".to_string(),
        "recon".to_string(),
        "test".to_string(),
        handle,
        token.clone(),
    );

    assert!(registry.cancel_agent("cancel-me"));
    assert!(token.is_cancelled());
    assert_eq!(registry.is_agent_running("cancel-me"), Some(false));
}
```

**Step 2: Add CancellationToken to SpawnedAgent and registry**

In `feroxmute-core/src/agents/registry.rs`:

Add `use tokio_util::sync::CancellationToken;` to imports.

Add field to `SpawnedAgent`:
```rust
pub cancel_token: Option<CancellationToken>,
```

Add new `register_with_cancel` method:
```rust
pub fn register_with_cancel(
    &mut self,
    name: String,
    agent_type: String,
    instructions: String,
    handle: JoinHandle<()>,
    cancel_token: CancellationToken,
) {
    let agent = SpawnedAgent {
        name: name.clone(),
        agent_type,
        instructions,
        status: AgentStatus::Streaming,
        spawned_at: Instant::now(),
        handle: Some(handle),
        cancel_token: Some(cancel_token),
    };
    self.agents.insert(name, agent);
}
```

Add `cancel_agent` method:
```rust
pub fn cancel_agent(&mut self, name: &str) -> bool {
    if let Some(agent) = self.agents.get_mut(name) {
        if matches!(agent.status, AgentStatus::Completed | AgentStatus::Failed | AgentStatus::Cancelled) {
            return false;
        }
        if let Some(token) = &agent.cancel_token {
            token.cancel();
        }
        agent.status = AgentStatus::Cancelled;
        true
    } else {
        false
    }
}
```

Update existing `register` to set `cancel_token: None`.

**Step 3: Implement CancelAgentTool**

Add to `feroxmute-core/src/tools/orchestrator.rs`:

```rust
// ============================================================================
// CancelAgentTool
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct CancelAgentArgs {
    pub name: String,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CancelAgentOutput {
    pub cancelled: bool,
    pub message: String,
}

pub struct CancelAgentTool {
    context: Arc<OrchestratorContext>,
}

impl CancelAgentTool {
    pub fn new(context: Arc<OrchestratorContext>) -> Self {
        Self { context }
    }
}

impl Tool for CancelAgentTool {
    const NAME: &'static str = "cancel_agent";

    type Error = OrchestratorToolError;
    type Args = CancelAgentArgs;
    type Output = CancelAgentOutput;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: "cancel_agent".to_string(),
            description: "Cancel a running agent. Use when the agent's work is no longer needed or has been superseded.".to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Name of the agent to cancel"
                    },
                    "reason": {
                        "type": "string",
                        "description": "Why the agent is being cancelled"
                    }
                },
                "required": ["name"]
            }),
        }
    }

    async fn call(&self, args: Self::Args) -> Result<Self::Output, Self::Error> {
        self.context.events.send_tool_call();

        let mut registry = self.context.registry.lock().await;
        let cancelled = registry.cancel_agent(&args.name);

        let reason = args.reason.unwrap_or_else(|| "No reason given".to_string());

        if cancelled {
            self.context.events.send_feed(
                "orchestrator",
                &format!("Cancelled agent '{}': {}", args.name, reason),
                false,
            );
            self.context.events.send_status(
                &args.name,
                "",
                AgentStatus::Cancelled,
                None,
            );

            Ok(CancelAgentOutput {
                cancelled: true,
                message: format!("Agent '{}' cancelled: {}", args.name, reason),
            })
        } else {
            Ok(CancelAgentOutput {
                cancelled: false,
                message: format!("Agent '{}' not found or already finished", args.name),
            })
        }
    }
}
```

**Step 4: Update SpawnAgentTool to create CancellationTokens**

In `SpawnAgentTool::call`, create a `CancellationToken` for each spawned agent and pass it into the tokio::spawn closure. Use `register_with_cancel` instead of `register`. The token should be checked in the spawned task's main loop — add a `tokio::select!` around the agent's `complete_with_*` call that also listens on `token.cancelled()`.

**Step 5: Export and register**

Export `CancelAgentTool` from `mod.rs`. Register in `complete_with_orchestrator` in `macros.rs`.

**Step 6: Run tests**

Run: `cargo test -p feroxmute-core -p feroxmute-cli`
Expected: ALL PASS

**Step 7: Commit**

```bash
git add feroxmute-core/src/agents/registry.rs feroxmute-core/src/tools/orchestrator.rs feroxmute-core/src/tools/mod.rs feroxmute-core/src/providers/macros.rs
git commit -m "feat: add CancelAgentTool with per-agent CancellationToken"
```

---

### Task 8: Add UpdateAgentTool

**Files:**
- Modify: `feroxmute-core/src/agents/registry.rs` (add instruction channel)
- Modify: `feroxmute-core/src/tools/orchestrator.rs` (new tool)
- Modify: `feroxmute-core/src/tools/mod.rs`
- Modify: `feroxmute-core/src/providers/macros.rs`

**Step 1: Write the failing test**

Add to `feroxmute-core/src/agents/registry.rs` tests:

```rust
#[tokio::test]
async fn test_send_instructions_to_agent() {
    let (mut registry, _waiter) = AgentRegistry::new();
    let handle = tokio::spawn(async {});
    let token = tokio_util::sync::CancellationToken::new();
    registry.register_with_cancel(
        "update-me".to_string(),
        "scanner".to_string(),
        "original instructions".to_string(),
        handle,
        token,
    );

    let sent = registry.send_instructions("update-me", "new instructions");
    assert!(sent);
}
```

**Step 2: Add instruction channel to SpawnedAgent**

Add `pub instruction_tx: Option<mpsc::Sender<String>>` to `SpawnedAgent`.

Add `register_with_cancel` update to create an `mpsc::channel(8)` and store the sender.

Add method:
```rust
pub fn send_instructions(&self, name: &str, instructions: &str) -> bool {
    if let Some(agent) = self.agents.get(name) {
        if let Some(tx) = &agent.instruction_tx {
            tx.try_send(instructions.to_string()).is_ok()
        } else {
            false
        }
    } else {
        false
    }
}

pub fn take_instruction_rx(&mut self, name: &str) -> Option<mpsc::Receiver<String>> {
    // Called once when spawning the agent task
    self.agents.get_mut(name).and_then(|a| a.instruction_rx.take())
}
```

Actually, the simpler approach: create the channel in `register_with_cancel`, return the receiver for the spawn task to use.

Revised approach — update `register_with_cancel` to return `mpsc::Receiver<String>`:
```rust
pub fn register_with_cancel(
    &mut self,
    name: String,
    agent_type: String,
    instructions: String,
    handle: JoinHandle<()>,
    cancel_token: CancellationToken,
) -> mpsc::Receiver<String> {
    let (instruction_tx, instruction_rx) = mpsc::channel(8);
    let agent = SpawnedAgent {
        name: name.clone(),
        agent_type,
        instructions,
        status: AgentStatus::Streaming,
        spawned_at: Instant::now(),
        handle: Some(handle),
        cancel_token: Some(cancel_token),
        instruction_tx: Some(instruction_tx),
    };
    self.agents.insert(name, agent);
    instruction_rx
}
```

Wait — the problem is that the handle is created from `tokio::spawn` which needs the receiver *before* registration. Alternative: create the channel in `SpawnAgentTool::call`, pass the receiver to the spawned task, pass the sender to `register_with_cancel`.

Better approach:
```rust
pub fn register_with_cancel_and_instructions(
    &mut self,
    name: String,
    agent_type: String,
    instructions: String,
    handle: JoinHandle<()>,
    cancel_token: CancellationToken,
    instruction_tx: mpsc::Sender<String>,
) { ... }
```

And create the channel in `SpawnAgentTool::call` before spawning.

**Step 3: Implement UpdateAgentTool**

```rust
// ============================================================================
// UpdateAgentTool
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct UpdateAgentArgs {
    pub name: String,
    pub instructions: String,
}

#[derive(Debug, Serialize)]
pub struct UpdateAgentOutput {
    pub sent: bool,
    pub message: String,
}

pub struct UpdateAgentTool {
    context: Arc<OrchestratorContext>,
}

impl UpdateAgentTool {
    pub fn new(context: Arc<OrchestratorContext>) -> Self {
        Self { context }
    }
}

impl Tool for UpdateAgentTool {
    const NAME: &'static str = "update_agent";
    type Error = OrchestratorToolError;
    type Args = UpdateAgentArgs;
    type Output = UpdateAgentOutput;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: "update_agent".to_string(),
            description: "Send updated instructions to a running agent. The agent will receive these at its next tool-call boundary.".to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "name": { "type": "string", "description": "Name of the agent to update" },
                    "instructions": { "type": "string", "description": "New instructions for the agent" }
                },
                "required": ["name", "instructions"]
            }),
        }
    }

    async fn call(&self, args: Self::Args) -> Result<Self::Output, Self::Error> {
        self.context.events.send_tool_call();

        let registry = self.context.registry.lock().await;
        let sent = registry.send_instructions(&args.name, &args.instructions);

        if sent {
            self.context.events.send_feed(
                "orchestrator",
                &format!("Updated instructions for '{}': {}", args.name, truncate_output(&args.instructions, 100)),
                false,
            );
            Ok(UpdateAgentOutput { sent: true, message: format!("Instructions sent to '{}'", args.name) })
        } else {
            Ok(UpdateAgentOutput { sent: false, message: format!("Could not send to '{}' (not running or not found)", args.name) })
        }
    }
}
```

**Step 4: Wire instruction receiver into agent task loop**

In `feroxmute-core/src/providers/macros.rs`, in `complete_with_shell`, the agent runs in a loop. At each iteration start, check the instruction receiver:

```rust
// Check for updated instructions from orchestrator
while let Ok(new_instructions) = instruction_rx.try_recv() {
    current_prompt = format!(
        "[UPDATED INSTRUCTIONS FROM ORCHESTRATOR]: {}\n\n{}",
        new_instructions, current_prompt
    );
}
```

**Step 5: Export and register**

Export `UpdateAgentTool` from `mod.rs`. Register in `complete_with_orchestrator`.

**Step 6: Run tests**

Run: `cargo test -p feroxmute-core -p feroxmute-cli`
Expected: ALL PASS

**Step 7: Commit**

```bash
git add feroxmute-core/src/agents/registry.rs feroxmute-core/src/tools/orchestrator.rs feroxmute-core/src/tools/mod.rs feroxmute-core/src/providers/macros.rs
git commit -m "feat: add UpdateAgentTool for mid-execution instruction updates"
```

---

### Task 9: Emit AgentCompleted/AgentFailed events from SpawnAgentTool

**Files:**
- Modify: `feroxmute-core/src/tools/orchestrator.rs:405-568` (spawn closures)

**Step 1: Implement**

In each of the three spawn closures (report, llm_pentest, shell) in `SpawnAgentTool::call`, after sending the `AgentResult` via `result_tx.send()`, also emit an event to the event bus:

```rust
let _ = event_bus_sender.send(crate::agents::OrchestratorEvent {
    agent_name: agent_name.clone(),
    agent_type: agent_type.clone(),
    timestamp: Utc::now(),
    event: if success {
        crate::agents::EventKind::AgentCompleted {
            success: true,
            summary: truncate_output(&output, 200),
            key_findings: vec![],
            next_steps: vec![],
        }
    } else {
        crate::agents::EventKind::AgentFailed {
            error: truncate_output(&output, 200),
        }
    },
}).await;
```

Clone `event_bus_sender` into each spawn closure alongside `result_tx`.

**Step 2: Build and test**

Run: `cargo build && cargo test -p feroxmute-core -p feroxmute-cli`
Expected: ALL PASS

**Step 3: Commit**

```bash
git add feroxmute-core/src/tools/orchestrator.rs
git commit -m "feat: emit completion/failure events to AgentEventBus"
```

---

### Task 10: Update tool call limits

**Files:**
- Modify: `feroxmute-core/src/providers/macros.rs:232,334,410,507`

**Step 1: Change all max_turns values**

| Line | Old | New |
|------|-----|-----|
| 232 | `max_turns(50)` | `max_turns(500)` |
| 334 | `max_turns(50)` | `max_turns(500)` |
| 410 | `max_turns(20)` | `max_turns(50)` |
| 507 | `max_turns(50)` | `max_turns(500)` |

**Step 2: Build and test**

Run: `cargo build && cargo test -p feroxmute-core -p feroxmute-cli`
Expected: ALL PASS

**Step 3: Commit**

```bash
git add feroxmute-core/src/providers/macros.rs
git commit -m "feat: increase tool call limits (50->500 agents, 20->50 report)"
```

---

### Task 11: Rewrite orchestrator prompt for adaptive behavior

**Files:**
- Modify: `feroxmute-core/prompts.toml:5-193`

**Step 1: Rewrite the orchestrator prompt**

Replace the entire `[orchestrator]` prompt section. Key changes:
- Remove rigid phase ordering
- Remove "broken pattern" / "working pattern" enforcement
- Add guidance for adaptive behavior, event review, cancellation, reprioritization
- Keep phases as soft vocabulary
- Add `report_milestone` to the tools the orchestrator knows about
- Add `review_events`, `cancel_agent`, `update_agent` descriptions
- Encourage spawning multiple agents and reacting to findings

Keep:
- Security notice (line 9)
- Tool-driven execution requirement (text without tool call = done)
- One report agent max
- Recon + scanner before report (as soft guidance)

**Step 2: Update subagent prompts**

For each of [recon], [scanner], [exploit], [sast], [llm_pentest], add a section:

```
## Milestone Reporting
Report significant milestones as you work using report_milestone(). Examples:
- "Port scan complete" with details of what was found
- "Admin credentials discovered" with context
- "New subdomain found" with the subdomain
- "Authentication bypass confirmed"

In your completion summary, always suggest specific follow-up actions in next_steps, especially if you discovered new attack surface that needs additional recon or scanning.
```

**Step 3: Build and test**

Run: `cargo build && cargo test -p feroxmute-core -p feroxmute-cli`
Expected: ALL PASS (prompts are loaded at runtime, not compiled)

**Step 4: Commit**

```bash
git add feroxmute-core/prompts.toml
git commit -m "feat: rewrite prompts for adaptive event-driven workflow"
```

---

### Task 12: Update workflow hints to be informational

**Files:**
- Modify: `feroxmute-core/src/tools/orchestrator.rs:899-913` (workflow hint generation in WaitForAnyTool)
- Modify: `feroxmute-core/src/tools/orchestrator.rs:577-583` (SpawnAgentTool response message)

**Step 1: Replace prescriptive hints with informational context**

In `WaitForAnyTool::call`, replace the workflow hint generation (lines 899-913):

```rust
let workflow_hint = format!(
    "Agent '{}' ({}) completed. {} agent(s) still running. Review the results and decide: spawn new agents, cancel running agents, update instructions, review more events, or complete the engagement.",
    result.name, result.agent_type, remaining_running
);
```

In `SpawnAgentTool::call`, update the response message (line 580):

```rust
message: format!(
    "Agent '{}' ({}) is now running. Use review_events() or wait_for_any() to monitor progress.",
    args.name, args.agent_type
),
```

**Step 2: Build and test**

Run: `cargo build && cargo test -p feroxmute-core -p feroxmute-cli`
Expected: ALL PASS

**Step 3: Commit**

```bash
git add feroxmute-core/src/tools/orchestrator.rs
git commit -m "refactor: make workflow hints informational instead of prescriptive"
```

---

### Task 13: Remove phase tracking from control flow

**Files:**
- Modify: `feroxmute-core/src/tools/orchestrator.rs:373-384` (phase updates in SpawnAgentTool)

**Step 1: Keep phase updates for TUI but remove from control flow**

The phase updates in `SpawnAgentTool::call` (lines 373-384) are already purely informational — they send to TUI via `send_phase`. Keep them as-is. The control flow rigidity was in the prompts and workflow hints, which are already addressed in Tasks 11-12.

No code changes needed. Mark as done.

**Step 2: Commit** (skip — no changes)

---

### Task 14: Add Milestone and Cancelled event types to TUI channel

**Files:**
- Modify: `feroxmute-cli/src/tui/channel.rs`
- Modify: `feroxmute-cli/src/tui/runner.rs` (drain_events handling)
- Modify: `feroxmute-cli/src/runner.rs` (TuiEventSender — add send_milestone method)

**Step 1: Add new event variants**

In `feroxmute-cli/src/tui/channel.rs`, add to the `AgentEvent` enum:

```rust
/// Agent reached a milestone
Milestone {
    agent: String,
    milestone: String,
    details: String,
},
```

The `Cancelled` status is already handled by the existing `Status` event with `AgentStatus::Cancelled` (added in Task 1).

**Step 2: Handle in drain_events**

In `feroxmute-cli/src/tui/runner.rs`, in `drain_events`, add handling for the `Milestone` event:

```rust
AgentEvent::Milestone { agent, milestone, details } => {
    let msg = format!("[MILESTONE] {}: {}", milestone, details);
    app.feed.push(FeedEntry::new(&agent, &msg));
    // Index for per-agent feed
    let idx = app.feed.len() - 1;
    app.agent_feed_indices.entry(agent).or_default().push(idx);
}
```

**Step 3: Build and test**

Run: `cargo build && cargo test -p feroxmute-cli`
Expected: ALL PASS

**Step 4: Commit**

```bash
git add feroxmute-cli/src/tui/channel.rs feroxmute-cli/src/tui/runner.rs feroxmute-cli/src/runner.rs
git commit -m "feat: add Milestone event type to TUI channel"
```

---

### Task 15: Add event timeline TUI view

**Files:**
- Create: `feroxmute-cli/src/tui/widgets/timeline.rs`
- Modify: `feroxmute-cli/src/tui/widgets/mod.rs`
- Modify: `feroxmute-cli/src/tui/app.rs` (add `Timeline` to View enum, add timeline state)
- Modify: `feroxmute-cli/src/tui/events.rs` (handle 't' key for timeline view)
- Modify: `feroxmute-cli/src/tui/widgets/dashboard.rs` (add 't' to footer keybindings)

**Step 1: Add Timeline view variant**

In `feroxmute-cli/src/tui/app.rs`, add `Timeline` to the `View` enum:

```rust
pub enum View {
    #[default]
    Dashboard,
    AgentDetail(String),
    Logs,
    Help,
    Memory,
    Timeline,
}
```

Add timeline state to `App`:

```rust
/// Timeline events for the dedicated timeline view
pub timeline_events: Vec<TimelineEvent>,
pub timeline_scroll: usize,
```

Add `TimelineEvent` struct:

```rust
#[derive(Debug, Clone)]
pub struct TimelineEvent {
    pub timestamp: DateTime<Local>,
    pub agent: String,
    pub event_type: String, // "milestone", "finding", "completed", "failed", "cancelled", "spawned"
    pub message: String,
}
```

**Step 2: Create timeline widget**

Create `feroxmute-cli/src/tui/widgets/timeline.rs`:

```rust
//! Event timeline view showing real-time events across all agents

use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState};

use crate::tui::app::App;

pub fn render(frame: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(3),    // Timeline events
            Constraint::Length(1), // Footer
        ])
        .split(area);

    // Timeline entries
    let lines: Vec<Line> = app.timeline_events.iter().rev().map(|e| {
        let time = e.timestamp.format("%H:%M:%S").to_string();
        let type_style = match e.event_type.as_str() {
            "finding" => Style::default().fg(Color::Red),
            "milestone" => Style::default().fg(Color::Yellow),
            "completed" => Style::default().fg(Color::Green),
            "failed" => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            "cancelled" => Style::default().fg(Color::DarkGray),
            "spawned" => Style::default().fg(Color::Cyan),
            _ => Style::default(),
        };

        Line::from(vec![
            Span::styled(format!("{} ", time), Style::default().fg(Color::DarkGray)),
            Span::styled(format!("[{}] ", e.event_type), type_style),
            Span::styled(format!("{}: ", e.agent), Style::default().fg(Color::Cyan)),
            Span::raw(&e.message),
        ])
    }).collect();

    let paragraph = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title(" Event Timeline "))
        .scroll((app.timeline_scroll as u16, 0));

    frame.render_widget(paragraph, chunks[0]);

    // Footer
    let footer = Paragraph::new(Line::from(vec![
        Span::styled(" Tab", Style::default().fg(Color::Yellow)),
        Span::raw(":dashboard "),
        Span::styled("j/k", Style::default().fg(Color::Yellow)),
        Span::raw(":scroll "),
        Span::styled("q", Style::default().fg(Color::Yellow)),
        Span::raw(":quit"),
    ]));
    frame.render_widget(footer, chunks[1]);
}
```

**Step 3: Register widget module**

In `feroxmute-cli/src/tui/widgets/mod.rs`, add:

```rust
pub mod timeline;
```

**Step 4: Handle 't' key**

In `feroxmute-cli/src/tui/events.rs`, add key handling for 't' (match on the existing key dispatch):

```rust
KeyCode::Char('t') if app.view == View::Dashboard => {
    app.view = View::Timeline;
}
```

Add scroll handling when in Timeline view (j/k/up/down).

**Step 5: Add timeline event recording**

In `drain_events` in `feroxmute-cli/src/tui/runner.rs`, when processing relevant events (Feed, Summary, Vulnerability, Milestone, Status changes to Completed/Failed/Cancelled), push to `app.timeline_events`.

**Step 6: Update dashboard footer**

In `feroxmute-cli/src/tui/widgets/dashboard.rs`, add `t:timeline` to the footer keybinding hints.

**Step 7: Wire rendering**

In the main render function (wherever views dispatch), add:

```rust
View::Timeline => widgets::timeline::render(frame, app, area),
```

**Step 8: Build and test**

Run: `cargo build && cargo test -p feroxmute-cli`
Expected: ALL PASS

**Step 9: Commit**

```bash
git add feroxmute-cli/src/tui/widgets/timeline.rs feroxmute-cli/src/tui/widgets/mod.rs feroxmute-cli/src/tui/app.rs feroxmute-cli/src/tui/events.rs feroxmute-cli/src/tui/runner.rs feroxmute-cli/src/tui/widgets/dashboard.rs
git commit -m "feat: add event timeline TUI view"
```

---

### Task 16: Handle Cancelled status in TUI display

**Files:**
- Modify: `feroxmute-cli/src/tui/widgets/dashboard.rs` (agent status display)

**Step 1: Update agent status rendering**

In the dashboard's agent table rendering, add a display case for `AgentStatus::Cancelled`:

```rust
AgentStatus::Cancelled => ("Cancelled", Style::default().fg(Color::DarkGray)),
```

This should be wherever status is mapped to display string + style. Search for the existing `AgentStatus::Failed` case and add `Cancelled` alongside it.

**Step 2: Build and test**

Run: `cargo build && cargo test -p feroxmute-cli`
Expected: ALL PASS

**Step 3: Commit**

```bash
git add feroxmute-cli/src/tui/widgets/dashboard.rs
git commit -m "feat: display Cancelled agent status in TUI"
```

---

### Task 17: Integration test — full event flow

**Files:**
- Create: `feroxmute-core/tests/event_flow.rs`

**Step 1: Write integration test**

```rust
//! Integration test for the event-driven workflow

use feroxmute_core::agents::event_bus::{AgentEventBus, EventKind};
use chrono::Utc;

#[tokio::test]
async fn test_milestone_flows_to_event_bus() {
    let mut bus = AgentEventBus::new(32);
    let sender = bus.sender();

    // Simulate agent emitting a milestone
    sender.send(feroxmute_core::agents::event_bus::AgentEvent {
        agent_name: "web-recon".to_string(),
        agent_type: "recon".to_string(),
        timestamp: Utc::now(),
        event: EventKind::MilestoneReached {
            milestone: "Port scan complete".to_string(),
            details: "80, 443, 8080 open".to_string(),
        },
    }).await.unwrap();

    // Simulate agent recording a finding
    sender.send(feroxmute_core::agents::event_bus::AgentEvent {
        agent_name: "vuln-scan".to_string(),
        agent_type: "scanner".to_string(),
        timestamp: Utc::now(),
        event: EventKind::FindingRecorded {
            severity: "high".to_string(),
            title: "SQL injection in /login".to_string(),
        },
    }).await.unwrap();

    // Simulate agent completion
    sender.send(feroxmute_core::agents::event_bus::AgentEvent {
        agent_name: "web-recon".to_string(),
        agent_type: "recon".to_string(),
        timestamp: Utc::now(),
        event: EventKind::AgentCompleted {
            success: true,
            summary: "Mapped 15 endpoints".to_string(),
            key_findings: vec!["Admin panel at /admin".to_string()],
            next_steps: vec!["Scan admin panel".to_string()],
        },
    }).await.unwrap();

    // Drain and verify
    let events = bus.drain();
    assert_eq!(events.len(), 3);

    matches!(&events[0].event, EventKind::MilestoneReached { milestone, .. } if milestone == "Port scan complete");
    matches!(&events[1].event, EventKind::FindingRecorded { severity, .. } if severity == "high");
    matches!(&events[2].event, EventKind::AgentCompleted { success, .. } if *success);
}
```

**Step 2: Run test**

Run: `cargo test -p feroxmute-core test_milestone_flows_to_event_bus`
Expected: PASS

**Step 3: Commit**

```bash
git add feroxmute-core/tests/event_flow.rs
git commit -m "test: add integration test for event-driven workflow"
```

---

### Task 18: Final verification

**Step 1: Run full test suite**

Run: `cargo test -p feroxmute-core -p feroxmute-cli`
Expected: ALL PASS

**Step 2: Run clippy**

Run: `cargo clippy -- -D warnings`
Expected: No warnings

**Step 3: Run fmt**

Run: `cargo fmt`
Expected: No changes (already formatted)

**Step 4: Build release**

Run: `cargo build --release`
Expected: Compiles successfully

**Step 5: Final commit if any remaining changes**

```bash
cargo fmt && cargo clippy --fix --allow-dirty && cargo build
git add -A && git commit -m "chore: final cleanup for dynamic workflow feature"
```
