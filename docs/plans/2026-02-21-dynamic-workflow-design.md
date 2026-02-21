# Dynamic Event-Driven Workflow Design

**Date:** 2026-02-21
**Status:** Approved

## Problem

The orchestrator workflow is rigidly scripted: spawn recon → wait → spawn scanner → wait → spawn report. Workflow hints enforce linear progression. Only one recon agent typically runs. When agents discover new attack surface (admin panels, new subdomains, credentials), the orchestrator cannot react dynamically.

## Goals

- Orchestrator reacts to findings mid-engagement by spawning new agents
- Agents communicate significant events (findings, milestones) to the orchestrator in real-time
- Orchestrator can cancel or reprioritize running agents
- Phases serve as soft vocabulary, not control flow
- Tool call limit increased from 50 to 500

## Design

### 1. Event System

Agents emit events during execution through a shared channel:

```rust
struct AgentEvent {
    agent_name: String,
    agent_type: String,
    timestamp: DateTime<Utc>,
    event: EventKind,
}

enum EventKind {
    FindingRecorded { severity: String, title: String, description: String },
    MilestoneReached { milestone: String, details: String },
    AgentCompleted { summary: AgentSummary },
    AgentFailed { error: String },
    AgentCancelled { partial_summary: Option<AgentSummary> },
}
```

**Event sources:**
- `RecordFindingTool`: emits `FindingRecorded` as a side-effect alongside the existing SQLite write
- `ReportMilestoneTool` (new): subagents call this to signal milestones ("port scan complete", "admin creds found")
- Agent completion/failure: emits terminal events as today, but through the event channel

**Event transport:** `tokio::mpsc` channel from agents to orchestrator. Events accumulate in a buffer that the orchestrator drains on demand.

### 2. Orchestrator Processing Model

The orchestrator remains an LLM tool-call loop but gains new tools:

**New tools:**
- **`ReviewEventsTool`**: Drains the event buffer and returns all accumulated events as structured text. Blocks until at least one event arrives (with configurable timeout). This is the orchestrator's primary way to stay informed.
- **`CancelAgentTool`**: Cancels a running agent by name via `CancellationToken`.
- **`UpdateAgentTool`**: Sends updated instructions to a running agent. The agent receives new instructions as a prepended system message at its next tool-call boundary.
- **`ReportMilestoneTool`** (for subagents): Lets agents signal milestones.

**Preserved tools:**
- `SpawnAgentTool` (unchanged API)
- `WaitForAnyTool` (kept as simpler blocking alternative to ReviewEvents)
- `ListAgentsTool`, `CompleteEngagementTool`, memory tools (unchanged)

**Orchestrator loop:**
1. Spawn initial agents
2. Call `review_events` (or `wait_for_any`) to get updates
3. Analyze events — spawn more agents, cancel agents, update instructions, or continue waiting
4. Repeat until calling `complete_engagement`

### 3. Agent Control

**Cancellation:**
- Each spawned agent gets a `tokio_util::sync::CancellationToken`
- `CancelAgentTool` triggers the token
- Agent's tool-call loop checks the token between iterations
- On cancellation, agent writes a partial summary and emits `AgentCancelled`
- Registry marks agent as `Cancelled`

**Reprioritization:**
- Each agent has an `mpsc::Receiver<String>` for instruction updates
- `UpdateAgentTool` sends new instructions through this channel
- At each tool-call boundary, the agent checks for pending messages
- New instructions are prepended: `"[UPDATED INSTRUCTIONS FROM ORCHESTRATOR]: ..."`

**Agent status:**
```rust
enum AgentStatus {
    Pending,
    Running,
    Cancelled,
    Completed,
    Failed,
}
```

### 4. Prompt Changes

**Orchestrator prompt:**
- Remove rigid phase ordering ("always run recon → scanner → report")
- Replace with adaptive guidance: analyze events and findings to decide next agents; loop back to recon when new scope appears
- Remove "broken pattern" / "working pattern" linear examples
- Keep phases as soft vocabulary for describing typical progression
- Add guidance on when to cancel/reprioritize agents

**Workflow hints:**
- Remove prescriptive hints ("you MUST now spawn scanner")
- Replace with informational context: agent summary, running agent count, findings so far

**Subagent prompts:**
- Add `ReportMilestoneTool` to all subagent tool lists
- Encourage milestone reporting ("report significant milestones as you work")
- Emphasize `next_steps` in completion summaries, especially for new attack surface

### 5. Tool Call Limits

| Agent | Old | New |
|-------|-----|-----|
| Orchestrator | 50 | 500 |
| Subagents (shell) | 50 | 500 |
| Report | 20 | 50 |

### 6. TUI Changes

- **Event timeline view**: New dedicated view showing real-time event stream across all agents (milestones, findings, completions, cancellations)
- **Agent detail**: Show milestones and cancellation status in existing agent detail view
- **Phase display**: Remains as informational indicator, no longer tied to control flow

## What Stays the Same

- `SpawnAgentTool` API
- Agent types (recon, scanner, sast, llm_pentest, exploit, report)
- SQLite persistence, memory tools, docker execution
- One report agent max constraint
- Session storage structure
