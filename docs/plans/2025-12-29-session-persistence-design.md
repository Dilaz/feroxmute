# Session Persistence Design

## Overview

Enable feroxmute to persist engagement data to disk and resume interrupted sessions. Users can quit mid-engagement and later continue with `--resume`, with the orchestrator receiving context about prior work.

## Goals

1. **Resume interrupted engagements** - Pick up where you left off after crash or quit
2. **Post-run analysis** - Review findings and memory after engagement ends
3. **Session discoverability** - List available sessions with `--list-sessions`

## Design Decisions

| Aspect | Decision | Rationale |
|--------|----------|-----------|
| What's persisted | Findings + agent memory | LLM conversation state is complex and provider-specific; memory captures key learnings |
| Persistence timing | Continuous (every operation) | SQLite handles frequent writes; guarantees no data loss on crash |
| Session IDs | Date-target format (`2025-12-28-example-com`) | Human-readable, obvious which session is which |
| Docker on resume | Fresh container always | Containers should be stateless; findings/memory in SQLite |
| Resume context | Inject summary into orchestrator prompt | Avoids replaying exact conversation; LLM rebuilds context |

## Data Model

### Existing Tables (unchanged)

- `memory` - Key-value scratchpad entries
- `findings` - Vulnerability findings from RecordFindingTool
- `session_meta` - Key-value metadata (id, target, created_at)

### New Table: session_state

```sql
CREATE TABLE session_state (
    id INTEGER PRIMARY KEY,
    status TEXT NOT NULL DEFAULT 'running',  -- running, completed, interrupted
    phase TEXT,                               -- current EngagementPhase
    last_activity_at TEXT,                    -- ISO timestamp
    completed_agents TEXT                     -- JSON array of completed agent names
);
```

### Status Transitions

```
new() ──────────────► Running
                         │
                         ├──► Interrupted (SIGINT / quit)
                         │         │
                         │         └──► Running (resume)
                         │
                         └──► Completed (CompleteEngagementTool)
```

## Implementation Changes

### 1. Session Struct Enhancements (`session.rs`)

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionStatus {
    Running,
    Completed,
    Interrupted,
}

impl Session {
    // Existing: new(), resume(), conn(), artifacts_dir(), etc.

    /// Get current session status
    pub fn status(&self) -> SessionStatus;

    /// Update session status
    pub fn set_status(&self, status: SessionStatus) -> Result<()>;

    /// Record an agent as completed
    pub fn mark_agent_completed(&self, agent_name: &str) -> Result<()>;

    /// Get list of completed agents
    pub fn completed_agents(&self) -> Result<Vec<String>>;

    /// Update last activity timestamp
    pub fn touch(&self) -> Result<()>;

    /// Get summary of findings for resume context
    pub fn findings_summary(&self) -> Result<FindingsSummary>;

    /// Get all memory entries for resume context
    pub fn memory_entries(&self) -> Result<Vec<MemoryEntry>>;
}
```

### 2. CLI Arguments (`args.rs`)

```rust
/// List available sessions and their status
#[arg(long)]
pub list_sessions: bool,
```

Output format for `--list-sessions`:
```
SESSION ID                    TARGET              STATUS       LAST ACTIVITY
2025-12-28-example-com        example.com         interrupted  2h ago
2025-12-27-testsite-org       testsite.org        completed    1d ago
```

Resume supports partial matching:
- `--resume 2025-12-28-example` finds `2025-12-28-example-com`
- `--resume example.com` finds most recent session for that target

### 3. main.rs Integration

```rust
// Handle --list-sessions
if args.list_sessions {
    let sessions_dir = config.output.session_dir;
    for entry in fs::read_dir(&sessions_dir)? {
        let path = entry?.path();
        if let Ok(session) = Session::resume(&path) {
            println!("{} | {} | {:?}",
                session.id,
                session.config.target.host,
                session.status());
        }
    }
    return Ok(());
}

// Create or resume session
let session = if let Some(ref resume_path) = args.resume {
    Session::resume(resume_path)?
} else {
    Session::new(config.clone(), &config.output.session_dir)?
};

let session = Arc::new(session);

// Pass to TUI and runner
let mut app = tui::App::new(&target, &session.id, Some(rx));
// ... later ...
runner::run_orchestrator(..., Arc::clone(&session)).await
```

### 4. runner.rs Integration

Change function signature:
```rust
pub async fn run_orchestrator(
    target: String,
    provider: Arc<dyn LlmProvider>,
    container: Arc<ContainerManager>,
    tx: mpsc::Sender<AgentEvent>,
    cancel: CancellationToken,
    source_path: Option<String>,
    limitations: Arc<EngagementLimitations>,
    instruction: Option<String>,
    session: Arc<Session>,  // NEW
) -> Result<()>
```

Use session DB instead of in-memory:
```rust
let memory_context = Arc::new(MemoryContext {
    conn: session.conn_arc(),  // File-backed connection
    events: Arc::clone(&events),
    agent_name: "orchestrator".to_string(),
});
```

On resume, prepend context to orchestrator prompt:
```
RESUMING ENGAGEMENT - Prior context:
- Completed agents: recon-1, scanner-1
- Memory: [key-value pairs from memory table]
- Findings: 2 High, 5 Medium, 3 Low severity issues found
Continue from where you left off.
```

## Error Handling

### Session Directory Conflicts

Same target on same day appends counter:
- `2025-12-28-example-com`
- `2025-12-28-example-com-2`
- `2025-12-28-example-com-3`

### Corrupted Sessions

`Session::resume()` returns clear error: "Session database corrupted or incompatible version"

### SIGINT Handling

1. Set status to `Interrupted`
2. Cancel token triggers graceful shutdown
3. SQLite transactions ensure no partial writes

### Resuming Completed Sessions

Show warning: "This engagement was completed. Resume anyway? [y/N]"

## Testing Strategy

### Unit Tests (`session.rs`)

- `test_create_session_creates_directory`
- `test_create_session_conflict_appends_counter`
- `test_resume_session_loads_state`
- `test_status_transitions`
- `test_mark_agent_completed`
- `test_resume_nonexistent_errors`

### Integration Tests

- `test_session_persists_findings`
- `test_session_persists_memory`
- `test_list_sessions_shows_all`

### Manual Testing Checklist

1. Run engagement, quit mid-way, verify `interrupted` status
2. Resume, verify orchestrator gets context about prior work
3. Complete engagement, verify `completed` status
4. Try resuming completed engagement, verify warning shown
5. Run `--list-sessions`, verify output format

## Files to Modify

| File | Changes |
|------|---------|
| `feroxmute-core/src/state/session.rs` | Add SessionStatus, helper methods |
| `feroxmute-core/src/state/mod.rs` | New migration for session_state table |
| `feroxmute-cli/src/args.rs` | Add `--list-sessions` flag |
| `feroxmute-cli/src/main.rs` | Wire up Session, handle list/resume flows |
| `feroxmute-cli/src/runner.rs` | Use session DB, inject resume context |

## Out of Scope

- Automatic session cleanup (users manage their own directory)
- LLM conversation replay (memory provides sufficient context)
- Container state persistence (fresh containers are reliable)
