# Agent Summaries & Scratch Pad Design

## Overview

Two features to improve orchestrator context management:

1. **Agent Result Summarization** - When the orchestrator waits for an agent, raw output gets LLM-summarized into a structured format before returning.

2. **Scratch Pad** - A persistent key-value store with CRUD tools for the orchestrator.

## Data Structures

### Structured Summary Format

```rust
struct AgentSummary {
    success: bool,
    summary: String,            // 1-2 sentence overview
    key_findings: Vec<String>,  // Important discoveries
    next_steps: Vec<String>,    // Suggested follow-ups
}
```

### Scratch Pad Entry

```rust
struct ScratchPadEntry {
    key: String,
    value: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}
```

### SQLite Table

```sql
CREATE TABLE scratch_pad (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
```

The summary is generated on-the-fly (not stored), while scratch pad entries persist in the session database.

## Summarization Flow

**Where it happens:** Inside `WaitForAgentTool::call()` and `WaitForAnyTool::call()`, after receiving the raw agent output but before returning to the orchestrator.

**Flow:**
```
Agent completes → Raw output stored in AgentResult
                           ↓
Orchestrator calls wait_for_agent/wait_for_any
                           ↓
Tool retrieves AgentResult with raw output
                           ↓
LLM summarization call (same provider)
                           ↓
Returns AgentSummary instead of truncated string
```

**Summarization Prompt:**
```
You are summarizing agent output for an orchestrator coordinating a penetration test.

Agent: {agent_name} ({agent_type})
Task: {original_instructions}

Raw Output:
{raw_output}

Respond with JSON only:
{
  "success": true/false,
  "summary": "1-2 sentence overview",
  "key_findings": ["finding 1", "finding 2"],
  "next_steps": ["suggested action 1", "suggested action 2"]
}
```

**Changes to output types:**
- `WaitForAgentOutput.output: String` → `WaitForAgentOutput.summary: AgentSummary`
- `WaitForAnyOutput.output: String` → `WaitForAnyOutput.summary: AgentSummary`

The orchestrator LLM sees structured JSON in tool results instead of truncated raw text.

## Scratch Pad Tools

Four new tools for the orchestrator:

### `memory_add` - Store or update an entry

```json
{
  "key": "discovered-subdomains",
  "value": "api.example.com, admin.example.com, dev.example.com"
}
```
Returns: `{ "stored": true, "key": "discovered-subdomains" }`

### `memory_get` - Retrieve a specific entry

```json
{
  "key": "discovered-subdomains"
}
```
Returns: `{ "found": true, "key": "...", "value": "..." }` or `{ "found": false }`

### `memory_list` - List all keys (with optional prefix filter)

```json
{
  "prefix": "recon-"  // optional
}
```
Returns: `{ "keys": ["recon-subdomains", "recon-ports", ...] }`

### `memory_remove` - Delete an entry

```json
{
  "key": "discovered-subdomains"
}
```
Returns: `{ "removed": true }` or `{ "removed": false, "reason": "not found" }`

**Implementation location:** New file `feroxmute-core/src/tools/memory.rs` with four tool structs following the same pattern as existing orchestrator tools.

## Integration & Changes

### Files to modify

1. **`feroxmute-core/src/tools/orchestrator.rs`**
   - Add `summarize_output()` helper that calls LLM
   - Modify `WaitForAgentTool::call()` to summarize before returning
   - Modify `WaitForAnyTool::call()` to summarize before returning
   - Store original instructions in `AgentRegistry` (needed for summarization prompt)

2. **`feroxmute-core/src/agents/registry.rs`**
   - Add `instructions: String` field to tracked agent info
   - Expose via `get_agent_instructions(name)` method

3. **`feroxmute-core/src/state/models.rs`**
   - Add `ScratchPadEntry` struct

4. **`feroxmute-core/src/state/session.rs`**
   - Add `scratch_pad` table creation in schema
   - Add CRUD methods: `memory_add()`, `memory_get()`, `memory_list()`, `memory_remove()`

### New files

5. **`feroxmute-core/src/tools/memory.rs`**
   - Four tool structs: `MemoryAddTool`, `MemoryGetTool`, `MemoryListTool`, `MemoryRemoveTool`
   - Shared `MemoryContext` with DB connection

6. **Wire tools into orchestrator** in `feroxmute-core/src/tools/mod.rs` and wherever orchestrator tools are registered

## Edge Cases & Error Handling

### Summarization failures
- If LLM summarization fails (timeout, parse error), fall back to truncated raw output with `success: false` and `summary: "Summarization failed - raw output truncated"`
- Log the error but don't fail the wait operation

### Empty agent output
- Return `summary: "Agent produced no output"`, empty `key_findings` and `next_steps`

### Scratch pad limits
- No hard limits on entry count or value size (LLM context limits naturally constrain usage)
- If `memory_list` returns too many keys, orchestrator can use prefix filtering

### Key collisions
- `memory_add` with existing key overwrites (upsert behavior)
- Updates `updated_at` timestamp

### Session resume
- Scratch pad loads from SQLite automatically
- Agent summaries are not persisted (regenerated if needed on resume)

### Concurrent access
- Scratch pad access serialized via existing DB connection mutex
- No race conditions since orchestrator is single-threaded
