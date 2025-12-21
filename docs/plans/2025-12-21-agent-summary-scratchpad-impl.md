# Agent Summary & Scratch Pad Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add LLM-generated structured summaries for agent results and a persistent scratch pad for orchestrator context management.

**Architecture:** Summarization happens in `WaitForAgentTool`/`WaitForAnyTool` using the same LLM provider. Scratch pad is stored in SQLite and accessed via four new orchestrator tools (`memory_add`, `memory_get`, `memory_list`, `memory_remove`).

**Tech Stack:** Rust, rusqlite, rig-core, serde_json, tokio

---

## Task 1: Add AgentSummary Struct

**Files:**
- Modify: `feroxmute-core/src/tools/orchestrator.rs`

**Step 1: Add the AgentSummary struct**

Add after line 31 (after `OrchestratorToolError`):

```rust
/// Structured summary of an agent's work
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSummary {
    /// Whether the agent completed successfully
    pub success: bool,
    /// 1-2 sentence overview of what the agent did
    pub summary: String,
    /// Important discoveries or results
    pub key_findings: Vec<String>,
    /// Suggested follow-up actions
    pub next_steps: Vec<String>,
}

impl Default for AgentSummary {
    fn default() -> Self {
        Self {
            success: false,
            summary: String::new(),
            key_findings: Vec::new(),
            next_steps: Vec::new(),
        }
    }
}
```

**Step 2: Run build to verify**

Run: `cargo build -p feroxmute-core`
Expected: SUCCESS

**Step 3: Commit**

```bash
git add feroxmute-core/src/tools/orchestrator.rs
git commit -m "feat(tools): add AgentSummary struct for structured agent results"
```

---

## Task 2: Add get_agent_instructions to AgentRegistry

**Files:**
- Modify: `feroxmute-core/src/agents/registry.rs`
- Test: `feroxmute-core/src/agents/registry.rs` (inline tests)

**Step 1: Add the test**

Add to the `#[cfg(test)] mod tests` block:

```rust
#[test]
fn test_get_agent_instructions() {
    let mut registry = AgentRegistry::new();

    // Register a mock agent
    let handle = tokio::spawn(async {});
    registry.register(
        "test-agent".to_string(),
        "recon".to_string(),
        "Enumerate subdomains for example.com".to_string(),
        handle,
    );

    let instructions = registry.get_agent_instructions("test-agent");
    assert_eq!(instructions, Some("Enumerate subdomains for example.com".to_string()));

    let missing = registry.get_agent_instructions("nonexistent");
    assert_eq!(missing, None);
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p feroxmute-core test_get_agent_instructions`
Expected: FAIL with "no method named `get_agent_instructions`"

**Step 3: Implement get_agent_instructions**

Add to `impl AgentRegistry` after line 85 (after `list_agents`):

```rust
/// Get the instructions for a specific agent
pub fn get_agent_instructions(&self, name: &str) -> Option<String> {
    self.agents.get(name).map(|a| a.instructions.clone())
}
```

**Step 4: Run test to verify it passes**

Run: `cargo test -p feroxmute-core test_get_agent_instructions`
Expected: PASS

**Step 5: Commit**

```bash
git add feroxmute-core/src/agents/registry.rs
git commit -m "feat(agents): add get_agent_instructions to AgentRegistry"
```

---

## Task 3: Add summarize_agent_output Helper

**Files:**
- Modify: `feroxmute-core/src/tools/orchestrator.rs`

**Step 1: Add the summarization helper function**

Add after the `AgentSummary` impl block (around line 55):

```rust
/// Summarize agent output using the LLM
async fn summarize_agent_output(
    provider: &dyn crate::providers::LlmProvider,
    agent_name: &str,
    agent_type: &str,
    instructions: &str,
    raw_output: &str,
) -> AgentSummary {
    use crate::providers::{CompletionRequest, Message};

    let prompt = format!(
        r#"You are summarizing agent output for an orchestrator coordinating a penetration test.

Agent: {} ({})
Task: {}

Raw Output:
{}

Respond with JSON only, no markdown formatting:
{{"success": true/false, "summary": "1-2 sentence overview", "key_findings": ["finding 1", "finding 2"], "next_steps": ["action 1", "action 2"]}}"#,
        agent_name, agent_type, instructions, raw_output
    );

    let request = CompletionRequest::new(vec![Message::user(&prompt)])
        .with_system("You extract structured summaries from agent output. Respond with valid JSON only.")
        .with_max_tokens(1024);

    match provider.complete(request).await {
        Ok(response) => {
            if let Some(content) = response.content {
                // Try to parse the JSON response
                if let Ok(summary) = serde_json::from_str::<AgentSummary>(&content) {
                    return summary;
                }
                // Try to extract JSON from markdown code block
                let cleaned = content
                    .trim()
                    .trim_start_matches("```json")
                    .trim_start_matches("```")
                    .trim_end_matches("```")
                    .trim();
                if let Ok(summary) = serde_json::from_str::<AgentSummary>(cleaned) {
                    return summary;
                }
            }
            // Fallback: return a basic summary
            AgentSummary {
                success: !raw_output.to_lowercase().contains("error"),
                summary: "Summarization failed - raw output available".to_string(),
                key_findings: vec![],
                next_steps: vec![],
            }
        }
        Err(_) => AgentSummary {
            success: !raw_output.to_lowercase().contains("error"),
            summary: "Summarization failed - raw output available".to_string(),
            key_findings: vec![],
            next_steps: vec![],
        },
    }
}
```

**Step 2: Run build to verify**

Run: `cargo build -p feroxmute-core`
Expected: SUCCESS

**Step 3: Commit**

```bash
git add feroxmute-core/src/tools/orchestrator.rs
git commit -m "feat(tools): add summarize_agent_output helper function"
```

---

## Task 4: Update WaitForAgentOutput to Use AgentSummary

**Files:**
- Modify: `feroxmute-core/src/tools/orchestrator.rs`

**Step 1: Update WaitForAgentOutput struct**

Change `WaitForAgentOutput` (around line 315):

```rust
#[derive(Debug, Serialize)]
pub struct WaitForAgentOutput {
    pub found: bool,
    pub summary: AgentSummary,
    /// Raw output truncated for reference (if needed)
    pub raw_output_truncated: String,
}
```

**Step 2: Update WaitForAgentTool::call to use summarization**

Replace the `call` method implementation (around line 355-402):

```rust
async fn call(&self, args: Self::Args) -> Result<Self::Output, Self::Error> {
    self.context.events.send_feed(
        "orchestrator",
        &format!("Waiting for agent '{}'...", args.name),
        false,
    );

    // Update orchestrator status to Waiting while blocked
    self.context
        .events
        .send_status("orchestrator", "orchestrator", AgentStatus::Waiting, None);

    // Get instructions before waiting (registry will be locked during wait)
    let instructions = {
        let registry = self.context.registry.lock().await;
        registry.get_agent_instructions(&args.name).unwrap_or_default()
    };

    let mut registry = self.context.registry.lock().await;
    let result = registry.wait_for_agent(&args.name).await;
    drop(registry);

    // Restore orchestrator status to Running
    self.context.events.send_status(
        "orchestrator",
        "orchestrator",
        AgentStatus::Streaming,
        None,
    );

    match result {
        Some(result) => {
            self.context.events.send_status(
                &result.name,
                &result.agent_type,
                if result.success {
                    AgentStatus::Completed
                } else {
                    AgentStatus::Failed
                },
                None,
            );

            // Summarize the output
            let summary = summarize_agent_output(
                self.context.provider.as_ref(),
                &result.name,
                &result.agent_type,
                &instructions,
                &result.output,
            )
            .await;

            Ok(WaitForAgentOutput {
                found: true,
                summary,
                raw_output_truncated: truncate_output(&result.output, 500),
            })
        }
        None => Ok(WaitForAgentOutput {
            found: false,
            summary: AgentSummary {
                success: false,
                summary: format!("Agent '{}' not found", args.name),
                key_findings: vec![],
                next_steps: vec![],
            },
            raw_output_truncated: String::new(),
        }),
    }
}
```

**Step 3: Run build to verify**

Run: `cargo build -p feroxmute-core`
Expected: SUCCESS

**Step 4: Commit**

```bash
git add feroxmute-core/src/tools/orchestrator.rs
git commit -m "feat(tools): update WaitForAgentTool to return structured summaries"
```

---

## Task 5: Update WaitForAnyOutput to Use AgentSummary

**Files:**
- Modify: `feroxmute-core/src/tools/orchestrator.rs`

**Step 1: Update WaitForAnyOutput struct**

Change `WaitForAnyOutput` (around line 414):

```rust
#[derive(Debug, Serialize)]
pub struct WaitForAnyOutput {
    pub found: bool,
    pub name: String,
    pub agent_type: String,
    pub summary: AgentSummary,
    pub raw_output_truncated: String,
    /// Number of agents still running after this one completed
    pub remaining_running: usize,
}
```

**Step 2: Update WaitForAnyTool::call to use summarization**

Replace the `call` method implementation (around line 452-520):

```rust
async fn call(&self, _args: Self::Args) -> Result<Self::Output, Self::Error> {
    self.context.events.send_feed(
        "orchestrator",
        "Waiting for any agent to complete...",
        false,
    );

    // Update orchestrator status to Waiting while blocked
    self.context
        .events
        .send_status("orchestrator", "orchestrator", AgentStatus::Waiting, None);

    let mut registry = self.context.registry.lock().await;
    let result = registry.wait_for_any().await;

    // Get instructions while we still have the lock
    let instructions = result.as_ref()
        .and_then(|r| registry.get_agent_instructions(&r.name))
        .unwrap_or_default();

    // Count remaining running agents
    let remaining_running = registry
        .list_agents()
        .iter()
        .filter(|(_, _, status)| {
            matches!(
                status,
                AgentStatus::Thinking
                    | AgentStatus::Streaming
                    | AgentStatus::Executing
                    | AgentStatus::Processing
            )
        })
        .count();

    drop(registry);

    // Restore orchestrator status to Running
    self.context.events.send_status(
        "orchestrator",
        "orchestrator",
        AgentStatus::Streaming,
        None,
    );

    match result {
        Some(result) => {
            self.context.events.send_status(
                &result.name,
                &result.agent_type,
                if result.success {
                    AgentStatus::Completed
                } else {
                    AgentStatus::Failed
                },
                None,
            );

            // Summarize the output
            let summary = summarize_agent_output(
                self.context.provider.as_ref(),
                &result.name,
                &result.agent_type,
                &instructions,
                &result.output,
            )
            .await;

            Ok(WaitForAnyOutput {
                found: true,
                name: result.name,
                agent_type: result.agent_type,
                summary,
                raw_output_truncated: truncate_output(&result.output, 500),
                remaining_running,
            })
        }
        None => Ok(WaitForAnyOutput {
            found: false,
            name: String::new(),
            agent_type: String::new(),
            summary: AgentSummary::default(),
            raw_output_truncated: "No running agents".to_string(),
            remaining_running: 0,
        }),
    }
}
```

**Step 3: Run build to verify**

Run: `cargo build -p feroxmute-core`
Expected: SUCCESS

**Step 4: Run all tests**

Run: `cargo test -p feroxmute-core`
Expected: PASS

**Step 5: Commit**

```bash
git add feroxmute-core/src/tools/orchestrator.rs
git commit -m "feat(tools): update WaitForAnyTool to return structured summaries"
```

---

## Task 6: Add Scratch Pad Schema

**Files:**
- Modify: `feroxmute-core/src/state/schema.rs`

**Step 1: Add scratch_pad table to schema**

Add before the closing `"#;` (after line 131, before the indexes):

```sql
-- Orchestrator scratch pad for persistent notes
CREATE TABLE IF NOT EXISTS scratch_pad (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
```

**Step 2: Run build to verify**

Run: `cargo build -p feroxmute-core`
Expected: SUCCESS

**Step 3: Commit**

```bash
git add feroxmute-core/src/state/schema.rs
git commit -m "feat(state): add scratch_pad table to schema"
```

---

## Task 7: Update Migration Test

**Files:**
- Modify: `feroxmute-core/src/state/migrations.rs`

The schema uses `CREATE TABLE IF NOT EXISTS`, so adding the table to schema.rs (Task 6) is sufficient. We just need to update the test to verify the new table exists.

**Step 1: Update the migration test**

Add `scratch_pad` to the list of verified tables in `test_migrations_run_successfully`:

```rust
#[test]
fn test_migrations_run_successfully() {
    let conn = Connection::open_in_memory().unwrap();
    run_migrations(&conn).unwrap();

    // Verify tables exist
    let tables: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .filter_map(|r| r.ok())
        .collect();

    assert!(tables.contains(&"hosts".to_string()));
    assert!(tables.contains(&"vulnerabilities".to_string()));
    assert!(tables.contains(&"agent_tasks".to_string()));
    assert!(tables.contains(&"scratch_pad".to_string()));
}
```

**Step 2: Run tests**

Run: `cargo test -p feroxmute-core test_migrations`
Expected: PASS

**Step 3: Commit**

```bash
git add feroxmute-core/src/state/migrations.rs
git commit -m "test(state): verify scratch_pad table in migration test"
```

---

## Task 8: Create Memory Tools Module

**Files:**
- Create: `feroxmute-core/src/tools/memory.rs`

**Step 1: Create the memory tools file**

```rust
//! Memory/scratch pad tools for the orchestrator
//!
//! Provides persistent key-value storage for orchestrator context management.

use std::sync::Arc;

use rig::completion::ToolDefinition;
use rig::tool::Tool;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;
use tokio::sync::Mutex;

/// Errors from memory tools
#[derive(Debug, Error)]
pub enum MemoryToolError {
    #[error("Database error: {0}")]
    Database(String),
}

/// Shared context for memory tools
pub struct MemoryContext {
    pub conn: Arc<Mutex<Connection>>,
}

// ============================================================================
// MemoryAddTool
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct MemoryAddArgs {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Serialize)]
pub struct MemoryAddOutput {
    pub stored: bool,
    pub key: String,
}

pub struct MemoryAddTool {
    context: Arc<MemoryContext>,
}

impl MemoryAddTool {
    pub fn new(context: Arc<MemoryContext>) -> Self {
        Self { context }
    }
}

impl Tool for MemoryAddTool {
    const NAME: &'static str = "memory_add";

    type Error = MemoryToolError;
    type Args = MemoryAddArgs;
    type Output = MemoryAddOutput;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: "memory_add".to_string(),
            description: "Store or update a key-value pair in the scratch pad for later reference."
                .to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "key": {
                        "type": "string",
                        "description": "Unique key to store the value under"
                    },
                    "value": {
                        "type": "string",
                        "description": "The value to store"
                    }
                },
                "required": ["key", "value"]
            }),
        }
    }

    async fn call(&self, args: Self::Args) -> Result<Self::Output, Self::Error> {
        let conn = self.context.conn.lock().await;
        conn.execute(
            "INSERT INTO scratch_pad (key, value, created_at, updated_at)
             VALUES (?1, ?2, datetime('now'), datetime('now'))
             ON CONFLICT(key) DO UPDATE SET value = ?2, updated_at = datetime('now')",
            [&args.key, &args.value],
        )
        .map_err(|e| MemoryToolError::Database(e.to_string()))?;

        Ok(MemoryAddOutput {
            stored: true,
            key: args.key,
        })
    }
}

// ============================================================================
// MemoryGetTool
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct MemoryGetArgs {
    pub key: String,
}

#[derive(Debug, Serialize)]
pub struct MemoryGetOutput {
    pub found: bool,
    pub key: String,
    pub value: Option<String>,
}

pub struct MemoryGetTool {
    context: Arc<MemoryContext>,
}

impl MemoryGetTool {
    pub fn new(context: Arc<MemoryContext>) -> Self {
        Self { context }
    }
}

impl Tool for MemoryGetTool {
    const NAME: &'static str = "memory_get";

    type Error = MemoryToolError;
    type Args = MemoryGetArgs;
    type Output = MemoryGetOutput;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: "memory_get".to_string(),
            description: "Retrieve a value from the scratch pad by its key.".to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "key": {
                        "type": "string",
                        "description": "The key to look up"
                    }
                },
                "required": ["key"]
            }),
        }
    }

    async fn call(&self, args: Self::Args) -> Result<Self::Output, Self::Error> {
        let conn = self.context.conn.lock().await;
        let result: Result<String, _> = conn.query_row(
            "SELECT value FROM scratch_pad WHERE key = ?1",
            [&args.key],
            |row| row.get(0),
        );

        match result {
            Ok(value) => Ok(MemoryGetOutput {
                found: true,
                key: args.key,
                value: Some(value),
            }),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(MemoryGetOutput {
                found: false,
                key: args.key,
                value: None,
            }),
            Err(e) => Err(MemoryToolError::Database(e.to_string())),
        }
    }
}

// ============================================================================
// MemoryListTool
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct MemoryListArgs {
    #[serde(default)]
    pub prefix: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct MemoryListOutput {
    pub keys: Vec<String>,
}

pub struct MemoryListTool {
    context: Arc<MemoryContext>,
}

impl MemoryListTool {
    pub fn new(context: Arc<MemoryContext>) -> Self {
        Self { context }
    }
}

impl Tool for MemoryListTool {
    const NAME: &'static str = "memory_list";

    type Error = MemoryToolError;
    type Args = MemoryListArgs;
    type Output = MemoryListOutput;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: "memory_list".to_string(),
            description: "List all keys in the scratch pad, optionally filtered by prefix."
                .to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "prefix": {
                        "type": "string",
                        "description": "Optional prefix to filter keys (e.g., 'recon-' to list all recon-related entries)"
                    }
                }
            }),
        }
    }

    async fn call(&self, args: Self::Args) -> Result<Self::Output, Self::Error> {
        let conn = self.context.conn.lock().await;

        let keys: Vec<String> = match &args.prefix {
            Some(prefix) => {
                let pattern = format!("{}%", prefix);
                let mut stmt = conn
                    .prepare("SELECT key FROM scratch_pad WHERE key LIKE ?1 ORDER BY key")
                    .map_err(|e| MemoryToolError::Database(e.to_string()))?;
                stmt.query_map([pattern], |row| row.get(0))
                    .map_err(|e| MemoryToolError::Database(e.to_string()))?
                    .filter_map(|r| r.ok())
                    .collect()
            }
            None => {
                let mut stmt = conn
                    .prepare("SELECT key FROM scratch_pad ORDER BY key")
                    .map_err(|e| MemoryToolError::Database(e.to_string()))?;
                stmt.query_map([], |row| row.get(0))
                    .map_err(|e| MemoryToolError::Database(e.to_string()))?
                    .filter_map(|r| r.ok())
                    .collect()
            }
        };

        Ok(MemoryListOutput { keys })
    }
}

// ============================================================================
// MemoryRemoveTool
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct MemoryRemoveArgs {
    pub key: String,
}

#[derive(Debug, Serialize)]
pub struct MemoryRemoveOutput {
    pub removed: bool,
    pub key: String,
}

pub struct MemoryRemoveTool {
    context: Arc<MemoryContext>,
}

impl MemoryRemoveTool {
    pub fn new(context: Arc<MemoryContext>) -> Self {
        Self { context }
    }
}

impl Tool for MemoryRemoveTool {
    const NAME: &'static str = "memory_remove";

    type Error = MemoryToolError;
    type Args = MemoryRemoveArgs;
    type Output = MemoryRemoveOutput;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: "memory_remove".to_string(),
            description: "Remove an entry from the scratch pad.".to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "key": {
                        "type": "string",
                        "description": "The key to remove"
                    }
                },
                "required": ["key"]
            }),
        }
    }

    async fn call(&self, args: Self::Args) -> Result<Self::Output, Self::Error> {
        let conn = self.context.conn.lock().await;
        let rows_affected = conn
            .execute("DELETE FROM scratch_pad WHERE key = ?1", [&args.key])
            .map_err(|e| MemoryToolError::Database(e.to_string()))?;

        Ok(MemoryRemoveOutput {
            removed: rows_affected > 0,
            key: args.key,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::run_migrations;

    fn setup_context() -> Arc<MemoryContext> {
        let conn = Connection::open_in_memory().unwrap();
        run_migrations(&conn).unwrap();
        Arc::new(MemoryContext {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    #[tokio::test]
    async fn test_memory_add_and_get() {
        let context = setup_context();
        let add_tool = MemoryAddTool::new(Arc::clone(&context));
        let get_tool = MemoryGetTool::new(Arc::clone(&context));

        // Add a value
        let result = add_tool
            .call(MemoryAddArgs {
                key: "test-key".to_string(),
                value: "test-value".to_string(),
            })
            .await
            .unwrap();
        assert!(result.stored);

        // Get it back
        let result = get_tool
            .call(MemoryGetArgs {
                key: "test-key".to_string(),
            })
            .await
            .unwrap();
        assert!(result.found);
        assert_eq!(result.value, Some("test-value".to_string()));
    }

    #[tokio::test]
    async fn test_memory_get_not_found() {
        let context = setup_context();
        let get_tool = MemoryGetTool::new(context);

        let result = get_tool
            .call(MemoryGetArgs {
                key: "nonexistent".to_string(),
            })
            .await
            .unwrap();
        assert!(!result.found);
        assert_eq!(result.value, None);
    }

    #[tokio::test]
    async fn test_memory_list() {
        let context = setup_context();
        let add_tool = MemoryAddTool::new(Arc::clone(&context));
        let list_tool = MemoryListTool::new(Arc::clone(&context));

        // Add some values
        add_tool
            .call(MemoryAddArgs {
                key: "recon-subdomains".to_string(),
                value: "a.com, b.com".to_string(),
            })
            .await
            .unwrap();
        add_tool
            .call(MemoryAddArgs {
                key: "recon-ports".to_string(),
                value: "80, 443".to_string(),
            })
            .await
            .unwrap();
        add_tool
            .call(MemoryAddArgs {
                key: "scanner-results".to_string(),
                value: "vulns found".to_string(),
            })
            .await
            .unwrap();

        // List all
        let result = list_tool
            .call(MemoryListArgs { prefix: None })
            .await
            .unwrap();
        assert_eq!(result.keys.len(), 3);

        // List with prefix
        let result = list_tool
            .call(MemoryListArgs {
                prefix: Some("recon-".to_string()),
            })
            .await
            .unwrap();
        assert_eq!(result.keys.len(), 2);
        assert!(result.keys.contains(&"recon-subdomains".to_string()));
        assert!(result.keys.contains(&"recon-ports".to_string()));
    }

    #[tokio::test]
    async fn test_memory_remove() {
        let context = setup_context();
        let add_tool = MemoryAddTool::new(Arc::clone(&context));
        let remove_tool = MemoryRemoveTool::new(Arc::clone(&context));
        let get_tool = MemoryGetTool::new(Arc::clone(&context));

        // Add and then remove
        add_tool
            .call(MemoryAddArgs {
                key: "to-remove".to_string(),
                value: "value".to_string(),
            })
            .await
            .unwrap();

        let result = remove_tool
            .call(MemoryRemoveArgs {
                key: "to-remove".to_string(),
            })
            .await
            .unwrap();
        assert!(result.removed);

        // Verify it's gone
        let result = get_tool
            .call(MemoryGetArgs {
                key: "to-remove".to_string(),
            })
            .await
            .unwrap();
        assert!(!result.found);
    }

    #[tokio::test]
    async fn test_memory_upsert() {
        let context = setup_context();
        let add_tool = MemoryAddTool::new(Arc::clone(&context));
        let get_tool = MemoryGetTool::new(Arc::clone(&context));

        // Add initial value
        add_tool
            .call(MemoryAddArgs {
                key: "key".to_string(),
                value: "value1".to_string(),
            })
            .await
            .unwrap();

        // Update with same key
        add_tool
            .call(MemoryAddArgs {
                key: "key".to_string(),
                value: "value2".to_string(),
            })
            .await
            .unwrap();

        // Should have new value
        let result = get_tool
            .call(MemoryGetArgs {
                key: "key".to_string(),
            })
            .await
            .unwrap();
        assert_eq!(result.value, Some("value2".to_string()));
    }
}
```

**Step 2: Run build to verify**

Run: `cargo build -p feroxmute-core`
Expected: FAIL (module not registered)

**Step 3: Commit the file (will fix module registration next)**

```bash
git add feroxmute-core/src/tools/memory.rs
git commit -m "feat(tools): add memory/scratch pad tools module"
```

---

## Task 9: Export Memory Tools

**Files:**
- Modify: `feroxmute-core/src/tools/mod.rs`

**Step 1: Add memory module and exports**

Update `feroxmute-core/src/tools/mod.rs`:

```rust
//! Tool integration module

pub mod executor;
pub mod memory;
pub mod orchestrator;
pub mod report;
pub mod sast;
pub mod shell;

pub use executor::{ToolDef, ToolExecution, ToolExecutor, ToolRegistry};
pub use memory::{
    MemoryAddTool, MemoryContext, MemoryGetTool, MemoryListTool, MemoryRemoveTool,
    MemoryToolError,
};
pub use orchestrator::{
    AgentSummary, CompleteEngagementTool, EventSender, ListAgentsTool, OrchestratorContext,
    OrchestratorToolError, RecordFindingTool, SpawnAgentTool, WaitForAgentTool, WaitForAnyTool,
};
pub use report::{
    AddRecommendationTool, ExportJsonTool, ExportMarkdownTool, GenerateReportTool, ReportContext,
};
pub use shell::DockerShellTool;
```

**Step 2: Run build to verify**

Run: `cargo build -p feroxmute-core`
Expected: SUCCESS

**Step 3: Run tests**

Run: `cargo test -p feroxmute-core memory`
Expected: PASS

**Step 4: Commit**

```bash
git add feroxmute-core/src/tools/mod.rs
git commit -m "feat(tools): export memory tools from mod.rs"
```

---

## Task 10: Add MemoryContext to OrchestratorContext

**Files:**
- Modify: `feroxmute-core/src/tools/orchestrator.rs`

**Step 1: Add memory_context field to OrchestratorContext**

Update `OrchestratorContext` struct (around line 66):

```rust
/// Shared context for all orchestrator tools
pub struct OrchestratorContext {
    pub registry: Arc<Mutex<AgentRegistry>>,
    pub provider: Arc<dyn LlmProvider>,
    pub container: Arc<ContainerManager>,
    pub events: Arc<dyn EventSender>,
    pub cancel: CancellationToken,
    pub prompts: Prompts,
    pub target: String,
    pub findings: Arc<Mutex<Vec<String>>>,
    /// Engagement scope limitations
    pub limitations: Arc<EngagementLimitations>,
    /// Memory/scratch pad context for persistent notes
    pub memory: Arc<super::memory::MemoryContext>,
}
```

**Step 2: Run build to verify**

Run: `cargo build -p feroxmute-core`
Expected: FAIL (runner.rs needs updating)

**Step 3: Commit**

```bash
git add feroxmute-core/src/tools/orchestrator.rs
git commit -m "feat(tools): add memory context to OrchestratorContext"
```

---

## Task 11: Update Runner to Create MemoryContext

**Files:**
- Modify: `feroxmute-cli/src/runner.rs`

**Step 1: Add memory context creation**

Update the imports and `run_orchestrator_with_tools` function:

Add import:
```rust
use feroxmute_core::tools::MemoryContext;
```

Update `OrchestratorContext` creation (around line 250):

```rust
// Create memory context with in-memory DB (TODO: use session DB when available)
let memory_conn = rusqlite::Connection::open_in_memory()
    .map_err(|e| anyhow::anyhow!("Failed to create memory DB: {}", e))?;
feroxmute_core::state::run_migrations(&memory_conn)
    .map_err(|e| anyhow::anyhow!("Failed to run migrations: {}", e))?;
let memory_context = Arc::new(MemoryContext {
    conn: Arc::new(Mutex::new(memory_conn)),
});

// Create the orchestrator context with all shared state
let context = Arc::new(OrchestratorContext {
    registry: Arc::new(Mutex::new(AgentRegistry::new())),
    provider: Arc::clone(&provider),
    container,
    events: Arc::new(TuiEventSender::new(tx.clone())),
    cancel,
    prompts: prompts.clone(),
    target: target.to_string(),
    findings: Arc::new(Mutex::new(Vec::new())),
    limitations: Arc::clone(&limitations),
    memory: memory_context,
});
```

**Step 2: Run build to verify**

Run: `cargo build`
Expected: SUCCESS

**Step 3: Commit**

```bash
git add feroxmute-cli/src/runner.rs
git commit -m "feat(cli): create MemoryContext in runner"
```

---

## Task 12: Wire Memory Tools into Provider Macro

**Files:**
- Modify: `feroxmute-core/src/providers/macros.rs`

**Step 1: Add memory tools to complete_with_orchestrator**

In the `complete_with_orchestrator` method, add memory tools after the existing orchestrator tools (around line 362):

```rust
let agent = self
    .client
    .agent(&self.model)
    .preamble(system_prompt)
    .max_tokens(4096)
    .tool($crate::tools::SpawnAgentTool::new(std::sync::Arc::clone(&context)))
    .tool($crate::tools::WaitForAgentTool::new(std::sync::Arc::clone(&context)))
    .tool($crate::tools::WaitForAnyTool::new(std::sync::Arc::clone(&context)))
    .tool($crate::tools::ListAgentsTool::new(std::sync::Arc::clone(&context)))
    .tool($crate::tools::RecordFindingTool::new(std::sync::Arc::clone(&context)))
    .tool($crate::tools::CompleteEngagementTool::new(std::sync::Arc::clone(&context)))
    .tool($crate::tools::MemoryAddTool::new(std::sync::Arc::clone(&context.memory)))
    .tool($crate::tools::MemoryGetTool::new(std::sync::Arc::clone(&context.memory)))
    .tool($crate::tools::MemoryListTool::new(std::sync::Arc::clone(&context.memory)))
    .tool($crate::tools::MemoryRemoveTool::new(std::sync::Arc::clone(&context.memory)))
    .build();
```

**Step 2: Run build to verify**

Run: `cargo build`
Expected: SUCCESS

**Step 3: Run all tests**

Run: `cargo test`
Expected: PASS

**Step 4: Commit**

```bash
git add feroxmute-core/src/providers/macros.rs
git commit -m "feat(providers): wire memory tools into orchestrator agent"
```

---

## Task 13: Final Integration Test

**Files:**
- None (manual verification)

**Step 1: Run full test suite**

Run: `cargo test`
Expected: All tests PASS

**Step 2: Run clippy**

Run: `cargo clippy`
Expected: No errors

**Step 3: Run format check**

Run: `cargo fmt -- --check`
Expected: No formatting issues

**Step 4: Final commit (if any fixes needed)**

```bash
git add -A
git commit -m "chore: fix any remaining issues from integration"
```

---

## Summary

This plan implements:
1. **Structured agent summaries** via `AgentSummary` struct and `summarize_agent_output` helper
2. **Updated wait tools** that return summaries instead of truncated output
3. **Persistent scratch pad** with SQLite storage and four CRUD tools
4. **Full integration** into the orchestrator's tool set

Total: 13 tasks with TDD approach, frequent commits, and verification at each step.
