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

use super::EventSender;

/// Errors from memory tools
#[derive(Debug, Error)]
pub enum MemoryToolError {
    #[error("Database error: {0}")]
    Database(String),
}

/// Shared context for memory tools
pub struct MemoryContext {
    pub conn: Arc<Mutex<Connection>>,
    pub events: Arc<dyn EventSender>,
    pub agent_name: String,
}

/// Query all memory entries and send update event
async fn broadcast_memory_update(context: &MemoryContext) {
    let entries = {
        let conn = context.conn.lock().await;
        let mut stmt = match conn
            .prepare("SELECT key, value, created_at, updated_at FROM scratch_pad ORDER BY key")
        {
            Ok(s) => s,
            Err(_) => return,
        };

        stmt.query_map([], |row| {
            Ok(super::MemoryEntryData {
                key: row.get(0)?,
                value: row.get(1)?,
                created_at: row.get(2)?,
                updated_at: row.get(3)?,
            })
        })
        .ok()
        .map(|rows| rows.filter_map(|r| r.ok()).collect())
        .unwrap_or_default()
    }; // conn lock released here

    context.events.send_memory_update(entries);
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
        // Log the memory operation
        self.context.events.send_feed(
            &self.context.agent_name,
            &format!("Storing '{}' in memory", args.key),
            false,
        );

        let conn = self.context.conn.lock().await;
        conn.execute(
            "INSERT INTO scratch_pad (key, value, created_at, updated_at)
             VALUES (?1, ?2, datetime('now'), datetime('now'))
             ON CONFLICT(key) DO UPDATE SET value = ?2, updated_at = datetime('now')",
            [&args.key, &args.value],
        )
        .map_err(|e| MemoryToolError::Database(e.to_string()))?;

        drop(conn); // Release lock before broadcast
        broadcast_memory_update(&self.context).await;

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
        // Log the memory operation
        self.context.events.send_feed(
            &self.context.agent_name,
            &format!("Reading '{}' from memory", args.key),
            false,
        );

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
        // Log the memory operation
        let msg = match &args.prefix {
            Some(prefix) => format!("Listing memory keys with prefix '{}'", prefix),
            None => "Listing all memory keys".to_string(),
        };
        self.context
            .events
            .send_feed(&self.context.agent_name, &msg, false);

        let conn = self.context.conn.lock().await;

        let keys: Vec<String> = match &args.prefix {
            Some(prefix) => {
                // Escape SQL LIKE special characters to prevent pattern injection
                let escaped = prefix
                    .replace('\\', "\\\\")
                    .replace('%', "\\%")
                    .replace('_', "\\_");
                let pattern = format!("{}%", escaped);
                let mut stmt = conn
                    .prepare(
                        "SELECT key FROM scratch_pad WHERE key LIKE ?1 ESCAPE '\\' ORDER BY key",
                    )
                    .map_err(|e| MemoryToolError::Database(e.to_string()))?;
                let rows = stmt
                    .query_map([pattern], |row| row.get(0))
                    .map_err(|e| MemoryToolError::Database(e.to_string()))?;
                rows.filter_map(|r| r.ok()).collect()
            }
            None => {
                let mut stmt = conn
                    .prepare("SELECT key FROM scratch_pad ORDER BY key")
                    .map_err(|e| MemoryToolError::Database(e.to_string()))?;
                let rows = stmt
                    .query_map([], |row| row.get(0))
                    .map_err(|e| MemoryToolError::Database(e.to_string()))?;
                rows.filter_map(|r| r.ok()).collect()
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
        // Log the memory operation
        self.context.events.send_feed(
            &self.context.agent_name,
            &format!("Removing '{}' from memory", args.key),
            false,
        );

        let conn = self.context.conn.lock().await;
        let rows_affected = conn
            .execute("DELETE FROM scratch_pad WHERE key = ?1", [&args.key])
            .map_err(|e| MemoryToolError::Database(e.to_string()))?;

        drop(conn); // Release lock before broadcast
        broadcast_memory_update(&self.context).await;

        Ok(MemoryRemoveOutput {
            removed: rows_affected > 0,
            key: args.key,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::agents::{AgentStatus, EngagementPhase};
    use crate::state::{run_migrations, Severity};
    use crate::tools::orchestrator::AgentSummary;

    /// No-op event sender for tests
    struct NoopEventSender;

    impl EventSender for NoopEventSender {
        fn send_feed(&self, _agent: &str, _message: &str, _is_error: bool) {}
        fn send_feed_with_output(
            &self,
            _agent: &str,
            _message: &str,
            _is_error: bool,
            _output: &str,
        ) {
        }
        fn send_status(
            &self,
            _agent: &str,
            _agent_type: &str,
            _status: AgentStatus,
            _current_tool: Option<String>,
        ) {
        }
        fn send_metrics(
            &self,
            _input_tokens: u64,
            _output_tokens: u64,
            _cache_read_tokens: u64,
            _cost_usd: f64,
            _tool_calls: u64,
        ) {
        }
        fn send_vulnerability(&self, _severity: Severity, _title: &str) {}
        fn send_thinking(&self, _agent: &str, _content: Option<String>) {}
        fn send_phase(&self, _phase: EngagementPhase) {}
        fn send_summary(&self, _agent: &str, _summary: &AgentSummary) {}
        fn send_memory_update(&self, _entries: Vec<crate::tools::MemoryEntryData>) {}
    }

    fn setup_context() -> Arc<MemoryContext> {
        let conn = Connection::open_in_memory().expect("should open in-memory db");
        run_migrations(&conn).expect("migrations should succeed");
        Arc::new(MemoryContext {
            conn: Arc::new(Mutex::new(conn)),
            events: Arc::new(NoopEventSender),
            agent_name: "test".to_string(),
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
            .expect("should add memory");
        assert!(result.stored);

        // Get it back
        let result = get_tool
            .call(MemoryGetArgs {
                key: "test-key".to_string(),
            })
            .await
            .expect("should get memory");
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
            .expect("should get memory");
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
            .expect("should add memory 1");
        add_tool
            .call(MemoryAddArgs {
                key: "recon-ports".to_string(),
                value: "80, 443".to_string(),
            })
            .await
            .expect("should add memory 2");
        add_tool
            .call(MemoryAddArgs {
                key: "scanner-results".to_string(),
                value: "vulns found".to_string(),
            })
            .await
            .expect("should add memory 3");

        // List all
        let result = list_tool
            .call(MemoryListArgs { prefix: None })
            .await
            .expect("should list all memory");
        assert_eq!(result.keys.len(), 3);

        // List with prefix
        let result = list_tool
            .call(MemoryListArgs {
                prefix: Some("recon-".to_string()),
            })
            .await
            .expect("should list memory with prefix");
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
            .expect("should add memory");

        let result = remove_tool
            .call(MemoryRemoveArgs {
                key: "to-remove".to_string(),
            })
            .await
            .expect("should remove memory");
        assert!(result.removed);

        // Verify it's gone
        let result = get_tool
            .call(MemoryGetArgs {
                key: "to-remove".to_string(),
            })
            .await
            .expect("should get memory after removal");
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
            .expect("should add initial value");

        // Update with same key
        add_tool
            .call(MemoryAddArgs {
                key: "key".to_string(),
                value: "value2".to_string(),
            })
            .await
            .expect("should update value");

        // Should have new value
        let result = get_tool
            .call(MemoryGetArgs {
                key: "key".to_string(),
            })
            .await
            .expect("should get updated value");
        assert_eq!(result.value, Some("value2".to_string()));
    }
}
