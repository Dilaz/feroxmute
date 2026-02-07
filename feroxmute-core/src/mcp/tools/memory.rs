//! MCP wrappers for memory/scratchpad tools

use std::sync::Arc;

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;

use crate::Result;
use crate::mcp::{McpTool, McpToolResult};
use crate::tools::MemoryContext;

// ============================================================================
// McpMemoryAddTool
// ============================================================================

/// MCP wrapper for adding key-value pairs to memory
pub struct McpMemoryAddTool {
    context: Arc<MemoryContext>,
}

#[derive(Debug, Deserialize)]
struct MemoryAddArgs {
    key: String,
    value: String,
}

impl McpMemoryAddTool {
    pub fn new(context: Arc<MemoryContext>) -> Self {
        Self { context }
    }
}

#[async_trait]
impl McpTool for McpMemoryAddTool {
    fn name(&self) -> &str {
        "memory_add"
    }

    fn description(&self) -> &str {
        "Store or update a key-value pair in the scratch pad for later reference."
    }

    fn input_schema(&self) -> Value {
        serde_json::json!({
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
        })
    }

    async fn execute(&self, arguments: Value) -> Result<McpToolResult> {
        let args: MemoryAddArgs = serde_json::from_value(arguments)
            .map_err(|e| crate::Error::Provider(format!("Invalid memory_add arguments: {e}")))?;

        // Notify TUI
        self.context.events.send_feed(
            &self.context.agent_name,
            &format!("Storing '{}' in memory", args.key),
            false,
        );
        self.context.events.send_tool_call();

        // Store the value
        let conn = self.context.conn.lock().await;
        conn.execute(
            "INSERT INTO scratch_pad (key, value, created_at, updated_at)
             VALUES (?1, ?2, datetime('now'), datetime('now'))
             ON CONFLICT(key) DO UPDATE SET value = ?2, updated_at = datetime('now')",
            [&args.key, &args.value],
        )
        .map_err(|e| crate::Error::Provider(format!("Database error: {e}")))?;

        drop(conn);
        broadcast_memory_update(&self.context).await;

        Ok(McpToolResult::text(
            serde_json::json!({
                "stored": true,
                "key": args.key
            })
            .to_string(),
        ))
    }
}

// ============================================================================
// McpMemoryGetTool
// ============================================================================

/// MCP wrapper for retrieving values from memory by key
pub struct McpMemoryGetTool {
    context: Arc<MemoryContext>,
}

#[derive(Debug, Deserialize)]
struct MemoryGetArgs {
    key: String,
}

impl McpMemoryGetTool {
    pub fn new(context: Arc<MemoryContext>) -> Self {
        Self { context }
    }
}

#[async_trait]
impl McpTool for McpMemoryGetTool {
    fn name(&self) -> &str {
        "memory_get"
    }

    fn description(&self) -> &str {
        "Retrieve a value from the scratch pad by its key."
    }

    fn input_schema(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "key": {
                    "type": "string",
                    "description": "The key to look up"
                }
            },
            "required": ["key"]
        })
    }

    async fn execute(&self, arguments: Value) -> Result<McpToolResult> {
        let args: MemoryGetArgs = serde_json::from_value(arguments)
            .map_err(|e| crate::Error::Provider(format!("Invalid memory_get arguments: {e}")))?;

        // Notify TUI
        self.context.events.send_feed(
            &self.context.agent_name,
            &format!("Reading '{}' from memory", args.key),
            false,
        );
        self.context.events.send_tool_call();

        let conn = self.context.conn.lock().await;
        let result: std::result::Result<String, _> = conn.query_row(
            "SELECT value FROM scratch_pad WHERE key = ?1",
            [&args.key],
            |row| row.get(0),
        );

        match result {
            Ok(value) => Ok(McpToolResult::text(
                serde_json::json!({
                    "found": true,
                    "key": args.key,
                    "value": value
                })
                .to_string(),
            )),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(McpToolResult::text(
                serde_json::json!({
                    "found": false,
                    "key": args.key,
                    "value": null
                })
                .to_string(),
            )),
            Err(e) => Err(crate::Error::Provider(format!("Database error: {e}"))),
        }
    }
}

// ============================================================================
// McpMemoryListTool
// ============================================================================

/// MCP wrapper for listing all memory entries
pub struct McpMemoryListTool {
    context: Arc<MemoryContext>,
}

#[derive(Debug, Deserialize)]
struct MemoryListArgs {
    #[serde(default)]
    prefix: Option<String>,
}

impl McpMemoryListTool {
    pub fn new(context: Arc<MemoryContext>) -> Self {
        Self { context }
    }
}

#[async_trait]
impl McpTool for McpMemoryListTool {
    fn name(&self) -> &str {
        "memory_list"
    }

    fn description(&self) -> &str {
        "List all keys in the scratch pad, optionally filtered by prefix."
    }

    fn input_schema(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "prefix": {
                    "type": "string",
                    "description": "Optional prefix to filter keys (e.g., 'recon-' to list all recon-related entries)"
                }
            }
        })
    }

    async fn execute(&self, arguments: Value) -> Result<McpToolResult> {
        let args: MemoryListArgs = serde_json::from_value(arguments)
            .map_err(|e| crate::Error::Provider(format!("Invalid memory_list arguments: {e}")))?;

        // Notify TUI
        let msg = match &args.prefix {
            Some(prefix) => format!("Listing memory keys with prefix '{}'", prefix),
            None => "Listing all memory keys".to_string(),
        };
        self.context
            .events
            .send_feed(&self.context.agent_name, &msg, false);
        self.context.events.send_tool_call();

        let conn = self.context.conn.lock().await;

        let keys: Vec<String> = match &args.prefix {
            Some(prefix) => {
                // Escape SQL LIKE special characters
                let escaped = prefix
                    .replace('\\', "\\\\")
                    .replace('%', "\\%")
                    .replace('_', "\\_");
                let pattern = format!("{}%", escaped);
                let mut stmt = conn
                    .prepare(
                        "SELECT key FROM scratch_pad WHERE key LIKE ?1 ESCAPE '\\' ORDER BY key",
                    )
                    .map_err(|e| crate::Error::Provider(format!("Database error: {e}")))?;
                let rows = stmt
                    .query_map([pattern], |row| row.get(0))
                    .map_err(|e| crate::Error::Provider(format!("Database error: {e}")))?;
                rows.filter_map(|r| r.ok()).collect()
            }
            None => {
                let mut stmt = conn
                    .prepare("SELECT key FROM scratch_pad ORDER BY key")
                    .map_err(|e| crate::Error::Provider(format!("Database error: {e}")))?;
                let rows = stmt
                    .query_map([], |row| row.get(0))
                    .map_err(|e| crate::Error::Provider(format!("Database error: {e}")))?;
                rows.filter_map(|r| r.ok()).collect()
            }
        };

        Ok(McpToolResult::text(
            serde_json::json!({
                "keys": keys
            })
            .to_string(),
        ))
    }
}

// ============================================================================
// Helper functions
// ============================================================================

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
            Ok(crate::tools::MemoryEntryData {
                key: row.get(0)?,
                value: row.get(1)?,
                created_at: row.get(2)?,
                updated_at: row.get(3)?,
            })
        })
        .ok()
        .map(|rows| rows.filter_map(|r| r.ok()).collect())
        .unwrap_or_default()
    };

    context.events.send_memory_update(entries);
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::agents::{AgentStatus, EngagementPhase};
    use crate::state::models::FindingType;
    use crate::state::{Severity, run_migrations};
    use crate::tools::EventSender;
    use crate::tools::orchestrator::AgentSummary;
    use rusqlite::Connection;
    use tokio::sync::Mutex;

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
        fn send_code_finding(
            &self,
            _agent: &str,
            _file_path: &str,
            _line_number: Option<u32>,
            _severity: Severity,
            _finding_type: FindingType,
            _title: &str,
            _tool: &str,
            _cve_id: Option<&str>,
            _package_name: Option<&str>,
        ) {
        }
        fn send_tool_call(&self) {}
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
    async fn test_mcp_memory_add_and_get() {
        let context = setup_context();
        let add_tool = McpMemoryAddTool::new(Arc::clone(&context));
        let get_tool = McpMemoryGetTool::new(Arc::clone(&context));

        // Add a value
        let result = add_tool
            .execute(serde_json::json!({
                "key": "test-key",
                "value": "test-value"
            }))
            .await
            .expect("should add memory");

        let content = result.content.expect("should have content");
        let text = match &content[0] {
            crate::mcp::McpContent::Text { text } => text,
        };
        let parsed: serde_json::Value = serde_json::from_str(text).expect("should parse JSON");
        assert_eq!(parsed["stored"], true);

        // Get it back
        let result = get_tool
            .execute(serde_json::json!({
                "key": "test-key"
            }))
            .await
            .expect("should get memory");

        let content = result.content.expect("should have content");
        let text = match &content[0] {
            crate::mcp::McpContent::Text { text } => text,
        };
        let parsed: serde_json::Value = serde_json::from_str(text).expect("should parse JSON");
        assert_eq!(parsed["found"], true);
        assert_eq!(parsed["value"], "test-value");
    }

    #[tokio::test]
    async fn test_mcp_memory_list() {
        let context = setup_context();
        let add_tool = McpMemoryAddTool::new(Arc::clone(&context));
        let list_tool = McpMemoryListTool::new(Arc::clone(&context));

        // Add some values
        add_tool
            .execute(serde_json::json!({
                "key": "recon-subdomains",
                "value": "a.com, b.com"
            }))
            .await
            .expect("should add memory 1");
        add_tool
            .execute(serde_json::json!({
                "key": "recon-ports",
                "value": "80, 443"
            }))
            .await
            .expect("should add memory 2");
        add_tool
            .execute(serde_json::json!({
                "key": "scanner-results",
                "value": "vulns found"
            }))
            .await
            .expect("should add memory 3");

        // List all
        let result = list_tool
            .execute(serde_json::json!({}))
            .await
            .expect("should list all memory");

        let content = result.content.expect("should have content");
        let text = match &content[0] {
            crate::mcp::McpContent::Text { text } => text,
        };
        let parsed: serde_json::Value = serde_json::from_str(text).expect("should parse JSON");
        let keys = parsed["keys"].as_array().expect("should have keys array");
        assert_eq!(keys.len(), 3);

        // List with prefix
        let result = list_tool
            .execute(serde_json::json!({
                "prefix": "recon-"
            }))
            .await
            .expect("should list memory with prefix");

        let content = result.content.expect("should have content");
        let text = match &content[0] {
            crate::mcp::McpContent::Text { text } => text,
        };
        let parsed: serde_json::Value = serde_json::from_str(text).expect("should parse JSON");
        let keys = parsed["keys"].as_array().expect("should have keys array");
        assert_eq!(keys.len(), 2);
        assert!(keys.iter().any(|k| k == "recon-subdomains"));
        assert!(keys.iter().any(|k| k == "recon-ports"));
    }
}
