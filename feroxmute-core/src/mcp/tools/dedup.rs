//! MCP wrapper for LLM-based finding deduplication

use std::sync::Arc;

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;

use crate::Result;
use crate::mcp::{McpTool, McpToolResult};
use crate::state::Vulnerability;
use crate::tools::report::ReportContext;

/// MCP wrapper for deduplicating findings using LLM-extracted canonical keys
pub struct McpDeduplicateFindingsTool {
    context: Arc<ReportContext>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct DeduplicateFindingsArgs {
    // No required inputs - operates on current session's findings
}

impl McpDeduplicateFindingsTool {
    pub fn new(context: Arc<ReportContext>) -> Self {
        Self { context }
    }
}

#[async_trait]
impl McpTool for McpDeduplicateFindingsTool {
    fn name(&self) -> &str {
        "deduplicate_findings"
    }

    fn description(&self) -> &str {
        "Deduplicate findings by extracting canonical vulnerability identifiers using LLM. Call this BEFORE generate_report to merge semantically similar vulnerabilities."
    }

    fn input_schema(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {},
            "required": []
        })
    }

    async fn execute(&self, _arguments: Value) -> Result<McpToolResult> {
        self.context.events.send_tool_call();
        self.context
            .events
            .send_feed("report", "Deduplicating findings...", false);

        // Load findings from database
        let db_path = match &self.context.session_db_path {
            Some(p) => p,
            None => {
                return Ok(McpToolResult::error(
                    "No session database available for deduplication",
                ));
            }
        };

        let conn = match rusqlite::Connection::open(db_path) {
            Ok(c) => c,
            Err(e) => {
                return Ok(McpToolResult::error(format!(
                    "Failed to open session database: {}",
                    e
                )));
            }
        };

        let vulns = match Vulnerability::all(&conn) {
            Ok(v) => v,
            Err(e) => {
                return Ok(McpToolResult::error(format!(
                    "Failed to load vulnerabilities: {}",
                    e
                )));
            }
        };

        if vulns.is_empty() {
            return Ok(McpToolResult::text(
                serde_json::json!({
                    "success": true,
                    "message": "No findings to deduplicate",
                    "original_count": 0,
                    "deduplicated_count": 0
                })
                .to_string(),
            ));
        }

        let original_count = vulns.len();

        // For now, use the existing exact-match deduplication as placeholder
        // The LLM-based deduplication will be added later
        let deduped = crate::reports::deduplicate_vulnerabilities(vulns);
        let deduped_count = deduped.len();

        // Store in context for generate_report to use
        let mut cache = self.context.deduplicated_findings.lock().await;
        *cache = Some(deduped);

        self.context.events.send_feed(
            "report",
            &format!(
                "Deduplicated {} findings into {} unique vulnerabilities",
                original_count, deduped_count
            ),
            false,
        );

        Ok(McpToolResult::text(
            serde_json::json!({
                "success": true,
                "message": format!(
                    "Deduplicated {} findings into {} unique vulnerabilities",
                    original_count, deduped_count
                ),
                "original_count": original_count,
                "deduplicated_count": deduped_count
            })
            .to_string(),
        ))
    }
}
