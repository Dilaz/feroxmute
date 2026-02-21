//! MCP wrapper for vulnerability playbook lookup

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;

use crate::Result;
use crate::mcp::{McpTool, McpToolResult};
use crate::tools::playbook;

/// MCP wrapper for retrieving vulnerability testing playbooks
#[derive(Default)]
pub struct McpGetPlaybookTool;

#[derive(Debug, Deserialize)]
struct GetPlaybookArgs {
    category: String,
}

impl McpGetPlaybookTool {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl McpTool for McpGetPlaybookTool {
    fn name(&self) -> &str {
        "get_playbook"
    }

    fn description(&self) -> &str {
        "Retrieve detailed vulnerability testing playbook for a specific category. Returns techniques, tools, payloads, and bypass methods. ALWAYS fetch relevant playbooks before starting vulnerability testing."
    }

    fn input_schema(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "category": {
                    "type": "string",
                    "description": "Vulnerability category: sql-injection, xss, csrf, command-injection, jwt-attacks, xxe, lfi-rfi, ssti, ssrf, deserialization, race-conditions, nosql-injection, graphql, websockets, windows-web, windows-ad, crypto"
                }
            },
            "required": ["category"]
        })
    }

    async fn execute(&self, arguments: Value) -> Result<McpToolResult> {
        let args: GetPlaybookArgs = serde_json::from_value(arguments)?;

        match playbook::get_playbook(&args.category) {
            Some(content) => Ok(McpToolResult::text(format!(
                "# Playbook: {}\n\n{}",
                args.category, content
            ))),
            None => Ok(McpToolResult::error(format!(
                "Unknown playbook category '{}'. Available: {}",
                args.category,
                playbook::PLAYBOOK_CATEGORIES.join(", ")
            ))),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_get_playbook_valid() {
        let tool = McpGetPlaybookTool::new();
        let result = tool
            .execute(serde_json::json!({"category": "sql-injection"}))
            .await
            .unwrap();

        let content = result.content.unwrap();
        let text = match &content[0] {
            crate::mcp::McpContent::Text { text } => text,
        };
        assert!(text.contains("Playbook: sql-injection"));
        assert!(text.contains("SQL"));
        assert_eq!(result.is_error, None);
    }

    #[tokio::test]
    async fn test_get_playbook_invalid() {
        let tool = McpGetPlaybookTool::new();
        let result = tool
            .execute(serde_json::json!({"category": "nonexistent"}))
            .await
            .unwrap();

        assert_eq!(result.is_error, Some(true));
        let content = result.content.unwrap();
        let text = match &content[0] {
            crate::mcp::McpContent::Text { text } => text,
        };
        assert!(text.contains("Unknown playbook category"));
        assert!(text.contains("sql-injection")); // lists available categories
    }
}
