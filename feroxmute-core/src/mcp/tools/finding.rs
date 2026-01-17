//! MCP wrapper for recording security findings

use std::sync::Arc;

use async_trait::async_trait;
use rusqlite::Connection;
use serde::Deserialize;
use serde_json::Value;
use tokio::sync::Mutex;

use crate::Result;
use crate::mcp::{McpTool, McpToolResult};
use crate::state::{Severity, Vulnerability};
use crate::tools::EventSender;

/// Context for the record finding tool
pub struct FindingContext {
    pub conn: Arc<Mutex<Connection>>,
    pub events: Arc<dyn EventSender>,
    pub agent_name: String,
}

/// MCP wrapper for recording security findings
pub struct McpRecordFindingTool {
    context: Arc<FindingContext>,
}

#[derive(Debug, Deserialize)]
struct RecordFindingArgs {
    title: String,
    description: String,
    severity: String,
    #[serde(default)]
    affected_asset: Option<String>,
    #[serde(default)]
    evidence: Option<String>,
    #[serde(default)]
    recommendation: Option<String>,
}

impl McpRecordFindingTool {
    pub fn new(context: Arc<FindingContext>) -> Self {
        Self { context }
    }
}

/// Parse a severity string into a Severity enum
fn parse_severity(s: &str) -> Option<Severity> {
    match s.to_lowercase().as_str() {
        "critical" => Some(Severity::Critical),
        "high" => Some(Severity::High),
        "medium" => Some(Severity::Medium),
        "low" => Some(Severity::Low),
        "info" | "informational" => Some(Severity::Info),
        _ => None,
    }
}

#[async_trait]
impl McpTool for McpRecordFindingTool {
    fn name(&self) -> &str {
        "record_finding"
    }

    fn description(&self) -> &str {
        "Record a security finding discovered during the engagement. Use this to document vulnerabilities, misconfigurations, or security issues."
    }

    fn input_schema(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "title": {
                    "type": "string",
                    "description": "Short descriptive title of the finding"
                },
                "description": {
                    "type": "string",
                    "description": "Detailed description of the vulnerability or issue"
                },
                "severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low", "info"],
                    "description": "Severity level of the finding"
                },
                "affected_asset": {
                    "type": "string",
                    "description": "The affected URL, IP, port, or resource (optional)"
                },
                "evidence": {
                    "type": "string",
                    "description": "Proof or evidence of the vulnerability (optional)"
                },
                "recommendation": {
                    "type": "string",
                    "description": "Suggested remediation steps (optional)"
                }
            },
            "required": ["title", "description", "severity"]
        })
    }

    async fn execute(&self, arguments: Value) -> Result<McpToolResult> {
        let args: RecordFindingArgs = serde_json::from_value(arguments).map_err(|e| {
            crate::Error::Provider(format!("Invalid record_finding arguments: {e}"))
        })?;

        // Parse and validate severity
        let severity = match parse_severity(&args.severity) {
            Some(s) => s,
            None => {
                return Ok(McpToolResult::error(format!(
                    "Invalid severity '{}'. Must be one of: critical, high, medium, low, info",
                    args.severity
                )));
            }
        };

        // Notify TUI
        self.context.events.send_feed(
            &self.context.agent_name,
            &format!("Recording finding: {} [{}]", args.title, severity),
            false,
        );
        self.context.events.send_tool_call();

        // Create vulnerability record
        let mut vuln = Vulnerability::new(
            &args.title,
            "mcp_finding", // vuln_type
            severity,
            &self.context.agent_name,
        )
        .with_description(&args.description);

        if let Some(ref asset) = args.affected_asset {
            vuln = vuln.with_asset(asset);
        }

        if let Some(ref evidence) = args.evidence {
            vuln = vuln.with_evidence(evidence);
        }

        if let Some(ref recommendation) = args.recommendation {
            vuln = vuln.with_remediation(recommendation);
        }

        // Store in database
        let vuln_id = vuln.id.clone();
        let conn = self.context.conn.lock().await;
        vuln.insert(&conn)
            .map_err(|e| crate::Error::Provider(format!("Database error: {e}")))?;

        // Send vulnerability event to TUI
        self.context
            .events
            .send_vulnerability(severity, &args.title);

        Ok(McpToolResult::text(
            serde_json::json!({
                "recorded": true,
                "finding_id": vuln_id,
                "title": args.title,
                "severity": args.severity
            })
            .to_string(),
        ))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::agents::{AgentStatus, EngagementPhase};
    use crate::state::models::FindingType;
    use crate::state::run_migrations;
    use crate::tools::MemoryEntryData;
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
        fn send_memory_update(&self, _entries: Vec<MemoryEntryData>) {}
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

    fn setup_context() -> Arc<FindingContext> {
        let conn = Connection::open_in_memory().expect("should open in-memory db");
        run_migrations(&conn).expect("migrations should succeed");
        Arc::new(FindingContext {
            conn: Arc::new(Mutex::new(conn)),
            events: Arc::new(NoopEventSender),
            agent_name: "test-agent".to_string(),
        })
    }

    #[tokio::test]
    async fn test_record_valid_finding() {
        let context = setup_context();
        let tool = McpRecordFindingTool::new(Arc::clone(&context));

        let result = tool
            .execute(serde_json::json!({
                "title": "SQL Injection in login form",
                "description": "The login form is vulnerable to SQL injection via the username field",
                "severity": "critical",
                "affected_asset": "https://example.com/login",
                "evidence": "Payload: ' OR '1'='1",
                "recommendation": "Use parameterized queries"
            }))
            .await
            .expect("should record finding");

        let content = result.content.expect("should have content");
        let text = match &content[0] {
            crate::mcp::McpContent::Text { text } => text,
        };
        let parsed: serde_json::Value = serde_json::from_str(text).expect("should parse JSON");

        assert_eq!(parsed["recorded"], true);
        assert_eq!(parsed["title"], "SQL Injection in login form");
        assert_eq!(parsed["severity"], "critical");
        assert!(
            parsed["finding_id"]
                .as_str()
                .is_some_and(|id| id.starts_with("VULN-"))
        );

        // Verify it was stored in the database
        let conn = context.conn.lock().await;
        let vulns = Vulnerability::all(&conn).expect("should query vulnerabilities");
        assert_eq!(vulns.len(), 1);
        let vuln = &vulns[0];
        assert_eq!(vuln.title, "SQL Injection in login form");
        assert_eq!(vuln.severity, Severity::Critical);
        assert_eq!(vuln.asset, Some("https://example.com/login".to_string()));
    }

    #[tokio::test]
    async fn test_record_finding_invalid_severity() {
        let context = setup_context();
        let tool = McpRecordFindingTool::new(context);

        let result = tool
            .execute(serde_json::json!({
                "title": "Test finding",
                "description": "Test description",
                "severity": "super_critical"
            }))
            .await
            .expect("should return error result");

        assert_eq!(result.is_error, Some(true));
        let content = result.content.expect("should have content");
        let text = match &content[0] {
            crate::mcp::McpContent::Text { text } => text,
        };
        assert!(text.contains("Invalid severity"));
        assert!(text.contains("super_critical"));
    }
}
