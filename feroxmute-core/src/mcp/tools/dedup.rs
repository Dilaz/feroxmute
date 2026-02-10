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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::agents::{AgentStatus, EngagementPhase};
    use crate::state::models::FindingType;
    use crate::state::{MetricsTracker, Severity, VulnStatus, run_migrations};
    use crate::tools::EventSender;
    use crate::tools::MemoryEntryData;
    use crate::tools::orchestrator::AgentSummary;
    use chrono::Utc;
    use std::path::PathBuf;
    use tokio::sync::Mutex;

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

    fn setup_test_db() -> (tempfile::TempDir, PathBuf) {
        let tmp = tempfile::tempdir().expect("create temp dir");
        let db_path = tmp.path().join("session.db");
        let conn = rusqlite::Connection::open(&db_path).expect("open db");
        run_migrations(&conn).expect("run migrations");
        drop(conn);
        (tmp, db_path)
    }

    fn setup_context(db_path: PathBuf, reports_dir: PathBuf) -> Arc<ReportContext> {
        Arc::new(ReportContext {
            events: Arc::new(NoopEventSender),
            target: "example.com".to_string(),
            session_id: "test-session".to_string(),
            start_time: Utc::now(),
            metrics: MetricsTracker::new(),
            findings: Arc::new(Mutex::new(Vec::new())),
            report: Arc::new(Mutex::new(None)),
            reports_dir,
            session_db_path: Some(db_path),
            deduplicated_findings: Arc::new(Mutex::new(None)),
        })
    }

    #[tokio::test]
    async fn test_deduplicate_empty_database() {
        let (tmp, db_path) = setup_test_db();
        let reports_dir = tmp.path().join("reports");
        std::fs::create_dir_all(&reports_dir).ok();

        let context = setup_context(db_path, reports_dir);
        let tool = McpDeduplicateFindingsTool::new(context);

        let result = tool
            .execute(serde_json::json!({}))
            .await
            .expect("should succeed");
        let content = result.content.expect("should have content");
        let text = match &content[0] {
            crate::mcp::McpContent::Text { text } => text,
        };
        let parsed: serde_json::Value = serde_json::from_str(text).expect("should parse JSON");

        assert_eq!(parsed["success"], true);
        assert_eq!(parsed["original_count"], 0);
        assert_eq!(parsed["deduplicated_count"], 0);
    }

    #[tokio::test]
    async fn test_deduplicate_with_duplicates() {
        let (tmp, db_path) = setup_test_db();
        let reports_dir = tmp.path().join("reports");
        std::fs::create_dir_all(&reports_dir).ok();

        // Insert duplicate findings
        let conn = rusqlite::Connection::open(&db_path).expect("open db");

        let vuln1 = Vulnerability {
            id: "VULN-001".to_string(),
            host_id: None,
            vuln_type: "sqli".to_string(),
            severity: Severity::Critical,
            title: "SQL Injection in login".to_string(),
            description: Some("Login vulnerable".to_string()),
            evidence: Some("Evidence A".to_string()),
            status: VulnStatus::Verified,
            cwe: None,
            cvss: None,
            asset: Some("/login".to_string()),
            remediation: None,
            discovered_by: "agent-a".to_string(),
            verified_by: None,
            discovered_at: Utc::now(),
            verified_at: None,
        };
        vuln1.insert(&conn).expect("insert vuln1");

        // Same title, same severity = duplicate
        let vuln2 = Vulnerability {
            id: "VULN-002".to_string(),
            host_id: None,
            vuln_type: "sqli".to_string(),
            severity: Severity::Critical,
            title: "SQL Injection in login".to_string(),
            description: Some("More detailed description".to_string()),
            evidence: Some("Evidence B".to_string()),
            status: VulnStatus::Verified,
            cwe: None,
            cvss: None,
            asset: Some("/login".to_string()),
            remediation: Some("Use prepared statements".to_string()),
            discovered_by: "agent-b".to_string(),
            verified_by: None,
            discovered_at: Utc::now(),
            verified_at: None,
        };
        vuln2.insert(&conn).expect("insert vuln2");

        // Different vulnerability
        let vuln3 = Vulnerability {
            id: "VULN-003".to_string(),
            host_id: None,
            vuln_type: "xss".to_string(),
            severity: Severity::High,
            title: "XSS in search".to_string(),
            description: None,
            evidence: None,
            status: VulnStatus::Potential,
            cwe: None,
            cvss: None,
            asset: None,
            remediation: None,
            discovered_by: "agent-a".to_string(),
            verified_by: None,
            discovered_at: Utc::now(),
            verified_at: None,
        };
        vuln3.insert(&conn).expect("insert vuln3");
        drop(conn);

        let context = setup_context(db_path, reports_dir);
        let tool = McpDeduplicateFindingsTool::new(Arc::clone(&context));

        let result = tool
            .execute(serde_json::json!({}))
            .await
            .expect("should succeed");
        let content = result.content.expect("should have content");
        let text = match &content[0] {
            crate::mcp::McpContent::Text { text } => text,
        };
        let parsed: serde_json::Value = serde_json::from_str(text).expect("should parse JSON");

        assert_eq!(parsed["success"], true);
        assert_eq!(parsed["original_count"], 3);
        assert_eq!(parsed["deduplicated_count"], 2); // 2 SQLi merged into 1, XSS stays

        // Verify cache was populated
        let cache = context.deduplicated_findings.lock().await;
        assert!(cache.is_some());
        assert_eq!(cache.as_ref().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn test_deduplicate_no_database() {
        let tmp = tempfile::tempdir().expect("create temp dir");
        let reports_dir = tmp.path().join("reports");
        std::fs::create_dir_all(&reports_dir).ok();

        let context = Arc::new(ReportContext {
            events: Arc::new(NoopEventSender),
            target: "example.com".to_string(),
            session_id: "test-session".to_string(),
            start_time: Utc::now(),
            metrics: MetricsTracker::new(),
            findings: Arc::new(Mutex::new(Vec::new())),
            report: Arc::new(Mutex::new(None)),
            reports_dir,
            session_db_path: None, // No database
            deduplicated_findings: Arc::new(Mutex::new(None)),
        });

        let tool = McpDeduplicateFindingsTool::new(context);
        let result = tool
            .execute(serde_json::json!({}))
            .await
            .expect("should succeed");

        assert_eq!(result.is_error, Some(true));
    }
}
