//! MCP wrappers for report generation and export tools

use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use serde::Deserialize;
use serde_json::Value;

use crate::Result;
use crate::mcp::{McpTool, McpToolResult};
use crate::reports::{
    Finding, Report, ReportMetadata, ReportMetrics, ReportSummary, RiskRating, SeverityCounts,
    StatusCounts, export_html, export_json, export_markdown, export_pdf, generate_report,
};
use crate::tools::report::ReportContext;

// ============================================================================
// Shared export helper
// ============================================================================

/// Common logic for all export tools: validate filename, get report, call exporter.
async fn export_with<F>(
    context: &ReportContext,
    filename: &str,
    default_name: &str,
    format_name: &str,
    export_fn: F,
) -> Result<McpToolResult>
where
    F: FnOnce(&Report, &Path) -> crate::Result<()>,
{
    context.events.send_tool_call();

    let report_lock = context.report.lock().await;
    let report = match report_lock.as_ref() {
        Some(r) => r,
        None => {
            return Ok(McpToolResult::error(
                "No report generated yet. Call generate_report first.",
            ));
        }
    };

    // Use the provided filename or fall back to the default
    let raw_name = if filename.is_empty() {
        default_name
    } else {
        filename
    };

    // Path traversal prevention: strip directory components
    let safe_name = match Path::new(raw_name).file_name() {
        Some(name) => name,
        None => {
            return Ok(McpToolResult::error(
                "Invalid filename: must not contain path separators",
            ));
        }
    };

    let path = context.reports_dir.join(safe_name);
    let path_str = path.display().to_string();

    context.events.send_feed(
        "report",
        &format!("Exporting to {}: {}", format_name, path_str),
        false,
    );

    if let Err(e) = export_fn(report, &path) {
        return Ok(McpToolResult::error(format!(
            "{} export failed: {}",
            format_name, e
        )));
    }

    context.events.send_feed(
        "report",
        &format!("{} report exported to {}", format_name, path_str),
        false,
    );

    Ok(McpToolResult::text(
        serde_json::json!({
            "success": true,
            "path": path_str
        })
        .to_string(),
    ))
}

// ============================================================================
// McpGenerateReportTool
// ============================================================================

/// MCP wrapper for generating the penetration testing report
pub struct McpGenerateReportTool {
    context: Arc<ReportContext>,
}

#[derive(Debug, Deserialize)]
struct GenerateReportArgs {
    #[serde(default)]
    executive_summary: Option<String>,
    #[serde(default)]
    key_findings: Option<Vec<String>>,
}

impl McpGenerateReportTool {
    pub fn new(context: Arc<ReportContext>) -> Self {
        Self { context }
    }

    /// Fallback: build a report from the in-memory findings Vec
    async fn build_report_from_memory(&self, end_time: chrono::DateTime<Utc>) -> Report {
        let findings_strings = self.context.findings.lock().await;

        // Convert string findings to Finding structs
        // Format: "[severity] title: description"
        let findings: Vec<Finding> = findings_strings
            .iter()
            .map(|s| {
                let (severity, rest) = if s.starts_with('[') {
                    if let Some(end) = s.find(']') {
                        let sev = s.get(1..end).unwrap_or("medium").to_string();
                        let remainder = s.get(end + 2..).unwrap_or("").to_string();
                        (sev, remainder)
                    } else {
                        ("medium".to_string(), s.clone())
                    }
                } else {
                    ("medium".to_string(), s.clone())
                };

                let (title, description) = if let Some(idx) = rest.find(':') {
                    (
                        rest.get(..idx).unwrap_or("").trim().to_string(),
                        rest.get(idx + 1..).unwrap_or("").trim().to_string(),
                    )
                } else {
                    (rest, String::new())
                };

                Finding {
                    title,
                    severity,
                    affected: self.context.target.clone(),
                    description,
                    evidence: None,
                    reproduction_steps: None,
                    impact: None,
                    remediation: None,
                    references: Vec::new(),
                }
            })
            .collect();

        let finding_count = findings.len();

        let mut severity_counts = SeverityCounts::default();
        for f in &findings {
            match f.severity.to_lowercase().as_str() {
                "critical" => severity_counts.critical += 1,
                "high" => severity_counts.high += 1,
                "medium" => severity_counts.medium += 1,
                "low" => severity_counts.low += 1,
                _ => severity_counts.info += 1,
            }
        }

        let risk_rating = RiskRating::from_counts(
            severity_counts.critical,
            severity_counts.high,
            severity_counts.medium,
        );

        let metrics = self.context.metrics.snapshot();

        Report {
            metadata: ReportMetadata::new(
                &self.context.target,
                &self.context.session_id,
                self.context.start_time,
                end_time,
            ),
            summary: ReportSummary {
                total_vulnerabilities: finding_count as u32,
                by_severity: severity_counts,
                by_status: StatusCounts::default(),
                risk_rating,
                key_findings: Vec::new(),
                executive_summary: format!(
                    "Security assessment of {} completed with {} findings.",
                    self.context.target, finding_count
                ),
            },
            findings,
            metrics: ReportMetrics {
                tool_calls: metrics.tool_calls,
                input_tokens: metrics.tokens.input,
                output_tokens: metrics.tokens.output,
                cache_read_tokens: metrics.tokens.cached,
                hosts_discovered: 0,
                ports_discovered: 0,
            },
        }
    }
}

#[async_trait]
impl McpTool for McpGenerateReportTool {
    fn name(&self) -> &str {
        "generate_report"
    }

    fn description(&self) -> &str {
        "Generate the penetration testing report from collected findings. Call this before exporting to JSON, Markdown, HTML, or PDF."
    }

    fn input_schema(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "executive_summary": {
                    "type": "string",
                    "description": "Executive summary for the report"
                },
                "key_findings": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of key findings to highlight"
                }
            }
        })
    }

    async fn execute(&self, arguments: Value) -> Result<McpToolResult> {
        let args: GenerateReportArgs = serde_json::from_value(arguments).map_err(|e| {
            crate::Error::Provider(format!("Invalid generate_report arguments: {e}"))
        })?;

        self.context.events.send_tool_call();
        self.context
            .events
            .send_feed("report", "Generating report from findings...", false);

        let end_time = Utc::now();

        // Try loading findings from the database first (authoritative source),
        // falling back to the in-memory Vec for backwards compatibility
        let mut report = if let Some(ref db_path) = self.context.session_db_path {
            match rusqlite::Connection::open(db_path) {
                Ok(conn) => match generate_report(
                    &conn,
                    &self.context.target,
                    &self.context.session_id,
                    self.context.start_time,
                    end_time,
                    &self.context.metrics,
                ) {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::warn!(
                            "Failed to generate report from database: {e}, falling back to in-memory findings"
                        );
                        self.build_report_from_memory(end_time).await
                    }
                },
                Err(e) => {
                    tracing::warn!(
                        "Failed to open session database: {e}, falling back to in-memory findings"
                    );
                    self.build_report_from_memory(end_time).await
                }
            }
        } else {
            self.build_report_from_memory(end_time).await
        };

        // Override summary fields with LLM-provided content
        if let Some(summary) = args.executive_summary {
            report.summary.executive_summary = summary;
        }
        if let Some(key_findings) = args.key_findings {
            report.summary.key_findings = key_findings;
        }

        let finding_count = report.findings.len();
        let risk_rating_str = format!("{}", report.summary.risk_rating);

        // Store the report for export tools
        let mut report_lock = self.context.report.lock().await;
        *report_lock = Some(report);

        self.context.events.send_feed(
            "report",
            &format!(
                "Report generated: {} findings, {} risk",
                finding_count, risk_rating_str
            ),
            false,
        );

        Ok(McpToolResult::text(
            serde_json::json!({
                "success": true,
                "message": format!(
                    "Report generated with {} findings. Risk rating: {}",
                    finding_count, risk_rating_str
                ),
                "finding_count": finding_count,
                "risk_rating": risk_rating_str
            })
            .to_string(),
        ))
    }
}

// ============================================================================
// McpExportJsonTool
// ============================================================================

/// MCP wrapper for exporting the report to JSON format
pub struct McpExportJsonTool {
    context: Arc<ReportContext>,
}

#[derive(Debug, Deserialize)]
struct ExportJsonArgs {
    #[serde(default)]
    filename: Option<String>,
}

impl McpExportJsonTool {
    pub fn new(context: Arc<ReportContext>) -> Self {
        Self { context }
    }
}

#[async_trait]
impl McpTool for McpExportJsonTool {
    fn name(&self) -> &str {
        "export_json"
    }

    fn description(&self) -> &str {
        "Export the generated report to JSON format. Must call generate_report first."
    }

    fn input_schema(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "filename": {
                    "type": "string",
                    "description": "Filename for the JSON export (default: 'report.json')"
                }
            }
        })
    }

    async fn execute(&self, arguments: Value) -> Result<McpToolResult> {
        let args: ExportJsonArgs = serde_json::from_value(arguments)
            .map_err(|e| crate::Error::Provider(format!("Invalid export_json arguments: {e}")))?;

        let filename = args.filename.unwrap_or_default();
        export_with(
            &self.context,
            &filename,
            "report.json",
            "JSON",
            |report, path| export_json(report, path),
        )
        .await
    }
}

// ============================================================================
// McpExportMarkdownTool
// ============================================================================

/// MCP wrapper for exporting the report to Markdown format
pub struct McpExportMarkdownTool {
    context: Arc<ReportContext>,
}

#[derive(Debug, Deserialize)]
struct ExportMarkdownArgs {
    #[serde(default)]
    filename: Option<String>,
}

impl McpExportMarkdownTool {
    pub fn new(context: Arc<ReportContext>) -> Self {
        Self { context }
    }
}

#[async_trait]
impl McpTool for McpExportMarkdownTool {
    fn name(&self) -> &str {
        "export_markdown"
    }

    fn description(&self) -> &str {
        "Export the generated report to Markdown format. Must call generate_report first."
    }

    fn input_schema(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "filename": {
                    "type": "string",
                    "description": "Filename for the Markdown export (default: 'report.md')"
                }
            }
        })
    }

    async fn execute(&self, arguments: Value) -> Result<McpToolResult> {
        let args: ExportMarkdownArgs = serde_json::from_value(arguments).map_err(|e| {
            crate::Error::Provider(format!("Invalid export_markdown arguments: {e}"))
        })?;

        let filename = args.filename.unwrap_or_default();
        export_with(
            &self.context,
            &filename,
            "report.md",
            "Markdown",
            |report, path| export_markdown(report, path),
        )
        .await
    }
}

// ============================================================================
// McpExportHtmlTool
// ============================================================================

/// MCP wrapper for exporting the report to HTML format
pub struct McpExportHtmlTool {
    context: Arc<ReportContext>,
}

#[derive(Debug, Deserialize)]
struct ExportHtmlArgs {
    #[serde(default)]
    filename: Option<String>,
}

impl McpExportHtmlTool {
    pub fn new(context: Arc<ReportContext>) -> Self {
        Self { context }
    }
}

#[async_trait]
impl McpTool for McpExportHtmlTool {
    fn name(&self) -> &str {
        "export_html"
    }

    fn description(&self) -> &str {
        "Export the generated report to HTML format with styling. Must call generate_report first."
    }

    fn input_schema(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "filename": {
                    "type": "string",
                    "description": "Filename for the HTML export (default: 'report.html')"
                }
            }
        })
    }

    async fn execute(&self, arguments: Value) -> Result<McpToolResult> {
        let args: ExportHtmlArgs = serde_json::from_value(arguments)
            .map_err(|e| crate::Error::Provider(format!("Invalid export_html arguments: {e}")))?;

        let filename = args.filename.unwrap_or_default();
        export_with(
            &self.context,
            &filename,
            "report.html",
            "HTML",
            |report, path| export_html(report, path),
        )
        .await
    }
}

// ============================================================================
// McpExportPdfTool
// ============================================================================

/// MCP wrapper for exporting the report to PDF format
pub struct McpExportPdfTool {
    context: Arc<ReportContext>,
}

#[derive(Debug, Deserialize)]
struct ExportPdfArgs {
    #[serde(default)]
    filename: Option<String>,
}

impl McpExportPdfTool {
    pub fn new(context: Arc<ReportContext>) -> Self {
        Self { context }
    }
}

#[async_trait]
impl McpTool for McpExportPdfTool {
    fn name(&self) -> &str {
        "export_pdf"
    }

    fn description(&self) -> &str {
        "Export the generated report to PDF format. Must call generate_report first."
    }

    fn input_schema(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "filename": {
                    "type": "string",
                    "description": "Filename for the PDF export (default: 'report.pdf')"
                }
            }
        })
    }

    async fn execute(&self, arguments: Value) -> Result<McpToolResult> {
        let args: ExportPdfArgs = serde_json::from_value(arguments)
            .map_err(|e| crate::Error::Provider(format!("Invalid export_pdf arguments: {e}")))?;

        let filename = args.filename.unwrap_or_default();
        export_with(
            &self.context,
            &filename,
            "report.pdf",
            "PDF",
            |report, path| export_pdf(report, path),
        )
        .await
    }
}

// ============================================================================
// McpAddRecommendationTool
// ============================================================================

/// MCP wrapper for adding a security recommendation to the report
pub struct McpAddRecommendationTool {
    context: Arc<ReportContext>,
}

#[derive(Debug, Deserialize)]
struct AddRecommendationArgs {
    recommendation: String,
    #[serde(default)]
    priority: Option<String>,
}

impl McpAddRecommendationTool {
    pub fn new(context: Arc<ReportContext>) -> Self {
        Self { context }
    }
}

#[async_trait]
impl McpTool for McpAddRecommendationTool {
    fn name(&self) -> &str {
        "add_recommendation"
    }

    fn description(&self) -> &str {
        "Add a security recommendation to the report. Must call generate_report first."
    }

    fn input_schema(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "recommendation": {
                    "type": "string",
                    "description": "Security recommendation to add"
                },
                "priority": {
                    "type": "string",
                    "enum": ["high", "medium", "low"],
                    "description": "Priority level (default: medium)"
                }
            },
            "required": ["recommendation"]
        })
    }

    async fn execute(&self, arguments: Value) -> Result<McpToolResult> {
        let args: AddRecommendationArgs = serde_json::from_value(arguments).map_err(|e| {
            crate::Error::Provider(format!("Invalid add_recommendation arguments: {e}"))
        })?;

        self.context.events.send_tool_call();

        let mut report_lock = self.context.report.lock().await;
        let report = match report_lock.as_mut() {
            Some(r) => r,
            None => {
                return Ok(McpToolResult::error(
                    "No report generated yet. Call generate_report first.",
                ));
            }
        };

        let priority = args.priority.as_deref().unwrap_or("medium");
        let formatted = format!("[{}] {}", priority.to_uppercase(), args.recommendation);

        report.summary.key_findings.push(formatted.clone());

        self.context.events.send_feed(
            "report",
            &format!("Added recommendation: {}", args.recommendation),
            false,
        );

        Ok(McpToolResult::text(
            serde_json::json!({
                "success": true,
                "message": format!("Added recommendation: {}", formatted)
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
    use crate::state::{MetricsTracker, Severity};
    use crate::tools::EventSender;
    use crate::tools::MemoryEntryData;
    use crate::tools::orchestrator::AgentSummary;
    use std::path::PathBuf;
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

    fn setup_context(reports_dir: PathBuf) -> Arc<ReportContext> {
        Arc::new(ReportContext {
            events: Arc::new(NoopEventSender),
            target: "example.com".to_string(),
            session_id: "test-session-001".to_string(),
            start_time: Utc::now(),
            metrics: MetricsTracker::new(),
            findings: Arc::new(Mutex::new(vec![
                "[critical] SQL Injection: Login form vulnerable to SQLi".to_string(),
                "[high] XSS: Reflected XSS in search parameter".to_string(),
                "[low] Information Disclosure: Server version exposed".to_string(),
            ])),
            report: Arc::new(Mutex::new(None)),
            reports_dir,
            session_db_path: None,
            deduplicated_findings: Arc::new(Mutex::new(None)),
        })
    }

    #[tokio::test]
    async fn test_generate_report() {
        let tmp = std::env::temp_dir().join("feroxmute_test_report_gen");
        let context = setup_context(tmp);
        let tool = McpGenerateReportTool::new(Arc::clone(&context));

        let result = tool
            .execute(serde_json::json!({
                "executive_summary": "Test executive summary",
                "key_findings": ["Finding A", "Finding B"]
            }))
            .await
            .expect("should generate report");

        let content = result.content.expect("should have content");
        let text = match &content[0] {
            crate::mcp::McpContent::Text { text } => text,
        };
        let parsed: serde_json::Value = serde_json::from_str(text).expect("should parse JSON");

        assert_eq!(parsed["success"], true);
        assert_eq!(parsed["finding_count"], 3);
        assert!(parsed["risk_rating"].as_str().is_some());

        // Verify report was stored
        let report_lock = context.report.lock().await;
        assert!(report_lock.is_some());
        let report = report_lock.as_ref().unwrap();
        assert_eq!(report.findings.len(), 3);
        assert_eq!(report.summary.executive_summary, "Test executive summary");
    }

    #[tokio::test]
    async fn test_generate_report_defaults() {
        let tmp = std::env::temp_dir().join("feroxmute_test_report_defaults");
        let context = setup_context(tmp);
        let tool = McpGenerateReportTool::new(Arc::clone(&context));

        let result = tool
            .execute(serde_json::json!({}))
            .await
            .expect("should generate report with defaults");

        let content = result.content.expect("should have content");
        let text = match &content[0] {
            crate::mcp::McpContent::Text { text } => text,
        };
        let parsed: serde_json::Value = serde_json::from_str(text).expect("should parse JSON");
        assert_eq!(parsed["success"], true);

        // Default executive summary should mention the target
        let report_lock = context.report.lock().await;
        let report = report_lock.as_ref().unwrap();
        assert!(report.summary.executive_summary.contains("example.com"));
    }

    #[tokio::test]
    async fn test_export_json_no_report() {
        let tmp = std::env::temp_dir().join("feroxmute_test_export_no_report");
        let context = setup_context(tmp);
        let tool = McpExportJsonTool::new(context);

        let result = tool
            .execute(serde_json::json!({}))
            .await
            .expect("should return error result");

        assert_eq!(result.is_error, Some(true));
        let content = result.content.expect("should have content");
        let text = match &content[0] {
            crate::mcp::McpContent::Text { text } => text,
        };
        assert!(text.contains("No report generated"));
    }

    #[tokio::test]
    async fn test_export_json_path_traversal() {
        let tmp = std::env::temp_dir().join("feroxmute_test_export_traversal");
        std::fs::create_dir_all(&tmp).ok();
        let context = setup_context(tmp);

        // First generate a report
        let gen_tool = McpGenerateReportTool::new(Arc::clone(&context));
        gen_tool
            .execute(serde_json::json!({}))
            .await
            .expect("should generate report");

        let tool = McpExportJsonTool::new(Arc::clone(&context));
        let result = tool
            .execute(serde_json::json!({
                "filename": "../../../etc/evil.json"
            }))
            .await
            .expect("should handle path traversal");

        // Should succeed but the path should be sanitized (only "evil.json" used)
        let content = result.content.expect("should have content");
        let text = match &content[0] {
            crate::mcp::McpContent::Text { text } => text,
        };
        let parsed: serde_json::Value = serde_json::from_str(text).expect("should parse JSON");
        assert_eq!(parsed["success"], true);
        let path = parsed["path"].as_str().unwrap();
        assert!(path.ends_with("evil.json"));
        assert!(!path.contains("../"));
    }

    #[tokio::test]
    async fn test_add_recommendation_no_report() {
        let tmp = std::env::temp_dir().join("feroxmute_test_rec_no_report");
        let context = setup_context(tmp);
        let tool = McpAddRecommendationTool::new(context);

        let result = tool
            .execute(serde_json::json!({
                "recommendation": "Enable WAF"
            }))
            .await
            .expect("should return error result");

        assert_eq!(result.is_error, Some(true));
    }

    #[tokio::test]
    async fn test_add_recommendation() {
        let tmp = std::env::temp_dir().join("feroxmute_test_add_rec");
        let context = setup_context(tmp);

        // Generate report first
        let gen_tool = McpGenerateReportTool::new(Arc::clone(&context));
        gen_tool
            .execute(serde_json::json!({}))
            .await
            .expect("should generate report");

        let tool = McpAddRecommendationTool::new(Arc::clone(&context));
        let result = tool
            .execute(serde_json::json!({
                "recommendation": "Enable WAF",
                "priority": "high"
            }))
            .await
            .expect("should add recommendation");

        let content = result.content.expect("should have content");
        let text = match &content[0] {
            crate::mcp::McpContent::Text { text } => text,
        };
        let parsed: serde_json::Value = serde_json::from_str(text).expect("should parse JSON");
        assert_eq!(parsed["success"], true);
        assert!(
            parsed["message"]
                .as_str()
                .is_some_and(|m| m.contains("[HIGH]"))
        );

        // Verify it's in the report
        let report_lock = context.report.lock().await;
        let report = report_lock.as_ref().unwrap();
        assert!(
            report
                .summary
                .key_findings
                .iter()
                .any(|f| f.contains("Enable WAF"))
        );
    }

    #[tokio::test]
    async fn test_generate_report_loads_from_database() {
        use crate::state::{VulnStatus, Vulnerability, run_migrations};

        let tmp = tempfile::tempdir().expect("create temp dir");
        let db_path = tmp.path().join("session.db");
        let reports_dir = tmp.path().join("reports");
        std::fs::create_dir_all(&reports_dir).ok();

        // Create DB with schema and insert findings
        let conn = rusqlite::Connection::open(&db_path).expect("open db");
        run_migrations(&conn).expect("run migrations");

        let vuln1 = Vulnerability {
            id: "VULN-001".to_string(),
            host_id: None,
            vuln_type: "sqli".to_string(),
            severity: Severity::Critical,
            title: "SQL Injection in login".to_string(),
            description: Some("Login form vulnerable".to_string()),
            evidence: Some("Error-based SQLi detected".to_string()),
            status: VulnStatus::Verified,
            cwe: Some("CWE-89".to_string()),
            cvss: None,
            asset: Some("/api/login".to_string()),
            remediation: Some("Use parameterized queries".to_string()),
            discovered_by: "scanner-01".to_string(),
            verified_by: None,
            discovered_at: Utc::now(),
            verified_at: None,
        };
        vuln1.insert(&conn).expect("insert vuln1");

        let vuln2 = Vulnerability {
            id: "VULN-002".to_string(),
            host_id: None,
            vuln_type: "xss".to_string(),
            severity: Severity::High,
            title: "Reflected XSS".to_string(),
            description: Some("XSS in search".to_string()),
            evidence: None,
            status: VulnStatus::Potential,
            cwe: None,
            cvss: None,
            asset: Some("/search".to_string()),
            remediation: None,
            discovered_by: "scanner-01".to_string(),
            verified_by: None,
            discovered_at: Utc::now(),
            verified_at: None,
        };
        vuln2.insert(&conn).expect("insert vuln2");
        drop(conn);

        // Create context WITH session_db_path set (empty in-memory findings)
        let context = Arc::new(ReportContext {
            events: Arc::new(NoopEventSender),
            target: "example.com".to_string(),
            session_id: "test-db-session".to_string(),
            start_time: Utc::now(),
            metrics: MetricsTracker::new(),
            findings: Arc::new(Mutex::new(Vec::new())), // Empty in-memory
            report: Arc::new(Mutex::new(None)),
            reports_dir,
            session_db_path: Some(db_path),
            deduplicated_findings: Arc::new(Mutex::new(None)),
        });

        let tool = McpGenerateReportTool::new(Arc::clone(&context));
        let result = tool
            .execute(serde_json::json!({
                "executive_summary": "Test DB loading",
                "key_findings": ["Critical SQLi found"]
            }))
            .await
            .expect("should generate report from DB");

        let content = result.content.expect("should have content");
        let text = match &content[0] {
            crate::mcp::McpContent::Text { text } => text,
        };
        let parsed: serde_json::Value = serde_json::from_str(text).expect("should parse JSON");

        // Should have loaded 2 findings from DB, not 0 from empty in-memory Vec
        assert_eq!(parsed["success"], true);
        assert_eq!(parsed["finding_count"], 2);
        assert_eq!(parsed["risk_rating"], "Critical");

        // Verify report struct details
        let report_lock = context.report.lock().await;
        let report = report_lock.as_ref().unwrap();
        assert_eq!(report.findings.len(), 2);
        assert_eq!(report.summary.by_severity.critical, 1);
        assert_eq!(report.summary.by_severity.high, 1);
        assert_eq!(report.summary.total_vulnerabilities, 2);
        assert_eq!(report.summary.executive_summary, "Test DB loading");
        assert_eq!(report.summary.key_findings, vec!["Critical SQLi found"]);
    }
}
