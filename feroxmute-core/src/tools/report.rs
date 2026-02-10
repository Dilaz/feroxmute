//! Report generation tools for rig agents

use std::sync::Arc;

use chrono::{DateTime, Utc};
use rig::completion::ToolDefinition;
use rig::tool::Tool;
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;
use tokio::sync::Mutex;

use crate::reports::{
    Finding, Report, ReportMetadata, ReportMetrics, ReportSummary, RiskRating, SeverityCounts,
    StatusCounts, export_html, export_json, export_markdown, export_pdf, generate_report,
};
use crate::state::MetricsTracker;
use crate::tools::EventSender;

/// Errors from report tools
#[derive(Debug, Error)]
pub enum ReportToolError {
    #[error("Report generation failed: {0}")]
    Generation(String),
    #[error("Export failed: {0}")]
    Export(String),
    #[error("No report generated yet")]
    NoReport,
}

/// Shared context for report tools
pub struct ReportContext {
    /// Event sender for UI updates
    pub events: Arc<dyn EventSender>,
    /// Target being assessed
    pub target: String,
    /// Session ID
    pub session_id: String,
    /// Start time of engagement
    pub start_time: DateTime<Utc>,
    /// Metrics tracker
    pub metrics: MetricsTracker,
    /// Collected findings (from orchestrator, as formatted strings)
    pub findings: Arc<Mutex<Vec<String>>>,
    /// Generated report (mutable state shared between tools)
    pub report: Arc<Mutex<Option<Report>>>,
    /// Path to reports directory for saving report files
    pub reports_dir: std::path::PathBuf,
    /// Path to session database for loading vulnerabilities
    pub session_db_path: Option<std::path::PathBuf>,
    /// Deduplicated findings cache, populated by deduplicate_findings tool
    pub deduplicated_findings: Arc<Mutex<Option<Vec<crate::state::Vulnerability>>>>,
}

// ============================================================================
// DeduplicateFindingsTool
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct DeduplicateFindingsArgs {}

#[derive(Debug, Serialize)]
pub struct DeduplicateFindingsOutput {
    pub success: bool,
    pub message: String,
    pub original_count: usize,
    pub deduplicated_count: usize,
}

pub struct DeduplicateFindingsTool {
    context: Arc<ReportContext>,
}

impl DeduplicateFindingsTool {
    pub fn new(context: Arc<ReportContext>) -> Self {
        Self { context }
    }
}

impl Tool for DeduplicateFindingsTool {
    const NAME: &'static str = "deduplicate_findings";

    type Error = ReportToolError;
    type Args = DeduplicateFindingsArgs;
    type Output = DeduplicateFindingsOutput;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: "deduplicate_findings".to_string(),
            description: "Deduplicate findings by merging semantically similar vulnerabilities. Call this BEFORE generate_report to reduce duplicate entries.".to_string(),
            parameters: json!({
                "type": "object",
                "properties": {},
                "required": []
            }),
        }
    }

    async fn call(&self, _args: Self::Args) -> Result<Self::Output, Self::Error> {
        self.context.events.send_tool_call();
        self.context
            .events
            .send_feed("report", "Deduplicating findings...", false);

        let db_path = match &self.context.session_db_path {
            Some(p) => p,
            None => {
                return Ok(DeduplicateFindingsOutput {
                    success: true,
                    message: "No session database available for deduplication".to_string(),
                    original_count: 0,
                    deduplicated_count: 0,
                });
            }
        };

        let conn = rusqlite::Connection::open(db_path)
            .map_err(|e| ReportToolError::Generation(format!("Failed to open database: {}", e)))?;

        let vulns = crate::state::Vulnerability::all(&conn).map_err(|e| {
            ReportToolError::Generation(format!("Failed to load vulnerabilities: {}", e))
        })?;

        if vulns.is_empty() {
            return Ok(DeduplicateFindingsOutput {
                success: true,
                message: "No findings to deduplicate".to_string(),
                original_count: 0,
                deduplicated_count: 0,
            });
        }

        let original_count = vulns.len();
        let deduped = crate::reports::deduplicate_vulnerabilities(vulns);
        let deduped_count = deduped.len();

        // Store in context for generate_report to use
        let mut cache = self.context.deduplicated_findings.lock().await;
        *cache = Some(deduped);

        let message = format!(
            "Deduplicated {} findings into {} unique vulnerabilities",
            original_count, deduped_count
        );

        self.context.events.send_feed("report", &message, false);

        Ok(DeduplicateFindingsOutput {
            success: true,
            message,
            original_count,
            deduplicated_count: deduped_count,
        })
    }
}

// ============================================================================
// GenerateReportTool
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct GenerateReportArgs {
    /// Executive summary for the report
    #[serde(default)]
    pub executive_summary: Option<String>,
    /// Key findings to highlight
    #[serde(default)]
    pub key_findings: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
pub struct GenerateReportOutput {
    pub success: bool,
    pub message: String,
    pub finding_count: usize,
    pub risk_rating: String,
}

pub struct GenerateReportTool {
    context: Arc<ReportContext>,
}

impl GenerateReportTool {
    pub fn new(context: Arc<ReportContext>) -> Self {
        Self { context }
    }

    /// Fallback: build a report from the in-memory findings Vec
    async fn build_report_from_memory(&self, end_time: DateTime<Utc>) -> Report {
        let findings_strings = self.context.findings.lock().await;

        let findings: Vec<Finding> = findings_strings
            .iter()
            .map(|s| {
                // Parse "[category] title: description"
                let (severity, rest) = if s.starts_with('[') {
                    if let Some(end) = s.find(']') {
                        let tag = &s[1..end];
                        let remainder = if s.len() > end + 2 {
                            s[end + 2..].to_string()
                        } else {
                            String::new()
                        };
                        // Map category tags to severity; default to medium
                        let sev = match tag.to_lowercase().as_str() {
                            "critical" => "critical",
                            "high" => "high",
                            "medium" => "medium",
                            "low" => "low",
                            "info" | "informational" => "info",
                            _ => "medium",
                        };
                        (sev.to_string(), remainder)
                    } else {
                        ("medium".to_string(), s.clone())
                    }
                } else {
                    ("medium".to_string(), s.clone())
                };

                let (title, description) = if let Some(idx) = rest.find(':') {
                    (
                        rest[..idx].trim().to_string(),
                        rest[idx + 1..].trim().to_string(),
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

impl Tool for GenerateReportTool {
    const NAME: &'static str = "generate_report";

    type Error = ReportToolError;
    type Args = GenerateReportArgs;
    type Output = GenerateReportOutput;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: "generate_report".to_string(),
            description: "Generate the penetration testing report from collected findings. Call this before exporting to JSON or Markdown.".to_string(),
            parameters: json!({
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
                },
                "required": []
            }),
        }
    }

    async fn call(&self, args: Self::Args) -> Result<Self::Output, Self::Error> {
        // Notify TUI of tool invocation for counting
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

        Ok(GenerateReportOutput {
            success: true,
            message: format!(
                "Report generated with {} findings. Risk rating: {}",
                finding_count, risk_rating_str
            ),
            finding_count,
            risk_rating: risk_rating_str,
        })
    }
}

// ============================================================================
// ExportJsonTool
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct ExportJsonArgs {
    /// Filename for JSON export (saved to session reports directory)
    #[serde(default = "default_json_filename")]
    pub filename: String,
}

fn default_json_filename() -> String {
    "report.json".to_string()
}

#[derive(Debug, Serialize)]
pub struct ExportJsonOutput {
    pub success: bool,
    pub message: String,
    pub path: String,
}

pub struct ExportJsonTool {
    context: Arc<ReportContext>,
}

impl ExportJsonTool {
    pub fn new(context: Arc<ReportContext>) -> Self {
        Self { context }
    }
}

impl Tool for ExportJsonTool {
    const NAME: &'static str = "export_json";

    type Error = ReportToolError;
    type Args = ExportJsonArgs;
    type Output = ExportJsonOutput;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: "export_json".to_string(),
            description:
                "Export the generated report to JSON format. Must call generate_report first. The report is saved to the session's reports directory."
                    .to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "filename": {
                        "type": "string",
                        "description": "Filename for the JSON export (default: 'report.json')"
                    }
                },
                "required": []
            }),
        }
    }

    async fn call(&self, args: Self::Args) -> Result<Self::Output, Self::Error> {
        // Notify TUI of tool invocation for counting
        self.context.events.send_tool_call();

        let report_lock = self.context.report.lock().await;
        let report = report_lock.as_ref().ok_or(ReportToolError::NoReport)?;

        let safe_name = std::path::Path::new(&args.filename)
            .file_name()
            .ok_or_else(|| {
                ReportToolError::Export("Invalid filename: must not contain path separators".into())
            })?;
        let path = self.context.reports_dir.join(safe_name);
        let path_str = path.display().to_string();

        self.context
            .events
            .send_feed("report", &format!("Exporting to JSON: {}", path_str), false);

        export_json(report, &path).map_err(|e| ReportToolError::Export(e.to_string()))?;

        self.context.events.send_feed(
            "report",
            &format!("JSON report exported to {}", path_str),
            false,
        );

        Ok(ExportJsonOutput {
            success: true,
            message: format!("Report exported to JSON: {}", path_str),
            path: path_str,
        })
    }
}

// ============================================================================
// ExportMarkdownTool
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct ExportMarkdownArgs {
    /// Filename for Markdown export (saved to session reports directory)
    #[serde(default = "default_markdown_filename")]
    pub filename: String,
}

fn default_markdown_filename() -> String {
    "report.md".to_string()
}

#[derive(Debug, Serialize)]
pub struct ExportMarkdownOutput {
    pub success: bool,
    pub message: String,
    pub path: String,
}

pub struct ExportMarkdownTool {
    context: Arc<ReportContext>,
}

impl ExportMarkdownTool {
    pub fn new(context: Arc<ReportContext>) -> Self {
        Self { context }
    }
}

impl Tool for ExportMarkdownTool {
    const NAME: &'static str = "export_markdown";

    type Error = ReportToolError;
    type Args = ExportMarkdownArgs;
    type Output = ExportMarkdownOutput;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: "export_markdown".to_string(),
            description:
                "Export the generated report to Markdown format. Must call generate_report first. The report is saved to the session's reports directory."
                    .to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "filename": {
                        "type": "string",
                        "description": "Filename for the Markdown export (default: 'report.md')"
                    }
                },
                "required": []
            }),
        }
    }

    async fn call(&self, args: Self::Args) -> Result<Self::Output, Self::Error> {
        // Notify TUI of tool invocation for counting
        self.context.events.send_tool_call();

        let report_lock = self.context.report.lock().await;
        let report = report_lock.as_ref().ok_or(ReportToolError::NoReport)?;

        let safe_name = std::path::Path::new(&args.filename)
            .file_name()
            .ok_or_else(|| {
                ReportToolError::Export("Invalid filename: must not contain path separators".into())
            })?;
        let path = self.context.reports_dir.join(safe_name);
        let path_str = path.display().to_string();

        self.context.events.send_feed(
            "report",
            &format!("Exporting to Markdown: {}", path_str),
            false,
        );

        export_markdown(report, &path).map_err(|e| ReportToolError::Export(e.to_string()))?;

        self.context.events.send_feed(
            "report",
            &format!("Markdown report exported to {}", path_str),
            false,
        );

        Ok(ExportMarkdownOutput {
            success: true,
            message: format!("Report exported to Markdown: {}", path_str),
            path: path_str,
        })
    }
}

// ============================================================================
// ExportHtmlTool
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct ExportHtmlArgs {
    /// Filename for HTML export (saved to session reports directory)
    #[serde(default = "default_html_filename")]
    pub filename: String,
}

fn default_html_filename() -> String {
    "report.html".to_string()
}

#[derive(Debug, Serialize)]
pub struct ExportHtmlOutput {
    pub success: bool,
    pub message: String,
    pub path: String,
}

pub struct ExportHtmlTool {
    context: Arc<ReportContext>,
}

impl ExportHtmlTool {
    pub fn new(context: Arc<ReportContext>) -> Self {
        Self { context }
    }
}

impl Tool for ExportHtmlTool {
    const NAME: &'static str = "export_html";

    type Error = ReportToolError;
    type Args = ExportHtmlArgs;
    type Output = ExportHtmlOutput;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: "export_html".to_string(),
            description:
                "Export the generated report to HTML format with styling. Must call generate_report first. The report is saved to the session's reports directory."
                    .to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "filename": {
                        "type": "string",
                        "description": "Filename for the HTML export (default: 'report.html')"
                    }
                },
                "required": []
            }),
        }
    }

    async fn call(&self, args: Self::Args) -> Result<Self::Output, Self::Error> {
        // Notify TUI of tool invocation for counting
        self.context.events.send_tool_call();

        let report_lock = self.context.report.lock().await;
        let report = report_lock.as_ref().ok_or(ReportToolError::NoReport)?;

        let safe_name = std::path::Path::new(&args.filename)
            .file_name()
            .ok_or_else(|| {
                ReportToolError::Export("Invalid filename: must not contain path separators".into())
            })?;
        let path = self.context.reports_dir.join(safe_name);
        let path_str = path.display().to_string();

        self.context
            .events
            .send_feed("report", &format!("Exporting to HTML: {}", path_str), false);

        export_html(report, &path).map_err(|e| ReportToolError::Export(e.to_string()))?;

        self.context.events.send_feed(
            "report",
            &format!("HTML report exported to {}", path_str),
            false,
        );

        Ok(ExportHtmlOutput {
            success: true,
            message: format!("Report exported to HTML: {}", path_str),
            path: path_str,
        })
    }
}

// ============================================================================
// ExportPdfTool
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct ExportPdfArgs {
    /// Filename for PDF export (saved to session reports directory)
    #[serde(default = "default_pdf_filename")]
    pub filename: String,
}

fn default_pdf_filename() -> String {
    "report.pdf".to_string()
}

#[derive(Debug, Serialize)]
pub struct ExportPdfOutput {
    pub success: bool,
    pub message: String,
    pub path: String,
}

pub struct ExportPdfTool {
    context: Arc<ReportContext>,
}

impl ExportPdfTool {
    pub fn new(context: Arc<ReportContext>) -> Self {
        Self { context }
    }
}

impl Tool for ExportPdfTool {
    const NAME: &'static str = "export_pdf";

    type Error = ReportToolError;
    type Args = ExportPdfArgs;
    type Output = ExportPdfOutput;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: "export_pdf".to_string(),
            description:
                "Export the generated report to PDF format. Must call generate_report first. The report is saved to the session's reports directory."
                    .to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "filename": {
                        "type": "string",
                        "description": "Filename for the PDF export (default: 'report.pdf')"
                    }
                },
                "required": []
            }),
        }
    }

    async fn call(&self, args: Self::Args) -> Result<Self::Output, Self::Error> {
        // Notify TUI of tool invocation for counting
        self.context.events.send_tool_call();

        let report_lock = self.context.report.lock().await;
        let report = report_lock.as_ref().ok_or(ReportToolError::NoReport)?;

        let safe_name = std::path::Path::new(&args.filename)
            .file_name()
            .ok_or_else(|| {
                ReportToolError::Export("Invalid filename: must not contain path separators".into())
            })?;
        let path = self.context.reports_dir.join(safe_name);
        let path_str = path.display().to_string();

        self.context
            .events
            .send_feed("report", &format!("Exporting to PDF: {}", path_str), false);

        export_pdf(report, &path).map_err(|e| ReportToolError::Export(e.to_string()))?;

        self.context.events.send_feed(
            "report",
            &format!("PDF report exported to {}", path_str),
            false,
        );

        Ok(ExportPdfOutput {
            success: true,
            message: format!("Report exported to PDF: {}", path_str),
            path: path_str,
        })
    }
}

// ============================================================================
// AddRecommendationTool
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct AddRecommendationArgs {
    /// The recommendation to add
    pub recommendation: String,
    /// Priority: high, medium, low
    #[serde(default)]
    pub priority: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AddRecommendationOutput {
    pub success: bool,
    pub message: String,
}

pub struct AddRecommendationTool {
    context: Arc<ReportContext>,
}

impl AddRecommendationTool {
    pub fn new(context: Arc<ReportContext>) -> Self {
        Self { context }
    }
}

impl Tool for AddRecommendationTool {
    const NAME: &'static str = "add_recommendation";

    type Error = ReportToolError;
    type Args = AddRecommendationArgs;
    type Output = AddRecommendationOutput;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: "add_recommendation".to_string(),
            description:
                "Add a security recommendation to the report. Must call generate_report first."
                    .to_string(),
            parameters: json!({
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
            }),
        }
    }

    async fn call(&self, args: Self::Args) -> Result<Self::Output, Self::Error> {
        // Notify TUI of tool invocation for counting
        self.context.events.send_tool_call();

        let mut report_lock = self.context.report.lock().await;
        let report = report_lock.as_mut().ok_or(ReportToolError::NoReport)?;

        let priority = args.priority.as_deref().unwrap_or("medium");
        let formatted = format!("[{}] {}", priority.to_uppercase(), args.recommendation);

        report.summary.key_findings.push(formatted.clone());

        self.context.events.send_feed(
            "report",
            &format!("Added recommendation: {}", args.recommendation),
            false,
        );

        Ok(AddRecommendationOutput {
            success: true,
            message: format!("Added recommendation: {}", formatted),
        })
    }
}
