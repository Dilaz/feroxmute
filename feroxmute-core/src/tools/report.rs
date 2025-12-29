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
    export_json, export_markdown, Finding, Report, ReportMetadata, ReportMetrics, ReportSummary,
    RiskRating, SeverityCounts, StatusCounts,
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
        let findings_strings = self.context.findings.lock().await;

        // Convert string findings to Finding structs
        let findings: Vec<Finding> = findings_strings
            .iter()
            .map(|s| {
                // Parse the formatted string: "[severity] title: description"
                let (severity, rest) = if s.starts_with('[') {
                    if let Some(end) = s.find(']') {
                        (s[1..end].to_string(), s[end + 2..].to_string())
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
                    (rest.clone(), String::new())
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

        // Count by severity
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

        let report = Report {
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
                key_findings: args.key_findings.unwrap_or_default(),
                executive_summary: args.executive_summary.unwrap_or_else(|| {
                    format!(
                        "Security assessment of {} completed with {} findings.",
                        self.context.target, finding_count
                    )
                }),
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
        };

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

        let path = self.context.reports_dir.join(&args.filename);
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

        let path = self.context.reports_dir.join(&args.filename);
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
