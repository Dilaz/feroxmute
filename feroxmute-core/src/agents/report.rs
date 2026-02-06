//! Report generation agent

use async_trait::async_trait;
use chrono::Utc;
use serde_json::json;

use crate::providers::{CompletionRequest, Message, ToolDefinition};
use crate::reports::{Report, export_json, export_markdown, generate_markdown, generate_report};
use crate::state::MetricsTracker;
use crate::{Error, Result};

use super::{Agent, AgentContext, AgentStatus, AgentTask, Prompts};

/// Report generation agent
pub struct ReportAgent {
    status: AgentStatus,
    thinking: Option<String>,
    prompts: Prompts,
    start_time: chrono::DateTime<Utc>,
    metrics: MetricsTracker,
    generated_report: Option<Report>,
}

impl ReportAgent {
    /// Create a new report agent
    pub fn new(start_time: chrono::DateTime<Utc>, metrics: MetricsTracker) -> Self {
        Self {
            status: AgentStatus::Idle,
            thinking: None,
            prompts: Prompts::default(),
            start_time,
            metrics,
            generated_report: None,
        }
    }

    /// Create with custom prompts
    pub fn with_prompts(
        prompts: Prompts,
        start_time: chrono::DateTime<Utc>,
        metrics: MetricsTracker,
    ) -> Self {
        Self {
            status: AgentStatus::Idle,
            thinking: None,
            prompts,
            start_time,
            metrics,
            generated_report: None,
        }
    }

    /// Get the generated report
    pub fn report(&self) -> Option<&Report> {
        self.generated_report.as_ref()
    }

    /// Build tool definitions for this agent
    fn build_tools(&self) -> Vec<ToolDefinition> {
        vec![
            ToolDefinition {
                name: "generate_report".to_string(),
                description: "Generate the penetration testing report from findings".to_string(),
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
            },
            ToolDefinition {
                name: "export_json".to_string(),
                description: "Export the report to JSON format".to_string(),
                parameters: json!({
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "File path for JSON export"
                        }
                    },
                    "required": ["path"]
                }),
            },
            ToolDefinition {
                name: "export_markdown".to_string(),
                description: "Export the report to Markdown format".to_string(),
                parameters: json!({
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "File path for Markdown export"
                        }
                    },
                    "required": ["path"]
                }),
            },
            ToolDefinition {
                name: "complete_task".to_string(),
                description: "Call this when the report has been generated and exported."
                    .to_string(),
                parameters: json!({
                    "type": "object",
                    "properties": {
                        "summary": {
                            "type": "string",
                            "description": "Brief summary of what was reported"
                        }
                    },
                    "required": ["summary"]
                }),
            },
            ToolDefinition {
                name: "add_recommendation".to_string(),
                description: "Add a recommendation to the report".to_string(),
                parameters: json!({
                    "type": "object",
                    "properties": {
                        "recommendation": {
                            "type": "string",
                            "description": "Security recommendation to add"
                        },
                        "priority": {
                            "type": "string",
                            "description": "Priority: high, medium, low"
                        }
                    },
                    "required": ["recommendation"]
                }),
            },
        ]
    }
}

impl Default for ReportAgent {
    fn default() -> Self {
        Self::new(Utc::now(), MetricsTracker::new())
    }
}

#[async_trait(?Send)]
impl Agent for ReportAgent {
    fn name(&self) -> &str {
        "report"
    }

    fn status(&self) -> AgentStatus {
        self.status
    }

    fn system_prompt(&self) -> &str {
        self.prompts.get("report").unwrap_or("")
    }

    fn tools(&self) -> Vec<ToolDefinition> {
        self.build_tools()
    }

    async fn execute(&mut self, task: &AgentTask, ctx: &AgentContext<'_>) -> Result<String> {
        self.status = AgentStatus::Streaming;
        self.thinking = Some(format!("Generating report for task: {}", task.description));

        // Build initial message
        let task_message = format!(
            "Target: {}\nTask: {}\n\nContext: {}\n\n\
            Please generate a comprehensive penetration testing report. \
            Start by calling generate_report with an executive summary, \
            then export to both JSON and Markdown formats.",
            ctx.target,
            task.description,
            task.context.as_deref().unwrap_or("None")
        );

        let mut messages = vec![Message::user(&task_message)];
        let mut result = String::new();
        let max_iterations = 5;

        for iteration in 0..max_iterations {
            self.thinking = Some(format!("Iteration {}: Processing report...", iteration + 1));

            let request = CompletionRequest::new(messages.clone())
                .with_system(self.system_prompt())
                .with_tools(self.tools())
                .with_max_tokens(4096);

            let response = ctx.provider.complete(request).await?;

            if !response.tool_calls.is_empty() {
                for tool_call in &response.tool_calls {
                    self.thinking = Some(format!("Executing: {}", tool_call.name));

                    let args: serde_json::Value = serde_json::from_str(&tool_call.arguments)
                        .map_err(|e| Error::Provider(format!("Invalid tool arguments: {}", e)))?;

                    // Handle complete_task — agent signals it's done
                    if tool_call.name == "complete_task" {
                        let summary = args
                            .get("summary")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Report complete");
                        result.push_str(&format!("\n## Summary\n{}\n", summary));
                        self.status = AgentStatus::Completed;
                        return Ok(result);
                    }

                    let tool_result = match tool_call.name.as_str() {
                        "generate_report" => self.handle_generate_report(&args, ctx).await?,
                        "export_json" => self.handle_export_json(&args)?,
                        "export_markdown" => self.handle_export_markdown(&args)?,
                        "add_recommendation" => self.handle_add_recommendation(&args),
                        _ => "Unknown tool".to_string(),
                    };

                    result.push_str(&format!("\n## {}\n{}\n", tool_call.name, tool_result));
                    messages.push(Message::assistant(format!(
                        "Tool {} result: {}",
                        tool_call.name, tool_result
                    )));
                }
            } else if let Some(content) = response.content {
                self.thinking = Some("Finalizing report...".to_string());
                result.push_str(&format!("\n## Report Analysis\n{}\n", content));

                messages.push(Message::assistant(&content));
                messages.push(Message::user(
                    "Continue or call complete_task when the report is done.",
                ));
            } else {
                break;
            }
        }

        self.status = AgentStatus::Completed;
        self.thinking = Some("Report generation completed".to_string());

        Ok(result)
    }

    fn thinking(&self) -> Option<&str> {
        self.thinking.as_deref()
    }

    fn set_status(&mut self, status: AgentStatus) {
        self.status = status;
    }
}

impl ReportAgent {
    /// Handle report generation
    async fn handle_generate_report(
        &mut self,
        args: &serde_json::Value,
        ctx: &AgentContext<'_>,
    ) -> Result<String> {
        let end_time = Utc::now();

        // Generate the report
        let mut report = generate_report(
            ctx.conn,
            ctx.target,
            ctx.session_id,
            self.start_time,
            end_time,
            &self.metrics,
        )?;

        // Add executive summary if provided
        if let Some(summary) = args.get("executive_summary").and_then(|v| v.as_str()) {
            report.summary.executive_summary = summary.to_string();
        }

        // Add key findings if provided
        if let Some(findings) = args.get("key_findings").and_then(|v| v.as_array()) {
            for finding in findings {
                if let Some(f) = finding.as_str() {
                    report.summary.key_findings.push(f.to_string());
                }
            }
        }

        let result = format!(
            "Report generated with {} findings. Risk rating: {:?}",
            report.findings.len(),
            report.summary.risk_rating
        );
        self.generated_report = Some(report);

        Ok(result)
    }

    /// Handle JSON export
    fn handle_export_json(&self, args: &serde_json::Value) -> Result<String> {
        let path = args
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::Provider("Missing path for export".to_string()))?;

        if let Some(ref report) = self.generated_report {
            export_json(report, path)?;
            Ok(format!("Report exported to JSON: {}", path))
        } else {
            Err(Error::Provider("No report generated yet".to_string()))
        }
    }

    /// Handle Markdown export
    fn handle_export_markdown(&self, args: &serde_json::Value) -> Result<String> {
        let path = args
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::Provider("Missing path for export".to_string()))?;

        if let Some(ref report) = self.generated_report {
            export_markdown(report, path)?;
            Ok(format!("Report exported to Markdown: {}", path))
        } else {
            Err(Error::Provider("No report generated yet".to_string()))
        }
    }

    /// Handle adding a recommendation
    fn handle_add_recommendation(&mut self, args: &serde_json::Value) -> String {
        if let Some(ref mut report) = self.generated_report {
            let rec = args
                .get("recommendation")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown recommendation");
            let priority = args
                .get("priority")
                .and_then(|v| v.as_str())
                .unwrap_or("medium");

            let formatted = format!("[{}] {}", priority.to_uppercase(), rec);
            report.summary.key_findings.push(formatted.clone());

            format!("Added recommendation: {}", formatted)
        } else {
            "No report generated yet".to_string()
        }
    }

    /// Get markdown preview
    pub fn markdown_preview(&self) -> Option<String> {
        self.generated_report.as_ref().map(generate_markdown)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn test_report_agent_creation() {
        let agent = ReportAgent::default();
        assert_eq!(agent.name(), "report");
        assert_eq!(agent.status(), AgentStatus::Idle);
    }

    #[test]
    fn test_report_agent_tools() {
        let agent = ReportAgent::default();
        let tools = agent.tools();

        assert!(tools.iter().any(|t| t.name == "generate_report"));
        assert!(tools.iter().any(|t| t.name == "export_json"));
        assert!(tools.iter().any(|t| t.name == "export_markdown"));
        assert!(tools.iter().any(|t| t.name == "add_recommendation"));
    }

    #[test]
    fn test_report_has_complete_task_tool() {
        let agent = ReportAgent::default();
        let tools = agent.tools();
        assert!(
            tools.iter().any(|t| t.name == "complete_task"),
            "Report agent should have complete_task tool"
        );
    }
}
