//! Docker shell tool for rig agents

use std::sync::Arc;

use rig::completion::ToolDefinition;
use rig::tool::Tool;
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;

use crate::agents::AgentStatus;
use crate::docker::ContainerManager;
use crate::limitations::{EngagementLimitations, ToolRegistry};
use crate::tools::sast::{GitleaksOutput, GrypeOutput, SastToolOutput, SemgrepOutput};
use crate::tools::EventSender;

/// Arguments for the shell tool
#[derive(Debug, Deserialize)]
pub struct ShellArgs {
    /// The shell command to execute
    pub command: String,
    /// Brief explanation shown to user in real-time
    pub reason: String,
}

/// Maximum output length to prevent context overflow (in characters)
/// Ollama and other providers can fail with very large tool outputs
const MAX_OUTPUT_LENGTH: usize = 8000;

/// Output from the shell tool
#[derive(Debug, Serialize)]
pub struct ShellOutput {
    /// Combined stdout and stderr (truncated if too large)
    pub output: String,
    /// Exit code of the command
    pub exit_code: i64,
    /// Whether output was truncated
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,
}

/// Errors from the shell tool
#[derive(Debug, Error)]
pub enum ShellError {
    #[error("Docker execution failed: {0}")]
    Docker(String),
}

/// Shell tool that executes commands in a Docker container
pub struct DockerShellTool {
    container: Arc<ContainerManager>,
    events: Arc<dyn EventSender>,
    agent_name: String,
    limitations: Arc<EngagementLimitations>,
    tool_registry: ToolRegistry,
}

impl DockerShellTool {
    /// Create a new Docker shell tool
    pub fn new(
        container: Arc<ContainerManager>,
        events: Arc<dyn EventSender>,
        agent_name: String,
        limitations: Arc<EngagementLimitations>,
    ) -> Self {
        Self {
            container,
            events,
            agent_name,
            limitations,
            tool_registry: ToolRegistry::new(),
        }
    }
}

impl Tool for DockerShellTool {
    const NAME: &'static str = "shell";

    type Error = ShellError;
    type Args = ShellArgs;
    type Output = ShellOutput;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: "shell".to_string(),
            description: "Execute a shell command in a Kali Linux container with pentesting tools installed. Returns combined stdout/stderr and exit code.".to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "The shell command to execute (e.g., 'subfinder -d example.com -json')"
                    },
                    "reason": {
                        "type": "string",
                        "description": "Brief explanation of what this command does and why. This is shown to the user in real-time so they can follow your progress."
                    }
                },
                "required": ["command", "reason"]
            }),
        }
    }

    async fn call(&self, args: Self::Args) -> Result<Self::Output, Self::Error> {
        // Check if command is allowed by limitations
        if let Err(msg) = self.check_command_allowed(&args.command) {
            return Ok(ShellOutput {
                output: msg,
                exit_code: 1,
                truncated: false,
            });
        }

        // Extract tool name for status display (truncate command with args)
        let tool_display = if args.command.len() > 25 {
            format!(
                "{}...",
                &args.command[..args.command.floor_char_boundary(22)]
            )
        } else {
            args.command.clone()
        };

        // Update status to Executing with tool name
        self.events.send_status(
            &self.agent_name,
            "",
            AgentStatus::Executing,
            Some(tool_display),
        );

        // Report what we're about to do
        self.events.send_feed(&self.agent_name, &args.reason, false);

        // Report the actual command (indented)
        self.events
            .send_feed(&self.agent_name, &format!("  -> {}", args.command), false);

        // Wrap command to capture both stdout and stderr
        let wrapped_cmd = format!("{} 2>&1", args.command);

        let result = self
            .container
            .exec(vec!["sh", "-c", &wrapped_cmd], None)
            .await
            .map_err(|e| ShellError::Docker(e.to_string()))?;

        let raw_output = result.output();

        // Update status to Processing (reading result)
        self.events
            .send_status(&self.agent_name, "", AgentStatus::Processing, None);

        // Parse SAST tool outputs and send vulnerability events (use raw output for parsing)
        self.parse_sast_findings(&args.command, &raw_output);

        // Report result summary (indented)
        let line_count = raw_output.lines().count();
        self.events.send_feed_with_output(
            &self.agent_name,
            &format!(
                "  -> exit {}, {} lines output",
                result.exit_code, line_count
            ),
            result.exit_code != 0,
            &raw_output,
        );

        // After processing, go back to Streaming (ready for more LLM output)
        self.events
            .send_status(&self.agent_name, "", AgentStatus::Streaming, None);

        // Sanitize and truncate output for safe JSON serialization
        let (output, truncated) = prepare_output(&raw_output);
        if truncated {
            self.events.send_feed(
                &self.agent_name,
                "  -> output truncated to prevent context overflow",
                false,
            );
        }

        Ok(ShellOutput {
            output,
            exit_code: result.exit_code,
            truncated,
        })
    }
}

/// Sanitize output to remove control characters that can break JSON serialization
/// Keeps printable ASCII, newlines, tabs, and valid UTF-8
fn sanitize_output(s: &str) -> String {
    s.chars()
        .filter(|c| {
            // Keep printable ASCII, newlines, tabs, and non-ASCII (valid UTF-8)
            c.is_ascii_graphic() || *c == ' ' || *c == '\n' || *c == '\t' || !c.is_ascii()
        })
        .collect()
}

/// Truncate and sanitize output for safe JSON serialization
fn prepare_output(output: &str) -> (String, bool) {
    let sanitized = sanitize_output(output);

    if sanitized.len() <= MAX_OUTPUT_LENGTH {
        (sanitized, false)
    } else {
        // Truncate at a safe boundary (avoid cutting UTF-8 characters)
        let truncated = sanitized
            .char_indices()
            .take_while(|(i, _)| *i < MAX_OUTPUT_LENGTH)
            .map(|(_, c)| c)
            .collect::<String>();
        (
            format!(
                "{}\n... [output truncated, {} bytes omitted]",
                truncated,
                sanitized.len() - truncated.len()
            ),
            true,
        )
    }
}

impl DockerShellTool {
    /// Check if a command is allowed by engagement limitations
    fn check_command_allowed(&self, command: &str) -> Result<(), String> {
        let category = self.tool_registry.categorize(command);

        match category {
            Some(cat) if !self.limitations.is_allowed(cat) => {
                let tool = command.split_whitespace().next().unwrap_or("unknown");
                let msg = format!(
                    "Blocked: '{}' requires {:?} which is not allowed in current scope",
                    tool, cat
                );
                self.events.send_feed(&self.agent_name, &msg, true);
                Err(msg)
            }
            None => {
                // Unknown command - allow with warning
                let tool = command.split_whitespace().next().unwrap_or("unknown");
                self.events.send_feed(
                    &self.agent_name,
                    &format!("Warning: unrecognized command '{}' - allowing", tool),
                    false,
                );
                Ok(())
            }
            Some(_) => Ok(()),
        }
    }

    /// Parse SAST tool output and send code finding events
    fn parse_sast_findings(&self, command: &str, output: &str) {
        let cmd_lower = command.to_lowercase();

        // Try to parse grype output
        if cmd_lower.starts_with("grype") && cmd_lower.contains("-o json") {
            if let Ok(grype_output) = GrypeOutput::parse(output) {
                for finding in grype_output.to_code_findings() {
                    self.events.send_code_finding(
                        &self.agent_name,
                        &finding.file_path,
                        finding.line_number,
                        finding.severity,
                        finding.finding_type,
                        &finding.title,
                        &finding.tool,
                        finding.cve_id.as_deref(),
                        finding.package_name.as_deref(),
                    );
                }
            }
        }

        // Try to parse semgrep output
        if cmd_lower.starts_with("semgrep") && cmd_lower.contains("--json") {
            if let Ok(semgrep_output) = SemgrepOutput::parse(output) {
                for finding in semgrep_output.to_code_findings() {
                    self.events.send_code_finding(
                        &self.agent_name,
                        &finding.file_path,
                        finding.line_number,
                        finding.severity,
                        finding.finding_type,
                        &finding.title,
                        &finding.tool,
                        finding.cwe_id.as_deref(),
                        None,
                    );
                }
            }
        }

        // Try to parse gitleaks output
        if cmd_lower.starts_with("gitleaks") && cmd_lower.contains("json") {
            if let Ok(gitleaks_output) = GitleaksOutput::parse(output) {
                for finding in gitleaks_output.to_code_findings() {
                    self.events.send_code_finding(
                        &self.agent_name,
                        &finding.file_path,
                        finding.line_number,
                        finding.severity,
                        finding.finding_type,
                        &finding.title,
                        &finding.tool,
                        None,
                        None,
                    );
                }
            }
        }

        // Try to parse ast-grep output
        if cmd_lower.starts_with("ast-grep") && cmd_lower.contains("--json") {
            if let Ok(astgrep_output) = super::sast::AstGrepOutput::parse(output) {
                for finding in super::sast::SastToolOutput::to_code_findings(&astgrep_output) {
                    self.events.send_code_finding(
                        &self.agent_name,
                        &finding.file_path,
                        finding.line_number,
                        finding.severity,
                        finding.finding_type,
                        &finding.title,
                        &finding.tool,
                        None,
                        None,
                    );
                }
            }
        }
    }
}
