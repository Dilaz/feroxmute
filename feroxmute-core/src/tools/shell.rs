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
use crate::tools::EventSender;
use crate::tools::sast::{
    GitleaksOutput, GrypeOutput, RoutesOutput, SastToolOutput, SemgrepOutput,
};

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
        // Notify TUI of tool invocation for counting
        self.events.send_tool_call();

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

/// Extract all command names from a shell command string
/// Handles pipes (|), AND (&&), OR (||), semicolons (;), and subshells ($(...))
pub(crate) fn extract_commands(input: &str) -> Vec<&str> {
    let mut commands = Vec::new();

    // Split on shell operators
    // This regex-free approach handles: |, &&, ||, ;
    let mut remaining = input;

    while !remaining.is_empty() {
        // Find the next operator
        let mut split_pos = remaining.len();
        let mut skip_len = 0;

        for (i, _) in remaining.char_indices() {
            let rest = &remaining[i..];
            if rest.starts_with("&&") || rest.starts_with("||") {
                split_pos = i;
                skip_len = 2;
                break;
            } else if rest.starts_with('|') || rest.starts_with(';') {
                split_pos = i;
                skip_len = 1;
                break;
            }
        }

        let segment = &remaining[..split_pos];

        // Extract command name from segment (first word after stripping)
        let trimmed = segment.trim();
        if let Some(cmd) = trimmed.split_whitespace().next() {
            // Handle subshells: $(cmd ...) or `cmd ...`
            let cmd = cmd.trim_start_matches("$(").trim_start_matches('`');
            // Strip path prefix so /usr/bin/nmap is recognized as nmap
            let cmd = cmd.rsplit('/').next().unwrap_or(cmd);
            if !cmd.is_empty() {
                commands.push(cmd);
            }
        }

        // Move past the operator
        if split_pos + skip_len >= remaining.len() {
            break;
        }
        remaining = &remaining[split_pos + skip_len..];
    }

    // Also check for commands in $(...) subshells
    let mut search_pos = 0;
    while let Some(start) = input[search_pos..].find("$(") {
        let abs_start = search_pos + start + 2;
        if let Some(end) = input[abs_start..].find(')') {
            let subshell_content = &input[abs_start..abs_start + end];
            // Recursively extract from subshell
            for cmd in extract_commands(subshell_content) {
                if !commands.contains(&cmd) {
                    commands.push(cmd);
                }
            }
            search_pos = abs_start + end + 1;
        } else {
            break;
        }
    }

    commands
}

impl DockerShellTool {
    /// Check if a command is allowed by engagement limitations
    fn check_command_allowed(&self, command: &str) -> Result<(), String> {
        let commands = extract_commands(command);
        let allowed = self.limitations.allowed_categories();

        for cmd in commands {
            if let Some(category) = self.tool_registry.categorize(cmd)
                && !allowed.contains(&category)
            {
                let msg = format!(
                    "Blocked: '{}' requires {:?} which is not allowed in current scope",
                    cmd, category
                );
                self.events.send_feed(&self.agent_name, &msg, true);
                return Err(msg);
            }
            // Block unknown commands by default for security
            // This prevents bypassing restrictions via unregistered tools
            else if self.tool_registry.categorize(cmd).is_none() {
                let msg = format!(
                    "Blocked: '{}' is not in the tool registry and is blocked by default",
                    cmd
                );
                self.events.send_feed(&self.agent_name, &msg, true);
                return Err(msg);
            }
        }

        Ok(())
    }

    /// Parse SAST tool output and send code finding events
    fn parse_sast_findings(&self, command: &str, output: &str) {
        let cmd_lower = command.to_lowercase();

        // Try to parse grype output
        if cmd_lower.starts_with("grype")
            && cmd_lower.contains("-o json")
            && let Ok(grype_output) = GrypeOutput::parse(output)
        {
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

        // Try to parse semgrep/opengrep output (same JSON format)
        if (cmd_lower.starts_with("semgrep") || cmd_lower.starts_with("opengrep"))
            && cmd_lower.contains("--json")
            && let Ok(semgrep_output) = SemgrepOutput::parse(output)
        {
            // Determine tool name from command
            let tool_name = if cmd_lower.starts_with("opengrep") {
                "opengrep"
            } else {
                "semgrep"
            };
            for finding in semgrep_output.to_code_findings() {
                self.events.send_code_finding(
                    &self.agent_name,
                    &finding.file_path,
                    finding.line_number,
                    finding.severity,
                    finding.finding_type,
                    &finding.title,
                    tool_name,
                    finding.cwe_id.as_deref(),
                    None,
                );
            }
        }

        // Try to parse gitleaks output
        if cmd_lower.starts_with("gitleaks")
            && cmd_lower.contains("json")
            && let Ok(gitleaks_output) = GitleaksOutput::parse(output)
        {
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

        // Try to parse ast-grep output
        if cmd_lower.starts_with("ast-grep")
            && cmd_lower.contains("--json")
            && let Ok(astgrep_output) = super::sast::AstGrepOutput::parse(output)
        {
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

        // Try to parse discover_routes output
        if (cmd_lower.starts_with("discover_routes") || cmd_lower.contains("discover_routes"))
            && let Ok(routes_output) = serde_json::from_str::<RoutesOutput>(output)
        {
            let count = routes_output.routes.len();
            if count > 0 {
                self.events.send_feed(
                    &self.agent_name,
                    &format!("  -> discovered {} routes", count),
                    false,
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_single_command() {
        let cmds = extract_commands("naabu -host example.com");
        assert_eq!(cmds, vec!["naabu"]);
    }

    #[test]
    fn test_extract_pipe_commands() {
        let cmds = extract_commands("echo test | naabu -host example.com");
        assert_eq!(cmds, vec!["echo", "naabu"]);
    }

    #[test]
    fn test_extract_and_chain() {
        let cmds = extract_commands("ls && naabu -host example.com && echo done");
        assert_eq!(cmds, vec!["ls", "naabu", "echo"]);
    }

    #[test]
    fn test_extract_or_chain() {
        let cmds = extract_commands("naabu || subfinder -d example.com");
        assert_eq!(cmds, vec!["naabu", "subfinder"]);
    }

    #[test]
    fn test_extract_semicolon() {
        let cmds = extract_commands("echo start; naabu; echo end");
        assert_eq!(cmds, vec!["echo", "naabu", "echo"]);
    }

    #[test]
    fn test_extract_subshell() {
        let cmds = extract_commands("echo $(naabu -host test)");
        assert!(cmds.contains(&"naabu"));
    }

    #[test]
    fn test_extract_mixed_operators() {
        let cmds = extract_commands("cat file | grep x && naabu || subfinder; echo done");
        assert!(cmds.contains(&"cat"));
        assert!(cmds.contains(&"grep"));
        assert!(cmds.contains(&"naabu"));
        assert!(cmds.contains(&"subfinder"));
        assert!(cmds.contains(&"echo"));
    }
}
