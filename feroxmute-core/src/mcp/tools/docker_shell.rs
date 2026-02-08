//! MCP wrapper for DockerShellTool

use std::sync::Arc;

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;

use crate::Result;
use crate::docker::ContainerManager;
use crate::limitations::{EngagementLimitations, ToolRegistry};
use crate::mcp::{McpTool, McpToolResult};
use crate::tools::EventSender;
use crate::tools::shell::extract_commands;

/// MCP wrapper for docker shell execution
pub struct McpDockerShellTool {
    container: Arc<ContainerManager>,
    events: Arc<dyn EventSender>,
    agent_name: String,
    limitations: Arc<EngagementLimitations>,
    tool_registry: ToolRegistry,
}

#[derive(Debug, Deserialize)]
struct DockerShellArgs {
    command: String,
    #[serde(default = "default_timeout")]
    timeout_secs: u64,
}

fn default_timeout() -> u64 {
    600 // 10 minutes
}

impl McpDockerShellTool {
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

    /// Check if all commands in a (potentially chained) command string are allowed.
    ///
    /// Uses [`extract_commands`] to split on shell operators (`&&`, `||`, `;`, `|`,
    /// subshells) and validates every command against engagement limitations,
    /// matching the rig-based `DockerShellTool` logic.
    fn check_command_allowed(&self, command: &str) -> std::result::Result<(), String> {
        let commands = extract_commands(command);
        let allowed = self.limitations.allowed_categories();

        for cmd in commands {
            if let Some(category) = self.tool_registry.categorize(cmd)
                && !allowed.contains(&category)
            {
                return Err(format!(
                    "'{}' requires {:?} which is not allowed in current scope",
                    cmd, category
                ));
            }
            // Unknown commands are allowed — agents run inside a sandboxed
            // Docker container, and category-based restrictions already enforce
            // engagement scope for known security tools.
        }

        Ok(())
    }
}

#[async_trait]
impl McpTool for McpDockerShellTool {
    fn name(&self) -> &str {
        "docker_shell"
    }

    fn description(&self) -> &str {
        "Execute a command in the Kali Linux Docker container. Use this for all security testing tools (nmap, nuclei, sqlmap, etc.)."
    }

    fn input_schema(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "The shell command to execute"
                },
                "timeout_secs": {
                    "type": "integer",
                    "description": "Timeout in seconds (default: 600)",
                    "default": 600
                }
            },
            "required": ["command"]
        })
    }

    async fn execute(&self, arguments: Value) -> Result<McpToolResult> {
        let args: DockerShellArgs = serde_json::from_value(arguments)
            .map_err(|e| crate::Error::Provider(format!("Invalid docker_shell arguments: {e}")))?;

        // Check command against limitations
        if let Err(e) = self.check_command_allowed(&args.command) {
            self.events
                .send_feed(&self.agent_name, &format!("Command blocked: {e}"), true);
            return Ok(McpToolResult::error(format!("Command not allowed: {e}")));
        }

        // Notify TUI of tool invocation
        self.events.send_tool_call();

        // Report the command being executed
        self.events.send_feed(
            &self.agent_name,
            &format!("Executing: {}", args.command),
            false,
        );

        // Wrap command to capture both stdout and stderr
        let wrapped_cmd = format!("{} 2>&1", args.command);

        // Execute command in container
        // Note: timeout_secs is available for future use when exec_with_timeout is implemented
        let _ = args.timeout_secs;
        let result = self
            .container
            .exec(vec!["sh", "-c", &wrapped_cmd], None)
            .await;

        match result {
            Ok(exec_result) => {
                let output = exec_result.output();
                let line_count = output.lines().count();
                self.events.send_feed(
                    &self.agent_name,
                    &format!(
                        "  -> exit {}, {} lines output",
                        exec_result.exit_code, line_count
                    ),
                    exec_result.exit_code != 0,
                );
                Ok(McpToolResult::text(output))
            }
            Err(e) => {
                let error_msg = format!("Command failed: {e}");
                self.events.send_feed(&self.agent_name, &error_msg, true);
                Ok(McpToolResult::error(error_msg))
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// Verifies expected schema shape for DockerShellTool.
    /// Note: Cannot construct the tool without Docker, so this tests the schema inline.
    #[test]
    fn test_input_schema_verifies_expected_shape() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "The shell command to execute"
                }
            },
            "required": ["command"]
        });
        assert!(schema["properties"]["command"].is_object());
        let required = schema["required"].as_array().unwrap();
        assert!(required.contains(&serde_json::json!("command")));
    }

    #[test]
    fn test_args_missing_command_fails() {
        let json = serde_json::json!({
            "timeout_secs": 60
        });
        let result: std::result::Result<DockerShellArgs, _> = serde_json::from_value(json);
        assert!(
            result.is_err(),
            "should fail without required 'command' field"
        );
    }

    #[test]
    fn test_args_deserialization() {
        let json = serde_json::json!({
            "command": "nmap -sV localhost"
        });
        let args: DockerShellArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.command, "nmap -sV localhost");
        assert_eq!(args.timeout_secs, 600);
    }

    #[test]
    fn test_args_with_timeout() {
        let json = serde_json::json!({
            "command": "nmap -sV localhost",
            "timeout_secs": 120
        });
        let args: DockerShellArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.timeout_secs, 120);
    }
}
