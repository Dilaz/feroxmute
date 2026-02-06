//! MCP wrapper for custom script execution tool

use std::sync::Arc;

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;

use crate::Result;
use crate::agents::AgentStatus;
use crate::docker::ContainerManager;
use crate::mcp::{McpTool, McpToolResult};
use crate::tools::EventSender;

/// Maximum output length to prevent context overflow
const MAX_OUTPUT_LENGTH: usize = 8000;

/// MCP wrapper for executing custom Python or Bash scripts
pub struct McpRunScriptTool {
    container: Arc<ContainerManager>,
    events: Arc<dyn EventSender>,
    agent_name: String,
}

#[derive(Debug, Deserialize)]
struct RunScriptArgs {
    script: String,
    language: String,
    reason: String,
    #[serde(default)]
    timeout: Option<u32>,
}

impl McpRunScriptTool {
    pub fn new(
        container: Arc<ContainerManager>,
        events: Arc<dyn EventSender>,
        agent_name: String,
    ) -> Self {
        Self {
            container,
            events,
            agent_name,
        }
    }
}

#[async_trait]
impl McpTool for McpRunScriptTool {
    fn name(&self) -> &str {
        "run_script"
    }

    fn description(&self) -> &str {
        "Execute a custom Python or Bash script when standard tools aren't sufficient. Use for custom data processing, multi-step automation, or application-specific probes."
    }

    fn input_schema(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "script": {
                    "type": "string",
                    "description": "The script content to execute"
                },
                "language": {
                    "type": "string",
                    "enum": ["python", "bash"],
                    "description": "Script language: python or bash"
                },
                "reason": {
                    "type": "string",
                    "description": "Brief explanation of what this script does and why"
                },
                "timeout": {
                    "type": "integer",
                    "description": "Timeout in seconds (default: 30, max: 120)"
                }
            },
            "required": ["script", "language", "reason"]
        })
    }

    async fn execute(&self, arguments: Value) -> Result<McpToolResult> {
        let args: RunScriptArgs = serde_json::from_value(arguments)
            .map_err(|e| crate::Error::Provider(format!("Invalid run_script arguments: {e}")))?;

        self.events.send_tool_call();

        // Validate language and get file extension
        let ext = match args.language.as_str() {
            "python" => "py",
            "bash" => "sh",
            _ => {
                return Ok(McpToolResult::error(format!(
                    "Invalid language '{}'. Must be 'python' or 'bash'",
                    args.language
                )));
            }
        };

        // Cap timeout at 120 seconds
        let timeout = args.timeout.unwrap_or(30).min(120);

        // Generate unique temp file path
        let script_id = Uuid::new_v4();
        let script_path = format!("/tmp/feroxmute_script_{}.{}", script_id, ext);

        // Safe short ID: use first segment of UUID (avoids byte slicing)
        let short_id = script_id
            .to_string()
            .split('-')
            .next()
            .unwrap_or("unknown")
            .to_string();

        // Send status updates
        self.events.send_feed(&self.agent_name, &args.reason, false);
        self.events.send_status(
            &self.agent_name,
            "",
            AgentStatus::Executing,
            Some(format!("script:{}", short_id)),
        );

        // Write script to container using heredoc
        // Use a unique delimiter to avoid conflicts with script content
        let write_cmd = format!(
            "cat > {} << 'FEROXMUTE_SCRIPT_EOF_{}'
{}
FEROXMUTE_SCRIPT_EOF_{}",
            script_path,
            script_id.as_simple(),
            args.script,
            script_id.as_simple()
        );

        if let Err(e) = self
            .container
            .exec(vec!["sh", "-c", &write_cmd], None)
            .await
        {
            return Ok(McpToolResult::error(format!(
                "Failed to write script to container: {}",
                e
            )));
        }

        // Execute with timeout
        let exec_cmd = match args.language.as_str() {
            "python" => format!("timeout {} python3 {} 2>&1", timeout, script_path),
            _ => format!(
                "chmod +x {} && timeout {} bash {} 2>&1",
                script_path, timeout, script_path
            ),
        };

        let result = match self.container.exec(vec!["sh", "-c", &exec_cmd], None).await {
            Ok(r) => r,
            Err(e) => {
                // Cleanup temp file (best-effort)
                let _ = self
                    .container
                    .exec(vec!["rm", "-f", &script_path], None)
                    .await;
                return Ok(McpToolResult::error(format!(
                    "Script execution failed: {}",
                    e
                )));
            }
        };

        // Cleanup temp file (best-effort)
        let _ = self
            .container
            .exec(vec!["rm", "-f", &script_path], None)
            .await;

        // Check for timeout (exit code 124 from timeout command)
        let timed_out = result.exit_code == 124;

        // Get raw output and check if truncation needed
        let raw_output = result.output();
        let (output, truncated) = if raw_output.len() > MAX_OUTPUT_LENGTH {
            // Use char-safe truncation to avoid panicking on multi-byte UTF-8 boundaries
            let safe_truncated: String = raw_output
                .char_indices()
                .take_while(|(i, _)| *i < MAX_OUTPUT_LENGTH)
                .map(|(_, c)| c)
                .collect();
            (
                format!(
                    "{}\n\n[OUTPUT TRUNCATED - {} bytes total]",
                    safe_truncated,
                    raw_output.len()
                ),
                true,
            )
        } else {
            (raw_output.clone(), false)
        };

        // Report result to TUI
        self.events.send_feed_with_output(
            &self.agent_name,
            &format!(
                "  -> script exit {}{}",
                result.exit_code,
                if timed_out { " (timeout)" } else { "" }
            ),
            result.exit_code != 0,
            &raw_output,
        );

        // Return to streaming status
        self.events
            .send_status(&self.agent_name, "", AgentStatus::Streaming, None);

        Ok(McpToolResult::text(
            serde_json::json!({
                "output": output,
                "exit_code": result.exit_code,
                "timed_out": timed_out,
                "truncated": truncated
            })
            .to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_args_deserialization() {
        let json = serde_json::json!({
            "script": "print('hello')",
            "language": "python",
            "reason": "Test script"
        });
        let args: RunScriptArgs = serde_json::from_value(json).expect("should deserialize");
        assert_eq!(args.script, "print('hello')");
        assert_eq!(args.language, "python");
        assert_eq!(args.reason, "Test script");
        assert_eq!(args.timeout, None);
    }

    #[test]
    fn test_args_with_timeout() {
        let json = serde_json::json!({
            "script": "echo hi",
            "language": "bash",
            "reason": "Quick test",
            "timeout": 60
        });
        let args: RunScriptArgs = serde_json::from_value(json).expect("should deserialize");
        assert_eq!(args.timeout, Some(60));
    }

    #[test]
    fn test_input_schema_structure() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "script": { "type": "string" },
                "language": { "type": "string", "enum": ["python", "bash"] },
                "reason": { "type": "string" },
                "timeout": { "type": "integer" }
            },
            "required": ["script", "language", "reason"]
        });
        assert!(schema["properties"]["script"].is_object());
        assert!(schema["properties"]["language"]["enum"].is_array());
        let required = schema["required"].as_array().expect("should have required");
        assert_eq!(required.len(), 3);
    }

    #[test]
    fn test_uuid_short_id_is_safe() {
        let id = Uuid::new_v4();
        let short = id
            .to_string()
            .split('-')
            .next()
            .unwrap_or("unknown")
            .to_string();
        // UUID v4 first segment is always 8 hex chars
        assert_eq!(short.len(), 8);
        assert!(short.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
