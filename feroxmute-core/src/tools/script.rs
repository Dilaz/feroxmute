//! Script execution tool for custom Python/Bash scripts

use std::sync::Arc;

use rig::completion::ToolDefinition;
use rig::tool::Tool;
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;
use uuid::Uuid;

use crate::agents::AgentStatus;
use crate::docker::ContainerManager;
use crate::tools::EventSender;

/// Maximum output length to prevent context overflow
const MAX_OUTPUT_LENGTH: usize = 8000;

/// Errors from the script tool
#[derive(Debug, Error)]
pub enum ScriptError {
    #[error("Invalid language: {0}. Must be 'python' or 'bash'")]
    InvalidLanguage(String),
    #[error("Docker execution failed: {0}")]
    Docker(String),
}

/// Arguments for the script tool
#[derive(Debug, Deserialize)]
pub struct RunScriptArgs {
    /// The script content to execute
    pub script: String,
    /// Language: "python" or "bash"
    pub language: String,
    /// Brief explanation of what the script does
    pub reason: String,
    /// Timeout in seconds (default: 30, max: 120)
    #[serde(default = "default_timeout")]
    pub timeout: Option<u32>,
}

fn default_timeout() -> Option<u32> {
    Some(30)
}

/// Output from the script tool
#[derive(Debug, Serialize)]
pub struct RunScriptOutput {
    /// Combined stdout and stderr
    pub output: String,
    /// Exit code of the script
    pub exit_code: i64,
    /// Whether the script was killed due to timeout
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub timed_out: bool,
    /// Whether output was truncated
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,
}

/// Tool for executing custom Python or Bash scripts
pub struct RunScriptTool {
    container: Arc<ContainerManager>,
    events: Arc<dyn EventSender>,
    agent_name: String,
}

impl RunScriptTool {
    /// Create a new script tool
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

impl Tool for RunScriptTool {
    const NAME: &'static str = "run_script";

    type Error = ScriptError;
    type Args = RunScriptArgs;
    type Output = RunScriptOutput;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: "run_script".to_string(),
            description: "Execute a custom Python or Bash script when standard tools aren't sufficient. Use for custom data processing, multi-step automation, or application-specific probes.".to_string(),
            parameters: json!({
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
            }),
        }
    }

    async fn call(&self, args: Self::Args) -> Result<Self::Output, Self::Error> {
        // Notify TUI of tool invocation
        self.events.send_tool_call();

        // Validate language and get file extension
        let ext = match args.language.as_str() {
            "python" => "py",
            "bash" => "sh",
            _ => return Err(ScriptError::InvalidLanguage(args.language)),
        };

        // Cap timeout at 120 seconds
        let timeout = args.timeout.unwrap_or(30).min(120);

        // Generate unique temp file path
        let script_id = Uuid::new_v4();
        let script_path = format!("/tmp/feroxmute_script_{}.{}", script_id, ext);

        // Send status updates
        self.events.send_feed(&self.agent_name, &args.reason, false);
        self.events.send_status(
            &self.agent_name,
            "",
            AgentStatus::Executing,
            Some(format!("script:{}", &script_id.to_string()[..8])),
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

        self.container
            .exec(vec!["sh", "-c", &write_cmd], None)
            .await
            .map_err(|e| ScriptError::Docker(e.to_string()))?;

        // Execute with timeout
        let exec_cmd = match args.language.as_str() {
            "python" => format!("timeout {} python3 {} 2>&1", timeout, script_path),
            "bash" => format!(
                "chmod +x {} && timeout {} bash {} 2>&1",
                script_path, timeout, script_path
            ),
            _ => unreachable!(),
        };

        let result = self
            .container
            .exec(vec!["sh", "-c", &exec_cmd], None)
            .await
            .map_err(|e| ScriptError::Docker(e.to_string()))?;

        // Cleanup temp file (ignore errors)
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

        // Report result
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

        Ok(RunScriptOutput {
            output,
            exit_code: result.exit_code,
            timed_out,
            truncated,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_timeout() {
        assert_eq!(default_timeout(), Some(30));
    }
}
