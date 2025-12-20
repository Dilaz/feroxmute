//! Docker shell tool for rig agents

use std::sync::Arc;

use rig::completion::ToolDefinition;
use rig::tool::Tool;
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;

use crate::docker::ContainerManager;

/// Arguments for the shell tool
#[derive(Debug, Deserialize)]
pub struct ShellArgs {
    /// The shell command to execute
    pub command: String,
    /// Brief explanation shown to user in real-time
    pub reason: String,
}

/// Output from the shell tool
#[derive(Debug, Serialize)]
pub struct ShellOutput {
    /// Combined stdout and stderr
    pub output: String,
    /// Exit code of the command
    pub exit_code: i64,
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
}

impl DockerShellTool {
    /// Create a new Docker shell tool
    pub fn new(container: Arc<ContainerManager>) -> Self {
        Self { container }
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
        // Wrap command to capture both stdout and stderr
        let wrapped_cmd = format!("{} 2>&1", args.command);

        let result = self
            .container
            .exec(vec!["sh", "-c", &wrapped_cmd], None)
            .await
            .map_err(|e| ShellError::Docker(e.to_string()))?;

        Ok(ShellOutput {
            output: result.output(),
            exit_code: result.exit_code,
        })
    }
}
