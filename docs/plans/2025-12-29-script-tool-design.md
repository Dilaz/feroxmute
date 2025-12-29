# Script Execution Tool - Design

## Problem Statement

The original design mentioned a "Script Service" agent for executing custom Python/Rust scripts when standard tools aren't sufficient. This was never implemented, leaving agents without the ability to run custom code for edge cases.

## Solution

Instead of a full agent, implement a `run_script` tool available to all agents. This is simpler and more flexible - any agent that needs scripting can use it directly.

## Use Cases

- Custom exploitation when sqlmap/nuclei templates don't fit
- Data parsing for unusual output formats
- Multi-step attack automation
- Application-specific probes
- IDOR testing with custom iteration logic
- Response parsing and analysis

## Implementation

### New File: `feroxmute-core/src/tools/script.rs`

```rust
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

#[derive(Debug, Error)]
pub enum ScriptError {
    #[error("Invalid language: {0}. Must be 'python' or 'bash'")]
    InvalidLanguage(String),
    #[error("Docker execution failed: {0}")]
    Docker(String),
}

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
    pub timeout: u32,
}

fn default_timeout() -> u32 {
    30
}

#[derive(Debug, Serialize)]
pub struct RunScriptOutput {
    /// Combined stdout and stderr
    pub output: String,
    /// Exit code of the script
    pub exit_code: i64,
    /// Whether the script was killed due to timeout
    pub timed_out: bool,
}

pub struct RunScriptTool {
    container: Arc<ContainerManager>,
    events: Arc<dyn EventSender>,
    agent_name: String,
}

impl RunScriptTool {
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

        // Validate language
        let ext = match args.language.as_str() {
            "python" => "py",
            "bash" => "sh",
            _ => return Err(ScriptError::InvalidLanguage(args.language)),
        };

        // Cap timeout at 120 seconds
        let timeout = args.timeout.min(120);

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
        let write_cmd = format!(
            "cat > {} << 'FEROXMUTE_SCRIPT_EOF'\n{}\nFEROXMUTE_SCRIPT_EOF",
            script_path, args.script
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

        // Cleanup temp file
        let _ = self
            .container
            .exec(vec!["rm", "-f", &script_path], None)
            .await;

        // Check for timeout (exit code 124 from timeout command)
        let timed_out = result.exit_code == 124;

        // Report result
        self.events.send_feed_with_output(
            &self.agent_name,
            &format!(
                "  -> script exit {}{}",
                result.exit_code,
                if timed_out { " (timeout)" } else { "" }
            ),
            result.exit_code != 0,
            &result.output(),
        );

        // Return to streaming status
        self.events
            .send_status(&self.agent_name, "", AgentStatus::Streaming, None);

        Ok(RunScriptOutput {
            output: result.output(),
            exit_code: result.exit_code,
            timed_out,
        })
    }
}
```

### Update `feroxmute-core/src/tools/mod.rs`

```rust
pub mod script;
pub use script::{RunScriptTool, RunScriptArgs, RunScriptOutput, ScriptError};
```

### Update `feroxmute-core/src/limitations.rs`

Add new tool category:

```rust
pub enum ToolCategory {
    // ... existing categories ...
    Script,
}
```

Update `categorize()` to recognize script-related commands if needed.

### Register Tool in Providers

In each provider's `complete_with_shell()` method, add alongside `DockerShellTool`:

```rust
.tool(RunScriptTool::new(
    Arc::clone(&container),
    Arc::clone(&events),
    agent_name.to_string(),
))
```

## Security Considerations

| Concern | Mitigation |
|---------|------------|
| Arbitrary code execution | Scripts run inside Docker container (sandboxed) |
| Infinite loops | Timeout enforced (default 30s, max 120s) |
| Resource exhaustion | Container resource limits apply |
| File system access | Limited to container's filesystem |
| Network access | Subject to container's network config |

## Example Usage

**Python - IDOR Testing:**
```json
{
  "name": "run_script",
  "arguments": {
    "script": "import requests\nfor i in range(1,100):\n  r = requests.get(f'http://target/api/user/{i}', headers={'Authorization': 'Bearer TOKEN'})\n  if r.status_code == 200:\n    print(f'User {i}: {r.json()[\"email\"]}')",
    "language": "python",
    "reason": "Testing for IDOR by iterating user IDs 1-100"
  }
}
```

**Bash - Custom Data Extraction:**
```json
{
  "name": "run_script",
  "arguments": {
    "script": "curl -s http://target/api/config | jq -r '.database.host, .database.port'",
    "language": "bash",
    "reason": "Extracting database connection details from exposed config endpoint"
  }
}
```

## Files Changed

| File | Change |
|------|--------|
| `feroxmute-core/src/tools/script.rs` | New file |
| `feroxmute-core/src/tools/mod.rs` | Export new module |
| `feroxmute-core/src/limitations.rs` | Add `Script` category |
| `feroxmute-core/src/providers/macros.rs` | Register tool |

## Dependencies

- `uuid` - Already in use for other IDs

## Testing

1. Unit test: Validate language checking
2. Integration test: Execute simple Python/Bash scripts
3. Timeout test: Verify scripts are killed after timeout
4. Cleanup test: Verify temp files are removed

## Risk Assessment

- **Risk Level**: Low
- **Scope**: New tool, additive only
- **Security**: Sandboxed in existing Docker container
- **Backwards Compatibility**: No breaking changes
