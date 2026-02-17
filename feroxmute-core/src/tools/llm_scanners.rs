//! LLM scanning tool wrappers — Garak, Promptfoo, PyRIT

use std::sync::Arc;

use rig::completion::ToolDefinition;
use rig::tool::Tool;
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;

use super::llm_pentest_context::LlmPentestContext;

#[derive(Debug, Error)]
pub enum LlmScannerError {
    #[error("Scanner failed: {0}")]
    ScanFailed(String),
}

// ============================================================================
// GarakScanTool
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct GarakScanArgs {
    /// Garak probe name(s), comma-separated (e.g. "encoding", "dan.Dan_11_0")
    pub probes: String,
    /// Reason for running this scan
    pub reason: String,
}

#[derive(Debug, Serialize)]
pub struct GarakScanOutput {
    pub success: bool,
    pub output: String,
}

pub struct GarakScanTool {
    context: Arc<LlmPentestContext>,
}

impl GarakScanTool {
    pub fn new(context: Arc<LlmPentestContext>) -> Self {
        Self { context }
    }

    fn build_command(&self, args: &GarakScanArgs) -> String {
        let mut cmd = String::new();

        // Prepend env vars for garak
        cmd.push_str(&self.build_env_prefix());

        cmd.push_str("python3 -m garak");

        // Map provider name to garak target type
        let target_type = match self.context.target_provider_name.as_str() {
            "openai" | "azure" => "openai",
            "anthropic" => "anthropic",
            "ollama" => "ollama",
            _ => "rest",
        };

        cmd.push_str(&format!(" --model_type {}", target_type));
        cmd.push_str(&format!(" --model_name {}", self.context.target_model));
        cmd.push_str(&format!(" --probes {}", args.probes));

        // JSON report output
        cmd.push_str(" --report_prefix /tmp/garak_report");

        cmd
    }

    fn build_env_prefix(&self) -> String {
        let mut env_parts = vec![
            format!(
                "export TARGET_LLM_API_KEY='{}';",
                self.context.target_api_key
            ),
            format!("export TARGET_LLM_MODEL='{}';", self.context.target_model),
        ];

        if let Some(ref url) = self.context.target_base_url {
            env_parts.push(format!("export TARGET_LLM_BASE_URL='{}';", url));
        }

        // Provider-specific env vars that garak expects
        match self.context.target_provider_name.as_str() {
            "openai" | "azure" => {
                env_parts.push(format!(
                    "export OPENAI_API_KEY='{}';",
                    self.context.target_api_key
                ));
                if let Some(ref url) = self.context.target_base_url {
                    env_parts.push(format!("export OPENAI_API_BASE='{}';", url));
                }
            }
            "anthropic" => {
                env_parts.push(format!(
                    "export ANTHROPIC_API_KEY='{}';",
                    self.context.target_api_key
                ));
            }
            _ => {}
        }

        env_parts.join(" ")
    }
}

impl Tool for GarakScanTool {
    const NAME: &'static str = "garak_scan";

    type Error = LlmScannerError;
    type Args = GarakScanArgs;
    type Output = GarakScanOutput;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: "garak_scan".to_string(),
            description: "Run NVIDIA's Garak LLM vulnerability scanner against the target. \
                Garak has 100+ built-in probes for prompt injection, jailbreaks, data leakage, \
                toxicity, and more. Use this for broad automated vulnerability scanning."
                .to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "probes": {
                        "type": "string",
                        "description": "Garak probe name(s), comma-separated. Examples: 'encoding', 'dan.Dan_11_0', 'leakreplay', 'knownbadsignatures', 'malwaregen', 'xss'"
                    },
                    "reason": {
                        "type": "string",
                        "description": "Brief explanation of what this scan tests"
                    }
                },
                "required": ["probes", "reason"]
            }),
        }
    }

    async fn call(&self, args: Self::Args) -> Result<Self::Output, Self::Error> {
        self.context.events.send_feed(
            &self.context.agent_name,
            &format!(
                "Running Garak scan: {} (probes: {})",
                args.reason, args.probes
            ),
            false,
        );
        self.context.events.send_tool_call();

        let cmd = self.build_command(&args);

        // Execute in Docker container
        match self
            .context
            .container
            .exec(vec!["bash", "-c", &cmd], None)
            .await
        {
            Ok(result) => {
                let output = format!("{}{}", result.stdout, result.stderr);
                let truncated = if output.len() > 8000 {
                    let safe = output.chars().take(8000).collect::<String>();
                    format!("{}\n[OUTPUT TRUNCATED]", safe)
                } else {
                    output
                };

                Ok(GarakScanOutput {
                    success: result.exit_code == 0,
                    output: truncated,
                })
            }
            Err(e) => Ok(GarakScanOutput {
                success: false,
                output: format!("Garak scan failed: {}", e),
            }),
        }
    }
}

// ============================================================================
// PromptfooScanTool
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct PromptfooScanArgs {
    /// YAML configuration for the Promptfoo test suite
    pub config_yaml: String,
    /// Reason for running this scan
    pub reason: String,
}

#[derive(Debug, Serialize)]
pub struct PromptfooScanOutput {
    pub success: bool,
    pub output: String,
}

pub struct PromptfooScanTool {
    context: Arc<LlmPentestContext>,
}

impl PromptfooScanTool {
    pub fn new(context: Arc<LlmPentestContext>) -> Self {
        Self { context }
    }

    fn build_env_prefix(&self) -> String {
        let mut env_parts = vec![format!(
            "export TARGET_LLM_API_KEY='{}';",
            self.context.target_api_key,
        )];

        match self.context.target_provider_name.as_str() {
            "openai" | "azure" => {
                env_parts.push(format!(
                    "export OPENAI_API_KEY='{}';",
                    self.context.target_api_key
                ));
                if let Some(ref url) = self.context.target_base_url {
                    env_parts.push(format!("export OPENAI_API_BASE='{}';", url));
                }
            }
            "anthropic" => {
                env_parts.push(format!(
                    "export ANTHROPIC_API_KEY='{}';",
                    self.context.target_api_key
                ));
            }
            _ => {}
        }

        env_parts.join(" ")
    }
}

impl Tool for PromptfooScanTool {
    const NAME: &'static str = "promptfoo_scan";

    type Error = LlmScannerError;
    type Args = PromptfooScanArgs;
    type Output = PromptfooScanOutput;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: "promptfoo_scan".to_string(),
            description: "Run Promptfoo red team evaluation against the target LLM. Promptfoo \
                supports OWASP LLM Top 10 compliance mapping, structured test suites, and \
                graded results. Provide a YAML config defining the test cases."
                .to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "config_yaml": {
                        "type": "string",
                        "description": "YAML configuration for the Promptfoo evaluation. Define providers, prompts, and test assertions."
                    },
                    "reason": {
                        "type": "string",
                        "description": "Brief explanation of what this evaluation tests"
                    }
                },
                "required": ["config_yaml", "reason"]
            }),
        }
    }

    async fn call(&self, args: Self::Args) -> Result<Self::Output, Self::Error> {
        self.context.events.send_feed(
            &self.context.agent_name,
            &format!("Running Promptfoo evaluation: {}", args.reason),
            false,
        );
        self.context.events.send_tool_call();

        // Write config to temp file, then run promptfoo
        let escaped_yaml = args.config_yaml.replace('\'', "'\\''");
        let env_prefix = self.build_env_prefix();
        let cmd = format!(
            "{} echo '{}' > /tmp/promptfoo_config.yaml && \
             promptfoo eval -c /tmp/promptfoo_config.yaml --no-cache 2>&1",
            env_prefix, escaped_yaml
        );

        match self
            .context
            .container
            .exec(vec!["bash", "-c", &cmd], None)
            .await
        {
            Ok(result) => {
                let output = format!("{}{}", result.stdout, result.stderr);
                let truncated = if output.len() > 8000 {
                    let safe = output.chars().take(8000).collect::<String>();
                    format!("{}\n[OUTPUT TRUNCATED]", safe)
                } else {
                    output
                };

                Ok(PromptfooScanOutput {
                    success: result.exit_code == 0,
                    output: truncated,
                })
            }
            Err(e) => Ok(PromptfooScanOutput {
                success: false,
                output: format!("Promptfoo evaluation failed: {}", e),
            }),
        }
    }
}

// ============================================================================
// PyritAttackTool
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct PyritAttackArgs {
    /// Python script to execute using PyRIT
    pub script: String,
    /// Reason for running this attack
    pub reason: String,
}

#[derive(Debug, Serialize)]
pub struct PyritAttackOutput {
    pub success: bool,
    pub output: String,
}

pub struct PyritAttackTool {
    context: Arc<LlmPentestContext>,
}

impl PyritAttackTool {
    pub fn new(context: Arc<LlmPentestContext>) -> Self {
        Self { context }
    }

    fn build_env_prefix(&self) -> String {
        let mut env_parts = vec![
            format!(
                "export TARGET_LLM_API_KEY='{}';",
                self.context.target_api_key
            ),
            format!("export TARGET_LLM_MODEL='{}';", self.context.target_model),
        ];

        if let Some(ref url) = self.context.target_base_url {
            env_parts.push(format!("export TARGET_LLM_BASE_URL='{}';", url));
        }

        match self.context.target_provider_name.as_str() {
            "openai" | "azure" => {
                env_parts.push(format!(
                    "export OPENAI_API_KEY='{}';",
                    self.context.target_api_key
                ));
            }
            "anthropic" => {
                env_parts.push(format!(
                    "export ANTHROPIC_API_KEY='{}';",
                    self.context.target_api_key
                ));
            }
            _ => {}
        }

        env_parts.join(" ")
    }
}

impl Tool for PyritAttackTool {
    const NAME: &'static str = "pyrit_attack";

    type Error = LlmScannerError;
    type Args = PyritAttackArgs;
    type Output = PyritAttackOutput;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: "pyrit_attack".to_string(),
            description: "Run a PyRIT (Python Risk Identification Toolkit) attack script \
                against the target LLM. PyRIT excels at multi-turn orchestrated attacks with \
                converters and scoring. Write a Python script using PyRIT's API."
                .to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "script": {
                        "type": "string",
                        "description": "Python script using PyRIT's API. The target endpoint is available via TARGET_LLM_API_KEY and TARGET_LLM_BASE_URL environment variables."
                    },
                    "reason": {
                        "type": "string",
                        "description": "Brief explanation of what this attack tests"
                    }
                },
                "required": ["script", "reason"]
            }),
        }
    }

    async fn call(&self, args: Self::Args) -> Result<Self::Output, Self::Error> {
        self.context.events.send_feed(
            &self.context.agent_name,
            &format!("Running PyRIT attack: {}", args.reason),
            false,
        );
        self.context.events.send_tool_call();

        // Write script to temp file, then execute
        let escaped_script = args.script.replace('\'', "'\\''");
        let env_prefix = self.build_env_prefix();
        let cmd = format!(
            "{} echo '{}' > /tmp/pyrit_attack.py && python3 /tmp/pyrit_attack.py 2>&1",
            env_prefix, escaped_script
        );

        match self
            .context
            .container
            .exec(vec!["bash", "-c", &cmd], None)
            .await
        {
            Ok(result) => {
                let output = format!("{}{}", result.stdout, result.stderr);
                let truncated = if output.len() > 8000 {
                    let safe = output.chars().take(8000).collect::<String>();
                    format!("{}\n[OUTPUT TRUNCATED]", safe)
                } else {
                    output
                };

                Ok(PyritAttackOutput {
                    success: result.exit_code == 0,
                    output: truncated,
                })
            }
            Err(e) => Ok(PyritAttackOutput {
                success: false,
                output: format!("PyRIT attack failed: {}", e),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_garak_tool_name() {
        assert_eq!(GarakScanTool::NAME, "garak_scan");
    }

    #[test]
    fn test_promptfoo_tool_name() {
        assert_eq!(PromptfooScanTool::NAME, "promptfoo_scan");
    }

    #[test]
    fn test_pyrit_tool_name() {
        assert_eq!(PyritAttackTool::NAME, "pyrit_attack");
    }

    #[test]
    fn test_garak_args_deserialize() {
        let json = r#"{"probes": "encoding,dan", "reason": "test injection"}"#;
        let args: GarakScanArgs = serde_json::from_str(json).unwrap();
        assert_eq!(args.probes, "encoding,dan");
    }

    #[test]
    fn test_promptfoo_args_deserialize() {
        let json = r#"{"config_yaml": "providers:\n  - openai:gpt-4", "reason": "owasp test"}"#;
        let args: PromptfooScanArgs = serde_json::from_str(json).unwrap();
        assert!(args.config_yaml.contains("providers"));
    }

    #[test]
    fn test_pyrit_args_deserialize() {
        let json = r#"{"script": "from pyrit import *", "reason": "crescendo attack"}"#;
        let args: PyritAttackArgs = serde_json::from_str(json).unwrap();
        assert!(args.script.contains("pyrit"));
    }
}
