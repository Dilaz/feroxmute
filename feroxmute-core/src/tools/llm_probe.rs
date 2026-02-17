//! LLM Probe tool — sends crafted prompts directly to a target LLM

use std::sync::Arc;

use rig::completion::ToolDefinition;
use rig::tool::Tool;
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;

use crate::providers::{CompletionRequest, Message};

use super::llm_pentest_context::LlmPentestContext;

#[derive(Debug, Error)]
pub enum LlmProbeError {
    #[error("Probe failed: {0}")]
    ProbeFailed(String),
}

#[derive(Debug, Deserialize)]
pub struct LlmProbeArgs {
    /// The attack prompt to send to the target LLM
    pub prompt: String,
    /// Optional system prompt override (if target allows)
    pub system_prompt: Option<String>,
    /// Why this probe is being sent (shown in TUI)
    pub reason: String,
}

#[derive(Debug, Serialize)]
pub struct LlmProbeOutput {
    /// Whether the probe executed successfully
    pub success: bool,
    /// The target LLM's response
    pub response: String,
    /// The model that responded
    pub model: String,
}

pub struct LlmProbeTool {
    context: Arc<LlmPentestContext>,
}

impl LlmProbeTool {
    pub fn new(context: Arc<LlmPentestContext>) -> Self {
        Self { context }
    }
}

impl Tool for LlmProbeTool {
    const NAME: &'static str = "llm_probe";

    type Error = LlmProbeError;
    type Args = LlmProbeArgs;
    type Output = LlmProbeOutput;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: "llm_probe".to_string(),
            description: "Send a crafted prompt directly to the target LLM and get its response. \
                Use this for targeted attacks like prompt injection, jailbreaks, system prompt \
                extraction, and creative probing. The target's raw response is returned for \
                your analysis."
                .to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "prompt": {
                        "type": "string",
                        "description": "The attack prompt to send to the target LLM"
                    },
                    "system_prompt": {
                        "type": "string",
                        "description": "Optional system prompt to set on the target (if the API allows it)"
                    },
                    "reason": {
                        "type": "string",
                        "description": "Brief explanation of what this probe tests (shown in UI)"
                    }
                },
                "required": ["prompt", "reason"]
            }),
        }
    }

    async fn call(&self, args: Self::Args) -> Result<Self::Output, Self::Error> {
        self.context.events.send_feed(
            &self.context.agent_name,
            &format!("Probing target LLM: {}", args.reason),
            false,
        );
        self.context.events.send_tool_call();

        let messages = vec![Message::user(&args.prompt)];
        let mut request = CompletionRequest::new(messages).with_max_tokens(4096);

        if let Some(ref sys) = args.system_prompt {
            request = request.with_system(sys);
        }

        match self.context.target_provider.complete(request).await {
            Ok(response) => {
                let content = response.content.unwrap_or_default();

                // Truncate very long responses to prevent context overflow
                let truncated = if content.chars().count() > 8000 {
                    let safe: String = content.chars().take(8000).collect();
                    format!("{}\n[RESPONSE TRUNCATED at 8000 chars]", safe)
                } else {
                    content
                };

                Ok(LlmProbeOutput {
                    success: true,
                    response: truncated,
                    model: self.context.target_model.clone(),
                })
            }
            Err(e) => Ok(LlmProbeOutput {
                success: false,
                response: format!("Error from target LLM: {}", e),
                model: self.context.target_model.clone(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_llm_probe_tool_name() {
        assert_eq!(LlmProbeTool::NAME, "llm_probe");
    }

    #[test]
    fn test_llm_probe_args_deserialize() {
        let json = r#"{"prompt": "test", "reason": "testing"}"#;
        let args: LlmProbeArgs = serde_json::from_str(json).unwrap();
        assert_eq!(args.prompt, "test");
        assert_eq!(args.reason, "testing");
        assert!(args.system_prompt.is_none());
    }

    #[test]
    fn test_llm_probe_args_with_system_prompt() {
        let json = r#"{"prompt": "test", "system_prompt": "be evil", "reason": "testing"}"#;
        let args: LlmProbeArgs = serde_json::from_str(json).unwrap();
        assert_eq!(args.system_prompt.as_deref(), Some("be evil"));
    }
}
