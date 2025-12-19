//! Anthropic provider implementation using rig-core

use std::sync::Arc;

use async_trait::async_trait;
use rig::client::CompletionClient;
use rig::completion::Prompt;
use rig::providers::anthropic;

use crate::docker::ContainerManager;
use crate::state::MetricsTracker;
use crate::tools::DockerShellTool;
use crate::{Error, Result};

use super::{CompletionRequest, CompletionResponse, LlmProvider, StopReason, TokenUsage};

/// Anthropic provider using rig-core
pub struct AnthropicProvider {
    client: anthropic::Client,
    model: String,
    metrics: MetricsTracker,
}

impl AnthropicProvider {
    /// Create a new Anthropic provider from ANTHROPIC_API_KEY env var
    pub fn new(model: impl Into<String>, metrics: MetricsTracker) -> Result<Self> {
        let api_key = std::env::var("ANTHROPIC_API_KEY")
            .map_err(|_| Error::Provider("ANTHROPIC_API_KEY not set".to_string()))?;

        let client = anthropic::Client::builder()
            .api_key(api_key)
            .build()
            .map_err(|e| Error::Provider(format!("Failed to build Anthropic client: {}", e)))?;

        Ok(Self {
            client,
            model: model.into(),
            metrics,
        })
    }

    /// Create with custom API key
    pub fn with_api_key(
        api_key: impl Into<String>,
        model: impl Into<String>,
        metrics: MetricsTracker,
    ) -> Result<Self> {
        let client = anthropic::Client::builder()
            .api_key(api_key.into())
            .build()
            .map_err(|e| Error::Provider(format!("Failed to build Anthropic client: {}", e)))?;

        Ok(Self {
            client,
            model: model.into(),
            metrics,
        })
    }
}

#[async_trait]
impl LlmProvider for AnthropicProvider {
    fn name(&self) -> &str {
        "anthropic"
    }

    fn supports_tools(&self) -> bool {
        true
    }

    async fn complete(&self, request: CompletionRequest) -> Result<CompletionResponse> {
        // Build prompt from messages
        let prompt = request
            .messages
            .iter()
            .map(|m| format!("{:?}: {}", m.role, m.content))
            .collect::<Vec<_>>()
            .join("\n");

        // Build and execute request using Prompt trait with agent
        let agent = self
            .client
            .agent(&self.model)
            .preamble(
                request
                    .system
                    .as_deref()
                    .unwrap_or("You are a helpful assistant."),
            )
            .max_tokens(request.max_tokens.unwrap_or(4096) as u64)
            .build();

        let response = agent
            .prompt(&prompt)
            .await
            .map_err(|e| Error::Provider(format!("Anthropic completion failed: {}", e)))?;

        // Record token usage (estimated since rig doesn't expose raw usage directly)
        let estimated_input = prompt.len() as u64 / 4; // Rough token estimate
        let estimated_output = response.len() as u64 / 4;
        self.metrics
            .record_tokens(estimated_input, 0, estimated_output);

        Ok(CompletionResponse {
            content: Some(response),
            tool_calls: vec![],
            stop_reason: StopReason::EndTurn,
            usage: TokenUsage {
                input_tokens: estimated_input,
                output_tokens: estimated_output,
                cache_read_tokens: 0,
                cache_creation_tokens: 0,
            },
        })
    }

    async fn complete_with_shell(
        &self,
        system_prompt: &str,
        user_prompt: &str,
        container: Arc<ContainerManager>,
    ) -> Result<String> {
        let tool = DockerShellTool::new(container);

        let agent = self
            .client
            .agent(&self.model)
            .preamble(system_prompt)
            .max_tokens(4096)
            .tool(tool)
            .build();

        let response = agent
            .prompt(user_prompt)
            .await
            .map_err(|e| Error::Provider(format!("Anthropic completion failed: {}", e)))?;

        Ok(response)
    }

    fn metrics(&self) -> &MetricsTracker {
        &self.metrics
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_requires_api_key() {
        // Temporarily unset API key
        let original = std::env::var("ANTHROPIC_API_KEY").ok();
        std::env::remove_var("ANTHROPIC_API_KEY");

        let result = AnthropicProvider::new("claude-3-sonnet", MetricsTracker::new());
        assert!(result.is_err());

        // Restore
        if let Some(key) = original {
            std::env::set_var("ANTHROPIC_API_KEY", key);
        }
    }
}
