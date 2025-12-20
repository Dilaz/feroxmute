//! OpenAI provider implementation using rig-core

use std::sync::Arc;

use async_trait::async_trait;
use rig::client::CompletionClient;
use rig::completion::Prompt;
use rig::providers::openai;

use crate::docker::ContainerManager;
use crate::state::MetricsTracker;
use crate::tools::{
    CompleteEngagementTool, DockerShellTool, EventSender, ListAgentsTool, OrchestratorContext,
    RecordFindingTool, SpawnAgentTool, WaitForAgentTool, WaitForAnyTool,
};
use crate::{Error, Result};

use super::{CompletionRequest, CompletionResponse, LlmProvider, StopReason, TokenUsage};

/// OpenAI provider using rig-core
pub struct OpenAiProvider {
    client: openai::Client,
    model: String,
    metrics: MetricsTracker,
}

impl OpenAiProvider {
    /// Create a new OpenAI provider from OPENAI_API_KEY env var
    pub fn new(model: impl Into<String>, metrics: MetricsTracker) -> Result<Self> {
        let api_key = std::env::var("OPENAI_API_KEY")
            .map_err(|_| Error::Provider("OPENAI_API_KEY not set".to_string()))?;

        let client = openai::Client::builder()
            .api_key(api_key)
            .build()
            .map_err(|e| Error::Provider(format!("Failed to build OpenAI client: {}", e)))?;

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
        let client = openai::Client::builder()
            .api_key(api_key.into())
            .build()
            .map_err(|e| Error::Provider(format!("Failed to build OpenAI client: {}", e)))?;

        Ok(Self {
            client,
            model: model.into(),
            metrics,
        })
    }

    /// Create with custom base URL (for LiteLLM proxy or compatible APIs)
    pub fn with_base_url(
        api_key: impl Into<String>,
        base_url: impl Into<String>,
        model: impl Into<String>,
        metrics: MetricsTracker,
    ) -> Result<Self> {
        let client = openai::Client::builder()
            .api_key(api_key.into())
            .base_url(base_url.into())
            .build()
            .map_err(|e| Error::Provider(format!("Failed to build OpenAI client: {}", e)))?;

        Ok(Self {
            client,
            model: model.into(),
            metrics,
        })
    }
}

#[async_trait]
impl LlmProvider for OpenAiProvider {
    fn name(&self) -> &str {
        "openai"
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
            .map_err(|e| Error::Provider(format!("OpenAI completion failed: {}", e)))?;

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
        events: Arc<dyn EventSender>,
        agent_name: &str,
    ) -> Result<String> {
        let agent = self
            .client
            .agent(&self.model)
            .preamble(system_prompt)
            .max_tokens(4096)
            .tool(DockerShellTool::new(
                container,
                events,
                agent_name.to_string(),
            ))
            .build();

        // multi_turn enables tool loop with max 50 iterations
        agent
            .prompt(user_prompt)
            .multi_turn(50)
            .await
            .map_err(|e| Error::Provider(format!("Shell completion failed: {}", e)))
    }

    async fn complete_with_orchestrator(
        &self,
        system_prompt: &str,
        user_prompt: &str,
        context: Arc<OrchestratorContext>,
    ) -> Result<String> {
        let agent = self
            .client
            .agent(&self.model)
            .preamble(system_prompt)
            .max_tokens(4096)
            .tool(SpawnAgentTool::new(Arc::clone(&context)))
            .tool(WaitForAgentTool::new(Arc::clone(&context)))
            .tool(WaitForAnyTool::new(Arc::clone(&context)))
            .tool(ListAgentsTool::new(Arc::clone(&context)))
            .tool(RecordFindingTool::new(Arc::clone(&context)))
            .tool(CompleteEngagementTool::new(Arc::clone(&context)))
            .build();

        // Run with cancellation support (multi_turn enables tool loop with max 50 iterations)
        tokio::select! {
            result = agent.prompt(user_prompt).multi_turn(50) => {
                result.map_err(|e| Error::Provider(format!("Orchestrator completion failed: {}", e)))
            }
            _ = context.cancel.cancelled() => {
                // Engagement was completed via complete_engagement tool
                let findings = context.findings.lock().await;
                Ok(format!("Engagement completed with {} findings", findings.len()))
            }
        }
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
        let original = std::env::var("OPENAI_API_KEY").ok();
        std::env::remove_var("OPENAI_API_KEY");

        let result = OpenAiProvider::new("gpt-4o", MetricsTracker::new());
        assert!(result.is_err());

        // Restore
        if let Some(key) = original {
            std::env::set_var("OPENAI_API_KEY", key);
        }
    }

    #[test]
    fn test_provider_with_api_key() {
        let result = OpenAiProvider::with_api_key("test-key", "gpt-4o", MetricsTracker::new());
        assert!(result.is_ok());

        let provider = result.unwrap();
        assert_eq!(provider.name(), "openai");
        assert!(provider.supports_tools());
    }

    #[test]
    fn test_provider_with_base_url() {
        let result = OpenAiProvider::with_base_url(
            "test-key",
            "http://localhost:4000",
            "gpt-4o",
            MetricsTracker::new(),
        );
        assert!(result.is_ok());
    }
}
