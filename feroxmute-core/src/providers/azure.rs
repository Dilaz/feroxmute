//! Azure OpenAI provider implementation using rig-core

use std::sync::Arc;

use async_trait::async_trait;
use rig::client::CompletionClient;
use rig::completion::Prompt;
use rig::providers::azure;

use crate::docker::ContainerManager;
use crate::state::MetricsTracker;
use crate::tools::{
    CompleteEngagementTool, DockerShellTool, EventSender, ListAgentsTool, OrchestratorContext,
    RecordFindingTool, SpawnAgentTool, WaitForAgentTool, WaitForAnyTool,
};
use crate::{Error, Result};

use super::{CompletionRequest, CompletionResponse, LlmProvider, StopReason, TokenUsage};

/// Azure OpenAI provider using rig-core
pub struct AzureProvider {
    client: azure::Client,
    model: String,
    metrics: MetricsTracker,
}

impl AzureProvider {
    /// Create a new Azure OpenAI provider from environment variables
    pub fn new(model: impl Into<String>, metrics: MetricsTracker) -> Result<Self> {
        let api_key = std::env::var("AZURE_OPENAI_API_KEY")
            .map_err(|_| Error::Provider("AZURE_OPENAI_API_KEY not set".to_string()))?;
        let endpoint = std::env::var("AZURE_OPENAI_ENDPOINT")
            .map_err(|_| Error::Provider("AZURE_OPENAI_ENDPOINT not set".to_string()))?;

        let client = azure::Client::builder()
            .api_key(api_key)
            .azure_endpoint(endpoint)
            .build()
            .map_err(|e| Error::Provider(format!("Failed to build Azure client: {}", e)))?;

        Ok(Self {
            client,
            model: model.into(),
            metrics,
        })
    }

    /// Create with custom API key and endpoint
    pub fn with_api_key(
        api_key: impl Into<String>,
        endpoint: impl Into<String>,
        model: impl Into<String>,
        metrics: MetricsTracker,
    ) -> Result<Self> {
        let client = azure::Client::builder()
            .api_key(api_key.into())
            .azure_endpoint(endpoint.into())
            .build()
            .map_err(|e| Error::Provider(format!("Failed to build Azure client: {}", e)))?;

        Ok(Self {
            client,
            model: model.into(),
            metrics,
        })
    }
}

#[async_trait]
impl LlmProvider for AzureProvider {
    fn name(&self) -> &str {
        "azure"
    }

    fn supports_tools(&self) -> bool {
        true
    }

    async fn complete(&self, request: CompletionRequest) -> Result<CompletionResponse> {
        let prompt = request
            .messages
            .iter()
            .map(|m| format!("{:?}: {}", m.role, m.content))
            .collect::<Vec<_>>()
            .join("\n");

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
            .map_err(|e| Error::Provider(format!("Azure OpenAI completion failed: {}", e)))?;

        let estimated_input = prompt.len() as u64 / 4;
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

        // multi_turn enables tool loop with max 50 iterations
        tokio::select! {
            result = agent.prompt(user_prompt).multi_turn(50) => {
                result.map_err(|e| Error::Provider(format!("Orchestrator completion failed: {}", e)))
            }
            _ = context.cancel.cancelled() => {
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
        let original_key = std::env::var("AZURE_OPENAI_API_KEY").ok();
        let original_endpoint = std::env::var("AZURE_OPENAI_ENDPOINT").ok();
        std::env::remove_var("AZURE_OPENAI_API_KEY");
        std::env::remove_var("AZURE_OPENAI_ENDPOINT");

        let result = AzureProvider::new("gpt-4o", MetricsTracker::new());
        assert!(result.is_err());

        if let Some(key) = original_key {
            std::env::set_var("AZURE_OPENAI_API_KEY", key);
        }
        if let Some(endpoint) = original_endpoint {
            std::env::set_var("AZURE_OPENAI_ENDPOINT", endpoint);
        }
    }
}
