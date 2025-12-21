//! Ollama provider implementation using rig-core

use std::sync::Arc;

use async_trait::async_trait;
use rig::client::{CompletionClient, Nothing};
use rig::completion::Prompt;
use rig::providers::ollama;

use crate::docker::ContainerManager;
use crate::limitations::EngagementLimitations;
use crate::pricing::PricingConfig;
use crate::state::MetricsTracker;
use crate::tools::{
    AddRecommendationTool, CompleteEngagementTool, DockerShellTool, EventSender, ExportJsonTool,
    ExportMarkdownTool, GenerateReportTool, ListAgentsTool, OrchestratorContext, RecordFindingTool,
    ReportContext, SpawnAgentTool, WaitForAgentTool, WaitForAnyTool,
};
use crate::{Error, Result};

use super::{CompletionRequest, CompletionResponse, LlmProvider, StopReason, TokenUsage};

/// Estimate token count from text (roughly 4 characters per token for English)
/// This is used as a fallback when Ollama doesn't return actual token counts
fn estimate_tokens(text: &str) -> u64 {
    (text.len() as u64 + 3) / 4 // Round up
}

/// Ollama provider using rig-core
pub struct OllamaProvider {
    client: ollama::Client,
    model: String,
    metrics: MetricsTracker,
}

impl OllamaProvider {
    /// Create with default localhost URL (http://localhost:11434)
    pub fn new(model: impl Into<String>, metrics: MetricsTracker) -> Result<Self> {
        let client = ollama::Client::builder()
            .api_key(Nothing)
            .build()
            .map_err(|e| Error::Provider(format!("Failed to build Ollama client: {}", e)))?;

        Ok(Self {
            client,
            model: model.into(),
            metrics,
        })
    }

    /// Create with custom base URL
    pub fn with_base_url(
        base_url: impl Into<String>,
        model: impl Into<String>,
        metrics: MetricsTracker,
    ) -> Result<Self> {
        let client = ollama::Client::builder()
            .api_key(Nothing)
            .base_url(base_url.into())
            .build()
            .map_err(|e| Error::Provider(format!("Failed to build Ollama client: {}", e)))?;

        Ok(Self {
            client,
            model: model.into(),
            metrics,
        })
    }

    /// Create from OLLAMA_API_BASE_URL environment variable
    pub fn from_env(model: impl Into<String>, metrics: MetricsTracker) -> Result<Self> {
        let base_url = std::env::var("OLLAMA_API_BASE_URL")
            .map_err(|_| Error::Provider("OLLAMA_API_BASE_URL not set".to_string()))?;

        Self::with_base_url(base_url, model, metrics)
    }
}

#[async_trait]
impl LlmProvider for OllamaProvider {
    fn name(&self) -> &str {
        "ollama"
    }

    fn supports_tools(&self) -> bool {
        // Ollama supports tool calling with compatible models (llama3.1+, mistral, etc.)
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
            .map_err(|e| Error::Provider(format!("Ollama completion failed: {}", e)))?;

        // Record token usage (estimated since rig doesn't expose raw usage directly)
        let estimated_input = prompt.len() as u64 / 4; // Rough token estimate
        let estimated_output = response.len() as u64 / 4;
        let pricing = PricingConfig::load();
        let cost = pricing.calculate_cost("ollama", &self.model, estimated_input, estimated_output);
        self.metrics
            .record_tokens(estimated_input, 0, estimated_output, cost);

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
        limitations: Arc<EngagementLimitations>,
    ) -> Result<String> {
        let events_clone = Arc::clone(&events);
        let agent = self
            .client
            .agent(&self.model)
            .preamble(system_prompt)
            .max_tokens(4096)
            .tool(DockerShellTool::new(
                container,
                events,
                agent_name.to_string(),
                limitations,
            ))
            .build();

        // multi_turn enables tool loop with max 50 iterations
        // extended_details() gives us real token usage
        let response = agent
            .prompt(user_prompt)
            .extended_details()
            .multi_turn(50)
            .await
            .map_err(|e| Error::Provider(format!("Shell completion failed: {}", e)))?;

        // Use actual token counts if available, otherwise estimate
        // Ollama models may not always report token usage
        let input_tokens = if response.total_usage.input_tokens > 0 {
            response.total_usage.input_tokens
        } else {
            estimate_tokens(system_prompt) + estimate_tokens(user_prompt)
        };
        let output_tokens = if response.total_usage.output_tokens > 0 {
            response.total_usage.output_tokens
        } else {
            estimate_tokens(&response.output)
        };

        // Calculate cost
        let pricing = PricingConfig::load();
        let cost = pricing.calculate_cost("ollama", &self.model, input_tokens, output_tokens);

        // Note: Tool call count not available in non-streaming mode
        events_clone.send_metrics(input_tokens, output_tokens, 0, cost, 0);

        Ok(response.output)
    }

    async fn complete_with_orchestrator(
        &self,
        system_prompt: &str,
        user_prompt: &str,
        context: Arc<OrchestratorContext>,
    ) -> Result<String> {
        let events = Arc::clone(&context.events);
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
        // extended_details() gives us real token usage
        tokio::select! {
            result = agent.prompt(user_prompt).extended_details().multi_turn(50) => {
                match result {
                    Ok(response) => {
                        // Use actual token counts if available, otherwise estimate
                        // Ollama models may not always report token usage
                        let input_tokens = if response.total_usage.input_tokens > 0 {
                            response.total_usage.input_tokens
                        } else {
                            estimate_tokens(system_prompt) + estimate_tokens(user_prompt)
                        };
                        let output_tokens = if response.total_usage.output_tokens > 0 {
                            response.total_usage.output_tokens
                        } else {
                            estimate_tokens(&response.output)
                        };

                        // Calculate cost
                        let pricing = PricingConfig::load();
                        let cost = pricing.calculate_cost("ollama", &self.model, input_tokens, output_tokens);

                        // Note: Tool call count not available in non-streaming mode
                        events.send_metrics(input_tokens, output_tokens, 0, cost, 0);
                        Ok(response.output)
                    }
                    Err(e) => Err(Error::Provider(format!("Orchestrator completion failed: {}", e)))
                }
            }
            _ = context.cancel.cancelled() => {
                // Engagement was completed via complete_engagement tool
                let findings = context.findings.lock().await;
                Ok(format!("Engagement completed with {} findings", findings.len()))
            }
        }
    }

    async fn complete_with_report(
        &self,
        system_prompt: &str,
        user_prompt: &str,
        context: Arc<ReportContext>,
    ) -> Result<String> {
        let events = Arc::clone(&context.events);
        let agent = self
            .client
            .agent(&self.model)
            .preamble(system_prompt)
            .max_tokens(4096)
            .tool(GenerateReportTool::new(Arc::clone(&context)))
            .tool(ExportJsonTool::new(Arc::clone(&context)))
            .tool(ExportMarkdownTool::new(Arc::clone(&context)))
            .tool(AddRecommendationTool::new(Arc::clone(&context)))
            .build();

        // multi_turn enables tool loop with max 20 iterations
        // extended_details() gives us real token usage
        let response = agent
            .prompt(user_prompt)
            .extended_details()
            .multi_turn(20)
            .await
            .map_err(|e| Error::Provider(format!("Report completion failed: {}", e)))?;

        // Use actual token counts if available, otherwise estimate
        // Ollama models may not always report token usage
        let input_tokens = if response.total_usage.input_tokens > 0 {
            response.total_usage.input_tokens
        } else {
            estimate_tokens(system_prompt) + estimate_tokens(user_prompt)
        };
        let output_tokens = if response.total_usage.output_tokens > 0 {
            response.total_usage.output_tokens
        } else {
            estimate_tokens(&response.output)
        };

        // Calculate cost
        let pricing = PricingConfig::load();
        let cost = pricing.calculate_cost("ollama", &self.model, input_tokens, output_tokens);

        // Note: Tool call count not available in non-streaming mode
        events.send_metrics(input_tokens, output_tokens, 0, cost, 0);

        Ok(response.output)
    }

    fn metrics(&self) -> &MetricsTracker {
        &self.metrics
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_default_localhost() {
        // Should work without any env vars (defaults to localhost:11434)
        let result = OllamaProvider::new("llama3.2", MetricsTracker::new());
        assert!(result.is_ok());
    }

    #[test]
    fn test_provider_custom_base_url() {
        let result =
            OllamaProvider::with_base_url("http://custom:11434", "llama3.2", MetricsTracker::new());
        assert!(result.is_ok());
    }

    #[test]
    fn test_provider_from_env_requires_env_var() {
        // Temporarily unset env var
        let original = std::env::var("OLLAMA_API_BASE_URL").ok();
        std::env::remove_var("OLLAMA_API_BASE_URL");

        let result = OllamaProvider::from_env("llama3.2", MetricsTracker::new());
        assert!(result.is_err());

        // Restore
        if let Some(url) = original {
            std::env::set_var("OLLAMA_API_BASE_URL", url);
        }
    }
}
