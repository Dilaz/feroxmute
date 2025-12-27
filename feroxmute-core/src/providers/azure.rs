//! Azure OpenAI provider implementation using rig-core

use std::sync::Arc;

use async_trait::async_trait;
use rig::client::CompletionClient;
use rig::completion::Prompt;
use rig::providers::azure;

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
        let pricing = PricingConfig::load();
        let cost = pricing.calculate_cost("openai", &self.model, estimated_input, estimated_output);
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
        memory: Arc<crate::tools::MemoryContext>,
    ) -> Result<String> {
        use crate::tools::{MemoryAddTool, MemoryGetTool, MemoryListTool};

        let events_clone = Arc::clone(&events);

        // Continuation configuration
        const MAX_CONTINUATIONS: usize = 3;
        let mut continuation_count = 0;
        let mut accumulated_output = String::new();
        let mut current_prompt = user_prompt.to_string();

        loop {
            let agent = self
                .client
                .agent(&self.model)
                .preamble(system_prompt)
                .max_tokens(4096)
                .tool(DockerShellTool::new(
                    Arc::clone(&container),
                    Arc::clone(&events),
                    agent_name.to_string(),
                    Arc::clone(&limitations),
                ))
                .tool(MemoryAddTool::new(Arc::clone(&memory)))
                .tool(MemoryGetTool::new(Arc::clone(&memory)))
                .tool(MemoryListTool::new(Arc::clone(&memory)))
                .build();

            // multi_turn enables tool loop with max 50 iterations
            let response = agent
                .prompt(&current_prompt)
                .extended_details()
                .multi_turn(50)
                .await
                .map_err(|e| Error::Provider(format!("Shell completion failed: {}", e)))?;

            // Calculate cost
            let pricing = PricingConfig::load();
            let cost = pricing.calculate_cost(
                "openai",
                &self.model,
                response.total_usage.input_tokens,
                response.total_usage.output_tokens,
            );
            events_clone.send_metrics(
                response.total_usage.input_tokens,
                response.total_usage.output_tokens,
                0,
                cost,
                0,
            );

            accumulated_output.push_str(&response.output);
            accumulated_output.push('\n');

            // Check if output looks like it stopped too early
            let looks_incomplete = response.output.len() < 500
                && !response.output.contains("=== RECON SUMMARY ===")
                && !response.output.contains("=== SCANNER SUMMARY ===")
                && continuation_count < MAX_CONTINUATIONS;

            if looks_incomplete {
                continuation_count += 1;
                events_clone.send_feed(
                    agent_name,
                    &format!("Agent output looks incomplete. Continuing... ({}/{})", continuation_count, MAX_CONTINUATIONS),
                    false,
                );
                current_prompt = format!(
                    "You stopped too early. Continue your task.\n\nPrevious output:\n{}\n\n---\n\nKeep running tools until you have comprehensive results.",
                    response.output.chars().take(1500).collect::<String>()
                );
                continue;
            }

            return Ok(accumulated_output);
        }
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

        // multi_turn enables tool loop with max 50 iterations
        // extended_details() gives us real token usage
        tokio::select! {
            result = agent.prompt(user_prompt).extended_details().multi_turn(50) => {
                match result {
                    Ok(response) => {
                        // Calculate cost
                        let pricing = PricingConfig::load();
                        let cost = pricing.calculate_cost(
                            "openai",
                            &self.model,
                            response.total_usage.input_tokens,
                            response.total_usage.output_tokens,
                        );

                        // Note: Tool call count not available in non-streaming mode
                        events.send_metrics(
                            response.total_usage.input_tokens,
                            response.total_usage.output_tokens,
                            0,
                            cost,
                            0,
                        );
                        Ok(response.output)
                    }
                    Err(e) => Err(Error::Provider(format!("Orchestrator completion failed: {}", e)))
                }
            }
            _ = context.cancel.cancelled() => {
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

        // extended_details() gives us real token usage
        let response = agent
            .prompt(user_prompt)
            .extended_details()
            .multi_turn(20)
            .await
            .map_err(|e| Error::Provider(format!("Report completion failed: {}", e)))?;

        // Calculate cost
        let pricing = PricingConfig::load();
        let cost = pricing.calculate_cost(
            "openai",
            &self.model,
            response.total_usage.input_tokens,
            response.total_usage.output_tokens,
        );

        // Note: Tool call count not available in non-streaming mode
        events.send_metrics(
            response.total_usage.input_tokens,
            response.total_usage.output_tokens,
            0,
            cost,
            0,
        );

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
