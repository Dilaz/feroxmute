//! Perplexity provider implementation using rig-core

use std::sync::Arc;

use async_trait::async_trait;
use rig::client::CompletionClient;
use rig::completion::Prompt;
use rig::providers::perplexity;

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

/// Perplexity provider using rig-core
pub struct PerplexityProvider {
    client: perplexity::Client,
    model: String,
    metrics: MetricsTracker,
}

impl PerplexityProvider {
    /// Create a new Perplexity provider from PERPLEXITY_API_KEY env var
    pub fn new(model: impl Into<String>, metrics: MetricsTracker) -> Result<Self> {
        let api_key = std::env::var("PERPLEXITY_API_KEY")
            .map_err(|_| Error::Provider("PERPLEXITY_API_KEY not set".to_string()))?;

        let client = perplexity::Client::new(&api_key)
            .map_err(|e| Error::Provider(format!("Failed to build Perplexity client: {}", e)))?;

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
        let client = perplexity::Client::new(api_key.into())
            .map_err(|e| Error::Provider(format!("Failed to build Perplexity client: {}", e)))?;

        Ok(Self {
            client,
            model: model.into(),
            metrics,
        })
    }
}

#[async_trait]
impl LlmProvider for PerplexityProvider {
    fn name(&self) -> &str {
        "perplexity"
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
            .map_err(|e| Error::Provider(format!("Perplexity completion failed: {}", e)))?;

        let estimated_input = prompt.len() as u64 / 4;
        let estimated_output = response.len() as u64 / 4;
        let pricing = PricingConfig::load();
        let cost = pricing.calculate_cost("perplexity", &self.model, estimated_input, estimated_output);
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

        events_clone.send_metrics(
            response.total_usage.input_tokens,
            response.total_usage.output_tokens,
            0,
        );

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

        // multi_turn enables tool loop with max 50 iterations
        // extended_details() gives us real token usage
        tokio::select! {
            result = agent.prompt(user_prompt).extended_details().multi_turn(50) => {
                match result {
                    Ok(response) => {
                        events.send_metrics(
                            response.total_usage.input_tokens,
                            response.total_usage.output_tokens,
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

        events.send_metrics(
            response.total_usage.input_tokens,
            response.total_usage.output_tokens,
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
        let original = std::env::var("PERPLEXITY_API_KEY").ok();
        std::env::remove_var("PERPLEXITY_API_KEY");

        let result = PerplexityProvider::new("sonar-pro", MetricsTracker::new());
        assert!(result.is_err());

        if let Some(key) = original {
            std::env::set_var("PERPLEXITY_API_KEY", key);
        }
    }
}
