//! Perplexity provider implementation using rig-core

use async_trait::async_trait;
use rig::client::CompletionClient;
use rig::completion::Prompt;
use rig::providers::perplexity;

use crate::state::MetricsTracker;
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
