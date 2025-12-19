//! Google Gemini provider implementation using rig-core

use async_trait::async_trait;
use rig::client::CompletionClient;
use rig::completion::Prompt;
use rig::providers::gemini;

use crate::state::MetricsTracker;
use crate::{Error, Result};

use super::{CompletionRequest, CompletionResponse, LlmProvider, StopReason, TokenUsage};

/// Google Gemini provider using rig-core
pub struct GeminiProvider {
    client: gemini::Client,
    model: String,
    metrics: MetricsTracker,
}

impl GeminiProvider {
    /// Create a new Gemini provider from GEMINI_API_KEY or GOOGLE_API_KEY env var
    pub fn new(model: impl Into<String>, metrics: MetricsTracker) -> Result<Self> {
        let api_key = std::env::var("GEMINI_API_KEY")
            .or_else(|_| std::env::var("GOOGLE_API_KEY"))
            .map_err(|_| Error::Provider("GEMINI_API_KEY or GOOGLE_API_KEY not set".to_string()))?;

        let client = gemini::Client::new(&api_key)
            .map_err(|e| Error::Provider(format!("Failed to build Gemini client: {}", e)))?;

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
        let client = gemini::Client::new(api_key.into())
            .map_err(|e| Error::Provider(format!("Failed to build Gemini client: {}", e)))?;

        Ok(Self {
            client,
            model: model.into(),
            metrics,
        })
    }
}

#[async_trait]
impl LlmProvider for GeminiProvider {
    fn name(&self) -> &str {
        "gemini"
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
            .map_err(|e| Error::Provider(format!("Gemini completion failed: {}", e)))?;

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
        let original_gemini = std::env::var("GEMINI_API_KEY").ok();
        let original_google = std::env::var("GOOGLE_API_KEY").ok();
        std::env::remove_var("GEMINI_API_KEY");
        std::env::remove_var("GOOGLE_API_KEY");

        let result = GeminiProvider::new("gemini-1.5-pro", MetricsTracker::new());
        assert!(result.is_err());

        if let Some(key) = original_gemini {
            std::env::set_var("GEMINI_API_KEY", key);
        }
        if let Some(key) = original_google {
            std::env::set_var("GOOGLE_API_KEY", key);
        }
    }
}
