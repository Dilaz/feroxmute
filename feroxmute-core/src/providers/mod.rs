//! LLM provider integration
//!
//! This module provides LLM provider implementations using the `define_provider!` macro
//! for code generation. Most providers are defined in `definitions.rs` via the macro,
//! while Azure and Ollama have manual implementations due to special requirements.

#[macro_use]
mod macros;
pub mod cli_agent;
mod definitions;
pub mod factory;
pub mod retry;
pub mod traits;

// Manual implementations (can't use macro due to special requirements)
mod azure;
mod ollama;

pub use factory::create_provider;
pub use traits::{
    CompletionRequest, CompletionResponse, LlmProvider, Message, Role, StopReason, TokenUsage,
    ToolCall, ToolDefinition,
};

// Re-export macro-generated providers from definitions
pub use definitions::{
    AnthropicProvider, CohereProvider, DeepSeekProvider, GeminiProvider, LiteLlmProvider,
    MiraProvider, OpenAiProvider, PerplexityProvider, XaiProvider,
};

// Re-export manual implementations
pub use azure::AzureProvider;
pub use ollama::OllamaProvider;

// Re-export CLI agent types
pub use cli_agent::{CliAgentConfig, CliAgentType};
