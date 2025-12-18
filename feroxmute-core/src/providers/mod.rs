//! LLM provider integration

pub mod anthropic;
pub mod openai;
pub mod traits;

pub use anthropic::AnthropicProvider;
pub use openai::OpenAiProvider;
pub use traits::{
    CompletionRequest, CompletionResponse, LlmProvider, Message, Role, StopReason, ToolCall,
    ToolDefinition, TokenUsage,
};
