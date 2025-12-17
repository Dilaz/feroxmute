//! LLM provider integration

pub mod anthropic;
pub mod traits;

pub use anthropic::AnthropicProvider;
pub use traits::{
    CompletionRequest, CompletionResponse, LlmProvider, Message, Role, StopReason, ToolCall,
    ToolDefinition, TokenUsage,
};
