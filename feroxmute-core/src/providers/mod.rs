//! LLM provider integration

pub mod traits;

pub use traits::{
    CompletionRequest, CompletionResponse, LlmProvider, Message, Role, StopReason, ToolCall,
    ToolDefinition, TokenUsage,
};
