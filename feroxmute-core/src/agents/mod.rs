//! Agent framework for LLM-powered security testing

pub mod prompts;
pub mod traits;

pub use prompts::Prompts;
pub use traits::{Agent, AgentContext, AgentStatus, AgentTask, TaskStatus};
