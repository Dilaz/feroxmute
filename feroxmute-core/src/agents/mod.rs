//! Agent framework for LLM-powered security testing

pub mod orchestrator;
pub mod prompts;
pub mod recon;
pub mod scanner;
pub mod traits;

pub use orchestrator::{EngagementPhase, OrchestratorAgent};
pub use prompts::Prompts;
pub use recon::ReconAgent;
pub use scanner::ScannerAgent;
pub use traits::{Agent, AgentContext, AgentStatus, AgentTask, TaskStatus};
