//! Agent framework for LLM-powered security testing

pub mod orchestrator;
pub mod prompts;
pub mod recon;
pub mod registry;
pub mod report;
pub mod sast;
pub mod scanner;
pub mod traits;

pub use orchestrator::{EngagementPhase, OrchestratorAgent};
pub use prompts::Prompts;
pub use recon::ReconAgent;
pub use registry::{AgentRegistry, AgentResult, AgentResultWaiter, SpawnedAgent};
pub use report::ReportAgent;
pub use sast::SastAgent;
pub use scanner::ScannerAgent;
pub use traits::{Agent, AgentContext, AgentStatus, AgentTask, TaskStatus};
