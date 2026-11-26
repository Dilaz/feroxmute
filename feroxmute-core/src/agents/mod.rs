//! Agent framework for LLM-powered security testing

pub mod event_bus;
pub mod orchestrator;
pub mod prompts;
pub mod registry;
pub mod traits;

pub use event_bus::{AgentEvent as OrchestratorEvent, AgentEventBus, AgentEventSender, EventKind};
pub use orchestrator::{EngagementPhase, OrchestratorAgent};
pub use prompts::Prompts;
pub use registry::{AgentRegistry, AgentResult, AgentResultWaiter, SpawnedAgent};
pub use traits::AgentStatus;
