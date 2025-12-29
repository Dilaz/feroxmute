//! Tool integration module

pub mod executor;
pub mod memory;
pub mod orchestrator;
pub mod report;
pub mod sast;
pub mod script;
pub mod shell;

pub use executor::{ToolDef, ToolExecution, ToolExecutor, ToolRegistry};
pub use memory::{
    MemoryAddTool, MemoryContext, MemoryGetTool, MemoryListTool, MemoryRemoveTool, MemoryToolError,
};
pub use orchestrator::{
    AgentSummary, CompleteEngagementTool, EventSender, ListAgentsTool, OrchestratorContext,
    OrchestratorToolError, RecordFindingTool, SpawnAgentTool, WaitForAgentTool, WaitForAnyTool,
};
pub use report::{
    AddRecommendationTool, ExportJsonTool, ExportMarkdownTool, GenerateReportTool, ReportContext,
};
pub use script::{RunScriptTool, ScriptError};
pub use shell::DockerShellTool;

/// Memory entry for event updates
#[derive(Debug, Clone)]
pub struct MemoryEntryData {
    pub key: String,
    pub value: String,
    pub created_at: String,
    pub updated_at: String,
}
