//! Tool integration module

pub mod executor;
pub mod llm_pentest_context;
pub mod llm_probe;
pub mod llm_scanners;
pub mod memory;
pub mod orchestrator;
pub mod playbook;
pub mod report;
pub mod sast;
pub mod script;
pub mod shell;

pub use executor::{ToolDef, ToolExecution, ToolExecutor, ToolRegistry};
pub use llm_pentest_context::LlmPentestContext;
pub use llm_probe::{LlmProbeError, LlmProbeTool};
pub use llm_scanners::{GarakScanTool, LlmScannerError, PromptfooScanTool, PyritAttackTool};
pub use memory::{
    MemoryAddTool, MemoryContext, MemoryGetTool, MemoryListTool, MemoryRemoveTool, MemoryToolError,
};
pub use orchestrator::{
    AgentSummary, CompleteEngagementTool, EventSender, ListAgentsTool, OrchestratorContext,
    OrchestratorToolError, RecordFindingTool, ReportMilestoneTool, ReviewEventsTool,
    SpawnAgentTool, WaitForAgentTool, WaitForAnyTool,
};
pub use playbook::{PLAYBOOK_CATEGORIES, get_playbook, list_categories};
pub use report::{
    AddRecommendationTool, DeduplicateFindingsTool, ExportHtmlTool, ExportJsonTool,
    ExportMarkdownTool, ExportPdfTool, GenerateReportTool, ReportContext,
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
