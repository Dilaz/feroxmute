//! MCP tool wrappers for feroxmute tools

mod docker_shell;
mod finding;
mod memory;
mod orchestrator;
mod report;
mod script;

pub use docker_shell::McpDockerShellTool;
pub use finding::{FindingContext, McpRecordFindingTool};
pub use memory::{McpMemoryAddTool, McpMemoryGetTool, McpMemoryListTool};
pub use orchestrator::{
    McpCompleteEngagementTool, McpListAgentsTool, McpSpawnAgentTool, McpWaitForAgentTool,
    McpWaitForAnyTool,
};
pub use report::{
    McpAddRecommendationTool, McpExportHtmlTool, McpExportJsonTool, McpExportMarkdownTool,
    McpExportPdfTool, McpGenerateReportTool,
};
pub use script::McpRunScriptTool;
