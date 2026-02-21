//! Report generation module

pub mod generator;
pub mod models;

pub use generator::{
    deduplicate_vulnerabilities, export_html, export_json, export_markdown, export_pdf,
    generate_markdown, generate_report, llm_deduplicate_vulnerabilities,
};
pub use models::{
    Finding, Report, ReportMetadata, ReportMetrics, ReportSummary, RiskRating, SeverityCounts,
    StatusCounts, UNCLASSIFIED_CWE,
};
