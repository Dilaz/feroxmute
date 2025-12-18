//! Report generation module

pub mod generator;
pub mod models;

pub use generator::{export_json, export_markdown, generate_markdown, generate_report};
pub use models::{
    Finding, Report, ReportMetadata, ReportMetrics, ReportSummary, RiskRating, SeverityCounts,
    StatusCounts,
};
