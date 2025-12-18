mod ast_grep;
mod gitleaks;
mod grype;
mod semgrep;

pub use ast_grep::{AstGrepMatch, AstGrepOutput};
pub use gitleaks::{GitleaksFinding, GitleaksOutput};
pub use grype::{GrypeFinding, GrypeOutput};
pub use semgrep::{SemgrepOutput, SemgrepResult};

use crate::state::models::CodeFinding;

/// Trait for SAST tool output parsing
pub trait SastToolOutput {
    fn to_code_findings(&self) -> Vec<CodeFinding>;
}
