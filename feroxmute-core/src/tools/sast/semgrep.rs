use serde::Deserialize;

use crate::state::models::{CodeFinding, FindingType, Severity};

use super::SastToolOutput;

#[derive(Debug, Deserialize)]
pub struct SemgrepOutput {
    pub results: Vec<SemgrepResult>,
    #[serde(default, rename = "errors")]
    pub _errors: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct SemgrepResult {
    pub check_id: String,
    pub path: String,
    pub start: SemgrepLocation,
    #[serde(rename = "end")]
    pub _end: SemgrepLocation,
    pub extra: SemgrepExtra,
}

#[derive(Debug, Deserialize)]
pub struct SemgrepLocation {
    pub line: u32,
    #[serde(rename = "col")]
    pub _col: u32,
}

#[derive(Debug, Deserialize)]
pub struct SemgrepExtra {
    pub message: String,
    pub severity: String,
    pub metadata: Option<SemgrepMetadata>,
    pub lines: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SemgrepMetadata {
    pub cwe: Option<Vec<String>>,
    #[serde(rename = "owasp")]
    pub _owasp: Option<Vec<String>>,
}

impl SemgrepOutput {
    /// Parse Semgrep JSON output
    ///
    /// # Errors
    ///
    /// Returns an error if the JSON is malformed or doesn't match the expected schema
    pub fn parse(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

impl SastToolOutput for SemgrepOutput {
    fn to_code_findings(&self) -> Vec<CodeFinding> {
        self.results
            .iter()
            .map(|r| {
                let severity = match r.extra.severity.to_lowercase().as_str() {
                    "error" => Severity::High,
                    "warning" => Severity::Medium,
                    "info" => Severity::Low,
                    _ => Severity::Info,
                };

                let mut finding = CodeFinding::new(
                    &r.path,
                    severity,
                    FindingType::Sast,
                    &r.extra.message,
                    "semgrep",
                )
                .with_line(r.start.line);

                if let Some(ref lines) = r.extra.lines {
                    finding = finding.with_snippet(lines);
                }

                if let Some(ref metadata) = r.extra.metadata
                    && let Some(ref cwes) = metadata.cwe
                    && let Some(cwe) = cwes.first()
                {
                    finding = finding.with_cwe(cwe);
                }

                finding
            })
            .collect()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_semgrep_output() {
        let json = r#"{
            "results": [{
                "check_id": "python.lang.security.audit.dangerous-subprocess-use",
                "path": "src/main.py",
                "start": {"line": 10, "col": 1},
                "end": {"line": 10, "col": 50},
                "extra": {
                    "message": "Detected subprocess call with shell=True",
                    "severity": "ERROR",
                    "lines": "subprocess.call(cmd, shell=True)"
                }
            }],
            "errors": []
        }"#;

        let output = SemgrepOutput::parse(json).expect("should parse semgrep output");
        assert_eq!(output.results.len(), 1);

        let findings = output.to_code_findings();
        assert_eq!(findings.len(), 1);
        let first_finding = findings.first().expect("should have one finding");
        assert_eq!(first_finding.severity, Severity::High);
        assert_eq!(first_finding.tool, "semgrep");
        assert_eq!(first_finding.finding_type, FindingType::Sast);
    }

    #[test]
    fn test_parse_semgrep_with_cwe() {
        let json = r#"{
            "results": [{
                "check_id": "test-rule",
                "path": "src/app.py",
                "start": {"line": 5, "col": 1},
                "end": {"line": 5, "col": 20},
                "extra": {
                    "message": "SQL injection vulnerability",
                    "severity": "WARNING",
                    "metadata": {
                        "cwe": ["CWE-89"],
                        "owasp": ["A03:2021"]
                    },
                    "lines": "query = \"SELECT * FROM users WHERE id = \" + user_id"
                }
            }],
            "errors": []
        }"#;

        let output = SemgrepOutput::parse(json).expect("should parse semgrep with cwe");
        let findings = output.to_code_findings();

        assert_eq!(findings.len(), 1);
        let first_finding = findings.first().expect("should have one finding");
        assert_eq!(first_finding.severity, Severity::Medium);
        assert_eq!(first_finding.cwe_id, Some("CWE-89".to_string()));
        assert!(first_finding.snippet.is_some());
    }

    #[test]
    fn test_parse_empty_semgrep_output() {
        let json = r#"{"results": [], "errors": []}"#;

        let output = SemgrepOutput::parse(json).expect("should parse empty output");
        let findings = output.to_code_findings();

        assert_eq!(findings.len(), 0);
    }
}
