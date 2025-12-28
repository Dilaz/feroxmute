use serde::Deserialize;

use crate::state::models::{CodeFinding, FindingType, Severity};

use super::SastToolOutput;

#[derive(Debug, Deserialize)]
pub struct AstGrepOutput(pub Vec<AstGrepMatch>);

#[derive(Debug, Deserialize)]
pub struct AstGrepMatch {
    pub file: String,
    pub range: AstGrepRange,
    pub text: String,
    #[serde(rename = "ruleId")]
    pub rule_id: Option<String>,
    pub message: Option<String>,
    pub severity: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AstGrepRange {
    pub start: AstGrepPosition,
    #[serde(rename = "end")]
    pub _end: AstGrepPosition,
}

#[derive(Debug, Deserialize)]
pub struct AstGrepPosition {
    pub line: u32,
    #[serde(rename = "column")]
    pub _column: u32,
}

impl AstGrepOutput {
    /// Parse ast-grep JSON output
    ///
    /// # Errors
    ///
    /// Returns an error if the JSON is malformed or doesn't match the expected schema
    pub fn parse(json: &str) -> Result<Self, serde_json::Error> {
        let matches: Vec<AstGrepMatch> = serde_json::from_str(json)?;
        Ok(Self(matches))
    }
}

impl SastToolOutput for AstGrepOutput {
    fn to_code_findings(&self) -> Vec<CodeFinding> {
        self.0
            .iter()
            .map(|m| {
                let severity = m
                    .severity
                    .as_ref()
                    .map(|s| match s.to_lowercase().as_str() {
                        "error" | "high" => Severity::High,
                        "warning" | "medium" => Severity::Medium,
                        "info" | "low" => Severity::Low,
                        _ => Severity::Medium,
                    })
                    .unwrap_or(Severity::Medium);

                let title = m
                    .message
                    .clone()
                    .or_else(|| m.rule_id.clone())
                    .unwrap_or_else(|| "Pattern match found".to_string());

                CodeFinding::new(&m.file, severity, FindingType::Sast, title, "ast-grep")
                    .with_line(m.range.start.line)
                    .with_snippet(&m.text)
            })
            .collect()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ast_grep_output() {
        let json = r#"[{
            "file": "src/db.rs",
            "range": {
                "start": {"line": 42, "column": 5},
                "end": {"line": 42, "column": 60}
            },
            "text": "query = format!(\"SELECT * FROM users WHERE id = {}\", user_id)",
            "ruleId": "sql-injection",
            "message": "Potential SQL injection",
            "severity": "error"
        }]"#;

        let output = AstGrepOutput::parse(json).expect("should parse ast-grep output");
        assert_eq!(output.0.len(), 1);

        let findings = output.to_code_findings();
        assert_eq!(findings.len(), 1);
        let first_finding = findings.first().expect("should have one finding");
        assert_eq!(first_finding.severity, Severity::High);
        assert_eq!(first_finding.line_number, Some(42));
        assert_eq!(first_finding.finding_type, FindingType::Sast);
        assert_eq!(first_finding.tool, "ast-grep");
    }

    #[test]
    fn test_parse_ast_grep_with_defaults() {
        let json = r#"[{
            "file": "src/util.rs",
            "range": {
                "start": {"line": 10, "column": 1},
                "end": {"line": 10, "column": 30}
            },
            "text": "unsafe { some_operation() }"
        }]"#;

        let output = AstGrepOutput::parse(json).expect("should parse ast-grep with defaults");
        let findings = output.to_code_findings();

        assert_eq!(findings.len(), 1);
        let first_finding = findings.first().expect("should have one finding");
        assert_eq!(first_finding.severity, Severity::Medium);
        assert_eq!(first_finding.title, "Pattern match found");
        assert!(first_finding.snippet.is_some());
    }

    #[test]
    fn test_parse_ast_grep_severity_mapping() {
        let test_cases = vec![
            ("error", Severity::High),
            ("high", Severity::High),
            ("warning", Severity::Medium),
            ("medium", Severity::Medium),
            ("info", Severity::Low),
            ("low", Severity::Low),
            ("unknown", Severity::Medium),
        ];

        for (severity_str, expected) in test_cases {
            let json = format!(
                r#"[{{
                "file": "test.rs",
                "range": {{"start": {{"line": 1, "column": 1}}, "end": {{"line": 1, "column": 10}}}},
                "text": "test",
                "severity": "{}"
            }}]"#,
                severity_str
            );

            let output = AstGrepOutput::parse(&json).expect("should parse severity test");
            let findings = output.to_code_findings();

            let first_finding = findings.first().expect("should have one finding");
            assert_eq!(
                first_finding.severity, expected,
                "Failed for severity: {}",
                severity_str
            );
        }
    }

    #[test]
    fn test_parse_empty_ast_grep_output() {
        let json = r#"[]"#;

        let output = AstGrepOutput::parse(json).expect("should parse empty output");
        let findings = output.to_code_findings();

        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn test_ast_grep_with_rule_id_and_message() {
        let json = r#"[{
            "file": "src/api.rs",
            "range": {
                "start": {"line": 25, "column": 4},
                "end": {"line": 25, "column": 50}
            },
            "text": "let password = \"hardcoded_password\";",
            "ruleId": "hardcoded-credentials",
            "message": "Hardcoded credentials detected",
            "severity": "high"
        }]"#;

        let output =
            AstGrepOutput::parse(json).expect("should parse ast-grep with rule id and message");
        let findings = output.to_code_findings();

        assert_eq!(findings.len(), 1);
        let first_finding = findings.first().expect("should have one finding");
        assert_eq!(first_finding.title, "Hardcoded credentials detected");
        assert_eq!(first_finding.severity, Severity::High);
        assert_eq!(first_finding.file_path, "src/api.rs");
        assert_eq!(first_finding.line_number, Some(25));
    }
}
