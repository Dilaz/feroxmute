use serde::Deserialize;

use crate::state::models::{CodeFinding, FindingType, Severity};

use super::SastToolOutput;

#[derive(Debug, Deserialize)]
pub struct GitleaksOutput(pub Vec<GitleaksFinding>);

#[derive(Debug, Deserialize)]
pub struct GitleaksFinding {
    #[serde(rename = "Description")]
    pub description: String,
    #[serde(rename = "File")]
    pub file: String,
    #[serde(rename = "StartLine")]
    pub start_line: u32,
    #[serde(rename = "EndLine")]
    #[allow(dead_code)]
    pub end_line: u32,
    #[serde(rename = "Secret")]
    pub secret: String,
    #[serde(rename = "Match")]
    #[allow(dead_code)]
    pub match_text: String,
    #[serde(rename = "RuleID")]
    pub rule_id: String,
}

impl GitleaksOutput {
    /// Parse gitleaks JSON output
    ///
    /// # Errors
    ///
    /// Returns an error if the JSON is malformed or doesn't match the expected schema
    pub fn parse(json: &str) -> Result<Self, serde_json::Error> {
        let findings: Vec<GitleaksFinding> = serde_json::from_str(json)?;
        Ok(Self(findings))
    }
}

impl SastToolOutput for GitleaksOutput {
    fn to_code_findings(&self) -> Vec<CodeFinding> {
        self.0
            .iter()
            .map(|f| {
                // Secrets are always high severity
                let severity = Severity::High;

                // Redact the actual secret in the finding
                let redacted_secret = if f.secret.len() > 8 {
                    format!("{}...{}", &f.secret[..4], &f.secret[f.secret.len() - 4..])
                } else {
                    "****".to_string()
                };

                CodeFinding::new(
                    &f.file,
                    severity,
                    FindingType::Secret,
                    format!("{}: {}", f.description, f.rule_id),
                    "gitleaks",
                )
                .with_line(f.start_line)
                .with_snippet(format!("Secret (redacted): {}", redacted_secret))
                .with_description(format!(
                    "Hardcoded secret detected. Rule: {}. Remove and rotate this credential.",
                    f.rule_id
                ))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_gitleaks_output() {
        let json = r#"[{
            "Description": "AWS Access Key",
            "File": "src/config.rs",
            "StartLine": 23,
            "EndLine": 23,
            "Secret": "AKIAIOSFODNN7EXAMPLE",
            "Match": "aws_access_key = \"AKIAIOSFODNN7EXAMPLE\"",
            "RuleID": "aws-access-key-id"
        }]"#;

        let output = GitleaksOutput::parse(json).unwrap();
        assert_eq!(output.0.len(), 1);

        let findings = output.to_code_findings();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].finding_type, FindingType::Secret);
        assert_eq!(findings[0].tool, "gitleaks");
    }

    #[test]
    fn test_gitleaks_secret_redaction() {
        let json = r#"[{
            "Description": "Generic API Key",
            "File": "src/api.rs",
            "StartLine": 10,
            "EndLine": 10,
            "Secret": "sk_live_1234567890abcdefghijklmnop",
            "Match": "api_key = \"sk_live_1234567890abcdefghijklmnop\"",
            "RuleID": "generic-api-key"
        }]"#;

        let output = GitleaksOutput::parse(json).unwrap();
        let findings = output.to_code_findings();

        assert_eq!(findings.len(), 1);
        assert!(findings[0].snippet.is_some());

        let snippet = findings[0].snippet.as_ref().unwrap();
        // Check that the secret is redacted
        assert!(snippet.contains("sk_l..."));
        assert!(snippet.contains("...mnop"));
        assert!(snippet.contains("Secret (redacted):"));
    }

    #[test]
    fn test_gitleaks_short_secret_redaction() {
        let json = r#"[{
            "Description": "Short key",
            "File": "test.rs",
            "StartLine": 1,
            "EndLine": 1,
            "Secret": "abc123",
            "Match": "key = \"abc123\"",
            "RuleID": "test-key"
        }]"#;

        let output = GitleaksOutput::parse(json).unwrap();
        let findings = output.to_code_findings();

        let snippet = findings[0].snippet.as_ref().unwrap();
        // Short secrets (<=8 chars) should be completely redacted
        assert!(snippet.contains("****"));
    }

    #[test]
    fn test_gitleaks_multiple_findings() {
        let json = r#"[
            {
                "Description": "AWS Access Key",
                "File": "config/prod.rs",
                "StartLine": 5,
                "EndLine": 5,
                "Secret": "AKIAIOSFODNN7EXAMPLE",
                "Match": "aws_key = \"AKIAIOSFODNN7EXAMPLE\"",
                "RuleID": "aws-access-key-id"
            },
            {
                "Description": "Private Key",
                "File": "certs/key.pem",
                "StartLine": 1,
                "EndLine": 10,
                "Secret": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEF",
                "Match": "-----BEGIN PRIVATE KEY-----",
                "RuleID": "private-key"
            }
        ]"#;

        let output = GitleaksOutput::parse(json).unwrap();
        assert_eq!(output.0.len(), 2);

        let findings = output.to_code_findings();
        assert_eq!(findings.len(), 2);

        // All secrets should be High severity
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[1].severity, Severity::High);

        // All should be Secret finding type
        assert_eq!(findings[0].finding_type, FindingType::Secret);
        assert_eq!(findings[1].finding_type, FindingType::Secret);

        // Check titles contain rule IDs
        assert!(findings[0].title.contains("aws-access-key-id"));
        assert!(findings[1].title.contains("private-key"));
    }

    #[test]
    fn test_parse_empty_gitleaks_output() {
        let json = r#"[]"#;

        let output = GitleaksOutput::parse(json).unwrap();
        let findings = output.to_code_findings();

        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn test_gitleaks_finding_has_description() {
        let json = r#"[{
            "Description": "GitHub Personal Access Token",
            "File": ".env",
            "StartLine": 12,
            "EndLine": 12,
            "Secret": "ghp_1234567890abcdefghijklmnopqrstuvwxyz",
            "Match": "GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz",
            "RuleID": "github-pat"
        }]"#;

        let output = GitleaksOutput::parse(json).unwrap();
        let findings = output.to_code_findings();

        assert!(findings[0].description.is_some());
        let desc = findings[0].description.as_ref().unwrap();
        assert!(desc.contains("github-pat"));
        assert!(desc.contains("Remove and rotate"));
    }
}
