use serde::Deserialize;

use crate::state::models::{CodeFinding, FindingType, Severity};

use super::SastToolOutput;

#[derive(Debug, Deserialize)]
pub struct GrypeOutput {
    pub matches: Vec<GrypeMatch>,
}

#[derive(Debug, Deserialize)]
pub struct GrypeMatch {
    pub vulnerability: GrypeVulnerability,
    pub artifact: GrypeArtifact,
}

#[derive(Debug, Deserialize)]
pub struct GrypeVulnerability {
    pub id: String,
    pub severity: String,
    pub description: Option<String>,
    #[serde(rename = "fix")]
    pub fix_info: Option<GrypeFix>,
}

#[derive(Debug, Deserialize)]
pub struct GrypeFix {
    pub versions: Vec<String>,
    #[serde(rename = "state")]
    pub _state: String,
}

#[derive(Debug, Deserialize)]
pub struct GrypeArtifact {
    pub name: String,
    pub version: String,
    #[serde(rename = "type")]
    pub _artifact_type: String,
    pub locations: Option<Vec<GrypeLocation>>,
}

#[derive(Debug, Deserialize)]
pub struct GrypeLocation {
    pub path: String,
}

#[derive(Debug, Clone)]
pub struct GrypeFinding {
    pub cve: String,
    pub severity: Severity,
    pub package: String,
    pub version: String,
    pub fixed_version: Option<String>,
    pub description: Option<String>,
    pub file_path: String,
}

impl GrypeOutput {
    /// Parse Grype JSON output
    ///
    /// # Errors
    ///
    /// Returns an error if the JSON is malformed or doesn't match the expected schema
    pub fn parse(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

impl SastToolOutput for GrypeOutput {
    fn to_code_findings(&self) -> Vec<CodeFinding> {
        self.matches
            .iter()
            .map(|m| {
                let severity = match m.vulnerability.severity.to_lowercase().as_str() {
                    "critical" => Severity::Critical,
                    "high" => Severity::High,
                    "medium" => Severity::Medium,
                    "low" => Severity::Low,
                    _ => Severity::Info,
                };

                let file_path = m
                    .artifact
                    .locations
                    .as_ref()
                    .and_then(|l| l.first())
                    .map(|l| l.path.clone())
                    .unwrap_or_else(|| format!("{} ({})", m.artifact.name, m.artifact.version));

                let mut finding = CodeFinding::new(
                    &file_path,
                    severity,
                    FindingType::Dependency,
                    format!(
                        "{} in {}@{}",
                        m.vulnerability.id, m.artifact.name, m.artifact.version
                    ),
                    "grype",
                )
                .with_cve(&m.vulnerability.id)
                .with_package(&m.artifact.name, &m.artifact.version);

                if let Some(ref desc) = m.vulnerability.description {
                    finding = finding.with_description(desc);
                }

                if let Some(ref fix) = m.vulnerability.fix_info {
                    if let Some(version) = fix.versions.first() {
                        finding = finding.with_fixed_version(version);
                    }
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
    fn test_parse_grype_output() {
        let json = r#"{
            "matches": [{
                "vulnerability": {
                    "id": "CVE-2024-1234",
                    "severity": "Critical",
                    "description": "Remote code execution vulnerability",
                    "fix": {
                        "versions": ["4.17.21"],
                        "state": "fixed"
                    }
                },
                "artifact": {
                    "name": "lodash",
                    "version": "4.17.20",
                    "type": "npm",
                    "locations": [{"path": "package-lock.json"}]
                }
            }]
        }"#;

        let output = GrypeOutput::parse(json).expect("should parse grype output");
        assert_eq!(output.matches.len(), 1);

        let findings = output.to_code_findings();
        assert_eq!(findings.len(), 1);
        let first_finding = findings.first().expect("should have one finding");
        assert_eq!(first_finding.severity, Severity::Critical);
        assert_eq!(first_finding.package_name, Some("lodash".to_string()));
        assert_eq!(first_finding.package_version, Some("4.17.20".to_string()));
        assert_eq!(first_finding.fixed_version, Some("4.17.21".to_string()));
        assert_eq!(first_finding.finding_type, FindingType::Dependency);
        assert_eq!(first_finding.tool, "grype");
    }

    #[test]
    fn test_parse_grype_multiple_vulnerabilities() {
        let json = r#"{
            "matches": [
                {
                    "vulnerability": {
                        "id": "CVE-2024-1111",
                        "severity": "High",
                        "description": "Security issue 1"
                    },
                    "artifact": {
                        "name": "pkg1",
                        "version": "1.0.0",
                        "type": "cargo",
                        "locations": [{"path": "Cargo.lock"}]
                    }
                },
                {
                    "vulnerability": {
                        "id": "CVE-2024-2222",
                        "severity": "Medium",
                        "description": "Security issue 2",
                        "fix": {
                            "versions": ["2.5.0", "2.6.0"],
                            "state": "fixed"
                        }
                    },
                    "artifact": {
                        "name": "pkg2",
                        "version": "2.4.0",
                        "type": "cargo"
                    }
                }
            ]
        }"#;

        let output = GrypeOutput::parse(json).expect("should parse multiple vulnerabilities");
        let findings = output.to_code_findings();

        assert_eq!(findings.len(), 2);

        // First finding
        let first_finding = findings.first().expect("should have first finding");
        assert_eq!(first_finding.severity, Severity::High);
        assert_eq!(first_finding.cve_id, Some("CVE-2024-1111".to_string()));
        assert_eq!(first_finding.file_path, "Cargo.lock");

        // Second finding
        let second_finding = findings.get(1).expect("should have second finding");
        assert_eq!(second_finding.severity, Severity::Medium);
        assert_eq!(second_finding.cve_id, Some("CVE-2024-2222".to_string()));
        assert_eq!(second_finding.fixed_version, Some("2.5.0".to_string()));
    }

    #[test]
    fn test_parse_empty_grype_output() {
        let json = r#"{"matches": []}"#;

        let output = GrypeOutput::parse(json).expect("should parse empty output");
        let findings = output.to_code_findings();

        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn test_grype_severity_mapping() {
        let json_template = r#"{
            "matches": [{
                "vulnerability": {
                    "id": "CVE-TEST",
                    "severity": "SEVERITY_PLACEHOLDER"
                },
                "artifact": {
                    "name": "test-pkg",
                    "version": "1.0.0",
                    "type": "npm"
                }
            }]
        }"#;

        let test_cases = vec![
            ("Critical", Severity::Critical),
            ("High", Severity::High),
            ("Medium", Severity::Medium),
            ("Low", Severity::Low),
            ("Unknown", Severity::Info),
        ];

        for (grype_severity, expected_severity) in test_cases {
            let json = json_template.replace("SEVERITY_PLACEHOLDER", grype_severity);
            let output = GrypeOutput::parse(&json).expect("should parse severity test");
            let findings = output.to_code_findings();
            let first_finding = findings.first().expect("should have one finding");
            assert_eq!(
                first_finding.severity, expected_severity,
                "Failed for severity: {}",
                grype_severity
            );
        }
    }
}
