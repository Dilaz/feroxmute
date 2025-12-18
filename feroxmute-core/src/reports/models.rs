//! Report data models

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::state::Vulnerability;

/// Overall risk rating for the engagement
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskRating {
    Critical,
    High,
    Medium,
    Low,
    Minimal,
}

impl RiskRating {
    /// Determine risk rating based on vulnerability counts
    pub fn from_counts(critical: u32, high: u32, medium: u32) -> Self {
        if critical > 0 {
            Self::Critical
        } else if high > 0 {
            Self::High
        } else if medium > 0 {
            Self::Medium
        } else {
            Self::Low
        }
    }
}

impl std::fmt::Display for RiskRating {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Critical => write!(f, "Critical"),
            Self::High => write!(f, "High"),
            Self::Medium => write!(f, "Medium"),
            Self::Low => write!(f, "Low"),
            Self::Minimal => write!(f, "Minimal"),
        }
    }
}

/// Vulnerability counts by severity
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SeverityCounts {
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub info: u32,
}

impl SeverityCounts {
    pub fn total(&self) -> u32 {
        self.critical + self.high + self.medium + self.low + self.info
    }
}

/// Vulnerability counts by status
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StatusCounts {
    pub confirmed: u32,
    pub potential: u32,
    pub fixed: u32,
    pub false_positive: u32,
}

/// Report metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportMetadata {
    /// Report title
    pub title: String,
    /// Target host
    pub target: String,
    /// Engagement start time
    pub start_time: DateTime<Utc>,
    /// Engagement end time
    pub end_time: DateTime<Utc>,
    /// Report generation time
    pub generated_at: DateTime<Utc>,
    /// Session ID
    pub session_id: String,
    /// Engagement scope
    pub scope: String,
}

impl ReportMetadata {
    pub fn new(
        target: impl Into<String>,
        session_id: impl Into<String>,
        scope: impl Into<String>,
        start_time: DateTime<Utc>,
        end_time: DateTime<Utc>,
    ) -> Self {
        let target = target.into();
        Self {
            title: format!("Security Assessment Report - {}", target),
            target,
            start_time,
            end_time,
            generated_at: Utc::now(),
            session_id: session_id.into(),
            scope: scope.into(),
        }
    }
}

/// Report metrics/statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReportMetrics {
    /// Total tool executions
    pub tool_calls: u64,
    /// Input tokens used
    pub input_tokens: u64,
    /// Output tokens generated
    pub output_tokens: u64,
    /// Cache read tokens
    pub cache_read_tokens: u64,
    /// Hosts discovered
    pub hosts_discovered: u32,
    /// Ports discovered
    pub ports_discovered: u32,
}

/// Report summary section
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSummary {
    /// Total vulnerabilities found
    pub total_vulnerabilities: u32,
    /// Counts by severity
    pub by_severity: SeverityCounts,
    /// Counts by status
    pub by_status: StatusCounts,
    /// Overall risk rating
    pub risk_rating: RiskRating,
    /// Key findings (high-level summary)
    pub key_findings: Vec<String>,
    /// Executive summary text
    pub executive_summary: String,
}

impl Default for ReportSummary {
    fn default() -> Self {
        Self {
            total_vulnerabilities: 0,
            by_severity: SeverityCounts::default(),
            by_status: StatusCounts::default(),
            risk_rating: RiskRating::Minimal,
            key_findings: Vec::new(),
            executive_summary: String::new(),
        }
    }
}

/// A finding in the report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Finding title
    pub title: String,
    /// Severity
    pub severity: String,
    /// Affected endpoint/resource
    pub affected: String,
    /// Description
    pub description: String,
    /// Evidence/proof
    pub evidence: Option<String>,
    /// Reproduction steps
    pub reproduction_steps: Option<String>,
    /// Impact assessment
    pub impact: Option<String>,
    /// Remediation guidance
    pub remediation: Option<String>,
    /// References (CVEs, links)
    pub references: Vec<String>,
}

impl From<Vulnerability> for Finding {
    fn from(vuln: Vulnerability) -> Self {
        Self {
            title: vuln.title,
            severity: vuln.severity.to_string(),
            affected: vuln
                .asset
                .unwrap_or_else(|| vuln.host_id.unwrap_or_default()),
            description: vuln.description.unwrap_or_default(),
            evidence: vuln.evidence,
            reproduction_steps: None,
            impact: None,
            remediation: vuln.remediation,
            references: vuln.cwe.map(|c| vec![c]).unwrap_or_default(),
        }
    }
}

/// Complete penetration testing report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    /// Report metadata
    pub metadata: ReportMetadata,
    /// Engagement metrics
    pub metrics: ReportMetrics,
    /// Executive summary
    pub summary: ReportSummary,
    /// Detailed findings
    pub findings: Vec<Finding>,
}

impl Report {
    /// Create a new report
    pub fn new(metadata: ReportMetadata) -> Self {
        Self {
            metadata,
            metrics: ReportMetrics::default(),
            summary: ReportSummary::default(),
            findings: Vec::new(),
        }
    }

    /// Add a finding to the report
    pub fn add_finding(&mut self, finding: Finding) {
        self.findings.push(finding);
        self.update_summary();
    }

    /// Update summary based on findings
    fn update_summary(&mut self) {
        self.summary.total_vulnerabilities = self.findings.len() as u32;

        // Reset counts
        self.summary.by_severity = SeverityCounts::default();

        // Count by severity
        for finding in &self.findings {
            match finding.severity.to_lowercase().as_str() {
                "critical" => self.summary.by_severity.critical += 1,
                "high" => self.summary.by_severity.high += 1,
                "medium" => self.summary.by_severity.medium += 1,
                "low" => self.summary.by_severity.low += 1,
                _ => self.summary.by_severity.info += 1,
            }
        }

        // Update risk rating
        self.summary.risk_rating = RiskRating::from_counts(
            self.summary.by_severity.critical,
            self.summary.by_severity.high,
            self.summary.by_severity.medium,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_risk_rating_from_counts() {
        assert_eq!(RiskRating::from_counts(1, 0, 0), RiskRating::Critical);
        assert_eq!(RiskRating::from_counts(0, 1, 0), RiskRating::High);
        assert_eq!(RiskRating::from_counts(0, 0, 1), RiskRating::Medium);
        assert_eq!(RiskRating::from_counts(0, 0, 0), RiskRating::Low);
    }

    #[test]
    fn test_severity_counts_total() {
        let counts = SeverityCounts {
            critical: 1,
            high: 2,
            medium: 3,
            low: 4,
            info: 5,
        };
        assert_eq!(counts.total(), 15);
    }

    #[test]
    fn test_report_update_summary() {
        let metadata =
            ReportMetadata::new("example.com", "test-session", "web", Utc::now(), Utc::now());
        let mut report = Report::new(metadata);

        report.add_finding(Finding {
            title: "SQL Injection".to_string(),
            severity: "Critical".to_string(),
            affected: "/api/login".to_string(),
            description: "SQL injection vulnerability".to_string(),
            evidence: None,
            reproduction_steps: None,
            impact: None,
            remediation: None,
            references: Vec::new(),
        });

        report.add_finding(Finding {
            title: "XSS".to_string(),
            severity: "High".to_string(),
            affected: "/search".to_string(),
            description: "Cross-site scripting".to_string(),
            evidence: None,
            reproduction_steps: None,
            impact: None,
            remediation: None,
            references: Vec::new(),
        });

        assert_eq!(report.summary.total_vulnerabilities, 2);
        assert_eq!(report.summary.by_severity.critical, 1);
        assert_eq!(report.summary.by_severity.high, 1);
        assert_eq!(report.summary.risk_rating, RiskRating::Critical);
    }
}
