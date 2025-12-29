//! Report generation and export

use std::path::Path;

use chrono::{DateTime, Utc};
use rusqlite::Connection;

use crate::state::{MetricsTracker, Vulnerability};
use crate::Result;

use super::models::{Finding, Report, ReportMetadata, ReportMetrics};

/// Generate a report from the database
pub fn generate_report(
    conn: &Connection,
    target: &str,
    session_id: &str,
    start_time: DateTime<Utc>,
    end_time: DateTime<Utc>,
    metrics: &MetricsTracker,
) -> Result<Report> {
    // Create metadata
    let metadata = ReportMetadata::new(target, session_id, start_time, end_time);

    let mut report = Report::new(metadata);

    // Load metrics
    let snapshot = metrics.snapshot();
    report.metrics = ReportMetrics {
        tool_calls: snapshot.tool_calls,
        input_tokens: snapshot.tokens.input,
        output_tokens: snapshot.tokens.output,
        cache_read_tokens: snapshot.tokens.cached,
        hosts_discovered: count_hosts(conn)?,
        ports_discovered: count_ports(conn)?,
    };

    // Load vulnerabilities and convert to findings
    let vulnerabilities = load_vulnerabilities(conn)?;
    for vuln in vulnerabilities {
        report.add_finding(Finding::from(vuln));
    }

    Ok(report)
}

/// Count hosts in the database
fn count_hosts(conn: &Connection) -> Result<u32> {
    let count: u32 = conn.query_row("SELECT COUNT(*) FROM hosts", [], |row| row.get(0))?;
    Ok(count)
}

/// Count ports in the database
fn count_ports(conn: &Connection) -> Result<u32> {
    let count: u32 = conn.query_row("SELECT COUNT(*) FROM ports", [], |row| row.get(0))?;
    Ok(count)
}

/// Load vulnerabilities from database
fn load_vulnerabilities(conn: &Connection) -> Result<Vec<Vulnerability>> {
    Vulnerability::all(conn)
}

/// Export report to JSON file
pub fn export_json(report: &Report, path: impl AsRef<Path>) -> Result<()> {
    let json = serde_json::to_string_pretty(report)?;
    std::fs::write(path, json)?;
    Ok(())
}

/// Export report to Markdown file
pub fn export_markdown(report: &Report, path: impl AsRef<Path>) -> Result<()> {
    let markdown = generate_markdown(report);
    std::fs::write(path, markdown)?;
    Ok(())
}

/// Generate markdown report content
pub fn generate_markdown(report: &Report) -> String {
    let mut md = String::new();

    // Title
    md.push_str(&format!("# {}\n\n", report.metadata.title));

    // Metadata
    md.push_str("## Report Information\n\n");
    md.push_str(&format!("- **Target:** {}\n", report.metadata.target));
    md.push_str(&format!(
        "- **Session ID:** {}\n",
        report.metadata.session_id
    ));
    md.push_str(&format!(
        "- **Assessment Period:** {} to {}\n",
        report.metadata.start_time.format("%Y-%m-%d %H:%M UTC"),
        report.metadata.end_time.format("%Y-%m-%d %H:%M UTC")
    ));
    md.push_str(&format!(
        "- **Report Generated:** {}\n\n",
        report.metadata.generated_at.format("%Y-%m-%d %H:%M UTC")
    ));

    // Executive Summary
    md.push_str("## Executive Summary\n\n");
    md.push_str(&format!(
        "Overall Risk Rating: **{}**\n\n",
        report.summary.risk_rating
    ));

    if !report.summary.executive_summary.is_empty() {
        md.push_str(&format!("{}\n\n", report.summary.executive_summary));
    }

    // Vulnerability Summary
    md.push_str("### Vulnerability Summary\n\n");
    md.push_str("| Severity | Count |\n|----------|-------|\n");
    md.push_str(&format!(
        "| Critical | {} |\n",
        report.summary.by_severity.critical
    ));
    md.push_str(&format!("| High | {} |\n", report.summary.by_severity.high));
    md.push_str(&format!(
        "| Medium | {} |\n",
        report.summary.by_severity.medium
    ));
    md.push_str(&format!("| Low | {} |\n", report.summary.by_severity.low));
    md.push_str(&format!("| Info | {} |\n", report.summary.by_severity.info));
    md.push_str(&format!(
        "| **Total** | **{}** |\n\n",
        report.summary.total_vulnerabilities
    ));

    // Key Findings
    if !report.summary.key_findings.is_empty() {
        md.push_str("### Key Findings\n\n");
        for finding in &report.summary.key_findings {
            md.push_str(&format!("- {}\n", finding));
        }
        md.push('\n');
    }

    // Metrics
    md.push_str("## Assessment Metrics\n\n");
    md.push_str(&format!(
        "- **Tool Executions:** {}\n",
        report.metrics.tool_calls
    ));
    md.push_str(&format!(
        "- **Hosts Discovered:** {}\n",
        report.metrics.hosts_discovered
    ));
    md.push_str(&format!(
        "- **Ports Discovered:** {}\n",
        report.metrics.ports_discovered
    ));
    md.push_str(&format!(
        "- **LLM Tokens Used:** {} input, {} output\n\n",
        report.metrics.input_tokens, report.metrics.output_tokens
    ));

    // Detailed Findings
    md.push_str("## Detailed Findings\n\n");

    if report.findings.is_empty() {
        md.push_str("No vulnerabilities were identified during this assessment.\n\n");
    } else {
        for (i, finding) in report.findings.iter().enumerate() {
            md.push_str(&format!(
                "### {}. {} [{}]\n\n",
                i + 1,
                finding.title,
                finding.severity
            ));
            md.push_str(&format!("**Affected:** {}\n\n", finding.affected));
            md.push_str(&format!("**Description:**\n{}\n\n", finding.description));

            if let Some(ref evidence) = finding.evidence {
                md.push_str(&format!("**Evidence:**\n```\n{}\n```\n\n", evidence));
            }

            if let Some(ref steps) = finding.reproduction_steps {
                md.push_str(&format!("**Reproduction Steps:**\n{}\n\n", steps));
            }

            if let Some(ref impact) = finding.impact {
                md.push_str(&format!("**Impact:**\n{}\n\n", impact));
            }

            if let Some(ref remediation) = finding.remediation {
                md.push_str(&format!("**Remediation:**\n{}\n\n", remediation));
            }

            if !finding.references.is_empty() {
                md.push_str("**References:**\n");
                for reference in &finding.references {
                    md.push_str(&format!("- {}\n", reference));
                }
                md.push('\n');
            }

            md.push_str("---\n\n");
        }
    }

    // Footer
    md.push_str("## Disclaimer\n\n");
    md.push_str(
        "This report was generated by feroxmute, an LLM-powered penetration testing tool. ",
    );
    md.push_str(
        "Findings should be validated by qualified security professionals before taking action.\n",
    );

    md
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_markdown_empty_report() {
        let metadata = ReportMetadata::new("example.com", "test-session", Utc::now(), Utc::now());
        let report = Report::new(metadata);

        let markdown = generate_markdown(&report);

        assert!(markdown.contains("# Security Assessment Report"));
        assert!(markdown.contains("example.com"));
        assert!(markdown.contains("No vulnerabilities were identified"));
    }

    #[test]
    fn test_generate_markdown_with_findings() {
        let metadata = ReportMetadata::new("example.com", "test-session", Utc::now(), Utc::now());
        let mut report = Report::new(metadata);

        report.add_finding(Finding {
            title: "SQL Injection".to_string(),
            severity: "Critical".to_string(),
            affected: "/api/login".to_string(),
            description: "SQL injection in login endpoint".to_string(),
            evidence: Some("Error: SQL syntax error".to_string()),
            reproduction_steps: None,
            impact: Some("Full database access".to_string()),
            remediation: Some("Use parameterized queries".to_string()),
            references: vec!["CWE-89".to_string()],
        });

        let markdown = generate_markdown(&report);

        assert!(markdown.contains("SQL Injection"));
        assert!(markdown.contains("Critical"));
        assert!(markdown.contains("/api/login"));
        assert!(markdown.contains("SQL syntax error"));
        assert!(markdown.contains("parameterized queries"));
        assert!(markdown.contains("CWE-89"));
    }
}
