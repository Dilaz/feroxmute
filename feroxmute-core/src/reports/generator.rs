//! Report generation and export

use std::io::BufWriter;
use std::path::Path;

use chrono::{DateTime, Utc};
use printpdf::{BuiltinFont, Mm, PdfDocument};
use rusqlite::Connection;

use crate::Result;
use crate::state::{MetricsTracker, Vulnerability};

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

/// Export report to HTML file
pub fn export_html(report: &Report, path: impl AsRef<Path>) -> Result<()> {
    let html = generate_html(report);
    std::fs::write(path, html)?;
    Ok(())
}

/// Export report to PDF file
pub fn export_pdf(report: &Report, path: impl AsRef<Path>) -> Result<()> {
    let pdf_bytes = generate_pdf(report)?;
    std::fs::write(path, pdf_bytes)?;
    Ok(())
}

/// Generate HTML report content
fn generate_html(report: &Report) -> String {
    let severity_class = |s: &str| match s.to_lowercase().as_str() {
        "critical" => "critical",
        "high" => "high",
        "medium" => "medium",
        "low" => "low",
        _ => "info",
    };

    let mut findings_html = String::new();
    for finding in &report.findings {
        let class = severity_class(&finding.severity);
        findings_html.push_str(&format!(
            r#"<div class="finding {class}">
    <h3>[{severity}] {title}</h3>
    <p><strong>Affected:</strong> {affected}</p>
    <p>{description}</p>
    {evidence}
    {remediation}
</div>
"#,
            class = class,
            severity = finding.severity.to_uppercase(),
            title = html_escape(&finding.title),
            affected = html_escape(&finding.affected),
            description = html_escape(&finding.description),
            evidence = finding
                .evidence
                .as_ref()
                .map(|e| format!("<pre>{}</pre>", html_escape(e)))
                .unwrap_or_default(),
            remediation = finding
                .remediation
                .as_ref()
                .map(|r| format!("<p><strong>Remediation:</strong> {}</p>", html_escape(r)))
                .unwrap_or_default(),
        ));
    }

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Security Assessment: {target}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 900px;
            margin: 40px auto;
            padding: 0 20px;
            line-height: 1.6;
            color: #333;
        }}
        h1 {{ border-bottom: 2px solid #333; padding-bottom: 10px; }}
        h2 {{ color: #555; margin-top: 30px; }}
        .summary {{
            background: #f5f5f5;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 10px;
            text-align: center;
            margin-top: 15px;
        }}
        .summary-item {{ padding: 10px; border-radius: 4px; }}
        .summary-item.critical {{ background: #dc3545; color: white; }}
        .summary-item.high {{ background: #fd7e14; color: white; }}
        .summary-item.medium {{ background: #ffc107; color: #333; }}
        .summary-item.low {{ background: #28a745; color: white; }}
        .summary-item.info {{ background: #17a2b8; color: white; }}
        .finding {{
            border-left: 4px solid #ccc;
            padding: 15px 20px;
            margin: 20px 0;
            background: #fafafa;
        }}
        .finding.critical {{ border-color: #dc3545; }}
        .finding.high {{ border-color: #fd7e14; }}
        .finding.medium {{ border-color: #ffc107; }}
        .finding.low {{ border-color: #28a745; }}
        .finding.info {{ border-color: #17a2b8; }}
        .finding h3 {{ margin-top: 0; }}
        pre {{
            background: #2d2d2d;
            color: #f8f8f2;
            padding: 15px;
            border-radius: 4px;
            overflow-x: auto;
        }}
        .metrics {{
            color: #666;
            font-size: 0.9em;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
        }}
        .footer {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            color: #888;
            font-size: 0.85em;
        }}
    </style>
</head>
<body>
    <h1>Security Assessment: {target}</h1>

    <div class="summary">
        <strong>Risk Rating:</strong> {risk_rating}<br>
        <strong>Assessment Period:</strong> {start_time} to {end_time}<br>
        <strong>Session ID:</strong> {session_id}

        <div class="summary-grid">
            <div class="summary-item critical">{critical}<br>Critical</div>
            <div class="summary-item high">{high}<br>High</div>
            <div class="summary-item medium">{medium}<br>Medium</div>
            <div class="summary-item low">{low}<br>Low</div>
            <div class="summary-item info">{info}<br>Info</div>
        </div>

        <p style="margin-top: 15px;">{executive_summary}</p>
    </div>

    <h2>Findings ({total})</h2>
    {findings}

    <div class="metrics">
        <h3>Engagement Metrics</h3>
        <p>
            Tool Calls: {tool_calls} |
            Hosts: {hosts} |
            Ports: {ports} |
            Tokens: {input_tokens} input / {output_tokens} output
        </p>
    </div>

    <div class="footer">
        <p>Generated by feroxmute on {generated_at}. Findings should be validated by qualified security professionals.</p>
    </div>
</body>
</html>"#,
        target = html_escape(&report.metadata.target),
        risk_rating = report.summary.risk_rating,
        start_time = report.metadata.start_time.format("%Y-%m-%d %H:%M UTC"),
        end_time = report.metadata.end_time.format("%Y-%m-%d %H:%M UTC"),
        session_id = html_escape(&report.metadata.session_id),
        critical = report.summary.by_severity.critical,
        high = report.summary.by_severity.high,
        medium = report.summary.by_severity.medium,
        low = report.summary.by_severity.low,
        info = report.summary.by_severity.info,
        executive_summary = html_escape(&report.summary.executive_summary),
        total = report.summary.total_vulnerabilities,
        findings = if findings_html.is_empty() {
            "<p>No vulnerabilities were identified during this assessment.</p>".to_string()
        } else {
            findings_html
        },
        tool_calls = report.metrics.tool_calls,
        hosts = report.metrics.hosts_discovered,
        ports = report.metrics.ports_discovered,
        input_tokens = report.metrics.input_tokens,
        output_tokens = report.metrics.output_tokens,
        generated_at = report.metadata.generated_at.format("%Y-%m-%d %H:%M UTC"),
    )
}

/// Escape HTML special characters
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Generate PDF report content
fn generate_pdf(report: &Report) -> Result<Vec<u8>> {
    let (doc, page1, layer1) = PdfDocument::new(
        "Security Assessment Report",
        Mm(210.0),
        Mm(297.0),
        "Layer 1",
    );

    let font = doc
        .add_builtin_font(BuiltinFont::Helvetica)
        .map_err(|e| crate::Error::Report(format!("Failed to load font: {}", e)))?;
    let font_bold = doc
        .add_builtin_font(BuiltinFont::HelveticaBold)
        .map_err(|e| crate::Error::Report(format!("Failed to load bold font: {}", e)))?;

    let current_layer = doc.get_page(page1).get_layer(layer1);

    let x = Mm(20.0);
    let mut y = Mm(277.0);
    let line_height = Mm(5.0);
    let section_gap = Mm(10.0);

    // Title
    current_layer.use_text(
        format!("SECURITY ASSESSMENT: {}", report.metadata.target),
        14.0,
        x,
        y,
        &font_bold,
    );
    y -= Mm(8.0);

    // Underline
    current_layer.use_text("=".repeat(60), 10.0, x, y, &font);
    y -= section_gap;

    // Metadata
    current_layer.use_text(
        format!("Risk Rating: {}", report.summary.risk_rating),
        10.0,
        x,
        y,
        &font,
    );
    y -= line_height;

    current_layer.use_text(
        format!(
            "Assessment: {} to {}",
            report.metadata.start_time.format("%Y-%m-%d"),
            report.metadata.end_time.format("%Y-%m-%d")
        ),
        10.0,
        x,
        y,
        &font,
    );
    y -= line_height;

    current_layer.use_text(
        format!("Session: {}", report.metadata.session_id),
        10.0,
        x,
        y,
        &font,
    );
    y -= section_gap;

    // Summary counts
    current_layer.use_text("VULNERABILITY SUMMARY", 11.0, x, y, &font_bold);
    y -= line_height;

    current_layer.use_text(
        format!(
            "Critical: {} | High: {} | Medium: {} | Low: {} | Info: {}",
            report.summary.by_severity.critical,
            report.summary.by_severity.high,
            report.summary.by_severity.medium,
            report.summary.by_severity.low,
            report.summary.by_severity.info
        ),
        10.0,
        x,
        y,
        &font,
    );
    y -= section_gap;

    // Executive summary (truncated for PDF)
    if !report.summary.executive_summary.is_empty() {
        current_layer.use_text("EXECUTIVE SUMMARY", 11.0, x, y, &font_bold);
        y -= line_height;

        let summary = if report.summary.executive_summary.len() > 200 {
            format!("{}...", &report.summary.executive_summary[..200])
        } else {
            report.summary.executive_summary.clone()
        };

        // Wrap long lines
        for line in wrap_text(&summary, 80) {
            if y < Mm(30.0) {
                break; // Don't overflow page
            }
            current_layer.use_text(line, 9.0, x, y, &font);
            y -= line_height;
        }
        y -= Mm(5.0);
    }

    // Findings
    current_layer.use_text(
        format!("FINDINGS ({})", report.findings.len()),
        11.0,
        x,
        y,
        &font_bold,
    );
    y -= line_height;

    if report.findings.is_empty() {
        current_layer.use_text("No vulnerabilities were identified.", 10.0, x, y, &font);
    } else {
        for (i, finding) in report.findings.iter().take(10).enumerate() {
            if y < Mm(40.0) {
                current_layer.use_text("... (see HTML/JSON for full report)", 9.0, x, y, &font);
                break;
            }

            current_layer.use_text(
                format!(
                    "{}. [{}] {}",
                    i + 1,
                    finding.severity.to_uppercase(),
                    truncate(&finding.title, 60)
                ),
                10.0,
                x,
                y,
                &font,
            );
            y -= line_height;

            current_layer.use_text(
                format!("   Affected: {}", truncate(&finding.affected, 55)),
                9.0,
                x,
                y,
                &font,
            );
            y -= line_height + Mm(2.0);
        }
    }

    // Metrics at bottom
    y = Mm(25.0);
    current_layer.use_text(
        format!(
            "Metrics: {} tool calls | {} hosts | {} ports | {} tokens",
            report.metrics.tool_calls,
            report.metrics.hosts_discovered,
            report.metrics.ports_discovered,
            report.metrics.input_tokens + report.metrics.output_tokens
        ),
        8.0,
        x,
        y,
        &font,
    );

    y -= line_height;
    current_layer.use_text(
        format!(
            "Generated by feroxmute on {}",
            report.metadata.generated_at.format("%Y-%m-%d %H:%M UTC")
        ),
        8.0,
        x,
        y,
        &font,
    );

    // Save to bytes
    let mut buffer = BufWriter::new(Vec::new());
    doc.save(&mut buffer)
        .map_err(|e| crate::Error::Report(format!("Failed to save PDF: {}", e)))?;

    buffer
        .into_inner()
        .map_err(|e| crate::Error::Report(e.to_string()))
}

/// Wrap text to specified width
fn wrap_text(text: &str, max_chars: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current_line = String::new();

    for word in text.split_whitespace() {
        if current_line.len() + word.len() + 1 > max_chars && !current_line.is_empty() {
            lines.push(current_line);
            current_line = String::new();
        }
        if !current_line.is_empty() {
            current_line.push(' ');
        }
        current_line.push_str(word);
    }

    if !current_line.is_empty() {
        lines.push(current_line);
    }

    lines
}

/// Truncate string to max length
fn truncate(s: &str, max: usize) -> String {
    if s.len() > max {
        format!("{}...", &s[..max.saturating_sub(3)])
    } else {
        s.to_string()
    }
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
