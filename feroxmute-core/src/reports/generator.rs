//! Report generation and export

use std::collections::HashMap;
use std::path::Path;

use chrono::{DateTime, Utc};
use printpdf::{
    BuiltinFont, Mm, Op, PdfDocument, PdfPage, PdfSaveOptions, PdfWarnMsg, Pt, TextItem,
    graphics::Point, ops::PdfFontHandle,
};
use rusqlite::Connection;

use crate::Result;
use crate::state::{Metrics, MetricsTracker, Severity, Vulnerability};

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

    // Load metrics: use max of in-memory tracker vs DB-persisted values
    let snapshot = metrics.snapshot();
    let db_metrics = Metrics::load(conn).unwrap_or_default();
    report.metrics = ReportMetrics {
        tool_calls: snapshot.tool_calls.max(db_metrics.tool_calls),
        input_tokens: snapshot.tokens.input.max(db_metrics.tokens.input),
        output_tokens: snapshot.tokens.output.max(db_metrics.tokens.output),
        cache_read_tokens: snapshot.tokens.cached.max(db_metrics.tokens.cached),
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

/// Load vulnerabilities from database, deduplicating by (title, severity)
fn load_vulnerabilities(conn: &Connection) -> Result<Vec<Vulnerability>> {
    let vulns = Vulnerability::all(conn)?;
    Ok(deduplicate_vulnerabilities(vulns))
}

/// Deduplicate vulnerabilities by grouping on (normalized title, severity).
/// Merges evidence, remediation, and agent attribution from duplicates.
pub fn deduplicate_vulnerabilities(vulns: Vec<Vulnerability>) -> Vec<Vulnerability> {
    let mut groups: HashMap<(String, Severity), Vec<Vulnerability>> = HashMap::new();

    for vuln in vulns {
        let key = (vuln.title.trim().to_lowercase(), vuln.severity);
        groups.entry(key).or_default().push(vuln);
    }

    let mut result: Vec<Vulnerability> = groups
        .into_values()
        .map(merge_vulnerability_group)
        .collect();

    // Re-sort by severity (critical first) to match the original ordering
    result.sort_by_key(|v| match v.severity {
        Severity::Critical => 0,
        Severity::High => 1,
        Severity::Medium => 2,
        Severity::Low => 3,
        Severity::Info => 4,
    });

    result
}

/// Merge a group of duplicate vulnerabilities into a single entry.
/// Takes the longest description/remediation, combines evidence, collects all agents.
fn merge_vulnerability_group(mut group: Vec<Vulnerability>) -> Vulnerability {
    debug_assert!(!group.is_empty());
    // The first element becomes the base; remaining are merged in.
    // Safety: caller guarantees non-empty group (HashMap grouping).
    let mut merged = group.remove(0);

    for vuln in group {
        // Keep the longest description
        if let Some(ref desc) = vuln.description {
            match merged.description {
                Some(ref existing) if desc.len() > existing.len() => {
                    merged.description = Some(desc.clone());
                }
                None => merged.description = Some(desc.clone()),
                _ => {}
            }
        }

        // Keep the longest remediation
        if let Some(ref rem) = vuln.remediation {
            match merged.remediation {
                Some(ref existing) if rem.len() > existing.len() => {
                    merged.remediation = Some(rem.clone());
                }
                None => merged.remediation = Some(rem.clone()),
                _ => {}
            }
        }

        // Combine evidence with separator
        if let Some(ref new_evidence) = vuln.evidence {
            merged.evidence = Some(match merged.evidence {
                Some(ref existing) if existing.contains(new_evidence.as_str()) => existing.clone(),
                Some(ref existing) => format!("{}\n\n---\n\n{}", existing, new_evidence),
                None => new_evidence.clone(),
            });
        }

        // Collect distinct agents into discovered_by
        if !merged.discovered_by.contains(&vuln.discovered_by) {
            merged.discovered_by = format!("{}, {}", merged.discovered_by, vuln.discovered_by);
        }

        // Use most specific asset (non-empty, longest)
        if let Some(ref asset) = vuln.asset {
            match merged.asset {
                Some(ref existing) if asset.len() > existing.len() => {
                    merged.asset = Some(asset.clone());
                }
                None => merged.asset = Some(asset.clone()),
                _ => {}
            }
        }

        // Keep highest CVSS score
        if let Some(new_cvss) = vuln.cvss {
            match merged.cvss {
                Some(existing) if new_cvss > existing => merged.cvss = Some(new_cvss),
                None => merged.cvss = Some(new_cvss),
                _ => {}
            }
        }

        // Keep CWE if we don't have one
        if merged.cwe.is_none() {
            merged.cwe = vuln.cwe;
        }
    }

    merged
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

/// Helper: emit ops to write text with a builtin font at a given position and size.
/// Appends StartTextSection, SetFont, SetTextCursor, ShowText, EndTextSection ops.
fn text_ops(font: &PdfFontHandle, size: f32, x_mm: f32, y_mm: f32, text: &str) -> Vec<Op> {
    let x_pt: Pt = Mm(x_mm).into();
    let y_pt: Pt = Mm(y_mm).into();
    vec![
        Op::StartTextSection,
        Op::SetFont {
            font: font.clone(),
            size: Pt(size),
        },
        Op::SetTextCursor {
            pos: Point { x: x_pt, y: y_pt },
        },
        Op::ShowText {
            items: vec![TextItem::Text(text.to_string())],
        },
        Op::EndTextSection,
    ]
}

/// Generate PDF report content
fn generate_pdf(report: &Report) -> Result<Vec<u8>> {
    let font = PdfFontHandle::Builtin(BuiltinFont::Helvetica);
    let font_bold = PdfFontHandle::Builtin(BuiltinFont::HelveticaBold);

    let x = 20.0_f32; // mm
    let mut y = 277.0_f32; // mm
    let line_height = 5.0_f32;
    let section_gap = 10.0_f32;

    let mut ops: Vec<Op> = Vec::new();

    // Title
    ops.extend(text_ops(
        &font_bold,
        14.0,
        x,
        y,
        &format!("SECURITY ASSESSMENT: {}", report.metadata.target),
    ));
    y -= 8.0;

    // Underline
    ops.extend(text_ops(&font, 10.0, x, y, &"=".repeat(60)));
    y -= section_gap;

    // Metadata
    ops.extend(text_ops(
        &font,
        10.0,
        x,
        y,
        &format!("Risk Rating: {}", report.summary.risk_rating),
    ));
    y -= line_height;

    ops.extend(text_ops(
        &font,
        10.0,
        x,
        y,
        &format!(
            "Assessment: {} to {}",
            report.metadata.start_time.format("%Y-%m-%d"),
            report.metadata.end_time.format("%Y-%m-%d")
        ),
    ));
    y -= line_height;

    ops.extend(text_ops(
        &font,
        10.0,
        x,
        y,
        &format!("Session: {}", report.metadata.session_id),
    ));
    y -= section_gap;

    // Summary counts
    ops.extend(text_ops(&font_bold, 11.0, x, y, "VULNERABILITY SUMMARY"));
    y -= line_height;

    ops.extend(text_ops(
        &font,
        10.0,
        x,
        y,
        &format!(
            "Critical: {} | High: {} | Medium: {} | Low: {} | Info: {}",
            report.summary.by_severity.critical,
            report.summary.by_severity.high,
            report.summary.by_severity.medium,
            report.summary.by_severity.low,
            report.summary.by_severity.info
        ),
    ));
    y -= section_gap;

    // Executive summary (truncated for PDF)
    if !report.summary.executive_summary.is_empty() {
        ops.extend(text_ops(&font_bold, 11.0, x, y, "EXECUTIVE SUMMARY"));
        y -= line_height;

        let summary = if report.summary.executive_summary.chars().count() > 200 {
            format!(
                "{}...",
                report
                    .summary
                    .executive_summary
                    .chars()
                    .take(200)
                    .collect::<String>()
            )
        } else {
            report.summary.executive_summary.clone()
        };

        // Wrap long lines
        for line in wrap_text(&summary, 80) {
            if y < 30.0 {
                break; // Don't overflow page
            }
            ops.extend(text_ops(&font, 9.0, x, y, &line));
            y -= line_height;
        }
        y -= 5.0;
    }

    // Findings
    ops.extend(text_ops(
        &font_bold,
        11.0,
        x,
        y,
        &format!("FINDINGS ({})", report.findings.len()),
    ));
    y -= line_height;

    if report.findings.is_empty() {
        ops.extend(text_ops(
            &font,
            10.0,
            x,
            y,
            "No vulnerabilities were identified.",
        ));
    } else {
        for (i, finding) in report.findings.iter().take(10).enumerate() {
            if y < 40.0 {
                ops.extend(text_ops(
                    &font,
                    9.0,
                    x,
                    y,
                    "... (see HTML/JSON for full report)",
                ));
                break;
            }

            ops.extend(text_ops(
                &font,
                10.0,
                x,
                y,
                &format!(
                    "{}. [{}] {}",
                    i + 1,
                    finding.severity.to_uppercase(),
                    truncate(&finding.title, 60)
                ),
            ));
            y -= line_height;

            ops.extend(text_ops(
                &font,
                9.0,
                x,
                y,
                &format!("   Affected: {}", truncate(&finding.affected, 55)),
            ));
            y -= line_height + 2.0;
        }
    }

    // Metrics at bottom
    y = 25.0;
    ops.extend(text_ops(
        &font,
        8.0,
        x,
        y,
        &format!(
            "Metrics: {} tool calls | {} hosts | {} ports | {} tokens",
            report.metrics.tool_calls,
            report.metrics.hosts_discovered,
            report.metrics.ports_discovered,
            report.metrics.input_tokens + report.metrics.output_tokens
        ),
    ));

    y -= line_height;
    ops.extend(text_ops(
        &font,
        8.0,
        x,
        y,
        &format!(
            "Generated by feroxmute on {}",
            report.metadata.generated_at.format("%Y-%m-%d %H:%M UTC")
        ),
    ));

    // Build the page and document
    let page = PdfPage::new(Mm(210.0), Mm(297.0), ops);
    let mut doc = PdfDocument::new("Security Assessment Report");
    doc.with_pages(vec![page]);

    let mut warnings: Vec<PdfWarnMsg> = Vec::new();
    let pdf_bytes = doc.save(&PdfSaveOptions::default(), &mut warnings);

    Ok(pdf_bytes)
}

/// Wrap text to specified width
fn wrap_text(text: &str, max_chars: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current_line = String::new();

    for word in text.split_whitespace() {
        if current_line.chars().count() + word.chars().count() + 1 > max_chars
            && !current_line.is_empty()
        {
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
    if s.chars().count() > max {
        format!(
            "{}...",
            s.chars().take(max.saturating_sub(3)).collect::<String>()
        )
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
    use crate::state::VulnStatus;

    fn make_vuln(title: &str, severity: Severity, discovered_by: &str) -> Vulnerability {
        Vulnerability {
            id: format!("VULN-{}", title.len()),
            host_id: None,
            vuln_type: "test".to_string(),
            severity,
            title: title.to_string(),
            description: None,
            evidence: None,
            status: VulnStatus::Potential,
            cwe: None,
            cvss: None,
            asset: None,
            remediation: None,
            discovered_by: discovered_by.to_string(),
            verified_by: None,
            discovered_at: Utc::now(),
            verified_at: None,
        }
    }

    #[test]
    fn test_deduplicate_merges_same_title_severity() {
        let vulns = vec![
            make_vuln("SQL Injection", Severity::Critical, "recon-agent"),
            make_vuln("SQL Injection", Severity::Critical, "scanner-agent"),
            make_vuln("XSS", Severity::High, "scanner-agent"),
        ];

        let deduped = deduplicate_vulnerabilities(vulns);
        assert_eq!(deduped.len(), 2);

        let sqli = deduped.iter().find(|v| v.title == "SQL Injection").unwrap();
        assert!(sqli.discovered_by.contains("recon-agent"));
        assert!(sqli.discovered_by.contains("scanner-agent"));
    }

    #[test]
    fn test_deduplicate_case_insensitive_title() {
        let vulns = vec![
            make_vuln("Hardcoded Credentials", Severity::High, "agent-a"),
            make_vuln("hardcoded credentials", Severity::High, "agent-b"),
            make_vuln("HARDCODED CREDENTIALS", Severity::High, "agent-c"),
        ];

        let deduped = deduplicate_vulnerabilities(vulns);
        assert_eq!(deduped.len(), 1);
        assert!(deduped[0].discovered_by.contains("agent-a"));
        assert!(deduped[0].discovered_by.contains("agent-b"));
        assert!(deduped[0].discovered_by.contains("agent-c"));
    }

    #[test]
    fn test_deduplicate_different_severity_not_merged() {
        let vulns = vec![
            make_vuln("Open Port", Severity::Info, "recon"),
            make_vuln("Open Port", Severity::Medium, "scanner"),
        ];

        let deduped = deduplicate_vulnerabilities(vulns);
        assert_eq!(deduped.len(), 2);
    }

    #[test]
    fn test_deduplicate_merges_evidence() {
        let mut v1 = make_vuln("Bug", Severity::High, "a");
        v1.evidence = Some("Evidence A".to_string());
        let mut v2 = make_vuln("Bug", Severity::High, "b");
        v2.evidence = Some("Evidence B".to_string());

        let deduped = deduplicate_vulnerabilities(vec![v1, v2]);
        assert_eq!(deduped.len(), 1);
        let evidence = deduped[0].evidence.as_ref().unwrap();
        assert!(evidence.contains("Evidence A"));
        assert!(evidence.contains("Evidence B"));
    }

    #[test]
    fn test_deduplicate_keeps_longest_description() {
        let mut v1 = make_vuln("Bug", Severity::High, "a");
        v1.description = Some("Short".to_string());
        let mut v2 = make_vuln("Bug", Severity::High, "b");
        v2.description = Some("A much longer and more detailed description of the bug".to_string());

        let deduped = deduplicate_vulnerabilities(vec![v1, v2]);
        assert_eq!(deduped.len(), 1);
        assert!(
            deduped[0]
                .description
                .as_ref()
                .unwrap()
                .contains("much longer")
        );
    }

    #[test]
    fn test_deduplicate_no_duplicates_passthrough() {
        let vulns = vec![
            make_vuln("Bug A", Severity::Critical, "a"),
            make_vuln("Bug B", Severity::High, "b"),
            make_vuln("Bug C", Severity::Medium, "c"),
        ];

        let deduped = deduplicate_vulnerabilities(vulns);
        assert_eq!(deduped.len(), 3);
    }

    #[test]
    fn test_deduplicate_empty() {
        let deduped = deduplicate_vulnerabilities(vec![]);
        assert!(deduped.is_empty());
    }

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
