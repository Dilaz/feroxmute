//! Footer widget: metrics, severity summary, and context key hints on one line.

#![allow(clippy::indexing_slicing)]

use feroxmute_core::state::models::Severity;
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::Style,
    text::{Line, Span},
    widgets::Paragraph,
};

use crate::tui::app::App;

/// Render the footer line.
pub fn render(frame: &mut Frame, app: &App, area: Rect) {
    let theme = &app.theme;
    let g = &theme.glyphs;

    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(40),
            Constraint::Percentage(30),
            Constraint::Percentage(30),
        ])
        .split(area);

    // Left: metrics.
    let metrics = Line::from(vec![
        Span::styled(
            format!(
                "{} {}",
                g.metric_in,
                format_number(app.metrics.input_tokens)
            ),
            Style::default().fg(theme.muted),
        ),
        Span::raw("  "),
        Span::styled(
            format!(
                "{} {}",
                g.metric_out,
                format_number(app.metrics.output_tokens)
            ),
            Style::default().fg(theme.muted),
        ),
        Span::raw("  "),
        Span::styled(
            format_cost(app.metrics.estimated_cost_usd),
            Style::default().fg(theme.text),
        ),
        Span::raw("  "),
        Span::styled(
            format!("tools {}", app.metrics.tool_calls),
            Style::default().fg(theme.muted),
        ),
    ]);
    frame.render_widget(Paragraph::new(metrics), chunks[0]);

    // Middle: severity summary.
    let counts = app.severity_counts();
    let sevs = [
        ("C", Severity::Critical, counts[0]),
        ("H", Severity::High, counts[1]),
        ("M", Severity::Medium, counts[2]),
        ("L", Severity::Low, counts[3]),
        ("I", Severity::Info, counts[4]),
    ];
    let mut sev_spans = Vec::new();
    for (label, sev, count) in sevs {
        sev_spans.push(Span::styled(
            format!("{label}:{count}"),
            Style::default().fg(theme.severity_color(sev)),
        ));
        sev_spans.push(Span::raw(" "));
    }
    frame.render_widget(
        Paragraph::new(Line::from(sev_spans)).alignment(Alignment::Center),
        chunks[1],
    );

    // Right: key hints.
    let hints = if theme.caps.unicode {
        "tab focus · ↑↓ move · ⏎ detail · p mem · l logs · ? help · q quit"
    } else {
        "tab focus | up/dn move | enter detail | p mem | l logs | ? help | q quit"
    };
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            hints,
            Style::default().fg(theme.muted),
        )))
        .alignment(Alignment::Right),
        chunks[2],
    );
}

/// Format large numbers with K/M suffixes.
pub fn format_number(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.1}K", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}

/// Format cost with appropriate precision.
pub fn format_cost(cost: f64) -> String {
    if cost < 0.01 {
        format!("${cost:.4}")
    } else {
        format!("${cost:.2}")
    }
}
