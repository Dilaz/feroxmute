//! SAST agent detail widget

#![allow(clippy::indexing_slicing)]

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame,
};

use crate::tui::app::App;
use crate::tui::colors::{severity_style, status_style};

/// Render the SAST agent detail view
pub fn render(frame: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4), // Header
            Constraint::Length(6), // Summary
            Constraint::Min(10),   // Findings list
        ])
        .split(area);

    render_header(frame, app, chunks[0]);
    render_summary(frame, app, chunks[1]);
    render_findings(frame, app, chunks[2]);
}

/// Render header with status and source path
fn render_header(frame: &mut Frame, app: &App, area: Rect) {
    let status = app.agent_statuses.sast.as_deref().unwrap_or("idle");
    let source = app.source_path.as_deref().unwrap_or("-");

    let header = Paragraph::new(vec![
        Line::from(vec![
            Span::raw("Status: "),
            Span::styled(status, status_style(status)),
            Span::raw("  |  Source: "),
            Span::styled(source, Style::default().fg(Color::Cyan)),
        ]),
        Line::from(vec![
            Span::raw("Languages: "),
            Span::styled(
                app.detected_languages.join(", "),
                Style::default().fg(Color::Yellow),
            ),
        ]),
    ])
    .block(Block::default().borders(Borders::ALL).title(" SAST Agent "));

    frame.render_widget(header, area);
}

/// Render summary with finding counts by type
fn render_summary(frame: &mut Frame, app: &App, area: Rect) {
    let code_counts = &app.code_finding_counts;

    let summary_text = vec![
        Line::from(vec![Span::styled(
            "Findings by Type",
            Style::default().add_modifier(Modifier::BOLD),
        )]),
        Line::from(vec![
            Span::raw("  Dependencies: "),
            Span::styled(
                format!("{}", code_counts.dependencies),
                Style::default().fg(Color::Cyan),
            ),
        ]),
        Line::from(vec![
            Span::raw("  Code issues:  "),
            Span::styled(
                format!("{}", code_counts.sast),
                Style::default().fg(Color::Yellow),
            ),
        ]),
        Line::from(vec![
            Span::raw("  Secrets:      "),
            Span::styled(
                format!("{}", code_counts.secrets),
                Style::default().fg(Color::LightRed),
            ),
        ]),
    ];

    let summary = Paragraph::new(summary_text)
        .block(Block::default().borders(Borders::ALL).title(" Summary "));

    frame.render_widget(summary, area);
}

/// Render recent findings list with severity colors
fn render_findings(frame: &mut Frame, app: &App, area: Rect) {
    let items: Vec<ListItem> = app
        .code_findings
        .iter()
        .take(20)
        .map(|f| {
            let severity_span = Span::styled(
                format!("[{:8}]", format!("{:?}", f.severity)),
                severity_style(&f.severity),
            );

            let location = if let Some(line) = f.line_number {
                format!("{}:{}", f.file_path, line)
            } else {
                f.file_path.clone()
            };

            ListItem::new(Line::from(vec![
                severity_span,
                Span::raw(" "),
                Span::styled(&f.title, Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(" - "),
                Span::styled(location, Style::default().fg(Color::DarkGray)),
            ]))
        })
        .collect();

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Recent Findings "),
    );

    frame.render_widget(list, area);
}
