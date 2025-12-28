//! SAST agent detail widget with hybrid layout
//!
//! Shows SAST-specific header, findings summary, and standard feed output.

#![allow(clippy::indexing_slicing)]

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame,
};

use crate::tui::app::App;
use feroxmute_core::agents::AgentStatus;

/// Render the SAST agent detail view with hybrid layout
pub fn render(frame: &mut Frame, app: &App, agent_name: &str, area: Rect) {
    let thinking = app.agents.get(agent_name).and_then(|a| a.thinking.as_ref());
    let show_thinking = app.show_thinking && thinking.is_some();

    let constraints = if show_thinking {
        vec![
            Constraint::Length(4), // Header
            Constraint::Length(4), // Summary
            Constraint::Min(8),    // Feed/output
            Constraint::Length(6), // Thinking
            Constraint::Length(1), // Footer
        ]
    } else {
        vec![
            Constraint::Length(4), // Header
            Constraint::Length(4), // Summary
            Constraint::Min(10),   // Feed/output
            Constraint::Length(1), // Footer
        ]
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(area);

    render_header(frame, app, agent_name, chunks[0]);
    render_summary(frame, app, chunks[1]);
    render_output(frame, app, agent_name, chunks[2]);

    if show_thinking {
        render_thinking(frame, thinking, chunks[3]);
        render_footer(frame, agent_name, app, chunks[4]);
    } else {
        render_footer(frame, agent_name, app, chunks[3]);
    }
}

/// Render header with status, source path, and languages
fn render_header(frame: &mut Frame, app: &App, agent_name: &str, area: Rect) {
    let (status, current_tool) = app
        .agents
        .get(agent_name)
        .map(|a| (a.status, a.current_tool.as_deref()))
        .unwrap_or((AgentStatus::Idle, None));

    let status_text = format_status(status, current_tool);
    let source = app.source_path.as_deref().unwrap_or("-");
    let languages = if app.detected_languages.is_empty() {
        "-".to_string()
    } else {
        app.detected_languages.join(", ")
    };

    let header = Paragraph::new(vec![
        Line::from(vec![
            Span::raw("Status: "),
            Span::styled(&status_text.0, status_text.1),
        ]),
        Line::from(vec![
            Span::raw("Source: "),
            Span::styled(source, Style::default().fg(Color::Cyan)),
            Span::raw("  Languages: "),
            Span::styled(languages, Style::default().fg(Color::Yellow)),
        ]),
    ])
    .block(Block::default().borders(Borders::ALL).title(" SAST Agent "));

    frame.render_widget(header, area);
}

/// Render summary with finding counts by type
fn render_summary(frame: &mut Frame, app: &App, area: Rect) {
    let counts = &app.code_finding_counts;
    let total = counts.dependencies + counts.sast + counts.secrets;

    let summary_text = vec![Line::from(vec![
        Span::styled("Dependencies: ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!("{}", counts.dependencies),
            Style::default().fg(Color::Cyan),
        ),
        Span::raw("  │  "),
        Span::styled("Code: ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!("{}", counts.sast),
            Style::default().fg(Color::Yellow),
        ),
        Span::raw("  │  "),
        Span::styled("Secrets: ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!("{}", counts.secrets),
            Style::default().fg(Color::LightRed),
        ),
        Span::raw("  "),
        Span::styled(
            format!("({} total)", total),
            Style::default().fg(Color::DarkGray),
        ),
    ])];

    let summary = Paragraph::new(summary_text)
        .block(Block::default().borders(Borders::ALL).title(" Findings "));

    frame.render_widget(summary, area);
}

/// Render feed/output section (same as agent_detail)
fn render_output(frame: &mut Frame, app: &App, agent_name: &str, area: Rect) {
    let mut lines: Vec<Line> = Vec::new();

    for entry in app.feed.iter().filter(|e| e.agent == agent_name) {
        let style = if entry.is_error {
            Style::default().fg(Color::Red)
        } else {
            Style::default()
        };
        let time_str = entry.timestamp.format("%H:%M:%S").to_string();

        lines.push(Line::from(vec![
            Span::styled(time_str, Style::default().fg(Color::DarkGray)),
            Span::raw(" "),
            Span::styled(&entry.message, style),
        ]));

        if entry.expanded {
            if let Some(ref output) = entry.tool_output {
                for line in output.lines() {
                    lines.push(Line::from(vec![
                        Span::styled("         ", Style::default()),
                        Span::styled("│ ", Style::default().fg(Color::DarkGray)),
                        Span::styled(line, style),
                    ]));
                }
            }
        }
    }

    let content = if lines.is_empty() {
        vec![Line::from(Span::styled(
            "No output yet...",
            Style::default().fg(Color::DarkGray),
        ))]
    } else {
        lines
    };

    let output = Paragraph::new(content)
        .wrap(Wrap { trim: false })
        .scroll((app.log_scroll as u16, 0))
        .block(Block::default().borders(Borders::ALL).title(" Output "));
    frame.render_widget(output, area);
}

/// Render thinking panel
fn render_thinking(frame: &mut Frame, thinking: Option<&String>, area: Rect) {
    let thinking_text = thinking
        .map(|s| s.as_str())
        .unwrap_or("No current thinking...");

    let thinking_widget = Paragraph::new(thinking_text)
        .style(Style::default().fg(Color::Yellow))
        .wrap(Wrap { trim: true })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Thinking ")
                .border_style(Style::default().fg(Color::Yellow)),
        );
    frame.render_widget(thinking_widget, area);
}

/// Render footer with keybindings
fn render_footer(frame: &mut Frame, current_agent: &str, app: &App, area: Rect) {
    let current_key = app
        .agents
        .get(current_agent)
        .map(|a| (a.spawn_order + 1).to_string())
        .unwrap_or("?".to_string());

    let spawned_count = app.agents.len().saturating_sub(1);
    let max_key = (spawned_count + 1).min(9);
    let agents_hint = if max_key > 1 {
        format!("1-{}", max_key)
    } else {
        "1".to_string()
    };

    let (thinking_label, thinking_style) = if app.show_thinking {
        ("[ON]", Style::default().fg(Color::Green))
    } else {
        ("[OFF]", Style::default().fg(Color::Red))
    };

    let help = Line::from(vec![
        Span::styled("h", Style::default().fg(Color::Yellow)),
        Span::raw(" back  "),
        Span::styled("j/k", Style::default().fg(Color::Yellow)),
        Span::raw(" scroll  "),
        Span::styled("o", Style::default().fg(Color::Yellow)),
        Span::raw(" output  "),
        Span::styled("t", Style::default().fg(Color::Yellow)),
        Span::raw(" thinking "),
        Span::styled(thinking_label, thinking_style),
        Span::raw("  "),
        Span::styled(&agents_hint, Style::default().fg(Color::Yellow)),
        Span::raw(" agents  "),
        Span::styled(&current_key, Style::default().fg(Color::Cyan)),
        Span::raw(" (current)  "),
        Span::styled("q", Style::default().fg(Color::Yellow)),
        Span::raw(" quit"),
    ]);

    let footer = Paragraph::new(help).style(Style::default().fg(Color::DarkGray));
    frame.render_widget(footer, area);
}

/// Format status with optional tool name
fn format_status(status: AgentStatus, current_tool: Option<&str>) -> (String, Style) {
    match status {
        AgentStatus::Idle => ("Idle".to_string(), Style::default().fg(Color::Gray)),
        AgentStatus::Thinking => (
            "Thinking".to_string(),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        AgentStatus::Streaming => (
            "Streaming".to_string(),
            Style::default()
                .fg(Color::Blue)
                .add_modifier(Modifier::BOLD),
        ),
        AgentStatus::Executing => {
            let tool_display = current_tool
                .map(|t| {
                    if t.len() > 20 {
                        format!("{}...", &t[..t.floor_char_boundary(17)])
                    } else {
                        t.to_string()
                    }
                })
                .unwrap_or_else(|| "Executing".to_string());
            (
                tool_display,
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )
        }
        AgentStatus::Processing => (
            "Processing".to_string(),
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        ),
        AgentStatus::Waiting => ("Waiting".to_string(), Style::default().fg(Color::Yellow)),
        AgentStatus::Retrying => (
            "Retrying".to_string(),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::SLOW_BLINK),
        ),
        AgentStatus::Completed => ("Completed".to_string(), Style::default().fg(Color::Green)),
        AgentStatus::Failed => (
            "Failed".to_string(),
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ),
    }
}
