//! Agent detail widget for viewing individual agent status and output

#![allow(clippy::indexing_slicing)]

use feroxmute_core::agents::AgentStatus;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame,
};

use crate::tui::app::App;
use crate::tui::colors::format_agent_status;

/// Render the agent detail view
pub fn render(frame: &mut Frame, app: &App, agent_name: &str) {
    // Note: SAST-specific view (sast.rs) is available but requires CodeFinding events
    // to be implemented. For now, SAST agents use the standard agent detail view.

    let thinking = app.agents.get(agent_name).and_then(|a| a.thinking.as_ref());
    let show_thinking = app.show_thinking && thinking.is_some();

    let constraints = if show_thinking {
        vec![
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(8),
            Constraint::Length(1),
        ]
    } else {
        vec![
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(1),
        ]
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(frame.area());

    render_header(frame, app, agent_name, chunks[0]);
    render_output(frame, app, agent_name, chunks[1]);

    if show_thinking {
        render_thinking(frame, thinking, chunks[2]);
        render_footer(frame, agent_name, app, chunks[3]);
    } else {
        render_footer(frame, agent_name, app, chunks[2]);
    }
}

fn render_header(frame: &mut Frame, app: &App, agent_name: &str, area: Rect) {
    let (display_name, status, current_tool) = if let Some(info) = app.agents.get(agent_name) {
        let name = if info.agent_type.is_empty() {
            agent_name.to_string()
        } else {
            format!("{} ({})", agent_name, info.agent_type)
        };
        (name, info.status, info.current_tool.as_deref())
    } else {
        (agent_name.to_string(), AgentStatus::Idle, None)
    };

    let (status_text, status_style) = format_agent_status(status, current_tool);

    let header_text = vec![Line::from(vec![
        Span::styled(
            &display_name,
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  |  "),
        Span::styled("Status: ", Style::default().fg(Color::Gray)),
        Span::styled(status_text, status_style),
    ])];

    let header = Paragraph::new(header_text).block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" {} ", display_name)),
    );
    frame.render_widget(header, area);
}

fn render_output(frame: &mut Frame, app: &App, agent_name: &str, area: Rect) {
    let mut lines: Vec<Line> = Vec::new();

    // Use indexed lookup for efficient agent-specific filtering
    for entry in app.get_agent_feed(agent_name) {
        let style = if entry.is_error {
            Style::default().fg(Color::Red)
        } else {
            Style::default()
        };
        let time_str = entry.timestamp.format("%H:%M:%S").to_string();

        // Main message line
        lines.push(Line::from(vec![
            Span::styled(time_str, Style::default().fg(Color::DarkGray)),
            Span::raw(" "),
            Span::styled(&entry.message, style),
        ]));

        // If expanded and has output, show it
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

    // Clamp scroll to content height to prevent scrolling past content
    let content_height = content.len();
    let visible_height = area.height.saturating_sub(2) as usize;
    let max_scroll = content_height.saturating_sub(visible_height);
    let clamped_scroll = app.log_scroll.min(max_scroll);

    let output = Paragraph::new(content)
        .wrap(Wrap { trim: false })
        .scroll((clamped_scroll as u16, 0))
        .block(Block::default().borders(Borders::ALL).title(" Output "));
    frame.render_widget(output, area);
}

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

fn render_footer(frame: &mut Frame, current_agent: &str, app: &App, area: Rect) {
    let current_key = if current_agent == "orchestrator" {
        "1".to_string()
    } else {
        app.agents
            .get(current_agent)
            .map(|a| (a.spawn_order + 1).to_string())
            .unwrap_or("?".to_string())
    };

    let spawned_count = app.agents.len().saturating_sub(1);
    let max_key = (spawned_count + 1).min(9);
    let agents_hint = if max_key > 1 {
        format!("1-{}", max_key)
    } else {
        "1".to_string()
    };

    // Show thinking toggle state with color indicator
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
