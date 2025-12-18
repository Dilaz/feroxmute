//! Agent detail widget for viewing individual agent status and output

use feroxmute_core::agents::AgentStatus;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame,
};

use crate::tui::app::{AgentView, App};

/// Render the agent detail view
pub fn render(frame: &mut Frame, app: &App, agent_view: AgentView) {
    let show_thinking = app.show_thinking && app.current_thinking.is_some();

    let constraints = if show_thinking {
        vec![
            Constraint::Length(3), // Header
            Constraint::Min(10),   // Output
            Constraint::Length(8), // Thinking
            Constraint::Length(1), // Footer
        ]
    } else {
        vec![
            Constraint::Length(3), // Header
            Constraint::Min(10),   // Output
            Constraint::Length(1), // Footer
        ]
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(frame.area());

    render_header(frame, app, agent_view, chunks[0]);
    render_output(frame, app, agent_view, chunks[1]);

    if show_thinking {
        render_thinking(frame, app, chunks[2]);
        render_footer(frame, agent_view, chunks[3]);
    } else {
        render_footer(frame, agent_view, chunks[2]);
    }
}

/// Render the agent header
fn render_header(frame: &mut Frame, app: &App, agent_view: AgentView, area: Rect) {
    let (name, status) = match agent_view {
        AgentView::Orchestrator => ("Orchestrator", app.agent_statuses.orchestrator),
        AgentView::Recon => ("Recon Agent", app.agent_statuses.recon),
        AgentView::Scanner => ("Scanner Agent", app.agent_statuses.scanner),
        AgentView::Sast => ("SAST Agent", AgentStatus::Idle), // SAST uses string status
    };

    let (status_text, status_style) = format_status(status);

    let header_text = vec![Line::from(vec![
        Span::styled(
            name,
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
            .title(format!(" {} ", name)),
    );

    frame.render_widget(header, area);
}

/// Render the output area
fn render_output(frame: &mut Frame, app: &App, agent_view: AgentView, area: Rect) {
    // Get relevant feed entries for this agent
    let agent_name = match agent_view {
        AgentView::Orchestrator => "orchestrator",
        AgentView::Recon => "recon",
        AgentView::Scanner => "scanner",
        AgentView::Sast => "sast",
    };

    let output_text: Vec<Line> = app
        .feed
        .iter()
        .filter(|entry| entry.agent == agent_name)
        .rev()
        .map(|entry| {
            let style = if entry.is_error {
                Style::default().fg(Color::Red)
            } else {
                Style::default()
            };
            Line::from(Span::styled(&entry.message, style))
        })
        .collect();

    let content = if output_text.is_empty() {
        vec![Line::from(Span::styled(
            "No output yet...",
            Style::default().fg(Color::DarkGray),
        ))]
    } else {
        output_text
    };

    let output = Paragraph::new(content)
        .wrap(Wrap { trim: false })
        .scroll((app.log_scroll as u16, 0))
        .block(Block::default().borders(Borders::ALL).title(" Output "));

    frame.render_widget(output, area);
}

/// Render the thinking panel
fn render_thinking(frame: &mut Frame, app: &App, area: Rect) {
    let thinking_text = app
        .current_thinking
        .as_deref()
        .unwrap_or("No current thinking...");

    let thinking = Paragraph::new(thinking_text)
        .style(Style::default().fg(Color::Yellow))
        .wrap(Wrap { trim: true })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Thinking ")
                .border_style(Style::default().fg(Color::Yellow)),
        );

    frame.render_widget(thinking, area);
}

/// Render footer with keybindings
fn render_footer(frame: &mut Frame, agent_view: AgentView, area: Rect) {
    let current_key = match agent_view {
        AgentView::Orchestrator => "1",
        AgentView::Recon => "2",
        AgentView::Scanner => "3",
        AgentView::Sast => "4",
    };

    let help = Line::from(vec![
        Span::styled("h", Style::default().fg(Color::Yellow)),
        Span::raw(" back  "),
        Span::styled("j/k", Style::default().fg(Color::Yellow)),
        Span::raw(" scroll  "),
        Span::styled("t", Style::default().fg(Color::Yellow)),
        Span::raw(" thinking  "),
        Span::styled(current_key, Style::default().fg(Color::Cyan)),
        Span::raw(" (current)  "),
        Span::styled("q", Style::default().fg(Color::Yellow)),
        Span::raw(" quit"),
    ]);

    let footer = Paragraph::new(help).style(Style::default().fg(Color::DarkGray));
    frame.render_widget(footer, area);
}

/// Format agent status for display
fn format_status(status: AgentStatus) -> (&'static str, Style) {
    match status {
        AgentStatus::Idle => ("Idle", Style::default().fg(Color::Gray)),
        AgentStatus::Planning => ("Planning...", Style::default().fg(Color::Blue)),
        AgentStatus::Running => (
            "Running",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        AgentStatus::Waiting => ("Waiting", Style::default().fg(Color::Yellow)),
        AgentStatus::Completed => ("Completed", Style::default().fg(Color::Cyan)),
        AgentStatus::Failed => (
            "Failed",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ),
    }
}
