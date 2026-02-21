//! Event timeline view showing real-time events across all agents

#![allow(clippy::indexing_slicing)]

use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Paragraph};

use crate::tui::app::App;

/// Render the event timeline view
pub fn render(frame: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(1)])
        .split(area);

    let lines: Vec<Line> = app
        .timeline_events
        .iter()
        .rev()
        .map(|e| {
            let time = e.timestamp.format("%H:%M:%S").to_string();
            let type_style = match e.event_type.as_str() {
                "finding" => Style::default().fg(Color::Red),
                "milestone" => Style::default().fg(Color::Yellow),
                "completed" => Style::default().fg(Color::Green),
                "failed" => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                "cancelled" => Style::default().fg(Color::DarkGray),
                "spawned" => Style::default().fg(Color::Cyan),
                _ => Style::default(),
            };

            Line::from(vec![
                Span::styled(format!("{} ", time), Style::default().fg(Color::DarkGray)),
                Span::styled(format!("[{}] ", e.event_type), type_style),
                Span::styled(format!("{}: ", e.agent), Style::default().fg(Color::Cyan)),
                Span::raw(e.message.clone()),
            ])
        })
        .collect();

    let paragraph = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Event Timeline "),
        )
        .scroll((app.timeline_scroll as u16, 0));

    frame.render_widget(paragraph, chunks[0]);

    let footer = Paragraph::new(Line::from(vec![
        Span::styled(" h", Style::default().fg(Color::Yellow)),
        Span::raw(":dashboard "),
        Span::styled("j/k", Style::default().fg(Color::Yellow)),
        Span::raw(":scroll "),
        Span::styled("q", Style::default().fg(Color::Yellow)),
        Span::raw(":quit"),
    ]));
    frame.render_widget(footer, chunks[1]);
}
