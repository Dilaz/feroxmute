//! Memory detail modal (opened from the memory list overlay).

#![allow(clippy::indexing_slicing)]

use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout},
    style::Style,
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
};

use crate::tui::app::App;
use crate::tui::channel::MemoryEntry;

use super::overlay::{centered_rect, frame_block};

/// Render the memory detail modal on top of the memory list.
pub fn render(frame: &mut Frame, app: &App) {
    let Some(entry) = app.selected_memory_entry() else {
        return;
    };
    let theme = &app.theme;

    let rect = centered_rect(80, 80, frame.area());
    let title = format!("Memory: {}", entry.key);
    let inner = frame_block(frame, rect, &title, theme);

    render_content(frame, app, entry, inner);
}

fn render_content(frame: &mut Frame, app: &App, entry: &MemoryEntry, area: ratatui::layout::Rect) {
    let theme = &app.theme;
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(3),
            Constraint::Length(2),
            Constraint::Length(1),
        ])
        .split(area);

    let content_lines: Vec<Line> = entry
        .value
        .lines()
        .skip(app.memory_modal_scroll)
        .map(|line| Line::from(line.to_string()))
        .collect();

    let content = Paragraph::new(content_lines)
        .wrap(Wrap { trim: false })
        .style(Style::default().fg(theme.text));
    frame.render_widget(content, chunks[0]);

    let timestamps = Paragraph::new(Line::from(vec![
        Span::styled("Created: ", Style::default().fg(theme.muted)),
        Span::styled(entry.created_at.clone(), Style::default().fg(theme.text)),
        Span::styled("  Updated: ", Style::default().fg(theme.muted)),
        Span::styled(entry.updated_at.clone(), Style::default().fg(theme.text)),
    ]))
    .block(
        Block::default()
            .borders(Borders::TOP)
            .border_style(Style::default().fg(theme.border)),
    );
    frame.render_widget(timestamps, chunks[1]);

    let footer = Paragraph::new(Line::from(Span::styled(
        "j/k scroll · Esc close",
        Style::default().fg(theme.muted),
    )))
    .alignment(Alignment::Center);
    frame.render_widget(footer, chunks[2]);
}
