//! Memory modal popup widget

#![allow(clippy::indexing_slicing)]

use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
    Frame,
};

use crate::tui::app::App;
use crate::tui::channel::MemoryEntry;

/// Render the memory detail modal
pub fn render(frame: &mut Frame, app: &App) {
    let entry = match app.selected_memory_entry() {
        Some(e) => e,
        None => return,
    };

    let area = frame.area();

    // Calculate modal size (80% of screen)
    let modal_width = (area.width as f32 * 0.8) as u16;
    let modal_height = (area.height as f32 * 0.8) as u16;
    let modal_x = (area.width - modal_width) / 2;
    let modal_y = (area.height - modal_height) / 2;

    let modal_area = Rect {
        x: modal_x,
        y: modal_y,
        width: modal_width,
        height: modal_height,
    };

    // Clear the modal area (creates overlay effect)
    frame.render_widget(Clear, modal_area);

    // Render modal content
    render_modal_content(frame, app, entry, modal_area);
}

fn render_modal_content(frame: &mut Frame, app: &App, entry: &MemoryEntry, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(3),    // Content
            Constraint::Length(3), // Timestamps
            Constraint::Length(1), // Footer
        ])
        .split(area);

    // Main content area
    let title = format!(" Memory: {} ", entry.key);
    let content_block = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .border_style(Style::default().fg(Color::Cyan));

    let inner_area = content_block.inner(chunks[0]);
    frame.render_widget(content_block, chunks[0]);

    // Content with word wrap and scroll
    let content_lines: Vec<Line> = entry
        .value
        .lines()
        .skip(app.memory_modal_scroll)
        .map(|line| Line::from(line.to_string()))
        .collect();

    let content = Paragraph::new(content_lines)
        .wrap(Wrap { trim: false })
        .style(Style::default().fg(Color::White));

    frame.render_widget(content, inner_area);

    // Timestamps
    let timestamps = Paragraph::new(vec![
        Line::from(vec![
            Span::styled("Created: ", Style::default().fg(Color::DarkGray)),
            Span::styled(&entry.created_at, Style::default().fg(Color::Gray)),
            Span::raw("  "),
            Span::styled("Updated: ", Style::default().fg(Color::DarkGray)),
            Span::styled(&entry.updated_at, Style::default().fg(Color::Gray)),
        ]),
    ])
    .block(Block::default().borders(Borders::TOP));

    frame.render_widget(timestamps, chunks[1]);

    // Footer
    let footer = Paragraph::new(Line::from(vec![
        Span::styled("Esc/Enter", Style::default().fg(Color::Yellow)),
        Span::raw(" close  "),
        Span::styled("Up/Down", Style::default().fg(Color::Yellow)),
        Span::raw(" scroll"),
    ]))
    .style(Style::default().fg(Color::DarkGray))
    .alignment(Alignment::Center);

    frame.render_widget(footer, chunks[2]);
}
