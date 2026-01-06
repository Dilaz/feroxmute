//! Memory list widget

use ratatui::{
    Frame,
    layout::{Constraint, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
};

use crate::tui::app::App;

/// Render the memory list view
pub fn render(frame: &mut Frame, app: &App, area: Rect) {
    if app.memory_entries.is_empty() {
        render_empty(frame, area);
        return;
    }

    let header = Row::new(vec!["Key", "Value", "Updated"]).style(
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    );

    // Calculate column widths
    let key_width = (area.width as f32 * 0.3) as u16;
    let updated_width = 10;
    let value_width = area
        .width
        .saturating_sub(key_width + updated_width + 6)
        .max(5); // 6 for borders/spacing, min 5

    let rows: Vec<Row> = app
        .memory_entries
        .iter()
        .enumerate()
        .map(|(i, entry)| {
            let is_selected = i == app.selected_memory;
            let style = if is_selected {
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };

            // Truncate key
            let key_display = truncate_str(&entry.key, key_width as usize - 2);
            let key_cell = if is_selected {
                format!("▶ {}", key_display)
            } else {
                format!("  {}", key_display)
            };

            // Truncate value preview
            let value_preview = entry.value.replace('\n', " ");
            let value_display = truncate_str(&value_preview, value_width as usize - 1);

            // Format time (just HH:MM:SS from datetime string)
            let time_display = entry
                .updated_at
                .split(' ')
                .nth(1)
                .unwrap_or(&entry.updated_at)
                .chars()
                .take(8)
                .collect::<String>();

            Row::new(vec![
                Cell::from(key_cell),
                Cell::from(value_display).style(Style::default().fg(Color::DarkGray)),
                Cell::from(time_display).style(Style::default().fg(Color::DarkGray)),
            ])
            .style(style)
        })
        .collect();

    let title = format!(" Memory ({} entries) ", app.memory_entries.len());
    let table = Table::new(
        rows,
        [
            Constraint::Length(key_width),
            Constraint::Min(value_width),
            Constraint::Length(updated_width),
        ],
    )
    .header(header)
    .block(Block::default().borders(Borders::ALL).title(title));

    frame.render_widget(table, area);

    // Render footer
    render_footer(frame, area);
}

/// Render empty state
fn render_empty(frame: &mut Frame, area: Rect) {
    let text = Paragraph::new("No memory entries yet")
        .style(Style::default().fg(Color::DarkGray))
        .block(Block::default().borders(Borders::ALL).title(" Memory "));
    frame.render_widget(text, area);
}

/// Render footer with keybindings
fn render_footer(frame: &mut Frame, area: Rect) {
    let footer_area = Rect {
        x: area.x,
        y: area.y + area.height.saturating_sub(1),
        width: area.width,
        height: 1,
    };

    let help = Line::from(vec![
        Span::styled("↑/↓", Style::default().fg(Color::Yellow)),
        Span::raw(" navigate  "),
        Span::styled("Enter", Style::default().fg(Color::Yellow)),
        Span::raw(" view  "),
        Span::styled("h", Style::default().fg(Color::Yellow)),
        Span::raw(" back  "),
        Span::styled("q", Style::default().fg(Color::Yellow)),
        Span::raw(" quit"),
    ]);

    let footer = Paragraph::new(help).style(Style::default().fg(Color::DarkGray));
    frame.render_widget(footer, footer_area);
}

/// Truncate string to max length with ellipsis
fn truncate_str(s: &str, max_len: usize) -> String {
    if s.chars().count() <= max_len {
        s.to_string()
    } else {
        let truncated: String = s.chars().take(max_len.saturating_sub(3)).collect();
        format!("{}...", truncated)
    }
}
