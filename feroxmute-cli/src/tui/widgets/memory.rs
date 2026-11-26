//! Memory browser overlay (list view).

#![allow(clippy::indexing_slicing)]

use ratatui::{
    Frame,
    layout::{Constraint, Rect},
    style::{Modifier, Style},
    text::Line,
    widgets::{Cell, Paragraph, Row, Table, TableState},
};

use crate::tui::app::App;

use super::overlay::{centered_rect, frame_block};

/// Render the memory list overlay inside `area` (the frame area).
pub fn render(frame: &mut Frame, app: &App, area: Rect) {
    let theme = &app.theme;
    let rect = centered_rect(80, 80, area);
    let title = format!("Memory ({} entries)", app.memory_entries.len());
    let inner = frame_block(frame, rect, &title, theme);

    if app.memory_entries.is_empty() {
        let empty = Paragraph::new(Line::from("No memory entries yet"))
            .style(Style::default().fg(theme.muted));
        frame.render_widget(empty, inner);
        return;
    }

    let header = Row::new(vec!["Key", "Value", "Updated"]).style(
        Style::default()
            .fg(theme.accent)
            .add_modifier(Modifier::BOLD),
    );

    let key_width = (inner.width as f32 * 0.3) as u16;
    let updated_width = 10u16;
    let value_width = inner
        .width
        .saturating_sub(key_width + updated_width + 4)
        .max(5);

    let rows: Vec<Row> = app
        .memory_entries
        .iter()
        .enumerate()
        .map(|(i, entry)| {
            let is_selected = i == app.selected_memory;
            let row_style = if is_selected {
                Style::default().add_modifier(Modifier::REVERSED)
            } else {
                Style::default()
            };

            let key_display = truncate_str(&entry.key, (key_width as usize).saturating_sub(2));
            let key_cell = if is_selected {
                format!("▶ {key_display}")
            } else {
                format!("  {key_display}")
            };

            let value_preview = entry.value.replace('\n', " ");
            let value_display =
                truncate_str(&value_preview, (value_width as usize).saturating_sub(1));

            let time_display = entry
                .updated_at
                .split(' ')
                .nth(1)
                .unwrap_or(&entry.updated_at)
                .chars()
                .take(8)
                .collect::<String>();

            Row::new(vec![
                Cell::from(key_cell).style(Style::default().fg(theme.text)),
                Cell::from(value_display).style(Style::default().fg(theme.muted)),
                Cell::from(time_display).style(Style::default().fg(theme.muted)),
            ])
            .style(row_style)
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(key_width),
            Constraint::Min(value_width),
            Constraint::Length(updated_width),
        ],
    )
    .header(header);

    // Stateful render keeps the selected entry scrolled into view.
    let mut state = TableState::default();
    let selected = app
        .selected_memory
        .min(app.memory_entries.len().saturating_sub(1));
    state.select(Some(selected));
    frame.render_stateful_widget(table, inner, &mut state);
}

/// Truncate string to max length with ellipsis.
fn truncate_str(s: &str, max_len: usize) -> String {
    if s.chars().count() <= max_len {
        s.to_string()
    } else {
        let truncated: String = s.chars().take(max_len.saturating_sub(1)).collect();
        format!("{truncated}…")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::tui::app::App;
    use crate::tui::channel::MemoryEntry;
    use ratatui::{Terminal, backend::TestBackend};

    fn buffer_text(terminal: &Terminal<TestBackend>) -> String {
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|c| c.symbol())
            .collect()
    }

    #[test]
    fn selected_memory_scrolls_into_view() {
        let mut app = App::new("t", "s", None);
        app.memory_entries = (0..25)
            .map(|i| MemoryEntry {
                key: format!("memkey{i:02}"),
                value: format!("value {i}"),
                created_at: String::new(),
                updated_at: String::new(),
            })
            .collect();
        // Select the last entry, which sits below the visible overlay height.
        app.selected_memory = app.memory_entries.len() - 1;

        let backend = TestBackend::new(60, 10);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render(f, &app, f.area())).unwrap();
        let text = buffer_text(&terminal);
        assert!(
            text.contains("memkey24"),
            "selection beyond overlay height must scroll into view"
        );
    }
}
