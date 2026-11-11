//! Activity pane: the live event feed, wrapped, newest at the bottom.

#![allow(clippy::indexing_slicing)]

use ratatui::{
    Frame,
    layout::Rect,
    style::Style,
    text::{Line, Span},
    widgets::{Paragraph, Wrap},
};

use crate::tui::app::App;

/// Render the activity feed pane.
pub fn render(frame: &mut Frame, app: &App, area: Rect, focused: bool) {
    let theme = &app.theme;

    let lines: Vec<Line> = app
        .feed
        .iter()
        .map(|entry| {
            let time = entry.timestamp.format("%H:%M:%S").to_string();
            let msg_style = if entry.is_error {
                Style::default().fg(theme.sev_critical)
            } else {
                Style::default().fg(theme.text)
            };
            Line::from(vec![
                Span::styled(format!("{time} "), Style::default().fg(theme.muted)),
                Span::styled(
                    format!("[{}] ", entry.agent),
                    Style::default().fg(theme.accent),
                ),
                Span::styled(entry.message.clone(), msg_style),
            ])
        })
        .collect();

    // Scroll so the newest content sits at the bottom; activity_scroll moves the
    // window upward (toward older entries).
    let inner_height = area.height.saturating_sub(2) as usize;
    let total = lines.len();
    let max_scroll = total.saturating_sub(inner_height);
    let offset = max_scroll.saturating_sub(app.activity_scroll);

    let para = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .scroll((offset as u16, 0))
        .block(theme.block("Activity", focused));
    frame.render_widget(para, area);
}
