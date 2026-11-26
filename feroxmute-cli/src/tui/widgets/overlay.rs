//! Overlay helpers and the Logs / Help overlay renderers.
//!
//! Overlays are centered rectangles drawn on top of the command center. Each
//! clears its region and draws a focused themed block.

#![allow(clippy::indexing_slicing)]

use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::Style,
    text::{Line, Span},
    widgets::{Clear, List, ListItem, Paragraph},
};

use crate::tui::app::App;
use crate::tui::theme::Theme;

/// Compute a centered rectangle covering `pct_x`% × `pct_y`% of `area`.
pub fn centered_rect(pct_x: u16, pct_y: u16, area: Rect) -> Rect {
    let vertical = Layout::vertical([
        Constraint::Percentage((100 - pct_y) / 2),
        Constraint::Percentage(pct_y),
        Constraint::Percentage((100 - pct_y) / 2),
    ])
    .split(area);
    Layout::horizontal([
        Constraint::Percentage((100 - pct_x) / 2),
        Constraint::Percentage(pct_x),
        Constraint::Percentage((100 - pct_x) / 2),
    ])
    .split(vertical[1])[1]
}

/// Clear `area`, draw a focused themed block titled `title`, and return the
/// inner content rect.
pub fn frame_block(frame: &mut Frame, area: Rect, title: &str, theme: &Theme) -> Rect {
    frame.render_widget(Clear, area);
    let block = theme.block(title, true);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    inner
}

/// Render the full-screen Logs overlay.
pub fn render_logs(frame: &mut Frame, app: &App) {
    let theme = &app.theme;
    let area = centered_rect(85, 80, frame.area());
    let inner = frame_block(frame, area, "Logs", theme);

    let visible_height = inner.height as usize;
    let items: Vec<ListItem> = app
        .feed
        .iter()
        .rev()
        .skip(app.log_scroll)
        .take(visible_height)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .map(|entry| {
            let msg_style = if entry.is_error {
                Style::default().fg(theme.sev_critical)
            } else {
                Style::default().fg(theme.text)
            };
            let time = entry.timestamp.format("%H:%M:%S").to_string();
            ListItem::new(Line::from(vec![
                Span::styled(format!("{time} "), Style::default().fg(theme.muted)),
                Span::styled(
                    format!("[{}] ", entry.agent),
                    Style::default().fg(theme.accent),
                ),
                Span::styled(entry.message.clone(), msg_style),
            ]))
        })
        .collect();

    frame.render_widget(List::new(items), inner);
}

/// Render the Help overlay.
pub fn render_help(frame: &mut Frame, app: &App) {
    let theme = &app.theme;
    let area = centered_rect(60, 70, frame.area());
    let inner = frame_block(frame, area, "Help", theme);

    let key = |s: &'static str| Span::styled(s, Style::default().fg(theme.accent));
    let desc = |s: &'static str| Span::styled(s, Style::default().fg(theme.text));

    let lines = vec![
        Line::from(vec![key("Tab / Shift-Tab  "), desc("Cycle focused pane")]),
        Line::from(vec![
            key("↑ / k, ↓ / j     "),
            desc("Move selection / scroll"),
        ]),
        Line::from(vec![
            key("PageUp/PageDown  "),
            desc("Move 10 rows (command center)"),
        ]),
        Line::from(vec![
            key("Enter            "),
            desc("Open detail for focused pane"),
        ]),
        Line::from(vec![
            key("1-9              "),
            desc("Open agent detail (1=orchestrator)"),
        ]),
        Line::from(vec![key("p                "), desc("Memory browser")]),
        Line::from(vec![key("l                "), desc("Logs")]),
        Line::from(vec![key("m                "), desc("Toggle mouse support")]),
        Line::from(vec![
            key("i                "),
            desc("Steer the orchestrator"),
        ]),
        Line::from(vec![
            key("t                "),
            desc("Toggle thinking (agent detail)"),
        ]),
        Line::from(vec![
            key("o                "),
            desc("Toggle tool output (agent detail)"),
        ]),
        Line::from(vec![key("Esc              "), desc("Close overlay")]),
        Line::from(vec![
            key("? / Esc / key    "),
            desc("Close this help (q and Ctrl-C open quit-confirm instead)"),
        ]),
        Line::from(vec![
            key("q / Ctrl-C       "),
            desc("Open quit confirmation"),
        ]),
        Line::from(vec![
            key("y / Enter        "),
            desc("Confirm quit (at prompt)"),
        ]),
        Line::from(vec![
            key("n / Esc          "),
            desc("Cancel quit (at prompt)"),
        ]),
    ];

    frame.render_widget(Paragraph::new(lines), inner);
}
