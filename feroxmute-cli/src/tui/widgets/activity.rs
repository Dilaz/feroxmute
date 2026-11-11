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
    // window upward (toward older entries). Count wrapped rows (not logical
    // lines) so long messages don't push the newest events offscreen.
    let inner_width = area.width.saturating_sub(2);
    let inner_height = area.height.saturating_sub(2) as usize;
    let total = Paragraph::new(lines.clone())
        .wrap(Wrap { trim: false })
        .line_count(inner_width);
    let max_scroll = total.saturating_sub(inner_height);
    let offset = max_scroll.saturating_sub(app.activity_scroll);

    let para = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .scroll((offset as u16, 0))
        .block(theme.block("Activity", focused));
    frame.render_widget(para, area);
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::tui::app::FeedEntry;
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
    fn newest_entry_visible_despite_wrapping() {
        let mut app = App::new("t", "s", None);
        // Each message is long enough to wrap across the narrow pane.
        for i in 0..30 {
            app.add_feed(FeedEntry::new(
                "agent",
                format!("MSG{i:02} this is a deliberately long activity line that wraps"),
            ));
        }
        let backend = TestBackend::new(40, 8);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render(f, &app, f.area(), true)).unwrap();
        let text = buffer_text(&terminal);
        // Default scroll keeps the newest entry anchored at the bottom.
        assert!(text.contains("MSG29"), "newest entry must stay visible");
        assert!(
            !text.contains("MSG00"),
            "oldest entry should be scrolled off"
        );
    }
}
