//! Footer widget: metrics, severity summary, and context key hints on one line.

#![allow(clippy::indexing_slicing)]

use feroxmute_core::state::models::Severity;
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::Style,
    text::{Line, Span},
    widgets::Paragraph,
};

use crate::tui::app::App;

/// Render the footer line.
pub fn render(frame: &mut Frame, app: &App, area: Rect) {
    let theme = &app.theme;
    let g = &theme.glyphs;

    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(40),
            Constraint::Length(24),
            Constraint::Min(10),
        ])
        .split(area);

    // Left: metrics.
    let metrics = Line::from(vec![
        Span::styled(
            format!(
                "{} {}",
                g.metric_in,
                format_number(app.metrics.input_tokens)
            ),
            Style::default().fg(theme.muted),
        ),
        Span::raw("  "),
        Span::styled(
            format!(
                "{} {}",
                g.metric_out,
                format_number(app.metrics.output_tokens)
            ),
            Style::default().fg(theme.muted),
        ),
        Span::raw("  "),
        Span::styled(
            format_cost(app.metrics.estimated_cost_usd),
            Style::default().fg(theme.text),
        ),
        Span::raw("  "),
        Span::styled(
            format!("tools {}", app.metrics.tool_calls),
            Style::default().fg(theme.muted),
        ),
    ]);
    frame.render_widget(Paragraph::new(metrics), chunks[0]);

    // Middle: severity summary.
    let counts = app.severity_counts();
    let sevs = [
        ("C", Severity::Critical, counts[0]),
        ("H", Severity::High, counts[1]),
        ("M", Severity::Medium, counts[2]),
        ("L", Severity::Low, counts[3]),
        ("I", Severity::Info, counts[4]),
    ];
    let mut sev_spans = Vec::new();
    for (label, sev, count) in sevs {
        sev_spans.push(Span::styled(
            format!("{label}:{count}"),
            Style::default().fg(theme.severity_color(sev)),
        ));
        sev_spans.push(Span::raw(" "));
    }
    frame.render_widget(
        Paragraph::new(Line::from(sev_spans)).alignment(Alignment::Center),
        chunks[1],
    );

    // Right: key hints, sized to the richest tier that fits the pane.
    let hints = footer_hints(theme.caps.unicode, chunks[2].width);
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            hints,
            Style::default().fg(theme.muted),
        )))
        .alignment(Alignment::Right),
        chunks[2],
    );
}

/// Pick the richest key-hint tier whose rendered width fits `width` columns.
fn footer_hints(unicode: bool, width: u16) -> &'static str {
    let tiers: [&'static str; 5] = if unicode {
        [
            "tab focus · jk move · PgUp/Dn · 1-9 agent · ⏎ detail · p mem · l logs · i steer · m mouse · ? help · q quit",
            "tab focus · jk move · 1-9 agent · ⏎ detail · p mem · l logs · i steer · ? help · q quit",
            "jk move · ⏎ detail · p/l panes · ? help · q quit",
            "⏎ detail · ? help · q quit",
            "? help · q quit",
        ]
    } else {
        [
            "tab focus | jk move | pgup/dn | 1-9 agent | enter detail | p mem | l logs | i steer | m mouse | ? help | q quit",
            "tab focus | jk move | 1-9 agent | enter detail | p mem | l logs | i steer | ? help | q quit",
            "jk move | enter detail | p/l panes | ? help | q quit",
            "enter detail | ? help | q quit",
            "? help | q quit",
        ]
    };
    let w = width as usize;
    tiers
        .iter()
        .copied()
        .find(|t| t.chars().count() <= w)
        .unwrap_or(tiers[tiers.len() - 1])
}

/// Format large numbers with K/M suffixes.
pub fn format_number(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.1}K", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}

/// Format cost with appropriate precision.
pub fn format_cost(cost: f64) -> String {
    if cost < 0.01 {
        format!("${cost:.4}")
    } else {
        format!("${cost:.2}")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::tui::app::App;
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
    fn footer_hints_never_overflow_their_pane() {
        // A wide pane shows the richest tier: agent-jump plus detail keys.
        let wide = footer_hints(true, 200);
        assert!(wide.contains("1-9"), "wide hints should list agent jumps");
        assert!(wide.contains("detail"), "wide hints should list detail key");

        // Whatever tier is chosen must fit the requested width (no clipping),
        // except below the smallest tier where nothing can fit.
        for w in [30u16, 56, 80, 100, 160] {
            for unicode in [true, false] {
                let h = footer_hints(unicode, w);
                assert!(
                    h.chars().count() <= w as usize,
                    "tier {h:?} overflows width {w}"
                );
            }
        }

        // Even a narrow pane keeps the essential quit hint.
        assert!(footer_hints(true, 20).contains("quit"));
        assert!(footer_hints(false, 20).contains("quit"));
    }

    #[test]
    fn footer_renders_keys_at_normal_width() {
        let app = App::new("t", "s", None);
        let backend = TestBackend::new(120, 1);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render(f, &app, f.area())).unwrap();
        let text = buffer_text(&terminal);
        assert!(
            text.contains("detail"),
            "footer must render the detail hint at 120 cols: {text:?}"
        );
        assert!(
            text.contains("quit"),
            "footer must render the quit hint at 120 cols"
        );
    }
}
