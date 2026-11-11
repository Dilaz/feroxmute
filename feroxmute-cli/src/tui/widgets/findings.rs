//! Findings pane: a unified severity-sorted list of network vulns and code
//! findings, plus a detail renderer for the overlay.

#![allow(clippy::indexing_slicing)]

use ratatui::{
    Frame,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{List, ListItem, Paragraph, Wrap},
};

use crate::tui::app::App;

/// Truncate a string to `max` chars with an ellipsis.
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else if max <= 1 {
        s.chars().take(max).collect()
    } else {
        let t: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{t}…")
    }
}

/// Render the findings pane.
pub fn render(frame: &mut Frame, app: &App, area: Rect, focused: bool) {
    let theme = &app.theme;
    let sorted = app.sorted_findings();
    let block = theme.block("Findings", focused);

    if sorted.is_empty() {
        let empty = Paragraph::new(Line::from(Span::styled(
            "No findings yet",
            Style::default().fg(theme.muted),
        )))
        .block(block);
        frame.render_widget(empty, area);
        return;
    }

    let selected = app.findings_selected.min(sorted.len().saturating_sub(1));
    let inner_width = area.width.saturating_sub(2) as usize;

    let items: Vec<ListItem> = sorted
        .iter()
        .enumerate()
        .map(|(i, f)| {
            let marker = theme.severity_marker(f.severity);
            let sev_color = theme.severity_color(f.severity);
            let sev_label = f.severity.as_str().to_uppercase();

            // Budget the title to the remaining width.
            let lead = marker.chars().count()
                + 1
                + sev_label.chars().count()
                + 1
                + f.source.tag().len()
                + 1;
            let title = truncate(&f.title, inner_width.saturating_sub(lead + 1));

            let line = Line::from(vec![
                Span::styled(marker, Style::default().fg(sev_color)),
                Span::raw(" "),
                Span::styled(sev_label, Style::default().fg(sev_color)),
                Span::raw(" "),
                Span::styled(f.source.tag(), Style::default().fg(theme.muted)),
                Span::raw(" "),
                Span::styled(title, Style::default().fg(theme.text)),
            ]);

            let item = ListItem::new(line);
            if focused && i == selected {
                item.style(Style::default().add_modifier(Modifier::REVERSED))
            } else {
                item
            }
        })
        .collect();

    frame.render_widget(List::new(items).block(block), area);
}

/// Render the detail body for the finding at `idx` into `area`.
pub fn render_detail(frame: &mut Frame, app: &App, idx: usize, area: Rect) {
    let theme = &app.theme;
    let sorted = app.sorted_findings();
    let Some(f) = sorted.get(idx) else {
        let msg = Paragraph::new(Line::from(Span::styled(
            "Finding not found",
            Style::default().fg(theme.muted),
        )));
        frame.render_widget(msg, area);
        return;
    };

    let sev_color = theme.severity_color(f.severity);
    let mut lines = vec![
        Line::from(vec![
            Span::styled(
                format!("{} ", theme.severity_marker(f.severity)),
                Style::default().fg(sev_color),
            ),
            Span::styled(
                f.severity.as_str().to_uppercase(),
                Style::default().fg(sev_color).add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            Span::styled(f.source.tag(), Style::default().fg(theme.muted)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Agent:    ", Style::default().fg(theme.muted)),
            Span::styled(f.agent.clone(), Style::default().fg(theme.text)),
        ]),
    ];
    if let Some(loc) = &f.location {
        lines.push(Line::from(vec![
            Span::styled("Location: ", Style::default().fg(theme.muted)),
            Span::styled(loc.clone(), Style::default().fg(theme.text)),
        ]));
    }
    lines.push(Line::from(vec![
        Span::styled("Time:     ", Style::default().fg(theme.muted)),
        Span::styled(
            f.timestamp.format("%Y-%m-%d %H:%M:%S").to_string(),
            Style::default().fg(theme.text),
        ),
    ]));
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        f.title.clone(),
        Style::default().fg(theme.text),
    )));

    let para = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .scroll((app.log_scroll as u16, 0));
    frame.render_widget(para, area);
}
