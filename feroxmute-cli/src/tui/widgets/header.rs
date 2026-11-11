//! Header widget: target/session/elapsed plus an engagement phase progress bar.

use feroxmute_core::agents::EngagementPhase;
use ratatui::{
    Frame,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
};

use crate::tui::app::App;

const PHASE_COUNT: usize = 8;

/// Index of a phase within the ordered engagement workflow.
fn phase_index(phase: EngagementPhase) -> usize {
    match phase {
        EngagementPhase::Setup => 0,
        EngagementPhase::StaticAnalysis => 1,
        EngagementPhase::Reconnaissance => 2,
        EngagementPhase::Scanning => 3,
        EngagementPhase::LlmPentest => 4,
        EngagementPhase::Exploitation => 5,
        EngagementPhase::Reporting => 6,
        EngagementPhase::Complete => 7,
    }
}

/// Render the header block.
pub fn render(frame: &mut Frame, app: &App, area: Rect) {
    let theme = &app.theme;
    let current = phase_index(app.phase);

    let mut spans = vec![
        Span::styled(
            &app.target,
            Style::default()
                .fg(theme.accent)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("  ", Style::default()),
        Span::styled(&app.session_id, Style::default().fg(theme.muted)),
        Span::styled("  ", Style::default()),
        Span::styled(app.elapsed_display(), Style::default().fg(theme.text)),
        Span::styled("   ", Style::default()),
    ];

    // Phase progress bar.
    for i in 0..PHASE_COUNT {
        let (glyph, style) = if i < current {
            (
                theme.glyphs.bar_full,
                Style::default().fg(theme.status_done),
            )
        } else if i == current {
            (
                theme.glyphs.bar_full,
                Style::default()
                    .fg(theme.accent)
                    .add_modifier(Modifier::BOLD),
            )
        } else {
            (theme.glyphs.bar_empty, Style::default().fg(theme.muted))
        };
        spans.push(Span::styled(glyph.to_string(), style));
    }

    spans.push(Span::styled(
        format!(" {:?} {}/{}", app.phase, current + 1, PHASE_COUNT),
        Style::default().fg(theme.accent),
    ));

    let header = Paragraph::new(Line::from(spans)).block(theme.block("feroxmute", false));
    frame.render_widget(header, area);
}
