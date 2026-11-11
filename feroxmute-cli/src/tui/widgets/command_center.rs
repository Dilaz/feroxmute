//! Unified command-center layout: header, heroes row (agents + findings),
//! activity feed, and footer. Always rendered; overlays draw on top.

#![allow(clippy::indexing_slicing)]

use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout},
};

use crate::tui::app::{App, Pane};

use super::{activity, agents, findings, footer, header};

/// Render the full command center into the frame area.
pub fn render(frame: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),      // Header
            Constraint::Min(8),         // Heroes row (agents + findings)
            Constraint::Percentage(35), // Activity feed
            Constraint::Length(1),      // Footer
        ])
        .split(frame.area());

    let heroes = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(chunks[1]);

    header::render(frame, app, chunks[0]);
    agents::render(frame, app, heroes[0], app.focus == Pane::Agents);
    findings::render(frame, app, heroes[1], app.focus == Pane::Findings);
    activity::render(frame, app, chunks[2], app.focus == Pane::Activity);
    footer::render(frame, app, chunks[3]);
}
