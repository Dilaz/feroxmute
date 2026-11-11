//! Agents pane: a tree of the orchestrator and spawned agents with live status.

#![allow(clippy::indexing_slicing)]

use ratatui::{
    Frame,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{List, ListItem, ListState},
};

use crate::tui::app::{AgentDisplayInfo, App};

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

/// Render the agents pane.
pub fn render(frame: &mut Frame, app: &App, area: Rect, focused: bool) {
    let theme = &app.theme;
    let ordered = app.ordered_agents();
    let selected = app.agents_selected.min(ordered.len().saturating_sub(1));
    let inner_width = area.width.saturating_sub(2) as usize;
    let last_idx = ordered.len().saturating_sub(1);

    let items: Vec<ListItem> = ordered
        .iter()
        .enumerate()
        .map(|(i, (name, info))| {
            let line = agent_line(app, name, info, i == 0, i == last_idx, inner_width);
            ListItem::new(line)
        })
        .collect();

    let mut list = List::new(items).block(theme.block("Agents", focused));
    if focused {
        list = list.highlight_style(Style::default().add_modifier(Modifier::REVERSED));
    }

    // Stateful render keeps the selected row scrolled into view.
    let mut state = ListState::default();
    state.select(Some(selected));
    frame.render_stateful_widget(list, area, &mut state);
}

/// Build the display line for a single agent.
fn agent_line(
    app: &App,
    name: &str,
    info: &AgentDisplayInfo,
    is_root: bool,
    is_last: bool,
    inner_width: usize,
) -> Line<'static> {
    let theme = &app.theme;
    let g = &theme.glyphs;

    // Tree prefix.
    let prefix = if is_root {
        g.tree_root.to_string()
    } else if is_last {
        g.tree_last.to_string()
    } else {
        g.tree_branch.to_string()
    };

    // Name + key number.
    let label = if is_root {
        format!("[1] {name}")
    } else {
        format!("[{}] {}", info.spawn_order + 1, name)
    };

    // Status glyph.
    let glyph = theme.status_glyph(info.status, app.tick);
    let status_style = theme.status_style(info.status);

    // Trailing detail: agent_type, current tool, or activity.
    let mut detail = String::new();
    if !info.agent_type.is_empty() && !is_root {
        detail.push_str(&info.agent_type);
    }
    if let Some(tool) = &info.current_tool {
        if !detail.is_empty() {
            detail.push(' ');
        }
        detail.push_str(&format!("→{tool}"));
    }
    if detail.is_empty() && !info.activity.is_empty() {
        detail = info.activity.clone();
    }

    // Budget the detail to remaining width.
    let used = prefix.chars().count() + label.chars().count() + 2 + glyph.chars().count() + 1;
    let detail_budget = inner_width.saturating_sub(used);
    let detail = truncate(&detail, detail_budget);

    let mut spans = vec![
        Span::styled(prefix, Style::default().fg(theme.muted)),
        Span::styled(label, Style::default().fg(theme.text)),
        Span::raw(" "),
        Span::styled(glyph, status_style),
    ];
    if !detail.is_empty() {
        spans.push(Span::raw(" "));
        spans.push(Span::styled(detail, Style::default().fg(theme.muted)));
    }

    Line::from(spans)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use feroxmute_core::agents::AgentStatus;
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
    fn selected_agent_scrolls_into_view() {
        let mut app = App::new("t", "s", None);
        for i in 0..20 {
            app.update_spawned_agent_status(
                &format!("agent-{i:02}"),
                "recon",
                AgentStatus::Idle,
                None,
            );
        }
        // Select the last agent, which sits below the visible pane height.
        app.agents_selected = app.agents.len() - 1;
        let backend = TestBackend::new(50, 6);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render(f, &app, f.area(), true)).unwrap();
        let text = buffer_text(&terminal);
        assert!(
            text.contains("agent-19"),
            "selection beyond pane height must scroll into view"
        );
    }
}
