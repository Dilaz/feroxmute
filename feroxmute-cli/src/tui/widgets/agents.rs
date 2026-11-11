//! Agents pane: a tree of the orchestrator and spawned agents with live status.

#![allow(clippy::indexing_slicing)]

use ratatui::{
    Frame,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{List, ListItem},
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
            let is_last = i == last_idx;
            let line = agent_line(app, name, info, i == 0, is_last, inner_width);
            let item = ListItem::new(line);
            if focused && i == selected {
                item.style(Style::default().add_modifier(Modifier::REVERSED))
            } else {
                item
            }
        })
        .collect();

    let block = theme.block("Agents", focused);
    frame.render_widget(List::new(items).block(block), area);
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
