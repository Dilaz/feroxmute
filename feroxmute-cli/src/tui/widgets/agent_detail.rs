//! Agent detail overlay: status, SAST context (when applicable), feed output,
//! and optional thinking panel.

#![allow(clippy::indexing_slicing)]

use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::Style,
    text::{Line, Span},
    widgets::{Paragraph, Wrap},
};

use crate::tui::app::App;
use feroxmute_core::agents::AgentStatus;

use super::overlay::{centered_rect, frame_block};

/// Render the agent detail overlay inside `area` (the frame area).
pub fn render(frame: &mut Frame, app: &App, agent_name: &str, area: Rect) {
    let theme = &app.theme;
    let info = app.agents.get(agent_name);
    let agent_type = info.map(|a| a.agent_type.as_str()).unwrap_or("");
    let is_sast = agent_type == "sast";

    let title = if agent_type.is_empty() {
        agent_name.to_string()
    } else {
        format!("{agent_name} ({agent_type})")
    };

    let rect = centered_rect(88, 88, area);
    let inner = frame_block(frame, rect, &title, theme);

    let thinking = info.and_then(|a| a.thinking.as_ref());
    let show_thinking = app.show_thinking && thinking.is_some();

    let header_lines: u16 = if is_sast { 2 } else { 1 };
    let mut constraints = vec![Constraint::Length(header_lines), Constraint::Min(3)];
    if show_thinking {
        constraints.push(Constraint::Length(8));
    }
    constraints.push(Constraint::Length(1));

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(inner);

    render_header(frame, app, agent_name, is_sast, chunks[0]);
    render_output(frame, app, agent_name, chunks[1]);

    if show_thinking {
        render_thinking(frame, app, thinking, chunks[2]);
        render_footer(frame, app, chunks[3]);
    } else {
        render_footer(frame, app, chunks[2]);
    }
}

fn render_header(frame: &mut Frame, app: &App, agent_name: &str, is_sast: bool, area: Rect) {
    let theme = &app.theme;
    let (status, current_tool) = app
        .agents
        .get(agent_name)
        .map(|a| (a.status, a.current_tool.clone()))
        .unwrap_or((AgentStatus::Idle, None));

    let glyph = theme.status_glyph(status, app.tick);
    let mut status_text = format!("{glyph} {status:?}");
    if status == AgentStatus::Executing
        && let Some(tool) = &current_tool
    {
        status_text.push_str(&format!(" ({tool})"));
    }

    let mut lines = vec![Line::from(vec![
        Span::styled("Status: ", Style::default().fg(theme.muted)),
        Span::styled(status_text, theme.status_style(status)),
    ])];

    if is_sast {
        let source = app.source_path.as_deref().unwrap_or("-").to_string();
        let languages = if app.detected_languages.is_empty() {
            "-".to_string()
        } else {
            app.detected_languages.join(", ")
        };
        lines.push(Line::from(vec![
            Span::styled("Source: ", Style::default().fg(theme.muted)),
            Span::styled(source, Style::default().fg(theme.accent)),
            Span::styled("  Languages: ", Style::default().fg(theme.muted)),
            Span::styled(languages, Style::default().fg(theme.sev_medium)),
        ]));
    }

    frame.render_widget(Paragraph::new(lines), area);
}

fn render_output(frame: &mut Frame, app: &App, agent_name: &str, area: Rect) {
    let theme = &app.theme;
    let mut lines: Vec<Line> = Vec::new();

    for entry in app.get_agent_feed(agent_name) {
        let style = if entry.is_error {
            Style::default().fg(theme.sev_critical)
        } else {
            Style::default().fg(theme.text)
        };
        let time = entry.timestamp.format("%H:%M:%S").to_string();
        lines.push(Line::from(vec![
            Span::styled(time, Style::default().fg(theme.muted)),
            Span::raw(" "),
            Span::styled(entry.message.clone(), style),
        ]));

        if entry.expanded
            && let Some(output) = &entry.tool_output
        {
            for line in output.lines() {
                lines.push(Line::from(vec![
                    Span::raw("         "),
                    Span::styled("│ ", Style::default().fg(theme.muted)),
                    Span::styled(line.to_string(), style),
                ]));
            }
        }
    }

    let content = if lines.is_empty() {
        vec![Line::from(Span::styled(
            "No output yet…",
            Style::default().fg(theme.muted),
        ))]
    } else {
        lines
    };

    // Convert bottom-based scroll into top-based paragraph scroll.
    let content_height = content.len();
    let visible_height = area.height.saturating_sub(2) as usize;
    let max_scroll = content_height.saturating_sub(visible_height);
    let scroll_from_top = max_scroll.saturating_sub(app.log_scroll);

    let output = Paragraph::new(content)
        .wrap(Wrap { trim: false })
        .scroll((scroll_from_top as u16, 0))
        .block(theme.block("Output", false));
    frame.render_widget(output, area);
}

fn render_thinking(frame: &mut Frame, app: &App, thinking: Option<&String>, area: Rect) {
    let theme = &app.theme;
    let text = thinking
        .map(|s| s.as_str())
        .unwrap_or("No current thinking…");

    let widget = Paragraph::new(text)
        .style(Style::default().fg(theme.status_thinking))
        .wrap(Wrap { trim: true })
        .block(theme.block("Thinking", false));
    frame.render_widget(widget, area);
}

fn render_footer(frame: &mut Frame, app: &App, area: Rect) {
    let theme = &app.theme;
    let (thinking_label, thinking_style) = if app.show_thinking {
        ("on", Style::default().fg(theme.status_done))
    } else {
        ("off", Style::default().fg(theme.muted))
    };

    let key = |s: &'static str| Span::styled(s, Style::default().fg(theme.accent));
    let sep = Span::styled("  ", Style::default());
    let footer = Paragraph::new(Line::from(vec![
        key("j/k"),
        Span::styled(" scroll", Style::default().fg(theme.muted)),
        sep.clone(),
        key("o"),
        Span::styled(" output", Style::default().fg(theme.muted)),
        sep.clone(),
        key("t"),
        Span::styled(" thinking ", Style::default().fg(theme.muted)),
        Span::styled(thinking_label, thinking_style),
        sep.clone(),
        key("Esc"),
        Span::styled(" back", Style::default().fg(theme.muted)),
        sep,
        key("q"),
        Span::styled(" quit", Style::default().fg(theme.muted)),
    ]));
    frame.render_widget(footer, area);
}
