//! Dashboard widget for the main TUI view

#![allow(clippy::indexing_slicing)]

use feroxmute_core::agents::AgentStatus;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, List, ListItem, Paragraph, Row, Table},
    Frame,
};

use crate::tui::app::App;

/// Render the dashboard view
pub fn render(frame: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Length(5), // Metrics
            Constraint::Min(5),    // Agent status table (dynamic height)
            Constraint::Min(5),    // Feed
            Constraint::Length(1), // Footer
        ])
        .split(frame.area());

    render_header(frame, app, chunks[0]);
    render_metrics(frame, app, chunks[1]);
    render_agents(frame, app, chunks[2]);
    render_feed(frame, app, chunks[3]);
    render_footer(frame, app, chunks[4]);
}

/// Render the header with target info
fn render_header(frame: &mut Frame, app: &App, area: Rect) {
    let header_text = vec![Line::from(vec![
        Span::styled("Target: ", Style::default().fg(Color::Gray)),
        Span::styled(
            &app.target,
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  |  "),
        Span::styled("Session: ", Style::default().fg(Color::Gray)),
        Span::styled(&app.session_id, Style::default().fg(Color::Yellow)),
        Span::raw("  |  "),
        Span::styled("Phase: ", Style::default().fg(Color::Gray)),
        Span::styled(format!("{:?}", app.phase), phase_color(app.phase)),
        Span::raw("  |  "),
        Span::styled("Elapsed: ", Style::default().fg(Color::Gray)),
        Span::styled(app.elapsed_display(), Style::default().fg(Color::White)),
    ])];

    let header = Paragraph::new(header_text)
        .block(Block::default().borders(Borders::ALL).title(" feroxmute "));

    frame.render_widget(header, area);
}

/// Render metrics panel
fn render_metrics(frame: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Ratio(1, 3),
            Constraint::Ratio(1, 3),
            Constraint::Ratio(1, 3),
        ])
        .split(area);

    // Token metrics with cost
    let tokens = format!(
        "In: {} | Out: {} | Cache: {} | Cost: {}",
        format_number(app.metrics.input_tokens),
        format_number(app.metrics.output_tokens),
        format_number(app.metrics.cache_read_tokens),
        format_cost(app.metrics.estimated_cost_usd)
    );
    let token_block =
        Paragraph::new(tokens).block(Block::default().borders(Borders::ALL).title(" Tokens "));
    frame.render_widget(token_block, chunks[0]);

    // Tool calls
    let tools = format!("Tool Calls: {}", app.metrics.tool_calls);
    let tools_block =
        Paragraph::new(tools).block(Block::default().borders(Borders::ALL).title(" Activity "));
    frame.render_widget(tools_block, chunks[1]);

    // Vulnerabilities
    let vulns = format!(
        "C:{} H:{} M:{} L:{} I:{}",
        app.vuln_counts.critical,
        app.vuln_counts.high,
        app.vuln_counts.medium,
        app.vuln_counts.low,
        app.vuln_counts.info
    );
    let vuln_style = if app.vuln_counts.critical > 0 {
        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
    } else if app.vuln_counts.high > 0 {
        Style::default().fg(Color::LightRed)
    } else {
        Style::default()
    };
    let vuln_block = Paragraph::new(vulns).style(vuln_style).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Vulnerabilities "),
    );
    frame.render_widget(vuln_block, chunks[2]);
}

/// Render agent status table
fn render_agents(frame: &mut Frame, app: &App, area: Rect) {
    let header = Row::new(vec!["Agent", "Status", "Activity"]).style(
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    );

    // Always show orchestrator first
    let orch_info = app.agents.get("orchestrator");
    let mut rows = vec![agent_row_with_activity(
        "orchestrator",
        "Orchestrator",
        app.agent_statuses.orchestrator,
        orch_info.map(|a| a.activity.as_str()).unwrap_or("-"),
        orch_info.and_then(|a| a.current_tool.as_deref()),
    )];

    // Add dynamically spawned agents
    for (name, info) in &app.agents {
        if name != "orchestrator" {
            rows.push(agent_row_with_activity(
                name,
                name,
                info.status,
                &info.activity,
                info.current_tool.as_deref(),
            ));
        }
    }

    let table = Table::new(
        rows,
        [
            Constraint::Length(20),
            Constraint::Length(12),
            Constraint::Min(20),
        ],
    )
    .header(header)
    .block(Block::default().borders(Borders::ALL).title(" Agents "));

    frame.render_widget(table, area);
}

/// Create a row for an agent with activity
fn agent_row_with_activity(
    _key: &str,
    name: &str,
    status: AgentStatus,
    activity: &str,
    current_tool: Option<&str>,
) -> Row<'static> {
    let (status_text, status_style): (String, Style) = match status {
        AgentStatus::Idle => ("Idle".to_string(), Style::default().fg(Color::Gray)),
        AgentStatus::Thinking => (
            "Thinking".to_string(),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        AgentStatus::Streaming => (
            "Streaming".to_string(),
            Style::default()
                .fg(Color::Blue)
                .add_modifier(Modifier::BOLD),
        ),
        AgentStatus::Executing => {
            let tool_display = current_tool
                .map(|t| {
                    if t.len() > 20 {
                        format!("Tool: {}...", &t[..17])
                    } else {
                        format!("Tool: {}", t)
                    }
                })
                .unwrap_or_else(|| "Executing".to_string());
            (
                tool_display,
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )
        }
        AgentStatus::Processing => (
            "Processing".to_string(),
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        ),
        AgentStatus::Waiting => ("Waiting".to_string(), Style::default().fg(Color::Yellow)),
        AgentStatus::Retrying => (
            "Retrying".to_string(),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::SLOW_BLINK),
        ),
        AgentStatus::Completed => ("Done".to_string(), Style::default().fg(Color::Green)),
        AgentStatus::Failed => (
            "Failed".to_string(),
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ),
    };

    // Truncate activity to fit
    let activity_display = if activity.len() > 40 {
        format!("{}...", &activity[..37])
    } else {
        activity.to_string()
    };

    Row::new(vec![
        Cell::from(name.to_string()),
        Cell::from(status_text).style(status_style),
        Cell::from(activity_display).style(Style::default().fg(Color::DarkGray)),
    ])
}

/// Render activity feed with timestamps (newest at bottom)
fn render_feed(frame: &mut Frame, app: &App, area: Rect) {
    let visible_height = area.height.saturating_sub(2) as usize;
    let inner_width = area.width.saturating_sub(2) as usize;
    let scroll_x = app.feed_scroll_x as usize;

    // Take last N entries (newest at bottom)
    let items: Vec<ListItem> = app
        .feed
        .iter()
        .rev()
        .take(visible_height)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .map(|entry| {
            let style = if entry.is_error {
                Style::default().fg(Color::Red)
            } else {
                Style::default()
            };

            let time_str = entry.timestamp.format("%H:%M:%S").to_string();
            let prefix = format!("{} [{}] ", time_str, entry.agent);
            let full_text = format!("{}{}", prefix, entry.message);

            // Apply horizontal scroll
            let full_text_len = full_text.chars().count();
            let display_text: String = if scroll_x < full_text_len {
                let take_count = inner_width.min(full_text_len - scroll_x);
                full_text.chars().skip(scroll_x).take(take_count).collect()
            } else {
                String::new()
            };

            // Color the timestamp and agent prefix
            let time_len: usize = 8; // "HH:MM:SS"
            let prefix_char_len = prefix.chars().count();

            if scroll_x < prefix_char_len {
                let visible_prefix_len = prefix_char_len.saturating_sub(scroll_x);
                let display_char_count = display_text.chars().count();
                let visible_prefix: String = display_text
                    .chars()
                    .take(visible_prefix_len.min(display_char_count))
                    .collect();
                let visible_message: String = if display_char_count > visible_prefix_len {
                    display_text.chars().skip(visible_prefix_len).collect()
                } else {
                    String::new()
                };

                // Split prefix into time and agent parts for coloring
                let time_part: String = visible_prefix
                    .chars()
                    .take(time_len.saturating_sub(scroll_x))
                    .collect();
                let agent_part: String = visible_prefix
                    .chars()
                    .skip(time_len.saturating_sub(scroll_x))
                    .collect();

                let line = Line::from(vec![
                    Span::styled(time_part, Style::default().fg(Color::DarkGray)),
                    Span::styled(agent_part, Style::default().fg(Color::Cyan)),
                    Span::styled(visible_message, style),
                ]);
                ListItem::new(line)
            } else {
                ListItem::new(Line::from(Span::styled(display_text, style)))
            }
        })
        .collect();

    // Check if content extends beyond visible area
    let has_more_right = app.feed.iter().any(|e| {
        let full_len = format!(
            "{} [{}] {}",
            e.timestamp.format("%H:%M:%S"),
            e.agent,
            e.message
        )
        .chars()
        .count();
        scroll_x + inner_width < full_len
    });
    let has_more_left = scroll_x > 0;

    let title = match (has_more_left, has_more_right) {
        (true, true) => " <- Activity Feed -> ",
        (true, false) => " <- Activity Feed ",
        (false, true) => " Activity Feed -> ",
        (false, false) => " Activity Feed ",
    };

    let feed = List::new(items).block(Block::default().borders(Borders::ALL).title(title));

    frame.render_widget(feed, area);
}

/// Render footer with keybindings
fn render_footer(frame: &mut Frame, app: &App, area: Rect) {
    let spawned_count = app.agents.len().saturating_sub(1);
    let max_key = (spawned_count + 1).min(9);
    let agents_hint = if max_key > 1 {
        format!("1-{}", max_key)
    } else {
        "1".to_string()
    };

    let help = Line::from(vec![
        Span::styled("q", Style::default().fg(Color::Yellow)),
        Span::raw(" quit  "),
        Span::styled(&agents_hint, Style::default().fg(Color::Yellow)),
        Span::raw(" agents  "),
        Span::styled("l", Style::default().fg(Color::Yellow)),
        Span::raw(" logs  "),
        Span::styled("t", Style::default().fg(Color::Yellow)),
        Span::raw(" thinking  "),
        Span::styled("?", Style::default().fg(Color::Yellow)),
        Span::raw(" help"),
    ]);

    let footer = Paragraph::new(help).style(Style::default().fg(Color::DarkGray));
    frame.render_widget(footer, area);
}

/// Format large numbers with K/M suffixes
fn format_number(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.1}K", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}

/// Format cost with appropriate precision
fn format_cost(cost: f64) -> String {
    if cost < 0.01 {
        format!("${:.4}", cost)
    } else {
        format!("${:.2}", cost)
    }
}

/// Get color for engagement phase
fn phase_color(phase: feroxmute_core::agents::EngagementPhase) -> Style {
    use feroxmute_core::agents::EngagementPhase;
    match phase {
        EngagementPhase::Setup => Style::default().fg(Color::White),
        EngagementPhase::StaticAnalysis => Style::default().fg(Color::Magenta),
        EngagementPhase::Reconnaissance => Style::default().fg(Color::Blue),
        EngagementPhase::Scanning => Style::default().fg(Color::Yellow),
        EngagementPhase::Exploitation => Style::default().fg(Color::Red),
        EngagementPhase::Reporting => Style::default().fg(Color::Cyan),
        EngagementPhase::Complete => Style::default()
            .fg(Color::Green)
            .add_modifier(Modifier::BOLD),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_number() {
        assert_eq!(format_number(500), "500");
        assert_eq!(format_number(1500), "1.5K");
        assert_eq!(format_number(1_500_000), "1.5M");
    }

    #[test]
    fn test_format_cost() {
        assert_eq!(format_cost(0.0001), "$0.0001");
        assert_eq!(format_cost(0.005), "$0.0050");
        assert_eq!(format_cost(0.05), "$0.05");
        assert_eq!(format_cost(1.50), "$1.50");
        assert_eq!(format_cost(99.99), "$99.99");
    }
}
