//! Dashboard widget for the main TUI view

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
            Constraint::Length(3),  // Header
            Constraint::Length(5),  // Metrics
            Constraint::Length(7),  // Agent status table
            Constraint::Min(5),     // Feed
            Constraint::Length(1),  // Footer
        ])
        .split(frame.area());

    render_header(frame, app, chunks[0]);
    render_metrics(frame, app, chunks[1]);
    render_agents(frame, app, chunks[2]);
    render_feed(frame, app, chunks[3]);
    render_footer(frame, chunks[4]);
}

/// Render the header with target info
fn render_header(frame: &mut Frame, app: &App, area: Rect) {
    let header_text = vec![Line::from(vec![
        Span::styled("Target: ", Style::default().fg(Color::Gray)),
        Span::styled(&app.target, Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
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

    // Token metrics
    let tokens = format!(
        "In: {} | Out: {} | Cache: {}",
        format_number(app.metrics.input_tokens),
        format_number(app.metrics.output_tokens),
        format_number(app.metrics.cache_read_tokens)
    );
    let token_block = Paragraph::new(tokens)
        .block(Block::default().borders(Borders::ALL).title(" Tokens "));
    frame.render_widget(token_block, chunks[0]);

    // Tool calls
    let tools = format!("Tool Calls: {}", app.metrics.tool_calls);
    let tools_block = Paragraph::new(tools)
        .block(Block::default().borders(Borders::ALL).title(" Activity "));
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
    let vuln_block = Paragraph::new(vulns)
        .style(vuln_style)
        .block(Block::default().borders(Borders::ALL).title(" Vulnerabilities "));
    frame.render_widget(vuln_block, chunks[2]);
}

/// Render agent status table
fn render_agents(frame: &mut Frame, app: &App, area: Rect) {
    let header = Row::new(vec!["Agent", "Status", ""])
        .style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD));

    let rows = vec![
        agent_row("Orchestrator", app.agent_statuses.orchestrator, "[1]"),
        agent_row("Recon", app.agent_statuses.recon, "[2]"),
        agent_row("Scanner", app.agent_statuses.scanner, "[3]"),
    ];

    let table = Table::new(
        rows,
        [
            Constraint::Length(15),
            Constraint::Length(12),
            Constraint::Length(5),
        ],
    )
    .header(header)
    .block(Block::default().borders(Borders::ALL).title(" Agents "));

    frame.render_widget(table, area);
}

/// Create a row for an agent
fn agent_row<'a>(name: &'a str, status: AgentStatus, key: &'a str) -> Row<'a> {
    let (status_text, status_style) = match status {
        AgentStatus::Idle => ("Idle", Style::default().fg(Color::Gray)),
        AgentStatus::Planning => ("Planning", Style::default().fg(Color::Blue)),
        AgentStatus::Running => ("Running", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
        AgentStatus::Waiting => ("Waiting", Style::default().fg(Color::Yellow)),
        AgentStatus::Completed => ("Done", Style::default().fg(Color::Cyan)),
        AgentStatus::Failed => ("Failed", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
    };

    Row::new(vec![
        Cell::from(name),
        Cell::from(status_text).style(status_style),
        Cell::from(key).style(Style::default().fg(Color::DarkGray)),
    ])
}

/// Render activity feed
fn render_feed(frame: &mut Frame, app: &App, area: Rect) {
    let items: Vec<ListItem> = app
        .feed
        .iter()
        .rev()
        .take(area.height as usize - 2)
        .map(|entry| {
            let style = if entry.is_error {
                Style::default().fg(Color::Red)
            } else {
                Style::default()
            };
            let line = Line::from(vec![
                Span::styled(
                    format!("[{}] ", entry.agent),
                    Style::default().fg(Color::Cyan),
                ),
                Span::styled(&entry.message, style),
            ]);
            ListItem::new(line)
        })
        .collect();

    let feed = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(" Activity Feed "));

    frame.render_widget(feed, area);
}

/// Render footer with keybindings
fn render_footer(frame: &mut Frame, area: Rect) {
    let help = Line::from(vec![
        Span::styled("q", Style::default().fg(Color::Yellow)),
        Span::raw(" quit  "),
        Span::styled("1-3", Style::default().fg(Color::Yellow)),
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

/// Get color for engagement phase
fn phase_color(phase: feroxmute_core::agents::EngagementPhase) -> Style {
    use feroxmute_core::agents::EngagementPhase;
    match phase {
        EngagementPhase::Setup => Style::default().fg(Color::White),
        EngagementPhase::Reconnaissance => Style::default().fg(Color::Blue),
        EngagementPhase::Scanning => Style::default().fg(Color::Yellow),
        EngagementPhase::Exploitation => Style::default().fg(Color::Red),
        EngagementPhase::Reporting => Style::default().fg(Color::Cyan),
        EngagementPhase::Complete => Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
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
}
