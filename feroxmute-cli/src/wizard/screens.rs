//! Wizard screen renderers

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

use super::state::WizardState;
use super::widgets::{CheckboxGroup, SelectList, TextInput};

/// Render the welcome screen
pub fn render_welcome(frame: &mut Frame, _state: &WizardState) {
    let area = centered_rect(60, 50, frame.area());

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .title(" Feroxmute Setup ");

    let text = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  Welcome to Feroxmute!",
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from("  This wizard will help you create a configuration file"),
        Line::from("  with sensible defaults for your penetration testing."),
        Line::from(""),
        Line::from("  The config will be saved to:"),
        Line::from(Span::styled(
            "  ~/.feroxmute/config.toml",
            Style::default().fg(Color::Yellow),
        )),
        Line::from(""),
        Line::from(""),
        Line::from(vec![
            Span::styled("  Press ", Style::default().fg(Color::DarkGray)),
            Span::styled("Enter", Style::default().fg(Color::Green)),
            Span::styled(" to continue or ", Style::default().fg(Color::DarkGray)),
            Span::styled("q", Style::default().fg(Color::Red)),
            Span::styled(" to quit", Style::default().fg(Color::DarkGray)),
        ]),
    ];

    let para = Paragraph::new(text).block(block);
    frame.render_widget(para, area);
}

/// Helper to create a centered rectangle
pub fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

/// Standard screen layout with title, content, and footer
pub fn screen_layout(frame: &mut Frame, title: &str) -> (Rect, Rect, Rect) {
    let area = centered_rect(70, 70, frame.area());

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .title(format!(" {} ", title));

    frame.render_widget(block, area);

    let inner = Block::default().borders(Borders::ALL).inner(area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Title/description
            Constraint::Min(5),    // Content
            Constraint::Length(2), // Footer
        ])
        .split(inner);

    (chunks[0], chunks[1], chunks[2])
}

/// Render footer with keybindings
pub fn render_footer(frame: &mut Frame, area: Rect, can_go_back: bool) {
    let mut spans = vec![
        Span::styled("Enter", Style::default().fg(Color::Green)),
        Span::raw(" continue  "),
    ];

    if can_go_back {
        spans.extend([
            Span::styled("Esc", Style::default().fg(Color::Yellow)),
            Span::raw(" back  "),
        ]);
    }

    spans.extend([
        Span::styled("q", Style::default().fg(Color::Red)),
        Span::raw(" quit"),
    ]);

    let footer = Paragraph::new(Line::from(spans))
        .style(Style::default().fg(Color::DarkGray));
    frame.render_widget(footer, area);
}
