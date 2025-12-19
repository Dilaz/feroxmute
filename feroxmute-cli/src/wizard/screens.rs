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

/// Render the confirm overwrite screen
pub fn render_confirm_overwrite(frame: &mut Frame, state: &WizardState) {
    let area = centered_rect(60, 40, frame.area());

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Yellow))
        .title(" Existing Config Found ");

    let text = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  A configuration file already exists at:",
            Style::default(),
        )),
        Line::from(Span::styled(
            "  ~/.feroxmute/config.toml",
            Style::default().fg(Color::Yellow),
        )),
        Line::from(""),
        Line::from("  Do you want to overwrite it?"),
        Line::from(""),
    ];

    let options = ["Yes, overwrite", "No, cancel"];
    let list = SelectList::new(&options, state.selected_index)
        .focused(true)
        .label("");

    let para = Paragraph::new(text).block(block);
    frame.render_widget(para, area);

    let list_area = Rect {
        x: area.x + 2,
        y: area.y + 8,
        width: area.width.saturating_sub(4),
        height: 4,
    };
    list.render(frame, list_area);
}

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

/// Render the provider selection screen
pub fn render_provider(frame: &mut Frame, state: &WizardState) {
    let (title_area, content_area, footer_area) = screen_layout(frame, "Feroxmute Setup");

    let title = Paragraph::new(Line::from(vec![
        Span::styled("Step 1: ", Style::default().fg(Color::DarkGray)),
        Span::styled("Select LLM Provider", Style::default().add_modifier(Modifier::BOLD)),
    ]));
    frame.render_widget(title, title_area);

    let providers = ["Anthropic (Recommended)", "OpenAI", "LiteLLM (Local proxy)"];
    let list = SelectList::new(&providers, state.selected_index)
        .focused(true)
        .label("Provider");

    let list_area = Rect {
        x: content_area.x + 2,
        y: content_area.y + 1,
        width: content_area.width.saturating_sub(4),
        height: 5,
    };
    list.render(frame, list_area);

    render_footer(frame, footer_area, true);
}

/// Render the API key input screen
pub fn render_api_key(frame: &mut Frame, state: &WizardState) {
    let (title_area, content_area, footer_area) = screen_layout(frame, "Feroxmute Setup");

    let provider_name = match state.data.provider {
        feroxmute_core::config::ProviderName::Anthropic => "Anthropic",
        feroxmute_core::config::ProviderName::OpenAi => "OpenAI",
        feroxmute_core::config::ProviderName::LiteLlm => "LiteLLM",
        feroxmute_core::config::ProviderName::Cohere => "Cohere",
    };

    let title = Paragraph::new(Line::from(vec![
        Span::styled("Step 2: ", Style::default().fg(Color::DarkGray)),
        Span::styled(format!("Enter {} API Key", provider_name), Style::default().add_modifier(Modifier::BOLD)),
    ]));
    frame.render_widget(title, title_area);

    let warning_area = Rect {
        x: content_area.x + 2,
        y: content_area.y,
        width: content_area.width.saturating_sub(4),
        height: 2,
    };
    let warning = Paragraph::new(Line::from(vec![
        Span::styled("⚠ ", Style::default().fg(Color::Yellow)),
        Span::styled("API key will be stored in config. Ensure ~/.feroxmute/ is not shared.", Style::default().fg(Color::Yellow)),
    ]));
    frame.render_widget(warning, warning_area);

    let input_area = Rect {
        x: content_area.x + 2,
        y: content_area.y + 3,
        width: content_area.width.saturating_sub(4),
        height: 3,
    };

    let placeholder = match state.data.provider {
        feroxmute_core::config::ProviderName::Anthropic => "sk-ant-...",
        feroxmute_core::config::ProviderName::OpenAi => "sk-...",
        feroxmute_core::config::ProviderName::LiteLlm => "your-api-key",
        _ => "api-key",
    };

    let input = TextInput::new(&state.text_input, state.cursor_position)
        .placeholder(placeholder)
        .masked(true)
        .focused(true)
        .label("API Key");
    input.render(frame, input_area);

    render_footer(frame, footer_area, true);
}

/// Render the scope selection screen
pub fn render_scope(frame: &mut Frame, state: &WizardState) {
    let (title_area, content_area, footer_area) = screen_layout(frame, "Feroxmute Setup");

    let title = Paragraph::new(Line::from(vec![
        Span::styled("Step 3: ", Style::default().fg(Color::DarkGray)),
        Span::styled("Default Testing Scope", Style::default().add_modifier(Modifier::BOLD)),
    ]));
    frame.render_widget(title, title_area);

    let scopes = ["Web (HTTP/HTTPS only)", "Network (ports, services)", "Full (web + network)"];
    let list = SelectList::new(&scopes, state.selected_index)
        .focused(true)
        .label("Scope");

    let list_area = Rect {
        x: content_area.x + 2,
        y: content_area.y + 1,
        width: content_area.width.saturating_sub(4),
        height: 5,
    };
    list.render(frame, list_area);

    render_footer(frame, footer_area, true);
}

/// Render the constraints selection screen
pub fn render_constraints(frame: &mut Frame, state: &WizardState) {
    let (title_area, content_area, footer_area) = screen_layout(frame, "Feroxmute Setup");

    let title = Paragraph::new(Line::from(vec![
        Span::styled("Step 4: ", Style::default().fg(Color::DarkGray)),
        Span::styled("Default Constraints", Style::default().add_modifier(Modifier::BOLD)),
    ]));
    frame.render_widget(title, title_area);

    let items = [
        ("Passive only (no active probing)", state.data.passive),
        ("No exploitation (recon/scan only)", state.data.no_exploit),
        ("No port scanning", state.data.no_portscan),
    ];
    let checkbox = CheckboxGroup::new(&items, state.selected_index)
        .focused(true)
        .label("Constraints (Space to toggle)");

    let list_area = Rect {
        x: content_area.x + 2,
        y: content_area.y + 1,
        width: content_area.width.saturating_sub(4),
        height: 5,
    };
    checkbox.render(frame, list_area);

    render_footer(frame, footer_area, true);
}

/// Render the advanced prompt screen
pub fn render_advanced_prompt(frame: &mut Frame, state: &WizardState) {
    let (title_area, content_area, footer_area) = screen_layout(frame, "Feroxmute Setup");

    let title = Paragraph::new(Line::from(vec![
        Span::styled("Step 5: ", Style::default().fg(Color::DarkGray)),
        Span::styled("Advanced Options", Style::default().add_modifier(Modifier::BOLD)),
    ]));
    frame.render_widget(title, title_area);

    let options = ["Skip (use defaults)", "Configure advanced options"];
    let list = SelectList::new(&options, state.selected_index)
        .focused(true)
        .label("Advanced Configuration");

    let list_area = Rect {
        x: content_area.x + 2,
        y: content_area.y + 1,
        width: content_area.width.saturating_sub(4),
        height: 4,
    };
    list.render(frame, list_area);

    render_footer(frame, footer_area, true);
}

/// Render the advanced options screen
pub fn render_advanced(frame: &mut Frame, state: &WizardState) {
    let (title_area, content_area, footer_area) = screen_layout(frame, "Feroxmute Setup");

    let title = Paragraph::new(Line::from(vec![
        Span::styled("Step 5: ", Style::default().fg(Color::DarkGray)),
        Span::styled("Advanced Options", Style::default().add_modifier(Modifier::BOLD)),
    ]));
    frame.render_widget(title, title_area);

    let items = [
        ("Export HTML reports", state.data.export_html),
        ("Export PDF reports", state.data.export_pdf),
    ];
    let checkbox = CheckboxGroup::new(&items, state.selected_index)
        .focused(true)
        .label("Output Options (Space to toggle)");

    let list_area = Rect {
        x: content_area.x + 2,
        y: content_area.y + 1,
        width: content_area.width.saturating_sub(4),
        height: 4,
    };
    checkbox.render(frame, list_area);

    render_footer(frame, footer_area, true);
}

/// Render the review screen
pub fn render_review(frame: &mut Frame, state: &WizardState) {
    let (title_area, content_area, footer_area) = screen_layout(frame, "Feroxmute Setup");

    let title = Paragraph::new(Line::from(vec![
        Span::styled("Review: ", Style::default().fg(Color::DarkGray)),
        Span::styled("Configuration Summary", Style::default().add_modifier(Modifier::BOLD)),
    ]));
    frame.render_widget(title, title_area);

    let provider_name = match state.data.provider {
        feroxmute_core::config::ProviderName::Anthropic => "Anthropic",
        feroxmute_core::config::ProviderName::OpenAi => "OpenAI",
        feroxmute_core::config::ProviderName::LiteLlm => "LiteLLM",
        feroxmute_core::config::ProviderName::Cohere => "Cohere",
    };

    let scope_name = match state.data.scope {
        feroxmute_core::config::Scope::Web => "Web",
        feroxmute_core::config::Scope::Network => "Network",
        feroxmute_core::config::Scope::Full => "Full",
    };

    let api_key_display = if state.data.api_key.len() > 8 {
        format!("{}...{}", &state.data.api_key[..4], &state.data.api_key[state.data.api_key.len()-4..])
    } else {
        "****".to_string()
    };

    let lines = vec![
        Line::from(vec![
            Span::styled("  Provider:    ", Style::default().fg(Color::DarkGray)),
            Span::raw(provider_name),
        ]),
        Line::from(vec![
            Span::styled("  API Key:     ", Style::default().fg(Color::DarkGray)),
            Span::raw(api_key_display),
        ]),
        Line::from(vec![
            Span::styled("  Scope:       ", Style::default().fg(Color::DarkGray)),
            Span::raw(scope_name),
        ]),
        Line::from(vec![
            Span::styled("  Passive:     ", Style::default().fg(Color::DarkGray)),
            Span::raw(if state.data.passive { "Yes" } else { "No" }),
        ]),
        Line::from(vec![
            Span::styled("  No Exploit:  ", Style::default().fg(Color::DarkGray)),
            Span::raw(if state.data.no_exploit { "Yes" } else { "No" }),
        ]),
        Line::from(vec![
            Span::styled("  No Portscan: ", Style::default().fg(Color::DarkGray)),
            Span::raw(if state.data.no_portscan { "Yes" } else { "No" }),
        ]),
        Line::from(""),
        Line::from(Span::styled("  Config will be saved to: ", Style::default().fg(Color::DarkGray))),
        Line::from(Span::styled("  ~/.feroxmute/config.toml", Style::default().fg(Color::Yellow))),
    ];

    let summary = Paragraph::new(lines);
    frame.render_widget(summary, content_area);

    let footer = Paragraph::new(Line::from(vec![
        Span::styled("Enter", Style::default().fg(Color::Green)),
        Span::raw(" save config  "),
        Span::styled("Esc", Style::default().fg(Color::Yellow)),
        Span::raw(" back  "),
        Span::styled("q", Style::default().fg(Color::Red)),
        Span::raw(" quit"),
    ]))
    .style(Style::default().fg(Color::DarkGray));
    frame.render_widget(footer, footer_area);
}
