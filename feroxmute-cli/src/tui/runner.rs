//! TUI main loop runner

#![allow(clippy::indexing_slicing)]

use std::io::{self, stdout};
use std::time::Duration;

use crossterm::{
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Frame, Terminal};

use super::app::{App, View};
use super::channel::{AgentEvent, VulnSeverity};
use super::events::{handle_event, poll_event, EventResult};
use super::widgets::{agent_detail, dashboard};

/// Render the current view
fn render(frame: &mut Frame, app: &App) {
    match &app.view {
        View::Dashboard => dashboard::render(frame, app),
        View::AgentDetail(agent_name) => agent_detail::render(frame, app, agent_name),
        View::Logs => render_logs(frame, app),
        View::Help => render_help(frame),
        View::Memory => {} // TODO: render memory view
    }

    if app.confirm_quit {
        render_quit_dialog(frame);
    }
}

/// Render quit confirmation dialog
fn render_quit_dialog(frame: &mut Frame) {
    use ratatui::{
        layout::{Constraint, Flex, Layout},
        style::{Color, Style},
        text::{Line, Span},
        widgets::{Block, Borders, Clear, Paragraph},
    };

    let area = frame.area();
    let dialog_width = 30;
    let dialog_height = 5;

    let [dialog_area] = Layout::horizontal([Constraint::Length(dialog_width)])
        .flex(Flex::Center)
        .areas(area);
    let [dialog_area] = Layout::vertical([Constraint::Length(dialog_height)])
        .flex(Flex::Center)
        .areas(dialog_area);

    frame.render_widget(Clear, dialog_area);

    let text = vec![
        Line::from(""),
        Line::from(vec![Span::raw("        Quit? (y/n)")]),
        Line::from(""),
    ];

    let dialog = Paragraph::new(text).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Yellow))
            .title(" Confirm "),
    );

    frame.render_widget(dialog, dialog_area);
}

/// Render logs view
fn render_logs(frame: &mut Frame, app: &App) {
    use ratatui::{
        layout::{Constraint, Direction, Layout},
        style::{Color, Style},
        text::{Line, Span},
        widgets::{Block, Borders, List, ListItem, Paragraph},
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(1)])
        .split(frame.area());

    let visible_height = chunks[0].height.saturating_sub(2) as usize;

    // Show newest at bottom, apply scroll from bottom
    let items: Vec<ListItem> = app
        .feed
        .iter()
        .rev()
        .skip(app.log_scroll)
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
            let line = Line::from(vec![
                Span::styled(
                    format!("{} ", time_str),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::styled(
                    format!("[{}] ", entry.agent),
                    Style::default().fg(Color::Cyan),
                ),
                Span::styled(&entry.message, style),
            ]);
            ListItem::new(line)
        })
        .collect();

    let logs = List::new(items).block(Block::default().borders(Borders::ALL).title(" Logs "));

    frame.render_widget(logs, chunks[0]);

    // Show thinking toggle state with color indicator
    let (thinking_label, thinking_style) = if app.show_thinking {
        ("[ON]", Style::default().fg(Color::Green))
    } else {
        ("[OFF]", Style::default().fg(Color::Red))
    };

    let help = Line::from(vec![
        Span::styled("h", Style::default().fg(Color::Yellow)),
        Span::raw(" back  "),
        Span::styled("j/k", Style::default().fg(Color::Yellow)),
        Span::raw(" scroll  "),
        Span::styled("t", Style::default().fg(Color::Yellow)),
        Span::raw(" thinking "),
        Span::styled(thinking_label, thinking_style),
        Span::raw("  "),
        Span::styled("q", Style::default().fg(Color::Yellow)),
        Span::raw(" quit"),
    ]);
    let footer = Paragraph::new(help).style(Style::default().fg(Color::DarkGray));
    frame.render_widget(footer, chunks[1]);
}

/// Render help view
fn render_help(frame: &mut Frame) {
    use ratatui::{
        layout::{Constraint, Direction, Layout},
        style::{Color, Modifier, Style},
        text::{Line, Span},
        widgets::{Block, Borders, Paragraph},
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(1)])
        .split(frame.area());

    let help_text = vec![
        Line::from(""),
        Line::from(vec![Span::styled(
            "  Keybindings",
            Style::default().add_modifier(Modifier::BOLD),
        )]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  q, Ctrl+c  ", Style::default().fg(Color::Yellow)),
            Span::raw("Quit"),
        ]),
        Line::from(vec![
            Span::styled("  h, Home    ", Style::default().fg(Color::Yellow)),
            Span::raw("Dashboard"),
        ]),
        Line::from(vec![
            Span::styled("  l          ", Style::default().fg(Color::Yellow)),
            Span::raw("Logs view"),
        ]),
        Line::from(vec![
            Span::styled("  1-9        ", Style::default().fg(Color::Yellow)),
            Span::raw("Agent details (1=orchestrator, 2-9=spawned)"),
        ]),
        Line::from(vec![
            Span::styled("  t          ", Style::default().fg(Color::Yellow)),
            Span::raw("Toggle thinking panel"),
        ]),
        Line::from(vec![
            Span::styled("  m          ", Style::default().fg(Color::Yellow)),
            Span::raw("Toggle mouse support"),
        ]),
        Line::from(vec![
            Span::styled("  j, Down    ", Style::default().fg(Color::Yellow)),
            Span::raw("Scroll down"),
        ]),
        Line::from(vec![
            Span::styled("  k, Up      ", Style::default().fg(Color::Yellow)),
            Span::raw("Scroll up"),
        ]),
        Line::from(vec![
            Span::styled("  ?          ", Style::default().fg(Color::Yellow)),
            Span::raw("This help"),
        ]),
    ];

    let help =
        Paragraph::new(help_text).block(Block::default().borders(Borders::ALL).title(" Help "));

    frame.render_widget(help, chunks[0]);

    let footer_text = Line::from(vec![Span::styled(
        "Press any key to close",
        Style::default().fg(Color::DarkGray),
    )]);
    let footer = Paragraph::new(footer_text);
    frame.render_widget(footer, chunks[1]);
}

/// Drain pending events from the channel
fn drain_events(app: &mut App) {
    let mut events = Vec::new();
    if let Some(ref mut rx) = app.event_rx {
        while let Ok(event) = rx.try_recv() {
            events.push(event);
        }
    }

    for event in events {
        match event {
            AgentEvent::Feed {
                agent,
                message,
                is_error,
                tool_output,
            } => {
                // Track activity for non-indented messages
                if !message.starts_with("  ") {
                    app.update_agent_activity(&agent, &message);
                }

                let mut entry = if is_error {
                    super::app::FeedEntry::error(&agent, &message)
                } else {
                    super::app::FeedEntry::new(&agent, &message)
                };

                if let Some(output) = tool_output {
                    entry = entry.with_output(output);
                }

                app.add_feed(entry);
            }
            AgentEvent::Thinking { agent, content } => {
                app.update_agent_thinking(&agent, content);
            }
            AgentEvent::Status {
                agent,
                agent_type,
                status,
                current_tool,
            } => {
                app.update_agent_status(&agent, status);
                app.update_spawned_agent_status(&agent, &agent_type, status, current_tool);
            }
            AgentEvent::Metrics {
                input,
                output,
                cache_read,
                cost_usd,
                tool_calls,
            } => {
                app.metrics.input_tokens += input;
                app.metrics.output_tokens += output;
                app.metrics.cache_read_tokens += cache_read;
                app.metrics.estimated_cost_usd += cost_usd;
                app.metrics.tool_calls += tool_calls;
            }
            AgentEvent::Vulnerability { severity, title } => {
                match severity {
                    VulnSeverity::Critical => app.vuln_counts.critical += 1,
                    VulnSeverity::High => app.vuln_counts.high += 1,
                    VulnSeverity::Medium => app.vuln_counts.medium += 1,
                    VulnSeverity::Low => app.vuln_counts.low += 1,
                    VulnSeverity::Info => app.vuln_counts.info += 1,
                }
                app.add_feed(super::app::FeedEntry::new(
                    "vuln",
                    format!("[{:?}] {}", severity, title),
                ));
            }
            AgentEvent::Finished { success, message } => {
                let agent = "system";
                if success {
                    app.add_feed(super::app::FeedEntry::new(agent, &message));
                } else {
                    app.add_feed(super::app::FeedEntry::error(agent, &message));
                }
            }
            AgentEvent::Phase { phase } => {
                app.phase = phase;
            }
            AgentEvent::Summary {
                agent,
                success,
                summary,
                key_findings,
                next_steps,
                raw_output,
            } => {
                // Show raw output as separate feed entries for proper display
                let icon = if success { "✓" } else { "✗" };
                app.add_feed(super::app::FeedEntry::new(&agent, format!("{} AGENT COMPLETE", icon)));

                // Show raw output if available for debugging
                if let Some(output) = raw_output {
                    for line in output.lines() {
                        if !line.trim().is_empty() {
                            app.add_feed(super::app::FeedEntry::new(&agent, format!("  {}", line)));
                        }
                    }
                    app.add_feed(super::app::FeedEntry::new(&agent, "--- Summary ---"));
                }

                if !summary.is_empty() {
                    app.add_feed(super::app::FeedEntry::new(&agent, format!("  {}", summary)));
                }

                for finding in key_findings.iter().take(5) {
                    app.add_feed(super::app::FeedEntry::new(&agent, format!("  • {}", finding)));
                }

                for step in next_steps.iter().take(3) {
                    app.add_feed(super::app::FeedEntry::new(&agent, format!("  → {}", step)));
                }
            }
            AgentEvent::MemoryUpdated { entries } => {
                app.memory_entries = entries;
                // Clamp selection if entries were removed
                if app.selected_memory >= app.memory_entries.len() {
                    app.selected_memory = app.memory_entries.len().saturating_sub(1);
                }
            }
        }
    }
}

/// Run the TUI application
pub fn run(app: &mut App) -> io::Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen)?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    // Main loop
    let result = run_loop(&mut terminal, app);

    // Cleanup
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

/// Main event loop
fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
) -> io::Result<()> {
    loop {
        // Draw
        terminal.draw(|frame| render(frame, app))?;

        // Handle events
        if let Some(event) = poll_event(Duration::from_millis(100))? {
            match handle_event(app, event) {
                EventResult::Quit => break,
                EventResult::Continue => {}
            }
        }

        // Drain agent events
        drain_events(app);

        // Check for quit
        if app.should_quit {
            break;
        }
    }

    Ok(())
}
