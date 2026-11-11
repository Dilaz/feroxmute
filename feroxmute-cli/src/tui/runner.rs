//! TUI main loop runner

#![allow(clippy::indexing_slicing)]

use std::io::{self, stdout};
use std::time::Duration;

use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Frame, Terminal, backend::CrosstermBackend};

use super::app::{App, Finding, FindingSource, Overlay};
use super::channel::{AgentEvent, VulnSeverity};
use super::events::{EventResult, handle_event, poll_event};
use super::widgets::{agent_detail, command_center, findings, memory, memory_modal, overlay};
use feroxmute_core::state::models::{FindingType, Severity};

/// Render the command center plus any active overlay.
fn render(frame: &mut Frame, app: &App) {
    command_center::render(frame, app);

    if let Some(overlay) = &app.overlay {
        match overlay {
            Overlay::AgentDetail(name) => agent_detail::render(frame, app, name, frame.area()),
            Overlay::FindingDetail(idx) => render_finding_detail(frame, app, *idx),
            Overlay::Memory => {
                memory::render(frame, app, frame.area());
                if app.show_memory_modal {
                    memory_modal::render(frame, app);
                }
            }
            Overlay::Logs => overlay::render_logs(frame, app),
            Overlay::Help => overlay::render_help(frame, app),
        }
    }

    if app.confirm_quit {
        render_quit_dialog(frame, app);
    }
}

/// Render the finding detail overlay.
fn render_finding_detail(frame: &mut Frame, app: &App, idx: usize) {
    let area = overlay::centered_rect(70, 60, frame.area());
    let inner = overlay::frame_block(frame, area, "Finding", &app.theme);
    findings::render_detail(frame, app, idx, inner);
}

/// Render quit confirmation dialog
fn render_quit_dialog(frame: &mut Frame, app: &App) {
    use ratatui::{
        layout::{Constraint, Flex, Layout},
        style::{Modifier, Style},
        text::{Line, Span},
        widgets::{Clear, Paragraph},
    };

    let theme = &app.theme;
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
        Line::from(Span::styled(
            "        Quit? (y/n)",
            Style::default().fg(theme.text).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
    ];

    let dialog = Paragraph::new(text).block(theme.block("Confirm", true));
    frame.render_widget(dialog, dialog_area);
}

/// Map a channel vulnerability severity to the core model severity.
fn map_severity(severity: VulnSeverity) -> Severity {
    match severity {
        VulnSeverity::Critical => Severity::Critical,
        VulnSeverity::High => Severity::High,
        VulnSeverity::Medium => Severity::Medium,
        VulnSeverity::Low => Severity::Low,
        VulnSeverity::Info => Severity::Info,
    }
}

/// Drain pending events from the channel
fn drain_events(app: &mut App) {
    let mut events = Vec::new();
    if let Some(rx) = &mut app.event_rx {
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
                app.add_finding(Finding {
                    severity: map_severity(severity),
                    title: title.clone(),
                    source: FindingSource::Net,
                    agent: "vuln".to_string(),
                    location: None,
                    timestamp: chrono::Local::now(),
                });
                app.add_feed(super::app::FeedEntry::new(
                    "vuln",
                    format!("[{severity:?}] {title}"),
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
                let icon = if success {
                    app.theme.glyphs.ok
                } else {
                    app.theme.glyphs.fail
                };
                app.add_feed(super::app::FeedEntry::new(
                    &agent,
                    format!("{icon} AGENT COMPLETE"),
                ));

                if let Some(output) = raw_output {
                    for line in output.lines() {
                        if !line.trim().is_empty() {
                            app.add_feed(super::app::FeedEntry::new(&agent, format!("  {line}")));
                        }
                    }
                    app.add_feed(super::app::FeedEntry::new(&agent, "--- Summary ---"));
                }

                if !summary.is_empty() {
                    app.add_feed(super::app::FeedEntry::new(&agent, format!("  {summary}")));
                }

                for finding in key_findings.iter().take(5) {
                    app.add_feed(super::app::FeedEntry::new(&agent, format!("  • {finding}")));
                }

                for step in next_steps.iter().take(3) {
                    app.add_feed(super::app::FeedEntry::new(&agent, format!("  → {step}")));
                }
            }
            AgentEvent::MemoryUpdated { entries } => {
                app.memory_entries = entries;
                // Clamp selection if entries were removed
                if app.selected_memory >= app.memory_entries.len() {
                    app.selected_memory = app.memory_entries.len().saturating_sub(1);
                }
            }
            AgentEvent::CodeFinding { agent, finding } => {
                // Surface the affected package for dependency findings, else the
                // file path (with line number when available).
                let location = match finding.finding_type {
                    FindingType::Dependency => finding
                        .package_name
                        .clone()
                        .or_else(|| Some(finding.file_path.clone())),
                    _ => finding
                        .line_number
                        .map(|l| format!("{}:{}", finding.file_path, l))
                        .or_else(|| Some(finding.file_path.clone())),
                };
                // Append the CVE id to the title when present.
                let title = match &finding.cve_id {
                    Some(cve) if !finding.title.contains(cve.as_str()) => {
                        format!("{} ({cve})", finding.title)
                    }
                    _ => finding.title.clone(),
                };
                app.add_finding(Finding {
                    severity: finding.severity,
                    title: title.clone(),
                    source: FindingSource::from(finding.finding_type),
                    agent: agent.clone(),
                    location,
                    timestamp: chrono::Local::now(),
                });

                app.add_feed(super::app::FeedEntry::new(
                    &agent,
                    format!("[{:?}] {} ({})", finding.severity, title, finding.tool),
                ));
            }
            AgentEvent::Milestone {
                agent,
                milestone,
                details,
            } => {
                let msg = format!("[MILESTONE] {milestone}: {details}");
                app.add_feed(super::app::FeedEntry::new(&agent, &msg));
            }
            AgentEvent::ToolCall => {
                app.metrics.tool_calls += 1;
            }
        }
    }
}

/// Run the TUI application
pub fn run(app: &mut App) -> io::Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    // Main loop
    let result = run_loop(&mut terminal, app);

    // Cleanup
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        DisableMouseCapture,
        LeaveAlternateScreen
    )?;
    terminal.show_cursor()?;

    result
}

/// Main event loop
fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
) -> io::Result<()> {
    loop {
        // Advance the animation frame counter (spinner animation).
        app.tick = app.tick.wrapping_add(1);

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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::tui::app::FindingSource;
    use feroxmute_core::agents::{AgentStatus, EngagementPhase};
    use feroxmute_core::state::models::Severity;
    use ratatui::{Terminal, backend::TestBackend};

    fn sample_app() -> App {
        let mut app = App::new("example.com", "sess-1", None);
        app.phase = EngagementPhase::Scanning;
        app.update_spawned_agent_status(
            "recon-1",
            "recon",
            AgentStatus::Executing,
            Some("nmap".into()),
        );
        app.add_finding(Finding {
            severity: Severity::Critical,
            title: "Remote code execution".to_string(),
            source: FindingSource::Net,
            agent: "scanner".to_string(),
            location: None,
            timestamp: chrono::Local::now(),
        });
        app.add_finding(Finding {
            severity: Severity::Medium,
            title: "Hardcoded secret".to_string(),
            source: FindingSource::Sast,
            agent: "sast".to_string(),
            location: Some("src/main.rs:10".to_string()),
            timestamp: chrono::Local::now(),
        });
        app.add_feed(super::super::app::FeedEntry::new(
            "system",
            "engagement started",
        ));
        app.add_feed(super::super::app::FeedEntry::new(
            "recon-1",
            "scanning host",
        ));
        app
    }

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
    fn renders_command_center() {
        let app = sample_app();
        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render(f, &app)).unwrap();

        let text = buffer_text(&terminal);
        assert!(text.contains("example.com"), "target shown");
        assert!(text.contains("Agents"), "agents pane title");
        assert!(text.contains("Findings"), "findings pane title");
        assert!(text.contains("Activity"), "activity pane title");
        assert!(text.contains("recon-1"), "spawned agent shown");
        assert!(
            text.contains("Remote code execution"),
            "finding title shown"
        );
    }

    #[test]
    fn renders_help_overlay_without_panic() {
        let mut app = sample_app();
        app.overlay = Some(Overlay::Help);
        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render(f, &app)).unwrap();
        let text = buffer_text(&terminal);
        assert!(text.contains("Help"), "help overlay title shown");
    }

    #[test]
    fn renders_ascii_mode_without_panic() {
        let mut app = sample_app();
        app.theme = crate::tui::theme::Theme::detect(true);
        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        // Must not panic in the ASCII/16-color fallback path.
        terminal.draw(|f| render(f, &app)).unwrap();
    }
}
