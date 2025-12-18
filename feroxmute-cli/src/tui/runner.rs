//! TUI main loop runner

use std::io::{self, stdout};
use std::time::Duration;

use crossterm::{
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Frame, Terminal};

use super::app::{AgentView, App, View};
use super::events::{handle_event, poll_event, EventResult};
use super::widgets::{agent_detail, dashboard};

/// Render the current view
fn render(frame: &mut Frame, app: &App) {
    match app.view {
        View::Dashboard => dashboard::render(frame, app),
        View::AgentDetail(agent_view) => agent_detail::render(frame, app, agent_view),
        View::Logs => render_logs(frame, app),
        View::Help => render_help(frame),
    }
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

    let items: Vec<ListItem> = app
        .feed
        .iter()
        .rev()
        .skip(app.log_scroll)
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

    let logs = List::new(items).block(Block::default().borders(Borders::ALL).title(" Logs "));

    frame.render_widget(logs, chunks[0]);

    let help = Line::from(vec![
        Span::styled("h", Style::default().fg(Color::Yellow)),
        Span::raw(" back  "),
        Span::styled("j/k", Style::default().fg(Color::Yellow)),
        Span::raw(" scroll  "),
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
            Span::styled("  1          ", Style::default().fg(Color::Yellow)),
            Span::raw("Orchestrator details"),
        ]),
        Line::from(vec![
            Span::styled("  2          ", Style::default().fg(Color::Yellow)),
            Span::raw("Recon agent details"),
        ]),
        Line::from(vec![
            Span::styled("  3          ", Style::default().fg(Color::Yellow)),
            Span::raw("Scanner agent details"),
        ]),
        Line::from(vec![
            Span::styled("  4          ", Style::default().fg(Color::Yellow)),
            Span::raw("SAST agent details"),
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

        // Check for quit
        if app.should_quit {
            break;
        }
    }

    Ok(())
}
