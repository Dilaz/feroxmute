//! Configuration wizard for feroxmute

mod screens;
mod state;
mod widgets;

use std::io::{self, stdout};
use std::path::PathBuf;

use crossterm::{
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, backend::CrosstermBackend};

/// Run the configuration wizard
/// Returns the path to the created config file
pub fn run_wizard() -> anyhow::Result<PathBuf> {
    let mut state = state::WizardState::new();

    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen)?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    // Run wizard loop
    let result = run_loop(&mut terminal, &mut state);

    // Cleanup terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    state: &mut state::WizardState,
) -> anyhow::Result<PathBuf> {
    use crossterm::event::{self, Event};
    use std::time::Duration;

    loop {
        terminal.draw(|frame| state.render(frame))?;

        if event::poll(Duration::from_millis(100))?
            && let Event::Key(key) = event::read()?
        {
            match state.handle_key(key) {
                state::WizardAction::Continue => {}
                state::WizardAction::Quit => {
                    anyhow::bail!("Wizard cancelled by user");
                }
                state::WizardAction::Complete(path) => {
                    return Ok(path);
                }
            }
        }
    }
}
