//! TUI Event handling

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers, MouseEvent, MouseEventKind};
use std::time::Duration;

use super::app::{AgentView, App, View};

/// Event handling result
pub enum EventResult {
    /// Continue running
    Continue,
    /// Should quit
    Quit,
}

/// Poll for events with timeout
pub fn poll_event(timeout: Duration) -> std::io::Result<Option<Event>> {
    if event::poll(timeout)? {
        Ok(Some(event::read()?))
    } else {
        Ok(None)
    }
}

/// Handle keyboard events
pub fn handle_key_event(app: &mut App, key: KeyEvent) -> EventResult {
    // Check for quit keys
    if key.code == KeyCode::Char('q')
        || (key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL))
    {
        app.should_quit = true;
        return EventResult::Quit;
    }

    match key.code {
        // Navigation
        KeyCode::Char('h') | KeyCode::Home | KeyCode::Esc => {
            app.navigate(View::Dashboard);
        }
        KeyCode::Char('l') => {
            app.navigate(View::Logs);
        }

        // Agent detail views (number keys)
        KeyCode::Char('1') => {
            app.navigate(View::AgentDetail(AgentView::Orchestrator));
        }
        KeyCode::Char('2') => {
            app.navigate(View::AgentDetail(AgentView::Recon));
        }
        KeyCode::Char('3') => {
            app.navigate(View::AgentDetail(AgentView::Scanner));
        }
        KeyCode::Char('4') => {
            app.navigate(View::AgentDetail(AgentView::Sast));
        }

        // Toggles
        KeyCode::Char('t') => {
            app.toggle_thinking();
        }
        KeyCode::Char('m') => {
            app.mouse_enabled = !app.mouse_enabled;
        }
        KeyCode::Char('?') => {
            app.navigate(View::Help);
        }

        // Scrolling
        KeyCode::Up | KeyCode::Char('k') => {
            if matches!(app.view, View::Logs | View::AgentDetail(_)) {
                app.scroll_up();
            } else {
                app.select_prev();
            }
        }
        KeyCode::Down | KeyCode::Char('j') => {
            if matches!(app.view, View::Logs | View::AgentDetail(_)) {
                app.scroll_down();
            } else {
                app.select_next();
            }
        }
        KeyCode::PageUp => {
            for _ in 0..10 {
                app.scroll_up();
            }
        }
        KeyCode::PageDown => {
            for _ in 0..10 {
                app.scroll_down();
            }
        }

        // Enter to select/confirm
        KeyCode::Enter => {
            // Could expand selected feed item, etc.
        }

        _ => {}
    }

    EventResult::Continue
}

/// Handle mouse events
pub fn handle_mouse_event(app: &mut App, mouse: MouseEvent) -> EventResult {
    if !app.mouse_enabled {
        return EventResult::Continue;
    }

    match mouse.kind {
        MouseEventKind::ScrollUp => {
            app.scroll_up();
        }
        MouseEventKind::ScrollDown => {
            app.scroll_down();
        }
        MouseEventKind::Down(_) => {
            // Could implement click handling for specific areas
        }
        _ => {}
    }

    EventResult::Continue
}

/// Process an event
pub fn handle_event(app: &mut App, event: Event) -> EventResult {
    match event {
        Event::Key(key) => handle_key_event(app, key),
        Event::Mouse(mouse) => handle_mouse_event(app, mouse),
        Event::Resize(_, _) => {
            // Terminal resize - ratatui handles this automatically
            EventResult::Continue
        }
        _ => EventResult::Continue,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quit_on_q() {
        let mut app = App::new("test.com", "test-session");
        let key = KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE);

        let result = handle_key_event(&mut app, key);
        assert!(matches!(result, EventResult::Quit));
        assert!(app.should_quit);
    }

    #[test]
    fn test_quit_on_ctrl_c() {
        let mut app = App::new("test.com", "test-session");
        let key = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);

        let result = handle_key_event(&mut app, key);
        assert!(matches!(result, EventResult::Quit));
    }

    #[test]
    fn test_navigation_to_dashboard() {
        let mut app = App::new("test.com", "test-session");
        app.navigate(View::Logs);
        assert_eq!(app.view, View::Logs);

        let key = KeyEvent::new(KeyCode::Char('h'), KeyModifiers::NONE);
        handle_key_event(&mut app, key);

        assert_eq!(app.view, View::Dashboard);
    }

    #[test]
    fn test_navigation_to_agent_detail() {
        let mut app = App::new("test.com", "test-session");

        let key = KeyEvent::new(KeyCode::Char('1'), KeyModifiers::NONE);
        handle_key_event(&mut app, key);
        assert_eq!(app.view, View::AgentDetail(AgentView::Orchestrator));

        let key = KeyEvent::new(KeyCode::Char('2'), KeyModifiers::NONE);
        handle_key_event(&mut app, key);
        assert_eq!(app.view, View::AgentDetail(AgentView::Recon));
    }

    #[test]
    fn test_toggle_thinking() {
        let mut app = App::new("test.com", "test-session");
        let initial = app.show_thinking;

        let key = KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE);
        handle_key_event(&mut app, key);

        assert_ne!(app.show_thinking, initial);
    }

    #[test]
    fn test_scroll() {
        let mut app = App::new("test.com", "test-session");
        app.navigate(View::Logs);
        app.log_scroll = 5;

        let key = KeyEvent::new(KeyCode::Up, KeyModifiers::NONE);
        handle_key_event(&mut app, key);
        assert_eq!(app.log_scroll, 4);

        let key = KeyEvent::new(KeyCode::Down, KeyModifiers::NONE);
        handle_key_event(&mut app, key);
        assert_eq!(app.log_scroll, 5);
    }
}
