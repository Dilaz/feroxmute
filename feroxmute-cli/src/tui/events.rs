//! TUI Event handling

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers, MouseEvent, MouseEventKind};
use std::time::Duration;

use super::app::{App, View};

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
    // Handle quit confirmation dialog
    if app.confirm_quit {
        match key.code {
            KeyCode::Char('y') | KeyCode::Enter => {
                app.should_quit = true;
                return EventResult::Quit;
            }
            KeyCode::Char('n') | KeyCode::Esc => {
                app.confirm_quit = false;
            }
            _ => {}
        }
        return EventResult::Continue;
    }

    // Check for quit keys - show confirmation
    if key.code == KeyCode::Char('q')
        || (key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL))
    {
        app.confirm_quit = true;
        return EventResult::Continue;
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
        KeyCode::Char(c @ '1'..='9') => {
            let key_num = c.to_digit(10).unwrap() as usize;
            if let Some(agent_name) = app.get_agent_by_key(key_num) {
                app.selected_agent = Some(agent_name.clone());
                app.navigate(View::AgentDetail(agent_name));
            }
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

        // Horizontal feed scrolling (Dashboard view only)
        KeyCode::Left | KeyCode::Char('H') => {
            if matches!(app.view, View::Dashboard) {
                app.scroll_feed_left();
            }
        }
        KeyCode::Right | KeyCode::Char('L') => {
            if matches!(app.view, View::Dashboard) {
                app.scroll_feed_right();
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
#[allow(clippy::needless_pass_by_value)]
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
    fn test_quit_shows_confirmation() {
        let mut app = App::new("test.com", "test-session", None);
        let key = KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE);

        let result = handle_key_event(&mut app, key);
        assert!(matches!(result, EventResult::Continue));
        assert!(app.confirm_quit);
        assert!(!app.should_quit);
    }

    #[test]
    fn test_quit_confirmation_yes() {
        let mut app = App::new("test.com", "test-session", None);
        app.confirm_quit = true;

        let key = KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE);
        let result = handle_key_event(&mut app, key);
        assert!(matches!(result, EventResult::Quit));
        assert!(app.should_quit);
    }

    #[test]
    fn test_quit_confirmation_no() {
        let mut app = App::new("test.com", "test-session", None);
        app.confirm_quit = true;

        let key = KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE);
        let result = handle_key_event(&mut app, key);
        assert!(matches!(result, EventResult::Continue));
        assert!(!app.confirm_quit);
    }

    #[test]
    fn test_ctrl_c_shows_confirmation() {
        let mut app = App::new("test.com", "test-session", None);
        let key = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);

        let result = handle_key_event(&mut app, key);
        assert!(matches!(result, EventResult::Continue));
        assert!(app.confirm_quit);
    }

    #[test]
    fn test_navigation_to_dashboard() {
        let mut app = App::new("test.com", "test-session", None);
        app.navigate(View::Logs);
        assert_eq!(app.view, View::Logs);

        let key = KeyEvent::new(KeyCode::Char('h'), KeyModifiers::NONE);
        handle_key_event(&mut app, key);

        assert_eq!(app.view, View::Dashboard);
    }

    #[test]
    fn test_navigation_to_agent_detail() {
        let mut app = App::new("test.com", "test-session", None);

        let key = KeyEvent::new(KeyCode::Char('1'), KeyModifiers::NONE);
        handle_key_event(&mut app, key);
        assert_eq!(app.view, View::AgentDetail("orchestrator".to_string()));

        app.navigate(View::Dashboard);
        let key = KeyEvent::new(KeyCode::Char('2'), KeyModifiers::NONE);
        handle_key_event(&mut app, key);
        assert_eq!(app.view, View::Dashboard);  // No agent at key 2
    }

    #[test]
    fn test_toggle_thinking() {
        let mut app = App::new("test.com", "test-session", None);
        let initial = app.show_thinking;

        let key = KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE);
        handle_key_event(&mut app, key);

        assert_ne!(app.show_thinking, initial);
    }

    #[test]
    fn test_scroll() {
        let mut app = App::new("test.com", "test-session", None);
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
