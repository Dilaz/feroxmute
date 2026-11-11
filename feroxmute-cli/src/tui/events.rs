//! TUI Event handling

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers, MouseEvent, MouseEventKind};
use std::time::Duration;

use super::app::{App, Overlay, Pane};

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
    // Quit confirmation dialog takes precedence.
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

    // Quit keys show confirmation.
    if key.code == KeyCode::Char('q')
        || (key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL))
    {
        app.confirm_quit = true;
        return EventResult::Continue;
    }

    // Overlay-specific handling.
    if let Some(overlay) = app.overlay.clone() {
        handle_overlay_key(app, overlay, key);
        return EventResult::Continue;
    }

    // Command center keys.
    match key.code {
        KeyCode::Tab => app.focus_next(),
        KeyCode::BackTab => app.focus_prev(),
        KeyCode::Up | KeyCode::Char('k') => app.move_up(),
        KeyCode::Down | KeyCode::Char('j') => app.move_down(),
        KeyCode::PageUp => {
            for _ in 0..10 {
                app.move_up();
            }
        }
        KeyCode::PageDown => {
            for _ in 0..10 {
                app.move_down();
            }
        }
        KeyCode::Enter => open_focused_detail(app),
        KeyCode::Char(c @ '1'..='9') => {
            if let Some(n) = c.to_digit(10)
                && let Some(name) = app.get_agent_by_key(n as usize)
            {
                app.focus = Pane::Agents;
                let idx = app.ordered_agents().iter().position(|(nm, _)| **nm == name);
                if let Some(i) = idx {
                    app.agents_selected = i;
                }
                app.selected_agent = Some(name.clone());
                app.open_overlay(Overlay::AgentDetail(name));
            }
        }
        KeyCode::Char('p') => app.open_overlay(Overlay::Memory),
        KeyCode::Char('l') => app.open_overlay(Overlay::Logs),
        KeyCode::Char('?') => app.open_overlay(Overlay::Help),
        KeyCode::Char('m') => app.mouse_enabled = !app.mouse_enabled,
        _ => {}
    }

    EventResult::Continue
}

/// Open the detail overlay for the currently focused pane.
fn open_focused_detail(app: &mut App) {
    match app.focus {
        Pane::Agents => {
            let name = {
                let ordered = app.ordered_agents();
                let idx = app.agents_selected.min(ordered.len().saturating_sub(1));
                ordered.get(idx).map(|(n, _)| (*n).clone())
            };
            if let Some(name) = name {
                app.selected_agent = Some(name.clone());
                app.open_overlay(Overlay::AgentDetail(name));
            }
        }
        Pane::Findings => {
            if !app.findings.is_empty() {
                let idx = app
                    .findings_selected
                    .min(app.findings.len().saturating_sub(1));
                app.open_overlay(Overlay::FindingDetail(idx));
            }
        }
        Pane::Activity => app.open_overlay(Overlay::Logs),
    }
}

/// Dispatch a key while an overlay is open.
fn handle_overlay_key(app: &mut App, overlay: Overlay, key: KeyEvent) {
    match overlay {
        Overlay::Memory => {
            if app.show_memory_modal {
                match key.code {
                    KeyCode::Esc | KeyCode::Enter => app.close_memory_modal(),
                    KeyCode::Up | KeyCode::Char('k') => app.scroll_memory_modal_up(),
                    KeyCode::Down | KeyCode::Char('j') => app.scroll_memory_modal_down(),
                    _ => {}
                }
            } else {
                match key.code {
                    KeyCode::Esc => app.close_overlay(),
                    KeyCode::Up | KeyCode::Char('k') => app.select_prev_memory(),
                    KeyCode::Down | KeyCode::Char('j') => app.select_next_memory(),
                    KeyCode::Enter => app.open_memory_modal(),
                    _ => {}
                }
            }
        }
        Overlay::AgentDetail(name) => match key.code {
            KeyCode::Esc => app.close_overlay(),
            KeyCode::Up | KeyCode::Char('k') => app.scroll_up(),
            KeyCode::Down | KeyCode::Char('j') => app.scroll_down(),
            KeyCode::Char('t') => app.toggle_thinking(),
            KeyCode::Char('o') => app.toggle_output(Some(&name)),
            _ => {}
        },
        Overlay::FindingDetail(_) | Overlay::Logs => match key.code {
            KeyCode::Esc => app.close_overlay(),
            KeyCode::Up | KeyCode::Char('k') => app.scroll_up(),
            KeyCode::Down | KeyCode::Char('j') => app.scroll_down(),
            _ => {}
        },
        Overlay::Help => app.close_overlay(),
    }
}

/// Handle mouse events
pub fn handle_mouse_event(app: &mut App, mouse: MouseEvent) -> EventResult {
    if !app.mouse_enabled {
        return EventResult::Continue;
    }

    let overlay_open = app.overlay.is_some();
    match mouse.kind {
        MouseEventKind::ScrollUp => {
            if overlay_open {
                app.scroll_up();
            } else {
                app.move_up();
            }
        }
        MouseEventKind::ScrollDown => {
            if overlay_open {
                app.scroll_down();
            } else {
                app.move_down();
            }
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
        Event::Resize(_, _) => EventResult::Continue,
        _ => EventResult::Continue,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::tui::app::{Finding, FindingSource};
    use feroxmute_core::state::models::Severity;

    fn finding(sev: Severity, title: &str) -> Finding {
        Finding {
            severity: sev,
            title: title.to_string(),
            source: FindingSource::Net,
            agent: "test".to_string(),
            location: None,
            timestamp: chrono::Local::now(),
        }
    }

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
    fn test_tab_advances_focus() {
        let mut app = App::new("test.com", "test-session", None);
        assert_eq!(app.focus, Pane::Agents);
        handle_key_event(&mut app, KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
        assert_eq!(app.focus, Pane::Findings);
        handle_key_event(&mut app, KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
        assert_eq!(app.focus, Pane::Activity);
    }

    #[test]
    fn test_enter_on_findings_opens_detail() {
        let mut app = App::new("test.com", "test-session", None);
        app.add_finding(finding(Severity::High, "open port"));
        app.focus = Pane::Findings;
        handle_key_event(&mut app, KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(app.overlay, Some(Overlay::FindingDetail(0)));
    }

    #[test]
    fn test_key_one_opens_orchestrator_detail() {
        let mut app = App::new("test.com", "test-session", None);
        handle_key_event(
            &mut app,
            KeyEvent::new(KeyCode::Char('1'), KeyModifiers::NONE),
        );
        assert_eq!(
            app.overlay,
            Some(Overlay::AgentDetail("orchestrator".to_string()))
        );
    }

    #[test]
    fn test_esc_closes_overlay() {
        let mut app = App::new("test.com", "test-session", None);
        app.open_overlay(Overlay::Logs);
        handle_key_event(&mut app, KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert!(app.overlay.is_none());
    }

    #[test]
    fn test_question_opens_help() {
        let mut app = App::new("test.com", "test-session", None);
        handle_key_event(
            &mut app,
            KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE),
        );
        assert_eq!(app.overlay, Some(Overlay::Help));
    }

    #[test]
    fn test_help_closes_on_any_key() {
        let mut app = App::new("test.com", "test-session", None);
        app.open_overlay(Overlay::Help);
        handle_key_event(
            &mut app,
            KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE),
        );
        assert!(app.overlay.is_none());
    }

    #[test]
    fn test_agent_detail_scroll() {
        let mut app = App::new("test.com", "test-session", None);
        app.open_overlay(Overlay::AgentDetail("orchestrator".to_string()));
        app.log_scroll = 5;
        handle_key_event(&mut app, KeyEvent::new(KeyCode::Up, KeyModifiers::NONE));
        assert_eq!(app.log_scroll, 6);
        handle_key_event(&mut app, KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        assert_eq!(app.log_scroll, 5);
    }
}
