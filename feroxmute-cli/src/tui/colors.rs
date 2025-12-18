//! Color and style helpers for severity and status indicators

use feroxmute_core::state::models::Severity;
use ratatui::style::{Color, Modifier, Style};

/// Get the color for a given severity level
pub fn severity_color(severity: &Severity) -> Color {
    match severity {
        Severity::Critical => Color::Red,
        Severity::High => Color::LightRed,
        Severity::Medium => Color::Yellow,
        Severity::Low => Color::Blue,
        Severity::Info => Color::DarkGray,
    }
}

/// Get the styled representation for a severity level
/// Critical severity is bold
pub fn severity_style(severity: &Severity) -> Style {
    let color = severity_color(severity);
    let style = Style::default().fg(color);

    if matches!(severity, Severity::Critical) {
        style.add_modifier(Modifier::BOLD)
    } else {
        style
    }
}

/// Get the color for an agent status string
pub fn status_color(status: &str) -> Color {
    match status.to_lowercase().as_str() {
        "running" => Color::Green,
        "queued" => Color::Yellow,
        "idle" => Color::DarkGray,
        "completed" => Color::Cyan,
        "failed" | "error" => Color::Red,
        _ => Color::White,
    }
}

/// Get the styled representation for an agent status
pub fn status_style(status: &str) -> Style {
    Style::default().fg(status_color(status))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_colors() {
        assert_eq!(severity_color(&Severity::Critical), Color::Red);
        assert_eq!(severity_color(&Severity::High), Color::LightRed);
        assert_eq!(severity_color(&Severity::Medium), Color::Yellow);
        assert_eq!(severity_color(&Severity::Low), Color::Blue);
        assert_eq!(severity_color(&Severity::Info), Color::DarkGray);
    }

    #[test]
    fn test_severity_style_critical_is_bold() {
        let style = severity_style(&Severity::Critical);
        assert_eq!(style.fg, Some(Color::Red));
        assert!(style.add_modifier.contains(Modifier::BOLD));
    }

    #[test]
    fn test_severity_style_high_not_bold() {
        let style = severity_style(&Severity::High);
        assert_eq!(style.fg, Some(Color::LightRed));
        assert!(!style.add_modifier.contains(Modifier::BOLD));
    }

    #[test]
    fn test_status_colors() {
        assert_eq!(status_color("running"), Color::Green);
        assert_eq!(status_color("RUNNING"), Color::Green); // case insensitive
        assert_eq!(status_color("queued"), Color::Yellow);
        assert_eq!(status_color("idle"), Color::DarkGray);
        assert_eq!(status_color("completed"), Color::Cyan);
        assert_eq!(status_color("failed"), Color::Red);
        assert_eq!(status_color("error"), Color::Red);
        assert_eq!(status_color("unknown"), Color::White); // default
    }

    #[test]
    fn test_status_style() {
        let style = status_style("running");
        assert_eq!(style.fg, Some(Color::Green));

        let style = status_style("Failed");
        assert_eq!(style.fg, Some(Color::Red));
    }
}
