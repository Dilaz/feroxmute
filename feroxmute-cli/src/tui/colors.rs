//! Color and style helpers for agent status indicators

use feroxmute_core::agents::AgentStatus;
use ratatui::style::{Color, Modifier, Style};

/// Format an agent status with optional current tool info
/// Returns (display_text, style) for consistent status rendering
/// Use `max_tool_len` to control tool name truncation (default 20)
pub fn format_agent_status(status: AgentStatus, current_tool: Option<&str>) -> (String, Style) {
    format_agent_status_with_len(status, current_tool, 20)
}

/// Format an agent status with configurable tool name length
pub fn format_agent_status_with_len(
    status: AgentStatus,
    current_tool: Option<&str>,
    max_tool_len: usize,
) -> (String, Style) {
    match status {
        AgentStatus::Idle => ("Idle".to_string(), Style::default().fg(Color::Gray)),
        AgentStatus::Thinking => (
            "Thinking".to_string(),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        AgentStatus::Streaming => (
            "Streaming".to_string(),
            Style::default()
                .fg(Color::Blue)
                .add_modifier(Modifier::BOLD),
        ),
        AgentStatus::Executing => {
            let tool_display = current_tool
                .map(|t| {
                    if t.chars().count() > max_tool_len {
                        let truncated: String =
                            t.chars().take(max_tool_len.saturating_sub(3)).collect();
                        format!("Tool: {}...", truncated)
                    } else {
                        format!("Tool: {}", t)
                    }
                })
                .unwrap_or_else(|| "Executing".to_string());
            (
                tool_display,
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )
        }
        AgentStatus::Processing => (
            "Processing".to_string(),
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        ),
        AgentStatus::Waiting => ("Waiting".to_string(), Style::default().fg(Color::Yellow)),
        AgentStatus::Retrying => (
            "Retrying".to_string(),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::SLOW_BLINK),
        ),
        AgentStatus::Completed => ("Completed".to_string(), Style::default().fg(Color::Green)),
        AgentStatus::Failed => (
            "Failed".to_string(),
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn test_format_agent_status_idle() {
        let (text, style) = format_agent_status(AgentStatus::Idle, None);
        assert_eq!(text, "Idle");
        assert_eq!(style.fg, Some(Color::Gray));
    }

    #[test]
    fn test_format_agent_status_executing_with_tool() {
        let (text, style) = format_agent_status(AgentStatus::Executing, Some("nmap"));
        assert_eq!(text, "Tool: nmap");
        assert_eq!(style.fg, Some(Color::Yellow));
        assert!(style.add_modifier.contains(Modifier::BOLD));
    }

    #[test]
    fn test_format_agent_status_executing_long_tool_truncated() {
        let (text, _) =
            format_agent_status(AgentStatus::Executing, Some("very_long_tool_name_here"));
        assert!(text.starts_with("Tool: "));
        assert!(text.ends_with("..."));
        // Default max_tool_len is 20: "Tool: " (6) + 17 chars + "..." (3) = 26
        assert!(text.chars().count() <= 26);
    }

    #[test]
    fn test_format_agent_status_completed() {
        let (text, style) = format_agent_status(AgentStatus::Completed, None);
        assert_eq!(text, "Completed");
        assert_eq!(style.fg, Some(Color::Green));
    }

    #[test]
    fn test_format_agent_status_failed() {
        let (text, style) = format_agent_status(AgentStatus::Failed, None);
        assert_eq!(text, "Failed");
        assert_eq!(style.fg, Some(Color::Red));
        assert!(style.add_modifier.contains(Modifier::BOLD));
    }
}
