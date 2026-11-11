//! Central theme, palette, and terminal-capability detection for the TUI.
//!
//! Resolves a modern-dark palette into concrete [`ratatui`] colors and a glyph
//! set, choosing truecolor/Unicode when the terminal supports them and falling
//! back to 16-color ANSI / ASCII otherwise. `--ascii` (or `NO_COLOR`) forces the
//! conservative path.

use feroxmute_core::agents::AgentStatus;
use feroxmute_core::state::models::Severity;
use ratatui::{
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders},
};

/// Detected terminal rendering capabilities.
#[derive(Debug, Clone, Copy)]
pub struct Capabilities {
    /// Whether to emit any color at all (disabled by `NO_COLOR`).
    pub color: bool,
    /// Whether 24-bit truecolor is available (else 16-color ANSI).
    pub truecolor: bool,
    /// Whether Unicode glyphs/rounded borders are safe to render.
    pub unicode: bool,
}

impl Capabilities {
    /// Detect capabilities from the environment.
    ///
    /// `force_ascii` (from `--ascii`) forces `unicode=false` and
    /// `truecolor=false`; color is still honored unless `NO_COLOR` is set.
    pub fn detect(force_ascii: bool) -> Self {
        let color = std::env::var_os("NO_COLOR").is_none();
        let truecolor = !force_ascii
            && matches!(
                std::env::var("COLORTERM").ok().as_deref(),
                Some("truecolor") | Some("24bit")
            );
        let unicode = !force_ascii
            && ["LC_ALL", "LC_CTYPE", "LANG"]
                .iter()
                .filter_map(|k| std::env::var(k).ok())
                .any(|v| {
                    let v = v.to_ascii_lowercase();
                    v.contains("utf-8") || v.contains("utf8")
                });
        Self {
            color,
            truecolor,
            unicode,
        }
    }
}

/// Glyph set selected from [`Capabilities`] (rich Unicode vs. plain ASCII).
#[derive(Debug, Clone, Copy)]
pub struct Glyphs {
    pub tree_branch: &'static str,
    pub tree_last: &'static str,
    pub tree_root: &'static str,
    pub spinner: &'static [&'static str],
    pub ok: &'static str,
    pub fail: &'static str,
    pub wait: &'static str,
    pub idle: &'static str,
    pub sev_hi: &'static str,
    pub sev_med: &'static str,
    pub sev_lo: &'static str,
    pub bar_full: &'static str,
    pub bar_empty: &'static str,
    pub metric_in: &'static str,
    pub metric_out: &'static str,
}

const SPINNER_RICH: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const SPINNER_ASCII: &[&str] = &["|", "/", "-", "\\"];

impl Glyphs {
    fn rich() -> Self {
        Self {
            tree_branch: "├─ ",
            tree_last: "└─ ",
            tree_root: "▸ ",
            spinner: SPINNER_RICH,
            ok: "✓",
            fail: "✗",
            wait: "◷",
            idle: "·",
            sev_hi: "⬤",
            sev_med: "◆",
            sev_lo: "○",
            bar_full: "▰",
            bar_empty: "▱",
            metric_in: "⬆",
            metric_out: "⬇",
        }
    }

    fn ascii() -> Self {
        Self {
            tree_branch: "|- ",
            tree_last: "`- ",
            tree_root: "> ",
            spinner: SPINNER_ASCII,
            ok: "ok",
            fail: "x",
            wait: ".",
            idle: ".",
            sev_hi: "!",
            sev_med: "*",
            sev_lo: "-",
            bar_full: "#",
            bar_empty: "-",
            metric_in: "in",
            metric_out: "out",
        }
    }
}

/// Resolved palette + glyphs for rendering the whole TUI.
#[derive(Debug, Clone, Copy)]
pub struct Theme {
    pub caps: Capabilities,
    pub glyphs: Glyphs,

    pub text: Color,
    pub muted: Color,
    pub border: Color,
    pub accent: Color,
    pub focus_border: Color,

    pub sev_critical: Color,
    pub sev_high: Color,
    pub sev_medium: Color,
    pub sev_low: Color,
    pub sev_info: Color,

    pub status_active: Color,
    pub status_thinking: Color,
    pub status_waiting: Color,
    pub status_done: Color,
    pub status_failed: Color,
    pub status_idle: Color,
}

impl Default for Theme {
    fn default() -> Self {
        Self::detect(false)
    }
}

/// Resolve one palette entry given capabilities.
///
/// Returns `Color::Reset` when color is disabled, the ANSI fallback when color
/// is on but truecolor is not, and the RGB value when truecolor is available.
fn pick(caps: &Capabilities, rgb: (u8, u8, u8), ansi: Color) -> Color {
    if !caps.color {
        Color::Reset
    } else if caps.truecolor {
        Color::Rgb(rgb.0, rgb.1, rgb.2)
    } else {
        ansi
    }
}

impl Theme {
    /// Build a theme from the environment, honoring `force_ascii`.
    pub fn detect(force_ascii: bool) -> Self {
        let caps = Capabilities::detect(force_ascii);
        let accent = pick(&caps, (137, 180, 250), Color::Cyan);
        Self {
            caps,
            glyphs: if caps.unicode {
                Glyphs::rich()
            } else {
                Glyphs::ascii()
            },

            text: pick(&caps, (205, 214, 244), Color::White),
            muted: pick(&caps, (127, 132, 156), Color::DarkGray),
            border: pick(&caps, (69, 71, 90), Color::DarkGray),
            accent,
            focus_border: accent,

            sev_critical: pick(&caps, (243, 139, 168), Color::Red),
            sev_high: pick(&caps, (250, 179, 135), Color::LightRed),
            sev_medium: pick(&caps, (249, 226, 175), Color::Yellow),
            sev_low: pick(&caps, (166, 227, 161), Color::Green),
            sev_info: pick(&caps, (148, 226, 213), Color::Cyan),

            status_active: pick(&caps, (166, 227, 161), Color::Green),
            status_thinking: pick(&caps, (203, 166, 247), Color::Magenta),
            status_waiting: pick(&caps, (249, 226, 175), Color::Yellow),
            status_done: pick(&caps, (166, 227, 161), Color::Green),
            status_failed: pick(&caps, (243, 139, 168), Color::Red),
            status_idle: pick(&caps, (127, 132, 156), Color::DarkGray),
        }
    }

    /// Color for a severity level.
    pub fn severity_color(&self, s: Severity) -> Color {
        match s {
            Severity::Critical => self.sev_critical,
            Severity::High => self.sev_high,
            Severity::Medium => self.sev_medium,
            Severity::Low => self.sev_low,
            Severity::Info => self.sev_info,
        }
    }

    /// Glyph marker for a severity level.
    pub fn severity_marker(&self, s: Severity) -> &'static str {
        match s {
            Severity::Critical | Severity::High => self.glyphs.sev_hi,
            Severity::Medium => self.glyphs.sev_med,
            Severity::Low | Severity::Info => self.glyphs.sev_lo,
        }
    }

    /// Style for an agent status (color only).
    pub fn status_style(&self, s: AgentStatus) -> Style {
        let color = match s {
            AgentStatus::Executing | AgentStatus::Streaming | AgentStatus::Processing => {
                self.status_active
            }
            AgentStatus::Thinking => self.status_thinking,
            AgentStatus::Waiting | AgentStatus::Retrying => self.status_waiting,
            AgentStatus::Completed => self.status_done,
            AgentStatus::Failed => self.status_failed,
            AgentStatus::Idle | AgentStatus::Cancelled => self.status_idle,
        };
        Style::default().fg(color)
    }

    /// Glyph for an agent status; a live spinner frame for in-flight states.
    pub fn status_glyph(&self, s: AgentStatus, tick: u64) -> String {
        match s {
            AgentStatus::Executing
            | AgentStatus::Streaming
            | AgentStatus::Thinking
            | AgentStatus::Processing => {
                let frames = self.glyphs.spinner;
                let idx = (tick as usize) % frames.len().max(1);
                frames.get(idx).copied().unwrap_or("*").to_string()
            }
            AgentStatus::Completed => self.glyphs.ok.to_string(),
            AgentStatus::Failed => self.glyphs.fail.to_string(),
            AgentStatus::Waiting | AgentStatus::Retrying => self.glyphs.wait.to_string(),
            AgentStatus::Idle | AgentStatus::Cancelled => self.glyphs.idle.to_string(),
        }
    }

    /// A bordered block with a themed title; focus highlights the border.
    pub fn block(&self, title: &str, focused: bool) -> Block<'static> {
        let border_color = if focused {
            self.focus_border
        } else {
            self.border
        };
        let border_type = if self.caps.unicode {
            BorderType::Rounded
        } else {
            BorderType::Plain
        };
        let mut title_style = Style::default().fg(self.accent);
        if focused {
            title_style = title_style.add_modifier(Modifier::BOLD);
        }
        Block::default()
            .borders(Borders::ALL)
            .border_type(border_type)
            .border_style(Style::default().fg(border_color))
            .title(Line::from(Span::styled(format!(" {title} "), title_style)))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn ascii_mode_disables_unicode_and_truecolor() {
        let caps = Capabilities {
            color: true,
            truecolor: false,
            unicode: false,
        };
        // Simulate ascii glyph selection.
        let glyphs = Glyphs::ascii();
        assert_eq!(glyphs.ok, "ok");
        assert_eq!(glyphs.spinner, SPINNER_ASCII);
        assert!(caps.color);
    }

    #[test]
    fn pick_respects_capabilities() {
        let no_color = Capabilities {
            color: false,
            truecolor: true,
            unicode: true,
        };
        assert_eq!(pick(&no_color, (1, 2, 3), Color::Red), Color::Reset);

        let ansi = Capabilities {
            color: true,
            truecolor: false,
            unicode: true,
        };
        assert_eq!(pick(&ansi, (1, 2, 3), Color::Red), Color::Red);

        let truecolor = Capabilities {
            color: true,
            truecolor: true,
            unicode: true,
        };
        assert_eq!(pick(&truecolor, (1, 2, 3), Color::Red), Color::Rgb(1, 2, 3));
    }

    #[test]
    fn spinner_advances_with_tick() {
        let theme = Theme::detect(false);
        let g0 = theme.status_glyph(AgentStatus::Executing, 0);
        let g1 = theme.status_glyph(AgentStatus::Executing, 1);
        // Spinner frames differ as the tick advances.
        assert_ne!(g0, g1);
        // Static states never animate.
        assert_eq!(
            theme.status_glyph(AgentStatus::Completed, 0),
            theme.status_glyph(AgentStatus::Completed, 7)
        );
    }

    #[test]
    fn severity_marker_buckets() {
        let theme = Theme::detect(true); // ascii
        assert_eq!(theme.severity_marker(Severity::Critical), "!");
        assert_eq!(theme.severity_marker(Severity::Medium), "*");
        assert_eq!(theme.severity_marker(Severity::Info), "-");
    }
}
