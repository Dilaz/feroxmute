# Config Wizard Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement a TUI wizard that creates `~/.feroxmute/config.toml` with good defaults through an interactive, progressive flow.

**Architecture:** The wizard is a separate TUI module in feroxmute-cli that runs instead of the main app when `--wizard` is passed. It has its own state machine (WizardScreen enum), form data struct, and reusable input widgets. The generated config is saved with 0600 permissions.

**Tech Stack:** Rust, ratatui, crossterm (all already dependencies)

---

## Task 1: Add api_key field to ProviderConfig

**Files:**
- Modify: `feroxmute-core/src/config.rs:77-94`
- Modify: `feroxmute-core/src/providers/factory.rs:12-50`

**Step 1: Add api_key field to ProviderConfig struct**

In `feroxmute-core/src/config.rs`, update the `ProviderConfig` struct:

```rust
/// LLM provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderConfig {
    #[serde(default)]
    pub name: ProviderName,
    pub model: String,
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default)]
    pub base_url: Option<String>,
}

impl Default for ProviderConfig {
    fn default() -> Self {
        Self {
            name: ProviderName::Anthropic,
            model: "claude-sonnet-4-20250514".to_string(),
            api_key: None,
            base_url: None,
        }
    }
}
```

**Step 2: Update factory to use config api_key with env fallback**

In `feroxmute-core/src/providers/factory.rs`, update `create_provider`:

```rust
pub fn create_provider(
    config: &ProviderConfig,
    metrics: MetricsTracker,
) -> Result<Arc<dyn LlmProvider>> {
    match config.name {
        ProviderName::Anthropic => {
            // Use config api_key if set, otherwise fall back to env var
            if let Some(ref api_key) = config.api_key {
                std::env::set_var("ANTHROPIC_API_KEY", api_key);
            }
            let provider = AnthropicProvider::new(&config.model, metrics)?;
            Ok(Arc::new(provider))
        }
        ProviderName::OpenAi => {
            let api_key = config.api_key.clone()
                .or_else(|| std::env::var("OPENAI_API_KEY").ok())
                .ok_or_else(|| Error::Provider("OPENAI_API_KEY not set".to_string()))?;

            let provider = if let Some(ref base_url) = config.base_url {
                OpenAiProvider::with_base_url(api_key, base_url, &config.model, metrics)?
            } else {
                std::env::set_var("OPENAI_API_KEY", &api_key);
                OpenAiProvider::new(&config.model, metrics)?
            };
            Ok(Arc::new(provider))
        }
        ProviderName::LiteLlm => {
            let base_url = config
                .base_url
                .clone()
                .unwrap_or_else(|| "http://localhost:4000".to_string());
            let api_key = config.api_key.clone()
                .or_else(|| std::env::var("LITELLM_API_KEY").ok())
                .or_else(|| std::env::var("OPENAI_API_KEY").ok())
                .ok_or_else(|| Error::Provider("LITELLM_API_KEY or OPENAI_API_KEY not set".to_string()))?;
            let provider =
                OpenAiProvider::with_base_url(api_key, base_url, &config.model, metrics)?;
            Ok(Arc::new(provider))
        }
        ProviderName::Cohere => Err(Error::Provider(
            "Cohere provider not implemented".to_string(),
        )),
    }
}
```

**Step 3: Run tests**

```bash
cargo test -p feroxmute-core config
cargo test -p feroxmute-core factory
```

**Step 4: Commit**

```bash
git add feroxmute-core/src/config.rs feroxmute-core/src/providers/factory.rs
git commit -m "$(cat <<'EOF'
feat(core): add api_key field to ProviderConfig

Config can now store API key directly. Factory falls back to
environment variables if config api_key is not set.
EOF
)"
```

---

## Task 2: Add config loading cascade

**Files:**
- Modify: `feroxmute-core/src/config.rs`

**Step 1: Add load_default_config function**

Add this function to `feroxmute-core/src/config.rs`:

```rust
impl EngagementConfig {
    /// Load configuration from default locations with cascade:
    /// 1. ./feroxmute.toml (local override)
    /// 2. ~/.feroxmute/config.toml (global defaults)
    /// 3. Built-in defaults
    pub fn load_default() -> Self {
        // Try local config first
        if let Ok(config) = Self::from_file("feroxmute.toml") {
            return config;
        }

        // Try global config
        if let Some(home) = dirs::home_dir() {
            let global_path = home.join(".feroxmute").join("config.toml");
            if let Ok(config) = Self::from_file(&global_path) {
                return config;
            }
        }

        // Fall back to defaults (requires a target, so this is partial)
        Self {
            target: TargetConfig {
                host: String::new(),
                scope: Scope::default(),
                ports: Vec::new(),
            },
            constraints: Constraints::default(),
            auth: AuthConfig::default(),
            provider: ProviderConfig::default(),
            output: OutputConfig::default(),
        }
    }

    /// Get the path to the global config file
    pub fn global_config_path() -> Option<PathBuf> {
        dirs::home_dir().map(|h| h.join(".feroxmute").join("config.toml"))
    }
}
```

**Step 2: Add test for load_default**

```rust
#[test]
fn test_global_config_path() {
    let path = EngagementConfig::global_config_path();
    assert!(path.is_some());
    let path = path.unwrap();
    assert!(path.ends_with(".feroxmute/config.toml"));
}
```

**Step 3: Run tests**

```bash
cargo test -p feroxmute-core config
```

**Step 4: Commit**

```bash
git add feroxmute-core/src/config.rs
git commit -m "$(cat <<'EOF'
feat(core): add config loading cascade

Configs are loaded from: ./feroxmute.toml -> ~/.feroxmute/config.toml -> defaults
EOF
)"
```

---

## Task 3: Create wizard module structure

**Files:**
- Create: `feroxmute-cli/src/wizard/mod.rs`
- Create: `feroxmute-cli/src/wizard/state.rs`
- Modify: `feroxmute-cli/src/main.rs` (add mod declaration)

**Step 1: Create wizard/mod.rs**

```rust
//! Configuration wizard for feroxmute

mod state;

pub use state::{WizardData, WizardScreen};

use std::io::{self, stdout};
use std::path::PathBuf;

use crossterm::{
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};

use crate::tui::colors;

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
    use crossterm::event::{self, Event, KeyCode};
    use std::time::Duration;

    loop {
        terminal.draw(|frame| state.render(frame))?;

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
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
}
```

**Step 2: Create wizard/state.rs**

```rust
//! Wizard state management

use std::path::PathBuf;

use crossterm::event::{KeyCode, KeyEvent};
use feroxmute_core::config::{ProviderName, Scope};
use ratatui::Frame;

/// Which screen the wizard is on
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WizardScreen {
    #[default]
    Welcome,
    Provider,
    ApiKey,
    Scope,
    Constraints,
    AdvancedPrompt,
    Advanced,
    Review,
}

/// Form data collected by the wizard
#[derive(Debug, Clone, Default)]
pub struct WizardData {
    pub provider: ProviderName,
    pub api_key: String,
    pub model: Option<String>,
    pub base_url: Option<String>,
    pub scope: Scope,
    pub passive: bool,
    pub no_exploit: bool,
    pub no_portscan: bool,
    pub rate_limit: Option<u32>,
    pub export_html: bool,
    pub export_pdf: bool,
}

/// Action to take after handling input
pub enum WizardAction {
    Continue,
    Quit,
    Complete(PathBuf),
}

/// Wizard state machine
pub struct WizardState {
    pub screen: WizardScreen,
    pub data: WizardData,
    pub selected_index: usize,
    pub text_input: String,
    pub show_advanced: bool,
    pub error_message: Option<String>,
}

impl WizardState {
    pub fn new() -> Self {
        Self {
            screen: WizardScreen::Welcome,
            data: WizardData::default(),
            selected_index: 0,
            text_input: String::new(),
            show_advanced: false,
            error_message: None,
        }
    }

    pub fn render(&self, frame: &mut Frame) {
        // Placeholder - will be implemented in later tasks
        use ratatui::widgets::{Block, Borders, Paragraph};
        let block = Block::default()
            .borders(Borders::ALL)
            .title(" Feroxmute Setup ");
        let text = format!("Screen: {:?}\nPress Enter to continue, q to quit", self.screen);
        let para = Paragraph::new(text).block(block);
        frame.render_widget(para, frame.area());
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> WizardAction {
        // Handle quit
        if key.code == KeyCode::Char('q') && self.screen == WizardScreen::Welcome {
            return WizardAction::Quit;
        }

        match key.code {
            KeyCode::Enter => self.next_screen(),
            KeyCode::Esc => self.prev_screen(),
            _ => WizardAction::Continue,
        }
    }

    fn next_screen(&mut self) -> WizardAction {
        self.screen = match self.screen {
            WizardScreen::Welcome => WizardScreen::Provider,
            WizardScreen::Provider => WizardScreen::ApiKey,
            WizardScreen::ApiKey => WizardScreen::Scope,
            WizardScreen::Scope => WizardScreen::Constraints,
            WizardScreen::Constraints => WizardScreen::AdvancedPrompt,
            WizardScreen::AdvancedPrompt => {
                if self.show_advanced {
                    WizardScreen::Advanced
                } else {
                    WizardScreen::Review
                }
            }
            WizardScreen::Advanced => WizardScreen::Review,
            WizardScreen::Review => {
                // Save config and return path
                match self.save_config() {
                    Ok(path) => return WizardAction::Complete(path),
                    Err(e) => {
                        self.error_message = Some(e.to_string());
                        return WizardAction::Continue;
                    }
                }
            }
        };
        self.selected_index = 0;
        WizardAction::Continue
    }

    fn prev_screen(&mut self) -> WizardAction {
        self.screen = match self.screen {
            WizardScreen::Welcome => return WizardAction::Quit,
            WizardScreen::Provider => WizardScreen::Welcome,
            WizardScreen::ApiKey => WizardScreen::Provider,
            WizardScreen::Scope => WizardScreen::ApiKey,
            WizardScreen::Constraints => WizardScreen::Scope,
            WizardScreen::AdvancedPrompt => WizardScreen::Constraints,
            WizardScreen::Advanced => WizardScreen::AdvancedPrompt,
            WizardScreen::Review => {
                if self.show_advanced {
                    WizardScreen::Advanced
                } else {
                    WizardScreen::AdvancedPrompt
                }
            }
        };
        WizardAction::Continue
    }

    fn save_config(&self) -> anyhow::Result<PathBuf> {
        use feroxmute_core::config::EngagementConfig;
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        let config_dir = dirs::home_dir()
            .ok_or_else(|| anyhow::anyhow!("Could not find home directory"))?
            .join(".feroxmute");

        fs::create_dir_all(&config_dir)?;

        let config_path = config_dir.join("config.toml");
        let content = self.generate_toml();

        fs::write(&config_path, &content)?;

        // Set file permissions to 0600 (owner read/write only)
        #[cfg(unix)]
        {
            let mut perms = fs::metadata(&config_path)?.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(&config_path, perms)?;
        }

        Ok(config_path)
    }

    fn generate_toml(&self) -> String {
        let mut toml = String::new();
        toml.push_str("# Feroxmute default configuration\n");
        toml.push_str(&format!(
            "# Generated by wizard on {}\n",
            chrono::Local::now().format("%Y-%m-%d")
        ));
        toml.push_str("# Override per-engagement with --config or CLI flags\n\n");

        toml.push_str("[provider]\n");
        toml.push_str(&format!("name = \"{}\"\n", provider_name_str(&self.data.provider)));
        toml.push_str(&format!("api_key = \"{}\"\n", self.data.api_key));
        let model = self.data.model.clone().unwrap_or_else(|| default_model(&self.data.provider));
        toml.push_str(&format!("model = \"{}\"\n", model));
        if let Some(ref url) = self.data.base_url {
            toml.push_str(&format!("base_url = \"{}\"\n", url));
        }

        toml.push_str("\n[target]\n");
        toml.push_str(&format!("# Default scope for new engagements\nscope = \"{}\"\n",
            scope_str(&self.data.scope)));

        toml.push_str("\n[constraints]\n");
        toml.push_str(&format!("passive = {}\n", self.data.passive));
        toml.push_str(&format!("no_exploit = {}\n", self.data.no_exploit));
        toml.push_str(&format!("no_portscan = {}\n", self.data.no_portscan));
        if let Some(rate) = self.data.rate_limit {
            toml.push_str(&format!("rate_limit = {}\n", rate));
        } else {
            toml.push_str("# rate_limit = 10  # Uncomment to limit requests/sec\n");
        }

        toml.push_str("\n[output]\n");
        toml.push_str(&format!("export_html = {}\n", self.data.export_html));
        toml.push_str(&format!("export_pdf = {}\n", self.data.export_pdf));

        toml
    }
}

fn provider_name_str(p: &ProviderName) -> &'static str {
    match p {
        ProviderName::Anthropic => "anthropic",
        ProviderName::OpenAi => "openai",
        ProviderName::LiteLlm => "litellm",
        ProviderName::Cohere => "cohere",
    }
}

fn scope_str(s: &Scope) -> &'static str {
    match s {
        Scope::Web => "web",
        Scope::Network => "network",
        Scope::Full => "full",
    }
}

fn default_model(p: &ProviderName) -> String {
    match p {
        ProviderName::Anthropic => "claude-sonnet-4-20250514".to_string(),
        ProviderName::OpenAi => "gpt-4o".to_string(),
        ProviderName::LiteLlm => "gpt-4o".to_string(),
        ProviderName::Cohere => "command".to_string(),
    }
}
```

**Step 3: Add mod declaration and chrono dependency**

In `feroxmute-cli/src/main.rs`, add after line 2:
```rust
mod wizard;
```

In `feroxmute-cli/Cargo.toml`, add to dependencies:
```toml
chrono = "0.4"
```

**Step 4: Build to verify**

```bash
cargo build -p feroxmute-cli
```

**Step 5: Commit**

```bash
git add feroxmute-cli/src/wizard/ feroxmute-cli/src/main.rs feroxmute-cli/Cargo.toml
git commit -m "$(cat <<'EOF'
feat(cli): add wizard module skeleton

Basic state machine with screen navigation and config generation.
Actual screen rendering to be implemented next.
EOF
)"
```

---

## Task 4: Implement text input widget

**Files:**
- Create: `feroxmute-cli/src/wizard/widgets.rs`
- Modify: `feroxmute-cli/src/wizard/mod.rs`

**Step 1: Create widgets.rs with TextInput**

```rust
//! Reusable TUI widgets for the wizard

use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

/// Text input widget with cursor and optional masking
pub struct TextInput<'a> {
    value: &'a str,
    cursor_pos: usize,
    placeholder: &'a str,
    masked: bool,
    focused: bool,
    label: &'a str,
}

impl<'a> TextInput<'a> {
    pub fn new(value: &'a str, cursor_pos: usize) -> Self {
        Self {
            value,
            cursor_pos,
            placeholder: "",
            masked: false,
            focused: false,
            label: "",
        }
    }

    pub fn placeholder(mut self, placeholder: &'a str) -> Self {
        self.placeholder = placeholder;
        self
    }

    pub fn masked(mut self, masked: bool) -> Self {
        self.masked = masked;
        self
    }

    pub fn focused(mut self, focused: bool) -> Self {
        self.focused = focused;
        self
    }

    pub fn label(mut self, label: &'a str) -> Self {
        self.label = label;
        self
    }

    pub fn render(self, frame: &mut Frame, area: Rect) {
        let display_value = if self.value.is_empty() {
            Span::styled(self.placeholder, Style::default().fg(Color::DarkGray))
        } else if self.masked {
            Span::raw("•".repeat(self.value.len()))
        } else {
            Span::raw(self.value)
        };

        let border_color = if self.focused {
            Color::Cyan
        } else {
            Color::DarkGray
        };

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(border_color))
            .title(format!(" {} ", self.label));

        let para = Paragraph::new(Line::from(display_value)).block(block);
        frame.render_widget(para, area);

        // Show cursor when focused
        if self.focused && !self.value.is_empty() {
            let cursor_x = area.x + 1 + self.cursor_pos.min(self.value.len()) as u16;
            let cursor_y = area.y + 1;
            frame.set_cursor_position((cursor_x, cursor_y));
        } else if self.focused && self.value.is_empty() {
            frame.set_cursor_position((area.x + 1, area.y + 1));
        }
    }
}

/// Selection list widget
pub struct SelectList<'a> {
    items: &'a [&'a str],
    selected: usize,
    focused: bool,
    label: &'a str,
}

impl<'a> SelectList<'a> {
    pub fn new(items: &'a [&'a str], selected: usize) -> Self {
        Self {
            items,
            selected,
            focused: false,
            label: "",
        }
    }

    pub fn focused(mut self, focused: bool) -> Self {
        self.focused = focused;
        self
    }

    pub fn label(mut self, label: &'a str) -> Self {
        self.label = label;
        self
    }

    pub fn render(self, frame: &mut Frame, area: Rect) {
        let border_color = if self.focused {
            Color::Cyan
        } else {
            Color::DarkGray
        };

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(border_color))
            .title(format!(" {} ", self.label));

        let lines: Vec<Line> = self
            .items
            .iter()
            .enumerate()
            .map(|(i, item)| {
                let prefix = if i == self.selected { "› " } else { "  " };
                let style = if i == self.selected {
                    Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                };
                Line::from(Span::styled(format!("{}{}", prefix, item), style))
            })
            .collect();

        let para = Paragraph::new(lines).block(block);
        frame.render_widget(para, area);
    }
}

/// Checkbox group widget
pub struct CheckboxGroup<'a> {
    items: &'a [(&'a str, bool)],
    selected: usize,
    focused: bool,
    label: &'a str,
}

impl<'a> CheckboxGroup<'a> {
    pub fn new(items: &'a [(&'a str, bool)], selected: usize) -> Self {
        Self {
            items,
            selected,
            focused: false,
            label: "",
        }
    }

    pub fn focused(mut self, focused: bool) -> Self {
        self.focused = focused;
        self
    }

    pub fn label(mut self, label: &'a str) -> Self {
        self.label = label;
        self
    }

    pub fn render(self, frame: &mut Frame, area: Rect) {
        let border_color = if self.focused {
            Color::Cyan
        } else {
            Color::DarkGray
        };

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(border_color))
            .title(format!(" {} ", self.label));

        let lines: Vec<Line> = self
            .items
            .iter()
            .enumerate()
            .map(|(i, (label, checked))| {
                let checkbox = if *checked { "[x]" } else { "[ ]" };
                let prefix = if i == self.selected { "› " } else { "  " };
                let style = if i == self.selected {
                    Style::default().fg(Color::Cyan)
                } else {
                    Style::default()
                };
                Line::from(Span::styled(format!("{}{} {}", prefix, checkbox, label), style))
            })
            .collect();

        let para = Paragraph::new(lines).block(block);
        frame.render_widget(para, area);
    }
}
```

**Step 2: Add mod declaration in wizard/mod.rs**

After `mod state;` add:
```rust
mod widgets;
```

**Step 3: Build to verify**

```bash
cargo build -p feroxmute-cli
```

**Step 4: Commit**

```bash
git add feroxmute-cli/src/wizard/widgets.rs feroxmute-cli/src/wizard/mod.rs
git commit -m "$(cat <<'EOF'
feat(cli): add wizard input widgets

TextInput (with masking), SelectList, and CheckboxGroup widgets
for use in wizard screens.
EOF
)"
```

---

## Task 5: Implement Welcome screen

**Files:**
- Create: `feroxmute-cli/src/wizard/screens.rs`
- Modify: `feroxmute-cli/src/wizard/mod.rs`
- Modify: `feroxmute-cli/src/wizard/state.rs`

**Step 1: Create screens.rs with welcome screen**

```rust
//! Wizard screen renderers

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

use super::state::WizardState;
use super::widgets::{CheckboxGroup, SelectList, TextInput};

/// Render the welcome screen
pub fn render_welcome(frame: &mut Frame, _state: &WizardState) {
    let area = centered_rect(60, 50, frame.area());

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .title(" Feroxmute Setup ");

    let text = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  Welcome to Feroxmute!",
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from("  This wizard will help you create a configuration file"),
        Line::from("  with sensible defaults for your penetration testing."),
        Line::from(""),
        Line::from("  The config will be saved to:"),
        Line::from(Span::styled(
            "  ~/.feroxmute/config.toml",
            Style::default().fg(Color::Yellow),
        )),
        Line::from(""),
        Line::from(""),
        Line::from(vec![
            Span::styled("  Press ", Style::default().fg(Color::DarkGray)),
            Span::styled("Enter", Style::default().fg(Color::Green)),
            Span::styled(" to continue or ", Style::default().fg(Color::DarkGray)),
            Span::styled("q", Style::default().fg(Color::Red)),
            Span::styled(" to quit", Style::default().fg(Color::DarkGray)),
        ]),
    ];

    let para = Paragraph::new(text).block(block);
    frame.render_widget(para, area);
}

/// Helper to create a centered rectangle
pub fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

/// Standard screen layout with title, content, and footer
pub fn screen_layout(frame: &mut Frame, title: &str) -> (Rect, Rect, Rect) {
    let area = centered_rect(70, 70, frame.area());

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .title(format!(" {} ", title));

    frame.render_widget(block, area);

    let inner = Block::default().borders(Borders::ALL).inner(area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Title/description
            Constraint::Min(5),    // Content
            Constraint::Length(2), // Footer
        ])
        .split(inner);

    (chunks[0], chunks[1], chunks[2])
}

/// Render footer with keybindings
pub fn render_footer(frame: &mut Frame, area: Rect, can_go_back: bool) {
    let mut spans = vec![
        Span::styled("Enter", Style::default().fg(Color::Green)),
        Span::raw(" continue  "),
    ];

    if can_go_back {
        spans.extend([
            Span::styled("Esc", Style::default().fg(Color::Yellow)),
            Span::raw(" back  "),
        ]);
    }

    spans.extend([
        Span::styled("q", Style::default().fg(Color::Red)),
        Span::raw(" quit"),
    ]);

    let footer = Paragraph::new(Line::from(spans))
        .style(Style::default().fg(Color::DarkGray));
    frame.render_widget(footer, area);
}
```

**Step 2: Update wizard/mod.rs**

Add after `mod widgets;`:
```rust
mod screens;
```

**Step 3: Update state.rs render method**

Replace the placeholder `render` method in `WizardState`:

```rust
pub fn render(&self, frame: &mut Frame) {
    match self.screen {
        WizardScreen::Welcome => screens::render_welcome(frame, self),
        _ => {
            // Placeholder for other screens
            use ratatui::widgets::{Block, Borders, Paragraph};
            let block = Block::default()
                .borders(Borders::ALL)
                .title(" Feroxmute Setup ");
            let text = format!("Screen: {:?}\nPress Enter to continue, Esc to go back", self.screen);
            let para = Paragraph::new(text).block(block);
            frame.render_widget(para, frame.area());
        }
    }
}
```

Add import at top of state.rs:
```rust
use super::screens;
```

**Step 4: Build and manually test**

```bash
cargo build -p feroxmute-cli
cargo run -p feroxmute-cli -- --wizard
```

**Step 5: Commit**

```bash
git add feroxmute-cli/src/wizard/
git commit -m "$(cat <<'EOF'
feat(cli): implement wizard welcome screen

First screen of the wizard with centered layout and keybinding hints.
EOF
)"
```

---

## Task 6: Implement Provider selection screen

**Files:**
- Modify: `feroxmute-cli/src/wizard/screens.rs`
- Modify: `feroxmute-cli/src/wizard/state.rs`

**Step 1: Add render_provider to screens.rs**

```rust
/// Render the provider selection screen
pub fn render_provider(frame: &mut Frame, state: &WizardState) {
    let (title_area, content_area, footer_area) = screen_layout(frame, "Feroxmute Setup");

    // Title
    let title = Paragraph::new(Line::from(vec![
        Span::styled("Step 1: ", Style::default().fg(Color::DarkGray)),
        Span::styled("Select LLM Provider", Style::default().add_modifier(Modifier::BOLD)),
    ]));
    frame.render_widget(title, title_area);

    // Provider list
    let providers = ["Anthropic (Recommended)", "OpenAI", "LiteLLM (Local proxy)"];
    let list = SelectList::new(&providers, state.selected_index)
        .focused(true)
        .label("Provider");

    let list_area = Rect {
        x: content_area.x + 2,
        y: content_area.y + 1,
        width: content_area.width.saturating_sub(4),
        height: 5,
    };
    list.render(frame, list_area);

    render_footer(frame, footer_area, true);
}
```

**Step 2: Update state.rs to handle provider selection**

Add to imports at top:
```rust
use crossterm::event::KeyModifiers;
```

Update `handle_key` method:

```rust
pub fn handle_key(&mut self, key: KeyEvent) -> WizardAction {
    // Global quit on Ctrl+C
    if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
        return WizardAction::Quit;
    }

    // Screen-specific handling
    match self.screen {
        WizardScreen::Welcome => {
            match key.code {
                KeyCode::Char('q') => return WizardAction::Quit,
                KeyCode::Enter => return self.next_screen(),
                _ => {}
            }
        }
        WizardScreen::Provider => {
            match key.code {
                KeyCode::Char('q') => return WizardAction::Quit,
                KeyCode::Up | KeyCode::Char('k') => {
                    self.selected_index = self.selected_index.saturating_sub(1);
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    self.selected_index = (self.selected_index + 1).min(2);
                }
                KeyCode::Enter => {
                    self.data.provider = match self.selected_index {
                        0 => ProviderName::Anthropic,
                        1 => ProviderName::OpenAi,
                        _ => ProviderName::LiteLlm,
                    };
                    return self.next_screen();
                }
                KeyCode::Esc => return self.prev_screen(),
                _ => {}
            }
        }
        _ => {
            match key.code {
                KeyCode::Char('q') => return WizardAction::Quit,
                KeyCode::Enter => return self.next_screen(),
                KeyCode::Esc => return self.prev_screen(),
                _ => {}
            }
        }
    }
    WizardAction::Continue
}
```

Update `render` method to include provider:

```rust
pub fn render(&self, frame: &mut Frame) {
    match self.screen {
        WizardScreen::Welcome => screens::render_welcome(frame, self),
        WizardScreen::Provider => screens::render_provider(frame, self),
        _ => {
            // Placeholder for other screens
            use ratatui::widgets::{Block, Borders, Paragraph};
            let block = Block::default()
                .borders(Borders::ALL)
                .title(" Feroxmute Setup ");
            let text = format!("Screen: {:?}\nPress Enter to continue, Esc to go back", self.screen);
            let para = Paragraph::new(text).block(block);
            frame.render_widget(para, frame.area());
        }
    }
}
```

**Step 3: Build and test**

```bash
cargo build -p feroxmute-cli
cargo run -p feroxmute-cli -- --wizard
```

**Step 4: Commit**

```bash
git add feroxmute-cli/src/wizard/
git commit -m "$(cat <<'EOF'
feat(cli): implement wizard provider selection screen

Arrow key navigation to select LLM provider.
EOF
)"
```

---

## Task 7: Implement API key input screen

**Files:**
- Modify: `feroxmute-cli/src/wizard/screens.rs`
- Modify: `feroxmute-cli/src/wizard/state.rs`

**Step 1: Add render_api_key to screens.rs**

```rust
/// Render the API key input screen
pub fn render_api_key(frame: &mut Frame, state: &WizardState) {
    let (title_area, content_area, footer_area) = screen_layout(frame, "Feroxmute Setup");

    let provider_name = match state.data.provider {
        feroxmute_core::config::ProviderName::Anthropic => "Anthropic",
        feroxmute_core::config::ProviderName::OpenAi => "OpenAI",
        feroxmute_core::config::ProviderName::LiteLlm => "LiteLLM",
        feroxmute_core::config::ProviderName::Cohere => "Cohere",
    };

    // Title
    let title = Paragraph::new(Line::from(vec![
        Span::styled("Step 2: ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!("Enter {} API Key", provider_name),
            Style::default().add_modifier(Modifier::BOLD),
        ),
    ]));
    frame.render_widget(title, title_area);

    // Warning
    let warning_area = Rect {
        x: content_area.x + 2,
        y: content_area.y,
        width: content_area.width.saturating_sub(4),
        height: 2,
    };
    let warning = Paragraph::new(Line::from(vec![
        Span::styled("⚠ ", Style::default().fg(Color::Yellow)),
        Span::styled(
            "API key will be stored in config. Ensure ~/.feroxmute/ is not shared.",
            Style::default().fg(Color::Yellow),
        ),
    ]));
    frame.render_widget(warning, warning_area);

    // API key input
    let input_area = Rect {
        x: content_area.x + 2,
        y: content_area.y + 3,
        width: content_area.width.saturating_sub(4),
        height: 3,
    };

    let placeholder = match state.data.provider {
        feroxmute_core::config::ProviderName::Anthropic => "sk-ant-...",
        feroxmute_core::config::ProviderName::OpenAi => "sk-...",
        feroxmute_core::config::ProviderName::LiteLlm => "your-api-key",
        _ => "api-key",
    };

    let input = TextInput::new(&state.text_input, state.cursor_position)
        .placeholder(placeholder)
        .masked(true)
        .focused(true)
        .label("API Key");
    input.render(frame, input_area);

    render_footer(frame, footer_area, true);
}
```

**Step 2: Add cursor_position field to WizardState**

In state.rs, add field to WizardState struct:
```rust
pub struct WizardState {
    pub screen: WizardScreen,
    pub data: WizardData,
    pub selected_index: usize,
    pub text_input: String,
    pub cursor_position: usize,
    pub show_advanced: bool,
    pub error_message: Option<String>,
}
```

Update `new()`:
```rust
impl WizardState {
    pub fn new() -> Self {
        Self {
            screen: WizardScreen::Welcome,
            data: WizardData::default(),
            selected_index: 0,
            text_input: String::new(),
            cursor_position: 0,
            show_advanced: false,
            error_message: None,
        }
    }
```

**Step 3: Handle text input in state.rs**

Add to `handle_key` match for `WizardScreen::ApiKey`:

```rust
WizardScreen::ApiKey => {
    match key.code {
        KeyCode::Char('q') if self.text_input.is_empty() => return WizardAction::Quit,
        KeyCode::Char(c) => {
            self.text_input.insert(self.cursor_position, c);
            self.cursor_position += 1;
        }
        KeyCode::Backspace => {
            if self.cursor_position > 0 {
                self.cursor_position -= 1;
                self.text_input.remove(self.cursor_position);
            }
        }
        KeyCode::Delete => {
            if self.cursor_position < self.text_input.len() {
                self.text_input.remove(self.cursor_position);
            }
        }
        KeyCode::Left => {
            self.cursor_position = self.cursor_position.saturating_sub(1);
        }
        KeyCode::Right => {
            self.cursor_position = (self.cursor_position + 1).min(self.text_input.len());
        }
        KeyCode::Home => {
            self.cursor_position = 0;
        }
        KeyCode::End => {
            self.cursor_position = self.text_input.len();
        }
        KeyCode::Enter => {
            if !self.text_input.is_empty() {
                self.data.api_key = self.text_input.clone();
                self.text_input.clear();
                self.cursor_position = 0;
                return self.next_screen();
            }
        }
        KeyCode::Esc => {
            self.text_input.clear();
            self.cursor_position = 0;
            return self.prev_screen();
        }
        _ => {}
    }
}
```

Update `render` to include ApiKey:
```rust
WizardScreen::ApiKey => screens::render_api_key(frame, self),
```

**Step 4: Build and test**

```bash
cargo build -p feroxmute-cli
cargo run -p feroxmute-cli -- --wizard
```

**Step 5: Commit**

```bash
git add feroxmute-cli/src/wizard/
git commit -m "$(cat <<'EOF'
feat(cli): implement wizard API key input screen

Masked text input with cursor navigation for entering API keys.
EOF
)"
```

---

## Task 8: Implement remaining screens

**Files:**
- Modify: `feroxmute-cli/src/wizard/screens.rs`
- Modify: `feroxmute-cli/src/wizard/state.rs`

**Step 1: Add scope, constraints, advanced prompt, advanced, and review screens**

Add to screens.rs:

```rust
/// Render the scope selection screen
pub fn render_scope(frame: &mut Frame, state: &WizardState) {
    let (title_area, content_area, footer_area) = screen_layout(frame, "Feroxmute Setup");

    let title = Paragraph::new(Line::from(vec![
        Span::styled("Step 3: ", Style::default().fg(Color::DarkGray)),
        Span::styled("Default Testing Scope", Style::default().add_modifier(Modifier::BOLD)),
    ]));
    frame.render_widget(title, title_area);

    let scopes = ["Web (HTTP/HTTPS only)", "Network (ports, services)", "Full (web + network)"];
    let list = SelectList::new(&scopes, state.selected_index)
        .focused(true)
        .label("Scope");

    let list_area = Rect {
        x: content_area.x + 2,
        y: content_area.y + 1,
        width: content_area.width.saturating_sub(4),
        height: 5,
    };
    list.render(frame, list_area);

    render_footer(frame, footer_area, true);
}

/// Render the constraints selection screen
pub fn render_constraints(frame: &mut Frame, state: &WizardState) {
    let (title_area, content_area, footer_area) = screen_layout(frame, "Feroxmute Setup");

    let title = Paragraph::new(Line::from(vec![
        Span::styled("Step 4: ", Style::default().fg(Color::DarkGray)),
        Span::styled("Default Constraints", Style::default().add_modifier(Modifier::BOLD)),
    ]));
    frame.render_widget(title, title_area);

    let items = [
        ("Passive only (no active probing)", state.data.passive),
        ("No exploitation (recon/scan only)", state.data.no_exploit),
        ("No port scanning", state.data.no_portscan),
    ];
    let checkbox = CheckboxGroup::new(&items, state.selected_index)
        .focused(true)
        .label("Constraints (Space to toggle)");

    let list_area = Rect {
        x: content_area.x + 2,
        y: content_area.y + 1,
        width: content_area.width.saturating_sub(4),
        height: 5,
    };
    checkbox.render(frame, list_area);

    render_footer(frame, footer_area, true);
}

/// Render the advanced prompt screen
pub fn render_advanced_prompt(frame: &mut Frame, state: &WizardState) {
    let (title_area, content_area, footer_area) = screen_layout(frame, "Feroxmute Setup");

    let title = Paragraph::new(Line::from(vec![
        Span::styled("Step 5: ", Style::default().fg(Color::DarkGray)),
        Span::styled("Advanced Options", Style::default().add_modifier(Modifier::BOLD)),
    ]));
    frame.render_widget(title, title_area);

    let options = ["Skip (use defaults)", "Configure advanced options"];
    let list = SelectList::new(&options, state.selected_index)
        .focused(true)
        .label("Advanced Configuration");

    let list_area = Rect {
        x: content_area.x + 2,
        y: content_area.y + 1,
        width: content_area.width.saturating_sub(4),
        height: 4,
    };
    list.render(frame, list_area);

    render_footer(frame, footer_area, true);
}

/// Render the advanced options screen
pub fn render_advanced(frame: &mut Frame, state: &WizardState) {
    let (title_area, content_area, footer_area) = screen_layout(frame, "Feroxmute Setup");

    let title = Paragraph::new(Line::from(vec![
        Span::styled("Step 5: ", Style::default().fg(Color::DarkGray)),
        Span::styled("Advanced Options", Style::default().add_modifier(Modifier::BOLD)),
    ]));
    frame.render_widget(title, title_area);

    let items = [
        ("Export HTML reports", state.data.export_html),
        ("Export PDF reports", state.data.export_pdf),
    ];
    let checkbox = CheckboxGroup::new(&items, state.selected_index)
        .focused(true)
        .label("Output Options (Space to toggle)");

    let list_area = Rect {
        x: content_area.x + 2,
        y: content_area.y + 1,
        width: content_area.width.saturating_sub(4),
        height: 4,
    };
    checkbox.render(frame, list_area);

    render_footer(frame, footer_area, true);
}

/// Render the review screen
pub fn render_review(frame: &mut Frame, state: &WizardState) {
    let (title_area, content_area, footer_area) = screen_layout(frame, "Feroxmute Setup");

    let title = Paragraph::new(Line::from(vec![
        Span::styled("Review: ", Style::default().fg(Color::DarkGray)),
        Span::styled("Configuration Summary", Style::default().add_modifier(Modifier::BOLD)),
    ]));
    frame.render_widget(title, title_area);

    let provider_name = match state.data.provider {
        feroxmute_core::config::ProviderName::Anthropic => "Anthropic",
        feroxmute_core::config::ProviderName::OpenAi => "OpenAI",
        feroxmute_core::config::ProviderName::LiteLlm => "LiteLLM",
        feroxmute_core::config::ProviderName::Cohere => "Cohere",
    };

    let scope_name = match state.data.scope {
        feroxmute_core::config::Scope::Web => "Web",
        feroxmute_core::config::Scope::Network => "Network",
        feroxmute_core::config::Scope::Full => "Full",
    };

    let api_key_display = if state.data.api_key.len() > 8 {
        format!("{}...{}", &state.data.api_key[..4], &state.data.api_key[state.data.api_key.len()-4..])
    } else {
        "****".to_string()
    };

    let lines = vec![
        Line::from(vec![
            Span::styled("  Provider:    ", Style::default().fg(Color::DarkGray)),
            Span::raw(provider_name),
        ]),
        Line::from(vec![
            Span::styled("  API Key:     ", Style::default().fg(Color::DarkGray)),
            Span::raw(api_key_display),
        ]),
        Line::from(vec![
            Span::styled("  Scope:       ", Style::default().fg(Color::DarkGray)),
            Span::raw(scope_name),
        ]),
        Line::from(vec![
            Span::styled("  Passive:     ", Style::default().fg(Color::DarkGray)),
            Span::raw(if state.data.passive { "Yes" } else { "No" }),
        ]),
        Line::from(vec![
            Span::styled("  No Exploit:  ", Style::default().fg(Color::DarkGray)),
            Span::raw(if state.data.no_exploit { "Yes" } else { "No" }),
        ]),
        Line::from(vec![
            Span::styled("  No Portscan: ", Style::default().fg(Color::DarkGray)),
            Span::raw(if state.data.no_portscan { "Yes" } else { "No" }),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  Config will be saved to: ", Style::default().fg(Color::DarkGray)),
        ]),
        Line::from(Span::styled(
            "  ~/.feroxmute/config.toml",
            Style::default().fg(Color::Yellow),
        )),
    ];

    let summary = Paragraph::new(lines);
    frame.render_widget(summary, content_area);

    // Custom footer for review
    let footer = Paragraph::new(Line::from(vec![
        Span::styled("Enter", Style::default().fg(Color::Green)),
        Span::raw(" save config  "),
        Span::styled("Esc", Style::default().fg(Color::Yellow)),
        Span::raw(" back  "),
        Span::styled("q", Style::default().fg(Color::Red)),
        Span::raw(" quit"),
    ]))
    .style(Style::default().fg(Color::DarkGray));
    frame.render_widget(footer, footer_area);
}
```

**Step 2: Update state.rs render and handle_key for all screens**

Update the `render` method:
```rust
pub fn render(&self, frame: &mut Frame) {
    match self.screen {
        WizardScreen::Welcome => screens::render_welcome(frame, self),
        WizardScreen::Provider => screens::render_provider(frame, self),
        WizardScreen::ApiKey => screens::render_api_key(frame, self),
        WizardScreen::Scope => screens::render_scope(frame, self),
        WizardScreen::Constraints => screens::render_constraints(frame, self),
        WizardScreen::AdvancedPrompt => screens::render_advanced_prompt(frame, self),
        WizardScreen::Advanced => screens::render_advanced(frame, self),
        WizardScreen::Review => screens::render_review(frame, self),
    }
}
```

Update `handle_key` to handle all screens:
```rust
pub fn handle_key(&mut self, key: KeyEvent) -> WizardAction {
    if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
        return WizardAction::Quit;
    }

    match self.screen {
        WizardScreen::Welcome => {
            match key.code {
                KeyCode::Char('q') => return WizardAction::Quit,
                KeyCode::Enter => return self.next_screen(),
                _ => {}
            }
        }
        WizardScreen::Provider => {
            match key.code {
                KeyCode::Char('q') => return WizardAction::Quit,
                KeyCode::Up | KeyCode::Char('k') => {
                    self.selected_index = self.selected_index.saturating_sub(1);
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    self.selected_index = (self.selected_index + 1).min(2);
                }
                KeyCode::Enter => {
                    self.data.provider = match self.selected_index {
                        0 => ProviderName::Anthropic,
                        1 => ProviderName::OpenAi,
                        _ => ProviderName::LiteLlm,
                    };
                    return self.next_screen();
                }
                KeyCode::Esc => return self.prev_screen(),
                _ => {}
            }
        }
        WizardScreen::ApiKey => {
            match key.code {
                KeyCode::Char('q') if self.text_input.is_empty() => return WizardAction::Quit,
                KeyCode::Char(c) => {
                    self.text_input.insert(self.cursor_position, c);
                    self.cursor_position += 1;
                }
                KeyCode::Backspace => {
                    if self.cursor_position > 0 {
                        self.cursor_position -= 1;
                        self.text_input.remove(self.cursor_position);
                    }
                }
                KeyCode::Delete => {
                    if self.cursor_position < self.text_input.len() {
                        self.text_input.remove(self.cursor_position);
                    }
                }
                KeyCode::Left => {
                    self.cursor_position = self.cursor_position.saturating_sub(1);
                }
                KeyCode::Right => {
                    self.cursor_position = (self.cursor_position + 1).min(self.text_input.len());
                }
                KeyCode::Home => {
                    self.cursor_position = 0;
                }
                KeyCode::End => {
                    self.cursor_position = self.text_input.len();
                }
                KeyCode::Enter => {
                    if !self.text_input.is_empty() {
                        self.data.api_key = self.text_input.clone();
                        self.text_input.clear();
                        self.cursor_position = 0;
                        return self.next_screen();
                    }
                }
                KeyCode::Esc => {
                    self.text_input.clear();
                    self.cursor_position = 0;
                    return self.prev_screen();
                }
                _ => {}
            }
        }
        WizardScreen::Scope => {
            match key.code {
                KeyCode::Char('q') => return WizardAction::Quit,
                KeyCode::Up | KeyCode::Char('k') => {
                    self.selected_index = self.selected_index.saturating_sub(1);
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    self.selected_index = (self.selected_index + 1).min(2);
                }
                KeyCode::Enter => {
                    self.data.scope = match self.selected_index {
                        0 => Scope::Web,
                        1 => Scope::Network,
                        _ => Scope::Full,
                    };
                    return self.next_screen();
                }
                KeyCode::Esc => return self.prev_screen(),
                _ => {}
            }
        }
        WizardScreen::Constraints => {
            match key.code {
                KeyCode::Char('q') => return WizardAction::Quit,
                KeyCode::Up | KeyCode::Char('k') => {
                    self.selected_index = self.selected_index.saturating_sub(1);
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    self.selected_index = (self.selected_index + 1).min(2);
                }
                KeyCode::Char(' ') => {
                    match self.selected_index {
                        0 => self.data.passive = !self.data.passive,
                        1 => self.data.no_exploit = !self.data.no_exploit,
                        2 => self.data.no_portscan = !self.data.no_portscan,
                        _ => {}
                    }
                }
                KeyCode::Enter => return self.next_screen(),
                KeyCode::Esc => return self.prev_screen(),
                _ => {}
            }
        }
        WizardScreen::AdvancedPrompt => {
            match key.code {
                KeyCode::Char('q') => return WizardAction::Quit,
                KeyCode::Up | KeyCode::Char('k') => {
                    self.selected_index = self.selected_index.saturating_sub(1);
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    self.selected_index = (self.selected_index + 1).min(1);
                }
                KeyCode::Enter => {
                    self.show_advanced = self.selected_index == 1;
                    return self.next_screen();
                }
                KeyCode::Esc => return self.prev_screen(),
                _ => {}
            }
        }
        WizardScreen::Advanced => {
            match key.code {
                KeyCode::Char('q') => return WizardAction::Quit,
                KeyCode::Up | KeyCode::Char('k') => {
                    self.selected_index = self.selected_index.saturating_sub(1);
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    self.selected_index = (self.selected_index + 1).min(1);
                }
                KeyCode::Char(' ') => {
                    match self.selected_index {
                        0 => self.data.export_html = !self.data.export_html,
                        1 => self.data.export_pdf = !self.data.export_pdf,
                        _ => {}
                    }
                }
                KeyCode::Enter => return self.next_screen(),
                KeyCode::Esc => return self.prev_screen(),
                _ => {}
            }
        }
        WizardScreen::Review => {
            match key.code {
                KeyCode::Char('q') => return WizardAction::Quit,
                KeyCode::Enter => {
                    match self.save_config() {
                        Ok(path) => return WizardAction::Complete(path),
                        Err(e) => {
                            self.error_message = Some(e.to_string());
                        }
                    }
                }
                KeyCode::Esc => return self.prev_screen(),
                _ => {}
            }
        }
    }
    WizardAction::Continue
}
```

**Step 3: Build and test full wizard flow**

```bash
cargo build -p feroxmute-cli
cargo run -p feroxmute-cli -- --wizard
```

**Step 4: Commit**

```bash
git add feroxmute-cli/src/wizard/
git commit -m "$(cat <<'EOF'
feat(cli): implement all wizard screens

Complete wizard flow: welcome, provider, API key, scope, constraints,
advanced options prompt, advanced options, and review screens.
EOF
)"
```

---

## Task 9: Wire up wizard in main.rs

**Files:**
- Modify: `feroxmute-cli/src/main.rs`

**Step 1: Replace placeholder with actual wizard call**

In main.rs, replace lines 29-32:
```rust
if args.wizard {
    println!("Interactive wizard not yet implemented");
    return Ok(());
}
```

With:
```rust
if args.wizard {
    match wizard::run_wizard() {
        Ok(path) => {
            println!("\n✓ Configuration saved to: {}", path.display());
            println!("\nYou can now run feroxmute with:");
            println!("  feroxmute --target example.com");
            return Ok(());
        }
        Err(e) => {
            if e.to_string().contains("cancelled") {
                println!("\nWizard cancelled.");
            } else {
                eprintln!("\nError: {}", e);
            }
            return Ok(());
        }
    }
}
```

**Step 2: Build and test**

```bash
cargo build -p feroxmute-cli
cargo run -p feroxmute-cli -- --wizard
```

**Step 3: Commit**

```bash
git add feroxmute-cli/src/main.rs
git commit -m "$(cat <<'EOF'
feat(cli): wire up wizard to main entrypoint

Running --wizard now launches the interactive TUI wizard.
EOF
)"
```

---

## Task 10: Handle existing config (overwrite prompt)

**Files:**
- Modify: `feroxmute-cli/src/wizard/state.rs`
- Modify: `feroxmute-cli/src/wizard/screens.rs`

**Step 1: Add ConfirmOverwrite screen**

In state.rs, add to WizardScreen enum:
```rust
pub enum WizardScreen {
    #[default]
    Welcome,
    ConfirmOverwrite,  // New
    Provider,
    // ... rest
}
```

**Step 2: Check for existing config in WizardState::new()**

```rust
impl WizardState {
    pub fn new() -> Self {
        let config_exists = dirs::home_dir()
            .map(|h| h.join(".feroxmute").join("config.toml").exists())
            .unwrap_or(false);

        Self {
            screen: if config_exists {
                WizardScreen::ConfirmOverwrite
            } else {
                WizardScreen::Welcome
            },
            data: WizardData::default(),
            selected_index: 0,
            text_input: String::new(),
            cursor_position: 0,
            show_advanced: false,
            error_message: None,
        }
    }
```

**Step 3: Add render_confirm_overwrite to screens.rs**

```rust
/// Render the confirm overwrite screen
pub fn render_confirm_overwrite(frame: &mut Frame, state: &WizardState) {
    let area = centered_rect(60, 40, frame.area());

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Yellow))
        .title(" Existing Config Found ");

    let text = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  A configuration file already exists at:",
            Style::default(),
        )),
        Line::from(Span::styled(
            "  ~/.feroxmute/config.toml",
            Style::default().fg(Color::Yellow),
        )),
        Line::from(""),
        Line::from("  Do you want to overwrite it?"),
        Line::from(""),
    ];

    let options = ["Yes, overwrite", "No, cancel"];
    let list = SelectList::new(&options, state.selected_index)
        .focused(true)
        .label("");

    let para = Paragraph::new(text).block(block);
    frame.render_widget(para, area);

    let list_area = Rect {
        x: area.x + 2,
        y: area.y + 8,
        width: area.width.saturating_sub(4),
        height: 4,
    };
    list.render(frame, list_area);
}
```

**Step 4: Handle ConfirmOverwrite in state.rs**

Add to `render`:
```rust
WizardScreen::ConfirmOverwrite => screens::render_confirm_overwrite(frame, self),
```

Add to `handle_key`:
```rust
WizardScreen::ConfirmOverwrite => {
    match key.code {
        KeyCode::Char('q') => return WizardAction::Quit,
        KeyCode::Up | KeyCode::Char('k') => {
            self.selected_index = self.selected_index.saturating_sub(1);
        }
        KeyCode::Down | KeyCode::Char('j') => {
            self.selected_index = (self.selected_index + 1).min(1);
        }
        KeyCode::Enter => {
            if self.selected_index == 0 {
                // Yes, continue to wizard
                self.screen = WizardScreen::Welcome;
                self.selected_index = 0;
            } else {
                // No, quit
                return WizardAction::Quit;
            }
        }
        KeyCode::Esc => return WizardAction::Quit,
        _ => {}
    }
}
```

Update `prev_screen` to handle ConfirmOverwrite:
```rust
fn prev_screen(&mut self) -> WizardAction {
    self.screen = match self.screen {
        WizardScreen::ConfirmOverwrite => return WizardAction::Quit,
        WizardScreen::Welcome => return WizardAction::Quit,
        // ... rest unchanged
    };
    WizardAction::Continue
}
```

**Step 5: Build and test**

```bash
cargo build -p feroxmute-cli
# First run creates config
cargo run -p feroxmute-cli -- --wizard
# Second run should prompt for overwrite
cargo run -p feroxmute-cli -- --wizard
```

**Step 6: Commit**

```bash
git add feroxmute-cli/src/wizard/
git commit -m "$(cat <<'EOF'
feat(cli): prompt before overwriting existing config

Wizard now checks for existing config and asks for confirmation
before overwriting.
EOF
)"
```

---

## Task 11: Final cleanup and testing

**Step 1: Run full test suite**

```bash
cargo test
cargo clippy
cargo fmt --check
```

**Step 2: Manual end-to-end test**

```bash
# Remove existing config
rm -f ~/.feroxmute/config.toml

# Run wizard
cargo run -p feroxmute-cli -- --wizard
# Go through all steps, verify config is created

# Verify permissions
ls -la ~/.feroxmute/config.toml
# Should show -rw------- (600)

# Verify content
cat ~/.feroxmute/config.toml
```

**Step 3: Commit any fixes**

```bash
git add -A
git commit -m "$(cat <<'EOF'
chore: cleanup and formatting
EOF
)"
```

---

## Summary

This plan implements the config wizard in 11 tasks:

1. Add `api_key` field to `ProviderConfig`
2. Add config loading cascade
3. Create wizard module skeleton
4. Implement input widgets
5. Implement Welcome screen
6. Implement Provider selection screen
7. Implement API key input screen
8. Implement remaining screens (scope, constraints, advanced, review)
9. Wire up wizard in main.rs
10. Handle existing config (overwrite prompt)
11. Final cleanup and testing

Total new files: 4
Modified files: 4
