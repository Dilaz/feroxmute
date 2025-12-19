//! Wizard state management

use std::fs;
use std::path::PathBuf;

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;

/// Wizard screens in order
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WizardScreen {
    Welcome,
    Provider,
    ApiKey,
    Scope,
    Constraints,
    AdvancedPrompt,
    Advanced,
    Review,
}

/// Wizard data collected from user
#[derive(Debug, Clone)]
pub struct WizardData {
    pub provider: usize,
    pub api_key: String,
    pub scope: usize,
    pub max_depth: String,
    pub max_time: String,
    pub max_cost: String,
    pub custom_prompt: String,
    pub advanced_shown: bool,
    pub docker_image: String,
    pub session_dir: String,
}

impl Default for WizardData {
    fn default() -> Self {
        Self {
            provider: 0,
            api_key: String::new(),
            scope: 0,
            max_depth: "3".to_string(),
            max_time: "60".to_string(),
            max_cost: "10.00".to_string(),
            custom_prompt: String::new(),
            advanced_shown: false,
            docker_image: "feroxmute-kali:latest".to_string(),
            session_dir: "~/.feroxmute/sessions".to_string(),
        }
    }
}

/// Actions returned from key handler
#[derive(Debug, Clone)]
pub enum WizardAction {
    Continue,
    Quit,
    Complete(PathBuf),
}

/// Wizard state
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

    /// Render the current screen (placeholder for now)
    pub fn render(&mut self, frame: &mut Frame) {
        use ratatui::layout::{Alignment, Constraint, Direction, Layout};
        use ratatui::style::{Color, Style};
        use ratatui::text::{Line, Span};
        use ratatui::widgets::{Block, Borders, Paragraph};

        let screen_name = match self.screen {
            WizardScreen::Welcome => "Welcome",
            WizardScreen::Provider => "Provider Selection",
            WizardScreen::ApiKey => "API Key",
            WizardScreen::Scope => "Scope Selection",
            WizardScreen::Constraints => "Constraints",
            WizardScreen::AdvancedPrompt => "Advanced Options",
            WizardScreen::Advanced => "Advanced Settings",
            WizardScreen::Review => "Review Configuration",
        };

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(0),
                Constraint::Length(3),
            ])
            .split(frame.area());

        let title = Paragraph::new(format!("feroxmute Configuration Wizard - {}", screen_name))
            .style(Style::default().fg(Color::Cyan))
            .alignment(Alignment::Center)
            .block(Block::default().borders(Borders::ALL));

        let content = Paragraph::new("Screen content will be implemented next...")
            .alignment(Alignment::Center);

        let help = Paragraph::new("Press 'q' to quit")
            .style(Style::default().fg(Color::DarkGray))
            .alignment(Alignment::Center);

        frame.render_widget(title, chunks[0]);
        frame.render_widget(content, chunks[1]);
        frame.render_widget(help, chunks[2]);
    }

    /// Handle key events
    pub fn handle_key(&mut self, key: KeyEvent) -> WizardAction {
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => WizardAction::Quit,
            KeyCode::Enter => {
                if self.screen == WizardScreen::Review {
                    match self.save_config() {
                        Ok(path) => WizardAction::Complete(path),
                        Err(e) => {
                            self.error_message = Some(format!("Failed to save config: {}", e));
                            WizardAction::Continue
                        }
                    }
                } else {
                    self.next_screen();
                    WizardAction::Continue
                }
            }
            KeyCode::Backspace => {
                if !self.text_input.is_empty() {
                    self.text_input.pop();
                }
                WizardAction::Continue
            }
            KeyCode::Char(c) => {
                self.text_input.push(c);
                WizardAction::Continue
            }
            KeyCode::Up => {
                if self.selected_index > 0 {
                    self.selected_index -= 1;
                }
                WizardAction::Continue
            }
            KeyCode::Down => {
                self.selected_index += 1;
                WizardAction::Continue
            }
            _ => WizardAction::Continue,
        }
    }

    /// Move to next screen
    fn next_screen(&mut self) {
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
            WizardScreen::Review => WizardScreen::Review,
        };
    }

    /// Move to previous screen
    #[allow(dead_code)]
    fn prev_screen(&mut self) {
        self.screen = match self.screen {
            WizardScreen::Welcome => WizardScreen::Welcome,
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
    }

    /// Save configuration to file
    fn save_config(&self) -> anyhow::Result<PathBuf> {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        let config_dir = PathBuf::from(home).join(".feroxmute");
        fs::create_dir_all(&config_dir)?;

        let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
        let filename = format!("config_{}.toml", timestamp);
        let path = config_dir.join(&filename);

        let toml_content = self.generate_toml()?;
        fs::write(&path, toml_content)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&path)?.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(&path, perms)?;
        }

        Ok(path)
    }

    /// Generate TOML content
    fn generate_toml(&self) -> anyhow::Result<String> {
        let provider_name = provider_name_str(self.data.provider);
        let scope_name = scope_str(self.data.scope);
        let default_model = default_model(self.data.provider);

        let mut toml = String::new();
        toml.push_str(&format!("# feroxmute configuration\n"));
        toml.push_str(&format!("# Generated: {}\n\n", chrono::Local::now().format("%Y-%m-%d %H:%M:%S")));

        toml.push_str("[provider]\n");
        toml.push_str(&format!("name = \"{}\"\n", provider_name));
        toml.push_str(&format!("api_key = \"{}\"\n", self.data.api_key));
        toml.push_str(&format!("default_model = \"{}\"\n\n", default_model));

        toml.push_str("[scope]\n");
        toml.push_str(&format!("level = \"{}\"\n\n", scope_name));

        toml.push_str("[constraints]\n");
        toml.push_str(&format!("max_depth = {}\n", self.data.max_depth));
        toml.push_str(&format!("max_time_minutes = {}\n", self.data.max_time));
        toml.push_str(&format!("max_cost_dollars = {}\n", self.data.max_cost));

        if !self.data.custom_prompt.is_empty() {
            toml.push_str(&format!("\n[prompts]\n"));
            toml.push_str(&format!("custom = \"\"\"\n{}\n\"\"\"\n", self.data.custom_prompt));
        }

        if self.data.advanced_shown {
            toml.push_str(&format!("\n[docker]\n"));
            toml.push_str(&format!("image = \"{}\"\n\n", self.data.docker_image));
            toml.push_str(&format!("[session]\n"));
            toml.push_str(&format!("base_dir = \"{}\"\n", self.data.session_dir));
        }

        Ok(toml)
    }
}

fn provider_name_str(index: usize) -> &'static str {
    match index {
        0 => "anthropic",
        1 => "openai",
        2 => "litellm",
        _ => "anthropic",
    }
}

fn scope_str(index: usize) -> &'static str {
    match index {
        0 => "passive",
        1 => "active",
        2 => "aggressive",
        _ => "passive",
    }
}

fn default_model(provider_index: usize) -> &'static str {
    match provider_index {
        0 => "claude-sonnet-4-20250514",
        1 => "gpt-4o",
        2 => "openai/gpt-4o",
        _ => "claude-sonnet-4-20250514",
    }
}
