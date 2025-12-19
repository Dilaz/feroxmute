//! Wizard state management

use std::fs;
use std::path::PathBuf;

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;

use feroxmute_core::config::{ProviderName, Scope};

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
        let provider_name = match self.data.provider {
            ProviderName::Anthropic => "anthropic",
            ProviderName::OpenAi => "openai",
            ProviderName::Cohere => "cohere",
            ProviderName::LiteLlm => "litellm",
        };

        let scope_name = match self.data.scope {
            Scope::Web => "web",
            Scope::Network => "network",
            Scope::Full => "full",
        };

        let model = self.data.model.as_deref().unwrap_or_else(|| {
            match self.data.provider {
                ProviderName::Anthropic => "claude-sonnet-4-20250514",
                ProviderName::OpenAi => "gpt-4o",
                ProviderName::Cohere => "command-r-plus",
                ProviderName::LiteLlm => "openai/gpt-4o",
            }
        });

        let mut toml = String::new();
        toml.push_str(&format!("# feroxmute configuration\n"));
        toml.push_str(&format!("# Generated: {}\n\n", chrono::Local::now().format("%Y-%m-%d %H:%M:%S")));

        toml.push_str("[provider]\n");
        toml.push_str(&format!("name = \"{}\"\n", provider_name));
        toml.push_str(&format!("api_key = \"{}\"\n", self.data.api_key));
        toml.push_str(&format!("model = \"{}\"\n", model));
        if let Some(ref base_url) = self.data.base_url {
            toml.push_str(&format!("base_url = \"{}\"\n", base_url));
        }
        toml.push_str("\n");

        toml.push_str("[target]\n");
        toml.push_str(&format!("scope = \"{}\"\n\n", scope_name));

        toml.push_str("[constraints]\n");
        toml.push_str(&format!("passive = {}\n", self.data.passive));
        toml.push_str(&format!("no_exploit = {}\n", self.data.no_exploit));
        toml.push_str(&format!("no_portscan = {}\n", self.data.no_portscan));
        if let Some(rate_limit) = self.data.rate_limit {
            toml.push_str(&format!("rate_limit = {}\n", rate_limit));
        } else {
            toml.push_str("# rate_limit = 10\n");
        }
        toml.push_str("\n");

        toml.push_str("[output]\n");
        toml.push_str(&format!("export_html = {}\n", self.data.export_html));
        toml.push_str(&format!("export_pdf = {}\n", self.data.export_pdf));

        Ok(toml)
    }
}
