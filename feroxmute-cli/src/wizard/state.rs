//! Wizard state management

use std::fs;
use std::path::PathBuf;

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;

use feroxmute_core::config::{ProviderName, Scope};

use super::screens;

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
    pub cursor_position: usize,
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
            cursor_position: 0,
            show_advanced: false,
            error_message: None,
        }
    }

    /// Render the current screen
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

    /// Handle key events
    pub fn handle_key(&mut self, key: KeyEvent) -> WizardAction {
        use crossterm::event::KeyModifiers;

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
                        self.selected_index = 0;
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
                    KeyCode::Home => self.cursor_position = 0,
                    KeyCode::End => self.cursor_position = self.text_input.len(),
                    KeyCode::Enter => {
                        if !self.text_input.is_empty() {
                            self.data.api_key = self.text_input.clone();
                            self.text_input.clear();
                            self.cursor_position = 0;
                            self.selected_index = 0;
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
                        self.selected_index = 0;
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
                    KeyCode::Enter => {
                        self.selected_index = 0;
                        return self.next_screen();
                    }
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
                        self.selected_index = 0;
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
                    KeyCode::Enter => {
                        self.selected_index = 0;
                        return self.next_screen();
                    }
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

    /// Move to next screen
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
            WizardScreen::Review => WizardScreen::Review,
        };
        WizardAction::Continue
    }

    /// Move to previous screen
    fn prev_screen(&mut self) -> WizardAction {
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
        WizardAction::Continue
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
