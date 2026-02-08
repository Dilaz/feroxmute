//! Wizard state management

use std::fs;
use std::path::PathBuf;

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;

use feroxmute_core::config::ProviderName;

use super::screens;

const FEROXMUTE_DIR: &str = ".feroxmute";
const CONFIG_FILE: &str = "config.toml";

/// Wizard screens in order
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WizardScreen {
    #[default]
    Welcome,
    ConfirmOverwrite,
    Provider,
    ApiKey,
    AzureEndpoint,
    OllamaBaseUrl,
    OllamaApiKey,
    Capabilities,
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
    // Capability flags (additive)
    pub discover: bool,
    pub portscan: bool,
    pub network: bool,
    // Constraint flags
    pub passive: bool,
    pub no_exploit: bool,
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
        let config_exists = dirs::home_dir()
            .map(|h: PathBuf| h.join(FEROXMUTE_DIR).join(CONFIG_FILE).exists())
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

    /// Render the current screen
    pub fn render(&self, frame: &mut Frame) {
        match self.screen {
            WizardScreen::Welcome => screens::render_welcome(frame, self),
            WizardScreen::ConfirmOverwrite => screens::render_confirm_overwrite(frame, self),
            WizardScreen::Provider => screens::render_provider(frame, self),
            WizardScreen::ApiKey => screens::render_api_key(frame, self),
            WizardScreen::AzureEndpoint => screens::render_azure_endpoint(frame, self),
            WizardScreen::OllamaBaseUrl => screens::render_ollama_base_url(frame, self),
            WizardScreen::OllamaApiKey => screens::render_ollama_api_key(frame, self),
            WizardScreen::Capabilities => screens::render_capabilities(frame, self),
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
            WizardScreen::Welcome => match key.code {
                KeyCode::Char('q') => return WizardAction::Quit,
                KeyCode::Enter => return self.next_screen(),
                _ => {}
            },
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
            WizardScreen::Provider => match key.code {
                KeyCode::Char('q') => return WizardAction::Quit,
                KeyCode::Up | KeyCode::Char('k') => {
                    self.selected_index = self.selected_index.saturating_sub(1);
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    self.selected_index = (self.selected_index + 1).min(10);
                }
                KeyCode::Enter => {
                    self.data.provider = match self.selected_index {
                        0 => ProviderName::Anthropic,
                        1 => ProviderName::OpenAi,
                        2 => ProviderName::Gemini,
                        3 => ProviderName::Xai,
                        4 => ProviderName::DeepSeek,
                        5 => ProviderName::Perplexity,
                        6 => ProviderName::Cohere,
                        7 => ProviderName::Azure,
                        8 => ProviderName::Mira,
                        9 => ProviderName::Ollama,
                        _ => ProviderName::LiteLlm,
                    };
                    self.selected_index = 0;
                    return self.next_screen();
                }
                KeyCode::Esc => return self.prev_screen(),
                _ => {}
            },
            WizardScreen::ApiKey => match key.code {
                KeyCode::Char('q') if self.text_input.is_empty() => return WizardAction::Quit,
                KeyCode::Char(c) => {
                    let byte_idx = char_to_byte_index(&self.text_input, self.cursor_position);
                    self.text_input.insert(byte_idx, c);
                    self.cursor_position += 1;
                }
                KeyCode::Backspace => {
                    if self.cursor_position > 0 {
                        self.cursor_position -= 1;
                        let byte_idx = char_to_byte_index(&self.text_input, self.cursor_position);
                        self.text_input.remove(byte_idx);
                    }
                }
                KeyCode::Delete => {
                    if self.cursor_position < self.text_input.chars().count() {
                        let byte_idx = char_to_byte_index(&self.text_input, self.cursor_position);
                        self.text_input.remove(byte_idx);
                    }
                }
                KeyCode::Left => {
                    self.cursor_position = self.cursor_position.saturating_sub(1);
                }
                KeyCode::Right => {
                    self.cursor_position =
                        (self.cursor_position + 1).min(self.text_input.chars().count());
                }
                KeyCode::Home => self.cursor_position = 0,
                KeyCode::End => self.cursor_position = self.text_input.chars().count(),
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
            },
            WizardScreen::AzureEndpoint => match key.code {
                KeyCode::Char('q') if self.text_input.is_empty() => return WizardAction::Quit,
                KeyCode::Char(c) => {
                    let byte_idx = char_to_byte_index(&self.text_input, self.cursor_position);
                    self.text_input.insert(byte_idx, c);
                    self.cursor_position += 1;
                }
                KeyCode::Backspace => {
                    if self.cursor_position > 0 {
                        self.cursor_position -= 1;
                        let byte_idx = char_to_byte_index(&self.text_input, self.cursor_position);
                        self.text_input.remove(byte_idx);
                    }
                }
                KeyCode::Delete => {
                    if self.cursor_position < self.text_input.chars().count() {
                        let byte_idx = char_to_byte_index(&self.text_input, self.cursor_position);
                        self.text_input.remove(byte_idx);
                    }
                }
                KeyCode::Left => {
                    self.cursor_position = self.cursor_position.saturating_sub(1);
                }
                KeyCode::Right => {
                    self.cursor_position =
                        (self.cursor_position + 1).min(self.text_input.chars().count());
                }
                KeyCode::Home => self.cursor_position = 0,
                KeyCode::End => self.cursor_position = self.text_input.chars().count(),
                KeyCode::Enter => {
                    if !self.text_input.is_empty() {
                        self.data.base_url = Some(self.text_input.clone());
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
            },
            WizardScreen::OllamaBaseUrl => match key.code {
                KeyCode::Char('q') if self.text_input.is_empty() => return WizardAction::Quit,
                KeyCode::Char(c) => {
                    let byte_idx = char_to_byte_index(&self.text_input, self.cursor_position);
                    self.text_input.insert(byte_idx, c);
                    self.cursor_position += 1;
                }
                KeyCode::Backspace => {
                    if self.cursor_position > 0 {
                        self.cursor_position -= 1;
                        let byte_idx = char_to_byte_index(&self.text_input, self.cursor_position);
                        self.text_input.remove(byte_idx);
                    }
                }
                KeyCode::Delete => {
                    if self.cursor_position < self.text_input.chars().count() {
                        let byte_idx = char_to_byte_index(&self.text_input, self.cursor_position);
                        self.text_input.remove(byte_idx);
                    }
                }
                KeyCode::Left => {
                    self.cursor_position = self.cursor_position.saturating_sub(1);
                }
                KeyCode::Right => {
                    self.cursor_position =
                        (self.cursor_position + 1).min(self.text_input.chars().count());
                }
                KeyCode::Home => self.cursor_position = 0,
                KeyCode::End => self.cursor_position = self.text_input.chars().count(),
                KeyCode::Enter => {
                    // Use default localhost:11434 if empty
                    let base_url = if self.text_input.is_empty() {
                        "http://localhost:11434".to_string()
                    } else {
                        self.text_input.clone()
                    };
                    self.data.base_url = Some(base_url);
                    self.text_input.clear();
                    self.cursor_position = 0;
                    self.selected_index = 0;
                    return self.next_screen();
                }
                KeyCode::Esc => {
                    self.text_input.clear();
                    self.cursor_position = 0;
                    return self.prev_screen();
                }
                _ => {}
            },
            WizardScreen::OllamaApiKey => match key.code {
                KeyCode::Char('q') if self.text_input.is_empty() => return WizardAction::Quit,
                KeyCode::Char(c) => {
                    let byte_idx = char_to_byte_index(&self.text_input, self.cursor_position);
                    self.text_input.insert(byte_idx, c);
                    self.cursor_position += 1;
                }
                KeyCode::Backspace => {
                    if self.cursor_position > 0 {
                        self.cursor_position -= 1;
                        let byte_idx = char_to_byte_index(&self.text_input, self.cursor_position);
                        self.text_input.remove(byte_idx);
                    }
                }
                KeyCode::Delete => {
                    if self.cursor_position < self.text_input.chars().count() {
                        let byte_idx = char_to_byte_index(&self.text_input, self.cursor_position);
                        self.text_input.remove(byte_idx);
                    }
                }
                KeyCode::Left => {
                    self.cursor_position = self.cursor_position.saturating_sub(1);
                }
                KeyCode::Right => {
                    self.cursor_position =
                        (self.cursor_position + 1).min(self.text_input.chars().count());
                }
                KeyCode::Home => self.cursor_position = 0,
                KeyCode::End => self.cursor_position = self.text_input.chars().count(),
                KeyCode::Enter => {
                    // API key is optional for Ollama, so allow empty
                    if !self.text_input.is_empty() {
                        self.data.api_key = self.text_input.clone();
                    }
                    self.text_input.clear();
                    self.cursor_position = 0;
                    self.selected_index = 0;
                    return self.next_screen();
                }
                KeyCode::Esc => {
                    self.text_input.clear();
                    self.cursor_position = 0;
                    return self.prev_screen();
                }
                _ => {}
            },
            WizardScreen::Capabilities => match key.code {
                KeyCode::Char('q') => return WizardAction::Quit,
                KeyCode::Up | KeyCode::Char('k') => {
                    self.selected_index = self.selected_index.saturating_sub(1);
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    self.selected_index = (self.selected_index + 1).min(2);
                }
                KeyCode::Char(' ') => match self.selected_index {
                    0 => self.data.discover = !self.data.discover,
                    1 => self.data.portscan = !self.data.portscan,
                    2 => self.data.network = !self.data.network,
                    _ => {}
                },
                KeyCode::Enter => {
                    self.selected_index = 0;
                    return self.next_screen();
                }
                KeyCode::Esc => return self.prev_screen(),
                _ => {}
            },
            WizardScreen::Constraints => match key.code {
                KeyCode::Char('q') => return WizardAction::Quit,
                KeyCode::Up | KeyCode::Char('k') => {
                    self.selected_index = self.selected_index.saturating_sub(1);
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    self.selected_index = (self.selected_index + 1).min(1);
                }
                KeyCode::Char(' ') => match self.selected_index {
                    0 => self.data.passive = !self.data.passive,
                    1 => self.data.no_exploit = !self.data.no_exploit,
                    _ => {}
                },
                KeyCode::Enter => {
                    self.selected_index = 0;
                    return self.next_screen();
                }
                KeyCode::Esc => return self.prev_screen(),
                _ => {}
            },
            WizardScreen::AdvancedPrompt => match key.code {
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
            },
            WizardScreen::Advanced => match key.code {
                KeyCode::Char('q') => return WizardAction::Quit,
                KeyCode::Up | KeyCode::Char('k') => {
                    self.selected_index = self.selected_index.saturating_sub(1);
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    self.selected_index = (self.selected_index + 1).min(1);
                }
                KeyCode::Char(' ') => match self.selected_index {
                    0 => self.data.export_html = !self.data.export_html,
                    1 => self.data.export_pdf = !self.data.export_pdf,
                    _ => {}
                },
                KeyCode::Enter => {
                    self.selected_index = 0;
                    return self.next_screen();
                }
                KeyCode::Esc => return self.prev_screen(),
                _ => {}
            },
            WizardScreen::Review => match key.code {
                KeyCode::Char('q') => return WizardAction::Quit,
                KeyCode::Enter => match self.save_config() {
                    Ok(path) => return WizardAction::Complete(path),
                    Err(e) => {
                        self.error_message = Some(e.to_string());
                    }
                },
                KeyCode::Esc => return self.prev_screen(),
                _ => {}
            },
        }
        WizardAction::Continue
    }

    /// Move to next screen
    fn next_screen(&mut self) -> WizardAction {
        self.screen = match self.screen {
            WizardScreen::ConfirmOverwrite => WizardScreen::Welcome,
            WizardScreen::Welcome => WizardScreen::Provider,
            WizardScreen::Provider => {
                if self.data.provider == ProviderName::Ollama {
                    WizardScreen::OllamaBaseUrl
                } else {
                    WizardScreen::ApiKey
                }
            }
            WizardScreen::ApiKey => {
                if self.data.provider == ProviderName::Azure {
                    WizardScreen::AzureEndpoint
                } else {
                    WizardScreen::Capabilities
                }
            }
            WizardScreen::AzureEndpoint => WizardScreen::Capabilities,
            WizardScreen::OllamaBaseUrl => WizardScreen::OllamaApiKey,
            WizardScreen::OllamaApiKey => WizardScreen::Capabilities,
            WizardScreen::Capabilities => WizardScreen::Constraints,
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
            WizardScreen::ConfirmOverwrite => return WizardAction::Quit,
            WizardScreen::Welcome => return WizardAction::Quit,
            WizardScreen::Provider => WizardScreen::Welcome,
            WizardScreen::ApiKey => WizardScreen::Provider,
            WizardScreen::AzureEndpoint => WizardScreen::ApiKey,
            WizardScreen::OllamaBaseUrl => WizardScreen::Provider,
            WizardScreen::OllamaApiKey => WizardScreen::OllamaBaseUrl,
            WizardScreen::Capabilities => {
                if self.data.provider == ProviderName::Azure {
                    WizardScreen::AzureEndpoint
                } else if self.data.provider == ProviderName::Ollama {
                    WizardScreen::OllamaApiKey
                } else {
                    WizardScreen::ApiKey
                }
            }
            WizardScreen::Constraints => WizardScreen::Capabilities,
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
        let config_dir = PathBuf::from(home).join(FEROXMUTE_DIR);
        fs::create_dir_all(&config_dir)?;

        let path = config_dir.join(CONFIG_FILE);

        // Backup existing config if present
        if path.exists() {
            let backup_path = config_dir.join(format!("{}.bak", CONFIG_FILE));
            fs::rename(&path, &backup_path)?;
        }

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
            ProviderName::Gemini => "gemini",
            ProviderName::Xai => "xai",
            ProviderName::DeepSeek => "deepseek",
            ProviderName::Perplexity => "perplexity",
            ProviderName::Cohere => "cohere",
            ProviderName::Azure => "azure",
            ProviderName::Mira => "mira",
            ProviderName::LiteLlm => "litellm",
            ProviderName::Ollama => "ollama",
            // CLI agent providers
            ProviderName::ClaudeCode => "claude-code",
            ProviderName::Codex => "codex",
            ProviderName::GeminiCli => "gemini-cli",
        };

        #[allow(clippy::unnecessary_lazy_evaluations)]
        let model = self
            .data
            .model
            .as_deref()
            .unwrap_or_else(|| match self.data.provider {
                ProviderName::Anthropic => "claude-sonnet-4-20250514",
                ProviderName::OpenAi => "gpt-4o",
                ProviderName::Gemini => "gemini-1.5-pro",
                ProviderName::Xai => "grok-2",
                ProviderName::DeepSeek => "deepseek-chat",
                ProviderName::Perplexity => "sonar-pro",
                ProviderName::Cohere => "command-r-plus",
                ProviderName::Azure => "gpt-4o",
                ProviderName::Mira => "mira-chat",
                ProviderName::LiteLlm => "openai/gpt-4o",
                ProviderName::Ollama => "llama3.2",
                // CLI agent providers (default models)
                ProviderName::ClaudeCode => "claude-opus-4.5",
                ProviderName::Codex => "gpt-5.2",
                ProviderName::GeminiCli => "gemini-3-pro",
            });

        let mut toml = String::new();
        toml.push_str("# feroxmute configuration\n");
        toml.push_str(&format!(
            "# Generated: {}\n\n",
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
        ));

        toml.push_str("[provider]\n");
        toml.push_str(&format!(
            "name = \"{}\"\n",
            escape_toml_string(provider_name)
        ));
        toml.push_str(&format!(
            "api_key = \"{}\"\n",
            escape_toml_string(&self.data.api_key)
        ));
        toml.push_str(&format!("model = \"{}\"\n", escape_toml_string(model)));
        if let Some(ref base_url) = self.data.base_url {
            toml.push_str(&format!(
                "base_url = \"{}\"\n",
                escape_toml_string(base_url)
            ));
        }
        toml.push('\n');

        toml.push_str("[capabilities]\n");
        toml.push_str(&format!("discover = {}\n", self.data.discover));
        toml.push_str(&format!("portscan = {}\n", self.data.portscan));
        toml.push_str(&format!("network = {}\n\n", self.data.network));

        toml.push_str("[constraints]\n");
        toml.push_str(&format!("passive = {}\n", self.data.passive));
        toml.push_str(&format!("no_exploit = {}\n", self.data.no_exploit));
        if let Some(rate_limit) = self.data.rate_limit {
            toml.push_str(&format!("rate_limit = {}\n", rate_limit));
        } else {
            toml.push_str("# rate_limit = 10\n");
        }
        toml.push('\n');

        toml.push_str("[output]\n");
        toml.push_str(&format!("export_html = {}\n", self.data.export_html));
        toml.push_str(&format!("export_pdf = {}\n", self.data.export_pdf));

        Ok(toml)
    }
}

/// Convert a character index to a byte index in a string.
///
/// `cursor_position` tracks the number of characters, but `String::insert()`
/// and `String::remove()` require byte indices. This function converts between
/// the two so that multi-byte characters are handled correctly.
fn char_to_byte_index(s: &str, char_idx: usize) -> usize {
    s.char_indices()
        .nth(char_idx)
        .map(|(byte_idx, _)| byte_idx)
        .unwrap_or(s.len())
}

/// Escape a string for use inside TOML double-quoted strings.
///
/// Handles backslashes, double quotes, and control characters that would
/// break or inject into the TOML output.
fn escape_toml_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                // Encode other control chars as \uXXXX
                for unit in c.encode_utf16(&mut [0; 2]) {
                    out.push_str(&format!("\\u{:04X}", unit));
                }
            }
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_toml_string_plain() {
        assert_eq!(escape_toml_string("sk-ant-123"), "sk-ant-123");
    }

    #[test]
    fn test_escape_toml_string_quotes() {
        assert_eq!(escape_toml_string(r#"key"val"#), r#"key\"val"#);
    }

    #[test]
    fn test_escape_toml_string_backslash() {
        assert_eq!(escape_toml_string(r"path\to"), r"path\\to");
    }

    #[test]
    fn test_escape_toml_string_newline_injection() {
        // An attacker might try to inject a newline + extra TOML key
        let malicious = "real-key\"\nmalicious = \"injected";
        let escaped = escape_toml_string(malicious);
        assert!(!escaped.contains('\n'));
        assert!(escaped.contains("\\n"));
    }

    #[test]
    fn test_char_to_byte_index_ascii() {
        assert_eq!(char_to_byte_index("hello", 3), 3);
    }

    #[test]
    fn test_char_to_byte_index_multibyte() {
        // "café" - é is 2 bytes, so char index 4 -> byte index 5
        assert_eq!(char_to_byte_index("café", 4), 5);
    }

    #[test]
    fn test_char_to_byte_index_cjk() {
        // "日本語" - each char is 3 bytes
        assert_eq!(char_to_byte_index("日本語", 1), 3);
    }

    #[test]
    fn test_char_to_byte_index_past_end() {
        assert_eq!(char_to_byte_index("hi", 10), 2);
    }

    #[test]
    fn test_char_to_byte_index_empty() {
        assert_eq!(char_to_byte_index("", 0), 0);
    }

    #[test]
    fn test_escape_toml_control_chars() {
        let input = "\x01\x02";
        let escaped = escape_toml_string(input);
        assert!(escaped.contains("\\u0001"));
        assert!(escaped.contains("\\u0002"));
        assert!(!escaped.contains('\x01'));
        assert!(!escaped.contains('\x02'));
    }

    fn test_wizard_state() -> WizardState {
        WizardState {
            screen: WizardScreen::Welcome,
            data: WizardData::default(),
            selected_index: 0,
            text_input: String::new(),
            cursor_position: 0,
            show_advanced: false,
            error_message: None,
        }
    }

    #[test]
    fn test_generate_toml_basic() {
        let mut state = test_wizard_state();
        state.data = WizardData {
            provider: ProviderName::Anthropic,
            api_key: "sk-test-123".to_string(),
            discover: true,
            portscan: false,
            network: false,
            passive: false,
            no_exploit: true,
            ..Default::default()
        };
        let toml = state.generate_toml().unwrap();
        assert!(toml.contains("[provider]"));
        assert!(toml.contains("name = \"anthropic\""));
        assert!(toml.contains("api_key = \"sk-test-123\""));
        assert!(toml.contains("[capabilities]"));
        assert!(toml.contains("discover = true"));
        assert!(toml.contains("portscan = false"));
        assert!(toml.contains("[constraints]"));
        assert!(toml.contains("no_exploit = true"));
    }

    #[test]
    fn test_wizard_quit_on_q() {
        let mut state = test_wizard_state();
        assert_eq!(state.screen, WizardScreen::Welcome);
        let action = state.handle_key(KeyEvent::from(KeyCode::Char('q')));
        assert!(matches!(action, WizardAction::Quit));
    }

    #[test]
    fn test_wizard_screen_navigation() {
        let mut state = test_wizard_state();
        assert_eq!(state.screen, WizardScreen::Welcome);
        let action = state.handle_key(KeyEvent::from(KeyCode::Enter));
        assert!(matches!(action, WizardAction::Continue));
        // After pressing Enter on Welcome, screen should advance
        assert_ne!(state.screen, WizardScreen::Welcome);
    }
}
