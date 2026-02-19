# Design: Model Selection Wizard Screen (Issue #10)

## Problem

Default model strings per provider are outdated, and the wizard offers no way to change the model without manually editing TOML.

## Updated Default Models

| Provider | Old Default | New Default | Rationale |
|----------|------------|-------------|-----------|
| Anthropic | `claude-sonnet-4-20250514` | `claude-sonnet-4-20250514` | Still current Sonnet |
| OpenAI | `gpt-4o` | `gpt-4o` | Widely available; safe default |
| Gemini | `gemini-1.5-pro` | `gemini-2.5-flash` | 1.5-pro deprecated March 2026 |
| xAI | `grok-2` | `grok-3` | Grok 3 is GA |
| DeepSeek | `deepseek-chat` | `deepseek-chat` | Maps to V3.2 |
| Perplexity | `sonar-pro` | `sonar-pro` | Still current |
| Cohere | `command-r-plus` | `command-a-03-2025` | Command A is recommended |
| Azure | `gpt-4o` | `gpt-4o` | Unchanged |
| Ollama | `llama3.2` | `llama4` | Llama 4 available |
| LiteLLM | `openai/gpt-4o` | `openai/gpt-4o` | Unchanged |
| Mira | `mira-chat` | `mira-chat` | Unchanged |

## New Model Selection Screen

### Flow

Provider -> **ModelSelection** -> ApiKey (or Ollama flow)

CLI agent providers (ClaudeCode, Codex, GeminiCli) skip this screen.

### UX

- Curated list of 3-4 models per provider; first is "(Recommended)"
- Last item: "Custom model name..."
- Selecting a preset stores it and advances
- Selecting "Custom..." switches to inline text input (hybrid mode)
- Text input pre-filled with default model; Enter accepts, Esc returns to list

### Curated Model Lists

- **Anthropic:** `claude-sonnet-4-20250514`, `claude-opus-4-6`, `claude-haiku-4-5-20251001`
- **OpenAI:** `gpt-4o`, `gpt-5.2`, `o4-mini`
- **Gemini:** `gemini-2.5-flash`, `gemini-2.5-pro`, `gemini-3-pro`
- **xAI:** `grok-3`, `grok-3-mini`
- **DeepSeek:** `deepseek-chat`, `deepseek-reasoner`
- **Perplexity:** `sonar-pro`, `sonar`, `sonar-reasoning-pro`
- **Cohere:** `command-a-03-2025`, `command-r-plus-08-2024`
- **Azure:** `gpt-4o`, `gpt-5.2`
- **Ollama:** `llama4`, `llama3.3`, `qwen3`
- **LiteLLM:** `openai/gpt-4o`, `anthropic/claude-sonnet-4-20250514`
- **Mira:** `mira-chat`

## Architecture

### Files to Modify

1. `feroxmute-cli/src/wizard/state.rs` — Add `ModelSelection` variant, handler, model list data, update defaults
2. `feroxmute-cli/src/wizard/screens.rs` — Add `render_model_selection()` function

### State Additions

- `entering_custom_model: bool` on `WizardState` for hybrid list/input mode
- Reuse existing `text_input` and `cursor_position` for custom model input
- `fn models_for_provider(provider: &ProviderName) -> &[(&str, &str)]` returning `(model_id, label)` tuples

### Navigation Changes

- `next_screen()`: Provider -> ModelSelection (skip for CLI agents)
- `prev_screen()`: ModelSelection -> Provider
- ModelSelection -> ApiKey / OllamaBaseUrl (depending on provider)
