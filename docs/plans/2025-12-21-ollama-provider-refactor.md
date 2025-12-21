# Ollama Provider & Provider Refactor Design

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add native Ollama provider support and reduce provider code repetition via macros.

**Architecture:** Macro-based code generation (`define_provider!`) to eliminate ~2,350 lines of duplicated code across 9 provider files. New Ollama provider using rig-core's native ollama module.

**Tech Stack:** Rust macros, rig-core ollama provider, existing TUI wizard

---

## Overview

### Current State
- 9 provider files, each ~290 lines (2,600+ lines total)
- 95% identical code - only client type and provider name differ
- No native Ollama support

### After Refactor
- Single `define_provider!` macro (~200 lines)
- All 11 providers defined in ~250 lines total
- ~73% code reduction (3,200 → 850 lines)
- Native Ollama with wizard support

---

## Component 1: Provider Macro

### File: `feroxmute-core/src/providers/macros.rs`

The macro generates:
- Provider struct with `client`, `model`, `metrics` fields
- Constructor `new(model, metrics)` - from env var
- Constructor `with_api_key(api_key, model, metrics)` - explicit key
- Constructor `with_base_url(base_url, model, metrics)` - for Ollama/custom endpoints
- Full `LlmProvider` trait implementation

### Macro Signature

```rust
macro_rules! define_provider {
    (
        name: $name:ident,
        provider_name: $provider_name:expr,
        client_type: $client_type:ty,
        env_key: $env_key:expr,
        supports_tools: $supports_tools:expr,
        client_builder: $client_builder:expr,
    ) => { ... };
}
```

### Provider Definition Example

```rust
define_provider! {
    name: Anthropic,
    provider_name: "anthropic",
    client_type: anthropic::Client,
    env_key: "ANTHROPIC_API_KEY",
    supports_tools: true,
    client_builder: |api_key: String| {
        anthropic::Client::builder()
            .api_key(api_key)
            .build()
    },
}
```

### Ollama Definition (no API key)

```rust
define_provider! {
    name: Ollama,
    provider_name: "ollama",
    client_type: ollama::Client,
    env_key: None,
    supports_tools: true,
    client_builder: || ollama::Client::new(),
    with_base_url: |url: String| ollama::Client::from_url(url),
}
```

---

## Component 2: Provider Definitions

### File: `feroxmute-core/src/providers/definitions.rs`

All 11 providers defined via macro:

1. **Anthropic** - `ANTHROPIC_API_KEY`, builder pattern
2. **OpenAI** - `OPENAI_API_KEY`, builder pattern, supports base_url
3. **Gemini** - `GEMINI_API_KEY` or `GOOGLE_API_KEY`
4. **xAI** - `XAI_API_KEY`
5. **DeepSeek** - `DEEPSEEK_API_KEY`
6. **Perplexity** - `PERPLEXITY_API_KEY`
7. **Cohere** - `COHERE_API_KEY`
8. **Azure** - `AZURE_OPENAI_API_KEY`, requires base_url
9. **Mira** - `MIRA_API_KEY`
10. **LiteLLM** - Uses OpenAI client with custom base_url
11. **Ollama** - No API key required, optional base_url

---

## Component 3: Wizard Updates

### File: `feroxmute-cli/src/wizard/state.rs`

**Provider list expansion** (line ~147):
```rust
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
    9 => ProviderName::LiteLlm,
    _ => ProviderName::Ollama,  // NEW
};
```

**Ollama-specific flow:**
- After provider selection → OllamaBaseUrl screen (new)
- Base URL with default `http://localhost:11434`
- Then → OllamaApiKey screen (new, optional)
- Then → Scope (normal flow continues)

**New wizard screens:**
```rust
pub enum WizardScreen {
    // ... existing screens ...
    OllamaBaseUrl,    // NEW
    OllamaApiKey,     // NEW (optional)
}
```

**Default model for Ollama:**
```rust
ProviderName::Ollama => "gemma",
```

---

## Component 4: Pricing

### File: `feroxmute-core/pricing.toml`

```toml
[models.ollama]
# Local models - no API cost
gemma = { input = 0.0, output = 0.0 }
llama3 = { input = 0.0, output = 0.0 }
llama3-2 = { input = 0.0, output = 0.0 }
mistral = { input = 0.0, output = 0.0 }
codellama = { input = 0.0, output = 0.0 }
qwen2 = { input = 0.0, output = 0.0 }
phi3 = { input = 0.0, output = 0.0 }
```

---

## Component 5: Config Updates

### File: `feroxmute-core/src/config.rs`

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProviderName {
    #[default]
    Anthropic,
    OpenAi,
    Gemini,
    Xai,
    DeepSeek,
    Perplexity,
    Cohere,
    Azure,
    Mira,
    LiteLlm,
    Ollama,  // NEW
}
```

---

## Component 6: Factory Updates

### File: `feroxmute-core/src/providers/factory.rs`

```rust
ProviderName::Ollama => {
    let base_url = config
        .base_url
        .clone()
        .unwrap_or_else(|| "http://localhost:11434".to_string());

    let provider = if let Some(ref api_key) = config.api_key {
        OllamaProvider::with_api_key_and_base_url(api_key, base_url, &config.model, metrics)?
    } else {
        OllamaProvider::with_base_url(base_url, &config.model, metrics)?
    };
    Ok(Arc::new(provider))
}
```

---

## File Structure

### Before
```
providers/
├── mod.rs          (28 lines)
├── traits.rs       (222 lines)
├── factory.rs      (285 lines)
├── anthropic.rs    (299 lines)
├── openai.rs       (339 lines)
├── gemini.rs       (294 lines)
├── azure.rs        (302 lines)
├── cohere.rs       (288 lines)
├── deepseek.rs     (288 lines)
├── mira.rs         (288 lines)
├── perplexity.rs   (288 lines)
├── xai.rs          (288 lines)
└── Total: ~3,209 lines
```

### After
```
providers/
├── mod.rs          (~30 lines - exports)
├── traits.rs       (222 lines - unchanged)
├── factory.rs      (~180 lines - simplified)
├── macros.rs       (~200 lines - define_provider! macro)
├── definitions.rs  (~280 lines - all 11 providers)
└── Total: ~912 lines
```

**Reduction: ~2,297 lines (71%)**

---

## Testing Strategy

1. **Unit tests** - Each provider constructor works
2. **Integration test** - Ollama provider connects to local server (if available)
3. **Wizard test** - Ollama flow generates correct TOML
4. **Existing tests** - All current provider tests still pass

---

## Implementation Order

1. Create `macros.rs` with `define_provider!` macro
2. Create `definitions.rs` with all providers (including Ollama)
3. Update `mod.rs` to export from new structure
4. Update `factory.rs` to use new providers
5. Delete old individual provider files
6. Add `ProviderName::Ollama` to config
7. Add Ollama pricing to `pricing.toml`
8. Update wizard state with Ollama screens
9. Update wizard screens rendering
10. Run tests, verify all pass

---

## Risk Mitigation

- **Macro complexity**: Start with simple macro, iterate
- **rig-core Ollama API**: Verify API matches expectations before implementation
- **Breaking changes**: Keep trait interface identical, only change internals
