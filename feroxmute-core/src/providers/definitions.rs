//! Provider definitions using the define_provider! macro
//!
//! This module contains macro-generated provider implementations for all supported
//! LLM providers. Each provider is defined using the `define_provider!` macro which
//! generates the struct, constructors, and LlmProvider trait implementation.
//!
//! ## Providers Defined (9 total)
//!
//! Using the `define_provider!` macro:
//! - Anthropic - Claude models via ANTHROPIC_API_KEY
//! - OpenAI - GPT models via OPENAI_API_KEY (supports base_url)
//! - Gemini - Google Gemini via GEMINI_API_KEY
//! - xAI - Grok models via XAI_API_KEY
//! - DeepSeek - DeepSeek models via DEEPSEEK_API_KEY
//! - Perplexity - Perplexity models via PERPLEXITY_API_KEY
//! - Cohere - Cohere models via COHERE_API_KEY
//! - Mira - Mira models via MIRA_API_KEY
//! - LiteLLM - Proxy via LITELLM_API_KEY (uses OpenAI client with base_url)
//!
//! ## Manual Implementations Required (2 total)
//!
//! These providers have special requirements that the macro cannot handle:
//! - **Azure**: Requires `azure_endpoint()` in addition to `api_key()` - see azure.rs
//! - **Ollama**: No API key required by default - see ollama.rs (if it exists)
//!
//! ## Notes
//!
//! - All providers support tool calling via rig-core's tool framework
//! - The macro assumes all clients have a `::builder()` pattern even if existing
//!   code uses `::new()` for simplicity
//! - LiteLLM defaults to http://localhost:4000 if no base_url is provided

use rig::providers::{anthropic, azure, cohere, deepseek, gemini, mira, openai, perplexity, xai};

// =============================================================================
// Anthropic
// =============================================================================

define_provider! {
    name: AnthropicProvider,
    provider_name: "anthropic",
    client_type: anthropic::Client,
    env_var: "ANTHROPIC_API_KEY",
    supports_tools: true,
    client_builder: |builder, _base_url| builder,
    has_base_url: false
}

// =============================================================================
// OpenAI
// =============================================================================

define_provider! {
    name: OpenAiProvider,
    provider_name: "openai",
    client_type: openai::Client,
    env_var: "OPENAI_API_KEY",
    supports_tools: true,
    client_builder: |builder, base_url| {
        if let Some(url) = base_url {
            builder.base_url(url)
        } else {
            builder
        }
    },
    has_base_url: true
}

// =============================================================================
// Gemini
// =============================================================================

define_provider! {
    name: GeminiProvider,
    provider_name: "gemini",
    client_type: gemini::Client,
    env_var: "GEMINI_API_KEY",
    supports_tools: true,
    client_builder: |builder, _base_url| builder,
    has_base_url: false
}

// =============================================================================
// xAI
// =============================================================================

define_provider! {
    name: XaiProvider,
    provider_name: "xai",
    client_type: xai::Client,
    env_var: "XAI_API_KEY",
    supports_tools: true,
    client_builder: |builder, _base_url| builder,
    has_base_url: false
}

// =============================================================================
// DeepSeek
// =============================================================================

define_provider! {
    name: DeepSeekProvider,
    provider_name: "deepseek",
    client_type: deepseek::Client,
    env_var: "DEEPSEEK_API_KEY",
    supports_tools: true,
    client_builder: |builder, _base_url| builder,
    has_base_url: false
}

// =============================================================================
// Perplexity
// =============================================================================

define_provider! {
    name: PerplexityProvider,
    provider_name: "perplexity",
    client_type: perplexity::Client,
    env_var: "PERPLEXITY_API_KEY",
    supports_tools: true,
    client_builder: |builder, _base_url| builder,
    has_base_url: false
}

// =============================================================================
// Cohere
// =============================================================================

define_provider! {
    name: CohereProvider,
    provider_name: "cohere",
    client_type: cohere::Client,
    env_var: "COHERE_API_KEY",
    supports_tools: true,
    client_builder: |builder, _base_url| builder,
    has_base_url: false
}

// =============================================================================
// Mira
// =============================================================================

define_provider! {
    name: MiraProvider,
    provider_name: "mira",
    client_type: mira::Client,
    env_var: "MIRA_API_KEY",
    supports_tools: true,
    client_builder: |builder, _base_url| builder,
    has_base_url: false
}

// =============================================================================
// LiteLLM (uses OpenAI client with mandatory base_url)
// =============================================================================

define_provider! {
    name: LiteLlmProvider,
    provider_name: "litellm",
    client_type: openai::Client,
    env_var: "LITELLM_API_KEY",
    supports_tools: true,
    client_builder: |builder, base_url| {
        // LiteLLM requires a base_url, default to localhost:4000
        let url = base_url.unwrap_or_else(|| "http://localhost:4000".to_string());
        builder.base_url(url)
    },
    has_base_url: true
}

// =============================================================================
// Manual implementations needed for:
// =============================================================================
//
// Azure - Requires azure_endpoint() method
// The macro doesn't support custom builder methods beyond base_url, so Azure
// needs manual implementation to handle AZURE_OPENAI_ENDPOINT via the existing
// azure.rs file.
//
// Ollama - No API key required by default, needs special handling for optional auth.
// The existing implementation should be kept as manual since it has different
// constructor signatures (no required API key).
