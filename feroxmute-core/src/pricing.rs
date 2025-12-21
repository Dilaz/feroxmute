//! Model pricing for cost estimation

use once_cell::sync::Lazy;
use serde::Deserialize;
use std::collections::HashMap;

/// Pricing info for a model (per 1M tokens in USD)
#[derive(Debug, Clone, Deserialize)]
pub struct ModelPricing {
    pub input: f64,
    pub output: f64,
}

/// Provider pricing map
#[derive(Debug, Clone, Deserialize)]
pub struct ProviderPricing {
    #[serde(flatten)]
    pub models: HashMap<String, ModelPricing>,
}

/// All model pricing data
#[derive(Debug, Clone, Deserialize)]
pub struct PricingConfig {
    pub models: HashMap<String, ProviderPricing>,
}

static PRICING_CONFIG: Lazy<PricingConfig> = Lazy::new(|| {
    let toml_str = include_str!("../pricing.toml");
    toml::from_str(toml_str).expect("Invalid pricing.toml")
});

impl PricingConfig {
    /// Load pricing from embedded TOML (cached after first call)
    pub fn load() -> &'static Self {
        &PRICING_CONFIG
    }

    /// Get pricing for a provider and model
    pub fn get(&self, provider: &str, model: &str) -> Option<&ModelPricing> {
        // Normalize model name (remove date suffixes like -20250514)
        let normalized = normalize_model_name(model);

        self.models
            .get(provider)
            .and_then(|p| p.models.get(&normalized))
    }

    /// Calculate cost for token usage
    pub fn calculate_cost(
        &self,
        provider: &str,
        model: &str,
        input_tokens: u64,
        output_tokens: u64,
    ) -> f64 {
        self.get(provider, model)
            .map(|pricing| {
                let input_cost = (input_tokens as f64 / 1_000_000.0) * pricing.input;
                let output_cost = (output_tokens as f64 / 1_000_000.0) * pricing.output;
                input_cost + output_cost
            })
            .unwrap_or(0.0)
    }
}

/// Regex for removing date suffixes (compiled once)
static DATE_SUFFIX_RE: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(r"-\d{4}[-]?\d{2}[-]?\d{2}$")
        .expect("Hardcoded regex pattern should be valid")
});

/// Normalize model name by removing date suffixes and common variations
fn normalize_model_name(model: &str) -> String {
    let model = model.to_lowercase();

    // Remove date suffixes like -20250514, -2024-08-06
    let model = DATE_SUFFIX_RE.replace(&model, "").to_string();

    // Map common aliases
    let model = model
        .replace("claude-sonnet-4", "claude-4-sonnet")
        .replace("claude-opus-4", "claude-4-opus")
        .replace("claude-3.5-", "claude-3-5-")
        .replace("gemini-2.5-", "gemini-2-5-")
        .replace("gpt-4.1", "gpt-4-1");

    model
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_pricing() {
        let config = PricingConfig::load();
        assert!(config.models.contains_key("anthropic"));
        assert!(config.models.contains_key("openai"));
    }

    #[test]
    fn test_get_pricing() {
        let config = PricingConfig::load();
        let pricing = config.get("anthropic", "claude-4-5-sonnet").unwrap();
        assert_eq!(pricing.input, 3.0);
        assert_eq!(pricing.output, 15.0);
    }

    #[test]
    fn test_normalize_model_name() {
        assert_eq!(
            normalize_model_name("claude-sonnet-4-20250514"),
            "claude-4-sonnet"
        );
        assert_eq!(normalize_model_name("gpt-4o-2024-08-06"), "gpt-4o");
        assert_eq!(normalize_model_name("claude-3.5-haiku"), "claude-3-5-haiku");
    }

    #[test]
    fn test_calculate_cost() {
        let config = PricingConfig::load();
        // 1M input + 1M output for claude-4-5-sonnet = $3 + $15 = $18
        let cost = config.calculate_cost("anthropic", "claude-4-5-sonnet", 1_000_000, 1_000_000);
        assert!((cost - 18.0).abs() < 0.001);
    }

    #[test]
    fn test_calculate_cost_unknown_model() {
        let config = PricingConfig::load();
        let cost = config.calculate_cost("unknown", "unknown-model", 1000, 1000);
        assert_eq!(cost, 0.0);
    }
}
