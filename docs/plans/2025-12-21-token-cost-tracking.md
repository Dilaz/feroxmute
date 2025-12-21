# Token Cost Tracking Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add per-completion cost tracking with TOML pricing config and display session costs in the TUI metrics panel.

**Architecture:** Create a `pricing` module in feroxmute-core that loads model pricing from a TOML file. Extend `Metrics` and `MetricsTracker` to track estimated costs. Update TUI dashboard to display running cost alongside tokens.

**Tech Stack:** Rust, TOML (serde), SQLite, Ratatui

---

## Task 1: Create Pricing TOML Config

**Files:**
- Create: `feroxmute-core/pricing.toml`

**Step 1: Create the pricing configuration file**

```toml
# Model pricing per 1M tokens (USD)
# Format: [models.<provider>.<model-key>]

[models.anthropic]
# Claude 4.5 series
claude-4-5-sonnet = { input = 3.0, output = 15.0 }
claude-4-5-sonnet-thinking = { input = 3.0, output = 15.0 }
# Claude 4 series
claude-4-sonnet = { input = 3.0, output = 15.0 }
claude-4-sonnet-thinking = { input = 3.0, output = 15.0 }
claude-4-opus = { input = 15.0, output = 75.0 }
claude-4-opus-thinking = { input = 15.0, output = 75.0 }
claude-4-1-opus = { input = 15.0, output = 75.0 }
claude-4-1-opus-thinking = { input = 15.0, output = 75.0 }
# Claude 3.5 series
claude-3-5-haiku = { input = 0.8, output = 4.0 }
claude-3-5-sonnet = { input = 3.0, output = 15.0 }

[models.openai]
# GPT-4o series
gpt-4o = { input = 2.5, output = 10.0 }
gpt-4o-mini = { input = 0.15, output = 0.6 }
# GPT-4.1 series
gpt-4-1 = { input = 2.0, output = 8.0 }
gpt-4-1-mini = { input = 0.4, output = 1.6 }
gpt-4-1-nano = { input = 0.1, output = 0.4 }
# GPT-5 series
gpt-5 = { input = 1.25, output = 10.0 }
gpt-5-mini = { input = 0.25, output = 2.0 }
gpt-5-nano = { input = 0.05, output = 0.4 }
# O-series reasoning
o1 = { input = 15.0, output = 60.0 }
o1-mini = { input = 1.1, output = 4.4 }
o3 = { input = 2.0, output = 8.0 }
o3-mini = { input = 1.1, output = 4.4 }
o4-mini = { input = 1.1, output = 4.4 }

[models.gemini]
# Gemini 2.5 series
gemini-2-5-flash = { input = 0.3, output = 2.5 }
gemini-2-5-pro = { input = 1.25, output = 10.0 }
# Gemini 3 preview (placeholder - update when available)
gemini-3-pro-preview = { input = 1.5, output = 12.0 }
gemini-3-flash-preview = { input = 0.4, output = 3.0 }

[models.xai]
# Grok 4 series
grok-4 = { input = 3.0, output = 15.0 }
grok-4-fast = { input = 0.2, output = 0.5 }
grok-4-fast-reasoning = { input = 0.2, output = 0.5 }

[models.deepseek]
deepseek-v3 = { input = 0.5, output = 1.25 }
deepseek-r1 = { input = 0.8, output = 3.0 }

[models.cohere]
command-r-plus = { input = 2.5, output = 10.0 }
command-r = { input = 0.15, output = 0.6 }
command-a = { input = 2.5, output = 10.0 }

[models.perplexity]
sonar = { input = 1.0, output = 1.0 }
sonar-pro = { input = 3.0, output = 15.0 }
sonar-reasoning = { input = 1.0, output = 5.0 }
```

**Step 2: Verify file is valid TOML**

Run: `cat feroxmute-core/pricing.toml | python3 -c "import sys, tomllib; tomllib.loads(sys.stdin.read()); print('Valid TOML')"` (or use a toml validator)
Expected: Valid TOML

**Step 3: Commit**

```bash
git add feroxmute-core/pricing.toml
git commit -m "$(cat <<'EOF'
feat: add model pricing configuration

Add TOML file with per-1M-token pricing for supported models:
- Anthropic Claude 4.5/4/3.5 series
- OpenAI GPT-4o/4.1/5 series and O-series
- Gemini 2.5 and 3 preview
- Grok 4, DeepSeek, Cohere, Perplexity
EOF
)"
```

---

## Task 2: Create Pricing Module

**Files:**
- Create: `feroxmute-core/src/pricing.rs`
- Modify: `feroxmute-core/src/lib.rs:6` (add module)

**Step 1: Write the failing test**

Create `feroxmute-core/src/pricing.rs`:

```rust
//! Model pricing for cost estimation

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

impl PricingConfig {
    /// Load pricing from embedded TOML
    pub fn load() -> Self {
        let toml_str = include_str!("../pricing.toml");
        toml::from_str(toml_str).expect("Invalid pricing.toml")
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

/// Normalize model name by removing date suffixes and common variations
fn normalize_model_name(model: &str) -> String {
    let model = model.to_lowercase();

    // Remove date suffixes like -20250514, -2024-08-06
    let re = regex::Regex::new(r"-\d{4}[-]?\d{2}[-]?\d{2}$").unwrap();
    let model = re.replace(&model, "").to_string();

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
        assert_eq!(normalize_model_name("claude-sonnet-4-20250514"), "claude-4-sonnet");
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
```

**Step 2: Add module to lib.rs**

Modify `feroxmute-core/src/lib.rs` line 6, add after `pub mod error;`:

```rust
pub mod pricing;
```

**Step 3: Add regex dependency if not present**

Check `feroxmute-core/Cargo.toml` for regex. If missing:

```bash
cd feroxmute-core && cargo add regex
```

**Step 4: Run tests to verify**

Run: `cargo test -p feroxmute-core pricing`
Expected: All tests pass

**Step 5: Commit**

```bash
git add feroxmute-core/src/pricing.rs feroxmute-core/src/lib.rs feroxmute-core/Cargo.toml
git commit -m "$(cat <<'EOF'
feat(pricing): add pricing module for cost estimation

- Load pricing from embedded TOML config
- Normalize model names (handle date suffixes, aliases)
- Calculate cost from input/output token counts
EOF
)"
```

---

## Task 3: Extend Metrics with Cost Tracking

**Files:**
- Modify: `feroxmute-core/src/state/metrics.rs:46-57` (TokenCounts, Metrics structs)
- Modify: `feroxmute-core/src/state/schema.rs:117-124` (metrics table)
- Modify: `feroxmute-core/src/state/migrations.rs:12-16` (init metrics)

**Step 1: Add estimated_cost_usd to TokenCounts**

In `feroxmute-core/src/state/metrics.rs`, update `TokenCounts` struct (lines 45-50):

```rust
/// Snapshot of token counts
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TokenCounts {
    pub input: u64,
    pub cached: u64,
    pub output: u64,
}
```

Change to:

```rust
/// Snapshot of token counts
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TokenCounts {
    pub input: u64,
    pub cached: u64,
    pub output: u64,
    pub estimated_cost_usd: f64,
}
```

**Step 2: Update Metrics struct**

The `Metrics` struct uses `TokenCounts`, so it inherits the new field. No changes needed there.

**Step 3: Update schema.rs metrics table (lines 117-124)**

Change:

```sql
CREATE TABLE IF NOT EXISTS metrics (
    id TEXT PRIMARY KEY,
    tool_calls INTEGER NOT NULL DEFAULT 0,
    tokens_input INTEGER NOT NULL DEFAULT 0,
    tokens_cached INTEGER NOT NULL DEFAULT 0,
    tokens_output INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
```

To:

```sql
CREATE TABLE IF NOT EXISTS metrics (
    id TEXT PRIMARY KEY,
    tool_calls INTEGER NOT NULL DEFAULT 0,
    tokens_input INTEGER NOT NULL DEFAULT 0,
    tokens_cached INTEGER NOT NULL DEFAULT 0,
    tokens_output INTEGER NOT NULL DEFAULT 0,
    estimated_cost_usd REAL NOT NULL DEFAULT 0.0,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
```

**Step 4: Update migrations.rs init (lines 12-16)**

Change:

```rust
conn.execute(
    "INSERT OR IGNORE INTO metrics (id, tool_calls, tokens_input, tokens_cached, tokens_output)
     VALUES ('global', 0, 0, 0, 0)",
    [],
)?;
```

To:

```rust
conn.execute(
    "INSERT OR IGNORE INTO metrics (id, tool_calls, tokens_input, tokens_cached, tokens_output, estimated_cost_usd)
     VALUES ('global', 0, 0, 0, 0, 0.0)",
    [],
)?;
```

**Step 5: Update Metrics::load() in metrics.rs (lines 61-78)**

Change the query and struct construction to include estimated_cost_usd:

```rust
pub fn load(conn: &Connection) -> Result<Self> {
    let mut stmt = conn.prepare(
        "SELECT tool_calls, tokens_input, tokens_cached, tokens_output, estimated_cost_usd FROM metrics WHERE id = 'global'"
    )?;

    let metrics = stmt.query_row([], |row| {
        Ok(Self {
            tool_calls: row.get::<_, i64>(0)? as u64,
            tokens: TokenCounts {
                input: row.get::<_, i64>(1)? as u64,
                cached: row.get::<_, i64>(2)? as u64,
                output: row.get::<_, i64>(3)? as u64,
                estimated_cost_usd: row.get::<_, f64>(4)?,
            },
        })
    })?;

    Ok(metrics)
}
```

**Step 6: Update Metrics::save() in metrics.rs (lines 80-98)**

```rust
pub fn save(&self, conn: &Connection) -> Result<()> {
    conn.execute(
        "UPDATE metrics SET
            tool_calls = ?1,
            tokens_input = ?2,
            tokens_cached = ?3,
            tokens_output = ?4,
            estimated_cost_usd = ?5,
            updated_at = datetime('now')
         WHERE id = 'global'",
        params![
            self.tool_calls as i64,
            self.tokens.input as i64,
            self.tokens.cached as i64,
            self.tokens.output as i64,
            self.tokens.estimated_cost_usd,
        ],
    )?;
    Ok(())
}
```

**Step 7: Update add_tokens method (lines 105-110)**

Add cost parameter:

```rust
/// Add token counts and cost
pub fn add_tokens(&mut self, input: u64, cached: u64, output: u64, cost: f64) {
    self.tokens.input += input;
    self.tokens.cached += cached;
    self.tokens.output += output;
    self.tokens.estimated_cost_usd += cost;
}
```

**Step 8: Run tests**

Run: `cargo test -p feroxmute-core state::metrics`
Expected: Tests pass (may need to update test assertions for new field)

**Step 9: Commit**

```bash
git add feroxmute-core/src/state/metrics.rs feroxmute-core/src/state/schema.rs feroxmute-core/src/state/migrations.rs
git commit -m "$(cat <<'EOF'
feat(metrics): add estimated_cost_usd to token tracking

- Add estimated_cost_usd field to TokenCounts
- Update database schema and migrations
- Extend add_tokens() to accumulate cost
EOF
)"
```

---

## Task 4: Extend MetricsTracker for Thread-Safe Cost

**Files:**
- Modify: `feroxmute-core/src/state/metrics.rs:113-180` (MetricsTracker)

**Step 1: Add AtomicU64 for cost (stored as cents to avoid floating point)**

Update `TokenCounter` struct (lines 11-16):

```rust
/// Token usage counters
#[derive(Debug, Default)]
pub struct TokenCounter {
    pub input: AtomicU64,
    pub cached: AtomicU64,
    pub output: AtomicU64,
    /// Cost in micro-dollars (1 USD = 1_000_000 micro-dollars) for atomic precision
    pub cost_micro_usd: AtomicU64,
}
```

**Step 2: Add method to add cost**

Add after `add_output` method (around line 32):

```rust
/// Add cost in USD (converted to micro-dollars internally)
pub fn add_cost(&self, cost_usd: f64) {
    let micro_usd = (cost_usd * 1_000_000.0) as u64;
    self.cost_micro_usd.fetch_add(micro_usd, Ordering::Relaxed);
}
```

**Step 3: Update TokenCounter::get() (lines 34-42)**

```rust
/// Get current counts
pub fn get(&self) -> TokenCounts {
    TokenCounts {
        input: self.input.load(Ordering::Relaxed),
        cached: self.cached.load(Ordering::Relaxed),
        output: self.output.load(Ordering::Relaxed),
        estimated_cost_usd: self.cost_micro_usd.load(Ordering::Relaxed) as f64 / 1_000_000.0,
    }
}
```

**Step 4: Update MetricsTracker::from_metrics() (lines 136-154)**

Add cost initialization:

```rust
pub fn from_metrics(metrics: &Metrics) -> Self {
    let tracker = Self::new();
    tracker
        .tool_calls
        .store(metrics.tool_calls, Ordering::Relaxed);
    tracker
        .tokens
        .input
        .store(metrics.tokens.input, Ordering::Relaxed);
    tracker
        .tokens
        .cached
        .store(metrics.tokens.cached, Ordering::Relaxed);
    tracker
        .tokens
        .output
        .store(metrics.tokens.output, Ordering::Relaxed);
    tracker
        .tokens
        .cost_micro_usd
        .store((metrics.tokens.estimated_cost_usd * 1_000_000.0) as u64, Ordering::Relaxed);
    tracker
}
```

**Step 5: Update record_tokens to include cost (lines 161-166)**

```rust
/// Record token usage and cost
pub fn record_tokens(&self, input: u64, cached: u64, output: u64, cost_usd: f64) {
    self.tokens.add_input(input);
    self.tokens.add_cached(cached);
    self.tokens.add_output(output);
    self.tokens.add_cost(cost_usd);
}
```

**Step 6: Run tests**

Run: `cargo test -p feroxmute-core state::metrics`
Expected: Tests pass

**Step 7: Commit**

```bash
git add feroxmute-core/src/state/metrics.rs
git commit -m "$(cat <<'EOF'
feat(metrics): add thread-safe cost tracking to MetricsTracker

- Store cost as micro-dollars (AtomicU64) for atomic precision
- Update record_tokens() to accept cost parameter
- Convert to/from f64 USD at boundaries
EOF
)"
```

---

## Task 5: Update Providers to Calculate and Record Cost

**Files:**
- Modify: `feroxmute-core/src/providers/anthropic.rs` (as template for other providers)

**Step 1: Find where tokens are recorded**

Search for `record_tokens` calls in the provider files:

Run: `grep -n "record_tokens" feroxmute-core/src/providers/*.rs`

**Step 2: Update each provider to calculate cost**

For each provider that calls `record_tokens`, update to include cost calculation.

Example for Anthropic provider - find the location where `record_tokens` is called and add:

```rust
use crate::pricing::PricingConfig;

// In the completion method, after getting token usage:
let pricing = PricingConfig::load();
let cost = pricing.calculate_cost(
    "anthropic",
    &self.model,
    usage.input_tokens,
    usage.output_tokens,
);
self.metrics.record_tokens(
    usage.input_tokens,
    usage.cache_read_tokens,
    usage.output_tokens,
    cost,
);
```

Note: Each provider needs its own provider name string ("anthropic", "openai", "gemini", etc.)

**Step 3: Run build to check compilation**

Run: `cargo build -p feroxmute-core`
Expected: Builds successfully

**Step 4: Commit**

```bash
git add feroxmute-core/src/providers/
git commit -m "$(cat <<'EOF'
feat(providers): calculate and record token costs

- Load pricing config in each provider
- Calculate cost from token usage
- Pass cost to metrics tracker
EOF
)"
```

---

## Task 6: Update TUI App State for Cost Display

**Files:**
- Modify: `feroxmute-cli/src/tui/app.rs:31-38` (Metrics struct)
- Modify: `feroxmute-cli/src/tui/channel.rs:37-41` (AgentEvent::Metrics)

**Step 1: Add estimated_cost_usd to TUI Metrics struct**

In `feroxmute-cli/src/tui/app.rs`, update the Metrics struct (lines 31-38):

```rust
/// Metrics display
#[derive(Debug, Clone, Default)]
pub struct Metrics {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_tokens: u64,
    pub tool_calls: u64,
    pub estimated_cost_usd: f64,
}
```

**Step 2: Update AgentEvent::Metrics in channel.rs (lines 37-41)**

```rust
/// Update token metrics
Metrics {
    input: u64,
    output: u64,
    cache_read: u64,
    cost_usd: f64,
},
```

**Step 3: Update App::update_metrics method (lines 292-298)**

```rust
/// Update metrics
pub fn update_metrics(&mut self, input: u64, output: u64, cache_read: u64, tool_calls: u64, cost: f64) {
    self.metrics.input_tokens += input;
    self.metrics.output_tokens += output;
    self.metrics.cache_read_tokens += cache_read;
    self.metrics.tool_calls += tool_calls;
    self.metrics.estimated_cost_usd += cost;
}
```

**Step 4: Update event handler for Metrics event**

Find where `AgentEvent::Metrics` is handled in the TUI runner and update to pass cost.

**Step 5: Run build**

Run: `cargo build -p feroxmute-cli`
Expected: Builds successfully

**Step 6: Commit**

```bash
git add feroxmute-cli/src/tui/app.rs feroxmute-cli/src/tui/channel.rs
git commit -m "$(cat <<'EOF'
feat(tui): add cost field to app metrics

- Add estimated_cost_usd to Metrics struct
- Update AgentEvent::Metrics to include cost
- Update update_metrics() to accumulate cost
EOF
)"
```

---

## Task 7: Update Dashboard to Display Cost

**Files:**
- Modify: `feroxmute-cli/src/tui/widgets/dashboard.rs:74-83` (render_metrics)

**Step 1: Update token metrics display**

In `feroxmute-cli/src/tui/widgets/dashboard.rs`, update the token metrics section (lines 74-83):

Change:

```rust
// Token metrics
let tokens = format!(
    "In: {} | Out: {} | Cache: {}",
    format_number(app.metrics.input_tokens),
    format_number(app.metrics.output_tokens),
    format_number(app.metrics.cache_read_tokens)
);
let token_block =
    Paragraph::new(tokens).block(Block::default().borders(Borders::ALL).title(" Tokens "));
```

To:

```rust
// Token metrics with cost
let tokens = format!(
    "In: {} | Out: {} | Cache: {} | Cost: {}",
    format_number(app.metrics.input_tokens),
    format_number(app.metrics.output_tokens),
    format_number(app.metrics.cache_read_tokens),
    format_cost(app.metrics.estimated_cost_usd)
);
let token_block =
    Paragraph::new(tokens).block(Block::default().borders(Borders::ALL).title(" Tokens "));
```

**Step 2: Add format_cost helper function**

Add after `format_number` function (around line 326):

```rust
/// Format cost in USD
fn format_cost(cost: f64) -> String {
    if cost < 0.01 {
        format!("${:.4}", cost)
    } else if cost < 1.0 {
        format!("${:.2}", cost)
    } else if cost < 100.0 {
        format!("${:.2}", cost)
    } else {
        format!("${:.0}", cost)
    }
}
```

**Step 3: Add test for format_cost**

Add to the tests module:

```rust
#[test]
fn test_format_cost() {
    assert_eq!(format_cost(0.0001), "$0.0001");
    assert_eq!(format_cost(0.05), "$0.05");
    assert_eq!(format_cost(1.234), "$1.23");
    assert_eq!(format_cost(150.0), "$150");
}
```

**Step 4: Run tests**

Run: `cargo test -p feroxmute-cli widgets::dashboard`
Expected: Tests pass

**Step 5: Commit**

```bash
git add feroxmute-cli/src/tui/widgets/dashboard.rs
git commit -m "$(cat <<'EOF'
feat(tui): display session cost in metrics panel

- Add cost to token metrics display: "Cost: $X.XX"
- Smart formatting (4 decimals for tiny, 2 for normal)
EOF
)"
```

---

## Task 8: Wire Up Event Emission

**Files:**
- Find and modify: Files that emit `AgentEvent::Metrics`

**Step 1: Search for Metrics event emission**

Run: `grep -rn "AgentEvent::Metrics" feroxmute-cli/src/`

**Step 2: Update each emission site**

Where `AgentEvent::Metrics` is sent, ensure cost is included:

```rust
AgentEvent::Metrics {
    input: usage.input_tokens,
    output: usage.output_tokens,
    cache_read: usage.cache_read_tokens,
    cost_usd: calculated_cost,
}
```

**Step 3: Run full test suite**

Run: `cargo test`
Expected: All tests pass

**Step 4: Commit**

```bash
git add .
git commit -m "$(cat <<'EOF'
feat: wire up cost tracking through event system

- Update all AgentEvent::Metrics emissions to include cost
- End-to-end cost tracking from provider to TUI
EOF
)"
```

---

## Task 9: Final Integration Test

**Step 1: Build release**

Run: `cargo build --release`
Expected: Builds successfully

**Step 2: Manual verification (if applicable)**

Run feroxmute with a test target and verify:
- TUI shows "Cost: $X.XX" in the metrics panel
- Cost increases as LLM calls are made
- Cost persists in session database

**Step 3: Clean up costs.json**

The original `costs.json` file is no longer needed:

```bash
rm costs.json
git add -A
git commit -m "chore: remove costs.json (replaced by pricing.toml)"
```

---

## Summary

This implementation adds:

1. **pricing.toml** - TOML config with model pricing for Anthropic, OpenAI, Gemini, Grok, DeepSeek, Cohere, Perplexity
2. **pricing module** - Loads config, normalizes model names, calculates costs
3. **Metrics extension** - `estimated_cost_usd` field in `TokenCounts` and `Metrics`
4. **Thread-safe tracking** - `MetricsTracker` with atomic cost accumulation
5. **Provider integration** - Each provider calculates and records cost per completion
6. **TUI display** - Dashboard shows "Cost: $X.XX" alongside token counts
7. **Persistence** - Cost saved to SQLite session database
