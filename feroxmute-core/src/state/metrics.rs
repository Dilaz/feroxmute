//! Metrics tracking for tool calls and token usage

use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::Result;

/// Token usage counters
#[derive(Debug, Default)]
pub struct TokenCounter {
    pub input: AtomicU64,
    pub cached: AtomicU64,
    pub output: AtomicU64,
    /// Cost in micro-dollars (1 USD = 1_000_000 micro-dollars) for atomic precision
    pub cost_micro_usd: AtomicU64,
}

impl TokenCounter {
    /// Add input tokens
    pub fn add_input(&self, count: u64) {
        self.input.fetch_add(count, Ordering::Relaxed);
    }

    /// Add cached tokens
    pub fn add_cached(&self, count: u64) {
        self.cached.fetch_add(count, Ordering::Relaxed);
    }

    /// Add output tokens
    pub fn add_output(&self, count: u64) {
        self.output.fetch_add(count, Ordering::Relaxed);
    }

    /// Add cost in USD (converted to micro-dollars internally)
    pub fn add_cost(&self, cost_usd: f64) {
        let micro_usd = (cost_usd * 1_000_000.0) as u64;
        self.cost_micro_usd.fetch_add(micro_usd, Ordering::Relaxed);
    }

    /// Get current counts
    pub fn get(&self) -> TokenCounts {
        TokenCounts {
            input: self.input.load(Ordering::Relaxed),
            cached: self.cached.load(Ordering::Relaxed),
            output: self.output.load(Ordering::Relaxed),
            estimated_cost_usd: self.cost_micro_usd.load(Ordering::Relaxed) as f64 / 1_000_000.0,
        }
    }
}

/// Snapshot of token counts
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TokenCounts {
    pub input: u64,
    pub cached: u64,
    pub output: u64,
    pub estimated_cost_usd: f64,
}

/// Session metrics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Metrics {
    pub tool_calls: u64,
    pub tokens: TokenCounts,
}

impl Metrics {
    /// Load metrics from database
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

    /// Save metrics to database
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

    /// Increment tool calls
    pub fn increment_tool_calls(&mut self) {
        self.tool_calls += 1;
    }

    /// Add token counts and cost
    pub fn add_tokens(&mut self, input: u64, cached: u64, output: u64, cost: f64) {
        self.tokens.input += input;
        self.tokens.cached += cached;
        self.tokens.output += output;
        self.tokens.estimated_cost_usd += cost;
    }
}

/// Thread-safe metrics tracker
#[derive(Debug, Clone)]
pub struct MetricsTracker {
    tool_calls: Arc<AtomicU64>,
    tokens: Arc<TokenCounter>,
}

impl Default for MetricsTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricsTracker {
    /// Create a new metrics tracker
    pub fn new() -> Self {
        Self {
            tool_calls: Arc::new(AtomicU64::new(0)),
            tokens: Arc::new(TokenCounter::default()),
        }
    }

    /// Create from existing metrics
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
        tracker.tokens.cost_micro_usd.store(
            (metrics.tokens.estimated_cost_usd * 1_000_000.0) as u64,
            Ordering::Relaxed,
        );
        tracker
    }

    /// Record a tool call
    pub fn record_tool_call(&self) {
        self.tool_calls.fetch_add(1, Ordering::Relaxed);
    }

    /// Record token usage and cost
    pub fn record_tokens(&self, input: u64, cached: u64, output: u64, cost_usd: f64) {
        self.tokens.add_input(input);
        self.tokens.add_cached(cached);
        self.tokens.add_output(output);
        self.tokens.add_cost(cost_usd);
    }

    /// Get current metrics snapshot
    pub fn snapshot(&self) -> Metrics {
        Metrics {
            tool_calls: self.tool_calls.load(Ordering::Relaxed),
            tokens: self.tokens.get(),
        }
    }

    /// Save to database
    pub fn save(&self, conn: &Connection) -> Result<()> {
        self.snapshot().save(conn)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::state::run_migrations;

    fn setup_db() -> Connection {
        let conn = Connection::open_in_memory().expect("should open in-memory db");
        run_migrations(&conn).expect("migrations should succeed");
        conn
    }

    #[test]
    fn test_metrics_load_save() {
        let conn = setup_db();

        let mut metrics = Metrics::load(&conn).expect("should load metrics");
        assert_eq!(metrics.tool_calls, 0);

        metrics.tool_calls = 42;
        metrics.tokens.input = 1000;
        metrics.tokens.output = 500;
        metrics.save(&conn).expect("should save metrics");

        let loaded = Metrics::load(&conn).expect("should load updated metrics");
        assert_eq!(loaded.tool_calls, 42);
        assert_eq!(loaded.tokens.input, 1000);
    }

    #[test]
    fn test_metrics_tracker() {
        let tracker = MetricsTracker::new();

        tracker.record_tool_call();
        tracker.record_tool_call();
        tracker.record_tokens(100, 20, 50, 0.05);

        let snapshot = tracker.snapshot();
        assert_eq!(snapshot.tool_calls, 2);
        assert_eq!(snapshot.tokens.input, 100);
        assert_eq!(snapshot.tokens.cached, 20);
        assert_eq!(snapshot.tokens.output, 50);
        assert!((snapshot.tokens.estimated_cost_usd - 0.05).abs() < 1e-6);
    }

    #[test]
    fn test_metrics_tracker_thread_safe() {
        use std::thread;

        let tracker = MetricsTracker::new();
        let tracker2 = tracker.clone();

        let handle = thread::spawn(move || {
            for _ in 0..100 {
                tracker2.record_tool_call();
            }
        });

        for _ in 0..100 {
            tracker.record_tool_call();
        }

        handle.join().expect("thread should complete");

        assert_eq!(tracker.snapshot().tool_calls, 200);
    }
}
