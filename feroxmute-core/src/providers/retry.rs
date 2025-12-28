//! Retry logic for LLM provider operations
//!
//! This module provides retry functionality with exponential backoff for transient
//! LLM provider errors such as HTTP 500, rate limits, and connection timeouts.

use std::time::Duration;

use backon::ExponentialBuilder;

/// Configuration for retry behavior
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of retry attempts
    pub max_retries: usize,
    /// Initial delay before first retry
    pub initial_delay: Duration,
    /// Maximum delay between retries
    pub max_delay: Duration,
    /// Whether to add jitter to delays
    pub jitter: bool,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(30),
            jitter: true,
        }
    }
}

/// Classify an error message as retriable (transient) or not (permanent)
///
/// Retriable errors include:
/// - HTTP 5xx server errors (500, 502, 503, 504)
/// - HTTP 429 rate limiting
/// - Connection timeouts and failures
/// - Provider overload/capacity issues
pub fn is_retriable_error(error_message: &str) -> bool {
    let lower = error_message.to_lowercase();

    // HTTP status codes and messages that indicate transient issues
    let transient_patterns = [
        // HTTP 5xx server errors
        "500",
        "502",
        "503",
        "504",
        "internal server error",
        "bad gateway",
        "service unavailable",
        "gateway timeout",
        // Rate limiting
        "429",
        "rate limit",
        "too many requests",
        "quota exceeded",
        // Connection issues
        "timeout",
        "timed out",
        "connection refused",
        "connection reset",
        "connection failed",
        "network error",
        // Provider-specific overload messages
        "overloaded",
        "capacity",
        "temporarily unavailable",
        "try again",
        "retry",
    ];

    // Check if any transient pattern matches
    transient_patterns
        .iter()
        .any(|pattern| lower.contains(pattern))
}

/// Build an exponential backoff strategy from configuration
pub fn build_backoff(config: &RetryConfig) -> ExponentialBuilder {
    let mut builder = ExponentialBuilder::default()
        .with_min_delay(config.initial_delay)
        .with_max_delay(config.max_delay)
        .with_max_times(config.max_retries);

    if config.jitter {
        builder = builder.with_jitter();
    }

    builder
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn test_retriable_http_500() {
        assert!(is_retriable_error("HTTP 500 Internal Server Error"));
        assert!(is_retriable_error("Status code 500"));
        assert!(is_retriable_error("internal server error"));
    }

    #[test]
    fn test_retriable_rate_limit() {
        assert!(is_retriable_error("429 Too Many Requests"));
        assert!(is_retriable_error("rate limit exceeded"));
        assert!(is_retriable_error("quota exceeded for today"));
    }

    #[test]
    fn test_retriable_connection() {
        assert!(is_retriable_error("connection timeout"));
        assert!(is_retriable_error("connection refused"));
        assert!(is_retriable_error("network error occurred"));
    }

    #[test]
    fn test_retriable_provider_overload() {
        assert!(is_retriable_error("API is currently overloaded"));
        assert!(is_retriable_error("at capacity, please try again"));
        assert!(is_retriable_error("temporarily unavailable"));
    }

    #[test]
    fn test_non_retriable_auth() {
        assert!(!is_retriable_error("401 Unauthorized"));
        assert!(!is_retriable_error("Invalid API key"));
        assert!(!is_retriable_error("403 Forbidden"));
    }

    #[test]
    fn test_non_retriable_bad_request() {
        assert!(!is_retriable_error("400 Bad Request"));
        assert!(!is_retriable_error("Invalid model name"));
        assert!(!is_retriable_error("Malformed request"));
    }

    #[test]
    fn test_default_config() {
        let config = RetryConfig::default();
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.initial_delay, Duration::from_secs(1));
        assert_eq!(config.max_delay, Duration::from_secs(30));
        assert!(config.jitter);
    }
}
