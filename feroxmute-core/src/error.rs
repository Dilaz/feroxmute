//! Error types for feroxmute-core

use miette::Diagnostic;
use thiserror::Error;

/// Result type alias using feroxmute Error
pub type Result<T> = std::result::Result<T, Error>;

/// Core error types for feroxmute
#[derive(Debug, Error, Diagnostic)]
pub enum Error {
    #[error("Configuration error: {0}")]
    #[diagnostic(code(feroxmute::config))]
    Config(String),

    #[error("Database error: {0}")]
    #[diagnostic(code(feroxmute::database))]
    Database(#[from] rusqlite::Error),

    #[error("Docker error: {0}")]
    #[diagnostic(code(feroxmute::docker))]
    Docker(#[from] bollard::errors::Error),

    #[error("IO error: {0}")]
    #[diagnostic(code(feroxmute::io))]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    #[diagnostic(code(feroxmute::serde))]
    Serde(#[from] serde_json::Error),

    #[error("TOML parse error: {0}")]
    #[diagnostic(code(feroxmute::toml))]
    Toml(#[from] toml::de::Error),

    #[error("Provider error: {0}")]
    #[diagnostic(code(feroxmute::provider))]
    Provider(String),

    #[error("Agent error: {0}")]
    #[diagnostic(code(feroxmute::agent))]
    Agent(String),

    #[error("Tool execution error: {0}")]
    #[diagnostic(code(feroxmute::tool))]
    Tool(String),

    #[error("Session not found: {0}")]
    #[diagnostic(code(feroxmute::session))]
    SessionNotFound(String),

    #[error("Report generation error: {0}")]
    #[diagnostic(code(feroxmute::report))]
    Report(String),
}
