# feroxmute Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build an LLM-powered penetration testing framework with hierarchical agents, TUI, and report generation.

**Architecture:** Rust workspace with two crates (feroxmute-core library, feroxmute-cli binary). Agents run tools inside a Kali Docker container via bollard. State persisted in SQLite. Rig.rs for LLM providers.

**Tech Stack:** Rust, rig-core, rusqlite, bollard, ratatui, tokio, serde, clap, miette, thiserror, tracing

---

## Phase 1: Project Setup

### Task 1.1: Convert to Workspace

**Files:**
- Modify: `/home/dilaz/kood/feroxmute/Cargo.toml`
- Delete: `/home/dilaz/kood/feroxmute/src/main.rs`
- Create: `/home/dilaz/kood/feroxmute/feroxmute-core/Cargo.toml`
- Create: `/home/dilaz/kood/feroxmute/feroxmute-core/src/lib.rs`
- Create: `/home/dilaz/kood/feroxmute/feroxmute-cli/Cargo.toml`
- Create: `/home/dilaz/kood/feroxmute/feroxmute-cli/src/main.rs`

**Step 1: Update workspace Cargo.toml**

```toml
[workspace]
resolver = "2"
members = ["feroxmute-core", "feroxmute-cli"]

[workspace.package]
version = "0.1.0"
edition = "2021"
license = "MIT"
authors = ["Your Name"]

[workspace.dependencies]
# Async runtime
tokio = { version = "1", features = ["full"] }

# Serialization
serde = { version = "1", features = ["derive"] }
serde_json = "1"
toml = "0.8"

# Error handling
thiserror = "2"
anyhow = "1"
miette = { version = "7", features = ["fancy"] }

# Logging
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }

# LLM
rig-core = "0.6"

# Database
rusqlite = { version = "0.32", features = ["bundled"] }

# Docker
bollard = "0.18"

# TUI
ratatui = "0.29"
crossterm = "0.28"

# CLI
clap = { version = "4", features = ["derive"] }

# Time
chrono = { version = "0.4", features = ["serde"] }

# Utilities
uuid = { version = "1", features = ["v4", "serde"] }
async-trait = "0.1"
futures = "0.3"
```

**Step 2: Create feroxmute-core directory and Cargo.toml**

```bash
mkdir -p feroxmute-core/src
```

Create `feroxmute-core/Cargo.toml`:

```toml
[package]
name = "feroxmute-core"
version.workspace = true
edition.workspace = true

[dependencies]
tokio.workspace = true
serde.workspace = true
serde_json.workspace = true
toml.workspace = true
thiserror.workspace = true
miette.workspace = true
tracing.workspace = true
rig-core.workspace = true
rusqlite.workspace = true
bollard.workspace = true
chrono.workspace = true
uuid.workspace = true
async-trait.workspace = true
futures.workspace = true

[dev-dependencies]
tokio = { workspace = true, features = ["test-util"] }
tempfile = "3"
```

**Step 3: Create feroxmute-core/src/lib.rs**

```rust
//! feroxmute-core: LLM-powered penetration testing framework library

pub mod config;
pub mod error;

pub use error::{Error, Result};
```

**Step 4: Create feroxmute-cli directory and Cargo.toml**

```bash
mkdir -p feroxmute-cli/src
```

Create `feroxmute-cli/Cargo.toml`:

```toml
[package]
name = "feroxmute-cli"
version.workspace = true
edition.workspace = true

[[bin]]
name = "feroxmute"
path = "src/main.rs"

[dependencies]
feroxmute-core = { path = "../feroxmute-core" }
tokio.workspace = true
serde.workspace = true
anyhow.workspace = true
miette = { workspace = true, features = ["fancy"] }
tracing.workspace = true
tracing-subscriber.workspace = true
ratatui.workspace = true
crossterm.workspace = true
clap.workspace = true
```

**Step 5: Create feroxmute-cli/src/main.rs**

```rust
use anyhow::Result;
use tracing_subscriber::{fmt, EnvFilter};

fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    println!("feroxmute v{}", env!("CARGO_PKG_VERSION"));
    Ok(())
}
```

**Step 6: Delete old src/main.rs**

```bash
rm -rf src
```

**Step 7: Verify workspace builds**

Run: `cargo build`
Expected: Build succeeds with both crates

**Step 8: Commit**

```bash
git add -A
git commit -m "feat: convert to workspace with core and cli crates"
```

---

### Task 1.2: Core Error Types

**Files:**
- Create: `/home/dilaz/kood/feroxmute/feroxmute-core/src/error.rs`
- Modify: `/home/dilaz/kood/feroxmute/feroxmute-core/src/lib.rs`

**Step 1: Create error.rs with thiserror**

```rust
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
}
```

**Step 2: Update lib.rs to export error module**

```rust
//! feroxmute-core: LLM-powered penetration testing framework library

pub mod config;
pub mod error;

pub use error::{Error, Result};
```

**Step 3: Verify it compiles**

Run: `cargo build -p feroxmute-core`
Expected: Build succeeds

**Step 4: Commit**

```bash
git add -A
git commit -m "feat(core): add error types with miette diagnostics"
```

---

### Task 1.3: Configuration Types

**Files:**
- Create: `/home/dilaz/kood/feroxmute/feroxmute-core/src/config.rs`

**Step 1: Write test for config parsing**

Create `feroxmute-core/src/config.rs`:

```rust
//! Configuration types for feroxmute engagements

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Testing scope
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    #[default]
    Web,
    Network,
    Full,
}

/// Authentication type for target
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthType {
    #[default]
    None,
    Basic,
    Bearer,
    Cookie,
}

/// LLM provider selection
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProviderName {
    #[default]
    Anthropic,
    OpenAi,
    Cohere,
    LiteLlm,
}

/// Target configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetConfig {
    pub host: String,
    #[serde(default)]
    pub scope: Scope,
    #[serde(default)]
    pub ports: Vec<u16>,
}

/// Engagement constraints
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Constraints {
    #[serde(default)]
    pub passive: bool,
    #[serde(default)]
    pub no_exploit: bool,
    #[serde(default)]
    pub no_portscan: bool,
    #[serde(default)]
    pub rate_limit: Option<u32>,
    #[serde(default)]
    pub excluded_paths: Vec<String>,
}

/// Authentication configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuthConfig {
    #[serde(default, rename = "type")]
    pub auth_type: AuthType,
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
}

/// LLM provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderConfig {
    #[serde(default)]
    pub name: ProviderName,
    pub model: String,
    #[serde(default)]
    pub base_url: Option<String>,
}

impl Default for ProviderConfig {
    fn default() -> Self {
        Self {
            name: ProviderName::Anthropic,
            model: "claude-sonnet-4-20250514".to_string(),
            base_url: None,
        }
    }
}

/// Output configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    #[serde(default = "default_session_dir")]
    pub session_dir: PathBuf,
    #[serde(default)]
    pub export_html: bool,
    #[serde(default)]
    pub export_pdf: bool,
}

fn default_session_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".feroxmute")
        .join("sessions")
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            session_dir: default_session_dir(),
            export_html: false,
            export_pdf: false,
        }
    }
}

/// Complete engagement configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngagementConfig {
    pub target: TargetConfig,
    #[serde(default)]
    pub constraints: Constraints,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub provider: ProviderConfig,
    #[serde(default)]
    pub output: OutputConfig,
}

impl EngagementConfig {
    /// Load configuration from a TOML file
    pub fn from_file(path: impl AsRef<std::path::Path>) -> crate::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        Self::from_str(&content)
    }

    /// Parse configuration from TOML string
    pub fn from_str(content: &str) -> crate::Result<Self> {
        Ok(toml::from_str(content)?)
    }

    /// Expand environment variables in token fields
    pub fn expand_env_vars(&mut self) {
        if let Some(ref token) = self.auth.token {
            if token.starts_with("${") && token.ends_with("}") {
                let var_name = &token[2..token.len() - 1];
                if let Ok(value) = std::env::var(var_name) {
                    self.auth.token = Some(value);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal_config() {
        let toml = r#"
[target]
host = "example.com"
"#;
        let config = EngagementConfig::from_str(toml).unwrap();
        assert_eq!(config.target.host, "example.com");
        assert_eq!(config.target.scope, Scope::Web);
    }

    #[test]
    fn test_parse_full_config() {
        let toml = r#"
[target]
host = "example.com"
scope = "web"
ports = [80, 443, 8080]

[constraints]
passive = false
no_exploit = true
rate_limit = 10

[auth]
type = "bearer"
token = "secret123"

[provider]
name = "anthropic"
model = "claude-sonnet-4-20250514"

[output]
export_html = true
"#;
        let config = EngagementConfig::from_str(toml).unwrap();
        assert_eq!(config.target.host, "example.com");
        assert_eq!(config.target.ports, vec![80, 443, 8080]);
        assert!(config.constraints.no_exploit);
        assert_eq!(config.constraints.rate_limit, Some(10));
        assert_eq!(config.auth.auth_type, AuthType::Bearer);
        assert!(config.output.export_html);
    }

    #[test]
    fn test_env_var_expansion() {
        std::env::set_var("TEST_TOKEN", "expanded_value");
        let toml = r#"
[target]
host = "example.com"

[auth]
type = "bearer"
token = "${TEST_TOKEN}"
"#;
        let mut config = EngagementConfig::from_str(toml).unwrap();
        config.expand_env_vars();
        assert_eq!(config.auth.token, Some("expanded_value".to_string()));
        std::env::remove_var("TEST_TOKEN");
    }
}
```

**Step 2: Add dirs dependency to feroxmute-core**

Update `feroxmute-core/Cargo.toml` dependencies:

```toml
dirs = "5"
```

**Step 3: Run tests to verify**

Run: `cargo test -p feroxmute-core`
Expected: All 3 tests pass

**Step 4: Commit**

```bash
git add -A
git commit -m "feat(core): add configuration types with TOML parsing"
```

---

### Task 1.4: CLI Argument Parsing

**Files:**
- Create: `/home/dilaz/kood/feroxmute/feroxmute-cli/src/args.rs`
- Modify: `/home/dilaz/kood/feroxmute/feroxmute-cli/src/main.rs`

**Step 1: Create args.rs with clap derive**

```rust
//! CLI argument parsing

use clap::Parser;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "feroxmute")]
#[command(author, version, about = "LLM-powered penetration testing framework")]
pub struct Args {
    /// Target domain or IP address
    #[arg(short, long)]
    pub target: Option<String>,

    /// Path to configuration file
    #[arg(short, long)]
    pub config: Option<PathBuf>,

    /// Interactive setup wizard
    #[arg(long)]
    pub wizard: bool,

    /// Resume a previous session
    #[arg(long)]
    pub resume: Option<PathBuf>,

    /// Testing scope (web, network, full)
    #[arg(long, default_value = "web")]
    pub scope: String,

    /// Recon and scan only, no exploitation
    #[arg(long)]
    pub no_exploit: bool,

    /// Skip port scanning
    #[arg(long)]
    pub no_portscan: bool,

    /// Passive recon only
    #[arg(long)]
    pub passive: bool,

    /// Limit port range (comma-separated)
    #[arg(long)]
    pub ports: Option<String>,

    /// Max requests per second
    #[arg(long)]
    pub rate_limit: Option<u32>,

    /// LLM provider (anthropic, openai, litellm)
    #[arg(long, default_value = "anthropic")]
    pub provider: String,

    /// Model to use
    #[arg(long)]
    pub model: Option<String>,

    /// Output directory for session
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Export HTML report
    #[arg(long)]
    pub html: bool,

    /// Export PDF report
    #[arg(long)]
    pub pdf: bool,

    /// Verbose output
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,
}

impl Args {
    /// Parse ports string into Vec<u16>
    pub fn parse_ports(&self) -> Vec<u16> {
        self.ports
            .as_ref()
            .map(|p| {
                p.split(',')
                    .filter_map(|s| s.trim().parse().ok())
                    .collect()
            })
            .unwrap_or_default()
    }
}
```

**Step 2: Update main.rs to use args**

```rust
mod args;

use anyhow::Result;
use args::Args;
use clap::Parser;
use tracing_subscriber::{fmt, EnvFilter};

fn main() -> Result<()> {
    let args = Args::parse();

    // Set up tracing based on verbosity
    let filter = match args.verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| filter.into()))
        .init();

    tracing::info!("feroxmute v{}", env!("CARGO_PKG_VERSION"));

    if args.wizard {
        println!("Interactive wizard not yet implemented");
        return Ok(());
    }

    if let Some(ref session) = args.resume {
        println!("Resuming session: {}", session.display());
        return Ok(());
    }

    if let Some(ref target) = args.target {
        println!("Target: {}", target);
        println!("Scope: {}", args.scope);
        println!("Provider: {}", args.provider);
        if let Some(ref model) = args.model {
            println!("Model: {}", model);
        }
    } else {
        println!("No target specified. Use --target or --wizard");
    }

    Ok(())
}
```

**Step 3: Verify CLI works**

Run: `cargo run -p feroxmute-cli -- --help`
Expected: Help text displays all options

Run: `cargo run -p feroxmute-cli -- --target example.com --verbose`
Expected: Shows target info with info-level logging

**Step 4: Commit**

```bash
git add -A
git commit -m "feat(cli): add CLI argument parsing with clap"
```

---

### Task 1.5: Docker Configuration

**Files:**
- Create: `/home/dilaz/kood/feroxmute/docker/Dockerfile`
- Create: `/home/dilaz/kood/feroxmute/docker/compose.yml`

**Step 1: Create docker directory**

```bash
mkdir -p docker
```

**Step 2: Create Dockerfile**

```dockerfile
FROM kalilinux/kali-rolling

# Avoid prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install base packages
RUN apt-get update && apt-get install -y \
    golang \
    git \
    curl \
    wget \
    sqlmap \
    feroxbuster \
    ffuf \
    chromium \
    python3 \
    whois \
    dnsutils \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Install ProjectDiscovery tools via pdtm
ENV GOPATH=/root/go
ENV PATH="${GOPATH}/bin:${PATH}"
RUN go install -v github.com/projectdiscovery/pdtm/cmd/pdtm@latest \
    && pdtm -install-all

# Install uv for Python package management
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.local/bin:${PATH}"

# Install Python packages with uv
RUN uv pip install --system playwright \
    && playwright install chromium --with-deps

# Create working directories
RUN mkdir -p /feroxmute/workdir/{orchestrator,recon,scanner,exploit,scripts} \
    /feroxmute/artifacts/{downloads,evidence} \
    /feroxmute/screenshots \
    /feroxmute/shared

WORKDIR /feroxmute

# Default command keeps container running
CMD ["tail", "-f", "/dev/null"]
```

**Step 3: Create compose.yml**

```yaml
services:
  kali:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: feroxmute-kali
    volumes:
      - ../sessions:/root/.feroxmute/sessions
      - ./workdir:/feroxmute/workdir
    networks:
      - feroxmute
    # Allow network access for scanning
    cap_add:
      - NET_ADMIN
      - NET_RAW
    security_opt:
      - seccomp:unconfined

  # Optional LiteLLM sidecar - only starts with --profile litellm
  litellm:
    profiles: ["litellm"]
    image: ghcr.io/berriai/litellm:main-latest
    container_name: feroxmute-litellm
    ports:
      - "4000:4000"
    environment:
      - OPENAI_API_KEY
      - ANTHROPIC_API_KEY
    networks:
      - feroxmute
    command: --model gpt-4o --model claude-sonnet-4-20250514

networks:
  feroxmute:
    driver: bridge
```

**Step 4: Create .dockerignore**

Create `/home/dilaz/kood/feroxmute/docker/.dockerignore`:

```
target/
.git/
*.md
```

**Step 5: Verify Dockerfile syntax**

Run: `docker build -t feroxmute-kali-test ./docker --dry-run 2>&1 | head -20 || echo "Syntax check passed (dry-run may not be supported)"`

**Step 6: Commit**

```bash
git add -A
git commit -m "feat: add Docker configuration for Kali container"
```

---

## Phase 2: State Management

### Task 2.1: Database Schema and Migrations

**Files:**
- Create: `/home/dilaz/kood/feroxmute/feroxmute-core/src/state/mod.rs`
- Create: `/home/dilaz/kood/feroxmute/feroxmute-core/src/state/schema.rs`
- Create: `/home/dilaz/kood/feroxmute/feroxmute-core/src/state/migrations.rs`
- Modify: `/home/dilaz/kood/feroxmute/feroxmute-core/src/lib.rs`

**Step 1: Create state module structure**

```bash
mkdir -p feroxmute-core/src/state
```

**Step 2: Create schema.rs with SQL definitions**

```rust
//! Database schema definitions

/// SQL to create all tables
pub const SCHEMA: &str = r#"
-- Core entities
CREATE TABLE IF NOT EXISTS hosts (
    id TEXT PRIMARY KEY,
    address TEXT NOT NULL,
    hostname TEXT,
    discovered_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS ports (
    id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL REFERENCES hosts(id),
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL DEFAULT 'tcp',
    service TEXT,
    state TEXT NOT NULL DEFAULT 'open',
    discovered_at TEXT NOT NULL,
    UNIQUE(host_id, port, protocol)
);

CREATE TABLE IF NOT EXISTS technologies (
    id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL REFERENCES hosts(id),
    name TEXT NOT NULL,
    version TEXT,
    category TEXT,
    discovered_at TEXT NOT NULL
);

-- Findings
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id TEXT PRIMARY KEY,
    host_id TEXT REFERENCES hosts(id),
    vuln_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    evidence TEXT,
    status TEXT NOT NULL DEFAULT 'potential',
    cwe TEXT,
    cvss REAL,
    asset TEXT,
    remediation TEXT,
    discovered_by TEXT NOT NULL,
    verified_by TEXT,
    discovered_at TEXT NOT NULL,
    verified_at TEXT
);

-- Agent state
CREATE TABLE IF NOT EXISTS agent_tasks (
    id TEXT PRIMARY KEY,
    agent TEXT NOT NULL,
    task TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    result TEXT,
    error TEXT,
    started_at TEXT,
    completed_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS agent_messages (
    id TEXT PRIMARY KEY,
    from_agent TEXT NOT NULL,
    to_agent TEXT NOT NULL,
    content TEXT NOT NULL,
    timestamp TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS tool_executions (
    id TEXT PRIMARY KEY,
    agent TEXT NOT NULL,
    tool TEXT NOT NULL,
    args TEXT NOT NULL,
    output TEXT,
    exit_code INTEGER,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Metrics
CREATE TABLE IF NOT EXISTS metrics (
    id TEXT PRIMARY KEY,
    tool_calls INTEGER NOT NULL DEFAULT 0,
    tokens_input INTEGER NOT NULL DEFAULT 0,
    tokens_cached INTEGER NOT NULL DEFAULT 0,
    tokens_output INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Session metadata
CREATE TABLE IF NOT EXISTS session_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Create indexes for common queries
CREATE INDEX IF NOT EXISTS idx_ports_host ON ports(host_id);
CREATE INDEX IF NOT EXISTS idx_technologies_host ON technologies(host_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_host ON vulnerabilities(host_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_status ON vulnerabilities(status);
CREATE INDEX IF NOT EXISTS idx_agent_tasks_agent ON agent_tasks(agent);
CREATE INDEX IF NOT EXISTS idx_agent_tasks_status ON agent_tasks(status);
CREATE INDEX IF NOT EXISTS idx_tool_executions_agent ON tool_executions(agent);
"#;
```

**Step 3: Create migrations.rs**

```rust
//! Database migrations

use rusqlite::Connection;

use crate::Result;

/// Run all migrations on the database
pub fn run_migrations(conn: &Connection) -> Result<()> {
    conn.execute_batch(super::schema::SCHEMA)?;

    // Initialize metrics if not exists
    conn.execute(
        "INSERT OR IGNORE INTO metrics (id, tool_calls, tokens_input, tokens_cached, tokens_output)
         VALUES ('global', 0, 0, 0, 0)",
        [],
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    #[test]
    fn test_migrations_run_successfully() {
        let conn = Connection::open_in_memory().unwrap();
        run_migrations(&conn).unwrap();

        // Verify tables exist
        let tables: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();

        assert!(tables.contains(&"hosts".to_string()));
        assert!(tables.contains(&"vulnerabilities".to_string()));
        assert!(tables.contains(&"agent_tasks".to_string()));
    }

    #[test]
    fn test_migrations_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        run_migrations(&conn).unwrap();
        run_migrations(&conn).unwrap(); // Should not fail
    }
}
```

**Step 4: Create state/mod.rs**

```rust
//! State management module

pub mod migrations;
pub mod schema;

pub use migrations::run_migrations;
```

**Step 5: Update lib.rs**

```rust
//! feroxmute-core: LLM-powered penetration testing framework library

pub mod config;
pub mod error;
pub mod state;

pub use error::{Error, Result};
```

**Step 6: Run tests**

Run: `cargo test -p feroxmute-core state`
Expected: Both migration tests pass

**Step 7: Commit**

```bash
git add -A
git commit -m "feat(core): add SQLite schema and migrations"
```

---

### Task 2.2: Session Management

**Files:**
- Create: `/home/dilaz/kood/feroxmute/feroxmute-core/src/state/session.rs`
- Modify: `/home/dilaz/kood/feroxmute/feroxmute-core/src/state/mod.rs`

**Step 1: Create session.rs**

```rust
//! Session management for feroxmute engagements

use chrono::{DateTime, Utc};
use rusqlite::Connection;
use std::path::{Path, PathBuf};
use uuid::Uuid;

use crate::config::EngagementConfig;
use crate::state::run_migrations;
use crate::{Error, Result};

/// A feroxmute session representing a single engagement
pub struct Session {
    /// Unique session identifier
    pub id: String,
    /// Session directory path
    pub path: PathBuf,
    /// Database connection
    conn: Connection,
    /// Session configuration
    pub config: EngagementConfig,
    /// When the session was created
    pub created_at: DateTime<Utc>,
}

impl Session {
    /// Create a new session for an engagement
    pub fn new(config: EngagementConfig, base_dir: impl AsRef<Path>) -> Result<Self> {
        let created_at = Utc::now();
        let id = format!(
            "{}-{}",
            created_at.format("%Y-%m-%d"),
            config.target.host.replace('.', "-")
        );

        let path = base_dir.as_ref().join(&id);
        std::fs::create_dir_all(&path)?;

        // Create subdirectories
        std::fs::create_dir_all(path.join("artifacts/downloads"))?;
        std::fs::create_dir_all(path.join("artifacts/evidence"))?;
        std::fs::create_dir_all(path.join("screenshots"))?;
        std::fs::create_dir_all(path.join("scripts/python"))?;
        std::fs::create_dir_all(path.join("scripts/rust"))?;
        std::fs::create_dir_all(path.join("reports"))?;

        // Save config
        let config_path = path.join("config.toml");
        let config_str = toml::to_string_pretty(&config)
            .map_err(|e| Error::Config(e.to_string()))?;
        std::fs::write(&config_path, config_str)?;

        // Create database
        let db_path = path.join("session.db");
        let conn = Connection::open(&db_path)?;
        run_migrations(&conn)?;

        // Store session metadata
        conn.execute(
            "INSERT INTO session_meta (key, value) VALUES ('id', ?1)",
            [&id],
        )?;
        conn.execute(
            "INSERT INTO session_meta (key, value) VALUES ('target', ?1)",
            [&config.target.host],
        )?;
        conn.execute(
            "INSERT INTO session_meta (key, value) VALUES ('created_at', ?1)",
            [&created_at.to_rfc3339()],
        )?;

        Ok(Self {
            id,
            path,
            conn,
            config,
            created_at,
        })
    }

    /// Resume an existing session from disk
    pub fn resume(session_path: impl AsRef<Path>) -> Result<Self> {
        let path = session_path.as_ref().to_path_buf();

        if !path.exists() {
            return Err(Error::SessionNotFound(path.display().to_string()));
        }

        // Load config
        let config_path = path.join("config.toml");
        let config = EngagementConfig::from_file(&config_path)?;

        // Open database
        let db_path = path.join("session.db");
        let conn = Connection::open(&db_path)?;

        // Read session metadata
        let id: String = conn.query_row(
            "SELECT value FROM session_meta WHERE key = 'id'",
            [],
            |row| row.get(0),
        )?;

        let created_at_str: String = conn.query_row(
            "SELECT value FROM session_meta WHERE key = 'created_at'",
            [],
            |row| row.get(0),
        )?;
        let created_at = DateTime::parse_from_rfc3339(&created_at_str)
            .map_err(|e| Error::Config(e.to_string()))?
            .with_timezone(&Utc);

        Ok(Self {
            id,
            path,
            conn,
            config,
            created_at,
        })
    }

    /// Get a reference to the database connection
    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    /// Get path to artifacts directory
    pub fn artifacts_dir(&self) -> PathBuf {
        self.path.join("artifacts")
    }

    /// Get path to screenshots directory
    pub fn screenshots_dir(&self) -> PathBuf {
        self.path.join("screenshots")
    }

    /// Get path to scripts directory
    pub fn scripts_dir(&self) -> PathBuf {
        self.path.join("scripts")
    }

    /// Get path to reports directory
    pub fn reports_dir(&self) -> PathBuf {
        self.path.join("reports")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use crate::config::TargetConfig;

    fn test_config() -> EngagementConfig {
        EngagementConfig {
            target: TargetConfig {
                host: "example.com".to_string(),
                scope: Default::default(),
                ports: vec![80, 443],
            },
            constraints: Default::default(),
            auth: Default::default(),
            provider: Default::default(),
            output: Default::default(),
        }
    }

    #[test]
    fn test_create_new_session() {
        let temp = TempDir::new().unwrap();
        let config = test_config();

        let session = Session::new(config, temp.path()).unwrap();

        assert!(session.id.contains("example-com"));
        assert!(session.path.exists());
        assert!(session.path.join("session.db").exists());
        assert!(session.path.join("config.toml").exists());
        assert!(session.artifacts_dir().join("downloads").exists());
    }

    #[test]
    fn test_resume_session() {
        let temp = TempDir::new().unwrap();
        let config = test_config();

        let original = Session::new(config, temp.path()).unwrap();
        let session_path = original.path.clone();
        drop(original);

        let resumed = Session::resume(&session_path).unwrap();

        assert!(resumed.id.contains("example-com"));
        assert_eq!(resumed.config.target.host, "example.com");
    }

    #[test]
    fn test_resume_nonexistent_session() {
        let result = Session::resume("/nonexistent/path");
        assert!(matches!(result, Err(Error::SessionNotFound(_))));
    }
}
```

**Step 2: Update state/mod.rs**

```rust
//! State management module

pub mod migrations;
pub mod schema;
pub mod session;

pub use migrations::run_migrations;
pub use session::Session;
```

**Step 3: Add tempfile to dev-dependencies**

Already added in Task 1.1.

**Step 4: Run tests**

Run: `cargo test -p feroxmute-core session`
Expected: All 3 session tests pass

**Step 5: Commit**

```bash
git add -A
git commit -m "feat(core): add session management with create and resume"
```

---

### Task 2.3: Data Models (Hosts, Ports, Vulnerabilities)

**Files:**
- Create: `/home/dilaz/kood/feroxmute/feroxmute-core/src/state/models.rs`
- Modify: `/home/dilaz/kood/feroxmute/feroxmute-core/src/state/mod.rs`

**Step 1: Create models.rs**

```rust
//! Data models for feroxmute state

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, Row};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::Result;

/// Severity level for vulnerabilities
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Critical => write!(f, "critical"),
            Severity::High => write!(f, "high"),
            Severity::Medium => write!(f, "medium"),
            Severity::Low => write!(f, "low"),
            Severity::Info => write!(f, "info"),
        }
    }
}

impl std::str::FromStr for Severity {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "critical" => Ok(Severity::Critical),
            "high" => Ok(Severity::High),
            "medium" => Ok(Severity::Medium),
            "low" => Ok(Severity::Low),
            "info" => Ok(Severity::Info),
            _ => Err(format!("Unknown severity: {}", s)),
        }
    }
}

/// Vulnerability status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VulnStatus {
    Potential,
    Verified,
    Exploited,
    FalsePositive,
}

impl std::fmt::Display for VulnStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VulnStatus::Potential => write!(f, "potential"),
            VulnStatus::Verified => write!(f, "verified"),
            VulnStatus::Exploited => write!(f, "exploited"),
            VulnStatus::FalsePositive => write!(f, "false_positive"),
        }
    }
}

impl std::str::FromStr for VulnStatus {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "potential" => Ok(VulnStatus::Potential),
            "verified" => Ok(VulnStatus::Verified),
            "exploited" => Ok(VulnStatus::Exploited),
            "false_positive" => Ok(VulnStatus::FalsePositive),
            _ => Err(format!("Unknown status: {}", s)),
        }
    }
}

/// A discovered host
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Host {
    pub id: String,
    pub address: String,
    pub hostname: Option<String>,
    pub discovered_at: DateTime<Utc>,
}

impl Host {
    /// Create a new host
    pub fn new(address: impl Into<String>, hostname: Option<String>) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            address: address.into(),
            hostname,
            discovered_at: Utc::now(),
        }
    }

    /// Insert host into database
    pub fn insert(&self, conn: &Connection) -> Result<()> {
        conn.execute(
            "INSERT INTO hosts (id, address, hostname, discovered_at) VALUES (?1, ?2, ?3, ?4)",
            params![self.id, self.address, self.hostname, self.discovered_at.to_rfc3339()],
        )?;
        Ok(())
    }

    /// Find host by address
    pub fn find_by_address(conn: &Connection, address: &str) -> Result<Option<Self>> {
        let mut stmt = conn.prepare(
            "SELECT id, address, hostname, discovered_at FROM hosts WHERE address = ?1"
        )?;

        let mut rows = stmt.query([address])?;
        if let Some(row) = rows.next()? {
            Ok(Some(Self::from_row(row)?))
        } else {
            Ok(None)
        }
    }

    /// Get all hosts
    pub fn all(conn: &Connection) -> Result<Vec<Self>> {
        let mut stmt = conn.prepare(
            "SELECT id, address, hostname, discovered_at FROM hosts ORDER BY discovered_at"
        )?;

        let hosts = stmt
            .query_map([], |row| Ok(Self::from_row(row).unwrap()))?
            .filter_map(|r| r.ok())
            .collect();

        Ok(hosts)
    }

    fn from_row(row: &Row) -> Result<Self> {
        let discovered_at_str: String = row.get(3)?;
        let discovered_at = DateTime::parse_from_rfc3339(&discovered_at_str)
            .map_err(|e| crate::Error::Config(e.to_string()))?
            .with_timezone(&Utc);

        Ok(Self {
            id: row.get(0)?,
            address: row.get(1)?,
            hostname: row.get(2)?,
            discovered_at,
        })
    }
}

/// A discovered port on a host
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Port {
    pub id: String,
    pub host_id: String,
    pub port: u16,
    pub protocol: String,
    pub service: Option<String>,
    pub state: String,
    pub discovered_at: DateTime<Utc>,
}

impl Port {
    /// Create a new port
    pub fn new(host_id: impl Into<String>, port: u16, protocol: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            host_id: host_id.into(),
            port,
            protocol: protocol.into(),
            service: None,
            state: "open".to_string(),
            discovered_at: Utc::now(),
        }
    }

    /// Set service name
    pub fn with_service(mut self, service: impl Into<String>) -> Self {
        self.service = Some(service.into());
        self
    }

    /// Insert port into database
    pub fn insert(&self, conn: &Connection) -> Result<()> {
        conn.execute(
            "INSERT INTO ports (id, host_id, port, protocol, service, state, discovered_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                self.id,
                self.host_id,
                self.port,
                self.protocol,
                self.service,
                self.state,
                self.discovered_at.to_rfc3339()
            ],
        )?;
        Ok(())
    }

    /// Get all ports for a host
    pub fn for_host(conn: &Connection, host_id: &str) -> Result<Vec<Self>> {
        let mut stmt = conn.prepare(
            "SELECT id, host_id, port, protocol, service, state, discovered_at
             FROM ports WHERE host_id = ?1 ORDER BY port"
        )?;

        let ports = stmt
            .query_map([host_id], |row| {
                let discovered_at_str: String = row.get(6)?;
                let discovered_at = DateTime::parse_from_rfc3339(&discovered_at_str)
                    .unwrap()
                    .with_timezone(&Utc);

                Ok(Self {
                    id: row.get(0)?,
                    host_id: row.get(1)?,
                    port: row.get(2)?,
                    protocol: row.get(3)?,
                    service: row.get(4)?,
                    state: row.get(5)?,
                    discovered_at,
                })
            })?
            .filter_map(|r| r.ok())
            .collect();

        Ok(ports)
    }
}

/// A discovered vulnerability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub id: String,
    pub host_id: Option<String>,
    pub vuln_type: String,
    pub severity: Severity,
    pub title: String,
    pub description: Option<String>,
    pub evidence: Option<String>,
    pub status: VulnStatus,
    pub cwe: Option<String>,
    pub cvss: Option<f64>,
    pub asset: Option<String>,
    pub remediation: Option<String>,
    pub discovered_by: String,
    pub verified_by: Option<String>,
    pub discovered_at: DateTime<Utc>,
    pub verified_at: Option<DateTime<Utc>>,
}

impl Vulnerability {
    /// Create a new vulnerability
    pub fn new(
        title: impl Into<String>,
        vuln_type: impl Into<String>,
        severity: Severity,
        discovered_by: impl Into<String>,
    ) -> Self {
        Self {
            id: format!("VULN-{}", Uuid::new_v4().to_string().split('-').next().unwrap().to_uppercase()),
            host_id: None,
            vuln_type: vuln_type.into(),
            severity,
            title: title.into(),
            description: None,
            evidence: None,
            status: VulnStatus::Potential,
            cwe: None,
            cvss: None,
            asset: None,
            remediation: None,
            discovered_by: discovered_by.into(),
            verified_by: None,
            discovered_at: Utc::now(),
            verified_at: None,
        }
    }

    /// Builder methods
    pub fn with_host(mut self, host_id: impl Into<String>) -> Self {
        self.host_id = Some(host_id.into());
        self
    }

    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    pub fn with_evidence(mut self, evidence: impl Into<String>) -> Self {
        self.evidence = Some(evidence.into());
        self
    }

    pub fn with_asset(mut self, asset: impl Into<String>) -> Self {
        self.asset = Some(asset.into());
        self
    }

    pub fn with_cwe(mut self, cwe: impl Into<String>) -> Self {
        self.cwe = Some(cwe.into());
        self
    }

    pub fn with_cvss(mut self, cvss: f64) -> Self {
        self.cvss = Some(cvss);
        self
    }

    pub fn with_remediation(mut self, remediation: impl Into<String>) -> Self {
        self.remediation = Some(remediation.into());
        self
    }

    /// Insert vulnerability into database
    pub fn insert(&self, conn: &Connection) -> Result<()> {
        conn.execute(
            "INSERT INTO vulnerabilities
             (id, host_id, vuln_type, severity, title, description, evidence, status,
              cwe, cvss, asset, remediation, discovered_by, verified_by, discovered_at, verified_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            params![
                self.id,
                self.host_id,
                self.vuln_type,
                self.severity.to_string(),
                self.title,
                self.description,
                self.evidence,
                self.status.to_string(),
                self.cwe,
                self.cvss,
                self.asset,
                self.remediation,
                self.discovered_by,
                self.verified_by,
                self.discovered_at.to_rfc3339(),
                self.verified_at.map(|dt| dt.to_rfc3339()),
            ],
        )?;
        Ok(())
    }

    /// Mark vulnerability as verified
    pub fn verify(&mut self, conn: &Connection, verified_by: impl Into<String>) -> Result<()> {
        self.status = VulnStatus::Verified;
        self.verified_by = Some(verified_by.into());
        self.verified_at = Some(Utc::now());

        conn.execute(
            "UPDATE vulnerabilities SET status = ?1, verified_by = ?2, verified_at = ?3 WHERE id = ?4",
            params![
                self.status.to_string(),
                self.verified_by,
                self.verified_at.map(|dt| dt.to_rfc3339()),
                self.id
            ],
        )?;
        Ok(())
    }

    /// Get all vulnerabilities
    pub fn all(conn: &Connection) -> Result<Vec<Self>> {
        let mut stmt = conn.prepare(
            "SELECT id, host_id, vuln_type, severity, title, description, evidence, status,
                    cwe, cvss, asset, remediation, discovered_by, verified_by, discovered_at, verified_at
             FROM vulnerabilities ORDER BY
                CASE severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    ELSE 5
                END"
        )?;

        let vulns = stmt
            .query_map([], |row| Ok(Self::from_row(row)))?
            .filter_map(|r| r.ok())
            .collect();

        Ok(vulns)
    }

    /// Count vulnerabilities by status
    pub fn count_by_status(conn: &Connection) -> Result<VulnCounts> {
        let mut counts = VulnCounts::default();

        let mut stmt = conn.prepare(
            "SELECT status, COUNT(*) FROM vulnerabilities GROUP BY status"
        )?;

        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let status: String = row.get(0)?;
            let count: i64 = row.get(1)?;

            match status.as_str() {
                "potential" => counts.potential = count as u32,
                "verified" => counts.verified = count as u32,
                "exploited" => counts.exploited = count as u32,
                _ => {}
            }
        }

        counts.total = counts.potential + counts.verified + counts.exploited;
        Ok(counts)
    }

    fn from_row(row: &Row) -> Self {
        let severity_str: String = row.get(3).unwrap();
        let status_str: String = row.get(7).unwrap();
        let discovered_at_str: String = row.get(14).unwrap();
        let verified_at_str: Option<String> = row.get(15).unwrap();

        Self {
            id: row.get(0).unwrap(),
            host_id: row.get(1).unwrap(),
            vuln_type: row.get(2).unwrap(),
            severity: severity_str.parse().unwrap(),
            title: row.get(4).unwrap(),
            description: row.get(5).unwrap(),
            evidence: row.get(6).unwrap(),
            status: status_str.parse().unwrap(),
            cwe: row.get(8).unwrap(),
            cvss: row.get(9).unwrap(),
            asset: row.get(10).unwrap(),
            remediation: row.get(11).unwrap(),
            discovered_by: row.get(12).unwrap(),
            verified_by: row.get(13).unwrap(),
            discovered_at: DateTime::parse_from_rfc3339(&discovered_at_str)
                .unwrap()
                .with_timezone(&Utc),
            verified_at: verified_at_str.map(|s| {
                DateTime::parse_from_rfc3339(&s)
                    .unwrap()
                    .with_timezone(&Utc)
            }),
        }
    }
}

/// Vulnerability counts by status
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VulnCounts {
    pub total: u32,
    pub potential: u32,
    pub verified: u32,
    pub exploited: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::run_migrations;

    fn setup_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        run_migrations(&conn).unwrap();
        conn
    }

    #[test]
    fn test_host_crud() {
        let conn = setup_db();

        let host = Host::new("192.168.1.1", Some("example.com".to_string()));
        host.insert(&conn).unwrap();

        let found = Host::find_by_address(&conn, "192.168.1.1").unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().hostname, Some("example.com".to_string()));

        let all = Host::all(&conn).unwrap();
        assert_eq!(all.len(), 1);
    }

    #[test]
    fn test_port_crud() {
        let conn = setup_db();

        let host = Host::new("192.168.1.1", None);
        host.insert(&conn).unwrap();

        let port = Port::new(&host.id, 80, "tcp").with_service("http");
        port.insert(&conn).unwrap();

        let port2 = Port::new(&host.id, 443, "tcp").with_service("https");
        port2.insert(&conn).unwrap();

        let ports = Port::for_host(&conn, &host.id).unwrap();
        assert_eq!(ports.len(), 2);
        assert_eq!(ports[0].port, 80);
        assert_eq!(ports[1].port, 443);
    }

    #[test]
    fn test_vulnerability_crud() {
        let conn = setup_db();

        let mut vuln = Vulnerability::new(
            "SQL Injection in login",
            "sqli",
            Severity::Critical,
            "web_scanner",
        )
        .with_asset("https://example.com/login")
        .with_cwe("CWE-89")
        .with_cvss(9.8);

        vuln.insert(&conn).unwrap();

        let vulns = Vulnerability::all(&conn).unwrap();
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0].severity, Severity::Critical);
        assert_eq!(vulns[0].status, VulnStatus::Potential);

        // Verify the vulnerability
        vuln.verify(&conn, "exploit_agent").unwrap();

        let counts = Vulnerability::count_by_status(&conn).unwrap();
        assert_eq!(counts.verified, 1);
        assert_eq!(counts.potential, 0);
    }
}
```

**Step 2: Update state/mod.rs**

```rust
//! State management module

pub mod migrations;
pub mod models;
pub mod schema;
pub mod session;

pub use migrations::run_migrations;
pub use models::{Host, Port, Severity, VulnCounts, VulnStatus, Vulnerability};
pub use session::Session;
```

**Step 3: Run tests**

Run: `cargo test -p feroxmute-core models`
Expected: All 3 model tests pass

**Step 4: Commit**

```bash
git add -A
git commit -m "feat(core): add data models for hosts, ports, and vulnerabilities"
```

---

### Task 2.4: Metrics Tracking

**Files:**
- Create: `/home/dilaz/kood/feroxmute/feroxmute-core/src/state/metrics.rs`
- Modify: `/home/dilaz/kood/feroxmute/feroxmute-core/src/state/mod.rs`

**Step 1: Create metrics.rs**

```rust
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

    /// Get current counts
    pub fn get(&self) -> TokenCounts {
        TokenCounts {
            input: self.input.load(Ordering::Relaxed),
            cached: self.cached.load(Ordering::Relaxed),
            output: self.output.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of token counts
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TokenCounts {
    pub input: u64,
    pub cached: u64,
    pub output: u64,
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
            "SELECT tool_calls, tokens_input, tokens_cached, tokens_output FROM metrics WHERE id = 'global'"
        )?;

        let metrics = stmt.query_row([], |row| {
            Ok(Self {
                tool_calls: row.get::<_, i64>(0)? as u64,
                tokens: TokenCounts {
                    input: row.get::<_, i64>(1)? as u64,
                    cached: row.get::<_, i64>(2)? as u64,
                    output: row.get::<_, i64>(3)? as u64,
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
                updated_at = datetime('now')
             WHERE id = 'global'",
            params![
                self.tool_calls as i64,
                self.tokens.input as i64,
                self.tokens.cached as i64,
                self.tokens.output as i64,
            ],
        )?;
        Ok(())
    }

    /// Increment tool calls
    pub fn increment_tool_calls(&mut self) {
        self.tool_calls += 1;
    }

    /// Add token counts
    pub fn add_tokens(&mut self, input: u64, cached: u64, output: u64) {
        self.tokens.input += input;
        self.tokens.cached += cached;
        self.tokens.output += output;
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
        tracker.tool_calls.store(metrics.tool_calls, Ordering::Relaxed);
        tracker.tokens.input.store(metrics.tokens.input, Ordering::Relaxed);
        tracker.tokens.cached.store(metrics.tokens.cached, Ordering::Relaxed);
        tracker.tokens.output.store(metrics.tokens.output, Ordering::Relaxed);
        tracker
    }

    /// Record a tool call
    pub fn record_tool_call(&self) {
        self.tool_calls.fetch_add(1, Ordering::Relaxed);
    }

    /// Record token usage
    pub fn record_tokens(&self, input: u64, cached: u64, output: u64) {
        self.tokens.add_input(input);
        self.tokens.add_cached(cached);
        self.tokens.add_output(output);
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
mod tests {
    use super::*;
    use crate::state::run_migrations;

    fn setup_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        run_migrations(&conn).unwrap();
        conn
    }

    #[test]
    fn test_metrics_load_save() {
        let conn = setup_db();

        let mut metrics = Metrics::load(&conn).unwrap();
        assert_eq!(metrics.tool_calls, 0);

        metrics.tool_calls = 42;
        metrics.tokens.input = 1000;
        metrics.tokens.output = 500;
        metrics.save(&conn).unwrap();

        let loaded = Metrics::load(&conn).unwrap();
        assert_eq!(loaded.tool_calls, 42);
        assert_eq!(loaded.tokens.input, 1000);
    }

    #[test]
    fn test_metrics_tracker() {
        let tracker = MetricsTracker::new();

        tracker.record_tool_call();
        tracker.record_tool_call();
        tracker.record_tokens(100, 20, 50);

        let snapshot = tracker.snapshot();
        assert_eq!(snapshot.tool_calls, 2);
        assert_eq!(snapshot.tokens.input, 100);
        assert_eq!(snapshot.tokens.cached, 20);
        assert_eq!(snapshot.tokens.output, 50);
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

        handle.join().unwrap();

        assert_eq!(tracker.snapshot().tool_calls, 200);
    }
}
```

**Step 2: Update state/mod.rs**

```rust
//! State management module

pub mod metrics;
pub mod migrations;
pub mod models;
pub mod schema;
pub mod session;

pub use metrics::{Metrics, MetricsTracker, TokenCounts, TokenCounter};
pub use migrations::run_migrations;
pub use models::{Host, Port, Severity, VulnCounts, VulnStatus, Vulnerability};
pub use session::Session;
```

**Step 3: Run tests**

Run: `cargo test -p feroxmute-core metrics`
Expected: All 3 metrics tests pass

**Step 4: Commit**

```bash
git add -A
git commit -m "feat(core): add metrics tracking for tool calls and tokens"
```

---

## Phase 3: Docker Integration

### Task 3.1: Container Management

**Files:**
- Create: `/home/dilaz/kood/feroxmute/feroxmute-core/src/docker/mod.rs`
- Create: `/home/dilaz/kood/feroxmute/feroxmute-core/src/docker/container.rs`
- Modify: `/home/dilaz/kood/feroxmute/feroxmute-core/src/lib.rs`

**Step 1: Create docker module**

```bash
mkdir -p feroxmute-core/src/docker
```

**Step 2: Create container.rs**

```rust
//! Docker container management for Kali tools

use bollard::container::{
    Config, CreateContainerOptions, LogsOptions, RemoveContainerOptions, StartContainerOptions,
    StopContainerOptions, WaitContainerOptions,
};
use bollard::exec::{CreateExecOptions, StartExecResults};
use bollard::image::CreateImageOptions;
use bollard::Docker;
use futures::StreamExt;
use std::collections::HashMap;
use std::path::Path;
use tracing::{debug, info, warn};

use crate::{Error, Result};

/// Container configuration
pub struct ContainerConfig {
    pub image: String,
    pub name: String,
    pub workdir: String,
    pub volumes: Vec<(String, String)>,
}

impl Default for ContainerConfig {
    fn default() -> Self {
        Self {
            image: "feroxmute-kali".to_string(),
            name: "feroxmute-kali".to_string(),
            workdir: "/feroxmute".to_string(),
            volumes: vec![],
        }
    }
}

/// Docker container manager
pub struct ContainerManager {
    docker: Docker,
    config: ContainerConfig,
    container_id: Option<String>,
}

impl ContainerManager {
    /// Create a new container manager
    pub async fn new(config: ContainerConfig) -> Result<Self> {
        let docker = Docker::connect_with_local_defaults()?;

        // Verify Docker is accessible
        docker.ping().await.map_err(|e| {
            Error::Docker(bollard::errors::Error::DockerResponseServerError {
                status_code: 500,
                message: format!("Cannot connect to Docker: {}", e),
            })
        })?;

        Ok(Self {
            docker,
            config,
            container_id: None,
        })
    }

    /// Check if the container image exists
    pub async fn image_exists(&self) -> Result<bool> {
        match self.docker.inspect_image(&self.config.image).await {
            Ok(_) => Ok(true),
            Err(bollard::errors::Error::DockerResponseServerError { status_code: 404, .. }) => {
                Ok(false)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Start or create the container
    pub async fn start(&mut self) -> Result<()> {
        // Check if container already exists
        match self.docker.inspect_container(&self.config.name, None).await {
            Ok(info) => {
                self.container_id = Some(info.id.unwrap_or_default());

                // Start if not running
                if info.state.and_then(|s| s.running) != Some(true) {
                    info!("Starting existing container: {}", self.config.name);
                    self.docker
                        .start_container(&self.config.name, None::<StartContainerOptions<String>>)
                        .await?;
                }
            }
            Err(bollard::errors::Error::DockerResponseServerError { status_code: 404, .. }) => {
                // Create new container
                info!("Creating new container: {}", self.config.name);
                self.create_container().await?;
            }
            Err(e) => return Err(e.into()),
        }

        Ok(())
    }

    /// Create a new container
    async fn create_container(&mut self) -> Result<()> {
        let mut binds = vec![];
        for (host, container) in &self.config.volumes {
            binds.push(format!("{}:{}", host, container));
        }

        let host_config = bollard::service::HostConfig {
            binds: Some(binds),
            cap_add: Some(vec!["NET_ADMIN".to_string(), "NET_RAW".to_string()]),
            security_opt: Some(vec!["seccomp:unconfined".to_string()]),
            ..Default::default()
        };

        let config = Config {
            image: Some(self.config.image.clone()),
            hostname: Some("feroxmute".to_string()),
            working_dir: Some(self.config.workdir.clone()),
            host_config: Some(host_config),
            tty: Some(true),
            cmd: Some(vec!["tail".to_string(), "-f".to_string(), "/dev/null".to_string()]),
            ..Default::default()
        };

        let options = CreateContainerOptions {
            name: &self.config.name,
            platform: None,
        };

        let response = self.docker.create_container(Some(options), config).await?;
        self.container_id = Some(response.id.clone());

        self.docker
            .start_container(&self.config.name, None::<StartContainerOptions<String>>)
            .await?;

        info!("Container started: {}", response.id);
        Ok(())
    }

    /// Execute a command in the container
    pub async fn exec(&self, cmd: Vec<&str>, workdir: Option<&str>) -> Result<ExecResult> {
        let container_id = self.container_id.as_ref().ok_or_else(|| {
            Error::Docker(bollard::errors::Error::DockerResponseServerError {
                status_code: 500,
                message: "Container not started".to_string(),
            })
        })?;

        debug!("Executing: {:?}", cmd);

        let exec_config = CreateExecOptions {
            cmd: Some(cmd.iter().map(|s| s.to_string()).collect()),
            working_dir: workdir.map(|s| s.to_string()),
            attach_stdout: Some(true),
            attach_stderr: Some(true),
            ..Default::default()
        };

        let exec = self.docker.create_exec(container_id, exec_config).await?;

        let mut output = String::new();
        let mut stderr = String::new();

        if let StartExecResults::Attached { mut output: stream, .. } =
            self.docker.start_exec(&exec.id, None).await?
        {
            while let Some(msg) = stream.next().await {
                match msg {
                    Ok(bollard::container::LogOutput::StdOut { message }) => {
                        output.push_str(&String::from_utf8_lossy(&message));
                    }
                    Ok(bollard::container::LogOutput::StdErr { message }) => {
                        stderr.push_str(&String::from_utf8_lossy(&message));
                    }
                    Ok(_) => {}
                    Err(e) => {
                        warn!("Error reading exec output: {}", e);
                    }
                }
            }
        }

        // Get exit code
        let inspect = self.docker.inspect_exec(&exec.id).await?;
        let exit_code = inspect.exit_code.unwrap_or(-1);

        Ok(ExecResult {
            stdout: output,
            stderr,
            exit_code,
        })
    }

    /// Stop the container
    pub async fn stop(&self) -> Result<()> {
        if let Some(ref id) = self.container_id {
            info!("Stopping container: {}", id);
            self.docker
                .stop_container(id, Some(StopContainerOptions { t: 10 }))
                .await?;
        }
        Ok(())
    }

    /// Remove the container
    pub async fn remove(&self) -> Result<()> {
        if let Some(ref id) = self.container_id {
            info!("Removing container: {}", id);
            self.docker
                .remove_container(
                    id,
                    Some(RemoveContainerOptions {
                        force: true,
                        ..Default::default()
                    }),
                )
                .await?;
        }
        Ok(())
    }
}

/// Result of executing a command
#[derive(Debug, Clone)]
pub struct ExecResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i64,
}

impl ExecResult {
    /// Check if command succeeded
    pub fn success(&self) -> bool {
        self.exit_code == 0
    }

    /// Get combined output
    pub fn output(&self) -> String {
        if self.stderr.is_empty() {
            self.stdout.clone()
        } else {
            format!("{}\n{}", self.stdout, self.stderr)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Integration tests require Docker - skip in CI unless Docker is available
    #[tokio::test]
    #[ignore = "requires Docker"]
    async fn test_container_manager_creation() {
        let config = ContainerConfig::default();
        let manager = ContainerManager::new(config).await;
        assert!(manager.is_ok());
    }
}
```

**Step 3: Create docker/mod.rs**

```rust
//! Docker integration module

pub mod container;

pub use container::{ContainerConfig, ContainerManager, ExecResult};
```

**Step 4: Update lib.rs**

```rust
//! feroxmute-core: LLM-powered penetration testing framework library

pub mod config;
pub mod docker;
pub mod error;
pub mod state;

pub use error::{Error, Result};
```

**Step 5: Verify it compiles**

Run: `cargo build -p feroxmute-core`
Expected: Build succeeds

**Step 6: Commit**

```bash
git add -A
git commit -m "feat(core): add Docker container management with bollard"
```

---

### Task 3.2: Tool Execution

**Files:**
- Create: `/home/dilaz/kood/feroxmute/feroxmute-core/src/tools/mod.rs`
- Create: `/home/dilaz/kood/feroxmute/feroxmute-core/src/tools/executor.rs`
- Modify: `/home/dilaz/kood/feroxmute/feroxmute-core/src/lib.rs`

**Step 1: Create tools module**

```bash
mkdir -p feroxmute-core/src/tools
```

**Step 2: Create executor.rs**

```rust
//! Tool execution within Docker container

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::docker::{ContainerManager, ExecResult};
use crate::state::MetricsTracker;
use crate::{Error, Result};

/// A security tool that can be executed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tool {
    pub name: String,
    pub command: String,
    pub description: String,
    pub json_output: bool,
}

impl Tool {
    pub fn new(name: impl Into<String>, command: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            command: command.into(),
            description: String::new(),
            json_output: false,
        }
    }

    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    pub fn with_json_output(mut self) -> Self {
        self.json_output = true;
        self
    }
}

/// Record of a tool execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolExecution {
    pub id: String,
    pub agent: String,
    pub tool: String,
    pub args: Vec<String>,
    pub output: Option<String>,
    pub exit_code: Option<i64>,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

impl ToolExecution {
    /// Create a new tool execution record
    pub fn new(agent: impl Into<String>, tool: impl Into<String>, args: Vec<String>) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            agent: agent.into(),
            tool: tool.into(),
            args,
            output: None,
            exit_code: None,
            started_at: Utc::now(),
            completed_at: None,
        }
    }

    /// Record completion
    pub fn complete(&mut self, result: &ExecResult) {
        self.output = Some(result.output());
        self.exit_code = Some(result.exit_code);
        self.completed_at = Some(Utc::now());
    }

    /// Save to database
    pub fn save(&self, conn: &Connection) -> Result<()> {
        conn.execute(
            "INSERT INTO tool_executions
             (id, agent, tool, args, output, exit_code, started_at, completed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                self.id,
                self.agent,
                self.tool,
                serde_json::to_string(&self.args)?,
                self.output,
                self.exit_code,
                self.started_at.to_rfc3339(),
                self.completed_at.map(|dt| dt.to_rfc3339()),
            ],
        )?;
        Ok(())
    }
}

/// Tool executor that runs commands in the Docker container
pub struct ToolExecutor {
    container: ContainerManager,
    metrics: MetricsTracker,
}

impl ToolExecutor {
    /// Create a new tool executor
    pub fn new(container: ContainerManager, metrics: MetricsTracker) -> Self {
        Self { container, metrics }
    }

    /// Execute a tool with arguments
    pub async fn execute(
        &self,
        tool: &Tool,
        args: &[&str],
        workdir: Option<&str>,
        agent: &str,
        conn: &Connection,
    ) -> Result<ToolExecution> {
        // Build command
        let mut cmd = vec![&tool.command[..]];
        cmd.extend(args);

        // Create execution record
        let mut execution = ToolExecution::new(
            agent,
            &tool.name,
            args.iter().map(|s| s.to_string()).collect(),
        );

        // Execute in container
        let result = self.container.exec(cmd, workdir).await?;

        // Record completion
        execution.complete(&result);

        // Update metrics
        self.metrics.record_tool_call();

        // Save to database
        execution.save(conn)?;

        Ok(execution)
    }

    /// Execute a raw command (for tools not in registry)
    pub async fn execute_raw(
        &self,
        cmd: Vec<&str>,
        workdir: Option<&str>,
        agent: &str,
        conn: &Connection,
    ) -> Result<ToolExecution> {
        let tool_name = cmd.first().copied().unwrap_or("unknown");

        let mut execution = ToolExecution::new(
            agent,
            tool_name,
            cmd.iter().skip(1).map(|s| s.to_string()).collect(),
        );

        let result = self.container.exec(cmd, workdir).await?;
        execution.complete(&result);

        self.metrics.record_tool_call();
        execution.save(conn)?;

        Ok(execution)
    }
}

/// Registry of available tools
pub struct ToolRegistry {
    tools: Vec<Tool>,
}

impl Default for ToolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ToolRegistry {
    /// Create a new tool registry with default tools
    pub fn new() -> Self {
        let tools = vec![
            // ProjectDiscovery - Discovery
            Tool::new("subfinder", "subfinder")
                .with_description("Subdomain enumeration")
                .with_json_output(),
            Tool::new("naabu", "naabu")
                .with_description("Port scanning")
                .with_json_output(),
            Tool::new("httpx", "httpx")
                .with_description("HTTP probing")
                .with_json_output(),
            Tool::new("katana", "katana")
                .with_description("Web crawling")
                .with_json_output(),
            Tool::new("dnsx", "dnsx")
                .with_description("DNS resolution")
                .with_json_output(),
            Tool::new("tlsx", "tlsx")
                .with_description("TLS analysis")
                .with_json_output(),
            Tool::new("asnmap", "asnmap")
                .with_description("ASN mapping")
                .with_json_output(),
            Tool::new("uncover", "uncover")
                .with_description("Asset discovery")
                .with_json_output(),
            // ProjectDiscovery - Detection
            Tool::new("nuclei", "nuclei")
                .with_description("Vulnerability scanning")
                .with_json_output(),
            // Other tools
            Tool::new("sqlmap", "sqlmap")
                .with_description("SQL injection testing"),
            Tool::new("feroxbuster", "feroxbuster")
                .with_description("Directory bruteforcing")
                .with_json_output(),
            Tool::new("ffuf", "ffuf")
                .with_description("Fuzzing")
                .with_json_output(),
            Tool::new("nmap", "nmap")
                .with_description("Network scanning"),
            Tool::new("whois", "whois")
                .with_description("WHOIS lookup"),
            Tool::new("dig", "dig")
                .with_description("DNS queries"),
        ];

        Self { tools }
    }

    /// Get a tool by name
    pub fn get(&self, name: &str) -> Option<&Tool> {
        self.tools.iter().find(|t| t.name == name)
    }

    /// Get all tools
    pub fn all(&self) -> &[Tool] {
        &self.tools
    }

    /// Get tools that output JSON
    pub fn json_tools(&self) -> Vec<&Tool> {
        self.tools.iter().filter(|t| t.json_output).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tool_registry() {
        let registry = ToolRegistry::new();

        assert!(registry.get("subfinder").is_some());
        assert!(registry.get("nuclei").is_some());
        assert!(registry.get("nonexistent").is_none());

        let json_tools = registry.json_tools();
        assert!(json_tools.iter().any(|t| t.name == "httpx"));
    }

    #[test]
    fn test_tool_execution_record() {
        let mut exec = ToolExecution::new("recon", "subfinder", vec!["-d".to_string(), "example.com".to_string()]);

        assert!(exec.output.is_none());
        assert!(exec.completed_at.is_none());

        let result = ExecResult {
            stdout: "found.example.com".to_string(),
            stderr: String::new(),
            exit_code: 0,
        };

        exec.complete(&result);

        assert_eq!(exec.output, Some("found.example.com".to_string()));
        assert_eq!(exec.exit_code, Some(0));
        assert!(exec.completed_at.is_some());
    }
}
```

**Step 3: Create tools/mod.rs**

```rust
//! Tool integration module

pub mod executor;

pub use executor::{Tool, ToolExecution, ToolExecutor, ToolRegistry};
```

**Step 4: Update lib.rs**

```rust
//! feroxmute-core: LLM-powered penetration testing framework library

pub mod config;
pub mod docker;
pub mod error;
pub mod state;
pub mod tools;

pub use error::{Error, Result};
```

**Step 5: Run tests**

Run: `cargo test -p feroxmute-core tools`
Expected: Both tests pass

**Step 6: Commit**

```bash
git add -A
git commit -m "feat(core): add tool execution and registry"
```

---

## Phase 4: LLM Provider Integration

### Task 4.1: Provider Abstraction Trait

**Files:**
- Create: `/home/dilaz/kood/feroxmute/feroxmute-core/src/providers/mod.rs`
- Create: `/home/dilaz/kood/feroxmute/feroxmute-core/src/providers/traits.rs`
- Modify: `/home/dilaz/kood/feroxmute/feroxmute-core/src/lib.rs`

**Step 1: Create providers module**

```bash
mkdir -p feroxmute-core/src/providers
```

**Step 2: Create traits.rs**

```rust
//! Provider trait definitions

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::state::MetricsTracker;
use crate::Result;

/// A message in a conversation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub role: Role,
    pub content: String,
}

/// Message role
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    System,
    User,
    Assistant,
}

/// Tool definition for function calling
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub parameters: serde_json::Value,
}

/// A tool call made by the model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub arguments: String,
}

/// Completion request
#[derive(Debug, Clone)]
pub struct CompletionRequest {
    pub messages: Vec<Message>,
    pub system: Option<String>,
    pub tools: Vec<ToolDefinition>,
    pub max_tokens: Option<u32>,
    pub temperature: Option<f32>,
}

impl CompletionRequest {
    pub fn new(messages: Vec<Message>) -> Self {
        Self {
            messages,
            system: None,
            tools: vec![],
            max_tokens: Some(4096),
            temperature: Some(0.7),
        }
    }

    pub fn with_system(mut self, system: impl Into<String>) -> Self {
        self.system = Some(system.into());
        self
    }

    pub fn with_tools(mut self, tools: Vec<ToolDefinition>) -> Self {
        self.tools = tools;
        self
    }
}

/// Completion response
#[derive(Debug, Clone)]
pub struct CompletionResponse {
    pub content: Option<String>,
    pub tool_calls: Vec<ToolCall>,
    pub stop_reason: StopReason,
    pub usage: TokenUsage,
}

/// Stop reason for completion
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    EndTurn,
    ToolUse,
    MaxTokens,
}

/// Token usage for a completion
#[derive(Debug, Clone, Default)]
pub struct TokenUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_tokens: u64,
}

/// LLM Provider trait
#[async_trait]
pub trait LlmProvider: Send + Sync {
    fn name(&self) -> &str;
    fn supports_tools(&self) -> bool;
    async fn complete(&self, request: CompletionRequest) -> Result<CompletionResponse>;
    fn metrics(&self) -> &MetricsTracker;
}
```

**Step 3: Create providers/mod.rs**

```rust
//! LLM provider integration

pub mod traits;

pub use traits::{
    CompletionRequest, CompletionResponse, LlmProvider, Message, Role, StopReason,
    ToolCall, ToolDefinition, TokenUsage,
};
```

**Step 4: Update lib.rs to add providers module**

**Step 5: Verify it compiles**

Run: `cargo build -p feroxmute-core`

**Step 6: Commit**

```bash
git add -A && git commit -m "feat(core): add LLM provider trait abstraction"
```

---

### Task 4.2: Anthropic Provider (via Rig.rs)

**Files:**
- Create: `/home/dilaz/kood/feroxmute/feroxmute-core/src/providers/anthropic.rs`
- Modify: `/home/dilaz/kood/feroxmute/feroxmute-core/src/providers/mod.rs`

**Step 1: Create anthropic.rs with rig-core integration**

- Use `rig::providers::anthropic::ClientBuilder`
- Implement `LlmProvider` trait
- Handle tool calling responses
- Track token usage via MetricsTracker

**Step 2: Update providers/mod.rs to export AnthropicProvider**

**Step 3: Commit**

```bash
git add -A && git commit -m "feat(core): add Anthropic provider via rig-core"
```

---

### Task 4.3: OpenAI Provider (via Rig.rs)

**Files:**
- Create: `/home/dilaz/kood/feroxmute/feroxmute-core/src/providers/openai.rs`
- Modify: `/home/dilaz/kood/feroxmute/feroxmute-core/src/providers/mod.rs`

**Step 1: Create openai.rs**

- Use `rig::providers::openai::ClientBuilder`
- Support custom base_url for LiteLLM proxy
- Implement `LlmProvider` trait

**Step 2: Update mod.rs to export OpenAiProvider**

**Step 3: Commit**

```bash
git add -A && git commit -m "feat(core): add OpenAI provider via rig-core"
```

---

### Task 4.4: Provider Factory

**Files:**
- Create: `/home/dilaz/kood/feroxmute/feroxmute-core/src/providers/factory.rs`
- Modify: `/home/dilaz/kood/feroxmute/feroxmute-core/src/providers/mod.rs`

**Step 1: Create factory.rs**

```rust
//! Provider factory

use std::sync::Arc;
use crate::config::{ProviderConfig, ProviderName};
use crate::state::MetricsTracker;
use crate::Result;
use super::LlmProvider;

pub fn create_provider(
    config: &ProviderConfig,
    metrics: MetricsTracker,
) -> Result<Arc<dyn LlmProvider>> {
    match config.name {
        ProviderName::Anthropic => { /* create AnthropicProvider */ }
        ProviderName::OpenAi => { /* create OpenAiProvider */ }
        ProviderName::LiteLlm => { /* use OpenAI with custom base_url */ }
        ProviderName::Cohere => { /* not implemented */ }
    }
}
```

**Step 2: Commit**

```bash
git add -A && git commit -m "feat(core): add provider factory"
```

---

## Phase 5: Agent Framework

### Task 5.1: Agent Trait and Types

**Files:**
- Create: `/home/dilaz/kood/feroxmute/feroxmute-core/src/agents/mod.rs`
- Create: `/home/dilaz/kood/feroxmute/feroxmute-core/src/agents/traits.rs`
- Modify: `/home/dilaz/kood/feroxmute/feroxmute-core/src/lib.rs`

**Step 1: Create agents module with core types**

```rust
//! Agent trait definitions

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentStatus { Idle, Planning, Running, Waiting, Completed, Failed }

pub struct AgentTask {
    pub id: String,
    pub agent: String,
    pub description: String,
    pub status: TaskStatus,
    // ...
}

pub struct AgentContext<'a> {
    pub provider: &'a dyn LlmProvider,
    pub executor: &'a ToolExecutor,
    pub conn: &'a Connection,
}

#[async_trait]
pub trait Agent: Send + Sync {
    fn name(&self) -> &str;
    fn status(&self) -> AgentStatus;
    fn system_prompt(&self) -> &str;
    fn tools(&self) -> Vec<ToolDefinition>;
    async fn execute(&mut self, task: &AgentTask, ctx: &AgentContext<'_>) -> Result<String>;
    fn thinking(&self) -> Option<&str> { None }
}
```

**Step 2: Commit**

```bash
git add -A && git commit -m "feat(core): add agent trait and types"
```

---

### Task 5.2: Agent Prompts

**Files:**
- Create: `/home/dilaz/kood/feroxmute/feroxmute-core/src/agents/prompts.rs`

**Step 1: Create system prompts for each agent**

- `ORCHESTRATOR_PROMPT`: Plans phases, delegates tasks, tracks progress
- `RECON_AGENT_PROMPT`: Asset discovery, subdomain enum, port scanning
- `WEB_SCANNER_PROMPT`: Vulnerability detection, nuclei, fuzzing
- `EXPLOIT_PROMPT`: PoC validation, safe exploitation
- `REPORT_PROMPT`: Finding aggregation, report generation

**Step 2: Commit**

```bash
git add -A && git commit -m "feat(core): add agent system prompts"
```

---

### Task 5.3: Recon Agent

**Files:**
- Create: `/home/dilaz/kood/feroxmute/feroxmute-core/src/agents/recon.rs`

**Step 1: Implement ReconAgent**

- Tools: subfinder, naabu, httpx, katana, dnsx, tlsx, asnmap
- Conversation loop with tool execution
- Store thinking for TUI display

**Step 2: Commit**

```bash
git add -A && git commit -m "feat(core): add recon agent"
```

---

### Task 5.4: Web Scanner Agent

**Files:**
- Create: `/home/dilaz/kood/feroxmute/feroxmute-core/src/agents/scanner.rs`

**Step 1: Implement ScannerAgent**

- Tools: nuclei, feroxbuster, ffuf, report_vulnerability
- Parse nuclei JSON output
- Create Vulnerability records

**Step 2: Commit**

```bash
git add -A && git commit -m "feat(core): add web scanner agent"
```

---

### Task 5.5: Orchestrator Agent

**Files:**
- Create: `/home/dilaz/kood/feroxmute/feroxmute-core/src/agents/orchestrator.rs`

**Step 1: Implement OrchestratorAgent**

- Manages engagement phases (Recon → Scanning → Exploit → Report)
- Delegates to specialist agents
- Tools: delegate_recon, delegate_scanner, advance_phase, get_status

**Step 2: Update agents/mod.rs to export all agents**

**Step 3: Commit**

```bash
git add -A && git commit -m "feat(core): add orchestrator agent"
```

---

## Phase 6: Terminal UI (TUI)

### Task 6.1: TUI Application State

**Files:**
- Create: `/home/dilaz/kood/feroxmute/feroxmute-cli/src/tui/mod.rs`
- Create: `/home/dilaz/kood/feroxmute/feroxmute-cli/src/tui/app.rs`

**Step 1: Create App struct**

```rust
pub enum View { Dashboard, AgentDetail(AgentView), Logs }
pub enum AgentView { Orchestrator, Recon, Scanner, Exploit, Report }

pub struct App {
    pub view: View,
    pub should_quit: bool,
    pub show_thinking: bool,
    pub mouse_enabled: bool,
    pub target: String,
    pub session_id: String,
    pub phase: Phase,
    pub elapsed: Duration,
    pub metrics: Metrics,
    pub vuln_counts: VulnCounts,
    pub agent_statuses: AgentStatuses,
    pub feed: Vec<FeedEntry>,
}
```

**Step 2: Commit**

```bash
git add -A && git commit -m "feat(cli): add TUI application state"
```

---

### Task 6.2: Event Handling

**Files:**
- Create: `/home/dilaz/kood/feroxmute/feroxmute-cli/src/tui/events.rs`

**Step 1: Implement keyboard and mouse handlers**

- q/Ctrl+C: Quit
- h/Home/Esc: Dashboard
- 1-4: Agent detail views
- t: Toggle thinking
- m: Toggle mouse
- j/k/arrows: Scroll

**Step 2: Commit**

```bash
git add -A && git commit -m "feat(cli): add TUI event handling"
```

---

### Task 6.3: Dashboard Widget

**Files:**
- Create: `/home/dilaz/kood/feroxmute/feroxmute-cli/src/tui/widgets/dashboard.rs`

**Step 1: Implement dashboard layout**

- Header: target, session, phase, elapsed
- Metrics: tool calls, tokens, vulnerabilities
- Agents table: status indicators, findings count
- Live feed: scrollable log entries
- Footer: keybindings

**Step 2: Commit**

```bash
git add -A && git commit -m "feat(cli): add dashboard widget"
```

---

### Task 6.4: Agent Detail Widget

**Files:**
- Create: `/home/dilaz/kood/feroxmute/feroxmute-cli/src/tui/widgets/agent_detail.rs`

**Step 1: Implement agent detail view**

- Header with agent name and status
- Tool output area
- Thinking panel (toggleable)
- Footer with keybindings

**Step 2: Commit**

```bash
git add -A && git commit -m "feat(cli): add agent detail widget"
```

---

### Task 6.5: TUI Runner

**Files:**
- Create: `/home/dilaz/kood/feroxmute/feroxmute-cli/src/tui/runner.rs`
- Modify: `/home/dilaz/kood/feroxmute/feroxmute-cli/src/main.rs`

**Step 1: Implement main TUI loop**

```rust
pub fn run(app: &mut App) -> io::Result<()> {
    enable_raw_mode()?;
    execute!(stdout, EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout))?;

    loop {
        terminal.draw(|f| render(f, app))?;
        if let Some(event) = poll_event(Duration::from_millis(100))? {
            handle_event(event, app);
        }
        if app.should_quit { break; }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    Ok(())
}
```

**Step 2: Update main.rs to launch TUI**

**Step 3: Commit**

```bash
git add -A && git commit -m "feat(cli): add TUI runner and integrate with main"
```

---

## Phase 7: Report Generation

### Task 7.1: Report Models

**Files:**
- Create: `/home/dilaz/kood/feroxmute/feroxmute-core/src/reports/mod.rs`
- Create: `/home/dilaz/kood/feroxmute/feroxmute-core/src/reports/models.rs`

**Step 1: Create report data structures**

```rust
pub struct Report {
    pub metadata: ReportMetadata,
    pub metrics: ReportMetrics,
    pub summary: ReportSummary,
    pub findings: Vec<Finding>,
}

pub struct ReportSummary {
    pub total_vulnerabilities: u32,
    pub by_severity: SeverityCounts,
    pub by_status: VulnCounts,
    pub risk_rating: RiskRating,
    pub key_findings: Vec<String>,
}

pub enum RiskRating { Critical, High, Medium, Low, Minimal }
```

**Step 2: Commit**

```bash
git add -A && git commit -m "feat(core): add report data models"
```

---

### Task 7.2: Report Generator

**Files:**
- Create: `/home/dilaz/kood/feroxmute/feroxmute-core/src/reports/generator.rs`

**Step 1: Implement generate_report function**

- Load vulnerabilities, hosts, metrics from database
- Calculate severity counts and risk rating
- Build Report struct

**Step 2: Implement export_json**

```rust
pub fn export_json(report: &Report, path: impl AsRef<Path>) -> Result<()> {
    let json = serde_json::to_string_pretty(report)?;
    std::fs::write(path, json)?;
    Ok(())
}
```

**Step 3: Implement export_markdown**

- Executive summary
- Vulnerability table
- Detailed findings with evidence
- Remediation recommendations

**Step 4: Commit**

```bash
git add -A && git commit -m "feat(core): add report generator with JSON/Markdown export"
```

---

### Task 7.3: Report Agent

**Files:**
- Create: `/home/dilaz/kood/feroxmute/feroxmute-core/src/agents/report.rs`

**Step 1: Implement ReportAgent**

- Tools: generate_report, export_json, export_markdown
- Orchestrator delegates when engagement complete

**Step 2: Update agents/mod.rs to export ReportAgent

**Step 3: Commit**

```bash
git add -A && git commit -m "feat(core): add report agent"
```

---

## Summary

**Phase 1: Project Setup** (5 tasks) ✅ Completed
**Phase 2: State Management** (4 tasks) ✅ Completed
**Phase 3: Docker Integration** (2 tasks) ✅ Completed
**Phase 4: LLM Provider Integration** (4 tasks)
**Phase 5: Agent Framework** (5 tasks)
**Phase 6: Terminal UI** (5 tasks)
**Phase 7: Report Generation** (3 tasks)

**Total tasks:** 28
**Completed:** 11
**Remaining:** 17
