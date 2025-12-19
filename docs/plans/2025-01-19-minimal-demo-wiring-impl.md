# Minimal Demo Wiring Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Wire together TUI, Docker, LLM provider, and recon agent so the application builds, validates dependencies, and displays live agent output.

**Architecture:** Channel-based communication between async agent task and sync TUI. Fail-fast validation of Docker and LLM provider before TUI starts. CancellationToken for graceful shutdown.

**Tech Stack:** tokio, tokio-util (CancellationToken), mpsc channels, bollard (Docker), ratatui

---

## Task 1: Add tokio-util Dependency

**Files:**
- Modify: `feroxmute-cli/Cargo.toml`

**Step 1: Add tokio-util with sync feature**

```toml
tokio-util = { version = "0.7", features = ["rt"] }
```

Add after the `tokio.workspace = true` line.

**Step 2: Verify it compiles**

Run: `cargo check -p feroxmute-cli`
Expected: Compiles successfully

**Step 3: Commit**

```bash
git add feroxmute-cli/Cargo.toml
git commit -m "chore: add tokio-util dependency for CancellationToken"
```

---

## Task 2: Create AgentEvent Channel Module

**Files:**
- Create: `feroxmute-cli/src/tui/channel.rs`
- Modify: `feroxmute-cli/src/tui/mod.rs`

**Step 1: Create the channel module**

Create `feroxmute-cli/src/tui/channel.rs`:

```rust
//! Channel communication between agent and TUI

use feroxmute_core::agents::AgentStatus;

/// Events sent from agent to TUI
#[derive(Debug, Clone)]
pub enum AgentEvent {
    /// Add entry to activity feed
    Feed {
        agent: String,
        message: String,
        is_error: bool,
    },

    /// Update the thinking panel
    Thinking(Option<String>),

    /// Update agent status
    Status { agent: String, status: AgentStatus },

    /// Update token metrics
    Metrics {
        input: u64,
        output: u64,
        cache_read: u64,
    },

    /// Agent finished
    Finished { success: bool, message: String },
}
```

**Step 2: Export from mod.rs**

In `feroxmute-cli/src/tui/mod.rs`, add after the other module declarations:

```rust
pub mod channel;
```

And add to the pub use section:

```rust
pub use channel::AgentEvent;
```

**Step 3: Verify it compiles**

Run: `cargo check -p feroxmute-cli`
Expected: Compiles successfully

**Step 4: Commit**

```bash
git add feroxmute-cli/src/tui/channel.rs feroxmute-cli/src/tui/mod.rs
git commit -m "feat(tui): add AgentEvent channel module"
```

---

## Task 3: Add Receiver to App State

**Files:**
- Modify: `feroxmute-cli/src/tui/app.rs`

**Step 1: Add import for mpsc**

Add at the top of the file:

```rust
use tokio::sync::mpsc;
use super::channel::AgentEvent;
```

**Step 2: Add receiver field to App struct**

After the `code_finding_counts` field, add:

```rust
    /// Channel receiver for agent events
    pub event_rx: Option<mpsc::Receiver<AgentEvent>>,
```

**Step 3: Update App::new to accept optional receiver**

Change the `new` function signature and add initialization:

```rust
    /// Create a new app instance
    pub fn new(
        target: impl Into<String>,
        session_id: impl Into<String>,
        event_rx: Option<mpsc::Receiver<AgentEvent>>,
    ) -> Self {
        Self {
            view: View::Dashboard,
            should_quit: false,
            confirm_quit: false,
            show_thinking: true,
            mouse_enabled: true,
            target: target.into(),
            session_id: session_id.into(),
            phase: EngagementPhase::Setup,
            start_time: Instant::now(),
            metrics: Metrics::default(),
            vuln_counts: VulnCounts::default(),
            agent_statuses: AgentStatuses::default(),
            feed: Vec::new(),
            current_thinking: None,
            log_scroll: 0,
            selected_feed: 0,
            source_path: None,
            detected_languages: Vec::new(),
            code_findings: Vec::new(),
            code_finding_counts: CodeFindingCounts::default(),
            event_rx,
        }
    }
```

**Step 4: Update tests to pass None**

In the tests module at the bottom of the file, update all `App::new` calls:

```rust
    #[test]
    fn test_app_creation() {
        let app = App::new("example.com", "session-123", None);
        // ... rest unchanged
    }

    #[test]
    fn test_navigation() {
        let mut app = App::new("test.com", "test-session", None);
        // ... rest unchanged
    }
```

**Step 5: Verify tests pass**

Run: `cargo test -p feroxmute-cli`
Expected: All tests pass

**Step 6: Commit**

```bash
git add feroxmute-cli/src/tui/app.rs
git commit -m "feat(tui): add event receiver to App state"
```

---

## Task 4: Poll Channel in TUI Event Loop

**Files:**
- Modify: `feroxmute-cli/src/tui/runner.rs`

**Step 1: Add import for channel**

Add to imports:

```rust
use super::channel::AgentEvent;
```

**Step 2: Add drain_events helper function**

Add after the `render` function:

```rust
/// Drain pending events from the channel
fn drain_events(app: &mut App) {
    if let Some(ref mut rx) = app.event_rx {
        while let Ok(event) = rx.try_recv() {
            match event {
                AgentEvent::Feed { agent, message, is_error } => {
                    if is_error {
                        app.add_feed(super::app::FeedEntry::error(&agent, &message));
                    } else {
                        app.add_feed(super::app::FeedEntry::new(&agent, &message));
                    }
                }
                AgentEvent::Thinking(thinking) => {
                    app.current_thinking = thinking;
                }
                AgentEvent::Status { agent, status } => {
                    app.update_agent_status(&agent, status);
                }
                AgentEvent::Metrics { input, output, cache_read } => {
                    app.metrics.input_tokens += input;
                    app.metrics.output_tokens += output;
                    app.metrics.cache_read_tokens += cache_read;
                }
                AgentEvent::Finished { success, message } => {
                    let agent = "system";
                    if success {
                        app.add_feed(super::app::FeedEntry::new(agent, &message));
                    } else {
                        app.add_feed(super::app::FeedEntry::error(agent, &message));
                    }
                }
            }
        }
    }
}
```

**Step 3: Call drain_events in run_loop**

In the `run_loop` function, add after handling events and before the quit check:

```rust
        // Drain agent events
        drain_events(app);

        // Check for quit
        if app.should_quit {
```

**Step 4: Verify it compiles**

Run: `cargo check -p feroxmute-cli`
Expected: Compiles successfully

**Step 5: Commit**

```bash
git add feroxmute-cli/src/tui/runner.rs
git commit -m "feat(tui): poll agent events in run loop"
```

---

## Task 5: Update Main to Pass None (Temporary)

**Files:**
- Modify: `feroxmute-cli/src/main.rs`

**Step 1: Update App::new call**

Find the line:

```rust
        let mut app = tui::App::new(&target, &session_id);
```

Change to:

```rust
        let mut app = tui::App::new(&target, &session_id, None);
```

**Step 2: Verify it compiles and runs**

Run: `cargo run -p feroxmute-cli -- --target example.com`
Expected: TUI launches (press q, then y to quit)

**Step 3: Commit**

```bash
git add feroxmute-cli/src/main.rs
git commit -m "chore: update App::new call for new signature"
```

---

## Task 6: Make Main Async with Startup Validation

**Files:**
- Modify: `feroxmute-cli/src/main.rs`

**Step 1: Add async imports**

Replace the imports section with:

```rust
mod args;
mod tui;
mod wizard;

use anyhow::{anyhow, Result};
use args::Args;
use clap::Parser;
use feroxmute_core::config::{EngagementConfig, ProviderConfig, ProviderName};
use feroxmute_core::docker::ContainerConfig;
use feroxmute_core::providers::create_provider;
use feroxmute_core::state::MetricsTracker;
use feroxmute_core::targets::{RelationshipDetector, TargetCollection};
use std::io::{self, Write};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;
```

**Step 2: Make main async**

Change:

```rust
fn main() -> Result<()> {
```

To:

```rust
#[tokio::main]
async fn main() -> Result<()> {
```

**Step 3: Add startup validation after wizard/resume handling**

After the `if let Some(ref session) = args.resume { ... }` block and before `if !args.target.is_empty() {`, add:

```rust
    // Load configuration
    let config = EngagementConfig::load_default();

    // Build provider config from CLI args
    let provider_name = match args.provider.to_lowercase().as_str() {
        "anthropic" => ProviderName::Anthropic,
        "openai" => ProviderName::OpenAi,
        "litellm" => ProviderName::LiteLlm,
        "cohere" => ProviderName::Cohere,
        "gemini" => ProviderName::Gemini,
        "xai" => ProviderName::Xai,
        "deepseek" => ProviderName::DeepSeek,
        "azure" => ProviderName::Azure,
        "perplexity" => ProviderName::Perplexity,
        "mira" => ProviderName::Mira,
        _ => ProviderName::Anthropic,
    };

    let provider_config = ProviderConfig {
        name: provider_name,
        model: args.model.clone().unwrap_or_else(|| config.provider.model.clone()),
        api_key: config.provider.api_key.clone(),
        base_url: config.provider.base_url.clone(),
    };

    // Validate LLM provider - fail fast
    let metrics = MetricsTracker::new();
    let provider = create_provider(&provider_config, metrics.clone()).map_err(|e| {
        anyhow!(
            "LLM provider error: {}\n\nHint: Set API key in ~/.feroxmute/config.toml or {} environment variable",
            e,
            match provider_config.name {
                ProviderName::Anthropic => "ANTHROPIC_API_KEY",
                ProviderName::OpenAi => "OPENAI_API_KEY",
                ProviderName::Cohere => "COHERE_API_KEY",
                ProviderName::Gemini => "GEMINI_API_KEY or GOOGLE_API_KEY",
                ProviderName::Xai => "XAI_API_KEY",
                ProviderName::DeepSeek => "DEEPSEEK_API_KEY",
                ProviderName::Azure => "AZURE_OPENAI_API_KEY",
                ProviderName::Perplexity => "PERPLEXITY_API_KEY",
                ProviderName::Mira => "MIRA_API_KEY",
                ProviderName::LiteLlm => "LITELLM_API_KEY",
            }
        )
    })?;

    // Check Docker connectivity - fail fast
    let docker = bollard::Docker::connect_with_local_defaults()
        .map_err(|_| anyhow!("Cannot connect to Docker.\n\nHint: Is Docker running? Try 'docker ps'"))?;

    docker.ping().await.map_err(|_| {
        anyhow!("Docker not responding.\n\nHint: Is Docker daemon running? Try 'docker ps'")
    })?;

    // Check if Kali image exists
    let container_config = ContainerConfig::default();
    match docker.inspect_image(&container_config.image).await {
        Ok(_) => {}
        Err(_) => {
            return Err(anyhow!(
                "Docker image '{}' not found.\n\nHint: Run 'docker compose build' first",
                container_config.image
            ));
        }
    }

    tracing::info!("Docker and LLM provider validated successfully");
```

**Step 4: Add bollard to imports**

The bollard crate is already available via feroxmute-core. Add to Cargo.toml if needed, but it should be accessible. If not, add:

```toml
bollard.workspace = true
```

**Step 5: Verify it compiles**

Run: `cargo check -p feroxmute-cli`
Expected: Compiles (may have unused variable warnings for `provider`, that's OK)

**Step 6: Test fail-fast behavior**

Run without Docker: `cargo run -p feroxmute-cli -- --target example.com`
Expected: Clear error message about Docker

Run without API key (unset ANTHROPIC_API_KEY first): Same command
Expected: Clear error message about API key

**Step 7: Commit**

```bash
git add feroxmute-cli/src/main.rs feroxmute-cli/Cargo.toml
git commit -m "feat(cli): add async main with fail-fast validation"
```

---

## Task 7: Create Agent Runner Module

**Files:**
- Create: `feroxmute-cli/src/runner.rs`
- Modify: `feroxmute-cli/src/main.rs`

**Step 1: Create the runner module**

Create `feroxmute-cli/src/runner.rs`:

```rust
//! Agent execution runner

use std::sync::Arc;

use anyhow::Result;
use feroxmute_core::agents::{Agent, AgentContext, AgentStatus, AgentTask, ReconAgent};
use feroxmute_core::docker::ContainerManager;
use feroxmute_core::providers::LlmProvider;
use feroxmute_core::state::MetricsTracker;
use feroxmute_core::tools::ToolExecutor;
use rusqlite::Connection;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::tui::AgentEvent;

/// Run the recon agent with TUI feedback
pub async fn run_recon_agent(
    target: String,
    provider: Arc<dyn LlmProvider>,
    container: ContainerManager,
    metrics: MetricsTracker,
    conn: Connection,
    tx: mpsc::Sender<AgentEvent>,
    cancel: CancellationToken,
) -> Result<()> {
    // Send initial status
    let _ = tx
        .send(AgentEvent::Status {
            agent: "recon".to_string(),
            status: AgentStatus::Running,
        })
        .await;

    let _ = tx
        .send(AgentEvent::Feed {
            agent: "recon".to_string(),
            message: format!("Starting reconnaissance on {}", target),
            is_error: false,
        })
        .await;

    // Create agent and executor
    let mut agent = ReconAgent::new();
    let executor = ToolExecutor::new(container, metrics);

    // Create task
    let task = AgentTask::new("recon-main", "recon", format!("Reconnaissance of {}", target));

    // Create context
    let ctx = AgentContext::new(provider.as_ref(), &executor, &conn, &target);

    // Run with cancellation support
    tokio::select! {
        result = agent.execute(&task, &ctx) => {
            match result {
                Ok(output) => {
                    let _ = tx.send(AgentEvent::Status {
                        agent: "recon".to_string(),
                        status: AgentStatus::Completed,
                    }).await;

                    let _ = tx.send(AgentEvent::Finished {
                        success: true,
                        message: format!("Reconnaissance complete. Output:\n{}", output),
                    }).await;
                }
                Err(e) => {
                    let _ = tx.send(AgentEvent::Status {
                        agent: "recon".to_string(),
                        status: AgentStatus::Failed,
                    }).await;

                    let _ = tx.send(AgentEvent::Finished {
                        success: false,
                        message: format!("Reconnaissance failed: {}", e),
                    }).await;
                }
            }
        }
        _ = cancel.cancelled() => {
            let _ = tx.send(AgentEvent::Feed {
                agent: "recon".to_string(),
                message: "Cancelled by user".to_string(),
                is_error: false,
            }).await;

            let _ = tx.send(AgentEvent::Status {
                agent: "recon".to_string(),
                status: AgentStatus::Idle,
            }).await;
        }
    }

    Ok(())
}
```

**Step 2: Add module declaration**

In `feroxmute-cli/src/main.rs`, add after the other mod declarations:

```rust
mod runner;
```

**Step 3: Verify it compiles**

Run: `cargo check -p feroxmute-cli`
Expected: Compiles (with warnings about unused imports, that's OK for now)

**Step 4: Commit**

```bash
git add feroxmute-cli/src/runner.rs feroxmute-cli/src/main.rs
git commit -m "feat(cli): add agent runner module"
```

---

## Task 8: Wire Up Agent Execution in Main

**Files:**
- Modify: `feroxmute-cli/src/main.rs`

**Step 1: Add required imports**

Ensure these imports are at the top:

```rust
use feroxmute_core::docker::{ContainerConfig, ContainerManager};
```

**Step 2: Replace the TUI section**

Find the section that starts with `if !args.target.is_empty() {` and contains target processing. After all the target processing logic and just before `// Run TUI`, replace the TUI launch code with:

```rust
        // Create channel for agent events
        let (tx, rx) = mpsc::channel::<tui::AgentEvent>(100);

        // Create cancellation token
        let cancel = CancellationToken::new();

        // Create TUI app with receiver
        let mut app = tui::App::new(&target, &session_id, Some(rx));

        // Add initial feed entries
        app.add_feed(tui::FeedEntry::new(
            "system",
            format!("Starting engagement against {}", target),
        ));
        app.add_feed(tui::FeedEntry::new(
            "system",
            format!("Provider: {} | Model: {}", args.provider, provider_config.model),
        ));

        // If we have linked sources, add info about them
        for group in &targets.groups {
            if let Some(ref source) = group.source_target {
                app.add_feed(tui::FeedEntry::new(
                    "system",
                    format!(
                        "Linked source code: {} -> {}",
                        source.raw, group.web_target.raw
                    ),
                ));
            }
        }

        // If we have standalone sources, note them
        for source in &targets.standalone_sources {
            app.add_feed(tui::FeedEntry::new(
                "system",
                format!("Standalone source for SAST: {}", source.raw),
            ));
        }

        // Start the Kali container
        app.add_feed(tui::FeedEntry::new("system", "Starting Docker container..."));
        let mut container = ContainerManager::new(container_config).await.map_err(|e| {
            anyhow!("Failed to create container manager: {}\n\nHint: Is Docker running?", e)
        })?;
        container.start().await.map_err(|e| {
            anyhow!("Failed to start container: {}\n\nHint: Run 'docker compose build' first", e)
        })?;
        app.add_feed(tui::FeedEntry::new("system", "Docker container started"));

        // Create database connection (in-memory for demo)
        let conn = rusqlite::Connection::open_in_memory()?;
        feroxmute_core::state::run_migrations(&conn)?;

        // Spawn agent task
        let agent_target = target.clone();
        let agent_cancel = cancel.clone();
        let agent_handle = tokio::spawn(async move {
            runner::run_recon_agent(
                agent_target,
                provider,
                container,
                metrics,
                conn,
                tx,
                agent_cancel,
            )
            .await
        });

        // Run TUI (blocking)
        let tui_cancel = cancel.clone();
        let tui_result = tokio::task::spawn_blocking(move || tui::run(&mut app)).await?;

        // Signal cancellation and wait for agent
        cancel.cancel();
        let _ = agent_handle.await;

        tui_result?;
```

**Step 3: Add rusqlite to CLI dependencies**

In `feroxmute-cli/Cargo.toml`, add:

```toml
rusqlite.workspace = true
```

**Step 4: Verify it compiles**

Run: `cargo check -p feroxmute-cli`
Expected: Compiles successfully

**Step 5: Commit**

```bash
git add feroxmute-cli/src/main.rs feroxmute-cli/Cargo.toml
git commit -m "feat(cli): wire up agent execution with TUI"
```

---

## Task 9: Test End-to-End Flow

**Step 1: Build the Docker image**

Run: `docker compose build`
Expected: Kali image builds successfully

**Step 2: Set API key**

Run: `export ANTHROPIC_API_KEY=your-key-here`

**Step 3: Run the application**

Run: `cargo run --release -- --target example.com`
Expected:
- TUI launches
- "Starting Docker container..." appears in feed
- "Docker container started" appears
- "Starting reconnaissance on example.com" appears
- Agent runs tools (if Docker image has them installed)
- Press q, then y to quit

**Step 4: Test error cases**

Without Docker:
Run: `docker stop feroxmute-kali 2>/dev/null; cargo run -- --target example.com`
Expected: Clear error about Docker

Without API key:
Run: `unset ANTHROPIC_API_KEY && cargo run -- --target example.com`
Expected: Clear error about API key

**Step 5: Final commit**

```bash
git add -A
git commit -m "feat: complete minimal demo wiring - end-to-end working"
```

---

## Summary

After completing all tasks:
- Application validates Docker and LLM before starting
- TUI receives live updates from agent via channel
- Recon agent executes and reports progress
- Graceful shutdown on quit
- Clear error messages for common issues
