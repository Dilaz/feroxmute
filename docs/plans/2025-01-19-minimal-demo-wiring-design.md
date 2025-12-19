# Minimal Demo Wiring Design

Wire together existing components so the application builds, starts Docker, runs recon agent, and displays output in TUI with proper error handling.

## Architecture

```
┌─────────────┐     channel      ┌─────────────┐
│  TUI Loop   │◄────────────────│ Agent Task  │
│  (sync)     │   AgentEvent    │  (tokio)    │
└─────────────┘                  └──────┬──────┘
                                        │
                         ┌──────────────┼──────────────┐
                         ▼              ▼              ▼
                   ┌──────────┐  ┌───────────┐  ┌──────────┐
                   │ Provider │  │  Docker   │  │ Database │
                   │  (LLM)   │  │ Container │  │ (SQLite) │
                   └──────────┘  └───────────┘  └──────────┘
```

## Startup Sequence

1. Parse CLI args (existing)
2. Load config
3. Validate LLM provider credentials - fail fast with helpful error if missing
4. Check Docker connectivity - fail fast if unavailable
5. Start Kali Docker container
6. Create session directory and SQLite database
7. Create channel for agent → TUI communication
8. Launch TUI on main thread (via spawn_blocking)
9. Spawn recon agent on tokio background task
10. Agent sends AgentEvent messages (feed entries, thinking updates, status changes)
11. TUI polls channel every 100ms and updates display

## Channel Communication

```rust
pub enum AgentEvent {
    /// Add entry to activity feed
    Feed { agent: String, message: String, is_error: bool },

    /// Update the thinking panel
    Thinking(Option<String>),

    /// Update agent status (Idle, Running, Complete, Error)
    Status { agent: String, status: AgentStatus },

    /// Update token metrics
    Metrics { input: u64, output: u64, cache_read: u64 },

    /// Agent finished (success or error)
    Finished { success: bool, message: String },
}
```

TUI integration:
- App gains `receiver: mpsc::Receiver<AgentEvent>` field
- In run_loop, after polling crossterm events, drain the channel with try_recv()
- Channel is bounded (100 messages) for backpressure

## Fail-Fast Error Handling

Validate before TUI starts:

```rust
#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let config = load_or_create_config()?;

    // Validate LLM provider
    let provider = create_provider(&config)
        .map_err(|e| anyhow!("LLM provider error: {e}\n\nHint: Set API key in ~/.feroxmute/config.toml or environment"))?;

    // Check Docker
    let docker = Docker::connect_with_local_defaults()
        .map_err(|_| anyhow!("Cannot connect to Docker.\n\nHint: Is Docker running?"))?;
    docker.ping().await
        .map_err(|_| anyhow!("Docker not responding.\n\nHint: Try 'docker ps' to verify"))?;

    // Start Kali container
    let container = ContainerManager::new(docker).await?;
    container.start().await
        .map_err(|e| anyhow!("Failed to start Kali container: {e}\n\nHint: Run 'docker compose build' first"))?;

    // ... continue to TUI + agent launch
}
```

## TUI + Agent Coordination

```rust
// Create channel
let (tx, rx) = mpsc::channel::<AgentEvent>(100);

// Create cancellation token for graceful shutdown
let cancel = CancellationToken::new();

// Build app with receiver
let mut app = App::new(&args.target, &session.id, rx);

// Spawn agent task
let agent_handle = tokio::spawn(run_recon_agent(target, provider, container, tx, cancel.clone()));

// Run TUI (blocks until quit)
let tui_result = tokio::task::spawn_blocking(move || {
    tui::run(&mut app, cancel.clone())
}).await?;

// Cleanup
cancel.cancel();
let _ = agent_handle.await;
container.stop().await?;
```

## Recon Agent Runner

```rust
async fn run_recon_agent(
    target: String,
    provider: Box<dyn Provider>,
    container: ContainerManager,
    tx: mpsc::Sender<AgentEvent>,
    cancel: CancellationToken,
) -> Result<()> {
    tx.send(AgentEvent::Status { agent: "recon".into(), status: AgentStatus::Running }).await?;
    tx.send(AgentEvent::Feed { agent: "recon".into(), message: format!("Starting reconnaissance on {target}"), is_error: false }).await?;

    let agent = ReconAgent::new();
    let executor = ToolExecutor::new(&container);

    // Callbacks for streaming updates
    let on_thinking = |text: &str| {
        let _ = tx.blocking_send(AgentEvent::Thinking(Some(text.into())));
    };

    let on_tool_call = |tool: &str, result: &str| {
        let _ = tx.blocking_send(AgentEvent::Feed {
            agent: "recon".into(),
            message: format!("[{tool}] {result}"),
            is_error: false,
        });
    };

    // Run with cancellation support
    tokio::select! {
        result = agent.execute(&target, &provider, &executor, on_thinking, on_tool_call) => {
            tx.send(AgentEvent::Finished {
                success: result.is_ok(),
                message: result.map(|_| "Recon complete".into()).unwrap_or_else(|e| e.to_string())
            }).await?;
        }
        _ = cancel.cancelled() => {
            tx.send(AgentEvent::Feed { agent: "recon".into(), message: "Cancelled by user".into(), is_error: false }).await?;
        }
    }

    Ok(())
}
```

## Files to Modify

**New files:**
- `feroxmute-cli/src/tui/channel.rs` - AgentEvent enum
- `feroxmute-cli/src/runner.rs` - run_recon_agent function

**Modified files:**
- `feroxmute-cli/src/main.rs` - Add #[tokio::main], startup validation, spawn agent
- `feroxmute-cli/src/tui/app.rs` - Add receiver field to App
- `feroxmute-cli/src/tui/runner.rs` - Poll channel in event loop, accept CancellationToken
- `feroxmute-cli/src/tui/mod.rs` - Export channel module
- `feroxmute-cli/Cargo.toml` - Add tokio-util (for CancellationToken)

**May need adjustment in core:**
- `feroxmute-core/src/agents/recon.rs` - Add callback parameters to execute() for streaming

## Shutdown

- User presses q → confirmation dialog → signal CancellationToken
- Agent receives cancellation, sends final status, exits
- Main awaits agent handle
- Container stopped and cleaned up
- TUI exits cleanly
