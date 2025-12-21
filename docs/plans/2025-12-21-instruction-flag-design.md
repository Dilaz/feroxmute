# Instruction Flag Design

## Overview

Add a `--instruction` CLI flag that allows users to provide a custom objective that supplements the default penetration testing workflow.

## Usage

```bash
feroxmute --target ctf.example.com --instruction "find the flag in /root/flag.txt"
feroxmute --target webapp.local --instruction "focus on authentication bypass"
```

## Design Decisions

| Aspect | Decision |
|--------|----------|
| Behavior | Supplements default pentesting goal (not replaces) |
| Visibility | Logged once in TUI feed at startup |
| Cardinality | Single instruction only |
| Persistence | CLI only (no config file support) |

## Implementation

### 1. CLI Argument (args.rs)

```rust
/// Custom instruction to guide the engagement (supplements default behavior)
#[arg(long)]
pub instruction: Option<String>,
```

### 2. Data Flow (main.rs -> runner.rs)

Pass instruction through the call chain:

```rust
// main.rs
runner::run_orchestrator(
    agent_target,
    provider,
    container,
    tx,
    agent_cancel,
    has_source,
    limitations,
    args.instruction.clone(),  // NEW
)
```

### 3. Runner Signature (runner.rs)

```rust
pub async fn run_orchestrator(
    target: String,
    provider: Arc<dyn LlmProvider>,
    container: Arc<ContainerManager>,
    tx: mpsc::Sender<AgentEvent>,
    cancel: CancellationToken,
    has_source_target: bool,
    limitations: Arc<EngagementLimitations>,
    instruction: Option<String>,  // NEW
) -> Result<()>
```

### 4. User Prompt Modification (runner.rs)

```rust
let engagement_task = match &instruction {
    Some(instr) => format!(
        "Engagement Task: Perform security assessment\n\nAdditional Objective: {}",
        instr
    ),
    None => "Engagement Task: Perform security assessment".to_string(),
};
```

### 5. TUI Feed Entry (main.rs)

```rust
if let Some(ref instr) = args.instruction {
    app.add_feed(tui::FeedEntry::new(
        "system",
        format!("Objective: {}", instr),
    ));
}
```

## Files Modified

1. `feroxmute-cli/src/args.rs` - Add instruction field
2. `feroxmute-cli/src/main.rs` - Pass to runner, add feed entry
3. `feroxmute-cli/src/runner.rs` - Accept parameter, modify prompt

## Scope

~20 lines of code changes across 3 files.
