# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

feroxmute is an LLM-powered penetration testing framework with hierarchical agent architecture. It automates security testing using specialized AI agents coordinated by an orchestrator, running tools inside a Kali Linux Docker container with a terminal UI for monitoring.

## Build and Development Commands

```bash
# Build
cargo build                    # Debug build
cargo build --release          # Release build

# Run
cargo run -- --target example.com --provider anthropic
cargo run -- --target example.com --source ./app  # With source code for SAST
cargo run -- --sast-only --target ./app           # Source-only analysis
cargo run -- --wizard          # Interactive setup
cargo run -- --resume <path>   # Resume session

# Test
cargo test                     # Run all tests
cargo test -p feroxmute-core   # Test core library only
cargo test test_name           # Run single test by name

# Lint and Format
cargo fmt                      # Format code
cargo clippy                   # Lint

# Docker
docker compose -f docker/compose.yml build               # Build Kali image
docker compose -f docker/compose.yml up                  # Start containers
docker compose -f docker/compose.yml --profile litellm up  # With LiteLLM proxy
```

## Architecture

### Crate Structure

- **feroxmute-core**: Library crate with agents, LLM providers, state management, and tool execution
- **feroxmute-cli**: Binary crate with TUI and CLI argument parsing

### Agent Hierarchy

```
                    Orchestrator
                         │
        ┌────────┬───────┼───────┬────────┐
        ▼        ▼       ▼       ▼        ▼
     Recon   Scanner  Exploit  Report  Script
```

The Orchestrator plans engagement phases and delegates to specialists. Each agent:
1. Receives tasks from orchestrator via `SpawnAgentTool`
2. Executes tools in the Kali Docker container via `DockerShellTool`
3. Stores findings in SQLite via `RecordFindingTool`
4. Reports completion back; orchestrator waits via `WaitForAgentTool`

### Key Modules (feroxmute-core/src/)

- **agents/**: Agent implementations (orchestrator, recon, scanner, exploit, report)
  - `traits.rs`: `Agent` trait with `execute()`, `system_prompt()`, `tools()`
  - `prompts.rs`: Prompt loading from prompts.toml
- **providers/**: LLM provider abstraction via rig-core
  - `traits.rs`: `LlmProvider` trait with `complete_with_shell()`, `complete_with_orchestrator()`, `complete_with_report()`
  - `macros.rs`: `define_provider!` macro generates 95% of provider boilerplate
  - `factory.rs`: Provider instantiation by name
  - Supports: Anthropic, OpenAI, Gemini, Cohere, xAI, DeepSeek, Azure, Perplexity, Ollama, LiteLLM
- **tools/**: rig-compatible tool implementations
  - `executor.rs`: `ToolExecutor` runs commands in Kali container
  - `docker_shell.rs`: `DockerShellTool` for agent shell access
  - `orchestrator.rs`: `SpawnAgentTool`, `WaitForAgentTool`, `ListAgentsTool`, `CompleteEngagementTool`
  - `memory.rs`: `MemoryAddTool`, `MemoryGetTool`, `MemoryListTool` for agent scratchpad
  - `report.rs`: `GenerateReportTool`, `ExportJsonTool`, `ExportMarkdownTool`
- **state/**: SQLite persistence and session management
- **docker/**: Container management via bollard

### Key Modules (feroxmute-cli/src/)

- **tui/**: Ratatui terminal UI
  - `app.rs`: Application state and event handling
  - `runner.rs`: Main event loop
  - `widgets/`: Dashboard, AgentDetail views
  - TUI keys: `q` quit, `Tab` switch view, `p` view orchestrator memory

### Data Flow

1. User provides target via CLI args
2. TUI creates session, spawns Kali container with optional source mount
3. Orchestrator plans phases, spawns specialists via `SpawnAgentTool`
4. Specialists use `DockerShellTool` to run security tools (nmap, nuclei, sqlmap, etc.)
5. Results stored via `RecordFindingTool`
6. Report agent generates JSON/Markdown via report tools
7. TUI displays live progress via `EventSender` channel

### Provider Macro System

New providers are added using `define_provider!` in `providers/macros.rs`:
```rust
define_provider! {
    name: AnthropicProvider,
    provider_name: "anthropic",
    client_type: anthropic::Client,
    env_var: "ANTHROPIC_API_KEY",
    supports_tools: true,
    client_builder: |builder, _base_url| builder,
    has_base_url: false
}
```

### Session Storage

Sessions are stored in `~/.feroxmute/sessions/<session-id>/`:
- `session.db`: SQLite database
- `config.toml`: Engagement configuration
- `artifacts/`: Downloaded files, evidence
- `reports/`: Generated findings (JSON, Markdown)

Logs: `~/.feroxmute/logs/feroxmute.log`

## Configuration

Agent prompts are defined in `feroxmute-core/prompts.toml`. The engagement config supports TOML files with environment variable expansion (e.g., `${FEROXMUTE_AUTH_TOKEN}`).

Default LLM provider: Anthropic with claude-sonnet-4-20250514

## Development Guidelines

### Package Manager

**Always use `bun`, never `npm`.** For any JavaScript/TypeScript tooling or dependencies, use bun commands:
- `bun install` instead of `npm install`
- `bun run` instead of `npm run`
- `bun add` instead of `npm install <package>`

**Use `biome` for JavaScript/TypeScript code quality:**
```bash
bunx biome check .              # Check for issues
bunx biome check --write .      # Auto-fix issues
```

### Dependency Management

**Use `cargo add` to add Rust dependencies.** Never edit `Cargo.toml` directly for adding dependencies:
```bash
cargo add serde --features derive    # Add with features
cargo add tokio -p feroxmute-core    # Add to specific crate
```

### Pre-Commit Requirements

Before every commit, you MUST:
1. Run `cargo fmt` to format all Rust code
2. Run `cargo clippy` and fix ALL warnings (not just errors)
3. Ensure the build passes with `cargo build`

```bash
# Pre-commit checklist
cargo fmt && cargo clippy --fix --allow-dirty && cargo build
```

### Code Quality

- **Keep files focused and small.** If a file exceeds ~300-400 lines, consider refactoring into smaller modules.
- **Refactor proactively.** Don't let technical debt accumulate—clean up as you go.
- **Optimize for developer experience.** Code should be easy to read, navigate, and modify.
- **Use clear module boundaries.** Each module should have a single responsibility.
