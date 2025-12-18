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
cargo run -- --wizard          # Interactive setup (not yet implemented)
cargo run -- --resume <path>   # Resume session

# Test
cargo test                     # Run all tests
cargo test -p feroxmute-core   # Test core library only

# Lint and Format
cargo fmt                      # Format code
cargo clippy                   # Lint

# Docker
docker compose build                    # Build Kali image
docker compose up                       # Start containers
docker compose up --profile litellm     # Start with LiteLLM sidecar
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
1. Receives tasks from orchestrator
2. Executes tools in the Kali Docker container
3. Stores findings in SQLite
4. Reports completion back

### Key Modules (feroxmute-core/src/)

- **agents/**: Agent implementations (orchestrator, recon, scanner, exploit, report)
  - `traits.rs`: Agent trait definitions
  - `prompts.rs`: Prompt loading from prompts.toml
- **providers/**: LLM provider abstraction (Anthropic, OpenAI via rig-core)
  - `traits.rs`: Provider trait and Message types
  - `factory.rs`: Provider instantiation
- **state/**: SQLite persistence and session management
  - `models.rs`: Host, Port, Vulnerability data structures
  - `session.rs`: Session lifecycle
- **tools/**: Tool execution via Docker
  - `executor.rs`: Runs commands in Kali container
- **docker/**: Container management via bollard

### Key Modules (feroxmute-cli/src/)

- **tui/**: Ratatui terminal UI
  - `app.rs`: Application state
  - `runner.rs`: Main event loop
  - `widgets/`: Dashboard, AgentDetail views

### Data Flow

1. User provides target via CLI args
2. TUI creates session with EngagementConfig
3. Orchestrator plans phases, delegates to specialists
4. Specialists call LLM, execute tools in Docker container
5. Results stored in SQLite session database
6. Report agent generates JSON/Markdown findings
7. TUI displays live progress

### Session Storage

Sessions are stored in `~/.feroxmute/sessions/<session-id>/`:
- `session.db`: SQLite database
- `config.toml`: Engagement configuration
- `artifacts/`: Downloaded files, evidence
- `reports/`: Generated findings (JSON, Markdown)

## Configuration

Agent prompts are defined in `feroxmute-core/prompts.toml`. The engagement config supports TOML files with environment variable expansion (e.g., `${FEROXMUTE_AUTH_TOKEN}`).

Default LLM provider: Anthropic with claude-sonnet-4-20250514
