# feroxmute Design Document

An LLM-powered penetration testing framework with a hierarchical agent architecture.

## Overview

**feroxmute** automates penetration testing using specialized AI agents coordinated by an orchestrator. It runs tools inside a Kali Linux Docker container and provides a terminal UI for monitoring progress.

### Scope
- **Primary:** Web application testing (SQLi, XSS, SSRF, IDOR, auth bypass, etc.)
- **Secondary:** Network reconnaissance (port scanning, service enumeration)

### Key Features
- Hierarchical agent orchestration
- ProjectDiscovery toolchain integration
- Rig.rs for LLM providers with optional LiteLLM sidecar
- SQLite state persistence with artifact storage
- Ratatui TUI with dashboard and agent detail views
- JSON + Markdown reports with optional HTML/PDF export

---

## Architecture

### Crate Structure

```
feroxmute/
├── Cargo.toml              # Workspace manifest
├── feroxmute-core/         # Library crate
│   ├── src/
│   │   ├── lib.rs
│   │   ├── agents/         # Orchestrator + specialists
│   │   ├── tools/          # Tool integrations (PD, browser, scripts)
│   │   ├── providers/      # LLM provider abstraction (Rig + LiteLLM)
│   │   ├── state/          # SQLite + artifact storage
│   │   └── config/         # Engagement configuration
│   └── Cargo.toml
├── feroxmute-cli/          # TUI binary crate
│   ├── src/
│   │   ├── main.rs
│   │   ├── tui/            # Ratatui views (dashboard, agent detail)
│   │   ├── input/          # Keybindings, command handling
│   │   └── wizard/         # Interactive setup
│   └── Cargo.toml
└── docker/
    ├── Dockerfile          # Kali + ProjectDiscovery tools
    └── compose.yml         # Optional LiteLLM sidecar
```

### Dependencies

**Core:**
- rig-core: LLM provider abstraction and agent primitives
- rusqlite: State persistence
- tokio: Async runtime
- bollard: Docker API for container management
- ratatui + crossterm: Terminal UI

**Developer Experience:**
- miette: Pretty error diagnostics with source spans
- tracing + tracing-subscriber: Structured logging and instrumentation
- thiserror: Derive macros for library error types (feroxmute-core)
- anyhow: Ergonomic error handling in binary (feroxmute-cli)
- serde + serde_json: Serialization for config, state, tool outputs
- clap: CLI argument parsing with derive

---

## Agent Architecture

The system uses a hierarchical orchestrator pattern. One lead agent plans and delegates to specialist agents.

```
                    ┌─────────────────┐
                    │  Orchestrator   │
                    │  (Lead Agent)   │
                    └────────┬────────┘
                             │ delegates
        ┌──────────┬─────────┼─────────┬──────────┐
        ▼          ▼         ▼         ▼          ▼
   ┌─────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐
   │  Recon  │ │  Web   │ │Exploit │ │ Report │ │ Script │
   │  Agent  │ │Scanner │ │ Agent  │ │ Agent  │ │Service │
   └─────────┘ └────────┘ └────────┘ └────────┘ └────────┘
        │           │          │                     ▲
        └───────────┴──────────┴─────────────────────┘
                    (any agent can use scripts)
```

### Agent Responsibilities

| Agent | Role | Outputs |
|-------|------|---------|
| **Orchestrator** | Plans engagement phases, delegates tasks, tracks progress | Phase transitions, agent assignments |
| **Recon** | Asset discovery, tech fingerprinting, surface mapping | Hosts, ports, technologies, endpoints |
| **Web Scanner** | Crawling, vulnerability scanning, parameter fuzzing | Potential vulnerabilities, evidence |
| **Exploit** | PoC validation, exploitation attempts | Confirmed vulns, exploitation proof |
| **Report** | Aggregates findings, generates reports | JSON, Markdown, HTML/PDF |
| **Script Service** | Executes Python/Rust scripts on demand | Script outputs, artifacts |

### Agent Communication

Agents communicate through the SQLite database and a message bus. Each agent:
1. Receives tasks from orchestrator
2. Executes tools in the Kali container
3. Stores findings in SQLite
4. Reports completion back to orchestrator

---

## Tool Integration

Agents execute tools inside a shared Kali Docker container with namespaced working directories.

### Container Structure

```
/feroxmute/
├── workdir/
│   ├── orchestrator/
│   ├── recon/
│   ├── scanner/
│   ├── exploit/
│   └── scripts/
├── artifacts/          # Downloaded files, dumps, binaries
├── screenshots/        # Browser captures
└── shared/             # Cross-agent data (e.g., target list)
```

### Tool Mapping

| Agent | ProjectDiscovery Tools | Other Tools |
|-------|------------------------|-------------|
| **Recon** | subfinder, naabu, httpx, dnsx, tlsx, katana, asnmap, uncover | whois, dig |
| **Web Scanner** | nuclei, katana, httpx, interactsh | feroxbuster, ffuf |
| **Exploit** | nuclei (exploit templates), interactsh | sqlmap, commix |
| **Script Service** | - | python3, rustc (feature flag) |
| **Shared** | notify, cvemap, proxify | curl, wget, playwright |

### Tool Execution Flow

```
Agent                    Core                     Container
  │                        │                          │
  ├─ request tool ────────►│                          │
  │                        ├─ bollard exec ──────────►│
  │                        │                          ├─ run tool
  │                        │                          │
  │                        │◄─ stdout/stderr stream ──┤
  │◄─ parsed JSON result ──┤                          │
  │                        │                          │
  ├─ store in SQLite ─────►│                          │
```

### Dockerfile

```dockerfile
FROM kalilinux/kali-rolling
RUN apt-get update && apt-get install -y \
    golang sqlmap feroxbuster ffuf chromium python3

# ProjectDiscovery tools
RUN go install -v github.com/projectdiscovery/pdtm/cmd/pdtm@latest
RUN pdtm -install-all

# Python with uv
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.cargo/bin:$PATH"
RUN uv python install 3.12

# Browser automation
RUN uv pip install playwright && playwright install chromium
```

---

## State Management

Each engagement is stored as a session with SQLite for structured data and filesystem for artifacts.

### Session Directory Structure

```
~/.feroxmute/sessions/
└── 2024-01-15-example-com/
    ├── session.db              # SQLite database
    ├── config.toml             # Engagement configuration
    ├── artifacts/
    │   ├── downloads/          # Dumped files, binaries
    │   └── evidence/           # PoC screenshots, responses
    ├── screenshots/            # Browser captures
    ├── scripts/
    │   ├── python/             # Generated Python scripts
    │   └── rust/               # Generated Rust scripts (feature flag)
    └── reports/
        ├── findings.json       # Machine-readable
        ├── report.md           # Human-readable
        └── report.html         # Optional export
```

### SQLite Schema

```sql
-- Core entities
CREATE TABLE hosts (id, address, hostname, discovered_at);
CREATE TABLE ports (id, host_id, port, protocol, service, state);
CREATE TABLE technologies (id, host_id, name, version, category);

-- Findings
CREATE TABLE vulnerabilities (
    id, host_id, type, severity,
    title, description, evidence,
    status,  -- potential | confirmed | exploited
    discovered_by,  -- which agent
    discovered_at
);

-- Agent state
CREATE TABLE agent_tasks (id, agent, task, status, started_at, completed_at);
CREATE TABLE agent_messages (id, from_agent, to_agent, content, timestamp);
CREATE TABLE tool_executions (id, agent, tool, args, output, exit_code, executed_at);
```

### State Recovery

On crash or interrupt, feroxmute can resume from the last known state:
- Orchestrator reloads phase and pending tasks
- Agents resume incomplete tool executions
- Partial findings are preserved

---

## Terminal UI

The TUI uses ratatui with a single-pane design, toggleable dashboard view, and mouse support.

### Dashboard View

```
┌─ feroxmute ──────────────────────────────────────────────────┐
│ Target: example.com          Session: 2024-01-15-example-com │
│ Phase: Reconnaissance        Elapsed: 00:14:32               │
├──────────────────────────────────────────────────────────────┤
│ Metrics                                                      │
│ Tools: 142 calls    Tokens: 12.4k in │ 2.1k cached │ 8.7k out│
│ Vulns: 7 total      5 potential │ 2 verified │ 0 exploited   │
├──────────────────────────────────────────────────────────────┤
│ Agents              Status          Findings        [click]  │
│ ● Orchestrator      planning        -                  ○     │
│ ● Recon             running         3 hosts, 47 ports  ○     │
│ ○ Web Scanner       queued          -                  ○     │
│ ○ Exploit           idle            -                  ○     │
│ ○ Report            idle            -                  ○     │
├──────────────────────────────────────────────────────────────┤
│ Live Feed                                                    │
│ [14:32:01] recon: subfinder found admin.example.com          │
│ [14:32:03] recon: httpx probing 47 endpoints...              │
│ [14:32:07] recon: Found admin panel at /wp-admin             │
└──────────────────────────────────────────────────────────────┘
│ [h]ome [t]hinking [d]etail [1-4]agent [q]uit    mouse:on     │
└──────────────────────────────────────────────────────────────┘
```

### Agent Detail View

```
┌─ Recon Agent ────────────────────────────────────────────────┐
│ Status: running              Current tool: httpx             │
├──────────────────────────────────────────────────────────────┤
│ Tool Output                                                  │
│ https://example.com [200] [nginx] [HTML]                     │
│ https://admin.example.com [401] [nginx] [Basic Auth]         │
│ https://api.example.com [200] [cloudflare] [JSON]            │
│ ...                                                          │
├──────────────────────────────────────────────────────────────┤
│ Thinking (toggle: t)                                         │
│ Found 3 subdomains. api.example.com returns JSON, likely     │
│ an API endpoint. admin.example.com has Basic Auth - worth    │
│ investigating. Running nuclei scan next...                   │
└──────────────────────────────────────────────────────────────┘
```

### Keybindings

| Key | Action |
|-----|--------|
| `h` / `Home` | Dashboard view |
| `1-4` | Jump to agent (1=Recon, 2=Scanner, 3=Exploit, 4=Report) |
| `Enter` | Dive into selected agent |
| `Esc` | Back to dashboard |
| `t` | Toggle thinking/reasoning panel |
| `d` | Toggle detailed tool output |
| `l` | View full logs |
| `p` | Pause/resume agents |
| `q` | Quit (with confirmation) |

### Mouse Support

- **Click agent row** → Opens agent detail view
- **Click metrics** → Expands to detailed breakdown
- **Click tabs/buttons** → Navigate views
- **Scroll** → Scroll through logs/output

---

## Configuration

Configuration uses TOML files with CLI flag overrides, plus an interactive wizard.

### CLI Usage

```bash
# Quick start with wizard
feroxmute --wizard

# Standard usage
feroxmute --target example.com --config engagement.toml

# Override config with flags
feroxmute --target example.com --no-exploit --passive --rate-limit 5

# Resume previous session
feroxmute --resume ~/.feroxmute/sessions/2024-01-15-example-com
```

### CLI Flags

| Flag | Description |
|------|-------------|
| `--target <HOST>` | Target domain or IP |
| `--config <FILE>` | Path to config file |
| `--wizard` | Interactive setup mode |
| `--resume <SESSION>` | Resume previous session |
| `--scope <web\|network\|full>` | Testing scope (default: web) |
| `--no-exploit` | Recon and scan only, no exploitation |
| `--no-portscan` | Skip port scanning |
| `--passive` | Passive recon only, no active probing |
| `--ports <LIST>` | Limit port range (e.g., "80,443,8080") |
| `--rate-limit <N>` | Max requests per second |
| `--provider <NAME>` | LLM provider (openai, anthropic, litellm) |
| `--model <NAME>` | Model to use |
| `--output <DIR>` | Output directory for session |
| `--html` | Export HTML report |
| `--pdf` | Export PDF report |

### Config File (engagement.toml)

```toml
[target]
host = "example.com"
scope = "web"
ports = [80, 443, 8080, 8443]

[constraints]
passive = false
no_exploit = false
no_portscan = false
rate_limit = 10
excluded_paths = ["/logout", "/admin/delete"]

[auth]
type = "bearer"  # none | basic | bearer | cookie
token = "${FEROXMUTE_AUTH_TOKEN}"  # env var expansion

[provider]
name = "anthropic"
model = "claude-sonnet-4-20250514"
# Or use LiteLLM proxy
# name = "litellm"
# base_url = "http://localhost:4000"
# model = "gpt-4o"

[output]
session_dir = "~/.feroxmute/sessions"
export_html = false
export_pdf = false
```

---

## LLM Provider Integration

Rig.rs handles direct provider connections, with optional LiteLLM sidecar for extended provider support.

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      feroxmute-core                         │
│  ┌─────────────────────────────────────────────────────────┐│
│  │              Provider Abstraction Layer                 ││
│  └──────────┬──────────────────────┬───────────────────────┘│
│             │                      │                        │
│      ┌──────▼──────┐        ┌──────▼──────┐                 │
│      │   Rig.rs    │        │   LiteLLM   │                 │
│      │  (native)   │        │  (sidecar)  │                 │
│      └──────┬──────┘        └──────┬──────┘                 │
└─────────────┼──────────────────────┼────────────────────────┘
              │                      │
       ┌──────▼──────┐        ┌──────▼──────┐
       │  Anthropic  │        │  100+ LLMs  │
       │   OpenAI    │        │   Ollama    │
       │   Cohere    │        │   Azure     │
       └─────────────┘        └─────────────┘
```

### Provider Selection

```bash
# Direct providers - no LiteLLM needed
feroxmute --target example.com --provider anthropic --model claude-sonnet-4-20250514
feroxmute --target example.com --provider openai --model gpt-4o

# Only when you need LiteLLM (Ollama, Azure, Bedrock, etc.)
feroxmute --target example.com --provider litellm --model ollama/llama3
```

### Docker Compose with Optional Profile

```yaml
services:
  kali:
    build: ./docker
    volumes:
      - ./sessions:/root/.feroxmute/sessions

  # Only starts with: docker compose --profile litellm up
  litellm:
    profiles: ["litellm"]
    image: ghcr.io/berriai/litellm:main-latest
    ports:
      - "4000:4000"
    environment:
      - OPENAI_API_KEY
      - ANTHROPIC_API_KEY
```

### Provider Trait

```rust
#[async_trait]
pub trait LlmProvider: Send + Sync {
    async fn complete(&self, request: CompletionRequest) -> Result<CompletionResponse>;
    async fn complete_stream(&self, request: CompletionRequest) -> Result<CompletionStream>;
    fn supports_tools(&self) -> bool;
    fn token_counter(&self) -> &TokenCounter;
}

pub struct TokenCounter {
    pub input: AtomicU64,
    pub cached: AtomicU64,
    pub output: AtomicU64,
}
```

---

## Agent Prompts

Each agent has a specialized system prompt. See full prompts in `feroxmute-core/src/agents/prompts/`.

### Orchestrator

Plans engagement phases, delegates to specialists, tracks progress, respects scope constraints.

### Recon Agent

Tools: subfinder, naabu, httpx, katana, dnsx, tlsx, asnmap, uncover

Maps attack surface: subdomains, ports, technologies, endpoints.

### Web Scanner Agent

Tools: nuclei, katana, httpx, feroxbuster, interactsh

Identifies vulnerabilities: injection, access control, server-side, misconfigurations.

### Exploit Agent

Tools: sqlmap, commix, nuclei (exploit templates), interactsh, scripts

Validates vulnerabilities with safe PoC exploitation. Never destructive.

### Report Agent

Aggregates findings, generates JSON + Markdown reports, optional HTML/PDF export.

### Script Service

Writes and executes Python/Rust scripts on demand for any agent.

---

## Report Output

### JSON (findings.json)

```json
{
  "metadata": {
    "target": "example.com",
    "session_id": "2024-01-15-example-com",
    "started_at": "2024-01-15T10:00:00Z",
    "completed_at": "2024-01-15T12:34:56Z",
    "scope": "web"
  },
  "metrics": {
    "tool_calls": 342,
    "tokens": {"input": 45200, "cached": 12100, "output": 18700}
  },
  "summary": {
    "hosts_discovered": 5,
    "vulnerabilities": {"critical": 1, "high": 3, "medium": 7, "low": 4}
  },
  "findings": [
    {
      "id": "VULN-001",
      "title": "SQL Injection in login endpoint",
      "severity": "critical",
      "status": "verified",
      "asset": "https://example.com/api/login",
      "cwe": "CWE-89",
      "evidence": {...},
      "remediation": "Use parameterized queries."
    }
  ]
}
```

### Markdown (report.md)

Executive summary, findings table, detailed findings with evidence, remediation guidance.

### HTML/PDF

Optional exports via `--html` and `--pdf` flags.

---

## Next Steps

1. Set up workspace with feroxmute-core and feroxmute-cli crates
2. Implement provider abstraction with Rig.rs
3. Build Docker image with Kali + ProjectDiscovery tools
4. Implement SQLite state management
5. Build agent framework (orchestrator + specialists)
6. Implement tool execution via bollard
7. Build TUI with ratatui
8. Add report generation
9. Add interactive wizard
