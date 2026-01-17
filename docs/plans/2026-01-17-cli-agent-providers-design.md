# CLI Agent Providers Design

Add support for CLI-based coding agents (Claude Code, Codex, Gemini CLI) as feroxmute providers, enabling users to leverage their existing subscriptions instead of API calls.

## Overview

This design introduces a new provider type that wraps CLI agents using two protocols:

- **ACP (Agent Client Protocol)** - Feroxmute acts as an ACP client, spawning CLI agents as subprocesses and communicating via stdin/stdout JSON-RPC
- **MCP (Model Context Protocol)** - Feroxmute acts as an MCP server, exposing all feroxmute tools for CLI agents to call

### Architecture

```
┌────────────────────────────────────────────────────────────────────┐
│ feroxmute                                                          │
│  ┌─────────────────┐      ┌─────────────────┐                      │
│  │ ACP Client      │      │ MCP Server      │                      │
│  │ (drives agent)  │      │ (provides tools)│                      │
│  └────────┬────────┘      └────────┬────────┘                      │
│           │ ACP                    │ MCP                           │
│           ▼                        ▼                               │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ CLI Agent subprocess (claude / codex / gemini)              │   │
│  │ Session 1: Orchestrator                                     │   │
│  │ Session 2: Recon specialist                                 │   │
│  │ Session N: ...                                              │   │
│  └─────────────────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────────────────┘
         │
         ▼
┌────────────────────────────────────────────────────────────────────┐
│ Kali Docker Container                                              │
│  nmap, nuclei, sqlmap, nikto, etc.                                 │
└────────────────────────────────────────────────────────────────────┘
```

### Key Design Decisions

1. **Hybrid execution mode** - CLI agents handle reasoning/planning, feroxmute intercepts tool calls and executes them inside the Kali Docker container

2. **MCP-based tool exposure** - Rather than intercepting and translating tool calls, feroxmute exposes its tools via MCP. CLI agents explicitly call feroxmute tools.

3. **Single binary, CLI agent spawned** - `feroxmute --provider claude-code` spawns the CLI agent as subprocess, connects via ACP, and provides MCP tools. TUI still shows progress.

4. **Same CLI agent for all roles** - When orchestrator spawns a specialist agent, feroxmute creates a new ACP session with the same CLI agent (different system prompt). All agents use the same CLI backend.

5. **Full feature parity** - All existing feroxmute tools exposed via MCP, including orchestrator tools (spawn_agent, wait_for_agent, etc.)

## Provider Implementation

### Module Structure

```
feroxmute-core/src/
├── providers/
│   └── cli_agent/
│       ├── mod.rs           # Module exports
│       ├── provider.rs      # LlmProvider implementation
│       ├── acp_client.rs    # ACP connection management
│       ├── mcp_server.rs    # MCP tool server
│       └── config.rs        # CLI agent configuration
└── mcp/
    ├── mod.rs               # Module exports
    ├── protocol.rs          # JSON-RPC types for MCP
    └── transport.rs         # stdio handling
```

### Provider Struct

```rust
pub struct CliAgentProvider {
    agent_type: CliAgentType,
    acp_connection: AcpConnection,
    mcp_server: McpServer,
    sessions: HashMap<String, SessionId>,  // agent_name -> ACP session
    metrics: MetricsTracker,
}

pub enum CliAgentType {
    ClaudeCode { path: PathBuf },
    Codex { path: PathBuf },
    Gemini { path: PathBuf },
}
```

### LlmProvider Trait Implementation

The provider implements the existing `LlmProvider` trait:

- `complete_with_shell()` - Creates ACP session with specialist system prompt
- `complete_with_orchestrator()` - Creates ACP session with orchestrator prompt, `spawn_agent` creates new sessions
- `complete_with_report()` - Creates ACP session with report prompt

The provider does NOT use rig-core internally. Instead, it uses the `agent-client-protocol` crate directly.

## MCP Server Implementation

### Tool Mapping

All current feroxmute tools exposed via MCP:

| Feroxmute Tool | MCP Tool Name | Available To |
|----------------|---------------|--------------|
| `DockerShellTool` | `docker_shell` | Specialists |
| `RunScriptTool` | `run_script` | Specialists |
| `MemoryAddTool` | `memory_add` | All |
| `MemoryGetTool` | `memory_get` | All |
| `MemoryListTool` | `memory_list` | All |
| `MemoryRemoveTool` | `memory_remove` | Orchestrator |
| `SpawnAgentTool` | `spawn_agent` | Orchestrator |
| `WaitForAgentTool` | `wait_for_agent` | Orchestrator |
| `WaitForAnyTool` | `wait_for_any` | Orchestrator |
| `ListAgentsTool` | `list_agents` | Orchestrator |
| `RecordFindingTool` | `record_finding` | Orchestrator |
| `CompleteEngagementTool` | `complete_engagement` | Orchestrator |
| `GenerateReportTool` | `generate_report` | Report |
| `ExportJsonTool` | `export_json` | Report |
| `ExportMarkdownTool` | `export_markdown` | Report |
| `ExportHtmlTool` | `export_html` | Report |
| `ExportPdfTool` | `export_pdf` | Report |
| `AddRecommendationTool` | `add_recommendation` | Report |

### Tool Availability Per Session

When creating an ACP session, feroxmute configures which MCP tools are visible based on agent role. This mirrors how API providers build different tool sets for orchestrator vs specialists.

### MCP Server Lifecycle

1. Started when CLI agent provider is created
2. Runs on a local socket or stdio pipe
3. CLI agent is configured to connect to it via `--mcp-server` flag or config file
4. Shut down when engagement completes

### Minimal Implementation

MCP is a simple JSON-RPC protocol over stdio. Minimal hand-rolled implementation (~200 lines):

```rust
pub struct McpServer {
    tools: HashMap<String, Box<dyn McpTool>>,
}

impl McpServer {
    pub async fn handle_request(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        match req.method.as_str() {
            "tools/list" => self.list_tools(),
            "tools/call" => self.call_tool(req.params),
            _ => JsonRpcResponse::error(METHOD_NOT_FOUND),
        }
    }
}
```

## ACP Client Implementation

### Connection Structure

```rust
pub struct AcpConnection {
    child: Child,                              // CLI subprocess
    connection: ClientSideConnection,          // From agent-client-protocol crate
    sessions: HashMap<SessionId, SessionState>,
    io_task: JoinHandle<()>,                  // Reads stdout, dispatches responses
}
```

### Spawning CLI Agents

```rust
impl AcpConnection {
    pub async fn spawn(agent_type: CliAgentType, mcp_config: &Path) -> Result<Self> {
        // 1. Build command based on agent type
        let mut cmd = match agent_type {
            CliAgentType::ClaudeCode { path } => Command::new(path),
            CliAgentType::Codex { path } => Command::new(path),
            CliAgentType::Gemini { path } => Command::new(path),
        };

        // 2. Configure MCP server connection
        cmd.arg("--mcp-config").arg(mcp_config);

        // 3. Spawn with piped stdio
        let child = cmd.stdin(Stdio::piped())
                      .stdout(Stdio::piped())
                      .stderr(Stdio::piped())
                      .spawn()?;

        // 4. Initialize ACP connection
        let connection = ClientSideConnection::new(stdin, stdout);
        connection.initialize(InitializeRequest::new(ProtocolVersion::V1)).await?;

        Ok(Self { child, connection, sessions: HashMap::new(), ... })
    }
}
```

### Session Management for Multi-Agent

- Orchestrator session created at engagement start
- When `spawn_agent` MCP tool called, feroxmute creates new ACP session with specialist prompt
- Each session has independent conversation history
- Sessions can run concurrently (parallel agent execution)

### Key ACP Operations

- `new_session()` - Create session for each agent
- `prompt()` - Send message, receive streaming response
- `cancel()` - Abort running session

## CLI and Configuration

### New CLI Flags

```bash
# Use Claude Code as provider
feroxmute --target example.com --provider claude-code

# Use Codex as provider
feroxmute --target example.com --provider codex

# Use Gemini CLI as provider
feroxmute --target example.com --provider gemini-cli

# Specify custom CLI path (if not in PATH)
feroxmute --target example.com --provider claude-code --cli-path /usr/local/bin/claude
```

### Provider Factory Updates

```rust
pub fn create_provider(name: &str, model: &str, metrics: MetricsTracker) -> Result<Arc<dyn LlmProvider>> {
    match name {
        "anthropic" => Ok(Arc::new(AnthropicProvider::new(model, metrics)?)),
        "openai" => Ok(Arc::new(OpenAiProvider::new(model, metrics)?)),
        // ... existing providers ...

        // NEW: CLI agent providers
        "claude-code" => Ok(Arc::new(CliAgentProvider::new(CliAgentType::ClaudeCode, metrics)?)),
        "codex" => Ok(Arc::new(CliAgentProvider::new(CliAgentType::Codex, metrics)?)),
        "gemini-cli" => Ok(Arc::new(CliAgentProvider::new(CliAgentType::Gemini, metrics)?)),

        _ => Err(Error::Provider(format!("Unknown provider: {}", name))),
    }
}
```

### Configuration File Support

`~/.feroxmute/config.toml`:

```toml
[providers.claude-code]
path = "/usr/local/bin/claude"  # Optional, defaults to "claude"
default_model = "claude-opus-4.5"

[providers.codex]
path = "codex"
default_model = "gpt-5.2"

[providers.gemini-cli]
path = "gemini"
default_model = "gemini-3-pro"
```

## TUI Integration

### Event Flow

Events flow through the existing `EventSender` channel:

```
CLI Agent (via ACP)
    │
    ▼ calls MCP tool
Feroxmute MCP Server
    │
    ├─► docker_shell execution
    │       │
    │       ▼
    │   EventSender::send_tool_call("recon", "docker_shell", "nmap -sV ...")
    │   EventSender::send_tool_output("recon", "<nmap output>")
    │
    ├─► spawn_agent
    │       │
    │       ▼
    │   EventSender::send_status("scanner", AgentStatus::Spawned)
    │
    └─► record_finding
            │
            ▼
        EventSender::send_finding(Finding { ... })
```

### TUI Displays (Unchanged)

- Agent status panel shows orchestrator + specialists
- Tool call/output feed works identically
- Findings panel populates as `record_finding` called
- Memory view (`p` key) shows orchestrator memory

### New TUI Indicators

- Provider badge shows "Claude Code" / "Codex" / "Gemini CLI" instead of "Anthropic" / "OpenAI"
- Could show CLI agent version from ACP `initialize` response

### Token/Cost Tracking

- CLI agents don't report token usage via ACP (usage is on user's subscription)
- `MetricsTracker` shows "N/A" or "Subscription" for cost
- Tool call counts still tracked

## Error Handling

### CLI Agent Not Installed

```rust
pub fn new(agent_type: CliAgentType, metrics: MetricsTracker) -> Result<Self> {
    let path = agent_type.binary_path();
    if !which::which(&path).is_ok() {
        return Err(Error::Provider(format!(
            "{} not found. Install it or specify path with --cli-path",
            agent_type.name()
        )));
    }
    // ...
}
```

### Authentication Required

- ACP returns `AuthRequired` error if CLI agent needs login
- Feroxmute displays: "Claude Code requires authentication. Run `claude login` first."
- Same pattern for Codex (`codex auth`) and Gemini (`gemini auth`)

### CLI Agent Crashes Mid-Session

- ACP connection detects EOF on stdout
- Mark all active sessions as failed
- `EventSender::send_status(agent_name, AgentStatus::Failed)`
- TUI shows error, engagement can be resumed later

### Tool Execution Timeout

- MCP tools inherit feroxmute's existing timeout logic
- `docker_shell` has 10-minute timeout (same as current)
- If CLI agent doesn't respond to tool result, ACP has its own timeout

### Rate Limiting (Gemini CLI Free Tier)

- Gemini CLI: 60 requests/min, 1000/day
- If rate limited, ACP returns error
- Feroxmute can implement backoff/retry at session level

### Session State on Resume

- CLI agents support session persistence (ACP `load_session`)
- When resuming engagement, feroxmute reloads ACP sessions
- Conversation history preserved

## Dependencies

### New Dependencies

```toml
[dependencies]
# ACP client (same crate Zed uses)
agent-client-protocol = { version = "0.9", features = ["unstable"] }
```

### No External MCP Dependency

Minimal hand-rolled MCP server implementation using existing deps (serde_json, tokio).

## Implementation Order

1. **MCP server foundation** - JSON-RPC protocol, tool registry
2. **MCP tool wrappers** - Wrap existing feroxmute tools as MCP tools
3. **ACP client** - Subprocess management, session handling
4. **CliAgentProvider** - Implement `LlmProvider` trait
5. **CLI/config integration** - New flags, factory updates
6. **Testing** - E2E tests with each CLI agent type

## Estimated New Code

| Component | Lines |
|-----------|-------|
| `providers/cli_agent/mod.rs` | ~50 |
| `providers/cli_agent/provider.rs` | ~300 |
| `providers/cli_agent/acp_client.rs` | ~400 |
| `providers/cli_agent/mcp_server.rs` | ~250 |
| `providers/cli_agent/config.rs` | ~100 |
| `mcp/mod.rs` | ~30 |
| `mcp/protocol.rs` | ~150 |
| `mcp/transport.rs` | ~100 |
| **Total** | **~1,400** |

## Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| ACP protocol version mismatch | Pin to 0.9.x, test against latest CLIs |
| CLI agent behavior differences | Integration tests per agent type |
| MCP tool availability per session | Clear tool filtering logic |

## Out of Scope (Future Work)

- A2A protocol for remote agent discovery
- Running feroxmute purely as MCP server mode
- Mixed providers (CLI orchestrator + API specialists)

## References

- [ACP Protocol Spec](https://github.com/agentclientprotocol/agent-client-protocol)
- [ACP Rust SDK](https://crates.io/crates/agent-client-protocol)
- [Zed's agent_servers implementation](https://github.com/zed-industries/zed/tree/main/crates/agent_servers)
- [MCP Protocol](https://modelcontextprotocol.io/)
