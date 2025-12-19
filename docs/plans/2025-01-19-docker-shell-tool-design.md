# Docker Shell Tool Design

## Overview

Replace the current broken tool-calling implementation with a single `shell` tool that gives LLM agents direct command execution in the Kali Linux container. Rig handles the tool-calling loop.

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   LLM Provider  │────▶│  DockerShellTool │────▶│  Kali Container │
│   (via rig)     │◀────│  (rig::Tool)     │◀────│                 │
└─────────────────┘     └──────────────────┘     └─────────────────┘
```

## Components

### 1. DockerShellTool

Implements `rig::tool::Tool` trait:

```rust
struct DockerShellTool {
    container: Arc<ContainerManager>,
}

#[derive(Deserialize)]
struct ShellArgs {
    command: String,
}

#[derive(Serialize)]
struct ShellOutput {
    output: String,    // stdout + stderr combined
    exit_code: i64,
}

impl Tool for DockerShellTool {
    const NAME: &'static str = "shell";
    type Args = ShellArgs;
    type Output = ShellOutput;
    type Error = ShellError;

    async fn definition(&self, _prompt: &str) -> ToolDefinition {
        ToolDefinition {
            name: "shell".to_string(),
            description: "Execute a shell command in a Kali Linux container. Returns combined stdout/stderr and exit code.".to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "Shell command to execute (e.g., 'subfinder -d example.com -json')"
                    }
                },
                "required": ["command"]
            }),
        }
    }

    async fn call(&self, args: Self::Args) -> Result<Self::Output, Self::Error> {
        // Wrap command to capture both stdout and stderr
        let wrapped = format!("{} 2>&1", args.command);
        let result = self.container.exec(vec!["sh", "-c", &wrapped], None).await?;
        Ok(ShellOutput {
            output: result.output(),
            exit_code: result.exit_code,
        })
    }
}
```

### 2. Provider Simplification

Remove manual tool-call parsing from providers. Use rig's agent with tools:

```rust
let agent = client
    .agent(&model)
    .preamble(system_prompt)
    .tool(DockerShellTool::new(container))
    .build();

// Single call - rig handles the tool loop
let result = agent.prompt(&task).await?;
```

### 3. System Prompt

Rich prompt listing available tools with few-shot example:

```
You are a penetration testing agent with shell access to a Kali Linux container.

## Available Security Tools

### Reconnaissance
- subfinder: Subdomain enumeration
  Example: subfinder -d example.com -json
- naabu: Fast port scanner
  Example: naabu -host example.com -json -top-ports 1000
- httpx: HTTP probing and technology detection
  Example: httpx -l urls.txt -json -td -sc -cl
- dnsx: DNS resolution and bruteforcing
  Example: dnsx -d example.com -json

### Scanning
- nuclei: Vulnerability scanner with templates
  Example: nuclei -u https://example.com -json
- nmap: Network scanner
  Example: nmap -sV -sC example.com

### Web Testing
- feroxbuster: Directory bruteforcing
  Example: feroxbuster -u https://example.com -o results.json --json
- ffuf: Fuzzing
  Example: ffuf -u https://example.com/FUZZ -w wordlist.txt -o results.json -of json
- sqlmap: SQL injection testing
  Example: sqlmap -u "https://example.com/?id=1" --batch

### Python Scripting
Python 3 is available. You can:
- Run inline: python3 -c "print('hello')"
- Write scripts: echo 'code' > /feroxmute/scripts/script.py && python3 /feroxmute/scripts/script.py
- Install packages: uv pip install --system requests

### Working Directories
- /feroxmute/workdir/ - Temporary files
- /feroxmute/scripts/ - Custom scripts
- /feroxmute/artifacts/ - Downloaded files, evidence

## Guidelines
1. Use -json flags when available for structured output
2. Chain tools based on findings (subdomains → ports → http probe → scan)
3. Save important findings to files
4. If a command fails (non-zero exit), read the error and adjust
5. When done, summarize findings clearly

## Example Workflow

User: Perform reconnaissance on example.com

Assistant: I'll start by enumerating subdomains for example.com.
[Calls shell: subfinder -d example.com -json]

Tool output: {"host":"api.example.com"}
{"host":"www.example.com"}
{"host":"mail.example.com"}
(exit_code: 0)

Assistant: Found 3 subdomains. Now I'll probe them for HTTP services.
[Calls shell: echo "api.example.com\nwww.example.com\nmail.example.com" | httpx -json]

Tool output: {"url":"https://www.example.com","status_code":200,"tech":["nginx"]}
{"url":"https://api.example.com","status_code":200,"tech":["nginx","express"]}
(exit_code: 0)

Assistant: Found 2 live HTTP services. Now scanning for vulnerabilities...
[Calls shell: nuclei -l /feroxmute/workdir/urls.txt -json]

...continues until complete...
```

## Files to Modify

1. **New**: `feroxmute-core/src/tools/shell.rs` - DockerShellTool implementation
2. **Modify**: `feroxmute-core/src/tools/mod.rs` - Export new module
3. **Modify**: `feroxmute-core/src/providers/openai.rs` - Use rig agent with tool
4. **Modify**: `feroxmute-core/src/providers/anthropic.rs` - Same changes
5. **Modify**: `feroxmute-core/src/agents/recon.rs` - Simplify to single agent.prompt() call
6. **Modify**: `feroxmute-core/prompts.toml` - Update system prompts with tool list

## Data Flow

1. User runs: `feroxmute --target example.com`
2. ReconAgent created with system prompt listing tools
3. Agent calls `rig_agent.prompt("Perform reconnaissance on example.com")`
4. Rig sends request to LLM with shell tool definition
5. LLM responds with tool call: `shell({ "command": "subfinder -d example.com -json" })`
6. Rig invokes `DockerShellTool::call()` -> runs in container -> returns output
7. Rig sends output back to LLM
8. LLM analyzes, decides next action (more tools or summarize)
9. Loop continues until LLM returns final text response
10. Agent returns findings to TUI

## Error Handling

- Command timeout: 5 minutes default, configurable
- Non-zero exit: Include stderr in output, let LLM decide how to proceed
- Container not running: Return error, agent should fail gracefully

## Security Considerations

- Container is isolated from host
- No network restrictions within container (intentional for pentesting)
- Prompt injection risk: LLM could be tricked into running unintended commands
  - Mitigation: Container has no host access, disposable environment
