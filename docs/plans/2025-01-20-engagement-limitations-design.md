# Engagement Limitations Design

## Problem

CLI args like `--scope web`, `--no-portscan`, `--passive` exist but are not passed to agents. The orchestrator and spawned agents have no information about engagement scope restrictions, so they may attempt disallowed actions.

## Solution

Implement defense-in-depth with both prompt-level guidance and code-level enforcement.

## Data Structures

### ToolCategory Enum

```rust
// feroxmute-core/src/limitations.rs

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ToolCategory {
    // Discovery (expands attack surface)
    SubdomainEnum,   // subfinder, dnsx subdomain bruteforce
    PortScan,        // naabu, nmap port discovery
    AssetDiscovery,  // asnmap, certificate transparency

    // Web application (tests given target)
    WebCrawl,        // katana, httpx probing
    WebScan,         // nuclei, feroxbuster, ffuf
    WebExploit,      // sqlmap, XSS validation

    // Network (beyond HTTP)
    NetworkScan,     // nmap service detection, scripts
    NetworkExploit,  // network-level exploitation

    // Code analysis
    Sast,            // semgrep, gitleaks, grype

    // Always allowed
    Report,          // report generation
}
```

### EngagementLimitations Struct

```rust
#[derive(Debug, Clone)]
pub struct EngagementLimitations {
    pub allowed_categories: HashSet<ToolCategory>,
    pub target_ports: Option<Vec<u16>>,   // None = any port allowed
    pub rate_limit: Option<u32>,          // requests per second
}
```

### ToolRegistry

Maps command names to categories:

```rust
pub struct ToolRegistry {
    tools: HashMap<&'static str, ToolCategory>,
}

impl ToolRegistry {
    pub fn new() -> Self {
        let mut tools = HashMap::new();

        // Discovery
        tools.insert("subfinder", ToolCategory::SubdomainEnum);
        tools.insert("dnsx", ToolCategory::SubdomainEnum);
        tools.insert("asnmap", ToolCategory::AssetDiscovery);
        tools.insert("tlsx", ToolCategory::AssetDiscovery);

        // Port scanning
        tools.insert("naabu", ToolCategory::PortScan);
        tools.insert("nmap", ToolCategory::PortScan);

        // Web application
        tools.insert("httpx", ToolCategory::WebCrawl);
        tools.insert("katana", ToolCategory::WebCrawl);
        tools.insert("nuclei", ToolCategory::WebScan);
        tools.insert("feroxbuster", ToolCategory::WebScan);
        tools.insert("ffuf", ToolCategory::WebScan);
        tools.insert("sqlmap", ToolCategory::WebExploit);

        // SAST
        tools.insert("semgrep", ToolCategory::Sast);
        tools.insert("gitleaks", ToolCategory::Sast);
        tools.insert("grype", ToolCategory::Sast);
        tools.insert("ast-grep", ToolCategory::Sast);

        Self { tools }
    }

    pub fn categorize(&self, command: &str) -> Option<ToolCategory> {
        let cmd = command.split_whitespace().next()?;
        self.tools.get(cmd).copied()
    }
}
```

## CLI Args to Limitations

### New CLI Flag

Add `--no-discovery` flag to `args.rs`:

```rust
/// Skip subdomain enumeration and asset discovery (webapp-only testing)
#[arg(long)]
pub no_discovery: bool,
```

### Derivation Logic

```rust
impl EngagementLimitations {
    pub fn from_args(args: &Args) -> Self {
        use ToolCategory::*;
        let mut allowed: HashSet<ToolCategory> = HashSet::new();

        // Handle --sast-only first (overrides scope)
        if args.sast_only {
            allowed.insert(Sast);
            allowed.insert(Report);
            return Self {
                allowed_categories: allowed,
                target_ports: None,
                rate_limit: args.rate_limit,
            };
        }

        // Handle --passive (minimal set)
        if args.passive {
            allowed.extend([AssetDiscovery, Report]);
            return Self {
                allowed_categories: allowed,
                target_ports: None,
                rate_limit: args.rate_limit,
            };
        }

        // Base scope
        match args.scope.as_str() {
            "web" => {
                allowed.extend([WebCrawl, WebScan, WebExploit, Report]);
                if !args.no_discovery {
                    allowed.extend([SubdomainEnum, AssetDiscovery]);
                }
            }
            "network" => {
                allowed.extend([WebCrawl, WebScan, WebExploit, Report]);
                allowed.extend([PortScan, NetworkScan]);
                if !args.no_discovery {
                    allowed.extend([SubdomainEnum, AssetDiscovery]);
                }
            }
            "full" => {
                allowed.extend([
                    SubdomainEnum, PortScan, AssetDiscovery,
                    WebCrawl, WebScan, WebExploit,
                    NetworkScan, NetworkExploit,
                    Sast, Report
                ]);
            }
            _ => {
                // Default to web
                allowed.extend([WebCrawl, WebScan, Report]);
            }
        }

        // Subtractive flags
        if args.no_portscan {
            allowed.remove(&PortScan);
        }
        if args.no_exploit {
            allowed.remove(&WebExploit);
            allowed.remove(&NetworkExploit);
        }

        // Parse target ports
        let target_ports = args.ports.as_ref().map(|p| {
            p.split(',')
                .filter_map(|s| s.trim().parse().ok())
                .collect()
        });

        Self {
            allowed_categories: allowed,
            target_ports,
            rate_limit: args.rate_limit,
        }
    }
}
```

## Prompt-Level Guidance

Generate a limitations section for agent prompts:

```rust
impl EngagementLimitations {
    pub fn to_prompt_section(&self) -> String {
        use ToolCategory::*;
        let mut lines = vec!["## Engagement Limitations".to_string()];

        if !self.allowed_categories.contains(&SubdomainEnum)
           && !self.allowed_categories.contains(&AssetDiscovery) {
            lines.push("- NO subdomain enumeration or asset discovery - test only the specified target".into());
        }
        if !self.allowed_categories.contains(&PortScan) {
            lines.push("- NO port scanning - target ports are already known".into());
        }
        if !self.allowed_categories.contains(&WebExploit)
           && !self.allowed_categories.contains(&NetworkExploit) {
            lines.push("- NO exploitation - reconnaissance and scanning only".into());
        }
        if !self.allowed_categories.contains(&NetworkScan) {
            lines.push("- Web application testing only - no network-level scanning".into());
        }
        if let Some(ports) = &self.target_ports {
            lines.push(format!("- Restrict testing to ports: {:?}", ports));
        }
        if let Some(rate) = self.rate_limit {
            lines.push(format!("- Rate limit: {} requests/second maximum", rate));
        }

        if lines.len() == 1 {
            lines.push("- No restrictions - full scope authorized".into());
        }

        lines.push("\nCommands violating these limitations will be blocked.".into());
        lines.join("\n")
    }
}
```

## Code-Level Enforcement

### SpawnAgentTool Enforcement

Block spawning agents that have no allowed capabilities:

```rust
fn agent_required_categories(agent_type: &str) -> Vec<ToolCategory> {
    use ToolCategory::*;
    match agent_type {
        "recon" => vec![SubdomainEnum, AssetDiscovery, PortScan, WebCrawl],
        "scanner" => vec![WebScan, NetworkScan],
        "exploit" => vec![WebExploit, NetworkExploit],
        "sast" => vec![Sast],
        "report" => vec![Report],
        _ => vec![]
    }
}

// In SpawnAgentTool::call()
let required = agent_required_categories(&args.agent_type);
let has_any_allowed = required.iter()
    .any(|c| self.context.limitations.allowed_categories.contains(c));

if !has_any_allowed {
    let msg = format!(
        "Cannot spawn '{}' agent: no allowed capabilities for current engagement scope",
        args.agent_type
    );
    self.context.events.send_feed("orchestrator", &msg, true);
    return Ok(SpawnAgentOutput {
        success: false,
        message: msg,
    });
}
```

### DockerShellTool Enforcement

Block commands in disallowed categories:

```rust
fn check_command_allowed(&self, command: &str) -> Result<(), String> {
    let category = self.tool_registry.categorize(command);

    match category {
        Some(cat) if !self.limitations.allowed_categories.contains(&cat) => {
            let tool = command.split_whitespace().next().unwrap_or("unknown");
            let msg = format!(
                "Blocked: '{}' requires {:?} which is not allowed in current scope",
                tool, cat
            );
            self.events.send_feed(&self.agent_name, &msg, true);
            Err(msg)
        }
        None => {
            // Unknown command - allow with warning
            let tool = command.split_whitespace().next().unwrap_or("unknown");
            self.events.send_feed(
                &self.agent_name,
                &format!("Warning: unrecognized command '{}' - allowing", tool),
                false
            );
            Ok(())
        }
        Some(_) => Ok(())
    }
}
```

## Integration Points

### OrchestratorContext Changes

```rust
pub struct OrchestratorContext {
    pub registry: Arc<Mutex<AgentRegistry>>,
    pub provider: Arc<dyn LlmProvider>,
    pub container: Arc<ContainerManager>,
    pub events: Arc<dyn EventSender>,
    pub cancel: CancellationToken,
    pub prompts: Prompts,
    pub target: String,
    pub findings: Arc<Mutex<Vec<String>>>,
    pub limitations: Arc<EngagementLimitations>,  // NEW
}
```

### Runner Changes

Build limitations from args and pass to context:

```rust
// In run_orchestrator_with_tools()
let limitations = Arc::new(EngagementLimitations::from_args(&args));

let context = Arc::new(OrchestratorContext {
    // ... existing fields
    limitations: Arc::clone(&limitations),
});

// Include limitations in user prompt
let user_prompt = format!(
    "Target: {}\n{}\n\nEngagement Task: Perform security assessment...",
    target,
    limitations.to_prompt_section()
);
```

### DockerShellTool Changes

Add limitations and tool registry:

```rust
pub struct DockerShellTool {
    container: Arc<ContainerManager>,
    events: Arc<dyn EventSender>,
    agent_name: String,
    limitations: Arc<EngagementLimitations>,  // NEW
    tool_registry: ToolRegistry,               // NEW
}
```

## File Changes Summary

| File | Change |
|------|--------|
| `feroxmute-core/src/limitations.rs` | NEW - ToolCategory, EngagementLimitations, ToolRegistry |
| `feroxmute-core/src/lib.rs` | Add `pub mod limitations` |
| `feroxmute-cli/src/args.rs` | Add `--no-discovery` flag |
| `feroxmute-cli/src/runner.rs` | Build limitations from args, pass to context, include in prompt |
| `feroxmute-core/src/tools/orchestrator.rs` | Add limitations to OrchestratorContext, enforce in SpawnAgentTool |
| `feroxmute-core/src/tools/shell.rs` | Add limitations + registry, enforce before execution |

## Example Usage

```bash
# Web app only - no discovery, no port scan
feroxmute --target https://app.example.com --scope web --no-discovery

# Passive recon only
feroxmute --target example.com --passive

# Full network pentest, no exploitation
feroxmute --target 10.0.0.0/24 --scope network --no-exploit

# SAST only on source code
feroxmute --target ./src --sast-only
```
