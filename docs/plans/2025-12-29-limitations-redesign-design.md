# Limitations Redesign

## Problem

The current engagement limitations system has several issues:

1. **Confusing defaults** - `--scope web|network|full` presets are unclear about what's included
2. **Inverted flags** - `--no-discovery`, `--no-portscan` require users to think in negatives
3. **"Full" doesn't work** - Port scanning appears blocked even with `--scope full`
4. **Command bypass** - `echo|naabu` or `ls && naabu` bypasses checks (only first command checked)
5. **Prompts mention unavailable tools** - LLM gets confused about what it can use

## Solution

Replace the preset-based system with additive capability flags, parse command pipelines properly, and add conditional sections to prompts.

## CLI Flag Changes

### Remove
- `--scope` (confusing preset system)
- `--no-discovery` (inverting the default)
- `--no-portscan` (inverting the default)

### Keep
- `--passive` (minimal passive recon only)
- `--sast-only` (source analysis only)
- `--no-exploit` (disable exploitation)
- `--ports`, `--rate-limit` (constraints)

### Add
- `--discover` - Enable subdomain enumeration and asset discovery
- `--portscan` - Enable port scanning (naabu, nmap)
- `--network` - Enable network-level scanning beyond HTTP

### Default Behavior

Without any flags, these categories are enabled:
- WebCrawl (httpx, katana)
- WebScan (nuclei, feroxbuster, ffuf)
- WebExploit (sqlmap)
- Sast (semgrep, gitleaks, grype)
- Report
- Utility

### Example Usage

```bash
# Default: test given URL thoroughly
feroxmute --target https://app.example.com

# Expand to find subdomains first
feroxmute --target example.com --discover

# Full network pentest
feroxmute --target 10.0.0.0/24 --discover --portscan --network

# Recon only, no exploitation
feroxmute --target example.com --discover --portscan --no-exploit
```

## Command Pipeline Parsing

Update `check_command_allowed()` to parse shell pipelines and check all segments.

```rust
fn extract_commands(input: &str) -> Vec<&str> {
    // Split on shell operators: |, &&, ||, ;
    // For each segment, extract the command (first word after stripping)
    // Handle subshells $(...) and backticks `...`
}

fn check_command_allowed(&self, command: &str) -> Result<(), String> {
    let commands = extract_commands(command);

    for cmd in commands {
        let category = self.tool_registry.categorize(cmd);
        if let Some(cat) = category {
            if !self.limitations.is_allowed(cat) {
                return Err(format!(
                    "Blocked: '{}' requires {:?} which is not allowed",
                    cmd, cat
                ));
            }
        }
    }
    Ok(())
}
```

### Edge Cases

- `echo "test" | naabu` → blocks on `naabu`
- `naabu && echo done` → blocks on `naabu`
- `cat file.txt | grep naabu` → allowed (grep is utility, "naabu" is just text)
- `$(naabu ...)` and backticks → parsed and checked

## Dynamic Prompt Conditionals

Add template processing for `prompts.toml` with `{{#if capability}}...{{/if}}` blocks.

### Template Syntax

```toml
[orchestrator]
system = """
You are the orchestrator agent...

## Available Capabilities

{{#if discover}}
### Discovery
- subfinder: Enumerate subdomains
- dnsx: DNS resolution and bruteforce
- asnmap: ASN and IP range discovery
{{/if}}

{{#if portscan}}
### Port Scanning
- naabu: Fast port scanner
- nmap: Comprehensive port/service detection
{{/if}}

{{#if network}}
### Network Testing
- nmap scripts: Service-specific vulnerability checks
{{/if}}

### Web Testing (always available)
- httpx: HTTP probing
- katana: Web crawling
- nuclei: Vulnerability scanning
- feroxbuster: Directory bruteforce
- sqlmap: SQL injection testing
...
"""
```

### PromptContext

```rust
pub struct PromptContext {
    pub discover: bool,
    pub portscan: bool,
    pub network: bool,
    pub exploit: bool,
}

impl Prompts {
    pub fn render(&self, agent: &str, ctx: &PromptContext) -> String {
        let template = self.get_system_prompt(agent);
        process_conditionals(template, ctx)
    }
}
```

## EngagementLimitations Refactor

Replace category sets with simple bool flags.

```rust
#[derive(Debug, Clone, Default)]
pub struct EngagementLimitations {
    pub discover: bool,      // --discover flag
    pub portscan: bool,      // --portscan flag
    pub network: bool,       // --network flag
    pub exploit: bool,       // true by default, false if --no-exploit
    pub passive: bool,       // --passive (overrides everything)
    pub sast_only: bool,     // --sast-only (overrides everything)
    pub target_ports: Option<Vec<u16>>,
    pub rate_limit: Option<u32>,
}

impl EngagementLimitations {
    pub fn from_args(args: &Args) -> Self {
        Self {
            discover: args.discover,
            portscan: args.portscan,
            network: args.network,
            exploit: !args.no_exploit,
            passive: args.passive,
            sast_only: args.sast_only,
            target_ports: parse_ports(&args.ports),
            rate_limit: args.rate_limit,
        }
    }

    pub fn allowed_categories(&self) -> HashSet<ToolCategory> {
        use ToolCategory::*;
        let mut allowed = HashSet::new();

        // Always allowed
        allowed.insert(Report);
        allowed.insert(Utility);

        if self.sast_only {
            allowed.insert(Sast);
            return allowed;
        }

        if self.passive {
            allowed.insert(AssetDiscovery);
            return allowed;
        }

        // Default: web testing + SAST
        allowed.extend([WebCrawl, WebScan, Sast]);

        if self.exploit {
            allowed.insert(WebExploit);
        }
        if self.discover {
            allowed.extend([SubdomainEnum, AssetDiscovery]);
        }
        if self.portscan {
            allowed.insert(PortScan);
        }
        if self.network {
            allowed.extend([NetworkScan, NetworkExploit]);
        }

        allowed
    }

    pub fn to_prompt_context(&self) -> PromptContext {
        PromptContext {
            discover: self.discover,
            portscan: self.portscan,
            network: self.network,
            exploit: self.exploit,
        }
    }
}
```

## File Changes

| File | Change |
|------|--------|
| `feroxmute-cli/src/args.rs` | Remove `--scope`, `--no-discovery`, `--no-portscan`. Add `--discover`, `--portscan`, `--network` |
| `feroxmute-core/src/limitations.rs` | Refactor to additive bool flags, add `allowed_categories()` method, add `to_prompt_context()` |
| `feroxmute-core/src/tools/shell.rs` | Update `check_command_allowed()` to parse pipelines/chains, check all segments |
| `feroxmute-core/src/prompts.rs` | Add `PromptContext` struct and `process_conditionals()` template function |
| `feroxmute-core/prompts.toml` | Add `{{#if}}...{{/if}}` blocks around tool-specific guidance |
| `feroxmute-cli/src/runner.rs` | Update to use new `EngagementLimitations::from_args()` and pass context to prompt rendering |
| `feroxmute-cli/src/wizard/state.rs` | Update wizard to use new flags instead of scope presets |
| `feroxmute-cli/src/wizard/*.rs` | Update UI text/options for capability selection |
| `feroxmute-core/src/config.rs` | Update config struct to use `discover`, `portscan`, `network` bools instead of `scope` |
| `README.md` | Update usage examples and flag documentation |
| `feroxmute-core/src/limitations.rs` (tests) | Update tests for new flag model |

## Migration Notes

- Users with scripts using `--scope full` need to change to `--discover --portscan --network`
- `--no-discovery` behavior is now the default (no flag needed)
- `--no-portscan` behavior is now the default (no flag needed)
