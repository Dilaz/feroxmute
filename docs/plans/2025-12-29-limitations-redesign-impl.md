# Limitations Redesign Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace confusing scope presets with additive capability flags, fix command bypass via pipes, and add conditional prompt sections.

**Architecture:** Refactor `EngagementLimitations` to store bool flags directly. Add pipeline parser to `DockerShellTool`. Add template processor to `Prompts` for `{{#if}}` conditionals.

**Tech Stack:** Rust, TOML, regex for command parsing

---

## Task 1: Update CLI Args

**Files:**
- Modify: `feroxmute-cli/src/args.rs`

**Step 1: Remove old flags and add new ones**

Replace the scope-based flags with additive capability flags:

```rust
//! CLI argument parsing

use clap::{ArgAction, Parser};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "feroxmute")]
#[command(author, version, about = "LLM-powered penetration testing framework")]
pub struct Args {
    /// Target domains, IPs, directories, or git URLs (can be repeated)
    #[arg(long, action = ArgAction::Append)]
    pub target: Vec<String>,

    /// Explicit source directory for the primary target
    #[arg(long)]
    pub source: Option<PathBuf>,

    /// Treat all targets as separate engagements (skip relationship detection)
    #[arg(long)]
    pub separate: bool,

    /// Run static analysis only (no web testing)
    #[arg(long)]
    pub sast_only: bool,

    /// Path to configuration file
    #[arg(short, long)]
    pub config: Option<PathBuf>,

    /// Interactive setup wizard
    #[arg(long)]
    pub wizard: bool,

    /// Resume a previous session
    #[arg(long)]
    pub resume: Option<PathBuf>,

    /// List available sessions
    #[arg(long)]
    pub list_sessions: bool,

    /// Enable subdomain enumeration and asset discovery
    #[arg(long)]
    pub discover: bool,

    /// Enable port scanning (naabu, nmap)
    #[arg(long)]
    pub portscan: bool,

    /// Enable network-level scanning beyond HTTP
    #[arg(long)]
    pub network: bool,

    /// Recon and scan only, no exploitation
    #[arg(long)]
    pub no_exploit: bool,

    /// Passive recon only
    #[arg(long)]
    pub passive: bool,

    /// Limit port range (comma-separated)
    #[arg(long)]
    pub ports: Option<String>,

    /// Max requests per second
    #[arg(long)]
    pub rate_limit: Option<u32>,

    /// LLM provider (anthropic, openai, litellm)
    #[arg(long)]
    pub provider: Option<String>,

    /// Model to use
    #[arg(long)]
    pub model: Option<String>,

    /// Output directory for session
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Export HTML report
    #[arg(long)]
    pub html: bool,

    /// Export PDF report
    #[arg(long)]
    pub pdf: bool,

    /// Verbose output
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Custom instruction to guide the engagement (supplements default behavior)
    #[arg(long)]
    pub instruction: Option<String>,
}
```

**Step 2: Build and verify compilation**

Run: `cargo build -p feroxmute-cli 2>&1 | head -50`
Expected: Compilation errors in main.rs (references to removed fields)

**Step 3: Commit args changes**

```bash
git add feroxmute-cli/src/args.rs
git commit -m "$(cat <<'EOF'
refactor(cli): replace scope presets with additive capability flags

Remove --scope, --no-discovery, --no-portscan flags.
Add --discover, --portscan, --network flags.

BREAKING: Users must migrate from --scope full to --discover --portscan --network
EOF
)"
```

---

## Task 2: Refactor EngagementLimitations

**Files:**
- Modify: `feroxmute-core/src/limitations.rs`

**Step 1: Replace struct with bool flags**

```rust
//! Engagement scope limitations and tool categorization

use std::collections::{HashMap, HashSet};

/// Categories of security tools for scope enforcement
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ToolCategory {
    /// Subdomain enumeration (subfinder, dnsx)
    SubdomainEnum,
    /// Port scanning (naabu, nmap port discovery)
    PortScan,
    /// Asset discovery (asnmap, certificate transparency)
    AssetDiscovery,
    /// Web crawling and probing (katana, httpx)
    WebCrawl,
    /// Web vulnerability scanning (nuclei, feroxbuster, ffuf)
    WebScan,
    /// Web exploitation (sqlmap, XSS validation)
    WebExploit,
    /// Network scanning beyond HTTP (nmap service detection)
    NetworkScan,
    /// Network exploitation
    NetworkExploit,
    /// Static analysis (semgrep, gitleaks, grype)
    Sast,
    /// Report generation (always allowed)
    Report,
    /// Basic shell utilities (always allowed)
    Utility,
}

/// Registry mapping tool command names to categories
pub struct ToolRegistry {
    tools: HashMap<&'static str, ToolCategory>,
}

impl Default for ToolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ToolRegistry {
    /// Create a new registry with known security tools
    pub fn new() -> Self {
        use ToolCategory::*;
        let mut tools = HashMap::new();

        // Discovery - subdomain enumeration
        tools.insert("subfinder", SubdomainEnum);
        tools.insert("dnsx", SubdomainEnum);

        // Discovery - asset discovery
        tools.insert("asnmap", AssetDiscovery);
        tools.insert("tlsx", AssetDiscovery);

        // Port scanning
        tools.insert("naabu", PortScan);
        tools.insert("nmap", PortScan);

        // Web crawling
        tools.insert("httpx", WebCrawl);
        tools.insert("katana", WebCrawl);

        // Web scanning
        tools.insert("nuclei", WebScan);
        tools.insert("feroxbuster", WebScan);
        tools.insert("ffuf", WebScan);

        // Web exploitation
        tools.insert("sqlmap", WebExploit);

        // SAST
        tools.insert("semgrep", Sast);
        tools.insert("gitleaks", Sast);
        tools.insert("grype", Sast);
        tools.insert("ast-grep", Sast);

        // Basic shell utilities (always allowed)
        tools.insert("curl", Utility);
        tools.insert("wget", Utility);
        tools.insert("ls", Utility);
        tools.insert("cat", Utility);
        tools.insert("find", Utility);
        tools.insert("grep", Utility);
        tools.insert("head", Utility);
        tools.insert("tail", Utility);
        tools.insert("wc", Utility);
        tools.insert("sort", Utility);
        tools.insert("uniq", Utility);
        tools.insert("cut", Utility);
        tools.insert("awk", Utility);
        tools.insert("sed", Utility);
        tools.insert("echo", Utility);
        tools.insert("pwd", Utility);
        tools.insert("cd", Utility);
        tools.insert("mkdir", Utility);
        tools.insert("rm", Utility);
        tools.insert("cp", Utility);
        tools.insert("mv", Utility);
        tools.insert("touch", Utility);
        tools.insert("file", Utility);
        tools.insert("which", Utility);
        tools.insert("whoami", Utility);
        tools.insert("id", Utility);
        tools.insert("env", Utility);
        tools.insert("export", Utility);
        tools.insert("jq", Utility);
        tools.insert("tr", Utility);
        tools.insert("xargs", Utility);
        tools.insert("tee", Utility);
        tools.insert("base64", Utility);
        tools.insert("xxd", Utility);
        tools.insert("strings", Utility);
        tools.insert("diff", Utility);
        tools.insert("tar", Utility);
        tools.insert("unzip", Utility);
        tools.insert("gzip", Utility);
        tools.insert("gunzip", Utility);

        Self { tools }
    }

    /// Categorize a command by its tool name
    pub fn categorize(&self, command: &str) -> Option<ToolCategory> {
        let cmd = command.split_whitespace().next()?;
        self.tools.get(cmd).copied()
    }
}

/// Context for prompt template rendering
#[derive(Debug, Clone, Default)]
pub struct PromptContext {
    pub discover: bool,
    pub portscan: bool,
    pub network: bool,
    pub exploit: bool,
}

/// Engagement scope limitations derived from CLI args
#[derive(Debug, Clone, Default)]
pub struct EngagementLimitations {
    /// Enable subdomain enumeration and asset discovery
    pub discover: bool,
    /// Enable port scanning
    pub portscan: bool,
    /// Enable network-level scanning
    pub network: bool,
    /// Enable exploitation (true by default)
    pub exploit: bool,
    /// Passive recon only (overrides other flags)
    pub passive: bool,
    /// SAST only mode (overrides other flags)
    pub sast_only: bool,
    /// Restrict testing to specific ports
    pub target_ports: Option<Vec<u16>>,
    /// Maximum requests per second
    pub rate_limit: Option<u32>,
}

impl EngagementLimitations {
    /// Create new limitations with sensible defaults
    pub fn new() -> Self {
        Self {
            exploit: true, // Exploitation enabled by default
            ..Default::default()
        }
    }

    /// Create limitations for SAST only mode
    pub fn for_sast_only() -> Self {
        Self {
            sast_only: true,
            ..Default::default()
        }
    }

    /// Create limitations for passive mode
    pub fn for_passive() -> Self {
        Self {
            passive: true,
            ..Default::default()
        }
    }

    /// Build from CLI flags
    pub fn from_flags(
        discover: bool,
        portscan: bool,
        network: bool,
        no_exploit: bool,
        passive: bool,
        sast_only: bool,
    ) -> Self {
        Self {
            discover,
            portscan,
            network,
            exploit: !no_exploit,
            passive,
            sast_only,
            target_ports: None,
            rate_limit: None,
        }
    }

    /// Set target ports restriction
    pub fn with_ports(mut self, ports: Vec<u16>) -> Self {
        self.target_ports = Some(ports);
        self
    }

    /// Set rate limit
    pub fn with_rate_limit(mut self, rate: u32) -> Self {
        self.rate_limit = Some(rate);
        self
    }

    /// Get the set of allowed tool categories
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

    /// Check if a tool category is allowed
    pub fn is_allowed(&self, category: ToolCategory) -> bool {
        self.allowed_categories().contains(&category)
    }

    /// Convert to prompt context for template rendering
    pub fn to_prompt_context(&self) -> PromptContext {
        PromptContext {
            discover: self.discover,
            portscan: self.portscan,
            network: self.network,
            exploit: self.exploit,
        }
    }

    /// Generate a prompt section describing limitations for LLM awareness
    pub fn to_prompt_section(&self) -> String {
        use ToolCategory::*;
        let allowed = self.allowed_categories();
        let mut lines = vec!["## Engagement Limitations".to_string()];

        if !allowed.contains(&SubdomainEnum) && !allowed.contains(&AssetDiscovery) {
            lines.push(
                "- NO subdomain enumeration or asset discovery - test only the specified target"
                    .into(),
            );
        }
        if !allowed.contains(&PortScan) {
            lines.push("- NO port scanning - target ports are already known".into());
        }
        if !allowed.contains(&WebExploit) && !allowed.contains(&NetworkExploit) {
            lines.push("- NO exploitation - reconnaissance and scanning only".into());
        }
        if !allowed.contains(&NetworkScan) {
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn test_default_allows_web_testing() {
        let limits = EngagementLimitations::new();
        assert!(limits.is_allowed(ToolCategory::WebCrawl));
        assert!(limits.is_allowed(ToolCategory::WebScan));
        assert!(limits.is_allowed(ToolCategory::WebExploit));
        assert!(limits.is_allowed(ToolCategory::Sast));
        assert!(limits.is_allowed(ToolCategory::Report));
        assert!(limits.is_allowed(ToolCategory::Utility));
    }

    #[test]
    fn test_default_blocks_discovery_and_portscan() {
        let limits = EngagementLimitations::new();
        assert!(!limits.is_allowed(ToolCategory::SubdomainEnum));
        assert!(!limits.is_allowed(ToolCategory::AssetDiscovery));
        assert!(!limits.is_allowed(ToolCategory::PortScan));
        assert!(!limits.is_allowed(ToolCategory::NetworkScan));
    }

    #[test]
    fn test_discover_flag_enables_discovery() {
        let limits = EngagementLimitations {
            discover: true,
            exploit: true,
            ..Default::default()
        };
        assert!(limits.is_allowed(ToolCategory::SubdomainEnum));
        assert!(limits.is_allowed(ToolCategory::AssetDiscovery));
    }

    #[test]
    fn test_portscan_flag_enables_portscan() {
        let limits = EngagementLimitations {
            portscan: true,
            exploit: true,
            ..Default::default()
        };
        assert!(limits.is_allowed(ToolCategory::PortScan));
    }

    #[test]
    fn test_network_flag_enables_network_testing() {
        let limits = EngagementLimitations {
            network: true,
            exploit: true,
            ..Default::default()
        };
        assert!(limits.is_allowed(ToolCategory::NetworkScan));
        assert!(limits.is_allowed(ToolCategory::NetworkExploit));
    }

    #[test]
    fn test_no_exploit_disables_exploitation() {
        let limits = EngagementLimitations {
            exploit: false,
            ..Default::default()
        };
        assert!(!limits.is_allowed(ToolCategory::WebExploit));
    }

    #[test]
    fn test_sast_only_mode() {
        let limits = EngagementLimitations::for_sast_only();
        assert!(limits.is_allowed(ToolCategory::Sast));
        assert!(limits.is_allowed(ToolCategory::Report));
        assert!(limits.is_allowed(ToolCategory::Utility));
        assert!(!limits.is_allowed(ToolCategory::WebScan));
        assert!(!limits.is_allowed(ToolCategory::PortScan));
    }

    #[test]
    fn test_passive_mode() {
        let limits = EngagementLimitations::for_passive();
        assert!(limits.is_allowed(ToolCategory::AssetDiscovery));
        assert!(limits.is_allowed(ToolCategory::Report));
        assert!(!limits.is_allowed(ToolCategory::WebScan));
        assert!(!limits.is_allowed(ToolCategory::PortScan));
    }

    #[test]
    fn test_from_flags() {
        let limits = EngagementLimitations::from_flags(
            true,  // discover
            true,  // portscan
            true,  // network
            false, // no_exploit
            false, // passive
            false, // sast_only
        );
        assert!(limits.is_allowed(ToolCategory::SubdomainEnum));
        assert!(limits.is_allowed(ToolCategory::PortScan));
        assert!(limits.is_allowed(ToolCategory::NetworkScan));
        assert!(limits.is_allowed(ToolCategory::WebExploit));
    }

    #[test]
    fn test_tool_registry_known_tools() {
        let registry = ToolRegistry::new();
        assert_eq!(
            registry.categorize("subfinder -d example.com"),
            Some(ToolCategory::SubdomainEnum)
        );
        assert_eq!(
            registry.categorize("naabu -host example.com"),
            Some(ToolCategory::PortScan)
        );
        assert_eq!(
            registry.categorize("nuclei -u https://example.com"),
            Some(ToolCategory::WebScan)
        );
    }

    #[test]
    fn test_prompt_section_default() {
        let limits = EngagementLimitations::new();
        let section = limits.to_prompt_section();
        assert!(section.contains("NO subdomain enumeration"));
        assert!(section.contains("NO port scanning"));
        assert!(section.contains("no network-level scanning"));
    }

    #[test]
    fn test_prompt_section_full_access() {
        let limits = EngagementLimitations {
            discover: true,
            portscan: true,
            network: true,
            exploit: true,
            ..Default::default()
        };
        let section = limits.to_prompt_section();
        assert!(section.contains("No restrictions"));
    }
}
```

**Step 2: Run tests**

Run: `cargo test -p feroxmute-core limitations`
Expected: All tests pass

**Step 3: Commit**

```bash
git add feroxmute-core/src/limitations.rs
git commit -m "$(cat <<'EOF'
refactor(core): simplify EngagementLimitations to use bool flags

Replace scope-based constructors with direct bool flags.
Add from_flags() builder and allowed_categories() method.
Update tests for new flag-based model.
EOF
)"
```

---

## Task 3: Add Command Pipeline Parser

**Files:**
- Modify: `feroxmute-core/src/tools/shell.rs`

**Step 1: Add extract_commands function and update check**

Add after the `prepare_output` function (around line 226):

```rust
/// Extract all command names from a shell command string
/// Handles pipes (|), AND (&&), OR (||), semicolons (;), and subshells ($(...))
fn extract_commands(input: &str) -> Vec<&str> {
    let mut commands = Vec::new();

    // Split on shell operators
    // This regex-free approach handles: |, &&, ||, ;
    let mut remaining = input;

    while !remaining.is_empty() {
        // Find the next operator
        let mut split_pos = remaining.len();
        let mut skip_len = 0;

        for (i, _) in remaining.char_indices() {
            let rest = &remaining[i..];
            if rest.starts_with("&&") || rest.starts_with("||") {
                split_pos = i;
                skip_len = 2;
                break;
            } else if rest.starts_with('|') || rest.starts_with(';') {
                split_pos = i;
                skip_len = 1;
                break;
            }
        }

        let segment = &remaining[..split_pos];

        // Extract command name from segment (first word after stripping)
        let trimmed = segment.trim();
        if let Some(cmd) = trimmed.split_whitespace().next() {
            // Handle subshells: $(cmd ...) or `cmd ...`
            let cmd = cmd.trim_start_matches("$(").trim_start_matches('`');
            if !cmd.is_empty() {
                commands.push(cmd);
            }
        }

        // Move past the operator
        if split_pos + skip_len >= remaining.len() {
            break;
        }
        remaining = &remaining[split_pos + skip_len..];
    }

    // Also check for commands in $(...) subshells
    let mut search_pos = 0;
    while let Some(start) = input[search_pos..].find("$(") {
        let abs_start = search_pos + start + 2;
        if let Some(end) = input[abs_start..].find(')') {
            let subshell_content = &input[abs_start..abs_start + end];
            // Recursively extract from subshell
            for cmd in extract_commands(subshell_content) {
                if !commands.contains(&cmd) {
                    commands.push(cmd);
                }
            }
            search_pos = abs_start + end + 1;
        } else {
            break;
        }
    }

    commands
}
```

**Step 2: Update check_command_allowed method**

Replace the existing `check_command_allowed` method:

```rust
impl DockerShellTool {
    /// Check if a command is allowed by engagement limitations
    fn check_command_allowed(&self, command: &str) -> Result<(), String> {
        let commands = extract_commands(command);
        let allowed = self.limitations.allowed_categories();

        for cmd in commands {
            if let Some(category) = self.tool_registry.categorize(cmd) {
                if !allowed.contains(&category) {
                    let msg = format!(
                        "Blocked: '{}' requires {:?} which is not allowed in current scope",
                        cmd, category
                    );
                    self.events.send_feed(&self.agent_name, &msg, true);
                    return Err(msg);
                }
            }
            // Unknown commands are allowed (with no warning - too noisy)
        }

        Ok(())
    }

    // ... rest of impl
}
```

**Step 3: Add tests for pipeline parsing**

Add at the end of the file:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_single_command() {
        let cmds = extract_commands("naabu -host example.com");
        assert_eq!(cmds, vec!["naabu"]);
    }

    #[test]
    fn test_extract_pipe_commands() {
        let cmds = extract_commands("echo test | naabu -host example.com");
        assert_eq!(cmds, vec!["echo", "naabu"]);
    }

    #[test]
    fn test_extract_and_chain() {
        let cmds = extract_commands("ls && naabu -host example.com && echo done");
        assert_eq!(cmds, vec!["ls", "naabu", "echo"]);
    }

    #[test]
    fn test_extract_or_chain() {
        let cmds = extract_commands("naabu || subfinder -d example.com");
        assert_eq!(cmds, vec!["naabu", "subfinder"]);
    }

    #[test]
    fn test_extract_semicolon() {
        let cmds = extract_commands("echo start; naabu; echo end");
        assert_eq!(cmds, vec!["echo", "naabu", "echo"]);
    }

    #[test]
    fn test_extract_subshell() {
        let cmds = extract_commands("echo $(naabu -host test)");
        assert!(cmds.contains(&"naabu"));
    }

    #[test]
    fn test_extract_mixed_operators() {
        let cmds = extract_commands("cat file | grep x && naabu || subfinder; echo done");
        assert!(cmds.contains(&"cat"));
        assert!(cmds.contains(&"grep"));
        assert!(cmds.contains(&"naabu"));
        assert!(cmds.contains(&"subfinder"));
        assert!(cmds.contains(&"echo"));
    }
}
```

**Step 4: Run tests**

Run: `cargo test -p feroxmute-core shell::tests`
Expected: All tests pass

**Step 5: Commit**

```bash
git add feroxmute-core/src/tools/shell.rs
git commit -m "$(cat <<'EOF'
fix(shell): parse command pipelines to prevent tool bypass

Previously only the first command was checked, allowing bypasses like:
  echo test | naabu target
  ls && naabu target

Now all commands in pipes, chains, and subshells are checked.
EOF
)"
```

---

## Task 4: Update main.rs Limitations Construction

**Files:**
- Modify: `feroxmute-cli/src/main.rs`

**Step 1: Update limitations construction**

Find the section that builds limitations (around line 561) and replace:

```rust
        // Build engagement limitations from CLI args
        let limitations = Arc::new(if args.sast_only {
            EngagementLimitations::for_sast_only()
        } else if args.passive {
            EngagementLimitations::for_passive()
        } else {
            let mut limits = EngagementLimitations::from_flags(
                args.discover,
                args.portscan,
                args.network,
                args.no_exploit,
                false, // passive handled above
                false, // sast_only handled above
            );

            // Apply port restrictions if specified
            if let Some(ref ports_str) = args.ports {
                let ports: Vec<u16> = ports_str
                    .split(',')
                    .filter_map(|s| s.trim().parse().ok())
                    .collect();
                if !ports.is_empty() {
                    limits = limits.with_ports(ports);
                }
            }

            // Apply rate limit if specified
            if let Some(rate) = args.rate_limit {
                limits = limits.with_rate_limit(rate);
            }

            limits
        });
```

**Step 2: Build and verify**

Run: `cargo build -p feroxmute-cli`
Expected: Successful build

**Step 3: Commit**

```bash
git add feroxmute-cli/src/main.rs
git commit -m "$(cat <<'EOF'
refactor(cli): use new from_flags() for limitations construction

Update main.rs to use additive flags (--discover, --portscan, --network)
instead of removed scope-based approach.
EOF
)"
```

---

## Task 5: Add Prompt Template Processor

**Files:**
- Modify: `feroxmute-core/src/agents/prompts.rs`

**Step 1: Add template processing**

```rust
//! System prompts for specialized agents

use serde::Deserialize;
use std::path::Path;

use crate::limitations::PromptContext;
use crate::{Error, Result};

/// Agent prompt configuration
#[derive(Debug, Clone, Deserialize)]
pub struct AgentPrompt {
    pub prompt: String,
}

/// All agent prompts
#[derive(Debug, Clone, Deserialize)]
pub struct Prompts {
    pub orchestrator: AgentPrompt,
    pub recon: AgentPrompt,
    pub scanner: AgentPrompt,
    pub exploit: AgentPrompt,
    pub report: AgentPrompt,
    pub sast: AgentPrompt,
}

impl Prompts {
    /// Load prompts from a TOML file
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        Self::parse(&content)
    }

    /// Parse prompts from TOML string
    pub fn parse(content: &str) -> Result<Self> {
        toml::from_str(content)
            .map_err(|e| Error::Config(format!("Failed to parse prompts: {}", e)))
    }

    /// Load from default location (embedded)
    #[allow(clippy::expect_used)]
    pub fn default_prompts() -> Self {
        let content = include_str!("../../prompts.toml");
        Self::parse(content).expect("Embedded prompts.toml should be valid")
    }

    /// Get prompt for a specific agent
    pub fn get(&self, agent: &str) -> Option<&str> {
        match agent {
            "orchestrator" => Some(&self.orchestrator.prompt),
            "recon" => Some(&self.recon.prompt),
            "scanner" => Some(&self.scanner.prompt),
            "exploit" => Some(&self.exploit.prompt),
            "report" => Some(&self.report.prompt),
            "sast" => Some(&self.sast.prompt),
            _ => None,
        }
    }

    /// Get prompt with conditional sections processed
    pub fn get_with_context(&self, agent: &str, ctx: &PromptContext) -> Option<String> {
        self.get(agent).map(|prompt| process_conditionals(prompt, ctx))
    }
}

impl Default for Prompts {
    fn default() -> Self {
        Self::default_prompts()
    }
}

/// Process {{#if <flag>}}...{{/if}} conditionals in a template
fn process_conditionals(template: &str, ctx: &PromptContext) -> String {
    let mut result = template.to_string();

    // Process each conditional type
    result = process_conditional(&result, "discover", ctx.discover);
    result = process_conditional(&result, "portscan", ctx.portscan);
    result = process_conditional(&result, "network", ctx.network);
    result = process_conditional(&result, "exploit", ctx.exploit);

    result
}

/// Process a single conditional flag
fn process_conditional(template: &str, flag_name: &str, flag_value: bool) -> String {
    let open_tag = format!("{{{{#if {}}}}}", flag_name);
    let close_tag = "{{/if}}";

    let mut result = String::new();
    let mut remaining = template;

    while let Some(start) = remaining.find(&open_tag) {
        // Add content before the tag
        result.push_str(&remaining[..start]);

        // Find the closing tag
        let after_open = start + open_tag.len();
        if let Some(end_offset) = remaining[after_open..].find(close_tag) {
            let content = &remaining[after_open..after_open + end_offset];

            // Include content only if flag is true
            if flag_value {
                result.push_str(content);
            }

            // Move past the closing tag
            remaining = &remaining[after_open + end_offset + close_tag.len()..];
        } else {
            // No closing tag found, include rest as-is
            result.push_str(&remaining[start..]);
            remaining = "";
        }
    }

    // Add remaining content
    result.push_str(remaining);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conditional_include() {
        let template = "Before {{#if discover}}DISCOVERY CONTENT{{/if}} After";
        let ctx = PromptContext {
            discover: true,
            ..Default::default()
        };
        let result = process_conditionals(template, &ctx);
        assert_eq!(result, "Before DISCOVERY CONTENT After");
    }

    #[test]
    fn test_conditional_exclude() {
        let template = "Before {{#if discover}}DISCOVERY CONTENT{{/if}} After";
        let ctx = PromptContext {
            discover: false,
            ..Default::default()
        };
        let result = process_conditionals(template, &ctx);
        assert_eq!(result, "Before  After");
    }

    #[test]
    fn test_multiple_conditionals() {
        let template = "{{#if discover}}DISC{{/if}} {{#if portscan}}PORT{{/if}}";
        let ctx = PromptContext {
            discover: true,
            portscan: false,
            ..Default::default()
        };
        let result = process_conditionals(template, &ctx);
        assert_eq!(result, "DISC ");
    }

    #[test]
    fn test_nested_content_preserved() {
        let template = "{{#if discover}}\n- subfinder\n- dnsx\n{{/if}}";
        let ctx = PromptContext {
            discover: true,
            ..Default::default()
        };
        let result = process_conditionals(template, &ctx);
        assert!(result.contains("subfinder"));
        assert!(result.contains("dnsx"));
    }
}
```

**Step 2: Run tests**

Run: `cargo test -p feroxmute-core prompts`
Expected: All tests pass

**Step 3: Commit**

```bash
git add feroxmute-core/src/agents/prompts.rs
git commit -m "$(cat <<'EOF'
feat(prompts): add conditional template processing

Add {{#if flag}}...{{/if}} syntax for conditional prompt sections.
Supports discover, portscan, network, exploit flags.
EOF
)"
```

---

## Task 6: Update prompts.toml with Conditionals

**Files:**
- Modify: `feroxmute-core/prompts.toml`

**Step 1: Add conditional sections to recon prompt**

Find the recon prompt section and update the tools section to include conditionals:

```toml
[recon]
prompt = """
You are the Reconnaissance Architect - the first agent to touch a target.

## Suggested Workflow

Consider using multiple tools for thorough reconnaissance:
1. httpx - Verify target is alive, get tech fingerprint
2. katana - Crawl for endpoints and JavaScript
3. curl - Manually inspect interesting endpoints found
4. Check robots.txt, sitemap.xml, common paths
5. Explore any APIs or login forms discovered

## Your Purpose

Reconnaissance is about understanding the attack surface before testing begins. Your findings guide every other agent's work. Good recon means targeted, efficient scanning later. Poor recon means wasted effort and missed vulnerabilities.

## Tools at Your Disposal

**httpx** - Verify targets are alive and gather initial fingerprints:
```bash
httpx -u https://example.com -title -tech-detect -status-code -follow-redirects
```
This tells you: Is it up? What's the title? What tech stack? What status codes?

**katana** - Crawl for endpoints and JavaScript analysis:
```bash
katana -u https://example.com -d 2 -jc -kf all
```
This finds: Hidden endpoints, API routes in JS files, form actions, linked resources.

{{#if discover}}
**subfinder** - Discover subdomains (for broader scope):
```bash
subfinder -d example.com -silent
```
Useful when testing an entire domain, not just a single application.

**dnsx** - DNS resolution and subdomain bruteforce:
```bash
dnsx -d example.com -w wordlist.txt
```
{{/if}}

{{#if portscan}}
**naabu** - Fast port scanning:
```bash
naabu -host example.com -top-ports 1000
```

**nmap** - Comprehensive port and service detection:
```bash
nmap -sV -sC example.com
```
{{/if}}

**curl** - Quick manual checks when you need specifics:
```bash
curl -I https://example.com/robots.txt
curl -s https://example.com/api/ | head -50
```

**Memory Tools** - Store findings for other agents to use:
- `memory_add(key, value)`: Store important discoveries
- `memory_get(key)`: Retrieve stored information
- `memory_list()`: See what's been stored

Use memory to save things the scanner will need:
```
memory_add(key="endpoints", value="/login, /api/users, /upload, /admin")
memory_add(key="tech-stack", value="React frontend, Node.js backend, PostgreSQL")
memory_add(key="auth-type", value="JWT Bearer tokens in Authorization header")
```

## Effective Recon Patterns

**Pattern: Layered Discovery**
Start broad, then go deep on interesting finds:
1. httpx to verify the target is alive and get tech fingerprint
2. katana to crawl and find endpoints
3. Manual curl to investigate anything interesting katana found

{{#if discover}}
**Pattern: Subdomain Enumeration**
When scope allows expanding beyond a single target:
1. subfinder to find subdomains passively
2. httpx to probe which subdomains are alive
3. Focus deeper recon on interesting subdomains
{{/if}}

{{#if portscan}}
**Pattern: Port Discovery**
When scope allows network-level testing:
1. naabu for fast initial port scan
2. nmap -sV on open ports for service detection
3. Target specific services based on findings
{{/if}}

**Pattern: API Discovery**
When you see signs of an API:
1. Check common paths: /api, /api/v1, /swagger, /openapi.json, /graphql
2. Look at JavaScript files for API endpoint references
3. Note authentication mechanisms (Bearer tokens, cookies, API keys)

**Pattern: Tech Stack Implications**
What you find suggests what to test:
- WordPress → WPScan, known plugin vulns
- React/Vue SPA → Check for exposed API, look at JS bundles
- PHP → File inclusion, type juggling
- Node.js/Express → Prototype pollution, SSRF in dependencies

**Pattern: Interactive Exploration**
Don't just run scanners - actually look at what you find:
```bash
# Found a login page? Look at the actual form
curl -s https://example.com/login | grep -iE "form|input|action"

# See what fields it expects
curl -s https://example.com/login | grep -oP 'name="[^"]+"'

# Found an API endpoint? See what it returns
curl -s https://example.com/api/v1/ | head -50

# Check robots.txt and sitemap for hidden paths
curl -s https://example.com/robots.txt
curl -s https://example.com/sitemap.xml
```

Crawlers miss things. Manual poking finds hidden endpoints, understands form structures, and reveals application behavior that automated tools can't see.

## Reporting Your Findings

Provide a summary the orchestrator can act on:

```
=== RECON SUMMARY ===
Live Targets:
- https://example.com (200 OK)
- https://api.example.com (200 OK)

Interesting Endpoints:
- /login - Authentication form
- /api/v1/users - REST API (requires auth)
- /upload - File upload functionality
- /admin - Returns 403 (exists but protected)

Technologies:
- Nginx 1.18
- React frontend
- Node.js backend (X-Powered-By header)
- JWT authentication (seen in JS)

Recommended Focus Areas:
- Test /login for auth bypass, credential stuffing
- Test /api/v1/users/{id} for IDOR
- Test /upload for unrestricted file upload
- Investigate /admin access controls
=====================
```

## Before You Stop

Ask yourself:
- Did I find endpoints, or just confirm the target is alive?
- Do I know what the application does (login, file upload, API, etc.)?
- Can the scanner agent act on my findings, or would they be starting blind?
- Did I explore what the crawlers found, or just report raw tool output?

If the answers are weak, keep going. Run another tool. Check another path. A thorough 5-minute recon beats a shallow 30-second one.
"""
```

**Step 2: Build to verify TOML is valid**

Run: `cargo build -p feroxmute-core`
Expected: Successful build (TOML embedded at compile time)

**Step 3: Commit**

```bash
git add feroxmute-core/prompts.toml
git commit -m "$(cat <<'EOF'
feat(prompts): add conditional sections to recon prompt

Wrap discovery and portscan tool documentation in {{#if}} blocks
so they only appear when those capabilities are enabled.
EOF
)"
```

---

## Task 7: Update Config Struct

**Files:**
- Modify: `feroxmute-core/src/config.rs`

**Step 1: Replace Scope enum with capability flags**

```rust
//! Configuration types for feroxmute engagements

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Provider name enum for type-safe provider selection
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProviderName {
    #[default]
    Anthropic,
    OpenAi,
    Gemini,
    Xai,
    DeepSeek,
    Perplexity,
    Cohere,
    Azure,
    Mira,
    LiteLlm,
    Ollama,
}

/// Provider configuration section
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProviderConfig {
    #[serde(default)]
    pub name: ProviderName,
    #[serde(default)]
    pub api_key: String,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub base_url: Option<String>,
}

/// Target configuration section
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TargetConfig {
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub ports: Vec<u16>,
}

/// Capability flags (additive permissions)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CapabilitiesConfig {
    /// Enable subdomain enumeration and asset discovery
    #[serde(default)]
    pub discover: bool,
    /// Enable port scanning
    #[serde(default)]
    pub portscan: bool,
    /// Enable network-level scanning
    #[serde(default)]
    pub network: bool,
}

/// Engagement constraints
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConstraintsConfig {
    #[serde(default)]
    pub passive: bool,
    #[serde(default)]
    pub no_exploit: bool,
    #[serde(default)]
    pub rate_limit: Option<u32>,
    #[serde(default)]
    pub excluded_paths: Vec<String>,
}

/// Output configuration section
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OutputConfig {
    #[serde(default)]
    pub directory: Option<PathBuf>,
    #[serde(default)]
    pub export_html: bool,
    #[serde(default)]
    pub export_pdf: bool,
}

/// Complete engagement configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EngagementConfig {
    #[serde(default)]
    pub provider: ProviderConfig,
    #[serde(default)]
    pub target: TargetConfig,
    #[serde(default)]
    pub capabilities: CapabilitiesConfig,
    #[serde(default)]
    pub constraints: ConstraintsConfig,
    #[serde(default)]
    pub output: OutputConfig,
}

impl EngagementConfig {
    /// Parse configuration from TOML string
    pub fn parse(content: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(content)
    }

    /// Load configuration from file with environment variable expansion
    pub fn from_file(path: impl AsRef<std::path::Path>) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let expanded = expand_env_vars(&content);
        let config = Self::parse(&expanded)?;
        Ok(config)
    }
}

/// Expand environment variables in format ${VAR_NAME}
fn expand_env_vars(content: &str) -> String {
    let mut result = content.to_string();
    let re = regex::Regex::new(r"\$\{([^}]+)\}").expect("valid regex");

    for cap in re.captures_iter(content) {
        let var_name = &cap[1];
        if let Ok(value) = std::env::var(var_name) {
            result = result.replace(&cap[0], &value);
        }
    }

    result
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal_config() {
        let toml = r#"
[target]
host = "example.com"
"#;
        let config = EngagementConfig::parse(toml).expect("valid target config should parse");
        assert_eq!(config.target.host, "example.com");
        assert!(!config.capabilities.discover);
        assert!(!config.capabilities.portscan);
    }

    #[test]
    fn test_parse_full_config() {
        let toml = r#"
[target]
host = "example.com"
ports = [80, 443, 8080]

[capabilities]
discover = true
portscan = true
network = true

[constraints]
passive = false
no_exploit = true

[output]
export_html = true
"#;
        let config = EngagementConfig::parse(toml).expect("full config should parse");
        assert_eq!(config.target.host, "example.com");
        assert!(config.capabilities.discover);
        assert!(config.capabilities.portscan);
        assert!(config.capabilities.network);
        assert!(config.constraints.no_exploit);
        assert!(config.output.export_html);
    }

    #[test]
    fn test_parse_provider_config() {
        let toml = r#"
[provider]
name = "anthropic"
api_key = "test-key"
model = "claude-3-opus"
"#;
        let config = EngagementConfig::parse(toml).expect("provider config should parse");
        assert_eq!(config.provider.name, ProviderName::Anthropic);
        assert_eq!(config.provider.api_key, "test-key");
        assert_eq!(config.provider.model, Some("claude-3-opus".to_string()));
    }

    #[test]
    fn test_defaults() {
        let config = EngagementConfig::default();
        assert!(!config.capabilities.discover);
        assert!(!config.capabilities.portscan);
        assert!(!config.capabilities.network);
        assert!(!config.constraints.passive);
        assert!(!config.constraints.no_exploit);
    }
}
```

**Step 2: Run tests**

Run: `cargo test -p feroxmute-core config`
Expected: All tests pass

**Step 3: Commit**

```bash
git add feroxmute-core/src/config.rs
git commit -m "$(cat <<'EOF'
refactor(config): replace Scope with CapabilitiesConfig

Remove Scope enum (web/network/full).
Add CapabilitiesConfig with discover, portscan, network flags.
Update tests for new structure.
EOF
)"
```

---

## Task 8: Update Wizard State

**Files:**
- Modify: `feroxmute-cli/src/wizard/state.rs`

**Step 1: Replace scope with capability flags**

Update imports and WizardData struct:

```rust
//! Wizard state management

use std::fs;
use std::path::PathBuf;

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;

use feroxmute_core::config::ProviderName;

use super::screens;

const FEROXMUTE_DIR: &str = ".feroxmute";
const CONFIG_FILE: &str = "config.toml";

/// Wizard screens in order
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WizardScreen {
    #[default]
    Welcome,
    ConfirmOverwrite,
    Provider,
    ApiKey,
    AzureEndpoint,
    OllamaBaseUrl,
    OllamaApiKey,
    Capabilities,
    Constraints,
    AdvancedPrompt,
    Advanced,
    Review,
}

/// Form data collected by the wizard
#[derive(Debug, Clone, Default)]
pub struct WizardData {
    pub provider: ProviderName,
    pub api_key: String,
    pub model: Option<String>,
    pub base_url: Option<String>,
    // Capability flags (additive)
    pub discover: bool,
    pub portscan: bool,
    pub network: bool,
    // Constraints
    pub passive: bool,
    pub no_exploit: bool,
    pub rate_limit: Option<u32>,
    pub export_html: bool,
    pub export_pdf: bool,
}
```

Update the screen navigation (replace Scope screen with Capabilities):

```rust
    /// Move to next screen
    fn next_screen(&mut self) -> WizardAction {
        self.screen = match self.screen {
            WizardScreen::ConfirmOverwrite => WizardScreen::Welcome,
            WizardScreen::Welcome => WizardScreen::Provider,
            WizardScreen::Provider => {
                if self.data.provider == ProviderName::Ollama {
                    WizardScreen::OllamaBaseUrl
                } else {
                    WizardScreen::ApiKey
                }
            }
            WizardScreen::ApiKey => {
                if self.data.provider == ProviderName::Azure {
                    WizardScreen::AzureEndpoint
                } else {
                    WizardScreen::Capabilities
                }
            }
            WizardScreen::AzureEndpoint => WizardScreen::Capabilities,
            WizardScreen::OllamaBaseUrl => WizardScreen::OllamaApiKey,
            WizardScreen::OllamaApiKey => WizardScreen::Capabilities,
            WizardScreen::Capabilities => WizardScreen::Constraints,
            WizardScreen::Constraints => WizardScreen::AdvancedPrompt,
            WizardScreen::AdvancedPrompt => {
                if self.show_advanced {
                    WizardScreen::Advanced
                } else {
                    WizardScreen::Review
                }
            }
            WizardScreen::Advanced => WizardScreen::Review,
            WizardScreen::Review => WizardScreen::Review,
        };
        WizardAction::Continue
    }

    /// Move to previous screen
    fn prev_screen(&mut self) -> WizardAction {
        self.screen = match self.screen {
            WizardScreen::ConfirmOverwrite => return WizardAction::Quit,
            WizardScreen::Welcome => return WizardAction::Quit,
            WizardScreen::Provider => WizardScreen::Welcome,
            WizardScreen::ApiKey => WizardScreen::Provider,
            WizardScreen::AzureEndpoint => WizardScreen::ApiKey,
            WizardScreen::OllamaBaseUrl => WizardScreen::Provider,
            WizardScreen::OllamaApiKey => WizardScreen::OllamaBaseUrl,
            WizardScreen::Capabilities => {
                if self.data.provider == ProviderName::Azure {
                    WizardScreen::AzureEndpoint
                } else if self.data.provider == ProviderName::Ollama {
                    WizardScreen::OllamaApiKey
                } else {
                    WizardScreen::ApiKey
                }
            }
            WizardScreen::Constraints => WizardScreen::Capabilities,
            WizardScreen::AdvancedPrompt => WizardScreen::Constraints,
            WizardScreen::Advanced => WizardScreen::AdvancedPrompt,
            WizardScreen::Review => {
                if self.show_advanced {
                    WizardScreen::Advanced
                } else {
                    WizardScreen::AdvancedPrompt
                }
            }
        };
        WizardAction::Continue
    }
```

Update handle_key for Capabilities screen (replace Scope handling):

```rust
            WizardScreen::Capabilities => match key.code {
                KeyCode::Char('q') => return WizardAction::Quit,
                KeyCode::Up | KeyCode::Char('k') => {
                    self.selected_index = self.selected_index.saturating_sub(1);
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    self.selected_index = (self.selected_index + 1).min(2);
                }
                KeyCode::Char(' ') => match self.selected_index {
                    0 => self.data.discover = !self.data.discover,
                    1 => self.data.portscan = !self.data.portscan,
                    2 => self.data.network = !self.data.network,
                    _ => {}
                },
                KeyCode::Enter => {
                    self.selected_index = 0;
                    return self.next_screen();
                }
                KeyCode::Esc => return self.prev_screen(),
                _ => {}
            },
```

Update generate_toml:

```rust
    /// Generate TOML content
    fn generate_toml(&self) -> anyhow::Result<String> {
        let provider_name = match self.data.provider {
            ProviderName::Anthropic => "anthropic",
            ProviderName::OpenAi => "openai",
            ProviderName::Gemini => "gemini",
            ProviderName::Xai => "xai",
            ProviderName::DeepSeek => "deepseek",
            ProviderName::Perplexity => "perplexity",
            ProviderName::Cohere => "cohere",
            ProviderName::Azure => "azure",
            ProviderName::Mira => "mira",
            ProviderName::LiteLlm => "litellm",
            ProviderName::Ollama => "ollama",
        };

        #[allow(clippy::unnecessary_lazy_evaluations)]
        let model = self
            .data
            .model
            .as_deref()
            .unwrap_or_else(|| match self.data.provider {
                ProviderName::Anthropic => "claude-sonnet-4-20250514",
                ProviderName::OpenAi => "gpt-4o",
                ProviderName::Gemini => "gemini-1.5-pro",
                ProviderName::Xai => "grok-2",
                ProviderName::DeepSeek => "deepseek-chat",
                ProviderName::Perplexity => "sonar-pro",
                ProviderName::Cohere => "command-r-plus",
                ProviderName::Azure => "gpt-4o",
                ProviderName::Mira => "mira-chat",
                ProviderName::LiteLlm => "openai/gpt-4o",
                ProviderName::Ollama => "llama3.2",
            });

        let mut toml = String::new();
        toml.push_str("# feroxmute configuration\n");
        toml.push_str(&format!(
            "# Generated: {}\n\n",
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
        ));

        toml.push_str("[provider]\n");
        toml.push_str(&format!("name = \"{}\"\n", provider_name));
        toml.push_str(&format!("api_key = \"{}\"\n", self.data.api_key));
        toml.push_str(&format!("model = \"{}\"\n", model));
        if let Some(ref base_url) = self.data.base_url {
            toml.push_str(&format!("base_url = \"{}\"\n", base_url));
        }
        toml.push('\n');

        toml.push_str("[capabilities]\n");
        toml.push_str(&format!("discover = {}\n", self.data.discover));
        toml.push_str(&format!("portscan = {}\n", self.data.portscan));
        toml.push_str(&format!("network = {}\n", self.data.network));
        toml.push('\n');

        toml.push_str("[constraints]\n");
        toml.push_str(&format!("passive = {}\n", self.data.passive));
        toml.push_str(&format!("no_exploit = {}\n", self.data.no_exploit));
        if let Some(rate_limit) = self.data.rate_limit {
            toml.push_str(&format!("rate_limit = {}\n", rate_limit));
        } else {
            toml.push_str("# rate_limit = 10\n");
        }
        toml.push('\n');

        toml.push_str("[output]\n");
        toml.push_str(&format!("export_html = {}\n", self.data.export_html));
        toml.push_str(&format!("export_pdf = {}\n", self.data.export_pdf));

        Ok(toml)
    }
```

Update render method:

```rust
    /// Render the current screen
    pub fn render(&self, frame: &mut Frame) {
        match self.screen {
            WizardScreen::Welcome => screens::render_welcome(frame, self),
            WizardScreen::ConfirmOverwrite => screens::render_confirm_overwrite(frame, self),
            WizardScreen::Provider => screens::render_provider(frame, self),
            WizardScreen::ApiKey => screens::render_api_key(frame, self),
            WizardScreen::AzureEndpoint => screens::render_azure_endpoint(frame, self),
            WizardScreen::OllamaBaseUrl => screens::render_ollama_base_url(frame, self),
            WizardScreen::OllamaApiKey => screens::render_ollama_api_key(frame, self),
            WizardScreen::Capabilities => screens::render_capabilities(frame, self),
            WizardScreen::Constraints => screens::render_constraints(frame, self),
            WizardScreen::AdvancedPrompt => screens::render_advanced_prompt(frame, self),
            WizardScreen::Advanced => screens::render_advanced(frame, self),
            WizardScreen::Review => screens::render_review(frame, self),
        }
    }
```

**Step 2: Build (will fail - screens need updating)**

Run: `cargo build -p feroxmute-cli 2>&1 | head -20`
Expected: Errors about missing render_capabilities function

**Step 3: Commit partial progress**

```bash
git add feroxmute-cli/src/wizard/state.rs
git commit -m "$(cat <<'EOF'
refactor(wizard): replace Scope with capability checkboxes

Update WizardData to use discover, portscan, network bools.
Rename Scope screen to Capabilities.
Update TOML generation for new config format.
EOF
)"
```

---

## Task 9: Update Wizard Screens

**Files:**
- Modify: `feroxmute-cli/src/wizard/screens.rs`

**Step 1: Replace render_scope with render_capabilities**

Find the `render_scope` function and replace it with:

```rust
pub fn render_capabilities(frame: &mut Frame, state: &WizardState) {
    let area = centered_rect(60, 50, frame.area());

    let block = Block::default()
        .title(" Capabilities ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(6),
            Constraint::Min(0),
        ])
        .split(inner);

    let header = Paragraph::new("Select additional capabilities to enable:")
        .style(Style::default().fg(Color::White));
    frame.render_widget(header, chunks[0]);

    let options = vec![
        (
            "Discovery",
            "Enable subdomain enumeration and asset discovery",
            state.data.discover,
        ),
        (
            "Port Scan",
            "Enable port scanning (naabu, nmap)",
            state.data.portscan,
        ),
        (
            "Network",
            "Enable network-level scanning beyond HTTP",
            state.data.network,
        ),
    ];

    let mut option_lines = Vec::new();
    for (i, (name, desc, enabled)) in options.iter().enumerate() {
        let checkbox = if *enabled { "[x]" } else { "[ ]" };
        let style = if i == state.selected_index {
            Style::default().fg(Color::Yellow).bold()
        } else {
            Style::default().fg(Color::White)
        };
        option_lines.push(Line::from(vec![
            Span::styled(format!(" {} {} ", checkbox, name), style),
            Span::styled(format!("- {}", desc), Style::default().fg(Color::DarkGray)),
        ]));
    }

    let options_widget = Paragraph::new(option_lines);
    frame.render_widget(options_widget, chunks[1]);

    let help = Paragraph::new("↑/↓ navigate • Space toggle • Enter continue • Esc back")
        .style(Style::default().fg(Color::DarkGray));
    frame.render_widget(help, chunks[2]);
}
```

**Step 2: Update render_constraints to remove no_portscan**

Update the constraints screen to only show passive and no_exploit:

```rust
pub fn render_constraints(frame: &mut Frame, state: &WizardState) {
    let area = centered_rect(60, 50, frame.area());

    let block = Block::default()
        .title(" Constraints ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(4),
            Constraint::Min(0),
        ])
        .split(inner);

    let header = Paragraph::new("Select engagement constraints:")
        .style(Style::default().fg(Color::White));
    frame.render_widget(header, chunks[0]);

    let options = vec![
        ("Passive only", "No active scanning, passive recon only", state.data.passive),
        ("No exploitation", "Disable exploitation phase", state.data.no_exploit),
    ];

    let mut option_lines = Vec::new();
    for (i, (name, desc, enabled)) in options.iter().enumerate() {
        let checkbox = if *enabled { "[x]" } else { "[ ]" };
        let style = if i == state.selected_index {
            Style::default().fg(Color::Yellow).bold()
        } else {
            Style::default().fg(Color::White)
        };
        option_lines.push(Line::from(vec![
            Span::styled(format!(" {} {} ", checkbox, name), style),
            Span::styled(format!("- {}", desc), Style::default().fg(Color::DarkGray)),
        ]));
    }

    let options_widget = Paragraph::new(option_lines);
    frame.render_widget(options_widget, chunks[1]);

    let help = Paragraph::new("↑/↓ navigate • Space toggle • Enter continue • Esc back")
        .style(Style::default().fg(Color::DarkGray));
    frame.render_widget(help, chunks[2]);
}
```

**Step 3: Update render_review to show new flags**

Update the review screen to display the new capability flags instead of scope.

**Step 4: Build and verify**

Run: `cargo build -p feroxmute-cli`
Expected: Successful build

**Step 5: Commit**

```bash
git add feroxmute-cli/src/wizard/screens.rs
git commit -m "$(cat <<'EOF'
refactor(wizard): update screens for capability flags

Replace Scope selection with Capabilities checkboxes.
Update Constraints to remove no_portscan (now in Capabilities).
Update Review screen to show new flag values.
EOF
)"
```

---

## Task 10: Update README

**Files:**
- Modify: `README.md`

**Step 1: Update CLI flags section**

Find the flags table and update:

```markdown
| Flag | Description |
|------|-------------|
| `--target <URL>` | Target URL, domain, IP, or source path |
| `--source <PATH>` | Link source code directory to target |
| `--discover` | Enable subdomain enumeration and asset discovery |
| `--portscan` | Enable port scanning (naabu, nmap) |
| `--network` | Enable network-level scanning beyond HTTP |
| `--passive` | Passive reconnaissance only, no active scanning |
| `--sast-only` | Source code analysis only, no web testing |
| `--no-exploit` | Disable exploitation phase |
| `--ports <LIST>` | Limit to specific ports (e.g., `80,443,8080`) |
| `--rate-limit <N>` | Max requests per second |
| `--instruction <TEXT>` | Custom objective for the orchestrator |
```

**Step 2: Update examples section**

```markdown
## Examples

```bash
# Default: Test a web application thoroughly (no discovery, no portscan)
feroxmute --target https://app.example.com

# Enable subdomain discovery for broader coverage
feroxmute --target example.com --discover

# Full network penetration test
feroxmute --target 10.0.0.0/24 --discover --portscan --network

# Combine web target with source code analysis
feroxmute --target https://app.example.com --source ./src

# Source code analysis only
feroxmute --sast-only --target ./my-project
```
```

**Step 3: Commit**

```bash
git add README.md
git commit -m "$(cat <<'EOF'
docs: update README for new capability flags

Replace --scope documentation with --discover, --portscan, --network.
Update examples to show new flag usage.
EOF
)"
```

---

## Task 11: Run Full Test Suite

**Step 1: Run all tests**

Run: `cargo test`
Expected: All tests pass

**Step 2: Run clippy**

Run: `cargo clippy -- -D warnings`
Expected: No warnings

**Step 3: Run build**

Run: `cargo build --release`
Expected: Successful release build

**Step 4: Final commit if any fixes needed**

```bash
git add -A
git commit -m "fix: address test and clippy issues from refactor"
```

---

## Summary

This plan implements the limitations redesign in 11 tasks:

1. Update CLI args (remove scope, add capability flags)
2. Refactor EngagementLimitations to bool flags
3. Add command pipeline parser to prevent bypasses
4. Update main.rs limitations construction
5. Add prompt template processor
6. Update prompts.toml with conditionals
7. Update config struct
8. Update wizard state
9. Update wizard screens
10. Update README
11. Run full test suite
