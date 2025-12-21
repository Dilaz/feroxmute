# Engagement Limitations Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Wire CLI scope flags to agents via EngagementLimitations struct with prompt guidance and code enforcement.

**Architecture:** Create `limitations.rs` module with ToolCategory enum, EngagementLimitations struct, and ToolRegistry. Integrate into OrchestratorContext and DockerShellTool for two-layer enforcement. Generate prompt sections for LLM awareness.

**Tech Stack:** Rust, std::collections::HashSet, existing feroxmute-core/cli crates

---

## Task 1: Create ToolCategory Enum

**Files:**
- Create: `feroxmute-core/src/limitations.rs`

**Step 1: Write the test**

```rust
// At end of feroxmute-core/src/limitations.rs

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tool_category_equality() {
        assert_eq!(ToolCategory::PortScan, ToolCategory::PortScan);
        assert_ne!(ToolCategory::PortScan, ToolCategory::WebScan);
    }

    #[test]
    fn test_tool_category_hash() {
        let mut set = std::collections::HashSet::new();
        set.insert(ToolCategory::WebScan);
        set.insert(ToolCategory::WebScan); // duplicate
        assert_eq!(set.len(), 1);
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p feroxmute-core tool_category`
Expected: FAIL - module not found

**Step 3: Create the module with ToolCategory enum**

```rust
// feroxmute-core/src/limitations.rs

//! Engagement scope limitations and tool categorization

use std::collections::HashSet;

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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tool_category_equality() {
        assert_eq!(ToolCategory::PortScan, ToolCategory::PortScan);
        assert_ne!(ToolCategory::PortScan, ToolCategory::WebScan);
    }

    #[test]
    fn test_tool_category_hash() {
        let mut set = HashSet::new();
        set.insert(ToolCategory::WebScan);
        set.insert(ToolCategory::WebScan);
        assert_eq!(set.len(), 1);
    }
}
```

**Step 4: Add module to lib.rs**

In `feroxmute-core/src/lib.rs`, add:
```rust
pub mod limitations;
```

**Step 5: Run test to verify it passes**

Run: `cargo test -p feroxmute-core tool_category`
Expected: PASS (2 tests)

**Step 6: Commit**

```bash
git add feroxmute-core/src/limitations.rs feroxmute-core/src/lib.rs
git commit -m "feat(limitations): add ToolCategory enum"
```

---

## Task 2: Create ToolRegistry

**Files:**
- Modify: `feroxmute-core/src/limitations.rs`

**Step 1: Write the test**

```rust
// Add to tests module in limitations.rs

#[test]
fn test_tool_registry_known_tools() {
    let registry = ToolRegistry::new();
    assert_eq!(registry.categorize("subfinder -d example.com"), Some(ToolCategory::SubdomainEnum));
    assert_eq!(registry.categorize("naabu -host example.com"), Some(ToolCategory::PortScan));
    assert_eq!(registry.categorize("nuclei -u https://example.com"), Some(ToolCategory::WebScan));
    assert_eq!(registry.categorize("sqlmap -u http://test"), Some(ToolCategory::WebExploit));
    assert_eq!(registry.categorize("semgrep --config auto"), Some(ToolCategory::Sast));
}

#[test]
fn test_tool_registry_unknown_tools() {
    let registry = ToolRegistry::new();
    assert_eq!(registry.categorize("curl http://example.com"), None);
    assert_eq!(registry.categorize("python3 script.py"), None);
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p feroxmute-core tool_registry`
Expected: FAIL - ToolRegistry not found

**Step 3: Implement ToolRegistry**

Add to `feroxmute-core/src/limitations.rs` after ToolCategory:

```rust
use std::collections::HashMap;

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

        Self { tools }
    }

    /// Categorize a command by its tool name
    pub fn categorize(&self, command: &str) -> Option<ToolCategory> {
        let cmd = command.split_whitespace().next()?;
        self.tools.get(cmd).copied()
    }
}
```

**Step 4: Run test to verify it passes**

Run: `cargo test -p feroxmute-core tool_registry`
Expected: PASS (2 tests)

**Step 5: Commit**

```bash
git add feroxmute-core/src/limitations.rs
git commit -m "feat(limitations): add ToolRegistry for command categorization"
```

---

## Task 3: Create EngagementLimitations Struct

**Files:**
- Modify: `feroxmute-core/src/limitations.rs`

**Step 1: Write the test**

```rust
// Add to tests module

#[test]
fn test_limitations_default_allows_report() {
    let limits = EngagementLimitations::default();
    assert!(limits.is_allowed(ToolCategory::Report));
}

#[test]
fn test_limitations_check_category() {
    let mut allowed = HashSet::new();
    allowed.insert(ToolCategory::WebScan);
    allowed.insert(ToolCategory::Report);

    let limits = EngagementLimitations {
        allowed_categories: allowed,
        target_ports: None,
        rate_limit: None,
    };

    assert!(limits.is_allowed(ToolCategory::WebScan));
    assert!(limits.is_allowed(ToolCategory::Report));
    assert!(!limits.is_allowed(ToolCategory::PortScan));
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p feroxmute-core limitations_`
Expected: FAIL - EngagementLimitations not found

**Step 3: Implement EngagementLimitations**

Add to `feroxmute-core/src/limitations.rs`:

```rust
/// Engagement scope limitations derived from CLI args
#[derive(Debug, Clone)]
pub struct EngagementLimitations {
    /// Categories of tools allowed in this engagement
    pub allowed_categories: HashSet<ToolCategory>,
    /// Restrict testing to specific ports (None = any port)
    pub target_ports: Option<Vec<u16>>,
    /// Maximum requests per second
    pub rate_limit: Option<u32>,
}

impl Default for EngagementLimitations {
    fn default() -> Self {
        let mut allowed = HashSet::new();
        allowed.insert(ToolCategory::Report);
        Self {
            allowed_categories: allowed,
            target_ports: None,
            rate_limit: None,
        }
    }
}

impl EngagementLimitations {
    /// Check if a tool category is allowed
    pub fn is_allowed(&self, category: ToolCategory) -> bool {
        self.allowed_categories.contains(&category)
    }
}
```

**Step 4: Run test to verify it passes**

Run: `cargo test -p feroxmute-core limitations_`
Expected: PASS (2 tests)

**Step 5: Commit**

```bash
git add feroxmute-core/src/limitations.rs
git commit -m "feat(limitations): add EngagementLimitations struct"
```

---

## Task 4: Add to_prompt_section Method

**Files:**
- Modify: `feroxmute-core/src/limitations.rs`

**Step 1: Write the test**

```rust
// Add to tests module

#[test]
fn test_prompt_section_no_portscan() {
    let mut allowed = HashSet::new();
    allowed.insert(ToolCategory::WebScan);
    allowed.insert(ToolCategory::Report);

    let limits = EngagementLimitations {
        allowed_categories: allowed,
        target_ports: None,
        rate_limit: None,
    };

    let prompt = limits.to_prompt_section();
    assert!(prompt.contains("NO port scanning"));
    assert!(prompt.contains("Engagement Limitations"));
}

#[test]
fn test_prompt_section_with_rate_limit() {
    let mut allowed = HashSet::new();
    allowed.insert(ToolCategory::WebScan);
    allowed.insert(ToolCategory::Report);

    let limits = EngagementLimitations {
        allowed_categories: allowed,
        target_ports: Some(vec![80, 443]),
        rate_limit: Some(10),
    };

    let prompt = limits.to_prompt_section();
    assert!(prompt.contains("10 requests/second"));
    assert!(prompt.contains("80") && prompt.contains("443"));
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p feroxmute-core prompt_section`
Expected: FAIL - method not found

**Step 3: Implement to_prompt_section**

Add to `impl EngagementLimitations`:

```rust
    /// Generate a prompt section describing limitations for LLM awareness
    pub fn to_prompt_section(&self) -> String {
        use ToolCategory::*;
        let mut lines = vec!["## Engagement Limitations".to_string()];

        if !self.is_allowed(SubdomainEnum) && !self.is_allowed(AssetDiscovery) {
            lines.push("- NO subdomain enumeration or asset discovery - test only the specified target".into());
        }
        if !self.is_allowed(PortScan) {
            lines.push("- NO port scanning - target ports are already known".into());
        }
        if !self.is_allowed(WebExploit) && !self.is_allowed(NetworkExploit) {
            lines.push("- NO exploitation - reconnaissance and scanning only".into());
        }
        if !self.is_allowed(NetworkScan) {
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
```

**Step 4: Run test to verify it passes**

Run: `cargo test -p feroxmute-core prompt_section`
Expected: PASS (2 tests)

**Step 5: Commit**

```bash
git add feroxmute-core/src/limitations.rs
git commit -m "feat(limitations): add to_prompt_section for LLM guidance"
```

---

## Task 5: Add --no-discovery CLI Flag

**Files:**
- Modify: `feroxmute-cli/src/args.rs`

**Step 1: Add the flag**

In `feroxmute-cli/src/args.rs`, add after `--passive`:

```rust
    /// Skip subdomain enumeration and asset discovery (webapp-only testing)
    #[arg(long)]
    pub no_discovery: bool,
```

**Step 2: Verify it compiles**

Run: `cargo build -p feroxmute-cli`
Expected: Success

**Step 3: Verify help shows the flag**

Run: `cargo run -- --help 2>&1 | grep -A1 "no-discovery"`
Expected: Shows `--no-discovery` with description

**Step 4: Commit**

```bash
git add feroxmute-cli/src/args.rs
git commit -m "feat(cli): add --no-discovery flag for webapp-only testing"
```

---

## Task 6: Add from_args Constructor

**Files:**
- Modify: `feroxmute-core/src/limitations.rs`
- Depends on: CLI Args struct accessible from core (via parameter passing)

**Step 1: Write the test**

```rust
// Add to tests module

#[test]
fn test_web_scope_defaults() {
    use ToolCategory::*;
    let limits = EngagementLimitations::for_web_scope(false, false, false);

    assert!(limits.is_allowed(WebCrawl));
    assert!(limits.is_allowed(WebScan));
    assert!(limits.is_allowed(WebExploit));
    assert!(limits.is_allowed(SubdomainEnum));
    assert!(limits.is_allowed(Report));
    assert!(!limits.is_allowed(PortScan));
    assert!(!limits.is_allowed(NetworkScan));
}

#[test]
fn test_web_scope_no_discovery() {
    use ToolCategory::*;
    let limits = EngagementLimitations::for_web_scope(true, false, false);

    assert!(limits.is_allowed(WebScan));
    assert!(!limits.is_allowed(SubdomainEnum));
    assert!(!limits.is_allowed(AssetDiscovery));
}

#[test]
fn test_web_scope_no_exploit() {
    use ToolCategory::*;
    let limits = EngagementLimitations::for_web_scope(false, true, false);

    assert!(limits.is_allowed(WebScan));
    assert!(!limits.is_allowed(WebExploit));
}

#[test]
fn test_sast_only() {
    use ToolCategory::*;
    let limits = EngagementLimitations::for_sast_only();

    assert!(limits.is_allowed(Sast));
    assert!(limits.is_allowed(Report));
    assert!(!limits.is_allowed(WebScan));
    assert!(!limits.is_allowed(PortScan));
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p feroxmute-core scope`
Expected: FAIL - methods not found

**Step 3: Implement scope constructors**

Add to `impl EngagementLimitations`:

```rust
    /// Create limitations for web scope
    pub fn for_web_scope(no_discovery: bool, no_exploit: bool, no_portscan: bool) -> Self {
        use ToolCategory::*;
        let mut allowed = HashSet::new();

        // Web app testing always allowed
        allowed.insert(WebCrawl);
        allowed.insert(WebScan);
        allowed.insert(Report);

        // Conditional
        if !no_exploit {
            allowed.insert(WebExploit);
        }
        if !no_discovery {
            allowed.insert(SubdomainEnum);
            allowed.insert(AssetDiscovery);
        }
        if !no_portscan {
            // Web scope doesn't include portscan by default
        }

        Self {
            allowed_categories: allowed,
            target_ports: None,
            rate_limit: None,
        }
    }

    /// Create limitations for network scope
    pub fn for_network_scope(no_discovery: bool, no_exploit: bool, no_portscan: bool) -> Self {
        use ToolCategory::*;
        let mut limits = Self::for_web_scope(no_discovery, no_exploit, no_portscan);

        if !no_portscan {
            limits.allowed_categories.insert(PortScan);
        }
        limits.allowed_categories.insert(NetworkScan);

        if !no_exploit {
            limits.allowed_categories.insert(NetworkExploit);
        }

        limits
    }

    /// Create limitations for full scope
    pub fn for_full_scope() -> Self {
        use ToolCategory::*;
        let allowed: HashSet<_> = [
            SubdomainEnum, PortScan, AssetDiscovery,
            WebCrawl, WebScan, WebExploit,
            NetworkScan, NetworkExploit,
            Sast, Report
        ].into_iter().collect();

        Self {
            allowed_categories: allowed,
            target_ports: None,
            rate_limit: None,
        }
    }

    /// Create limitations for SAST only
    pub fn for_sast_only() -> Self {
        use ToolCategory::*;
        let allowed: HashSet<_> = [Sast, Report].into_iter().collect();

        Self {
            allowed_categories: allowed,
            target_ports: None,
            rate_limit: None,
        }
    }

    /// Create limitations for passive mode
    pub fn for_passive() -> Self {
        use ToolCategory::*;
        let allowed: HashSet<_> = [AssetDiscovery, Report].into_iter().collect();

        Self {
            allowed_categories: allowed,
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
```

**Step 4: Run test to verify it passes**

Run: `cargo test -p feroxmute-core scope`
Expected: PASS (4 tests)

**Step 5: Commit**

```bash
git add feroxmute-core/src/limitations.rs
git commit -m "feat(limitations): add scope constructors for CLI integration"
```

---

## Task 7: Add Limitations to OrchestratorContext

**Files:**
- Modify: `feroxmute-core/src/tools/orchestrator.rs`

**Step 1: Add import**

At top of `feroxmute-core/src/tools/orchestrator.rs`, add:

```rust
use crate::limitations::EngagementLimitations;
```

**Step 2: Add field to OrchestratorContext**

In the `OrchestratorContext` struct, add:

```rust
    /// Engagement scope limitations
    pub limitations: Arc<EngagementLimitations>,
```

**Step 3: Verify it compiles**

Run: `cargo build -p feroxmute-core`
Expected: FAIL - missing field in struct construction (expected)

**Step 4: Commit the context change**

```bash
git add feroxmute-core/src/tools/orchestrator.rs
git commit -m "feat(orchestrator): add limitations field to OrchestratorContext"
```

---

## Task 8: Add Limitations to DockerShellTool

**Files:**
- Modify: `feroxmute-core/src/tools/shell.rs`

**Step 1: Add imports**

At top of `feroxmute-core/src/tools/shell.rs`, add:

```rust
use crate::limitations::{EngagementLimitations, ToolRegistry};
```

**Step 2: Add fields to DockerShellTool**

Add to the struct:

```rust
    limitations: Arc<EngagementLimitations>,
    tool_registry: ToolRegistry,
```

**Step 3: Update constructor**

Update `DockerShellTool::new()` to accept limitations:

```rust
    pub fn new(
        container: Arc<ContainerManager>,
        events: Arc<dyn EventSender>,
        agent_name: String,
        limitations: Arc<EngagementLimitations>,
    ) -> Self {
        Self {
            container,
            events,
            agent_name,
            limitations,
            tool_registry: ToolRegistry::new(),
        }
    }
```

**Step 4: Verify it compiles (will fail - call sites need updating)**

Run: `cargo build -p feroxmute-core`
Expected: FAIL - call sites missing parameter

**Step 5: Commit the shell tool change**

```bash
git add feroxmute-core/src/tools/shell.rs
git commit -m "feat(shell): add limitations and registry to DockerShellTool"
```

---

## Task 9: Implement Shell Command Enforcement

**Files:**
- Modify: `feroxmute-core/src/tools/shell.rs`

**Step 1: Add check_command method**

Add to `impl DockerShellTool`:

```rust
    /// Check if a command is allowed by engagement limitations
    fn check_command_allowed(&self, command: &str) -> Result<(), String> {
        let category = self.tool_registry.categorize(command);

        match category {
            Some(cat) if !self.limitations.is_allowed(cat) => {
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
                    false,
                );
                Ok(())
            }
            Some(_) => Ok(()),
        }
    }
```

**Step 2: Call check in the Tool::call method**

In the `call` method, add check before execution:

```rust
    async fn call(&self, args: Self::Args) -> Result<Self::Output, Self::Error> {
        // Check if command is allowed by limitations
        if let Err(msg) = self.check_command_allowed(&args.command) {
            return Ok(ShellOutput {
                exit_code: 1,
                stdout: String::new(),
                stderr: msg,
            });
        }

        // ... rest of existing implementation
```

**Step 3: Verify it compiles**

Run: `cargo build -p feroxmute-core`
Expected: FAIL (call sites still need updating)

**Step 4: Commit**

```bash
git add feroxmute-core/src/tools/shell.rs
git commit -m "feat(shell): implement command enforcement in DockerShellTool"
```

---

## Task 10: Implement Spawn Agent Enforcement

**Files:**
- Modify: `feroxmute-core/src/tools/orchestrator.rs`

**Step 1: Add helper function**

Before `impl SpawnAgentTool`, add:

```rust
use crate::limitations::ToolCategory;

/// Get required categories for an agent type
fn agent_required_categories(agent_type: &str) -> Vec<ToolCategory> {
    use ToolCategory::*;
    match agent_type {
        "recon" => vec![SubdomainEnum, AssetDiscovery, PortScan, WebCrawl],
        "scanner" => vec![WebScan, NetworkScan],
        "exploit" => vec![WebExploit, NetworkExploit],
        "sast" => vec![Sast],
        "report" => vec![Report],
        _ => vec![],
    }
}
```

**Step 2: Add check in SpawnAgentTool::call**

At start of `SpawnAgentTool::call`, add:

```rust
        // Check if agent type is allowed by limitations
        let required = agent_required_categories(&args.agent_type);
        let has_any_allowed = required
            .iter()
            .any(|c| self.context.limitations.is_allowed(*c));

        if !has_any_allowed && !required.is_empty() {
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

**Step 3: Verify it compiles**

Run: `cargo build -p feroxmute-core`
Expected: Still failing (context construction needs updating)

**Step 4: Commit**

```bash
git add feroxmute-core/src/tools/orchestrator.rs
git commit -m "feat(orchestrator): implement agent spawn enforcement"
```

---

## Task 11: Update Provider Call Sites

**Files:**
- Modify: `feroxmute-core/src/providers/anthropic.rs` (and all other providers)

**Step 1: Update DockerShellTool::new calls**

In each provider's `complete_with_shell` method, update the DockerShellTool construction. Since limitations aren't available in this method, we need to pass them through.

First, update the `LlmProvider` trait in `feroxmute-core/src/providers/traits.rs`:

```rust
    async fn complete_with_shell(
        &self,
        system_prompt: &str,
        user_prompt: &str,
        container: Arc<ContainerManager>,
        events: Arc<dyn EventSender>,
        agent_name: &str,
        limitations: Arc<EngagementLimitations>,  // NEW
    ) -> Result<String>;
```

**Step 2: Add import to traits.rs**

```rust
use crate::limitations::EngagementLimitations;
```

**Step 3: Update each provider implementation**

Update signature and pass limitations to DockerShellTool::new() in all providers.

**Step 4: Verify it compiles**

Run: `cargo build -p feroxmute-core`
Expected: FAIL - call sites in orchestrator.rs need updating

**Step 5: Commit**

```bash
git add feroxmute-core/src/providers/
git commit -m "feat(providers): add limitations param to complete_with_shell"
```

---

## Task 12: Update SpawnAgentTool to Pass Limitations

**Files:**
- Modify: `feroxmute-core/src/tools/orchestrator.rs`

**Step 1: Update the spawned agent call**

In `SpawnAgentTool::call`, update the `complete_with_shell` call:

```rust
                let output = match provider
                    .complete_with_shell(
                        &full_prompt,
                        &target,
                        container,
                        events,
                        &agent_name,
                        Arc::clone(&limitations),  // Pass limitations
                    )
                    .await
```

Where `limitations` comes from `self.context.limitations`.

**Step 2: Verify it compiles**

Run: `cargo build -p feroxmute-core`
Expected: Still failing - runner.rs needs updating

**Step 3: Commit**

```bash
git add feroxmute-core/src/tools/orchestrator.rs
git commit -m "feat(orchestrator): pass limitations to spawned agents"
```

---

## Task 13: Wire Up CLI Runner

**Files:**
- Modify: `feroxmute-cli/src/runner.rs`

**Step 1: Add import**

```rust
use feroxmute_core::limitations::EngagementLimitations;
```

**Step 2: Build limitations from args**

Update `run_orchestrator` function signature to accept limitations:

```rust
pub async fn run_orchestrator(
    target: String,
    provider: Arc<dyn LlmProvider>,
    container: Arc<ContainerManager>,
    tx: mpsc::Sender<AgentEvent>,
    cancel: CancellationToken,
    has_source_target: bool,
    limitations: Arc<EngagementLimitations>,  // NEW
) -> Result<()> {
```

**Step 3: Pass to run_orchestrator_with_tools**

Update `run_orchestrator_with_tools` to accept and use limitations:

```rust
async fn run_orchestrator_with_tools(
    orchestrator: &OrchestratorAgent,
    target: &str,
    tx: &mpsc::Sender<AgentEvent>,
    provider: Arc<dyn LlmProvider>,
    container: Arc<ContainerManager>,
    prompts: &Prompts,
    cancel: CancellationToken,
    has_source_target: bool,
    limitations: Arc<EngagementLimitations>,  // NEW
) -> Result<String> {
    let context = Arc::new(OrchestratorContext {
        registry: Arc::new(Mutex::new(AgentRegistry::new())),
        provider: Arc::clone(&provider),
        container,
        events: Arc::new(TuiEventSender::new(tx.clone())),
        cancel,
        prompts: prompts.clone(),
        target: target.to_string(),
        findings: Arc::new(Mutex::new(Vec::new())),
        limitations: Arc::clone(&limitations),  // NEW
    });

    // Include limitations in user prompt
    let user_prompt = format!(
        "Target: {}\n\n{}\n\nEngagement Task: Perform security assessment\n\n\
        You have tools to spawn agents (recon, scanner{}, report), wait for them, \
        record findings, and complete the engagement.\n\n\
        Start by spawning appropriate agents for reconnaissance.",
        target,
        limitations.to_prompt_section(),
        if has_source_target { ", sast" } else { "" }
    );
    // ... rest unchanged
```

**Step 4: Verify it compiles**

Run: `cargo build -p feroxmute-cli`
Expected: FAIL - call site in main/tui needs updating

**Step 5: Commit**

```bash
git add feroxmute-cli/src/runner.rs
git commit -m "feat(runner): wire limitations from CLI to orchestrator"
```

---

## Task 14: Update TUI/Main Entry Point

**Files:**
- Modify: `feroxmute-cli/src/tui/runner.rs` or `feroxmute-cli/src/main.rs`

**Step 1: Build limitations from args in main**

Where `run_orchestrator` is called, build limitations first:

```rust
use feroxmute_core::limitations::EngagementLimitations;

// Build limitations from CLI args
let limitations = Arc::new(if args.sast_only {
    EngagementLimitations::for_sast_only()
} else if args.passive {
    EngagementLimitations::for_passive()
} else {
    match args.scope.as_str() {
        "network" => EngagementLimitations::for_network_scope(
            args.no_discovery,
            args.no_exploit,
            args.no_portscan,
        ),
        "full" => EngagementLimitations::for_full_scope(),
        _ => EngagementLimitations::for_web_scope(
            args.no_discovery,
            args.no_exploit,
            args.no_portscan,
        ),
    }
});

// Apply optional modifiers
let limitations = if let Some(ports) = &args.ports {
    let ports: Vec<u16> = ports
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();
    Arc::new((*limitations).clone().with_ports(ports))
} else {
    limitations
};

let limitations = if let Some(rate) = args.rate_limit {
    Arc::new((*limitations).clone().with_rate_limit(rate))
} else {
    limitations
};
```

**Step 2: Pass to run_orchestrator**

Update the call to include limitations.

**Step 3: Verify full build**

Run: `cargo build`
Expected: SUCCESS

**Step 4: Run tests**

Run: `cargo test`
Expected: All tests pass

**Step 5: Commit**

```bash
git add feroxmute-cli/src/
git commit -m "feat(cli): build limitations from args and wire to runner"
```

---

## Task 15: Export from lib.rs

**Files:**
- Modify: `feroxmute-core/src/lib.rs`

**Step 1: Ensure public export**

Verify `feroxmute-core/src/lib.rs` has:

```rust
pub mod limitations;
```

**Step 2: Verify external usage works**

Run: `cargo build`
Expected: SUCCESS

**Step 3: Final commit**

```bash
git add .
git commit -m "feat: complete engagement limitations implementation"
```

---

## Verification

After all tasks complete:

1. Run full test suite: `cargo test`
2. Build release: `cargo build --release`
3. Test CLI flags:
   ```bash
   cargo run -- --target example.com --scope web --no-discovery --help
   ```

---

Plan complete and saved to `docs/plans/2025-01-20-engagement-limitations-impl.md`.

**Two execution options:**

**1. Subagent-Driven (this session)** - I dispatch fresh subagent per task, review between tasks, fast iteration

**2. Parallel Session (separate)** - Open new session in worktree with executing-plans, batch execution with checkpoints

**Which approach?**
