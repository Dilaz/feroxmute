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
        tools.insert("opengrep", Sast);
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
