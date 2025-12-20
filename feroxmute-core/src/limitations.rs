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

        Self { tools }
    }

    /// Categorize a command by its tool name
    pub fn categorize(&self, command: &str) -> Option<ToolCategory> {
        let cmd = command.split_whitespace().next()?;
        self.tools.get(cmd).copied()
    }
}

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

    /// Generate a prompt section describing limitations for LLM awareness
    pub fn to_prompt_section(&self) -> String {
        use ToolCategory::*;
        let mut lines = vec!["## Engagement Limitations".to_string()];

        if !self.is_allowed(SubdomainEnum) && !self.is_allowed(AssetDiscovery) {
            lines.push(
                "- NO subdomain enumeration or asset discovery - test only the specified target"
                    .into(),
            );
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
        assert_eq!(
            registry.categorize("sqlmap -u http://test"),
            Some(ToolCategory::WebExploit)
        );
        assert_eq!(
            registry.categorize("semgrep --config auto"),
            Some(ToolCategory::Sast)
        );
    }

    #[test]
    fn test_tool_registry_unknown_tools() {
        let registry = ToolRegistry::new();
        assert_eq!(registry.categorize("curl http://example.com"), None);
        assert_eq!(registry.categorize("python3 script.py"), None);
    }

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
}
