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
}
