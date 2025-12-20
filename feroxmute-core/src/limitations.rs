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
