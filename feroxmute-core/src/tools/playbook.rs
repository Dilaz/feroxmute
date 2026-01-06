//! Vulnerability playbook lookup
//!
//! Provides embedded playbooks for vulnerability testing techniques.

use std::collections::HashMap;
use std::sync::LazyLock;

/// All available playbook categories
pub const PLAYBOOK_CATEGORIES: &[&str] = &[
    "sql-injection",
    "xss",
    "csrf",
    "command-injection",
    "jwt-attacks",
    "xxe",
    "lfi-rfi",
    "ssti",
    "ssrf",
    "deserialization",
    "race-conditions",
    "nosql-injection",
    "graphql",
    "websockets",
    "windows-web",
    "windows-ad",
    "crypto",
];

/// Embedded playbooks loaded at compile time
static PLAYBOOKS: LazyLock<HashMap<&'static str, &'static str>> = LazyLock::new(|| {
    let mut map = HashMap::new();
    map.insert(
        "sql-injection",
        include_str!("../../playbooks/sql-injection.md"),
    );
    map.insert("xss", include_str!("../../playbooks/xss.md"));
    map.insert("csrf", include_str!("../../playbooks/csrf.md"));
    map.insert(
        "command-injection",
        include_str!("../../playbooks/command-injection.md"),
    );
    map.insert(
        "jwt-attacks",
        include_str!("../../playbooks/jwt-attacks.md"),
    );
    map.insert("xxe", include_str!("../../playbooks/xxe.md"));
    map.insert("lfi-rfi", include_str!("../../playbooks/lfi-rfi.md"));
    map.insert("ssti", include_str!("../../playbooks/ssti.md"));
    map.insert("ssrf", include_str!("../../playbooks/ssrf.md"));
    map.insert(
        "deserialization",
        include_str!("../../playbooks/deserialization.md"),
    );
    map.insert(
        "race-conditions",
        include_str!("../../playbooks/race-conditions.md"),
    );
    map.insert(
        "nosql-injection",
        include_str!("../../playbooks/nosql-injection.md"),
    );
    map.insert("graphql", include_str!("../../playbooks/graphql.md"));
    map.insert("websockets", include_str!("../../playbooks/websockets.md"));
    map.insert(
        "windows-web",
        include_str!("../../playbooks/windows-web.md"),
    );
    map.insert("windows-ad", include_str!("../../playbooks/windows-ad.md"));
    map.insert("crypto", include_str!("../../playbooks/crypto.md"));
    map
});

/// Get a playbook by category name
pub fn get_playbook(category: &str) -> Option<&'static str> {
    PLAYBOOKS.get(category).copied()
}

/// List all available playbook categories
pub fn list_categories() -> &'static [&'static str] {
    PLAYBOOK_CATEGORIES
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_playbook_exists() {
        let playbook = get_playbook("sql-injection");
        assert!(playbook.is_some());
        assert!(playbook.unwrap().contains("SQL"));
    }

    #[test]
    fn test_get_playbook_not_found() {
        let playbook = get_playbook("nonexistent");
        assert!(playbook.is_none());
    }

    #[test]
    fn test_list_categories() {
        let categories = list_categories();
        assert_eq!(categories.len(), 17);
        assert!(categories.contains(&"sql-injection"));
        assert!(categories.contains(&"windows-ad"));
    }
}
