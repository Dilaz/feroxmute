use std::fs;
use std::path::Path;

use super::{Target, TargetCollection};

#[derive(Debug, Clone)]
pub struct RelationshipHint {
    pub source_raw: String,
    pub web_raw: String,
    pub confidence: f32,
    pub reason: String,
}

pub struct RelationshipDetector;

impl RelationshipDetector {
    /// Detect relationships between targets using heuristics
    pub fn detect(collection: &TargetCollection) -> Vec<RelationshipHint> {
        let mut hints = Vec::new();

        for source in &collection.standalone_sources {
            for group in &collection.groups {
                let web = &group.web_target;

                if let Some(hint) = Self::check_relationship(source, web) {
                    hints.push(hint);
                }
            }
        }

        hints
    }

    fn check_relationship(source: &Target, web: &Target) -> Option<RelationshipHint> {
        let source_path = match &source.target_type {
            super::TargetType::Directory { path } => path.clone(),
            super::TargetType::Repository {
                local_path: Some(path),
                ..
            } => path.clone(),
            _ => return None,
        };

        let web_url = match &web.target_type {
            super::TargetType::Web { url } => url.clone(),
            _ => return None,
        };

        // Extract domain from URL
        let domain = Self::extract_domain(&web_url)?;

        let mut score: f32 = 0.0;
        let mut reasons = Vec::new();

        // Check config files for domain references
        if Self::check_config_files(&source_path, &domain) {
            score += 0.4;
            reasons.push("domain found in config files");
        }

        // Check for URL in .env files
        if Self::check_env_files(&source_path, &domain) {
            score += 0.3;
            reasons.push("domain found in .env file");
        }

        // Check package.json homepage
        if Self::check_package_json(&source_path, &domain) {
            score += 0.3;
            reasons.push("domain matches package.json homepage");
        }

        // Check docker-compose for matching services
        if Self::check_docker_compose(&source_path, &domain) {
            score += 0.2;
            reasons.push("domain found in docker-compose");
        }

        if score >= 0.3 {
            Some(RelationshipHint {
                source_raw: source.raw.clone(),
                web_raw: web.raw.clone(),
                confidence: score.min(1.0),
                reason: reasons.join(", "),
            })
        } else {
            None
        }
    }

    fn extract_domain(url: &str) -> Option<String> {
        let url = url
            .trim_start_matches("https://")
            .trim_start_matches("http://");
        let domain = url.split('/').next()?;
        Some(domain.to_lowercase())
    }

    fn check_config_files(source_path: &Path, domain: &str) -> bool {
        let config_patterns = [
            "config.toml",
            "config.yaml",
            "config.yml",
            "config.json",
            "settings.py",
            "config/default.toml",
            "config/production.toml",
        ];

        for pattern in config_patterns {
            let path = source_path.join(pattern);
            if path.exists() {
                if let Ok(content) = fs::read_to_string(&path) {
                    if content.to_lowercase().contains(domain) {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn check_env_files(source_path: &Path, domain: &str) -> bool {
        let env_files = [".env", ".env.local", ".env.production", ".env.example"];

        for file in env_files {
            let path = source_path.join(file);
            if path.exists() {
                if let Ok(content) = fs::read_to_string(&path) {
                    if content.to_lowercase().contains(domain) {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn check_package_json(source_path: &Path, domain: &str) -> bool {
        let path = source_path.join("package.json");
        if path.exists() {
            if let Ok(content) = fs::read_to_string(&path) {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
                    if let Some(homepage) = json.get("homepage").and_then(|h| h.as_str()) {
                        return homepage.to_lowercase().contains(domain);
                    }
                }
            }
        }
        false
    }

    fn check_docker_compose(source_path: &Path, domain: &str) -> bool {
        let compose_files = ["docker-compose.yml", "docker-compose.yaml", "compose.yml"];

        for file in compose_files {
            let path = source_path.join(file);
            if path.exists() {
                if let Ok(content) = fs::read_to_string(&path) {
                    if content.to_lowercase().contains(domain) {
                        return true;
                    }
                }
            }
        }
        false
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn test_extract_domain() {
        assert_eq!(
            RelationshipDetector::extract_domain("https://example.com/path"),
            Some("example.com".to_string())
        );
        assert_eq!(
            RelationshipDetector::extract_domain("http://api.example.com"),
            Some("api.example.com".to_string())
        );
        assert_eq!(
            RelationshipDetector::extract_domain("https://example.com:8080/api"),
            Some("example.com:8080".to_string())
        );
    }

    #[test]
    fn test_no_relationship_without_evidence() {
        let temp_dir = TempDir::new().expect("should create temp dir");
        let temp_path = temp_dir.path().to_str().expect("path should be valid utf-8");

        let mut collection = TargetCollection::new();
        collection.add_target(Target::parse("https://example.com").expect("should parse url"));
        collection.add_target(Target::parse(temp_path).expect("should parse path"));

        let hints = RelationshipDetector::detect(&collection);
        assert!(
            hints.is_empty(),
            "Should not find relationship without evidence"
        );
    }

    #[test]
    fn test_detect_relationship_via_env_file() {
        let temp_dir = TempDir::new().expect("should create temp dir");
        let temp_path = temp_dir.path();

        // Create .env file with domain reference
        let env_path = temp_path.join(".env");
        let mut env_file =
            std::fs::File::create(&env_path).expect("should create .env file");
        writeln!(env_file, "API_URL=https://example.com/api").expect("should write to file");
        writeln!(env_file, "DATABASE_URL=postgres://localhost").expect("should write to file");

        let mut collection = TargetCollection::new();
        collection.add_target(Target::parse("https://example.com").expect("should parse url"));
        collection.add_target(
            Target::parse(temp_path.to_str().expect("path should be valid utf-8"))
                .expect("should parse path"),
        );

        let hints = RelationshipDetector::detect(&collection);
        assert_eq!(hints.len(), 1, "Should detect one relationship");
        let first_hint = hints.first().expect("should have one hint");
        assert!(
            first_hint.confidence >= 0.3,
            "Confidence should be at least 0.3"
        );
        assert!(
            first_hint.reason.contains(".env"),
            "Reason should mention .env file"
        );
    }

    #[test]
    fn test_detect_relationship_via_package_json() {
        let temp_dir = TempDir::new().expect("should create temp dir");
        let temp_path = temp_dir.path();

        // Create package.json with homepage
        let package_json = temp_path.join("package.json");
        let mut pkg_file =
            std::fs::File::create(&package_json).expect("should create package.json");
        writeln!(
            pkg_file,
            r#"{{"name": "test", "homepage": "https://example.com"}}"#
        )
        .expect("should write to file");

        let mut collection = TargetCollection::new();
        collection.add_target(Target::parse("https://example.com").expect("should parse url"));
        collection.add_target(
            Target::parse(temp_path.to_str().expect("path should be valid utf-8"))
                .expect("should parse path"),
        );

        let hints = RelationshipDetector::detect(&collection);
        assert_eq!(hints.len(), 1, "Should detect one relationship");
        let first_hint = hints.first().expect("should have one hint");
        assert!(
            first_hint.confidence >= 0.3,
            "Confidence should be at least 0.3"
        );
        assert!(
            first_hint.reason.contains("package.json"),
            "Reason should mention package.json"
        );
    }

    #[test]
    fn test_detect_relationship_via_config_file() {
        let temp_dir = TempDir::new().expect("should create temp dir");
        let temp_path = temp_dir.path();

        // Create config.toml with domain reference
        let config_path = temp_path.join("config.toml");
        let mut config_file =
            std::fs::File::create(&config_path).expect("should create config.toml");
        writeln!(config_file, "[server]").expect("should write to file");
        writeln!(config_file, "host = \"example.com\"").expect("should write to file");

        let mut collection = TargetCollection::new();
        collection.add_target(Target::parse("https://example.com").expect("should parse url"));
        collection.add_target(
            Target::parse(temp_path.to_str().expect("path should be valid utf-8"))
                .expect("should parse path"),
        );

        let hints = RelationshipDetector::detect(&collection);
        assert_eq!(hints.len(), 1, "Should detect one relationship");
        let first_hint = hints.first().expect("should have one hint");
        assert!(
            first_hint.confidence >= 0.3,
            "Confidence should be at least 0.3"
        );
        assert!(
            first_hint.reason.contains("config"),
            "Reason should mention config files"
        );
    }

    #[test]
    fn test_detect_relationship_via_docker_compose() {
        let temp_dir = TempDir::new().expect("should create temp dir");
        let temp_path = temp_dir.path();

        // Create docker-compose.yml with domain reference (0.2 points)
        let compose_path = temp_path.join("docker-compose.yml");
        let mut compose_file =
            std::fs::File::create(&compose_path).expect("should create docker-compose.yml");
        writeln!(compose_file, "services:").expect("should write to file");
        writeln!(compose_file, "  web:").expect("should write to file");
        writeln!(compose_file, "    environment:").expect("should write to file");
        writeln!(compose_file, "      - DOMAIN=example.com").expect("should write to file");

        // Add .env to push over 0.3 threshold (0.2 + 0.3 = 0.5)
        let env_path = temp_path.join(".env");
        let mut env_file =
            std::fs::File::create(&env_path).expect("should create .env file");
        writeln!(env_file, "API_URL=https://example.com/api").expect("should write to file");

        let mut collection = TargetCollection::new();
        collection.add_target(Target::parse("https://example.com").expect("should parse url"));
        collection.add_target(
            Target::parse(temp_path.to_str().expect("path should be valid utf-8"))
                .expect("should parse path"),
        );

        let hints = RelationshipDetector::detect(&collection);
        assert_eq!(hints.len(), 1, "Should detect one relationship");
        let first_hint = hints.first().expect("should have one hint");
        assert!(
            first_hint.confidence >= 0.5,
            "Confidence should be at least 0.5"
        );
        assert!(
            first_hint.reason.contains("docker-compose"),
            "Reason should mention docker-compose"
        );
    }

    #[test]
    fn test_high_confidence_with_multiple_signals() {
        let temp_dir = TempDir::new().expect("should create temp dir");
        let temp_path = temp_dir.path();

        // Create multiple files with domain reference
        let env_path = temp_path.join(".env");
        let mut env_file =
            std::fs::File::create(&env_path).expect("should create .env file");
        writeln!(env_file, "API_URL=https://example.com/api").expect("should write to file");

        let package_json = temp_path.join("package.json");
        let mut pkg_file =
            std::fs::File::create(&package_json).expect("should create package.json");
        writeln!(pkg_file, r#"{{"homepage": "https://example.com"}}"#).expect("should write to file");

        let config_path = temp_path.join("config.toml");
        let mut config_file =
            std::fs::File::create(&config_path).expect("should create config.toml");
        writeln!(config_file, "domain = \"example.com\"").expect("should write to file");

        let mut collection = TargetCollection::new();
        collection.add_target(Target::parse("https://example.com").expect("should parse url"));
        collection.add_target(
            Target::parse(temp_path.to_str().expect("path should be valid utf-8"))
                .expect("should parse path"),
        );

        let hints = RelationshipDetector::detect(&collection);
        assert_eq!(hints.len(), 1, "Should detect one relationship");
        let first_hint = hints.first().expect("should have one hint");
        // 0.3 (env) + 0.3 (package.json) + 0.4 (config) = 1.0
        assert!(
            first_hint.confidence >= 0.9,
            "Confidence should be high with multiple signals"
        );
        assert!(
            first_hint.reason.contains(","),
            "Reason should list multiple signals"
        );
    }

    #[test]
    fn test_no_relationship_different_domains() {
        let temp_dir = TempDir::new().expect("should create temp dir");
        let temp_path = temp_dir.path();

        // Create .env file with different domain
        let env_path = temp_path.join(".env");
        let mut env_file =
            std::fs::File::create(&env_path).expect("should create .env file");
        writeln!(env_file, "API_URL=https://different.com/api").expect("should write to file");

        let mut collection = TargetCollection::new();
        collection.add_target(Target::parse("https://example.com").expect("should parse url"));
        collection.add_target(
            Target::parse(temp_path.to_str().expect("path should be valid utf-8"))
                .expect("should parse path"),
        );

        let hints = RelationshipDetector::detect(&collection);
        assert!(
            hints.is_empty(),
            "Should not find relationship with different domain"
        );
    }

    #[test]
    fn test_case_insensitive_domain_matching() {
        let temp_dir = TempDir::new().expect("should create temp dir");
        let temp_path = temp_dir.path();

        // Create .env file with uppercase domain
        let env_path = temp_path.join(".env");
        let mut env_file =
            std::fs::File::create(&env_path).expect("should create .env file");
        writeln!(env_file, "API_URL=https://EXAMPLE.COM/api").expect("should write to file");

        let mut collection = TargetCollection::new();
        collection.add_target(Target::parse("https://example.com").expect("should parse url"));
        collection.add_target(
            Target::parse(temp_path.to_str().expect("path should be valid utf-8"))
                .expect("should parse path"),
        );

        let hints = RelationshipDetector::detect(&collection);
        assert_eq!(
            hints.len(),
            1,
            "Should detect relationship case-insensitively"
        );
    }

    #[test]
    fn test_subdomain_detection() {
        let temp_dir = TempDir::new().expect("should create temp dir");
        let temp_path = temp_dir.path();

        // Create .env file with subdomain reference
        let env_path = temp_path.join(".env");
        let mut env_file =
            std::fs::File::create(&env_path).expect("should create .env file");
        writeln!(env_file, "API_URL=https://api.example.com").expect("should write to file");

        let mut collection = TargetCollection::new();
        collection.add_target(Target::parse("https://api.example.com").expect("should parse url"));
        collection.add_target(
            Target::parse(temp_path.to_str().expect("path should be valid utf-8"))
                .expect("should parse path"),
        );

        let hints = RelationshipDetector::detect(&collection);
        assert_eq!(hints.len(), 1, "Should detect subdomain relationship");
    }
}
