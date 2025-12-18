use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq)]
pub enum TargetType {
    Web { url: String },
    Directory { path: PathBuf },
    Repository { url: String, local_path: Option<PathBuf> },
}

#[derive(Debug, Clone)]
pub struct Target {
    pub raw: String,
    pub target_type: TargetType,
    pub linked_to: Option<String>,
}

impl Target {
    pub fn parse(input: &str) -> Result<Self, TargetParseError> {
        let input = input.trim();

        // Check for HTTP/HTTPS URLs (but not git hosts)
        if input.starts_with("http://") || input.starts_with("https://") {
            // Check if it's a git repository URL
            if Self::is_git_host(input) {
                return Ok(Self {
                    raw: input.to_string(),
                    target_type: TargetType::Repository {
                        url: input.to_string(),
                        local_path: None,
                    },
                    linked_to: None,
                });
            }
            return Ok(Self {
                raw: input.to_string(),
                target_type: TargetType::Web { url: input.to_string() },
                linked_to: None,
            });
        }

        // Check for git SSH URLs
        if input.starts_with("git@") || input.ends_with(".git") {
            return Ok(Self {
                raw: input.to_string(),
                target_type: TargetType::Repository {
                    url: input.to_string(),
                    local_path: None,
                },
                linked_to: None,
            });
        }

        // Check if it's a local path
        let path = PathBuf::from(input);
        if path.exists() {
            return Ok(Self {
                raw: input.to_string(),
                target_type: TargetType::Directory { path },
                linked_to: None,
            });
        }

        // Check if it looks like a relative path (starts with ./ or ../)
        if input.starts_with("./") || input.starts_with("../") {
            return Err(TargetParseError::PathNotFound(input.to_string()));
        }

        // Default: treat as domain (web target)
        Ok(Self {
            raw: input.to_string(),
            target_type: TargetType::Web {
                url: format!("https://{}", input),
            },
            linked_to: None,
        })
    }

    fn is_git_host(url: &str) -> bool {
        let git_hosts = ["github.com", "gitlab.com", "bitbucket.org", "codeberg.org"];
        git_hosts.iter().any(|host| url.contains(host))
    }

    pub fn is_source(&self) -> bool {
        matches!(self.target_type, TargetType::Directory { .. } | TargetType::Repository { .. })
    }

    pub fn is_web(&self) -> bool {
        matches!(self.target_type, TargetType::Web { .. })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TargetParseError {
    #[error("Invalid target: {0}")]
    Invalid(String),
    #[error("Path does not exist: {0}")]
    PathNotFound(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_https_url() {
        let target = Target::parse("https://example.com").unwrap();
        assert!(matches!(target.target_type, TargetType::Web { url } if url == "https://example.com"));
    }

    #[test]
    fn test_parse_http_url() {
        let target = Target::parse("http://example.com").unwrap();
        assert!(matches!(target.target_type, TargetType::Web { .. }));
    }

    #[test]
    fn test_parse_domain_as_web() {
        let target = Target::parse("example.com").unwrap();
        assert!(matches!(target.target_type, TargetType::Web { .. }));
    }

    #[test]
    fn test_parse_github_url() {
        let target = Target::parse("https://github.com/owner/repo").unwrap();
        assert!(matches!(target.target_type, TargetType::Repository { .. }));
    }

    #[test]
    fn test_parse_git_ssh_url() {
        let target = Target::parse("git@github.com:owner/repo.git").unwrap();
        assert!(matches!(target.target_type, TargetType::Repository { .. }));
    }

    #[test]
    fn test_is_source() {
        let dir = Target {
            raw: "./src".to_string(),
            target_type: TargetType::Directory { path: PathBuf::from("./src") },
            linked_to: None,
        };
        assert!(dir.is_source());
        assert!(!dir.is_web());
    }
}
