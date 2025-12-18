//! Static Application Security Testing (SAST) agent

use async_trait::async_trait;
use serde_json::json;
use std::path::PathBuf;

use crate::agents::prompts::Prompts;
use crate::agents::traits::{Agent, AgentContext, AgentStatus, AgentTask};
use crate::providers::traits::ToolDefinition;
use crate::state::models::{CodeFinding, FindingType, Severity};
use crate::tools::sast::{
    AstGrepOutput, GitleaksOutput, GrypeOutput, SastToolOutput, SemgrepOutput,
};
use crate::Result;

/// SAST agent for static code analysis and dependency scanning
pub struct SastAgent {
    status: AgentStatus,
    thinking: Option<String>,
    prompts: Prompts,
    source_path: PathBuf,
    detected_languages: Vec<String>,
}

impl SastAgent {
    /// Create a new SAST agent with a source path
    pub fn new(source_path: PathBuf) -> Self {
        Self {
            status: AgentStatus::Idle,
            thinking: None,
            prompts: Prompts::default(),
            source_path,
            detected_languages: Vec::new(),
        }
    }

    /// Create with custom prompts
    pub fn with_prompts(prompts: Prompts) -> Self {
        Self {
            status: AgentStatus::Idle,
            thinking: None,
            prompts,
            source_path: PathBuf::from("."),
            detected_languages: Vec::new(),
        }
    }

    /// Set the source path for analysis
    pub fn set_source_path(&mut self, path: PathBuf) {
        self.source_path = path;
    }

    /// Preload detected languages
    pub fn with_languages(mut self, languages: Vec<String>) -> Self {
        self.detected_languages = languages;
        self
    }

    /// Detect programming languages in the source directory
    async fn detect_languages(&mut self, ctx: &AgentContext<'_>) -> Result<()> {
        let path = self.source_path.to_string_lossy();

        // Check for various manifest/config files
        let checks = vec![
            ("package.json", "javascript"),
            ("Cargo.toml", "rust"),
            ("requirements.txt", "python"),
            ("pyproject.toml", "python"),
            ("go.mod", "go"),
            ("pom.xml", "java"),
            ("build.gradle", "java"),
            ("Gemfile", "ruby"),
            ("composer.json", "php"),
        ];

        for (file, lang) in checks {
            let result = ctx
                .executor
                .execute_raw(
                    vec!["test", "-f", &format!("{}/{}", path, file)],
                    None,
                    "sast",
                    ctx.conn,
                )
                .await;

            if let Ok(exec) = result {
                if exec.exit_code == Some(0) && !self.detected_languages.contains(&lang.to_string())
                {
                    self.detected_languages.push(lang.to_string());
                }
            }
        }

        Ok(())
    }

    /// Run dependency vulnerability scan using Grype
    async fn run_dependency_scan(&self, ctx: &AgentContext<'_>) -> Result<Vec<CodeFinding>> {
        let path = self.source_path.to_string_lossy();
        let mut findings = Vec::new();

        // Run grype for dependency scanning
        let result = ctx
            .executor
            .execute_raw(
                vec!["grype", &path.to_string(), "-o", "json"],
                None,
                "sast",
                ctx.conn,
            )
            .await?;

        if let Some(output) = result.output {
            if let Ok(grype_output) = GrypeOutput::parse(&output) {
                findings.extend(grype_output.to_code_findings());
            }
        }

        Ok(findings)
    }

    /// Run static code analysis using Semgrep and ast-grep
    async fn run_code_scan(&self, ctx: &AgentContext<'_>) -> Result<Vec<CodeFinding>> {
        let path = self.source_path.to_string_lossy();
        let mut findings = Vec::new();

        // Run semgrep
        let result = ctx
            .executor
            .execute_raw(
                vec![
                    "semgrep",
                    "scan",
                    "--config",
                    "auto",
                    "--json",
                    &path.to_string(),
                ],
                None,
                "sast",
                ctx.conn,
            )
            .await?;

        if let Some(output) = result.output {
            if let Ok(semgrep_output) = SemgrepOutput::parse(&output) {
                findings.extend(semgrep_output.to_code_findings());
            }
        }

        // Run ast-grep if available
        let result = ctx
            .executor
            .execute_raw(
                vec!["ast-grep", "scan", "--json", &path.to_string()],
                None,
                "sast",
                ctx.conn,
            )
            .await;

        // ast-grep is optional, don't fail if not available
        if let Ok(exec) = result {
            if let Some(output) = exec.output {
                if let Ok(ast_output) = AstGrepOutput::parse(&output) {
                    findings.extend(ast_output.to_code_findings());
                }
            }
        }

        Ok(findings)
    }

    /// Run secret scanning using Gitleaks
    async fn run_secret_scan(&self, ctx: &AgentContext<'_>) -> Result<Vec<CodeFinding>> {
        let path = self.source_path.to_string_lossy();

        let result = ctx
            .executor
            .execute_raw(
                vec![
                    "gitleaks",
                    "detect",
                    "--source",
                    &path.to_string(),
                    "--report-format",
                    "json",
                    "--report-path",
                    "/dev/stdout",
                ],
                None,
                "sast",
                ctx.conn,
            )
            .await;

        // Gitleaks may exit with non-zero if secrets found
        if let Ok(exec) = result {
            if let Some(output) = exec.output {
                if !output.trim().is_empty() {
                    if let Ok(gitleaks_output) = GitleaksOutput::parse(&output) {
                        return Ok(gitleaks_output.to_code_findings());
                    }
                }
            }
        }

        Ok(Vec::new())
    }

    /// Read a file from the source directory
    #[allow(dead_code)]
    async fn read_file(&self, ctx: &AgentContext<'_>, relative_path: &str) -> Result<String> {
        let full_path = self.source_path.join(relative_path);
        let path_str = full_path.to_string_lossy();

        let result = ctx
            .executor
            .execute_raw(vec!["cat", &path_str], None, "sast", ctx.conn)
            .await?;

        Ok(result.output.unwrap_or_default())
    }
}

impl Default for SastAgent {
    fn default() -> Self {
        Self::new(PathBuf::from("."))
    }
}

#[async_trait(?Send)]
impl Agent for SastAgent {
    fn name(&self) -> &str {
        "sast"
    }

    fn status(&self) -> AgentStatus {
        self.status
    }

    fn set_status(&mut self, status: AgentStatus) {
        self.status = status;
    }

    fn system_prompt(&self) -> &str {
        self.prompts
            .get("sast")
            .unwrap_or("You are a static analysis security expert.")
    }

    fn thinking(&self) -> Option<&str> {
        self.thinking.as_deref()
    }

    fn tools(&self) -> Vec<ToolDefinition> {
        vec![
            ToolDefinition {
                name: "run_semgrep".to_string(),
                description: "Run semgrep static analysis on the source code".to_string(),
                parameters: json!({
                    "type": "object",
                    "properties": {
                        "config": {
                            "type": "string",
                            "description": "Semgrep config (auto, p/security-audit, etc.)"
                        }
                    }
                }),
            },
            ToolDefinition {
                name: "run_grype".to_string(),
                description: "Scan dependencies for known vulnerabilities".to_string(),
                parameters: json!({
                    "type": "object",
                    "properties": {}
                }),
            },
            ToolDefinition {
                name: "run_gitleaks".to_string(),
                description: "Scan for hardcoded secrets and credentials".to_string(),
                parameters: json!({
                    "type": "object",
                    "properties": {}
                }),
            },
            ToolDefinition {
                name: "run_ast_grep".to_string(),
                description: "Run ast-grep for semantic code pattern matching".to_string(),
                parameters: json!({
                    "type": "object",
                    "properties": {
                        "pattern": {
                            "type": "string",
                            "description": "The ast-grep pattern to search for"
                        }
                    }
                }),
            },
            ToolDefinition {
                name: "read_file".to_string(),
                description: "Read a source file for manual analysis".to_string(),
                parameters: json!({
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Path to file relative to source root"
                        }
                    },
                    "required": ["path"]
                }),
            },
        ]
    }

    async fn execute(&mut self, _task: &AgentTask, ctx: &AgentContext<'_>) -> Result<String> {
        self.status = AgentStatus::Running;
        self.thinking = Some("Detecting project languages and dependencies...".to_string());

        // Detect languages
        self.detect_languages(ctx).await?;

        let mut all_findings: Vec<CodeFinding> = Vec::new();

        // Run dependency scan
        self.thinking = Some("Running dependency vulnerability scan (grype)...".to_string());
        let dep_findings = self.run_dependency_scan(ctx).await?;
        all_findings.extend(dep_findings);

        // Run code scan
        self.thinking = Some("Running static code analysis (semgrep, ast-grep)...".to_string());
        let code_findings = self.run_code_scan(ctx).await?;
        all_findings.extend(code_findings);

        // Run secret scan
        self.thinking = Some("Scanning for hardcoded secrets (gitleaks)...".to_string());
        let secret_findings = self.run_secret_scan(ctx).await?;
        all_findings.extend(secret_findings);

        // Store all findings in database
        for finding in &all_findings {
            finding.insert(ctx.conn)?;
        }

        // Generate summary
        let critical = all_findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .count();
        let high = all_findings
            .iter()
            .filter(|f| f.severity == Severity::High)
            .count();
        let medium = all_findings
            .iter()
            .filter(|f| f.severity == Severity::Medium)
            .count();
        let deps = all_findings
            .iter()
            .filter(|f| f.finding_type == FindingType::Dependency)
            .count();
        let secrets = all_findings
            .iter()
            .filter(|f| f.finding_type == FindingType::Secret)
            .count();

        self.status = AgentStatus::Completed;
        self.thinking = None;

        Ok(format!(
            "Static analysis complete. Found {} findings:\n\
             - Critical: {}\n\
             - High: {}\n\
             - Medium: {}\n\
             - Dependency issues: {}\n\
             - Hardcoded secrets: {}\n\
             Detected languages: {}",
            all_findings.len(),
            critical,
            high,
            medium,
            deps,
            secrets,
            self.detected_languages.join(", ")
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sast_agent_creation() {
        let agent = SastAgent::new(PathBuf::from("/tmp/test"));
        assert_eq!(agent.name(), "sast");
        assert_eq!(agent.status(), AgentStatus::Idle);
        assert_eq!(agent.source_path, PathBuf::from("/tmp/test"));
    }

    #[test]
    fn test_sast_agent_tools() {
        let agent = SastAgent::new(PathBuf::from("."));
        let tools = agent.tools();

        assert!(!tools.is_empty());
        assert!(tools.iter().any(|t| t.name == "run_semgrep"));
        assert!(tools.iter().any(|t| t.name == "run_grype"));
        assert!(tools.iter().any(|t| t.name == "run_gitleaks"));
        assert!(tools.iter().any(|t| t.name == "run_ast_grep"));
        assert!(tools.iter().any(|t| t.name == "read_file"));
    }

    #[test]
    fn test_sast_agent_with_languages() {
        let agent = SastAgent::new(PathBuf::from("."))
            .with_languages(vec!["rust".to_string(), "python".to_string()]);
        assert_eq!(agent.detected_languages.len(), 2);
        assert!(agent.detected_languages.contains(&"rust".to_string()));
    }
}
