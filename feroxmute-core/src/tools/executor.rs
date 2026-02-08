//! Tool execution within Docker container

use chrono::{DateTime, Utc};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::Result;
use crate::docker::{ContainerManager, ExecResult};
use crate::state::MetricsTracker;

/// A security tool definition (renamed from Tool to avoid conflict with rig::tool::Tool)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDef {
    pub name: String,
    pub command: String,
    pub description: String,
    pub json_output: bool,
}

impl ToolDef {
    pub fn new(name: impl Into<String>, command: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            command: command.into(),
            description: String::new(),
            json_output: false,
        }
    }

    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    pub fn with_json_output(mut self) -> Self {
        self.json_output = true;
        self
    }
}

/// Record of a tool execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolExecution {
    pub id: String,
    pub agent: String,
    pub tool: String,
    pub args: Vec<String>,
    pub output: Option<String>,
    pub exit_code: Option<i64>,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

impl ToolExecution {
    /// Create a new tool execution record
    pub fn new(agent: impl Into<String>, tool: impl Into<String>, args: Vec<String>) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            agent: agent.into(),
            tool: tool.into(),
            args,
            output: None,
            exit_code: None,
            started_at: Utc::now(),
            completed_at: None,
        }
    }

    /// Record completion
    pub fn complete(&mut self, result: &ExecResult) {
        self.output = Some(result.output());
        self.exit_code = Some(result.exit_code);
        self.completed_at = Some(Utc::now());
    }

    /// Save to database
    pub fn save(&self, conn: &Connection) -> Result<()> {
        conn.execute(
            "INSERT INTO tool_executions
             (id, agent, tool, args, output, exit_code, started_at, completed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                self.id,
                self.agent,
                self.tool,
                serde_json::to_string(&self.args)?,
                self.output,
                self.exit_code,
                self.started_at.to_rfc3339(),
                self.completed_at.map(|dt| dt.to_rfc3339()),
            ],
        )?;
        Ok(())
    }
}

/// Tool executor that runs commands in the Docker container
pub struct ToolExecutor {
    container: ContainerManager,
    metrics: MetricsTracker,
}

impl ToolExecutor {
    /// Create a new tool executor
    pub fn new(container: ContainerManager, metrics: MetricsTracker) -> Self {
        Self { container, metrics }
    }

    /// Execute a tool with arguments
    pub async fn execute(
        &self,
        tool: &ToolDef,
        args: &[&str],
        workdir: Option<&str>,
        agent: &str,
        conn: &Connection,
    ) -> Result<ToolExecution> {
        // Build command
        let mut cmd = vec![&tool.command[..]];
        cmd.extend(args);

        // Create execution record
        let mut execution = ToolExecution::new(
            agent,
            &tool.name,
            args.iter().map(|s| s.to_string()).collect(),
        );

        // Execute in container
        let result = self.container.exec(cmd, workdir).await?;

        // Record completion
        execution.complete(&result);

        // Update metrics
        self.metrics.record_tool_call();

        // Save to database
        execution.save(conn)?;

        Ok(execution)
    }

    /// Execute a raw command (for tools not in registry)
    pub async fn execute_raw(
        &self,
        cmd: Vec<&str>,
        workdir: Option<&str>,
        agent: &str,
        conn: &Connection,
    ) -> Result<ToolExecution> {
        let tool_name = cmd.first().copied().unwrap_or("unknown");

        let mut execution = ToolExecution::new(
            agent,
            tool_name,
            cmd.iter().skip(1).map(|s| s.to_string()).collect(),
        );

        let result = self.container.exec(cmd, workdir).await?;
        execution.complete(&result);

        self.metrics.record_tool_call();
        execution.save(conn)?;

        Ok(execution)
    }
}

/// Registry of available tools
pub struct ToolRegistry {
    tools: Vec<ToolDef>,
}

impl Default for ToolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ToolRegistry {
    /// Create a new tool registry with default tools
    pub fn new() -> Self {
        let tools = vec![
            // ProjectDiscovery - Discovery
            ToolDef::new("subfinder", "subfinder")
                .with_description("Subdomain enumeration")
                .with_json_output(),
            ToolDef::new("naabu", "naabu")
                .with_description("Port scanning")
                .with_json_output(),
            ToolDef::new("httpx", "httpx")
                .with_description("HTTP probing")
                .with_json_output(),
            ToolDef::new("katana", "katana")
                .with_description("Web crawling")
                .with_json_output(),
            ToolDef::new("dnsx", "dnsx")
                .with_description("DNS resolution")
                .with_json_output(),
            ToolDef::new("tlsx", "tlsx")
                .with_description("TLS analysis")
                .with_json_output(),
            ToolDef::new("asnmap", "asnmap")
                .with_description("ASN mapping")
                .with_json_output(),
            ToolDef::new("uncover", "uncover")
                .with_description("Asset discovery")
                .with_json_output(),
            // ProjectDiscovery - Detection
            ToolDef::new("nuclei", "nuclei")
                .with_description("Vulnerability scanning")
                .with_json_output(),
            // Other tools
            ToolDef::new("sqlmap", "sqlmap").with_description("SQL injection testing"),
            ToolDef::new("feroxbuster", "feroxbuster")
                .with_description("Directory bruteforcing")
                .with_json_output(),
            ToolDef::new("ffuf", "ffuf")
                .with_description("Fuzzing")
                .with_json_output(),
            ToolDef::new("nmap", "nmap").with_description("Network scanning"),
            ToolDef::new("whois", "whois").with_description("WHOIS lookup"),
            ToolDef::new("dig", "dig").with_description("DNS queries"),
        ];

        Self { tools }
    }

    /// Get a tool by name
    pub fn get(&self, name: &str) -> Option<&ToolDef> {
        self.tools.iter().find(|t| t.name == name)
    }

    /// Get all tools
    pub fn all(&self) -> &[ToolDef] {
        &self.tools
    }

    /// Get tools that output JSON
    pub fn json_tools(&self) -> Vec<&ToolDef> {
        self.tools.iter().filter(|t| t.json_output).collect()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn test_tool_registry() {
        let registry = ToolRegistry::new();

        assert!(registry.get("subfinder").is_some());
        assert!(registry.get("nuclei").is_some());
        assert!(registry.get("nonexistent").is_none());

        let json_tools = registry.json_tools();
        assert!(json_tools.iter().any(|t| t.name == "httpx"));
    }

    #[test]
    fn test_tool_execution_record() {
        let mut exec = ToolExecution::new(
            "recon",
            "subfinder",
            vec!["-d".to_string(), "example.com".to_string()],
        );

        assert!(exec.output.is_none());
        assert!(exec.completed_at.is_none());

        let result = ExecResult {
            stdout: "found.example.com".to_string(),
            stderr: String::new(),
            exit_code: 0,
        };

        exec.complete(&result);

        assert_eq!(exec.output, Some("found.example.com".to_string()));
        assert_eq!(exec.exit_code, Some(0));
        assert!(exec.completed_at.is_some());
    }

    #[test]
    fn test_tool_execution_save_to_db() {
        use crate::state::migrations::run_migrations;
        use rusqlite::Connection;

        let conn = Connection::open_in_memory().unwrap();
        run_migrations(&conn).unwrap();

        let mut exec = ToolExecution::new(
            "recon",
            "nmap",
            vec!["-sV".to_string(), "localhost".to_string()],
        );
        let result = ExecResult {
            stdout: "22/tcp open ssh".to_string(),
            stderr: String::new(),
            exit_code: 0,
        };
        exec.complete(&result);
        exec.save(&conn).unwrap();

        // Query back
        let mut stmt = conn
            .prepare("SELECT agent, tool, output FROM tool_executions WHERE id = ?1")
            .unwrap();
        let (agent, tool, output): (String, String, Option<String>) = stmt
            .query_row([&exec.id], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .unwrap();
        assert_eq!(agent, "recon");
        assert_eq!(tool, "nmap");
        assert_eq!(output.unwrap(), "22/tcp open ssh");
    }

    #[test]
    fn test_tool_registry_all() {
        let registry = ToolRegistry::new();
        let all = registry.all();
        assert!(!all.is_empty(), "registry should have tools");
        assert!(all.iter().any(|t| t.name == "nmap"));
        assert!(all.iter().any(|t| t.name == "subfinder"));
    }

    #[test]
    fn test_tool_registry_json_tools_subset() {
        let registry = ToolRegistry::new();
        let json_tools = registry.json_tools();
        for tool in &json_tools {
            assert!(
                tool.json_output,
                "json_tools() should only return tools with json_output=true"
            );
        }
    }
}
