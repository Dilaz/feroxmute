//! Web scanner agent for vulnerability detection

use async_trait::async_trait;
use serde_json::json;

use crate::providers::{CompletionRequest, Message, ToolDefinition};
use crate::{Error, Result};

use super::{Agent, AgentContext, AgentStatus, AgentTask, Prompts};

/// Web scanner agent for vulnerability detection
pub struct ScannerAgent {
    status: AgentStatus,
    thinking: Option<String>,
    prompts: Prompts,
}

impl ScannerAgent {
    /// Create a new scanner agent
    pub fn new() -> Self {
        Self {
            status: AgentStatus::Idle,
            thinking: None,
            prompts: Prompts::default(),
        }
    }

    /// Create with custom prompts
    pub fn with_prompts(prompts: Prompts) -> Self {
        Self {
            status: AgentStatus::Idle,
            thinking: None,
            prompts,
        }
    }

    /// Build tool definitions for this agent
    fn build_tools(&self) -> Vec<ToolDefinition> {
        vec![
            ToolDefinition {
                name: "nuclei".to_string(),
                description: "Vulnerability scanner using nuclei templates".to_string(),
                parameters: json!({
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "Target URL or host to scan"
                        },
                        "templates": {
                            "type": "string",
                            "description": "Template tags to use (e.g., 'cve,oast,sqli')"
                        },
                        "severity": {
                            "type": "string",
                            "description": "Minimum severity (info, low, medium, high, critical)"
                        },
                        "rate_limit": {
                            "type": "integer",
                            "description": "Requests per second limit"
                        }
                    },
                    "required": ["target"]
                }),
            },
            ToolDefinition {
                name: "feroxbuster".to_string(),
                description: "Directory and file bruteforcing tool".to_string(),
                parameters: json!({
                    "type": "object",
                    "properties": {
                        "url": {
                            "type": "string",
                            "description": "Target URL to brute force"
                        },
                        "wordlist": {
                            "type": "string",
                            "description": "Path to wordlist file"
                        },
                        "extensions": {
                            "type": "string",
                            "description": "File extensions to check (e.g., 'php,html,js')"
                        },
                        "depth": {
                            "type": "integer",
                            "description": "Recursion depth"
                        }
                    },
                    "required": ["url"]
                }),
            },
            ToolDefinition {
                name: "ffuf".to_string(),
                description: "Fast fuzzer for web applications".to_string(),
                parameters: json!({
                    "type": "object",
                    "properties": {
                        "url": {
                            "type": "string",
                            "description": "Target URL with FUZZ keyword for fuzzing position"
                        },
                        "wordlist": {
                            "type": "string",
                            "description": "Path to wordlist file"
                        },
                        "filter_code": {
                            "type": "string",
                            "description": "Filter out responses with these status codes"
                        },
                        "match_code": {
                            "type": "string",
                            "description": "Only show responses with these status codes"
                        }
                    },
                    "required": ["url", "wordlist"]
                }),
            },
            ToolDefinition {
                name: "sqlmap".to_string(),
                description: "SQL injection detection and exploitation".to_string(),
                parameters: json!({
                    "type": "object",
                    "properties": {
                        "url": {
                            "type": "string",
                            "description": "Target URL with parameter"
                        },
                        "data": {
                            "type": "string",
                            "description": "POST data string"
                        },
                        "level": {
                            "type": "integer",
                            "description": "Level of tests (1-5)"
                        },
                        "risk": {
                            "type": "integer",
                            "description": "Risk of tests (1-3)"
                        },
                        "batch": {
                            "type": "boolean",
                            "description": "Non-interactive mode"
                        }
                    },
                    "required": ["url"]
                }),
            },
            ToolDefinition {
                name: "report_vulnerability".to_string(),
                description: "Report a confirmed vulnerability finding".to_string(),
                parameters: json!({
                    "type": "object",
                    "properties": {
                        "title": {
                            "type": "string",
                            "description": "Vulnerability title"
                        },
                        "severity": {
                            "type": "string",
                            "description": "Severity: critical, high, medium, low, info"
                        },
                        "description": {
                            "type": "string",
                            "description": "Detailed description of the vulnerability"
                        },
                        "endpoint": {
                            "type": "string",
                            "description": "Affected endpoint/URL"
                        },
                        "evidence": {
                            "type": "string",
                            "description": "Proof of concept or evidence"
                        },
                        "remediation": {
                            "type": "string",
                            "description": "Suggested fix"
                        }
                    },
                    "required": ["title", "severity", "description", "endpoint"]
                }),
            },
        ]
    }
}

impl Default for ScannerAgent {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait(?Send)]
impl Agent for ScannerAgent {
    fn name(&self) -> &str {
        "scanner"
    }

    fn status(&self) -> AgentStatus {
        self.status
    }

    fn system_prompt(&self) -> &str {
        self.prompts.get("scanner").unwrap_or("")
    }

    fn tools(&self) -> Vec<ToolDefinition> {
        self.build_tools()
    }

    async fn execute(&mut self, task: &AgentTask, ctx: &AgentContext<'_>) -> Result<String> {
        self.status = AgentStatus::Running;
        self.thinking = Some(format!(
            "Starting vulnerability scan for task: {}",
            task.description
        ));

        // Build initial message
        let task_message = format!(
            "Target: {}\nTask: {}\n\nContext: {}",
            ctx.target,
            task.description,
            task.context.as_deref().unwrap_or("None")
        );

        let mut messages = vec![Message::user(&task_message)];
        let mut result = String::new();
        let mut vulnerabilities_found = Vec::new();
        let max_iterations = 10;

        for iteration in 0..max_iterations {
            self.thinking = Some(format!(
                "Iteration {}: Planning next scan...",
                iteration + 1
            ));

            // Make completion request
            let request = CompletionRequest::new(messages.clone())
                .with_system(self.system_prompt())
                .with_tools(self.tools())
                .with_max_tokens(4096);

            let response = ctx.provider.complete(request).await?;

            // Handle response
            if !response.tool_calls.is_empty() {
                self.status = AgentStatus::Running;

                for tool_call in &response.tool_calls {
                    self.thinking = Some(format!("Executing tool: {}", tool_call.name));

                    // Parse arguments
                    let args: serde_json::Value = serde_json::from_str(&tool_call.arguments)
                        .map_err(|e| Error::Provider(format!("Invalid tool arguments: {}", e)))?;

                    // Handle report_vulnerability specially
                    if tool_call.name == "report_vulnerability" {
                        let vuln_report = self.handle_vulnerability_report(&args);
                        vulnerabilities_found.push(vuln_report.clone());
                        result.push_str(&format!("\n## Vulnerability Found\n{}\n", vuln_report));
                        messages.push(Message::assistant(format!(
                            "Vulnerability recorded: {}",
                            args.get("title")
                                .and_then(|v| v.as_str())
                                .unwrap_or("Unknown")
                        )));
                    } else {
                        // Execute the scanning tool
                        let cmd_args = self.build_command_args(&tool_call.name, &args);

                        let execution = ctx
                            .executor
                            .execute_raw(
                                cmd_args.iter().map(|s| s.as_str()).collect(),
                                None,
                                self.name(),
                                ctx.conn,
                            )
                            .await?;

                        let tool_result =
                            execution.output.unwrap_or_else(|| "No output".to_string());
                        messages.push(Message::assistant(format!(
                            "Tool {} executed. Result:\n{}",
                            tool_call.name, tool_result
                        )));
                        messages.push(Message::user(
                            "Analyze the results and continue scanning or report findings.",
                        ));

                        result.push_str(&format!(
                            "\n## {} Output\n{}\n",
                            tool_call.name, tool_result
                        ));
                    }
                }
            } else if let Some(content) = response.content {
                self.thinking = Some("Analyzing scan results...".to_string());
                result.push_str(&format!("\n## Analysis\n{}\n", content));

                // Check if the LLM indicates completion
                if content.to_lowercase().contains("scan complete")
                    || content.to_lowercase().contains("vulnerability summary")
                {
                    break;
                }

                messages.push(Message::assistant(&content));
                messages.push(Message::user(
                    "Continue scanning or provide a summary of findings.",
                ));
            } else {
                break;
            }
        }

        // Add summary of vulnerabilities
        if !vulnerabilities_found.is_empty() {
            result.push_str("\n## Vulnerability Summary\n");
            result.push_str(&format!(
                "Total vulnerabilities found: {}\n",
                vulnerabilities_found.len()
            ));
            for (i, vuln) in vulnerabilities_found.iter().enumerate() {
                result.push_str(&format!("\n{}. {}\n", i + 1, vuln));
            }
        }

        self.status = AgentStatus::Completed;
        self.thinking = Some("Scanning completed".to_string());

        Ok(result)
    }

    fn thinking(&self) -> Option<&str> {
        self.thinking.as_deref()
    }

    fn set_status(&mut self, status: AgentStatus) {
        self.status = status;
    }
}

impl ScannerAgent {
    /// Build command arguments for a tool invocation
    fn build_command_args(&self, tool: &str, args: &serde_json::Value) -> Vec<String> {
        let mut cmd = vec![tool.to_string()];

        match tool {
            "nuclei" => {
                if let Some(target) = args.get("target").and_then(|v| v.as_str()) {
                    cmd.extend(["-u".to_string(), target.to_string()]);
                }
                if let Some(templates) = args.get("templates").and_then(|v| v.as_str()) {
                    cmd.extend(["-tags".to_string(), templates.to_string()]);
                }
                if let Some(severity) = args.get("severity").and_then(|v| v.as_str()) {
                    cmd.extend(["-severity".to_string(), severity.to_string()]);
                }
                if let Some(rate) = args.get("rate_limit").and_then(|v| v.as_i64()) {
                    cmd.extend(["-rl".to_string(), rate.to_string()]);
                }
                cmd.push("-json".to_string());
            }
            "feroxbuster" => {
                if let Some(url) = args.get("url").and_then(|v| v.as_str()) {
                    cmd.extend(["-u".to_string(), url.to_string()]);
                }
                if let Some(wordlist) = args.get("wordlist").and_then(|v| v.as_str()) {
                    cmd.extend(["-w".to_string(), wordlist.to_string()]);
                } else {
                    cmd.extend([
                        "-w".to_string(),
                        "/usr/share/seclists/Discovery/Web-Content/common.txt".to_string(),
                    ]);
                }
                if let Some(ext) = args.get("extensions").and_then(|v| v.as_str()) {
                    cmd.extend(["-x".to_string(), ext.to_string()]);
                }
                if let Some(depth) = args.get("depth").and_then(|v| v.as_i64()) {
                    cmd.extend(["-d".to_string(), depth.to_string()]);
                }
                cmd.push("--json".to_string());
            }
            "ffuf" => {
                if let Some(url) = args.get("url").and_then(|v| v.as_str()) {
                    cmd.extend(["-u".to_string(), url.to_string()]);
                }
                if let Some(wordlist) = args.get("wordlist").and_then(|v| v.as_str()) {
                    cmd.extend(["-w".to_string(), wordlist.to_string()]);
                }
                if let Some(fc) = args.get("filter_code").and_then(|v| v.as_str()) {
                    cmd.extend(["-fc".to_string(), fc.to_string()]);
                }
                if let Some(mc) = args.get("match_code").and_then(|v| v.as_str()) {
                    cmd.extend(["-mc".to_string(), mc.to_string()]);
                }
                cmd.extend(["-of".to_string(), "json".to_string()]);
            }
            "sqlmap" => {
                if let Some(url) = args.get("url").and_then(|v| v.as_str()) {
                    cmd.extend(["-u".to_string(), url.to_string()]);
                }
                if let Some(data) = args.get("data").and_then(|v| v.as_str()) {
                    cmd.extend(["--data".to_string(), data.to_string()]);
                }
                if let Some(level) = args.get("level").and_then(|v| v.as_i64()) {
                    cmd.extend(["--level".to_string(), level.to_string()]);
                }
                if let Some(risk) = args.get("risk").and_then(|v| v.as_i64()) {
                    cmd.extend(["--risk".to_string(), risk.to_string()]);
                }
                if args.get("batch").and_then(|v| v.as_bool()).unwrap_or(true) {
                    cmd.push("--batch".to_string());
                }
            }
            _ => {}
        }

        cmd
    }

    /// Handle vulnerability reporting
    fn handle_vulnerability_report(&self, args: &serde_json::Value) -> String {
        let title = args
            .get("title")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown");
        let severity = args
            .get("severity")
            .and_then(|v| v.as_str())
            .unwrap_or("info");
        let description = args
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let endpoint = args.get("endpoint").and_then(|v| v.as_str()).unwrap_or("");
        let evidence = args
            .get("evidence")
            .and_then(|v| v.as_str())
            .unwrap_or("N/A");
        let remediation = args
            .get("remediation")
            .and_then(|v| v.as_str())
            .unwrap_or("N/A");

        format!(
            "**{}** [{}]\n\
            Endpoint: {}\n\
            Description: {}\n\
            Evidence: {}\n\
            Remediation: {}",
            title,
            severity.to_uppercase(),
            endpoint,
            description,
            evidence,
            remediation
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_agent_creation() {
        let agent = ScannerAgent::new();
        assert_eq!(agent.name(), "scanner");
        assert_eq!(agent.status(), AgentStatus::Idle);
    }

    #[test]
    fn test_scanner_agent_tools() {
        let agent = ScannerAgent::new();
        let tools = agent.tools();

        assert!(!tools.is_empty());
        assert!(tools.iter().any(|t| t.name == "nuclei"));
        assert!(tools.iter().any(|t| t.name == "feroxbuster"));
        assert!(tools.iter().any(|t| t.name == "ffuf"));
        assert!(tools.iter().any(|t| t.name == "sqlmap"));
        assert!(tools.iter().any(|t| t.name == "report_vulnerability"));
    }

    #[test]
    fn test_build_nuclei_args() {
        let agent = ScannerAgent::new();
        let args = json!({
            "target": "https://example.com",
            "templates": "cve,sqli",
            "severity": "high"
        });
        let cmd = agent.build_command_args("nuclei", &args);

        assert_eq!(cmd[0], "nuclei");
        assert!(cmd.contains(&"-u".to_string()));
        assert!(cmd.contains(&"https://example.com".to_string()));
        assert!(cmd.contains(&"-tags".to_string()));
        assert!(cmd.contains(&"-severity".to_string()));
        assert!(cmd.contains(&"-json".to_string()));
    }

    #[test]
    fn test_vulnerability_report() {
        let agent = ScannerAgent::new();
        let args = json!({
            "title": "SQL Injection",
            "severity": "high",
            "description": "SQL injection in login form",
            "endpoint": "/api/login",
            "evidence": "Response showed database error",
            "remediation": "Use parameterized queries"
        });
        let report = agent.handle_vulnerability_report(&args);

        assert!(report.contains("SQL Injection"));
        assert!(report.contains("HIGH"));
        assert!(report.contains("/api/login"));
    }
}
