//! Reconnaissance agent for asset discovery and enumeration

use async_trait::async_trait;
use serde_json::json;

use crate::providers::{CompletionRequest, Message, ToolDefinition};
use crate::state::ReconFinding;
use crate::{Error, Result};

use super::{Agent, AgentContext, AgentStatus, AgentTask, Prompts};

/// Reconnaissance agent for asset discovery
pub struct ReconAgent {
    status: AgentStatus,
    thinking: Option<String>,
    prompts: Prompts,
}

impl ReconAgent {
    /// Create a new recon agent
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
                name: "subfinder".to_string(),
                description: "Enumerate subdomains for a domain using passive sources".to_string(),
                parameters: json!({
                    "type": "object",
                    "properties": {
                        "domain": {
                            "type": "string",
                            "description": "Target domain to enumerate subdomains for"
                        },
                        "silent": {
                            "type": "boolean",
                            "description": "Only output subdomains (no banner/stats)"
                        }
                    },
                    "required": ["domain"]
                }),
            },
            ToolDefinition {
                name: "naabu".to_string(),
                description: "Fast port scanner to discover open ports".to_string(),
                parameters: json!({
                    "type": "object",
                    "properties": {
                        "host": {
                            "type": "string",
                            "description": "Target host or IP to scan"
                        },
                        "ports": {
                            "type": "string",
                            "description": "Ports to scan (e.g., '80,443' or '1-1000' or 'top-100')"
                        },
                        "rate": {
                            "type": "integer",
                            "description": "Packets per second rate limit"
                        }
                    },
                    "required": ["host"]
                }),
            },
            ToolDefinition {
                name: "httpx".to_string(),
                description: "HTTP probing tool to identify web servers and technologies"
                    .to_string(),
                parameters: json!({
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "Target URL or host to probe"
                        },
                        "tech_detect": {
                            "type": "boolean",
                            "description": "Enable technology detection"
                        },
                        "status_code": {
                            "type": "boolean",
                            "description": "Include status code in output"
                        }
                    },
                    "required": ["target"]
                }),
            },
            ToolDefinition {
                name: "katana".to_string(),
                description: "Web crawler to discover URLs and endpoints".to_string(),
                parameters: json!({
                    "type": "object",
                    "properties": {
                        "url": {
                            "type": "string",
                            "description": "Target URL to crawl"
                        },
                        "depth": {
                            "type": "integer",
                            "description": "Crawl depth limit"
                        },
                        "js_crawl": {
                            "type": "boolean",
                            "description": "Enable JavaScript parsing"
                        }
                    },
                    "required": ["url"]
                }),
            },
            ToolDefinition {
                name: "dnsx".to_string(),
                description: "DNS resolution and query tool".to_string(),
                parameters: json!({
                    "type": "object",
                    "properties": {
                        "domain": {
                            "type": "string",
                            "description": "Domain to resolve"
                        },
                        "record_type": {
                            "type": "string",
                            "description": "DNS record type (A, AAAA, CNAME, MX, NS, TXT)"
                        }
                    },
                    "required": ["domain"]
                }),
            },
            ToolDefinition {
                name: "tlsx".to_string(),
                description: "TLS/SSL certificate analyzer".to_string(),
                parameters: json!({
                    "type": "object",
                    "properties": {
                        "host": {
                            "type": "string",
                            "description": "Target host to analyze TLS"
                        },
                        "port": {
                            "type": "integer",
                            "description": "Port to connect to (default: 443)"
                        }
                    },
                    "required": ["host"]
                }),
            },
            ToolDefinition {
                name: "asnmap".to_string(),
                description: "Map ASN information for IP addresses or domains".to_string(),
                parameters: json!({
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "IP address or domain to lookup ASN"
                        }
                    },
                    "required": ["target"]
                }),
            },
            ToolDefinition {
                name: "whois".to_string(),
                description: "WHOIS lookup for domain registration information".to_string(),
                parameters: json!({
                    "type": "object",
                    "properties": {
                        "domain": {
                            "type": "string",
                            "description": "Domain to lookup"
                        }
                    },
                    "required": ["domain"]
                }),
            },
            ToolDefinition {
                name: "record_recon_finding".to_string(),
                description: "Record a reconnaissance finding (subdomain, IP, port, service, technology, endpoint, certificate, email, etc). Call this for every discovery.".to_string(),
                parameters: json!({
                    "type": "object",
                    "properties": {
                        "finding_type": {
                            "type": "string",
                            "enum": ["subdomain", "ip", "port", "service", "technology", "endpoint", "certificate", "email", "dns_record", "other"],
                            "description": "Type of reconnaissance finding"
                        },
                        "value": {
                            "type": "string",
                            "description": "The discovered value (e.g., 'api.example.com', '443/tcp', 'nginx/1.25')"
                        }
                    },
                    "required": ["finding_type", "value"]
                }),
            },
        ]
    }
}

impl Default for ReconAgent {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait(?Send)]
impl Agent for ReconAgent {
    fn name(&self) -> &str {
        "recon"
    }

    fn status(&self) -> AgentStatus {
        self.status
    }

    fn system_prompt(&self) -> &str {
        self.prompts.get("recon").unwrap_or("")
    }

    fn tools(&self) -> Vec<ToolDefinition> {
        self.build_tools()
    }

    async fn execute(&mut self, task: &AgentTask, ctx: &AgentContext<'_>) -> Result<String> {
        self.status = AgentStatus::Streaming;
        self.thinking = Some(format!(
            "Starting reconnaissance for task: {}",
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
        let max_iterations = 10;

        for iteration in 0..max_iterations {
            self.thinking = Some(format!(
                "Iteration {}: Planning next action...",
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
                self.status = AgentStatus::Streaming;

                for tool_call in &response.tool_calls {
                    self.thinking = Some(format!("Executing tool: {}", tool_call.name));

                    // Parse arguments and build command
                    let args: serde_json::Value = serde_json::from_str(&tool_call.arguments)
                        .map_err(|e| Error::Provider(format!("Invalid tool arguments: {}", e)))?;

                    // Handle record_recon_finding specially (no shell execution)
                    if tool_call.name == "record_recon_finding" {
                        let finding_type = args
                            .get("finding_type")
                            .and_then(|v| v.as_str())
                            .unwrap_or("other");
                        let value = args.get("value").and_then(|v| v.as_str()).unwrap_or("");
                        let finding = ReconFinding::new(finding_type, value, "recon-agent")
                            .with_target(ctx.target);
                        if let Err(e) = finding.insert(ctx.conn) {
                            tracing::warn!("Failed to persist recon finding: {}", e);
                        }
                        let tool_result = format!("Recorded {} finding: {}", finding_type, value);
                        messages.push(Message::assistant(format!(
                            "Tool {} executed. Result:\n{}",
                            tool_call.name, tool_result
                        )));
                        messages.push(Message::user(
                            "Continue with the reconnaissance or report findings.",
                        ));
                        result.push_str(&format!(
                            "\n## {} Output\n{}\n",
                            tool_call.name, tool_result
                        ));
                        continue;
                    }

                    // Build command arguments based on tool
                    let cmd_args = self.build_command_args(&tool_call.name, &args);

                    // Execute the tool
                    let execution = ctx
                        .executor
                        .execute_raw(
                            cmd_args.iter().map(|s| s.as_str()).collect(),
                            None,
                            self.name(),
                            ctx.conn,
                        )
                        .await?;

                    // Add tool result to messages
                    let tool_result = execution.output.unwrap_or_else(|| "No output".to_string());

                    // Persist raw tool output as recon finding
                    let finding =
                        ReconFinding::new("tool_output", &tool_call.name, &tool_call.name)
                            .with_raw_output(&tool_result)
                            .with_target(ctx.target);
                    if let Err(e) = finding.insert(ctx.conn) {
                        tracing::warn!("Failed to persist recon tool output: {}", e);
                    }

                    messages.push(Message::assistant(format!(
                        "Tool {} executed. Result:\n{}",
                        tool_call.name, tool_result
                    )));
                    messages.push(Message::user(
                        "Continue with the reconnaissance or report findings.",
                    ));

                    result.push_str(&format!(
                        "\n## {} Output\n{}\n",
                        tool_call.name, tool_result
                    ));
                }
            } else if let Some(content) = response.content {
                // LLM provided a response without tool calls
                self.thinking = Some("Analyzing results...".to_string());
                result.push_str(&format!("\n## Analysis\n{}\n", content));

                // Check if the LLM indicates completion
                if content.to_lowercase().contains("reconnaissance complete")
                    || content.to_lowercase().contains("findings summary")
                {
                    break;
                }

                messages.push(Message::assistant(&content));
                messages.push(Message::user(
                    "Continue with additional reconnaissance or provide a summary.",
                ));
            } else {
                break;
            }
        }

        self.status = AgentStatus::Completed;
        self.thinking = Some("Reconnaissance completed".to_string());

        Ok(result)
    }

    fn thinking(&self) -> Option<&str> {
        self.thinking.as_deref()
    }

    fn set_status(&mut self, status: AgentStatus) {
        self.status = status;
    }
}

impl ReconAgent {
    /// Build command arguments for a tool invocation
    fn build_command_args(&self, tool: &str, args: &serde_json::Value) -> Vec<String> {
        let mut cmd = vec![tool.to_string()];

        match tool {
            "subfinder" => {
                if let Some(domain) = args.get("domain").and_then(|v| v.as_str()) {
                    cmd.extend(["-d".to_string(), domain.to_string()]);
                }
                if args
                    .get("silent")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
                {
                    cmd.push("-silent".to_string());
                }
                cmd.push("-json".to_string());
            }
            "naabu" => {
                if let Some(host) = args.get("host").and_then(|v| v.as_str()) {
                    cmd.extend(["-host".to_string(), host.to_string()]);
                }
                if let Some(ports) = args.get("ports").and_then(|v| v.as_str()) {
                    cmd.extend(["-p".to_string(), ports.to_string()]);
                }
                if let Some(rate) = args.get("rate").and_then(|v| v.as_i64()) {
                    cmd.extend(["-rate".to_string(), rate.to_string()]);
                }
                cmd.push("-json".to_string());
            }
            "httpx" => {
                if let Some(target) = args.get("target").and_then(|v| v.as_str()) {
                    cmd.extend(["-u".to_string(), target.to_string()]);
                }
                if args
                    .get("tech_detect")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
                {
                    cmd.push("-td".to_string());
                }
                if args
                    .get("status_code")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true)
                {
                    cmd.push("-sc".to_string());
                }
                cmd.push("-json".to_string());
            }
            "katana" => {
                if let Some(url) = args.get("url").and_then(|v| v.as_str()) {
                    cmd.extend(["-u".to_string(), url.to_string()]);
                }
                if let Some(depth) = args.get("depth").and_then(|v| v.as_i64()) {
                    cmd.extend(["-d".to_string(), depth.to_string()]);
                }
                if args
                    .get("js_crawl")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
                {
                    cmd.push("-jc".to_string());
                }
                cmd.push("-json".to_string());
            }
            "dnsx" => {
                if let Some(domain) = args.get("domain").and_then(|v| v.as_str()) {
                    cmd.extend(["-d".to_string(), domain.to_string()]);
                }
                if let Some(record_type) = args.get("record_type").and_then(|v| v.as_str()) {
                    let flag = match record_type.to_uppercase().as_str() {
                        "A" => "-a",
                        "AAAA" => "-aaaa",
                        "CNAME" => "-cname",
                        "MX" => "-mx",
                        "NS" => "-ns",
                        "TXT" => "-txt",
                        _ => "-a",
                    };
                    cmd.push(flag.to_string());
                }
                cmd.push("-json".to_string());
            }
            "tlsx" => {
                if let Some(host) = args.get("host").and_then(|v| v.as_str()) {
                    cmd.extend(["-u".to_string(), host.to_string()]);
                }
                if let Some(port) = args.get("port").and_then(|v| v.as_i64()) {
                    cmd.extend(["-p".to_string(), port.to_string()]);
                }
                cmd.push("-json".to_string());
            }
            "asnmap" => {
                if let Some(target) = args.get("target").and_then(|v| v.as_str()) {
                    cmd.extend(["-i".to_string(), target.to_string()]);
                }
                cmd.push("-json".to_string());
            }
            "whois" => {
                if let Some(domain) = args.get("domain").and_then(|v| v.as_str()) {
                    cmd.push(domain.to_string());
                }
            }
            _ => {}
        }

        cmd
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn test_recon_agent_creation() {
        let agent = ReconAgent::new();
        assert_eq!(agent.name(), "recon");
        assert_eq!(agent.status(), AgentStatus::Idle);
    }

    #[test]
    fn test_recon_agent_tools() {
        let agent = ReconAgent::new();
        let tools = agent.tools();

        assert!(!tools.is_empty());
        assert!(tools.iter().any(|t| t.name == "subfinder"));
        assert!(tools.iter().any(|t| t.name == "naabu"));
        assert!(tools.iter().any(|t| t.name == "httpx"));
    }

    #[test]
    fn test_build_subfinder_args() {
        let agent = ReconAgent::new();
        let args = json!({
            "domain": "example.com",
            "silent": true
        });
        let cmd = agent.build_command_args("subfinder", &args);

        assert_eq!(
            cmd.first()
                .expect("command should have at least one element"),
            "subfinder"
        );
        assert!(cmd.contains(&"-d".to_string()));
        assert!(cmd.contains(&"example.com".to_string()));
        assert!(cmd.contains(&"-silent".to_string()));
        assert!(cmd.contains(&"-json".to_string()));
    }

    #[test]
    fn test_recon_has_record_finding_tool() {
        let agent = ReconAgent::new();
        let tools = agent.tools();
        assert!(
            tools.iter().any(|t| t.name == "record_recon_finding"),
            "Recon agent should have record_recon_finding tool"
        );
    }

    #[test]
    fn test_build_naabu_args() {
        let agent = ReconAgent::new();
        let args = json!({
            "host": "192.168.1.1",
            "ports": "80,443,8080",
            "rate": 1000
        });
        let cmd = agent.build_command_args("naabu", &args);

        assert_eq!(
            cmd.first()
                .expect("command should have at least one element"),
            "naabu"
        );
        assert!(cmd.contains(&"-host".to_string()));
        assert!(cmd.contains(&"192.168.1.1".to_string()));
        assert!(cmd.contains(&"-p".to_string()));
        assert!(cmd.contains(&"80,443,8080".to_string()));
    }
}
