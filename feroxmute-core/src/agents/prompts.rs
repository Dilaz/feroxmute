//! System prompts for specialized agents

use serde::Deserialize;
use std::path::Path;

use crate::limitations::PromptContext;
use crate::{Error, Result};

/// Agent prompt configuration
#[derive(Debug, Clone, Deserialize)]
pub struct AgentPrompt {
    pub prompt: String,
}

/// All agent prompts
#[derive(Debug, Clone, Deserialize)]
pub struct Prompts {
    pub orchestrator: AgentPrompt,
    pub recon: AgentPrompt,
    pub scanner: AgentPrompt,
    pub exploit: AgentPrompt,
    pub report: AgentPrompt,
    pub sast: AgentPrompt,
}

impl Prompts {
    /// Load prompts from a TOML file
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        Self::parse(&content)
    }

    /// Parse prompts from TOML string
    pub fn parse(content: &str) -> Result<Self> {
        toml::from_str(content)
            .map_err(|e| Error::Config(format!("Failed to parse prompts: {}", e)))
    }

    /// Load from default location (embedded)
    #[allow(clippy::expect_used)]
    pub fn default_prompts() -> Self {
        let content = include_str!("../../prompts.toml");
        Self::parse(content).expect("Embedded prompts.toml should be valid")
    }

    /// Get prompt for a specific agent
    pub fn get(&self, agent: &str) -> Option<&str> {
        match agent {
            "orchestrator" => Some(&self.orchestrator.prompt),
            "recon" => Some(&self.recon.prompt),
            "scanner" => Some(&self.scanner.prompt),
            "exploit" => Some(&self.exploit.prompt),
            "report" => Some(&self.report.prompt),
            "sast" => Some(&self.sast.prompt),
            _ => None,
        }
    }

    /// Get prompt with conditional sections processed
    pub fn get_with_context(&self, agent: &str, ctx: &PromptContext) -> Option<String> {
        self.get(agent).map(|prompt| process_conditionals(prompt, ctx))
    }
}

impl Default for Prompts {
    fn default() -> Self {
        Self::default_prompts()
    }
}

/// Process {{#if <flag>}}...{{/if}} conditionals in a template
fn process_conditionals(template: &str, ctx: &PromptContext) -> String {
    let mut result = template.to_string();

    // Process each conditional type
    result = process_conditional(&result, "discover", ctx.discover);
    result = process_conditional(&result, "portscan", ctx.portscan);
    result = process_conditional(&result, "network", ctx.network);
    result = process_conditional(&result, "exploit", ctx.exploit);

    result
}

/// Process a single conditional flag
fn process_conditional(template: &str, flag_name: &str, flag_value: bool) -> String {
    let open_tag = format!("{{{{#if {}}}}}", flag_name);
    let close_tag = "{{/if}}";

    let mut result = String::new();
    let mut remaining = template;

    while let Some(start) = remaining.find(&open_tag) {
        // Add content before the tag
        result.push_str(&remaining[..start]);

        // Find the closing tag
        let after_open = start + open_tag.len();
        if let Some(end_offset) = remaining[after_open..].find(close_tag) {
            let content = &remaining[after_open..after_open + end_offset];

            // Include content only if flag is true
            if flag_value {
                result.push_str(content);
            }

            // Move past the closing tag
            remaining = &remaining[after_open + end_offset + close_tag.len()..];
        } else {
            // No closing tag found, include rest as-is
            result.push_str(&remaining[start..]);
            remaining = "";
        }
    }

    // Add remaining content
    result.push_str(remaining);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conditional_include() {
        let template = "Before {{#if discover}}DISCOVERY CONTENT{{/if}} After";
        let ctx = PromptContext {
            discover: true,
            ..Default::default()
        };
        let result = process_conditionals(template, &ctx);
        assert_eq!(result, "Before DISCOVERY CONTENT After");
    }

    #[test]
    fn test_conditional_exclude() {
        let template = "Before {{#if discover}}DISCOVERY CONTENT{{/if}} After";
        let ctx = PromptContext {
            discover: false,
            ..Default::default()
        };
        let result = process_conditionals(template, &ctx);
        assert_eq!(result, "Before  After");
    }

    #[test]
    fn test_multiple_conditionals() {
        let template = "{{#if discover}}DISC{{/if}} {{#if portscan}}PORT{{/if}}";
        let ctx = PromptContext {
            discover: true,
            portscan: false,
            ..Default::default()
        };
        let result = process_conditionals(template, &ctx);
        assert_eq!(result, "DISC ");
    }

    #[test]
    fn test_nested_content_preserved() {
        let template = "{{#if discover}}\n- subfinder\n- dnsx\n{{/if}}";
        let ctx = PromptContext {
            discover: true,
            ..Default::default()
        };
        let result = process_conditionals(template, &ctx);
        assert!(result.contains("subfinder"));
        assert!(result.contains("dnsx"));
    }
}
