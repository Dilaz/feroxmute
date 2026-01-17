//! MCP Server implementation

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;
use tokio::sync::RwLock;

use crate::Result;
use crate::mcp::protocol::{
    JsonRpcRequest, JsonRpcResponse, McpToolCall, McpToolDefinition, McpToolResult, error_codes,
};

/// Trait for MCP tools
#[async_trait]
pub trait McpTool: Send + Sync {
    /// Tool name (must be unique)
    fn name(&self) -> &str;

    /// Tool description
    fn description(&self) -> &str;

    /// JSON Schema for input parameters
    fn input_schema(&self) -> Value;

    /// Execute the tool with given arguments
    async fn execute(&self, arguments: Value) -> Result<McpToolResult>;
}

/// MCP Server that manages tools and handles requests
pub struct McpServer {
    tools: RwLock<HashMap<String, Arc<dyn McpTool>>>,
    server_name: String,
    server_version: String,
}

impl McpServer {
    /// Create a new MCP server
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            tools: RwLock::new(HashMap::new()),
            server_name: name.into(),
            server_version: version.into(),
        }
    }

    /// Register a tool
    pub async fn register_tool(&self, tool: Arc<dyn McpTool>) {
        let mut tools = self.tools.write().await;
        tools.insert(tool.name().to_string(), tool);
    }

    /// Handle an incoming JSON-RPC request
    pub async fn handle_request(&self, request: JsonRpcRequest) -> JsonRpcResponse {
        match request.method.as_str() {
            "initialize" => self.handle_initialize(request.id).await,
            "tools/list" => self.handle_list_tools(request.id).await,
            "tools/call" => self.handle_call_tool(request.id, request.params).await,
            _ => JsonRpcResponse::error(
                request.id,
                error_codes::METHOD_NOT_FOUND,
                format!("Unknown method: {}", request.method),
            ),
        }
    }

    async fn handle_initialize(&self, id: Option<Value>) -> JsonRpcResponse {
        JsonRpcResponse::success(
            id,
            serde_json::json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": self.server_name,
                    "version": self.server_version
                }
            }),
        )
    }

    async fn handle_list_tools(&self, id: Option<Value>) -> JsonRpcResponse {
        let tools = self.tools.read().await;
        let tool_defs: Vec<McpToolDefinition> = tools
            .values()
            .map(|t| McpToolDefinition {
                name: t.name().to_string(),
                description: t.description().to_string(),
                input_schema: t.input_schema(),
            })
            .collect();

        JsonRpcResponse::success(id, serde_json::json!({ "tools": tool_defs }))
    }

    async fn handle_call_tool(&self, id: Option<Value>, params: Option<Value>) -> JsonRpcResponse {
        let params = match params {
            Some(p) => p,
            None => {
                return JsonRpcResponse::error(
                    id,
                    error_codes::INVALID_PARAMS,
                    "Missing params for tools/call",
                );
            }
        };

        let call: McpToolCall = match serde_json::from_value(params) {
            Ok(c) => c,
            Err(e) => {
                return JsonRpcResponse::error(
                    id,
                    error_codes::INVALID_PARAMS,
                    format!("Invalid tool call params: {}", e),
                );
            }
        };

        let tools = self.tools.read().await;
        let tool = match tools.get(&call.name) {
            Some(t) => Arc::clone(t),
            None => {
                return JsonRpcResponse::error(
                    id,
                    error_codes::METHOD_NOT_FOUND,
                    format!("Unknown tool: {}", call.name),
                );
            }
        };

        // Release lock before executing tool
        drop(tools);

        match tool.execute(call.arguments).await {
            Ok(result) => match serde_json::to_value(result) {
                Ok(v) => JsonRpcResponse::success(id, v),
                Err(e) => JsonRpcResponse::error(
                    id,
                    error_codes::INTERNAL_ERROR,
                    format!("Failed to serialize tool result: {}", e),
                ),
            },
            Err(e) => match serde_json::to_value(McpToolResult::error(e.to_string())) {
                Ok(v) => JsonRpcResponse::success(id, v),
                Err(ser_err) => JsonRpcResponse::error(
                    id,
                    error_codes::INTERNAL_ERROR,
                    format!("Tool error: {}; serialization failed: {}", e, ser_err),
                ),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct EchoTool;

    #[async_trait]
    impl McpTool for EchoTool {
        fn name(&self) -> &str {
            "echo"
        }

        fn description(&self) -> &str {
            "Echoes back the input"
        }

        fn input_schema(&self) -> Value {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "message": { "type": "string" }
                },
                "required": ["message"]
            })
        }

        async fn execute(&self, arguments: Value) -> Result<McpToolResult> {
            let message = arguments
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("no message");
            Ok(McpToolResult::text(message))
        }
    }

    #[tokio::test]
    async fn test_server_initialize() {
        let server = McpServer::new("test", "1.0.0");
        let req = JsonRpcRequest::new("initialize").with_id(1);
        let resp = server.handle_request(req).await;
        assert!(resp.result.is_some());
        let result = resp.result.unwrap();
        assert_eq!(result["serverInfo"]["name"], "test");
    }

    #[tokio::test]
    async fn test_server_list_tools() {
        let server = McpServer::new("test", "1.0.0");
        server.register_tool(Arc::new(EchoTool)).await;

        let req = JsonRpcRequest::new("tools/list").with_id(1);
        let resp = server.handle_request(req).await;
        assert!(resp.result.is_some());
        let result = resp.result.unwrap();
        let tools = result["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["name"], "echo");
    }

    #[tokio::test]
    async fn test_server_call_tool() {
        let server = McpServer::new("test", "1.0.0");
        server.register_tool(Arc::new(EchoTool)).await;

        let req = JsonRpcRequest::new("tools/call")
            .with_id(1)
            .with_params(serde_json::json!({
                "name": "echo",
                "arguments": { "message": "hello" }
            }));
        let resp = server.handle_request(req).await;
        assert!(resp.result.is_some());
        let result = resp.result.unwrap();
        let content = &result["content"][0]["text"];
        assert_eq!(content, "hello");
    }

    #[tokio::test]
    async fn test_server_unknown_method() {
        let server = McpServer::new("test", "1.0.0");
        let req = JsonRpcRequest::new("unknown/method").with_id(1);
        let resp = server.handle_request(req).await;
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, error_codes::METHOD_NOT_FOUND);
    }

    #[tokio::test]
    async fn test_server_unknown_tool() {
        let server = McpServer::new("test", "1.0.0");
        let req = JsonRpcRequest::new("tools/call")
            .with_id(1)
            .with_params(serde_json::json!({
                "name": "nonexistent",
                "arguments": {}
            }));
        let resp = server.handle_request(req).await;
        assert!(resp.error.is_some());
    }
}
