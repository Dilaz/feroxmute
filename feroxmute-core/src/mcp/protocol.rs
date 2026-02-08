//! MCP JSON-RPC protocol types

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// JSON-RPC request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: Option<Value>,
    pub method: String,
    #[serde(default)]
    pub params: Option<Value>,
}

impl JsonRpcRequest {
    pub fn new(method: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id: None,
            method: method.into(),
            params: None,
        }
    }

    pub fn with_id(mut self, id: impl Into<Value>) -> Self {
        self.id = Some(id.into());
        self
    }

    pub fn with_params(mut self, params: Value) -> Self {
        self.params = Some(params);
        self
    }
}

/// JSON-RPC response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

impl JsonRpcResponse {
    pub fn success(id: Option<Value>, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn error(id: Option<Value>, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
                data: None,
            }),
        }
    }
}

/// JSON-RPC error
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

/// Standard JSON-RPC error codes
pub mod error_codes {
    pub const PARSE_ERROR: i32 = -32700;
    pub const INVALID_REQUEST: i32 = -32600;
    pub const METHOD_NOT_FOUND: i32 = -32601;
    pub const INVALID_PARAMS: i32 = -32602;
    pub const INTERNAL_ERROR: i32 = -32603;
}

/// MCP Tool definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpToolDefinition {
    pub name: String,
    pub description: String,
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
}

/// MCP Tool call request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpToolCall {
    pub name: String,
    #[serde(default)]
    pub arguments: Value,
}

/// MCP Tool call result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpToolResult {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<Vec<McpContent>>,
    #[serde(rename = "isError", skip_serializing_if = "Option::is_none")]
    pub is_error: Option<bool>,
}

impl McpToolResult {
    pub fn text(content: impl Into<String>) -> Self {
        Self {
            content: Some(vec![McpContent::Text {
                text: content.into(),
            }]),
            is_error: None,
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self {
            content: Some(vec![McpContent::Text {
                text: message.into(),
            }]),
            is_error: Some(true),
        }
    }
}

/// MCP content types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum McpContent {
    Text { text: String },
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn test_jsonrpc_request_serialization() {
        let req = JsonRpcRequest::new("tools/list").with_id(1);
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"method\":\"tools/list\""));
        assert!(json.contains("\"jsonrpc\":\"2.0\""));
    }

    #[test]
    fn test_jsonrpc_response_success() {
        let resp = JsonRpcResponse::success(Some(1.into()), serde_json::json!({"ok": true}));
        assert!(resp.result.is_some());
        assert!(resp.error.is_none());
    }

    #[test]
    fn test_jsonrpc_response_error() {
        let resp =
            JsonRpcResponse::error(Some(1.into()), error_codes::METHOD_NOT_FOUND, "Not found");
        assert!(resp.result.is_none());
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, error_codes::METHOD_NOT_FOUND);
    }

    #[test]
    fn test_mcp_tool_result_text() {
        let result = McpToolResult::text("output");
        assert!(result.is_error.is_none());
    }

    #[test]
    fn test_mcp_tool_result_error() {
        let result = McpToolResult::error("failed");
        assert_eq!(result.is_error, Some(true));
    }

    #[test]
    fn test_mcp_content_text_wire_format() {
        let content = McpContent::Text {
            text: "hello".to_string(),
        };
        let json = serde_json::to_value(&content).unwrap();
        assert_eq!(json["type"], "text");
        assert_eq!(json["text"], "hello");
    }

    #[test]
    fn test_mcp_content_roundtrip() {
        let original = McpContent::Text {
            text: "roundtrip".to_string(),
        };
        let json = serde_json::to_string(&original).unwrap();
        let deserialized: McpContent = serde_json::from_str(&json).unwrap();
        match deserialized {
            McpContent::Text { text } => assert_eq!(text, "roundtrip"),
        }
    }

    #[test]
    fn test_response_skip_serializing_none() {
        let success = JsonRpcResponse::success(Some(1.into()), serde_json::json!("ok"));
        let json = serde_json::to_value(&success).unwrap();
        assert!(json.get("result").is_some());
        assert!(
            json.get("error").is_none(),
            "error should not be serialized when None"
        );

        let error = JsonRpcResponse::error(Some(1.into()), error_codes::INTERNAL_ERROR, "fail");
        let json = serde_json::to_value(&error).unwrap();
        assert!(json.get("error").is_some());
        assert!(
            json.get("result").is_none(),
            "result should not be serialized when None"
        );
    }

    #[test]
    fn test_mcp_tool_result_text_content() {
        let result = McpToolResult::text("output");
        let content = result.content.unwrap();
        assert_eq!(content.len(), 1);
        match &content[0] {
            McpContent::Text { text } => assert_eq!(text, "output"),
        }
    }

    #[test]
    fn test_jsonrpc_request_roundtrip() {
        let req = JsonRpcRequest::new("tools/call")
            .with_id(42)
            .with_params(serde_json::json!({"name": "echo"}));
        let json = serde_json::to_string(&req).unwrap();
        let deserialized: JsonRpcRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.method, "tools/call");
        assert_eq!(deserialized.id, Some(serde_json::json!(42)));
        assert!(deserialized.params.is_some());
    }
}
