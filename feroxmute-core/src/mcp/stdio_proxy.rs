//! stdio ↔ HTTP MCP proxy.
//!
//! Some ACP agents (notably `claude-code-acp`) only support **stdio** MCP
//! servers — they spawn a subprocess and speak MCP over its stdin/stdout.
//! feroxmute serves its tools over an in-process HTTP MCP server
//! ([`crate::mcp::http::HttpMcpServer`]) whose tools hold live engagement
//! context (the Docker container, event channel, database), so that context
//! cannot be recreated in a separate process.
//!
//! This proxy bridges the gap: feroxmute attaches itself as a stdio MCP
//! server whose command re-invokes the feroxmute binary in proxy mode. The
//! proxy reads newline-delimited JSON-RPC from stdin, forwards each message to
//! the HTTP MCP server (with the bearer token), and writes the response back
//! to stdout. All tool execution still happens in the main feroxmute process.

use serde_json::Value;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};

use crate::Result;

/// Environment variable carrying the HTTP MCP bearer token to the proxy.
pub const MCP_TOKEN_ENV: &str = "FEROXMUTE_MCP_TOKEN";

/// Run the stdio ↔ HTTP MCP proxy until stdin reaches EOF.
///
/// `url` is the feroxmute HTTP MCP server URL; `token` is its bearer token.
/// Newline-delimited JSON-RPC requests on stdin are forwarded to the server;
/// responses are written back to stdout. Notification requests (those the
/// server answers with an empty body) produce no stdout, per the MCP spec.
///
/// # Errors
///
/// Returns an error only if stdin/stdout I/O fails; per-request HTTP failures
/// are reported back to the client as JSON-RPC error responses so the agent
/// is never left waiting.
pub async fn run_stdio_proxy(url: String, token: String) -> Result<()> {
    let reader = BufReader::new(tokio::io::stdin());
    let mut stdout = tokio::io::stdout();
    proxy_io(reader, &mut stdout, &url, &token).await
}

/// Core proxy loop, generic over the I/O streams so it can be tested with
/// in-memory buffers against a real [`crate::mcp::http::HttpMcpServer`].
async fn proxy_io<R, W>(reader: R, writer: &mut W, url: &str, token: &str) -> Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let client = reqwest::Client::new();
    let bearer = format!("Bearer {token}");
    let mut lines = reader.lines();

    while let Some(line) = lines
        .next_line()
        .await
        .map_err(|e| crate::Error::Provider(format!("MCP proxy stdin read failed: {e}")))?
    {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        match forward(&client, url, &bearer, line).await {
            ForwardOutcome::Response(body) => {
                write_line(writer, body.trim_end().as_bytes()).await?;
            }
            // Notification (empty/202 body): MCP expects no reply.
            ForwardOutcome::NoReply => {}
            ForwardOutcome::Failed(message) => {
                let id = serde_json::from_str::<Value>(line)
                    .ok()
                    .and_then(|v| v.get("id").cloned())
                    .unwrap_or(Value::Null);
                let error = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": { "code": -32603, "message": message }
                });
                write_line(writer, error.to_string().as_bytes()).await?;
            }
        }
    }

    Ok(())
}

async fn write_line<W: AsyncWrite + Unpin>(writer: &mut W, bytes: &[u8]) -> Result<()> {
    writer.write_all(bytes).await.map_err(|e| write_err(&e))?;
    writer.write_all(b"\n").await.map_err(|e| write_err(&e))?;
    writer.flush().await.map_err(|e| write_err(&e))?;
    Ok(())
}

enum ForwardOutcome {
    Response(String),
    NoReply,
    Failed(String),
}

async fn forward(client: &reqwest::Client, url: &str, bearer: &str, body: &str) -> ForwardOutcome {
    let response = client
        .post(url)
        .header(reqwest::header::AUTHORIZATION, bearer)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body.to_string())
        .send()
        .await;

    let response = match response {
        Ok(r) => r,
        Err(e) => {
            return ForwardOutcome::Failed(format!("feroxmute MCP proxy request failed: {e}"));
        }
    };

    let status = response.status();
    let text = match response.text().await {
        Ok(t) => t,
        Err(e) => {
            return ForwardOutcome::Failed(format!(
                "feroxmute MCP proxy failed to read response: {e}"
            ));
        }
    };

    if !status.is_success() {
        return ForwardOutcome::Failed(format!(
            "feroxmute MCP server returned HTTP {status}: {}",
            text.trim()
        ));
    }

    if text.trim().is_empty() {
        ForwardOutcome::NoReply
    } else {
        ForwardOutcome::Response(text)
    }
}

fn write_err(e: &std::io::Error) -> crate::Error {
    crate::Error::Provider(format!("MCP proxy stdout write failed: {e}"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::mcp::http::HttpMcpServer;
    use crate::mcp::protocol::McpToolResult;
    use crate::mcp::{McpServer, McpTool};
    use async_trait::async_trait;
    use std::sync::Arc;

    struct EchoTool;

    #[async_trait]
    impl McpTool for EchoTool {
        fn name(&self) -> &str {
            "echo"
        }
        fn description(&self) -> &str {
            "Echoes the message back"
        }
        fn input_schema(&self) -> Value {
            serde_json::json!({"type": "object", "properties": {"message": {"type": "string"}}})
        }
        async fn execute(&self, arguments: Value) -> Result<McpToolResult> {
            let msg = arguments
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            Ok(McpToolResult::text(msg))
        }
    }

    async fn start_server() -> HttpMcpServer {
        let server = Arc::new(McpServer::new("test", "1.0.0"));
        server.register_tool(Arc::new(EchoTool)).await;
        HttpMcpServer::start(server).await.unwrap()
    }

    #[tokio::test]
    async fn test_proxy_forwards_request_and_returns_response() {
        let http = start_server().await;

        let input = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}\n".to_vec();
        let mut output = Vec::new();
        proxy_io(&input[..], &mut output, &http.url(), http.token())
            .await
            .unwrap();

        let out = String::from_utf8(output).unwrap();
        let response: Value = serde_json::from_str(out.trim()).unwrap();
        assert_eq!(response["id"], 1);
        let tool_names: Vec<&str> = response["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|t| t["name"].as_str())
            .collect();
        assert!(
            tool_names.contains(&"echo"),
            "tools/list should expose echo"
        );

        http.shutdown().await;
    }

    #[tokio::test]
    async fn test_proxy_tool_call_round_trip() {
        let http = start_server().await;

        let input =
            b"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"echo\",\"arguments\":{\"message\":\"hi there\"}}}\n"
                .to_vec();
        let mut output = Vec::new();
        proxy_io(&input[..], &mut output, &http.url(), http.token())
            .await
            .unwrap();

        let out = String::from_utf8(output).unwrap();
        assert!(
            out.contains("hi there"),
            "echoed text should round-trip: {out}"
        );

        http.shutdown().await;
    }

    #[tokio::test]
    async fn test_proxy_notification_produces_no_output() {
        let http = start_server().await;

        // No `id` -> the server treats it as a notification (202, empty body).
        let input = b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n".to_vec();
        let mut output = Vec::new();
        proxy_io(&input[..], &mut output, &http.url(), http.token())
            .await
            .unwrap();

        assert!(output.is_empty(), "notifications must not get a reply");

        http.shutdown().await;
    }

    #[tokio::test]
    async fn test_proxy_reports_connection_failure_as_jsonrpc_error() {
        let input = b"{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"tools/list\"}\n".to_vec();
        let mut output = Vec::new();
        // Port 1 is unbound -> request fails.
        proxy_io(&input[..], &mut output, "http://127.0.0.1:1/mcp", "tok")
            .await
            .unwrap();

        let response: Value =
            serde_json::from_str(String::from_utf8(output).unwrap().trim()).unwrap();
        assert_eq!(response["id"], 9);
        assert_eq!(response["error"]["code"], -32603);
    }
}
