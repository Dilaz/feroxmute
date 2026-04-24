//! HTTP endpoint for the MCP server
//!
//! Provides an HTTP POST endpoint that CLI agents can use to access
//! feroxmute tools via the MCP protocol over JSON-RPC.
//!
//! Each server instance generates a random bearer token on startup.
//! Requests without a valid `Authorization: Bearer <token>` header
//! are rejected with `401 Unauthorized`.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tracing::{debug, error, warn};
use uuid::Uuid;

use crate::Result;
use crate::mcp::McpServer;
use crate::mcp::protocol::{JsonRpcRequest, error_codes};

const MAX_HTTP_DIAGNOSTICS: usize = 30;

#[derive(Default)]
struct HttpMcpDiagnostics {
    entries: Mutex<VecDeque<String>>,
}

impl HttpMcpDiagnostics {
    fn push(&self, entry: impl Into<String>) {
        if let Ok(mut entries) = self.entries.lock() {
            if entries.len() >= MAX_HTTP_DIAGNOSTICS {
                entries.pop_front();
            }
            entries.push_back(entry.into());
        }
    }

    fn summary(&self) -> String {
        let Ok(entries) = self.entries.lock() else {
            return String::new();
        };

        entries
            .iter()
            .map(|entry| format!("  {entry}"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn latest(&self) -> Option<String> {
        self.entries
            .lock()
            .ok()
            .and_then(|entries| entries.back().cloned())
    }
}

/// HTTP server wrapping an MCP server for tool access via HTTP POST.
///
/// Binds to an OS-assigned port on localhost and forwards JSON-RPC
/// requests to the underlying [`McpServer`]. All requests must include
/// a valid `Authorization: Bearer <token>` header.
pub struct HttpMcpServer {
    port: u16,
    /// Bearer token required for all requests.
    token: String,
    diagnostics: Arc<HttpMcpDiagnostics>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    _task: JoinHandle<()>,
}

impl HttpMcpServer {
    /// Start the HTTP MCP server on an OS-assigned port.
    ///
    /// Binds to `127.0.0.1:0` and spawns a background task to accept
    /// connections. A random bearer token is generated; use
    /// [`token()`](Self::token) to retrieve it for passing to CLI agents.
    pub async fn start(server: Arc<McpServer>) -> Result<Self> {
        let addr = SocketAddr::from(([127, 0, 0, 1], 0));
        let listener = TcpListener::bind(addr).await?;
        let local_addr = listener.local_addr()?;
        let port = local_addr.port();

        let token = Uuid::new_v4().to_string();

        debug!("MCP HTTP server listening on {}", local_addr);

        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let diagnostics = Arc::new(HttpMcpDiagnostics::default());
        diagnostics.push(format!("listening on http://127.0.0.1:{port}"));

        let accept_token = token.clone();
        let accept_diagnostics = Arc::clone(&diagnostics);
        let task = tokio::spawn(async move {
            Self::accept_loop(
                listener,
                server,
                accept_token,
                accept_diagnostics,
                shutdown_rx,
            )
            .await;
        });

        Ok(Self {
            port,
            token,
            diagnostics,
            shutdown_tx: Some(shutdown_tx),
            _task: task,
        })
    }

    /// The full URL of the running server (e.g. `http://127.0.0.1:12345`).
    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// The bearer token required for authentication.
    pub fn token(&self) -> &str {
        &self.token
    }

    /// The port the server is listening on.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Recent HTTP/MCP activity, formatted for diagnostic error messages.
    pub fn recent_activity_summary(&self) -> String {
        self.diagnostics.summary()
    }

    /// Latest HTTP/MCP activity as a single line for live status updates.
    pub fn latest_activity(&self) -> Option<String> {
        self.diagnostics.latest()
    }

    /// Gracefully shut down the server.
    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }

    /// Accept loop that runs until shutdown is signalled.
    async fn accept_loop(
        listener: TcpListener,
        server: Arc<McpServer>,
        token: String,
        diagnostics: Arc<HttpMcpDiagnostics>,
        mut shutdown_rx: oneshot::Receiver<()>,
    ) {
        let token = Arc::new(token);
        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, addr)) => {
                            debug!("MCP HTTP connection from {}", addr);
                            diagnostics.push(format!("connection from {addr}"));
                            let server = Arc::clone(&server);
                            let token = Arc::clone(&token);
                            let diagnostics = Arc::clone(&diagnostics);
                            tokio::spawn(async move {
                                let io = TokioIo::new(stream);
                                let service = service_fn(move |req| {
                                    let server = Arc::clone(&server);
                                    let token = Arc::clone(&token);
                                    let diagnostics = Arc::clone(&diagnostics);
                                    handle_mcp_request(server, token, diagnostics, req)
                                });
                                if let Err(e) = http1::Builder::new()
                                    .serve_connection(io, service)
                                    .await
                                {
                                    error!("MCP HTTP connection error: {}", e);
                                }
                            });
                        }
                        Err(e) => {
                            error!("MCP HTTP accept error: {}", e);
                            diagnostics.push(format!("accept error: {e}"));
                        }
                    }
                }
                _ = &mut shutdown_rx => {
                    debug!("MCP HTTP server shutting down");
                    diagnostics.push("server shutting down");
                    break;
                }
            }
        }
    }
}

/// Build a JSON error response with the given status code and body.
fn json_response(status: StatusCode, body: &serde_json::Value) -> Response<Full<Bytes>> {
    let bytes = serde_json::to_vec(body).unwrap_or_default();
    // StatusCode and header are all valid constants, so the builder cannot fail.
    // We use unwrap_or_else with a fallback empty response just in case.
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(bytes)))
        .unwrap_or_else(|_| {
            warn!("Failed to build HTTP response, returning empty 500");
            let mut resp = Response::new(Full::new(Bytes::new()));
            *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            resp
        })
}

/// Build an empty HTTP response.
fn empty_response(status: StatusCode) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|_| {
            warn!("Failed to build empty HTTP response, returning empty 500");
            let mut resp = Response::new(Full::new(Bytes::new()));
            *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            resp
        })
}

/// Validate the `Authorization: Bearer <token>` header.
fn check_bearer_token(req: &Request<hyper::body::Incoming>, expected: &str) -> bool {
    req.headers()
        .get(hyper::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .is_some_and(|t| t == expected)
}

fn describe_mcp_request(request: &JsonRpcRequest) -> String {
    if request.method == "tools/call" {
        let tool_name = request
            .params
            .as_ref()
            .and_then(|params| params.get("name"))
            .and_then(|name| name.as_str())
            .unwrap_or("<unknown>");
        format!("tools/call {tool_name}")
    } else {
        request.method.clone()
    }
}

/// Handle a single HTTP request by dispatching to the MCP server.
async fn handle_mcp_request(
    server: Arc<McpServer>,
    token: Arc<String>,
    diagnostics: Arc<HttpMcpDiagnostics>,
    req: Request<hyper::body::Incoming>,
) -> std::result::Result<Response<Full<Bytes>>, hyper::Error> {
    // Only accept POST requests
    if req.method() != hyper::Method::POST {
        diagnostics.push(format!("{} -> 405 method not allowed", req.method()));
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": null,
            "error": {
                "code": error_codes::INVALID_REQUEST,
                "message": "Method not allowed, use POST"
            }
        });
        return Ok(json_response(StatusCode::METHOD_NOT_ALLOWED, &body));
    }

    // Validate bearer token
    if !check_bearer_token(&req, &token) {
        diagnostics.push("POST -> 401 unauthorized");
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": null,
            "error": {
                "code": error_codes::INVALID_REQUEST,
                "message": "Unauthorized: missing or invalid bearer token"
            }
        });
        return Ok(json_response(StatusCode::UNAUTHORIZED, &body));
    }

    // Read and collect the request body
    let body = req.collect().await?.to_bytes();

    // Parse JSON-RPC request
    let rpc_request: JsonRpcRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            diagnostics.push(format!("POST -> parse error: {e}"));
            let error_body = serde_json::json!({
                "jsonrpc": "2.0",
                "id": null,
                "error": {
                    "code": error_codes::PARSE_ERROR,
                    "message": format!("Parse error: {e}")
                }
            });
            return Ok(json_response(StatusCode::OK, &error_body));
        }
    };
    let request_description = describe_mcp_request(&rpc_request);

    // Handle notification methods that don't require processing
    if rpc_request.method == "notifications/initialized" || rpc_request.method == "initialized" {
        diagnostics.push(format!("{request_description} -> accepted"));
        return Ok(empty_response(StatusCode::ACCEPTED));
    }

    if rpc_request.id.is_none() {
        diagnostics.push(format!("{request_description} -> accepted notification"));
        return Ok(empty_response(StatusCode::ACCEPTED));
    }

    // Delegate to the MCP server
    let rpc_response = server.handle_request(rpc_request).await;
    if let Some(error) = &rpc_response.error {
        diagnostics.push(format!(
            "{request_description} -> error {} ({})",
            error.code, error.message
        ));
    } else {
        diagnostics.push(format!("{request_description} -> ok"));
    }

    let json_bytes = serde_json::to_vec(&rpc_response).unwrap_or_default();
    let response = Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(json_bytes)))
        .unwrap_or_else(|_| {
            warn!("Failed to build HTTP response for MCP result");
            let mut resp = Response::new(Full::new(Bytes::new()));
            *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            resp
        });

    Ok(response)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::mcp::McpTool;
    use crate::mcp::protocol::McpToolResult;
    use async_trait::async_trait;
    use serde_json::Value;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct EchoTool;

    #[async_trait]
    impl McpTool for EchoTool {
        fn name(&self) -> &str {
            "echo"
        }

        fn description(&self) -> &str {
            "Echoes back the input message"
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

        async fn execute(&self, arguments: Value) -> crate::Result<McpToolResult> {
            let msg = arguments
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("no message");
            Ok(McpToolResult::text(msg))
        }
    }

    #[tokio::test]
    async fn test_http_server_start_and_shutdown() {
        let server = Arc::new(McpServer::new("test", "1.0.0"));
        let http = HttpMcpServer::start(server).await.unwrap();

        assert!(http.port() > 0);
        let url = http.url();
        assert!(url.starts_with("http://127.0.0.1:"));
        assert!(!http.token().is_empty());

        http.shutdown().await;
    }

    #[tokio::test]
    async fn test_http_server_registers_on_ephemeral_port() {
        let server = Arc::new(McpServer::new("test", "1.0.0"));
        server.register_tool(Arc::new(EchoTool)).await;

        let http = HttpMcpServer::start(Arc::clone(&server)).await.unwrap();
        // Ephemeral ports are typically > 1024
        assert!(http.port() > 1024);

        http.shutdown().await;
    }

    #[tokio::test]
    async fn test_http_server_unique_tokens() {
        let server1 = Arc::new(McpServer::new("test1", "1.0.0"));
        let server2 = Arc::new(McpServer::new("test2", "1.0.0"));

        let http1 = HttpMcpServer::start(server1).await.unwrap();
        let http2 = HttpMcpServer::start(server2).await.unwrap();

        assert_ne!(
            http1.token(),
            http2.token(),
            "each server should have a unique token"
        );

        http1.shutdown().await;
        http2.shutdown().await;
    }

    #[tokio::test]
    async fn test_http_url_format() {
        let server = Arc::new(McpServer::new("test", "1.0.0"));
        let http = HttpMcpServer::start(server).await.unwrap();

        let url = http.url();
        assert!(url.starts_with("http://127.0.0.1:"));
        let port_str = url.strip_prefix("http://127.0.0.1:").unwrap();
        let port: u16 = port_str.parse().expect("port should be a valid u16");
        assert!(port > 0);
        assert_eq!(port, http.port());

        http.shutdown().await;
    }

    #[tokio::test]
    async fn test_initialized_notification_returns_accepted_without_jsonrpc_body() {
        let server = Arc::new(McpServer::new("test", "1.0.0"));
        let http = HttpMcpServer::start(server).await.unwrap();

        let body = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
        let request = format!(
            "POST / HTTP/1.1\r\n\
             Host: 127.0.0.1:{}\r\n\
             Authorization: Bearer {}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n\
             {}",
            http.port(),
            http.token(),
            body.len(),
            body
        );

        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", http.port()))
            .await
            .unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();

        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        let response = String::from_utf8(response).unwrap();

        assert!(
            response.starts_with("HTTP/1.1 202 Accepted"),
            "unexpected response: {response}"
        );
        assert!(
            !response.contains("\"jsonrpc\""),
            "notifications must not receive JSON-RPC response bodies: {response}"
        );

        http.shutdown().await;
    }
}
