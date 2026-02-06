//! HTTP endpoint for the MCP server
//!
//! Provides an HTTP POST endpoint that CLI agents can use to access
//! feroxmute tools via the MCP protocol over JSON-RPC.

use std::net::SocketAddr;
use std::sync::Arc;

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

use crate::Result;
use crate::mcp::McpServer;
use crate::mcp::protocol::{JsonRpcRequest, error_codes};

/// HTTP server wrapping an MCP server for tool access via HTTP POST.
///
/// Binds to an OS-assigned port on localhost and forwards JSON-RPC
/// requests to the underlying [`McpServer`].
pub struct HttpMcpServer {
    port: u16,
    shutdown_tx: Option<oneshot::Sender<()>>,
    _task: JoinHandle<()>,
}

impl HttpMcpServer {
    /// Start the HTTP MCP server on an OS-assigned port.
    ///
    /// Binds to `127.0.0.1:0` and spawns a background task to accept
    /// connections. Use [`url()`](Self::url) to get the server address.
    pub async fn start(server: Arc<McpServer>) -> Result<Self> {
        let addr = SocketAddr::from(([127, 0, 0, 1], 0));
        let listener = TcpListener::bind(addr).await?;
        let local_addr = listener.local_addr()?;
        let port = local_addr.port();

        debug!("MCP HTTP server listening on {}", local_addr);

        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

        let task = tokio::spawn(async move {
            Self::accept_loop(listener, server, shutdown_rx).await;
        });

        Ok(Self {
            port,
            shutdown_tx: Some(shutdown_tx),
            _task: task,
        })
    }

    /// The full URL of the running server (e.g. `http://127.0.0.1:12345`).
    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// The port the server is listening on.
    pub fn port(&self) -> u16 {
        self.port
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
        mut shutdown_rx: oneshot::Receiver<()>,
    ) {
        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, addr)) => {
                            debug!("MCP HTTP connection from {}", addr);
                            let server = Arc::clone(&server);
                            tokio::spawn(async move {
                                let io = TokioIo::new(stream);
                                let service = service_fn(move |req| {
                                    let server = Arc::clone(&server);
                                    handle_mcp_request(server, req)
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
                        }
                    }
                }
                _ = &mut shutdown_rx => {
                    debug!("MCP HTTP server shutting down");
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

/// Handle a single HTTP request by dispatching to the MCP server.
async fn handle_mcp_request(
    server: Arc<McpServer>,
    req: Request<hyper::body::Incoming>,
) -> std::result::Result<Response<Full<Bytes>>, hyper::Error> {
    // Only accept POST requests
    if req.method() != hyper::Method::POST {
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

    // Read and collect the request body
    let body = req.collect().await?.to_bytes();

    // Parse JSON-RPC request
    let rpc_request: JsonRpcRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
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

    // Handle notification methods that don't require processing
    if rpc_request.method == "notifications/initialized" || rpc_request.method == "initialized" {
        let response_body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": rpc_request.id,
            "result": {}
        });
        return Ok(json_response(StatusCode::OK, &response_body));
    }

    // Delegate to the MCP server
    let rpc_response = server.handle_request(rpc_request).await;

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
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::mcp::McpTool;
    use crate::mcp::protocol::McpToolResult;
    use async_trait::async_trait;
    use serde_json::Value;

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
}
