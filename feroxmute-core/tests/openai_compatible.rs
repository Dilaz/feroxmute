//! OpenAI-compatible gateways must use the Chat Completions protocol.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::Duration;

use feroxmute_core::config::EngagementConfig;
use feroxmute_core::providers::{CompletionRequest, Message, create_provider};
use feroxmute_core::state::MetricsTracker;

async fn gateway_completion(config: &str) -> serde_json::Value {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut request = Vec::new();
        let mut buffer = [0; 4096];
        loop {
            let count = stream.read(&mut buffer).unwrap();
            assert_ne!(count, 0);
            request.extend_from_slice(&buffer[..count]);
            if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                let headers = String::from_utf8_lossy(&request[..end]);
                let length: usize = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse().unwrap())
                    })
                    .unwrap_or(0);
                if request.len() >= end + 4 + length {
                    break;
                }
            }
        }
        let chat = request.starts_with(b"POST /v1/chat/completions ");
        let body = if chat {
            serde_json::json!({
                "id": "completion-test", "object": "chat.completion", "created": 1,
                "model": "z-ai/glm-5.3-flash",
                "choices": [{"index": 0, "finish_reason": "stop", "logprobs": null,
                    "message": {"role": "assistant", "content": "OK", "reasoning": "Done"}}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3}
            })
        } else {
            serde_json::json!({
                "id": "response-test", "object": "response", "created_at": 1,
                "status": "completed", "model": "z-ai/glm-5.3-flash", "output": [],
                "reasoning": {"effort": "max"}
            })
        }
        .to_string();
        write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).unwrap();
        let end = request.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
        serde_json::from_slice::<serde_json::Value>(&request[end + 4..]).unwrap()
    });
    let mut config = EngagementConfig::parse(config).unwrap();
    config.provider.base_url = Some(format!("http://{address}/v1"));
    let provider = create_provider(&config.provider, MetricsTracker::new(), None).unwrap();
    let result = provider
        .complete(CompletionRequest::new(vec![Message::user("Reply OK")]))
        .await;
    let request = server.join().unwrap();
    assert_eq!(result.unwrap().content.as_deref(), Some("OK"));
    request
}

#[tokio::test]
async fn compatible_gateway_preserves_default_reasoning() {
    let request = gateway_completion(
        r#"
        [provider]
        name = "openai"
        model = "z-ai/glm-5.3-flash"
        api_key = "test-key"
    "#,
    )
    .await;
    assert!(request.get("reasoning_effort").is_none());
    assert!(request.get("reasoning").is_none());
}

#[tokio::test]
async fn compatible_gateway_applies_configured_reasoning() {
    let request = gateway_completion(
        r#"
        [provider]
        name = "openai"
        model = "reasoning-model"
        api_key = "test-key"
        reasoning_effort = "high"
    "#,
    )
    .await;
    assert_eq!(request["reasoning_effort"], "high");
}

#[tokio::test]
async fn litellm_explicit_none_disables_reasoning_instead_of_using_default() {
    let request = gateway_completion(
        r#"
        [provider]
        name = "litellm"
        model = "reasoning-model"
        api_key = "test-key"
        reasoning_effort = "none"
    "#,
    )
    .await;
    assert_eq!(request["reasoning_effort"], "none");
}
