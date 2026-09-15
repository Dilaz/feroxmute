//! Exercise session readiness against an ACP peer with a different default model.

use super::*;
use tokio::io::AsyncWriteExt as _;

async fn exercise_sessions(model: &str) -> Result<()> {
    let (client_io, agent_io) = tokio::io::duplex(16384);
    let (client_read, client_write) = tokio::io::split(client_io);
    let (agent_read, mut agent_write) = tokio::io::split(agent_io);
    let (tx, mut rx) = mpsc::channel(8);
    let (connect_tx, connect_rx) = oneshot::channel();
    let collector = Arc::new(std::sync::Mutex::new(ResponseCollector::default()));
    let activity = Arc::new(Notify::new());
    let diagnostics = Rc::new(RefCell::new(CliDiagnostics::default()));
    let config = CliAgentConfig::new(CliAgentType::ClaudeCode).with_model(model);

    let client = Client.builder().connect_with(
        ByteStreams::new(client_write.compat_write(), client_read.compat()),
        |connection: ConnectionTo<Agent>| async move {
            run_standard_protocol(
                connection,
                &mut rx,
                &collector,
                &activity,
                &diagnostics,
                connect_tx,
                &config,
            )
            .await;
            Ok(())
        },
    );
    let peer = async move {
        let mut lines = BufReader::new(agent_read).lines();
        let mut selected = String::new();
        let mut session_number = 0;
        while let Some(line) = lines.next_line().await.unwrap() {
            let request: Value = serde_json::from_str(&line).unwrap();
            let id = &request["id"];
            let response = match request["method"].as_str().unwrap() {
                "initialize" => json!({"result": {
                    "protocolVersion": 1, "agentCapabilities": {}
                }}),
                "session/new" => {
                    session_number += 1;
                    selected = "fable".into();
                    json!({"result": {"sessionId": format!("s{session_number}")}})
                }
                "session/set_config_option" => {
                    if request["params"]["configId"] == "model"
                        && request["params"]["value"] == "claude-opus-4-8"
                    {
                        selected = "claude-opus-4-8".into();
                        json!({"result": {"configOptions": []}})
                    } else {
                        json!({"error": {"code": -32602, "message": "Model unavailable"}})
                    }
                }
                "session/prompt" if selected == "claude-opus-4-8" => {
                    json!({"result": {"stopReason": "end_turn"}})
                }
                "session/prompt" => {
                    json!({"error": {"code": -32602, "message": "Prompt reached the wrong model"}})
                }
                method => panic!("Unexpected ACP method: {method}"),
            };
            let mut response = response;
            response["jsonrpc"] = json!("2.0");
            response["id"] = id.clone();
            agent_write
                .write_all(format!("{response}\n").as_bytes())
                .await
                .unwrap();
        }
    };
    let drive = async move {
        let result = async {
            connect_rx.await.unwrap()?;
            // Every specialist session must override the adapter's default independently.
            for role in ["orchestrator", "report"] {
                let (reply, result) = oneshot::channel();
                tx.send(AcpCommand::NewSession {
                    agent_role: role.into(),
                    working_dir: PathBuf::from("/tmp"),
                    mcp_server_url: None,
                    bearer_token: None,
                    reply,
                })
                .await
                .unwrap();
                let session_id = result.await.unwrap()?;
                let (reply, result) = oneshot::channel();
                tx.send(AcpCommand::Prompt {
                    session_id,
                    message: "Reply OK".into(),
                    reply,
                })
                .await
                .unwrap();
                result.await.unwrap()?;
            }
            Ok(())
        }
        .await;
        tx.send(AcpCommand::Shutdown).await.unwrap();
        result
    };
    let (client_result, (), result) = tokio::join!(client, peer, drive);
    client_result.unwrap();
    result
}

#[tokio::test]
async fn selected_model_overrides_adapter_default_for_every_session() {
    exercise_sessions("claude-opus-4-8").await.unwrap();
}

#[tokio::test]
async fn rejected_model_prevents_session_becoming_ready() {
    let error = exercise_sessions("unavailable-model").await.unwrap_err();
    assert!(error.to_string().contains("unavailable-model"), "{error}");
    assert!(error.to_string().contains("Model unavailable"), "{error}");
}
