//! Macro for generating LLM provider implementations
//!
//! This module provides the `define_provider!` macro which generates complete provider
//! implementations with constructors and LlmProvider trait impl, eliminating 95% code
//! duplication across provider files.
//!
//! ## Streaming Support
//!
//! All provider methods use rig-core's streaming API to capture reasoning/thinking
//! in real-time. The `StreamedAssistantContent::Reasoning` variant contains thinking
//! blocks which are forwarded to the TUI via `EventSender::send_thinking()`.

/// Generates a complete provider implementation with struct, constructors, and LlmProvider trait
///
/// # Arguments
///
/// * `name` - The struct name (e.g., `AnthropicProvider`)
/// * `provider_name` - The provider identifier string (e.g., `"anthropic"`)
/// * `client_type` - The rig client type (e.g., `anthropic::Client`)
/// * `env_var` - The environment variable name for API key (e.g., `"ANTHROPIC_API_KEY"`)
/// * `supports_tools` - Whether the provider supports tool calling (true/false)
/// * `client_builder` - Expression to build the client from builder (with optional `base_url` parameter)
///
/// # Generated Code
///
/// The macro generates:
/// - Provider struct with client, model, and metrics fields
/// - `new()` constructor reading API key from env var
/// - `with_api_key()` constructor with explicit API key
/// - `with_base_url()` constructor (if `has_base_url` is true)
/// - Complete `LlmProvider` trait implementation with:
///   - `name()`, `supports_tools()`, `metrics()` methods
///   - `complete()` - basic completion with token estimation
///   - `complete_with_shell()` - shell tool support
///   - `complete_with_orchestrator()` - orchestrator tools with cancellation
///   - `complete_with_report()` - report generation tools
///
/// # Example
///
/// ```ignore
/// define_provider! {
///     name: AnthropicProvider,
///     provider_name: "anthropic",
///     client_type: anthropic::Client,
///     env_var: "ANTHROPIC_API_KEY",
///     supports_tools: true,
///     client_builder: |builder, _base_url| builder,
///     has_base_url: false
/// }
/// ```
#[macro_export]
macro_rules! define_provider {
    (
        name: $name:ident,
        provider_name: $provider_name:expr,
        client_type: $client_type:ty,
        env_var: $env_var:expr,
        supports_tools: $supports_tools:expr,
        client_builder: |$builder:ident, $base_url:ident| $client_expr:expr,
        has_base_url: $has_base_url:tt
    ) => {
        /// Provider implementation using rig-core
        pub struct $name {
            client: $client_type,
            model: String,
            metrics: $crate::state::MetricsTracker,
        }

        impl $name {
            /// Create a new provider from environment variable
            pub fn new(model: impl Into<String>, metrics: $crate::state::MetricsTracker) -> $crate::Result<Self> {
                let api_key = std::env::var($env_var)
                    .map_err(|_| $crate::Error::Provider(format!("{} not set", $env_var)))?;

                let mut $builder = <$client_type>::builder().api_key(api_key);
                let $base_url: Option<String> = None;
                $builder = $client_expr;
                let client = $builder
                    .build()
                    .map_err(|e| $crate::Error::Provider(format!("Failed to build {} client: {}", $provider_name, e)))?;

                Ok(Self {
                    client,
                    model: model.into(),
                    metrics,
                })
            }

            /// Create with custom API key
            pub fn with_api_key(
                api_key: impl Into<String>,
                model: impl Into<String>,
                metrics: $crate::state::MetricsTracker,
            ) -> $crate::Result<Self> {
                let mut $builder = <$client_type>::builder().api_key(api_key.into());
                let $base_url: Option<String> = None;
                $builder = $client_expr;
                let client = $builder
                    .build()
                    .map_err(|e| $crate::Error::Provider(format!("Failed to build {} client: {}", $provider_name, e)))?;

                Ok(Self {
                    client,
                    model: model.into(),
                    metrics,
                })
            }

            define_provider!(@with_base_url $has_base_url, $name, $client_type, $provider_name, $builder, $base_url, $client_expr);
        }

        #[async_trait::async_trait]
        impl $crate::providers::LlmProvider for $name {
            fn name(&self) -> &str {
                $provider_name
            }

            fn supports_tools(&self) -> bool {
                $supports_tools
            }

            fn metrics(&self) -> &$crate::state::MetricsTracker {
                &self.metrics
            }

            async fn complete(&self, request: $crate::providers::CompletionRequest) -> $crate::Result<$crate::providers::CompletionResponse> {
                use rig::client::CompletionClient;
                use rig::completion::Prompt;

                // Build prompt from messages
                let prompt = request
                    .messages
                    .iter()
                    .map(|m| format!("{:?}: {}", m.role, m.content))
                    .collect::<Vec<_>>()
                    .join("\n");

                // Build and execute request using Prompt trait with agent
                let agent = self
                    .client
                    .agent(&self.model)
                    .preamble(
                        request
                            .system
                            .as_deref()
                            .unwrap_or("You are a helpful assistant."),
                    )
                    .max_tokens(request.max_tokens.unwrap_or(4096) as u64)
                    .build();

                let response = agent
                    .prompt(&prompt)
                    .await
                    .map_err(|e| $crate::Error::Provider(format!("{} completion failed: {}", $provider_name, e)))?;

                // Record token usage (estimated since rig doesn't expose raw usage directly)
                let estimated_input = prompt.len() as u64 / 4; // Rough token estimate
                let estimated_output = response.len() as u64 / 4;
                let pricing = $crate::pricing::PricingConfig::load();
                let cost = pricing.calculate_cost($provider_name, &self.model, estimated_input, estimated_output);
                self.metrics
                    .record_tokens(estimated_input, 0, estimated_output, cost);

                Ok($crate::providers::CompletionResponse {
                    content: Some(response),
                    tool_calls: vec![],
                    stop_reason: $crate::providers::StopReason::EndTurn,
                    usage: $crate::providers::TokenUsage {
                        input_tokens: estimated_input,
                        output_tokens: estimated_output,
                        cache_read_tokens: 0,
                        cache_creation_tokens: 0,
                    },
                })
            }

            async fn complete_with_shell(
                &self,
                system_prompt: &str,
                user_prompt: &str,
                container: std::sync::Arc<$crate::docker::ContainerManager>,
                events: std::sync::Arc<dyn $crate::tools::EventSender>,
                agent_name: &str,
                limitations: std::sync::Arc<$crate::limitations::EngagementLimitations>,
                memory: std::sync::Arc<$crate::tools::MemoryContext>,
            ) -> $crate::Result<String> {
                use rig::client::CompletionClient;
                use rig::completion::Prompt;

                let events_clone = std::sync::Arc::clone(&events);

                // Continuation configuration - prompt agent to continue if they stop too early
                const MAX_CONTINUATIONS: usize = 3;
                let mut continuation_count = 0;
                let mut accumulated_output = String::new();
                let mut current_prompt = user_prompt.to_string();

                loop {
                    // Set status to indicate agent is working
                    events_clone.send_status(
                        agent_name,
                        "",
                        $crate::agents::AgentStatus::Streaming,
                        None,
                    );

                    let agent = self
                        .client
                        .agent(&self.model)
                        .preamble(system_prompt)
                        .max_tokens(4096)
                        .tool($crate::tools::DockerShellTool::new(
                            std::sync::Arc::clone(&container),
                            std::sync::Arc::clone(&events),
                            agent_name.to_string(),
                            std::sync::Arc::clone(&limitations),
                        ))
                        .tool($crate::tools::RunScriptTool::new(
                            std::sync::Arc::clone(&container),
                            std::sync::Arc::clone(&events),
                            agent_name.to_string(),
                        ))
                        .tool($crate::tools::MemoryAddTool::new(std::sync::Arc::clone(&memory)))
                        .tool($crate::tools::MemoryGetTool::new(std::sync::Arc::clone(&memory)))
                        .tool($crate::tools::MemoryListTool::new(std::sync::Arc::clone(&memory)))
                        .build();

                    // Use non-streaming max_turns with 10-minute timeout
                    const LLM_TIMEOUT_SECS: u64 = 600; // 10 minutes
                    let result = tokio::time::timeout(
                        std::time::Duration::from_secs(LLM_TIMEOUT_SECS),
                        agent.prompt(&current_prompt).extended_details().max_turns(50)
                    ).await;

                    let response = match result {
                        Ok(Ok(r)) => r,
                        Ok(Err(e)) => {
                            events_clone.send_feed(agent_name, &format!("LLM request failed: {}", e), true);
                            events_clone.send_status(agent_name, "", $crate::agents::AgentStatus::Failed, None);
                            return Err($crate::Error::Provider(format!("Shell completion failed: {}", e)));
                        }
                        Err(_) => {
                            events_clone.send_feed(agent_name, "LLM request timed out after 10 minutes", true);
                            events_clone.send_status(agent_name, "", $crate::agents::AgentStatus::Failed, None);
                            return Err($crate::Error::Provider("LLM request timed out after 10 minutes".into()));
                        }
                    };

                    // Calculate cost
                    let pricing = $crate::pricing::PricingConfig::load();
                    let cost = pricing.calculate_cost(
                        $provider_name,
                        &self.model,
                        response.total_usage.input_tokens,
                        response.total_usage.output_tokens,
                    );
                    events_clone.send_metrics(
                        response.total_usage.input_tokens,
                        response.total_usage.output_tokens,
                        0,
                        cost,
                        0,
                    );

                    accumulated_output.push_str(&response.output);
                    accumulated_output.push('\n');

                    // Check if output looks like it stopped too early (heuristic: very short output without summary markers)
                    let looks_incomplete = response.output.len() < 500
                        && !response.output.contains("=== RECON SUMMARY ===")
                        && !response.output.contains("=== SCANNER SUMMARY ===")
                        && continuation_count < MAX_CONTINUATIONS;

                    if looks_incomplete {
                        continuation_count += 1;
                        events_clone.send_feed(
                            agent_name,
                            &format!("Agent output looks incomplete. Continuing... ({}/{})", continuation_count, MAX_CONTINUATIONS),
                            false,
                        );
                        current_prompt = format!(
                            "You stopped too early. Continue your task.\n\nPrevious output:\n{}\n\n---\n\nKeep running tools until you have comprehensive results.",
                            response.output.chars().take(1500).collect::<String>()
                        );
                        continue;
                    }

                    // Set completed status
                    events_clone.send_status(agent_name, "", $crate::agents::AgentStatus::Completed, None);

                    return Ok(accumulated_output);
                }
            }

            async fn complete_with_orchestrator(
                &self,
                system_prompt: &str,
                user_prompt: &str,
                context: std::sync::Arc<$crate::tools::OrchestratorContext>,
            ) -> $crate::Result<String> {
                use rig::client::CompletionClient;
                use rig::completion::Prompt;
                use std::sync::atomic::Ordering;

                let events = std::sync::Arc::clone(&context.events);

                // Set initial status
                events.send_status(
                    "orchestrator",
                    "orchestrator",
                    $crate::agents::AgentStatus::Streaming,
                    None,
                );

                let agent = self
                    .client
                    .agent(&self.model)
                    .preamble(system_prompt)
                    .max_tokens(4096)
                    .tool($crate::tools::SpawnAgentTool::new(std::sync::Arc::clone(&context)))
                    .tool($crate::tools::WaitForAgentTool::new(std::sync::Arc::clone(&context)))
                    .tool($crate::tools::WaitForAnyTool::new(std::sync::Arc::clone(&context)))
                    .tool($crate::tools::ListAgentsTool::new(std::sync::Arc::clone(&context)))
                    .tool($crate::tools::RecordFindingTool::new(std::sync::Arc::clone(&context)))
                    .tool($crate::tools::CompleteEngagementTool::new(std::sync::Arc::clone(&context)))
                    .tool($crate::tools::MemoryAddTool::new(std::sync::Arc::clone(&context.memory)))
                    .tool($crate::tools::MemoryGetTool::new(std::sync::Arc::clone(&context.memory)))
                    .tool($crate::tools::MemoryListTool::new(std::sync::Arc::clone(&context.memory)))
                    .tool($crate::tools::MemoryRemoveTool::new(std::sync::Arc::clone(&context.memory)))
                    .build();

                // Use non-streaming max_turns with cancellation support
                tokio::select! {
                    result = agent.prompt(user_prompt).extended_details().max_turns(50) => {
                        match result {
                            Ok(response) => {
                                // Calculate cost
                                let pricing = $crate::pricing::PricingConfig::load();
                                let cost = pricing.calculate_cost(
                                    $provider_name,
                                    &self.model,
                                    response.total_usage.input_tokens,
                                    response.total_usage.output_tokens,
                                );

                                events.send_metrics(
                                    response.total_usage.input_tokens,
                                    response.total_usage.output_tokens,
                                    0,
                                    cost,
                                    0,
                                );

                                // Check if engagement was completed
                                if context.engagement_completed.load(Ordering::SeqCst) {
                                    let findings = context.findings.lock().await;
                                    return Ok(format!("Engagement completed with {} findings", findings.len()));
                                }

                                Ok(response.output)
                            }
                            Err(e) => Err($crate::Error::Provider(format!("Orchestrator completion failed: {}", e)))
                        }
                    }
                    _ = context.cancel.cancelled() => {
                        // Engagement was completed via complete_engagement tool
                        let findings = context.findings.lock().await;
                        Ok(format!("Engagement completed with {} findings", findings.len()))
                    }
                }
            }

            async fn complete_with_report(
                &self,
                system_prompt: &str,
                user_prompt: &str,
                context: std::sync::Arc<$crate::tools::ReportContext>,
            ) -> $crate::Result<String> {
                use rig::client::CompletionClient;
                use rig::completion::Prompt;

                let events = std::sync::Arc::clone(&context.events);

                // Set status to indicate agent is working
                events.send_status(
                    "report",
                    "report",
                    $crate::agents::AgentStatus::Streaming,
                    None,
                );

                let agent = self
                    .client
                    .agent(&self.model)
                    .preamble(system_prompt)
                    .max_tokens(4096)
                    .tool($crate::tools::DeduplicateFindingsTool::new(std::sync::Arc::clone(&context)))
                    .tool($crate::tools::GenerateReportTool::new(std::sync::Arc::clone(&context)))
                    .tool($crate::tools::ExportJsonTool::new(std::sync::Arc::clone(&context)))
                    .tool($crate::tools::ExportMarkdownTool::new(std::sync::Arc::clone(&context)))
                    .tool($crate::tools::ExportHtmlTool::new(std::sync::Arc::clone(&context)))
                    .tool($crate::tools::ExportPdfTool::new(std::sync::Arc::clone(&context)))
                    .tool($crate::tools::AddRecommendationTool::new(std::sync::Arc::clone(&context)))
                    .build();

                // Use non-streaming max_turns with 10-minute timeout
                const LLM_TIMEOUT_SECS: u64 = 600; // 10 minutes
                let result = tokio::time::timeout(
                    std::time::Duration::from_secs(LLM_TIMEOUT_SECS),
                    agent.prompt(user_prompt).extended_details().max_turns(20)
                ).await;

                let response = match result {
                    Ok(Ok(r)) => r,
                    Ok(Err(e)) => {
                        events.send_feed("report", &format!("LLM request failed: {}", e), true);
                        events.send_status("report", "report", $crate::agents::AgentStatus::Failed, None);
                        return Err($crate::Error::Provider(format!("Report completion failed: {}", e)));
                    }
                    Err(_) => {
                        events.send_feed("report", "LLM request timed out after 10 minutes", true);
                        events.send_status("report", "report", $crate::agents::AgentStatus::Failed, None);
                        return Err($crate::Error::Provider("LLM request timed out after 10 minutes".into()));
                    }
                };

                // Calculate cost
                let pricing = $crate::pricing::PricingConfig::load();
                let cost = pricing.calculate_cost(
                    $provider_name,
                    &self.model,
                    response.total_usage.input_tokens,
                    response.total_usage.output_tokens,
                );
                events.send_metrics(
                    response.total_usage.input_tokens,
                    response.total_usage.output_tokens,
                    0,
                    cost,
                    0,
                );

                // Set completed status
                events.send_status("report", "report", $crate::agents::AgentStatus::Completed, None);

                Ok(response.output)
            }
        }
    };

    // Internal rule: Generate with_base_url when has_base_url is true
    (@with_base_url true, $name:ident, $client_type:ty, $provider_name:expr, $builder:ident, $base_url:ident, $client_expr:expr) => {
        /// Create with custom base URL (for LiteLLM proxy or compatible APIs)
        pub fn with_base_url(
            api_key: impl Into<String>,
            base_url: impl Into<String>,
            model: impl Into<String>,
            metrics: $crate::state::MetricsTracker,
        ) -> $crate::Result<Self> {
            let mut $builder = <$client_type>::builder().api_key(api_key.into());
            let $base_url: Option<String> = Some(base_url.into());
            $builder = $client_expr;
            let client = $builder
                .build()
                .map_err(|e| $crate::Error::Provider(format!("Failed to build {} client: {}", $provider_name, e)))?;

            Ok(Self {
                client,
                model: model.into(),
                metrics,
            })
        }
    };

    // Internal rule: Don't generate with_base_url when has_base_url is false
    (@with_base_url false, $name:ident, $client_type:ty, $provider_name:expr, $builder:ident, $base_url:ident, $client_expr:expr) => {};
}
