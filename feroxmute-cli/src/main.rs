mod args;
mod runner;
mod tui;
mod wizard;

use anyhow::{anyhow, Result};
use args::Args;
use clap::Parser;
use feroxmute_core::config::{EngagementConfig, ProviderConfig, ProviderName};
use feroxmute_core::docker::{find_docker_dir, ContainerConfig, ContainerManager};
use feroxmute_core::limitations::EngagementLimitations;
use feroxmute_core::providers::create_provider;
use feroxmute_core::state::MetricsTracker;
use feroxmute_core::targets::{RelationshipDetector, TargetCollection};
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

fn format_relative_time(dt: chrono::DateTime<chrono::Utc>) -> String {
    let now = chrono::Utc::now();
    let duration = now.signed_duration_since(dt);

    if duration.num_seconds() < 60 {
        "just now".to_string()
    } else if duration.num_minutes() < 60 {
        format!("{}m ago", duration.num_minutes())
    } else if duration.num_hours() < 24 {
        format!("{}h ago", duration.num_hours())
    } else if duration.num_days() < 7 {
        format!("{}d ago", duration.num_days())
    } else {
        dt.format("%Y-%m-%d").to_string()
    }
}

fn find_session_by_pattern(sessions_dir: &std::path::Path, pattern: &std::path::Path) -> anyhow::Result<std::path::PathBuf> {
    let pattern_str = pattern.to_string_lossy();

    if !sessions_dir.exists() {
        anyhow::bail!("Sessions directory does not exist: {}", sessions_dir.display());
    }

    let mut matches: Vec<_> = std::fs::read_dir(sessions_dir)?
        .filter_map(|e| e.ok())
        .filter(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            name.contains(pattern_str.as_ref()) ||
            // Also match by target hostname
            feroxmute_core::state::Session::resume(e.path())
                .map(|s| s.config.target.host.contains(pattern_str.as_ref()))
                .unwrap_or(false)
        })
        .collect();

    // Sort by modification time (newest first)
    matches.sort_by(|a, b| {
        let a_time = a.metadata().and_then(|m| m.modified()).ok();
        let b_time = b.metadata().and_then(|m| m.modified()).ok();
        b_time.cmp(&a_time)
    });

    match matches.len() {
        0 => anyhow::bail!("No session found matching: {}", pattern_str),
        1 => Ok(matches.into_iter().next().expect("len is 1").path()),
        _ => {
            println!("Multiple sessions match '{}'. Please be more specific:", pattern_str);
            for entry in &matches {
                println!("  {}", entry.file_name().to_string_lossy());
            }
            anyhow::bail!("Ambiguous session pattern");
        }
    }
}

#[tokio::main]
#[allow(clippy::print_stdout)]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Set up tracing based on verbosity
    let filter = match args.verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };

    // Create logs directory
    let log_dir = dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".feroxmute")
        .join("logs");
    fs::create_dir_all(&log_dir).ok();

    // Set up file appender for persistent logs
    let file_appender = tracing_appender::rolling::daily(&log_dir, "feroxmute.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    // Combine file and console logging
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| filter.into());
    tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer().with_writer(non_blocking))
        .init();

    tracing::info!("feroxmute v{}", env!("CARGO_PKG_VERSION"));

    if args.wizard {
        match wizard::run_wizard() {
            Ok(path) => {
                println!("\n✓ Configuration saved to: {}", path.display());
                println!("\nYou can now run feroxmute with:");
                println!("  feroxmute --target example.com");
                return Ok(());
            }
            Err(e) => {
                if e.to_string().contains("cancelled") {
                    println!("\nWizard cancelled.");
                } else {
                    eprintln!("\nError: {}", e);
                }
                return Ok(());
            }
        }
    }

    // Load configuration
    let mut config = EngagementConfig::load_default();
    config.expand_env_vars();

    if args.list_sessions {
        let sessions_dir = config.output.session_dir.clone();
        if !sessions_dir.exists() {
            println!("No sessions found. Directory does not exist: {}", sessions_dir.display());
            return Ok(());
        }

        println!("{:<40} {:<20} {:<12} {}", "SESSION ID", "TARGET", "STATUS", "LAST ACTIVITY");
        println!("{}", "-".repeat(90));

        let mut sessions: Vec<_> = std::fs::read_dir(&sessions_dir)?
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_dir())
            .collect();

        // Sort by modification time (newest first)
        sessions.sort_by(|a, b| {
            let a_time = a.metadata().and_then(|m| m.modified()).ok();
            let b_time = b.metadata().and_then(|m| m.modified()).ok();
            b_time.cmp(&a_time)
        });

        for entry in sessions {
            let path = entry.path();
            match feroxmute_core::state::Session::resume(&path) {
                Ok(session) => {
                    let status = session.status()
                        .map(|s| format!("{:?}", s))
                        .unwrap_or_else(|_| "unknown".to_string());
                    let last_activity = session.last_activity()
                        .map(format_relative_time)
                        .unwrap_or_else(|_| "unknown".to_string());
                    println!("{:<40} {:<20} {:<12} {}",
                        session.id,
                        session.config.target.host,
                        status.to_lowercase(),
                        last_activity
                    );
                }
                Err(_) => {
                    // Skip invalid session directories
                }
            }
        }

        return Ok(());
    }

    // Resolve provider: CLI arg takes precedence, then config file, then default
    let provider_name = args
        .provider
        .as_ref()
        .map(|p| match p.to_lowercase().as_str() {
            "anthropic" => ProviderName::Anthropic,
            "openai" => ProviderName::OpenAi,
            "litellm" => ProviderName::LiteLlm,
            "cohere" => ProviderName::Cohere,
            "gemini" => ProviderName::Gemini,
            "xai" => ProviderName::Xai,
            "deepseek" => ProviderName::DeepSeek,
            "azure" => ProviderName::Azure,
            "perplexity" => ProviderName::Perplexity,
            "mira" => ProviderName::Mira,
            "ollama" => ProviderName::Ollama,
            _ => ProviderName::Anthropic,
        })
        .unwrap_or_else(|| config.provider.name.clone());

    let provider_config = ProviderConfig {
        name: provider_name,
        model: args
            .model
            .clone()
            .unwrap_or_else(|| config.provider.model.clone()),
        api_key: config.provider.api_key.clone(),
        base_url: config.provider.base_url.clone(),
    };

    // Validate LLM provider - fail fast
    let metrics = MetricsTracker::new();
    let provider = create_provider(&provider_config, metrics).map_err(|e| {
        anyhow!(
            "LLM provider error: {}\n\nHint: Set API key in ~/.feroxmute/config.toml or {} environment variable",
            e,
            match provider_config.name {
                ProviderName::Anthropic => "ANTHROPIC_API_KEY",
                ProviderName::OpenAi => "OPENAI_API_KEY",
                ProviderName::Cohere => "COHERE_API_KEY",
                ProviderName::Gemini => "GEMINI_API_KEY or GOOGLE_API_KEY",
                ProviderName::Xai => "XAI_API_KEY",
                ProviderName::DeepSeek => "DEEPSEEK_API_KEY",
                ProviderName::Azure => "AZURE_OPENAI_API_KEY",
                ProviderName::Perplexity => "PERPLEXITY_API_KEY",
                ProviderName::Mira => "MIRA_API_KEY",
                ProviderName::LiteLlm => "LITELLM_API_KEY",
                ProviderName::Ollama => "OLLAMA_API_BASE_URL (optional, defaults to localhost:11434)",
            }
        )
    })?;

    // Check Docker connectivity - fail fast
    let docker = bollard::Docker::connect_with_local_defaults().map_err(|_| {
        anyhow!("Cannot connect to Docker.\n\nHint: Is Docker running? Try 'docker ps'")
    })?;

    docker.ping().await.map_err(|_| {
        anyhow!("Docker not responding.\n\nHint: Is Docker daemon running? Try 'docker ps'")
    })?;

    // Check if Kali image exists, build if needed
    let container_config = ContainerConfig::default();
    match docker.inspect_image(&container_config.image).await {
        Ok(_) => {
            tracing::info!("Docker image '{}' found", container_config.image);
        }
        Err(_) => {
            println!(
                "Docker image '{}' not found. Building...",
                container_config.image
            );

            // Find the docker directory
            let docker_dir = find_docker_dir().map_err(|e| {
                anyhow!(
                    "Could not find docker directory: {}\n\nHint: Ensure you're running from the project root or set FEROXMUTE_DOCKER_DIR",
                    e
                )
            })?;

            // Create a temporary ContainerManager to build the image
            let temp_container = ContainerManager::new(ContainerConfig::default())
                .await
                .map_err(|e| anyhow!("Failed to create container manager for building: {}", e))?;

            // Build the image with progress output
            temp_container
                .build_image(&docker_dir, |msg| {
                    print!("{}", msg);
                    io::stdout().flush().ok();
                })
                .await
                .map_err(|e| anyhow!("Failed to build Docker image: {}", e))?;

            println!("\nDocker image built successfully!");
        }
    }

    tracing::info!("Docker and LLM provider validated successfully");

    if !args.target.is_empty() {
        // Parse all targets into a TargetCollection
        let mut targets = TargetCollection::from_strings(&args.target)?;

        // If --source is explicitly provided, add it to the collection and link to primary web target
        if let Some(ref source_path) = args.source {
            let source_str = source_path.to_string_lossy().to_string();

            // First, parse and add the source to the collection
            match feroxmute_core::targets::Target::parse(&source_str) {
                Ok(source_target) => {
                    if source_target.is_source() {
                        targets.add_target(source_target);

                        // Now link it to the primary web target
                        let web_raw = targets.web_targets().first().map(|t| t.raw.clone());
                        if let Some(web_target_raw) = web_raw {
                            let linked = targets.link_source_to_web(&source_str, &web_target_raw);
                            if linked {
                                tracing::info!(
                                    "Explicitly linked source {} to {}",
                                    source_str,
                                    web_target_raw
                                );
                            } else {
                                tracing::warn!(
                                    "Failed to link source {} to {}",
                                    source_str,
                                    web_target_raw
                                );
                            }
                        } else {
                            tracing::warn!("--source provided but no web target found");
                        }
                    } else {
                        tracing::warn!(
                            "--source path {} is not a valid source directory",
                            source_str
                        );
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to parse --source path {}: {}", source_str, e);
                }
            }
        }

        // If not --separate, run relationship detection
        if !args.separate && !targets.standalone_sources.is_empty() {
            let hints = RelationshipDetector::detect(&targets);

            for hint in hints {
                if hint.confidence >= 0.5 {
                    // Auto-link high confidence matches
                    targets.link_source_to_web(&hint.source_raw, &hint.web_raw);
                    tracing::info!(
                        "Auto-linked {} to {} (confidence: {:.2}, reason: {})",
                        hint.source_raw,
                        hint.web_raw,
                        hint.confidence,
                        hint.reason
                    );
                } else if hint.confidence >= 0.3 {
                    // For medium confidence, ask user
                    println!("\nDetected potential relationship:");
                    println!("  Source: {}", hint.source_raw);
                    println!("  Web target: {}", hint.web_raw);
                    println!("  Confidence: {:.2}", hint.confidence);
                    println!("  Reason: {}", hint.reason);
                    print!("Link them? [Y/n]: ");
                    io::stdout().flush()?;

                    let mut response = String::new();
                    io::stdin().read_line(&mut response)?;
                    let response = response.trim().to_lowercase();

                    if response.is_empty() || response == "y" || response == "yes" {
                        targets.link_source_to_web(&hint.source_raw, &hint.web_raw);
                        tracing::info!(
                            "User confirmed linking {} to {}",
                            hint.source_raw,
                            hint.web_raw
                        );
                    } else {
                        tracing::info!(
                            "User declined linking {} to {}",
                            hint.source_raw,
                            hint.web_raw
                        );
                    }
                } else {
                    // Low confidence - just log for information
                    tracing::debug!(
                        "Low confidence relationship hint: {} -> {} (confidence: {:.2})",
                        hint.source_raw,
                        hint.web_raw,
                        hint.confidence
                    );
                }
            }
        }

        // Use the first web target for now (full multi-target support in orchestrator)
        let target = if let Some(web_target) = targets.web_targets().first() {
            match &web_target.target_type {
                feroxmute_core::targets::TargetType::Web { url } => url.clone(),
                _ => args.target.first().cloned().unwrap_or_default(),
            }
        } else {
            // No web targets, might be SAST-only
            if args.sast_only && !targets.standalone_sources.is_empty() {
                "sast-only".to_string()
            } else {
                println!("No web targets found. Use --sast-only for source code analysis only.");
                return Ok(());
            }
        };

        // Create or resume session
        let session = if let Some(ref resume_path) = args.resume {
            // Try exact path first, then search in sessions dir
            let path = if resume_path.exists() {
                resume_path.clone()
            } else {
                // Search for partial match in sessions directory
                find_session_by_pattern(&config.output.session_dir, resume_path)?
            };

            let session = feroxmute_core::state::Session::resume(&path)?;

            // Warn if resuming completed session
            if session.status()? == feroxmute_core::state::SessionStatus::Completed {
                print!("This engagement was completed. Resume anyway? [y/N]: ");
                io::stdout().flush()?;
                let mut response = String::new();
                io::stdin().read_line(&mut response)?;
                if !response.trim().to_lowercase().starts_with('y') {
                    println!("Aborted.");
                    return Ok(());
                }
            }

            // Set status back to Running
            session.set_status(feroxmute_core::state::SessionStatus::Running)?;
            session
        } else {
            // Update config with CLI target
            let mut session_config = config.clone();
            session_config.target.host = target.clone();
            feroxmute_core::state::Session::new(session_config, &config.output.session_dir)?
        };

        let session = Arc::new(session);

        // Create channel for agent events
        let (tx, rx) = mpsc::channel::<tui::AgentEvent>(100);

        // Create cancellation token
        let cancel = CancellationToken::new();

        // Create TUI app with receiver
        let mut app = tui::App::new(&target, &session.id, Some(rx));

        // Add initial feed entries
        app.add_feed(tui::FeedEntry::new(
            "system",
            format!("Starting engagement against {}", target),
        ));
        app.add_feed(tui::FeedEntry::new(
            "system",
            format!(
                "Provider: {:?} | Model: {}",
                provider_config.name, provider_config.model
            ),
        ));

        // Log custom instruction if provided
        if let Some(ref instr) = args.instruction {
            app.add_feed(tui::FeedEntry::new(
                "system",
                format!("Objective: {}", instr),
            ));
        }

        // If we have linked sources, add info about them
        for group in &targets.groups {
            if let Some(ref source) = group.source_target {
                app.add_feed(tui::FeedEntry::new(
                    "system",
                    format!(
                        "Linked source code: {} -> {}",
                        source.raw, group.web_target.raw
                    ),
                ));
            }
        }

        // If we have standalone sources, note them
        for source in &targets.standalone_sources {
            app.add_feed(tui::FeedEntry::new(
                "system",
                format!("Standalone source for SAST: {}", source.raw),
            ));
        }

        // Extract source path for container mounting (prefer linked, then standalone)
        let host_source_path: Option<String> = targets
            .groups
            .iter()
            .find_map(|g| g.source_target.as_ref().map(|s| s.raw.clone()))
            .or_else(|| targets.standalone_sources.first().map(|s| s.raw.clone()));

        // Create container config with source mount if available
        let container_config = if let Some(ref source) = host_source_path {
            ContainerConfig::default().with_source_mount(source)
        } else {
            ContainerConfig::default()
        };

        // Start the Kali container
        app.add_feed(tui::FeedEntry::new(
            "system",
            "Starting Docker container...",
        ));
        let mut container = ContainerManager::new(container_config).await.map_err(|e| {
            anyhow!(
                "Failed to create container manager: {}\n\nHint: Is Docker running?",
                e
            )
        })?;
        container.start().await.map_err(|e| {
            anyhow!(
                "Failed to start container: {}\n\nHint: Run 'docker compose build' first",
                e
            )
        })?;
        app.add_feed(tui::FeedEntry::new("system", "Docker container started"));

        // Create a LocalSet to run !Send futures
        let local = tokio::task::LocalSet::new();

        // Spawn agent task on LocalSet
        let agent_target = target.clone();
        let agent_cancel = cancel.clone();

        // If source is mounted, use container path /source instead of host path
        let source_path: Option<String> = if host_source_path.is_some() {
            Some("/source".to_string())
        } else {
            None
        };

        let container = Arc::new(container);

        // Build engagement limitations from CLI args
        let limitations = Arc::new(if args.sast_only {
            EngagementLimitations::for_sast_only()
        } else if args.passive {
            EngagementLimitations::for_passive()
        } else {
            let base = match args.scope.as_str() {
                "network" => EngagementLimitations::for_network_scope(
                    args.no_discovery,
                    args.no_exploit,
                    args.no_portscan,
                ),
                "full" => EngagementLimitations::for_full_scope(),
                _ => EngagementLimitations::for_web_scope(
                    args.no_discovery,
                    args.no_exploit,
                    args.no_portscan,
                ),
            };

            // Apply optional port and rate limit modifiers
            let base = if let Some(ref ports) = args.ports {
                let ports: Vec<u16> = ports
                    .split(',')
                    .filter_map(|p| p.trim().parse().ok())
                    .collect();
                base.with_ports(ports)
            } else {
                base
            };

            if let Some(rate) = args.rate_limit {
                base.with_rate_limit(rate)
            } else {
                base
            }
        });

        let instruction = args.instruction.clone();
        let agent_handle = local.spawn_local(async move {
            runner::run_orchestrator(
                agent_target,
                provider,
                container,
                tx,
                agent_cancel,
                source_path,
                limitations,
                instruction,
                Arc::clone(&session),
            )
            .await
        });

        // Spawn TUI in blocking task
        let tui_cancel = cancel.clone();
        let tui_handle = tokio::task::spawn_blocking(move || {
            let result = tui::run(&mut app);
            tui_cancel.cancel();
            result
        });

        // Run the LocalSet until agent completes or is cancelled
        local
            .run_until(async move {
                tokio::select! {
                    _ = agent_handle => {},
                    _ = cancel.cancelled() => {},
                }
            })
            .await;

        // Wait for TUI to finish
        tui_handle.await??;
    } else {
        println!("No target specified. Use --target or --wizard");
    }

    Ok(())
}
