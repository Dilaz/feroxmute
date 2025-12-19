mod args;
mod runner;
mod tui;
mod wizard;

use anyhow::{anyhow, Result};
use args::Args;
use clap::Parser;
use feroxmute_core::config::{EngagementConfig, ProviderConfig, ProviderName};
use feroxmute_core::docker::ContainerConfig;
use feroxmute_core::providers::create_provider;
use feroxmute_core::state::MetricsTracker;
use feroxmute_core::targets::{RelationshipDetector, TargetCollection};
use std::io::{self, Write};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Set up tracing based on verbosity
    let filter = match args.verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| filter.into()))
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

    if let Some(ref session) = args.resume {
        println!("Resuming session: {}", session.display());
        return Ok(());
    }

    // Load configuration
    let config = EngagementConfig::load_default();

    // Build provider config from CLI args
    let provider_name = match args.provider.to_lowercase().as_str() {
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
        _ => ProviderName::Anthropic,
    };

    let provider_config = ProviderConfig {
        name: provider_name,
        model: args.model.clone().unwrap_or_else(|| config.provider.model.clone()),
        api_key: config.provider.api_key.clone(),
        base_url: config.provider.base_url.clone(),
    };

    // Validate LLM provider - fail fast
    let metrics = MetricsTracker::new();
    let provider = create_provider(&provider_config, metrics.clone()).map_err(|e| {
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
            }
        )
    })?;

    // Check Docker connectivity - fail fast
    let docker = bollard::Docker::connect_with_local_defaults()
        .map_err(|_| anyhow!("Cannot connect to Docker.\n\nHint: Is Docker running? Try 'docker ps'"))?;

    docker.ping().await.map_err(|_| {
        anyhow!("Docker not responding.\n\nHint: Is Docker daemon running? Try 'docker ps'")
    })?;

    // Check if Kali image exists
    let container_config = ContainerConfig::default();
    match docker.inspect_image(&container_config.image).await {
        Ok(_) => {}
        Err(_) => {
            return Err(anyhow!(
                "Docker image '{}' not found.\n\nHint: Run 'docker compose build' first",
                container_config.image
            ));
        }
    }

    tracing::info!("Docker and LLM provider validated successfully");

    if !args.target.is_empty() {
        // Parse all targets into a TargetCollection
        let mut targets = TargetCollection::from_strings(&args.target)?;

        // If --source is explicitly provided, link it to the primary web target
        if let Some(ref source_path) = args.source {
            let source_str = source_path.to_string_lossy().to_string();
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
                    tracing::warn!("Failed to link source {} to {}", source_str, web_target_raw);
                }
            } else {
                tracing::warn!("--source provided but no web target found");
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
                _ => args.target[0].clone(),
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

        // Create session ID
        let session_id = Uuid::new_v4().to_string()[..8].to_string();

        // Create TUI app
        let mut app = tui::App::new(&target, &session_id, None);

        // Add initial feed entries
        app.add_feed(tui::FeedEntry::new(
            "system",
            format!("Starting engagement against {}", target),
        ));
        app.add_feed(tui::FeedEntry::new(
            "system",
            format!("Provider: {} | Scope: {}", args.provider, args.scope),
        ));

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

        // If we have standalone sources (not linked), note them
        for source in &targets.standalone_sources {
            app.add_feed(tui::FeedEntry::new(
                "system",
                format!("Standalone source for SAST: {}", source.raw),
            ));
        }

        // Run TUI
        tui::run(&mut app)?;
    } else {
        println!("No target specified. Use --target or --wizard");
    }

    Ok(())
}
