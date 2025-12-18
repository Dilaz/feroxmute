mod args;
mod tui;

use anyhow::Result;
use args::Args;
use clap::Parser;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

fn main() -> Result<()> {
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
        println!("Interactive wizard not yet implemented");
        return Ok(());
    }

    if let Some(ref session) = args.resume {
        println!("Resuming session: {}", session.display());
        return Ok(());
    }

    if let Some(ref target) = args.target {
        // Create session ID
        let session_id = Uuid::new_v4().to_string()[..8].to_string();

        // Create TUI app
        let mut app = tui::App::new(target, &session_id);

        // Add initial feed entry
        app.add_feed(tui::FeedEntry::new(
            "system",
            format!("Starting engagement against {}", target),
        ));
        app.add_feed(tui::FeedEntry::new(
            "system",
            format!("Provider: {} | Scope: {}", args.provider, args.scope),
        ));

        // Run TUI
        tui::run(&mut app)?;
    } else {
        println!("No target specified. Use --target or --wizard");
    }

    Ok(())
}
