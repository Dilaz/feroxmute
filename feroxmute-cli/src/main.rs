mod args;

use anyhow::Result;
use args::Args;
use clap::Parser;
use tracing_subscriber::EnvFilter;

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
        println!("Target: {}", target);
        println!("Scope: {}", args.scope);
        println!("Provider: {}", args.provider);
        if let Some(ref model) = args.model {
            println!("Model: {}", model);
        }
    } else {
        println!("No target specified. Use --target or --wizard");
    }

    Ok(())
}
