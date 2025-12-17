use anyhow::Result;
use tracing_subscriber::EnvFilter;

fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    println!("feroxmute v{}", env!("CARGO_PKG_VERSION"));
    Ok(())
}
