//! feroxmute-core: LLM-powered penetration testing framework library

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]

pub mod agents;
pub mod config;
pub mod docker;
pub mod error;
pub mod providers;
pub mod reports;
pub mod state;
pub mod targets;
pub mod tools;

pub use error::{Error, Result};
