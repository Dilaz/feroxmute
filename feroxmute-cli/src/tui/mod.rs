//! Terminal User Interface module

pub mod app;
pub mod channel;
pub mod colors;
pub mod events;
pub mod runner;
pub mod widgets;

pub use app::{AgentStatuses, AgentView, App, FeedEntry, Metrics, View, VulnCounts};
pub use channel::AgentEvent;
pub use events::{handle_event, poll_event, EventResult};
pub use runner::run;
