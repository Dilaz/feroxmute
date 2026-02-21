//! Event bus for inter-agent communication
//!
//! Provides an [`AgentEventBus`] that allows subagents to emit structured events
//! (findings, milestones, completion status) back to the orchestrator. The bus
//! uses a tokio mpsc channel internally; the sender half is cloneable and given
//! to each spawned agent.

use std::mem;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

/// An event emitted by a subagent during execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentEvent {
    /// Name of the agent that emitted this event
    pub agent_name: String,
    /// Type of agent (e.g. "recon", "scanner", "exploit")
    pub agent_type: String,
    /// When the event was created
    pub timestamp: DateTime<Utc>,
    /// The event payload
    pub event: EventKind,
}

/// The kind of event an agent can emit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventKind {
    /// A new finding was recorded by the agent
    FindingRecorded {
        /// Severity level (e.g. "critical", "high", "medium", "low", "info")
        severity: String,
        /// Short title of the finding
        title: String,
    },
    /// The agent reached a significant milestone
    MilestoneReached {
        /// Name of the milestone
        milestone: String,
        /// Additional details about what was accomplished
        details: String,
    },
    /// The agent completed successfully
    AgentCompleted {
        /// Whether the agent succeeded
        success: bool,
        /// Summary of what the agent accomplished
        summary: String,
        /// Key findings discovered
        key_findings: Vec<String>,
        /// Suggested next steps
        next_steps: Vec<String>,
    },
    /// The agent failed with an error
    AgentFailed {
        /// Description of the error
        error: String,
    },
    /// The agent was cancelled
    AgentCancelled {
        /// Partial summary of work done before cancellation, if any
        partial_summary: Option<String>,
    },
}

/// Cloneable sender half, given to each spawned agent.
pub type AgentEventSender = mpsc::Sender<AgentEvent>;

/// Event bus that collects events from subagents for the orchestrator.
///
/// The orchestrator owns the bus and periodically drains events to review
/// what subagents have reported.
pub struct AgentEventBus {
    rx: mpsc::Receiver<AgentEvent>,
    tx: mpsc::Sender<AgentEvent>,
    buffer: Vec<AgentEvent>,
}

impl AgentEventBus {
    /// Create a new event bus with the given channel capacity.
    pub fn new(capacity: usize) -> Self {
        let (tx, rx) = mpsc::channel(capacity);
        Self {
            rx,
            tx,
            buffer: Vec::new(),
        }
    }

    /// Get a cloneable sender for subagents to emit events.
    pub fn sender(&self) -> AgentEventSender {
        self.tx.clone()
    }

    /// Non-blocking drain: pull all pending events from the channel into the
    /// buffer, then return the entire buffer.
    pub fn drain(&mut self) -> Vec<AgentEvent> {
        while let Ok(event) = self.rx.try_recv() {
            self.buffer.push(event);
        }
        mem::take(&mut self.buffer)
    }

    /// Drain with a timeout: if the buffer already has events, return them
    /// immediately. Otherwise wait up to `timeout` for the first event, then
    /// drain any additional events that arrived.
    ///
    /// # Errors
    ///
    /// This method does not return errors; an empty `Vec` signals timeout or
    /// no events.
    pub async fn drain_or_wait(&mut self, timeout: Duration) -> Vec<AgentEvent> {
        if !self.buffer.is_empty() {
            return mem::take(&mut self.buffer);
        }

        // Wait for the first event with a timeout
        match tokio::time::timeout(timeout, self.rx.recv()).await {
            Ok(Some(event)) => {
                self.buffer.push(event);
                // Drain any additional events that arrived concurrently
                while let Ok(event) = self.rx.try_recv() {
                    self.buffer.push(event);
                }
                mem::take(&mut self.buffer)
            }
            // Timeout or channel closed
            Ok(None) | Err(_) => Vec::new(),
        }
    }

    /// Check whether there are buffered events or pending channel messages.
    pub fn has_pending(&self) -> bool {
        !self.buffer.is_empty() || !self.rx.is_empty()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn make_event(name: &str, kind: EventKind) -> AgentEvent {
        AgentEvent {
            agent_name: name.to_string(),
            agent_type: "recon".to_string(),
            timestamp: Utc::now(),
            event: kind,
        }
    }

    #[tokio::test]
    async fn test_event_bus_send_and_drain() {
        let mut bus = AgentEventBus::new(16);
        let tx = bus.sender();

        let event = make_event(
            "recon-1",
            EventKind::FindingRecorded {
                severity: "high".to_string(),
                title: "SQL Injection in login".to_string(),
            },
        );
        tx.send(event).await.unwrap();

        let events = bus.drain();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].agent_name, "recon-1");
        match &events[0].event {
            EventKind::FindingRecorded { severity, title } => {
                assert_eq!(severity, "high");
                assert_eq!(title, "SQL Injection in login");
            }
            other => unreachable!("Expected FindingRecorded, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_event_bus_drain_empty() {
        let mut bus = AgentEventBus::new(16);
        let events = bus.drain();
        assert!(events.is_empty());
    }

    #[tokio::test]
    async fn test_event_bus_drain_or_wait_timeout() {
        let mut bus = AgentEventBus::new(16);
        let events = bus.drain_or_wait(Duration::from_millis(50)).await;
        assert!(events.is_empty());
    }

    #[tokio::test]
    async fn test_event_bus_drain_or_wait_receives() {
        let mut bus = AgentEventBus::new(16);
        let tx = bus.sender();

        // Send from another task after a small delay
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            let event = make_event(
                "scanner-1",
                EventKind::MilestoneReached {
                    milestone: "port_scan_complete".to_string(),
                    details: "Scanned 1000 ports".to_string(),
                },
            );
            tx.send(event).await.unwrap();
        });

        let events = bus.drain_or_wait(Duration::from_secs(2)).await;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].agent_name, "scanner-1");
    }

    #[tokio::test]
    async fn test_event_bus_multiple_senders() {
        let mut bus = AgentEventBus::new(16);
        let tx1 = bus.sender();
        let tx2 = bus.sender();

        tx1.send(make_event(
            "agent-a",
            EventKind::AgentCompleted {
                success: true,
                summary: "Recon done".to_string(),
                key_findings: vec!["open port 80".to_string()],
                next_steps: vec!["scan port 80".to_string()],
            },
        ))
        .await
        .unwrap();

        tx2.send(make_event(
            "agent-b",
            EventKind::AgentFailed {
                error: "timeout".to_string(),
            },
        ))
        .await
        .unwrap();

        // Small delay to let channel propagate
        tokio::time::sleep(Duration::from_millis(10)).await;

        let events = bus.drain();
        assert_eq!(events.len(), 2);

        let names: Vec<&str> = events.iter().map(|e| e.agent_name.as_str()).collect();
        assert!(names.contains(&"agent-a"));
        assert!(names.contains(&"agent-b"));
    }
}
