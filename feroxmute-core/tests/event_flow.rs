//! Integration test for the event-driven workflow

use feroxmute_core::agents::event_bus::{AgentEvent, AgentEventBus, EventKind};

use chrono::Utc;

#[tokio::test]
async fn test_milestone_flows_to_event_bus() {
    let mut bus = AgentEventBus::new(32);
    let sender = bus.sender();

    // Simulate agent emitting a milestone
    sender
        .send(AgentEvent {
            agent_name: "web-recon".to_string(),
            agent_type: "recon".to_string(),
            timestamp: Utc::now(),
            event: EventKind::MilestoneReached {
                milestone: "Port scan complete".to_string(),
                details: "80, 443, 8080 open".to_string(),
            },
        })
        .await
        .unwrap();

    // Simulate agent recording a finding
    sender
        .send(AgentEvent {
            agent_name: "vuln-scan".to_string(),
            agent_type: "scanner".to_string(),
            timestamp: Utc::now(),
            event: EventKind::FindingRecorded {
                severity: "high".to_string(),
                title: "SQL injection in /login".to_string(),
            },
        })
        .await
        .unwrap();

    // Simulate agent completion
    sender
        .send(AgentEvent {
            agent_name: "web-recon".to_string(),
            agent_type: "recon".to_string(),
            timestamp: Utc::now(),
            event: EventKind::AgentCompleted {
                success: true,
                summary: "Mapped 15 endpoints".to_string(),
                key_findings: vec!["Admin panel at /admin".to_string()],
                next_steps: vec!["Scan admin panel".to_string()],
            },
        })
        .await
        .unwrap();

    // Drain and verify
    let events = bus.drain();
    assert_eq!(events.len(), 3);

    assert!(
        matches!(&events[0].event, EventKind::MilestoneReached { milestone, .. } if milestone == "Port scan complete")
    );
    assert!(
        matches!(&events[1].event, EventKind::FindingRecorded { severity, .. } if severity == "high")
    );
    assert!(matches!(&events[2].event, EventKind::AgentCompleted { success, .. } if *success));
}

#[tokio::test]
async fn test_cancellation_event() {
    let mut bus = AgentEventBus::new(32);
    let sender = bus.sender();

    sender
        .send(AgentEvent {
            agent_name: "old-recon".to_string(),
            agent_type: "recon".to_string(),
            timestamp: Utc::now(),
            event: EventKind::AgentCancelled {
                partial_summary: Some("Cancelled after scanning 3 of 10 hosts".to_string()),
            },
        })
        .await
        .unwrap();

    let events = bus.drain();
    assert_eq!(events.len(), 1);
    assert!(
        matches!(&events[0].event, EventKind::AgentCancelled { partial_summary } if partial_summary.is_some())
    );
}

#[tokio::test]
async fn test_drain_or_wait_with_multiple_event_types() {
    let mut bus = AgentEventBus::new(32);
    let sender = bus.sender();

    // Send events from multiple agents
    for i in 0..5 {
        sender
            .send(AgentEvent {
                agent_name: format!("agent-{i}"),
                agent_type: "scanner".to_string(),
                timestamp: Utc::now(),
                event: EventKind::MilestoneReached {
                    milestone: format!("Step {i} done"),
                    details: String::new(),
                },
            })
            .await
            .unwrap();
    }

    let events = bus
        .drain_or_wait(std::time::Duration::from_millis(100))
        .await;
    assert_eq!(events.len(), 5);
}
