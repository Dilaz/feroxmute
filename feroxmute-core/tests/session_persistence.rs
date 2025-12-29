//! Integration tests for session persistence

use feroxmute_core::config::{EngagementConfig, TargetConfig};
use feroxmute_core::state::{Session, SessionStatus};
use tempfile::TempDir;

fn test_config() -> EngagementConfig {
    EngagementConfig {
        target: TargetConfig {
            host: "test.example.com".to_string(),
            ports: vec![80, 443],
        },
        capabilities: Default::default(),
        constraints: Default::default(),
        auth: Default::default(),
        provider: Default::default(),
        output: Default::default(),
    }
}

#[test]
fn test_session_persists_across_restart() {
    let temp = TempDir::new().expect("should create temp dir");
    let config = test_config();

    // Create session and add some data
    let session = Session::new(config, temp.path()).expect("should create session");
    let session_path = session.path.clone();
    let session_id = session.id.clone();

    // Add memory entry
    session
        .conn()
        .execute(
            "INSERT INTO scratch_pad (key, value) VALUES ('test_key', 'test_value')",
            [],
        )
        .expect("should insert");

    // Mark agent completed
    session
        .mark_agent_completed("recon-1")
        .expect("should mark");

    // Set interrupted
    session
        .set_status(SessionStatus::Interrupted)
        .expect("should set status");

    // Drop session (simulating app exit)
    drop(session);

    // Resume session
    let resumed = Session::resume(&session_path).expect("should resume");

    assert_eq!(resumed.id, session_id);
    assert_eq!(
        resumed.status().expect("should get status"),
        SessionStatus::Interrupted
    );

    let agents = resumed.completed_agents().expect("should get agents");
    assert!(agents.contains(&"recon-1".to_string()));

    let memory = resumed.memory_entries().expect("should get memory");
    assert!(memory
        .iter()
        .any(|(k, v)| k == "test_key" && v == "test_value"));

    // Check resume context is generated
    assert!(resumed.is_resuming().expect("should check"));
    let context = resumed.resume_context().expect("should get context");
    assert!(context.contains("recon-1"));
    assert!(context.contains("test_key"));
}

#[test]
fn test_session_status_lifecycle() {
    let temp = TempDir::new().expect("should create temp dir");
    let config = test_config();

    let session = Session::new(config, temp.path()).expect("should create session");

    // New sessions start as Running
    assert_eq!(
        session.status().expect("should get status"),
        SessionStatus::Running
    );

    // Can transition through states
    session
        .set_status(SessionStatus::Interrupted)
        .expect("should set");
    assert_eq!(
        session.status().expect("should get status"),
        SessionStatus::Interrupted
    );

    session
        .set_status(SessionStatus::Completed)
        .expect("should set");
    assert_eq!(
        session.status().expect("should get status"),
        SessionStatus::Completed
    );
}

#[test]
fn test_session_id_uniqueness() {
    let temp = TempDir::new().expect("should create temp dir");
    let config = test_config();

    // Create multiple sessions for same target
    let s1 = Session::new(config.clone(), temp.path()).expect("should create");
    let s2 = Session::new(config.clone(), temp.path()).expect("should create");
    let s3 = Session::new(config, temp.path()).expect("should create");

    // All IDs should be unique
    assert_ne!(s1.id, s2.id);
    assert_ne!(s2.id, s3.id);
    assert_ne!(s1.id, s3.id);

    // IDs should follow naming convention
    assert!(s1.id.contains("test-example-com"));
    assert!(s2.id.ends_with("-2"));
    assert!(s3.id.ends_with("-3"));
}

#[test]
fn test_findings_persist_and_summarize() {
    let temp = TempDir::new().expect("should create temp dir");
    let config = test_config();

    let session = Session::new(config, temp.path()).expect("should create session");

    // Add findings of various severities
    session
        .conn()
        .execute(
            "INSERT INTO vulnerabilities (id, vuln_type, severity, title, discovered_by, discovered_at)
             VALUES ('v1', 'sqli', 'critical', 'SQL Injection', 'scanner', datetime('now'))",
            [],
        )
        .expect("should insert");
    session
        .conn()
        .execute(
            "INSERT INTO vulnerabilities (id, vuln_type, severity, title, discovered_by, discovered_at)
             VALUES ('v2', 'xss', 'high', 'XSS', 'scanner', datetime('now'))",
            [],
        )
        .expect("should insert");
    session
        .conn()
        .execute(
            "INSERT INTO vulnerabilities (id, vuln_type, severity, title, discovered_by, discovered_at)
             VALUES ('v3', 'info-disclosure', 'medium', 'Info Disclosure', 'scanner', datetime('now'))",
            [],
        )
        .expect("should insert");

    let summary = session.findings_summary().expect("should summarize");
    assert_eq!(summary.critical, 1);
    assert_eq!(summary.high, 1);
    assert_eq!(summary.medium, 1);
    assert_eq!(summary.total(), 3);

    // Verify resume context includes findings
    let context = session.resume_context().expect("should get context");
    assert!(context.contains("1 Critical"));
    assert!(context.contains("1 High"));
    assert!(context.contains("1 Medium"));
}
