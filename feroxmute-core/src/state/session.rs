//! Session management for feroxmute engagements

use chrono::{DateTime, Utc};
use rusqlite::Connection;
use std::path::{Path, PathBuf};

use crate::config::EngagementConfig;
use crate::state::run_migrations;
use crate::{Error, Result};

/// Session status for resume support
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionStatus {
    Running,
    Completed,
    Interrupted,
}

impl SessionStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            SessionStatus::Running => "running",
            SessionStatus::Completed => "completed",
            SessionStatus::Interrupted => "interrupted",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "running" => Some(SessionStatus::Running),
            "completed" => Some(SessionStatus::Completed),
            "interrupted" => Some(SessionStatus::Interrupted),
            _ => None,
        }
    }
}

/// Summary of findings by severity
#[derive(Debug, Clone, Default)]
pub struct FindingsSummary {
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub info: u32,
}

impl FindingsSummary {
    pub fn total(&self) -> u32 {
        self.critical + self.high + self.medium + self.low + self.info
    }
}

/// A feroxmute session representing a single engagement
pub struct Session {
    /// Unique session identifier
    pub id: String,
    /// Session directory path
    pub path: PathBuf,
    /// Database connection
    conn: Connection,
    /// Session configuration
    pub config: EngagementConfig,
    /// When the session was created
    pub created_at: DateTime<Utc>,
}

impl Session {
    /// Create a new session for an engagement
    pub fn new(config: EngagementConfig, base_dir: impl AsRef<Path>) -> Result<Self> {
        let created_at = Utc::now();
        let base_id = format!(
            "{}-{}",
            created_at.format("%Y-%m-%d"),
            config.target.host.replace('.', "-")
        );

        // Find unique ID by appending counter if needed
        let base_dir = base_dir.as_ref();
        let (id, path) = {
            let first_path = base_dir.join(&base_id);
            if !first_path.exists() {
                (base_id, first_path)
            } else {
                let mut counter = 2;
                loop {
                    let candidate_id = format!("{}-{}", base_id, counter);
                    let candidate_path = base_dir.join(&candidate_id);
                    if !candidate_path.exists() {
                        break (candidate_id, candidate_path);
                    }
                    counter += 1;
                }
            }
        };

        std::fs::create_dir_all(&path)?;

        // Create subdirectories
        std::fs::create_dir_all(path.join("artifacts/downloads"))?;
        std::fs::create_dir_all(path.join("artifacts/evidence"))?;
        std::fs::create_dir_all(path.join("screenshots"))?;
        std::fs::create_dir_all(path.join("scripts/python"))?;
        std::fs::create_dir_all(path.join("scripts/rust"))?;
        std::fs::create_dir_all(path.join("reports"))?;

        // Save config
        let config_path = path.join("config.toml");
        let config_str =
            toml::to_string_pretty(&config).map_err(|e| Error::Config(e.to_string()))?;
        std::fs::write(&config_path, config_str)?;

        // Create database
        let db_path = path.join("session.db");
        let conn = Connection::open(&db_path)?;
        run_migrations(&conn)?;

        // Store session metadata
        conn.execute(
            "INSERT INTO session_meta (key, value) VALUES ('id', ?1)",
            [&id],
        )?;
        conn.execute(
            "INSERT INTO session_meta (key, value) VALUES ('target', ?1)",
            [&config.target.host],
        )?;
        conn.execute(
            "INSERT INTO session_meta (key, value) VALUES ('created_at', ?1)",
            [&created_at.to_rfc3339()],
        )?;

        // Initialize session state
        conn.execute(
            "INSERT INTO session_state (id, status, last_activity_at) VALUES (1, 'running', datetime('now'))",
            [],
        )?;

        Ok(Self {
            id,
            path,
            conn,
            config,
            created_at,
        })
    }

    /// Resume an existing session from disk
    pub fn resume(session_path: impl AsRef<Path>) -> Result<Self> {
        let path = session_path.as_ref().to_path_buf();

        if !path.exists() {
            return Err(Error::SessionNotFound(path.display().to_string()));
        }

        // Load config
        let config_path = path.join("config.toml");
        let config = EngagementConfig::from_file(&config_path)?;

        // Open database
        let db_path = path.join("session.db");
        let conn = Connection::open(&db_path)?;

        // Read session metadata
        let id: String = conn.query_row(
            "SELECT value FROM session_meta WHERE key = 'id'",
            [],
            |row| row.get(0),
        )?;

        let created_at_str: String = conn.query_row(
            "SELECT value FROM session_meta WHERE key = 'created_at'",
            [],
            |row| row.get(0),
        )?;
        let created_at = DateTime::parse_from_rfc3339(&created_at_str)
            .map_err(|e| Error::Config(e.to_string()))?
            .with_timezone(&Utc);

        Ok(Self {
            id,
            path,
            conn,
            config,
            created_at,
        })
    }

    /// Get a reference to the database connection
    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    /// Open a new connection to the session database.
    ///
    /// Returns a new SQLite connection to the same database file. Use this when you need
    /// a separate connection for concurrent access (e.g., from async tasks wrapped in Arc<Mutex>).
    /// The returned connection shares the same database and schema as the main connection.
    ///
    /// Note: Caller is responsible for synchronization if accessing from multiple threads.
    pub fn open_connection(&self) -> Result<Connection> {
        let db_path = self.path.join("session.db");
        Ok(Connection::open(&db_path)?)
    }

    /// Get path to artifacts directory
    pub fn artifacts_dir(&self) -> PathBuf {
        self.path.join("artifacts")
    }

    /// Get path to screenshots directory
    pub fn screenshots_dir(&self) -> PathBuf {
        self.path.join("screenshots")
    }

    /// Get path to scripts directory
    pub fn scripts_dir(&self) -> PathBuf {
        self.path.join("scripts")
    }

    /// Get path to reports directory
    pub fn reports_dir(&self) -> PathBuf {
        self.path.join("reports")
    }

    /// Get current session status
    pub fn status(&self) -> Result<SessionStatus> {
        let status_str: String =
            self.conn
                .query_row("SELECT status FROM session_state WHERE id = 1", [], |row| {
                    row.get(0)
                })?;
        SessionStatus::from_str(&status_str)
            .ok_or_else(|| Error::Config(format!("Invalid session status: {}", status_str)))
    }

    /// Update session status
    pub fn set_status(&self, status: SessionStatus) -> Result<()> {
        self.conn.execute(
            "UPDATE session_state SET status = ?1, last_activity_at = datetime('now') WHERE id = 1",
            [status.as_str()],
        )?;
        Ok(())
    }

    /// Update last activity timestamp
    pub fn touch(&self) -> Result<()> {
        self.conn.execute(
            "UPDATE session_state SET last_activity_at = datetime('now') WHERE id = 1",
            [],
        )?;
        Ok(())
    }

    /// Get last activity timestamp
    pub fn last_activity(&self) -> Result<DateTime<Utc>> {
        let timestamp_str: String = self.conn.query_row(
            "SELECT last_activity_at FROM session_state WHERE id = 1",
            [],
            |row| row.get(0),
        )?;
        // Parse SQLite datetime format "YYYY-MM-DD HH:MM:SS"
        chrono::NaiveDateTime::parse_from_str(&timestamp_str, "%Y-%m-%d %H:%M:%S")
            .map(|dt| dt.and_utc())
            .map_err(|e| Error::Config(format!("Invalid timestamp '{}': {}", timestamp_str, e)))
    }

    /// Get list of completed agent names
    pub fn completed_agents(&self) -> Result<Vec<String>> {
        let json_str: String = self.conn.query_row(
            "SELECT completed_agents FROM session_state WHERE id = 1",
            [],
            |row| row.get(0),
        )?;
        serde_json::from_str(&json_str)
            .map_err(|e| Error::Config(format!("Invalid completed_agents JSON: {}", e)))
    }

    /// Mark an agent as completed
    pub fn mark_agent_completed(&self, agent_name: &str) -> Result<()> {
        let mut agents = self.completed_agents()?;
        if !agents.contains(&agent_name.to_string()) {
            agents.push(agent_name.to_string());
            let json_str = serde_json::to_string(&agents)
                .map_err(|e| Error::Config(format!("Failed to serialize agents: {}", e)))?;
            self.conn.execute(
                "UPDATE session_state SET completed_agents = ?1, last_activity_at = datetime('now') WHERE id = 1",
                [json_str],
            )?;
        }
        Ok(())
    }

    /// Get summary of findings by severity
    pub fn findings_summary(&self) -> Result<FindingsSummary> {
        let mut summary = FindingsSummary::default();

        let mut stmt = self
            .conn
            .prepare("SELECT severity, COUNT(*) FROM vulnerabilities GROUP BY severity")?;

        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, u32>(1)?))
        })?;

        for row in rows {
            let (severity, count) = row?;
            match severity.to_lowercase().as_str() {
                "critical" => summary.critical = count,
                "high" => summary.high = count,
                "medium" => summary.medium = count,
                "low" => summary.low = count,
                "info" | "informational" => summary.info = count,
                _ => {}
            }
        }

        Ok(summary)
    }

    /// Get all memory entries from scratch pad
    pub fn memory_entries(&self) -> Result<Vec<(String, String)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT key, value FROM scratch_pad ORDER BY created_at")?;

        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;

        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| e.into())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::config::TargetConfig;
    use tempfile::TempDir;

    fn test_config() -> EngagementConfig {
        EngagementConfig {
            target: TargetConfig {
                host: "example.com".to_string(),
                scope: Default::default(),
                ports: vec![80, 443],
            },
            constraints: Default::default(),
            auth: Default::default(),
            provider: Default::default(),
            output: Default::default(),
        }
    }

    #[test]
    fn test_create_new_session() {
        let temp = TempDir::new().expect("should create temp dir");
        let config = test_config();

        let session = Session::new(config, temp.path()).expect("should create session");

        assert!(session.id.contains("example-com"));
        assert!(session.path.exists());
        assert!(session.path.join("session.db").exists());
        assert!(session.path.join("config.toml").exists());
        assert!(session.artifacts_dir().join("downloads").exists());
    }

    #[test]
    fn test_resume_session() {
        let temp = TempDir::new().expect("should create temp dir");
        let config = test_config();

        let original = Session::new(config, temp.path()).expect("should create session");
        let session_path = original.path.clone();
        drop(original);

        let resumed = Session::resume(&session_path).expect("should resume session");

        assert!(resumed.id.contains("example-com"));
        assert_eq!(resumed.config.target.host, "example.com");
    }

    #[test]
    fn test_resume_nonexistent_session() {
        let result = Session::resume("/nonexistent/path");
        assert!(matches!(result, Err(Error::SessionNotFound(_))));
    }

    #[test]
    fn test_session_status_display() {
        assert_eq!(SessionStatus::Running.as_str(), "running");
        assert_eq!(SessionStatus::Completed.as_str(), "completed");
        assert_eq!(SessionStatus::Interrupted.as_str(), "interrupted");
    }

    #[test]
    fn test_session_status_from_str() {
        assert_eq!(
            SessionStatus::from_str("running"),
            Some(SessionStatus::Running)
        );
        assert_eq!(
            SessionStatus::from_str("completed"),
            Some(SessionStatus::Completed)
        );
        assert_eq!(
            SessionStatus::from_str("interrupted"),
            Some(SessionStatus::Interrupted)
        );
        assert_eq!(SessionStatus::from_str("invalid"), None);
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

        // Can update to Interrupted
        session
            .set_status(SessionStatus::Interrupted)
            .expect("should set status");
        assert_eq!(
            session.status().expect("should get status"),
            SessionStatus::Interrupted
        );

        // Can update to Completed
        session
            .set_status(SessionStatus::Completed)
            .expect("should set status");
        assert_eq!(
            session.status().expect("should get status"),
            SessionStatus::Completed
        );
    }

    #[test]
    fn test_session_touch_updates_timestamp() {
        let temp = TempDir::new().expect("should create temp dir");
        let config = test_config();

        let session = Session::new(config, temp.path()).expect("should create session");

        let before = session.last_activity().expect("should get timestamp");
        std::thread::sleep(std::time::Duration::from_secs(1));
        session.touch().expect("should touch");
        let after = session.last_activity().expect("should get timestamp");

        assert!(after > before);
    }

    #[test]
    fn test_completed_agents_tracking() {
        let temp = TempDir::new().expect("should create temp dir");
        let config = test_config();

        let session = Session::new(config, temp.path()).expect("should create session");

        // Initially empty
        let agents = session.completed_agents().expect("should get agents");
        assert!(agents.is_empty());

        // Add agents
        session
            .mark_agent_completed("recon-1")
            .expect("should mark");
        session
            .mark_agent_completed("scanner-1")
            .expect("should mark");

        let agents = session.completed_agents().expect("should get agents");
        assert_eq!(agents.len(), 2);
        assert!(agents.contains(&"recon-1".to_string()));
        assert!(agents.contains(&"scanner-1".to_string()));

        // Idempotent - adding same agent twice doesn't duplicate
        session
            .mark_agent_completed("recon-1")
            .expect("should mark");
        let agents = session.completed_agents().expect("should get agents");
        assert_eq!(agents.len(), 2);
    }

    #[test]
    fn test_findings_summary() {
        let temp = TempDir::new().expect("should create temp dir");
        let config = test_config();

        let session = Session::new(config, temp.path()).expect("should create session");

        // Initially all zeros
        let summary = session.findings_summary().expect("should get summary");
        assert_eq!(summary.critical, 0);
        assert_eq!(summary.high, 0);
        assert_eq!(summary.total(), 0);

        // Add some findings directly to DB
        session.conn().execute(
            "INSERT INTO vulnerabilities (id, vuln_type, severity, title, discovered_by, discovered_at)
             VALUES ('v1', 'sqli', 'high', 'SQL Injection', 'scanner', datetime('now'))",
            [],
        ).expect("should insert");
        session.conn().execute(
            "INSERT INTO vulnerabilities (id, vuln_type, severity, title, discovered_by, discovered_at)
             VALUES ('v2', 'xss', 'medium', 'XSS', 'scanner', datetime('now'))",
            [],
        ).expect("should insert");

        let summary = session.findings_summary().expect("should get summary");
        assert_eq!(summary.high, 1);
        assert_eq!(summary.medium, 1);
        assert_eq!(summary.total(), 2);
    }

    #[test]
    fn test_memory_entries() {
        let temp = TempDir::new().expect("should create temp dir");
        let config = test_config();

        let session = Session::new(config, temp.path()).expect("should create session");

        // Initially empty
        let entries = session.memory_entries().expect("should get entries");
        assert!(entries.is_empty());

        // Add entries directly to DB
        session
            .conn()
            .execute(
                "INSERT INTO scratch_pad (key, value) VALUES ('target_info', 'Apache 2.4')",
                [],
            )
            .expect("should insert");
        session
            .conn()
            .execute(
                "INSERT INTO scratch_pad (key, value) VALUES ('open_ports', '80, 443, 8080')",
                [],
            )
            .expect("should insert");

        let entries = session.memory_entries().expect("should get entries");
        assert_eq!(entries.len(), 2);
        assert!(entries
            .iter()
            .any(|(k, v)| k == "target_info" && v == "Apache 2.4"));
    }

    #[test]
    fn test_session_id_conflict_appends_counter() {
        let temp = TempDir::new().expect("should create temp dir");
        let config = test_config();

        let session1 = Session::new(config.clone(), temp.path()).expect("should create session");
        let id1 = session1.id.clone();
        drop(session1);

        // Create another session for same target on same day
        let session2 = Session::new(config.clone(), temp.path()).expect("should create session");
        let id2 = session2.id.clone();
        drop(session2);

        // IDs should be different
        assert_ne!(id1, id2);
        assert!(
            id2.ends_with("-2"),
            "Second session should have -2 suffix, got: {}",
            id2
        );

        // Third session
        let session3 = Session::new(config, temp.path()).expect("should create session");
        assert!(
            session3.id.ends_with("-3"),
            "Third session should have -3 suffix, got: {}",
            session3.id
        );
    }

    #[test]
    fn test_open_connection() {
        let temp = TempDir::new().expect("should create temp dir");
        let config = test_config();

        let session = Session::new(config, temp.path()).expect("should create session");

        // Can open a new connection
        let conn = session.open_connection().expect("should open connection");

        // Connection can query the database
        let count: i32 = conn
            .query_row("SELECT COUNT(*) FROM session_meta", [], |row| row.get(0))
            .expect("should query");
        assert!(count > 0); // session_meta has entries from Session::new

        // Multiple connections can coexist
        let conn2 = session
            .open_connection()
            .expect("should open second connection");
        let count2: i32 = conn2
            .query_row("SELECT COUNT(*) FROM session_meta", [], |row| row.get(0))
            .expect("should query");
        assert_eq!(count, count2);
    }
}
