//! Session management for feroxmute engagements

use chrono::{DateTime, Utc};
use rusqlite::Connection;
use std::path::{Path, PathBuf};

use crate::config::EngagementConfig;
use crate::state::run_migrations;
use crate::{Error, Result};

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
        let id = format!(
            "{}-{}",
            created_at.format("%Y-%m-%d"),
            config.target.host.replace('.', "-")
        );

        let path = base_dir.as_ref().join(&id);
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
}
