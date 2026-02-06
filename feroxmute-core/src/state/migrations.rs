//! Database migrations

use rusqlite::Connection;

use crate::Result;

/// Run all migrations on the database
pub fn run_migrations(conn: &Connection) -> Result<()> {
    // Enable WAL mode for better concurrent access
    conn.execute_batch("PRAGMA journal_mode=WAL;")?;
    // Set busy timeout to handle concurrent writes gracefully
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    // Enable foreign key constraint enforcement
    conn.execute_batch("PRAGMA foreign_keys = ON;")?;

    conn.execute_batch(super::schema::SCHEMA)?;

    // Initialize metrics if not exists
    conn.execute(
        "INSERT OR IGNORE INTO metrics (id, tool_calls, tokens_input, tokens_cached, tokens_output, estimated_cost_usd)
         VALUES ('global', 0, 0, 0, 0, 0.0)",
        [],
    )?;

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    #[test]
    fn test_migrations_run_successfully() {
        let conn = Connection::open_in_memory().expect("should open in-memory db");
        run_migrations(&conn).expect("migrations should succeed");

        // Verify tables exist
        let tables: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .expect("should prepare statement")
            .query_map([], |row| row.get(0))
            .expect("should execute query")
            .filter_map(|r| r.ok())
            .collect();

        assert!(tables.contains(&"hosts".to_string()));
        assert!(tables.contains(&"vulnerabilities".to_string()));
        assert!(tables.contains(&"agent_tasks".to_string()));
        assert!(tables.contains(&"scratch_pad".to_string()));
    }

    #[test]
    fn test_foreign_keys_enabled() {
        let conn = Connection::open_in_memory().expect("should open in-memory db");
        run_migrations(&conn).expect("migrations should succeed");

        let fk_enabled: bool = conn
            .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
            .expect("should query pragma");
        assert!(fk_enabled, "foreign_keys should be enabled after migrations");
    }

    #[test]
    fn test_migrations_idempotent() {
        let conn = Connection::open_in_memory().expect("should open in-memory db");
        run_migrations(&conn).expect("first migration should succeed");
        run_migrations(&conn).expect("second migration should also succeed"); // Should not fail
    }
}
