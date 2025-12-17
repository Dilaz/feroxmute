//! Database migrations

use rusqlite::Connection;

use crate::Result;

/// Run all migrations on the database
pub fn run_migrations(conn: &Connection) -> Result<()> {
    conn.execute_batch(super::schema::SCHEMA)?;

    // Initialize metrics if not exists
    conn.execute(
        "INSERT OR IGNORE INTO metrics (id, tool_calls, tokens_input, tokens_cached, tokens_output)
         VALUES ('global', 0, 0, 0, 0)",
        [],
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    #[test]
    fn test_migrations_run_successfully() {
        let conn = Connection::open_in_memory().unwrap();
        run_migrations(&conn).unwrap();

        // Verify tables exist
        let tables: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();

        assert!(tables.contains(&"hosts".to_string()));
        assert!(tables.contains(&"vulnerabilities".to_string()));
        assert!(tables.contains(&"agent_tasks".to_string()));
    }

    #[test]
    fn test_migrations_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        run_migrations(&conn).unwrap();
        run_migrations(&conn).unwrap(); // Should not fail
    }
}
