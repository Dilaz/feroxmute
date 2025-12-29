# Session Persistence Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Wire up the existing Session struct to persist engagement data to disk, enabling resume of interrupted sessions.

**Architecture:** Add session_state table to track status/completed agents. Pass Session through main→runner instead of creating in-memory DB. On resume, inject prior context into orchestrator prompt.

**Tech Stack:** Rust, rusqlite, clap, tokio

---

## Task 1: Add session_state Table to Schema

**Files:**
- Modify: `feroxmute-core/src/state/schema.rs`

**Step 1: Add session_state table definition**

In `feroxmute-core/src/state/schema.rs`, add after the `scratch_pad` table definition (around line 139):

```rust
-- Session state for resume support
CREATE TABLE IF NOT EXISTS session_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    status TEXT NOT NULL DEFAULT 'running',
    phase TEXT,
    last_activity_at TEXT NOT NULL DEFAULT (datetime('now')),
    completed_agents TEXT NOT NULL DEFAULT '[]'
);
```

**Step 2: Run tests to verify schema is valid**

Run: `cargo test -p feroxmute-core test_migrations`
Expected: PASS

**Step 3: Commit**

```bash
git add feroxmute-core/src/state/schema.rs
git commit -m "feat(state): add session_state table for resume support"
```

---

## Task 2: Add SessionStatus Enum

**Files:**
- Modify: `feroxmute-core/src/state/session.rs`
- Modify: `feroxmute-core/src/state/mod.rs`

**Step 1: Write the test for SessionStatus**

Add at the end of the `tests` module in `feroxmute-core/src/state/session.rs`:

```rust
    #[test]
    fn test_session_status_display() {
        assert_eq!(SessionStatus::Running.as_str(), "running");
        assert_eq!(SessionStatus::Completed.as_str(), "completed");
        assert_eq!(SessionStatus::Interrupted.as_str(), "interrupted");
    }

    #[test]
    fn test_session_status_from_str() {
        assert_eq!(SessionStatus::from_str("running"), Some(SessionStatus::Running));
        assert_eq!(SessionStatus::from_str("completed"), Some(SessionStatus::Completed));
        assert_eq!(SessionStatus::from_str("interrupted"), Some(SessionStatus::Interrupted));
        assert_eq!(SessionStatus::from_str("invalid"), None);
    }
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p feroxmute-core test_session_status`
Expected: FAIL with "cannot find type `SessionStatus`"

**Step 3: Implement SessionStatus enum**

Add after the imports in `feroxmute-core/src/state/session.rs` (after line 9):

```rust
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
```

**Step 4: Run test to verify it passes**

Run: `cargo test -p feroxmute-core test_session_status`
Expected: PASS

**Step 5: Export SessionStatus from mod.rs**

In `feroxmute-core/src/state/mod.rs`, change line 12 to:

```rust
pub use session::{Session, SessionStatus};
```

**Step 6: Commit**

```bash
git add feroxmute-core/src/state/session.rs feroxmute-core/src/state/mod.rs
git commit -m "feat(state): add SessionStatus enum"
```

---

## Task 3: Add Status Methods to Session

**Files:**
- Modify: `feroxmute-core/src/state/session.rs`

**Step 1: Write the test for status methods**

Add to tests module:

```rust
    #[test]
    fn test_session_status_lifecycle() {
        let temp = TempDir::new().expect("should create temp dir");
        let config = test_config();

        let session = Session::new(config, temp.path()).expect("should create session");

        // New sessions start as Running
        assert_eq!(session.status().expect("should get status"), SessionStatus::Running);

        // Can update to Interrupted
        session.set_status(SessionStatus::Interrupted).expect("should set status");
        assert_eq!(session.status().expect("should get status"), SessionStatus::Interrupted);

        // Can update to Completed
        session.set_status(SessionStatus::Completed).expect("should set status");
        assert_eq!(session.status().expect("should get status"), SessionStatus::Completed);
    }

    #[test]
    fn test_session_touch_updates_timestamp() {
        let temp = TempDir::new().expect("should create temp dir");
        let config = test_config();

        let session = Session::new(config, temp.path()).expect("should create session");

        let before = session.last_activity().expect("should get timestamp");
        std::thread::sleep(std::time::Duration::from_millis(10));
        session.touch().expect("should touch");
        let after = session.last_activity().expect("should get timestamp");

        assert!(after > before);
    }
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p feroxmute-core test_session_status_lifecycle`
Expected: FAIL with "no method named `status`"

**Step 3: Initialize session_state in Session::new**

In `Session::new()`, add after the session_meta inserts (after line 69):

```rust
        // Initialize session state
        conn.execute(
            "INSERT INTO session_state (id, status, last_activity_at) VALUES (1, 'running', datetime('now'))",
            [],
        )?;
```

**Step 4: Implement status methods**

Add to `impl Session` block (after `reports_dir` method):

```rust
    /// Get current session status
    pub fn status(&self) -> Result<SessionStatus> {
        let status_str: String = self.conn.query_row(
            "SELECT status FROM session_state WHERE id = 1",
            [],
            |row| row.get(0),
        )?;
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
        DateTime::parse_from_rfc3339(&format!("{}+00:00", timestamp_str.replace(' ', "T")))
            .map(|dt| dt.with_timezone(&Utc))
            .or_else(|_| {
                // Try parsing without timezone for SQLite datetime format
                chrono::NaiveDateTime::parse_from_str(&timestamp_str, "%Y-%m-%d %H:%M:%S")
                    .map(|dt| dt.and_utc())
                    .map_err(|e| Error::Config(e.to_string()))
            })
            .map_err(|e| Error::Config(format!("Invalid timestamp: {}", e)))
    }
```

**Step 5: Run tests to verify they pass**

Run: `cargo test -p feroxmute-core test_session_status_lifecycle test_session_touch`
Expected: PASS

**Step 6: Commit**

```bash
git add feroxmute-core/src/state/session.rs
git commit -m "feat(state): add status and touch methods to Session"
```

---

## Task 4: Add Completed Agents Tracking

**Files:**
- Modify: `feroxmute-core/src/state/session.rs`

**Step 1: Write the test**

Add to tests module:

```rust
    #[test]
    fn test_completed_agents_tracking() {
        let temp = TempDir::new().expect("should create temp dir");
        let config = test_config();

        let session = Session::new(config, temp.path()).expect("should create session");

        // Initially empty
        let agents = session.completed_agents().expect("should get agents");
        assert!(agents.is_empty());

        // Add agents
        session.mark_agent_completed("recon-1").expect("should mark");
        session.mark_agent_completed("scanner-1").expect("should mark");

        let agents = session.completed_agents().expect("should get agents");
        assert_eq!(agents.len(), 2);
        assert!(agents.contains(&"recon-1".to_string()));
        assert!(agents.contains(&"scanner-1".to_string()));

        // Idempotent - adding same agent twice doesn't duplicate
        session.mark_agent_completed("recon-1").expect("should mark");
        let agents = session.completed_agents().expect("should get agents");
        assert_eq!(agents.len(), 2);
    }
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p feroxmute-core test_completed_agents`
Expected: FAIL with "no method named `completed_agents`"

**Step 3: Implement completed agents methods**

Add to `impl Session` block:

```rust
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
```

**Step 4: Add serde_json to dependencies if not present**

Check `feroxmute-core/Cargo.toml` - serde_json should already be there. If not:

```toml
serde_json = "1"
```

**Step 5: Run test to verify it passes**

Run: `cargo test -p feroxmute-core test_completed_agents`
Expected: PASS

**Step 6: Commit**

```bash
git add feroxmute-core/src/state/session.rs
git commit -m "feat(state): add completed agents tracking to Session"
```

---

## Task 5: Add Findings Summary Method

**Files:**
- Modify: `feroxmute-core/src/state/session.rs`

**Step 1: Write the test**

Add to tests module:

```rust
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
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p feroxmute-core test_findings_summary`
Expected: FAIL with "no method named `findings_summary`"

**Step 3: Add FindingsSummary struct and implement method**

Add after SessionStatus impl:

```rust
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
```

Add to `impl Session` block:

```rust
    /// Get summary of findings by severity
    pub fn findings_summary(&self) -> Result<FindingsSummary> {
        let mut summary = FindingsSummary::default();

        let mut stmt = self.conn.prepare(
            "SELECT severity, COUNT(*) FROM vulnerabilities GROUP BY severity"
        )?;

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
```

**Step 4: Export FindingsSummary from mod.rs**

Update `feroxmute-core/src/state/mod.rs` line 12:

```rust
pub use session::{FindingsSummary, Session, SessionStatus};
```

**Step 5: Run test to verify it passes**

Run: `cargo test -p feroxmute-core test_findings_summary`
Expected: PASS

**Step 6: Commit**

```bash
git add feroxmute-core/src/state/session.rs feroxmute-core/src/state/mod.rs
git commit -m "feat(state): add findings_summary method to Session"
```

---

## Task 6: Add Memory Entries Method

**Files:**
- Modify: `feroxmute-core/src/state/session.rs`

**Step 1: Write the test**

Add to tests module:

```rust
    #[test]
    fn test_memory_entries() {
        let temp = TempDir::new().expect("should create temp dir");
        let config = test_config();

        let session = Session::new(config, temp.path()).expect("should create session");

        // Initially empty
        let entries = session.memory_entries().expect("should get entries");
        assert!(entries.is_empty());

        // Add entries directly to DB
        session.conn().execute(
            "INSERT INTO scratch_pad (key, value) VALUES ('target_info', 'Apache 2.4')",
            [],
        ).expect("should insert");
        session.conn().execute(
            "INSERT INTO scratch_pad (key, value) VALUES ('open_ports', '80, 443, 8080')",
            [],
        ).expect("should insert");

        let entries = session.memory_entries().expect("should get entries");
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().any(|(k, v)| k == "target_info" && v == "Apache 2.4"));
    }
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p feroxmute-core test_memory_entries`
Expected: FAIL with "no method named `memory_entries`"

**Step 3: Implement memory_entries method**

Add to `impl Session` block:

```rust
    /// Get all memory entries from scratch pad
    pub fn memory_entries(&self) -> Result<Vec<(String, String)>> {
        let mut stmt = self.conn.prepare(
            "SELECT key, value FROM scratch_pad ORDER BY created_at"
        )?;

        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;

        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| e.into())
    }
```

**Step 4: Run test to verify it passes**

Run: `cargo test -p feroxmute-core test_memory_entries`
Expected: PASS

**Step 5: Commit**

```bash
git add feroxmute-core/src/state/session.rs
git commit -m "feat(state): add memory_entries method to Session"
```

---

## Task 7: Handle Session ID Conflicts

**Files:**
- Modify: `feroxmute-core/src/state/session.rs`

**Step 1: Write the test**

Add to tests module:

```rust
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
        assert!(id2.ends_with("-2"), "Second session should have -2 suffix, got: {}", id2);

        // Third session
        let session3 = Session::new(config, temp.path()).expect("should create session");
        assert!(session3.id.ends_with("-3"), "Third session should have -3 suffix, got: {}", session3.id);
    }
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p feroxmute-core test_session_id_conflict`
Expected: FAIL (currently Session::new would fail or overwrite)

**Step 3: Update Session::new to handle conflicts**

Replace the id generation and path creation in `Session::new` (lines 28-36):

```rust
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
```

**Step 4: Run test to verify it passes**

Run: `cargo test -p feroxmute-core test_session_id_conflict`
Expected: PASS

**Step 5: Commit**

```bash
git add feroxmute-core/src/state/session.rs
git commit -m "feat(state): handle session ID conflicts with counter suffix"
```

---

## Task 8: Add --list-sessions CLI Flag

**Files:**
- Modify: `feroxmute-cli/src/args.rs`

**Step 1: Add the flag**

Add after the `resume` field (around line 37):

```rust
    /// List available sessions
    #[arg(long)]
    pub list_sessions: bool,
```

**Step 2: Verify it compiles**

Run: `cargo build -p feroxmute-cli`
Expected: Success

**Step 3: Verify help shows the flag**

Run: `cargo run -p feroxmute-cli -- --help | grep list-sessions`
Expected: Shows `--list-sessions` flag

**Step 4: Commit**

```bash
git add feroxmute-cli/src/args.rs
git commit -m "feat(cli): add --list-sessions flag"
```

---

## Task 9: Implement --list-sessions Handler

**Files:**
- Modify: `feroxmute-cli/src/main.rs`

**Step 1: Add list_sessions handler after wizard check**

After the wizard handling (around line 74), add:

```rust
    if args.list_sessions {
        let sessions_dir = config.output.session_dir.clone();
        if !sessions_dir.exists() {
            println!("No sessions found. Directory does not exist: {}", sessions_dir.display());
            return Ok(());
        }

        println!("{:<40} {:<20} {:<12} {}", "SESSION ID", "TARGET", "STATUS", "LAST ACTIVITY");
        println!("{}", "-".repeat(90));

        let mut sessions: Vec<_> = std::fs::read_dir(&sessions_dir)?
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_dir())
            .collect();

        // Sort by modification time (newest first)
        sessions.sort_by(|a, b| {
            let a_time = a.metadata().and_then(|m| m.modified()).ok();
            let b_time = b.metadata().and_then(|m| m.modified()).ok();
            b_time.cmp(&a_time)
        });

        for entry in sessions {
            let path = entry.path();
            match feroxmute_core::state::Session::resume(&path) {
                Ok(session) => {
                    let status = session.status().map(|s| format!("{:?}", s)).unwrap_or_else(|_| "unknown".to_string());
                    let last_activity = session.last_activity()
                        .map(|dt| format_relative_time(dt))
                        .unwrap_or_else(|_| "unknown".to_string());
                    println!("{:<40} {:<20} {:<12} {}",
                        session.id,
                        session.config.target.host,
                        status.to_lowercase(),
                        last_activity
                    );
                }
                Err(_) => {
                    // Skip invalid session directories
                }
            }
        }

        return Ok(());
    }
```

**Step 2: Add format_relative_time helper**

Add before `main()`:

```rust
fn format_relative_time(dt: chrono::DateTime<chrono::Utc>) -> String {
    let now = chrono::Utc::now();
    let duration = now.signed_duration_since(dt);

    if duration.num_seconds() < 60 {
        "just now".to_string()
    } else if duration.num_minutes() < 60 {
        format!("{}m ago", duration.num_minutes())
    } else if duration.num_hours() < 24 {
        format!("{}h ago", duration.num_hours())
    } else if duration.num_days() < 7 {
        format!("{}d ago", duration.num_days())
    } else {
        dt.format("%Y-%m-%d").to_string()
    }
}
```

**Step 3: Add chrono import if needed**

Ensure chrono is imported at the top of main.rs. It should already be available through feroxmute_core.

**Step 4: Verify it compiles**

Run: `cargo build -p feroxmute-cli`
Expected: Success

**Step 5: Commit**

```bash
git add feroxmute-cli/src/main.rs
git commit -m "feat(cli): implement --list-sessions command"
```

---

## Task 10: Wire Up Session in main.rs

**Files:**
- Modify: `feroxmute-cli/src/main.rs`

**Step 1: Create Session instead of UUID**

Replace the session_id creation (around line 305):

```rust
        // Create session ID
        let session_id = Uuid::new_v4().to_string()[..8].to_string();
```

With:

```rust
        // Create or resume session
        let session = if let Some(ref resume_path) = args.resume {
            // Try exact path first, then search in sessions dir
            let path = if resume_path.exists() {
                resume_path.clone()
            } else {
                // Search for partial match in sessions directory
                find_session_by_pattern(&config.output.session_dir, resume_path)?
            };

            let session = feroxmute_core::state::Session::resume(&path)?;

            // Warn if resuming completed session
            if session.status()? == feroxmute_core::state::SessionStatus::Completed {
                print!("This engagement was completed. Resume anyway? [y/N]: ");
                io::stdout().flush()?;
                let mut response = String::new();
                io::stdin().read_line(&mut response)?;
                if !response.trim().to_lowercase().starts_with('y') {
                    println!("Aborted.");
                    return Ok(());
                }
            }

            // Set status back to Running
            session.set_status(feroxmute_core::state::SessionStatus::Running)?;
            session
        } else {
            // Update config with CLI target
            let mut session_config = config.clone();
            session_config.target.host = target.clone();
            feroxmute_core::state::Session::new(session_config, &config.output.session_dir)?
        };

        let session = Arc::new(session);
```

**Step 2: Add find_session_by_pattern helper**

Add before `main()`:

```rust
fn find_session_by_pattern(sessions_dir: &std::path::Path, pattern: &std::path::Path) -> anyhow::Result<std::path::PathBuf> {
    let pattern_str = pattern.to_string_lossy();

    if !sessions_dir.exists() {
        anyhow::bail!("Sessions directory does not exist: {}", sessions_dir.display());
    }

    let mut matches: Vec<_> = std::fs::read_dir(sessions_dir)?
        .filter_map(|e| e.ok())
        .filter(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            name.contains(pattern_str.as_ref()) ||
            // Also match by target hostname
            feroxmute_core::state::Session::resume(e.path())
                .map(|s| s.config.target.host.contains(pattern_str.as_ref()))
                .unwrap_or(false)
        })
        .collect();

    // Sort by modification time (newest first)
    matches.sort_by(|a, b| {
        let a_time = a.metadata().and_then(|m| m.modified()).ok();
        let b_time = b.metadata().and_then(|m| m.modified()).ok();
        b_time.cmp(&a_time)
    });

    match matches.len() {
        0 => anyhow::bail!("No session found matching: {}", pattern_str),
        1 => Ok(matches[0].path()),
        _ => {
            println!("Multiple sessions match '{}'. Please be more specific:", pattern_str);
            for entry in &matches {
                println!("  {}", entry.file_name().to_string_lossy());
            }
            anyhow::bail!("Ambiguous session pattern");
        }
    }
}
```

**Step 3: Update App::new to use session.id**

Change line 314:

```rust
        let mut app = tui::App::new(&target, &session.id, Some(rx));
```

**Step 4: Add Arc import if needed**

Ensure `use std::sync::Arc;` is present (should already be there).

**Step 5: Verify it compiles**

Run: `cargo build -p feroxmute-cli`
Expected: Success

**Step 6: Commit**

```bash
git add feroxmute-cli/src/main.rs
git commit -m "feat(cli): wire up Session creation and resume in main"
```

---

## Task 11: Update runner.rs to Accept Session

**Files:**
- Modify: `feroxmute-cli/src/runner.rs`

**Step 1: Update function signature**

Change `run_orchestrator` signature to accept session:

```rust
pub async fn run_orchestrator(
    target: String,
    provider: Arc<dyn LlmProvider>,
    container: Arc<ContainerManager>,
    tx: mpsc::Sender<AgentEvent>,
    cancel: CancellationToken,
    source_path: Option<String>,
    limitations: Arc<EngagementLimitations>,
    instruction: Option<String>,
    session: Arc<feroxmute_core::state::Session>,  // NEW
) -> Result<()>
```

**Step 2: Update run_orchestrator_with_tools signature**

```rust
async fn run_orchestrator_with_tools(
    orchestrator: &OrchestratorAgent,
    target: &str,
    tx: &mpsc::Sender<AgentEvent>,
    provider: Arc<dyn LlmProvider>,
    container: Arc<ContainerManager>,
    prompts: &Prompts,
    cancel: CancellationToken,
    source_path: Option<String>,
    limitations: Arc<EngagementLimitations>,
    instruction: Option<String>,
    engagement_completed: Arc<std::sync::atomic::AtomicBool>,
    session: Arc<feroxmute_core::state::Session>,  // NEW
) -> Result<String>
```

**Step 3: Pass session in the call from run_orchestrator**

Update the call around line 264:

```rust
        result = run_orchestrator_with_tools(&orchestrator, &target, &tx, Arc::clone(&provider), Arc::clone(&container), &prompts, cancel.clone(), source_path.clone(), Arc::clone(&limitations), instruction, Arc::clone(&engagement_completed), Arc::clone(&session)) => {
```

**Step 4: Verify it compiles (will fail - we'll fix caller next)**

Run: `cargo build -p feroxmute-cli`
Expected: FAIL (main.rs doesn't pass session yet)

**Step 5: Update main.rs to pass session to runner**

In main.rs, update the `run_orchestrator` call (around line 447):

```rust
            runner::run_orchestrator(
                agent_target,
                provider,
                container,
                tx,
                agent_cancel,
                source_path,
                limitations,
                instruction,
                Arc::clone(&session),  // NEW
            )
            .await
```

**Step 6: Verify it compiles**

Run: `cargo build -p feroxmute-cli`
Expected: Success

**Step 7: Commit**

```bash
git add feroxmute-cli/src/runner.rs feroxmute-cli/src/main.rs
git commit -m "feat(runner): pass Session through to orchestrator"
```

---

## Task 12: Use Session DB Instead of In-Memory

**Files:**
- Modify: `feroxmute-cli/src/runner.rs`
- Modify: `feroxmute-core/src/state/session.rs`

**Step 1: Add conn_arc method to Session**

In `feroxmute-core/src/state/session.rs`, we need to allow sharing the connection. However, rusqlite::Connection is not thread-safe. We need to wrap it in a Mutex.

First, update Session struct to store connection in Arc<Mutex>:

This is a significant refactor. For now, let's create a separate connection for the runner that shares the same file:

Add to `impl Session`:

```rust
    /// Open a new connection to the session database (for concurrent access)
    pub fn open_connection(&self) -> Result<Connection> {
        let db_path = self.path.join("session.db");
        Ok(Connection::open(&db_path)?)
    }
```

**Step 2: Update runner.rs to use session DB**

Replace the in-memory DB creation (lines 370-374):

```rust
    // Create memory context with in-memory DB (TODO: use session DB when available)
    let memory_conn = rusqlite::Connection::open_in_memory()
        .map_err(|e| anyhow::anyhow!("Failed to create memory DB: {}", e))?;
    feroxmute_core::state::run_migrations(&memory_conn)
        .map_err(|e| anyhow::anyhow!("Failed to run migrations: {}", e))?;
```

With:

```rust
    // Use session DB for persistent storage
    let memory_conn = session.open_connection()
        .map_err(|e| anyhow::anyhow!("Failed to open session DB: {}", e))?;
```

**Step 3: Verify it compiles**

Run: `cargo build -p feroxmute-cli`
Expected: Success

**Step 4: Commit**

```bash
git add feroxmute-core/src/state/session.rs feroxmute-cli/src/runner.rs
git commit -m "feat(runner): use session DB instead of in-memory"
```

---

## Task 13: Build Resume Context Injection

**Files:**
- Modify: `feroxmute-cli/src/runner.rs`
- Modify: `feroxmute-core/src/state/session.rs`

**Step 1: Add is_resuming check to Session**

Add to `impl Session` in session.rs:

```rust
    /// Check if this is a resumed session (has prior activity)
    pub fn is_resuming(&self) -> Result<bool> {
        let agents = self.completed_agents()?;
        let memory = self.memory_entries()?;
        let findings = self.findings_summary()?;
        Ok(!agents.is_empty() || !memory.is_empty() || findings.total() > 0)
    }

    /// Build resume context string for orchestrator prompt
    pub fn resume_context(&self) -> Result<String> {
        let agents = self.completed_agents()?;
        let memory = self.memory_entries()?;
        let findings = self.findings_summary()?;

        let mut context = String::from("RESUMING ENGAGEMENT - Prior context:\n");

        if !agents.is_empty() {
            context.push_str(&format!("- Completed agents: {}\n", agents.join(", ")));
        }

        if !memory.is_empty() {
            context.push_str("- Memory:\n");
            for (key, value) in memory.iter().take(10) {
                // Truncate long values
                let display_value = if value.len() > 100 {
                    format!("{}...", &value[..100])
                } else {
                    value.clone()
                };
                context.push_str(&format!("  - {}: {}\n", key, display_value));
            }
            if memory.len() > 10 {
                context.push_str(&format!("  - ... and {} more entries\n", memory.len() - 10));
            }
        }

        if findings.total() > 0 {
            context.push_str(&format!(
                "- Findings: {} Critical, {} High, {} Medium, {} Low, {} Info\n",
                findings.critical, findings.high, findings.medium, findings.low, findings.info
            ));
        }

        context.push_str("\nContinue from where you left off. Do NOT repeat work already done by completed agents.\n");

        Ok(context)
    }
```

**Step 2: Inject resume context in runner.rs**

In `run_orchestrator_with_tools`, before building the user_prompt (around line 400), add:

```rust
    // Check if resuming and prepend context
    let resume_prefix = if session.is_resuming().unwrap_or(false) {
        session.resume_context().unwrap_or_default()
    } else {
        String::new()
    };
```

Then update the user_prompt building to include it:

```rust
    let user_prompt = format!(
        "{}Target: {}\n\n{}\n\n{}{}\n\n\
        Available agent types: recon, scanner{}, report.\n\n\
        {}\n\n\
        CRITICAL: After EVERY spawn_agent call, you MUST call wait_for_any() to get results. Never stop without waiting for spawned agents.\n\n\
        {}",
        resume_prefix,  // NEW - prepend resume context
        target,
        // ... rest unchanged
```

**Step 3: Verify it compiles**

Run: `cargo build -p feroxmute-cli`
Expected: Success

**Step 4: Commit**

```bash
git add feroxmute-core/src/state/session.rs feroxmute-cli/src/runner.rs
git commit -m "feat(runner): inject resume context into orchestrator prompt"
```

---

## Task 14: Set Interrupted Status on Quit

**Files:**
- Modify: `feroxmute-cli/src/main.rs`

**Step 1: Clone session for cleanup handler**

Before spawning the agent task (around line 446), add:

```rust
        let cleanup_session = Arc::clone(&session);
```

**Step 2: Update TUI quit handler to set interrupted status**

After the `tui_handle.await??;` line (around line 479), add cleanup:

```rust
        // Set session status based on how engagement ended
        if cleanup_session.status().unwrap_or(feroxmute_core::state::SessionStatus::Running)
            != feroxmute_core::state::SessionStatus::Completed
        {
            let _ = cleanup_session.set_status(feroxmute_core::state::SessionStatus::Interrupted);
        }
```

**Step 3: Verify it compiles**

Run: `cargo build -p feroxmute-cli`
Expected: Success

**Step 4: Commit**

```bash
git add feroxmute-cli/src/main.rs
git commit -m "feat(cli): set session status to interrupted on quit"
```

---

## Task 15: Mark Completed on CompleteEngagementTool

**Files:**
- Modify: `feroxmute-core/src/tools/orchestrator.rs`

**Step 1: Find CompleteEngagementTool**

Search for where CompleteEngagementTool sets engagement_completed flag.

**Step 2: Add session status update**

This requires passing session through the OrchestratorContext. In `feroxmute-core/src/tools/mod.rs` or wherever OrchestratorContext is defined, add:

```rust
pub session: Option<Arc<Session>>,
```

Then in CompleteEngagementTool::call, after setting engagement_completed:

```rust
if let Some(ref session) = context.session {
    let _ = session.set_status(SessionStatus::Completed);
}
```

**Step 3: Update context creation in runner.rs**

Add session to OrchestratorContext:

```rust
    let context = Arc::new(OrchestratorContext {
        // ... existing fields ...
        session: Some(Arc::clone(&session)),  // NEW
    });
```

**Step 4: Verify it compiles**

Run: `cargo build`
Expected: Success

**Step 5: Commit**

```bash
git add feroxmute-core/src/tools/orchestrator.rs feroxmute-core/src/tools/mod.rs feroxmute-cli/src/runner.rs
git commit -m "feat(tools): set session completed on CompleteEngagementTool"
```

---

## Task 16: Integration Test - Full Persistence Flow

**Files:**
- Create: `feroxmute-cli/tests/session_persistence.rs`

**Step 1: Write integration test**

```rust
//! Integration tests for session persistence

use feroxmute_core::config::EngagementConfig;
use feroxmute_core::state::{Session, SessionStatus};
use tempfile::TempDir;

#[test]
fn test_session_persists_across_restart() {
    let temp = TempDir::new().expect("should create temp dir");

    // Create session and add some data
    let config = EngagementConfig::default();
    let mut config = config;
    config.target.host = "test.example.com".to_string();

    let session = Session::new(config, temp.path()).expect("should create session");
    let session_path = session.path.clone();
    let session_id = session.id.clone();

    // Add memory entry
    session.conn().execute(
        "INSERT INTO scratch_pad (key, value) VALUES ('test_key', 'test_value')",
        [],
    ).expect("should insert");

    // Mark agent completed
    session.mark_agent_completed("recon-1").expect("should mark");

    // Set interrupted
    session.set_status(SessionStatus::Interrupted).expect("should set status");

    // Drop session (simulating app exit)
    drop(session);

    // Resume session
    let resumed = Session::resume(&session_path).expect("should resume");

    assert_eq!(resumed.id, session_id);
    assert_eq!(resumed.status().expect("should get status"), SessionStatus::Interrupted);

    let agents = resumed.completed_agents().expect("should get agents");
    assert!(agents.contains(&"recon-1".to_string()));

    let memory = resumed.memory_entries().expect("should get memory");
    assert!(memory.iter().any(|(k, v)| k == "test_key" && v == "test_value"));

    // Check resume context is generated
    assert!(resumed.is_resuming().expect("should check"));
    let context = resumed.resume_context().expect("should get context");
    assert!(context.contains("recon-1"));
    assert!(context.contains("test_key"));
}
```

**Step 2: Run integration test**

Run: `cargo test -p feroxmute-cli test_session_persists`
Expected: PASS

**Step 3: Commit**

```bash
git add feroxmute-cli/tests/session_persistence.rs
git commit -m "test: add integration test for session persistence"
```

---

## Task 17: Final Verification

**Step 1: Run all tests**

Run: `cargo test`
Expected: All tests pass

**Step 2: Run clippy**

Run: `cargo clippy`
Expected: No errors (warnings acceptable)

**Step 3: Format code**

Run: `cargo fmt`

**Step 4: Manual smoke test**

1. Run: `cargo run -- --target httpbin.org` (start engagement, press 'q' to quit early)
2. Run: `cargo run -- --list-sessions` (should show interrupted session)
3. Run: `cargo run -- --resume httpbin` (should resume with context)

**Step 5: Final commit if needed**

```bash
git add -A
git commit -m "chore: final cleanup for session persistence"
```
