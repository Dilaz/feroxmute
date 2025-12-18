# Multi-Target and SAST Integration Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Enable multiple targets with intelligent source-to-web linking and static analysis via a new SAST Agent.

**Architecture:** Add a target module for parsing and classifying targets (web/directory/repo). New SAST Agent runs static analysis tools and shares findings with other agents via SQLite. Orchestrator coordinates SAST before web testing when targets are linked.

**Tech Stack:** Rust, rusqlite, clap, ratatui, Docker (semgrep, ast-grep, grype, gitleaks)

---

## Phase 1: Target Types and Parsing

### Task 1: Create Target Type Enum

**Files:**
- Create: `feroxmute-core/src/targets/mod.rs`
- Create: `feroxmute-core/src/targets/types.rs`
- Modify: `feroxmute-core/src/lib.rs`

**Step 1: Write failing test for Target enum**

Create `feroxmute-core/src/targets/types.rs`:

```rust
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq)]
pub enum TargetType {
    Web { url: String },
    Directory { path: PathBuf },
    Repository { url: String, local_path: Option<PathBuf> },
}

#[derive(Debug, Clone)]
pub struct Target {
    pub raw: String,
    pub target_type: TargetType,
    pub linked_to: Option<String>,
}

impl Target {
    pub fn parse(input: &str) -> Result<Self, TargetParseError> {
        todo!()
    }

    pub fn is_source(&self) -> bool {
        matches!(self.target_type, TargetType::Directory { .. } | TargetType::Repository { .. })
    }

    pub fn is_web(&self) -> bool {
        matches!(self.target_type, TargetType::Web { .. })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TargetParseError {
    #[error("Invalid target: {0}")]
    Invalid(String),
    #[error("Path does not exist: {0}")]
    PathNotFound(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_https_url() {
        let target = Target::parse("https://example.com").unwrap();
        assert!(matches!(target.target_type, TargetType::Web { url } if url == "https://example.com"));
    }

    #[test]
    fn test_parse_http_url() {
        let target = Target::parse("http://example.com").unwrap();
        assert!(matches!(target.target_type, TargetType::Web { .. }));
    }

    #[test]
    fn test_parse_domain_as_web() {
        let target = Target::parse("example.com").unwrap();
        assert!(matches!(target.target_type, TargetType::Web { .. }));
    }

    #[test]
    fn test_parse_github_url() {
        let target = Target::parse("https://github.com/owner/repo").unwrap();
        assert!(matches!(target.target_type, TargetType::Repository { .. }));
    }

    #[test]
    fn test_parse_git_ssh_url() {
        let target = Target::parse("git@github.com:owner/repo.git").unwrap();
        assert!(matches!(target.target_type, TargetType::Repository { .. }));
    }

    #[test]
    fn test_is_source() {
        let dir = Target {
            raw: "./src".to_string(),
            target_type: TargetType::Directory { path: PathBuf::from("./src") },
            linked_to: None,
        };
        assert!(dir.is_source());
        assert!(!dir.is_web());
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p feroxmute-core target`
Expected: FAIL with "not yet implemented"

**Step 3: Implement Target::parse**

Update `feroxmute-core/src/targets/types.rs` - replace `todo!()` with:

```rust
impl Target {
    pub fn parse(input: &str) -> Result<Self, TargetParseError> {
        let input = input.trim();

        // Check for HTTP/HTTPS URLs (but not git hosts)
        if input.starts_with("http://") || input.starts_with("https://") {
            // Check if it's a git repository URL
            if Self::is_git_host(input) {
                return Ok(Self {
                    raw: input.to_string(),
                    target_type: TargetType::Repository {
                        url: input.to_string(),
                        local_path: None,
                    },
                    linked_to: None,
                });
            }
            return Ok(Self {
                raw: input.to_string(),
                target_type: TargetType::Web { url: input.to_string() },
                linked_to: None,
            });
        }

        // Check for git SSH URLs
        if input.starts_with("git@") || input.ends_with(".git") {
            return Ok(Self {
                raw: input.to_string(),
                target_type: TargetType::Repository {
                    url: input.to_string(),
                    local_path: None,
                },
                linked_to: None,
            });
        }

        // Check if it's a local path
        let path = PathBuf::from(input);
        if path.exists() {
            return Ok(Self {
                raw: input.to_string(),
                target_type: TargetType::Directory { path },
                linked_to: None,
            });
        }

        // Check if it looks like a relative path (starts with ./ or ../)
        if input.starts_with("./") || input.starts_with("../") {
            return Err(TargetParseError::PathNotFound(input.to_string()));
        }

        // Default: treat as domain (web target)
        Ok(Self {
            raw: input.to_string(),
            target_type: TargetType::Web {
                url: format!("https://{}", input),
            },
            linked_to: None,
        })
    }

    fn is_git_host(url: &str) -> bool {
        let git_hosts = ["github.com", "gitlab.com", "bitbucket.org", "codeberg.org"];
        git_hosts.iter().any(|host| url.contains(host))
    }
}
```

**Step 4: Run test to verify it passes**

Run: `cargo test -p feroxmute-core target`
Expected: All tests PASS

**Step 5: Create module file and export**

Create `feroxmute-core/src/targets/mod.rs`:

```rust
mod types;

pub use types::{Target, TargetParseError, TargetType};
```

**Step 6: Add to lib.rs**

Add to `feroxmute-core/src/lib.rs`:

```rust
pub mod targets;
```

**Step 7: Verify build**

Run: `cargo build -p feroxmute-core`
Expected: SUCCESS

**Step 8: Commit**

```bash
git add feroxmute-core/src/targets/ feroxmute-core/src/lib.rs
git commit -m "feat(core): add target types and parsing"
```

---

### Task 2: Add Target Collection and Multi-Target Config

**Files:**
- Create: `feroxmute-core/src/targets/collection.rs`
- Modify: `feroxmute-core/src/targets/mod.rs`

**Step 1: Write failing test for TargetCollection**

Create `feroxmute-core/src/targets/collection.rs`:

```rust
use super::{Target, TargetParseError};

#[derive(Debug, Clone)]
pub struct TargetGroup {
    pub web_target: Target,
    pub source_target: Option<Target>,
}

#[derive(Debug, Clone)]
pub struct TargetCollection {
    pub groups: Vec<TargetGroup>,
    pub standalone_sources: Vec<Target>,
}

impl TargetCollection {
    pub fn new() -> Self {
        Self {
            groups: Vec::new(),
            standalone_sources: Vec::new(),
        }
    }

    pub fn from_strings(inputs: &[String]) -> Result<Self, TargetParseError> {
        todo!()
    }

    pub fn add_target(&mut self, target: Target) {
        todo!()
    }

    pub fn link_source_to_web(&mut self, source_raw: &str, web_raw: &str) -> bool {
        todo!()
    }

    pub fn web_targets(&self) -> Vec<&Target> {
        self.groups.iter().map(|g| &g.web_target).collect()
    }

    pub fn has_linked_source(&self, web_raw: &str) -> bool {
        self.groups
            .iter()
            .any(|g| g.web_target.raw == web_raw && g.source_target.is_some())
    }
}

impl Default for TargetCollection {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_strings_single_web() {
        let inputs = vec!["https://example.com".to_string()];
        let collection = TargetCollection::from_strings(&inputs).unwrap();
        assert_eq!(collection.groups.len(), 1);
        assert!(collection.groups[0].source_target.is_none());
    }

    #[test]
    fn test_from_strings_web_and_source() {
        // Note: This test needs a real directory, use temp
        let inputs = vec![
            "https://example.com".to_string(),
        ];
        let collection = TargetCollection::from_strings(&inputs).unwrap();
        assert_eq!(collection.groups.len(), 1);
    }

    #[test]
    fn test_link_source_to_web() {
        let mut collection = TargetCollection::new();
        let web = Target::parse("https://example.com").unwrap();
        collection.add_target(web);

        assert!(!collection.has_linked_source("https://example.com"));
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p feroxmute-core collection`
Expected: FAIL with "not yet implemented"

**Step 3: Implement TargetCollection**

Replace `todo!()` implementations:

```rust
impl TargetCollection {
    pub fn from_strings(inputs: &[String]) -> Result<Self, TargetParseError> {
        let mut collection = Self::new();
        for input in inputs {
            let target = Target::parse(input)?;
            collection.add_target(target);
        }
        Ok(collection)
    }

    pub fn add_target(&mut self, target: Target) {
        if target.is_web() {
            self.groups.push(TargetGroup {
                web_target: target,
                source_target: None,
            });
        } else {
            self.standalone_sources.push(target);
        }
    }

    pub fn link_source_to_web(&mut self, source_raw: &str, web_raw: &str) -> bool {
        // Find the source in standalone_sources
        let source_idx = self
            .standalone_sources
            .iter()
            .position(|t| t.raw == source_raw);

        let Some(idx) = source_idx else {
            return false;
        };

        // Find the web target group
        let group = self.groups.iter_mut().find(|g| g.web_target.raw == web_raw);

        let Some(group) = group else {
            return false;
        };

        // Move source from standalone to linked
        let mut source = self.standalone_sources.remove(idx);
        source.linked_to = Some(web_raw.to_string());
        group.source_target = Some(source);
        true
    }
}
```

**Step 4: Run test to verify it passes**

Run: `cargo test -p feroxmute-core collection`
Expected: PASS

**Step 5: Export from mod.rs**

Update `feroxmute-core/src/targets/mod.rs`:

```rust
mod collection;
mod types;

pub use collection::{TargetCollection, TargetGroup};
pub use types::{Target, TargetParseError, TargetType};
```

**Step 6: Commit**

```bash
git add feroxmute-core/src/targets/
git commit -m "feat(core): add target collection for multi-target support"
```

---

## Phase 2: CLI Argument Updates

### Task 3: Add Multi-Target CLI Arguments

**Files:**
- Modify: `feroxmute-cli/src/args.rs`

**Step 1: Read current args.rs**

Read the file to understand current structure.

**Step 2: Add new arguments**

Add these fields to the `Args` struct:

```rust
/// Target domains, IPs, directories, or git URLs (can be repeated)
#[arg(long, action = ArgAction::Append)]
pub target: Vec<String>,

/// Explicit source directory for the primary target
#[arg(long)]
pub source: Option<PathBuf>,

/// Treat all targets as separate engagements (skip relationship detection)
#[arg(long)]
pub separate: bool,

/// Run static analysis only (no web testing)
#[arg(long)]
pub sast_only: bool,
```

**Step 3: Verify build**

Run: `cargo build -p feroxmute-cli`
Expected: SUCCESS (may have warnings about unused)

**Step 4: Commit**

```bash
git add feroxmute-cli/src/args.rs
git commit -m "feat(cli): add multi-target CLI arguments"
```

---

## Phase 3: Database Schema for Code Findings

### Task 4: Add Code Finding Models

**Files:**
- Modify: `feroxmute-core/src/state/models.rs`
- Modify: `feroxmute-core/src/state/migrations.rs`

**Step 1: Write failing test for CodeFinding**

Add to `feroxmute-core/src/state/models.rs`:

```rust
#[derive(Debug, Clone, PartialEq)]
pub enum FindingType {
    Dependency,
    Sast,
    Secret,
}

impl FindingType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Dependency => "dependency",
            Self::Sast => "sast",
            Self::Secret => "secret",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "dependency" => Some(Self::Dependency),
            "sast" => Some(Self::Sast),
            "secret" => Some(Self::Secret),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CodeFinding {
    pub id: String,
    pub file_path: String,
    pub line_number: Option<u32>,
    pub severity: Severity,
    pub finding_type: FindingType,
    pub cve_id: Option<String>,
    pub cwe_id: Option<String>,
    pub title: String,
    pub description: Option<String>,
    pub snippet: Option<String>,
    pub tool: String,
    pub package_name: Option<String>,
    pub package_version: Option<String>,
    pub fixed_version: Option<String>,
    pub discovered_at: DateTime<Utc>,
}

impl CodeFinding {
    pub fn new(
        file_path: impl Into<String>,
        severity: Severity,
        finding_type: FindingType,
        title: impl Into<String>,
        tool: impl Into<String>,
    ) -> Self {
        Self {
            id: format!("CODE-{}", &uuid::Uuid::new_v4().to_string()[..8]),
            file_path: file_path.into(),
            line_number: None,
            severity,
            finding_type,
            cve_id: None,
            cwe_id: None,
            title: title.into(),
            description: None,
            snippet: None,
            tool: tool.into(),
            package_name: None,
            package_version: None,
            fixed_version: None,
            discovered_at: Utc::now(),
        }
    }

    pub fn with_line(mut self, line: u32) -> Self {
        self.line_number = Some(line);
        self
    }

    pub fn with_cve(mut self, cve: impl Into<String>) -> Self {
        self.cve_id = Some(cve.into());
        self
    }

    pub fn with_cwe(mut self, cwe: impl Into<String>) -> Self {
        self.cwe_id = Some(cwe.into());
        self
    }

    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    pub fn with_snippet(mut self, snippet: impl Into<String>) -> Self {
        self.snippet = Some(snippet.into());
        self
    }

    pub fn with_package(mut self, name: impl Into<String>, version: impl Into<String>) -> Self {
        self.package_name = Some(name.into());
        self.package_version = Some(version.into());
        self
    }

    pub fn with_fixed_version(mut self, version: impl Into<String>) -> Self {
        self.fixed_version = Some(version.into());
        self
    }

    pub fn insert(&self, conn: &Connection) -> Result<()> {
        conn.execute(
            "INSERT INTO code_findings (id, file_path, line_number, severity, finding_type, cve_id, cwe_id, title, description, snippet, tool, package_name, package_version, fixed_version, discovered_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
            params![
                self.id,
                self.file_path,
                self.line_number,
                self.severity.as_str(),
                self.finding_type.as_str(),
                self.cve_id,
                self.cwe_id,
                self.title,
                self.description,
                self.snippet,
                self.tool,
                self.package_name,
                self.package_version,
                self.fixed_version,
                self.discovered_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn all(conn: &Connection) -> Result<Vec<Self>> {
        let mut stmt = conn.prepare(
            "SELECT id, file_path, line_number, severity, finding_type, cve_id, cwe_id, title, description, snippet, tool, package_name, package_version, fixed_version, discovered_at FROM code_findings ORDER BY discovered_at DESC"
        )?;
        let findings = stmt.query_map([], |row| {
            Ok(Self {
                id: row.get(0)?,
                file_path: row.get(1)?,
                line_number: row.get(2)?,
                severity: Severity::from_str(&row.get::<_, String>(3)?).unwrap_or(Severity::Info),
                finding_type: FindingType::from_str(&row.get::<_, String>(4)?).unwrap_or(FindingType::Sast),
                cve_id: row.get(5)?,
                cwe_id: row.get(6)?,
                title: row.get(7)?,
                description: row.get(8)?,
                snippet: row.get(9)?,
                tool: row.get(10)?,
                package_name: row.get(11)?,
                package_version: row.get(12)?,
                fixed_version: row.get(13)?,
                discovered_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(14)?)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
            })
        })?.collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(findings)
    }

    pub fn count_by_severity(conn: &Connection) -> Result<std::collections::HashMap<Severity, u32>> {
        let mut stmt = conn.prepare(
            "SELECT severity, COUNT(*) FROM code_findings GROUP BY severity"
        )?;
        let mut counts = std::collections::HashMap::new();
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, u32>(1)?))
        })?;
        for row in rows {
            let (sev_str, count) = row?;
            if let Some(sev) = Severity::from_str(&sev_str) {
                counts.insert(sev, count);
            }
        }
        Ok(counts)
    }
}

#[cfg(test)]
mod code_finding_tests {
    use super::*;
    use rusqlite::Connection;

    fn setup_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute(
            "CREATE TABLE code_findings (
                id TEXT PRIMARY KEY,
                file_path TEXT NOT NULL,
                line_number INTEGER,
                severity TEXT NOT NULL,
                finding_type TEXT NOT NULL,
                cve_id TEXT,
                cwe_id TEXT,
                title TEXT NOT NULL,
                description TEXT,
                snippet TEXT,
                tool TEXT NOT NULL,
                package_name TEXT,
                package_version TEXT,
                fixed_version TEXT,
                discovered_at TEXT NOT NULL
            )",
            [],
        ).unwrap();
        conn
    }

    #[test]
    fn test_code_finding_insert_and_retrieve() {
        let conn = setup_db();
        let finding = CodeFinding::new(
            "src/main.rs",
            Severity::High,
            FindingType::Sast,
            "SQL Injection",
            "semgrep",
        )
        .with_line(42)
        .with_cwe("CWE-89");

        finding.insert(&conn).unwrap();

        let findings = CodeFinding::all(&conn).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].title, "SQL Injection");
        assert_eq!(findings[0].line_number, Some(42));
    }

    #[test]
    fn test_dependency_finding() {
        let conn = setup_db();
        let finding = CodeFinding::new(
            "Cargo.toml",
            Severity::Critical,
            FindingType::Dependency,
            "CVE-2024-1234",
            "grype",
        )
        .with_cve("CVE-2024-1234")
        .with_package("lodash", "4.17.20")
        .with_fixed_version("4.17.21");

        finding.insert(&conn).unwrap();

        let findings = CodeFinding::all(&conn).unwrap();
        assert_eq!(findings[0].package_name, Some("lodash".to_string()));
    }
}
```

**Step 2: Run test to verify structure compiles**

Run: `cargo test -p feroxmute-core code_finding`
Expected: May fail on missing Severity::from_str, fix if needed

**Step 3: Add migration for code_findings table**

Add to `feroxmute-core/src/state/migrations.rs`:

```rust
pub const MIGRATION_CODE_FINDINGS: &str = r#"
CREATE TABLE IF NOT EXISTS code_findings (
    id TEXT PRIMARY KEY,
    file_path TEXT NOT NULL,
    line_number INTEGER,
    severity TEXT NOT NULL,
    finding_type TEXT NOT NULL,
    cve_id TEXT,
    cwe_id TEXT,
    title TEXT NOT NULL,
    description TEXT,
    snippet TEXT,
    tool TEXT NOT NULL,
    package_name TEXT,
    package_version TEXT,
    fixed_version TEXT,
    discovered_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_code_findings_severity ON code_findings(severity);
CREATE INDEX IF NOT EXISTS idx_code_findings_type ON code_findings(finding_type);
"#;
```

**Step 4: Run tests**

Run: `cargo test -p feroxmute-core code_finding`
Expected: PASS

**Step 5: Commit**

```bash
git add feroxmute-core/src/state/
git commit -m "feat(core): add CodeFinding model for SAST results"
```

---

### Task 5: Add CodeEndpoint Model for Extracted Routes

**Files:**
- Modify: `feroxmute-core/src/state/models.rs`

**Step 1: Write test and implementation**

Add to `feroxmute-core/src/state/models.rs`:

```rust
#[derive(Debug, Clone)]
pub struct CodeEndpoint {
    pub id: String,
    pub route: String,
    pub method: Option<String>,
    pub handler_file: String,
    pub handler_line: Option<u32>,
    pub parameters: Vec<String>,
    pub auth_required: Option<bool>,
    pub notes: Option<String>,
}

impl CodeEndpoint {
    pub fn new(route: impl Into<String>, handler_file: impl Into<String>) -> Self {
        Self {
            id: format!("EP-{}", &uuid::Uuid::new_v4().to_string()[..8]),
            route: route.into(),
            method: None,
            handler_file: handler_file.into(),
            handler_line: None,
            parameters: Vec::new(),
            auth_required: None,
            notes: None,
        }
    }

    pub fn with_method(mut self, method: impl Into<String>) -> Self {
        self.method = Some(method.into());
        self
    }

    pub fn with_line(mut self, line: u32) -> Self {
        self.handler_line = Some(line);
        self
    }

    pub fn with_parameters(mut self, params: Vec<String>) -> Self {
        self.parameters = params;
        self
    }

    pub fn with_auth(mut self, required: bool) -> Self {
        self.auth_required = Some(required);
        self
    }

    pub fn insert(&self, conn: &Connection) -> Result<()> {
        let params_json = serde_json::to_string(&self.parameters).unwrap_or_else(|_| "[]".to_string());
        conn.execute(
            "INSERT INTO code_endpoints (id, route, method, handler_file, handler_line, parameters, auth_required, notes)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                self.id,
                self.route,
                self.method,
                self.handler_file,
                self.handler_line,
                params_json,
                self.auth_required,
                self.notes,
            ],
        )?;
        Ok(())
    }

    pub fn all(conn: &Connection) -> Result<Vec<Self>> {
        let mut stmt = conn.prepare(
            "SELECT id, route, method, handler_file, handler_line, parameters, auth_required, notes FROM code_endpoints"
        )?;
        let endpoints = stmt.query_map([], |row| {
            let params_str: String = row.get(5)?;
            let parameters: Vec<String> = serde_json::from_str(&params_str).unwrap_or_default();
            Ok(Self {
                id: row.get(0)?,
                route: row.get(1)?,
                method: row.get(2)?,
                handler_file: row.get(3)?,
                handler_line: row.get(4)?,
                parameters,
                auth_required: row.get(6)?,
                notes: row.get(7)?,
            })
        })?.collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(endpoints)
    }

    pub fn find_by_route(conn: &Connection, route: &str) -> Result<Option<Self>> {
        let mut stmt = conn.prepare(
            "SELECT id, route, method, handler_file, handler_line, parameters, auth_required, notes FROM code_endpoints WHERE route = ?1"
        )?;
        let mut rows = stmt.query(params![route])?;
        if let Some(row) = rows.next()? {
            let params_str: String = row.get(5)?;
            let parameters: Vec<String> = serde_json::from_str(&params_str).unwrap_or_default();
            Ok(Some(Self {
                id: row.get(0)?,
                route: row.get(1)?,
                method: row.get(2)?,
                handler_file: row.get(3)?,
                handler_line: row.get(4)?,
                parameters,
                auth_required: row.get(6)?,
                notes: row.get(7)?,
            }))
        } else {
            Ok(None)
        }
    }
}
```

**Step 2: Add migration**

Add to migrations:

```rust
pub const MIGRATION_CODE_ENDPOINTS: &str = r#"
CREATE TABLE IF NOT EXISTS code_endpoints (
    id TEXT PRIMARY KEY,
    route TEXT NOT NULL,
    method TEXT,
    handler_file TEXT NOT NULL,
    handler_line INTEGER,
    parameters TEXT NOT NULL DEFAULT '[]',
    auth_required INTEGER,
    notes TEXT
);

CREATE INDEX IF NOT EXISTS idx_code_endpoints_route ON code_endpoints(route);
"#;
```

**Step 3: Run tests and commit**

```bash
cargo test -p feroxmute-core
git add feroxmute-core/src/state/
git commit -m "feat(core): add CodeEndpoint model for extracted routes"
```

---

## Phase 4: SAST Tool Wrappers

### Task 6: Create SAST Tool Module Structure

**Files:**
- Create: `feroxmute-core/src/tools/sast/mod.rs`
- Create: `feroxmute-core/src/tools/sast/semgrep.rs`
- Create: `feroxmute-core/src/tools/sast/grype.rs`
- Modify: `feroxmute-core/src/tools/mod.rs`

**Step 1: Create SAST module**

Create `feroxmute-core/src/tools/sast/mod.rs`:

```rust
mod grype;
mod semgrep;

pub use grype::{GrypeOutput, GrypeFinding};
pub use semgrep::{SemgrepOutput, SemgrepResult};

use crate::state::models::{CodeFinding, FindingType, Severity};

/// Trait for SAST tool output parsing
pub trait SastToolOutput {
    fn to_code_findings(&self) -> Vec<CodeFinding>;
}
```

**Step 2: Implement Semgrep parser**

Create `feroxmute-core/src/tools/sast/semgrep.rs`:

```rust
use serde::Deserialize;
use crate::state::models::{CodeFinding, FindingType, Severity};
use super::SastToolOutput;

#[derive(Debug, Deserialize)]
pub struct SemgrepOutput {
    pub results: Vec<SemgrepResult>,
    pub errors: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct SemgrepResult {
    pub check_id: String,
    pub path: String,
    pub start: SemgrepLocation,
    pub end: SemgrepLocation,
    pub extra: SemgrepExtra,
}

#[derive(Debug, Deserialize)]
pub struct SemgrepLocation {
    pub line: u32,
    pub col: u32,
}

#[derive(Debug, Deserialize)]
pub struct SemgrepExtra {
    pub message: String,
    pub severity: String,
    pub metadata: Option<SemgrepMetadata>,
    pub lines: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SemgrepMetadata {
    pub cwe: Option<Vec<String>>,
    pub owasp: Option<Vec<String>>,
}

impl SemgrepOutput {
    pub fn parse(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

impl SastToolOutput for SemgrepOutput {
    fn to_code_findings(&self) -> Vec<CodeFinding> {
        self.results
            .iter()
            .map(|r| {
                let severity = match r.extra.severity.to_lowercase().as_str() {
                    "error" => Severity::High,
                    "warning" => Severity::Medium,
                    "info" => Severity::Low,
                    _ => Severity::Info,
                };

                let mut finding = CodeFinding::new(
                    &r.path,
                    severity,
                    FindingType::Sast,
                    &r.extra.message,
                    "semgrep",
                )
                .with_line(r.start.line);

                if let Some(ref lines) = r.extra.lines {
                    finding = finding.with_snippet(lines);
                }

                if let Some(ref metadata) = r.extra.metadata {
                    if let Some(ref cwes) = metadata.cwe {
                        if let Some(cwe) = cwes.first() {
                            finding = finding.with_cwe(cwe);
                        }
                    }
                }

                finding
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_semgrep_output() {
        let json = r#"{
            "results": [{
                "check_id": "python.lang.security.audit.dangerous-subprocess-use",
                "path": "src/main.py",
                "start": {"line": 10, "col": 1},
                "end": {"line": 10, "col": 50},
                "extra": {
                    "message": "Detected subprocess call with shell=True",
                    "severity": "ERROR",
                    "lines": "subprocess.call(cmd, shell=True)"
                }
            }],
            "errors": []
        }"#;

        let output = SemgrepOutput::parse(json).unwrap();
        assert_eq!(output.results.len(), 1);

        let findings = output.to_code_findings();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }
}
```

**Step 3: Implement Grype parser**

Create `feroxmute-core/src/tools/sast/grype.rs`:

```rust
use serde::Deserialize;
use crate::state::models::{CodeFinding, FindingType, Severity};
use super::SastToolOutput;

#[derive(Debug, Deserialize)]
pub struct GrypeOutput {
    pub matches: Vec<GrypeMatch>,
}

#[derive(Debug, Deserialize)]
pub struct GrypeMatch {
    pub vulnerability: GrypeVulnerability,
    pub artifact: GrypeArtifact,
}

#[derive(Debug, Deserialize)]
pub struct GrypeVulnerability {
    pub id: String,
    pub severity: String,
    pub description: Option<String>,
    #[serde(rename = "fix")]
    pub fix_info: Option<GrypeFix>,
}

#[derive(Debug, Deserialize)]
pub struct GrypeFix {
    pub versions: Vec<String>,
    pub state: String,
}

#[derive(Debug, Deserialize)]
pub struct GrypeArtifact {
    pub name: String,
    pub version: String,
    #[serde(rename = "type")]
    pub artifact_type: String,
    pub locations: Option<Vec<GrypeLocation>>,
}

#[derive(Debug, Deserialize)]
pub struct GrypeLocation {
    pub path: String,
}

#[derive(Debug, Clone)]
pub struct GrypeFinding {
    pub cve: String,
    pub severity: Severity,
    pub package: String,
    pub version: String,
    pub fixed_version: Option<String>,
    pub description: Option<String>,
    pub file_path: String,
}

impl GrypeOutput {
    pub fn parse(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

impl SastToolOutput for GrypeOutput {
    fn to_code_findings(&self) -> Vec<CodeFinding> {
        self.matches
            .iter()
            .map(|m| {
                let severity = match m.vulnerability.severity.to_lowercase().as_str() {
                    "critical" => Severity::Critical,
                    "high" => Severity::High,
                    "medium" => Severity::Medium,
                    "low" => Severity::Low,
                    _ => Severity::Info,
                };

                let file_path = m
                    .artifact
                    .locations
                    .as_ref()
                    .and_then(|l| l.first())
                    .map(|l| l.path.clone())
                    .unwrap_or_else(|| format!("{} ({})", m.artifact.name, m.artifact.artifact_type));

                let mut finding = CodeFinding::new(
                    &file_path,
                    severity,
                    FindingType::Dependency,
                    format!("{} in {}@{}", m.vulnerability.id, m.artifact.name, m.artifact.version),
                    "grype",
                )
                .with_cve(&m.vulnerability.id)
                .with_package(&m.artifact.name, &m.artifact.version);

                if let Some(ref desc) = m.vulnerability.description {
                    finding = finding.with_description(desc);
                }

                if let Some(ref fix) = m.vulnerability.fix_info {
                    if let Some(version) = fix.versions.first() {
                        finding = finding.with_fixed_version(version);
                    }
                }

                finding
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_grype_output() {
        let json = r#"{
            "matches": [{
                "vulnerability": {
                    "id": "CVE-2024-1234",
                    "severity": "Critical",
                    "description": "Remote code execution vulnerability",
                    "fix": {
                        "versions": ["4.17.21"],
                        "state": "fixed"
                    }
                },
                "artifact": {
                    "name": "lodash",
                    "version": "4.17.20",
                    "type": "npm",
                    "locations": [{"path": "package-lock.json"}]
                }
            }]
        }"#;

        let output = GrypeOutput::parse(json).unwrap();
        assert_eq!(output.matches.len(), 1);

        let findings = output.to_code_findings();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].package_name, Some("lodash".to_string()));
    }
}
```

**Step 4: Export from tools/mod.rs**

Add to `feroxmute-core/src/tools/mod.rs`:

```rust
pub mod sast;
```

**Step 5: Run tests and commit**

```bash
cargo test -p feroxmute-core sast
git add feroxmute-core/src/tools/sast/
git commit -m "feat(core): add SAST tool output parsers (semgrep, grype)"
```

---

### Task 7: Add ast-grep and gitleaks Parsers

**Files:**
- Create: `feroxmute-core/src/tools/sast/ast_grep.rs`
- Create: `feroxmute-core/src/tools/sast/gitleaks.rs`
- Modify: `feroxmute-core/src/tools/sast/mod.rs`

**Step 1: Implement ast-grep parser**

Create `feroxmute-core/src/tools/sast/ast_grep.rs`:

```rust
use serde::Deserialize;
use crate::state::models::{CodeFinding, FindingType, Severity};
use super::SastToolOutput;

#[derive(Debug, Deserialize)]
pub struct AstGrepOutput(pub Vec<AstGrepMatch>);

#[derive(Debug, Deserialize)]
pub struct AstGrepMatch {
    pub file: String,
    pub range: AstGrepRange,
    pub text: String,
    #[serde(rename = "ruleId")]
    pub rule_id: Option<String>,
    pub message: Option<String>,
    pub severity: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AstGrepRange {
    pub start: AstGrepPosition,
    pub end: AstGrepPosition,
}

#[derive(Debug, Deserialize)]
pub struct AstGrepPosition {
    pub line: u32,
    pub column: u32,
}

impl AstGrepOutput {
    pub fn parse(json: &str) -> Result<Self, serde_json::Error> {
        let matches: Vec<AstGrepMatch> = serde_json::from_str(json)?;
        Ok(Self(matches))
    }
}

impl SastToolOutput for AstGrepOutput {
    fn to_code_findings(&self) -> Vec<CodeFinding> {
        self.0
            .iter()
            .map(|m| {
                let severity = m
                    .severity
                    .as_ref()
                    .map(|s| match s.to_lowercase().as_str() {
                        "error" | "high" => Severity::High,
                        "warning" | "medium" => Severity::Medium,
                        "info" | "low" => Severity::Low,
                        _ => Severity::Medium,
                    })
                    .unwrap_or(Severity::Medium);

                let title = m
                    .message
                    .clone()
                    .or_else(|| m.rule_id.clone())
                    .unwrap_or_else(|| "Pattern match found".to_string());

                CodeFinding::new(&m.file, severity, FindingType::Sast, title, "ast-grep")
                    .with_line(m.range.start.line)
                    .with_snippet(&m.text)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ast_grep_output() {
        let json = r#"[{
            "file": "src/db.rs",
            "range": {
                "start": {"line": 42, "column": 5},
                "end": {"line": 42, "column": 60}
            },
            "text": "query = format!(\"SELECT * FROM users WHERE id = {}\", user_id)",
            "ruleId": "sql-injection",
            "message": "Potential SQL injection",
            "severity": "error"
        }]"#;

        let output = AstGrepOutput::parse(json).unwrap();
        assert_eq!(output.0.len(), 1);

        let findings = output.to_code_findings();
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].line_number, Some(42));
    }
}
```

**Step 2: Implement gitleaks parser**

Create `feroxmute-core/src/tools/sast/gitleaks.rs`:

```rust
use serde::Deserialize;
use crate::state::models::{CodeFinding, FindingType, Severity};
use super::SastToolOutput;

#[derive(Debug, Deserialize)]
pub struct GitleaksOutput(pub Vec<GitleaksFinding>);

#[derive(Debug, Deserialize)]
pub struct GitleaksFinding {
    #[serde(rename = "Description")]
    pub description: String,
    #[serde(rename = "File")]
    pub file: String,
    #[serde(rename = "StartLine")]
    pub start_line: u32,
    #[serde(rename = "EndLine")]
    pub end_line: u32,
    #[serde(rename = "Secret")]
    pub secret: String,
    #[serde(rename = "Match")]
    pub match_text: String,
    #[serde(rename = "RuleID")]
    pub rule_id: String,
}

impl GitleaksOutput {
    pub fn parse(json: &str) -> Result<Self, serde_json::Error> {
        let findings: Vec<GitleaksFinding> = serde_json::from_str(json)?;
        Ok(Self(findings))
    }
}

impl SastToolOutput for GitleaksOutput {
    fn to_code_findings(&self) -> Vec<CodeFinding> {
        self.0
            .iter()
            .map(|f| {
                // Secrets are always high severity
                let severity = Severity::High;

                // Redact the actual secret in the finding
                let redacted_secret = if f.secret.len() > 8 {
                    format!("{}...{}", &f.secret[..4], &f.secret[f.secret.len()-4..])
                } else {
                    "****".to_string()
                };

                CodeFinding::new(
                    &f.file,
                    severity,
                    FindingType::Secret,
                    format!("{}: {}", f.description, f.rule_id),
                    "gitleaks",
                )
                .with_line(f.start_line)
                .with_snippet(format!("Secret (redacted): {}", redacted_secret))
                .with_description(format!(
                    "Hardcoded secret detected. Rule: {}. Remove and rotate this credential.",
                    f.rule_id
                ))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_gitleaks_output() {
        let json = r#"[{
            "Description": "AWS Access Key",
            "File": "src/config.rs",
            "StartLine": 23,
            "EndLine": 23,
            "Secret": "AKIAIOSFODNN7EXAMPLE",
            "Match": "aws_access_key = \"AKIAIOSFODNN7EXAMPLE\"",
            "RuleID": "aws-access-key-id"
        }]"#;

        let output = GitleaksOutput::parse(json).unwrap();
        assert_eq!(output.0.len(), 1);

        let findings = output.to_code_findings();
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].finding_type, FindingType::Secret);
    }
}
```

**Step 3: Update mod.rs exports**

Update `feroxmute-core/src/tools/sast/mod.rs`:

```rust
mod ast_grep;
mod gitleaks;
mod grype;
mod semgrep;

pub use ast_grep::{AstGrepOutput, AstGrepMatch};
pub use gitleaks::{GitleaksOutput, GitleaksFinding};
pub use grype::{GrypeOutput, GrypeFinding};
pub use semgrep::{SemgrepOutput, SemgrepResult};

use crate::state::models::CodeFinding;

/// Trait for SAST tool output parsing
pub trait SastToolOutput {
    fn to_code_findings(&self) -> Vec<CodeFinding>;
}
```

**Step 4: Run tests and commit**

```bash
cargo test -p feroxmute-core sast
git add feroxmute-core/src/tools/sast/
git commit -m "feat(core): add ast-grep and gitleaks output parsers"
```

---

## Phase 5: SAST Agent Implementation

### Task 8: Create SAST Agent Skeleton

**Files:**
- Create: `feroxmute-core/src/agents/sast.rs`
- Modify: `feroxmute-core/src/agents/mod.rs`

**Step 1: Create SAST Agent structure**

Create `feroxmute-core/src/agents/sast.rs`:

```rust
use async_trait::async_trait;
use serde_json::json;
use std::path::PathBuf;

use crate::agents::prompts::Prompts;
use crate::agents::traits::{Agent, AgentContext, AgentStatus, AgentTask};
use crate::providers::traits::ToolDefinition;
use crate::state::models::{CodeFinding, FindingType, Severity};
use crate::tools::sast::{GrypeOutput, SemgrepOutput, AstGrepOutput, GitleaksOutput, SastToolOutput};
use crate::Result;

pub struct SastAgent {
    status: AgentStatus,
    thinking: Option<String>,
    prompts: Prompts,
    source_path: PathBuf,
    detected_languages: Vec<String>,
}

impl SastAgent {
    pub fn new(source_path: PathBuf) -> Self {
        Self {
            status: AgentStatus::Idle,
            thinking: None,
            prompts: Prompts::load(),
            source_path,
            detected_languages: Vec::new(),
        }
    }

    pub fn with_languages(mut self, languages: Vec<String>) -> Self {
        self.detected_languages = languages;
        self
    }

    async fn detect_languages(&mut self, ctx: &AgentContext<'_>) -> Result<()> {
        let path = self.source_path.to_string_lossy();

        // Check for various manifest files
        let checks = vec![
            ("package.json", "javascript"),
            ("Cargo.toml", "rust"),
            ("requirements.txt", "python"),
            ("pyproject.toml", "python"),
            ("go.mod", "go"),
            ("pom.xml", "java"),
            ("build.gradle", "java"),
            ("Gemfile", "ruby"),
            ("composer.json", "php"),
        ];

        for (file, lang) in checks {
            let result = ctx
                .executor
                .execute_raw(
                    vec!["test", "-f", &format!("{}/{}", path, file)],
                    None,
                    "sast",
                    ctx.conn,
                )
                .await;

            if let Ok(exec) = result {
                if exec.exit_code == Some(0) && !self.detected_languages.contains(&lang.to_string()) {
                    self.detected_languages.push(lang.to_string());
                }
            }
        }

        Ok(())
    }

    async fn run_dependency_scan(&self, ctx: &AgentContext<'_>) -> Result<Vec<CodeFinding>> {
        let path = self.source_path.to_string_lossy();
        let mut findings = Vec::new();

        // Run grype for dependency scanning
        let result = ctx
            .executor
            .execute_raw(
                vec!["grype", &path.to_string(), "-o", "json"],
                None,
                "sast",
                ctx.conn,
            )
            .await?;

        if let Some(output) = result.output {
            if let Ok(grype_output) = GrypeOutput::parse(&output) {
                findings.extend(grype_output.to_code_findings());
            }
        }

        Ok(findings)
    }

    async fn run_code_scan(&self, ctx: &AgentContext<'_>) -> Result<Vec<CodeFinding>> {
        let path = self.source_path.to_string_lossy();
        let mut findings = Vec::new();

        // Run semgrep
        let result = ctx
            .executor
            .execute_raw(
                vec!["semgrep", "scan", "--config", "auto", "--json", &path.to_string()],
                None,
                "sast",
                ctx.conn,
            )
            .await?;

        if let Some(output) = result.output {
            if let Ok(semgrep_output) = SemgrepOutput::parse(&output) {
                findings.extend(semgrep_output.to_code_findings());
            }
        }

        // Run ast-grep if available
        let result = ctx
            .executor
            .execute_raw(
                vec!["ast-grep", "scan", "--json", &path.to_string()],
                None,
                "sast",
                ctx.conn,
            )
            .await?;

        if let Some(output) = result.output {
            if let Ok(ast_output) = AstGrepOutput::parse(&output) {
                findings.extend(ast_output.to_code_findings());
            }
        }

        Ok(findings)
    }

    async fn run_secret_scan(&self, ctx: &AgentContext<'_>) -> Result<Vec<CodeFinding>> {
        let path = self.source_path.to_string_lossy();

        let result = ctx
            .executor
            .execute_raw(
                vec!["gitleaks", "detect", "--source", &path.to_string(), "--report-format", "json", "--report-path", "/dev/stdout"],
                None,
                "sast",
                ctx.conn,
            )
            .await?;

        if let Some(output) = result.output {
            if let Ok(gitleaks_output) = GitleaksOutput::parse(&output) {
                return Ok(gitleaks_output.to_code_findings());
            }
        }

        Ok(Vec::new())
    }
}

#[async_trait]
impl Agent for SastAgent {
    fn name(&self) -> &str {
        "sast"
    }

    fn status(&self) -> AgentStatus {
        self.status.clone()
    }

    fn set_status(&mut self, status: AgentStatus) {
        self.status = status;
    }

    fn system_prompt(&self) -> &str {
        self.prompts.get("sast").unwrap_or("You are a static analysis security expert.")
    }

    fn thinking(&self) -> Option<&str> {
        self.thinking.as_deref()
    }

    fn tools(&self) -> Vec<ToolDefinition> {
        vec![
            ToolDefinition {
                name: "run_semgrep".to_string(),
                description: "Run semgrep static analysis on the source code".to_string(),
                parameters: json!({
                    "type": "object",
                    "properties": {
                        "config": {
                            "type": "string",
                            "description": "Semgrep config (auto, p/security-audit, etc.)"
                        }
                    }
                }),
            },
            ToolDefinition {
                name: "run_grype".to_string(),
                description: "Scan dependencies for known vulnerabilities".to_string(),
                parameters: json!({
                    "type": "object",
                    "properties": {}
                }),
            },
            ToolDefinition {
                name: "run_gitleaks".to_string(),
                description: "Scan for hardcoded secrets and credentials".to_string(),
                parameters: json!({
                    "type": "object",
                    "properties": {}
                }),
            },
            ToolDefinition {
                name: "run_ast_grep".to_string(),
                description: "Run ast-grep for semantic code pattern matching".to_string(),
                parameters: json!({
                    "type": "object",
                    "properties": {
                        "pattern": {
                            "type": "string",
                            "description": "The ast-grep pattern to search for"
                        }
                    }
                }),
            },
            ToolDefinition {
                name: "read_file".to_string(),
                description: "Read a source file for manual analysis".to_string(),
                parameters: json!({
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Path to file relative to source root"
                        }
                    },
                    "required": ["path"]
                }),
            },
        ]
    }

    async fn execute(&mut self, task: &AgentTask, ctx: &AgentContext<'_>) -> Result<String> {
        self.status = AgentStatus::Running;
        self.thinking = Some("Detecting project languages and dependencies...".to_string());

        // Detect languages
        self.detect_languages(ctx).await?;

        let mut all_findings: Vec<CodeFinding> = Vec::new();

        // Run dependency scan
        self.thinking = Some("Running dependency vulnerability scan (grype)...".to_string());
        let dep_findings = self.run_dependency_scan(ctx).await?;
        all_findings.extend(dep_findings);

        // Run code scan
        self.thinking = Some("Running static code analysis (semgrep, ast-grep)...".to_string());
        let code_findings = self.run_code_scan(ctx).await?;
        all_findings.extend(code_findings);

        // Run secret scan
        self.thinking = Some("Scanning for hardcoded secrets (gitleaks)...".to_string());
        let secret_findings = self.run_secret_scan(ctx).await?;
        all_findings.extend(secret_findings);

        // Store all findings in database
        for finding in &all_findings {
            finding.insert(ctx.conn)?;
        }

        // Generate summary
        let critical = all_findings.iter().filter(|f| f.severity == Severity::Critical).count();
        let high = all_findings.iter().filter(|f| f.severity == Severity::High).count();
        let medium = all_findings.iter().filter(|f| f.severity == Severity::Medium).count();
        let deps = all_findings.iter().filter(|f| f.finding_type == FindingType::Dependency).count();
        let secrets = all_findings.iter().filter(|f| f.finding_type == FindingType::Secret).count();

        self.status = AgentStatus::Completed;
        self.thinking = None;

        Ok(format!(
            "Static analysis complete. Found {} findings:\n\
             - Critical: {}\n\
             - High: {}\n\
             - Medium: {}\n\
             - Dependency issues: {}\n\
             - Hardcoded secrets: {}",
            all_findings.len(),
            critical,
            high,
            medium,
            deps,
            secrets
        ))
    }
}
```

**Step 2: Export from agents/mod.rs**

Add to `feroxmute-core/src/agents/mod.rs`:

```rust
mod sast;
pub use sast::SastAgent;
```

**Step 3: Add SAST prompt to prompts.toml**

Add to `feroxmute-core/prompts.toml`:

```toml
[sast]
system = """You are a static analysis security expert. Your job is to analyze source code for security vulnerabilities.

You have access to these tools:
- semgrep: Static analysis with community rules
- grype: Dependency vulnerability scanning
- gitleaks: Secret detection
- ast-grep: Semantic code pattern matching

For each scan:
1. Run dependency scan first to find vulnerable packages
2. Run code analysis to find SAST issues (injection, XSS, etc.)
3. Run secret scan to find hardcoded credentials
4. Review findings and filter obvious false positives
5. Extract useful information for web testing (routes, parameters, auth patterns)

Always report:
- Severity (critical/high/medium/low)
- File path and line number
- Code snippet showing the issue
- CWE ID if applicable
- CVE ID for dependency issues
- Remediation guidance
"""
```

**Step 4: Build and test**

Run: `cargo build -p feroxmute-core`
Expected: SUCCESS

**Step 5: Commit**

```bash
git add feroxmute-core/src/agents/ feroxmute-core/prompts.toml
git commit -m "feat(core): add SAST agent for static analysis"
```

---

## Phase 6: Relationship Detection

### Task 9: Implement Relationship Heuristics

**Files:**
- Create: `feroxmute-core/src/targets/detection.rs`
- Modify: `feroxmute-core/src/targets/mod.rs`

**Step 1: Create detection module with tests**

Create `feroxmute-core/src/targets/detection.rs`:

```rust
use std::path::Path;
use std::fs;

use super::{Target, TargetCollection};

#[derive(Debug, Clone)]
pub struct RelationshipHint {
    pub source_raw: String,
    pub web_raw: String,
    pub confidence: f32,
    pub reason: String,
}

pub struct RelationshipDetector;

impl RelationshipDetector {
    /// Detect relationships between targets using heuristics
    pub fn detect(collection: &TargetCollection) -> Vec<RelationshipHint> {
        let mut hints = Vec::new();

        for source in &collection.standalone_sources {
            for group in &collection.groups {
                let web = &group.web_target;

                if let Some(hint) = Self::check_relationship(source, web) {
                    hints.push(hint);
                }
            }
        }

        hints
    }

    fn check_relationship(source: &Target, web: &Target) -> Option<RelationshipHint> {
        let source_path = match &source.target_type {
            super::TargetType::Directory { path } => path.clone(),
            super::TargetType::Repository { local_path: Some(path), .. } => path.clone(),
            _ => return None,
        };

        let web_url = match &web.target_type {
            super::TargetType::Web { url } => url.clone(),
            _ => return None,
        };

        // Extract domain from URL
        let domain = Self::extract_domain(&web_url)?;

        let mut score = 0.0;
        let mut reasons = Vec::new();

        // Check config files for domain references
        if Self::check_config_files(&source_path, &domain) {
            score += 0.4;
            reasons.push("domain found in config files");
        }

        // Check for URL in .env files
        if Self::check_env_files(&source_path, &domain) {
            score += 0.3;
            reasons.push("domain found in .env file");
        }

        // Check package.json homepage
        if Self::check_package_json(&source_path, &domain) {
            score += 0.3;
            reasons.push("domain matches package.json homepage");
        }

        // Check docker-compose for matching services
        if Self::check_docker_compose(&source_path, &domain) {
            score += 0.2;
            reasons.push("domain found in docker-compose");
        }

        if score >= 0.3 {
            Some(RelationshipHint {
                source_raw: source.raw.clone(),
                web_raw: web.raw.clone(),
                confidence: score.min(1.0),
                reason: reasons.join(", "),
            })
        } else {
            None
        }
    }

    fn extract_domain(url: &str) -> Option<String> {
        let url = url.trim_start_matches("https://").trim_start_matches("http://");
        let domain = url.split('/').next()?;
        Some(domain.to_lowercase())
    }

    fn check_config_files(source_path: &Path, domain: &str) -> bool {
        let config_patterns = [
            "config.toml",
            "config.yaml",
            "config.yml",
            "config.json",
            "settings.py",
            "config/default.toml",
            "config/production.toml",
        ];

        for pattern in config_patterns {
            let path = source_path.join(pattern);
            if path.exists() {
                if let Ok(content) = fs::read_to_string(&path) {
                    if content.to_lowercase().contains(domain) {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn check_env_files(source_path: &Path, domain: &str) -> bool {
        let env_files = [".env", ".env.local", ".env.production", ".env.example"];

        for file in env_files {
            let path = source_path.join(file);
            if path.exists() {
                if let Ok(content) = fs::read_to_string(&path) {
                    if content.to_lowercase().contains(domain) {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn check_package_json(source_path: &Path, domain: &str) -> bool {
        let path = source_path.join("package.json");
        if path.exists() {
            if let Ok(content) = fs::read_to_string(&path) {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
                    if let Some(homepage) = json.get("homepage").and_then(|h| h.as_str()) {
                        return homepage.to_lowercase().contains(domain);
                    }
                }
            }
        }
        false
    }

    fn check_docker_compose(source_path: &Path, domain: &str) -> bool {
        let compose_files = ["docker-compose.yml", "docker-compose.yaml", "compose.yml"];

        for file in compose_files {
            let path = source_path.join(file);
            if path.exists() {
                if let Ok(content) = fs::read_to_string(&path) {
                    if content.to_lowercase().contains(domain) {
                        return true;
                    }
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_domain() {
        assert_eq!(
            RelationshipDetector::extract_domain("https://example.com/path"),
            Some("example.com".to_string())
        );
        assert_eq!(
            RelationshipDetector::extract_domain("http://api.example.com"),
            Some("api.example.com".to_string())
        );
    }

    #[test]
    fn test_no_relationship_without_evidence() {
        let mut collection = TargetCollection::new();
        collection.add_target(Target::parse("https://example.com").unwrap());
        // Can't add a directory without it existing, so test with empty

        let hints = RelationshipDetector::detect(&collection);
        assert!(hints.is_empty());
    }
}
```

**Step 2: Export from mod.rs**

Update `feroxmute-core/src/targets/mod.rs`:

```rust
mod collection;
mod detection;
mod types;

pub use collection::{TargetCollection, TargetGroup};
pub use detection::{RelationshipDetector, RelationshipHint};
pub use types::{Target, TargetParseError, TargetType};
```

**Step 3: Commit**

```bash
cargo test -p feroxmute-core detection
git add feroxmute-core/src/targets/
git commit -m "feat(core): add relationship detection heuristics"
```

---

## Phase 7: TUI Updates

### Task 10: Add Severity Colors

**Files:**
- Create: `feroxmute-cli/src/tui/colors.rs`
- Modify: `feroxmute-cli/src/tui/mod.rs`

**Step 1: Create colors module**

Create `feroxmute-cli/src/tui/colors.rs`:

```rust
use ratatui::style::{Color, Modifier, Style};
use feroxmute_core::state::models::Severity;

pub fn severity_color(severity: &Severity) -> Color {
    match severity {
        Severity::Critical => Color::Red,
        Severity::High => Color::LightRed,
        Severity::Medium => Color::Yellow,
        Severity::Low => Color::Blue,
        Severity::Info => Color::DarkGray,
    }
}

pub fn severity_style(severity: &Severity) -> Style {
    let color = severity_color(severity);
    let style = Style::default().fg(color);

    if matches!(severity, Severity::Critical) {
        style.add_modifier(Modifier::BOLD)
    } else {
        style
    }
}

pub fn status_color(status: &str) -> Color {
    match status.to_lowercase().as_str() {
        "running" => Color::Green,
        "queued" => Color::Yellow,
        "idle" => Color::DarkGray,
        "completed" => Color::Cyan,
        "failed" | "error" => Color::Red,
        _ => Color::White,
    }
}

pub fn status_style(status: &str) -> Style {
    Style::default().fg(status_color(status))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_colors() {
        assert_eq!(severity_color(&Severity::Critical), Color::Red);
        assert_eq!(severity_color(&Severity::High), Color::LightRed);
    }

    #[test]
    fn test_status_colors() {
        assert_eq!(status_color("running"), Color::Green);
        assert_eq!(status_color("RUNNING"), Color::Green); // case insensitive
    }
}
```

**Step 2: Export from tui/mod.rs**

Add to `feroxmute-cli/src/tui/mod.rs`:

```rust
pub mod colors;
```

**Step 3: Commit**

```bash
cargo build -p feroxmute-cli
git add feroxmute-cli/src/tui/colors.rs feroxmute-cli/src/tui/mod.rs
git commit -m "feat(cli): add severity and status color helpers"
```

---

### Task 11: Add SAST Widget

**Files:**
- Create: `feroxmute-cli/src/tui/widgets/sast.rs`
- Modify: `feroxmute-cli/src/tui/widgets/mod.rs`

**Step 1: Create SAST widget**

Create `feroxmute-cli/src/tui/widgets/sast.rs`:

```rust
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Row, Table},
    Frame,
};

use crate::tui::app::App;
use crate::tui::colors::{severity_style, status_style};

pub fn render(frame: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // Header
            Constraint::Length(6),  // Summary
            Constraint::Min(10),    // Findings list
        ])
        .split(area);

    render_header(frame, app, chunks[0]);
    render_summary(frame, app, chunks[1]);
    render_findings(frame, app, chunks[2]);
}

fn render_header(frame: &mut Frame, app: &App, area: Rect) {
    let status = app.agent_statuses.sast.as_deref().unwrap_or("idle");

    let header = Paragraph::new(vec![
        Line::from(vec![
            Span::raw("Status: "),
            Span::styled(status, status_style(status)),
            Span::raw("              Source: "),
            Span::styled(&app.source_path.as_deref().unwrap_or("-"), Style::default().fg(Color::Cyan)),
        ]),
        Line::from(vec![
            Span::raw("Languages: "),
            Span::styled(
                app.detected_languages.join(", "),
                Style::default().fg(Color::Yellow),
            ),
        ]),
    ])
    .block(Block::default().borders(Borders::ALL).title(" SAST Agent "));

    frame.render_widget(header, area);
}

fn render_summary(frame: &mut Frame, app: &App, area: Rect) {
    let code_counts = &app.code_finding_counts;

    let summary_text = vec![
        Line::from(vec![
            Span::raw("Findings by Type"),
        ]),
        Line::from(vec![
            Span::raw("Dependencies: "),
            Span::styled(
                format!("{}", code_counts.dependencies),
                Style::default().fg(Color::Cyan),
            ),
        ]),
        Line::from(vec![
            Span::raw("Code issues:  "),
            Span::styled(
                format!("{}", code_counts.sast),
                Style::default().fg(Color::Yellow),
            ),
        ]),
        Line::from(vec![
            Span::raw("Secrets:      "),
            Span::styled(
                format!("{}", code_counts.secrets),
                Style::default().fg(Color::LightRed),
            ),
        ]),
    ];

    let summary = Paragraph::new(summary_text)
        .block(Block::default().borders(Borders::ALL).title(" Summary "));

    frame.render_widget(summary, area);
}

fn render_findings(frame: &mut Frame, app: &App, area: Rect) {
    let items: Vec<ListItem> = app
        .code_findings
        .iter()
        .take(20)
        .map(|f| {
            let severity_span = Span::styled(
                format!("[{:?}]", f.severity),
                severity_style(&f.severity),
            );

            let location = if let Some(line) = f.line_number {
                format!("{}:{}", f.file_path, line)
            } else {
                f.file_path.clone()
            };

            ListItem::new(Line::from(vec![
                severity_span,
                Span::raw(" "),
                Span::styled(&f.title, Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(" "),
                Span::styled(location, Style::default().fg(Color::DarkGray)),
            ]))
        })
        .collect();

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(" Recent Findings "));

    frame.render_widget(list, area);
}
```

**Step 2: Update App struct for SAST data**

Add these fields to `App` in `feroxmute-cli/src/tui/app.rs`:

```rust
pub source_path: Option<String>,
pub detected_languages: Vec<String>,
pub code_findings: Vec<CodeFinding>,
pub code_finding_counts: CodeFindingCounts,

// Add struct
#[derive(Default, Clone)]
pub struct CodeFindingCounts {
    pub dependencies: u32,
    pub sast: u32,
    pub secrets: u32,
}
```

**Step 3: Update widgets/mod.rs**

Add to `feroxmute-cli/src/tui/widgets/mod.rs`:

```rust
pub mod sast;
```

**Step 4: Add SAST to View enum**

Update View enum in `app.rs`:

```rust
pub enum View {
    Dashboard,
    AgentDetail(AgentView),
    Sast,  // Add this
    Logs,
    Help,
}

pub enum AgentView {
    Orchestrator,
    Recon,
    Scanner,
    Exploit,
    Report,
    Sast,  // Add this
}
```

**Step 5: Commit**

```bash
cargo build -p feroxmute-cli
git add feroxmute-cli/src/tui/
git commit -m "feat(cli): add SAST agent widget with severity colors"
```

---

## Phase 8: Dockerfile Updates

### Task 12: Add SAST Tools to Dockerfile

**Files:**
- Modify: `docker/Dockerfile`

**Step 1: Read current Dockerfile**

Review current content.

**Step 2: Add SAST tools**

Add these lines after the ProjectDiscovery tools section:

```dockerfile
# SAST tools
RUN cargo install ast-grep --locked

# Python SAST tools via uv
RUN uv tool install semgrep bandit pip-audit

# Go-based tools
RUN go install github.com/gitleaks/gitleaks/v8@latest
RUN go install golang.org/x/vuln/cmd/govulncheck@latest

# Grype for dependency scanning
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Trivy for container/dependency scanning
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
```

**Step 3: Commit**

```bash
git add docker/Dockerfile
git commit -m "feat(docker): add SAST tools (semgrep, ast-grep, grype, gitleaks)"
```

---

## Phase 9: Integration

### Task 13: Update Orchestrator for SAST Coordination

**Files:**
- Modify: `feroxmute-core/src/agents/orchestrator.rs`

**Step 1: Read current orchestrator**

Review current implementation.

**Step 2: Add SAST phase**

Add a new phase and SAST agent integration:

```rust
// Add to EngagementPhase enum if not present
pub enum EngagementPhase {
    Planning,
    StaticAnalysis,  // Add this
    Reconnaissance,
    Scanning,
    Exploitation,
    Reporting,
    Complete,
}

// In execute method, add SAST phase handling:
if self.has_source_target && matches!(self.phase, EngagementPhase::Planning) {
    self.phase = EngagementPhase::StaticAnalysis;
    // Delegate to SAST agent
    let sast_task = AgentTask::new("Perform static analysis on source code");
    self.sast_agent.execute(&sast_task, ctx).await?;
    self.phase = EngagementPhase::Reconnaissance;
}
```

**Step 3: Commit**

```bash
git add feroxmute-core/src/agents/orchestrator.rs
git commit -m "feat(core): integrate SAST agent into orchestrator flow"
```

---

### Task 14: Wire Up CLI Multi-Target Handling

**Files:**
- Modify: `feroxmute-cli/src/main.rs`

**Step 1: Add target parsing to main**

```rust
use feroxmute_core::targets::{TargetCollection, RelationshipDetector};

// In main(), after parsing args:
let targets = TargetCollection::from_strings(&args.target)?;

// If --source provided, explicitly link it
if let Some(source_path) = &args.source {
    let source_str = source_path.to_string_lossy().to_string();
    if let Some(web) = targets.web_targets().first() {
        targets.link_source_to_web(&source_str, &web.raw);
    }
}

// If not --separate, run relationship detection
if !args.separate && !targets.standalone_sources.is_empty() {
    let hints = RelationshipDetector::detect(&targets);
    for hint in hints {
        if hint.confidence >= 0.5 {
            // Auto-link high confidence
            targets.link_source_to_web(&hint.source_raw, &hint.web_raw);
        } else {
            // Ask user for medium confidence
            println!("Detected potential relationship:");
            println!("  {} may be source for {}", hint.source_raw, hint.web_raw);
            println!("  Reason: {}", hint.reason);
            print!("Link them? [Y/n]: ");
            // Handle user input...
        }
    }
}
```

**Step 2: Commit**

```bash
git add feroxmute-cli/src/main.rs
git commit -m "feat(cli): wire up multi-target parsing and relationship detection"
```

---

## Summary

This plan implements multi-target support with SAST integration in 14 tasks across 9 phases:

1. **Phase 1**: Target types and parsing (Tasks 1-2)
2. **Phase 2**: CLI argument updates (Task 3)
3. **Phase 3**: Database schema for code findings (Tasks 4-5)
4. **Phase 4**: SAST tool wrappers (Tasks 6-7)
5. **Phase 5**: SAST Agent implementation (Task 8)
6. **Phase 6**: Relationship detection (Task 9)
7. **Phase 7**: TUI updates (Tasks 10-11)
8. **Phase 8**: Dockerfile updates (Task 12)
9. **Phase 9**: Integration (Tasks 13-14)

Each task follows TDD: write failing test → verify failure → implement → verify pass → commit.

**Estimated commits**: 14 atomic commits
**Key dependencies**: rusqlite, serde_json, clap, ratatui
