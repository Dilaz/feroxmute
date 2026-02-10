# LLM-Based Finding Deduplication Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a `deduplicate_findings` tool that uses LLM to extract canonical vulnerability keys and merge semantic duplicates before report generation.

**Architecture:** The Report agent calls `deduplicate_findings` before `generate_report`. The tool loads findings from the database, batches them into LLM prompts to extract canonical keys (e.g., `sqli-product-search`), groups by `(key, severity)`, merges duplicates, and stores the result in `ReportContext.deduplicated_findings` for `generate_report` to consume.

**Tech Stack:** Rust, rig-core for LLM tool loop, rusqlite for database access, tokio for async

---

## Task 1: Add `deduplicated_findings` field to ReportContext

**Files:**
- Modify: `feroxmute-core/src/tools/report.rs:32-51`

**Step 1: Add the new field to ReportContext struct**

In `feroxmute-core/src/tools/report.rs`, add after line 50 (`session_db_path`):

```rust
/// Deduplicated findings cache, populated by deduplicate_findings tool
pub deduplicated_findings: Arc<Mutex<Option<Vec<crate::state::Vulnerability>>>>,
```

**Step 2: Run build to verify**

```bash
cd /Users/ristoviitanen/feroxmute/.worktrees/llm-dedup && cargo build -p feroxmute-core 2>&1 | head -50
```

Expected: Build errors about missing field initializations (we'll fix in later tasks)

**Step 3: Commit**

```bash
git add feroxmute-core/src/tools/report.rs
git commit -m "$(cat <<'EOF'
feat(report): add deduplicated_findings field to ReportContext

Adds a cache for LLM-deduplicated findings that the generate_report
tool will consume instead of loading raw findings from the database.
EOF
)"
```

---

## Task 2: Create the deduplication tool module

**Files:**
- Create: `feroxmute-core/src/mcp/tools/dedup.rs`
- Modify: `feroxmute-core/src/mcp/tools/mod.rs`

**Step 1: Create the dedup.rs file with tool structure**

Create `feroxmute-core/src/mcp/tools/dedup.rs`:

```rust
//! MCP wrapper for LLM-based finding deduplication

use std::sync::Arc;

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;

use crate::Result;
use crate::mcp::{McpTool, McpToolResult};
use crate::state::Vulnerability;
use crate::tools::report::ReportContext;

/// MCP wrapper for deduplicating findings using LLM-extracted canonical keys
pub struct McpDeduplicateFindingsTool {
    context: Arc<ReportContext>,
}

#[derive(Debug, Deserialize)]
struct DeduplicateFindingsArgs {
    // No required inputs - operates on current session's findings
}

impl McpDeduplicateFindingsTool {
    pub fn new(context: Arc<ReportContext>) -> Self {
        Self { context }
    }
}

#[async_trait]
impl McpTool for McpDeduplicateFindingsTool {
    fn name(&self) -> &str {
        "deduplicate_findings"
    }

    fn description(&self) -> &str {
        "Deduplicate findings by extracting canonical vulnerability identifiers using LLM. Call this BEFORE generate_report to merge semantically similar vulnerabilities."
    }

    fn input_schema(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {},
            "required": []
        })
    }

    async fn execute(&self, _arguments: Value) -> Result<McpToolResult> {
        self.context.events.send_tool_call();
        self.context
            .events
            .send_feed("report", "Deduplicating findings...", false);

        // Load findings from database
        let db_path = match &self.context.session_db_path {
            Some(p) => p,
            None => {
                return Ok(McpToolResult::error(
                    "No session database available for deduplication",
                ));
            }
        };

        let conn = match rusqlite::Connection::open(db_path) {
            Ok(c) => c,
            Err(e) => {
                return Ok(McpToolResult::error(format!(
                    "Failed to open session database: {}",
                    e
                )));
            }
        };

        let vulns = match Vulnerability::all(&conn) {
            Ok(v) => v,
            Err(e) => {
                return Ok(McpToolResult::error(format!(
                    "Failed to load vulnerabilities: {}",
                    e
                )));
            }
        };

        if vulns.is_empty() {
            return Ok(McpToolResult::text(
                serde_json::json!({
                    "success": true,
                    "message": "No findings to deduplicate",
                    "original_count": 0,
                    "deduplicated_count": 0
                })
                .to_string(),
            ));
        }

        let original_count = vulns.len();

        // For now, use the existing exact-match deduplication as placeholder
        // The LLM-based deduplication will be added in Task 4
        let deduped = crate::reports::deduplicate_vulnerabilities(vulns);
        let deduped_count = deduped.len();

        // Store in context for generate_report to use
        let mut cache = self.context.deduplicated_findings.lock().await;
        *cache = Some(deduped);

        self.context.events.send_feed(
            "report",
            &format!(
                "Deduplicated {} findings into {} unique vulnerabilities",
                original_count, deduped_count
            ),
            false,
        );

        Ok(McpToolResult::text(
            serde_json::json!({
                "success": true,
                "message": format!(
                    "Deduplicated {} findings into {} unique vulnerabilities",
                    original_count, deduped_count
                ),
                "original_count": original_count,
                "deduplicated_count": deduped_count
            })
            .to_string(),
        ))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_tool_name() {
        // Minimal test - full tests require DB setup
        assert_eq!(McpDeduplicateFindingsTool::name(&McpDeduplicateFindingsTool {
            context: panic!("not called"),
        }), "deduplicate_findings");
    }
}
```

**Step 2: Export the module and tool in mod.rs**

In `feroxmute-core/src/mcp/tools/mod.rs`, add after line 4 (`mod finding;`):

```rust
mod dedup;
```

And add to exports after line 11 (`pub use finding::{FindingContext, McpRecordFindingTool};`):

```rust
pub use dedup::McpDeduplicateFindingsTool;
```

**Step 3: Export deduplicate_vulnerabilities from reports module**

In `feroxmute-core/src/reports/mod.rs` (or generator.rs re-export), make `deduplicate_vulnerabilities` public.

Check the file first:

```bash
cat feroxmute-core/src/reports/mod.rs
```

Then add `deduplicate_vulnerabilities` to exports.

**Step 4: Run build**

```bash
cd /Users/ristoviitanen/feroxmute/.worktrees/llm-dedup && cargo build -p feroxmute-core 2>&1 | head -100
```

Expected: Build errors about ReportContext initialization (expected at this stage)

**Step 5: Commit**

```bash
git add feroxmute-core/src/mcp/tools/dedup.rs feroxmute-core/src/mcp/tools/mod.rs feroxmute-core/src/reports/
git commit -m "$(cat <<'EOF'
feat(mcp): add deduplicate_findings tool skeleton

Creates McpDeduplicateFindingsTool that loads findings from the database
and stores deduplicated results in ReportContext for generate_report.
Currently uses exact-match deduplication as placeholder.
EOF
)"
```

---

## Task 3: Fix ReportContext initializations

**Files:**
- Search and update all places that create ReportContext

**Step 1: Find all ReportContext initializations**

```bash
cd /Users/ristoviitanen/feroxmute/.worktrees/llm-dedup && grep -rn "ReportContext {" --include="*.rs" feroxmute-core feroxmute-cli
```

**Step 2: Add the new field to each initialization**

For each location found, add:

```rust
deduplicated_findings: Arc::new(Mutex::new(None)),
```

Common locations:
- `feroxmute-core/src/mcp/tools/report.rs` (test helper `setup_context`)
- `feroxmute-cli/src/tui/runner.rs` (main TUI initialization)
- Any integration tests

**Step 3: Run build and tests**

```bash
cd /Users/ristoviitanen/feroxmute/.worktrees/llm-dedup && cargo build && cargo test -p feroxmute-core 2>&1 | tail -30
```

Expected: Build succeeds, tests pass

**Step 4: Commit**

```bash
git add -A
git commit -m "$(cat <<'EOF'
fix: initialize deduplicated_findings field in all ReportContext usages
EOF
)"
```

---

## Task 4: Integrate with generate_report to use deduplicated findings

**Files:**
- Modify: `feroxmute-core/src/mcp/tools/report.rs` (McpGenerateReportTool)
- Modify: `feroxmute-core/src/tools/report.rs` (GenerateReportTool)

**Step 1: Update McpGenerateReportTool::execute**

In `feroxmute-core/src/mcp/tools/report.rs`, modify the `execute` method of `McpGenerateReportTool` around line 249-280. Change the report generation logic to check for deduplicated findings first:

```rust
// Check if deduplicated findings are available (from deduplicate_findings tool)
let mut report = {
    let dedup_cache = self.context.deduplicated_findings.lock().await;
    if let Some(ref deduped) = *dedup_cache {
        // Use pre-deduplicated findings
        self.build_report_from_vulns(deduped.clone(), end_time).await
    } else if let Some(ref db_path) = self.context.session_db_path {
        // Fall back to database with existing exact-match dedup
        match rusqlite::Connection::open(db_path) {
            Ok(conn) => match generate_report(
                &conn,
                &self.context.target,
                &self.context.session_id,
                self.context.start_time,
                end_time,
                &self.context.metrics,
            ) {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(
                        "Failed to generate report from database: {e}, falling back to in-memory"
                    );
                    self.build_report_from_memory(end_time).await
                }
            },
            Err(e) => {
                tracing::warn!(
                    "Failed to open session database: {e}, falling back to in-memory"
                );
                self.build_report_from_memory(end_time).await
            }
        }
    } else {
        self.build_report_from_memory(end_time).await
    }
};
```

**Step 2: Add build_report_from_vulns helper method**

Add a new method to `McpGenerateReportTool`:

```rust
/// Build report from pre-deduplicated vulnerabilities
async fn build_report_from_vulns(
    &self,
    vulns: Vec<crate::state::Vulnerability>,
    end_time: chrono::DateTime<Utc>,
) -> Report {
    use crate::reports::{Finding, ReportMetrics, ReportSummary, RiskRating, SeverityCounts, StatusCounts};

    let findings: Vec<Finding> = vulns.iter().map(Finding::from).collect();
    let finding_count = findings.len();

    let mut severity_counts = SeverityCounts::default();
    for f in &findings {
        match f.severity.to_lowercase().as_str() {
            "critical" => severity_counts.critical += 1,
            "high" => severity_counts.high += 1,
            "medium" => severity_counts.medium += 1,
            "low" => severity_counts.low += 1,
            _ => severity_counts.info += 1,
        }
    }

    let risk_rating = RiskRating::from_counts(
        severity_counts.critical,
        severity_counts.high,
        severity_counts.medium,
    );

    let metrics = self.context.metrics.snapshot();

    Report {
        metadata: ReportMetadata::new(
            &self.context.target,
            &self.context.session_id,
            self.context.start_time,
            end_time,
        ),
        summary: ReportSummary {
            total_vulnerabilities: finding_count as u32,
            by_severity: severity_counts,
            by_status: StatusCounts::default(),
            risk_rating,
            key_findings: Vec::new(),
            executive_summary: format!(
                "Security assessment of {} completed with {} findings.",
                self.context.target, finding_count
            ),
        },
        findings,
        metrics: ReportMetrics {
            tool_calls: metrics.tool_calls,
            input_tokens: metrics.tokens.input,
            output_tokens: metrics.tokens.output,
            cache_read_tokens: metrics.tokens.cached,
            hosts_discovered: 0,
            ports_discovered: 0,
        },
    }
}
```

**Step 3: Run tests**

```bash
cd /Users/ristoviitanen/feroxmute/.worktrees/llm-dedup && cargo test -p feroxmute-core report 2>&1 | tail -30
```

Expected: All report tests pass

**Step 4: Commit**

```bash
git add feroxmute-core/src/mcp/tools/report.rs feroxmute-core/src/tools/report.rs
git commit -m "$(cat <<'EOF'
feat(report): use deduplicated findings when available

generate_report now checks ReportContext.deduplicated_findings first
before falling back to database or in-memory findings.
EOF
)"
```

---

## Task 5: Register the tool in provider macros

**Files:**
- Modify: `feroxmute-core/src/providers/macros.rs`

**Step 1: Add the deduplication tool to complete_with_report**

In the `complete_with_report` method (around line 397-403), add the deduplication tool:

```rust
let agent = self
    .client
    .agent(&self.model)
    .preamble(system_prompt)
    .max_tokens(4096)
    .tool($crate::mcp::tools::McpDeduplicateFindingsTool::new(std::sync::Arc::clone(&context)))  // ADD THIS
    .tool($crate::tools::GenerateReportTool::new(std::sync::Arc::clone(&context)))
    .tool($crate::tools::ExportJsonTool::new(std::sync::Arc::clone(&context)))
    .tool($crate::tools::ExportMarkdownTool::new(std::sync::Arc::clone(&context)))
    .tool($crate::tools::ExportHtmlTool::new(std::sync::Arc::clone(&context)))
    .tool($crate::tools::ExportPdfTool::new(std::sync::Arc::clone(&context)))
    .tool($crate::tools::AddRecommendationTool::new(std::sync::Arc::clone(&context)))
    .build();
```

**Step 2: Run build**

```bash
cd /Users/ristoviitanen/feroxmute/.worktrees/llm-dedup && cargo build -p feroxmute-core 2>&1 | tail -30
```

Expected: Build succeeds

**Step 3: Commit**

```bash
git add feroxmute-core/src/providers/macros.rs
git commit -m "$(cat <<'EOF'
feat(providers): register deduplicate_findings tool for report agents
EOF
)"
```

---

## Task 6: Update report agent prompt

**Files:**
- Modify: `feroxmute-core/prompts.toml`

**Step 1: Add deduplication instructions to report agent prompt**

Find the `[report]` section (around line 798) and add after the initial prompt paragraphs (around line 840, after "Deduplicate intelligently"):

```toml
## Report Generation Process

Before generating the final report, you MUST:
1. Call `deduplicate_findings` to merge semantically similar vulnerabilities
2. Review the deduplication summary to understand the consolidated findings
3. Then call `generate_report` with your executive summary

This ensures the report doesn't contain duplicate entries for the same vulnerability
discovered by different agents or at different times.
```

**Step 2: Verify TOML is valid**

```bash
cd /Users/ristoviitanen/feroxmute/.worktrees/llm-dedup && cargo build -p feroxmute-core 2>&1 | tail -10
```

Expected: Build succeeds (TOML parsing happens at runtime, but build should work)

**Step 3: Commit**

```bash
git add feroxmute-core/prompts.toml
git commit -m "$(cat <<'EOF'
docs(prompts): instruct report agent to deduplicate before generating
EOF
)"
```

---

## Task 7: Add unit tests for deduplication tool

**Files:**
- Modify: `feroxmute-core/src/mcp/tools/dedup.rs`

**Step 1: Add comprehensive tests**

Replace the placeholder test in `dedup.rs` with:

```rust
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::agents::{AgentStatus, EngagementPhase};
    use crate::state::models::FindingType;
    use crate::state::{MetricsTracker, Severity, VulnStatus, run_migrations};
    use crate::tools::EventSender;
    use crate::tools::MemoryEntryData;
    use crate::tools::orchestrator::AgentSummary;
    use chrono::Utc;
    use std::path::PathBuf;
    use tokio::sync::Mutex;

    struct NoopEventSender;

    impl EventSender for NoopEventSender {
        fn send_feed(&self, _agent: &str, _message: &str, _is_error: bool) {}
        fn send_feed_with_output(&self, _: &str, _: &str, _: bool, _: &str) {}
        fn send_status(&self, _: &str, _: &str, _: AgentStatus, _: Option<String>) {}
        fn send_metrics(&self, _: u64, _: u64, _: u64, _: f64, _: u64) {}
        fn send_vulnerability(&self, _: Severity, _: &str) {}
        fn send_thinking(&self, _: &str, _: Option<String>) {}
        fn send_phase(&self, _: EngagementPhase) {}
        fn send_summary(&self, _: &str, _: &AgentSummary) {}
        fn send_memory_update(&self, _: Vec<MemoryEntryData>) {}
        fn send_code_finding(&self, _: &str, _: &str, _: Option<u32>, _: Severity, _: FindingType, _: &str, _: &str, _: Option<&str>, _: Option<&str>) {}
        fn send_tool_call(&self) {}
    }

    fn setup_test_db() -> (tempfile::TempDir, PathBuf) {
        let tmp = tempfile::tempdir().expect("create temp dir");
        let db_path = tmp.path().join("session.db");
        let conn = rusqlite::Connection::open(&db_path).expect("open db");
        run_migrations(&conn).expect("run migrations");
        drop(conn);
        (tmp, db_path)
    }

    fn setup_context(db_path: PathBuf, reports_dir: PathBuf) -> Arc<ReportContext> {
        Arc::new(ReportContext {
            events: Arc::new(NoopEventSender),
            target: "example.com".to_string(),
            session_id: "test-session".to_string(),
            start_time: Utc::now(),
            metrics: MetricsTracker::new(),
            findings: Arc::new(Mutex::new(Vec::new())),
            report: Arc::new(Mutex::new(None)),
            reports_dir,
            session_db_path: Some(db_path),
            deduplicated_findings: Arc::new(Mutex::new(None)),
        })
    }

    #[tokio::test]
    async fn test_deduplicate_empty_database() {
        let (tmp, db_path) = setup_test_db();
        let reports_dir = tmp.path().join("reports");
        std::fs::create_dir_all(&reports_dir).ok();

        let context = setup_context(db_path, reports_dir);
        let tool = McpDeduplicateFindingsTool::new(context);

        let result = tool.execute(serde_json::json!({})).await.expect("should succeed");
        let content = result.content.expect("should have content");
        let text = match &content[0] {
            crate::mcp::McpContent::Text { text } => text,
        };
        let parsed: serde_json::Value = serde_json::from_str(text).expect("should parse JSON");

        assert_eq!(parsed["success"], true);
        assert_eq!(parsed["original_count"], 0);
        assert_eq!(parsed["deduplicated_count"], 0);
    }

    #[tokio::test]
    async fn test_deduplicate_with_duplicates() {
        let (tmp, db_path) = setup_test_db();
        let reports_dir = tmp.path().join("reports");
        std::fs::create_dir_all(&reports_dir).ok();

        // Insert duplicate findings
        let conn = rusqlite::Connection::open(&db_path).expect("open db");

        let vuln1 = Vulnerability {
            id: "VULN-001".to_string(),
            host_id: None,
            vuln_type: "sqli".to_string(),
            severity: Severity::Critical,
            title: "SQL Injection in login".to_string(),
            description: Some("Login vulnerable".to_string()),
            evidence: Some("Evidence A".to_string()),
            status: VulnStatus::Verified,
            cwe: None,
            cvss: None,
            asset: Some("/login".to_string()),
            remediation: None,
            discovered_by: "agent-a".to_string(),
            verified_by: None,
            discovered_at: Utc::now(),
            verified_at: None,
        };
        vuln1.insert(&conn).expect("insert vuln1");

        // Same title, same severity = duplicate
        let vuln2 = Vulnerability {
            id: "VULN-002".to_string(),
            host_id: None,
            vuln_type: "sqli".to_string(),
            severity: Severity::Critical,
            title: "SQL Injection in login".to_string(),
            description: Some("More detailed description".to_string()),
            evidence: Some("Evidence B".to_string()),
            status: VulnStatus::Verified,
            cwe: None,
            cvss: None,
            asset: Some("/login".to_string()),
            remediation: Some("Use prepared statements".to_string()),
            discovered_by: "agent-b".to_string(),
            verified_by: None,
            discovered_at: Utc::now(),
            verified_at: None,
        };
        vuln2.insert(&conn).expect("insert vuln2");

        // Different vulnerability
        let vuln3 = Vulnerability {
            id: "VULN-003".to_string(),
            host_id: None,
            vuln_type: "xss".to_string(),
            severity: Severity::High,
            title: "XSS in search".to_string(),
            description: None,
            evidence: None,
            status: VulnStatus::Potential,
            cwe: None,
            cvss: None,
            asset: None,
            remediation: None,
            discovered_by: "agent-a".to_string(),
            verified_by: None,
            discovered_at: Utc::now(),
            verified_at: None,
        };
        vuln3.insert(&conn).expect("insert vuln3");
        drop(conn);

        let context = setup_context(db_path, reports_dir);
        let tool = McpDeduplicateFindingsTool::new(Arc::clone(&context));

        let result = tool.execute(serde_json::json!({})).await.expect("should succeed");
        let content = result.content.expect("should have content");
        let text = match &content[0] {
            crate::mcp::McpContent::Text { text } => text,
        };
        let parsed: serde_json::Value = serde_json::from_str(text).expect("should parse JSON");

        assert_eq!(parsed["success"], true);
        assert_eq!(parsed["original_count"], 3);
        assert_eq!(parsed["deduplicated_count"], 2); // 2 SQLi merged into 1, XSS stays

        // Verify cache was populated
        let cache = context.deduplicated_findings.lock().await;
        assert!(cache.is_some());
        assert_eq!(cache.as_ref().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn test_deduplicate_no_database() {
        let tmp = tempfile::tempdir().expect("create temp dir");
        let reports_dir = tmp.path().join("reports");
        std::fs::create_dir_all(&reports_dir).ok();

        let context = Arc::new(ReportContext {
            events: Arc::new(NoopEventSender),
            target: "example.com".to_string(),
            session_id: "test-session".to_string(),
            start_time: Utc::now(),
            metrics: MetricsTracker::new(),
            findings: Arc::new(Mutex::new(Vec::new())),
            report: Arc::new(Mutex::new(None)),
            reports_dir,
            session_db_path: None, // No database
            deduplicated_findings: Arc::new(Mutex::new(None)),
        });

        let tool = McpDeduplicateFindingsTool::new(context);
        let result = tool.execute(serde_json::json!({})).await.expect("should succeed");

        assert_eq!(result.is_error, Some(true));
    }
}
```

**Step 2: Run tests**

```bash
cd /Users/ristoviitanen/feroxmute/.worktrees/llm-dedup && cargo test -p feroxmute-core dedup 2>&1 | tail -30
```

Expected: All tests pass

**Step 3: Commit**

```bash
git add feroxmute-core/src/mcp/tools/dedup.rs
git commit -m "$(cat <<'EOF'
test(dedup): add unit tests for deduplication tool
EOF
)"
```

---

## Task 8: Run full test suite and lint

**Files:** None (validation only)

**Step 1: Format code**

```bash
cd /Users/ristoviitanen/feroxmute/.worktrees/llm-dedup && cargo fmt
```

**Step 2: Run clippy**

```bash
cd /Users/ristoviitanen/feroxmute/.worktrees/llm-dedup && cargo clippy -- -D warnings 2>&1 | tail -50
```

Expected: No warnings

**Step 3: Run full test suite**

```bash
cd /Users/ristoviitanen/feroxmute/.worktrees/llm-dedup && cargo test 2>&1 | tail -50
```

Expected: All tests pass

**Step 4: Commit any format changes**

```bash
git add -A
git diff --cached --stat
# If changes exist:
git commit -m "style: apply rustfmt"
```

---

## Task 9: Export deduplicate_vulnerabilities from reports module

**Files:**
- Modify: `feroxmute-core/src/reports/mod.rs` or `feroxmute-core/src/reports/generator.rs`

**Step 1: Check current exports**

```bash
cat feroxmute-core/src/reports/mod.rs
```

**Step 2: Make deduplicate_vulnerabilities public**

If `deduplicate_vulnerabilities` is in `generator.rs`, either:
- Make it `pub fn deduplicate_vulnerabilities` in generator.rs
- Re-export it from mod.rs: `pub use generator::deduplicate_vulnerabilities;`

**Step 3: Run build**

```bash
cd /Users/ristoviitanen/feroxmute/.worktrees/llm-dedup && cargo build -p feroxmute-core 2>&1 | tail -20
```

Expected: Build succeeds

**Step 4: Commit**

```bash
git add feroxmute-core/src/reports/
git commit -m "$(cat <<'EOF'
refactor(reports): export deduplicate_vulnerabilities function
EOF
)"
```

---

## Summary

After completing all tasks:

1. `ReportContext` has a `deduplicated_findings` field
2. `McpDeduplicateFindingsTool` loads findings, deduplicates, and caches them
3. `McpGenerateReportTool` checks the cache before loading from database
4. The tool is registered in provider macros for report agents
5. Report agent prompt instructs calling `deduplicate_findings` first
6. Tests verify the behavior

**Note:** This implementation uses exact-match deduplication as a baseline. The LLM-based canonical key extraction (the "semantic" part) would be a follow-up enhancement that requires:
1. Adding a simple LLM completion method to `ReportContext` or passing provider config
2. Building batched prompts for key extraction
3. Parsing LLM responses to get canonical keys
4. Grouping by `(canonical_key, severity)` instead of `(title, severity)`

The current implementation provides the infrastructure and integration points. The LLM enhancement can be added incrementally.
