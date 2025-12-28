# SAST Agent View Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement a dedicated SAST agent TUI view with real-time findings display using a hybrid layout (header, summary, feed).

**Architecture:** Extend the EventSender trait with `send_code_finding()`, add a `CodeFinding` event variant, update SAST tool parsers to emit events, and route SAST agents to a specialized widget.

**Tech Stack:** Rust, ratatui, tokio channels, feroxmute-core/feroxmute-cli crates

---

## Task 1: Add CodeFinding Event to Channel

**Files:**
- Modify: `feroxmute-cli/src/tui/channel.rs`

**Step 1: Add CodeFindingEvent struct and AgentEvent variant**

After the `MemoryEntry` struct (around line 85), add:

```rust
use feroxmute_core::state::models::{FindingType, Severity};

/// Code finding event for SAST TUI updates
#[derive(Debug, Clone)]
pub struct CodeFindingEvent {
    pub file_path: String,
    pub line_number: Option<u32>,
    pub severity: Severity,
    pub finding_type: FindingType,
    pub title: String,
    pub tool: String,
    pub cve_id: Option<String>,
    pub package_name: Option<String>,
}
```

Add to the `AgentEvent` enum (after `MemoryUpdated`):

```rust
    /// Code finding from SAST tools
    CodeFinding {
        agent: String,
        finding: CodeFindingEvent,
    },
```

**Step 2: Run cargo check**

Run: `cargo check -p feroxmute-cli`
Expected: PASS (new types added, not yet used)

**Step 3: Commit**

```bash
git add feroxmute-cli/src/tui/channel.rs
git commit -m "feat(tui): add CodeFinding event variant for SAST"
```

---

## Task 2: Add send_code_finding to EventSender Trait

**Files:**
- Modify: `feroxmute-core/src/tools/orchestrator.rs:119-151`

**Step 1: Add the new trait method**

Add to the `EventSender` trait (after `send_memory_update`):

```rust
    /// Send a code finding from SAST analysis
    fn send_code_finding(
        &self,
        agent: &str,
        file_path: &str,
        line_number: Option<u32>,
        severity: Severity,
        finding_type: FindingType,
        title: &str,
        tool: &str,
        cve_id: Option<&str>,
        package_name: Option<&str>,
    );
```

**Step 2: Add FindingType import**

Add to imports at top of file:

```rust
use crate::state::models::FindingType;
```

**Step 3: Run cargo check**

Run: `cargo check -p feroxmute-core`
Expected: FAIL - trait method not implemented in CLI

**Step 4: Commit**

```bash
git add feroxmute-core/src/tools/orchestrator.rs
git commit -m "feat(core): add send_code_finding to EventSender trait"
```

---

## Task 3: Implement send_code_finding in TuiEventSender

**Files:**
- Modify: `feroxmute-cli/src/runner.rs`

**Step 1: Add imports**

Add to imports:

```rust
use feroxmute_core::state::models::FindingType;
use crate::tui::channel::CodeFindingEvent;
```

**Step 2: Implement the trait method**

Add after `send_memory_update` (around line 186):

```rust
    fn send_code_finding(
        &self,
        agent: &str,
        file_path: &str,
        line_number: Option<u32>,
        severity: Severity,
        finding_type: FindingType,
        title: &str,
        tool: &str,
        cve_id: Option<&str>,
        package_name: Option<&str>,
    ) {
        let tx = self.tx.clone();
        let agent = agent.to_string();
        let finding = CodeFindingEvent {
            file_path: file_path.to_string(),
            line_number,
            severity,
            finding_type,
            title: title.to_string(),
            tool: tool.to_string(),
            cve_id: cve_id.map(String::from),
            package_name: package_name.map(String::from),
        };
        tokio::spawn(async move {
            let _ = tx
                .send(AgentEvent::CodeFinding { agent, finding })
                .await;
        });
    }
```

**Step 3: Run cargo check**

Run: `cargo check -p feroxmute-cli`
Expected: PASS

**Step 4: Commit**

```bash
git add feroxmute-cli/src/runner.rs
git commit -m "feat(cli): implement send_code_finding in TuiEventSender"
```

---

## Task 4: Handle CodeFinding Event in drain_events

**Files:**
- Modify: `feroxmute-cli/src/tui/runner.rs`
- Modify: `feroxmute-cli/src/tui/app.rs`

**Step 1: Remove dead_code allows from app.rs**

In `app.rs`, remove `#[allow(dead_code)]` from these fields (around lines 179-190):

```rust
    /// Source path for SAST analysis
    pub source_path: Option<String>,
    /// Detected programming languages
    pub detected_languages: Vec<String>,
    /// Code findings from SAST
    pub code_findings: Vec<CodeFinding>,
    /// Code finding counts by type
    pub code_finding_counts: CodeFindingCounts,
```

**Step 2: Add helper method to App**

Add to `impl App` (around line 330):

```rust
    /// Add a code finding and update counts
    pub fn add_code_finding(&mut self, finding: CodeFinding) {
        match finding.finding_type {
            FindingType::Dependency => self.code_finding_counts.dependencies += 1,
            FindingType::Sast => self.code_finding_counts.sast += 1,
            FindingType::Secret => self.code_finding_counts.secrets += 1,
        }
        self.code_findings.push(finding);
    }
```

Add import at top:

```rust
use feroxmute_core::state::models::FindingType;
```

**Step 3: Handle event in drain_events**

In `runner.rs`, add to the `drain_events` match (after `MemoryUpdated` around line 357):

```rust
            AgentEvent::CodeFinding { agent, finding } => {
                // Convert event to CodeFinding model
                let code_finding = feroxmute_core::state::models::CodeFinding::new(
                    &finding.file_path,
                    finding.severity,
                    finding.finding_type,
                    &finding.title,
                    &finding.tool,
                );
                let code_finding = if let Some(line) = finding.line_number {
                    code_finding.with_line(line)
                } else {
                    code_finding
                };
                let code_finding = if let Some(ref cve) = finding.cve_id {
                    code_finding.with_cve(cve)
                } else {
                    code_finding
                };
                let code_finding = if let Some(ref pkg) = finding.package_name {
                    code_finding.with_package(pkg, "")
                } else {
                    code_finding
                };

                app.add_code_finding(code_finding);

                // Also add to feed for visibility
                app.add_feed(super::app::FeedEntry::new(
                    &agent,
                    format!("[{:?}] {}", finding.severity, finding.title),
                ));
            }
```

**Step 4: Run cargo check**

Run: `cargo check -p feroxmute-cli`
Expected: PASS

**Step 5: Commit**

```bash
git add feroxmute-cli/src/tui/app.rs feroxmute-cli/src/tui/runner.rs
git commit -m "feat(tui): handle CodeFinding events and update app state"
```

---

## Task 5: Update SAST Widget with Hybrid Layout

**Files:**
- Modify: `feroxmute-cli/src/tui/widgets/sast.rs`

**Step 1: Rewrite sast.rs with hybrid layout**

Replace the entire file:

```rust
//! SAST agent detail widget with hybrid layout
//!
//! Shows SAST-specific header, findings summary, and standard feed output.

#![allow(clippy::indexing_slicing)]

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
    Frame,
};

use crate::tui::app::App;
use crate::tui::colors::{severity_style, status_style};
use feroxmute_core::agents::AgentStatus;

/// Render the SAST agent detail view with hybrid layout
pub fn render(frame: &mut Frame, app: &App, agent_name: &str, area: Rect) {
    let thinking = app.agents.get(agent_name).and_then(|a| a.thinking.as_ref());
    let show_thinking = app.show_thinking && thinking.is_some();

    let constraints = if show_thinking {
        vec![
            Constraint::Length(4),  // Header
            Constraint::Length(4),  // Summary
            Constraint::Min(8),     // Feed/output
            Constraint::Length(6),  // Thinking
            Constraint::Length(1),  // Footer
        ]
    } else {
        vec![
            Constraint::Length(4),  // Header
            Constraint::Length(4),  // Summary
            Constraint::Min(10),    // Feed/output
            Constraint::Length(1),  // Footer
        ]
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(area);

    render_header(frame, app, agent_name, chunks[0]);
    render_summary(frame, app, chunks[1]);
    render_output(frame, app, agent_name, chunks[2]);

    if show_thinking {
        render_thinking(frame, thinking, chunks[3]);
        render_footer(frame, agent_name, app, chunks[4]);
    } else {
        render_footer(frame, agent_name, app, chunks[3]);
    }
}

/// Render header with status, source path, and languages
fn render_header(frame: &mut Frame, app: &App, agent_name: &str, area: Rect) {
    let (status, current_tool) = app
        .agents
        .get(agent_name)
        .map(|a| (a.status, a.current_tool.as_deref()))
        .unwrap_or((AgentStatus::Idle, None));

    let status_text = format_status(status, current_tool);
    let source = app.source_path.as_deref().unwrap_or("-");
    let languages = if app.detected_languages.is_empty() {
        "-".to_string()
    } else {
        app.detected_languages.join(", ")
    };

    let header = Paragraph::new(vec![
        Line::from(vec![
            Span::raw("Status: "),
            Span::styled(&status_text.0, status_text.1),
        ]),
        Line::from(vec![
            Span::raw("Source: "),
            Span::styled(source, Style::default().fg(Color::Cyan)),
            Span::raw("  Languages: "),
            Span::styled(languages, Style::default().fg(Color::Yellow)),
        ]),
    ])
    .block(Block::default().borders(Borders::ALL).title(" SAST Agent "));

    frame.render_widget(header, area);
}

/// Render summary with finding counts by type
fn render_summary(frame: &mut Frame, app: &App, area: Rect) {
    let counts = &app.code_finding_counts;
    let total = counts.dependencies + counts.sast + counts.secrets;

    let summary_text = vec![
        Line::from(vec![
            Span::styled("Dependencies: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{}", counts.dependencies),
                Style::default().fg(Color::Cyan),
            ),
            Span::raw("  │  "),
            Span::styled("Code: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{}", counts.sast),
                Style::default().fg(Color::Yellow),
            ),
            Span::raw("  │  "),
            Span::styled("Secrets: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{}", counts.secrets),
                Style::default().fg(Color::LightRed),
            ),
            Span::raw("  "),
            Span::styled(
                format!("({} total)", total),
                Style::default().fg(Color::DarkGray),
            ),
        ]),
    ];

    let summary = Paragraph::new(summary_text)
        .block(Block::default().borders(Borders::ALL).title(" Findings "));

    frame.render_widget(summary, area);
}

/// Render feed/output section (same as agent_detail)
fn render_output(frame: &mut Frame, app: &App, agent_name: &str, area: Rect) {
    let mut lines: Vec<Line> = Vec::new();

    for entry in app.feed.iter().filter(|e| e.agent == agent_name) {
        let style = if entry.is_error {
            Style::default().fg(Color::Red)
        } else {
            Style::default()
        };
        let time_str = entry.timestamp.format("%H:%M:%S").to_string();

        lines.push(Line::from(vec![
            Span::styled(time_str, Style::default().fg(Color::DarkGray)),
            Span::raw(" "),
            Span::styled(&entry.message, style),
        ]));

        if entry.expanded {
            if let Some(ref output) = entry.tool_output {
                for line in output.lines() {
                    lines.push(Line::from(vec![
                        Span::styled("         ", Style::default()),
                        Span::styled("│ ", Style::default().fg(Color::DarkGray)),
                        Span::styled(line, style),
                    ]));
                }
            }
        }
    }

    let content = if lines.is_empty() {
        vec![Line::from(Span::styled(
            "No output yet...",
            Style::default().fg(Color::DarkGray),
        ))]
    } else {
        lines
    };

    let output = Paragraph::new(content)
        .wrap(Wrap { trim: false })
        .scroll((app.log_scroll as u16, 0))
        .block(Block::default().borders(Borders::ALL).title(" Output "));
    frame.render_widget(output, area);
}

/// Render thinking panel
fn render_thinking(frame: &mut Frame, thinking: Option<&String>, area: Rect) {
    let thinking_text = thinking
        .map(|s| s.as_str())
        .unwrap_or("No current thinking...");

    let thinking_widget = Paragraph::new(thinking_text)
        .style(Style::default().fg(Color::Yellow))
        .wrap(Wrap { trim: true })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Thinking ")
                .border_style(Style::default().fg(Color::Yellow)),
        );
    frame.render_widget(thinking_widget, area);
}

/// Render footer with keybindings
fn render_footer(frame: &mut Frame, current_agent: &str, app: &App, area: Rect) {
    let current_key = app
        .agents
        .get(current_agent)
        .map(|a| (a.spawn_order + 1).to_string())
        .unwrap_or("?".to_string());

    let spawned_count = app.agents.len().saturating_sub(1);
    let max_key = (spawned_count + 1).min(9);
    let agents_hint = if max_key > 1 {
        format!("1-{}", max_key)
    } else {
        "1".to_string()
    };

    let (thinking_label, thinking_style) = if app.show_thinking {
        ("[ON]", Style::default().fg(Color::Green))
    } else {
        ("[OFF]", Style::default().fg(Color::Red))
    };

    let help = Line::from(vec![
        Span::styled("h", Style::default().fg(Color::Yellow)),
        Span::raw(" back  "),
        Span::styled("j/k", Style::default().fg(Color::Yellow)),
        Span::raw(" scroll  "),
        Span::styled("o", Style::default().fg(Color::Yellow)),
        Span::raw(" output  "),
        Span::styled("t", Style::default().fg(Color::Yellow)),
        Span::raw(" thinking "),
        Span::styled(thinking_label, thinking_style),
        Span::raw("  "),
        Span::styled(&agents_hint, Style::default().fg(Color::Yellow)),
        Span::raw(" agents  "),
        Span::styled(&current_key, Style::default().fg(Color::Cyan)),
        Span::raw(" (current)  "),
        Span::styled("q", Style::default().fg(Color::Yellow)),
        Span::raw(" quit"),
    ]);

    let footer = Paragraph::new(help).style(Style::default().fg(Color::DarkGray));
    frame.render_widget(footer, area);
}

/// Format status with optional tool name
fn format_status(status: AgentStatus, current_tool: Option<&str>) -> (String, Style) {
    match status {
        AgentStatus::Idle => ("Idle".to_string(), Style::default().fg(Color::Gray)),
        AgentStatus::Thinking => (
            "Thinking".to_string(),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        AgentStatus::Streaming => (
            "Streaming".to_string(),
            Style::default()
                .fg(Color::Blue)
                .add_modifier(Modifier::BOLD),
        ),
        AgentStatus::Executing => {
            let tool_display = current_tool
                .map(|t| {
                    if t.len() > 20 {
                        format!("{}...", &t[..t.floor_char_boundary(17)])
                    } else {
                        t.to_string()
                    }
                })
                .unwrap_or_else(|| "Executing".to_string());
            (
                tool_display,
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )
        }
        AgentStatus::Processing => (
            "Processing".to_string(),
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        ),
        AgentStatus::Waiting => ("Waiting".to_string(), Style::default().fg(Color::Yellow)),
        AgentStatus::Retrying => (
            "Retrying".to_string(),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::SLOW_BLINK),
        ),
        AgentStatus::Completed => ("Completed".to_string(), Style::default().fg(Color::Green)),
        AgentStatus::Failed => (
            "Failed".to_string(),
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ),
    }
}
```

**Step 2: Run cargo check**

Run: `cargo check -p feroxmute-cli`
Expected: PASS

**Step 3: Commit**

```bash
git add feroxmute-cli/src/tui/widgets/sast.rs
git commit -m "feat(tui): update SAST widget with hybrid layout"
```

---

## Task 6: Route SAST Agents to Specialized Widget

**Files:**
- Modify: `feroxmute-cli/src/tui/runner.rs`

**Step 1: Add sast import**

Add to widget imports (around line 17):

```rust
use super::widgets::{agent_detail, dashboard, memory, memory_modal, sast};
```

**Step 2: Update render function**

Modify the `View::AgentDetail` match arm (around line 23):

```rust
        View::AgentDetail(agent_name) => {
            let is_sast = app
                .agents
                .get(agent_name)
                .map(|a| a.agent_type == "sast")
                .unwrap_or(false);

            if is_sast {
                sast::render(frame, app, agent_name, frame.area())
            } else {
                agent_detail::render(frame, app, agent_name)
            }
        }
```

**Step 3: Run cargo check**

Run: `cargo check -p feroxmute-cli`
Expected: PASS

**Step 4: Commit**

```bash
git add feroxmute-cli/src/tui/runner.rs
git commit -m "feat(tui): route SAST agents to specialized widget"
```

---

## Task 7: Update Shell Tool to Emit CodeFinding Events

**Files:**
- Modify: `feroxmute-core/src/tools/shell.rs`

**Step 1: Add FindingType import**

Add to imports:

```rust
use crate::state::models::FindingType;
```

**Step 2: Update parse_sast_findings to emit events**

Replace the `parse_sast_findings` method (around line 256):

```rust
    /// Parse SAST tool output and send code finding events
    fn parse_sast_findings(&self, command: &str, output: &str) {
        let cmd_lower = command.to_lowercase();

        // Try to parse grype output
        if cmd_lower.starts_with("grype") && cmd_lower.contains("-o json") {
            if let Ok(grype_output) = GrypeOutput::parse(output) {
                for finding in grype_output.to_code_findings() {
                    self.events.send_code_finding(
                        &self.agent_name,
                        &finding.file_path,
                        finding.line_number,
                        finding.severity,
                        finding.finding_type,
                        &finding.title,
                        &finding.tool,
                        finding.cve_id.as_deref(),
                        finding.package_name.as_deref(),
                    );
                }
            }
        }

        // Try to parse semgrep output
        if cmd_lower.starts_with("semgrep") && cmd_lower.contains("--json") {
            if let Ok(semgrep_output) = SemgrepOutput::parse(output) {
                for finding in semgrep_output.to_code_findings() {
                    self.events.send_code_finding(
                        &self.agent_name,
                        &finding.file_path,
                        finding.line_number,
                        finding.severity,
                        finding.finding_type,
                        &finding.title,
                        &finding.tool,
                        finding.cwe_id.as_deref(),
                        None,
                    );
                }
            }
        }

        // Try to parse gitleaks output
        if cmd_lower.starts_with("gitleaks") && cmd_lower.contains("json") {
            if let Ok(gitleaks_output) = GitleaksOutput::parse(output) {
                for finding in gitleaks_output.to_code_findings() {
                    self.events.send_code_finding(
                        &self.agent_name,
                        &finding.file_path,
                        finding.line_number,
                        finding.severity,
                        finding.finding_type,
                        &finding.title,
                        &finding.tool,
                        None,
                        None,
                    );
                }
            }
        }

        // Try to parse ast-grep output
        if cmd_lower.starts_with("ast-grep") && cmd_lower.contains("--json") {
            if let Ok(astgrep_output) = super::sast::AstGrepOutput::parse(output) {
                for finding in super::sast::SastToolOutput::to_code_findings(&astgrep_output) {
                    self.events.send_code_finding(
                        &self.agent_name,
                        &finding.file_path,
                        finding.line_number,
                        finding.severity,
                        finding.finding_type,
                        &finding.title,
                        &finding.tool,
                        None,
                        None,
                    );
                }
            }
        }
    }
```

**Step 3: Run cargo check**

Run: `cargo check -p feroxmute-core`
Expected: PASS

**Step 4: Commit**

```bash
git add feroxmute-core/src/tools/shell.rs
git commit -m "feat(core): emit CodeFinding events from shell tool"
```

---

## Task 8: Add Tests

**Files:**
- Modify: `feroxmute-cli/src/tui/app.rs`

**Step 1: Add tests for add_code_finding**

Add to the `#[cfg(test)]` module:

```rust
    #[test]
    fn test_add_code_finding() {
        use feroxmute_core::state::models::{CodeFinding, FindingType, Severity};

        let mut app = App::new("test.com", "test-session", None);

        // Add dependency finding
        let dep_finding = CodeFinding::new(
            "Cargo.lock",
            Severity::High,
            FindingType::Dependency,
            "CVE-2024-1234 in pkg@1.0",
            "grype",
        );
        app.add_code_finding(dep_finding);
        assert_eq!(app.code_finding_counts.dependencies, 1);
        assert_eq!(app.code_finding_counts.sast, 0);
        assert_eq!(app.code_finding_counts.secrets, 0);

        // Add SAST finding
        let sast_finding = CodeFinding::new(
            "src/main.rs",
            Severity::Medium,
            FindingType::Sast,
            "SQL injection",
            "semgrep",
        );
        app.add_code_finding(sast_finding);
        assert_eq!(app.code_finding_counts.dependencies, 1);
        assert_eq!(app.code_finding_counts.sast, 1);

        // Add secret finding
        let secret_finding = CodeFinding::new(
            ".env",
            Severity::High,
            FindingType::Secret,
            "API key exposed",
            "gitleaks",
        );
        app.add_code_finding(secret_finding);
        assert_eq!(app.code_finding_counts.secrets, 1);

        // Total findings
        assert_eq!(app.code_findings.len(), 3);
    }
```

**Step 2: Run tests**

Run: `cargo test -p feroxmute-cli test_add_code_finding`
Expected: PASS

**Step 3: Commit**

```bash
git add feroxmute-cli/src/tui/app.rs
git commit -m "test(tui): add tests for code finding handling"
```

---

## Task 9: Final Build and Format

**Step 1: Format code**

Run: `cargo fmt`

**Step 2: Run clippy**

Run: `cargo clippy --all-targets`
Expected: No errors (warnings OK)

**Step 3: Run all tests**

Run: `cargo test`
Expected: All tests pass

**Step 4: Build release**

Run: `cargo build --release`
Expected: Successful build

**Step 5: Final commit if any formatting changes**

```bash
git add -A
git commit -m "chore: format and cleanup"
```

---

## Summary

After completing all tasks, the SAST agent view will:

1. Display a specialized header showing status, source path, and detected languages
2. Show a findings summary with counts by type (dependencies, code issues, secrets)
3. Include the standard feed/output section for tool execution logs
4. Support thinking panel toggle
5. Receive real-time findings via `CodeFinding` events from SAST tools
6. Update counts dynamically as findings are discovered
