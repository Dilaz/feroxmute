# SAST Agent View Design

Design for implementing a dedicated SAST agent TUI view with real-time findings display.

## Overview

Replace the generic agent detail view for SAST agents with a specialized hybrid layout that shows:
- SAST-specific header (status, source path, detected languages)
- Findings summary by type (dependencies, code issues, secrets)
- Standard feed/output section for tool execution logs

## Data Flow

### New `AgentEvent` Variant

Add to `feroxmute-cli/src/tui/channel.rs`:

```rust
AgentEvent::CodeFinding {
    agent: String,
    file_path: String,
    line_number: Option<u32>,
    severity: Severity,
    finding_type: FindingType,  // Dependency | Sast | Secret
    title: String,
    tool: String,
    cve_id: Option<String>,
    package_name: Option<String>,
}
```

### Event Flow

1. SAST tool runs via `complete_with_shell` (already has memory access)
2. Tool wrapper (grype/semgrep/gitleaks) parses JSON output
3. For each finding, sends `AgentEvent::CodeFinding` to TUI channel
4. TUI's `drain_events()` updates `app.code_findings` and `app.code_finding_counts`
5. SAST view re-renders with new data

### EventSender Trait Extension

Add to `feroxmute-core/src/tools/mod.rs`:

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
);
```

## TUI Layout

### Vertical Stack Layout

```
┌─ SAST Agent ─────────────────────────────────────────────┐
│ Status: running    Source: ./src    Languages: rust, js  │  <- Header (4 lines)
├──────────────────────────────────────────────────────────┤
│ Dependencies: 3  │  Code: 5  │  Secrets: 1   (9 total)   │  <- Summary (4 lines)
├──────────────────────────────────────────────────────────┤
│ Output                                                   │
│ 10:15:03 Running grype on ./src...                       │  <- Feed (flexible)
│ 10:15:05   -> exit 0, found 3 vulnerabilities            │
│ 10:15:06 Running semgrep with auto config...             │
│ 10:15:12   -> exit 0, found 5 issues                     │
│ 10:15:13 Running gitleaks...                             │
│ 10:15:14   -> exit 0, found 1 secret                     │
├──────────────────────────────────────────────────────────┤
│ h back  j/k scroll  o output  t thinking  1-3 agents  q  │  <- Footer (1 line)
└──────────────────────────────────────────────────────────┘
```

### Layout Constraints

```rust
let chunks = Layout::default()
    .direction(Direction::Vertical)
    .constraints([
        Constraint::Length(4),   // Header with status/source/languages
        Constraint::Length(4),   // Summary counts
        Constraint::Min(10),     // Feed/output (reuse from agent_detail)
        Constraint::Length(1),   // Footer
    ])
    .split(area);
```

### Routing Logic

In `runner.rs`:

```rust
View::AgentDetail(agent_name) => {
    let is_sast = app.agents.get(agent_name)
        .map(|a| a.agent_type == "sast")
        .unwrap_or(false);

    if is_sast {
        sast::render(frame, app, agent_name, area)
    } else {
        agent_detail::render(frame, app, agent_name)
    }
}
```

## SAST Tool Integration

Each SAST tool parser gets a `parse_and_emit()` method:

```rust
impl GrypeOutput {
    pub fn parse_and_emit(
        json: &str,
        events: &dyn EventSender,
        agent: &str,
    ) -> Result<Vec<CodeFinding>> {
        let findings = Self::parse(json)?.to_code_findings();
        for f in &findings {
            events.send_code_finding(
                agent,
                &f.file_path,
                f.line_number,
                f.severity,
                f.finding_type,
                &f.title,
                &f.tool,
                f.cve_id.as_deref(),
                f.package_name.as_deref(),
            );
        }
        Ok(findings)
    }
}
```

The `DockerShellTool` calls these parsers after detecting SAST command execution.

## Files to Modify

| File | Changes |
|------|---------|
| `feroxmute-cli/src/tui/channel.rs` | Add `AgentEvent::CodeFinding` variant |
| `feroxmute-cli/src/tui/app.rs` | Remove `#[allow(dead_code)]` from SAST fields |
| `feroxmute-cli/src/tui/runner.rs` | Handle `CodeFinding` event in `drain_events()`, route SAST agents to `sast::render` |
| `feroxmute-cli/src/tui/widgets/sast.rs` | Update to hybrid layout with header, summary, feed, footer |
| `feroxmute-core/src/tools/mod.rs` | Add `send_code_finding()` to `EventSender` trait |
| `feroxmute-core/src/tools/sast/grype.rs` | Add `parse_and_emit()` method |
| `feroxmute-core/src/tools/sast/semgrep.rs` | Add `parse_and_emit()` method |
| `feroxmute-core/src/tools/sast/gitleaks.rs` | Add `parse_and_emit()` method |
| `feroxmute-core/src/tools/sast/ast_grep.rs` | Add `parse_and_emit()` method |
| `feroxmute-core/src/tools/shell.rs` | Call `parse_and_emit()` after SAST tool execution |

## Implementation Order

1. Add `send_code_finding()` to `EventSender` trait and implementations
2. Add `AgentEvent::CodeFinding` to channel
3. Handle event in `drain_events()` to populate `app.code_findings`
4. Update `sast.rs` widget with hybrid layout
5. Route SAST agents to new widget in `runner.rs`
6. Add `parse_and_emit()` to each SAST tool parser
7. Call parsers from `DockerShellTool` when SAST commands complete
