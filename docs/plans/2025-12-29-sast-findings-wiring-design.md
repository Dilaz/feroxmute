# SAST Code Findings TUI Wiring - Design

## Problem Statement

The SAST TUI widget (`feroxmute-cli/src/tui/widgets/sast.rs`) displays finding counts, but they always show 0. The infrastructure for emitting `CodeFinding` events exists and is fully wired, but findings are never parsed because the LLM runs SAST tools without JSON output flags.

## Root Cause Analysis

### The Wiring (Already Complete)

1. **EventSender trait** (`feroxmute-core/src/tools/orchestrator.rs:154`): `send_code_finding()` method exists
2. **TuiEventSender** (`feroxmute-cli/src/runner.rs:189`): Implements `send_code_finding()`, sends `AgentEvent::CodeFinding`
3. **DockerShellTool** (`feroxmute-core/src/tools/shell.rs:160`): Calls `parse_sast_findings()` after every command
4. **parse_sast_findings()** (`shell.rs:322-400`): Parses grype/semgrep/gitleaks/ast-grep JSON output and emits events
5. **TUI drain_events** (`runner.rs:370`): Handles `AgentEvent::CodeFinding`, updates `app.code_finding_counts`
6. **SAST widget** (`sast.rs:91-124`): Renders `app.code_finding_counts`

### The Gap

The parsing logic in `parse_sast_findings()` only triggers when commands include JSON flags:

```rust
if cmd_lower.starts_with("semgrep") && cmd_lower.contains("--json")
if cmd_lower.starts_with("grype") && cmd_lower.contains("-o json")
if cmd_lower.starts_with("gitleaks") && cmd_lower.contains("json")
if cmd_lower.starts_with("ast-grep") && cmd_lower.contains("--json")
```

But the SAST prompt in `prompts.toml` shows examples **without** JSON flags:

```bash
semgrep --config=auto /path/to/code        # Missing --json
trufflehog filesystem /path/to/code        # Not even the right tool
```

## Solution

Update `feroxmute-core/prompts.toml` to include JSON output flags in all SAST tool examples.

### Changes to `[sast]` Section

**Phase 1 tool examples (around line 843):**

Before:
```bash
semgrep --config=auto /path/to/code
semgrep --config=p/security-audit /path/to/code
```

After:
```bash
semgrep --config=auto --json /path/to/code
semgrep --config=p/security-audit --json /path/to/code
```

**Add grype example (dependency scanning):**

```bash
grype /path/to/code -o json
```

**Replace trufflehog with gitleaks (which has parser support):**

Before:
```bash
trufflehog filesystem /path/to/code
```

After:
```bash
gitleaks detect --source /path/to/code --report-format json --report-path /dev/stdout
```

## Files Changed

| File | Change |
|------|--------|
| `feroxmute-core/prompts.toml` | Add JSON flags to SAST tool examples |

## Testing

1. Build: `cargo build`
2. Run with source: `cargo run -- --target example.com --source ./some-code`
3. Watch SAST agent view - counts should update as tools execute
4. Verify JSON output is being parsed in feed messages

## Risk Assessment

- **Risk Level**: Low
- **Scope**: Prompt text only, no code logic changes
- **Backwards Compatibility**: N/A (fixing broken feature)
- **Rollback**: Revert prompts.toml

## Implementation Estimate

- 1 file, ~15 lines changed
- No tests needed (existing infrastructure already tested)
