# Multi-Target Support with SAST Integration

Design document for adding multi-target support and static analysis capabilities to feroxmute.

## Overview

Enable feroxmute to accept multiple targets, intelligently detect relationships between them (e.g., source code for a web application), and perform static analysis on code targets. When source code is linked to a web target, findings from static analysis guide and enhance dynamic testing.

## Target Model

### Target Types

```
Target Types:
├── Web       → URL (http/https) or domain
├── Directory → Local filesystem path
└── Repository → Git URL (github.com, gitlab.com, etc.)
```

### Target Resolution Flow

1. Parse all `--target` arguments
2. Classify each by pattern:
   - Starts with `http://` or `https://` → Web
   - Starts with `git@` or contains `github.com`/`gitlab.com` → Repository (clone to temp dir)
   - Path exists on filesystem → Directory
   - Otherwise → assume domain, treat as Web
3. Run relationship detection (heuristics)
4. If uncertain, prompt user to confirm groupings

### CLI Syntax

```bash
# Multiple targets
feroxmute --target https://example.com --target ./src

# Explicit source linking (bypasses heuristics)
feroxmute --target https://example.com --source ./src

# Force separate engagements (skip relationship detection)
feroxmute --target https://example.com --target https://other.com --separate

# SAST-only mode (no web testing)
feroxmute --target ./src --sast-only
```

---

## Relationship Detection Heuristics

When multiple targets exist, the orchestrator runs heuristics to detect if a directory/repo is source code for a web target.

### Heuristics (checked in order)

1. **Config files** - Look for URLs in:
   - `.env`, `.env.*` files
   - `config/*.toml`, `config/*.yaml`, `settings.py`
   - `docker-compose.yml`, `Dockerfile` (exposed ports, domains)

2. **Package metadata** - Check `package.json` homepage, `Cargo.toml` repository, `setup.py` url

3. **Route matching** - Extract routes from code (e.g., `@app.route("/api/users")`) and check if web target has matching endpoints

4. **Domain references** - Grep for web target's domain in source files

5. **Framework detection** - If code is Django and web target returns Django-style responses, likely match

### Confidence Scoring

- 2+ heuristics match → Auto-link with high confidence
- 1 heuristic matches → Ask user to confirm
- 0 matches → Treat as separate targets

### User Prompt (when uncertain)

```
Detected targets:
  [1] https://example.com (web)
  [2] ./backend (directory)

Found potential relationship:
  - ./backend/config.toml contains "example.com"

Is ./backend the source code for https://example.com? [Y/n]
```

---

## SAST Agent

A new specialist agent dedicated to static analysis, sitting alongside Recon, Scanner, Exploit, and Report.

### Agent Hierarchy (updated)

```
                    ┌─────────────────┐
                    │  Orchestrator   │
                    │  (Lead Agent)   │
                    └────────┬────────┘
                             │ delegates
        ┌────────┬───────────┼───────────┬────────┬────────┐
        ▼        ▼           ▼           ▼        ▼        ▼
   ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐
   │  SAST  │ │  Recon │ │  Web   │ │Exploit │ │ Report │ │ Script │
   │  Agent │ │  Agent │ │Scanner │ │ Agent  │ │ Agent  │ │Service │
   └────────┘ └────────┘ └────────┘ └────────┘ └────────┘ └────────┘
```

### Tools

| Category | Tools |
|----------|-------|
| **Dependency scanning** | grype, trivy, npm audit, cargo-audit, pip-audit, govulncheck |
| **Code analysis** | semgrep, ast-grep, bandit, gosec, eslint-plugin-security |
| **Secrets** | gitleaks, trufflehog |

### Agent Workflow

1. **Detect languages** - Scan for manifest files (`package.json`, `Cargo.toml`, `requirements.txt`, `go.mod`, etc.)
2. **Dependency audit** - Run vulnerability scanners against:
   - `package.json` / `package-lock.json` → npm audit, grype
   - `Cargo.toml` / `Cargo.lock` → cargo-audit, grype
   - `requirements.txt` / `poetry.lock` → pip-audit, grype
   - `go.mod` / `go.sum` → govulncheck, grype
   - `pom.xml` / `build.gradle` → grype, trivy
3. **Run SAST tools** - Static analysis for code vulnerabilities
4. **Parse results** - Normalize all findings (CVE IDs for deps, CWE for code issues)
5. **LLM review** - Filter false positives, assess exploitability, identify additional issues
6. **Extract intelligence** - Routes, parameters, auth patterns for web testing
7. **Store findings** - SQLite with severity, CVE/CWE, affected component

### Output Shared with Other Agents

- Endpoint map (route → handler file:line)
- Parameter names and types
- SQL queries and ORM patterns
- Auth/authz logic locations
- Hardcoded secrets
- Dependency vulnerabilities (package, version, CVE, fixed version)

---

## Code-to-Web Correlation

When source code is linked to a web target, the orchestrator coordinates SAST and web testing for maximum effectiveness.

### Correlation Strategies

1. **Direct exploitation** - SAST finds clear vulnerability → Scanner/Exploit test immediately
   - Found `query = "SELECT * FROM users WHERE id=" + user_id` in `/api/users` handler
   - → Scanner immediately tests `GET /api/users?id=1'` with SQLi payloads

2. **Prioritized queue** - Code suspicion boosts endpoint priority
   - Handler has complex auth logic with multiple branches
   - → Scanner tests that endpoint earlier and more thoroughly

3. **Guided fuzzing** - Code context generates smarter payloads
   - Code shows parameter is parsed as integer then used in query
   - → Fuzzer tries integer overflow, negative values, type juggling

4. **Vulnerability confirmation** - Match SAST findings with DAST results
   - SAST: "Potential XSS in `/search` - user input echoed without sanitization"
   - DAST: "Reflected XSS confirmed at `/search?q=<script>`"
   - → Link findings, upgrade confidence to "verified"

### Data Flow

```
SAST Agent → endpoint_map, code_findings → SQLite
                                              ↓
Orchestrator reads findings, plans Scanner tasks with context
                                              ↓
Scanner Agent → receives task + code context → targeted testing
```

---

## Linked Target Execution Flow

When a directory/repo is linked to a web target, they form a single engagement with coordinated analysis.

### Execution Order

```
1. SAST Agent analyzes source code
   ├── Dependency audit (CVEs)
   ├── Static analysis (code vulnerabilities)
   ├── Extract routes, parameters, auth patterns
   └── Store all findings + intelligence

2. Recon Agent runs (enhanced)
   ├── Standard recon (subdomains, ports, tech stack)
   └── Cross-reference with code: "Code says Express.js, confirm?"

3. Scanner Agent runs (code-aware)
   ├── Prioritize endpoints flagged by SAST
   ├── Use extracted parameter names for fuzzing
   └── Test for vulnerabilities found in code

4. Exploit Agent runs (code-guided)
   ├── Read relevant code sections before exploitation
   ├── Craft payloads based on actual code logic
   └── Link confirmed vulns back to source location

5. Report Agent generates unified report
   └── "SQLi in /api/users (code: src/routes/users.rs:47, confirmed via DAST)"
```

---

## Multiple Separate Targets

When targets are determined to be unrelated (e.g., two different websites), the user chooses how to handle them.

### Runtime Prompt

```
Detected 2 separate engagements:
  [1] https://example.com
  [2] https://other-site.org

How should these be processed?
  [P] Parallel - Run both simultaneously (uses more resources)
  [S] Sequential - Complete one before starting the next
  [C] Cancel - Abort and refine targets

Choice [P/s/c]:
```

### Parallel Execution

- Spawns separate orchestrator instance per engagement
- Each gets own session directory (`~/.feroxmute/sessions/<target>/`)
- TUI shows tabs or split view for each engagement
- Resource limits apply per-engagement (rate limiting respected)

### Sequential Execution

- Single orchestrator processes targets in order
- Clear separation in reports ("Engagement 1 of 2")
- Option to skip remaining after completing one

### Session Structure (multi-target)

```
~/.feroxmute/sessions/2024-01-15-multi/
├── session.db              # Shared metadata
├── engagements/
│   ├── example-com/        # First engagement
│   │   ├── findings.db
│   │   └── artifacts/
│   └── other-site-org/     # Second engagement
│       ├── findings.db
│       └── artifacts/
└── reports/
    ├── example-com.md
    └── other-site-org.md
```

---

## Configuration

### Updated Config File (engagement.toml)

```toml
[[targets]]
url = "https://example.com"
type = "web"

[[targets]]
path = "./backend"
type = "directory"
linked_to = "https://example.com"  # explicit link

[[targets]]
url = "https://github.com/org/repo"
type = "repository"

[sast]
enabled = true
tools = ["semgrep", "ast-grep", "grype", "gitleaks"]  # or "all"
languages = ["rust", "python", "javascript"]  # auto-detect if omitted

[multi_target]
mode = "ask"  # "parallel" | "sequential" | "ask"
```

### New CLI Arguments

```rust
#[derive(Parser)]
struct Args {
    #[arg(long, action = ArgAction::Append)]
    target: Vec<String>,

    #[arg(long)]
    source: Option<PathBuf>,  // explicit source link

    #[arg(long)]
    separate: bool,  // skip relationship detection

    #[arg(long)]
    sast_only: bool,  // no web testing
}
```

---

## Tool Management

### Dockerfile

```dockerfile
FROM kalilinux/kali-rolling
RUN apt-get update && apt-get install -y \
    golang sqlmap feroxbuster ffuf chromium python3

# ProjectDiscovery tools
RUN go install -v github.com/projectdiscovery/pdtm/cmd/pdtm@latest
RUN pdtm -install-all

# Python with uv
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.cargo/bin:$PATH"
RUN uv python install 3.12

# Browser automation
RUN uv pip install playwright && playwright install chromium

# SAST tools
RUN cargo install ast-grep --locked
RUN uv tool install semgrep bandit pip-audit
RUN go install github.com/gitleaks/gitleaks/v8@latest
RUN go install golang.org/x/vuln/cmd/govulncheck@latest
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh
```

### Runtime Tool Verification

Before SAST Agent runs, verify tools are available in the container:

```rust
impl SastAgent {
    async fn ensure_tools(&self, executor: &DockerExecutor) -> Result<()> {
        let required = self.detect_required_tools(&languages);

        for tool in required {
            if !self.tool_exists(&tool, executor).await? {
                self.install_tool(&tool, executor).await?;
            }
        }
        Ok(())
    }
}

fn install_command(tool: &str) -> &'static str {
    match tool {
        "semgrep" | "bandit" | "pip-audit" => "uv tool install",
        "ast-grep" => "cargo install ast-grep --locked",
        "gitleaks" => "go install github.com/gitleaks/gitleaks/v8@latest",
        "grype" => "curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh",
        "govulncheck" => "go install golang.org/x/vuln/cmd/govulncheck@latest",
        _ => panic!("unknown tool"),
    }
}
```

---

## SQLite Schema Additions

```sql
-- Code findings from SAST
CREATE TABLE code_findings (
    id INTEGER PRIMARY KEY,
    file_path TEXT NOT NULL,
    line_number INTEGER,
    severity TEXT NOT NULL,  -- 'critical' | 'high' | 'medium' | 'low' | 'info'
    finding_type TEXT NOT NULL,  -- 'dependency' | 'sast' | 'secret'
    cve_id TEXT,  -- for dependency vulns
    cwe_id TEXT,  -- for code vulns
    title TEXT NOT NULL,
    description TEXT,
    snippet TEXT,  -- relevant code snippet
    tool TEXT NOT NULL,  -- which tool found it
    package_name TEXT,  -- for dependency vulns
    package_version TEXT,
    fixed_version TEXT,
    discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Correlation between code and web findings
CREATE TABLE finding_correlations (
    id INTEGER PRIMARY KEY,
    code_finding_id INTEGER REFERENCES code_findings(id),
    web_finding_id INTEGER REFERENCES vulnerabilities(id),
    correlation_type TEXT NOT NULL,  -- 'confirmed' | 'related' | 'same_root_cause'
    confidence REAL,  -- 0.0 to 1.0
    notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Extracted code intelligence
CREATE TABLE code_endpoints (
    id INTEGER PRIMARY KEY,
    route TEXT NOT NULL,
    method TEXT,  -- GET, POST, etc.
    handler_file TEXT NOT NULL,
    handler_line INTEGER,
    parameters TEXT,  -- JSON array of param names
    auth_required BOOLEAN,
    notes TEXT
);
```

---

## TUI Updates

### Dashboard (updated)

```
┌─ feroxmute ──────────────────────────────────────────────────┐
│ Targets: example.com ← ./backend (linked)    Session: ...    │
│ Phase: Static Analysis       Elapsed: 00:03:12               │
├──────────────────────────────────────────────────────────────┤
│ Metrics                                                      │
│ Tools: 42 calls     Tokens: 8.2k in │ 1.4k cached │ 3.1k out │
│ Code:  3 critical │ 7 high │ 12 medium    (22 total)         │
│ Web:   0 findings (pending)                                  │
├──────────────────────────────────────────────────────────────┤
│ Agents              Status          Findings        [click]  │
│ ● Orchestrator      coordinating    -                  ○     │
│ ● SAST              running         22 findings        ○     │
│ ○ Recon             queued          -                  ○     │
│ ○ Scanner           queued          -                  ○     │
│ ○ Exploit           idle            -                  ○     │
│ ○ Report            idle            -                  ○     │
├──────────────────────────────────────────────────────────────┤
│ Live Feed                                                    │
│ [03:12] sast: grype found CVE-2024-1234 in lodash@4.17.20    │
│ [03:11] sast: semgrep found SQL injection in src/db.rs:142   │
│ [03:10] sast: analyzing ./backend (rust, javascript)         │
└──────────────────────────────────────────────────────────────┘
```

### SAST Agent Detail View

```
┌─ SAST Agent ─────────────────────────────────────────────────┐
│ Status: running              Source: ./backend               │
│ Languages: rust, javascript  Tools: semgrep, grype, ast-grep │
├──────────────────────────────────────────────────────────────┤
│ Findings by Type                                             │
│ Dependencies:  8 (2 critical, 4 high, 2 medium)              │
│ Code issues:  12 (1 critical, 3 high, 8 medium)              │
│ Secrets:       2 (2 high)                                    │
├──────────────────────────────────────────────────────────────┤
│ Recent Findings                                              │
│ [CRIT] CVE-2024-1234 lodash@4.17.20 → upgrade to 4.17.21     │
│ [HIGH] SQLi src/routes/users.rs:142 → linked to /api/users   │
│ [HIGH] Hardcoded API key in src/config.rs:23                 │
└──────────────────────────────────────────────────────────────┘
```

### Color Scheme

| Severity | Color | Ratatui Style |
|----------|-------|---------------|
| Critical | Red | `Style::default().fg(Color::Red).bold()` |
| High | Orange | `Style::default().fg(Color::LightRed)` |
| Medium | Yellow | `Style::default().fg(Color::Yellow)` |
| Low | Blue | `Style::default().fg(Color::Blue)` |
| Info | Gray | `Style::default().fg(Color::DarkGray)` |

### Agent Status Colors

| Status | Color |
|--------|-------|
| Running | Green |
| Queued | Yellow |
| Idle | Gray |
| Error | Red |

### Keybindings (updated)

| Key | Action |
|-----|--------|
| `h` / `Home` | Dashboard view |
| `1` | Jump to SAST Agent |
| `2` | Jump to Recon Agent |
| `3` | Jump to Scanner Agent |
| `4` | Jump to Exploit Agent |
| `5` | Jump to Report Agent |
| `Enter` | Dive into selected agent |
| `Esc` | Back to dashboard |
| `t` | Toggle thinking/reasoning panel |
| `d` | Toggle detailed tool output |
| `l` | View full logs |
| `p` | Pause/resume agents |
| `q` | Quit (with confirmation) |

---

## Implementation Summary

### New Files

| File | Purpose |
|------|---------|
| `feroxmute-core/src/agents/sast.rs` | SAST Agent implementation |
| `feroxmute-core/src/targets/mod.rs` | Target module |
| `feroxmute-core/src/targets/types.rs` | Target enum and parsing |
| `feroxmute-core/src/targets/detection.rs` | Relationship heuristics |
| `feroxmute-core/src/targets/resolver.rs` | Git clone, path resolution |
| `feroxmute-core/src/tools/sast/mod.rs` | SAST tool wrappers |
| `feroxmute-core/src/tools/sast/semgrep.rs` | Semgrep integration |
| `feroxmute-core/src/tools/sast/grype.rs` | Grype integration |
| `feroxmute-core/src/tools/sast/ast_grep.rs` | ast-grep integration |
| `feroxmute-cli/src/tui/widgets/sast.rs` | SAST agent TUI widget |

### Modified Files

| File | Changes |
|------|---------|
| `feroxmute-cli/src/main.rs` | New CLI args |
| `feroxmute-core/src/config/mod.rs` | Multi-target config parsing |
| `feroxmute-core/src/agents/orchestrator.rs` | Target grouping, SAST coordination |
| `feroxmute-core/src/state/models.rs` | New tables for code findings |
| `feroxmute-core/src/state/session.rs` | Multi-engagement session structure |
| `feroxmute-cli/src/tui/app.rs` | SAST agent state, color helpers |
| `feroxmute-cli/src/tui/widgets/dashboard.rs` | Show linked targets, code findings |
| `docker/Dockerfile` | Add SAST tools |
| `feroxmute-core/prompts.toml` | Add SAST agent prompt |
