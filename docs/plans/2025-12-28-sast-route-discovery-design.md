# SAST Route Discovery Design

Design for adding web application route discovery and security categorization to the SAST agent.

## Overview

Extend the SAST agent to discover web application routes from source code, analyze them for security concerns, and store categorized findings in memory for other agents (especially the scanner) to consume.

## Route Discovery Tool

### Command
```bash
discover_routes <source_path>
```

### Pattern Matching

Framework-agnostic approach with known framework patterns:

| Framework | Pattern |
|-----------|---------|
| Express | `app.(get\|post\|put\|delete\|patch)\s*\(` |
| Flask | `@app.route\s*\(`, `@blueprint.route` |
| Django | `path\s*\(`, `url\s*\(` |
| Spring | `@(Get\|Post\|Put\|Delete)Mapping` |
| Go | `(HandleFunc\|Handle)\s*\(` |
| Rust/Axum | `.route\s*\(` |
| Generic | HTTP method literals near path strings |

### Output Format

```json
{
  "routes": [
    {
      "path": "/api/users/:id",
      "method": "GET",
      "file": "src/routes/users.js",
      "line": 42,
      "framework": "express"
    }
  ]
}
```

## LLM Security Analysis

After route discovery, the LLM analyzes routes for security concerns across 6 categories:

| Category | What to Look For | Scanner Use |
|----------|------------------|-------------|
| `sql_risk` | Query params, DB calls, ORM usage | SQL injection testing |
| `auth` | Missing auth middleware, public endpoints | Auth bypass testing |
| `file_ops` | Upload/download, file paths in params | Path traversal, upload exploits |
| `admin` | Admin routes, privilege checks | Privilege escalation |
| `injection_risk` | Template rendering, command execution | Various injection tests |
| `data_exposure` | User data endpoints, bulk exports | Data leakage testing |

## Memory Storage

### Categorized Keys

Routes are stored under categorized memory keys:

```
routes:sql_risk     → ["/api/search?q=", "/api/users/:id", ...]
routes:auth         → ["/api/login", "/api/register", ...]
routes:file_ops     → ["/api/upload", "/api/files/:id/download", ...]
routes:admin        → ["/admin/users", "/api/admin/config", ...]
routes:injection_risk → ["/api/render", "/api/exec", ...]
routes:data_exposure  → ["/api/users/export", "/api/reports", ...]
routes:all          → [{full metadata for each route}]
```

### Memory Write Format

```json
{
  "key": "routes:sql_risk",
  "value": {
    "routes": [
      {
        "path": "/api/search",
        "method": "GET",
        "params": ["q"],
        "file": "src/api/search.js",
        "line": 15,
        "reason": "Query parameter passed to database query"
      }
    ],
    "count": 1
  }
}
```

### Feed Visibility

When routes are stored, a message appears in the SAST agent feed:

```
Discovered 24 routes: 3 sql_risk, 5 auth, 2 file_ops, 1 admin
```

## Agent Consumption

### Scanner Agent

Reads categorized route keys to focus testing:

```
1. memory_read routes:sql_risk
2. For each route, run sqlmap or manual SQL injection tests
3. memory_read routes:auth
4. Test auth bypass on each endpoint
```

### Exploit Agent

Uses route metadata for targeted exploitation:

```
1. memory_read routes:file_ops
2. Attempt path traversal on file endpoints
3. memory_read routes:admin
4. Attempt privilege escalation
```

## SAST Agent Integration

### Workflow Sequence

```
1. SAST agent receives source path
2. Run existing tools (grype, semgrep, gitleaks, ast-grep)
3. Run discover_routes tool on source
4. LLM analyzes routes for security patterns
5. Store categorized routes in memory
6. Continue with vulnerability correlation
```

### Prompt Addition

Add to `prompts.toml` SAST section:

```
After running static analysis tools, discover web routes:

1. Run: discover_routes <source_path>
2. Analyze output for security concerns:
   - SQL/injection risk (query params, body parsing)
   - Auth requirements (missing auth middleware)
   - File operations (upload/download endpoints)
   - Admin functions (privileged operations)
3. Store findings using memory_write:
   - routes:sql_risk - endpoints needing SQL injection testing
   - routes:auth - endpoints for auth bypass testing
   - routes:file_ops - file upload/download testing
   - routes:admin - privilege escalation testing
   - routes:all - complete route inventory
```

### Error Handling

- No routes found → write `routes:all` with empty list, log to feed
- Parse errors → log warning, continue with other tools
- Unknown framework → still extract via generic patterns

## Files to Modify

| File | Changes |
|------|---------|
| `feroxmute-core/src/tools/sast/mod.rs` | Add `discover_routes` module |
| `feroxmute-core/src/tools/sast/routes.rs` | New file: route discovery patterns, JSON output |
| `feroxmute-core/src/tools/shell.rs` | Handle `discover_routes` command execution |
| `feroxmute-core/prompts.toml` | Add route discovery instructions to SAST agent |
| `feroxmute-cli/src/tui/channel.rs` | Optional: Add RouteDiscovered event for feed |

## Implementation Order

1. Create `routes.rs` with pattern matching and JSON output
2. Register `discover_routes` in shell.rs tool handling
3. Update SAST agent prompt with route discovery workflow
4. Add memory storage logic for categorized routes
5. Optional: Add RouteDiscovered event for feed visibility
6. Test with sample projects (Express, Flask, etc.)
