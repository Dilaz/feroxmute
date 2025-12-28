# SAST Route Discovery Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add route discovery tool to SAST agent that extracts web routes from source code and stores them in memory categorized by security concern.

**Architecture:** Create a `discover_routes` tool that uses regex patterns to find route definitions across frameworks (Express, Flask, Django, Spring, Go, Axum). The tool outputs JSON which shell.rs parses, then sends categorized routes to memory for scanner/exploit agents.

**Tech Stack:** Rust, regex crate, serde_json

---

### Task 1: Create Route Data Structures

**Files:**
- Create: `feroxmute-core/src/tools/sast/routes.rs`
- Modify: `feroxmute-core/src/tools/sast/mod.rs`

**Step 1: Write the failing test**

Add to `routes.rs`:

```rust
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn test_route_info_new() {
        let route = RouteInfo::new("/api/users", "GET", "src/routes.js", 42, "express");
        assert_eq!(route.path, "/api/users");
        assert_eq!(route.method, "GET");
        assert_eq!(route.file, "src/routes.js");
        assert_eq!(route.line, 42);
        assert_eq!(route.framework, "express");
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p feroxmute-core test_route_info_new`
Expected: FAIL with "cannot find value `RouteInfo`"

**Step 3: Write minimal implementation**

Create `feroxmute-core/src/tools/sast/routes.rs`:

```rust
use serde::{Deserialize, Serialize};

/// Information about a discovered web route
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteInfo {
    pub path: String,
    pub method: String,
    pub file: String,
    pub line: u32,
    pub framework: String,
}

impl RouteInfo {
    pub fn new(path: &str, method: &str, file: &str, line: u32, framework: &str) -> Self {
        Self {
            path: path.to_string(),
            method: method.to_string(),
            file: file.to_string(),
            line,
            framework: framework.to_string(),
        }
    }
}

/// Output from discover_routes command
#[derive(Debug, Serialize, Deserialize)]
pub struct RoutesOutput {
    pub routes: Vec<RouteInfo>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn test_route_info_new() {
        let route = RouteInfo::new("/api/users", "GET", "src/routes.js", 42, "express");
        assert_eq!(route.path, "/api/users");
        assert_eq!(route.method, "GET");
        assert_eq!(route.file, "src/routes.js");
        assert_eq!(route.line, 42);
        assert_eq!(route.framework, "express");
    }
}
```

**Step 4: Update mod.rs to include routes module**

Add to `feroxmute-core/src/tools/sast/mod.rs`:

```rust
mod routes;

pub use routes::{RouteInfo, RoutesOutput};
```

**Step 5: Run test to verify it passes**

Run: `cargo test -p feroxmute-core test_route_info_new`
Expected: PASS

**Step 6: Commit**

```bash
git add feroxmute-core/src/tools/sast/routes.rs feroxmute-core/src/tools/sast/mod.rs
git commit -m "feat(sast): add RouteInfo and RoutesOutput data structures"
```

---

### Task 2: Add Express Route Pattern Matching

**Files:**
- Modify: `feroxmute-core/src/tools/sast/routes.rs`

**Step 1: Write the failing test**

```rust
#[test]
fn test_express_route_pattern() {
    let code = r#"
        app.get('/api/users', userController.list);
        app.post('/api/users/:id', userController.update);
        router.delete('/items/:id', itemController.remove);
    "#;

    let routes = discover_routes_in_content(code, "routes.js", "express");
    assert_eq!(routes.len(), 3);
    assert_eq!(routes[0].path, "/api/users");
    assert_eq!(routes[0].method, "GET");
    assert_eq!(routes[1].path, "/api/users/:id");
    assert_eq!(routes[1].method, "POST");
    assert_eq!(routes[2].path, "/items/:id");
    assert_eq!(routes[2].method, "DELETE");
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p feroxmute-core test_express_route_pattern`
Expected: FAIL with "cannot find function `discover_routes_in_content`"

**Step 3: Write minimal implementation**

Add to `routes.rs`:

```rust
use regex::Regex;

/// Extract routes from source code content
pub fn discover_routes_in_content(content: &str, file: &str, framework: &str) -> Vec<RouteInfo> {
    let mut routes = Vec::new();

    match framework {
        "express" => {
            // Pattern: app.get('/path', ...) or router.post('/path', ...)
            let re = Regex::new(
                r#"(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*['"]([^'"]+)['"]"#
            ).unwrap();

            for (line_num, line) in content.lines().enumerate() {
                for cap in re.captures_iter(line) {
                    let method = cap.get(1).map(|m| m.as_str().to_uppercase()).unwrap_or_default();
                    let path = cap.get(2).map(|m| m.as_str()).unwrap_or_default();
                    routes.push(RouteInfo::new(path, &method, file, (line_num + 1) as u32, framework));
                }
            }
        }
        _ => {}
    }

    routes
}
```

**Step 4: Add regex to Cargo.toml if needed**

Check if regex is already a dependency. If not, add to `feroxmute-core/Cargo.toml`:

```toml
regex = "1"
```

**Step 5: Run test to verify it passes**

Run: `cargo test -p feroxmute-core test_express_route_pattern`
Expected: PASS

**Step 6: Commit**

```bash
git add feroxmute-core/src/tools/sast/routes.rs feroxmute-core/Cargo.toml
git commit -m "feat(sast): add Express route pattern matching"
```

---

### Task 3: Add Flask Route Pattern Matching

**Files:**
- Modify: `feroxmute-core/src/tools/sast/routes.rs`

**Step 1: Write the failing test**

```rust
#[test]
fn test_flask_route_pattern() {
    let code = r#"
        @app.route('/users', methods=['GET'])
        def list_users():
            pass

        @app.route('/users/<id>', methods=['POST', 'PUT'])
        def update_user(id):
            pass

        @blueprint.route('/items')
        def list_items():
            pass
    "#;

    let routes = discover_routes_in_content(code, "app.py", "flask");
    assert_eq!(routes.len(), 3);
    assert_eq!(routes[0].path, "/users");
    assert_eq!(routes[1].path, "/users/<id>");
    assert_eq!(routes[2].path, "/items");
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p feroxmute-core test_flask_route_pattern`
Expected: FAIL (returns 0 routes for flask framework)

**Step 3: Write minimal implementation**

Add Flask case to the match in `discover_routes_in_content`:

```rust
"flask" => {
    // Pattern: @app.route('/path') or @blueprint.route('/path')
    let re = Regex::new(
        r#"@(?:app|blueprint)\.route\s*\(\s*['"]([^'"]+)['"]"#
    ).unwrap();

    // Pattern for methods=['GET', 'POST']
    let methods_re = Regex::new(
        r#"methods\s*=\s*\[([^\]]+)\]"#
    ).unwrap();

    for (line_num, line) in content.lines().enumerate() {
        for cap in re.captures_iter(line) {
            let path = cap.get(1).map(|m| m.as_str()).unwrap_or_default();

            // Try to extract methods, default to GET
            let method = if let Some(methods_cap) = methods_re.captures(line) {
                methods_cap.get(1)
                    .map(|m| m.as_str().replace(['\'', '"', ' '], ""))
                    .unwrap_or_else(|| "GET".to_string())
            } else {
                "GET".to_string()
            };

            routes.push(RouteInfo::new(path, &method, file, (line_num + 1) as u32, framework));
        }
    }
}
```

**Step 4: Run test to verify it passes**

Run: `cargo test -p feroxmute-core test_flask_route_pattern`
Expected: PASS

**Step 5: Commit**

```bash
git add feroxmute-core/src/tools/sast/routes.rs
git commit -m "feat(sast): add Flask route pattern matching"
```

---

### Task 4: Add Remaining Framework Patterns (Go, Axum, Django, Spring)

**Files:**
- Modify: `feroxmute-core/src/tools/sast/routes.rs`

**Step 1: Write the failing tests**

```rust
#[test]
fn test_go_route_pattern() {
    let code = r#"
        http.HandleFunc("/api/users", handleUsers)
        r.Handle("/api/items", itemsHandler)
    "#;

    let routes = discover_routes_in_content(code, "main.go", "go");
    assert_eq!(routes.len(), 2);
    assert_eq!(routes[0].path, "/api/users");
    assert_eq!(routes[1].path, "/api/items");
}

#[test]
fn test_axum_route_pattern() {
    let code = r#"
        .route("/api/users", get(list_users))
        .route("/api/users/:id", post(create_user).delete(delete_user))
    "#;

    let routes = discover_routes_in_content(code, "main.rs", "axum");
    assert_eq!(routes.len(), 2);
}

#[test]
fn test_django_route_pattern() {
    let code = r#"
        path('users/', views.user_list),
        path('users/<int:id>/', views.user_detail),
        url(r'^api/items/$', views.items),
    "#;

    let routes = discover_routes_in_content(code, "urls.py", "django");
    assert_eq!(routes.len(), 3);
}

#[test]
fn test_spring_route_pattern() {
    let code = r#"
        @GetMapping("/api/users")
        public List<User> getUsers() {}

        @PostMapping("/api/users/{id}")
        public User updateUser(@PathVariable Long id) {}

        @RequestMapping(value = "/items", method = RequestMethod.DELETE)
        public void deleteItems() {}
    "#;

    let routes = discover_routes_in_content(code, "UserController.java", "spring");
    assert_eq!(routes.len(), 3);
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test -p feroxmute-core test_go_route_pattern test_axum_route_pattern test_django_route_pattern test_spring_route_pattern`
Expected: All FAIL (return 0 routes)

**Step 3: Write minimal implementation**

Add remaining cases to `discover_routes_in_content`:

```rust
"go" => {
    // Pattern: http.HandleFunc("/path", ...) or r.Handle("/path", ...)
    let re = Regex::new(
        r#"(?:http\.HandleFunc|\.Handle|\.HandleFunc)\s*\(\s*["']([^"']+)["']"#
    ).unwrap();

    for (line_num, line) in content.lines().enumerate() {
        for cap in re.captures_iter(line) {
            let path = cap.get(1).map(|m| m.as_str()).unwrap_or_default();
            routes.push(RouteInfo::new(path, "ANY", file, (line_num + 1) as u32, framework));
        }
    }
}
"axum" => {
    // Pattern: .route("/path", ...)
    let re = Regex::new(
        r#"\.route\s*\(\s*["']([^"']+)["']"#
    ).unwrap();

    for (line_num, line) in content.lines().enumerate() {
        for cap in re.captures_iter(line) {
            let path = cap.get(1).map(|m| m.as_str()).unwrap_or_default();
            routes.push(RouteInfo::new(path, "ANY", file, (line_num + 1) as u32, framework));
        }
    }
}
"django" => {
    // Pattern: path('route/', ...) or url(r'^route/$', ...)
    let re = Regex::new(
        r#"(?:path|url)\s*\(\s*[r]?['"]([^'"]+)['"]"#
    ).unwrap();

    for (line_num, line) in content.lines().enumerate() {
        for cap in re.captures_iter(line) {
            let path = cap.get(1).map(|m| m.as_str()).unwrap_or_default();
            routes.push(RouteInfo::new(path, "ANY", file, (line_num + 1) as u32, framework));
        }
    }
}
"spring" => {
    // Pattern: @GetMapping("/path"), @PostMapping, etc.
    let re = Regex::new(
        r#"@(Get|Post|Put|Delete|Patch|Request)Mapping\s*\(\s*(?:value\s*=\s*)?["']([^"']+)["']"#
    ).unwrap();

    for (line_num, line) in content.lines().enumerate() {
        for cap in re.captures_iter(line) {
            let method = cap.get(1).map(|m| {
                let m = m.as_str();
                if m == "Request" { "ANY" } else { m }
            }).unwrap_or("ANY").to_uppercase();
            let path = cap.get(2).map(|m| m.as_str()).unwrap_or_default();
            routes.push(RouteInfo::new(path, &method, file, (line_num + 1) as u32, framework));
        }
    }
}
```

**Step 4: Run tests to verify they pass**

Run: `cargo test -p feroxmute-core test_go_route_pattern test_axum_route_pattern test_django_route_pattern test_spring_route_pattern`
Expected: All PASS

**Step 5: Commit**

```bash
git add feroxmute-core/src/tools/sast/routes.rs
git commit -m "feat(sast): add Go, Axum, Django, Spring route patterns"
```

---

### Task 5: Add Auto-Detection of Framework from File Content

**Files:**
- Modify: `feroxmute-core/src/tools/sast/routes.rs`

**Step 1: Write the failing test**

```rust
#[test]
fn test_detect_framework() {
    assert_eq!(detect_framework("const express = require('express');"), Some("express"));
    assert_eq!(detect_framework("from flask import Flask"), Some("flask"));
    assert_eq!(detect_framework("from django.urls import path"), Some("django"));
    assert_eq!(detect_framework("import org.springframework.web.bind.annotation"), Some("spring"));
    assert_eq!(detect_framework("import \"net/http\""), Some("go"));
    assert_eq!(detect_framework("use axum::Router;"), Some("axum"));
    assert_eq!(detect_framework("some random code"), None);
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p feroxmute-core test_detect_framework`
Expected: FAIL with "cannot find function `detect_framework`"

**Step 3: Write minimal implementation**

```rust
/// Detect web framework from file content
pub fn detect_framework(content: &str) -> Option<&'static str> {
    let content_lower = content.to_lowercase();

    if content_lower.contains("require('express')") || content_lower.contains("require(\"express\")")
        || content_lower.contains("from 'express'") || content_lower.contains("from \"express\"") {
        return Some("express");
    }
    if content_lower.contains("from flask import") || content_lower.contains("import flask") {
        return Some("flask");
    }
    if content_lower.contains("from django") || content_lower.contains("import django") {
        return Some("django");
    }
    if content_lower.contains("org.springframework") {
        return Some("spring");
    }
    if content_lower.contains("\"net/http\"") || content_lower.contains("'net/http'") {
        return Some("go");
    }
    if content_lower.contains("use axum::") || content_lower.contains("axum::") {
        return Some("axum");
    }

    None
}
```

**Step 4: Run test to verify it passes**

Run: `cargo test -p feroxmute-core test_detect_framework`
Expected: PASS

**Step 5: Commit**

```bash
git add feroxmute-core/src/tools/sast/routes.rs
git commit -m "feat(sast): add framework auto-detection"
```

---

### Task 6: Add discover_routes_in_file Function

**Files:**
- Modify: `feroxmute-core/src/tools/sast/routes.rs`

**Step 1: Write the failing test**

```rust
#[test]
fn test_discover_routes_all_frameworks() {
    let express_code = r#"
        const express = require('express');
        app.get('/users', getUsers);
    "#;

    let routes = discover_routes_all_frameworks(express_code, "app.js");
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].framework, "express");
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p feroxmute-core test_discover_routes_all_frameworks`
Expected: FAIL with "cannot find function"

**Step 3: Write minimal implementation**

```rust
/// Discover routes by auto-detecting framework
pub fn discover_routes_all_frameworks(content: &str, file: &str) -> Vec<RouteInfo> {
    // First try to detect framework
    if let Some(framework) = detect_framework(content) {
        return discover_routes_in_content(content, file, framework);
    }

    // If no framework detected, try all patterns
    let frameworks = ["express", "flask", "django", "spring", "go", "axum"];
    let mut all_routes = Vec::new();

    for framework in frameworks {
        let routes = discover_routes_in_content(content, file, framework);
        all_routes.extend(routes);
    }

    all_routes
}
```

**Step 4: Run test to verify it passes**

Run: `cargo test -p feroxmute-core test_discover_routes_all_frameworks`
Expected: PASS

**Step 5: Commit**

```bash
git add feroxmute-core/src/tools/sast/routes.rs
git commit -m "feat(sast): add discover_routes_all_frameworks function"
```

---

### Task 7: Add File System Discovery Function

**Files:**
- Modify: `feroxmute-core/src/tools/sast/routes.rs`

**Step 1: Write the failing test**

```rust
#[test]
fn test_routes_output_to_json() {
    let routes = vec![
        RouteInfo::new("/api/users", "GET", "src/routes.js", 10, "express"),
        RouteInfo::new("/api/items", "POST", "src/routes.js", 20, "express"),
    ];
    let output = RoutesOutput { routes };

    let json = serde_json::to_string(&output).unwrap();
    assert!(json.contains("/api/users"));
    assert!(json.contains("/api/items"));
}

#[test]
fn test_routes_output_parse() {
    let json = r#"{"routes":[{"path":"/api/users","method":"GET","file":"app.js","line":10,"framework":"express"}]}"#;
    let output: RoutesOutput = serde_json::from_str(json).unwrap();
    assert_eq!(output.routes.len(), 1);
    assert_eq!(output.routes[0].path, "/api/users");
}
```

**Step 2: Run tests to verify they pass** (should already work with existing Serialize/Deserialize derives)

Run: `cargo test -p feroxmute-core test_routes_output`
Expected: PASS

**Step 3: Add discover_routes function that scans directory**

```rust
use std::path::Path;
use walkdir::WalkDir;

/// Discover routes in a directory
///
/// # Errors
///
/// Returns error if directory cannot be read
pub fn discover_routes(source_path: &Path) -> Result<RoutesOutput, std::io::Error> {
    let mut all_routes = Vec::new();

    // File extensions to scan
    let extensions = ["js", "ts", "jsx", "tsx", "py", "java", "go", "rs"];

    for entry in WalkDir::new(source_path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let path = entry.path();

        // Skip node_modules, venv, target, etc.
        let path_str = path.to_string_lossy();
        if path_str.contains("node_modules")
            || path_str.contains("venv")
            || path_str.contains("/target/")
            || path_str.contains("/.git/")
        {
            continue;
        }

        // Check extension
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if !extensions.contains(&ext) {
            continue;
        }

        // Read and scan file
        if let Ok(content) = std::fs::read_to_string(path) {
            let file_str = path.strip_prefix(source_path)
                .unwrap_or(path)
                .to_string_lossy()
                .to_string();
            let routes = discover_routes_all_frameworks(&content, &file_str);
            all_routes.extend(routes);
        }
    }

    Ok(RoutesOutput { routes: all_routes })
}
```

**Step 4: Add walkdir dependency if needed**

Check `feroxmute-core/Cargo.toml`. Add if missing:

```toml
walkdir = "2"
```

**Step 5: Run all tests**

Run: `cargo test -p feroxmute-core routes`
Expected: All PASS

**Step 6: Commit**

```bash
git add feroxmute-core/src/tools/sast/routes.rs feroxmute-core/Cargo.toml
git commit -m "feat(sast): add discover_routes directory scanner"
```

---

### Task 8: Parse discover_routes Output in shell.rs

**Files:**
- Modify: `feroxmute-core/src/tools/shell.rs`

**Step 1: Add routes to imports**

At the top of shell.rs, add:

```rust
use crate::tools::sast::{RoutesOutput, RouteInfo};
```

**Step 2: Add route parsing to parse_sast_findings**

Find the `parse_sast_findings` function and add this case after the existing tool checks:

```rust
// Try to parse discover_routes output
if cmd_lower.starts_with("discover_routes") || cmd_lower.contains("discover_routes") {
    if let Ok(routes_output) = serde_json::from_str::<RoutesOutput>(output) {
        let count = routes_output.routes.len();
        if count > 0 {
            self.events.send_feed(
                &self.agent_name,
                &format!("  -> discovered {} routes", count),
                false,
            );
        }
    }
}
```

**Step 3: Run build to verify no errors**

Run: `cargo build -p feroxmute-core`
Expected: Build succeeds

**Step 4: Commit**

```bash
git add feroxmute-core/src/tools/shell.rs
git commit -m "feat(sast): parse discover_routes output in shell"
```

---

### Task 9: Update SAST Agent Prompt

**Files:**
- Modify: `feroxmute-core/prompts.toml`

**Step 1: Add route discovery section to SAST prompt**

Find the `[sast]` section and add after Phase 1 (Tool-Assisted Discovery):

```toml
### Phase 1.5: Route Discovery

After running security scanners, discover web application routes:

**discover_routes** - Find API endpoints and route definitions:
```bash
discover_routes /path/to/source
```

This finds routes in Express, Flask, Django, Spring, Go, and Axum applications.

After discovering routes, analyze them for security concerns:

1. **SQL Risk**: Routes with query parameters or database operations
2. **Auth Endpoints**: Login, register, password reset (test for bypass)
3. **File Operations**: Upload/download endpoints (path traversal risk)
4. **Admin Routes**: Privileged operations (authorization testing)
5. **Injection Risk**: Template rendering, command execution
6. **Data Exposure**: User data exports, bulk operations

Store findings in memory for the scanner agent:
```
memory_add(key="routes:sql_risk", value="[list of endpoints with SQL concerns]")
memory_add(key="routes:auth", value="[auth-related endpoints]")
memory_add(key="routes:file_ops", value="[file handling endpoints]")
memory_add(key="routes:admin", value="[admin/privileged endpoints]")
memory_add(key="routes:all", value="[complete route list with metadata]")
```
```

**Step 2: Run format check**

Run: `cargo fmt --check`
Expected: No formatting issues (TOML not affected by cargo fmt)

**Step 3: Commit**

```bash
git add feroxmute-core/prompts.toml
git commit -m "docs(sast): add route discovery workflow to SAST prompt"
```

---

### Task 10: Final Build and Test

**Files:**
- All modified files

**Step 1: Run all tests**

Run: `cargo test`
Expected: All tests pass

**Step 2: Run clippy**

Run: `cargo clippy -- -D warnings`
Expected: No warnings

**Step 3: Run format**

Run: `cargo fmt`
Expected: Code formatted

**Step 4: Build release**

Run: `cargo build --release`
Expected: Build succeeds

**Step 5: Final commit if any changes from fmt**

```bash
git add -A
git commit -m "chore: format code" --allow-empty
```

---

## Summary

This implementation adds:
1. `RouteInfo` and `RoutesOutput` data structures
2. Pattern matching for 6 frameworks (Express, Flask, Django, Spring, Go, Axum)
3. Framework auto-detection from file content
4. Directory scanning with `discover_routes` function
5. Shell integration to parse route discovery output
6. SAST prompt with route discovery workflow and memory storage guidance
