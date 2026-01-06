use std::path::Path;

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use walkdir::WalkDir;

// Compiled regex patterns for each framework
#[allow(clippy::expect_used)] // Static initialization with hardcoded regex - panic is appropriate
static EXPRESS_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*['"]([^'"]+)['"]"#)
        .expect("Hardcoded express regex pattern should be valid")
});

#[allow(clippy::expect_used)]
static FLASK_ROUTE_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"@(?:app|blueprint)\.route\s*\(\s*['"]([^'"]+)['"]"#)
        .expect("Hardcoded flask route regex pattern should be valid")
});

#[allow(clippy::expect_used)]
static FLASK_METHODS_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"methods\s*=\s*\[([^\]]+)\]"#)
        .expect("Hardcoded flask methods regex pattern should be valid")
});

#[allow(clippy::expect_used)]
static GO_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?:http\.HandleFunc|\.Handle|\.HandleFunc)\s*\(\s*["']([^"']+)["']"#)
        .expect("Hardcoded go regex pattern should be valid")
});

#[allow(clippy::expect_used)]
static AXUM_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"\.route\s*\(\s*["']([^"']+)["']"#)
        .expect("Hardcoded axum regex pattern should be valid")
});

#[allow(clippy::expect_used)]
static DJANGO_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?:path|url)\s*\(\s*[r]?['"]([^'"]+)['"]"#)
        .expect("Hardcoded django regex pattern should be valid")
});

#[allow(clippy::expect_used)]
static SPRING_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"@(Get|Post|Put|Delete|Patch|Request)Mapping\s*\(\s*(?:value\s*=\s*)?["']([^"']+)["']"#,
    )
    .expect("Hardcoded spring regex pattern should be valid")
});

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

/// Extract routes from source code content
pub fn discover_routes_in_content(content: &str, file: &str, framework: &str) -> Vec<RouteInfo> {
    let mut routes = Vec::new();

    match framework {
        "express" => {
            for (line_num, line) in content.lines().enumerate() {
                for cap in EXPRESS_REGEX.captures_iter(line) {
                    let method = cap
                        .get(1)
                        .map(|m| m.as_str().to_uppercase())
                        .unwrap_or_default();
                    let path = cap.get(2).map(|m| m.as_str()).unwrap_or_default();
                    routes.push(RouteInfo::new(
                        path,
                        &method,
                        file,
                        (line_num + 1) as u32,
                        framework,
                    ));
                }
            }
        }
        "flask" => {
            for (line_num, line) in content.lines().enumerate() {
                for cap in FLASK_ROUTE_REGEX.captures_iter(line) {
                    let path = cap.get(1).map(|m| m.as_str()).unwrap_or_default();

                    // Try to extract methods, default to GET
                    let method = if let Some(methods_cap) = FLASK_METHODS_REGEX.captures(line) {
                        methods_cap
                            .get(1)
                            .map(|m| m.as_str().replace(['\'', '"', ' '], ""))
                            .unwrap_or_else(|| "GET".to_string())
                    } else {
                        "GET".to_string()
                    };

                    routes.push(RouteInfo::new(
                        path,
                        &method,
                        file,
                        (line_num + 1) as u32,
                        framework,
                    ));
                }
            }
        }
        "go" => {
            for (line_num, line) in content.lines().enumerate() {
                for cap in GO_REGEX.captures_iter(line) {
                    let path = cap.get(1).map(|m| m.as_str()).unwrap_or_default();
                    routes.push(RouteInfo::new(
                        path,
                        "ANY",
                        file,
                        (line_num + 1) as u32,
                        framework,
                    ));
                }
            }
        }
        "axum" => {
            for (line_num, line) in content.lines().enumerate() {
                for cap in AXUM_REGEX.captures_iter(line) {
                    let path = cap.get(1).map(|m| m.as_str()).unwrap_or_default();
                    routes.push(RouteInfo::new(
                        path,
                        "ANY",
                        file,
                        (line_num + 1) as u32,
                        framework,
                    ));
                }
            }
        }
        "django" => {
            for (line_num, line) in content.lines().enumerate() {
                for cap in DJANGO_REGEX.captures_iter(line) {
                    let path = cap.get(1).map(|m| m.as_str()).unwrap_or_default();
                    routes.push(RouteInfo::new(
                        path,
                        "ANY",
                        file,
                        (line_num + 1) as u32,
                        framework,
                    ));
                }
            }
        }
        "spring" => {
            for (line_num, line) in content.lines().enumerate() {
                for cap in SPRING_REGEX.captures_iter(line) {
                    let method = cap
                        .get(1)
                        .map(|m| {
                            let m = m.as_str();
                            if m == "Request" { "ANY" } else { m }
                        })
                        .unwrap_or("ANY")
                        .to_uppercase();
                    let path = cap.get(2).map(|m| m.as_str()).unwrap_or_default();
                    routes.push(RouteInfo::new(
                        path,
                        &method,
                        file,
                        (line_num + 1) as u32,
                        framework,
                    ));
                }
            }
        }
        _ => {}
    }

    routes
}

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
            let file_str = path
                .strip_prefix(source_path)
                .unwrap_or(path)
                .to_string_lossy()
                .to_string();
            let routes = discover_routes_all_frameworks(&content, &file_str);
            all_routes.extend(routes);
        }
    }

    Ok(RoutesOutput { routes: all_routes })
}

/// Detect web framework from file content
pub fn detect_framework(content: &str) -> Option<&'static str> {
    let content_lower = content.to_lowercase();

    if content_lower.contains("require('express')")
        || content_lower.contains("require(\"express\")")
        || content_lower.contains("from 'express'")
        || content_lower.contains("from \"express\"")
    {
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

    #[test]
    fn test_detect_framework() {
        assert_eq!(
            detect_framework("const express = require('express');"),
            Some("express")
        );
        assert_eq!(detect_framework("from flask import Flask"), Some("flask"));
        assert_eq!(
            detect_framework("from django.urls import path"),
            Some("django")
        );
        assert_eq!(
            detect_framework("import org.springframework.web.bind.annotation"),
            Some("spring")
        );
        assert_eq!(detect_framework("import \"net/http\""), Some("go"));
        assert_eq!(detect_framework("use axum::Router;"), Some("axum"));
        assert_eq!(detect_framework("some random code"), None);
    }

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
}
