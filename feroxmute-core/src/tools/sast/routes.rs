use regex::Regex;
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

/// Extract routes from source code content
pub fn discover_routes_in_content(content: &str, file: &str, framework: &str) -> Vec<RouteInfo> {
    let mut routes = Vec::new();

    match framework {
        "express" => {
            // Pattern: app.get('/path', ...) or router.post('/path', ...)
            let re = Regex::new(
                r#"(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*['"]([^'"]+)['"]"#,
            )
            .expect("Invalid express regex pattern");

            for (line_num, line) in content.lines().enumerate() {
                for cap in re.captures_iter(line) {
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
            // Pattern: @app.route('/path') or @blueprint.route('/path')
            let re = Regex::new(r#"@(?:app|blueprint)\.route\s*\(\s*['"]([^'"]+)['"]"#)
                .expect("Invalid flask regex pattern");

            // Pattern for methods=['GET', 'POST']
            let methods_re =
                Regex::new(r#"methods\s*=\s*\[([^\]]+)\]"#).expect("Invalid methods regex pattern");

            for (line_num, line) in content.lines().enumerate() {
                for cap in re.captures_iter(line) {
                    let path = cap.get(1).map(|m| m.as_str()).unwrap_or_default();

                    // Try to extract methods, default to GET
                    let method = if let Some(methods_cap) = methods_re.captures(line) {
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
            // Pattern: http.HandleFunc("/path", ...) or r.Handle("/path", ...)
            let re = Regex::new(r#"(?:http\.HandleFunc|\.Handle|\.HandleFunc)\s*\(\s*["']([^"']+)["']"#)
                .expect("Invalid go regex pattern");

            for (line_num, line) in content.lines().enumerate() {
                for cap in re.captures_iter(line) {
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
            // Pattern: .route("/path", ...)
            let re = Regex::new(r#"\.route\s*\(\s*["']([^"']+)["']"#)
                .expect("Invalid axum regex pattern");

            for (line_num, line) in content.lines().enumerate() {
                for cap in re.captures_iter(line) {
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
            // Pattern: path('route/', ...) or url(r'^route/$', ...)
            let re = Regex::new(r#"(?:path|url)\s*\(\s*[r]?['"]([^'"]+)['"]"#)
                .expect("Invalid django regex pattern");

            for (line_num, line) in content.lines().enumerate() {
                for cap in re.captures_iter(line) {
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
            // Pattern: @GetMapping("/path"), @PostMapping, etc.
            let re = Regex::new(
                r#"@(Get|Post|Put|Delete|Patch|Request)Mapping\s*\(\s*(?:value\s*=\s*)?["']([^"']+)["']"#,
            )
            .expect("Invalid spring regex pattern");

            for (line_num, line) in content.lines().enumerate() {
                for cap in re.captures_iter(line) {
                    let method = cap
                        .get(1)
                        .map(|m| {
                            let m = m.as_str();
                            if m == "Request" {
                                "ANY"
                            } else {
                                m
                            }
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
        assert_eq!(
            detect_framework("from flask import Flask"),
            Some("flask")
        );
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
}
