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
        _ => {}
    }

    routes
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
}
