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
