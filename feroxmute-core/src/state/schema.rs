//! Database schema definitions

/// SQL to create all tables
pub const SCHEMA: &str = r#"
-- Core entities
CREATE TABLE IF NOT EXISTS hosts (
    id TEXT PRIMARY KEY,
    address TEXT NOT NULL,
    hostname TEXT,
    discovered_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS ports (
    id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL REFERENCES hosts(id),
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL DEFAULT 'tcp',
    service TEXT,
    state TEXT NOT NULL DEFAULT 'open',
    discovered_at TEXT NOT NULL,
    UNIQUE(host_id, port, protocol)
);

CREATE TABLE IF NOT EXISTS technologies (
    id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL REFERENCES hosts(id),
    name TEXT NOT NULL,
    version TEXT,
    category TEXT,
    discovered_at TEXT NOT NULL
);

-- Findings
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id TEXT PRIMARY KEY,
    host_id TEXT REFERENCES hosts(id),
    vuln_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    evidence TEXT,
    status TEXT NOT NULL DEFAULT 'potential',
    cwe TEXT,
    cvss REAL,
    asset TEXT,
    remediation TEXT,
    discovered_by TEXT NOT NULL,
    verified_by TEXT,
    discovered_at TEXT NOT NULL,
    verified_at TEXT
);

CREATE TABLE IF NOT EXISTS code_findings (
    id TEXT PRIMARY KEY,
    file_path TEXT NOT NULL,
    line_number INTEGER,
    severity TEXT NOT NULL,
    finding_type TEXT NOT NULL,
    cve_id TEXT,
    cwe_id TEXT,
    title TEXT NOT NULL,
    description TEXT,
    snippet TEXT,
    tool TEXT NOT NULL,
    package_name TEXT,
    package_version TEXT,
    fixed_version TEXT,
    discovered_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS code_endpoints (
    id TEXT PRIMARY KEY,
    route TEXT NOT NULL,
    method TEXT,
    handler_file TEXT NOT NULL,
    handler_line INTEGER,
    parameters TEXT NOT NULL DEFAULT '[]',
    auth_required INTEGER,
    notes TEXT
);

-- Agent state
CREATE TABLE IF NOT EXISTS agent_tasks (
    id TEXT PRIMARY KEY,
    agent TEXT NOT NULL,
    task TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    result TEXT,
    error TEXT,
    started_at TEXT,
    completed_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS agent_messages (
    id TEXT PRIMARY KEY,
    from_agent TEXT NOT NULL,
    to_agent TEXT NOT NULL,
    content TEXT NOT NULL,
    timestamp TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS tool_executions (
    id TEXT PRIMARY KEY,
    agent TEXT NOT NULL,
    tool TEXT NOT NULL,
    args TEXT NOT NULL,
    output TEXT,
    exit_code INTEGER,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Metrics
CREATE TABLE IF NOT EXISTS metrics (
    id TEXT PRIMARY KEY,
    tool_calls INTEGER NOT NULL DEFAULT 0,
    tokens_input INTEGER NOT NULL DEFAULT 0,
    tokens_cached INTEGER NOT NULL DEFAULT 0,
    tokens_output INTEGER NOT NULL DEFAULT 0,
    estimated_cost_usd REAL NOT NULL DEFAULT 0.0,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Session metadata
CREATE TABLE IF NOT EXISTS session_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Create indexes for common queries
CREATE INDEX IF NOT EXISTS idx_ports_host ON ports(host_id);
CREATE INDEX IF NOT EXISTS idx_technologies_host ON technologies(host_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_host ON vulnerabilities(host_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_status ON vulnerabilities(status);
CREATE INDEX IF NOT EXISTS idx_code_findings_severity ON code_findings(severity);
CREATE INDEX IF NOT EXISTS idx_code_findings_type ON code_findings(finding_type);
CREATE INDEX IF NOT EXISTS idx_code_endpoints_route ON code_endpoints(route);
CREATE INDEX IF NOT EXISTS idx_agent_tasks_agent ON agent_tasks(agent);
CREATE INDEX IF NOT EXISTS idx_agent_tasks_status ON agent_tasks(status);
CREATE INDEX IF NOT EXISTS idx_tool_executions_agent ON tool_executions(agent);
"#;
