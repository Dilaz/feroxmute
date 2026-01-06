//! Data models for feroxmute state

#![allow(clippy::unwrap_used)]

use chrono::{DateTime, Utc};
use rusqlite::{Connection, Row, params};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::Result;

/// Severity level for vulnerabilities
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Critical => write!(f, "critical"),
            Severity::High => write!(f, "high"),
            Severity::Medium => write!(f, "medium"),
            Severity::Low => write!(f, "low"),
            Severity::Info => write!(f, "info"),
        }
    }
}

impl std::str::FromStr for Severity {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "critical" => Ok(Severity::Critical),
            "high" => Ok(Severity::High),
            "medium" => Ok(Severity::Medium),
            "low" => Ok(Severity::Low),
            "info" => Ok(Severity::Info),
            _ => Err(format!("Unknown severity: {}", s)),
        }
    }
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Info => "info",
        }
    }

    pub fn parse_opt(s: &str) -> Option<Self> {
        s.parse().ok()
    }
}

/// Vulnerability status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VulnStatus {
    Potential,
    Verified,
    Exploited,
    FalsePositive,
}

impl std::fmt::Display for VulnStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VulnStatus::Potential => write!(f, "potential"),
            VulnStatus::Verified => write!(f, "verified"),
            VulnStatus::Exploited => write!(f, "exploited"),
            VulnStatus::FalsePositive => write!(f, "false_positive"),
        }
    }
}

impl std::str::FromStr for VulnStatus {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "potential" => Ok(VulnStatus::Potential),
            "verified" => Ok(VulnStatus::Verified),
            "exploited" => Ok(VulnStatus::Exploited),
            "false_positive" => Ok(VulnStatus::FalsePositive),
            _ => Err(format!("Unknown status: {}", s)),
        }
    }
}

/// A discovered host
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Host {
    pub id: String,
    pub address: String,
    pub hostname: Option<String>,
    pub discovered_at: DateTime<Utc>,
}

impl Host {
    /// Create a new host
    pub fn new(address: impl Into<String>, hostname: Option<String>) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            address: address.into(),
            hostname,
            discovered_at: Utc::now(),
        }
    }

    /// Insert host into database
    pub fn insert(&self, conn: &Connection) -> Result<()> {
        conn.execute(
            "INSERT INTO hosts (id, address, hostname, discovered_at) VALUES (?1, ?2, ?3, ?4)",
            params![
                self.id,
                self.address,
                self.hostname,
                self.discovered_at.to_rfc3339()
            ],
        )?;
        Ok(())
    }

    /// Find host by address
    pub fn find_by_address(conn: &Connection, address: &str) -> Result<Option<Self>> {
        let mut stmt = conn
            .prepare("SELECT id, address, hostname, discovered_at FROM hosts WHERE address = ?1")?;

        let mut rows = stmt.query([address])?;
        if let Some(row) = rows.next()? {
            Ok(Some(Self::from_row(row)?))
        } else {
            Ok(None)
        }
    }

    /// Get all hosts
    pub fn all(conn: &Connection) -> Result<Vec<Self>> {
        let mut stmt = conn.prepare(
            "SELECT id, address, hostname, discovered_at FROM hosts ORDER BY discovered_at",
        )?;

        let hosts = stmt
            .query_map([], |row| Ok(Self::from_row(row).unwrap()))?
            .filter_map(|r| r.ok())
            .collect();

        Ok(hosts)
    }

    fn from_row(row: &Row) -> Result<Self> {
        let discovered_at_str: String = row.get(3)?;
        let discovered_at = DateTime::parse_from_rfc3339(&discovered_at_str)
            .map_err(|e| crate::Error::Config(e.to_string()))?
            .with_timezone(&Utc);

        Ok(Self {
            id: row.get(0)?,
            address: row.get(1)?,
            hostname: row.get(2)?,
            discovered_at,
        })
    }
}

/// A discovered port on a host
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Port {
    pub id: String,
    pub host_id: String,
    pub port: u16,
    pub protocol: String,
    pub service: Option<String>,
    pub state: String,
    pub discovered_at: DateTime<Utc>,
}

impl Port {
    /// Create a new port
    pub fn new(host_id: impl Into<String>, port: u16, protocol: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            host_id: host_id.into(),
            port,
            protocol: protocol.into(),
            service: None,
            state: "open".to_string(),
            discovered_at: Utc::now(),
        }
    }

    /// Set service name
    pub fn with_service(mut self, service: impl Into<String>) -> Self {
        self.service = Some(service.into());
        self
    }

    /// Insert port into database
    pub fn insert(&self, conn: &Connection) -> Result<()> {
        conn.execute(
            "INSERT INTO ports (id, host_id, port, protocol, service, state, discovered_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                self.id,
                self.host_id,
                self.port,
                self.protocol,
                self.service,
                self.state,
                self.discovered_at.to_rfc3339()
            ],
        )?;
        Ok(())
    }

    /// Get all ports for a host
    pub fn for_host(conn: &Connection, host_id: &str) -> Result<Vec<Self>> {
        let mut stmt = conn.prepare(
            "SELECT id, host_id, port, protocol, service, state, discovered_at
             FROM ports WHERE host_id = ?1 ORDER BY port",
        )?;

        let ports = stmt
            .query_map([host_id], |row| {
                let discovered_at_str: String = row.get(6)?;
                let discovered_at = DateTime::parse_from_rfc3339(&discovered_at_str)
                    .unwrap()
                    .with_timezone(&Utc);

                Ok(Self {
                    id: row.get(0)?,
                    host_id: row.get(1)?,
                    port: row.get(2)?,
                    protocol: row.get(3)?,
                    service: row.get(4)?,
                    state: row.get(5)?,
                    discovered_at,
                })
            })?
            .filter_map(|r| r.ok())
            .collect();

        Ok(ports)
    }
}

/// A discovered vulnerability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub id: String,
    pub host_id: Option<String>,
    pub vuln_type: String,
    pub severity: Severity,
    pub title: String,
    pub description: Option<String>,
    pub evidence: Option<String>,
    pub status: VulnStatus,
    pub cwe: Option<String>,
    pub cvss: Option<f64>,
    pub asset: Option<String>,
    pub remediation: Option<String>,
    pub discovered_by: String,
    pub verified_by: Option<String>,
    pub discovered_at: DateTime<Utc>,
    pub verified_at: Option<DateTime<Utc>>,
}

impl Vulnerability {
    /// Create a new vulnerability
    pub fn new(
        title: impl Into<String>,
        vuln_type: impl Into<String>,
        severity: Severity,
        discovered_by: impl Into<String>,
    ) -> Self {
        Self {
            id: format!(
                "VULN-{}",
                Uuid::new_v4()
                    .to_string()
                    .split('-')
                    .next()
                    .unwrap()
                    .to_uppercase()
            ),
            host_id: None,
            vuln_type: vuln_type.into(),
            severity,
            title: title.into(),
            description: None,
            evidence: None,
            status: VulnStatus::Potential,
            cwe: None,
            cvss: None,
            asset: None,
            remediation: None,
            discovered_by: discovered_by.into(),
            verified_by: None,
            discovered_at: Utc::now(),
            verified_at: None,
        }
    }

    /// Builder methods
    pub fn with_host(mut self, host_id: impl Into<String>) -> Self {
        self.host_id = Some(host_id.into());
        self
    }

    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    pub fn with_evidence(mut self, evidence: impl Into<String>) -> Self {
        self.evidence = Some(evidence.into());
        self
    }

    pub fn with_asset(mut self, asset: impl Into<String>) -> Self {
        self.asset = Some(asset.into());
        self
    }

    pub fn with_cwe(mut self, cwe: impl Into<String>) -> Self {
        self.cwe = Some(cwe.into());
        self
    }

    pub fn with_cvss(mut self, cvss: f64) -> Self {
        self.cvss = Some(cvss);
        self
    }

    pub fn with_remediation(mut self, remediation: impl Into<String>) -> Self {
        self.remediation = Some(remediation.into());
        self
    }

    /// Insert vulnerability into database
    pub fn insert(&self, conn: &Connection) -> Result<()> {
        conn.execute(
            "INSERT INTO vulnerabilities
             (id, host_id, vuln_type, severity, title, description, evidence, status,
              cwe, cvss, asset, remediation, discovered_by, verified_by, discovered_at, verified_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            params![
                self.id,
                self.host_id,
                self.vuln_type,
                self.severity.to_string(),
                self.title,
                self.description,
                self.evidence,
                self.status.to_string(),
                self.cwe,
                self.cvss,
                self.asset,
                self.remediation,
                self.discovered_by,
                self.verified_by,
                self.discovered_at.to_rfc3339(),
                self.verified_at.map(|dt| dt.to_rfc3339()),
            ],
        )?;
        Ok(())
    }

    /// Mark vulnerability as verified
    pub fn verify(&mut self, conn: &Connection, verified_by: impl Into<String>) -> Result<()> {
        self.status = VulnStatus::Verified;
        self.verified_by = Some(verified_by.into());
        self.verified_at = Some(Utc::now());

        conn.execute(
            "UPDATE vulnerabilities SET status = ?1, verified_by = ?2, verified_at = ?3 WHERE id = ?4",
            params![
                self.status.to_string(),
                self.verified_by,
                self.verified_at.map(|dt| dt.to_rfc3339()),
                self.id
            ],
        )?;
        Ok(())
    }

    /// Get all vulnerabilities
    pub fn all(conn: &Connection) -> Result<Vec<Self>> {
        let mut stmt = conn.prepare(
            "SELECT id, host_id, vuln_type, severity, title, description, evidence, status,
                    cwe, cvss, asset, remediation, discovered_by, verified_by, discovered_at, verified_at
             FROM vulnerabilities ORDER BY
                CASE severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    ELSE 5
                END"
        )?;

        let vulns = stmt
            .query_map([], |row| Ok(Self::from_row(row)))?
            .filter_map(|r| r.ok())
            .collect();

        Ok(vulns)
    }

    /// Count vulnerabilities by status
    pub fn count_by_status(conn: &Connection) -> Result<VulnCounts> {
        let mut counts = VulnCounts::default();

        let mut stmt =
            conn.prepare("SELECT status, COUNT(*) FROM vulnerabilities GROUP BY status")?;

        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let status: String = row.get(0)?;
            let count: i64 = row.get(1)?;

            match status.as_str() {
                "potential" => counts.potential = count as u32,
                "verified" => counts.verified = count as u32,
                "exploited" => counts.exploited = count as u32,
                _ => {}
            }
        }

        counts.total = counts.potential + counts.verified + counts.exploited;
        Ok(counts)
    }

    fn from_row(row: &Row) -> Self {
        let severity_str: String = row.get(3).unwrap();
        let status_str: String = row.get(7).unwrap();
        let discovered_at_str: String = row.get(14).unwrap();
        let verified_at_str: Option<String> = row.get(15).unwrap();

        Self {
            id: row.get(0).unwrap(),
            host_id: row.get(1).unwrap(),
            vuln_type: row.get(2).unwrap(),
            severity: severity_str.parse().unwrap(),
            title: row.get(4).unwrap(),
            description: row.get(5).unwrap(),
            evidence: row.get(6).unwrap(),
            status: status_str.parse().unwrap(),
            cwe: row.get(8).unwrap(),
            cvss: row.get(9).unwrap(),
            asset: row.get(10).unwrap(),
            remediation: row.get(11).unwrap(),
            discovered_by: row.get(12).unwrap(),
            verified_by: row.get(13).unwrap(),
            discovered_at: DateTime::parse_from_rfc3339(&discovered_at_str)
                .unwrap()
                .with_timezone(&Utc),
            verified_at: verified_at_str.map(|s| {
                DateTime::parse_from_rfc3339(&s)
                    .unwrap()
                    .with_timezone(&Utc)
            }),
        }
    }
}

/// Vulnerability counts by status
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VulnCounts {
    pub total: u32,
    pub potential: u32,
    pub verified: u32,
    pub exploited: u32,
}

/// Code finding type
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingType {
    Dependency,
    Sast,
    Secret,
}

impl FindingType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Dependency => "dependency",
            Self::Sast => "sast",
            Self::Secret => "secret",
        }
    }

    pub fn parse_opt(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "dependency" => Some(Self::Dependency),
            "sast" => Some(Self::Sast),
            "secret" => Some(Self::Secret),
            _ => None,
        }
    }
}

/// A code finding from static analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeFinding {
    pub id: String,
    pub file_path: String,
    pub line_number: Option<u32>,
    pub severity: Severity,
    pub finding_type: FindingType,
    pub cve_id: Option<String>,
    pub cwe_id: Option<String>,
    pub title: String,
    pub description: Option<String>,
    pub snippet: Option<String>,
    pub tool: String,
    pub package_name: Option<String>,
    pub package_version: Option<String>,
    pub fixed_version: Option<String>,
    pub discovered_at: DateTime<Utc>,
}

impl CodeFinding {
    pub fn new(
        file_path: impl Into<String>,
        severity: Severity,
        finding_type: FindingType,
        title: impl Into<String>,
        tool: impl Into<String>,
    ) -> Self {
        Self {
            id: format!("CODE-{}", &Uuid::new_v4().to_string()[..8]),
            file_path: file_path.into(),
            line_number: None,
            severity,
            finding_type,
            cve_id: None,
            cwe_id: None,
            title: title.into(),
            description: None,
            snippet: None,
            tool: tool.into(),
            package_name: None,
            package_version: None,
            fixed_version: None,
            discovered_at: Utc::now(),
        }
    }

    pub fn with_line(mut self, line: u32) -> Self {
        self.line_number = Some(line);
        self
    }

    pub fn with_cve(mut self, cve: impl Into<String>) -> Self {
        self.cve_id = Some(cve.into());
        self
    }

    pub fn with_cwe(mut self, cwe: impl Into<String>) -> Self {
        self.cwe_id = Some(cwe.into());
        self
    }

    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    pub fn with_snippet(mut self, snippet: impl Into<String>) -> Self {
        self.snippet = Some(snippet.into());
        self
    }

    pub fn with_package(mut self, name: impl Into<String>, version: impl Into<String>) -> Self {
        self.package_name = Some(name.into());
        self.package_version = Some(version.into());
        self
    }

    pub fn with_fixed_version(mut self, version: impl Into<String>) -> Self {
        self.fixed_version = Some(version.into());
        self
    }

    pub fn insert(&self, conn: &Connection) -> Result<()> {
        conn.execute(
            "INSERT INTO code_findings (id, file_path, line_number, severity, finding_type, cve_id, cwe_id, title, description, snippet, tool, package_name, package_version, fixed_version, discovered_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
            params![
                self.id,
                self.file_path,
                self.line_number,
                self.severity.as_str(),
                self.finding_type.as_str(),
                self.cve_id,
                self.cwe_id,
                self.title,
                self.description,
                self.snippet,
                self.tool,
                self.package_name,
                self.package_version,
                self.fixed_version,
                self.discovered_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn all(conn: &Connection) -> Result<Vec<Self>> {
        let mut stmt = conn.prepare(
            "SELECT id, file_path, line_number, severity, finding_type, cve_id, cwe_id, title, description, snippet, tool, package_name, package_version, fixed_version, discovered_at FROM code_findings ORDER BY discovered_at DESC"
        )?;
        let findings = stmt
            .query_map([], |row| {
                Ok(Self {
                    id: row.get(0)?,
                    file_path: row.get(1)?,
                    line_number: row.get(2)?,
                    severity: Severity::parse_opt(&row.get::<_, String>(3)?)
                        .unwrap_or(Severity::Info),
                    finding_type: FindingType::parse_opt(&row.get::<_, String>(4)?)
                        .unwrap_or(FindingType::Sast),
                    cve_id: row.get(5)?,
                    cwe_id: row.get(6)?,
                    title: row.get(7)?,
                    description: row.get(8)?,
                    snippet: row.get(9)?,
                    tool: row.get(10)?,
                    package_name: row.get(11)?,
                    package_version: row.get(12)?,
                    fixed_version: row.get(13)?,
                    discovered_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(14)?)
                        .map(|dt| dt.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now()),
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(findings)
    }

    pub fn count_by_severity(
        conn: &Connection,
    ) -> Result<std::collections::HashMap<Severity, u32>> {
        let mut stmt =
            conn.prepare("SELECT severity, COUNT(*) FROM code_findings GROUP BY severity")?;
        let mut counts = std::collections::HashMap::new();
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, u32>(1)?))
        })?;
        for row in rows {
            let (sev_str, count) = row?;
            if let Some(sev) = Severity::parse_opt(&sev_str) {
                counts.insert(sev, count);
            }
        }
        Ok(counts)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::state::run_migrations;

    fn setup_db() -> Connection {
        let conn = Connection::open_in_memory().expect("should open in-memory db");
        run_migrations(&conn).expect("migrations should succeed");
        conn
    }

    #[test]
    fn test_host_crud() {
        let conn = setup_db();

        let host = Host::new("192.168.1.1", Some("example.com".to_string()));
        host.insert(&conn).expect("should insert host");

        let found = Host::find_by_address(&conn, "192.168.1.1").expect("should find host");
        assert!(found.is_some());
        assert_eq!(
            found.expect("host should exist").hostname,
            Some("example.com".to_string())
        );

        let all = Host::all(&conn).expect("should get all hosts");
        assert_eq!(all.len(), 1);
    }

    #[test]
    fn test_port_crud() {
        let conn = setup_db();

        let host = Host::new("192.168.1.1", None);
        host.insert(&conn).expect("should insert host");

        let port = Port::new(&host.id, 80, "tcp").with_service("http");
        port.insert(&conn).expect("should insert port 80");

        let port2 = Port::new(&host.id, 443, "tcp").with_service("https");
        port2.insert(&conn).expect("should insert port 443");

        let ports = Port::for_host(&conn, &host.id).expect("should get ports for host");
        assert_eq!(ports.len(), 2);
        assert_eq!(ports.first().expect("should have first port").port, 80);
        assert_eq!(ports.get(1).expect("should have second port").port, 443);
    }

    #[test]
    fn test_vulnerability_crud() {
        let conn = setup_db();

        let mut vuln = Vulnerability::new(
            "SQL Injection in login",
            "sqli",
            Severity::Critical,
            "web_scanner",
        )
        .with_asset("https://example.com/login")
        .with_cwe("CWE-89")
        .with_cvss(9.8);

        vuln.insert(&conn).expect("should insert vulnerability");

        let vulns = Vulnerability::all(&conn).expect("should get all vulnerabilities");
        assert_eq!(vulns.len(), 1);
        let first_vuln = vulns.first().expect("should have one vulnerability");
        assert_eq!(first_vuln.severity, Severity::Critical);
        assert_eq!(first_vuln.status, VulnStatus::Potential);

        // Verify the vulnerability
        vuln.verify(&conn, "exploit_agent")
            .expect("should verify vulnerability");

        let counts =
            Vulnerability::count_by_status(&conn).expect("should count vulnerabilities by status");
        assert_eq!(counts.verified, 1);
        assert_eq!(counts.potential, 0);
    }

    #[test]
    fn test_code_finding_insert_and_retrieve() {
        let conn = setup_db();
        let finding = CodeFinding::new(
            "src/main.rs",
            Severity::High,
            FindingType::Sast,
            "SQL Injection",
            "semgrep",
        )
        .with_line(42)
        .with_cwe("CWE-89");

        finding.insert(&conn).expect("should insert code finding");

        let findings = CodeFinding::all(&conn).expect("should get all code findings");
        assert_eq!(findings.len(), 1);
        let first_finding = findings.first().expect("should have one finding");
        assert_eq!(first_finding.title, "SQL Injection");
        assert_eq!(first_finding.line_number, Some(42));
        assert_eq!(first_finding.cwe_id, Some("CWE-89".to_string()));
    }

    #[test]
    fn test_dependency_finding() {
        let conn = setup_db();
        let finding = CodeFinding::new(
            "Cargo.toml",
            Severity::Critical,
            FindingType::Dependency,
            "CVE-2024-1234",
            "grype",
        )
        .with_cve("CVE-2024-1234")
        .with_package("lodash", "4.17.20")
        .with_fixed_version("4.17.21");

        finding
            .insert(&conn)
            .expect("should insert dependency finding");

        let findings = CodeFinding::all(&conn).expect("should get all findings");
        assert_eq!(findings.len(), 1);
        let first_finding = findings.first().expect("should have one finding");
        assert_eq!(first_finding.package_name, Some("lodash".to_string()));
        assert_eq!(first_finding.package_version, Some("4.17.20".to_string()));
        assert_eq!(first_finding.fixed_version, Some("4.17.21".to_string()));
        assert_eq!(first_finding.finding_type, FindingType::Dependency);
    }

    #[test]
    fn test_secret_finding() {
        let conn = setup_db();
        let finding = CodeFinding::new(
            "config/.env",
            Severity::High,
            FindingType::Secret,
            "AWS Access Key",
            "gitleaks",
        )
        .with_line(10)
        .with_description("Hardcoded AWS credentials detected")
        .with_snippet("AWS_ACCESS_KEY=AKIA****");

        finding.insert(&conn).expect("should insert secret finding");

        let findings = CodeFinding::all(&conn).expect("should get all findings");
        assert_eq!(findings.len(), 1);
        let first_finding = findings.first().expect("should have one finding");
        assert_eq!(first_finding.finding_type, FindingType::Secret);
        assert_eq!(first_finding.severity, Severity::High);
    }

    #[test]
    fn test_count_by_severity() {
        let conn = setup_db();

        // Insert findings with different severities
        CodeFinding::new(
            "file1.rs",
            Severity::Critical,
            FindingType::Sast,
            "Issue 1",
            "tool",
        )
        .insert(&conn)
        .expect("should insert finding 1");
        CodeFinding::new(
            "file2.rs",
            Severity::Critical,
            FindingType::Sast,
            "Issue 2",
            "tool",
        )
        .insert(&conn)
        .expect("should insert finding 2");
        CodeFinding::new(
            "file3.rs",
            Severity::High,
            FindingType::Sast,
            "Issue 3",
            "tool",
        )
        .insert(&conn)
        .expect("should insert finding 3");
        CodeFinding::new(
            "file4.rs",
            Severity::Medium,
            FindingType::Sast,
            "Issue 4",
            "tool",
        )
        .insert(&conn)
        .expect("should insert finding 4");

        let counts = CodeFinding::count_by_severity(&conn).expect("should count by severity");
        assert_eq!(counts.get(&Severity::Critical), Some(&2));
        assert_eq!(counts.get(&Severity::High), Some(&1));
        assert_eq!(counts.get(&Severity::Medium), Some(&1));
        assert_eq!(counts.get(&Severity::Low), None);
    }

    #[test]
    fn test_code_endpoint_insert_and_retrieve() {
        let conn = setup_db();
        let endpoint = CodeEndpoint::new("/api/users", "src/routes/users.rs")
            .with_method("GET")
            .with_line(47)
            .with_parameters(vec!["id".to_string(), "limit".to_string()])
            .with_auth(true);

        endpoint.insert(&conn).expect("should insert endpoint");

        let endpoints = CodeEndpoint::all(&conn).expect("should get all endpoints");
        assert_eq!(endpoints.len(), 1);
        let first_endpoint = endpoints.first().expect("should have one endpoint");
        assert_eq!(first_endpoint.route, "/api/users");
        assert_eq!(first_endpoint.method, Some("GET".to_string()));
        assert_eq!(first_endpoint.handler_line, Some(47));
        assert_eq!(first_endpoint.parameters.len(), 2);
        assert_eq!(first_endpoint.auth_required, Some(true));
    }

    #[test]
    fn test_code_endpoint_find_by_route() {
        let conn = setup_db();
        let endpoint1 = CodeEndpoint::new("/api/users", "src/routes/users.rs").with_method("GET");
        let endpoint2 = CodeEndpoint::new("/api/posts", "src/routes/posts.rs").with_method("POST");

        endpoint1.insert(&conn).expect("should insert endpoint 1");
        endpoint2.insert(&conn).expect("should insert endpoint 2");

        let found = CodeEndpoint::find_by_route(&conn, "/api/users").expect("should find by route");
        assert!(found.is_some());
        assert_eq!(
            found.expect("should have endpoint").handler_file,
            "src/routes/users.rs"
        );

        let not_found =
            CodeEndpoint::find_by_route(&conn, "/api/invalid").expect("should search for route");
        assert!(not_found.is_none());
    }

    #[test]
    fn test_code_endpoint_minimal() {
        let conn = setup_db();
        let endpoint = CodeEndpoint::new("/health", "src/main.rs");

        endpoint.insert(&conn).expect("should insert endpoint");

        let endpoints = CodeEndpoint::all(&conn).expect("should get all endpoints");
        assert_eq!(endpoints.len(), 1);
        let first_endpoint = endpoints.first().expect("should have one endpoint");
        assert_eq!(first_endpoint.route, "/health");
        assert_eq!(first_endpoint.method, None);
        assert_eq!(first_endpoint.handler_line, None);
        assert_eq!(first_endpoint.parameters.len(), 0);
        assert_eq!(first_endpoint.auth_required, None);
    }

    #[test]
    fn test_code_endpoint_with_multiple_parameters() {
        let conn = setup_db();
        let params = vec![
            "user_id".to_string(),
            "page".to_string(),
            "limit".to_string(),
            "sort_by".to_string(),
        ];
        let endpoint = CodeEndpoint::new("/api/search", "src/search.rs")
            .with_method("POST")
            .with_line(120)
            .with_parameters(params.clone())
            .with_auth(false);

        endpoint.insert(&conn).expect("should insert endpoint");

        let found = CodeEndpoint::find_by_route(&conn, "/api/search")
            .expect("should find by route")
            .expect("endpoint should exist");
        assert_eq!(found.parameters, params);
        assert_eq!(found.auth_required, Some(false));
        assert_eq!(found.handler_line, Some(120));
    }
}

/// A code endpoint extracted from source code
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeEndpoint {
    pub id: String,
    pub route: String,
    pub method: Option<String>,
    pub handler_file: String,
    pub handler_line: Option<u32>,
    pub parameters: Vec<String>,
    pub auth_required: Option<bool>,
    pub notes: Option<String>,
}

impl CodeEndpoint {
    pub fn new(route: impl Into<String>, handler_file: impl Into<String>) -> Self {
        Self {
            id: format!("EP-{}", &Uuid::new_v4().to_string()[..8]),
            route: route.into(),
            method: None,
            handler_file: handler_file.into(),
            handler_line: None,
            parameters: Vec::new(),
            auth_required: None,
            notes: None,
        }
    }

    pub fn with_method(mut self, method: impl Into<String>) -> Self {
        self.method = Some(method.into());
        self
    }

    pub fn with_line(mut self, line: u32) -> Self {
        self.handler_line = Some(line);
        self
    }

    pub fn with_parameters(mut self, params: Vec<String>) -> Self {
        self.parameters = params;
        self
    }

    pub fn with_auth(mut self, required: bool) -> Self {
        self.auth_required = Some(required);
        self
    }

    pub fn insert(&self, conn: &Connection) -> Result<()> {
        let params_json =
            serde_json::to_string(&self.parameters).unwrap_or_else(|_| "[]".to_string());
        conn.execute(
            "INSERT INTO code_endpoints (id, route, method, handler_file, handler_line, parameters, auth_required, notes)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                self.id,
                self.route,
                self.method,
                self.handler_file,
                self.handler_line,
                params_json,
                self.auth_required,
                self.notes,
            ],
        )?;
        Ok(())
    }

    pub fn all(conn: &Connection) -> Result<Vec<Self>> {
        let mut stmt = conn.prepare(
            "SELECT id, route, method, handler_file, handler_line, parameters, auth_required, notes FROM code_endpoints"
        )?;
        let endpoints = stmt
            .query_map([], |row| {
                let params_str: String = row.get(5)?;
                let parameters: Vec<String> = serde_json::from_str(&params_str).unwrap_or_default();
                Ok(Self {
                    id: row.get(0)?,
                    route: row.get(1)?,
                    method: row.get(2)?,
                    handler_file: row.get(3)?,
                    handler_line: row.get(4)?,
                    parameters,
                    auth_required: row.get(6)?,
                    notes: row.get(7)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(endpoints)
    }

    pub fn find_by_route(conn: &Connection, route: &str) -> Result<Option<Self>> {
        let mut stmt = conn.prepare(
            "SELECT id, route, method, handler_file, handler_line, parameters, auth_required, notes FROM code_endpoints WHERE route = ?1"
        )?;
        let mut rows = stmt.query(params![route])?;
        if let Some(row) = rows.next()? {
            let params_str: String = row.get(5)?;
            let parameters: Vec<String> = serde_json::from_str(&params_str).unwrap_or_default();
            Ok(Some(Self {
                id: row.get(0)?,
                route: row.get(1)?,
                method: row.get(2)?,
                handler_file: row.get(3)?,
                handler_line: row.get(4)?,
                parameters,
                auth_required: row.get(6)?,
                notes: row.get(7)?,
            }))
        } else {
            Ok(None)
        }
    }
}
