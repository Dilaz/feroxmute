//! Data models for feroxmute state

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, Row};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::Result;

/// Severity level for vulnerabilities
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
            params![self.id, self.address, self.hostname, self.discovered_at.to_rfc3339()],
        )?;
        Ok(())
    }

    /// Find host by address
    pub fn find_by_address(conn: &Connection, address: &str) -> Result<Option<Self>> {
        let mut stmt = conn.prepare(
            "SELECT id, address, hostname, discovered_at FROM hosts WHERE address = ?1"
        )?;

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
            "SELECT id, address, hostname, discovered_at FROM hosts ORDER BY discovered_at"
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
             FROM ports WHERE host_id = ?1 ORDER BY port"
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
            id: format!("VULN-{}", Uuid::new_v4().to_string().split('-').next().unwrap().to_uppercase()),
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

        let mut stmt = conn.prepare(
            "SELECT status, COUNT(*) FROM vulnerabilities GROUP BY status"
        )?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::run_migrations;

    fn setup_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        run_migrations(&conn).unwrap();
        conn
    }

    #[test]
    fn test_host_crud() {
        let conn = setup_db();

        let host = Host::new("192.168.1.1", Some("example.com".to_string()));
        host.insert(&conn).unwrap();

        let found = Host::find_by_address(&conn, "192.168.1.1").unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().hostname, Some("example.com".to_string()));

        let all = Host::all(&conn).unwrap();
        assert_eq!(all.len(), 1);
    }

    #[test]
    fn test_port_crud() {
        let conn = setup_db();

        let host = Host::new("192.168.1.1", None);
        host.insert(&conn).unwrap();

        let port = Port::new(&host.id, 80, "tcp").with_service("http");
        port.insert(&conn).unwrap();

        let port2 = Port::new(&host.id, 443, "tcp").with_service("https");
        port2.insert(&conn).unwrap();

        let ports = Port::for_host(&conn, &host.id).unwrap();
        assert_eq!(ports.len(), 2);
        assert_eq!(ports[0].port, 80);
        assert_eq!(ports[1].port, 443);
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

        vuln.insert(&conn).unwrap();

        let vulns = Vulnerability::all(&conn).unwrap();
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0].severity, Severity::Critical);
        assert_eq!(vulns[0].status, VulnStatus::Potential);

        // Verify the vulnerability
        vuln.verify(&conn, "exploit_agent").unwrap();

        let counts = Vulnerability::count_by_status(&conn).unwrap();
        assert_eq!(counts.verified, 1);
        assert_eq!(counts.potential, 0);
    }
}
