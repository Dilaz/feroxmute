//! Orchestrator agent for managing engagement phases

use serde::{Deserialize, Serialize};

use super::Prompts;

/// Engagement phase
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EngagementPhase {
    /// Initial setup and scope validation
    #[default]
    Setup,
    /// Static analysis of source code
    StaticAnalysis,
    /// Asset discovery and enumeration
    Reconnaissance,
    /// Vulnerability scanning
    Scanning,
    /// LLM penetration testing
    LlmPentest,
    /// Exploitation (if authorized)
    Exploitation,
    /// Report generation
    Reporting,
    /// Engagement complete
    Complete,
}

impl EngagementPhase {
    /// Get the next phase in the engagement workflow
    pub fn next(&self) -> Option<Self> {
        match self {
            Self::Setup => Some(Self::StaticAnalysis),
            Self::StaticAnalysis => Some(Self::Reconnaissance),
            Self::Reconnaissance => Some(Self::Scanning),
            Self::Scanning => Some(Self::LlmPentest),
            Self::LlmPentest => Some(Self::Exploitation),
            Self::Exploitation => Some(Self::Reporting),
            Self::Reporting => Some(Self::Complete),
            Self::Complete => None,
        }
    }

    /// Get the next phase, optionally skipping StaticAnalysis if no source target
    pub fn next_with_config(&self, has_source_target: bool) -> Option<Self> {
        match self {
            Self::Setup => {
                if has_source_target {
                    Some(Self::StaticAnalysis)
                } else {
                    Some(Self::Reconnaissance)
                }
            }
            Self::StaticAnalysis => Some(Self::Reconnaissance),
            Self::Reconnaissance => Some(Self::Scanning),
            Self::Scanning => Some(Self::LlmPentest),
            Self::LlmPentest => Some(Self::Exploitation),
            Self::Exploitation => Some(Self::Reporting),
            Self::Reporting => Some(Self::Complete),
            Self::Complete => None,
        }
    }
}

/// Orchestrator agent that coordinates the engagement
pub struct OrchestratorAgent {
    prompts: Prompts,
    has_source_target: bool,
}

impl OrchestratorAgent {
    /// Create a new orchestrator agent
    pub fn new() -> Self {
        Self {
            prompts: Prompts::default(),
            has_source_target: false,
        }
    }

    /// Create with custom prompts
    pub fn with_prompts(prompts: Prompts) -> Self {
        Self {
            prompts,
            has_source_target: false,
        }
    }

    /// Enable SAST support (source target available)
    pub fn with_source_target(mut self) -> Self {
        self.has_source_target = true;
        self
    }

    /// Check if source target is available
    pub fn has_source_target(&self) -> bool {
        self.has_source_target
    }

    /// System prompt for the orchestrator (used by the rig completion loop).
    pub fn system_prompt(&self) -> &str {
        self.prompts.get("orchestrator").unwrap_or("")
    }
}

impl Default for OrchestratorAgent {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn test_orchestrator_creation() {
        let agent = OrchestratorAgent::new();
        assert!(!agent.has_source_target());
        assert!(!agent.system_prompt().is_empty());
    }

    #[test]
    fn test_phase_progression() {
        assert_eq!(
            EngagementPhase::Setup.next(),
            Some(EngagementPhase::StaticAnalysis)
        );
        assert_eq!(
            EngagementPhase::Reconnaissance.next(),
            Some(EngagementPhase::Scanning)
        );
        assert_eq!(EngagementPhase::Complete.next(), None);
    }

    #[test]
    fn test_orchestrator_with_source_target() {
        let agent = OrchestratorAgent::new().with_source_target();
        assert!(agent.has_source_target());
    }
}
