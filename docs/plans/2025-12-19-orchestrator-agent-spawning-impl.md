# Orchestrator Agent Spawning Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Restructure agent architecture so orchestrator dynamically spawns child agents via tool calls with async concurrent execution.

**Architecture:** New `AgentRegistry` manages spawned agents and their results via channels. Orchestrator uses `spawn_agent`, `wait_for_agent`, `wait_for_any` tools instead of holding child agents as struct fields. TUI feed gets horizontal scrolling.

**Tech Stack:** Rust, tokio (async), mpsc channels, ratatui (TUI)

---

## Task 1: Create AgentRegistry Module

**Files:**
- Create: `feroxmute-core/src/agents/registry.rs`
- Modify: `feroxmute-core/src/agents/mod.rs`

**Step 1: Write the failing test for AgentRegistry**

Add to `feroxmute-core/src/agents/registry.rs`:

```rust
//! Agent registry for managing spawned agents

use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::AgentStatus;

/// Result from a completed agent
#[derive(Debug, Clone)]
pub struct AgentResult {
    pub name: String,
    pub agent_type: String,
    pub success: bool,
    pub output: String,
    pub duration: Duration,
}

/// A spawned agent being tracked by the registry
pub struct SpawnedAgent {
    pub name: String,
    pub agent_type: String,
    pub instructions: String,
    pub status: AgentStatus,
    pub spawned_at: Instant,
    pub handle: Option<JoinHandle<()>>,
}

/// Registry for managing spawned agents
pub struct AgentRegistry {
    agents: HashMap<String, SpawnedAgent>,
    result_tx: mpsc::Sender<AgentResult>,
    result_rx: mpsc::Receiver<AgentResult>,
    pending_results: Vec<AgentResult>,
}

impl AgentRegistry {
    /// Create a new agent registry
    pub fn new() -> Self {
        let (result_tx, result_rx) = mpsc::channel(32);
        Self {
            agents: HashMap::new(),
            result_tx,
            result_rx,
            pending_results: Vec::new(),
        }
    }

    /// Get the sender for agent results
    pub fn result_sender(&self) -> mpsc::Sender<AgentResult> {
        self.result_tx.clone()
    }

    /// Register a spawned agent
    pub fn register(
        &mut self,
        name: String,
        agent_type: String,
        instructions: String,
        handle: JoinHandle<()>,
    ) {
        let agent = SpawnedAgent {
            name: name.clone(),
            agent_type,
            instructions,
            status: AgentStatus::Running,
            spawned_at: Instant::now(),
            handle: Some(handle),
        };
        self.agents.insert(name, agent);
    }

    /// Check if an agent with the given name exists
    pub fn has_agent(&self, name: &str) -> bool {
        self.agents.contains_key(name)
    }

    /// Get the status of all agents
    pub fn list_agents(&self) -> Vec<(&str, &str, AgentStatus)> {
        self.agents
            .values()
            .map(|a| (a.name.as_str(), a.agent_type.as_str(), a.status))
            .collect()
    }

    /// Get count of running agents
    pub fn running_count(&self) -> usize {
        self.agents
            .values()
            .filter(|a| a.status == AgentStatus::Running)
            .count()
    }
}

impl Default for AgentRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_creation() {
        let registry = AgentRegistry::new();
        assert_eq!(registry.running_count(), 0);
        assert!(registry.list_agents().is_empty());
    }

    #[test]
    fn test_has_agent() {
        let registry = AgentRegistry::new();
        assert!(!registry.has_agent("test-agent"));
    }
}
```

**Step 2: Run test to verify it compiles and passes**

Run: `cargo test -p feroxmute-core registry`

Expected: Tests pass (we're starting with basic struct creation)

**Step 3: Export registry module**

Modify `feroxmute-core/src/agents/mod.rs`, add after other module declarations:

```rust
mod registry;
pub use registry::{AgentRegistry, AgentResult, SpawnedAgent};
```

**Step 4: Run tests to verify export works**

Run: `cargo test -p feroxmute-core registry`

Expected: PASS

**Step 5: Commit**

```bash
git add feroxmute-core/src/agents/registry.rs feroxmute-core/src/agents/mod.rs
git commit -m "feat(agents): add AgentRegistry for managing spawned agents"
```

---

## Task 2: Add Wait Methods to AgentRegistry

**Files:**
- Modify: `feroxmute-core/src/agents/registry.rs`

**Step 1: Add wait_for_agent method with test**

Add to the `impl AgentRegistry` block in `registry.rs`:

```rust
    /// Wait for a specific agent to complete
    /// Returns None if agent doesn't exist, Some(result) when complete
    pub async fn wait_for_agent(&mut self, name: &str) -> Option<AgentResult> {
        if !self.agents.contains_key(name) {
            return None;
        }

        // Check pending results first
        if let Some(idx) = self.pending_results.iter().position(|r| r.name == name) {
            let result = self.pending_results.remove(idx);
            if let Some(agent) = self.agents.get_mut(name) {
                agent.status = if result.success {
                    AgentStatus::Completed
                } else {
                    AgentStatus::Failed
                };
            }
            return Some(result);
        }

        // Wait for results from channel
        while let Some(result) = self.result_rx.recv().await {
            if result.name == name {
                if let Some(agent) = self.agents.get_mut(name) {
                    agent.status = if result.success {
                        AgentStatus::Completed
                    } else {
                        AgentStatus::Failed
                    };
                }
                return Some(result);
            } else {
                // Store for later
                self.pending_results.push(result);
            }
        }

        None
    }

    /// Wait for any agent to complete
    /// Returns None if no agents are running
    pub async fn wait_for_any(&mut self) -> Option<AgentResult> {
        if self.running_count() == 0 && self.pending_results.is_empty() {
            return None;
        }

        // Check pending results first
        if !self.pending_results.is_empty() {
            let result = self.pending_results.remove(0);
            if let Some(agent) = self.agents.get_mut(&result.name) {
                agent.status = if result.success {
                    AgentStatus::Completed
                } else {
                    AgentStatus::Failed
                };
            }
            return Some(result);
        }

        // Wait for next result
        if let Some(result) = self.result_rx.recv().await {
            if let Some(agent) = self.agents.get_mut(&result.name) {
                agent.status = if result.success {
                    AgentStatus::Completed
                } else {
                    AgentStatus::Failed
                };
            }
            return Some(result);
        }

        None
    }
```

Add test:

```rust
    #[tokio::test]
    async fn test_wait_for_any_no_agents() {
        let mut registry = AgentRegistry::new();
        let result = registry.wait_for_any().await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_wait_for_agent_not_found() {
        let mut registry = AgentRegistry::new();
        let result = registry.wait_for_agent("nonexistent").await;
        assert!(result.is_none());
    }
```

**Step 2: Run tests**

Run: `cargo test -p feroxmute-core registry`

Expected: PASS

**Step 3: Commit**

```bash
git add feroxmute-core/src/agents/registry.rs
git commit -m "feat(agents): add wait_for_agent and wait_for_any to registry"
```

---

## Task 3: Refactor OrchestratorAgent - Remove Child Agent Fields

**Files:**
- Modify: `feroxmute-core/src/agents/orchestrator.rs`

**Step 1: Remove child agent imports and fields**

In `feroxmute-core/src/agents/orchestrator.rs`, update the imports at the top:

```rust
//! Orchestrator agent for managing engagement phases

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::providers::{CompletionRequest, Message, ToolDefinition};
use crate::{Error, Result};

use super::{Agent, AgentContext, AgentStatus, AgentTask, Prompts};
```

(Remove `ReconAgent, SastAgent, ScannerAgent` from the import)

**Step 2: Update OrchestratorAgent struct**

Replace the struct definition:

```rust
/// Orchestrator agent that coordinates the engagement
pub struct OrchestratorAgent {
    status: AgentStatus,
    thinking: Option<String>,
    prompts: Prompts,
    current_phase: EngagementPhase,
    has_source_target: bool,
    findings: Vec<String>,
}
```

**Step 3: Update constructors**

Replace `new()` and `with_prompts()`:

```rust
impl OrchestratorAgent {
    /// Create a new orchestrator agent
    pub fn new() -> Self {
        let prompts = Prompts::default();
        Self {
            status: AgentStatus::Idle,
            thinking: None,
            prompts,
            current_phase: EngagementPhase::Setup,
            has_source_target: false,
            findings: Vec::new(),
        }
    }

    /// Create with custom prompts
    pub fn with_prompts(prompts: Prompts) -> Self {
        Self {
            status: AgentStatus::Idle,
            thinking: None,
            prompts,
            current_phase: EngagementPhase::Setup,
            has_source_target: false,
            findings: Vec::new(),
        }
    }

    /// Enable SAST support (source target available)
    pub fn with_source_target(mut self) -> Self {
        self.has_source_target = true;
        self
    }

    /// Get the current engagement phase
    pub fn current_phase(&self) -> EngagementPhase {
        self.current_phase
    }

    /// Get all findings collected
    pub fn findings(&self) -> &[String] {
        &self.findings
    }

    /// Get prompts reference for spawning agents
    pub fn prompts(&self) -> &Prompts {
        &self.prompts
    }

    /// Check if source target is available
    pub fn has_source_target(&self) -> bool {
        self.has_source_target
    }
}
```

**Step 4: Run tests to check compilation**

Run: `cargo test -p feroxmute-core orchestrator`

Expected: Some tests may fail (we'll fix in next tasks), but should compile

**Step 5: Commit**

```bash
git add feroxmute-core/src/agents/orchestrator.rs
git commit -m "refactor(orchestrator): remove child agent struct fields"
```

---

## Task 4: Replace Orchestrator Tools with spawn/wait Tools

**Files:**
- Modify: `feroxmute-core/src/agents/orchestrator.rs`

**Step 1: Replace build_tools method**

Replace the entire `build_tools` method:

```rust
    /// Build tool definitions for the orchestrator
    fn build_tools(&self) -> Vec<ToolDefinition> {
        let mut tools = vec![
            ToolDefinition {
                name: "spawn_agent".to_string(),
                description: "Spawn a new agent to run a task in the background. Returns immediately.".to_string(),
                parameters: json!({
                    "type": "object",
                    "properties": {
                        "agent_type": {
                            "type": "string",
                            "enum": ["recon", "scanner", "report"],
                            "description": "Type of agent to spawn"
                        },
                        "name": {
                            "type": "string",
                            "description": "Unique name for this agent instance (e.g., 'subdomain-enum', 'port-scan')"
                        },
                        "instructions": {
                            "type": "string",
                            "description": "Task-specific instructions for the agent"
                        }
                    },
                    "required": ["agent_type", "name", "instructions"]
                }),
            },
            ToolDefinition {
                name: "wait_for_agent".to_string(),
                description: "Wait for a specific agent to complete and get its results.".to_string(),
                parameters: json!({
                    "type": "object",
                    "properties": {
                        "name": {
                            "type": "string",
                            "description": "Name of the agent to wait for"
                        }
                    },
                    "required": ["name"]
                }),
            },
            ToolDefinition {
                name: "wait_for_any".to_string(),
                description: "Wait for any running agent to complete and get its results.".to_string(),
                parameters: json!({
                    "type": "object",
                    "properties": {}
                }),
            },
            ToolDefinition {
                name: "list_agents".to_string(),
                description: "List all spawned agents and their current status.".to_string(),
                parameters: json!({
                    "type": "object",
                    "properties": {}
                }),
            },
            ToolDefinition {
                name: "record_finding".to_string(),
                description: "Record an important finding or insight.".to_string(),
                parameters: json!({
                    "type": "object",
                    "properties": {
                        "finding": {
                            "type": "string",
                            "description": "The finding to record"
                        },
                        "category": {
                            "type": "string",
                            "description": "Category: asset, vulnerability, info, recommendation"
                        }
                    },
                    "required": ["finding"]
                }),
            },
            ToolDefinition {
                name: "complete_engagement".to_string(),
                description: "Mark the engagement as complete and generate summary.".to_string(),
                parameters: json!({
                    "type": "object",
                    "properties": {
                        "summary": {
                            "type": "string",
                            "description": "Executive summary of the engagement"
                        }
                    },
                    "required": ["summary"]
                }),
            },
        ];

        // Add SAST to spawn options if source target available
        if self.has_source_target {
            if let Some(spawn_tool) = tools.iter_mut().find(|t| t.name == "spawn_agent") {
                spawn_tool.parameters = json!({
                    "type": "object",
                    "properties": {
                        "agent_type": {
                            "type": "string",
                            "enum": ["recon", "scanner", "sast", "report"],
                            "description": "Type of agent to spawn"
                        },
                        "name": {
                            "type": "string",
                            "description": "Unique name for this agent instance"
                        },
                        "instructions": {
                            "type": "string",
                            "description": "Task-specific instructions for the agent"
                        }
                    },
                    "required": ["agent_type", "name", "instructions"]
                });
            }
        }

        tools
    }
```

**Step 2: Run cargo check**

Run: `cargo check -p feroxmute-core`

Expected: Compiles (execute method will be updated next)

**Step 3: Commit**

```bash
git add feroxmute-core/src/agents/orchestrator.rs
git commit -m "feat(orchestrator): replace delegate tools with spawn/wait tools"
```

---

## Task 5: Update Orchestrator Execute Method

**Files:**
- Modify: `feroxmute-core/src/agents/orchestrator.rs`

**Step 1: Update execute method to return tool calls for external handling**

The orchestrator's execute method will now return tool calls that the runner handles. Replace the `Agent` impl:

```rust
#[async_trait(?Send)]
impl Agent for OrchestratorAgent {
    fn name(&self) -> &str {
        "orchestrator"
    }

    fn status(&self) -> AgentStatus {
        self.status
    }

    fn system_prompt(&self) -> &str {
        self.prompts.get("orchestrator").unwrap_or("")
    }

    fn tools(&self) -> Vec<ToolDefinition> {
        self.build_tools()
    }

    async fn execute(&mut self, task: &AgentTask, ctx: &AgentContext<'_>) -> Result<String> {
        self.status = AgentStatus::Running;
        self.thinking = Some(format!(
            "Starting engagement orchestration: {}",
            task.description
        ));

        // Build initial message
        let task_message = format!(
            "Target: {}\nEngagement Task: {}\n\nYou have the following tools:\n\
            - spawn_agent: Spawn agents (recon, scanner{}, report) to run tasks concurrently\n\
            - wait_for_agent: Wait for a specific agent by name\n\
            - wait_for_any: Wait for any agent to complete\n\
            - list_agents: See status of all agents\n\
            - record_finding: Record important findings\n\
            - complete_engagement: Finish the engagement\n\n\
            Start by spawning appropriate agents for reconnaissance.",
            ctx.target,
            task.description,
            if self.has_source_target { ", sast" } else { "" }
        );

        let messages = vec![Message::user(&task_message)];

        // Make single completion request - tool handling done by runner
        let request = CompletionRequest::new(messages)
            .with_system(self.system_prompt())
            .with_tools(self.tools())
            .with_max_tokens(4096);

        let response = ctx.provider.complete(request).await?;

        // Return the response content or tool calls as JSON for runner to handle
        if !response.tool_calls.is_empty() {
            let tool_calls_json: Vec<serde_json::Value> = response
                .tool_calls
                .iter()
                .map(|tc| {
                    json!({
                        "name": tc.name,
                        "arguments": tc.arguments
                    })
                })
                .collect();
            Ok(serde_json::to_string_pretty(&tool_calls_json).unwrap_or_default())
        } else {
            Ok(response.content.unwrap_or_default())
        }
    }

    fn thinking(&self) -> Option<&str> {
        self.thinking.as_deref()
    }

    fn set_status(&mut self, status: AgentStatus) {
        self.status = status;
    }
}
```

**Step 2: Remove old handler methods**

Delete these methods from the `impl OrchestratorAgent` block:
- `handle_delegate_recon`
- `handle_delegate_scanner`
- `handle_delegate_sast`
- `handle_advance_phase`
- `handle_get_status`

Keep:
- `handle_record_finding`
- `handle_complete_engagement`

**Step 3: Run cargo check**

Run: `cargo check -p feroxmute-core`

Expected: Compiles

**Step 4: Update tests**

Replace the test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_orchestrator_creation() {
        let agent = OrchestratorAgent::new();
        assert_eq!(agent.name(), "orchestrator");
        assert_eq!(agent.status(), AgentStatus::Idle);
        assert_eq!(agent.current_phase(), EngagementPhase::Setup);
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
    fn test_orchestrator_tools() {
        let agent = OrchestratorAgent::new();
        let tools = agent.tools();

        assert!(tools.iter().any(|t| t.name == "spawn_agent"));
        assert!(tools.iter().any(|t| t.name == "wait_for_agent"));
        assert!(tools.iter().any(|t| t.name == "wait_for_any"));
        assert!(tools.iter().any(|t| t.name == "list_agents"));
        assert!(tools.iter().any(|t| t.name == "record_finding"));
        assert!(tools.iter().any(|t| t.name == "complete_engagement"));
    }

    #[test]
    fn test_orchestrator_with_source_target() {
        let agent = OrchestratorAgent::new().with_source_target();
        assert!(agent.has_source_target());
    }

    #[test]
    fn test_record_finding() {
        let mut agent = OrchestratorAgent::new();
        assert!(agent.findings().is_empty());

        agent.handle_record_finding(&json!({
            "finding": "Found open port 80",
            "category": "asset"
        }));

        assert_eq!(agent.findings().len(), 1);
        assert!(agent.findings()[0].contains("ASSET"));
    }
}
```

**Step 5: Run tests**

Run: `cargo test -p feroxmute-core orchestrator`

Expected: PASS

**Step 6: Commit**

```bash
git add feroxmute-core/src/agents/orchestrator.rs
git commit -m "refactor(orchestrator): simplify execute method, remove delegate handlers"
```

---

## Task 6: Add feed_scroll_x to TUI App

**Files:**
- Modify: `feroxmute-cli/src/tui/app.rs`

**Step 1: Add feed_scroll_x field**

In `feroxmute-cli/src/tui/app.rs`, add to the `App` struct after `selected_feed`:

```rust
    /// Horizontal scroll offset for feed
    pub feed_scroll_x: u16,
```

**Step 2: Initialize in constructor**

In the `App::new()` method, add after `selected_feed: 0,`:

```rust
            feed_scroll_x: 0,
```

**Step 3: Add scroll methods**

Add these methods to `impl App`:

```rust
    /// Scroll feed left
    pub fn scroll_feed_left(&mut self) {
        self.feed_scroll_x = self.feed_scroll_x.saturating_sub(4);
    }

    /// Scroll feed right
    pub fn scroll_feed_right(&mut self) {
        self.feed_scroll_x = self.feed_scroll_x.saturating_add(4);
    }

    /// Reset feed scroll
    pub fn reset_feed_scroll(&mut self) {
        self.feed_scroll_x = 0;
    }
```

**Step 4: Add test**

Add to the test module:

```rust
    #[test]
    fn test_feed_scroll() {
        let mut app = App::new("test.com", "test-session", None);
        assert_eq!(app.feed_scroll_x, 0);

        app.scroll_feed_right();
        assert_eq!(app.feed_scroll_x, 4);

        app.scroll_feed_right();
        assert_eq!(app.feed_scroll_x, 8);

        app.scroll_feed_left();
        assert_eq!(app.feed_scroll_x, 4);

        app.reset_feed_scroll();
        assert_eq!(app.feed_scroll_x, 0);
    }
```

**Step 5: Run tests**

Run: `cargo test -p feroxmute-cli app`

Expected: PASS

**Step 6: Commit**

```bash
git add feroxmute-cli/src/tui/app.rs
git commit -m "feat(tui): add horizontal scroll state for feed"
```

---

## Task 7: Implement Horizontal Scrolling in Dashboard Feed

**Files:**
- Modify: `feroxmute-cli/src/tui/widgets/dashboard.rs`

**Step 1: Update render_feed function**

Replace the `render_feed` function:

```rust
/// Render activity feed with horizontal scrolling
fn render_feed(frame: &mut Frame, app: &App, area: Rect) {
    let inner_width = area.width.saturating_sub(2) as usize; // account for borders
    let scroll_x = app.feed_scroll_x as usize;

    let items: Vec<ListItem> = app
        .feed
        .iter()
        .rev()
        .take(area.height as usize - 2)
        .map(|entry| {
            let style = if entry.is_error {
                Style::default().fg(Color::Red)
            } else {
                Style::default()
            };

            let prefix = format!("[{}] ", entry.agent);
            let full_text = format!("{}{}", prefix, entry.message);

            // Apply horizontal scroll
            let display_text = if scroll_x < full_text.len() {
                let end = (scroll_x + inner_width).min(full_text.len());
                &full_text[scroll_x..end]
            } else {
                ""
            };

            // Color the prefix portion if visible
            let prefix_len = prefix.len();
            if scroll_x < prefix_len {
                let visible_prefix_end = prefix_len.saturating_sub(scroll_x);
                let visible_prefix = &display_text[..visible_prefix_end.min(display_text.len())];
                let visible_message = if display_text.len() > visible_prefix_end {
                    &display_text[visible_prefix_end..]
                } else {
                    ""
                };

                let line = Line::from(vec![
                    Span::styled(visible_prefix, Style::default().fg(Color::Cyan)),
                    Span::styled(visible_message, style),
                ]);
                ListItem::new(line)
            } else {
                ListItem::new(Line::from(Span::styled(display_text, style)))
            }
        })
        .collect();

    // Check if content extends beyond visible area
    let has_more_right = app.feed.iter().any(|e| {
        let full_len = format!("[{}] {}", e.agent, e.message).len();
        scroll_x + inner_width < full_len
    });
    let has_more_left = scroll_x > 0;

    let title = match (has_more_left, has_more_right) {
        (true, true) => " ← Activity Feed → ",
        (true, false) => " ← Activity Feed ",
        (false, true) => " Activity Feed → ",
        (false, false) => " Activity Feed ",
    };

    let feed = List::new(items).block(Block::default().borders(Borders::ALL).title(title));

    frame.render_widget(feed, area);
}
```

**Step 2: Run cargo check**

Run: `cargo check -p feroxmute-cli`

Expected: Compiles

**Step 3: Commit**

```bash
git add feroxmute-cli/src/tui/widgets/dashboard.rs
git commit -m "feat(tui): implement horizontal scrolling in dashboard feed"
```

---

## Task 8: Add Key Handlers for Feed Scrolling

**Files:**
- Modify: `feroxmute-cli/src/tui/events.rs`

**Step 1: Read current events.rs**

First examine the file to understand its structure.

**Step 2: Add left/right key handlers**

In the key handling match block for `View::Dashboard`, add:

```rust
KeyCode::Left | KeyCode::Char('H') => {
    app.scroll_feed_left();
}
KeyCode::Right | KeyCode::Char('L') => {
    app.scroll_feed_right();
}
```

(Note: Using capital H/L to avoid conflict with existing lowercase bindings)

**Step 3: Run cargo check**

Run: `cargo check -p feroxmute-cli`

Expected: Compiles

**Step 4: Commit**

```bash
git add feroxmute-cli/src/tui/events.rs
git commit -m "feat(tui): add arrow key handlers for feed horizontal scroll"
```

---

## Task 9: Create run_orchestrator Function in Runner

**Files:**
- Modify: `feroxmute-cli/src/runner.rs`

**Step 1: Replace runner.rs content**

Replace the entire file:

```rust
//! Agent execution runner

use std::sync::Arc;

use anyhow::Result;
use feroxmute_core::agents::{
    Agent, AgentContext, AgentRegistry, AgentResult, AgentStatus, AgentTask, OrchestratorAgent,
    Prompts,
};
use feroxmute_core::docker::ContainerManager;
use feroxmute_core::providers::LlmProvider;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::tui::AgentEvent;

/// Run the orchestrator agent with TUI feedback
pub async fn run_orchestrator(
    target: String,
    provider: Arc<dyn LlmProvider>,
    container: Arc<ContainerManager>,
    tx: mpsc::Sender<AgentEvent>,
    cancel: CancellationToken,
    has_source_target: bool,
) -> Result<()> {
    // Send initial status
    let _ = tx
        .send(AgentEvent::Status {
            agent: "orchestrator".to_string(),
            status: AgentStatus::Running,
        })
        .await;

    let _ = tx
        .send(AgentEvent::Feed {
            agent: "orchestrator".to_string(),
            message: format!("Starting engagement orchestration for {}", target),
            is_error: false,
        })
        .await;

    // Create orchestrator
    let prompts = Prompts::default();
    let mut orchestrator = OrchestratorAgent::with_prompts(prompts.clone());
    if has_source_target {
        orchestrator = orchestrator.with_source_target();
    }

    // Create agent registry
    let mut registry = AgentRegistry::new();

    // Create task
    let task = AgentTask::new("engagement-1", "orchestrator", "Perform security assessment");

    // Create context
    let ctx = AgentContext {
        target: &target,
        provider: provider.as_ref(),
        container: Some(container.as_ref()),
        session: None,
    };

    // Run orchestrator loop with cancellation support
    tokio::select! {
        result = run_orchestrator_loop(&mut orchestrator, &mut registry, &task, &ctx, &tx, provider.clone(), container.clone(), &prompts) => {
            match result {
                Ok(output) => {
                    let _ = tx.send(AgentEvent::Status {
                        agent: "orchestrator".to_string(),
                        status: AgentStatus::Completed,
                    }).await;

                    let _ = tx.send(AgentEvent::Finished {
                        success: true,
                        message: format!("Engagement complete.\n{}", output),
                    }).await;
                }
                Err(e) => {
                    let _ = tx.send(AgentEvent::Status {
                        agent: "orchestrator".to_string(),
                        status: AgentStatus::Failed,
                    }).await;

                    let _ = tx.send(AgentEvent::Finished {
                        success: false,
                        message: format!("Engagement failed: {}", e),
                    }).await;
                }
            }
        }
        _ = cancel.cancelled() => {
            let _ = tx.send(AgentEvent::Feed {
                agent: "orchestrator".to_string(),
                message: "Cancelled by user".to_string(),
                is_error: false,
            }).await;

            let _ = tx.send(AgentEvent::Status {
                agent: "orchestrator".to_string(),
                status: AgentStatus::Idle,
            }).await;
        }
    }

    Ok(())
}

/// Inner orchestrator loop that handles tool calls
async fn run_orchestrator_loop(
    orchestrator: &mut OrchestratorAgent,
    registry: &mut AgentRegistry,
    task: &AgentTask,
    ctx: &AgentContext<'_>,
    tx: &mpsc::Sender<AgentEvent>,
    provider: Arc<dyn LlmProvider>,
    container: Arc<ContainerManager>,
    prompts: &Prompts,
) -> Result<String> {
    let max_iterations = 50;
    let mut result = String::new();

    for iteration in 0..max_iterations {
        let _ = tx
            .send(AgentEvent::Feed {
                agent: "orchestrator".to_string(),
                message: format!("Iteration {}: thinking...", iteration + 1),
                is_error: false,
            })
            .await;

        // Execute orchestrator step
        let output = orchestrator.execute(task, ctx).await?;

        // Try to parse as tool calls
        if let Ok(tool_calls) = serde_json::from_str::<Vec<serde_json::Value>>(&output) {
            for tool_call in tool_calls {
                let tool_name = tool_call["name"].as_str().unwrap_or("");
                let args = &tool_call["arguments"];

                let tool_result = match tool_name {
                    "spawn_agent" => {
                        handle_spawn_agent(
                            args,
                            registry,
                            tx,
                            provider.clone(),
                            container.clone(),
                            prompts,
                            ctx.target,
                        )
                        .await
                    }
                    "wait_for_agent" => handle_wait_for_agent(args, registry, tx).await,
                    "wait_for_any" => handle_wait_for_any(registry, tx).await,
                    "list_agents" => handle_list_agents(registry),
                    "record_finding" => {
                        orchestrator.handle_record_finding(args);
                        "Finding recorded".to_string()
                    }
                    "complete_engagement" => {
                        result = orchestrator.handle_complete_engagement(args);
                        return Ok(result);
                    }
                    _ => format!("Unknown tool: {}", tool_name),
                };

                let _ = tx
                    .send(AgentEvent::Feed {
                        agent: "orchestrator".to_string(),
                        message: format!("[{}] {}", tool_name, tool_result),
                        is_error: false,
                    })
                    .await;
            }
        } else {
            // Not tool calls, just text response
            result.push_str(&output);
            result.push('\n');
        }
    }

    Ok(result)
}

async fn handle_spawn_agent(
    args: &serde_json::Value,
    registry: &mut AgentRegistry,
    tx: &mpsc::Sender<AgentEvent>,
    provider: Arc<dyn LlmProvider>,
    container: Arc<ContainerManager>,
    prompts: &Prompts,
    target: &str,
) -> String {
    let agent_type = args["agent_type"].as_str().unwrap_or("recon");
    let name = args["name"].as_str().unwrap_or("unnamed");
    let instructions = args["instructions"].as_str().unwrap_or("");

    if registry.has_agent(name) {
        return format!("Agent '{}' already exists", name);
    }

    // Get base prompt for agent type
    let base_prompt = prompts.get(agent_type).unwrap_or("");
    let full_prompt = format!(
        "{}\n\n---\n\n## Task from Orchestrator\n\nName: {}\nInstructions: {}\nTarget: {}",
        base_prompt, name, instructions, target
    );

    let _ = tx
        .send(AgentEvent::Feed {
            agent: name.to_string(),
            message: format!("Spawned: {}", instructions),
            is_error: false,
        })
        .await;

    let _ = tx
        .send(AgentEvent::Status {
            agent: agent_type.to_string(),
            status: AgentStatus::Running,
        })
        .await;

    // Spawn agent task
    let result_tx = registry.result_sender();
    let agent_name = name.to_string();
    let agent_type_str = agent_type.to_string();
    let target_owned = target.to_string();

    let handle = tokio::spawn(async move {
        let start = std::time::Instant::now();

        // Run agent with shell tool
        let output = match provider
            .complete_with_shell(&full_prompt, &target_owned, container)
            .await
        {
            Ok(out) => out,
            Err(e) => format!("Error: {}", e),
        };

        let success = !output.starts_with("Error:");

        let _ = result_tx
            .send(AgentResult {
                name: agent_name.clone(),
                agent_type: agent_type_str,
                success,
                output,
                duration: start.elapsed(),
            })
            .await;
    });

    registry.register(
        name.to_string(),
        agent_type.to_string(),
        instructions.to_string(),
        handle,
    );

    format!("Spawned agent '{}' ({})", name, agent_type)
}

async fn handle_wait_for_agent(
    args: &serde_json::Value,
    registry: &mut AgentRegistry,
    tx: &mpsc::Sender<AgentEvent>,
) -> String {
    let name = args["name"].as_str().unwrap_or("");

    let _ = tx
        .send(AgentEvent::Feed {
            agent: "orchestrator".to_string(),
            message: format!("Waiting for agent '{}'...", name),
            is_error: false,
        })
        .await;

    match registry.wait_for_agent(name).await {
        Some(result) => {
            let _ = tx
                .send(AgentEvent::Status {
                    agent: result.agent_type.clone(),
                    status: if result.success {
                        AgentStatus::Completed
                    } else {
                        AgentStatus::Failed
                    },
                })
                .await;

            format!(
                "Agent '{}' completed ({}): {}",
                result.name,
                if result.success { "success" } else { "failed" },
                truncate_output(&result.output, 500)
            )
        }
        None => format!("Agent '{}' not found", name),
    }
}

async fn handle_wait_for_any(
    registry: &mut AgentRegistry,
    tx: &mpsc::Sender<AgentEvent>,
) -> String {
    let _ = tx
        .send(AgentEvent::Feed {
            agent: "orchestrator".to_string(),
            message: "Waiting for any agent to complete...".to_string(),
            is_error: false,
        })
        .await;

    match registry.wait_for_any().await {
        Some(result) => {
            let _ = tx
                .send(AgentEvent::Status {
                    agent: result.agent_type.clone(),
                    status: if result.success {
                        AgentStatus::Completed
                    } else {
                        AgentStatus::Failed
                    },
                })
                .await;

            format!(
                "Agent '{}' completed ({}): {}",
                result.name,
                if result.success { "success" } else { "failed" },
                truncate_output(&result.output, 500)
            )
        }
        None => "No running agents".to_string(),
    }
}

fn handle_list_agents(registry: &AgentRegistry) -> String {
    let agents = registry.list_agents();
    if agents.is_empty() {
        "No agents spawned yet".to_string()
    } else {
        agents
            .iter()
            .map(|(name, agent_type, status)| format!("- {} ({}): {:?}", name, agent_type, status))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

fn truncate_output(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len])
    }
}
```

**Step 2: Run cargo check**

Run: `cargo check -p feroxmute-cli`

Expected: May have some errors to fix in next step

**Step 3: Commit**

```bash
git add feroxmute-cli/src/runner.rs
git commit -m "feat(runner): implement run_orchestrator with spawn/wait tool handlers"
```

---

## Task 10: Update main.rs to Use run_orchestrator

**Files:**
- Modify: `feroxmute-cli/src/main.rs`

**Step 1: Update the agent spawning section**

Find the section around line 287-291 that spawns the agent, and replace:

```rust
        // Spawn agent task on LocalSet
        let agent_target = target.clone();
        let agent_cancel = cancel.clone();
        let has_source = !targets.standalone_sources.is_empty()
            || targets.groups.iter().any(|g| g.source_target.is_some());
        let container = Arc::new(container);

        let agent_handle = local.spawn_local(async move {
            runner::run_orchestrator(
                agent_target,
                provider,
                container,
                tx,
                agent_cancel,
                has_source,
            )
            .await
        });
```

**Step 2: Update container creation**

The container needs to be wrapped in Arc before being passed. Find line ~275-281 and ensure the container manager is created without `mut`:

```rust
        // Start the Kali container
        app.add_feed(tui::FeedEntry::new("system", "Starting Docker container..."));
        let container = ContainerManager::new(container_config).await.map_err(|e| {
            anyhow!("Failed to create container manager: {}\n\nHint: Is Docker running?", e)
        })?;
        container.start().await.map_err(|e| {
            anyhow!("Failed to start container: {}\n\nHint: Run 'docker compose build' first", e)
        })?;
        app.add_feed(tui::FeedEntry::new("system", "Docker container started"));
```

**Step 3: Run cargo check**

Run: `cargo check -p feroxmute-cli`

Expected: Compiles

**Step 4: Run cargo build**

Run: `cargo build`

Expected: Build succeeds

**Step 5: Commit**

```bash
git add feroxmute-cli/src/main.rs
git commit -m "feat(main): switch from run_recon_agent to run_orchestrator"
```

---

## Task 11: Make handle_record_finding and handle_complete_engagement Public

**Files:**
- Modify: `feroxmute-core/src/agents/orchestrator.rs`

**Step 1: Add pub visibility**

Find `handle_record_finding` and `handle_complete_engagement` methods and add `pub`:

```rust
    /// Handle recording a finding
    pub fn handle_record_finding(&mut self, args: &serde_json::Value) -> String {
        // ... existing code
    }

    /// Handle engagement completion
    pub fn handle_complete_engagement(&mut self, args: &serde_json::Value) -> String {
        // ... existing code
    }
```

**Step 2: Run cargo check**

Run: `cargo check`

Expected: Compiles

**Step 3: Commit**

```bash
git add feroxmute-core/src/agents/orchestrator.rs
git commit -m "fix(orchestrator): make finding/complete handlers public"
```

---

## Task 12: Final Integration Test

**Step 1: Run all tests**

Run: `cargo test`

Expected: All tests pass

**Step 2: Run clippy**

Run: `cargo clippy`

Expected: No errors (warnings ok)

**Step 3: Run fmt**

Run: `cargo fmt`

**Step 4: Final commit if any formatting changes**

```bash
git add -A
git commit -m "chore: format code"
```

**Step 5: Build release**

Run: `cargo build --release`

Expected: Build succeeds

---

## Summary

After completing all tasks, you will have:

1. `AgentRegistry` managing spawned agents with async result channels
2. `OrchestratorAgent` with `spawn_agent`, `wait_for_agent`, `wait_for_any`, `list_agents` tools
3. `run_orchestrator` function that handles the agentic loop and tool execution
4. TUI dashboard with horizontal scrolling feed
5. Main entry point using orchestrator instead of directly spawning recon

The orchestrator can now spawn multiple agents concurrently and coordinate their results.
