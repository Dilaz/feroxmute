# Docker Shell Tool Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement a single `shell` tool using rig's Tool trait that gives LLM agents shell access to the Kali container, enabling real tool calling.

**Architecture:** DockerShellTool implements `rig::tool::Tool`, executes commands in Docker via existing ContainerManager. Provider uses rig's agent builder with `.tool()` to enable automatic tool-calling loop. Recon agent simplified to single `agent.prompt()` call.

**Tech Stack:** rig-core 0.27 (Tool trait), bollard (Docker), serde/serde_json, tokio

---

## Task 1: Create DockerShellTool

**Files:**
- Create: `feroxmute-core/src/tools/shell.rs`
- Modify: `feroxmute-core/src/tools/mod.rs`
- Modify: `feroxmute-core/src/tools/executor.rs` (rename Tool to ToolDef)

**Step 1: Rename Tool struct to ToolDef in executor.rs to avoid conflict with rig::tool::Tool**

In `feroxmute-core/src/tools/executor.rs`, change line 13:
```rust
// Before
pub struct Tool {
// After
pub struct ToolDef {
```

Also update all references: `Tool::new` -> `ToolDef::new`, `&Tool` -> `&ToolDef`, etc.

**Step 2: Update mod.rs exports**

```rust
//! Tool integration module

pub mod executor;
pub mod sast;
pub mod shell;

pub use executor::{ToolDef, ToolExecution, ToolExecutor, ToolRegistry};
pub use shell::DockerShellTool;
```

**Step 3: Create shell.rs**

```rust
//! Docker shell tool for rig agents

use std::sync::Arc;

use rig::tool::{Tool, ToolDefinition};
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;

use crate::docker::ContainerManager;

#[derive(Debug, Deserialize)]
pub struct ShellArgs {
    pub command: String,
}

#[derive(Debug, Serialize)]
pub struct ShellOutput {
    pub output: String,
    pub exit_code: i64,
}

#[derive(Debug, Error)]
pub enum ShellError {
    #[error("Docker execution failed: {0}")]
    Docker(String),
}

pub struct DockerShellTool {
    container: Arc<ContainerManager>,
}

impl DockerShellTool {
    pub fn new(container: Arc<ContainerManager>) -> Self {
        Self { container }
    }
}

impl Tool for DockerShellTool {
    const NAME: &'static str = "shell";
    type Error = ShellError;
    type Args = ShellArgs;
    type Output = ShellOutput;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: "shell".to_string(),
            description: "Execute a shell command in a Kali Linux container with pentesting tools. Returns combined stdout/stderr and exit code.".to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "Shell command to execute (e.g., 'subfinder -d example.com -json')"
                    }
                },
                "required": ["command"]
            }),
        }
    }

    async fn call(&self, args: Self::Args) -> Result<Self::Output, Self::Error> {
        let wrapped_cmd = format!("{} 2>&1", args.command);
        let result = self
            .container
            .exec(vec!["sh", "-c", &wrapped_cmd], None)
            .await
            .map_err(|e| ShellError::Docker(e.to_string()))?;

        Ok(ShellOutput {
            output: result.output(),
            exit_code: result.exit_code,
        })
    }
}
```

**Step 4: Run cargo check**

Run: `cargo check -p feroxmute-core`
Expected: Compiles successfully

**Step 5: Commit**

```bash
git add feroxmute-core/src/tools/
git commit -m "feat(tools): add DockerShellTool implementing rig Tool trait"
```

---

## Task 2: Add complete_with_shell to LlmProvider Trait

**Files:**
- Modify: `feroxmute-core/src/providers/traits.rs`

**Step 1: Add imports**

At top of traits.rs, add:
```rust
use std::sync::Arc;
use crate::docker::ContainerManager;
```

**Step 2: Add default method to LlmProvider trait**

After the `complete` method in the trait definition, add:
```rust
    /// Complete with shell tool access (uses rig's built-in tool loop)
    async fn complete_with_shell(
        &self,
        _system_prompt: &str,
        _user_prompt: &str,
        _container: Arc<ContainerManager>,
    ) -> Result<String> {
        Err(crate::Error::Provider(
            "Shell tool not supported by this provider".to_string(),
        ))
    }
```

**Step 3: Run cargo check**

Run: `cargo check -p feroxmute-core`
Expected: Compiles successfully

**Step 4: Commit**

```bash
git add feroxmute-core/src/providers/traits.rs
git commit -m "feat(providers): add complete_with_shell trait method"
```

---

## Task 3: Implement complete_with_shell for OpenAI Provider

**Files:**
- Modify: `feroxmute-core/src/providers/openai.rs`

**Step 1: Add imports**

```rust
use std::sync::Arc;
use crate::docker::ContainerManager;
use crate::tools::DockerShellTool;
```

**Step 2: Implement complete_with_shell**

Add after the existing `complete` method implementation:
```rust
    async fn complete_with_shell(
        &self,
        system_prompt: &str,
        user_prompt: &str,
        container: Arc<ContainerManager>,
    ) -> Result<String> {
        let tool = DockerShellTool::new(container);

        let agent = self
            .client
            .agent(&self.model)
            .preamble(system_prompt)
            .max_tokens(4096)
            .tool(tool)
            .build();

        let response = agent
            .prompt(user_prompt)
            .await
            .map_err(|e| Error::Provider(format!("OpenAI completion failed: {}", e)))?;

        Ok(response)
    }
```

**Step 3: Run cargo check**

Run: `cargo check -p feroxmute-core`
Expected: Compiles successfully

**Step 4: Commit**

```bash
git add feroxmute-core/src/providers/openai.rs
git commit -m "feat(openai): implement complete_with_shell with DockerShellTool"
```

---

## Task 4: Update Recon System Prompt

**Files:**
- Modify: `feroxmute-core/prompts.toml`

**Step 1: Replace recon prompt**

Replace the entire `[recon]` section with the comprehensive tool documentation prompt (see design doc for full prompt content including Available Security Tools, Guidelines, and Example Workflow sections).

**Step 2: Commit**

```bash
git add feroxmute-core/prompts.toml
git commit -m "feat(prompts): update recon prompt with shell tool documentation"
```

---

## Task 5: Update Runner to Use complete_with_shell

**Files:**
- Modify: `feroxmute-cli/src/runner.rs`

**Step 1: Read current runner.rs to understand structure**

**Step 2: Update run_recon_agent to use complete_with_shell**

The runner should:
1. Get the system prompt from prompts.toml
2. Build the user prompt with target info
3. Call `provider.complete_with_shell(system_prompt, user_prompt, container)`
4. Return the result

**Step 3: Run cargo check**

Run: `cargo check`
Expected: Compiles successfully

**Step 4: Commit**

```bash
git add feroxmute-cli/src/runner.rs
git commit -m "feat(runner): use complete_with_shell for recon agent"
```

---

## Task 6: Integration Test

**Step 1: Build the project**

Run: `cargo build`
Expected: Builds successfully

**Step 2: Start Docker container**

Run: `docker compose up -d`
Expected: Container starts

**Step 3: Run feroxmute with a test target**

Run: `cargo run -- --target example.com --provider openai`
Expected: Agent executes shell commands and returns findings

**Step 4: Commit any fixes**

```bash
git add -A
git commit -m "fix: integration fixes for shell tool"
```

---

## Summary

| Task | Description | Files |
|------|-------------|-------|
| 1 | Create DockerShellTool | tools/shell.rs, tools/mod.rs, tools/executor.rs |
| 2 | Add trait method | providers/traits.rs |
| 3 | Implement for OpenAI | providers/openai.rs |
| 4 | Update prompts | prompts.toml |
| 5 | Update runner | runner.rs |
| 6 | Integration test | - |
