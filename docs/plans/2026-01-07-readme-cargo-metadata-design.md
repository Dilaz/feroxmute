# README and Cargo.toml Metadata Design

## Overview

Document new features (vulnerability playbooks) in README and add essential metadata to Cargo.toml.

## Changes

### 1. README.md - Vulnerability Playbooks Section

Add new section after "Features", before "Quick Start":

```markdown
## Vulnerability Playbooks

Agents have access to 17 specialized playbooks that guide testing for specific vulnerability classes. Scanner and exploit agents can request playbooks using the `get_playbook` tool when they identify potential attack vectors.

Each playbook includes:
- **Indicators** - Signs the vulnerability may be present
- **Tools & commands** - Specific tool usage for the vulnerability type
- **Exploitation techniques** - Manual and automated approaches
- **Evasion methods** - WAF/filter bypass techniques where applicable

### Available Playbooks

**Injection**
- SQL Injection, NoSQL Injection, Command Injection, SSTI, XXE

**Client-Side**
- XSS, CSRF

**Server-Side**
- SSRF, LFI/RFI, Deserialization, Race Conditions

**Authentication & Crypto**
- JWT Attacks, Crypto Weaknesses

**Protocols & Platforms**
- GraphQL, WebSockets, Windows Web, Windows AD
```

### 2. README.md - Fix Repository URL

Update line 33 from:
```markdown
git clone https://github.com/yourusername/feroxmute
```

To:
```markdown
git clone https://github.com/dilaz/feroxmute
```

### 3. Cargo.toml - Essential Metadata

Add to `[workspace.package]`:
```toml
description = "LLM-powered penetration testing framework with autonomous agents"
repository = "https://github.com/dilaz/feroxmute"
```

## Rationale

- **Playbooks section**: Documents agent capability for guided vulnerability testing with categorized list for readability
- **Repository URL**: Fixes placeholder with actual repository location
- **Cargo.toml metadata**: Adds essential fields for package discoverability without over-engineering for crates.io publishing
