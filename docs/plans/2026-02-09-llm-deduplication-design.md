# LLM-Based Finding Deduplication Design

## Problem

The report generator produces duplicate vulnerability entries because multiple agents discover the same vulnerability and describe it with slightly different titles:

- "SQL Injection in Product Search"
- "Critical SQL Injection in Product Search"
- "SQL Injection in Product Search API"

The affected asset also varies between path-only (`/rest/products/search?q=`) and full URL (`http://host.docker.internal:3000/rest/products/search?q=`).

Current deduplication uses exact title matching (lowercased) + severity, which fails for semantic duplicates.

## Solution

Use LLM to extract canonical vulnerability identifiers from each finding, then group by `(canonical_key, severity)` before merging.

### Design Decisions

1. **When:** Deduplication happens at report generation time (not insert time), keeping raw data intact
2. **How:** Report agent calls a new `deduplicate_findings` tool before `generate_report`
3. **Key format:** Simple slugs like `sqli-product-search`, `xss-search-page`, `idor-user-basket`
4. **Fallback:** None - agent prompt enforces calling deduplication first

## New Tool: `DeduplicateFindingsTool`

**Location:** `feroxmute-core/src/mcp/tools/dedup.rs`

**Tool name:** `deduplicate_findings`

**Input schema:**
```rust
struct DeduplicateFindingsInput {
    // No required inputs - operates on current session's findings
}
```

**Process:**
1. Load all vulnerabilities from the database
2. Batch findings into groups and send to LLM for canonical key extraction
3. Group vulnerabilities by `(canonical_key, severity)`
4. Merge each group using existing `merge_vulnerability_group` logic
5. Store deduplicated findings in `ReportContext.deduplicated_findings`
6. Return summary: "Deduplicated 28 findings into 16 unique vulnerabilities"

## Canonical Key Extraction

**Batched LLM prompt:**
```
Extract canonical vulnerability identifiers for each finding.
Return one lowercase slug per line in the same order.
Format: {vuln-type}-{component} like "sqli-product-search" or "xss-search-page"

1. Title: "SQL Injection in Product Search" | Affected: /rest/products/search
2. Title: "Critical SQL Injection - Product Search API" | Affected: http://host:3000/rest/products/search
3. Title: "XSS in Search" | Affected: /#/search

Output (one per line):
```

Batching reduces ~28 findings to 3-4 LLM calls instead of 28 individual calls.

**Key extraction implementation:**
```rust
async fn extract_canonical_keys(
    provider: &dyn LlmProvider,
    vulns: &[Vulnerability],
    batch_size: usize,
) -> Result<Vec<String>> {
    let mut keys = Vec::with_capacity(vulns.len());

    for chunk in vulns.chunks(batch_size) {
        let prompt = build_batch_prompt(chunk);
        let response = provider.complete_simple(&prompt).await?;

        // Parse one key per line
        for line in response.lines() {
            let key = line.trim().to_lowercase().replace(' ', "-");
            keys.push(key);
        }
    }

    Ok(keys)
}
```

**Fallback for malformed LLM response:**
If LLM returns fewer keys than expected or malformed output, fall back to slugified title.

## Integration with ReportContext

**Changes to `ReportContext`:**
```rust
pub struct ReportContext {
    // ... existing fields ...

    /// Deduplicated findings cache, populated by deduplicate_findings tool
    pub deduplicated_findings: Arc<Mutex<Option<Vec<Vulnerability>>>>,
}
```

**How `McpGenerateReportTool` uses it:**
```rust
let findings = if let Some(deduped) = context.deduplicated_findings.lock().unwrap().take() {
    deduped
} else {
    // No deduplication was run - load raw from DB with existing exact-match dedup
    load_vulnerabilities(&conn)?
};
```

## Report Agent Prompt Changes

**Location:** `feroxmute-core/prompts.toml`

**Addition to report agent system prompt:**
```toml
[report]
system = """
...existing prompt...

## Report Generation Process

Before generating the final report, you MUST:
1. Call `deduplicate_findings` to merge semantically similar vulnerabilities
2. Review the deduplication summary to understand the consolidated findings
3. Then call `generate_report` with your executive summary

This ensures the report doesn't contain duplicate entries for the same vulnerability
discovered by different agents or at different times.
"""
```

## Files to Create

- `feroxmute-core/src/mcp/tools/dedup.rs` - New deduplication tool

## Files to Modify

- `feroxmute-core/src/mcp/tools/mod.rs` - Export new module
- `feroxmute-core/src/mcp/tools/report.rs` - Add `deduplicated_findings` to `ReportContext`
- `feroxmute-core/src/providers/traits.rs` - Add `complete_simple()` method if not present
- `feroxmute-core/prompts.toml` - Update report agent prompt

## Tool Registration

Register `McpDeduplicateFindingsTool` alongside other MCP tools in the same location where `McpGenerateReportTool` is registered.

## Testing

- Unit test: canonical key extraction with mocked LLM responses
- Unit test: grouping/merging logic with pre-extracted keys
- Integration test: full flow with sample duplicates from the juice-shop report

## Edge Cases

| Case | Handling |
|------|----------|
| Empty findings list | Return early: "No findings to deduplicate" |
| LLM returns malformed key | Fallback to slugified title |
| Single finding | Pass through, no deduplication needed |
| LLM returns wrong count | Match by position, fallback for missing |
| Provider unavailable | Error with clear message |
