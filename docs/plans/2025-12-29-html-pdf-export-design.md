# HTML/PDF Report Export - Design

## Problem Statement

CLI flags `--html` and `--pdf` exist, config fields `export_html` and `export_pdf` exist, and the wizard has checkboxes for these options. However, no actual HTML or PDF generation code exists. Only JSON and Markdown exports are implemented.

## Current State

| Component | Status |
|-----------|--------|
| Config fields (`export_html`, `export_pdf`) | Exists |
| CLI args (`--html`, `--pdf`) | Exists |
| Wizard checkboxes | Exists |
| `export_json()` | Implemented |
| `export_markdown()` | Implemented |
| `export_html()` | Missing |
| `export_pdf()` | Missing |
| `ExportHtmlTool` | Missing |
| `ExportPdfTool` | Missing |

## Solution

Implement HTML and PDF export using:
- **HTML**: Simple template with inline CSS (no external dependencies)
- **PDF**: Native Rust generation via `printpdf` crate (text-based, simple layout)

## Implementation Details

### Dependencies

```toml
# feroxmute-core/Cargo.toml
[dependencies]
printpdf = "0.7"
```

### New Functions in `reports/generator.rs`

#### `export_html()`

```rust
pub fn export_html(report: &Report, path: &Path) -> Result<()> {
    let html = generate_html(report);
    std::fs::write(path, html)?;
    Ok(())
}

fn generate_html(report: &Report) -> String {
    format!(r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Security Assessment: {target}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
               max-width: 900px; margin: 40px auto; padding: 0 20px; line-height: 1.6; }}
        h1 {{ border-bottom: 2px solid #333; padding-bottom: 10px; }}
        .summary {{ background: #f5f5f5; padding: 20px; border-radius: 8px; margin: 20px 0; }}
        .finding {{ border-left: 4px solid #ccc; padding: 10px 20px; margin: 15px 0; }}
        .critical {{ border-color: #dc3545; }}
        .high {{ border-color: #fd7e14; }}
        .medium {{ border-color: #ffc107; }}
        .low {{ border-color: #28a745; }}
        .info {{ border-color: #17a2b8; }}
        .metrics {{ color: #666; font-size: 0.9em; margin-top: 40px; }}
    </style>
</head>
<body>
    <h1>Security Assessment: {target}</h1>
    <div class="summary">
        <strong>Risk Rating:</strong> {risk_rating}<br>
        <strong>Findings:</strong> {total} total
        ({critical} critical, {high} high, {medium} medium, {low} low, {info} info)
        <p>{executive_summary}</p>
    </div>
    <h2>Findings</h2>
    {findings_html}
    <div class="metrics">
        <h3>Engagement Metrics</h3>
        <p>Tool Calls: {tool_calls} | Tokens: {input_tokens} input / {output_tokens} output</p>
    </div>
</body>
</html>"#,
        target = report.metadata.target,
        // ... other fields
    )
}
```

#### `export_pdf()`

```rust
use printpdf::*;
use std::io::BufWriter;

pub fn export_pdf(report: &Report, path: &Path) -> Result<()> {
    let (doc, page1, layer1) = PdfDocument::new(
        "Security Assessment Report",
        Mm(210.0), Mm(297.0), // A4 size
        "Layer 1"
    );

    let font = doc.add_builtin_font(BuiltinFont::Helvetica)?;
    let font_bold = doc.add_builtin_font(BuiltinFont::HelveticaBold)?;

    let current_layer = doc.get_page(page1).get_layer(layer1);

    let mut y = Mm(280.0); // Start near top
    let x = Mm(20.0);
    let line_height = Mm(6.0);

    // Title
    current_layer.use_text(
        format!("SECURITY ASSESSMENT: {}", report.metadata.target),
        14.0, x, y, &font_bold
    );
    y -= Mm(15.0);

    // Summary section
    current_layer.use_text(
        format!("Risk Rating: {}", report.summary.risk_rating),
        11.0, x, y, &font
    );
    y -= line_height;

    // ... continue with findings and metrics
    // Add new pages if y < Mm(30.0)

    doc.save(&mut BufWriter::new(File::create(path)?))?;
    Ok(())
}
```

### New Tools in `tools/report.rs`

#### `ExportHtmlTool`

```rust
pub struct ExportHtmlTool {
    context: Arc<ReportContext>,
}

impl Tool for ExportHtmlTool {
    const NAME: &'static str = "export_html";

    // Mirrors ExportMarkdownTool implementation
    // Calls export_html() instead of export_markdown()
}
```

#### `ExportPdfTool`

```rust
pub struct ExportPdfTool {
    context: Arc<ReportContext>,
}

impl Tool for ExportPdfTool {
    const NAME: &'static str = "export_pdf";

    // Mirrors ExportMarkdownTool implementation
    // Calls export_pdf() instead of export_markdown()
}
```

### Tool Registration

In `providers/macros.rs` or each provider's `complete_with_report()`:

```rust
.tool(ExportHtmlTool::new(Arc::clone(&context)))
.tool(ExportPdfTool::new(Arc::clone(&context)))
```

### Update `reports/mod.rs`

```rust
pub use generator::{export_html, export_json, export_markdown, export_pdf, ...};
```

## Files Changed

| File | Change |
|------|--------|
| `feroxmute-core/Cargo.toml` | Add `printpdf = "0.7"` |
| `feroxmute-core/src/reports/generator.rs` | Add `export_html()`, `export_pdf()`, `generate_html()` |
| `feroxmute-core/src/reports/mod.rs` | Export new functions |
| `feroxmute-core/src/tools/report.rs` | Add `ExportHtmlTool`, `ExportPdfTool` |
| `feroxmute-core/src/providers/macros.rs` | Register new tools |

## Output Examples

### HTML Output
- Self-contained HTML file with inline CSS
- Professional styling with severity color coding
- Responsive layout (max-width container)
- Sections: header, summary, findings, metrics

### PDF Output
- A4 page size
- Text-based layout (no images/graphics)
- Helvetica font family
- Sections: title, summary, findings list, metrics
- Multi-page support for long reports

## Testing

1. Build: `cargo build`
2. Run existing tests: `cargo test`
3. Manual test: Run engagement with `--html --pdf` flags
4. Verify output files in `~/.feroxmute/sessions/<id>/reports/`

## Risk Assessment

- **Risk Level**: Low-Medium
- **New dependency**: `printpdf` (well-maintained, pure Rust)
- **Backwards Compatibility**: Additive only, no breaking changes
