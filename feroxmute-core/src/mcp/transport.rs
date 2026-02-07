//! MCP stdio transport layer

use std::io::{BufRead, Write};

use crate::Result;
use crate::mcp::protocol::{JsonRpcRequest, JsonRpcResponse};

/// Read a JSON-RPC message from a buffered reader
/// MCP uses newline-delimited JSON
pub fn read_message<R: BufRead>(reader: &mut R) -> Result<Option<JsonRpcRequest>> {
    let mut line = String::new();
    let bytes_read = reader
        .read_line(&mut line)
        .map_err(|e| crate::Error::Provider(format!("Failed to read MCP message: {}", e)))?;

    if bytes_read == 0 {
        return Ok(None); // EOF
    }

    let line = line.trim();
    if line.is_empty() {
        return Ok(None);
    }

    let request: JsonRpcRequest = serde_json::from_str(line)
        .map_err(|e| crate::Error::Provider(format!("Failed to parse MCP request: {}", e)))?;

    Ok(Some(request))
}

/// Write a JSON-RPC response to a writer
pub fn write_message<W: Write>(writer: &mut W, response: &JsonRpcResponse) -> Result<()> {
    let json = serde_json::to_string(response)
        .map_err(|e| crate::Error::Provider(format!("Failed to serialize MCP response: {}", e)))?;

    writeln!(writer, "{}", json)
        .map_err(|e| crate::Error::Provider(format!("Failed to write MCP response: {}", e)))?;

    writer
        .flush()
        .map_err(|e| crate::Error::Provider(format!("Failed to flush MCP response: {}", e)))?;

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_read_message() {
        let input = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#.to_string() + "\n";
        let mut reader = Cursor::new(input);
        let result = read_message(&mut reader).unwrap();
        assert!(result.is_some());
        let req = result.unwrap();
        assert_eq!(req.method, "tools/list");
    }

    #[test]
    fn test_read_message_eof() {
        let mut reader = Cursor::new("");
        let result = read_message(&mut reader).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_write_message() {
        let response = JsonRpcResponse::success(Some(1.into()), serde_json::json!({}));
        let mut output = Vec::new();
        write_message(&mut output, &response).unwrap();
        let written = String::from_utf8(output).unwrap();
        assert!(written.contains("\"jsonrpc\":\"2.0\""));
        assert!(written.ends_with('\n'));
    }
}
