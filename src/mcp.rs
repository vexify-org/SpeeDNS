//! MCP (Model Context Protocol) server for SpeeDNS.
//!
//! `speedns-mcp` speaks JSON-RPC 2.0 over stdio using newline-delimited JSON
//! (one message per line), exactly as the MCP transport spec requires. It
//! exposes SpeeDNS as a set of AI tools — resolve, reverse-lookup, manage
//! records, flush/inspect the cache, and read live server status — so any MCP
//! host (Claude, TRAE, Cursor, …) can operate the resolver natively.
//!
//! All tool execution is delegated to the running `speednsd` daemon over its
//! Unix control socket; this binary stays a thin, stateless protocol bridge.

use crate::json::Json;
use std::io::{BufRead, Write};

/// Protocol version advertised during initialization.
const PROTOCOL_VERSION: &str = "2025-03-26";
/// JSON-RPC reserved error codes.
const ERR_INVALID_REQUEST: i64 = -32600;
const ERR_METHOD_NOT_FOUND: i64 = -32601;
const ERR_INVALID_PARAMS: i64 = -32602;

/// Run the MCP server loop until stdin closes.
pub fn serve(control_socket: &str) -> Result<(), String> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let mut line = String::new();
    let mut reader = stdin.lock();

    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break, // EOF
            Ok(_) => {}
            Err(_) => break,
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let request = match crate::json::parse(trimmed) {
            Ok(v) => v,
            Err(e) => {
                let err = error_response(None, ERR_INVALID_REQUEST, &format!("invalid JSON: {}", e));
                writeln!(stdout, "{}", err.to_string()).ok();
                let _ = stdout.flush();
                continue;
            }
        };
        if let Some(response) = handle(&request, control_socket) {
            writeln!(stdout, "{}", response.to_string()).ok();
            let _ = stdout.flush();
        }
    }
    Ok(())
}

/// Handle one JSON-RPC request. Returns `None` for notifications.
fn handle(request: &Json, control_socket: &str) -> Option<Json> {
    let id = request.get("id").cloned();
    let method = request.get("method").and_then(|m| m.as_str()).unwrap_or("");
    let is_notification = id.is_none() && !method.is_empty();

    let response = match method {
        "initialize" => jsonrpc_result(id, initialize_result()),
        "notifications/initialized" => return None,
        "ping" => jsonrpc_result(id, Json::obj()),
        "tools/list" => jsonrpc_result(id, tools_list()),
        "tools/call" => call_tool(request.get("params"), control_socket, id.clone()),
        "resources/list" => jsonrpc_result(id, resources_list()),
        "resources/read" => jsonrpc_result(id, resources_read()),
        "" => error_response(id, ERR_INVALID_REQUEST, "missing method"),
        _ => error_response(id, ERR_METHOD_NOT_FOUND, &format!("method not found: {}", method)),
    };

    if is_notification {
        None
    } else {
        Some(response)
    }
}

fn jsonrpc_result(id: Option<Json>, result: Json) -> Json {
    let mut j = Json::obj();
    j.insert("jsonrpc", Json::str("2.0"));
    match id {
        Some(id) => j.insert("id", id),
        None => j.insert("id", Json::null()),
    }
    j.insert("result", result);
    j
}

fn error_response(id: Option<Json>, code: i64, message: &str) -> Json {
    let mut j = Json::obj();
    j.insert("jsonrpc", Json::str("2.0"));
    match id {
        Some(id) => j.insert("id", id),
        None => j.insert("id", Json::null()),
    }
    let mut error = Json::obj();
    error.insert("code", Json::num(code as f64));
    error.insert("message", Json::str(message));
    j.insert("error", error);
    j
}

fn initialize_result() -> Json {
    let mut result = Json::obj();
    result.insert("protocolVersion", Json::str(PROTOCOL_VERSION));
    let mut capabilities = Json::obj();
    capabilities.insert("tools", Json::obj());
    result.insert("capabilities", capabilities);
    let mut server_info = Json::obj();
    server_info.insert("name", Json::str("speedns-mcp"));
    server_info.insert("version", Json::str(crate::VERSION));
    result.insert("serverInfo", server_info);
    result
}

fn tools_list() -> Json {
    let mut result = Json::obj();
    let mut tools = Json::arr();
    for def in tool_definitions() {
        tools.push(def);
    }
    result.insert("tools", tools);
    result
}

fn resources_list() -> Json {
    let mut result = Json::obj();
    result.insert("resources", Json::arr());
    result
}

fn resources_read() -> Json {
    let mut result = Json::obj();
    result.insert("contents", Json::arr());
    result
}

/// All tools exposed to AI hosts.
fn tool_definitions() -> Vec<Json> {
    let mut tools = Vec::new();

    tools.push(tool(
        "dns_resolve",
        "Resolve a domain name through the SpeeDNS resolver (local zone records first, then cache, then the configured upstream). Returns every matching record.",
        vec![
            prop("name", "Domain name to resolve (e.g. \"example.com\")", true),
            prop("type", "Record type: A, AAAA, CNAME, MX, NS, TXT, SOA, SRV, PTR or ANY (default ANY)", false),
        ],
    ));

    tools.push(tool(
        "dns_reverse",
        "Reverse-DNS lookup: given an IPv4 or IPv6 address, query its PTR record (e.g. 8.8.8.8 -> 8.8.8.8.in-addr.arpa).",
        vec![prop("ip", "IPv4 or IPv6 address", true)],
    ));

    tools.push(tool(
        "records_list",
        "List the locally configured authoritative records. Optionally filter by owner name.",
        vec![prop("name", "Filter records owned by this name", false)],
    ));

    tools.push(tool(
        "record_add",
        "Add an authoritative record at runtime. Accepts a records-file line, e.g. \"app.example.com. 300 A 192.168.1.42\" or \"example.com. MX 10 mail.example.com.\"",
        vec![prop("record", "Records-file format line: <owner> [ttl] <TYPE> <rdata>", true)],
    ));

    tools.push(tool(
        "record_remove",
        "Remove records by name, optionally narrowed by type and value.",
        vec![
            prop("name", "Owner name of the records to remove", true),
            prop("type", "Only remove this record type", false),
            prop("value", "Only remove records with this RDATA value", false),
        ],
    ));

    tools.push(tool(
        "cache_flush",
        "Flush the entire DNS response cache immediately.",
        vec![],
    ));

    tools.push(tool(
        "cache_snapshot",
        "Snapshot every entry currently held in the DNS response cache.",
        vec![],
    ));

    tools.push(tool(
        "server_status",
        "Read live server telemetry: version, uptime, query counters, cache size, authoritative records and upstream.",
        vec![],
    ));

    tools
}

fn tool(name: &str, description: &str, props: Vec<Json>) -> Json {
    let mut t = Json::obj();
    t.insert("name", Json::str(name));
    t.insert("description", Json::str(description));
    let mut schema = Json::obj();
    schema.insert("type", Json::str("object"));
    let mut properties = Json::obj();
    let mut required = Json::arr();
    for p in props {
        let prop_name = p.get("_name").and_then(|n| n.as_str()).unwrap_or("").to_string();
        let prop_desc = p.get("_desc").and_then(|n| n.as_str()).unwrap_or("").to_string();
        let prop_req = p.get("_required").and_then(|n| n.as_bool()).unwrap_or(false);
        let mut sp = Json::obj();
        sp.insert("type", Json::str("string"));
        sp.insert("description", Json::str(prop_desc));
        properties.insert(&prop_name, sp);
        if prop_req {
            required.push(Json::str(prop_name));
        }
    }
    schema.insert("properties", properties);
    schema.insert("required", required);
    t.insert("inputSchema", schema);
    t
}

fn prop(name: &str, description: &str, required: bool) -> Json {
    let mut p = Json::obj();
    p.insert("_name", Json::str(name));
    p.insert("_desc", Json::str(description));
    p.insert("_required", Json::bool(required));
    p
}

/// Dispatch a `tools/call`.
fn call_tool(params: Option<&Json>, control_socket: &str, id: Option<Json>) -> Json {
    let Some(params) = params else {
        return error_response(id, ERR_INVALID_PARAMS, "missing params");
    };
    let Some(name) = params.get("name").and_then(|n| n.as_str()) else {
        return error_response(id, ERR_INVALID_PARAMS, "missing tool name");
    };
    let args = params.get("arguments").cloned().unwrap_or_else(Json::obj);

    let outcome: Result<String, String> = match name {
        "dns_resolve" => cmd_query(&args, control_socket, false),
        "dns_reverse" => cmd_reverse(&args, control_socket),
        "records_list" => cmd_records(&args, control_socket),
        "record_add" => cmd_add(&args, control_socket),
        "record_remove" => cmd_remove(&args, control_socket),
        "cache_flush" => cmd_flush(control_socket),
        "cache_snapshot" => cmd_cache(control_socket),
        "server_status" => cmd_status(control_socket),
        _ => return error_response(id, ERR_METHOD_NOT_FOUND, &format!("unknown tool: {}", name)),
    };

    jsonrpc_result(id, tool_result(outcome))
}

/// Build a `tools/call` result from a success/error outcome.
fn tool_result(outcome: Result<String, String>) -> Json {
    let mut result = Json::obj();
    let mut content = Json::arr();
    let mut text = Json::obj();
    text.insert("type", Json::str("text"));
    match outcome {
        Ok(t) => {
            text.insert("text", Json::str(t));
            result.insert("isError", Json::bool(false));
        }
        Err(e) => {
            text.insert("text", Json::str(format!("ERROR: {}", e)));
            result.insert("isError", Json::bool(true));
        }
    }
    content.push(text);
    result.insert("content", content);
    result
}

/// A small client over the daemon's control socket.
fn ctl(control_socket: &str, cmd: &Json) -> Result<Json, String> {
    let response = crate::control::request(control_socket, cmd)?;
    if response.get("ok").and_then(|o| o.as_bool()) == Some(true) {
        Ok(response)
    } else {
        let msg = response.get("error").and_then(|e| e.as_str()).unwrap_or("unknown control error");
        Err(msg.to_string())
    }
}

fn cmd_query(args: &Json, control_socket: &str, _verbose: bool) -> Result<String, String> {
    let name = args
        .get("name")
        .and_then(|n| n.as_str())
        .filter(|n| !n.trim().is_empty())
        .ok_or("missing required argument 'name'")?;
    let qtype = args.get("type").and_then(|t| t.as_str()).unwrap_or("ANY");

    let mut cmd = Json::obj();
    cmd.insert("cmd", Json::str("query"));
    cmd.insert("name", Json::str(name));
    cmd.insert("type", Json::str(qtype));
    let resp = ctl(control_socket, &cmd)?;

    let mut out = String::new();
    let rcode = resp.get("rcode").and_then(|r| r.as_i64()).unwrap_or(-1);
    let rcode_name = resp.get("rcode_name").and_then(|r| r.as_str()).unwrap_or("?");
    let aa = resp.get("aa").and_then(|r| r.as_bool()).unwrap_or(false);
    let records = resp.get("records").and_then(|r| r.as_array()).cloned().unwrap_or_default();

    out.push_str(&format!("{} ({})\n", resp.get("name").and_then(|n| n.as_str()).unwrap_or(name), qtype));
    if records.is_empty() {
        out.push_str(&format!("  -> {} (no records)\n", rcode_name));
    } else {
        for rec in records {
            let rname = rec.get("name").and_then(|n| n.as_str()).unwrap_or("");
            let rtype = rec.get("type").and_then(|n| n.as_str()).unwrap_or("");
            let ttl = rec.get("ttl").and_then(|n| n.as_i64()).unwrap_or(0);
            let value = rec.get("value").and_then(|n| n.as_str()).unwrap_or("");
            out.push_str(&format!("  {}\t{}\tTTL={}\t{}\n", rname, rtype, ttl, value));
        }
    }
    out.push_str(&format!("rcode: {} ({}), authoritative: {}\n", rcode, rcode_name, aa));
    Ok(out)
}

fn cmd_reverse(args: &Json, control_socket: &str) -> Result<String, String> {
    let ip = args
        .get("ip")
        .and_then(|n| n.as_str())
        .filter(|n| !n.trim().is_empty())
        .ok_or("missing required argument 'ip'")?;
    let ptr = crate::control::reverse_name(ip)?;
    let mut cmd = Json::obj();
    cmd.insert("cmd", Json::str("query"));
    cmd.insert("name", Json::str(&ptr));
    cmd.insert("type", Json::str("PTR"));
    let resp = ctl(control_socket, &cmd)?;
    let mut out = String::new();
    out.push_str(&format!("reverse lookup of {} -> {}\n", ip, ptr));
    let records = resp.get("records").and_then(|r| r.as_array()).cloned().unwrap_or_default();
    if records.is_empty() {
        out.push_str("  -> no PTR record\n");
    } else {
        for rec in records {
            let value = rec.get("value").and_then(|n| n.as_str()).unwrap_or("");
            out.push_str(&format!("  {}\n", value));
        }
    }
    Ok(out)
}

fn cmd_records(args: &Json, control_socket: &str) -> Result<String, String> {
    let mut cmd = Json::obj();
    cmd.insert("cmd", Json::str("records"));
    if let Some(name) = args.get("name").and_then(|n| n.as_str()) {
        cmd.insert("name", Json::str(name));
    }
    let resp = ctl(control_socket, &cmd)?;
    let records = resp.get("records").and_then(|r| r.as_array()).cloned().unwrap_or_default();
    let mut out = String::new();
    if records.is_empty() {
        out.push_str("(no records)\n");
    } else {
        for rec in records {
            out.push_str(&format!("{}\n", rec.as_str().unwrap_or("")));
        }
    }
    Ok(out)
}

fn cmd_add(args: &Json, control_socket: &str) -> Result<String, String> {
    let record = args
        .get("record")
        .and_then(|n| n.as_str())
        .filter(|n| !n.trim().is_empty())
        .ok_or("missing required argument 'record'")?;
    let mut cmd = Json::obj();
    cmd.insert("cmd", Json::str("add"));
    cmd.insert("record", Json::str(record));
    let resp = ctl(control_socket, &cmd)?;
    let added = resp.get("added").and_then(|a| a.as_bool()).unwrap_or(false);
    Ok(format!("record added: {}", if added { "yes" } else { "no" }))
}

fn cmd_remove(args: &Json, control_socket: &str) -> Result<String, String> {
    let name = args
        .get("name")
        .and_then(|n| n.as_str())
        .filter(|n| !n.trim().is_empty())
        .ok_or("missing required argument 'name'")?;
    let mut cmd = Json::obj();
    cmd.insert("cmd", Json::str("remove"));
    cmd.insert("name", Json::str(name));
    if let Some(t) = args.get("type").and_then(|t| t.as_str()) {
        cmd.insert("type", Json::str(t));
    }
    if let Some(v) = args.get("value").and_then(|v| v.as_str()) {
        cmd.insert("value", Json::str(v));
    }
    let resp = ctl(control_socket, &cmd)?;
    let removed = resp.get("removed").and_then(|r| r.as_i64()).unwrap_or(0);
    Ok(format!("removed {} record(s)", removed))
}

fn cmd_flush(control_socket: &str) -> Result<String, String> {
    let mut cmd = Json::obj();
    cmd.insert("cmd", Json::str("flush"));
    ctl(control_socket, &cmd)?;
    Ok("cache flushed".to_string())
}

fn cmd_cache(control_socket: &str) -> Result<String, String> {
    let mut cmd = Json::obj();
    cmd.insert("cmd", Json::str("cache"));
    let resp = ctl(control_socket, &cmd)?;
    let entries = resp.get("entries").and_then(|r| r.as_array()).cloned().unwrap_or_default();
    let mut out = String::new();
    if entries.is_empty() {
        out.push_str("(cache empty)\n");
    } else {
        for entry in entries {
            let name = entry.get("name").and_then(|n| n.as_str()).unwrap_or("");
            let rtype = entry.get("type").and_then(|n| n.as_str()).unwrap_or("");
            let ttl = entry.get("ttl").and_then(|n| n.as_i64()).unwrap_or(0);
            out.push_str(&format!("{} {}\tTTL={}\n", name, rtype, ttl));
        }
    }
    Ok(out)
}

fn cmd_status(control_socket: &str) -> Result<String, String> {
    let mut cmd = Json::obj();
    cmd.insert("cmd", Json::str("status"));
    let resp = ctl(control_socket, &cmd)?;
    let mut out = String::new();
    for key in [
        "name", "version", "uptime_secs", "listen", "upstream", "records", "cache_entries",
        "queries", "cache_hits", "cache_misses", "authoritative", "forwarded", "errors",
    ] {
        let value = match resp.get(key) {
            Some(Json::Str(s)) => s.clone(),
            Some(Json::Num(n)) => {
                if n.fract() == 0.0 {
                    format!("{}", *n as i64)
                } else {
                    format!("{}", n)
                }
            }
            Some(Json::Null) => "-".to_string(),
            _ => continue,
        };
        out.push_str(&format!("{:>14}: {}\n", key, value));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tools_list_has_speedns_tools() {
        let names: Vec<String> = tool_definitions()
            .iter()
            .filter_map(|t| t.get("name").and_then(|n| n.as_str()).map(str::to_string))
            .collect();
        for expected in ["dns_resolve", "dns_reverse", "records_list", "record_add", "record_remove", "cache_flush", "cache_snapshot", "server_status"] {
            assert!(names.contains(&expected.to_string()), "missing tool {}", expected);
        }
    }

    #[test]
    fn initialize_handshake() {
        let msg = crate::json::parse(
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}"#,
        )
        .unwrap();
        let response = handle(&msg, "/tmp/nonexistent").unwrap();
        assert_eq!(response.get("id").unwrap().as_i64(), Some(1));
        let result = response.get("result").unwrap();
        assert_eq!(result.get("protocolVersion").unwrap().as_str(), Some(PROTOCOL_VERSION));
        assert_eq!(
            result.get("serverInfo").unwrap().get("name").unwrap().as_str(),
            Some("speedns-mcp")
        );
    }

    #[test]
    fn unknown_method_error() {
        let msg = crate::json::parse(r#"{"jsonrpc":"2.0","id":2,"method":"nope"}"#).unwrap();
        let response = handle(&msg, "/tmp/nonexistent").unwrap();
        assert_eq!(
            response.get("error").unwrap().get("code").unwrap().as_i64(),
            Some(ERR_METHOD_NOT_FOUND)
        );
    }

    #[test]
    fn notification_gets_no_response() {
        let msg = crate::json::parse(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#).unwrap();
        assert!(handle(&msg, "/tmp/nonexistent").is_none());
    }
}
