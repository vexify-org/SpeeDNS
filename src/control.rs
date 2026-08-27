//! Control-plane protocol between SpeeDNS processes.
//!
//! The daemon exposes a tiny JSON-lines API over a Unix domain socket so the
//! CLI (`speedns`) and the MCP server (`speedns-mcp`) can query and manage it
//! at runtime: resolve names, list/add/remove records, flush the cache and
//! inspect live stats. Requests and responses are one JSON object per line.

use crate::dns::{canonical, type_from_str, type_name, TYPE_ANY};
use crate::json::Json;
use crate::resolver::{records_to_json, Resolver};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;

/// One-request/one-response JSON-lines handler over a Unix socket.
pub struct ControlServer {
    resolver: Arc<Resolver>,
    path: String,
}

impl ControlServer {
    pub fn new(resolver: Arc<Resolver>, path: &str) -> Result<ControlServer, String> {
        if !path.starts_with('/') {
            return Err(format!("control socket must be an absolute path, got '{}'", path));
        }
        let _ = std::fs::remove_file(path);
        Ok(ControlServer {
            resolver,
            path: path.to_string(),
        })
    }

    /// Bind the listener and spawn the accept loop (non-blocking).
    pub fn spawn(self) -> Result<(), String> {
        let listener = UnixListener::bind(&self.path)
            .map_err(|e| format!("cannot bind control socket '{}': {}", self.path, e))?;
        thread::Builder::new()
            .name("speedns-control".to_string())
            .spawn(move || {
                for stream in listener.incoming() {
                    match stream {
                        Ok(stream) => {
                            let resolver = self.resolver.clone();
                            thread::Builder::new()
                                .name("speedns-control-conn".to_string())
                                .spawn(move || handle_connection(stream, &resolver))
                                .ok();
                        }
                        Err(_) => break,
                    }
                }
            })
            .map_err(|e| format!("cannot spawn control thread: {}", e))?;
        Ok(())
    }
}

fn handle_connection(stream: UnixStream, resolver: &Arc<Resolver>) {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let request = crate::json::parse(trimmed).unwrap_or_else(|e| {
                    let mut err = Json::obj();
                    err.insert("ok", Json::bool(false));
                    err.insert("error", Json::str(format!("bad JSON: {}", e)));
                    err
                });
                let response = dispatch(&request, resolver);
                if let Err(_e) = writeln!(&mut reader.get_mut(), "{}", response.to_string()) {
                    break;
                }
                let _ = reader.get_mut().flush();
            }
        }
    }
}

fn ok(data: Json) -> Json {
    let mut j = Json::obj();
    j.insert("ok", Json::bool(true));
    match data {
        Json::Obj(entries) => {
            for (k, v) in entries {
                j.insert(&k, v);
            }
        }
        _ => j.insert("data", data),
    }
    j
}

fn err(msg: impl Into<String>) -> Json {
    let mut j = Json::obj();
    j.insert("ok", Json::bool(false));
    j.insert("error", Json::str(msg.into()));
    j
}

fn dispatch(request: &Json, resolver: &Arc<Resolver>) -> Json {
    let cmd = request
        .get("cmd")
        .and_then(|c| c.as_str())
        .unwrap_or("ping");
    match cmd {
        "ping" => ok(Json::str("pong")),
        "query" | "resolve" => cmd_query(request, resolver),
        "records" | "records_list" => cmd_records(request, resolver),
        "add" | "record_add" => cmd_add(request, resolver),
        "remove" | "record_remove" => cmd_remove(request, resolver),
        "flush" | "cache_flush" => {
            resolver.flush_cache();
            ok(Json::str("cache flushed"))
        }
        "cache" | "cache_snapshot" => cmd_cache(request, resolver),
        "status" => cmd_status(resolver),
        _ => err(format!("unknown command '{}'", cmd)),
    }
}

fn cmd_query(request: &Json, resolver: &Arc<Resolver>) -> Json {
    let name = request.get("name").and_then(|n| n.as_str()).unwrap_or("").trim();
    if name.is_empty() {
        return err("missing 'name'");
    }
    let qtype = request
        .get("type")
        .and_then(|t| t.as_str())
        .and_then(type_from_str)
        .unwrap_or(TYPE_ANY);
    let result = resolver.resolve_name(name, qtype);

    let mut j = Json::obj();
    j.insert("name", Json::str(canonical(name)));
    j.insert("type", Json::str(type_name(qtype)));
    j.insert("rcode", Json::num(result.rcode as f64));
    j.insert("rcode_name", Json::str(rcode_name(result.rcode)));
    j.insert("aa", Json::bool(result.aa));
    j.insert("records", records_to_json(&result.records));
    ok(j)
}

fn cmd_records(request: &Json, resolver: &Arc<Resolver>) -> Json {
    let name = request.get("name").and_then(|n| n.as_str()).map(str::to_string);
    let store = resolver.store.read().unwrap();
    let all = store.all();
    let filtered: Vec<_> = match name {
        Some(n) => all.into_iter().filter(|r| canonical(&r.name) == canonical(&n)).collect(),
        None => all,
    };
    let mut arr = Json::arr();
    for rec in filtered {
        arr.push(Json::str(crate::store::render_record(&rec)));
    }
    let count = arr_len(&arr) as f64;
    let mut j = Json::obj();
    j.insert("records", arr);
    j.insert("count", Json::num(count));
    ok(j)
}

fn cmd_add(request: &Json, resolver: &Arc<Resolver>) -> Json {
    let record = request.get("record").and_then(|r| r.as_str()).unwrap_or("").trim();
    if record.is_empty() {
        return err("missing 'record' (e.g. \"example.com. 300 A 192.0.2.1\")");
    }
    let ttl = request.get("ttl").and_then(|t| t.as_u32()).unwrap_or(300);
    match crate::store::parse_record_line(record, ttl) {
        Ok(Some(rec)) => {
            resolver.store.write().unwrap().insert(rec);
            let mut j = Json::obj();
            j.insert("added", Json::bool(true));
            j.insert("record", Json::str(record));
            ok(j)
        }
        Ok(None) => err("empty record"),
        Err(e) => err(e),
    }
}

fn cmd_remove(request: &Json, resolver: &Arc<Resolver>) -> Json {
    let name = match request.get("name").and_then(|n| n.as_str()) {
        Some(n) if !n.trim().is_empty() => n.trim().to_string(),
        _ => return err("missing 'name'"),
    };
    let rtype = request.get("type").and_then(|t| t.as_str()).and_then(type_from_str);
    let value = request.get("value").and_then(|v| v.as_str());
    let removed = resolver
        .store
        .write()
        .unwrap()
        .remove(&name, rtype, value);
    let mut j = Json::obj();
    j.insert("removed", Json::num(removed as f64));
    ok(j)
}

fn cmd_cache(_request: &Json, resolver: &Arc<Resolver>) -> Json {
    let snapshot = resolver.cache_snapshot();
    let mut arr = Json::arr();
    for (name, qtype, ttl, records) in snapshot {
        let mut entry = Json::obj();
        entry.insert("name", Json::str(name));
        entry.insert("type", Json::str(type_name(qtype)));
        entry.insert("ttl", Json::num(ttl as f64));
        entry.insert("records", records_to_json(&records));
        arr.push(entry);
    }
    let count = arr_len(&arr) as f64;
    let mut j = Json::obj();
    j.insert("entries", arr);
    j.insert("count", Json::num(count));
    ok(j)
}

fn cmd_status(resolver: &Arc<Resolver>) -> Json {
    let stats = &resolver.stats;
    let store = resolver.store.read().unwrap();
    let mut j = Json::obj();
    j.insert("name", Json::str(crate::NAME));
    j.insert("version", Json::str(crate::VERSION));
    j.insert("uptime_secs", Json::num(stats.started.elapsed().as_secs() as f64));
    j.insert("upstream", match resolver.upstream() {
        Some(addr) => Json::str(addr.to_string()),
        None => Json::null(),
    });
    j.insert("cache_entries", Json::num(resolver.cache_size() as f64));
    j.insert("records", Json::num(store.len() as f64));
    j.insert("queries", Json::num(stats.queries.load(Ordering::Relaxed) as f64));
    j.insert("cache_hits", Json::num(stats.cache_hits.load(Ordering::Relaxed) as f64));
    j.insert("cache_misses", Json::num(stats.cache_misses.load(Ordering::Relaxed) as f64));
    j.insert("authoritative", Json::num(stats.authoritative.load(Ordering::Relaxed) as f64));
    j.insert("forwarded", Json::num(stats.forwarded.load(Ordering::Relaxed) as f64));
    j.insert("errors", Json::num(stats.errors.load(Ordering::Relaxed) as f64));
    ok(j)
}

fn rcode_name(rcode: u16) -> &'static str {
    match rcode {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        _ => "UNKNOWN",
    }
}

fn arr_len(arr: &Json) -> usize {
    arr.as_array().map(|a| a.len()).unwrap_or(0)
}

/// Convenience for resolving a reverse (PTR) lookup name from an IP.
pub fn reverse_name(ip: &str) -> Result<String, String> {
    if let Ok(v4) = ip.parse::<std::net::Ipv4Addr>() {
        return Ok(crate::store::reverse_v4(v4));
    }
    if let Ok(v6) = ip.parse::<std::net::Ipv6Addr>() {
        return Ok(crate::store::reverse_v6(v6));
    }
    Err(format!("'{}' is not a valid IP address", ip))
}

/// Client-side request over the control socket.
pub fn request(path: &str, cmd: &Json) -> Result<Json, String> {
    let mut stream = UnixStream::connect(path)
        .map_err(|e| format!("cannot connect to '{}': {} (is speednsd running?)", path, e))?;
    stream
        .write_all(cmd.to_string().as_bytes())
        .map_err(|e| e.to_string())?;
    stream.write_all(b"\n").map_err(|e| e.to_string())?;
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|e| format!("no response from daemon: {}", e))?;
    crate::json::parse(&line).map_err(|e| format!("bad daemon response: {}", e))
}
