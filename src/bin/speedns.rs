//! `speedns` — a dig-lite CLI plus control-plane client for SpeeDNS.
//!
//! `resolve`/`query` speak real DNS wire protocol over UDP to the daemon;
//! `status`, `records`, `add`, `rm`, `flush` and `cache` talk to the daemon's
//! Unix control socket.

use speedns::dns::{
    decode_message, encode_message, type_from_str, type_name, Header, Message, Question, CLASS_IN,
    TYPE_PTR,
};
use speedns::json::Json;
use speedns::{NAME, VERSION};
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

const DEFAULT_SERVER: &str = "127.0.0.1:53";
const DEFAULT_SOCKET: &str = "/tmp/speedns.sock";

const HELP: &str = "\
SpeeDNS — ultra-lightweight, AI-native (MCP) private DNS client.

USAGE:
    speedns <command> [args]

DNS QUERIES (wire protocol over UDP):
    resolve <name> [type] [--server <addr>]   Resolve a name (A/AAAA/CNAME/MX/...)
    query   <name> [type] [--server <addr>]   Alias of resolve
    reverse <ip>    [--server <addr>]         Reverse PTR lookup for an IP

CONTROL (Unix socket):
    status                                   Live daemon telemetry
    records [name]                           List local authoritative records
    add \"<owner> [ttl] <TYPE> <rdata>\"      Add a record at runtime
    rm <name> [type] [value]                 Remove records
    flush                                    Flush the response cache
    cache                                    Snapshot cached entries

GLOBAL:
    -s, --socket <path>   Control socket (default $SPEEDNS_CONTROL_SOCKET or /tmp/speedns.sock)
    -V, --version         Print version and exit
        --help            Print this help and exit

EXAMPLES:
    speedns resolve example.com A
    speedns resolve example.com --server 127.0.0.1:5353
    speedns reverse 8.8.8.8
    speedns add \"app.example.com. 300 A 192.168.1.42\"
    speedns rm app.example.com A
    speedns status
";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|a| a == "--help" || a == "-h") {
        println!("{}", HELP);
        std::process::exit(if args.is_empty() { 2 } else { 0 });
    }
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("{} v{}", NAME, VERSION);
        std::process::exit(0);
    }

    let default_socket = std::env::var("SPEEDNS_CONTROL_SOCKET").unwrap_or_else(|_| DEFAULT_SOCKET.to_string());
    let mut socket = default_socket.as_str();

    let cmd = args[0].as_str();
    let rest = &args[1..];

    // Extract --server and --socket before positional parsing.
    let mut server = DEFAULT_SERVER.to_string();
    let mut positional: Vec<String> = Vec::new();
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--server" | "-p" => {
                i += 1;
                if let Some(v) = rest.get(i) {
                    server = v.clone();
                }
            }
            "--socket" | "-s" => {
                i += 1;
                if let Some(v) = rest.get(i) {
                    socket = v;
                }
            }
            other => positional.push(other.to_string()),
        }
        i += 1;
    }

    let result = match cmd {
        "resolve" | "query" => {
            let name = positional.get(0).cloned().unwrap_or_default();
            let qtype = positional.get(1).cloned().map(|t| type_from_str(&t).unwrap_or(255)).unwrap_or(1);
            run_resolve(&server, &name, qtype)
        }
        "reverse" | "ptr" => {
            let ip = positional.get(0).cloned().unwrap_or_default();
            run_reverse(&server, &ip)
        }
        "status" => control_cmd(socket, "status", Json::obj()),
        "records" | "list" => {
            let mut cmd_json = Json::obj();
            cmd_json.insert("cmd", Json::str("records"));
            if let Some(name) = positional.get(0) {
                cmd_json.insert("name", Json::str(name.clone()));
            }
            control_cmd(socket, "records", cmd_json)
        }
        "add" => {
            let line = positional.join(" ");
            let mut cmd_json = Json::obj();
            cmd_json.insert("cmd", Json::str("add"));
            cmd_json.insert("record", Json::str(line));
            control_cmd(socket, "add", cmd_json)
        }
        "rm" | "remove" | "del" => {
            let mut cmd_json = Json::obj();
            cmd_json.insert("cmd", Json::str("remove"));
            if let Some(name) = positional.get(0) {
                cmd_json.insert("name", Json::str(name.clone()));
            }
            if let Some(t) = positional.get(1) {
                cmd_json.insert("type", Json::str(t.clone()));
            }
            if let Some(v) = positional.get(2) {
                cmd_json.insert("value", Json::str(v.clone()));
            }
            control_cmd(socket, "remove", cmd_json)
        }
        "flush" => control_cmd(socket, "flush", Json::obj()),
        "cache" => control_cmd(socket, "cache", Json::obj()),
        _ => {
            eprintln!("unknown command '{}'", cmd);
            println!("{}", HELP);
            std::process::exit(2);
        }
    };

    if let Err(e) = result {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}

// ---------------------------------------------------------------------------
// DNS wire-protocol queries
// ---------------------------------------------------------------------------

fn run_resolve(server: &str, name: &str, qtype: u16) -> Result<(), String> {
    if name.is_empty() {
        return Err("missing domain name (speedns resolve <name> [type])".to_string());
    }
    let addr: SocketAddr = server.parse().map_err(|_| format!("invalid server '{}'", server))?;
    let start = std::time::Instant::now();
    let response = dns_query(addr, name, qtype)?;
    let elapsed = start.elapsed().as_millis();

    println!("; <<>> {} v{} <<>> {} {}", NAME, VERSION, name, type_name(qtype));
    println!(";; server: {}", addr);
    let flags = format_flags(&response.header);
    println!(
        ";; flags: {}; QUERY: {}, ANSWER: {}, AUTHORITY: {}, ADDITIONAL: {}",
        flags, response.header.qdcount, response.header.ancount, response.header.nscount, response.header.arcount
    );
    println!();
    println!(";; QUESTION SECTION:");
    for q in &response.questions {
        println!(";{}. IN {}", q.name, type_name(q.qtype));
    }
    if !response.answers.is_empty() {
        println!();
        println!(";; ANSWER SECTION:");
        for r in &response.answers {
            println!("{}. {} IN {} {}", r.name, r.ttl, type_name(r.rtype), speedns::resolver::rdata_to_string(&r.rdata));
        }
    }
    if !response.authorities.is_empty() {
        println!();
        println!(";; AUTHORITY SECTION:");
        for r in &response.authorities {
            println!("{}. {} IN {} {}", r.name, r.ttl, type_name(r.rtype), speedns::resolver::rdata_to_string(&r.rdata));
        }
    }
    println!();
    println!(";; Query time: {} msec", elapsed);
    println!(";; STATUS: {}", rcode_name(response.header.rcode()));
    println!(";; MSG SIZE  rcvd: {}", encode_message(&response).len());
    Ok(())
}

fn run_reverse(server: &str, ip: &str) -> Result<(), String> {
    if ip.is_empty() {
        return Err("missing IP address (speedns reverse <ip>)".to_string());
    }
    let ptr = speedns::control::reverse_name(ip)?;
    run_resolve(server, &ptr, TYPE_PTR)
}

/// Send a single DNS query over UDP and decode the response.
fn dns_query(server: SocketAddr, name: &str, qtype: u16) -> Result<Message, String> {
    let mut header = Header::default();
    header.id = 0x5353;
    header.set_rd(true);
    header.qdcount = 1;
    let msg = Message {
        header,
        questions: vec![Question {
            name: name.to_string(),
            qtype,
            qclass: CLASS_IN,
        }],
        ..Default::default()
    };
    let packet = encode_message(&msg);

    let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    sock.connect(server).map_err(|e| e.to_string())?;
    sock.set_read_timeout(Some(Duration::from_secs(3))).ok();
    sock.send(&packet).map_err(|e| e.to_string())?;

    let mut buf = [0u8; 4096];
    let n = sock.recv(&mut buf).map_err(|e| format!("no response from {}: {}", server, e))?;
    let response = decode_message(&buf[..n]).map_err(|e| format!("bad response: {}", e))?;
    if response.header.id != header.id {
        return Err("response ID mismatch (aliased reply)".to_string());
    }
    Ok(response)
}

fn format_flags(header: &Header) -> String {
    let mut f = String::new();
    if header.qr() {
        f.push_str("qr ");
    }
    f.push_str("rd");
    if header.ra() {
        f.push_str(" ra");
    }
    if header.aa() {
        f.push_str(" aa");
    }
    if header.tc() {
        f.push_str(" tc");
    }
    f
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

// ---------------------------------------------------------------------------
// Control-plane client
// ---------------------------------------------------------------------------

fn control_cmd(socket: &str, label: &str, mut cmd: Json) -> Result<(), String> {
    if !cmd.get("cmd").is_some() {
        cmd.insert("cmd", Json::str(label));
    }
    let response = speedns::control::request(socket, &cmd)?;
    if response.get("ok").and_then(|o| o.as_bool()) != Some(true) {
        let msg = response.get("error").and_then(|e| e.as_str()).unwrap_or("unknown error");
        return Err(msg.to_string());
    }
    match label {
        "status" => {
            let mut text = String::new();
            for key in [
                "name", "version", "uptime_secs", "upstream", "records", "cache_entries",
                "queries", "cache_hits", "cache_misses", "authoritative", "forwarded", "errors",
            ] {
                if let Some(v) = display_value(response.get(key)) {
                    text.push_str(&format!("{:>14}: {}\n", key, v));
                }
            }
            print!("{}", text);
        }
        "records" | "list" => {
            let records = response.get("records").and_then(|r| r.as_array()).cloned().unwrap_or_default();
            for rec in &records {
                if let Some(s) = rec.as_str() {
                    println!("{}", s);
                }
            }
            if records.is_empty() {
                println!("(no records)");
            }
        }
        "add" => {
            let added = response.get("added").and_then(|a| a.as_bool()).unwrap_or(false);
            println!("record added: {}", if added { "yes" } else { "no" });
        }
        "remove" => {
            let removed = response.get("removed").and_then(|r| r.as_i64()).unwrap_or(0);
            println!("removed {} record(s)", removed);
        }
        "flush" => println!("cache flushed"),
        "cache" => {
            let entries = response.get("entries").and_then(|r| r.as_array()).cloned().unwrap_or_default();
            for entry in &entries {
                let name = entry.get("name").and_then(|n| n.as_str()).unwrap_or("");
                let rtype = entry.get("type").and_then(|n| n.as_str()).unwrap_or("");
                let ttl = entry.get("ttl").and_then(|n| n.as_i64()).unwrap_or(0);
                println!("{} {}\tTTL={}", name, rtype, ttl);
            }
            if entries.is_empty() {
                println!("(cache empty)");
            }
        }
        _ => {
            println!("{}", response.to_pretty(2));
        }
    }
    Ok(())
}

fn display_value(v: Option<&Json>) -> Option<String> {
    match v {
        Some(Json::Str(s)) => Some(s.clone()),
        Some(Json::Num(n)) => {
            if n.fract() == 0.0 {
                Some(format!("{}", *n as i64))
            } else {
                Some(format!("{}", n))
            }
        }
        Some(Json::Null) => Some("-".to_string()),
        _ => None,
    }
}
