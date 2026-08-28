//! `speedns-mcp` — expose SpeeDNS to AI agents as an MCP server.
//!
//! Speaks JSON-RPC 2.0 over stdio (newline-delimited JSON) per the MCP
//! transport spec. Register it in any MCP host and the agent gains native
//! tools for DNS resolution, reverse lookups, record management, cache
//! control and live server telemetry.

use speedns::mcp;
use speedns::{NAME, VERSION};

const DEFAULT_SOCKET: &str = "/tmp/speedns.sock";

const HELP: &str = "\
SpeeDNS MCP bridge — AI-native DNS for any MCP host.

USAGE:
    speedns-mcp [OPTIONS]

OPTIONS:
    -s, --control-socket <p>  SpeeDNS daemon control socket
                              (default: $SPEEDNS_CONTROL_SOCKET or /tmp/speedns.sock)
    -V, --version             Print version and exit
        --help                Print this help and exit

EXAMPLES:
    Claude Desktop:
      \"speedns\": { \"command\": \"speedns-mcp\" }

    TRAE / Cursor / any MCP client:
      \"speedns-mcp --control-socket /var/run/speedns.sock\"
";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("{}", HELP);
        std::process::exit(0);
    }
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("{} v{} (MCP bridge)", NAME, VERSION);
        std::process::exit(0);
    }

    // Resolve the control socket: CLI flag > env > default.
    let mut control_socket = std::env::var("SPEEDNS_CONTROL_SOCKET").unwrap_or_else(|_| DEFAULT_SOCKET.to_string());
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-s" | "--control-socket" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    control_socket = v.clone();
                }
            }
            other => {
                eprintln!("unknown argument '{}' (run speedns-mcp --help)", other);
                std::process::exit(2);
            }
        }
        i += 1;
    }

    eprintln!("[speedns-mcp] {} v{} — control socket '{}'", NAME, VERSION, control_socket);
    if let Err(e) = mcp::serve(&control_socket) {
        eprintln!("[speedns-mcp] error: {}", e);
        std::process::exit(1);
    }
}
