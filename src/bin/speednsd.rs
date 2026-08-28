//! `speednsd` — the SpeeDNS daemon.
//!
//! Binds UDP (and optionally TCP) DNS endpoints, serves the authoritative zone
//! store + TTL cache + upstream forwarding pipeline, and exposes a Unix
//! control socket for the CLI and MCP bridge.

use speedns::config::{load, CliArgs};
use speedns::control::ControlServer;
use speedns::resolver::Resolver;
use speedns::store::Store;
use speedns::{NAME, TAGLINE, VERSION};
use std::io::Write;
use std::net::{TcpListener, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

const HELP: &str = "\
SpeeDNS daemon — ultra-lightweight, AI-native (MCP) private DNS.

USAGE:
    speednsd [OPTIONS]

OPTIONS:
    -c, --config <file>       Load configuration from a file
    -l, --listen <addr>       Listen address (default 127.0.0.1:53)
    -u, --upstream <addr>     Upstream resolver (default 1.1.1.1:53)
        --no-upstream         Pure authoritative mode (refuse unknown names)
    -r, --records <file>      Authoritative records file (default records.conf)
        --hosts <file>        Import a /etc/hosts-style file (+ auto reverse PTR)
        --cache-size <n>      Max cache entries (default 2048)
        --ttl <n>             Default TTL for records without one (default 300)
    -s, --control-socket <p>  Unix control socket path (default /tmp/speedns.sock)
        --no-control          Disable the control socket
        --no-tcp              Disable the TCP listener
    -v, --verbose             Verbose logging
    -q, --quiet               Suppress non-error logging
    -V, --version             Print version and exit
        --help                Print this help and exit";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--help" || a == "-h" || a == "help") {
        println!("{}", HELP);
        std::process::exit(0);
    }
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("{} v{}", NAME, VERSION);
        std::process::exit(0);
    }

    let cli = match CliArgs::parse(&args) {
        Ok(cli) => cli,
        Err(e) => {
            eprintln!("error: {}", e);
            eprintln!("run 'speednsd --help' for usage");
            std::process::exit(2);
        }
    };
    let cfg = match load(&cli) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("error: {}", e);
            std::process::exit(2);
        }
    };

    if let Err(e) = run(cfg) {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}

fn run(cfg: speedns::config::Config) -> Result<(), String> {
    // ---- Build the authoritative store -----------------------------------
    let mut store = Store::new();
    if let Some(path) = &cfg.records_file {
        if speedns::config::path_exists(path) {
            let n = store
                .load_file(path, cfg.default_ttl)
                .map_err(|e| format!("records: {}", e))?;
            log(cfg.log_level, 1, &format!("loaded {} record(s) from '{}'", n, path));
        } else {
            log(cfg.log_level, 1, &format!("records file '{}' not found, starting empty", path));
        }
    }
    if let Some(path) = &cfg.hosts_file {
        let n = store
            .import_hosts_file(path, cfg.default_ttl)
            .map_err(|e| format!("hosts: {}", e))?;
        log(cfg.log_level, 1, &format!("imported {} host(s) from '{}'", n, path));
    }

    // ---- Resolver ---------------------------------------------------------
    let resolver = Arc::new(Resolver::new(store, cfg.cache_size, cfg.upstream, cfg.timeout_ms));

    // ---- Control socket ----------------------------------------------------
    if let Some(sock_path) = &cfg.control_socket {
        let control = ControlServer::new(resolver.clone(), sock_path)?;
        control.spawn()?;
        log(cfg.log_level, 1, &format!("control socket: {}", sock_path));
    }

    // ---- UDP listener -------------------------------------------------------
    let udp_sock = UdpSocket::bind(cfg.listen)
        .map_err(|e| format!("cannot bind UDP {}: {}", cfg.listen, e))?;
    let running = Arc::new(AtomicBool::new(true));

    {
        let resolver = resolver.clone();
        let running = running.clone();
        thread::Builder::new()
            .name("speedns-udp".to_string())
            .spawn(move || {
                let mut buf = [0u8; 4096];
                while running.load(Ordering::Relaxed) {
                    match udp_sock.recv_from(&mut buf) {
                        Ok((n, peer)) => {
                            let packet = buf[..n].to_vec();
                            let resolver = resolver.clone();
                            let udp_sock = udp_sock.try_clone();
                            let Ok(udp_sock) = udp_sock else { break };
                            thread::Builder::new()
                                .name("speedns-udp-q".to_string())
                                .spawn(move || {
                                    let response = resolver.handle_packet(&packet);
                                    if !response.is_empty() {
                                        let _ = udp_sock.send_to(&response, peer);
                                    }
                                })
                                .ok();
                        }
                        Err(_) => break,
                    }
                }
            })
            .map_err(|e| format!("cannot spawn UDP thread: {}", e))?;
    }

    // ---- TCP listener ---------------------------------------------------------
    if cfg.tcp {
        let tcp_listener = TcpListener::bind(cfg.listen)
            .map_err(|e| format!("cannot bind TCP {}: {}", cfg.listen, e))?;
        {
            let resolver = resolver.clone();
            let running = running.clone();
            thread::Builder::new()
                .name("speedns-tcp".to_string())
                .spawn(move || {
                    for stream in tcp_listener.incoming() {
                        if !running.load(Ordering::Relaxed) {
                            break;
                        }
                        let Ok(stream) = stream else { continue };
                        let resolver = resolver.clone();
                        thread::Builder::new()
                            .name("speedns-tcp-c".to_string())
                            .spawn(move || {
                                let _ = handle_tcp(stream, &resolver);
                            })
                            .ok();
                    }
                })
                .map_err(|e| format!("cannot spawn TCP thread: {}", e))?;
        }
    }

    // ---- Banner --------------------------------------------------------------
    println!();
    println!("  ███████╗██████╗ ███████╗███████╗██████╗ ███╗   ██╗███████╗");
    println!("  ██╔════╝██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║██╔════╝");
    println!("  ███████╗██████╔╝█████╗  █████╗  ██████╔╝██╔██╗ ██║███████╗");
    println!("  ╚════██║██╔═══╝ ██╔══╝  ██╔══╝  ██╔══██╗██║╚██╗██║╚════██║");
    println!("  ███████║██║     ███████╗███████╗██║  ██║██║ ╚████║███████║");
    println!("  ╚══════╝╚═╝     ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝");
    println!();
    println!("  {} v{}", NAME, VERSION);
    println!("  {}", TAGLINE);
    println!("  Powered By Vexify");
    println!();
    log(cfg.log_level, 1, &format!("listening on UDP{} {}", if cfg.tcp { "/TCP" } else { "" }, cfg.listen));
    log(
        cfg.log_level,
        1,
        &format!(
            "upstream: {} | cache: {} entries | zone records: {}",
            cfg.upstream.map(|a| a.to_string()).unwrap_or_else(|| "OFF (authoritative only)".to_string()),
            cfg.cache_size,
            resolver.store.read().unwrap().len(),
        ),
    );

    // ---- Keep the process alive ------------------------------------------------
    // Ctrl-C / SIGTERM terminate the process by default action; the control
    // socket is unlinked on the next start, so no stale state is left behind.
    loop {
        thread::sleep(std::time::Duration::from_secs(3600));
    }
}

/// Handle a single TCP client: length-prefixed queries until EOF.
fn handle_tcp(stream: std::net::TcpStream, resolver: &Resolver) -> Result<(), String> {
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .ok();
    let mut reader = std::io::BufReader::new(stream.try_clone().map_err(|e| e.to_string())?);
    let mut writer = stream;
    loop {
        let mut len_buf = [0u8; 2];
        match read_exact(&mut reader, &mut len_buf) {
            Ok(()) => {}
            Err(_) => break,
        }
        let len = u16::from_be_bytes(len_buf) as usize;
        if len == 0 || len > 4096 {
            break;
        }
        let mut packet = vec![0u8; len];
        if read_exact(&mut reader, &mut packet).is_err() {
            break;
        }
        let response = resolver.handle_packet_tcp(&packet);
        let rlen = response.len().min(u16::MAX as usize);
        writer
            .write_all(&(rlen as u16).to_be_bytes())
            .map_err(|e| e.to_string())?;
        writer.write_all(&response[..rlen]).map_err(|e| e.to_string())?;
        writer.flush().map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn read_exact<R: std::io::Read>(reader: &mut R, buf: &mut [u8]) -> std::io::Result<()> {
    let mut read = 0;
    while read < buf.len() {
        let n = reader.read(&mut buf[read..])?;
        if n == 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "eof"));
        }
        read += n;
    }
    Ok(())
}

/// Level-based logger: `level` = current verbosity, `min` = required.
fn log(level: u8, min: u8, msg: &str) {
    if level >= min && level > 0 {
        eprintln!("[speednsd] {}", msg);
    }
}
