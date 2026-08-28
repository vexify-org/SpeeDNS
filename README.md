<div align="center">

# ⚡ SpeeDNS

**The AI-native, ultra-lightweight private DNS server.**

Pure Rust. **Zero dependencies.** One static binary. Native MCP.

`Powered By Vexify`

![Rust](https://img.shields.io/badge/Rust-1.74%2B-orange?logo=rust)
![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)
![License](https://img.shields.io/badge/license-Apache--2.0-blue)
![Build](https://img.shields.io/badge/build-passing-brightgreen)
![Binary](https://img.shields.io/badge/size-%E2%89%A4598%20KB-success)

> Stop outsourcing your DNS to strangers. Run a private resolver that answers
> in microseconds, caches like a hawk, and lets **AI agents operate it natively**
> through the Model Context Protocol.

</div>

---

## Why SpeeDNS

The Domain Name System is the backbone of everything you do online — yet almost
everyone delegates it to a third party, and almost nobody can manage it from
inside their own tools. Existing private resolvers are heavyweight: enormous
dependency trees, configuration languages the size of a small compiler, and no
way for an AI to actually *operate* them.

SpeeDNS inverts that.

- **Zero dependencies.** Not one crate. The DNS wire protocol, the JSON engine,
  the MCP bridge — all written by hand on top of `std`. Fewer dependencies mean
  fewer CVEs, faster builds, and a binary measured in **kilobytes**, not gigabytes.
- **Private by default.** Bind `127.0.0.1:53`, load your own zone records, import
  your hosts file, and never leak a query outside your machine. Pure-authoritative
  mode exists: forward nothing, tell the world to go away.
- **AI-native.** SpeeDNS ships a first-class **MCP server** (`speedns-mcp`) that
  speaks JSON-RPC 2.0 over stdio. Any MCP host — Claude, TRAE, Cursor, or your own
  agent — can resolve names, add and remove records, flush the cache, and read live
  telemetry, natively.
- **Fast.** Authoritative answers from an in-memory store; everything else served
  from a TTL-decaying LRU cache; only true misses touch the upstream. On a private
  network, most queries never leave the box.

## Features

| Capability | Detail |
|---|---|
| 🚀 **Hybrid resolver** | Authoritative zone store → TTL LRU cache → upstream forwarding, with automatic CNAME chasing |
| 🧠 **AI-native MCP** | 8 tools over JSON-RPC 2.0/stdio: resolve, reverse, records, cache, telemetry |
| 🔒 **Private mode** | `--no-upstream` / `upstream = "none"` → anything unknown is REFUSED, zero leaks |
| 📦 **Zero dependencies** | 100% `std`, `#![forbid(unsafe_code)]`, one static binary per component |
| 🗂️ **Zone records** | Clean line format: A, AAAA, CNAME, MX, NS, PTR, SOA, SRV, TXT |
| 🏠 **hosts import** | Import `/etc/hosts`-style files with **automatic reverse-PTR generation** (v4 + v6) |
| ⚡ **TTL cache** | Bounded LRU with natural TTL decay and negative caching (NXDOMAIN/SERVFAIL) |
| 🌐 **UDP + TCP** | Full wire-protocol serving on 53, plus TCP for large/streamed answers |
| 🛠️ **Control plane** | Unix-socket JSON API: add/remove records, flush cache, live stats |
| 🖥️ **Web console** | Zero-dependency dashboard on `:80`: live stats, DNS query, add/remove records |
| 📟 **dig-lite CLI** | `speedns resolve`, `reverse`, `records`, `add`, `rm`, `flush`, `status` |
| 🪶 **Tiny binary** | ≈ 0.4–0.6 MB release binaries from ~3,900 lines of Rust |

## Architecture

```
                         ┌──────────────────────────────────────────────┐
                         │              speednsd (:53)                  │
                         │                                              │
   dig / curl / app ───▶ │  UDP │ TCP  ──▶  Resolver                    │
   (wire protocol)       │                 ├─▶ Zone Store  (authoritative)
                         │                 ├─▶ TTL Cache   (LRU, decay) │
                         │                 └─▶ Upstream    (UDP, retry) │
                         │                                              │
                         │              Control socket (Unix)           │
                         └───────────────────────▲──────────────────────┘
                                                 │ JSON-lines
                      ┌──────────────────────────┴───────────┐
                      │   speedns (CLI)        speedns-mcp    │
                      │   dig-lite + control    MCP tools     │
                      └───────────────────────────────────────┘
                                      ▲
                                      │ JSON-RPC 2.0 / stdio (NDJSON)
                        Claude · TRAE · Cursor · any MCP host
```

## Quick Start

```bash
# Build (release, zero dependencies)
cargo build --release

# Run the daemon — private authoritative mode on a test port
./target/release/speednsd \
    --listen 127.0.0.1:15353 \
    --no-upstream \
    --records examples/records.conf \
    --control-socket /tmp/speedns.sock

# Query it like dig
./target/release/speedns resolve api.speedns.local A --server 127.0.0.1:15353
#   ;; ANSWER SECTION:
#   api.speedns.local. 300 IN A 192.168.1.10

# CNAME chasing for free
./target/release/speedns resolve app.speedns.local --server 127.0.0.1:15353

# Reverse lookup
./target/release/speedns reverse 127.0.0.1 --server 127.0.0.1:15353

# Manage at runtime
./target/release/speedns add "staging.speedns.local. 60 A 10.9.9.9"
./target/release/speedns records
./target/release/speedns rm staging.speedns.local A
./target/release/speedns status
```

Point your system at it:

```bash
# Linux (systemd-resolved stub on 127.0.0.53 must be freed first, or use a port)
sudo ./target/release/speednsd --listen 127.0.0.1:53 --records records.conf
echo "nameserver 127.0.0.1" | sudo tee /etc/resolv.conf
```

> Run on `:53` needs root. For daily use, bind a high port and point clients at
> it, or grant `CAP_NET_BIND_SERVICE`.

## 🤖 AI-Native: MCP

SpeeDNS is the first DNS server designed to be **operated by AI agents**.
`speedns-mcp` is a complete MCP server — newline-delimited JSON-RPC 2.0 over
stdio, exactly per the MCP transport spec — exposing the resolver as native tools.

### Connect it

**Claude Desktop** — `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "speedns": {
      "command": "/path/to/speedns-mcp",
      "args": ["--control-socket", "/tmp/speedns.sock"],
      "env": { "SPEEDNS_CONTROL_SOCKET": "/tmp/speedns.sock" }
    }
  }
}
```

**TRAE / Cursor / any MCP client** — point it at the same command. That's it.

### The tools

| Tool | What the agent can do |
|---|---|
| `dns_resolve` | Resolve any name through your resolver (local → cache → upstream) |
| `dns_reverse` | Reverse-PTR lookup from an IPv4/IPv6 address |
| `records_list` | List every locally authoritative record |
| `record_add` | Add a record at runtime (`"app.example.com. 300 A 192.168.1.42"`) |
| `record_remove` | Remove records by name / type / value |
| `cache_flush` | Flush the response cache |
| `cache_snapshot` | Dump current cache contents |
| `server_status` | Read live telemetry: uptime, query counters, cache, upstream |

Try it by hand:

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' \
  | ./target/release/speedns-mcp 2>/dev/null

echo '{"jsonrpc":"2.0","id":2,"method":"tools/call",
       "params":{"name":"dns_resolve",
                 "arguments":{"name":"api.speedns.local","type":"A"}}}' \
  | ./target/release/speedns-mcp 2>/dev/null
```

## 🖥️ Web Console

SpeeDNS ships a built-in zero-dependency web console — no Node, no nginx, no
external assets. It serves a single dark-themed SPA at the root and a small
JSON API under `/api/*`, all backed by the same control plane the CLI and MCP
use.

```bash
# Default: bind 0.0.0.0:80 (needs root). Pick a port or disable as you like.
./target/release/speednsd --listen 127.0.0.1:53 --records records.conf
# → web dashboard: http://0.0.0.0:80

# High port, no root required
./target/release/speednsd --listen 127.0.0.1:53 --web 0.0.0.0:8080
# → http://localhost:8080

# Turn it off entirely
./target/release/speednsd --no-web
```

What the console gives you:

- **运行状态** — live telemetry: record count, cache entries, query counters,
  upstream mode, uptime.
- **DNS 查询** — resolve any name through the full pipeline (zone → cache →
  upstream) with any record type.
- **新增记录** — add authoritative records at runtime (A, AAAA, CNAME, MX, NS,
  SOA, TXT, PTR, SRV).
- **权威记录** — browse and delete every zone record with one click.
- **清空缓存** — flush the TTL cache.

JSON API (same semantics as the CLI/MCP control plane):

```text
GET  /api/status          live telemetry
GET  /api/records?name=…  zone records
GET  /api/query?name=..&type=..  live resolution
POST /api/add             { "record": "app.example.com. 60 A 192.0.2.10" }
POST /api/remove          { "name": …, "type": …, "value": … }
POST /api/flush           clear the cache
```

> ⚠️ **Security:** by default the console binds `0.0.0.0:80` and exposes
> read/write record management to anyone who can reach it. Bind it to localhost
> (`--web 127.0.0.1:8080`), or restrict it behind your firewall/VPN when it must
> be on a public interface.

## Configuration

Config file (TOML-flavored), environment variables (`SPEEDNS_*`), and CLI flags,
in that order of precedence.

```toml
# speedns.conf
listen = "127.0.0.1:53"
tcp = true
upstream = "1.1.1.1:53"        # "none" for pure authoritative mode
records = "records.conf"
hosts = "/etc/hosts"           # optional: auto reverse-PTR for every entry
cache_size = 2048
default_ttl = 300
timeout_ms = 1500
control_socket = "/tmp/speedns.sock"
web = "0.0.0.0:80"            # web console; "none" to disable
log_level = "info"
```

```bash
speednsd -c speedns.conf --no-upstream --cache-size 4096 --verbose
```

## Records file

```text
# <owner> [ttl] <TYPE> <rdata>
speedns.local.   300 SOA  ns1.speedns.local. admin.speedns.local. 1 3600 600 604800 300
speedns.local.   300 NS   ns1.speedns.local.
api.speedns.local.     A   192.168.1.10        # TTL falls back to default_ttl
nas.speedns.local.     AAAA 2001:db8::42
app.speedns.local.     CNAME api.speedns.local.
speedns.local.   300 MX   10 mail.speedns.local.
speedns.local.   300 TXT  "v=spf1 -all"
_sip._tcp.speedns.local.  300 SRV 10 60 5060 sip.speedns.local.
```

The `/etc/hosts` importer turns every `address name` line into an A/AAAA record
**and** the matching reverse-PTR record automatically.

## 🏛️ Authoritative DNS

Run SpeeDNS as a real authoritative server for your own zones — the same wire
protocol that `dig` and every resolver expects. Start with `--no-upstream`
(or `upstream = "none"`), load your zone, and it answers with correct
authoritative semantics:

- **`AA` flag** on every answer from your zone — resolvers treat it as the
  source of truth.
- **`RA` flag** cleared in authoritative-only mode — this is a master server,
  not a recursive resolver.
- **NXDOMAIN** for missing names *inside* your zone, with the **SOA** attached
  in the AUTHORITY section, so downstream negative caching works.
- **NODATA** for existing names that have no records of the requested type.
- **REFUSED** for anything *outside* your zones — nothing leaks upstream.
- **EDNS0** respected: responses honor the client's advertised UDP payload size
  (default 1232). Oversized answers are **truncated with the `TC` bit**, and the
  client falls back to **TCP**, where the full answer is served.
- **Record types**: A, AAAA, CNAME, MX, NS, PTR, SOA, SRV, TXT.

Example — serve `vexify.io` authoritatively:

```bash
# records.conf
vexify.io.    300 SOA  ns1.vexify.io. admin.vexify.io. 2026082801 3600 600 604800 300
vexify.io.    300 NS   ns1.vexify.io.
ns1.vexify.io. 300 A   127.0.0.1
vexify.io.    300 A    192.0.2.1
www.vexify.io. 300 A    192.0.2.10
mail.vexify.io. 300 MX  10 mail.vexify.io.
alias.vexify.io. 300 CNAME www.vexify.io.

# serve it
./target/release/speednsd --listen 127.0.0.1:53 --no-upstream --records records.conf

# verify it like any authority
dig @127.0.0.1 vexify.io A        # flags: qr aa rd;  answer 192.0.2.1
dig @127.0.0.1 nope.vexify.io A   # status: NXDOMAIN; SOA in AUTHORITY section
dig @127.0.0.1 example.org A      # status: REFUSED (outside your zone)
```

## CLI reference

```text
speedns resolve <name> [type] [--server <addr>]   DNS wire query (dig-lite)
speedns reverse <ip>        [--server <addr>]     PTR lookup
speedns status                                    live telemetry
speedns records [name]                            list zone records
speedns add "<owner> [ttl] <TYPE> <rdata>"        add at runtime
speedns rm <name> [type] [value]                  remove records
speedns flush                                     flush the cache
speedns cache                                     snapshot cached entries
```

## What it is not

SpeeDNS **is** a real authoritative server for the zones you load into it
(proper `AA`/NXDOMAIN/SOA semantics, EDNS0, TCP fallback). What it is **not** is
a full DNSSEC-signing, multi-zone, anycast-grade appliance. It is the sharp,
tiny tool for the 99% case: a private, AI-operated resolver — and, when you
want, authoritative server — for your laptop, LAN, homelab, or dev environment.
It wants to be understood in an afternoon and trusted for years.

## Roadmap

- [ ] TCP load balancing / query pipelining tuning
- [ ] `resources/` and `prompts/` MCP capabilities
- [ ] Cache persistence across restarts
- [ ] Configurable blocklists (ad/tracker filtering)
- [ ] `--daemonize` and systemd unit example

## Contributing

Contributions are welcome and encouraged — including brand-new record types,
performance work, or documentation. Keep the zero-dependency discipline:
**no new crates without a very good argument.**

1. Fork & branch
2. `cargo build && cargo test`
3. Open a pull request

## License

Licensed under the **Apache License 2.0**. See [LICENSE](LICENSE).

---

<div align="center">

**SpeeDNS — the DNS you own, and the DNS your AI can drive.**

`Powered By Vexify`

</div>
