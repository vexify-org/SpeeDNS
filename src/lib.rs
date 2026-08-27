//! SpeeDNS — ultra-lightweight, AI-native (MCP) private DNS server.
//!
//! Pure Rust, zero external dependencies, single static binaries. A hybrid
//! resolver that answers authoritatively from a local zone store, fast from a
//! TTL LRU cache, and forwards everything else to an upstream resolver.
//! Ships with a first-class MCP server so AI agents can query and manage DNS
//! natively.
//!
//! Binaries:
//! - [`speednsd`]    — the DNS daemon (UDP/TCP :53 + control socket)
//! - [`speedns-mcp`] — MCP stdio server exposing SpeeDNS as AI tools
//! - [`speedns`]     — dig-lite CLI + control client
//!
//! Powered By Vexify.

#![forbid(unsafe_code)]

pub mod cache;
pub mod config;
pub mod control;
pub mod dns;
pub mod json;
pub mod mcp;
pub mod resolver;
pub mod store;

/// Project name.
pub const NAME: &str = "SpeeDNS";
/// Version from Cargo.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
/// One-line mission statement.
pub const TAGLINE: &str =
    "Ultra-lightweight, AI-native (MCP) private DNS — pure Rust, zero dependencies.";
