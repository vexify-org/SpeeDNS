//! Configuration loading for the SpeeDNS daemon.
//!
//! Precedence (low → high): compiled defaults → config file → environment
//! variables (`SPEEDNS_*`) → command-line flags. The config file is a small
//! TOML-style subset — flat `key = value` lines with quoted strings, numbers
//! and booleans — so SpeeDNS stays dependency-free.

use std::net::SocketAddr;
use std::path::Path;

/// Fully-resolved daemon configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// UDP listen address (and TCP, if enabled).
    pub listen: SocketAddr,
    /// Serve TCP in addition to UDP.
    pub tcp: bool,
    /// Upstream resolver for names outside the local store. `None` = pure
    /// authoritative mode (anything unknown is REFUSED).
    pub upstream: Option<SocketAddr>,
    /// Path to the authoritative records file (optional).
    pub records_file: Option<String>,
    /// Path to a `/etc/hosts`-style file to import (optional).
    pub hosts_file: Option<String>,
    /// Maximum cache entries.
    pub cache_size: usize,
    /// Default TTL for records without one.
    pub default_ttl: u32,
    /// Upstream timeout in milliseconds.
    pub timeout_ms: u64,
    /// Unix control socket path (optional).
    pub control_socket: Option<String>,
    /// Log verbosity: 0 = quiet, 1 = normal, 2 = verbose.
    pub log_level: u8,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            listen: "127.0.0.1:53".parse().unwrap(),
            tcp: true,
            upstream: Some("1.1.1.1:53".parse().unwrap()),
            records_file: Some("records.conf".to_string()),
            hosts_file: None,
            cache_size: 2048,
            default_ttl: 300,
            timeout_ms: 1500,
            control_socket: Some("/tmp/speedns.sock".to_string()),
            log_level: 1,
        }
    }
}

impl Config {
    /// Apply a single `key = value` setting. Returns an error for unknown keys.
    pub fn set(&mut self, key: &str, value: &str) -> Result<(), String> {
        let v = value.trim().trim_matches('"');
        match key {
            "listen" => {
                self.listen = v
                    .parse()
                    .map_err(|_| format!("invalid listen address '{}'", v))?;
            }
            "tcp" => self.tcp = parse_bool(v)?,
            "upstream" => {
                if v.is_empty() || v.eq_ignore_ascii_case("none") {
                    self.upstream = None;
                } else {
                    self.upstream = Some(
                        v.parse()
                            .map_err(|_| format!("invalid upstream '{}'", v))?,
                    );
                }
            }
            "records" => self.records_file = optional_path(v),
            "hosts" => self.hosts_file = optional_path(v),
            "cache_size" => {
                self.cache_size = v
                    .parse()
                    .map_err(|_| format!("invalid cache_size '{}'", v))?;
            }
            "default_ttl" | "ttl" => {
                self.default_ttl = v
                    .parse()
                    .map_err(|_| format!("invalid default_ttl '{}'", v))?;
            }
            "timeout_ms" => {
                self.timeout_ms = v
                    .parse()
                    .map_err(|_| format!("invalid timeout_ms '{}'", v))?;
            }
            "control_socket" => self.control_socket = optional_path(v),
            "log_level" => {
                self.log_level = match v.to_ascii_lowercase().as_str() {
                    "quiet" | "error" | "0" => 0,
                    "info" | "normal" | "1" => 1,
                    "debug" | "verbose" | "2" => 2,
                    _ => return Err(format!("invalid log_level '{}'", v)),
                };
            }
            other => return Err(format!("unknown config key '{}'", other)),
        }
        Ok(())
    }

    /// Load a config file, overriding current values.
    pub fn apply_file(&mut self, path: &str) -> Result<(), String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read config '{}': {}", path, e))?;
        for (idx, raw) in content.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some(eq) = line.find('=') else {
                return Err(format!("config line {}: expected 'key = value'", idx + 1));
            };
            let key = line[..eq].trim();
            let value = line[eq + 1..].trim();
            self.set(key, value)
                .map_err(|e| format!("config line {}: {}", idx + 1, e))?;
        }
        Ok(())
    }

    /// Apply `SPEEDNS_*` environment overrides (best-effort).
    pub fn apply_env(&mut self) {
        for (key, var) in [
            ("listen", "SPEEDNS_LISTEN"),
            ("upstream", "SPEEDNS_UPSTREAM"),
            ("records", "SPEEDNS_RECORDS"),
            ("hosts", "SPEEDNS_HOSTS"),
            ("cache_size", "SPEEDNS_CACHE_SIZE"),
            ("default_ttl", "SPEEDNS_TTL"),
            ("control_socket", "SPEEDNS_CONTROL_SOCKET"),
        ] {
            if let Ok(val) = std::env::var(var) {
                let _ = self.set(key, &val);
            }
        }
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.cache_size < 16 {
            return Err("cache_size must be at least 16".to_string());
        }
        Ok(())
    }
}

fn parse_bool(v: &str) -> Result<bool, String> {
    match v.to_ascii_lowercase().as_str() {
        "true" | "yes" | "on" | "1" => Ok(true),
        "false" | "no" | "off" | "0" => Ok(false),
        _ => Err(format!("invalid boolean '{}'", v)),
    }
}

fn optional_path(v: &str) -> Option<String> {
    let t = v.trim_matches('"');
    if t.is_empty() || t.eq_ignore_ascii_case("none") {
        None
    } else {
        Some(t.to_string())
    }
}

/// A parsed command-line surface for the daemon.
#[derive(Debug, Default)]
pub struct CliArgs {
    pub config: Option<String>,
    pub listen: Option<String>,
    pub upstream: Option<String>,
    pub no_upstream: bool,
    pub records: Option<String>,
    pub hosts: Option<String>,
    pub cache_size: Option<usize>,
    pub default_ttl: Option<u32>,
    pub control_socket: Option<String>,
    pub no_control: bool,
    pub no_tcp: bool,
    pub tcp: bool,
    pub verbose: bool,
    pub quiet: bool,
}

impl CliArgs {
    /// Parse `--key value` / `-k value` style arguments (no combinators).
    pub fn parse(args: &[String]) -> Result<CliArgs, String> {
        let mut cli = CliArgs::default();
        let mut i = 0;
        while i < args.len() {
            let a = &args[i];
            let take_value = |flag: &str, i: &mut usize| -> Result<String, String> {
                *i += 1;
                args.get(*i)
                    .cloned()
                    .ok_or_else(|| format!("missing value for {}", flag))
            };
            match a.as_str() {
                "-c" | "--config" => cli.config = Some(take_value(a, &mut i)?),
                "-l" | "--listen" => cli.listen = Some(take_value(a, &mut i)?),
                "-u" | "--upstream" => cli.upstream = Some(take_value(a, &mut i)?),
                "--no-upstream" => cli.no_upstream = true,
                "-r" | "--records" => cli.records = Some(take_value(a, &mut i)?),
                "--hosts" => cli.hosts = Some(take_value(a, &mut i)?),
                "--cache-size" => {
                    cli.cache_size = Some(
                        take_value(a, &mut i)?.parse().map_err(|_| "invalid --cache-size".to_string())?,
                    )
                }
                "--ttl" => {
                    cli.default_ttl = Some(
                        take_value(a, &mut i)?.parse().map_err(|_| "invalid --ttl".to_string())?,
                    )
                }
                "-s" | "--control-socket" => cli.control_socket = Some(take_value(a, &mut i)?),
                "--no-control" => cli.no_control = true,
                "--no-tcp" => cli.no_tcp = true,
                "-t" | "--tcp" => cli.tcp = true,
                "-v" | "--verbose" => cli.verbose = true,
                "-q" | "--quiet" => cli.quiet = true,
                "-V" | "--version" => return Err("__VERSION__".to_string()),
                "--help" | "-h" => return Err("__HELP__".to_string()),
                other => return Err(format!("unknown argument '{}'", other)),
            }
            i += 1;
        }
        Ok(cli)
    }

    /// Merge CLI overrides into a config.
    pub fn apply_to(&self, cfg: &mut Config) -> Result<(), String> {
        if let Some(v) = &self.listen {
            cfg.set("listen", v)?;
        }
        if let Some(v) = &self.upstream {
            cfg.set("upstream", v)?;
        }
        if self.no_upstream {
            cfg.upstream = None;
        }
        if let Some(v) = &self.records {
            cfg.set("records", v)?;
        }
        if let Some(v) = &self.hosts {
            cfg.set("hosts", v)?;
        }
        if let Some(v) = self.cache_size {
            cfg.cache_size = v;
        }
        if let Some(v) = self.default_ttl {
            cfg.default_ttl = v;
        }
        if self.no_control {
            cfg.control_socket = None;
        } else if let Some(v) = &self.control_socket {
            cfg.set("control_socket", v)?;
        }
        if self.no_tcp {
            cfg.tcp = false;
        } else if self.tcp {
            cfg.tcp = true;
        }
        if self.verbose {
            cfg.log_level = 2;
        }
        if self.quiet {
            cfg.log_level = 0;
        }
        Ok(())
    }
}

/// Resolve the effective config from file + env + CLI.
pub fn load(cli: &CliArgs) -> Result<Config, String> {
    let mut cfg = Config::default();
    if let Some(path) = &cli.config {
        cfg.apply_file(path)?;
    }
    cfg.apply_env();
    cli.apply_to(&mut cfg)?;
    cfg.validate()?;
    Ok(cfg)
}

/// Check whether a path exists.
pub fn path_exists(p: &str) -> bool {
    Path::new(p).exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_config_file() {
        let dir = std::env::temp_dir();
        let path = dir.join("speedns_test.toml");
        std::fs::write(
            &path,
            "# test\nlisten = \"127.0.0.1:5353\"\nupstream = \"8.8.8.8:53\"\ncache_size = 512\ncontrol_socket = \"none\"\n",
        )
        .unwrap();
        let mut c = Config::default();
        c.apply_file(path.to_str().unwrap()).unwrap();
        assert_eq!(c.listen.port(), 5353);
        assert_eq!(c.upstream.unwrap().to_string(), "8.8.8.8:53");
        assert_eq!(c.cache_size, 512);
        assert!(c.control_socket.is_none());
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn cli_merge() {
        let args: Vec<String> = vec![
            "--listen".into(),
            "0.0.0.0:1053".into(),
            "--no-upstream".into(),
            "--cache-size".into(),
            "64".into(),
            "--verbose".into(),
        ];
        let cli = CliArgs::parse(&args).unwrap();
        let mut cfg = Config::default();
        cli.apply_to(&mut cfg).unwrap();
        assert_eq!(cfg.listen.port(), 1053);
        assert!(cfg.upstream.is_none());
        assert_eq!(cfg.cache_size, 64);
        assert_eq!(cfg.log_level, 2);
    }
}
