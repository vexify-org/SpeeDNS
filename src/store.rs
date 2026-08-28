//! In-memory authoritative zone store.
//!
//! Records are kept in a flat, name-keyed map. SpeeDNS intentionally has no
//! heavyweight zone-file parser: a clean line-oriented records format plus a
//! `/etc/hosts` importer (with automatic reverse-PTR generation) is all an
//! ultra-lightweight private resolver needs.

use crate::dns::{
    canonical, type_from_str, RData, Record, TYPE_A, TYPE_AAAA, TYPE_CNAME, TYPE_MX, TYPE_NS,
    TYPE_PTR, TYPE_SOA, TYPE_SRV, TYPE_TXT,
};
use std::collections::HashMap;
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};

/// The authoritative record store.
#[derive(Debug, Default)]
pub struct Store {
    records: HashMap<String, Vec<Record>>,
}

impl Store {
    pub fn new() -> Store {
        Store {
            records: HashMap::new(),
        }
    }

    /// Total number of records (including duplicates).
    pub fn len(&self) -> usize {
        self.records.values().map(|v| v.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Insert a record, deduplicating exact (name, type, rdata) duplicates.
    pub fn insert(&mut self, rec: Record) {
        let key = canonical(&rec.name);
        let entry = self.records.entry(key).or_default();
        if !entry.iter().any(|r| {
            r.rtype == rec.rtype
                && r.rdata == rec.rdata
                && canonical(&r.name) == canonical(&rec.name)
        }) {
            entry.push(rec);
        }
    }

    /// All records owned by exactly `name`.
    pub fn lookup(&self, name: &str) -> Vec<Record> {
        self.records
            .get(&canonical(name))
            .cloned()
            .unwrap_or_default()
    }

    /// True when SpeeDNS is authoritative for `name`: either the name itself
    /// has records, or it lives under a configured zone (a name holding SOA/NS).
    pub fn is_authoritative(&self, name: &str) -> bool {
        let mut cur = canonical(name);
        loop {
            if self.records.contains_key(&cur) {
                let has_soa_ns = self.records[&cur]
                    .iter()
                    .any(|r| r.rtype == TYPE_SOA || r.rtype == TYPE_NS);
                if has_soa_ns || cur == canonical(name) {
                    return true;
                }
            }
            match cur.find('.') {
                Some(idx) => cur = cur[idx + 1..].to_string(),
                None => return false,
            }
        }
    }

    /// Remove a specific record. `value` is the raw RDATA string to match;
    /// when `None`, every record of that name+type is removed.
    /// Returns the number of records removed.
    pub fn remove(&mut self, name: &str, rtype: Option<u16>, value: Option<&str>) -> usize {
        let key = canonical(name);
        let Some(entry) = self.records.get_mut(&key) else {
            return 0;
        };
        let before = entry.len();
        match (rtype, value) {
            (None, None) => {
                entry.clear();
            }
            (Some(t), None) => entry.retain(|r| r.rtype != t),
            (Some(t), Some(v)) => entry.retain(|r| !(r.rtype == t && render_rdata(&r.rdata) == v)),
            (None, Some(v)) => entry.retain(|r| render_rdata(&r.rdata) != v),
        }
        let removed = before - entry.len();
        if entry.is_empty() {
            self.records.remove(&key);
        }
        removed
    }

    /// Remove the entire name (all types).
    pub fn remove_name(&mut self, name: &str) -> usize {
        self.records.remove(&canonical(name)).map(|v| v.len()).unwrap_or(0)
    }

    /// Flattened, sorted snapshot of every record.
    pub fn all(&self) -> Vec<Record> {
        let mut out: Vec<Record> = self.records.values().flatten().cloned().collect();
        out.sort_by(|a, b| {
            a.name
                .cmp(&b.name)
                .then(a.rtype.cmp(&b.rtype))
                .then(render_rdata(&a.rdata).cmp(&render_rdata(&b.rdata)))
        });
        out
    }

    /// Load a records file. Returns the number of records loaded.
    pub fn load_file(&mut self, path: &str, default_ttl: u32) -> Result<usize, String> {
        let content = fs::read_to_string(path)
            .map_err(|e| format!("cannot read '{}': {}", path, e))?;
        self.load_str(&content, default_ttl)
    }

    /// Parse a records file from a string. Returns the number of records.
    pub fn load_str(&mut self, content: &str, default_ttl: u32) -> Result<usize, String> {
        let mut count = 0;
        for (idx, raw) in content.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            match parse_record_line(line, default_ttl) {
                Ok(Some(rec)) => {
                    self.insert(rec);
                    count += 1;
                }
                Ok(None) => {}
                Err(e) => return Err(format!("line {}: {}", idx + 1, e)),
            }
        }
        Ok(count)
    }

    /// Import `/etc/hosts`-style lines. Generates A/AAAA records and,
    /// automatically, the matching reverse-PTR records.
    pub fn import_hosts(&mut self, content: &str, default_ttl: u32) -> Result<usize, String> {
        let mut count = 0;
        for (idx, raw) in content.lines().enumerate() {
            let line = match raw.split('#').next() {
                Some(l) => l.trim(),
                None => continue,
            };
            if line.is_empty() {
                continue;
            }
            let mut parts = line.split_whitespace();
            let addr = parts.next().ok_or_else(|| format!("hosts line {}: no address", idx + 1))?;
            let names: Vec<String> = parts.map(|n| n.to_ascii_lowercase()).collect();
            if names.is_empty() {
                continue;
            }
            if let Ok(ip4) = addr.parse::<Ipv4Addr>() {
                for n in &names {
                    self.insert(Record {
                        name: n.clone(),
                        rtype: TYPE_A,
                        ttl: default_ttl,
                        rdata: RData::A(ip4),
                    });
                }
                let ptr = reverse_v4(ip4);
                self.insert(Record {
                    name: ptr,
                    rtype: TYPE_PTR,
                    ttl: default_ttl,
                    rdata: RData::Ptr(names[0].clone()),
                });
                count += names.len() + 1;
            } else if let Ok(ip6) = addr.parse::<Ipv6Addr>() {
                for n in &names {
                    self.insert(Record {
                        name: n.clone(),
                        rtype: TYPE_AAAA,
                        ttl: default_ttl,
                        rdata: RData::Aaaa(ip6),
                    });
                }
                let ptr = reverse_v6(ip6);
                self.insert(Record {
                    name: ptr,
                    rtype: TYPE_PTR,
                    ttl: default_ttl,
                    rdata: RData::Ptr(names[0].clone()),
                });
                count += names.len() + 1;
            } else {
                return Err(format!("hosts line {}: invalid address '{}'", idx + 1, addr));
            }
        }
        Ok(count)
    }

    /// Import a hosts file from disk.
    pub fn import_hosts_file(&mut self, path: &str, default_ttl: u32) -> Result<usize, String> {
        let content = fs::read_to_string(path)
            .map_err(|e| format!("cannot read hosts '{}': {}", path, e))?;
        self.import_hosts(&content, default_ttl)
    }
}

/// Compute the IPv4 reverse-PTR name for an address.
pub fn reverse_v4(ip: Ipv4Addr) -> String {
    let o = ip.octets();
    format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
}

/// Compute the IPv6 reverse-PTR name for an address (RFC 3596, nibble format).
pub fn reverse_v6(ip: Ipv6Addr) -> String {
    let mut labels: Vec<String> = Vec::with_capacity(32);
    // ip6.arpa lists nibbles least-significant first, so walk the octets from
    // the last byte to the first, emitting low nibble then high nibble.
    for octet in ip.octets().iter().rev() {
        labels.push(format!("{:x}", octet & 0x0F));
        labels.push(format!("{:x}", octet >> 4));
    }
    format!("{}.ip6.arpa", labels.join("."))
}

/// Split a line into tokens, honoring double quotes (used for TXT data).
fn tokenize(line: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut in_quote = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                if in_quote {
                    tokens.push(std::mem::take(&mut cur));
                    in_quote = false;
                } else {
                    in_quote = true;
                }
            }
            '#' if !in_quote => break,
            c if c.is_whitespace() && !in_quote => {
                if !cur.is_empty() {
                    tokens.push(std::mem::take(&mut cur));
                }
            }
            '\\' => {
                if let Some(&next) = chars.peek() {
                    cur.push(next);
                    chars.next();
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        tokens.push(cur);
    }
    tokens
}

/// Parse a single records-file line into an optional record.
///
/// Format: `owner [ttl] TYPE rdata...` where `TYPE` is one of
/// A, AAAA, CNAME, NS, PTR, TXT, MX, SOA, SRV.
pub fn parse_record_line(line: &str, default_ttl: u32) -> Result<Option<Record>, String> {
    let tokens = tokenize(line);
    if tokens.is_empty() {
        return Ok(None);
    }
    let owner = canonical(&tokens[0]);
    let mut idx = 1;

    let ttl = if let Some(t) = tokens.get(idx) {
        if let Ok(ttl) = t.parse::<u32>() {
            idx += 1;
            ttl
        } else {
            default_ttl
        }
    } else {
        default_ttl
    };

    let rtype_str = tokens.get(idx).ok_or("missing record type")?;
    let rtype = type_from_str(rtype_str).ok_or_else(|| format!("unknown record type '{}'", rtype_str))?;
    idx += 1;

    let rdata_tokens = &tokens[idx..];
    let rdata = parse_rdata(rtype, rdata_tokens)?;

    Ok(Some(Record {
        name: owner,
        rtype,
        ttl,
        rdata,
    }))
}

fn parse_rdata(rtype: u16, t: &[String]) -> Result<RData, String> {
    fn need<'a>(t: &'a [String], i: usize, what: &str) -> Result<&'a str, String> {
        t.get(i).map(|s| s.as_str()).ok_or_else(|| format!("missing {}", what))
    }
    match rtype {
        TYPE_A => {
            let v = need(t, 0, "IPv4 address")?;
            v.parse::<Ipv4Addr>()
                .map(RData::A)
                .map_err(|_| format!("invalid A address '{}'", v))
        }
        TYPE_AAAA => {
            let v = need(t, 0, "IPv6 address")?;
            v.parse::<Ipv6Addr>()
                .map(RData::Aaaa)
                .map_err(|_| format!("invalid AAAA address '{}'", v))
        }
        TYPE_CNAME => Ok(RData::Cname(canonical(need(t, 0, "target name")?))),
        TYPE_NS => Ok(RData::Ns(canonical(need(t, 0, "nameserver name")?))),
        TYPE_PTR => Ok(RData::Ptr(canonical(need(t, 0, "target name")?))),
        TYPE_MX => {
            let pref = need(t, 0, "MX preference")?
                .parse::<u16>()
                .map_err(|_| "invalid MX preference".to_string())?;
            let exchange = canonical(need(t, 1, "MX exchange")?);
            Ok(RData::Mx { pref, exchange })
        }
        TYPE_TXT => {
            if t.is_empty() {
                return Err("missing TXT data".to_string());
            }
            let chunks = t.iter().map(|s| s.as_bytes().to_vec()).collect();
            Ok(RData::Txt(chunks))
        }
        TYPE_SOA => {
            let mname = canonical(need(t, 0, "SOA mname")?);
            let rname = canonical(need(t, 1, "SOA rname")?);
            let serial = need(t, 2, "SOA serial")?.parse::<u32>().map_err(|_| "invalid SOA serial".to_string())?;
            let refresh = need(t, 3, "SOA refresh")?.parse::<u32>().map_err(|_| "invalid SOA refresh".to_string())?;
            let retry = need(t, 4, "SOA retry")?.parse::<u32>().map_err(|_| "invalid SOA retry".to_string())?;
            let expire = need(t, 5, "SOA expire")?.parse::<u32>().map_err(|_| "invalid SOA expire".to_string())?;
            let minimum = need(t, 6, "SOA minimum")?.parse::<u32>().map_err(|_| "invalid SOA minimum".to_string())?;
            Ok(RData::Soa { mname, rname, serial, refresh, retry, expire, minimum })
        }
        TYPE_SRV => {
            let priority = need(t, 0, "SRV priority")?.parse::<u16>().map_err(|_| "invalid SRV priority".to_string())?;
            let weight = need(t, 1, "SRV weight")?.parse::<u16>().map_err(|_| "invalid SRV weight".to_string())?;
            let port = need(t, 2, "SRV port")?.parse::<u16>().map_err(|_| "invalid SRV port".to_string())?;
            let target = canonical(need(t, 3, "SRV target")?);
            Ok(RData::Srv { priority, weight, port, target })
        }
        _ => Err("record type not supported in zone files".to_string()),
    }
}

/// Render a record's RDATA as a single-line string.
pub fn render_rdata(rdata: &RData) -> String {
    match rdata {
        RData::A(ip) => ip.to_string(),
        RData::Aaaa(ip) => ip.to_string(),
        RData::Cname(n) => format!("{}.", n),
        RData::Ns(n) => format!("{}.", n),
        RData::Ptr(n) => format!("{}.", n),
        RData::Txt(chunks) => {
            let parts: Vec<String> = chunks
                .iter()
                .map(|c| format!("\"{}\"", String::from_utf8_lossy(c)))
                .collect();
            parts.join(" ")
        }
        RData::Mx { pref, exchange } => format!("{} {}.", pref, exchange),
        RData::Soa { mname, rname, serial, refresh, retry, expire, minimum } => {
            format!("{}. {}. {} {} {} {} {}", mname, rname, serial, refresh, retry, expire, minimum)
        }
        RData::Srv { priority, weight, port, target } => {
            format!("{} {} {} {}.", priority, weight, port, target)
        }
        RData::Raw(b) => hex_encode(b),
    }
}

/// Render a full record as a records-file line.
pub fn render_record(rec: &Record) -> String {
    format!(
        "{}. {} {} {}",
        rec.name,
        rec.ttl,
        crate::dns::type_name(rec.rtype),
        render_rdata(&rec.rdata)
    )
}

/// Render a record as a zone-format line: `name. ttl IN TYPE rdata`.
pub fn render_zone(rec: &Record) -> String {
    format!(
        "{}. {} IN {} {}",
        rec.name,
        rec.ttl,
        crate::dns::type_name(rec.rtype),
        render_rdata(&rec.rdata)
    )
}

/// Small hex encoder so we never import a dependency for it.
pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0F) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_lookup() {
        let src = "\
# comment
example.com. 300 A 192.168.1.10
www.example.com. A 192.168.1.11
example.com. AAAA 2001:db8::1
alias.example.com. CNAME example.com.
example.com. MX 10 mail.example.com.
example.com. TXT \"v=spf1 -all\"
example.com. SOA ns1.example.com. admin.example.com. 1 3600 600 604800 300
";
        let mut s = Store::new();
        let n = s.load_str(src, 60).unwrap();
        assert_eq!(n, 7);
        assert_eq!(s.lookup("example.com").len(), 5);
        assert!(s.is_authoritative("example.com"));
        assert!(s.is_authoritative("deep.sub.example.com"));
        assert!(!s.is_authoritative("other.com"));
        assert_eq!(s.lookup("www.example.com")[0].ttl, 60);
    }

    #[test]
    fn hosts_import_creates_ptr() {
        let mut s = Store::new();
        let n = s.import_hosts("10.0.0.5 router.local\n2001:db8::1 nas.local\n", 300).unwrap();
        assert_eq!(n, 4); // A + PTR for v4, AAAA + PTR for v6
        assert_eq!(s.lookup("5.0.0.10.in-addr.arpa").len(), 1);
        assert_eq!(s.lookup("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa").len(), 1);
    }

    #[test]
    fn remove_records() {
        let mut s = Store::new();
        s.load_str("example.com. A 1.2.3.4\nexample.com. A 5.6.7.8\n", 60).unwrap();
        assert_eq!(s.remove("example.com", Some(TYPE_A), Some("1.2.3.4")), 1);
        assert_eq!(s.lookup("example.com").len(), 1);
        assert_eq!(s.remove_name("example.com"), 1);
        assert!(s.is_empty());
    }

    #[test]
    fn reverse_names() {
        assert_eq!(reverse_v4("192.168.1.1".parse().unwrap()), "1.1.168.192.in-addr.arpa");
        assert!(reverse_v6("2001:db8::1".parse().unwrap()).ends_with(".ip6.arpa"));
    }

    #[test]
    fn encoded_owner_matches_wire() {
        assert_eq!(
            crate::dns::encode_name("example.com"),
            vec![7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0]
        );
    }
}
