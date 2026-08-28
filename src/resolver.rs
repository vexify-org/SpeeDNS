//! Query resolution: authoritative store → TTL cache → upstream forwarding.
//!
//! SpeeDNS is a hybrid resolver. Queries are answered authoritatively from
//! the local zone store, fast from the TTL cache, and otherwise forwarded to
//! a configured upstream resolver over UDP. Every hop is counted in stats.

use crate::cache::Cache;
use crate::dns::{
    build_response, canonical, decode_message, encode_message, type_name, Header, Message,
    Question, RData, Record, CLASS_IN, RCODE_FORMERR, RCODE_NOTIMP, RCODE_NOERROR, RCODE_NXDOMAIN,
    RCODE_REFUSED, RCODE_SERVFAIL, TYPE_ANY, TYPE_CNAME, TYPE_SOA,
};
use crate::store::Store;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Maximum CNAME chain length before giving up.
const MAX_CNAME_HOPS: usize = 8;
/// Upstream forward attempts per query.
const FORWARD_ATTEMPTS: u32 = 2;

/// Query counters exposed to `/status` and the MCP `server_status` tool.
#[derive(Debug)]
pub struct Stats {
    pub started: Instant,
    pub queries: AtomicU64,
    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,
    pub authoritative: AtomicU64,
    pub forwarded: AtomicU64,
    pub errors: AtomicU64,
    pub id_counter: AtomicU64,
}

impl Default for Stats {
    fn default() -> Stats {
        Stats {
            started: Instant::now(),
            queries: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            authoritative: AtomicU64::new(0),
            forwarded: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            id_counter: AtomicU64::new(1),
        }
    }
}

impl Stats {
    pub fn next_id(&self) -> u16 {
        (self.id_counter.fetch_add(1, Ordering::Relaxed) % 0xFFFF) as u16
    }
}

/// The result of resolving a single name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolveResult {
    pub rcode: u16,
    pub records: Vec<Record>,
    pub aa: bool,
}

/// The shared resolver engine.
pub struct Resolver {
    pub store: Arc<RwLock<Store>>,
    cache: RwLock<Cache>,
    upstream: Option<SocketAddr>,
    timeout: Duration,
    pub stats: Stats,
}

impl Resolver {
    pub fn new(store: Store, cache_size: usize, upstream: Option<SocketAddr>, timeout_ms: u64) -> Resolver {
        Resolver {
            store: Arc::new(RwLock::new(store)),
            cache: RwLock::new(Cache::new(cache_size)),
            upstream,
            timeout: Duration::from_millis(timeout_ms.max(100)),
            stats: Stats::default(),
        }
    }

    pub fn cache_size(&self) -> usize {
        self.cache.read().unwrap().len()
    }

    pub fn cache_snapshot(&self) -> Vec<(String, u16, u32, Vec<Record>)> {
        self.cache.read().unwrap().snapshot()
    }

    pub fn flush_cache(&self) {
        self.cache.write().unwrap().flush();
    }

    pub fn upstream(&self) -> Option<SocketAddr> {
        self.upstream
    }

    /// Handle a raw DNS packet and produce the raw response packet for UDP,
    /// honoring the client's EDNS0 buffer size and truncating with TC.
    pub fn handle_packet(&self, packet: &[u8]) -> Vec<u8> {
        let query = match decode_message(packet) {
            Ok(q) => q,
            Err(_) => return formerr(packet),
        };
        // Max UDP payload: 512 without EDNS, otherwise the client's advertised
        // size clamped to a sane ceiling.
        let max_payload = match query.edns {
            Some(e) => (e.udp_size as usize).clamp(512, 4096),
            None => 512,
        };
        let response = self.resolve(&query);
        response.encode_limited(max_payload)
    }

    /// Handle a raw DNS packet over TCP, where responses may use the full
    /// 64 KiB message size (RFC 1035 4.2.2).
    pub fn handle_packet_tcp(&self, packet: &[u8]) -> Vec<u8> {
        let query = match decode_message(packet) {
            Ok(q) => q,
            Err(_) => return formerr(packet),
        };
        let response = self.resolve(&query);
        encode_message(&response)
    }

    /// Resolve a parsed query into a response message.
    pub fn resolve(&self, query: &Message) -> Message {
        let Some(q) = query.questions.first() else {
            return build_response(query, vec![], vec![], false, self.recursion_available(), RCODE_FORMERR);
        };
        if query.header.opcode() != 0 {
            return build_response(query, vec![], vec![], false, self.recursion_available(), RCODE_NOTIMP);
        }
        if q.qclass != CLASS_IN {
            return build_response(query, vec![], vec![], false, self.recursion_available(), RCODE_REFUSED);
        }

        self.stats.queries.fetch_add(1, Ordering::Relaxed);
        let result = self.lookup(&q.name, q.qtype);
        if result.aa {
            self.stats.authoritative.fetch_add(1, Ordering::Relaxed);
        }
        let authorities = if result.rcode != RCODE_NOERROR {
            self.find_soa(&q.name)
        } else {
            Vec::new()
        };
        let mut response = build_response(
            query,
            result.records,
            authorities,
            result.aa,
            self.recursion_available(),
            result.rcode,
        );
        // Echo a minimal EDNS0 OPT when the client used EDNS (RFC 6891).
        if query.edns.is_some() {
            response.additionals.push(crate::dns::make_opt());
        }
        response
    }

    /// Whether this resolver can recurse on behalf of clients.
    fn recursion_available(&self) -> bool {
        self.upstream.is_some()
    }

    /// Resolve a name to a plain result (used by control / MCP tooling).
    pub fn resolve_name(&self, name: &str, qtype: u16) -> ResolveResult {
        self.lookup(name, qtype)
    }

    /// Core lookup with CNAME chasing, cache and forwarding.
    fn lookup(&self, name: &str, qtype: u16) -> ResolveResult {
        let mut answers: Vec<Record> = Vec::new();
        let mut current = canonical(name);
        let mut aa = false;

        for _ in 0..MAX_CNAME_HOPS {
            // 1. Authoritative store.
            let local = self.store.read().unwrap().lookup(&current);
            if !local.is_empty() {
                aa = true;
                let cname = local.iter().find(|r| r.rtype == TYPE_CNAME).cloned();
                let direct: Vec<Record> = if qtype == TYPE_ANY {
                    local.clone()
                } else {
                    local.iter().filter(|r| r.rtype == qtype).cloned().collect()
                };
                if !direct.is_empty() {
                    answers.extend(direct);
                    return ResolveResult { rcode: RCODE_NOERROR, records: answers, aa };
                }
                if let Some(cname_rec) = cname {
                    let target = match &cname_rec.rdata {
                        RData::Cname(t) => Some(canonical(t)),
                        _ => None,
                    };
                    answers.push(cname_rec);
                    if let Some(target) = target {
                        current = target;
                        continue;
                    }
                }
                // Authoritative but no data of this type → NODATA.
                return ResolveResult { rcode: RCODE_NOERROR, records: answers, aa };
            }
            if self.store.read().unwrap().is_authoritative(&current) {
                // We own this zone but the name does not exist: authoritative
                // NXDOMAIN (AA is set, matching what a real master answers).
                return ResolveResult { rcode: RCODE_NXDOMAIN, records: answers, aa: true };
            }

            // 2. TTL cache.
            if let Some((rcode, records)) = self.cache.write().unwrap().get(&current, qtype) {
                if rcode != RCODE_NOERROR {
                    return ResolveResult { rcode, records: answers, aa };
                }
                if !records.is_empty() {
                    self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
                    answers.extend(records);
                    return ResolveResult { rcode: RCODE_NOERROR, records: answers, aa };
                }
            } else {
                self.stats.cache_misses.fetch_add(1, Ordering::Relaxed);
            }

            // 3. Forward upstream.
            if self.upstream.is_none() {
                // Ultra-lightweight mode: no upstream, so anything not local is refused.
                return ResolveResult { rcode: RCODE_REFUSED, records: answers, aa };
            }
            match self.forward(&current, qtype) {
                Ok((rcode, records)) => {
                    if rcode != RCODE_NOERROR {
                        self.cache.write().unwrap().put_negative(&current, qtype, rcode);
                        return ResolveResult { rcode, records: answers, aa };
                    }
                    // Cache each answer under its own owner/type.
                    for rec in &records {
                        self.cache
                            .write()
                            .unwrap()
                            .put(&rec.name, rec.rtype, vec![rec.clone()], rec.ttl);
                    }
                    self.stats.forwarded.fetch_add(1, Ordering::Relaxed);
                    answers.extend(records);
                    return ResolveResult { rcode: RCODE_NOERROR, records: answers, aa };
                }
                Err(_) => {
                    self.stats.errors.fetch_add(1, Ordering::Relaxed);
                    return ResolveResult { rcode: RCODE_SERVFAIL, records: answers, aa };
                }
            }
        }

        // CNAME chain exceeded.
        ResolveResult { rcode: RCODE_NOERROR, records: answers, aa }
    }

    /// Forward a single (name, type) query to the upstream resolver.
    fn forward(&self, name: &str, qtype: u16) -> Result<(u16, Vec<Record>), String> {
        let upstream = self.upstream.ok_or("no upstream configured")?;

        let mut header = Header::default();
        header.id = self.stats.next_id();
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
        sock.connect(upstream).map_err(|e| e.to_string())?;
        sock.set_read_timeout(Some(self.timeout)).ok();

        for attempt in 0..FORWARD_ATTEMPTS {
            if attempt > 0 {
                sock.set_read_timeout(Some(self.timeout)).ok();
            }
            sock.send(&packet).map_err(|e| e.to_string())?;
            let mut buf = [0u8; 4096];
            match sock.recv(&mut buf) {
                Ok(n) => {
                    let response = decode_message(&buf[..n]).map_err(|e| e.to_string())?;
                    if response.header.id != header.id {
                        continue; // stale/aliased response, retry
                    }
                    let rcode = response.header.rcode();
                    let records = response.answers;
                    return Ok((rcode, records));
                }
                Err(_) => continue, // timeout, retry
            }
        }
        Err("upstream timeout".to_string())
    }

    /// Find a SOA record for the closest enclosing zone (for negative answers).
    fn find_soa(&self, name: &str) -> Vec<Record> {
        let store = self.store.read().unwrap();
        let mut cur = canonical(name);
        loop {
            let records = store.lookup(&cur);
            if !records.is_empty() {
                if let Some(soa) = records.iter().find(|r| r.rtype == TYPE_SOA) {
                    return vec![soa.clone()];
                }
            }
            match cur.find('.') {
                Some(idx) => cur = cur[idx + 1..].to_string(),
                None => return Vec::new(),
            }
        }
    }
}

/// Minimal FORMERR response when a packet cannot be decoded at all.
fn formerr(packet: &[u8]) -> Vec<u8> {
    if packet.len() >= 2 {
        let mut h = Header::default();
        h.id = u16::from_be_bytes([packet[0], packet[1]]);
        h.set_qr(true);
        h.set_rcode(RCODE_FORMERR);
        let resp = Message { header: h, ..Default::default() };
        return encode_message(&resp);
    }
    Vec::new()
}

/// Render a resolved result for human/JSON consumption.
pub fn records_to_json(records: &[Record]) -> crate::json::Json {
    let mut arr = crate::json::Json::arr();
    for r in records {
        let mut j = crate::json::Json::obj();
        j.insert("name", crate::json::Json::str(r.name.clone()));
        j.insert("type", crate::json::Json::str(type_name(r.rtype)));
        j.insert("ttl", crate::json::Json::num(r.ttl as f64));
        j.insert("value", crate::json::Json::str(rdata_to_string(&r.rdata)));
        arr.push(j);
    }
    arr
}

/// Human-readable RDATA rendering shared with the CLI.
pub fn rdata_to_string(rdata: &RData) -> String {
    match rdata {
        RData::A(ip) => ip.to_string(),
        RData::Aaaa(ip) => ip.to_string(),
        RData::Cname(n) | RData::Ns(n) | RData::Ptr(n) => format!("{}.", n),
        RData::Txt(chunks) => chunks
            .iter()
            .map(|c| String::from_utf8_lossy(c).to_string())
            .collect::<Vec<_>>()
            .join(" "),
        RData::Mx { pref, exchange } => format!("{} {}.", pref, exchange),
        RData::Soa { mname, rname, serial, refresh, retry, expire, minimum } => format!(
            "{}. {}. {} {} {} {} {}",
            mname, rname, serial, refresh, retry, expire, minimum
        ),
        RData::Srv { priority, weight, port, target } => {
            format!("{} {} {} {}.", priority, weight, port, target)
        }
        RData::Raw(b) => format!("0x{}", crate::store::hex_encode(b)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::TYPE_A;

    fn test_store() -> Store {
        let mut s = Store::new();
        s.load_str(
            "example.com. 300 SOA ns1.example.com. admin.example.com. 1 3600 600 604800 300\n\
             example.com. 300 A 192.0.2.1\n\
             alias.example.com. 300 CNAME example.com.\n",
            60,
        )
        .unwrap();
        s
    }

    #[test]
    fn authoritative_hit() {
        let r = Resolver::new(test_store(), 128, None, 500);
        let result = r.resolve_name("example.com", TYPE_A);
        assert_eq!(result.rcode, RCODE_NOERROR);
        assert!(result.aa);
        assert_eq!(result.records.len(), 1);
    }

    #[test]
    fn cname_chase() {
        let r = Resolver::new(test_store(), 128, None, 500);
        let result = r.resolve_name("alias.example.com", TYPE_A);
        assert_eq!(result.rcode, RCODE_NOERROR);
        assert_eq!(result.records.len(), 2); // CNAME + A
    }

    #[test]
    fn nxdomain_authoritative() {
        let r = Resolver::new(test_store(), 128, None, 500);
        let result = r.resolve_name("nope.example.com", TYPE_A);
        assert_eq!(result.rcode, RCODE_NXDOMAIN);
    }

    #[test]
    fn refused_without_upstream() {
        let r = Resolver::new(test_store(), 128, None, 500);
        let result = r.resolve_name("example.org", TYPE_A);
        assert_eq!(result.rcode, RCODE_REFUSED);
    }

    fn test_query(name: &str) -> Message {
        Message {
            header: Header { id: 1, qdcount: 1, ..Default::default() },
            questions: vec![Question {
                name: name.to_string(),
                qtype: TYPE_A,
                qclass: CLASS_IN,
            }],
            ..Default::default()
        }
    }

    #[test]
    fn ra_flag_reflects_upstream() {
        let query = test_query("example.com");
        // With an upstream: recursion is available → RA set.
        let rec = Resolver::new(
            test_store(),
            128,
            Some("1.1.1.1:53".parse().unwrap()),
            500,
        );
        assert!(rec.resolve(&query).header.ra());
        // Authoritative-only: RA must be clear, AA set.
        let auth = Resolver::new(test_store(), 128, None, 500);
        let resp = auth.resolve(&query);
        assert!(!resp.header.ra());
        assert!(resp.header.aa());
    }

    #[test]
    fn authoritative_nxdomain_has_aa() {
        let r = Resolver::new(test_store(), 128, None, 500);
        let result = r.resolve_name("nope.example.com", TYPE_A);
        assert_eq!(result.rcode, RCODE_NXDOMAIN);
        assert!(result.aa);
    }

    #[test]
    fn edns_query_echoes_opt() {
        let r = Resolver::new(test_store(), 128, None, 500);
        let mut query = test_query("example.com");
        query.edns = Some(crate::dns::Edns { udp_size: 4096, version: 0 });
        let resp = r.resolve(&query);
        assert_eq!(resp.additionals.len(), 1);
        assert_eq!(resp.additionals[0].rtype, crate::dns::TYPE_OPT);
    }
}
