//! TTL-aware LRU response cache.
//!
//! Cached entries carry their original TTL and a fetch timestamp, so answers
//! decay naturally and are served until the freshest record expires. Bounded
//! by a maximum entry count with least-recently-used eviction, and supports
//! short negative caching for NXDOMAIN / SERVFAIL.

use crate::dns::{Record, RCODE_NXDOMAIN, RCODE_SERVFAIL};
use std::collections::{HashMap, VecDeque};
use std::time::Instant;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Key {
    name: String,
    qtype: u16,
}

#[derive(Debug, Clone)]
struct Entry {
    rcode: u16,
    records: Vec<Record>,
    fetched_at: Instant,
    ttl: u32,
}

/// How long to hold negative (NXDOMAIN / SERVFAIL) answers.
const NEGATIVE_TTL: u32 = 30;
/// Decay floor so a cached answer is never served with TTL 0.
const MIN_TTL: u32 = 1;

/// A bounded, TTL-decaying LRU cache.
#[derive(Debug)]
pub struct Cache {
    max_entries: usize,
    map: HashMap<Key, Entry>,
    order: VecDeque<Key>,
}

impl Cache {
    pub fn new(max_entries: usize) -> Cache {
        Cache {
            max_entries: max_entries.max(1),
            map: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Cache a positive answer. `ttl` is the response's minimum TTL.
    pub fn put(&mut self, name: &str, qtype: u16, records: Vec<Record>, ttl: u32) {
        let key = Key {
            name: name.to_ascii_lowercase(),
            qtype,
        };
        self.touch(&key);
        self.map.insert(
            key,
            Entry {
                rcode: 0,
                records,
                fetched_at: Instant::now(),
                ttl: ttl.max(1),
            },
        );
        self.evict();
    }

    /// Cache a negative answer (NXDOMAIN / SERVFAIL).
    pub fn put_negative(&mut self, name: &str, qtype: u16, rcode: u16) {
        if rcode != RCODE_NXDOMAIN && rcode != RCODE_SERVFAIL {
            return;
        }
        let key = Key {
            name: name.to_ascii_lowercase(),
            qtype,
        };
        self.touch(&key);
        self.map.insert(
            key,
            Entry {
                rcode,
                records: Vec::new(),
                fetched_at: Instant::now(),
                ttl: NEGATIVE_TTL,
            },
        );
        self.evict();
    }

    /// Look up a cached entry, decaying TTLs. Returns `(rcode, records)`.
    pub fn get(&mut self, name: &str, qtype: u16) -> Option<(u16, Vec<Record>)> {
        let key = Key {
            name: name.to_ascii_lowercase(),
            qtype,
        };
        let (rcode, records) = {
            let entry = self.map.get(&key)?;
            let elapsed = entry.fetched_at.elapsed().as_secs() as u32;
            if elapsed >= entry.ttl {
                return None;
            }
            let remaining = entry.ttl - elapsed;
            let records = if entry.rcode == 0 {
                entry
                    .records
                    .iter()
                    .map(|r| Record {
                        name: r.name.clone(),
                        rtype: r.rtype,
                        ttl: r.ttl.saturating_sub(elapsed).max(MIN_TTL).min(remaining),
                        rdata: r.rdata.clone(),
                    })
                    .collect()
            } else {
                Vec::new()
            };
            (entry.rcode, records)
        };
        self.touch(&key);
        Some((rcode, records))
    }

    /// Purge everything.
    pub fn flush(&mut self) {
        self.map.clear();
        self.order.clear();
    }

    /// Snapshot all live entries for status/audit: `(name, qtype, ttl, records)`.
    pub fn snapshot(&self) -> Vec<(String, u16, u32, Vec<Record>)> {
        let now = Instant::now();
        let mut out = Vec::new();
        for (key, entry) in &self.map {
            let elapsed = now.duration_since(entry.fetched_at).as_secs() as u32;
            let remaining = entry.ttl.saturating_sub(elapsed);
            if remaining == 0 {
                continue;
            }
            out.push((key.name.clone(), key.qtype, remaining, entry.records.clone()));
        }
        out.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
        out
    }

    fn touch(&mut self, key: &Key) {
        if let Some(pos) = self.order.iter().position(|k| k == key) {
            self.order.remove(pos);
        }
        self.order.push_back(key.clone());
    }

    fn evict(&mut self) {
        while self.map.len() > self.max_entries {
            match self.order.pop_front() {
                Some(k) => {
                    self.map.remove(&k);
                }
                None => break,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::{RData, TYPE_A, TYPE_CNAME};

    #[test]
    fn cache_roundtrip_and_decay() {
        let mut c = Cache::new(16);
        let rec = Record {
            name: "example.com".to_string(),
            rtype: TYPE_A,
            ttl: 60,
            rdata: RData::Cname("x".to_string()), // reuse; type mismatch is fine for cache
        };
        c.put("example.com", TYPE_A, vec![rec], 60);
        let (rcode, records) = c.get("example.com", TYPE_A).unwrap();
        assert_eq!(rcode, 0);
        assert_eq!(records.len(), 1);
        assert!(records[0].ttl <= 60);
    }

    #[test]
    fn negative_caching() {
        let mut c = Cache::new(16);
        c.put_negative("missing.example", TYPE_A, RCODE_NXDOMAIN);
        let (rcode, records) = c.get("missing.example", TYPE_A).unwrap();
        assert_eq!(rcode, RCODE_NXDOMAIN);
        assert!(records.is_empty());
        assert!(c.get("missing.example", TYPE_CNAME).is_none());
    }

    #[test]
    fn lru_eviction() {
        let mut c = Cache::new(2);
        let rec = || Record {
            name: "a".to_string(),
            rtype: TYPE_A,
            ttl: 60,
            rdata: RData::Cname("x".to_string()),
        };
        c.put("a", TYPE_A, vec![rec()], 60);
        c.put("b", TYPE_A, vec![rec()], 60);
        c.put("c", TYPE_A, vec![rec()], 60);
        assert_eq!(c.len(), 2);
        assert!(c.get("a", TYPE_A).is_none());
        assert!(c.get("b", TYPE_A).is_some());
        assert!(c.get("c", TYPE_A).is_some());
    }

    #[test]
    fn flush() {
        let mut c = Cache::new(16);
        let rec = Record {
            name: "a".to_string(),
            rtype: TYPE_A,
            ttl: 60,
            rdata: RData::Cname("x".to_string()),
        };
        c.put("a", TYPE_A, vec![rec], 60);
        c.flush();
        assert_eq!(c.len(), 0);
    }
}
