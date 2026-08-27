//! DNS wire-format encoding/decoding (RFC 1035 + RFC 3596 + RFC 2782).
//!
//! Implemented from scratch with zero dependencies: headers, questions,
//! resource records, label compression (reading) and name/RDATA (de)serialization.

use std::net::{Ipv4Addr, Ipv6Addr};

/// DNS record types SpeeDNS understands on the wire.
pub const TYPE_A: u16 = 1;
pub const TYPE_NS: u16 = 2;
pub const TYPE_CNAME: u16 = 5;
pub const TYPE_SOA: u16 = 6;
pub const TYPE_PTR: u16 = 12;
pub const TYPE_MX: u16 = 15;
pub const TYPE_TXT: u16 = 16;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_SRV: u16 = 33;
pub const TYPE_OPT: u16 = 41;
pub const TYPE_ANY: u16 = 255;

/// Internet class.
pub const CLASS_IN: u16 = 1;

/// Response codes.
pub const RCODE_NOERROR: u16 = 0;
pub const RCODE_FORMERR: u16 = 1;
pub const RCODE_SERVFAIL: u16 = 2;
pub const RCODE_NXDOMAIN: u16 = 3;
pub const RCODE_NOTIMP: u16 = 4;
pub const RCODE_REFUSED: u16 = 5;

/// Human-readable name for a DNS record type.
pub fn type_name(t: u16) -> &'static str {
    match t {
        TYPE_A => "A",
        TYPE_NS => "NS",
        TYPE_CNAME => "CNAME",
        TYPE_SOA => "SOA",
        TYPE_PTR => "PTR",
        TYPE_MX => "MX",
        TYPE_TXT => "TXT",
        TYPE_AAAA => "AAAA",
        TYPE_SRV => "SRV",
        TYPE_OPT => "OPT",
        TYPE_ANY => "ANY",
        _ => "TYPE?",
    }
}

/// Parse a record type string into its numeric value.
pub fn type_from_str(s: &str) -> Option<u16> {
    match s.trim().to_uppercase().as_str() {
        "A" => Some(TYPE_A),
        "NS" => Some(TYPE_NS),
        "CNAME" => Some(TYPE_CNAME),
        "SOA" => Some(TYPE_SOA),
        "PTR" => Some(TYPE_PTR),
        "MX" => Some(TYPE_MX),
        "TXT" => Some(TYPE_TXT),
        "AAAA" => Some(TYPE_AAAA),
        "SRV" => Some(TYPE_SRV),
        "ANY" => Some(TYPE_ANY),
        _ => s.parse::<u16>().ok(),
    }
}

/// The DNS message header (RFC 1035 section 4.1.1).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Header {
    pub id: u16,
    pub flags: u16,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

impl Header {
    pub fn qr(&self) -> bool {
        self.flags & 0x8000 != 0
    }
    pub fn opcode(&self) -> u16 {
        (self.flags >> 11) & 0xF
    }
    pub fn aa(&self) -> bool {
        self.flags & 0x0400 != 0
    }
    pub fn tc(&self) -> bool {
        self.flags & 0x0200 != 0
    }
    pub fn rd(&self) -> bool {
        self.flags & 0x0100 != 0
    }
    pub fn ra(&self) -> bool {
        self.flags & 0x0080 != 0
    }
    pub fn rcode(&self) -> u16 {
        self.flags & 0x000F
    }

    pub fn set_qr(&mut self, v: bool) {
        self.set_flag(0x8000, v);
    }
    pub fn set_aa(&mut self, v: bool) {
        self.set_flag(0x0400, v);
    }
    pub fn set_tc(&mut self, v: bool) {
        self.set_flag(0x0200, v);
    }
    pub fn set_ra(&mut self, v: bool) {
        self.set_flag(0x0080, v);
    }
    pub fn set_rcode(&mut self, code: u16) {
        self.flags = (self.flags & !0x000F) | (code & 0x000F);
    }
    pub fn set_rd(&mut self, v: bool) {
        self.set_flag(0x0100, v);
    }

    fn set_flag(&mut self, mask: u16, v: bool) {
        if v {
            self.flags |= mask;
        } else {
            self.flags &= !mask;
        }
    }

    pub fn encode(&self) -> [u8; 12] {
        let mut b = [0u8; 12];
        b[0..2].copy_from_slice(&self.id.to_be_bytes());
        b[2..4].copy_from_slice(&self.flags.to_be_bytes());
        b[4..6].copy_from_slice(&self.qdcount.to_be_bytes());
        b[6..8].copy_from_slice(&self.ancount.to_be_bytes());
        b[8..10].copy_from_slice(&self.nscount.to_be_bytes());
        b[10..12].copy_from_slice(&self.arcount.to_be_bytes());
        b
    }

    pub fn decode(b: &[u8]) -> Header {
        Header {
            id: u16::from_be_bytes([b[0], b[1]]),
            flags: u16::from_be_bytes([b[2], b[3]]),
            qdcount: u16::from_be_bytes([b[4], b[5]]),
            ancount: u16::from_be_bytes([b[6], b[7]]),
            nscount: u16::from_be_bytes([b[8], b[9]]),
            arcount: u16::from_be_bytes([b[10], b[11]]),
        }
    }
}

/// A DNS question section entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

/// Resource-record payload for the types SpeeDNS understands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(String),
    Ns(String),
    Ptr(String),
    Txt(Vec<Vec<u8>>),
    Mx { pref: u16, exchange: String },
    Soa {
        mname: String,
        rname: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    Raw(Vec<u8>),
}

/// A fully-formed resource record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub name: String,
    pub rtype: u16,
    pub ttl: u32,
    pub rdata: RData,
}

/// A parsed DNS message.
#[derive(Debug, Clone, Default)]
pub struct Message {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<Record>,
    pub authorities: Vec<Record>,
    pub additionals: Vec<Record>,
}

/// Canonicalize a domain name: lowercase, single trailing-dot-free FQDN.
pub fn canonical(name: &str) -> String {
    let trimmed = name.trim().trim_end_matches('.');
    trimmed.to_ascii_lowercase()
}

/// Encode a domain name into DNS wire format (uncompressed labels).
pub fn encode_name(name: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(name.len() + 2);
    let canonical = canonical(name);
    if canonical.is_empty() {
        out.push(0);
        return out;
    }
    for label in canonical.split('.') {
        let bytes = label.as_bytes();
        let len = bytes.len().min(63);
        out.push(len as u8);
        out.extend_from_slice(&bytes[..len]);
    }
    out.push(0);
    out
}

/// A byte cursor used while reading wire-format messages.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Reader<'a> {
        Reader { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn read_u8(&mut self) -> Option<u8> {
        let b = self.buf.get(self.pos)?;
        self.pos += 1;
        Some(*b)
    }

    fn read_u16(&mut self) -> Option<u16> {
        let hi = self.read_u8()?;
        let lo = self.read_u8()?;
        Some(u16::from_be_bytes([hi, lo]))
    }

    fn read_u32(&mut self) -> Option<u32> {
        let a = self.read_u8()?;
        let b = self.read_u8()?;
        let c = self.read_u8()?;
        let d = self.read_u8()?;
        Some(u32::from_be_bytes([a, b, c, d]))
    }

    fn read_bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let slice = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }

    /// Read a (possibly compressed) domain name. Returns the canonical name.
    fn read_name(&mut self) -> Result<String, &'static str> {
        let mut labels: Vec<String> = Vec::new();
        let mut jumped = false;
        let mut jumps = 0;
        let mut pos = self.pos;

        loop {
            if pos >= self.buf.len() {
                return Err("name out of bounds");
            }
            let len = self.buf[pos];
            match len {
                0 => {
                    if !jumped {
                        self.pos = pos + 1;
                    }
                    break;
                }
                0xC0..=0xFF => {
                    // Compression pointer.
                    if pos + 1 >= self.buf.len() {
                        return Err("truncated pointer");
                    }
                    let offset = (((len & 0x3F) as usize) << 8) | self.buf[pos + 1] as usize;
                    if !jumped {
                        self.pos = pos + 2;
                        jumped = true;
                    }
                    if offset >= self.buf.len() {
                        return Err("pointer out of bounds");
                    }
                    pos = offset;
                    jumps += 1;
                    if jumps > 32 {
                        return Err("too many compression jumps");
                    }
                }
                1..=63 => {
                    if pos + 1 + len as usize > self.buf.len() {
                        return Err("label out of bounds");
                    }
                    let label = &self.buf[pos + 1..pos + 1 + len as usize];
                    labels.push(
                        String::from_utf8_lossy(label)
                            .to_ascii_lowercase(),
                    );
                    pos += 1 + len as usize;
                }
                _ => return Err("invalid label length"),
            }
        }

        Ok(labels.join("."))
    }

    /// Read a record RDATA using the type to interpret the payload.
    fn read_rdata(&mut self, rtype: u16, rdlen: u16) -> Result<RData, &'static str> {
        let raw = self.read_bytes(rdlen as usize).ok_or("rdata out of bounds")?;
        let mut r = Reader::new(raw);
        let data = match rtype {
            TYPE_A => {
                if raw.len() != 4 {
                    return Err("bad A rdata");
                }
                RData::A(Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3]))
            }
            TYPE_AAAA => {
                if raw.len() != 16 {
                    return Err("bad AAAA rdata");
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(raw);
                RData::Aaaa(Ipv6Addr::from(octets))
            }
            TYPE_CNAME => RData::Cname(r.read_name()?),
            TYPE_NS => RData::Ns(r.read_name()?),
            TYPE_PTR => RData::Ptr(r.read_name()?),
            TYPE_MX => {
                let pref = r.read_u16().ok_or("bad MX rdata")?;
                let exchange = r.read_name()?;
                RData::Mx { pref, exchange }
            }
            TYPE_TXT => {
                let mut chunks = Vec::new();
                let mut tr = r;
                while tr.remaining() > 0 {
                    let len = tr.read_u8().ok_or("bad TXT rdata")? as usize;
                    let chunk = tr.read_bytes(len).ok_or("bad TXT chunk")?.to_vec();
                    chunks.push(chunk);
                }
                RData::Txt(chunks)
            }
            TYPE_SOA => {
                let mname = r.read_name()?;
                let rname = r.read_name()?;
                let serial = r.read_u32().ok_or("bad SOA rdata")?;
                let refresh = r.read_u32().ok_or("bad SOA rdata")?;
                let retry = r.read_u32().ok_or("bad SOA rdata")?;
                let expire = r.read_u32().ok_or("bad SOA rdata")?;
                let minimum = r.read_u32().ok_or("bad SOA rdata")?;
                RData::Soa {
                    mname,
                    rname,
                    serial,
                    refresh,
                    retry,
                    expire,
                    minimum,
                }
            }
            TYPE_SRV => {
                let priority = r.read_u16().ok_or("bad SRV rdata")?;
                let weight = r.read_u16().ok_or("bad SRV rdata")?;
                let port = r.read_u16().ok_or("bad SRV rdata")?;
                let target = r.read_name()?;
                RData::Srv {
                    priority,
                    weight,
                    port,
                    target,
                }
            }
            _ => RData::Raw(raw.to_vec()),
        };
        Ok(data)
    }
}

/// Encode a record's RDATA bytes for a given type.
pub fn encode_rdata(rtype: u16, rdata: &RData) -> Vec<u8> {
    let mut out = Vec::new();
    match (rtype, rdata) {
        (TYPE_A, RData::A(ip)) => out.extend_from_slice(&ip.octets()),
        (TYPE_AAAA, RData::Aaaa(ip)) => out.extend_from_slice(&ip.octets()),
        (TYPE_CNAME, RData::Cname(n))
        | (TYPE_NS, RData::Ns(n))
        | (TYPE_PTR, RData::Ptr(n)) => out.extend_from_slice(&encode_name(n)),
        (TYPE_MX, RData::Mx { pref, exchange }) => {
            out.extend_from_slice(&pref.to_be_bytes());
            out.extend_from_slice(&encode_name(exchange));
        }
        (TYPE_TXT, RData::Txt(chunks)) => {
            for chunk in chunks {
                let len = chunk.len().min(255) as u8;
                out.push(len);
                out.extend_from_slice(&chunk[..len as usize]);
            }
        }
        (TYPE_SOA, RData::Soa { mname, rname, serial, refresh, retry, expire, minimum }) => {
            out.extend_from_slice(&encode_name(mname));
            out.extend_from_slice(&encode_name(rname));
            out.extend_from_slice(&serial.to_be_bytes());
            out.extend_from_slice(&refresh.to_be_bytes());
            out.extend_from_slice(&retry.to_be_bytes());
            out.extend_from_slice(&expire.to_be_bytes());
            out.extend_from_slice(&minimum.to_be_bytes());
        }
        (TYPE_SRV, RData::Srv { priority, weight, port, target }) => {
            out.extend_from_slice(&priority.to_be_bytes());
            out.extend_from_slice(&weight.to_be_bytes());
            out.extend_from_slice(&port.to_be_bytes());
            out.extend_from_slice(&encode_name(target));
        }
        (_, RData::Raw(bytes)) => out.extend_from_slice(bytes),
        _ => {}
    }
    out
}

impl Record {
    /// Serialize a record into a write buffer (name + type + class + ttl + rdata).
    pub fn encode(&self, buf: &mut Vec<u8>, class: u16) {
        buf.extend_from_slice(&encode_name(&self.name));
        buf.extend_from_slice(&self.rtype.to_be_bytes());
        buf.extend_from_slice(&class.to_be_bytes());
        buf.extend_from_slice(&self.ttl.to_be_bytes());
        let rdata = encode_rdata(self.rtype, &self.rdata);
        buf.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        buf.extend_from_slice(&rdata);
    }
}

impl Question {
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&encode_name(&self.name));
        buf.extend_from_slice(&self.qtype.to_be_bytes());
        buf.extend_from_slice(&self.qclass.to_be_bytes());
    }
}

/// Decode a DNS message from its wire bytes.
pub fn decode_message(buf: &[u8]) -> Result<Message, &'static str> {
    if buf.len() < 12 {
        return Err("message too short");
    }
    let header = Header::decode(&buf[..12]);
    let mut r = Reader::new(buf);
    r.pos = 12;

    let mut msg = Message {
        header,
        ..Default::default()
    };

    for _ in 0..header.qdcount {
        let name = r.read_name()?;
        let qtype = r.read_u16().ok_or("truncated question")?;
        let qclass = r.read_u16().ok_or("truncated question")?;
        msg.questions.push(Question { name, qtype, qclass });
    }
    for _ in 0..header.ancount {
        msg.answers.push(read_record(&mut r)?);
    }
    for _ in 0..header.nscount {
        msg.authorities.push(read_record(&mut r)?);
    }
    for _ in 0..header.arcount {
        msg.additionals.push(read_record(&mut r)?);
    }
    Ok(msg)
}

fn read_record(r: &mut Reader) -> Result<Record, &'static str> {
    let name = r.read_name()?;
    let rtype = r.read_u16().ok_or("truncated record")?;
    let _class = r.read_u16().ok_or("truncated record")?;
    let ttl = r.read_u32().ok_or("truncated record")?;
    let rdlen = r.read_u16().ok_or("truncated record")?;
    let rdata = r.read_rdata(rtype, rdlen)?;
    Ok(Record { name, rtype, ttl, rdata })
}

/// Build a response message for the given query, preserving the question and ID.
pub fn build_response(query: &Message, answers: Vec<Record>, authorities: Vec<Record>, aa: bool, rcode: u16) -> Message {
    let mut header = Header {
        id: query.header.id,
        qdcount: 1,
        ..Default::default()
    };
    header.set_qr(true);
    header.set_ra(true);
    header.set_rd(query.header.rd());
    header.set_aa(aa);
    header.set_rcode(rcode);
    header.ancount = answers.len() as u16;
    header.nscount = authorities.len() as u16;

    let questions = if query.questions.is_empty() {
        Vec::new()
    } else {
        vec![query.questions[0].clone()]
    };

    Message {
        header,
        questions,
        answers,
        authorities,
        additionals: Vec::new(),
    }
}

/// Serialize a full message to wire bytes.
pub fn encode_message(msg: &Message) -> Vec<u8> {
    let mut out = Vec::with_capacity(512);
    out.extend_from_slice(&msg.header.encode());
    for q in &msg.questions {
        q.encode(&mut out);
    }
    for r in &msg.answers {
        r.encode(&mut out, CLASS_IN);
    }
    for r in &msg.authorities {
        r.encode(&mut out, CLASS_IN);
    }
    for r in &msg.additionals {
        r.encode(&mut out, CLASS_IN);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn name_roundtrip() {
        let wire = encode_name("WWW.Example.COM.");
        assert_eq!(
            wire,
            vec![3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0]
        );
        let mut r = Reader::new(&wire);
        assert_eq!(r.read_name().unwrap(), "www.example.com");
    }

    #[test]
    fn compressed_name_read() {
        // Name "a.example.com" then pointer to offset 0 for "example.com"
        let wire = vec![
            1, b'a', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0xC0, 0x02,
        ];
        let mut r = Reader::new(&wire);
        assert_eq!(r.read_name().unwrap(), "a.example.com");
        assert_eq!(r.read_name().unwrap(), "example.com");
    }

    #[test]
    fn message_roundtrip() {
        let q = Question {
            name: "example.com".to_string(),
            qtype: TYPE_A,
            qclass: CLASS_IN,
        };
        let mut m = Message::default();
        m.header.id = 0x1234;
        m.header.qdcount = 1;
        m.questions.push(q);
        let rec = Record {
            name: "example.com".to_string(),
            rtype: TYPE_A,
            ttl: 300,
            rdata: RData::A(Ipv4Addr::new(93, 184, 216, 34)),
        };
        m.answers.push(rec.clone());
        m.header.ancount = 1;

        let wire = encode_message(&m);
        let decoded = decode_message(&wire).unwrap();
        assert_eq!(decoded.header.id, 0x1234);
        assert_eq!(decoded.questions[0].name, "example.com");
        assert_eq!(decoded.answers[0].rdata, RData::A(Ipv4Addr::new(93, 184, 216, 34)));
    }

    #[test]
    fn type_parsing() {
        assert_eq!(type_from_str("A"), Some(1));
        assert_eq!(type_from_str("aaaa"), Some(28));
        assert_eq!(type_from_str("TXT"), Some(16));
        assert_eq!(type_name(28), "AAAA");
    }
}
