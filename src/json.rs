//! A minimal, dependency-free JSON value, parser and serializer.
//!
//! SpeeDNS speaks JSON-RPC 2.0 (MCP) and its own JSON control protocol.
//! To keep the binary truly zero-dependency and single-static, this crate
//! ships a compact JSON engine instead of pulling in serde_json.

/// A parsed JSON value. Objects preserve insertion order.
#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    pub fn null() -> Json {
        Json::Null
    }
    pub fn bool(b: bool) -> Json {
        Json::Bool(b)
    }
    pub fn num(n: impl Into<f64>) -> Json {
        Json::Num(n.into())
    }
    pub fn str(s: impl Into<String>) -> Json {
        Json::Str(s.into())
    }
    pub fn arr() -> Json {
        Json::Arr(Vec::new())
    }
    pub fn obj() -> Json {
        Json::Obj(Vec::new())
    }

    pub fn insert(&mut self, key: &str, value: Json) {
        if let Json::Obj(entries) = self {
            entries.push((key.to_string(), value));
        }
    }

    pub fn push(&mut self, value: Json) {
        if let Json::Arr(items) = self {
            items.push(value);
        }
    }

    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Json::Num(n) => Some(*n),
            Json::Str(s) => s.parse().ok(),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        self.as_f64().map(|f| f as i64)
    }

    pub fn as_u32(&self) -> Option<u32> {
        self.as_i64().and_then(|i| u32::try_from(i).ok())
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&Vec<Json>> {
        match self {
            Json::Arr(a) => Some(a),
            _ => None,
        }
    }

    pub fn is_null(&self) -> bool {
        matches!(self, Json::Null)
    }

    /// Compact single-line serialization.
    pub fn to_string(&self) -> String {
        let mut out = String::new();
        self.write(&mut out);
        out
    }

    /// Human-readable serialization with `indent`-space indentation.
    pub fn to_pretty(&self, indent: usize) -> String {
        let mut out = String::new();
        self.write_pretty(&mut out, indent, 0);
        out
    }

    fn write(&self, out: &mut String) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Json::Num(n) => {
                if n.fract() == 0.0 && n.abs() < 9.0e15 {
                    out.push_str(&format!("{}", *n as i64));
                } else {
                    out.push_str(&format!("{}", n));
                }
            }
            Json::Str(s) => write_string(s, out),
            Json::Arr(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write(out);
                }
                out.push(']');
            }
            Json::Obj(entries) => {
                out.push('{');
                for (i, (k, v)) in entries.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_string(k, out);
                    out.push(':');
                    v.write(out);
                }
                out.push('}');
            }
        }
    }

    fn write_pretty(&self, out: &mut String, indent: usize, depth: usize) {
        let pad = " ".repeat(indent * depth);
        let pad_children = " ".repeat(indent * (depth + 1));
        match self {
            Json::Arr(items) if !items.is_empty() => {
                out.push_str("[\n");
                for (i, item) in items.iter().enumerate() {
                    out.push_str(&pad_children);
                    item.write_pretty(out, indent, depth + 1);
                    if i + 1 < items.len() {
                        out.push(',');
                    }
                    out.push('\n');
                }
                out.push_str(&pad);
                out.push(']');
            }
            Json::Obj(entries) if !entries.is_empty() => {
                out.push_str("{\n");
                for (i, (k, v)) in entries.iter().enumerate() {
                    out.push_str(&pad_children);
                    write_string(k, out);
                    out.push_str(": ");
                    v.write_pretty(out, indent, depth + 1);
                    if i + 1 < entries.len() {
                        out.push(',');
                    }
                    out.push('\n');
                }
                out.push_str(&pad);
                out.push('}');
            }
            _ => self.write(out),
        }
    }
}

fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

struct Parser {
    chars: Vec<char>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn next(&mut self) -> Option<char> {
        let c = self.peek();
        if c.is_some() {
            self.pos += 1;
        }
        c
    }

    fn skip_ws(&mut self) {
        while let Some(c) = self.peek() {
            if c.is_whitespace() {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn parse_value(&mut self) -> Result<Json, String> {
        self.skip_ws();
        match self.peek() {
            Some('{') => self.parse_object(),
            Some('[') => self.parse_array(),
            Some('"') => Ok(Json::Str(self.parse_string()?)),
            Some('t') => {
                self.expect_literal("true")?;
                Ok(Json::Bool(true))
            }
            Some('f') => {
                self.expect_literal("false")?;
                Ok(Json::Bool(false))
            }
            Some('n') => {
                self.expect_literal("null")?;
                Ok(Json::Null)
            }
            Some(c) if c == '-' || c.is_ascii_digit() => self.parse_number(),
            Some(c) => Err(format!("unexpected character '{}'", c)),
            None => Err("unexpected end of input".to_string()),
        }
    }

    fn expect_literal(&mut self, lit: &str) -> Result<(), String> {
        for expected in lit.chars() {
            match self.next() {
                Some(c) if c == expected => {}
                Some(c) => return Err(format!("invalid literal, expected '{}' found '{}'", lit, c)),
                None => return Err("unexpected end of input".to_string()),
            }
        }
        Ok(())
    }

    fn parse_string(&mut self) -> Result<String, String> {
        if self.next() != Some('"') {
            return Err("expected string".to_string());
        }
        let mut s = String::new();
        loop {
            match self.next() {
                Some('"') => return Ok(s),
                Some('\\') => match self.next() {
                    Some('"') => s.push('"'),
                    Some('\\') => s.push('\\'),
                    Some('/') => s.push('/'),
                    Some('b') => s.push('\u{08}'),
                    Some('f') => s.push('\u{0c}'),
                    Some('n') => s.push('\n'),
                    Some('r') => s.push('\r'),
                    Some('t') => s.push('\t'),
                    Some('u') => {
                        let cp = self.parse_hex4()?;
                        // Handle surrogate pairs.
                        if (0xd800..=0xdbff).contains(&cp) {
                            if self.next() == Some('\\') && self.next() == Some('u') {
                                let low = self.parse_hex4()?;
                                if (0xdc00..=0xdfff).contains(&low) {
                                    let c = 0x10000 + ((cp - 0xd800) << 10) + (low - 0xdc00);
                                    if let Some(ch) = char::from_u32(c) {
                                        s.push(ch);
                                    }
                                }
                            }
                        } else if let Some(ch) = char::from_u32(cp) {
                            s.push(ch);
                        }
                    }
                    Some(c) => return Err(format!("invalid escape '\\{}'", c)),
                    None => return Err("unterminated string".to_string()),
                },
                Some(c) => s.push(c),
                None => return Err("unterminated string".to_string()),
            }
        }
    }

    fn parse_hex4(&mut self) -> Result<u32, String> {
        let mut v: u32 = 0;
        for _ in 0..4 {
            match self.next() {
                Some(c) if c.is_ascii_hexdigit() => {
                    v = v * 16 + c.to_digit(16).unwrap_or(0);
                }
                _ => return Err("invalid unicode escape".to_string()),
            }
        }
        Ok(v)
    }

    fn parse_number(&mut self) -> Result<Json, String> {
        let start = self.pos;
        if self.peek() == Some('-') {
            self.pos += 1;
        }
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() || c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-' {
                self.pos += 1;
            } else {
                break;
            }
        }
        let raw: String = self.chars[start..self.pos].iter().collect();
        raw.parse::<f64>()
            .map(Json::Num)
            .map_err(|_| format!("invalid number '{}'", raw))
    }

    fn parse_object(&mut self) -> Result<Json, String> {
        self.next(); // consume '{'
        let mut entries = Vec::new();
        self.skip_ws();
        if self.peek() == Some('}') {
            self.next();
            return Ok(Json::Obj(entries));
        }
        loop {
            self.skip_ws();
            let key = self.parse_string()?;
            self.skip_ws();
            if self.next() != Some(':') {
                return Err("expected ':' in object".to_string());
            }
            let value = self.parse_value()?;
            entries.push((key, value));
            self.skip_ws();
            match self.next() {
                Some(',') => continue,
                Some('}') => break,
                _ => return Err("expected ',' or '}' in object".to_string()),
            }
        }
        Ok(Json::Obj(entries))
    }

    fn parse_array(&mut self) -> Result<Json, String> {
        self.next(); // consume '['
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(']') {
            self.next();
            return Ok(Json::Arr(items));
        }
        loop {
            let value = self.parse_value()?;
            items.push(value);
            self.skip_ws();
            match self.next() {
                Some(',') => continue,
                Some(']') => break,
                _ => return Err("expected ',' or ']' in array".to_string()),
            }
        }
        Ok(Json::Arr(items))
    }
}

/// Parse a JSON document from a string.
pub fn parse(input: &str) -> Result<Json, String> {
    let mut p = Parser {
        chars: input.chars().collect(),
        pos: 0,
    };
    let value = p.parse_value()?;
    p.skip_ws();
    if p.pos != p.chars.len() {
        return Err("trailing characters after JSON value".to_string());
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_object() {
        let src = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"dns_resolve","arguments":{"name":"example.com","type":"A"}}}"#;
        let v = parse(src).unwrap();
        assert_eq!(v.get("method").unwrap().as_str(), Some("tools/call"));
        let params = v.get("params").unwrap();
        assert_eq!(
            params.get("name").unwrap().as_str(),
            Some("dns_resolve")
        );
        assert_eq!(v.to_string(), src.replace(' ', ""));
    }

    #[test]
    fn parse_numbers_and_unicode() {
        let v = parse(r#"{"ttl":300,"s":"\u4f60\u597d","n":-1.5e2}"#).unwrap();
        assert_eq!(v.get("ttl").unwrap().as_u32(), Some(300));
        assert_eq!(v.get("s").unwrap().as_str(), Some("你好"));
        assert_eq!(v.get("n").unwrap().as_f64(), Some(-150.0));
    }
}
