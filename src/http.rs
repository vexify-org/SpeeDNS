//! Minimal zero-dependency HTTP/1.1 server powering the SpeeDNS web dashboard.
//!
//! Serves a single-page dashboard at `GET /` and a small JSON API under
//! `/api/*`, both backed by the shared [`Resolver`]. Written from scratch on
//! `std` (no tokio, no hyper) to keep the zero-dependency promise intact.

use crate::control::dispatch;
use crate::dns::{type_from_str, type_name, Record, TYPE_ANY};
use crate::json::Json;
use crate::resolver::{records_to_json, Resolver};
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// Maximum accepted request body size (64 KiB is plenty for record adds).
const MAX_BODY: usize = 64 * 1024;
/// Per-connection read timeout, to shed slow or hung clients.
const READ_TIMEOUT: Duration = Duration::from_secs(10);

const OK: &str = "200 OK";
const BAD_REQUEST: &str = "400 Bad Request";
const NOT_FOUND: &str = "404 Not Found";
const METHOD_NOT_ALLOWED: &str = "405 Method Not Allowed";

/// The web dashboard server.
pub struct WebServer {
    resolver: Arc<Resolver>,
    listen: SocketAddr,
}

impl WebServer {
    pub fn new(resolver: Arc<Resolver>, listen: SocketAddr) -> WebServer {
        WebServer { resolver, listen }
    }

    /// Bind the listener and spawn the accept loop (non-blocking).
    pub fn spawn(self) -> Result<(), String> {
        let listener = TcpListener::bind(self.listen)
            .map_err(|e| format!("cannot bind web dashboard {}: {}", self.listen, e))?;
        thread::Builder::new()
            .name("speedns-web".to_string())
            .spawn(move || {
                for stream in listener.incoming() {
                    let Ok(stream) = stream else { continue };
                    let resolver = self.resolver.clone();
                    thread::Builder::new()
                        .name("speedns-web-c".to_string())
                        .spawn(move || {
                            let _ = handle_conn(stream, &resolver);
                        })
                        .ok();
                }
            })
            .map_err(|e| format!("cannot spawn web thread: {}", e))?;
        Ok(())
    }
}

/// A parsed HTTP/1.1 request (method, path, query pairs, body).
struct Request {
    method: String,
    path: String,
    query: Vec<(String, String)>,
    body: String,
}

impl Request {
    /// First value for a query key, or empty string.
    fn param(&self, key: &str) -> String {
        self.query
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    }
}

/// Parse one request off the reader. Returns `None` on EOF or malformed input.
fn read_request(reader: &mut impl BufRead) -> Option<Request> {
    let mut line = String::new();
    if reader.read_line(&mut line).ok()? == 0 {
        return None;
    }
    let mut parts = line.trim_end().split_whitespace();
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (target, String::new()),
    };
    let mut pairs: Vec<(String, String)> = Vec::new();
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let mut kv = pair.splitn(2, '=');
        let k = url_decode(kv.next().unwrap_or(""));
        let v = url_decode(kv.next().unwrap_or(""));
        pairs.push((k, v));
    }

    // Headers, up to the blank line.
    let mut content_length = 0usize;
    loop {
        let mut h = String::new();
        if reader.read_line(&mut h).ok()? == 0 {
            break;
        }
        let h = h.trim_end();
        if h.is_empty() {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                content_length = v.trim().parse().unwrap_or(0);
            }
        }
    }

    let mut body = String::new();
    if content_length > 0 {
        if content_length > MAX_BODY {
            return None;
        }
        let mut buf = vec![0u8; content_length];
        if reader.read_exact(&mut buf).is_err() {
            return None;
        }
        body = String::from_utf8_lossy(&buf).into_owned();
    }

    Some(Request {
        method,
        path,
        query: pairs,
        body,
    })
}

/// Percent-decode a query/form component (`+` is left as-is).
fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Handle one connection: read a single request, dispatch it, write the reply.
fn handle_conn(stream: TcpStream, resolver: &Arc<Resolver>) {
    let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
    let Ok(clone) = stream.try_clone() else { return };
    let mut reader = BufReader::new(clone);
    let mut writer = stream;

    let Some(req) = read_request(&mut reader) else {
        let _ = writer.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        let _ = writer.flush();
        return;
    };
    let (status, content_type, body) = route(&req, resolver);
    let head = format!(
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\nAccess-Control-Allow-Origin: *\r\n\r\n",
        status,
        content_type,
        body.len()
    );
    let _ = writer.write_all(head.as_bytes());
    let _ = writer.write_all(&body);
    let _ = writer.flush();
}

/// Route a request to the dashboard or the JSON API.
fn route(req: &Request, resolver: &Arc<Resolver>) -> (&'static str, &'static str, Vec<u8>) {
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/") | ("GET", "/index.html") => {
            (OK, "text/html; charset=utf-8", dashboard_html().into_bytes())
        }
        ("GET", "/api/status") => json_result(dispatch(&cmd("status"), resolver)),
        ("GET", "/api/records") => api_records(req, resolver),
        ("GET", "/api/cache") => json_result(dispatch(&cmd("cache"), resolver)),
        ("GET", "/api/query") => api_query(req, resolver),
        ("POST", "/api/add") => api_mutate(req, resolver, "add"),
        ("POST", "/api/remove") => api_mutate(req, resolver, "remove"),
        ("POST", "/api/flush") => json_result(dispatch(&cmd("flush"), resolver)),
        _ => {
            if req.path.starts_with("/api/") {
                const KNOWN: [&str; 7] = [
                    "/api/status", "/api/records", "/api/cache", "/api/query",
                    "/api/add", "/api/remove", "/api/flush",
                ];
                if KNOWN.contains(&req.path.as_str()) {
                    (METHOD_NOT_ALLOWED, "application/json", json_error("method not allowed").into_bytes())
                } else {
                    (NOT_FOUND, "application/json", json_error("not found").into_bytes())
                }
            } else {
                (NOT_FOUND, "text/plain", b"not found".to_vec())
            }
        }
    }
}

/// Wrap a dispatch result as an HTTP 200 JSON response.
fn json_result(j: Json) -> (&'static str, &'static str, Vec<u8>) {
    (OK, "application/json", j.to_string().into_bytes())
}

fn json_error(msg: &str) -> String {
    let mut j = Json::obj();
    j.insert("ok", Json::bool(false));
    j.insert("error", Json::str(msg.to_string()));
    j.to_string()
}

fn cmd(name: &str) -> Json {
    let mut j = Json::obj();
    j.insert("cmd", Json::str(name.to_string()));
    j
}

/// `GET /api/records[?name=...]` — structured record list for the table view.
fn api_records(req: &Request, resolver: &Arc<Resolver>) -> (&'static str, &'static str, Vec<u8>) {
    let filter = req.param("name");
    let store = resolver.store.read().unwrap();
    let all = store.all();
    let filtered: Vec<Record> = if filter.is_empty() {
        all
    } else {
        all.into_iter().filter(|r| r.name == filter).collect()
    };
    let mut j = Json::obj();
    j.insert("ok", Json::bool(true));
    j.insert("records", records_to_json(&filtered));
    j.insert("count", Json::num(filtered.len() as f64));
    (OK, "application/json", j.to_string().into_bytes())
}

/// `GET /api/query?name=..&type=..` — live resolution through the pipeline.
fn api_query(req: &Request, resolver: &Arc<Resolver>) -> (&'static str, &'static str, Vec<u8>) {
    let name = req.param("name");
    if name.is_empty() {
        return (BAD_REQUEST, "application/json", json_error("missing 'name'").into_bytes());
    }
    let raw_type = req.param("type");
    let qtype = if raw_type.is_empty() {
        TYPE_ANY
    } else {
        type_from_str(&raw_type).unwrap_or(TYPE_ANY)
    };
    let result = resolver.resolve_name(&name, qtype);

    let mut j = Json::obj();
    j.insert("ok", Json::bool(true));
    j.insert("name", Json::str(crate::dns::canonical(&name)));
    j.insert("type", Json::str(type_name(qtype)));
    j.insert("rcode", Json::num(result.rcode as f64));
    j.insert("rcode_name", Json::str(rcode_name(result.rcode)));
    j.insert("aa", Json::bool(result.aa));
    j.insert("records", records_to_json(&result.records));
    (OK, "application/json", j.to_string().into_bytes())
}

/// `POST /api/add|remove` with a JSON body, dispatched to the shared control
/// plane so the CLI, MCP and web all agree on semantics.
fn api_mutate(req: &Request, resolver: &Arc<Resolver>, cmd: &str) -> (&'static str, &'static str, Vec<u8>) {
    let body = match crate::json::parse(&req.body) {
        Ok(j) => j,
        Err(e) => {
            return (BAD_REQUEST, "application/json", json_error(&format!("bad JSON body: {}", e)).into_bytes());
        }
    };
    let mut j = Json::obj();
    j.insert("cmd", Json::str(cmd.to_string()));
    for (key, dst) in [
        ("record", "record"),
        ("name", "name"),
        ("type", "type"),
        ("value", "value"),
        ("ttl", "ttl"),
    ] {
        if let Some(v) = body.get(key) {
            j.insert(dst, v.clone());
        }
    }
    let response = dispatch(&j, resolver);
    let ok = response.get("ok").and_then(|o| o.as_bool()).unwrap_or(false);
    if ok {
        (OK, "application/json", response.to_string().into_bytes())
    } else {
        (BAD_REQUEST, "application/json", response.to_string().into_bytes())
    }
}

fn rcode_name(rcode: u16) -> &'static str {
    match rcode {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        _ => "UNKNOWN",
    }
}

/// Self-contained dashboard page (inline CSS/JS, no external assets).
fn dashboard_html() -> String {
    r##"<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SpeeDNS 控制台</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { margin: 0; font: 14px/1.5 -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, "PingFang SC", "Microsoft YaHei", sans-serif; background: #0d1117; color: #e6edf3; }
  .wrap { max-width: 960px; margin: 0 auto; padding: 24px 16px 48px; }
  header { display: flex; align-items: baseline; gap: 12px; border-bottom: 1px solid #21262d; padding-bottom: 14px; margin-bottom: 20px; flex-wrap: wrap; }
  h1 { font-size: 22px; margin: 0; }
  h1 .dot { color: #3fb950; }
  .sub { color: #8b949e; }
  .card { background: #161b22; border: 1px solid #21262d; border-radius: 10px; padding: 16px; margin-bottom: 18px; }
  .card h2 { font-size: 15px; margin: 0 0 12px; color: #c9d1d9; }
  .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 10px; }
  .stat { background: #0d1117; border: 1px solid #21262d; border-radius: 8px; padding: 10px 12px; }
  .stat b { display: block; font-size: 20px; color: #58a6ff; }
  .stat span { font-size: 12px; color: #8b949e; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th, td { text-align: left; padding: 7px 10px; border-bottom: 1px solid #21262d; vertical-align: top; }
  th { color: #8b949e; font-weight: 600; font-size: 12px; text-transform: uppercase; }
  td.name { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; color: #79c0ff; }
  td.type { font-family: ui-monospace, monospace; color: #ffa657; }
  td.val { font-family: ui-monospace, monospace; word-break: break-all; }
  input, select, button { font: inherit; background: #0d1117; color: #e6edf3; border: 1px solid #30363d; border-radius: 6px; padding: 7px 10px; }
  input:focus, select:focus { outline: none; border-color: #58a6ff; }
  button { cursor: pointer; }
  button.primary { background: #238636; border-color: #238636; color: #fff; }
  button.danger { background: #da3633; border-color: #da3633; color: #fff; }
  button.ghost { background: transparent; }
  button:disabled { opacity: .5; cursor: not-allowed; }
  .row { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
  .row input, .row select { flex: 1; min-width: 90px; }
  .row input[type=number] { flex: 0 0 90px; }
  .row .grow { flex: 2; }
  .msg { margin-top: 8px; font-size: 13px; min-height: 18px; }
  .msg.ok { color: #3fb950; }
  .msg.err { color: #f85149; }
  .muted { color: #8b949e; font-size: 12px; }
  .badge { display: inline-block; padding: 1px 8px; border-radius: 20px; font-size: 12px; background: #1f6feb33; color: #58a6ff; }
  .badge.off { background: #f8514933; color: #f85149; }
  .empty { color: #8b949e; padding: 12px 0; text-align: center; }
  code { font-family: ui-monospace, monospace; background: #21262d; padding: 1px 5px; border-radius: 4px; }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>⚡ SpeeDNS <span class="dot">控制台</span></h1>
    <span class="sub" id="version"></span>
    <span class="sub" id="upstream-badge"></span>
    <span class="sub" style="margin-left:auto">
      <button class="ghost" onclick="refresh()">🔄 刷新</button>
      <button class="danger" onclick="flush()">清空缓存</button>
    </span>
  </header>

  <div class="card">
    <h2>运行状态</h2>
    <div class="stats" id="stats"></div>
  </div>

  <div class="card">
    <h2>DNS 查询</h2>
    <div class="row">
      <input class="grow" id="q-name" placeholder="域名，如 www.example.com">
      <select id="q-type">
        <option value="">ANY</option><option>A</option><option>AAAA</option><option>CNAME</option>
        <option>MX</option><option>NS</option><option>SOA</option><option>TXT</option><option>PTR</option><option>SRV</option>
      </select>
      <button class="primary" onclick="query()">查询</button>
    </div>
    <div class="msg" id="q-msg"></div>
    <div id="q-result"></div>
  </div>

  <div class="card">
    <h2>新增记录</h2>
    <div class="row">
      <input class="grow" id="r-name" placeholder="域名，如 app.example.com">
      <input id="r-ttl" type="number" value="300" title="TTL 秒">
      <select id="r-type">
        <option>A</option><option>AAAA</option><option>CNAME</option><option>MX</option>
        <option>NS</option><option>SOA</option><option>TXT</option><option>PTR</option><option>SRV</option>
      </select>
      <input class="grow" id="r-value" placeholder="记录值，如 192.0.2.10">
      <button class="primary" onclick="add()">添加</button>
    </div>
    <div class="muted">例如：A 记录值填 <code>192.0.2.10</code>；MX 填 <code>10 mail.example.com.</code>；TXT 填 <code>"v=spf1 -all"</code></div>
    <div class="msg" id="r-msg"></div>
  </div>

  <div class="card">
    <h2>权威记录 <span class="muted" id="rec-count"></span></h2>
    <table>
      <thead><tr><th>名称</th><th>TTL</th><th>类型</th><th>值</th><th></th></tr></thead>
      <tbody id="records"></tbody>
    </table>
    <div class="empty" id="rec-empty" style="display:none">（暂无记录）</div>
  </div>
</div>

<script>
const $ = (id) => document.getElementById(id);
function esc(s) {
  return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
function setMsg(id, text, ok) {
  const el = $(id);
  el.textContent = text;
  el.className = 'msg ' + (ok ? 'ok' : 'err');
}

async function refresh() {
  try {
    const [s, r] = await Promise.all([
      fetch('/api/status').then(r => r.json()),
      fetch('/api/records').then(r => r.json())
    ]);
    if (s.ok) {
      $('version').textContent = s.name + ' v' + s.version + ' · 已运行 ' + fmtUptime(s.uptime_secs || 0);
      const up = s.upstream;
      $('upstream-badge').innerHTML = up
        ? '<span class="badge">上游 ' + esc(up) + '</span>'
        : '<span class="badge off">纯权威模式（无上游）</span>';
      const cards = [
        ['权威记录', s.records || 0], ['缓存条目', s.cache_entries || 0],
        ['总查询', s.queries || 0], ['缓存命中', s.cache_hits || 0],
        ['权威应答', s.authoritative || 0], ['转发', s.forwarded || 0], ['错误', s.errors || 0]
      ];
      $('stats').innerHTML = cards.map(c =>
        '<div class="stat"><b>' + esc(c[1]) + '</b><span>' + esc(c[0]) + '</span></div>').join('');
    }
    if (r.ok && r.records) {
      renderRecords(r.records);
    }
  } catch (e) {
    setMsg('r-msg', '加载失败：' + e, false);
  }
}

function fmtUptime(secs) {
  const d = Math.floor(secs / 86400), h = Math.floor(secs % 86400 / 3600), m = Math.floor(secs % 3600 / 60);
  return d > 0 ? d + '天' + h + '小时' : (h > 0 ? h + '小时' + m + '分' : m + '分');
}

function renderRecords(records) {
  $('rec-count').textContent = '（' + records.length + ' 条）';
  $('rec-empty').style.display = records.length ? 'none' : 'block';
  const tb = $('records');
  tb.innerHTML = records.map((rec, i) =>
    '<tr>' +
    '<td class="name">' + esc(rec.name) + '</td>' +
    '<td>' + esc(rec.ttl) + '</td>' +
    '<td class="type">' + esc(rec.type) + '</td>' +
    '<td class="val">' + esc(rec.value) + '</td>' +
    '<td><button class="danger" data-i="' + i + '" onclick="remove(this)">删除</button></td>' +
    '</tr>').join('');
  window._records = records;
}

async function remove(btn) {
  const rec = window._records[Number(btn.dataset.i)];
  if (!rec) return;
  if (!confirm('删除 ' + rec.name + ' ' + rec.type + ' ' + rec.value + ' ？')) return;
  btn.disabled = true;
  try {
    const resp = await fetch('/api/remove', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({name: rec.name, type: rec.type, value: rec.value})
    }).then(r => r.json());
    setMsg('r-msg', resp.ok ? '已删除 ' + (resp.removed || 0) + ' 条' : '删除失败：' + resp.error, resp.ok);
    refresh();
  } catch (e) { setMsg('r-msg', '删除失败：' + e, false); btn.disabled = false; }
}

async function add() {
  const record = ($('r-name').value.trim() + ' ' + ($('r-ttl').value || 300) + ' ' +
                 $('r-type').value + ' ' + $('r-value').value.trim()).replace(/\s+/g, ' ');
  if (!$('r-name').value.trim() || !$('r-value').value.trim()) { setMsg('r-msg', '请填写域名和记录值', false); return; }
  try {
    const resp = await fetch('/api/add', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({record: record})
    }).then(r => r.json());
    setMsg('r-msg', resp.ok ? '添加成功' : '添加失败：' + (resp.error || '参数错误'), resp.ok);
    if (resp.ok) { $('r-value').value = ''; refresh(); }
  } catch (e) { setMsg('r-msg', '添加失败：' + e, false); }
}

async function query() {
  const name = $('q-name').value.trim();
  const type = $('q-type').value;
  if (!name) { setMsg('q-msg', '请输入域名', false); return; }
  const url = '/api/query?name=' + encodeURIComponent(name) + (type ? '&type=' + encodeURIComponent(type) : '');
  try {
    const resp = await fetch(url).then(r => r.json());
    setMsg('q-msg', resp.rcode_name + (resp.aa ? ' · AA' : ''), resp.rcode_name === 'NOERROR' || resp.records.length > 0);
    $('q-result').innerHTML = resp.records.length
      ? '<table><thead><tr><th>名称</th><th>TTL</th><th>类型</th><th>值</th></tr></thead><tbody>' +
        resp.records.map(rec => '<tr><td class="name">' + esc(rec.name) + '</td><td>' + esc(rec.ttl) +
        '</td><td class="type">' + esc(rec.type) + '</td><td class="val">' + esc(rec.value) + '</td></tr>').join('') +
        '</tbody></table>'
      : '<div class="empty">（无记录）</div>';
  } catch (e) { setMsg('q-msg', '查询失败：' + e, false); }
}

async function flush() {
  if (!confirm('确定清空缓存？')) return;
  try {
    const resp = await fetch('/api/flush', {method: 'POST'}).then(r => r.json());
    setMsg('r-msg', resp.ok ? '缓存已清空' : '失败：' + resp.error, resp.ok);
  } catch (e) { setMsg('r-msg', '失败：' + e, false); }
}

refresh();
</script>
</body>
</html>
"##
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_decode_basic() {
        assert_eq!(url_decode("a%20b"), "a b");
        assert_eq!(url_decode("www.example.com"), "www.example.com");
        assert_eq!(url_decode("100%25"), "100%");
        assert_eq!(url_decode("%zz"), "%zz");
    }

    #[test]
    fn parse_get_request() {
        let raw = b"GET /api/records?name=app.example.com HTTP/1.1\r\nHost: x\r\n\r\n";
        let mut reader = BufReader::new(&raw[..]);
        let req = read_request(&mut reader).expect("parse");
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/api/records");
        assert_eq!(req.param("name"), "app.example.com");
        assert_eq!(req.body, "");
    }

    #[test]
    fn parse_post_with_body() {
        let raw = b"POST /api/add HTTP/1.1\r\nContent-Length: 38\r\n\r\n{\"record\":\"x.example.com. 60 A 1.2.3.4\"}";
        let mut reader = BufReader::new(&raw[..]);
        let req = read_request(&mut reader).expect("parse");
        assert_eq!(req.method, "POST");
        assert!(req.body.contains("1.2.3.4"));
    }
}
