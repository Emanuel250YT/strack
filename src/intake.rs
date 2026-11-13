//! Loading pirate streams by hand or from a monitoring tool. What people paste or upload (one stream
//! per line, CSV, or the live feed's own JSON) becomes detections the platform ingests exactly like
//! the feed: same evidence, same judge, same orders.

use std::net::IpAddr;

use serde_json::{Map, Value, json};

use crate::workflow::url_host;

/// Most streams one load takes; more are refused so a mistake cannot flood the judges.
pub const MAX_ITEMS: usize = 200;
const MAX_WATERMARK: usize = 64;
const MAX_URL: usize = 2048;

/// Where a detection came from, kept in the detection itself (and so in its hash).
pub const ORIGIN_MANUAL: &str = "manual";
pub const ORIGIN_API: &str = "api";

#[derive(Debug, Clone, PartialEq)]
pub struct Item {
    /// Line in the pasted text, or position in a JSON list (1-based).
    pub line: usize,
    pub stream_url: String,
    pub host: String,
    pub watermark: Option<String>,
    pub page: Option<String>,
    pub ip: Option<String>,
    /// Other feed fields given in JSON (capture, promotion, ASN), kept as they came.
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemError {
    InvalidStreamUrl,
    InvalidWatermark,
    InvalidPage,
    InvalidIp,
    Repeated,
    TooMany,
    UnreadableJson,
    Empty,
}

impl ItemError {
    pub fn code(self) -> &'static str {
        match self {
            ItemError::InvalidStreamUrl => "invalid_stream_url",
            ItemError::InvalidWatermark => "invalid_watermark",
            ItemError::InvalidPage => "invalid_page",
            ItemError::InvalidIp => "invalid_ip",
            ItemError::Repeated => "repeated",
            ItemError::TooMany => "too_many",
            ItemError::UnreadableJson => "unreadable_json",
            ItemError::Empty => "empty",
        }
    }
}

/// Valid streams and the problems found, in input order. Repeated streams are reported once.
#[derive(Debug, Default)]
pub struct Parsed {
    pub items: Vec<Item>,
    pub errors: Vec<(usize, ItemError)>,
}

fn http_url(s: &str) -> Option<String> {
    let lower = s.to_ascii_lowercase();
    let ok = s.len() <= MAX_URL
        && (lower.starts_with("http://") || lower.starts_with("https://"))
        && url_host(s).is_some_and(|h| !h.is_empty() && h.contains('.'));
    ok.then(|| s.to_string())
}

fn valid_watermark(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_WATERMARK && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn item(
    line: usize,
    stream: &str,
    watermark: Option<&str>,
    page: Option<&str>,
    ip: Option<&str>,
) -> Result<Item, ItemError> {
    let stream_url = http_url(stream.trim()).ok_or(ItemError::InvalidStreamUrl)?;
    let host = url_host(&stream_url).ok_or(ItemError::InvalidStreamUrl)?;
    let watermark = watermark.map(str::trim).filter(|w| !w.is_empty());
    if watermark.is_some_and(|w| !valid_watermark(w)) {
        return Err(ItemError::InvalidWatermark);
    }
    let page = match page.map(str::trim).filter(|p| !p.is_empty()) {
        Some(p) => Some(http_url(p).ok_or(ItemError::InvalidPage)?),
        None => None,
    };
    let ip = match ip.map(str::trim).filter(|i| !i.is_empty()) {
        Some(i) => Some(i.parse::<IpAddr>().map_err(|_| ItemError::InvalidIp)?.to_string()),
        None => None,
    };
    Ok(Item { line, stream_url, host, watermark: watermark.map(str::to_string), page, ip, extra: Map::new() })
}

/// One line of text: the stream address first, then in any order the watermark, the player page
/// (an address) and the server IP. Separated by commas, semicolons, tabs or spaces.
fn parse_line(line: usize, text: &str) -> Result<Item, ItemError> {
    let parts: Vec<&str> = if text.contains([',', ';', '\t']) {
        text.split([',', ';', '\t']).map(str::trim).collect()
    } else {
        text.split_whitespace().collect()
    };
    let (mut watermark, mut page, mut ip) = (None, None, None);
    for part in parts.iter().skip(1).filter(|p| !p.is_empty()) {
        if part.contains("://") {
            page = Some(*part);
        } else if part.parse::<IpAddr>().is_ok() {
            ip = Some(*part);
        } else {
            watermark = Some(*part);
        }
    }
    item(line, parts.first().copied().unwrap_or_default(), watermark, page, ip)
}

fn text_field<'a>(obj: &'a Map<String, Value>, names: &[&str]) -> Option<&'a str> {
    names.iter().find_map(|n| obj.get(*n).and_then(Value::as_str))
}

/// One object in the feed's format (`stream_url`, `pagina`, `marca_de_agua_extraida`,
/// `ip_servidor`, optional `captura`, `promocion`, `asn`).
fn parse_object(line: usize, value: &Value) -> Result<Item, ItemError> {
    let obj = value.as_object().ok_or(ItemError::InvalidStreamUrl)?;
    let mut parsed = item(
        line,
        text_field(obj, &["stream_url", "stream"]).unwrap_or_default(),
        text_field(obj, &["marca_de_agua_extraida", "marca_de_agua", "watermark"]),
        text_field(obj, &["pagina", "page"]),
        text_field(obj, &["ip_servidor", "ip"]),
    )?;
    for key in ["captura", "promocion", "asn"] {
        if let Some(v) = obj.get(key).filter(|v| !v.is_null()) {
            parsed.extra.insert(key.to_string(), v.clone());
        }
    }
    Ok(parsed)
}

/// A CSV header: its first column names the stream address instead of holding one.
fn looks_like_header(text: &str) -> bool {
    let first = text.split([',', ';', '\t', ' ']).next().unwrap_or_default().trim().to_lowercase();
    !text.contains("://")
        && matches!(first.as_str(), "stream" | "stream_url" | "streams" | "url" | "direccion" | "dirección")
}

/// Reads a JSON value (one object or a list of them), as the API receives it.
pub fn parse_json(value: &Value) -> Parsed {
    let list: Vec<&Value> = match value {
        Value::Array(items) => items.iter().collect(),
        other => vec![other],
    };
    collect(list.into_iter().enumerate().map(|(i, v)| (i + 1, parse_object(i + 1, v))))
}

/// Reads what someone pasted or uploaded: JSON when it starts with `[` or `{`, otherwise one
/// stream per line (a CSV header line and `#` comments are skipped).
pub fn parse_text(text: &str) -> Parsed {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Parsed { items: Vec::new(), errors: vec![(0, ItemError::Empty)] };
    }
    if trimmed.starts_with('[') || trimmed.starts_with('{') {
        return match serde_json::from_str::<Value>(trimmed) {
            Ok(value) => parse_json(&value),
            Err(_) => Parsed { items: Vec::new(), errors: vec![(0, ItemError::UnreadableJson)] },
        };
    }
    let mut first = true;
    let lines = text.lines().enumerate().filter_map(|(i, raw)| {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            return None;
        }
        let header = first && looks_like_header(line);
        first = false;
        (!header).then(|| (i + 1, parse_line(i + 1, line)))
    });
    let parsed = collect(lines);
    if parsed.items.is_empty() && parsed.errors.is_empty() {
        return Parsed { items: Vec::new(), errors: vec![(0, ItemError::Empty)] };
    }
    parsed
}

fn collect(results: impl Iterator<Item = (usize, Result<Item, ItemError>)>) -> Parsed {
    let mut parsed = Parsed::default();
    for (line, result) in results {
        match result {
            Ok(item) if parsed.items.iter().any(|i| i.stream_url == item.stream_url) => {
                parsed.errors.push((line, ItemError::Repeated));
            }
            Ok(_) if parsed.items.len() >= MAX_ITEMS => {
                parsed.errors.push((line, ItemError::TooMany));
                break;
            }
            Ok(item) => parsed.items.push(item),
            Err(e) => parsed.errors.push((line, e)),
        }
    }
    parsed
}

/// The detection the platform ingests for a loaded stream, in the feed's own format, plus where it
/// came from and who loaded it (part of the evidence and of its hash).
pub fn detection(item: &Item, id: &str, minute: f64, ip: &str, origin: &str, loaded_by: Option<&str>) -> Value {
    let mut obj = item.extra.clone();
    obj.insert("id".into(), json!(id));
    // Three decimals, like the audit log: longer floats do not survive a JSON round trip exactly,
    // and the detection's hash is re-checked from the stored JSON.
    obj.insert("minuto".into(), json!((minute * 1000.0).round() / 1000.0));
    obj.insert("pagina".into(), json!(item.page.clone().unwrap_or_default()));
    obj.insert("stream_url".into(), json!(item.stream_url));
    obj.insert("host_stream".into(), json!(item.host));
    obj.insert("ip_servidor".into(), json!(ip));
    obj.insert("marca_de_agua_extraida".into(), json!(item.watermark));
    obj.insert("origen".into(), json!(origin));
    if let Some(by) = loaded_by {
        obj.insert("cargado_por".into(), json!(by));
    }
    Value::Object(obj)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::intake::{ItemError, MAX_ITEMS, ORIGIN_MANUAL, detection, parse_text};
    use crate::simulator::Detection;

    #[test]
    fn lines_take_any_order_after_the_stream() {
        let parsed = parse_text(
            "stream_url,marca_de_agua,pagina\n\
             https://s1.pelota.test/hls/index.m3u8, LP26-PRA-OFI-S1, https://pelota.test/vivo\n\
             # a comment\n\
             https://cdn.gol.test/live.m3u8 203.0.113.9 LP26-X\n\
             https://solo.test/a.m3u8\n",
        );
        assert!(parsed.errors.is_empty(), "{:?}", parsed.errors);
        assert_eq!(parsed.items.len(), 3);
        let first = &parsed.items[0];
        assert_eq!(first.line, 2);
        assert_eq!(first.host, "s1.pelota.test");
        assert_eq!(first.watermark.as_deref(), Some("LP26-PRA-OFI-S1"));
        assert_eq!(first.page.as_deref(), Some("https://pelota.test/vivo"));
        assert_eq!(parsed.items[1].ip.as_deref(), Some("203.0.113.9"));
        assert_eq!(parsed.items[1].watermark.as_deref(), Some("LP26-X"));
        assert_eq!(parsed.items[2].watermark, None);
    }

    #[test]
    fn bad_lines_are_reported_and_the_rest_kept() {
        let parsed = parse_text(
            "ftp://x.test/a\nhttps://ok.test/a.m3u8 bad!mark\nhttps://ok.test/b.m3u8\nhttps://ok.test/b.m3u8\n",
        );
        assert_eq!(parsed.items.len(), 1);
        assert_eq!(
            parsed.errors,
            vec![(1, ItemError::InvalidStreamUrl), (2, ItemError::InvalidWatermark), (4, ItemError::Repeated)]
        );
        assert_eq!(parse_text("  ").errors, vec![(0, ItemError::Empty)]);
        assert_eq!(parse_text("[{oops").errors, vec![(0, ItemError::UnreadableJson)]);
        assert_eq!(parse_text("notaurl").errors, vec![(1, ItemError::InvalidStreamUrl)]);
        assert_eq!(
            parse_text(
                "stream_url,marca
# nada"
            )
            .errors,
            vec![(0, ItemError::Empty)]
        );
    }

    #[test]
    fn json_keeps_feed_fields_and_builds_a_feed_detection() {
        let text = json!([{
            "stream_url": "https://s1.pelota.test/hls/index.m3u8",
            "marca_de_agua_extraida": "LP26-PRA-OFI-S1",
            "captura": {"formato": "mpegts", "contenido_b64": "Rw=="},
            "promocion": [{"red": "x", "url": "https://x.example/1"}]
        }])
        .to_string();
        let parsed = parse_text(&text);
        assert_eq!(parsed.items.len(), 1);
        let raw =
            detection(&parsed.items[0], "M-0001", 9.163942500000001, "203.0.113.10", ORIGIN_MANUAL, Some("fiscalia"));
        assert_eq!(raw["minuto"], 9.164);
        let again: serde_json::Value = serde_json::from_str(&raw.to_string()).expect("json");
        assert_eq!(again, raw, "the detection survives a JSON round trip");
        assert_eq!(raw["origen"], "manual");
        assert_eq!(raw["cargado_por"], "fiscalia");
        let d: Detection = serde_json::from_value(raw).expect("feed format");
        assert_eq!(d.stream_host, "s1.pelota.test");
        assert_eq!(d.server_ip, "203.0.113.10");
        assert_eq!(d.watermark.as_deref(), Some("LP26-PRA-OFI-S1"));
        assert!(d.capture.is_some());
        assert_eq!(d.promotion.len(), 1);
    }

    #[test]
    fn a_load_has_a_ceiling() {
        let text: String = (0..MAX_ITEMS + 5).map(|i| format!("https://s{i}.test/a.m3u8\n")).collect();
        let parsed = parse_text(&text);
        assert_eq!(parsed.items.len(), MAX_ITEMS);
        assert_eq!(parsed.errors, vec![(MAX_ITEMS + 1, ItemError::TooMany)]);
    }
}
