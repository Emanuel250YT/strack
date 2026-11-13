//! Finds the video in a pirate page, so a trace can start from the address people actually see. The
//! page's HTML is read (size- and time-limited, never run) and the streams are taken from `<video>`,
//! `<source>`, `<embed>`, `<object>`, `<img>` pointing at MJPEG, and stream addresses written in its
//! scripts (`.m3u8`, `.mpd`, `.mjpg`, `.mp4`, `rtmp://` ...). Embedded players (`<iframe>`) are
//! followed one level.

use std::time::Duration;

use anyhow::{Context, bail};
use futures_util::StreamExt;
use reqwest::Url;

use crate::leak::source::{StreamFormat, readable_target};

/// Pages bigger than this are cut (players and their scripts are well below it).
const MAX_PAGE: usize = 2 * 1024 * 1024;
const MAX_IFRAMES: usize = 4;
pub const MAX_STREAMS: usize = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub url: String,
    pub format: Option<StreamFormat>,
    /// Where it was found: `video`, `source`, `img`, `script`, `iframe > video`, ...
    pub via: String,
}

fn rank(c: &Candidate) -> u8 {
    match c.format {
        Some(StreamFormat::Mjpeg) => 0,
        Some(StreamFormat::Hls) => 1,
        Some(StreamFormat::Dash) => 2,
        Some(StreamFormat::Video) => 3,
        Some(StreamFormat::Rtmp) => 4,
        Some(StreamFormat::Jpeg) | None => 5,
    }
}

/// Reads the value of attribute `name` in one tag's text (`<video src="..." ...>`).
fn attribute(tag: &str, name: &str) -> Option<String> {
    let lower = tag.to_ascii_lowercase();
    let mut from = 0;
    while let Some(pos) = lower[from..].find(name) {
        let start = from + pos;
        from = start + name.len();
        let before_ok = start == 0 || lower.as_bytes()[start - 1].is_ascii_whitespace();
        let rest = lower[from..].trim_start();
        if !before_ok || !rest.starts_with('=') {
            continue;
        }
        let offset = tag.len() - rest.len() + 1;
        let value = tag[offset..].trim_start();
        let value = match value.chars().next() {
            Some(q @ ('"' | '\'')) => value[1..].split(q).next().unwrap_or_default(),
            _ => value.split(|c: char| c.is_whitespace() || c == '>').next().unwrap_or_default(),
        };
        return Some(html_unescape(value.trim()));
    }
    None
}

fn html_unescape(s: &str) -> String {
    s.replace("&amp;", "&").replace("&#38;", "&").replace("&quot;", "\"").replace("&#39;", "'")
}

const STREAM_HINTS: [&str; 9] = [".m3u8", ".mpd", ".mjpg", ".mjpeg", ".mp4", ".webm", ".flv", ".ts?", "rtmp://"];

/// Addresses that look like streams anywhere in the text (scripts, data attributes, JSON configs).
fn script_urls(html: &str) -> Vec<String> {
    let lower = html.to_ascii_lowercase();
    let mut out = Vec::new();
    for hint in STREAM_HINTS {
        let mut from = 0;
        while let Some(pos) = lower[from..].find(hint) {
            let at = from + pos;
            from = at + hint.len();
            let is_delim =
                |c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '`' | '(' | ')' | '<' | '>' | ',' | ';' | '=');
            let start = html[..at].rfind(is_delim).map_or(0, |i| i + 1);
            let end = html[at..].find(is_delim).map_or(html.len(), |i| at + i);
            let token = html[start..end].replace("\\/", "/");
            if token.len() > 4 && token.len() < 2048 {
                out.push(token);
            }
        }
    }
    out
}

/// Stream candidates and embedded players found in one page's HTML.
pub fn extract(html: &str, base: &Url) -> (Vec<Candidate>, Vec<Url>) {
    let resolve = |raw: &str| -> Option<Url> {
        let raw = raw.trim();
        if raw.is_empty() || raw.starts_with("data:") || raw.starts_with("blob:") || raw.starts_with("javascript:") {
            return None;
        }
        let url = base.join(raw).ok()?;
        matches!(url.scheme(), "http" | "https" | "rtmp" | "rtmps").then_some(url)
    };
    let mut streams: Vec<Candidate> = Vec::new();
    let mut iframes: Vec<Url> = Vec::new();
    let push = |url: Url, via: &str, streams: &mut Vec<Candidate>| {
        let url = url.to_string();
        if !streams.iter().any(|c| c.url == url) {
            streams.push(Candidate { format: StreamFormat::from_url(&url), url, via: via.to_string() });
        }
    };
    let lower = html.to_ascii_lowercase();
    let mut from = 0;
    while let Some(pos) = lower[from..].find('<') {
        let start = from + pos;
        let Some(len) = lower[start..].find('>') else { break };
        let tag = &html[start..start + len + 1];
        from = start + len + 1;
        let name: String =
            tag[1..].chars().take_while(|c| c.is_ascii_alphanumeric()).collect::<String>().to_ascii_lowercase();
        match name.as_str() {
            "video" | "source" | "embed" | "audio" => {
                for attr in ["src", "data-src"] {
                    if let Some(url) = attribute(tag, attr).as_deref().and_then(&resolve) {
                        push(url, &name, &mut streams);
                    }
                }
            }
            "object" => {
                if let Some(url) = attribute(tag, "data").as_deref().and_then(&resolve) {
                    push(url, "object", &mut streams);
                }
            }
            "img" => {
                // Only images that are streams (MJPEG players); logos and posters are not.
                if let Some(url) = attribute(tag, "src").as_deref().and_then(&resolve)
                    && matches!(StreamFormat::from_url(url.as_str()), Some(StreamFormat::Mjpeg))
                {
                    push(url, "img", &mut streams);
                }
            }
            "iframe" => {
                if let Some(url) = attribute(tag, "src").as_deref().and_then(&resolve)
                    && !iframes.contains(&url)
                {
                    iframes.push(url);
                }
            }
            _ => {}
        }
    }
    for raw in script_urls(html) {
        if let Some(url) = resolve(&raw)
            && StreamFormat::from_url(url.as_str()).is_some()
        {
            push(url, "script", &mut streams);
        }
    }
    streams.sort_by_key(rank);
    (streams, iframes)
}

async fn fetch_page(http: &reqwest::Client, url: &Url) -> anyhow::Result<String> {
    let response = http.get(url.clone()).timeout(Duration::from_secs(10)).send().await?.error_for_status()?;
    let is_html = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.to_ascii_lowercase().contains("html"));
    if !is_html {
        bail!("not an HTML page");
    }
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        body.extend_from_slice(&chunk?);
        if body.len() >= MAX_PAGE {
            body.truncate(MAX_PAGE);
            break;
        }
    }
    Ok(String::from_utf8_lossy(&body).into_owned())
}

/// The streams of a pirate page (and of the players it embeds), best first, at most [`MAX_STREAMS`].
/// Embedded players are fetched only when `readable_target` allows their address.
pub async fn discover(http: &reqwest::Client, page: &str, allow_private: bool) -> anyhow::Result<Vec<Candidate>> {
    let base = Url::parse(page).context("not an address")?;
    let html = fetch_page(http, &base).await?;
    let (mut streams, iframes) = extract(&html, &base);
    for frame in iframes.into_iter().take(MAX_IFRAMES) {
        if !readable_target(frame.as_str(), allow_private).await {
            continue;
        }
        let Ok(inner) = fetch_page(http, &frame).await else { continue };
        let (found, _) = extract(&inner, &frame);
        for mut c in found {
            if !streams.iter().any(|s| s.url == c.url) {
                c.via = format!("iframe > {}", c.via);
                streams.push(c);
            }
        }
    }
    streams.sort_by_key(rank);
    streams.truncate(MAX_STREAMS);
    Ok(streams)
}

#[cfg(test)]
mod tests {
    use reqwest::Url;

    use crate::leak::discover::{attribute, extract};
    use crate::leak::source::StreamFormat;

    #[test]
    fn attributes_with_and_without_quotes() {
        assert_eq!(attribute(r#"<video class="p" src="/a.m3u8">"#, "src").as_deref(), Some("/a.m3u8"));
        assert_eq!(attribute("<source src='b.mpd' type=x>", "src").as_deref(), Some("b.mpd"));
        assert_eq!(attribute("<img src=/stream.mjpg alt=x>", "src").as_deref(), Some("/stream.mjpg"));
        assert_eq!(attribute(r#"<video data-src="x.mp4">"#, "src"), None, "data-src is not src");
        assert_eq!(attribute(r#"<a href="?a=1&amp;b=2">"#, "href").as_deref(), Some("?a=1&b=2"));
    }

    #[test]
    fn finds_the_streams_of_a_pirate_page() {
        let base = Url::parse("https://pirata.test/partido/hoy").unwrap();
        let html = r#"
            <img src="/logo.png"><img src="/vivo/stream.mjpg">
            <video id="p" poster="/p.jpg"><source src="https://cdn.pirata.test/live/index.m3u8" type="application/x-mpegURL"></video>
            <iframe src="//player.pirata.test/embed/7"></iframe>
            <script>var cfg = {"file":"https:\/\/cdn2.pirata.test\/hd\/master.m3u8","backup":'/media/partido.mp4'};</script>
            <video src="blob:https://pirata.test/1"></video>
        "#;
        let (streams, iframes) = extract(html, &base);
        let urls: Vec<&str> = streams.iter().map(|c| c.url.as_str()).collect();
        assert_eq!(
            urls,
            vec![
                "https://pirata.test/vivo/stream.mjpg",
                "https://cdn.pirata.test/live/index.m3u8",
                "https://cdn2.pirata.test/hd/master.m3u8",
                "https://pirata.test/media/partido.mp4",
            ]
        );
        assert_eq!(streams[0].format, Some(StreamFormat::Mjpeg));
        assert_eq!(streams[0].via, "img");
        assert_eq!(streams[2].via, "script");
        assert_eq!(iframes, vec![Url::parse("https://player.pirata.test/embed/7").unwrap()]);
    }
}
