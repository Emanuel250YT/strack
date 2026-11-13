//! The stream reader's egress guard for ffmpeg. ffmpeg resolves names and follows redirects and the
//! entries of a playlist on its own, so when private addresses are not allowed it reaches the web only
//! through this loopback proxy (`-http_proxy`), which opens connections to public addresses alone:
//! plain HTTP requests in absolute form and HTTPS through `CONNECT`. The address checked is the
//! address connected to, so a name that resolves elsewhere a moment later cannot slip through.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const MAX_HEAD: usize = 16 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Starts the guard on a loopback port and returns its address. `allow` says which resolved
/// addresses may be reached (`platforms::public_ip` in production).
pub async fn start(allow: fn(IpAddr) -> bool) -> std::io::Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        loop {
            let Ok((client, _)) = listener.accept().await else { continue };
            tokio::spawn(async move {
                if let Err(e) = handle(client, allow).await {
                    tracing::debug!(error = %e, "egress guard closed a connection");
                }
            });
        }
    });
    Ok(addr)
}

async fn refuse(client: &mut TcpStream, status: &str) -> anyhow::Result<()> {
    client.write_all(format!("HTTP/1.1 {status}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n").as_bytes()).await?;
    Ok(())
}

/// A public address for `host:port`, or `None` when it has none `allow` accepts.
async fn reachable(host: &str, port: u16, allow: fn(IpAddr) -> bool) -> Option<SocketAddr> {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = host.parse::<IpAddr>() {
        return allow(ip).then_some(SocketAddr::new(ip, port));
    }
    let lower = host.to_ascii_lowercase();
    if lower == "localhost" || lower.ends_with(".localhost") {
        return None;
    }
    tokio::net::lookup_host((host, port)).await.ok()?.find(|a| allow(a.ip()))
}

async fn connect(addr: SocketAddr) -> anyhow::Result<TcpStream> {
    Ok(tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await??)
}

async fn handle(mut client: TcpStream, allow: fn(IpAddr) -> bool) -> anyhow::Result<()> {
    let mut buf = Vec::with_capacity(2048);
    let head_end = loop {
        let mut chunk = [0u8; 2048];
        let n = client.read(&mut chunk).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        if buf.len() > MAX_HEAD {
            return refuse(&mut client, "431 Request Header Fields Too Large").await;
        }
    };
    let Ok(head) = std::str::from_utf8(&buf[..head_end]) else {
        return refuse(&mut client, "400 Bad Request").await;
    };
    let mut lines = head.split("\r\n");
    let first = lines.next().unwrap_or_default();
    let mut parts = first.split(' ');
    let (Some(method), Some(target), Some(version)) = (parts.next(), parts.next(), parts.next()) else {
        return refuse(&mut client, "400 Bad Request").await;
    };

    if method.eq_ignore_ascii_case("CONNECT") {
        let Some((host, port)) = target.rsplit_once(':').and_then(|(h, p)| Some((h, p.parse::<u16>().ok()?))) else {
            return refuse(&mut client, "400 Bad Request").await;
        };
        let Some(addr) = reachable(host, port, allow).await else {
            return refuse(&mut client, "403 Forbidden").await;
        };
        let mut upstream = connect(addr).await?;
        client.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await?;
        if buf.len() > head_end {
            upstream.write_all(&buf[head_end..]).await?;
        }
        tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
        return Ok(());
    }

    let Ok(url) = reqwest::Url::parse(target) else {
        return refuse(&mut client, "400 Bad Request").await;
    };
    let (Some(host), Some(port)) = (url.host_str(), url.port_or_known_default()) else {
        return refuse(&mut client, "400 Bad Request").await;
    };
    if url.scheme() != "http" {
        return refuse(&mut client, "400 Bad Request").await;
    }
    let Some(addr) = reachable(host, port, allow).await else {
        return refuse(&mut client, "403 Forbidden").await;
    };
    let mut path = url.path().to_string();
    if let Some(query) = url.query() {
        path.push('?');
        path.push_str(query);
    }
    let mut out = format!("{method} {path} {version}\r\n");
    for line in lines.filter(|l| !l.is_empty() && !l.to_ascii_lowercase().starts_with("proxy-")) {
        out.push_str(line);
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    let mut upstream = connect(addr).await?;
    upstream.write_all(out.as_bytes()).await?;
    if buf.len() > head_end {
        upstream.write_all(&buf[head_end..]).await?;
    }
    tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::leak::egress::start;
    use crate::leak::platforms::public_ip;

    async fn origin() -> std::net::SocketAddr {
        let app = axum::Router::new().route("/clip", axum::routing::get(|| async { "frames" }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move { axum::serve(listener, app).await });
        addr
    }

    async fn ask(proxy: std::net::SocketAddr, request: String) -> String {
        let mut s = tokio::net::TcpStream::connect(proxy).await.expect("proxy");
        s.write_all(request.as_bytes()).await.expect("write");
        let mut out = String::new();
        let _ = s.read_to_string(&mut out).await;
        out
    }

    fn loopback(ip: IpAddr) -> bool {
        ip.is_loopback()
    }

    #[tokio::test]
    async fn internal_addresses_are_refused_whatever_the_request() {
        let target = origin().await;
        let guard = start(public_ip).await.expect("guard");
        let get = format!("GET http://{target}/clip HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n");
        assert!(ask(guard, get).await.starts_with("HTTP/1.1 403"));
        let tunnel = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
        assert!(ask(guard, tunnel).await.starts_with("HTTP/1.1 403"));
        let named = "GET http://localhost:9/ HTTP/1.1\r\nHost: localhost\r\n\r\n".to_string();
        assert!(ask(guard, named).await.starts_with("HTTP/1.1 403"));
    }

    #[tokio::test]
    async fn allowed_addresses_are_relayed() {
        let target = origin().await;
        let guard = start(loopback).await.expect("guard");
        let get = format!(
            "GET http://{target}/clip HTTP/1.1\r\nHost: {target}\r\nProxy-Connection: keep-alive\r\nConnection: close\r\n\r\n"
        );
        let answer = ask(guard, get).await;
        assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
        assert!(answer.ends_with("frames"));
    }
}
