//! MJPEG over HTTP (`multipart/x-mixed-replace`): writing parts on the server side and reading frames
//! from a stream (or a single JPEG image) on the client side.

use std::pin::Pin;

use anyhow::bail;
use axum::body::Body;
use axum::http::header;
use axum::response::{IntoResponse, Response};
use bytes::{Bytes, BytesMut};
use futures_util::{Stream, StreamExt};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

pub const BOUNDARY: &str = "strackframe";
const MAX_BUFFER: usize = 8 * 1024 * 1024;

pub fn content_type() -> String {
    format!("multipart/x-mixed-replace; boundary={BOUNDARY}")
}

/// One multipart part carrying a JPEG frame.
pub fn part(jpeg: &[u8]) -> Bytes {
    let head = format!("--{BOUNDARY}\r\nContent-Type: image/jpeg\r\nContent-Length: {}\r\n\r\n", jpeg.len());
    let mut buf = BytesMut::with_capacity(head.len() + jpeg.len() + 2);
    buf.extend_from_slice(head.as_bytes());
    buf.extend_from_slice(jpeg);
    buf.extend_from_slice(b"\r\n");
    buf.freeze()
}

/// Streams the parts sent on `rx` as an MJPEG response; the stream ends when the sender is dropped.
pub fn response(rx: mpsc::Receiver<Bytes>) -> Response {
    let stream = ReceiverStream::new(rx).map(Ok::<Bytes, std::convert::Infallible>);
    (
        [(header::CONTENT_TYPE, content_type()), (header::CACHE_CONTROL, "no-store".to_string())],
        Body::from_stream(stream),
    )
        .into_response()
}

pub type ByteStream<E> = Pin<Box<dyn Stream<Item = Result<Bytes, E>> + Send>>;

/// Reads JPEG frames from an MJPEG body, or yields the whole body once for a single `image/jpeg`.
pub struct FrameReader<E> {
    stream: ByteStream<E>,
    buf: BytesMut,
    single: bool,
    done: bool,
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

impl<E> FrameReader<E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    pub fn new(stream: ByteStream<E>, single: bool) -> Self {
        FrameReader { stream, buf: BytesMut::new(), single, done: false }
    }

    pub async fn next_frame(&mut self) -> anyhow::Result<Option<Bytes>> {
        loop {
            if let Some(frame) = self.try_parse() {
                return Ok(Some(frame));
            }
            match self.stream.next().await {
                Some(chunk) => {
                    self.buf.extend_from_slice(&chunk?);
                    if self.buf.len() > MAX_BUFFER {
                        bail!("no frame boundary in {} bytes", self.buf.len());
                    }
                }
                None if self.single && !self.done && !self.buf.is_empty() => {
                    self.done = true;
                    return Ok(Some(self.buf.split().freeze()));
                }
                None => return Ok(None),
            }
        }
    }

    fn try_parse(&mut self) -> Option<Bytes> {
        if self.single {
            return None;
        }
        let header_end = find(&self.buf, b"\r\n\r\n")?;
        let headers = String::from_utf8_lossy(&self.buf[..header_end]).into_owned();
        let length = headers.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.trim().eq_ignore_ascii_case("content-length") { value.trim().parse::<usize>().ok() } else { None }
        });
        let body = header_end + 4;
        match length {
            Some(len) => {
                if self.buf.len() < body + len {
                    return None;
                }
                let _ = self.buf.split_to(body);
                Some(self.buf.split_to(len).freeze())
            }
            // No Content-Length: take the JPEG from its SOI to its EOI marker.
            None => {
                let soi = body + find(&self.buf[body..], &[0xFF, 0xD8])?;
                let end = soi + find(&self.buf[soi..], &[0xFF, 0xD9])? + 2;
                let _ = self.buf.split_to(soi);
                Some(self.buf.split_to(end - soi).freeze())
            }
        }
    }
}

/// Opens an MJPEG stream (or a JPEG image) for reading frames.
pub async fn open(http: &reqwest::Client, url: &str) -> anyhow::Result<FrameReader<reqwest::Error>> {
    let response = http.get(url).send().await?.error_for_status()?;
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let single = content_type.starts_with("image/");
    if !single && !content_type.starts_with("multipart/") {
        bail!("not an MJPEG stream or a JPEG image (content type {content_type:?})");
    }
    Ok(FrameReader::new(Box::pin(response.bytes_stream()), single))
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use futures_util::stream;

    use crate::leak::mjpeg::{FrameReader, part};

    #[tokio::test]
    async fn reads_frames_split_across_chunks() {
        let a = [0xFF, 0xD8, 1, 2, 3, 0xFF, 0xD9];
        let b = [0xFF, 0xD8, 9, 9, 0xFF, 0xD9];
        let mut wire = part(&a).to_vec();
        wire.extend_from_slice(&part(&b));
        let chunks: Vec<Result<Bytes, std::io::Error>> =
            wire.chunks(5).map(|c| Ok(Bytes::copy_from_slice(c))).collect();
        let mut reader = FrameReader::new(Box::pin(stream::iter(chunks)), false);
        assert_eq!(reader.next_frame().await.unwrap().unwrap().as_ref(), &a);
        assert_eq!(reader.next_frame().await.unwrap().unwrap().as_ref(), &b);
        assert!(reader.next_frame().await.unwrap().is_none());
    }
}
