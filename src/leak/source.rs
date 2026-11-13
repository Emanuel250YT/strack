//! Where a trace's frames come from. An MJPEG stream or a JPEG image is read natively; anything else
//! ffmpeg can play (HLS, DASH, MP4, MPEG-TS, WebM, FLV, RTMP) is decoded by ffmpeg into JPEG frames
//! for the same scanner. ffmpeg only gets network protocols, so an address someone types (or a
//! playlist it points to) can never make it read local files.

use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, bail};
use bytes::{Bytes, BytesMut};
use reqwest::header;
use tokio::io::AsyncReadExt;
use tokio::process::{Child, ChildStdout, Command};

use crate::leak::mjpeg::{self, FrameReader};

/// Frames per second ffmpeg hands to the scanner (the watermark detector works on 8 fps).
const DECODE_FPS: u32 = 8;
/// Network inputs are dropped after this long without data (ffmpeg's `-rw_timeout`, microseconds).
const RW_TIMEOUT_US: &str = "15000000";
/// Only network protocols: `file`, `concat`, `pipe` and friends stay out.
const PROTOCOLS: &str = "http,https,tcp,tls,crypto,hls,rtmp,rtmps,httpproxy";
/// A JPEG frame bigger than this means the output is not what we expect.
const MAX_FRAME: usize = 16 * 1024 * 1024;

/// What kind of stream an address holds, as people call it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamFormat {
    Mjpeg,
    Jpeg,
    Hls,
    Dash,
    Rtmp,
    /// A progressive file or a stream ffmpeg recognises by itself (MP4, MPEG-TS, WebM, FLV).
    Video,
}

impl StreamFormat {
    pub fn label(self) -> &'static str {
        match self {
            StreamFormat::Mjpeg => "MJPEG",
            StreamFormat::Jpeg => "Imagen JPEG",
            StreamFormat::Hls => "HLS",
            StreamFormat::Dash => "DASH",
            StreamFormat::Rtmp => "RTMP",
            StreamFormat::Video => "Video (MP4, TS, WebM…)",
        }
    }

    /// Guesses from the address alone (before anything is fetched).
    pub fn from_url(url: &str) -> Option<Self> {
        let lower = url.to_ascii_lowercase();
        let path = lower.split(['?', '#']).next().unwrap_or_default();
        if lower.starts_with("rtmp://") || lower.starts_with("rtmps://") {
            return Some(StreamFormat::Rtmp);
        }
        if path.ends_with(".m3u8") {
            Some(StreamFormat::Hls)
        } else if path.ends_with(".mpd") {
            Some(StreamFormat::Dash)
        } else if path.ends_with(".mjpg") || path.ends_with(".mjpeg") {
            Some(StreamFormat::Mjpeg)
        } else if [".mp4", ".m4v", ".ts", ".webm", ".flv", ".mkv", ".mov"].iter().any(|e| path.ends_with(e)) {
            Some(StreamFormat::Video)
        } else {
            None
        }
    }

    fn from_content_type(content_type: &str) -> Option<Self> {
        let ct = content_type.to_ascii_lowercase();
        if ct.starts_with("multipart/") {
            Some(StreamFormat::Mjpeg)
        } else if ct.starts_with("image/") {
            Some(StreamFormat::Jpeg)
        } else if ct.contains("mpegurl") {
            Some(StreamFormat::Hls)
        } else if ct.contains("dash+xml") {
            Some(StreamFormat::Dash)
        } else if ct.starts_with("video/") || ct.contains("octet-stream") || ct.contains("mp2t") {
            Some(StreamFormat::Video)
        } else {
            None
        }
    }
}

/// What a first request to an address found.
pub enum Probe {
    /// A stream: read it with [`FrameSource::open`].
    Stream(StreamFormat),
    /// An HTML page: look for the video in it (`leak::discover`).
    Page,
}

/// Looks at an address without reading the stream: its headers, or its scheme for RTMP.
pub async fn probe(http: &reqwest::Client, url: &str) -> anyhow::Result<Probe> {
    if let Some(StreamFormat::Rtmp) = StreamFormat::from_url(url) {
        return Ok(Probe::Stream(StreamFormat::Rtmp));
    }
    let response = http.get(url).timeout(Duration::from_secs(10)).send().await?.error_for_status()?;
    let content_type =
        response.headers().get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or_default().to_string();
    drop(response);
    if content_type.to_ascii_lowercase().contains("html") {
        return Ok(Probe::Page);
    }
    Ok(Probe::Stream(
        StreamFormat::from_content_type(&content_type)
            .or_else(|| StreamFormat::from_url(url))
            .unwrap_or(StreamFormat::Video),
    ))
}

/// ffmpeg playing a network stream and writing JPEG frames.
pub struct FfmpegFrames {
    _child: Child,
    stdout: ChildStdout,
    buf: BytesMut,
}

impl FfmpegFrames {
    pub fn spawn(ffmpeg: &str, url: &str) -> anyhow::Result<Self> {
        let mut cmd = Command::new(ffmpeg);
        cmd.args(["-hide_banner", "-loglevel", "error", "-nostdin", "-protocol_whitelist", PROTOCOLS]);
        if url.starts_with("http") {
            cmd.args(["-reconnect", "1", "-reconnect_streamed", "1", "-reconnect_delay_max", "5"]);
        }
        let mut child = cmd
            .args(["-rw_timeout", RW_TIMEOUT_US, "-re", "-i", url, "-an"])
            .args(["-vf", &format!("fps={DECODE_FPS},scale='min(1280,iw)':-2")])
            .args(["-f", "image2pipe", "-c:v", "mjpeg", "-q:v", "3", "pipe:1"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("running {ffmpeg}: install ffmpeg or pass --ffmpeg <path>"))?;
        let stdout = child.stdout.take().context("no ffmpeg output")?;
        Ok(FfmpegFrames { _child: child, stdout, buf: BytesMut::new() })
    }

    pub async fn next_frame(&mut self) -> anyhow::Result<Option<Bytes>> {
        let mut chunk = vec![0u8; 64 * 1024];
        loop {
            if let Some(frame) = take_jpeg(&mut self.buf) {
                return Ok(Some(frame));
            }
            if self.buf.len() > MAX_FRAME {
                bail!("ffmpeg output has no frame boundary in {} bytes", self.buf.len());
            }
            let n = self.stdout.read(&mut chunk).await?;
            if n == 0 {
                return Ok(None);
            }
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }
}

/// Takes the first whole JPEG (SOI to EOI) off the front of `buf`. Entropy-coded data never holds
/// `FF D9`: 0xFF bytes are stuffed as `FF 00`.
pub fn take_jpeg(buf: &mut BytesMut) -> Option<Bytes> {
    let soi = buf.windows(2).position(|w| w == [0xFF, 0xD8])?;
    let eoi = buf[soi + 2..].windows(2).position(|w| w == [0xFF, 0xD9])? + soi + 2;
    let _ = buf.split_to(soi);
    Some(buf.split_to(eoi + 2 - soi).freeze())
}

/// Frames of one connection to a stream, whatever its format.
pub enum FrameSource {
    Native(FrameReader<reqwest::Error>),
    Ffmpeg(Box<FfmpegFrames>),
}

impl FrameSource {
    /// Connects to `url`, read natively (MJPEG, JPEG) or through ffmpeg (everything else).
    pub async fn open(http: &reqwest::Client, url: &str, format: StreamFormat, ffmpeg: &str) -> anyhow::Result<Self> {
        match format {
            StreamFormat::Mjpeg | StreamFormat::Jpeg => Ok(FrameSource::Native(mjpeg::open(http, url).await?)),
            _ => Ok(FrameSource::Ffmpeg(Box::new(FfmpegFrames::spawn(ffmpeg, url)?))),
        }
    }

    pub async fn next_frame(&mut self) -> anyhow::Result<Option<Bytes>> {
        match self {
            FrameSource::Native(reader) => reader.next_frame().await,
            FrameSource::Ffmpeg(frames) => frames.next_frame().await,
        }
    }
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;

    use crate::leak::source::{StreamFormat, take_jpeg};

    #[test]
    fn formats_from_addresses() {
        assert_eq!(StreamFormat::from_url("https://cdn.test/live/index.m3u8?token=1"), Some(StreamFormat::Hls));
        assert_eq!(StreamFormat::from_url("https://cdn.test/manifest.mpd"), Some(StreamFormat::Dash));
        assert_eq!(StreamFormat::from_url("http://127.0.0.1:8200/stream.mjpg"), Some(StreamFormat::Mjpeg));
        assert_eq!(StreamFormat::from_url("rtmp://live.test/app/key"), Some(StreamFormat::Rtmp));
        assert_eq!(StreamFormat::from_url("https://x.test/partido.mp4#t=10"), Some(StreamFormat::Video));
        assert_eq!(StreamFormat::from_url("https://x.test/ver-partido"), None);
    }

    #[test]
    fn jpegs_come_off_a_growing_buffer() {
        let mut buf = BytesMut::from(&[0x00, 0xFF, 0xD8, 1, 0xFF, 0x00, 2, 0xFF, 0xD9, 0xFF, 0xD8, 3][..]);
        let first = take_jpeg(&mut buf).expect("one frame");
        assert_eq!(&first[..], &[0xFF, 0xD8, 1, 0xFF, 0x00, 2, 0xFF, 0xD9]);
        assert!(take_jpeg(&mut buf).is_none(), "the second frame is not complete yet");
        buf.extend_from_slice(&[0xFF, 0xD9]);
        assert_eq!(&take_jpeg(&mut buf).expect("second frame")[..], &[0xFF, 0xD8, 3, 0xFF, 0xD9]);
    }
}
