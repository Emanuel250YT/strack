//! One-off mark reading: open a stream (or the videos found in a page), scan its frames until a
//! licensed platform's session mark shows up, and return that mark with the frame it was read from.
//! Unlike a trace it keeps no record and sends no notice: "Cargar sitios" uses it to build a case's
//! watermark and capture evidence from the pirate stream itself.

use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;

use crate::app::App;
use crate::leak::discover;
use crate::leak::extract::Scanner;
use crate::leak::mark::{SessionMark, platform_code};
use crate::leak::source::{FrameSource, Probe, StreamFormat, probe, readable_target};

/// Frames are scanned at most this often (the watermark detector compares frames over time).
const SCAN_INTERVAL: Duration = Duration::from_millis(100);
/// ffmpeg needs a few seconds to start a stream; MJPEG frames come at once.
const FRAME_TIMEOUT: Duration = Duration::from_secs(20);

/// A session mark read from a pirate stream.
pub struct MarkReading {
    /// The stream the mark was read from (a video found in the page when a page was given).
    pub stream_url: String,
    /// The page the stream was found in, when the address given was a page.
    pub page_url: Option<String>,
    pub format: StreamFormat,
    pub mark: SessionMark,
    /// The JPEG frame the mark was read from.
    pub frame: Bytes,
}

/// Reads `url` for up to `limit`. `Ok(None)`: no mark of a registered platform was seen in time.
pub async fn read_mark(app: &Arc<App>, url: &str, limit: Duration) -> anyhow::Result<Option<MarkReading>> {
    let deadline = Instant::now() + limit;
    let allow_private = app.settings.allow_private_streams;
    if !readable_target(url, allow_private).await {
        anyhow::bail!("address not allowed");
    }
    let (mut candidates, page_url) = match probe(&app.http, url).await? {
        Probe::Page => {
            let found = discover::discover(&app.http, url, allow_private).await.unwrap_or_default();
            (found.into_iter().map(|c| (c.url, c.format)).collect::<Vec<_>>(), Some(url.to_string()))
        }
        Probe::Stream(format) => (vec![(url.to_string(), Some(format))], None),
    };
    // Native formats first: an MJPEG copy is read at once, video through ffmpeg takes longer.
    candidates.sort_by_key(|(_, format)| !matches!(format, Some(StreamFormat::Mjpeg | StreamFormat::Jpeg)));
    let mut last_error = None;
    for (stream_url, _) in candidates {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        if !readable_target(&stream_url, allow_private).await {
            continue;
        }
        match tokio::time::timeout(left, read_one(app, &stream_url)).await {
            Ok(Ok(Some((format, mark, frame)))) => {
                return Ok(Some(MarkReading { stream_url, page_url, format, mark, frame }));
            }
            Ok(Ok(None)) | Err(_) => {}
            Ok(Err(e)) => last_error = Some(e),
        }
    }
    match last_error {
        Some(e) => Err(e),
        None => Ok(None),
    }
}

async fn read_one(app: &Arc<App>, url: &str) -> anyhow::Result<Option<(StreamFormat, SessionMark, Bytes)>> {
    let format = match probe(&app.http, url).await? {
        Probe::Stream(format) => format,
        Probe::Page => return Ok(None),
    };
    let codes = app.platforms().platforms.iter().map(|p| platform_code(&p.id)).collect();
    let mut scanner = Some(Scanner::new(codes));
    let mut source = FrameSource::open(&app.http, url, format, &app.settings.ffmpeg).await?;
    let started = Instant::now();
    let mut last_scan: Option<Instant> = None;
    loop {
        let Some(frame) = tokio::time::timeout(FRAME_TIMEOUT, source.next_frame()).await?? else {
            return Ok(None);
        };
        if last_scan.is_some_and(|t| t.elapsed() < SCAN_INTERVAL) {
            continue;
        }
        last_scan = Some(Instant::now());
        let at = started.elapsed().as_secs_f64();
        let mut current = scanner.take().unwrap_or_default();
        let bytes = frame.clone();
        let (current, found) = tokio::task::spawn_blocking(move || {
            let found = current.scan(&bytes, at);
            (current, found)
        })
        .await?;
        scanner = Some(current);
        if let Some(found) = found.into_iter().next() {
            return Ok(Some((format, found.mark, frame)));
        }
    }
}
