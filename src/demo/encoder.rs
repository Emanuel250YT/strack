//! Live video for people: ffmpeg encodes the frames we feed it (raw RGB, or JPEG) to H.264, plus AAC
//! from the source file when there is one, as fragmented MP4 that a plain `<video>` plays live.
//!
//! The picture keeps the input's size and frame rate; quality is visually lossless (CRF 18) and there
//! is a keyframe every second, so a viewer joins and stays close to live. The encoder stops when the
//! viewer goes away or the feeder ends.
//!
//! The encoder never waits for the viewer: a paused player stops reading, and if that stalled ffmpeg
//! the live picture would be skipped while the sound (read from the file) would not, leaving them
//! apart. Instead the encoded video queues in memory (up to `MAX_PENDING_BYTES`) and the player
//! resumes where it paused, picture and sound together.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::header;
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::UnboundedReceiverStream;

/// Encoded video kept for a viewer who stopped reading (a paused player): about a minute and a half
/// at the usual rate. Past this the stream ends and the player has to reload.
const MAX_PENDING_BYTES: usize = 96 * 1024 * 1024;

#[derive(Clone, Copy)]
pub enum Input {
    Rgb { width: u32, height: u32 },
    Jpeg,
}

pub struct Audio {
    pub file: PathBuf,
    /// Second of the file the picture is at when the encoder starts.
    pub position: f64,
}

/// A running encoder; `start` also returns the HTTP response that streams its MP4 to the viewer.
pub struct Encoder {
    stdin: ChildStdin,
    /// Frame rate as a fraction (30000/1001 for 29.97 fps).
    rate: (u32, u32),
    child: Arc<Mutex<Child>>,
}

impl Encoder {
    /// Writes one frame; `false` once the encoder or the viewer is gone.
    pub fn write(&mut self, frame: &[u8]) -> bool {
        self.stdin.write_all(frame).is_ok()
    }

    /// Writes every frame `next` yields, as it comes: the source paces them (each original frame once).
    pub fn run_each(mut self, mut next: impl FnMut() -> Option<Vec<u8>>) {
        while let Some(frame) = next() {
            if !self.write(&frame) {
                break;
            }
        }
        self.finish();
    }

    /// Writes the current frame at a constant rate (repeating it when nothing new arrived), for
    /// sources that only expose their latest picture.
    pub fn run_paced(mut self, mut current: impl FnMut() -> Option<Vec<u8>>) {
        let period = Duration::from_secs_f64(f64::from(self.rate.1) / f64::from(self.rate.0));
        let mut due = Instant::now();
        while let Some(frame) = current() {
            if !self.write(&frame) {
                break;
            }
            due += period;
            let now = Instant::now();
            if due > now {
                std::thread::sleep(due - now);
            } else if now - due > Duration::from_secs(2) {
                due = now;
            }
        }
        self.finish();
    }

    /// Closes the input so ffmpeg flushes the last fragment, then makes sure the process ends.
    fn finish(self) {
        drop(self.stdin);
        let child = self.child;
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(5));
            kill(&child);
        });
    }
}

fn kill(child: &Arc<Mutex<Child>>) {
    if let Ok(mut c) = child.lock() {
        let _ = c.kill();
        let _ = c.wait();
    }
}

/// Starts ffmpeg and returns the frame writer plus the HTTP response that streams the video.
pub fn start(
    ffmpeg: &str,
    rate: (u32, u32),
    input: Input,
    audio: Option<Audio>,
) -> std::io::Result<(Encoder, Response)> {
    let rate = (rate.0.max(1), rate.1.max(1));
    let gop = (f64::from(rate.0) / f64::from(rate.1)).round().max(1.0).to_string();
    let mut cmd = Command::new(ffmpeg);
    cmd.args(["-hide_banner", "-loglevel", "error"]);
    match input {
        Input::Rgb { width, height } => {
            cmd.args(["-f", "rawvideo", "-pix_fmt", "rgb24", "-s", &format!("{width}x{height}")]);
        }
        Input::Jpeg => {
            // A small probe: the default (5 MB of JPEGs) would hold the first picture back for seconds.
            cmd.args(["-probesize", "65536", "-analyzeduration", "0", "-f", "image2pipe", "-c:v", "mjpeg"]);
        }
    }
    cmd.args(["-framerate", &format!("{}/{}", rate.0, rate.1), "-i", "pipe:0"]);
    if let Some(audio) = &audio {
        cmd.args(["-re", "-ss", &format!("{:.3}", audio.position.max(0.0)), "-i"]).arg(&audio.file);
        cmd.args(["-map", "0:v", "-map", "1:a?", "-c:a", "aac", "-b:a", "160k", "-ac", "2"]);
    }
    cmd.args(["-c:v", "libx264", "-preset", "veryfast", "-tune", "zerolatency", "-pix_fmt", "yuv420p"]);
    cmd.args(["-profile:v", "high", "-crf", "18", "-maxrate", "8M", "-bufsize", "8M"]);
    cmd.args(["-g", &gop, "-keyint_min", &gop, "-sc_threshold", "0"]);
    cmd.args(["-movflags", "frag_keyframe+empty_moov+default_base_moof", "-f", "mp4", "pipe:1"]);
    let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit()).spawn()?;
    let stdin = child.stdin.take().ok_or_else(|| std::io::Error::other("no stdin"))?;
    let mut stdout = child.stdout.take().ok_or_else(|| std::io::Error::other("no stdout"))?;
    let child = Arc::new(Mutex::new(child));

    let (tx, rx) = mpsc::unbounded_channel::<Bytes>();
    let pending = Arc::new(AtomicUsize::new(0));
    let reader_child = child.clone();
    let reader_pending = pending.clone();
    std::thread::spawn(move || {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match stdout.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if reader_pending.fetch_add(n, Ordering::Relaxed) + n > MAX_PENDING_BYTES {
                        tracing::warn!("a viewer stopped reading for too long: ending their stream");
                        break;
                    }
                    if tx.send(Bytes::copy_from_slice(&buf[..n])).is_err() {
                        break;
                    }
                }
            }
        }
        kill(&reader_child);
    });
    let body = UnboundedReceiverStream::new(rx).map(move |chunk| {
        pending.fetch_sub(chunk.len(), Ordering::Relaxed);
        Ok::<_, std::io::Error>(chunk)
    });
    let response =
        ([(header::CONTENT_TYPE, "video/mp4"), (header::CACHE_CONTROL, "no-store")], Body::from_stream(body))
            .into_response();
    Ok((Encoder { stdin, rate, child }, response))
}
