//! Real footage for the demo platform (`strack demo platform --video <file>`).
//!
//! ffmpeg (an external tool, needed only for this option) decodes the file in real time at its own
//! resolution and frame rate: no scaling and no dropped frames, so viewers get the original picture
//! (plus the invisible session mark). It plays the file once, start to end, unless `--loop` is given.
//!
//! Like live TV, the broadcast goes on air with its first viewer and then follows the wall clock, so
//! it lasts exactly as long as the file. ffmpeg only runs while somebody watches (it stops after a few
//! idle seconds); a viewer who arrives later joins at the current minute. The file is read from disk
//! and never copied anywhere.

use std::io::Read;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, anyhow, bail};
use image::RgbImage;
use serde_json::Value;
use tokio::sync::broadcast;

use crate::demo::platform::{Frame, end_slate};
use crate::leak::scene::channel_bug;

const IDLE_STOP: Duration = Duration::from_secs(10);

pub struct VideoSource {
    pub path: PathBuf,
    pub ffmpeg: String,
    pub start_secs: f64,
    pub width: u32,
    pub height: u32,
    /// Frame rate as a fraction (30000/1001 for 29.97 fps).
    pub rate: (u32, u32),
    /// Length of the file, to wrap the resume position (`None` if ffprobe could not tell).
    pub duration: Option<f64>,
    /// Start again at the end; otherwise the broadcast ends with the file.
    pub looping: bool,
}

fn ffprobe_for(ffmpeg: &str) -> String {
    match ffmpeg.rfind("ffmpeg") {
        Some(i) => format!("{}ffprobe{}", &ffmpeg[..i], &ffmpeg[i + "ffmpeg".len()..]),
        None => "ffprobe".to_string(),
    }
}

fn parse_rate(text: &str) -> Option<(u32, u32)> {
    let (num, den) = text.split_once('/').unwrap_or((text, "1"));
    let (num, den) = (num.trim().parse::<u32>().ok()?, den.trim().parse::<u32>().ok()?);
    (num > 0 && den > 0 && num / den <= 120).then_some((num, den))
}

impl VideoSource {
    /// Checks the file and ffmpeg and reads the video's size and rate before the platform starts.
    pub fn new(path: PathBuf, ffmpeg: String, start_secs: f64, looping: bool) -> anyhow::Result<Self> {
        if !path.is_file() {
            bail!("video file not found: {}", path.display());
        }
        let ok = Command::new(&ffmpeg)
            .arg("-version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .with_context(|| format!("running {ffmpeg}: install ffmpeg or pass --ffmpeg <path>"))?
            .success();
        if !ok {
            bail!("{ffmpeg} -version failed");
        }
        let probe = Command::new(ffprobe_for(&ffmpeg))
            .args(["-v", "error", "-select_streams", "v:0", "-show_entries", "stream=width,height,r_frame_rate"])
            .args(["-show_entries", "format=duration", "-of", "json"])
            .arg(&path)
            .output()
            .context("running ffprobe")?;
        let info: Value = serde_json::from_slice(&probe.stdout).context("reading ffprobe's answer")?;
        let stream = &info["streams"][0];
        let width = stream["width"].as_u64().ok_or_else(|| anyhow!("the file has no video stream"))? as u32;
        let height = stream["height"].as_u64().unwrap_or(0) as u32;
        let rate = stream["r_frame_rate"].as_str().and_then(parse_rate).unwrap_or((25, 1));
        let duration = info["format"]["duration"].as_str().and_then(|d| d.parse::<f64>().ok()).filter(|d| *d > 1.0);
        if width == 0 || height == 0 {
            bail!("could not read the video size");
        }
        Ok(VideoSource { path, ffmpeg, start_secs: start_secs.max(0.0), width, height, rate, duration, looping })
    }

    pub fn fps(&self) -> f64 {
        f64::from(self.rate.0) / f64::from(self.rate.1)
    }

    fn spawn(&self, position: f64) -> std::io::Result<Child> {
        let mut cmd = Command::new(&self.ffmpeg);
        cmd.args(["-hide_banner", "-loglevel", "error", "-nostdin"]);
        if self.looping {
            cmd.args(["-stream_loop", "-1"]);
        }
        cmd.arg("-ss")
            .arg(format!("{position:.3}"))
            .args(["-re", "-i"])
            .arg(&self.path)
            .args(["-an", "-f", "rawvideo", "-pix_fmt", "rgb24", "pipe:1"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
    }
}

/// Runs on its own thread for the life of the platform: publishes every decoded frame on `tx`, in
/// order (stamped with the broadcast clock and its second in the file), while anyone is watching.
/// When the file ends (without `--loop`) it publishes the closing card and sets `ended`.
pub fn run(
    source: VideoSource,
    tx: broadcast::Sender<Arc<Frame>>,
    channel: String,
    clock: Instant,
    ended: Arc<AtomicBool>,
) {
    let frame_bytes = (source.width * source.height * 3) as usize;
    let wrap = |pos: f64| match source.duration {
        Some(duration) if source.looping => pos % duration,
        _ => pos,
    };
    // Where the broadcast is now: the start point plus the time since it went on air.
    let live_position = |on_air: Instant| wrap(source.start_secs + on_air.elapsed().as_secs_f64());
    let past_end = |pos: f64| !source.looping && source.duration.is_some_and(|d| pos >= d - 1.0);
    let mut on_air: Option<Instant> = None;
    loop {
        if let Some(on_air) = on_air
            && past_end(live_position(on_air))
        {
            return close(&source, &tx, clock, &ended);
        }
        if tx.receiver_count() == 0 {
            std::thread::sleep(Duration::from_millis(300));
            continue;
        }
        let on_air = *on_air.get_or_insert_with(Instant::now);
        let position = live_position(on_air);
        let started = Instant::now();
        let mut child = match source.spawn(position) {
            Ok(child) => child,
            Err(e) => {
                tracing::warn!(error = %e, "could not start ffmpeg");
                std::thread::sleep(Duration::from_secs(5));
                continue;
            }
        };
        tracing::info!(position = format!("{position:.0} s"), "video decoding started");
        let Some(mut stdout) = child.stdout.take() else { continue };
        let mut buf = vec![0u8; frame_bytes];
        let mut idle_since: Option<Instant> = None;
        let mut index: u64 = 0;
        let reason = loop {
            if let Err(e) = stdout.read_exact(&mut buf) {
                break format!("ffmpeg stopped: {e}");
            }
            let Some(mut img) = RgbImage::from_raw(source.width, source.height, buf.clone()) else {
                break "unexpected frame size".to_string();
            };
            channel_bug(&mut img, &channel);
            let pos = wrap(position + index as f64 / source.fps());
            index += 1;
            let _ = tx.send(Arc::new(Frame { t: clock.elapsed().as_secs_f64(), img, pos: Some(pos), last: false }));
            if tx.receiver_count() > 0 {
                idle_since = None;
            } else if idle_since.get_or_insert_with(Instant::now).elapsed() > IDLE_STOP {
                break "nobody watching".to_string();
            }
        };
        let _ = child.kill();
        let _ = child.wait();
        if past_end(position + index as f64 / source.fps()) {
            return close(&source, &tx, clock, &ended);
        }
        tracing::info!(reason, "video decoding paused");
        if started.elapsed() < Duration::from_secs(1) {
            std::thread::sleep(Duration::from_secs(5));
        }
    }
}

/// The file is over: publish the closing card (the last frame of every session) and mark the end.
fn close(source: &VideoSource, tx: &broadcast::Sender<Arc<Frame>>, clock: Instant, ended: &AtomicBool) {
    tracing::info!("the video file ended: the broadcast is over");
    ended.store(true, Ordering::Relaxed);
    let card =
        image::imageops::resize(&end_slate(), source.width, source.height, image::imageops::FilterType::Triangle);
    let _ = tx.send(Arc::new(Frame { t: clock.elapsed().as_secs_f64(), img: card, pos: None, last: true }));
}
