//! `strack mark`: hides one viewing session's mark in a video, the way a licensed platform marks each
//! subscriber's stream. ffmpeg decodes the input to raw frames, the invisible watermark is added to
//! every frame (`leak::watermark::Pattern`), and ffmpeg encodes the result (H.264 with the same
//! settings as the demo platform's live player, sound re-encoded as AAC).
//!
//! `strack trace <file>` reads the mark back from a video file (ffmpeg decodes it to JPEG frames for
//! the same scanner that reads pirate streams), so a platform can check its pipeline end to end.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, anyhow, bail};
use image::RgbImage;

use crate::demo::video::VideoSource;
use crate::leak::mark::{SessionMark, platform_code};
use crate::leak::watermark::Pattern;

/// What `strack mark` did.
#[derive(Debug)]
pub struct Marked {
    pub mark: SessionMark,
    pub frames: u64,
    pub width: u32,
    pub height: u32,
}

/// A session id: 8 hex digits, or a random one.
pub fn session_id(given: Option<&str>) -> anyhow::Result<u64> {
    match given.map(str::trim).filter(|s| !s.is_empty()) {
        Some(hex) => {
            let value = u64::from_str_radix(hex.trim_start_matches("0x"), 16)
                .map_err(|_| anyhow!("the session must be hexadecimal (8 digits), got {hex}"))?;
            if value > 0xFFFF_FFFF {
                bail!("the session has 32 bits: at most 8 hexadecimal digits");
            }
            Ok(value)
        }
        None => Ok(u64::from(rand::random::<u32>())),
    }
}

/// Marks `input` for one session and writes `output`. Blocking; runs two ffmpeg processes.
pub fn mark_file(
    ffmpeg: &str,
    input: &Path,
    output: &Path,
    mark: SessionMark,
    strength: f32,
) -> anyhow::Result<Marked> {
    let source = VideoSource::new(input.to_path_buf(), ffmpeg.to_string(), 0.0, false)?;
    let (width, height) = (source.width, source.height);
    let (num, den) = source.rate;
    let fps = f64::from(num) / f64::from(den);
    let mut decoder = Command::new(ffmpeg)
        .args(["-hide_banner", "-loglevel", "error", "-nostdin", "-i"])
        .arg(input)
        .args(["-an", "-f", "rawvideo", "-pix_fmt", "rgb24", "pipe:1"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .context("starting the ffmpeg decoder")?;
    let mut encoder = Command::new(ffmpeg)
        .args(["-hide_banner", "-loglevel", "error", "-y", "-f", "rawvideo", "-pix_fmt", "rgb24"])
        .args(["-s", &format!("{width}x{height}"), "-r", &format!("{num}/{den}"), "-i", "pipe:0", "-i"])
        .arg(input)
        .args(["-map", "0:v:0", "-map", "1:a?", "-c:a", "aac", "-b:a", "160k"])
        .args(["-c:v", "libx264", "-preset", "veryfast", "-crf", "18", "-pix_fmt", "yuv420p", "-shortest"])
        // Index first, so the file plays (and can be traced) while it downloads.
        .args(["-movflags", "+faststart"])
        .arg(output)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .context("starting the ffmpeg encoder")?;
    let pattern = Pattern::new(&mark, width, height);
    let frame_bytes = (width * height * 3) as usize;
    let mut buffer = vec![0u8; frame_bytes];
    let mut frames = 0u64;
    {
        let reader = decoder.stdout.as_mut().ok_or_else(|| anyhow!("no decoder output"))?;
        let writer = encoder.stdin.as_mut().ok_or_else(|| anyhow!("no encoder input"))?;
        loop {
            match reader.read_exact(&mut buffer) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e).context("reading decoded frames"),
            }
            let mut img = RgbImage::from_raw(width, height, std::mem::take(&mut buffer))
                .ok_or_else(|| anyhow!("frame size mismatch"))?;
            pattern.apply(&mut img, frames as f64 / fps, strength);
            buffer = img.into_raw();
            writer.write_all(&buffer).context("sending frames to the encoder")?;
            frames += 1;
        }
    }
    drop(encoder.stdin.take());
    let decoded = decoder.wait().context("waiting for the decoder")?;
    let encoded = encoder.wait().context("waiting for the encoder")?;
    if !decoded.success() || !encoded.success() || frames == 0 {
        bail!("ffmpeg failed (decoder {decoded}, encoder {encoded}, {frames} frames)");
    }
    Ok(Marked { mark, frames, width, height })
}

/// The mark for a registered platform id, subscriber and session.
pub fn session_mark(platform_id: &str, client: u32, session: u64) -> SessionMark {
    SessionMark { platform: platform_code(platform_id), client, session }
}

/// Decodes a video file to JPEG frames at `fps` (each with its time in the file), for the scanner.
pub fn file_frames(ffmpeg: &str, input: &Path, fps: u32, max_secs: u64) -> anyhow::Result<Vec<(f64, Vec<u8>)>> {
    let out = Command::new(ffmpeg)
        .args(["-hide_banner", "-loglevel", "error", "-nostdin", "-t", &max_secs.to_string(), "-i"])
        .arg(input)
        .args(["-an", "-vf", &format!("fps={fps}"), "-f", "image2pipe", "-c:v", "mjpeg", "-q:v", "2", "pipe:1"])
        .stdin(Stdio::null())
        .stderr(Stdio::inherit())
        .output()
        .with_context(|| format!("running {ffmpeg}: install ffmpeg or pass --ffmpeg <path>"))?;
    if !out.status.success() {
        bail!("ffmpeg could not decode {}", input.display());
    }
    Ok(split_jpegs(&out.stdout).into_iter().enumerate().map(|(i, f)| (i as f64 / f64::from(fps), f)).collect())
}

/// Splits concatenated JPEG images (as ffmpeg's image2pipe writes them) at their start and end
/// markers. Entropy-coded data never holds `FF D9` (0xFF is stuffed as `FF 00`).
fn split_jpegs(bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut start = None;
    let mut i = 0;
    while i + 1 < bytes.len() {
        match (bytes[i], bytes[i + 1]) {
            (0xFF, 0xD8) if start.is_none() => {
                start = Some(i);
                i += 2;
            }
            (0xFF, 0xD9) if start.is_some() => {
                out.push(bytes[start.take().unwrap_or(0)..i + 2].to_vec());
                i += 2;
            }
            _ => i += 1,
        }
    }
    out
}

/// Arguments of `strack mark`.
#[derive(clap::Args)]
pub struct MarkArgs {
    /// Registered platform id (its code goes in the mark).
    #[arg(long)]
    pub platform: String,
    /// Subscriber number (`42` or `c-00042`).
    #[arg(long)]
    pub client: String,
    /// Session id, 8 hexadecimal digits; a random one when missing (keep it: notices name it).
    #[arg(long)]
    pub session: Option<String>,
    #[arg(long)]
    pub input: PathBuf,
    #[arg(long)]
    pub output: PathBuf,
    /// Peak brightness shift in levels (invisible at 2).
    #[arg(long, default_value_t = crate::leak::watermark::DEFAULT_STRENGTH)]
    pub strength: f32,
    #[arg(long, default_value = "ffmpeg")]
    pub ffmpeg: String,
}

#[cfg(test)]
mod tests {
    use crate::leak::marker::{session_id, session_mark, split_jpegs};

    #[test]
    fn sessions_and_marks() {
        assert_eq!(session_id(Some("1a2b3c4d")).unwrap(), 0x1a2b_3c4d);
        assert!(session_id(Some("1a2b3c4d5")).is_err());
        assert!(session_id(Some("xyz")).is_err());
        assert!(session_id(None).unwrap() <= 0xFFFF_FFFF);
        let mark = session_mark("tvf", 42, 0x1a2b_3c4d);
        assert!(mark.text().ends_with("|42|1a2b3c4d"), "{}", mark.text());
    }

    #[test]
    fn jpeg_stream_splits_at_markers() {
        let one = [0xFF, 0xD8, 1, 2, 0xFF, 0x00, 3, 0xFF, 0xD9];
        let two = [0xFF, 0xD8, 9, 0xFF, 0xD9];
        let joined: Vec<u8> = one.iter().chain(two.iter()).copied().collect();
        assert_eq!(split_jpegs(&joined), vec![one.to_vec(), two.to_vec()]);
    }
}
