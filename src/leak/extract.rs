//! Reading session marks back from a stream: the invisible watermark (survives re-encoding and
//! rescaling, needs a couple of seconds of frames), the JPEG comment (lost when a pirate re-encodes)
//! and the optional visible QR code.

use image::GrayImage;
use serde::{Deserialize, Serialize};

use crate::leak::jpeg;
use crate::leak::mark::SessionMark;
use crate::leak::watermark::Detector;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MarkSource {
    Watermark,
    Metadata,
    Qr,
}

#[derive(Debug, Clone)]
pub struct Found {
    pub mark: SessionMark,
    pub sources: Vec<MarkSource>,
}

fn add(found: &mut Vec<Found>, mark: SessionMark, source: MarkSource) {
    match found.iter_mut().find(|f| f.mark == mark) {
        Some(f) if !f.sources.contains(&source) => f.sources.push(source),
        Some(_) => {}
        None => found.push(Found { mark, sources: vec![source] }),
    }
}

pub fn read_qr(img: &GrayImage) -> Vec<SessionMark> {
    let (w, h) = (img.width() as usize, img.height() as usize);
    let raw = img.as_raw();
    let mut prepared = rqrr::PreparedImage::prepare_from_greyscale(w, h, |x, y| raw[y * w + x]);
    prepared
        .detect_grids()
        .into_iter()
        .filter_map(|grid| grid.decode().ok())
        .filter_map(|(_, text)| SessionMark::parse(&text))
        .collect()
}

/// The visible QR is looked for on one frame in this many (it is slower than the watermark).
const QR_EVERY: u64 = 4;

/// Scans the frames of one stream, in order. Keeps the history the watermark detector needs.
#[derive(Default)]
pub struct Scanner {
    detector: Detector,
    frames: u64,
}

impl Scanner {
    /// `platforms`: codes of the registered platforms (see `mark::platform_code`); with them the
    /// watermark detector can also correct a few unreliable bits. Empty accepts any platform.
    pub fn new(platforms: Vec<u16>) -> Self {
        Scanner { detector: Detector::new(platforms), frames: 0 }
    }

    /// Marks found in this frame; `at` is the frame's receive time in seconds (any fixed origin).
    pub fn scan(&mut self, jpeg_bytes: &[u8], at: f64) -> Vec<Found> {
        self.frames += 1;
        let mut found = Vec::new();
        for text in jpeg::comments(jpeg_bytes) {
            if let Some(mark) = SessionMark::parse(&text) {
                add(&mut found, mark, MarkSource::Metadata);
            }
        }
        if let Ok(luma) = jpeg::decode_luma(jpeg_bytes) {
            if let Some(mark) = self.detector.push(at, &luma) {
                add(&mut found, mark, MarkSource::Watermark);
            }
            if self.frames % QR_EVERY == 1 {
                for mark in read_qr(&luma) {
                    add(&mut found, mark, MarkSource::Qr);
                }
            }
        }
        found
    }
}

#[cfg(test)]
mod tests {
    use image::imageops;

    use crate::leak::extract::{MarkSource, Scanner};
    use crate::leak::jpeg::{decode_rgb, encode};
    use crate::leak::mark::SessionMark;
    use crate::leak::raster::QrMatrix;
    use crate::leak::scene::{overlay_mark, render_base};

    fn visible_frame(t: f64) -> (SessionMark, Vec<u8>) {
        let mark = SessionMark::new("tvf", 42, 0x00ab_cdef_0123);
        let qr = QrMatrix::new(&mark.text()).unwrap();
        let mut img = render_base(t, "TV FICTICIA PLAY");
        overlay_mark(&mut img, &mark, &qr, t);
        let bytes = encode(&img, 80, Some(&mark.text())).unwrap();
        (mark, bytes)
    }

    #[test]
    fn licensed_frame_carries_mark_in_metadata_and_visible_qr() {
        let (mark, bytes) = visible_frame(3.0);
        let found = Scanner::default().scan(&bytes, 0.0);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].mark, mark);
        assert!(found[0].sources.contains(&MarkSource::Metadata));
        assert!(found[0].sources.contains(&MarkSource::Qr));
    }

    #[test]
    fn visible_qr_survives_a_pirate_reencode() {
        for t in [1.0, 9.0, 17.0, 25.0] {
            let (mark, bytes) = visible_frame(t);
            let img = decode_rgb(&bytes).unwrap();
            let small = imageops::thumbnail(&img, img.width() * 4 / 5, img.height() * 4 / 5);
            let pirate = encode(&small, 55, None).unwrap();
            let found = Scanner::default().scan(&pirate, 0.0);
            assert_eq!(found.len(), 1, "corner at t={t}");
            assert_eq!(found[0].mark, mark);
            assert_eq!(found[0].sources, vec![MarkSource::Qr]);
        }
    }
}
