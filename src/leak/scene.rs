//! A synthetic match broadcast (pitch, players, ball, scoreboard) and the session-mark overlay.
//!
//! The demo streams this instead of real footage: no copyrighted video is needed to show the circuit.

use std::sync::OnceLock;

use image::{Rgb, RgbImage};

use crate::leak::mark::SessionMark;
use crate::leak::raster::{
    BLACK, QrMatrix, WHITE, disc, draw_text, draw_text_centered, fill_rect, ring, stroke_rect, text_width,
};

pub const WIDTH: u32 = 960;
pub const HEIGHT: u32 = 540;
/// Seconds the mark stays in one corner before moving to the next one.
pub const MARK_PERIOD_SECS: f64 = 8.0;
/// Pixels per QR module on a full-size frame.
pub const MARK_MODULE: i32 = 4;
const MARK_MARGIN: i32 = 14;

const GRASS_A: Rgb<u8> = Rgb([34, 116, 52]);
const GRASS_B: Rgb<u8> = Rgb([40, 130, 60]);
const SURROUND: Rgb<u8> = Rgb([24, 86, 40]);
const HOME: Rgb<u8> = Rgb([196, 36, 48]);
const AWAY: Rgb<u8> = Rgb([28, 74, 196]);
const BOARD: Rgb<u8> = Rgb([14, 22, 38]);
const ACCENT: Rgb<u8> = Rgb([255, 204, 0]);
const LIVE: Rgb<u8> = Rgb([210, 20, 30]);

// Pitch rectangle inside the frame.
const PX: i32 = 60;
const PY: i32 = 76;
const PW: i32 = 840;
const PH: i32 = 420;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Corner {
    TopLeft,
    TopRight,
    BottomRight,
    BottomLeft,
}

impl Corner {
    pub const ALL: [Corner; 4] = [Corner::TopLeft, Corner::TopRight, Corner::BottomRight, Corner::BottomLeft];

    /// Corner the mark occupies at `t` seconds of broadcast.
    pub fn at(t: f64) -> Corner {
        Corner::ALL[((t.max(0.0) / MARK_PERIOD_SECS) as usize) % 4]
    }

    /// Top-left position of a `w`x`h` box in this corner of a `fw`x`fh` frame.
    pub fn place(self, fw: i32, fh: i32, w: i32, h: i32, margin: i32) -> (i32, i32) {
        match self {
            Corner::TopLeft => (margin, margin),
            Corner::TopRight => (fw - w - margin, margin),
            Corner::BottomRight => (fw - w - margin, fh - h - margin),
            Corner::BottomLeft => (margin, fh - h - margin),
        }
    }
}

fn to_px(nx: f64, ny: f64) -> (i32, i32) {
    (PX + (nx.clamp(0.02, 0.98) * PW as f64) as i32, PY + (ny.clamp(0.04, 0.96) * PH as f64) as i32)
}

fn ball_at(t: f64) -> (f64, f64) {
    (0.5 + 0.40 * (t * 0.53).sin(), 0.5 + 0.36 * (t * 0.81 + 0.6).sin())
}

fn pitch(img: &mut RgbImage) {
    fill_rect(img, 0, 0, WIDTH as i32, HEIGHT as i32, SURROUND);
    let stripes = 12;
    for i in 0..stripes {
        let x = PX + i * PW / stripes;
        let color = if i % 2 == 0 { GRASS_A } else { GRASS_B };
        fill_rect(img, x, PY, PW / stripes + 1, PH, color);
    }
    let t = 3;
    stroke_rect(img, PX, PY, PW, PH, t, WHITE);
    fill_rect(img, PX + PW / 2 - 1, PY, t, PH, WHITE);
    let (cx, cy) = (PX + PW / 2, PY + PH / 2);
    ring(img, cx, cy, 58, 61, WHITE);
    disc(img, cx, cy, 4, WHITE);
    // Penalty and goal areas, both ends.
    let (box_w, box_h, area_w, area_h) = (130, 230, 46, 110);
    for left in [true, false] {
        let bx = if left { PX } else { PX + PW - box_w };
        stroke_rect(img, bx, cy - box_h / 2, box_w, box_h, t, WHITE);
        let ax = if left { PX } else { PX + PW - area_w };
        stroke_rect(img, ax, cy - area_h / 2, area_w, area_h, t, WHITE);
        let spot = if left { PX + 96 } else { PX + PW - 96 };
        disc(img, spot, cy, 3, WHITE);
        let gx = if left { PX - 14 } else { PX + PW - 1 };
        stroke_rect(img, gx, cy - 34, 15, 68, 2, WHITE);
    }
}

fn players(img: &mut RgbImage, t: f64) {
    // Formation anchors (fraction of the pitch) for the home side; the away side mirrors them.
    const ANCHORS: [(f64, f64); 11] = [
        (0.05, 0.50),
        (0.20, 0.18),
        (0.18, 0.40),
        (0.18, 0.60),
        (0.20, 0.82),
        (0.36, 0.25),
        (0.34, 0.50),
        (0.36, 0.75),
        (0.46, 0.15),
        (0.48, 0.50),
        (0.46, 0.85),
    ];
    let (bx, by) = ball_at(t);
    for (team, color) in [(0, HOME), (1, AWAY)] {
        for (i, (ax, ay)) in ANCHORS.iter().enumerate() {
            let phase = i as f64 * 1.3 + team as f64 * 0.7;
            let (mut x, mut y) = if team == 0 { (*ax, *ay) } else { (1.0 - ax, 1.0 - ay) };
            // Drift around the anchor and lean toward the ball (keepers barely move).
            let pull = if i == 0 { 0.04 } else { 0.22 };
            x += 0.05 * (t * 0.7 + phase).sin() + (bx - x) * pull;
            y += 0.06 * (t * 0.9 + phase).cos() + (by - y) * pull;
            let (px, py) = to_px(x, y);
            disc(img, px, py, 10, WHITE);
            disc(img, px, py, 8, color);
        }
    }
    let (px, py) = to_px(bx, by);
    disc(img, px, py, 7, BLACK);
    disc(img, px, py, 5, WHITE);
}

fn scoreboard(img: &mut RgbImage, t: f64) {
    let secs = t.max(0.0) as u64;
    let clock = format!("{:02}:{:02}", secs / 60, secs % 60);
    let score = "NOR 1 - 0 EJE";
    let (w, h) = (text_width(score, 2) + text_width(&clock, 2) + 56, 36);
    let x = (WIDTH as i32 - w) / 2;
    fill_rect(img, x, 18, w, h, BOARD);
    draw_text(img, x + 16, 28, score, 2, WHITE);
    let cx = x + 16 + text_width(score, 2) + 24;
    draw_text(img, cx, 28, &clock, 2, ACCENT);
}

/// The broadcaster's on-screen bug, bottom centre (also drawn over real footage).
pub fn channel_bug(img: &mut RgbImage, channel: &str) {
    let label = format!("{channel} · EN VIVO");
    let w = text_width(&label, 2) + 32;
    let x = (img.width() as i32 - w) / 2;
    let y = img.height() as i32 - 34;
    fill_rect(img, x, y, w, 26, BOARD);
    fill_rect(img, x, y, 8, 26, LIVE);
    draw_text(img, x + 20, y + 5, &label, 2, WHITE);
}

fn hash2(x: u32, y: u32, salt: u32) -> u32 {
    let mut h = x.wrapping_mul(0x8DA6_B343) ^ y.wrapping_mul(0xD816_3841) ^ salt.wrapping_mul(0xCB1A_B31F);
    h ^= h >> 13;
    h = h.wrapping_mul(0x5BD1_E995);
    h ^ (h >> 15)
}

/// Smooth value noise in [-1, 1] on a lattice of `cell` pixels.
fn value_noise(x: u32, y: u32, cell: u32, salt: u32) -> f32 {
    let (gx, gy) = (x / cell, y / cell);
    let smooth = |v: f32| v * v * (3.0 - 2.0 * v);
    let (tx, ty) = (smooth((x % cell) as f32 / cell as f32), smooth((y % cell) as f32 / cell as f32));
    let corner = |cx: u32, cy: u32| (hash2(cx, cy, salt) & 0xFFFF) as f32 / 32767.5 - 1.0;
    let top = corner(gx, gy) * (1.0 - tx) + corner(gx + 1, gy) * tx;
    let bottom = corner(gx, gy + 1) * (1.0 - tx) + corner(gx + 1, gy + 1) * tx;
    top * (1.0 - ty) + bottom * ty
}

/// Grass and camera texture: fine grain plus soft patches, like real pitch footage. It is static, so
/// it costs nothing per frame and cancels out in the watermark detector.
fn texture(img: &mut RgbImage) {
    for (x, y, px) in img.enumerate_pixels_mut() {
        let grain = (hash2(x, y, 7) % 7) as f32 - 3.0;
        let patches = 4.0 * value_noise(x, y, 28, 11) + 2.0 * value_noise(x, y, 9, 23);
        let d = (grain + patches).round() as i16;
        for c in px.0.iter_mut() {
            *c = (i16::from(*c) + d).clamp(0, 255) as u8;
        }
    }
}

/// Pitch and texture, drawn once.
fn background() -> &'static RgbImage {
    static BACKGROUND: OnceLock<RgbImage> = OnceLock::new();
    BACKGROUND.get_or_init(|| {
        let mut img = RgbImage::new(WIDTH, HEIGHT);
        pitch(&mut img);
        texture(&mut img);
        img
    })
}

/// The shared part of a frame: everything except the per-session mark.
pub fn render_base(t: f64, channel: &str) -> RgbImage {
    let mut img = background().clone();
    players(&mut img, t);
    scoreboard(&mut img, t);
    channel_bug(&mut img, channel);
    img
}

/// Draws the optional visible mark (QR plus a readable client label) in the corner for time `t`.
/// The default is the invisible watermark (`leak::watermark`); this mode exists to show what it carries.
pub fn overlay_mark(img: &mut RgbImage, mark: &SessionMark, qr: &QrMatrix, t: f64) {
    let side = qr.side(MARK_MODULE);
    let label = mark.client_label().to_uppercase();
    let label_h = 22;
    let total_h = side + label_h;
    let corner = Corner::at(t);
    let (x, y) = corner.place(img.width() as i32, img.height() as i32, side, total_h, MARK_MARGIN);
    let (qr_y, label_y) = match corner {
        Corner::TopLeft | Corner::TopRight => (y, y + side),
        Corner::BottomLeft | Corner::BottomRight => (y + label_h, y),
    };
    qr.draw(img, x, qr_y, MARK_MODULE);
    fill_rect(img, x, label_y, side, label_h, BOARD);
    draw_text_centered(img, x + side / 2, label_y + 3, &label, 2, WHITE);
}

/// Full-screen card with a title and a line of detail (suspended account, no signal).
pub fn slate(title: &str, detail: &str, background: Rgb<u8>) -> RgbImage {
    let mut img = RgbImage::from_pixel(WIDTH, HEIGHT, background);
    let cx = WIDTH as i32 / 2;
    draw_text_centered(&mut img, cx, HEIGHT as i32 / 2 - 40, title, 4, WHITE);
    draw_text_centered(&mut img, cx, HEIGHT as i32 / 2 + 16, detail, 2, Rgb([220, 226, 234]));
    img
}

#[cfg(test)]
mod tests {
    use crate::leak::scene::{Corner, MARK_PERIOD_SECS};

    #[test]
    fn mark_visits_every_corner() {
        let seen: Vec<Corner> = (0..4).map(|i| Corner::at(i as f64 * MARK_PERIOD_SECS + 0.5)).collect();
        assert_eq!(seen, Corner::ALL.to_vec());
        assert_eq!(Corner::at(4.0 * MARK_PERIOD_SECS), Corner::TopLeft);
    }
}
