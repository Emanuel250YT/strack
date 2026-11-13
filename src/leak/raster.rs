//! Minimal drawing on RGB frames: rectangles, discs, rings, 8x8 bitmap text and QR codes.

use font8x8::{BASIC_FONTS, LATIN_FONTS, UnicodeFonts};
use image::{Rgb, RgbImage};
use qrcode::{Color, EcLevel, QrCode};

pub const WHITE: Rgb<u8> = Rgb([255, 255, 255]);
pub const BLACK: Rgb<u8> = Rgb([0, 0, 0]);

pub fn fill_rect(img: &mut RgbImage, x: i32, y: i32, w: i32, h: i32, color: Rgb<u8>) {
    let (iw, ih) = (img.width() as i32, img.height() as i32);
    let (x0, y0) = (x.clamp(0, iw), y.clamp(0, ih));
    let (x1, y1) = ((x + w).clamp(0, iw), (y + h).clamp(0, ih));
    for yy in y0..y1 {
        for xx in x0..x1 {
            img.put_pixel(xx as u32, yy as u32, color);
        }
    }
}

/// Rectangle outline of the given thickness, drawn inside the box.
pub fn stroke_rect(img: &mut RgbImage, x: i32, y: i32, w: i32, h: i32, t: i32, color: Rgb<u8>) {
    fill_rect(img, x, y, w, t, color);
    fill_rect(img, x, y + h - t, w, t, color);
    fill_rect(img, x, y, t, h, color);
    fill_rect(img, x + w - t, y, t, h, color);
}

pub fn disc(img: &mut RgbImage, cx: i32, cy: i32, r: i32, color: Rgb<u8>) {
    ring(img, cx, cy, -1, r, color);
}

/// Pixels whose distance to the centre is in `(inner, outer]`; `inner < 0` fills the disc.
pub fn ring(img: &mut RgbImage, cx: i32, cy: i32, inner: i32, outer: i32, color: Rgb<u8>) {
    let (iw, ih) = (img.width() as i32, img.height() as i32);
    let (r_in, r_out) = (inner * inner.abs(), outer * outer);
    for y in (cy - outer).max(0)..=(cy + outer).min(ih - 1) {
        for x in (cx - outer).max(0)..=(cx + outer).min(iw - 1) {
            let d = (x - cx) * (x - cx) + (y - cy) * (y - cy);
            if d <= r_out && (inner < 0 || d > r_in) {
                img.put_pixel(x as u32, y as u32, color);
            }
        }
    }
}

fn glyph(c: char) -> [u8; 8] {
    BASIC_FONTS.get(c).or_else(|| LATIN_FONTS.get(c)).unwrap_or([0; 8])
}

pub fn text_width(text: &str, scale: i32) -> i32 {
    text.chars().count() as i32 * 8 * scale
}

/// 8x8 bitmap text; `scale` multiplies every pixel. Bit 0 of each glyph row is its leftmost pixel.
pub fn draw_text(img: &mut RgbImage, x: i32, y: i32, text: &str, scale: i32, color: Rgb<u8>) {
    for (i, c) in text.chars().enumerate() {
        let left = x + i as i32 * 8 * scale;
        for (row, bits) in glyph(c).iter().enumerate() {
            for col in 0..8 {
                if bits & (1 << col) != 0 {
                    fill_rect(img, left + col * scale, y + row as i32 * scale, scale, scale, color);
                }
            }
        }
    }
}

pub fn draw_text_centered(img: &mut RgbImage, cx: i32, y: i32, text: &str, scale: i32, color: Rgb<u8>) {
    draw_text(img, cx - text_width(text, scale) / 2, y, text, scale, color);
}

/// A QR code ready to be drawn, with its quiet zone.
pub struct QrMatrix {
    width: usize,
    dark: Vec<bool>,
}

impl QrMatrix {
    /// Quiet zone around the code, in modules.
    pub const QUIET: usize = 4;

    pub fn new(text: &str) -> Option<Self> {
        let code = QrCode::with_error_correction_level(text.as_bytes(), EcLevel::M).ok()?;
        let width = code.width();
        let dark = code.to_colors().into_iter().map(|c| c == Color::Dark).collect();
        Some(QrMatrix { width, dark })
    }

    /// Side in pixels, quiet zone included.
    pub fn side(&self, module: i32) -> i32 {
        (self.width + 2 * Self::QUIET) as i32 * module
    }

    pub fn draw(&self, img: &mut RgbImage, x: i32, y: i32, module: i32) {
        fill_rect(img, x, y, self.side(module), self.side(module), WHITE);
        let offset = Self::QUIET as i32 * module;
        for (i, dark) in self.dark.iter().enumerate() {
            if *dark {
                let (mx, my) = ((i % self.width) as i32, (i / self.width) as i32);
                fill_rect(img, x + offset + mx * module, y + offset + my * module, module, module, BLACK);
            }
        }
    }
}
