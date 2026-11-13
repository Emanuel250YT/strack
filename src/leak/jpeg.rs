//! JPEG encoding with an embedded comment (the metadata copy of the mark), and decoding.

use image::codecs::jpeg::JpegEncoder;
use image::{GrayImage, ImageFormat, RgbImage};

const SOI: [u8; 2] = [0xFF, 0xD8];
const COM: u8 = 0xFE;
const APP0: u8 = 0xE0;
const SOS: u8 = 0xDA;
const EOI: u8 = 0xD9;

pub fn encode(img: &RgbImage, quality: u8, comment: Option<&str>) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(96 * 1024);
    JpegEncoder::new_with_quality(&mut out, quality).encode_image(img)?;
    if let Some(text) = comment {
        insert_comment(&mut out, text.as_bytes());
    }
    Ok(out)
}

/// Inserts a COM segment after SOI (and after the JFIF APP0 segment, which must come first).
fn insert_comment(jpeg: &mut Vec<u8>, text: &[u8]) {
    if jpeg.len() < 4 || jpeg[..2] != SOI {
        return;
    }
    let mut at = 2;
    if jpeg.len() >= 6 && jpeg[2] == 0xFF && jpeg[3] == APP0 {
        at = 4 + u16::from_be_bytes([jpeg[4], jpeg[5]]) as usize;
        if at > jpeg.len() {
            return;
        }
    }
    let text = &text[..text.len().min(u16::MAX as usize - 2)];
    let len = (text.len() + 2) as u16;
    let mut segment = vec![0xFF, COM];
    segment.extend_from_slice(&len.to_be_bytes());
    segment.extend_from_slice(text);
    jpeg.splice(at..at, segment);
}

/// Text of every COM segment before the image data.
pub fn comments(jpeg: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    if jpeg.len() < 4 || jpeg[..2] != SOI {
        return out;
    }
    let mut i = 2;
    while i + 4 <= jpeg.len() {
        if jpeg[i] != 0xFF {
            break;
        }
        let marker = jpeg[i + 1];
        if marker == 0xFF {
            i += 1;
            continue;
        }
        if marker == SOS || marker == EOI {
            break;
        }
        if (0xD0..=0xD7).contains(&marker) || marker == 0x01 {
            i += 2;
            continue;
        }
        let len = u16::from_be_bytes([jpeg[i + 2], jpeg[i + 3]]) as usize;
        if len < 2 || i + 2 + len > jpeg.len() {
            break;
        }
        if marker == COM {
            out.push(String::from_utf8_lossy(&jpeg[i + 4..i + 2 + len]).into_owned());
        }
        i += 2 + len;
    }
    out
}

pub fn decode_rgb(jpeg: &[u8]) -> anyhow::Result<RgbImage> {
    Ok(image::load_from_memory_with_format(jpeg, ImageFormat::Jpeg)?.to_rgb8())
}

pub fn decode_luma(jpeg: &[u8]) -> anyhow::Result<GrayImage> {
    Ok(image::load_from_memory_with_format(jpeg, ImageFormat::Jpeg)?.to_luma8())
}

#[cfg(test)]
mod tests {
    use image::{Rgb, RgbImage};

    use crate::leak::jpeg::{comments, decode_rgb, encode};

    #[test]
    fn comment_survives_and_image_still_decodes() {
        let img = RgbImage::from_pixel(64, 48, Rgb([10, 120, 40]));
        let bytes = encode(&img, 80, Some("STK2|60de|42|0123456789ab")).unwrap();
        assert_eq!(comments(&bytes), vec!["STK2|60de|42|0123456789ab".to_string()]);
        let back = decode_rgb(&bytes).unwrap();
        assert_eq!(back.dimensions(), (64, 48));
        let plain = encode(&img, 80, None).unwrap();
        assert!(comments(&plain).is_empty());
    }
}
