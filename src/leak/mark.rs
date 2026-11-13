//! The session mark: which platform, which subscriber and which session a stream comes from.
//!
//! It travels as 120 bits in the invisible watermark (`leak::watermark`) and as text
//! (`STK2|<platform code>|<client>|<session>`) in the JPEG comment and the optional visible QR code.
//!
//! - `platform`: 16-bit code, the first two bytes of SHA-256 of the platform id, so Strack can match it
//!   against its registry without a central numbering.
//! - `client`: the platform's subscriber number, shown as `c-NNNNN`.
//! - `session`: 32 random bits issued by the platform per viewing session. Only that subscriber's stream
//!   carries it, so nobody can forge a mark that frames another subscriber: the platform rejects a
//!   session it did not issue, or one issued to someone else.
//! - A CRC-32 closes the payload. Its Hamming distance on 88 data bits is 6, so flipping a few
//!   unreliable bits while decoding (`watermark::decode_chase`) can never turn a mark into another
//!   valid one; a 16-bit check was too weak for that and could produce hybrids of two marks.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const VERSION: &str = "STK2";
/// First byte of the binary payload; it also fixes the sign when decoding the watermark.
pub const MAGIC: u8 = 0xB5;
/// Payload length in bits: magic (8), platform (16), client (32), session (32), CRC-32 (32).
pub const BITS: usize = 120;
const BODY: usize = 11;
const SESSION_MASK: u64 = 0xFFFF_FFFF;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionMark {
    pub platform: u16,
    pub client: u32,
    pub session: u64,
}

pub fn platform_code(platform_id: &str) -> u16 {
    let digest = Sha256::digest(platform_id.as_bytes());
    u16::from_be_bytes([digest[0], digest[1]])
}

/// Subscriber label used across the demo and the interface (`c-00042`).
pub fn client_label(client: u32) -> String {
    format!("c-{client:05}")
}

/// Parses `c-00042` (or a bare number) into a subscriber number.
pub fn parse_client(label: &str) -> Option<u32> {
    label.trim().strip_prefix("c-").unwrap_or(label.trim()).parse().ok()
}

/// CRC-32 (IEEE 802.3, reflected).
fn crc32(bytes: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

impl SessionMark {
    pub fn new(platform_id: &str, client: u32, session: u64) -> Self {
        SessionMark { platform: platform_code(platform_id), client, session: session & SESSION_MASK }
    }

    pub fn text(&self) -> String {
        format!("{VERSION}|{:04x}|{}|{:08x}", self.platform, self.client, self.session)
    }

    /// Parses the text form; anything that is not exactly a well-formed mark is `None`.
    pub fn parse(text: &str) -> Option<Self> {
        let mut parts = text.trim().split('|');
        if parts.next()? != VERSION {
            return None;
        }
        let (platform, client, session) = (parts.next()?, parts.next()?, parts.next()?);
        if parts.next().is_some() || platform.len() != 4 || session.len() != 8 {
            return None;
        }
        Some(SessionMark {
            platform: u16::from_str_radix(platform, 16).ok()?,
            client: client.parse().ok()?,
            session: u64::from_str_radix(session, 16).ok()?,
        })
    }

    pub fn client_label(&self) -> String {
        client_label(self.client)
    }

    pub fn platform_hex(&self) -> String {
        format!("{:04x}", self.platform)
    }

    pub fn session_hex(&self) -> String {
        format!("{:08x}", self.session)
    }

    /// Key of the leaking session across sightings.
    pub fn session_key(&self) -> String {
        format!("{:04x}|{:08x}", self.platform, self.session)
    }

    fn body(&self) -> [u8; BODY] {
        let mut out = [0u8; BODY];
        out[0] = MAGIC;
        out[1..3].copy_from_slice(&self.platform.to_be_bytes());
        out[3..7].copy_from_slice(&self.client.to_be_bytes());
        out[7..11].copy_from_slice(&(self.session as u32).to_be_bytes());
        out
    }

    /// The 120-bit payload, most significant bit first.
    pub fn to_bits(&self) -> [bool; BITS] {
        let body = self.body();
        let mut bytes = [0u8; BITS / 8];
        bytes[..BODY].copy_from_slice(&body);
        bytes[BODY..].copy_from_slice(&crc32(&body).to_be_bytes());
        let mut bits = [false; BITS];
        for (i, bit) in bits.iter_mut().enumerate() {
            *bit = bytes[i / 8] & (0x80 >> (i % 8)) != 0;
        }
        bits
    }

    /// Rebuilds a mark from decoded bits; `None` unless the magic byte and the CRC match.
    pub fn from_bits(bits: &[bool]) -> Option<Self> {
        if bits.len() != BITS {
            return None;
        }
        let mut bytes = [0u8; BITS / 8];
        for (i, bit) in bits.iter().enumerate() {
            if *bit {
                bytes[i / 8] |= 0x80 >> (i % 8);
            }
        }
        let crc = u32::from_be_bytes([bytes[BODY], bytes[BODY + 1], bytes[BODY + 2], bytes[BODY + 3]]);
        if bytes[0] != MAGIC || crc32(&bytes[..BODY]) != crc {
            return None;
        }
        Some(SessionMark {
            platform: u16::from_be_bytes([bytes[1], bytes[2]]),
            client: u32::from_be_bytes([bytes[3], bytes[4], bytes[5], bytes[6]]),
            session: u64::from(u32::from_be_bytes([bytes[7], bytes[8], bytes[9], bytes[10]])),
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::leak::mark::{SessionMark, client_label, parse_client, platform_code};

    #[test]
    fn text_and_bits_roundtrip() {
        let mark = SessionMark::new("tvf", 42, 0x44a1_b07d);
        assert_eq!(mark.platform, platform_code("tvf"));
        let text = mark.text();
        assert_eq!(text, format!("STK2|{:04x}|42|44a1b07d", platform_code("tvf")));
        assert_eq!(SessionMark::parse(&text), Some(mark));
        assert_eq!(SessionMark::from_bits(&mark.to_bits()), Some(mark));
    }

    /// The CRC-32 must reject every pattern of up to three flipped bits: Chase decoding relies on it.
    #[test]
    fn up_to_three_flipped_bits_are_always_rejected() {
        let mark = SessionMark::new("tvf", 42, 0x44a1_b07d);
        let bits = mark.to_bits();
        let n = bits.len();
        for a in 0..n {
            for b in a..n {
                for c in b..n {
                    let mut flipped = bits;
                    flipped[a] = !flipped[a];
                    if b != a {
                        flipped[b] = !flipped[b];
                    }
                    if c != b {
                        flipped[c] = !flipped[c];
                    }
                    if flipped != bits {
                        assert_eq!(SessionMark::from_bits(&flipped), None, "bits {a} {b} {c}");
                    }
                }
            }
        }
    }

    #[test]
    fn rejects_malformed_text() {
        for bad in ["", "hello", "STK2|abcd|42", "STK1|abcd|42|0123abcd", "STK2|abcd|x|0123abcd", "STK2|abcd|42|0123"] {
            assert!(SessionMark::parse(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn client_labels() {
        assert_eq!(client_label(42), "c-00042");
        assert_eq!(parse_client("c-00042"), Some(42));
        assert_eq!(parse_client("17"), Some(17));
        assert_eq!(parse_client("c-x"), None);
    }
}
