//! Invisible session watermark, readable only by software.
//!
//! The frame is split into a grid of 16-pixel blocks ("chips"). A public pseudo-random layout assigns
//! every chip to one of the 120 payload bits and gives it a sign. The platform shifts the brightness
//! around each chip centre by at most `strength` levels (2 of 255 by default) in the direction of its
//! bit, as a smooth surface between chip centres (no block edges for the eye to catch), and the shift
//! fades in and out with a 2-second period, so nothing visible appears or flickers.
//!
//! Detection compares two frames half a period apart: everything that does not move cancels out and
//! the chip pattern remains. Each bit is the signed sum of about 16 chips spread over the whole frame,
//! so rescaling, re-encoding, a logo over a corner or a moving player only weaken it a little. The
//! magic byte fixes the sign and the CRC-16 rejects anything that is not a mark. On moving footage a
//! lock-in accumulator correlates many frame pairs (half a second apart) with the known 2-second
//! rhythm, so the mark adds up while crowds, pans and close-ups average out, and Chase decoding
//! fixes the last few unreliable bits; only marks of registered platforms are accepted then.
//!
//! If the whole frame does not read, the detector searches for the crop (up to 10 % per side, in 1 %
//! steps) and mirror the pirate applied, scoring each candidate view by how coherent its bits are
//! (a summed-area table of the frame difference makes each candidate cheap), and keeps the view that
//! reads the mark.
//!
//! Limits (documented in the README): no rotation, perspective or camcording, no anti-collusion code,
//! a public layout; production systems add those and survive real temporal codecs.

use std::collections::VecDeque;
use std::sync::OnceLock;

use image::{GrayImage, RgbImage};

use crate::leak::mark::{BITS, SessionMark};

/// Reference frame size the chip grid is defined on; other sizes map proportionally.
pub const CANVAS_W: u32 = 960;
pub const CANVAS_H: u32 = 540;
pub const CHIP: u32 = 16;
pub const COLS: usize = 60;
pub const ROWS: usize = 33;
const CHIPS: usize = COLS * ROWS;
pub const PERIOD_SECS: f64 = 2.0;
pub const DEFAULT_STRENGTH: f32 = 2.0;
/// Public layout seed shared by platforms and detectors.
const LAYOUT_SEED: u64 = 0x534C_4232_2026_0001;
/// Chip changes larger than this between the two frames are content motion, not the watermark.
const OUTLIER: f32 = 10.0;
const CLIP: f32 = 5.0;
/// Inner margin of a chip ignored when measuring it (scaling blurs chip borders).
const MEASURE_MARGIN: f64 = 0.2;
const HISTORY_SECS: f64 = 2.5;
const PAIR_TOLERANCE: f64 = 0.4;
/// Memory of the lock-in accumulator: older frame pairs fade with this time constant.
const LOCKIN_TAU_SECS: f64 = 10.0;
/// Frame pairs for the lock-in are this far apart: close enough that moving pictures change
/// little, far enough that the mark changes clearly (measured on real match footage).
const LOCKIN_LAG_SECS: f64 = 0.5;
const LOCKIN_TOLERANCE_SECS: f64 = 0.1;
/// Chase decoding of accumulated bits: flip up to this many of the least reliable bits.
const CHASE_WEAKEST: usize = 14;

struct Layout {
    bit: Vec<u8>,
    sign: Vec<f32>,
}

fn splitmix(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

fn layout() -> &'static Layout {
    static LAYOUT: OnceLock<Layout> = OnceLock::new();
    LAYOUT.get_or_init(|| {
        let mut state = LAYOUT_SEED;
        let mut order: Vec<usize> = (0..CHIPS).collect();
        for i in (1..CHIPS).rev() {
            let j = (splitmix(&mut state) % (i as u64 + 1)) as usize;
            order.swap(i, j);
        }
        let mut bit = vec![0u8; CHIPS];
        let mut sign = vec![0f32; CHIPS];
        for (k, chip) in order.into_iter().enumerate() {
            bit[chip] = (k % BITS) as u8;
            sign[chip] = if splitmix(&mut state) & 1 == 0 { 1.0 } else { -1.0 };
        }
        Layout { bit, sign }
    })
}

/// Smooth temporal envelope in [-1, 1].
fn envelope(t: f64) -> f32 {
    (std::f64::consts::TAU * t / PERIOD_SECS).sin() as f32
}

/// Ordered dither so fractional shifts keep their average: `floor(delta + u)` with `u` in [0, 1).
const BAYER: [[f32; 4]; 4] = [
    [0.5 / 16.0, 8.5 / 16.0, 2.5 / 16.0, 10.5 / 16.0],
    [12.5 / 16.0, 4.5 / 16.0, 14.5 / 16.0, 6.5 / 16.0],
    [3.5 / 16.0, 11.5 / 16.0, 1.5 / 16.0, 9.5 / 16.0],
    [15.5 / 16.0, 7.5 / 16.0, 13.5 / 16.0, 5.5 / 16.0],
];

/// For every pixel along one axis: the two nearest chip centres and the smoothstep weight between
/// them, so the pattern is a smooth surface with no block edges for the eye to catch.
fn axis(len: u32, canvas: u32, cells: usize) -> Vec<(usize, usize, f32)> {
    (0..len)
        .map(|p| {
            let c = (f64::from(p) + 0.5) * f64::from(canvas) / f64::from(len);
            let f = c / f64::from(CHIP) - 0.5;
            if f <= 0.0 {
                return (0, 0, 0.0);
            }
            let i0 = (f.floor() as usize).min(cells - 1);
            let i1 = (i0 + 1).min(cells - 1);
            let t = (f - f.floor()) as f32;
            (i0, i1, t * t * (3.0 - 2.0 * t))
        })
        .collect()
}

/// One session's pattern at unit gain for every pixel of a `w`x`h` frame. It is computed once per
/// session; each frame then only scales it by the envelope, which keeps 25 fps cheap.
pub struct Pattern {
    w: u32,
    h: u32,
    field: Vec<f32>,
}

impl Pattern {
    pub fn new(mark: &SessionMark, w: u32, h: u32) -> Self {
        let layout = layout();
        let bits = mark.to_bits();
        let chips: Vec<f32> =
            (0..CHIPS).map(|i| layout.sign[i] * if bits[usize::from(layout.bit[i])] { 1.0 } else { -1.0 }).collect();
        let (ax, ay) = (axis(w, CANVAS_W, COLS), axis(h, CANVAS_H, ROWS));
        let mut field = Vec::with_capacity((w * h) as usize);
        for &(j0, j1, ty) in &ay {
            let (r0, r1) = (&chips[j0 * COLS..(j0 + 1) * COLS], &chips[j1 * COLS..(j1 + 1) * COLS]);
            for &(i0, i1, tx) in &ax {
                let top = r0[i0] + (r0[i1] - r0[i0]) * tx;
                let bottom = r1[i0] + (r1[i1] - r1[i0]) * tx;
                field.push(top + (bottom - top) * ty);
            }
        }
        Pattern { w, h, field }
    }

    pub fn size(&self) -> (u32, u32) {
        (self.w, self.h)
    }

    /// Adds the pattern for broadcast time `t` (seconds); `strength` is the peak shift in levels.
    pub fn apply(&self, img: &mut RgbImage, t: f64, strength: f32) {
        if img.dimensions() != (self.w, self.h) {
            return;
        }
        let gain = envelope(t) * strength;
        let w = self.w as usize;
        for (i, (px, f)) in img.as_mut().chunks_exact_mut(3).zip(&self.field).enumerate() {
            let d = (f * gain + BAYER[(i / w) % 4][(i % w) % 4]).floor() as i16;
            if d != 0 {
                for c in px.iter_mut() {
                    *c = (i16::from(*c) + d).clamp(0, 255) as u8;
                }
            }
        }
    }
}

/// Adds the session pattern for broadcast time `t` (seconds). `strength` is the peak shift in levels.
pub fn embed(img: &mut RgbImage, mark: &SessionMark, t: f64, strength: f32) {
    let (w, h) = img.dimensions();
    Pattern::new(mark, w, h).apply(img, t, strength);
}

/// Which part of the original picture a pirate shows: the fraction cropped from each side and whether
/// it is mirrored. Any rescaling is implied by the frame size and needs no parameter.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct View {
    pub left: f64,
    pub right: f64,
    pub top: f64,
    pub bottom: f64,
    pub mirror: bool,
}

impl View {
    pub const FULL: View = View { left: 0.0, right: 0.0, top: 0.0, bottom: 0.0, mirror: false };
}

/// Crop fractions tried per side in the coarse search; the best candidates are refined in 1 % steps.
const CROP_STEPS: [f64; 6] = [0.0, 0.02, 0.04, 0.06, 0.08, 0.10];
const COARSE_KEEP: usize = 6;
const DECODE_CANDIDATES: usize = 3;
/// A searched view replaces the current one only when its energy is clearly higher.
const ADOPT_FACTOR: f32 = 1.5;
const SEARCH_EVERY_SECS: f64 = 1.0;
/// After a successful read the view is trusted for this long before searching again.
const LOCK_SECS: f64 = 5.0;

/// Pixel ranges (inner part) of chip columns or rows on a received frame; `None` when the chip falls
/// outside what the pirate shows.
fn ranges(n: usize, canvas: u32, len: u32, lo: f64, hi: f64, mirror: bool) -> Vec<Option<(usize, usize)>> {
    let visible = 1.0 - lo - hi;
    let m = f64::from(CHIP) * MEASURE_MARGIN;
    let len_f = f64::from(len);
    (0..n)
        .map(|i| {
            let u0 = (f64::from(i as u32 * CHIP) + m) / f64::from(canvas);
            let u1 = (f64::from((i as u32 + 1) * CHIP) - m) / f64::from(canvas);
            let (mut a, mut b) = ((u0 - lo) / visible * len_f, (u1 - lo) / visible * len_f);
            if mirror {
                (a, b) = (len_f - b, len_f - a);
            }
            if a < 0.0 || b > len_f {
                return None;
            }
            let a = a.round() as usize;
            let b = (b.round() as usize).max(a + 1).min(len as usize);
            (a < b).then_some((a, b))
        })
        .collect()
}

struct Grid {
    cols: Vec<Option<(usize, usize)>>,
    rows: Vec<Option<(usize, usize)>>,
}

impl Grid {
    fn new(view: &View, w: u32, h: u32) -> Self {
        Grid {
            cols: ranges(COLS, CANVAS_W, w, view.left, view.right, view.mirror),
            rows: ranges(ROWS, CANVAS_H, h, view.top, view.bottom, false),
        }
    }
}

/// Summed-area table of the brightness difference between two frames: the mean change of any
/// rectangle in four lookups, so many candidate views cost little.
struct Diff {
    w: usize,
    h: usize,
    sums: Vec<i64>,
}

impl Diff {
    fn new(now: &GrayImage, before: &GrayImage) -> Option<Self> {
        if now.dimensions() != before.dimensions() {
            return None;
        }
        let (w, h) = (now.width() as usize, now.height() as usize);
        let (a, b) = (now.as_raw(), before.as_raw());
        let stride = w + 1;
        let mut sums = vec![0i64; stride * (h + 1)];
        for y in 0..h {
            let mut row = 0i64;
            for x in 0..w {
                row += i64::from(a[y * w + x]) - i64::from(b[y * w + x]);
                sums[(y + 1) * stride + x + 1] = sums[y * stride + x + 1] + row;
            }
        }
        Some(Diff { w, h, sums })
    }

    fn mean(&self, (x0, x1): (usize, usize), (y0, y1): (usize, usize)) -> f32 {
        let stride = self.w + 1;
        let s = self.sums[y1 * stride + x1] - self.sums[y0 * stride + x1] - self.sums[y1 * stride + x0]
            + self.sums[y0 * stride + x0];
        s as f32 / ((x1 - x0) * (y1 - y0)) as f32
    }

    fn soft_bits(&self, view: &View) -> Vec<f32> {
        let layout = layout();
        let grid = Grid::new(view, self.w as u32, self.h as u32);
        let mut soft = vec![0f32; BITS];
        for (cy, row) in grid.rows.iter().enumerate() {
            let Some(row) = row else { continue };
            for (cx, col) in grid.cols.iter().enumerate() {
                let Some(col) = col else { continue };
                let d = self.mean(*col, *row);
                if d.abs() > OUTLIER {
                    continue;
                }
                let i = cy * COLS + cx;
                soft[usize::from(layout.bit[i])] += layout.sign[i] * d.clamp(-CLIP, CLIP);
            }
        }
        soft
    }
}

/// How strongly the bits agree with themselves under a view: high only when the grid lines up.
fn energy(soft: &[f32]) -> f32 {
    soft.iter().map(|s| s.abs()).sum()
}

/// Candidate views, best first: a coarse grid of crops (with and without mirror), then 1 % refinement
/// around the best ones.
fn search(diff: &Diff) -> Vec<(f32, View)> {
    let score = |view: View| (energy(&diff.soft_bits(&view)), view);
    let mut coarse = Vec::with_capacity(2 * CROP_STEPS.len().pow(4));
    for mirror in [false, true] {
        for left in CROP_STEPS {
            for right in CROP_STEPS {
                for top in CROP_STEPS {
                    for bottom in CROP_STEPS {
                        coarse.push(score(View { left, right, top, bottom, mirror }));
                    }
                }
            }
        }
    }
    coarse.sort_by(|a, b| b.0.total_cmp(&a.0));
    let step = |v: f64, d: f64| (v + d).max(0.0);
    let mut refined = Vec::new();
    for (_, base) in coarse.iter().take(COARSE_KEEP) {
        for dl in [-0.01, 0.0, 0.01] {
            for dr in [-0.01, 0.0, 0.01] {
                for dt in [-0.01, 0.0, 0.01] {
                    for db in [-0.01, 0.0, 0.01] {
                        refined.push(score(View {
                            left: step(base.left, dl),
                            right: step(base.right, dr),
                            top: step(base.top, dt),
                            bottom: step(base.bottom, db),
                            mirror: base.mirror,
                        }));
                    }
                }
            }
        }
    }
    refined.sort_by(|a, b| b.0.total_cmp(&a.0));
    refined.dedup_by(|a, b| a.1 == b.1);
    refined
}

fn allowed(mark: &SessionMark, platforms: &[u16]) -> bool {
    platforms.is_empty() || platforms.contains(&mark.platform)
}

/// Hard decision on every bit, with either sign (the magic byte tells which is right).
fn decode(soft: &[f32], platforms: &[u16]) -> Option<SessionMark> {
    [1.0f32, -1.0].into_iter().find_map(|sign| {
        let bits: Vec<bool> = soft.iter().map(|s| s * sign > 0.0).collect();
        SessionMark::from_bits(&bits).filter(|m| allowed(m, platforms))
    })
}

/// Chase decoding for accumulated bits: besides the hard decision, try flipping one, two or three of
/// the `CHASE_WEAKEST` least reliable bits; the CRC and the magic byte reject wrong guesses. Only used
/// when the platform codes to accept are known, which keeps false reads out (see the README).
fn decode_chase(soft: &[f32], platforms: &[u16]) -> Option<SessionMark> {
    if platforms.is_empty() {
        return decode(soft, platforms);
    }
    let mut order: Vec<usize> = (0..soft.len()).collect();
    order.sort_by(|a, b| soft[*a].abs().total_cmp(&soft[*b].abs()));
    let weak = &order[..CHASE_WEAKEST.min(order.len())];
    let n = weak.len();
    for sign in [1.0f32, -1.0] {
        let base: Vec<bool> = soft.iter().map(|s| s * sign > 0.0).collect();
        let attempt = |flips: &[usize]| {
            let mut bits = base.clone();
            for i in flips {
                bits[*i] = !bits[*i];
            }
            SessionMark::from_bits(&bits).filter(|m| allowed(m, platforms))
        };
        let singles = (0..n).map(|a| vec![weak[a]]);
        let pairs = (0..n).flat_map(|a| (a + 1..n).map(move |b| vec![weak[a], weak[b]]));
        let triples =
            (0..n).flat_map(|a| (a + 1..n).flat_map(move |b| (b + 1..n).map(move |c| vec![weak[a], weak[b], weak[c]])));
        let found =
            std::iter::once(Vec::new()).chain(singles).chain(pairs).chain(triples).find_map(|flips| attempt(&flips));
        if found.is_some() {
            return found;
        }
    }
    None
}

/// Lock-in accumulator. The pattern difference between two frames half a period apart follows
/// `sin(2*pi*t/T + phase)` in receive time, with one unknown phase for the whole stream. Correlating
/// every pair with sine and cosine adds the mark up coherently while picture motion (crowds, camera
/// pans, close-ups) averages out; the phase is then estimated from all bits together.
#[derive(Default)]
struct LockIn {
    i: Vec<f32>,
    q: Vec<f32>,
    last: Option<f64>,
}

impl LockIn {
    fn add(&mut self, at: f64, soft: &[f32]) {
        if self.i.len() != BITS {
            self.i = vec![0.0; BITS];
            self.q = vec![0.0; BITS];
        }
        let decay = self.last.map_or(1.0, |t| (-(at - t).max(0.0) / LOCKIN_TAU_SECS).exp()) as f32;
        self.last = Some(at);
        let w = std::f64::consts::TAU * at / PERIOD_SECS;
        let (s, c) = (w.sin() as f32, w.cos() as f32);
        for (b, v) in soft.iter().enumerate() {
            self.i[b] = self.i[b] * decay + v * s;
            self.q[b] = self.q[b] * decay + v * c;
        }
    }

    /// Soft bits along the dominant phase (the sign is resolved by the magic byte when decoding).
    fn soft(&self) -> Vec<f32> {
        let (mut xx, mut yy, mut xy) = (0f32, 0f32, 0f32);
        for (x, y) in self.i.iter().zip(&self.q) {
            xx += x * x;
            yy += y * y;
            xy += x * y;
        }
        let phase = 0.5 * (2.0 * xy).atan2(xx - yy);
        let (c, s) = (phase.cos(), phase.sin());
        self.i.iter().zip(&self.q).map(|(x, y)| x * c + y * s).collect()
    }
}

/// Reads the watermark from a sequence of frames (fed in order, with their receive time in seconds).
/// A pair one second apart is tried on its own (static pictures read at once); pairs half a second
/// apart feed a lock-in accumulator with Chase decoding (moving pictures read after a few seconds).
/// When the whole picture does not read, the detector searches for the crop and mirror the pirate
/// applied; a better-looking view becomes a candidate with its own accumulator and replaces the current
/// view only once it reads the mark.
pub struct Detector {
    history: VecDeque<(f64, GrayImage)>,
    view: View,
    lock: LockIn,
    candidate: Option<(View, LockIn)>,
    last_read: Option<f64>,
    last_search: Option<f64>,
    /// Platform codes to accept (Strack's registry); empty accepts any and disables Chase decoding.
    platforms: Vec<u16>,
}

impl Default for Detector {
    fn default() -> Self {
        Detector::new(Vec::new())
    }
}

impl Detector {
    pub fn new(platforms: Vec<u16>) -> Self {
        Detector {
            history: VecDeque::new(),
            view: View::FULL,
            lock: LockIn::default(),
            candidate: None,
            last_read: None,
            last_search: None,
            platforms,
        }
    }

    /// The view the detector currently reads with (the whole frame unless a crop or mirror was found).
    pub fn view(&self) -> View {
        self.view
    }

    fn read(&mut self, view: View, mark: SessionMark, at: f64) -> Option<SessionMark> {
        self.view = view;
        self.lock = LockIn::default();
        self.candidate = None;
        self.last_read = Some(at);
        Some(mark)
    }

    fn pair(&self, luma: &GrayImage, target: f64, tolerance: f64) -> Option<Diff> {
        self.history
            .iter()
            .filter(|(t, _)| (t - target).abs() <= tolerance)
            .min_by(|a, b| (a.0 - target).abs().total_cmp(&(b.0 - target).abs()))
            .and_then(|(_, before)| Diff::new(luma, before))
    }

    pub fn push(&mut self, at: f64, luma: &GrayImage) -> Option<SessionMark> {
        let wide = self.pair(luma, at - PERIOD_SECS / 2.0, PAIR_TOLERANCE);
        let short = self.pair(luma, at - LOCKIN_LAG_SECS, LOCKIN_TOLERANCE_SECS);
        self.history.push_back((at, luma.clone()));
        while self.history.front().is_some_and(|(t, _)| *t < at - HISTORY_SECS) {
            self.history.pop_front();
        }
        let reference = at - LOCKIN_LAG_SECS / 2.0;

        let view = self.view;
        let wide_soft = wide.as_ref().map(|d| d.soft_bits(&view));
        if let Some(mark) = wide_soft.as_deref().and_then(|s| decode(s, &self.platforms)) {
            return self.read(view, mark, at);
        }
        if let Some(diff) = &short {
            self.lock.add(reference, &diff.soft_bits(&view));
            if let Some(mark) = decode_chase(&self.lock.soft(), &self.platforms) {
                return self.read(view, mark, at);
            }
        }
        let mut candidate_read = None;
        if let Some((candidate, lock)) = self.candidate.as_mut() {
            let found = wide.as_ref().and_then(|d| decode(&d.soft_bits(candidate), &self.platforms));
            let found = found.or_else(|| {
                let diff = short.as_ref()?;
                lock.add(reference, &diff.soft_bits(candidate));
                decode_chase(&lock.soft(), &self.platforms)
            });
            candidate_read = found.map(|mark| (*candidate, mark));
        }
        if let Some((candidate, mark)) = candidate_read {
            return self.read(candidate, mark, at);
        }

        let locked = self.last_read.is_some_and(|t| at - t < LOCK_SECS);
        let searched = self.last_search.is_some_and(|t| at - t < SEARCH_EVERY_SECS);
        let (Some(diff), Some(soft)) = (wide.as_ref(), wide_soft.as_ref()) else { return None };
        if locked || searched {
            return None;
        }
        self.last_search = Some(at);
        let candidates = search(diff);
        for (_, candidate) in candidates.iter().take(DECODE_CANDIDATES) {
            if let Some(mark) = decode(&diff.soft_bits(candidate), &self.platforms) {
                return self.read(*candidate, mark, at);
            }
        }
        if let Some((best, candidate)) = candidates.first() {
            let tracked = self.candidate.as_ref().is_some_and(|(v, _)| v == candidate);
            if *candidate != self.view && !tracked && *best > energy(soft) * ADOPT_FACTOR {
                self.candidate = Some((*candidate, LockIn::default()));
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use image::{Rgb, RgbImage, imageops};

    use crate::leak::jpeg::{decode_luma, decode_rgb, encode};
    use crate::leak::mark::{SessionMark, platform_code};
    use crate::leak::raster::fill_rect;
    use crate::leak::scene::render_base;
    use crate::leak::watermark::{DEFAULT_STRENGTH, Detector, embed};

    fn licensed_jpeg(mark: Option<&SessionMark>, t: f64) -> Vec<u8> {
        let mut img = render_base(t, "TV FICTICIA PLAY");
        if let Some(mark) = mark {
            embed(&mut img, mark, t, DEFAULT_STRENGTH);
        }
        encode(&img, 80, None).unwrap()
    }

    /// What the demo pirate does: 80 % size, a logo over a corner and the bug, JPEG quality 55.
    fn pirate(jpeg: &[u8]) -> Vec<u8> {
        let img = decode_rgb(jpeg).unwrap();
        let mut small = imageops::thumbnail(&img, img.width() * 4 / 5, img.height() * 4 / 5);
        let (w, h) = (small.width() as i32, small.height() as i32);
        fill_rect(&mut small, 0, 0, w / 5, h * 38 / 100, Rgb([176, 18, 30]));
        fill_rect(&mut small, w / 4, h - 34, w / 2, 30, Rgb([176, 18, 30]));
        encode(&small, 55, None).unwrap()
    }

    /// At the peak of the cycle (the worst moment) every pixel moves at most 2 levels of 255 and the
    /// PSNR stays above 40 dB, the usual threshold for a visually lossless change. On average over
    /// the cycle the change is about 3 dB smaller.
    #[test]
    fn invisible_to_the_eye() {
        let mark = SessionMark::new("tvf", 42, 0x9c2e_44a1_b07d);
        let original = render_base(0.5, "TV FICTICIA PLAY");
        let mut marked: RgbImage = original.clone();
        embed(&mut marked, &mark, 0.5, DEFAULT_STRENGTH);
        let (mut max, mut squared) = (0i32, 0f64);
        for (a, b) in original.as_raw().iter().zip(marked.as_raw()) {
            let d = i32::from(*a) - i32::from(*b);
            max = max.max(d.abs());
            squared += f64::from(d * d);
        }
        let mse = squared / original.as_raw().len() as f64;
        let psnr = 10.0 * (255.0f64 * 255.0 / mse).log10();
        assert!(max <= 2, "max change {max}");
        assert!(psnr > 40.0, "PSNR {psnr:.1} dB");
    }

    #[test]
    fn survives_the_pirate_from_the_first_good_pair() {
        let mark = SessionMark::new("tvf", 42, 0x9c2e_44a1_b07d);
        let mut detector = Detector::default();
        let a = pirate(&licensed_jpeg(Some(&mark), 0.5));
        let b = pirate(&licensed_jpeg(Some(&mark), 1.5));
        assert_eq!(detector.push(0.0, &decode_luma(&a).unwrap()), None);
        assert_eq!(detector.push(1.0, &decode_luma(&b).unwrap()), Some(mark));
    }

    #[test]
    fn found_within_a_few_seconds_at_any_phase() {
        for start in [0.0, 0.15, 0.4, 0.9, 1.3] {
            let mark = SessionMark::new("tvf", 7, 0x0123_4567_89ab);
            let mut detector = Detector::default();
            let found = (0..14).find_map(|k| {
                let at = k as f64 * 0.25;
                let frame = pirate(&licensed_jpeg(Some(&mark), start + at));
                detector.push(at, &decode_luma(&frame).unwrap())
            });
            assert_eq!(found, Some(mark), "start phase {start}");
        }
    }

    /// Crops (symmetric and not), a mirror and combinations with rescaling and heavy compression.
    #[test]
    fn found_through_crop_and_mirror() {
        type Transform = Box<dyn Fn(&RgbImage) -> RgbImage>;
        let cases: Vec<(&str, Transform, u8)> = vec![
            ("crop 2 %", Box::new(|a| crop(a, 2)), 60),
            ("crop 8 %", Box::new(|a| crop(a, 8)), 60),
            (
                "crop 5 % left, 7 % bottom",
                Box::new(|a| {
                    let (w, h) = a.dimensions();
                    imageops::crop_imm(a, w * 5 / 100, 0, w - w * 5 / 100, h - h * 7 / 100).to_image()
                }),
                60,
            ),
            ("mirror", Box::new(imageops::flip_horizontal), 60),
            ("mirror, crop 4 %, 50 % size", Box::new(|a| scale(&imageops::flip_horizontal(&crop(a, 4)), 50)), 40),
        ];
        let mark = SessionMark::new("tvf", 42, 0x9c2e_44a1_b07d);
        for (name, attack, quality) in cases {
            let mut detector = Detector::default();
            let found = (0..32).find_map(|k| {
                let at = k as f64 * 0.25;
                let frame = decode_rgb(&licensed_jpeg(Some(&mark), 0.3 + at)).unwrap();
                let jpeg = encode(&attack(&frame), quality, None).unwrap();
                detector.push(at, &decode_luma(&jpeg).unwrap())
            });
            assert_eq!(found, Some(mark), "{name}");
        }
    }

    #[test]
    fn no_mark_in_an_unmarked_stream() {
        let mut detector = Detector::new(vec![platform_code("tvf")]);
        for k in 0..14 {
            let at = k as f64 * 0.25;
            let frame = pirate(&licensed_jpeg(None, 0.3 + at));
            assert_eq!(detector.push(at, &decode_luma(&frame).unwrap()), None);
        }
    }

    type Attack = Box<dyn FnMut(&RgbImage, &RgbImage, usize) -> Option<RgbImage>>;

    fn scale(img: &RgbImage, percent: u32) -> RgbImage {
        imageops::thumbnail(img, img.width() * percent / 100, img.height() * percent / 100)
    }

    fn map_pixels(img: &RgbImage, f: impl Fn(u8) -> u8) -> RgbImage {
        let mut out = img.clone();
        out.pixels_mut().for_each(|p| p.0.iter_mut().for_each(|c| *c = f(*c)));
        out
    }

    fn crop(img: &RgbImage, percent: u32) -> RgbImage {
        let (w, h) = img.dimensions();
        let (dx, dy) = (w * percent / 100, h * percent / 100);
        imageops::crop_imm(img, dx, dy, w - 2 * dx, h - 2 * dy).to_image()
    }

    /// Encoder that keeps the previous picture of any 16x16 block that changed less than `threshold`
    /// levels on average (what H.264 "skip" blocks do to slow, faint changes in static areas).
    fn skip_blocks(threshold: f32) -> Attack {
        let mut previous: Option<RgbImage> = None;
        Box::new(move |a, _, _| {
            let mut out = a.clone();
            if let Some(prev) = &previous {
                for by in (0..a.height()).step_by(16) {
                    for bx in (0..a.width()).step_by(16) {
                        let (bw, bh) = (16.min(a.width() - bx), 16.min(a.height() - by));
                        let mut diff = 0f32;
                        for y in by..by + bh {
                            for x in bx..bx + bw {
                                let (p, q) = (a.get_pixel(x, y).0, prev.get_pixel(x, y).0);
                                diff += (i16::from(p[1]) - i16::from(q[1])).abs() as f32;
                            }
                        }
                        if diff / ((bw * bh) as f32) < threshold {
                            for y in by..by + bh {
                                for x in bx..bx + bw {
                                    out.put_pixel(x, y, *prev.get_pixel(x, y));
                                }
                            }
                        }
                    }
                }
            }
            previous = Some(out.clone());
            Some(out)
        })
    }

    /// Prints how the watermark fares against common piracy transformations and asserts the one
    /// property that must always hold: it never names the wrong subscriber.
    #[test]
    #[ignore = "robustness report; run with: cargo test --release -- --ignored --nocapture robustness"]
    fn robustness_report() {
        let pirate_img = |img: &RgbImage| {
            let mut small = scale(img, 80);
            let (w, h) = (small.width() as i32, small.height() as i32);
            fill_rect(&mut small, 0, 0, w / 5, h * 38 / 100, Rgb([176, 18, 30]));
            fill_rect(&mut small, w / 4, h - 34, w / 2, 30, Rgb([176, 18, 30]));
            small
        };
        let cases: Vec<(&str, u8, Attack)> = vec![
            ("demo pirate: 80 %, logo, banner, JPEG 55", 55, Box::new(move |a, _, _| Some(pirate_img(a)))),
            ("50 % size (480p), JPEG 50", 50, Box::new(|a, _, _| Some(scale(a, 50)))),
            ("33 % size (320x180), JPEG 30", 30, Box::new(|a, _, _| Some(scale(a, 33)))),
            ("JPEG quality 15", 15, Box::new(|a, _, _| Some(a.clone()))),
            ("blur sigma 2", 60, Box::new(|a, _, _| Some(imageops::blur(a, 2.0)))),
            (
                "random noise +-12 per frame",
                60,
                Box::new(|a, _, _| {
                    let mut out = a.clone();
                    for p in out.pixels_mut() {
                        let n = rand::random::<i16>() % 13;
                        p.0.iter_mut().for_each(|c| *c = (i16::from(*c) + n).clamp(0, 255) as u8);
                    }
                    Some(out)
                }),
            ),
            (
                "brightness/contrast (x1.25, -20)",
                60,
                Box::new(|a, _, _| Some(map_pixels(a, |c| (f32::from(c) * 1.25 - 20.0).clamp(0.0, 255.0) as u8))),
            ),
            (
                "gamma 0.7",
                60,
                Box::new(|a, _, _| Some(map_pixels(a, |c| (255.0 * (f32::from(c) / 255.0).powf(0.7)) as u8))),
            ),
            (
                "grayscale",
                60,
                Box::new(|a, _, _| Some(image::DynamicImage::ImageRgb8(a.clone()).grayscale().to_rgb8())),
            ),
            ("2 frames per second", 60, Box::new(|a, _, k| (k % 2 == 0).then(|| a.clone()))),
            ("1 frame per second", 60, Box::new(|a, _, k| (k % 4 == 0).then(|| a.clone()))),
            ("H.264-like skip blocks (threshold 1.5)", 60, skip_blocks(1.5)),
            ("H.264-like skip blocks (threshold 3)", 60, skip_blocks(3.0)),
            ("crop 2 % of each border", 60, Box::new(|a, _, _| Some(crop(a, 2)))),
            ("crop 8 % of each border", 60, Box::new(|a, _, _| Some(crop(a, 8)))),
            (
                "crop 5 % left and 7 % bottom",
                60,
                Box::new(|a, _, _| {
                    let (w, h) = a.dimensions();
                    Some(imageops::crop_imm(a, w * 5 / 100, 0, w - w * 5 / 100, h - h * 7 / 100).to_image())
                }),
            ),
            ("crop 12 % of each border (beyond the search)", 60, Box::new(|a, _, _| Some(crop(a, 12)))),
            ("horizontal mirror", 60, Box::new(|a, _, _| Some(imageops::flip_horizontal(a)))),
            (
                "mirror, crop 4 %, 50 % size, JPEG 40",
                40,
                Box::new(|a, _, _| Some(scale(&imageops::flip_horizontal(&crop(a, 4)), 50))),
            ),
            (
                "collusion: average of two subscribers",
                60,
                Box::new(|a, b, _| {
                    let mut out = a.clone();
                    for (p, q) in out.pixels_mut().zip(b.pixels()) {
                        for (c, d) in p.0.iter_mut().zip(q.0) {
                            *c = ((u16::from(*c) + u16::from(d)) / 2) as u8;
                        }
                    }
                    Some(out)
                }),
            ),
        ];
        let mark = SessionMark::new("tvf", 42, 0x9c2e_44a1_b07d);
        let other = SessionMark::new("tvf", 43, 0x1111_2222_3333);
        println!("\n{:<44} result", "attack");
        for (name, quality, mut attack) in cases {
            let mut detector = Detector::new(vec![platform_code("tvf")]);
            let mut result = "not found in 10 s".to_string();
            for k in 0..40 {
                let at = k as f64 * 0.25;
                let t = 0.3 + at;
                let a = decode_rgb(&licensed_jpeg(Some(&mark), t)).unwrap();
                let b = if name.starts_with("collusion") {
                    decode_rgb(&licensed_jpeg(Some(&other), t)).unwrap()
                } else {
                    a.clone()
                };
                let Some(attacked) = attack(&a, &b, k) else { continue };
                let jpeg = encode(&attacked, quality, None).unwrap();
                if let Some(found) = detector.push(at, &decode_luma(&jpeg).unwrap()) {
                    assert!(found == mark || (name.starts_with("collusion") && found == other), "{name}: wrong mark");
                    result = format!("found {} after {at:.2} s of video", found.client_label());
                    break;
                }
            }
            println!("{name:<44} {result}");
        }
    }

    /// Per-pair diagnostics on real footage: share of chips dropped as motion, bit errors of a single
    /// pair and of the lock-in accumulator (against the known payload), and when the detector reads.
    #[test]
    #[ignore = "diagnostics; set STRACK_FRAMES_DIR to a folder of 960x540 JPEG frames at 8 fps"]
    fn real_footage_diagnostics() {
        use crate::leak::watermark::{Diff, Grid, LockIn, OUTLIER, View};
        let Ok(dir) = std::env::var("STRACK_FRAMES_DIR") else { return };
        let strength: f32 =
            std::env::var("STRACK_STRENGTH").ok().and_then(|s| s.parse().ok()).unwrap_or(DEFAULT_STRENGTH);
        let mut files: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|x| x == "jpg"))
            .collect();
        files.sort();
        let mark = SessionMark::new("tvf", 42, 0x9c2e_44a1_b07d);
        let truth = mark.to_bits();
        let errors = |soft: &[f32]| {
            let wrong = soft.iter().zip(truth).filter(|(s, b)| (**s > 0.0) != *b).count();
            wrong.min(truth.len() - wrong)
        };
        let mut detector = Detector::new(vec![platform_code("tvf")]);
        let lags = [0.125, 0.25, 0.5, 1.0];
        let mut locks: Vec<LockIn> = lags.iter().map(|_| LockIn::default()).collect();
        let mut combined = LockIn::default();
        let mut history: Vec<(f64, image::GrayImage)> = Vec::new();
        println!("\n  time  motion%@1s  lock-in errors by lag (0.125 / 0.25 / 0.5 / 1 s)  combined  detector");
        let mut found_at = None;
        for (k, path) in files.iter().enumerate() {
            let at = k as f64 / 8.0;
            let mut img = image::open(path).unwrap().to_rgb8();
            embed(&mut img, &mark, at, strength);
            let licensed = encode(&img, 80, None).unwrap();
            let luma = decode_luma(&pirate(&licensed)).unwrap();
            if let Some(m) = detector.push(at, &luma) {
                found_at.get_or_insert((at, m));
            }
            let mut motion = f32::NAN;
            for (lag, lock) in lags.iter().zip(locks.iter_mut()) {
                let before = history.iter().find(|(t, _)| (at - t - lag).abs() < 0.03).map(|(_, l)| l);
                let Some(diff) = before.and_then(|b| Diff::new(&luma, b)) else { continue };
                let soft = diff.soft_bits(&View::FULL);
                lock.add(at - lag / 2.0, &soft);
                combined.add(at - lag / 2.0, &soft);
                if *lag == 1.0 {
                    let grid = Grid::new(&View::FULL, diff.w as u32, diff.h as u32);
                    let (mut moved, mut total) = (0, 0);
                    for row in grid.rows.iter().flatten() {
                        for col in grid.cols.iter().flatten() {
                            total += 1;
                            moved += usize::from(diff.mean(*col, *row).abs() > OUTLIER);
                        }
                    }
                    motion = 100.0 * moved as f32 / total as f32;
                }
            }
            history.push((at, luma));
            history.retain(|(t, _)| at - t < 1.5);
            if k % 8 == 0 && k > 0 {
                let errs: Vec<String> = locks.iter().map(|l| format!("{:3}", errors(&l.soft()))).collect();
                println!(
                    "{at:6.1}  {motion:9.1}  {:>44}  {:8}  {}",
                    errs.join(" / "),
                    errors(&combined.soft()),
                    found_at.map(|(t, m)| format!("{} at {t:.2} s", m.client_label())).unwrap_or_default()
                );
            }
        }
    }
}
