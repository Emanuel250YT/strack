//! Leak tracing: a per-session mark hidden in a licensed stream, and reading it back from a pirate copy.
//!
//! A licensed platform hides a mark in every subscriber's stream: an invisible watermark (a faint,
//! slowly changing brightness pattern only software can read) plus a copy in each JPEG's metadata. It
//! names the platform, the subscriber and the session. When the stream is restreamed, Strack reads the
//! mark from the pirate copy and notifies the platform, which suspends that subscriber: the leak is cut
//! at the source, without blocking any IP or domain.

pub mod discover;
pub mod extract;
pub mod jpeg;
pub mod mark;
pub mod marker;
pub mod mjpeg;
pub mod platforms;
pub mod raster;
pub mod scene;
pub mod source;
pub mod trace;
pub mod watermark;
