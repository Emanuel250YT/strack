//! Static assets, embedded in the binary: stylesheet, script and the self-hosted IBM Plex fonts
//! (SIL Open Font License, `assets/fonts/OFL.txt`). Fonts are served from here rather than from a
//! font CDN so no third party learns who opens the platform, and the CSP stays `'self'`.

use axum::extract::Path;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};

const CSS: &str = include_str!("../../assets/app.css");
const JS: &str = include_str!("../../assets/app.js");

const FONTS: [(&str, &[u8]); 3] = [
    ("ibm-plex-sans-var-latin.woff2", include_bytes!("../../assets/fonts/ibm-plex-sans-var-latin.woff2")),
    ("ibm-plex-mono-400-latin.woff2", include_bytes!("../../assets/fonts/ibm-plex-mono-400-latin.woff2")),
    ("ibm-plex-mono-500-latin.woff2", include_bytes!("../../assets/fonts/ibm-plex-mono-500-latin.woff2")),
];

pub async fn css() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "text/css; charset=utf-8"), (header::CACHE_CONTROL, "no-cache")], CSS)
}

pub async fn js() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "text/javascript; charset=utf-8"), (header::CACHE_CONTROL, "no-cache")], JS)
}

pub async fn font(Path(file): Path<String>) -> Response {
    match FONTS.iter().find(|(name, _)| *name == file) {
        Some((_, bytes)) => (
            [(header::CONTENT_TYPE, "font/woff2"), (header::CACHE_CONTROL, "public, max-age=31536000, immutable")],
            *bytes,
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}
