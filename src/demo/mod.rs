//! Demo servers for leak tracing, so the whole circuit can be shown without real services:
//!
//! - `platform`: a licensed streaming platform that hides a session mark in every subscriber's
//!   stream and accepts leak notices (it suspends the subscriber and closes the session). It shows a
//!   synthetic match, or real footage from a local file through ffmpeg (`video`). Subscribers sign
//!   up, sign in and recover their account (`site`, `accounts`); the staff manage them (`staff`).
//! - `pirate`: a pirate site that restreams the platform with subscriber accounts, re-encodes and
//!   rescales the picture, covers a corner with its logo and switches account when one is cut.
//!
//! Both are fictitious and only talk to each other and to Strack on the local machine.

pub mod accounts;
pub mod encoder;
pub mod pirate;
pub mod platform;
pub mod site;
pub mod staff;
pub mod video;

use axum::extract::Request;
use axum::http::{HeaderValue, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

const CSP: &str = "default-src 'none'; img-src 'self'; media-src 'self'; style-src 'self'; form-action 'self'; \
                   base-uri 'none'; frame-ancestors 'none'";

pub const CSS: &str = include_str!("../../assets/demo.css");

pub async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(CSP));
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    if !headers.contains_key(header::CACHE_CONTROL) {
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    response
}

pub async fn css() -> Response {
    ([(header::CONTENT_TYPE, "text/css; charset=utf-8"), (header::CACHE_CONTROL, "max-age=300")], CSS).into_response()
}

/// Local calendar date of an RFC 3339 time (`2026-11-12`).
pub fn local_date(rfc3339: &str) -> String {
    chrono::DateTime::parse_from_rfc3339(rfc3339)
        .map(|t| t.with_timezone(&chrono::Local).format("%Y-%m-%d").to_string())
        .unwrap_or_else(|_| rfc3339.to_string())
}

pub fn clock_time(rfc3339: &str) -> String {
    chrono::DateTime::parse_from_rfc3339(rfc3339)
        .map(|t| t.with_timezone(&chrono::Local).format("%H:%M:%S").to_string())
        .unwrap_or_else(|_| rfc3339.to_string())
}
