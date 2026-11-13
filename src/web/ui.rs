//! Reusable interface parts: page header with its main action, figure tiles, modal dialogs,
//! pagination, role pills and avatars. One system for every page.

use maud::{Markup, html};

use crate::judges::Role;

/// Page title, one line of context and the page's actions on the right.
pub fn page_header(title: &str, lede: &str, actions: Markup) -> Markup {
    html! {
        div class="page-header" {
            div class="page-title" {
                h1 { (title) }
                @if !lede.is_empty() { p class="lede" { (lede) } }
            }
            div class="page-actions" { (actions) }
        }
    }
}

/// Switches between the matches followed at the same time; nothing for a single match. `base`
/// ends in `?` or `&`.
pub fn match_tabs(matches: &[(String, String)], current: &str, base: &str) -> Markup {
    if matches.len() < 2 {
        return html! {};
    }
    html! {
        nav class="match-tabs" aria-label="Partidos" {
            @for (key, label) in matches {
                a href={ (base) "partido=" (key) } aria-current=[(key == current).then_some("page")] { (label) }
            }
        }
    }
}

/// A figure tile; with `href` the whole tile opens the list it counts.
pub fn figure(label: &str, value: impl std::fmt::Display, href: Option<&str>) -> Markup {
    html! {
        @match href {
            Some(href) => {
                a class="kpi kpi-link" href=(href) {
                    span class="kpi-label" { (label) }
                    span class="kpi-value" { (value) }
                }
            }
            None => {
                div class="kpi" {
                    span class="kpi-label" { (label) }
                    span class="kpi-value" { (value) }
                }
            }
        }
    }
}

pub fn figures(items: Markup) -> Markup {
    html! { div class="kpis" { (items) } }
}

/// A modal dialog. `opener` buttons carry `data-dialog-open="<id>"`; without script they are links
/// to a page holding the same form.
pub fn dialog(id: &str, title: &str, body: Markup) -> Markup {
    let title_id = format!("{id}-title");
    html! {
        dialog id=(id) class="modal" aria-labelledby=(title_id) {
            div class="modal-head" {
                h2 id=(title_id) { (title) }
                button type="button" class="icon-button" data-dialog-close aria-label="Cerrar" {
                    svg class="icon" viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor"
                        stroke-width="1.8" stroke-linecap="round" aria-hidden="true" focusable="false" {
                        path d="M6 6l12 12M18 6 6 18" {}
                    }
                }
            }
            (body)
        }
    }
}

/// Link styled as the primary button that opens a dialog (and falls back to `href`).
pub fn dialog_button(dialog_id: &str, href: &str, label: &str) -> Markup {
    html! { a class="button primary" href=(href) data-dialog-open=(dialog_id) { (label) } }
}

pub fn role_label(role: Role) -> &'static str {
    match role {
        Role::Judge => "Juez",
        Role::Operator => "Operador",
        Role::Admin => "Administración",
        Role::Platform => "Plataforma",
    }
}

pub fn role_pill(role: Role) -> Markup {
    let class = match role {
        Role::Judge => "pill pill-judge",
        Role::Operator => "pill pill-operator",
        Role::Platform => "pill pill-platform",
        Role::Admin => "pill pill-admin",
    };
    html! { span class=(class) { (role_label(role)) } }
}

pub fn initials(name: &str) -> String {
    name.split_whitespace()
        .filter_map(|w| w.chars().next().filter(|c| c.is_alphabetic()))
        .take(2)
        .collect::<String>()
        .to_uppercase()
}

pub fn avatar(name: &str, small: bool) -> Markup {
    html! { span class={ "avatar" @if small { " avatar-sm" } } aria-hidden="true" { (initials(name)) } }
}

/// `1 – 50 de 230` and previous / next links that keep the current filters (`base` ends in `?…&` or `?`).
pub fn pager(base: &str, page: usize, per_page: usize, total: usize) -> Markup {
    let pages = total.div_ceil(per_page).max(1);
    let first = if total == 0 { 0 } else { (page - 1) * per_page + 1 };
    let last = (page * per_page).min(total);
    html! {
        nav class="pager" aria-label="Páginas" {
            span class="hint" { (first) "–" (last) " de " (total) }
            @if page > 1 {
                a class="button" href={ (base) "page=" (page - 1) } rel="prev" { "Anterior" }
            }
            @if page < pages {
                a class="button" href={ (base) "page=" (page + 1) } rel="next" { "Siguiente" }
            }
        }
    }
}

/// Short local date and time for an RFC 3339 timestamp.
pub fn when(rfc3339: &str) -> String {
    chrono::DateTime::parse_from_rfc3339(rfc3339)
        .map(|t| t.with_timezone(&chrono::Local).format("%d/%m %H:%M").to_string())
        .unwrap_or_else(|_| rfc3339.to_string())
}

/// Full local date and time to the second, for evidence timestamps.
pub fn when_exact(rfc3339: &str) -> String {
    chrono::DateTime::parse_from_rfc3339(rfc3339)
        .map(|t| t.with_timezone(&chrono::Local).format("%d/%m/%Y %H:%M:%S").to_string())
        .unwrap_or_else(|_| rfc3339.to_string())
}

/// Encodes a query value for links built by hand (filters kept across pages).
pub fn query_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
