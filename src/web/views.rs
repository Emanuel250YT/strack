//! Shared view components: status words, notices, the case evidence and order tables.

use maud::{Markup, html};

use crate::evidence::{BlockKind, Proposal, WatermarkVerdict, site_of};
use crate::model::{Case, OrderRecord, Store};
use crate::web::labels::{self, Label, minute, until};
use crate::web::ui::{when, when_exact};
use crate::workflow::verify_case_hash;

pub fn status(label: Label) -> Markup {
    html! { span class={ "status " (label.tone) } { (label.text) } }
}

/// A ring chart with the total in the middle and its legend. `parts` are `(colour, label, count)`
/// with colour `coral`, `black`, `amber` or `grey`. Drawn in SVG (the CSP allows no inline styles).
pub fn ring(caption: &str, parts: &[(&str, &str, usize)]) -> Markup {
    const C: f64 = 100.0;
    let total: usize = parts.iter().map(|p| p.2).sum();
    let shown = parts.iter().filter(|p| p.2 > 0).count();
    let gap = if shown > 1 { 0.8 } else { 0.0 };
    let mut offset = 0.0;
    let mut segments = Vec::new();
    for (colour, _, n) in parts.iter().filter(|p| p.2 > 0) {
        let len = *n as f64 / total as f64 * C;
        segments.push((
            format!("seg-{colour}"),
            format!("{:.2} {:.2}", (len - gap).max(0.1), C - len + gap),
            format!("{:.2}", -offset),
        ));
        offset += len;
    }
    let summary = parts.iter().map(|(_, label, n)| format!("{label}: {n}")).collect::<Vec<_>>().join(", ");
    html! {
        div class="ring" {
            div class="ring-chart" role="img" aria-label={ (total) " " (caption) ". " (summary) } {
                svg viewBox="0 0 42 42" aria-hidden="true" focusable="false" {
                    circle class="ring-bg" cx="21" cy="21" r="15.915" {}
                    @for (class, dash, off) in &segments {
                        circle class=(class) cx="21" cy="21" r="15.915" stroke-dasharray=(dash) stroke-dashoffset=(off) {}
                    }
                }
                div class="ring-total" aria-hidden="true" { strong { (total) } span { (caption) } }
            }
            ul class="legend" {
                @for (colour, label, n) in parts {
                    li class={ "sw-" (colour) } { span { (label) } span class="num" { (n) } }
                }
            }
        }
    }
}

pub fn notice(text: &str, tone: &str) -> Markup {
    html! { div class={ "notice " (tone) } role="status" { p { (text) } } }
}

/// Notice for `?msg=` / `?error=` codes (only known codes render).
pub fn flash(code: Option<&str>) -> Markup {
    match code.and_then(labels::message) {
        Some((text, tone)) => notice(text, tone),
        None => html! {},
    }
}

fn provider_name(store: &Store, id: &str) -> String {
    store.provider(id).map_or_else(|| id.to_string(), |p| p.name.clone())
}

fn count(n: usize, one: &str, many: &str) -> String {
    if n == 1 { format!("1 {one}") } else { format!("{n} {many}") }
}

/// Plain-language statement of what the case asks for.
pub fn measure_summary(case: &Case) -> Markup {
    let Some(p) = &case.proposal else {
        return html! {
            p { "No se pide ningún bloqueo: " (labels::watermark_meaning(case.evidence.watermark.verdict).to_lowercase()) "." }
        };
    };
    let with_kind = |k: BlockKind| p.providers.iter().filter(|pp| pp.kind == Some(k)).count();
    let domain_only: Vec<&str> = p
        .providers
        .iter()
        .filter(|pp| pp.kind == Some(BlockKind::Domain))
        .map(|pp| pp.provider_name.as_str())
        .collect();
    let skipped: Vec<String> =
        p.providers.iter().filter(|pp| pp.kind.is_none()).map(|pp| pp.provider_name.clone()).collect();
    let third_parties =
        case.evidence.collateral.co_hosted.iter().filter(|d| site_of(d) != case.evidence.collateral.site).count();
    html! {
        @match p.measure {
            BlockKind::Ip => { p {
                "Bloquear el servidor de video " strong class="mono" { (p.host) } " por IP ("
                span class="mono" { (p.ip) } ") en " (count(with_kind(BlockKind::Ip), "proveedor", "proveedores"))
                @if !domain_only.is_empty() {
                    ", y por dominio en " (domain_only.join(", "))
                    (if domain_only.len() == 1 { ", que solo acepta dominio" } else { ", que solo aceptan dominio" })
                }
                ". Nadie más usa esa IP."
            } }
            BlockKind::Domain => { p {
                "Bloquear el servidor de video " strong class="mono" { (p.host) } " por dominio en "
                (count(with_kind(BlockKind::Domain), "proveedor", "proveedores")) ". La IP "
                span class="mono" { (p.ip) } " no se toca: "
                @if third_parties > 0 { "también aloja " (count(third_parties, "sitio legítimo", "sitios legítimos")) "." }
                @else { "es de una red compartida." }
            } }
        }
        p {
            "Rige " strong { (until(p.expires_ip_min, p.expires_ip_min)) }
            @if p.expires_domain_min != p.expires_ip_min && with_kind(BlockKind::Domain) > 0 {
                "; el bloqueo por dominio, " (until(p.expires_domain_min, p.expires_ip_min))
            }
            "."
        }
        @if !skipped.is_empty() {
            p class="hint" { "Sin orden para " (skipped.join(", ")) ": no acepta bloqueo por dominio y la IP es compartida." }
        }
    }
}

pub fn plan_table(p: &Proposal) -> Markup {
    html! {
        div class="table-wrap" role="region" aria-label="Bloqueo por proveedor" tabindex="0" {
            table {
                caption { "Qué recibe cada proveedor" }
                thead { tr {
                    th scope="col" { "Proveedor" }
                    th scope="col" class="num" { "Clientes" }
                    th scope="col" { "Bloqueo" }
                    th scope="col" { "Rige hasta" }
                    th scope="col" { "Nota" }
                } }
                tbody {
                    @for pp in &p.providers {
                        tr {
                            th scope="row" { (pp.provider_name) }
                            td class="num" { (format_thousands(pp.customers)) }
                            td {
                                @match (pp.kind, pp.target.as_deref()) {
                                    (Some(k), Some(t)) => { (labels::kind(k)) " " span class="mono" { (t) } }
                                    _ => { "—" }
                                }
                            }
                            td { (pp.expires_min.map(|e| labels::until_short(e, p.expires_ip_min)).unwrap_or_else(|| "—".into())) }
                            td { (labels::plan_note(pp.note)) }
                        }
                    }
                }
            }
        }
    }
}

pub fn format_thousands(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            out.push('.');
        }
        out.push(c);
    }
    out
}

pub fn orders_table(store: &Store, orders: &[&OrderRecord], caption: &str) -> Markup {
    let end = labels::match_end(store);
    html! {
        div class="table-wrap" role="region" aria-label=(caption) tabindex="0" {
            table {
                caption { (caption) }
                thead { tr {
                    th scope="col" { "Orden" }
                    th scope="col" { "Proveedor" }
                    th scope="col" { "Bloqueo" }
                    th scope="col" { "Motivo" }
                    th scope="col" { "Estado" }
                    th scope="col" class="num" { "Enviada" }
                    th scope="col" class="num" { "Aplicada" }
                    th scope="col" class="num" { "Fin" }
                    th scope="col" { "Firmó" }
                } }
                tbody {
                    @for o in orders {
                        tr {
                            th scope="row" class="mono" { (o.order_id) }
                            td { (provider_name(store, &o.provider_id)) }
                            td {
                                (labels::kind(o.kind)) " " span class="mono" { (o.target) }
                                br; span class="hint" { (until(o.expires_min, end)) }
                            }
                            td { (labels::purpose(o.purpose)) }
                            td {
                                (status(labels::order_status(o.status)))
                                @if let Some(err) = &o.last_error { br; span class="hint" { (err) } }
                                @if let Some(lift) = &o.lift { br; span class="hint" { "Levantada por el reclamo " (lift.claim_id) } }
                            }
                            td class="num" { (o.sent_min.map(minute).unwrap_or_else(|| "—".into())) }
                            td class="num" { (o.applied_min.map(minute).unwrap_or_else(|| "—".into())) }
                            td class="num" { (o.ended_min.map(minute).unwrap_or_else(|| "—".into())) }
                            td { (o.judge_id.as_deref().map(|j| store.judge_name(j)).unwrap_or_else(|| "—".into())) }
                        }
                    }
                }
            }
        }
    }
}

fn check(tone: &str, title: &str, detail: Markup) -> Markup {
    html! {
        li class={ "check " (tone) } {
            span class="check-mark" aria-hidden="true" {}
            div { strong { (title) } p { (detail) } }
        }
    }
}

/// Every piece of evidence of a case: what was verified first, then the details behind it.
pub fn evidence_panel(store: &Store, case: &Case) -> Markup {
    let ev = &case.evidence;
    let wm = &ev.watermark;
    let server = &ev.server;
    let collateral = &ev.collateral;
    let capture = &ev.capture;
    let intact = ev.integrity_problems().is_empty() && verify_case_hash(case);
    let licensee_domain = |d: &str| {
        store.match_info.as_ref().is_some_and(|m| {
            m.licensees.iter().any(|l| l.authorized_domains.iter().any(|a| crate::evidence::host_in_domain(d, a)))
        })
    };
    let official = matches!(wm.verdict, WatermarkVerdict::OfficialSignal | WatermarkVerdict::LicenseeOutsideOwnDomain);
    let server_confirmed = server.host_seen_on_ip == Some(true) && server.asn_consistent != Some(false);
    let network = [server.asn_reported.map(|a| format!("AS{a}")), server.organization.clone()]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" · ");
    let networks: Vec<String> = ev.promotion.iter().fold(Vec::new(), |mut acc, p| {
        let name = labels::network(&p.network);
        if !acc.contains(&name) {
            acc.push(name);
        }
        acc
    });
    html! {
        section class="panel" aria-labelledby="ev-summary" {
            h2 id="ev-summary" { "Qué se verificó" }
            ul class="checks" {
                (check(if official { "ok" } else { "muted" }, labels::watermark_meaning(wm.verdict), html! {
                    @if let Some(mark) = &wm.extracted { "Marca de agua " span class="mono" { (mark) } }
                    @if let Some(origin) = &wm.prefix_origin { " · " (origin) }
                    @if let Some(l) = &wm.licensee { " · licenciatario " (l) }
                }))
                @if server_confirmed {
                    (check("ok", "Servidor identificado", html! {
                        span class="mono" { (server.host) } " en " span class="mono" { (server.ip) }
                        @if !network.is_empty() { " · " (network) }
                    }))
                } @else {
                    (check("warn", "Servidor sin confirmar por DNS pasivo", html! {
                        span class="mono" { (server.host) } " en " span class="mono" { (server.ip) }
                        @if !network.is_empty() { " · " (network) }
                    }))
                }
                @if collateral.shared_ip {
                    (check("warn", "La IP es compartida", html! {
                        (collateral.findings.iter().map(labels::finding).collect::<Vec<_>>().join(". "))
                        @if !collateral.findings.is_empty() { ". " }
                        "Por eso se bloquea por dominio."
                    }))
                } @else {
                    (check("ok", "Nadie más usa esa IP", html! { "Se puede bloquear por IP sin afectar a otros sitios." }))
                }
                @if intact && capture.sha256.is_none() {
                    (check("warn", "Sin captura del stream", html! {
                        "Quien lo cargó no adjuntó una captura. La detección quedó registrada con su huella."
                    }))
                } @else if intact {
                    (check("ok", "Evidencia íntegra", html! {
                        "La detección y la captura coinciden con las huellas registradas al abrir el expediente."
                    }))
                } @else {
                    (check("danger", "La evidencia fue alterada", html! {
                        "Las huellas no coinciden con las registradas al abrir el expediente."
                    }))
                }
                @if !networks.is_empty() {
                    (check("info", &format!("Se promocionó en {}", networks.join(", ")), html! {
                        (count(ev.promotion.len(), "publicación", "publicaciones"))
                        @if let Some(first) = ev.promotion.iter().filter_map(|p| p.minute).reduce(f64::min) {
                            ", la primera al " (minute(first))
                        }
                    }))
                }
            }
        }
        section class="panel" aria-labelledby="ev-watermark" {
            h2 id="ev-watermark" { "Señal" }
            dl class="facts" {
                dt { "Resultado" } dd { (status(labels::watermark(wm.verdict))) }
                dt { "Marca de agua" } dd class="mono" { (wm.extracted.as_deref().unwrap_or("—")) }
                dt { "Prefijo reconocido" } dd class="mono" { (wm.matched_prefix.as_deref().unwrap_or("ninguno")) }
                @if let Some(origin) = &wm.prefix_origin { dt { "Origen" } dd { (origin) } }
                @if let Some(l) = &wm.licensee { dt { "Licenciatario" } dd { (l) } }
                @if let Some(l) = &wm.authorized_domain_of { dt { "Sitio autorizado de" } dd { (l) } }
            }
        }
        section class="panel" aria-labelledby="ev-server" {
            h2 id="ev-server" { "Servidor del video" }
            dl class="facts" {
                dt { "Página del reproductor" } dd class="mono" { (server.page) }
                dt { "Dirección del stream" } dd class="mono" { (server.stream_url) }
                dt { "Servidor" } dd class="mono" { (server.host) }
                dt { "IP" } dd class="mono" { (server.ip) }
                dt { "Red" } dd {
                    (if network.is_empty() { "Sin datos".to_string() } else { network.clone() })
                    @if server.asn_consistent == Some(false) {
                        br; span class="hint" { "El DNS pasivo la ubica en AS" (server.asn_passive_dns.unwrap_or_default()) "." }
                    }
                }
                dt { "DNS pasivo" } dd {
                    @match server.host_seen_on_ip {
                        Some(true) => { "Vio este servidor en esa IP" }
                        Some(false) => { "No vio este servidor en esa IP" }
                        None => { "Sin datos" }
                    }
                }
                @if !server.host_other_ips.is_empty() {
                    dt { "Otras IPs del servidor" } dd class="mono" { (server.host_other_ips.join(", ")) }
                }
            }
            p class="hint" { "Se bloquea el servidor que entrega el video, no la página que lo muestra." }
        }
        section class="panel" aria-labelledby="ev-collateral" {
            h2 id="ev-collateral" { "Otros sitios en la misma IP" }
            @if collateral.co_hosted.is_empty() {
                p { "El DNS pasivo no registra otros sitios en " span class="mono" { (server.ip) } "." }
            } @else {
                div class="table-wrap" role="region" aria-label="Sitios vistos en la IP" tabindex="0" {
                    table {
                        caption { "Sitios vistos en " span class="mono" { (server.ip) } }
                        thead { tr { th scope="col" { "Sitio" } th scope="col" { "Relación con el stream" } } }
                        tbody {
                            @for d in &collateral.co_hosted {
                                tr {
                                    th scope="row" class="mono" { (d) }
                                    td {
                                        @if licensee_domain(d) { "Licenciatario autorizado" }
                                        @else if site_of(d) == collateral.site { "Mismo sitio pirata" }
                                        @else { "Tercero: lo afectaría un bloqueo por IP" }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        @if !ev.promotion.is_empty() {
            section class="panel" aria-labelledby="ev-promotion" {
                h2 id="ev-promotion" { "Dónde se difundió el enlace" }
                ul class="plain" {
                    @for p in &ev.promotion {
                        li {
                            strong { (labels::network(&p.network)) } " · "
                            span class="mono" { (p.url) }
                            @if let Some(m) = p.minute { " · al " (minute(m)) }
                        }
                    }
                }
            }
        }
        @if let Some(p) = &case.proposal {
            section class="panel" aria-labelledby="ev-plan" {
                h2 id="ev-plan" { "Bloqueo por proveedor" }
                (plan_table(p))
            }
        }
        details class="panel tech" {
            summary { "Detalle técnico: huellas digitales y detecciones" }
            dl class="facts" {
                dt { "Detección" } dd {
                    span class="mono" { (ev.detection.get("id").and_then(|v| v.as_str()).unwrap_or("—")) }
                    " · al " (minute(case.first_detection_min()))
                }
                dt { "Recibida" } dd { (when_exact(&ev.received_at)) " · al " (minute(ev.received_min)) }
                dt { "SHA-256 de la detección" } dd class="mono" { (ev.detection_sha256) }
                dt { "Captura" } dd {
                    (capture.format.as_deref().unwrap_or("—"))
                    @if let Some(d) = capture.duration_sec { " · " (d) " s" }
                    @if let Some(s) = capture.size_bytes { " · " (s) " bytes" }
                    @if let Some(m) = capture.captured_min { " · capturada al " (minute(m)) }
                }
                dt { "SHA-256 de la captura" } dd class="mono" { (capture.sha256.as_deref().unwrap_or("—")) }
                @if let Some(sync) = capture.mpegts_sync_byte {
                    dt { "Formato MPEG-TS" } dd { (if sync { "Byte de sincronización 0x47 presente" } else { "Sin byte de sincronización" }) }
                }
                dt { "Hash del expediente" } dd class="mono" { (case.case_hash) }
            }
            p class="hint" {
                "El hash del expediente se escribió en el registro de auditoría al abrirse el caso: cualquier cambio posterior se detecta."
            }
            @if !case.sightings.is_empty() {
                h3 { "El mismo stream, detectado otra vez (" (case.sightings.len()) ")" }
                ul class="plain" {
                    @for s in &case.sightings {
                        li { span class="mono" { (s.detection_id) } " · al " (minute(s.minute)) " · SHA-256 " span class="mono" { (s.detection_sha256[..16].to_string()) "…" } }
                    }
                }
            }
        }
    }
}

/// Who decided and how, for a decided case.
pub fn decision_summary(case: &Case) -> Markup {
    match &case.decision {
        None => html! {},
        Some(d) => html! {
            dl class="facts" {
                dt { "Decisión" } dd {
                    @if d.approved { (status(Label { text: "Aprobada", tone: "tone-ok" })) }
                    @else { (status(Label { text: "Rechazada", tone: "tone-danger" })) }
                }
                dt { "Juez" } dd { (d.judge_name) }
                dt { "Cuándo" } dd { "Al " (minute(d.minute)) " · " (when(&d.at)) }
                @if let Some(m) = d.measure { dt { "Bloqueo" } dd { (match m { BlockKind::Ip => "Por IP", BlockKind::Domain => "Por dominio" }) } }
                @if let Some(r) = &d.reason { dt { "Motivo" } dd { (r) } }
                dt { "Firma" } dd class="mono" { (d.signature) }
            }
        },
    }
}
