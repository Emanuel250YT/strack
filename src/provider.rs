//! `strack provider`: a reference receiver an internet provider runs to take Strack's blocking orders,
//! in the wire format the regulation would standardise (the same the challenge simulator speaks). It
//! keeps every order on disk, applies it, reports its status, lifts it on a signed request and lets it
//! expire at `vence_min`. On its own it only records orders; `--hook <command>` runs a command for
//! every apply, lift and expiry (`STRACK_ACTION`, `STRACK_KIND`, `STRACK_TARGET`, `STRACK_ORDER_ID`
//! in its environment) so the provider can push the block to its DNS resolver or firewall.
//!
//! `--gateway <address>` also runs the provider's network edge for its subscribers: an HTTP proxy that
//! enforces the applied orders itself. A blocked domain or IP answers 451 with the block page, and a
//! stream already playing through it is cut the moment the order arrives.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Context;
use axum::body::Body;
use axum::extract::{Path, Request, State};
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, FixedOffset, Utc};
use futures_util::StreamExt;
use maud::{DOCTYPE, PreEscaped, html};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::simulator::{LiftBody, OrderBody, ProviderOrderView};

#[derive(clap::Args)]
pub struct ProviderArgs {
    /// This provider's id in Strack's registry.
    #[arg(long)]
    pub id: String,
    #[arg(long, default_value = "127.0.0.1:9101")]
    pub listen: SocketAddr,
    /// Kick-off of the match the orders refer to (RFC 3339): `vence_min` counts from it.
    #[arg(long)]
    pub kickoff: String,
    /// Block types this provider applies.
    #[arg(long, value_delimiter = ',', default_value = "ip,dominio")]
    pub accepts: Vec<String>,
    /// Where the orders are kept (default `var/provider-<id>.json`).
    #[arg(long)]
    pub data: Option<PathBuf>,
    /// Command run for every apply, lift and expiry, with the order in its environment.
    #[arg(long)]
    pub hook: Option<String>,
    /// Also run the provider's network edge at this address: an HTTP proxy for its subscribers that
    /// enforces the applied orders (block page, running streams cut).
    #[arg(long)]
    pub gateway: Option<SocketAddr>,
    /// The provider's name, shown on the block page.
    #[arg(long)]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Stored {
    order: OrderBody,
    state: String,
    applied_min: Option<f64>,
    ended_min: Option<f64>,
    reason: Option<String>,
}

struct Receiver {
    id: String,
    name: String,
    kickoff: DateTime<FixedOffset>,
    accepts: Vec<String>,
    data: PathBuf,
    hook: Option<String>,
    orders: Mutex<Vec<Stored>>,
    /// Upstream client of the gateway: no redirects followed, no proxy of its own.
    http: reqwest::Client,
}

impl Receiver {
    fn minute(&self) -> f64 {
        (Utc::now().signed_duration_since(self.kickoff).num_milliseconds() as f64) / 60_000.0
    }

    fn save(&self, orders: &[Stored]) {
        let tmp = self.data.with_extension("json.tmp");
        let written = serde_json::to_vec_pretty(orders)
            .map_err(anyhow::Error::from)
            .and_then(|bytes| Ok(std::fs::write(&tmp, bytes)?))
            .and_then(|()| Ok(std::fs::rename(&tmp, &self.data)?));
        if let Err(e) = written {
            tracing::warn!(error = %e, "could not save the orders");
        }
    }

    fn run_hook(&self, action: &str, order: &OrderBody) {
        let Some(hook) = &self.hook else { return };
        let mut cmd = if cfg!(windows) {
            let mut c = std::process::Command::new("cmd");
            c.args(["/C", hook]);
            c
        } else {
            let mut c = std::process::Command::new("sh");
            c.args(["-c", hook]);
            c
        };
        cmd.env("STRACK_ACTION", action)
            .env("STRACK_KIND", &order.kind)
            .env("STRACK_TARGET", &order.target)
            .env("STRACK_ORDER_ID", &order.order_id);
        match cmd.status() {
            Ok(status) if status.success() => {}
            Ok(status) => tracing::warn!(%status, action, order = %order.order_id, "hook failed"),
            Err(e) => tracing::warn!(error = %e, action, "could not run the hook"),
        }
    }

    /// The applied, unexpired order that blocks `host` (or one of its addresses), if any.
    fn blocking(&self, host: &str, addrs: &[IpAddr]) -> Option<OrderBody> {
        let now = self.minute();
        let orders = self.orders.lock().unwrap_or_else(|p| p.into_inner());
        orders
            .iter()
            .filter(|o| o.state == "aplicada" && o.order.expires_min as f64 > now)
            .find(|o| blocks(&o.order, host, addrs))
            .map(|o| o.order.clone())
    }

    /// Expires what is due; returns the orders that just expired.
    fn expire(&self, orders: &mut [Stored]) -> Vec<OrderBody> {
        let now = self.minute();
        let mut expired = Vec::new();
        for o in orders.iter_mut().filter(|o| o.state == "aplicada" && o.order.expires_min as f64 <= now) {
            o.state = "vencida".into();
            o.ended_min = Some(o.order.expires_min as f64);
            expired.push(o.order.clone());
        }
        expired
    }
}

/// Whether `order` covers a request to `host` (resolved to `addrs`): a domain order covers the domain
/// and its subdomains, an IP order the address.
fn blocks(order: &OrderBody, host: &str, addrs: &[IpAddr]) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let target = order.target.trim().trim_end_matches('.').to_ascii_lowercase();
    match order.kind.as_str() {
        "dominio" => host == target || host.ends_with(&format!(".{target}")),
        "ip" => host == target || target.parse::<IpAddr>().is_ok_and(|ip| addrs.contains(&ip)),
        _ => false,
    }
}

const HOP_BY_HOP: [&str; 10] = [
    "connection",
    "proxy-connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "host",
];

fn forwardable(headers: &HeaderMap) -> HeaderMap {
    let mut out = headers.clone();
    for name in HOP_BY_HOP {
        out.remove(name);
    }
    out
}

/// The page a subscriber gets for a blocked site (HTTP 451, Unavailable For Legal Reasons).
fn block_page(r: &Receiver, order: &OrderBody) -> Response {
    let kind = match order.kind.as_str() {
        "ip" => "la dirección IP",
        _ if order.target.parse::<IpAddr>().is_ok() => "el sitio",
        _ => "el dominio",
    };
    let page = html! {
        (DOCTYPE)
        html lang="es" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { "Sitio bloqueado por orden judicial" }
                style { (PreEscaped(BLOCK_PAGE_CSS)) }
            }
            body {
                main {
                    p class="eyebrow" { (r.name) }
                    h1 { "Este sitio está bloqueado por orden judicial" }
                    p {
                        "Tu proveedor de internet bloqueó " (kind) " " b { (order.target) }
                        " por una orden firmada por un juez durante el partido. El bloqueo termina solo cuando vence."
                    }
                    dl {
                        div { dt { "Expediente" } dd { (order.case_id) } }
                        div { dt { "Orden" } dd { (order.order_id) } }
                        div { dt { "Juzgado" } dd { (order.court_id) } }
                        div { dt { "Vigente hasta" } dd { "el minuto " (order.expires_min) " del partido" } }
                    }
                    p class="small" { "Todos los bloqueos vigentes, con el juez que los ordenó, están en el registro público de Strack." }
                }
            }
        }
    };
    (StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS, Html(page.into_string())).into_response()
}

const BLOCK_PAGE_CSS: &str = "body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f2f2f3;\
color:#18181b;font:16px/1.5 Inter,'Segoe UI',system-ui,sans-serif}main{background:#fff;border:1px solid #dcdce0;\
border-radius:20px;padding:40px;max-width:560px;margin:16px}h1{font-size:28px;line-height:1.2;margin:8px 0 16px}\
p{color:#3f3f46;margin:0 0 16px}.eyebrow{font-size:13px;font-weight:600;letter-spacing:2px;text-transform:uppercase;\
color:#b7301b;margin:0}dl{display:grid;gap:10px;margin:0 0 20px;padding:16px 0;border-top:1px solid #dcdce0;\
border-bottom:1px solid #dcdce0}dl div{display:flex;justify-content:space-between;gap:16px}dt{color:#5b5b63}\
dd{margin:0;font-weight:600;text-align:right}.small{font-size:14px;color:#5b5b63;margin:0}";

/// The provider's network edge: forwards its subscribers' plain HTTP requests, unless an applied
/// order blocks the site. A response already streaming stops as soon as an order covers it.
async fn gateway(State(r): State<Arc<Receiver>>, req: Request) -> Response {
    let Some(authority) = req.uri().authority().cloned() else {
        return (StatusCode::BAD_REQUEST, format!("Red de {}: usá esta dirección como proxy HTTP.", r.name))
            .into_response();
    };
    if req.method() == Method::CONNECT {
        return (StatusCode::METHOD_NOT_ALLOWED, "Solo HTTP en esta red de prueba.").into_response();
    }
    let host = authority.host().trim_start_matches('[').trim_end_matches(']').to_string();
    let port = authority.port_u16().unwrap_or(80);
    let addrs: Vec<IpAddr> = match host.parse::<IpAddr>() {
        Ok(ip) => vec![ip],
        Err(_) => tokio::net::lookup_host((host.as_str(), port))
            .await
            .map(|a| a.map(|s| s.ip()).collect())
            .unwrap_or_default(),
    };
    if let Some(order) = r.blocking(&host, &addrs) {
        tracing::info!(host = %host, order = %order.order_id, "request blocked");
        return block_page(&r, &order);
    }
    let url = req.uri().to_string();
    let method = req.method().clone();
    let headers = forwardable(req.headers());
    let Ok(body) = axum::body::to_bytes(req.into_body(), 16 * 1024 * 1024).await else {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    };
    let upstream = match r.http.request(method, &url).headers(headers).body(body).send().await {
        Ok(resp) => resp,
        Err(e) => {
            tracing::warn!(error = %e, url = %url, "upstream request failed");
            return (StatusCode::BAD_GATEWAY, "No se pudo llegar al sitio.").into_response();
        }
    };
    let status = upstream.status();
    let mut out_headers = forwardable(upstream.headers());
    out_headers.remove(header::CONTENT_LENGTH);
    let watch = r.clone();
    let stream = upstream.bytes_stream().take_while(move |_| {
        let open = watch.blocking(&host, &addrs).is_none();
        if !open {
            tracing::info!(host = %host, "stream cut by an applied order");
        }
        futures_util::future::ready(open)
    });
    let mut response = Response::new(Body::from_stream(stream));
    *response.status_mut() = status;
    *response.headers_mut() = out_headers;
    response
}

fn error(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({ "error": message }))).into_response()
}

fn view(o: &Stored) -> ProviderOrderView {
    ProviderOrderView {
        order_id: o.order.order_id.clone(),
        state: o.state.clone(),
        applied_min: o.applied_min,
        ended_min: o.ended_min,
        reason: o.reason.clone(),
    }
}

async fn receive(
    State(r): State<Arc<Receiver>>,
    Path(provider): Path<String>,
    Json(order): Json<OrderBody>,
) -> Response {
    if provider != r.id {
        return error(StatusCode::NOT_FOUND, "proveedor desconocido");
    }
    if !r.accepts.contains(&order.kind) {
        return error(StatusCode::UNPROCESSABLE_ENTITY, "tipo de bloqueo no aceptado");
    }
    if order.target.trim().is_empty() || order.signature.trim().is_empty() {
        return error(StatusCode::BAD_REQUEST, "falta el objetivo o la firma");
    }
    let now = r.minute();
    if order.expires_min as f64 <= now {
        return error(StatusCode::UNPROCESSABLE_ENTITY, "vence_min ya pasó");
    }
    {
        let mut orders = r.orders.lock().unwrap_or_else(|p| p.into_inner());
        if orders.iter().any(|o| o.order.order_id == order.order_id) {
            return error(StatusCode::CONFLICT, "orden_id duplicada");
        }
        orders.push(Stored {
            order: order.clone(),
            state: "aplicada".into(),
            applied_min: Some(now),
            ended_min: None,
            reason: None,
        });
        r.save(&orders);
    }
    tracing::info!(order = %order.order_id, kind = %order.kind, target = %order.target, "order applied");
    r.run_hook("apply", &order);
    (StatusCode::CREATED, Json(json!({ "orden_id": order.order_id, "estado": "recibida" }))).into_response()
}

async fn list(State(r): State<Arc<Receiver>>, Path(provider): Path<String>) -> Response {
    if provider != r.id {
        return error(StatusCode::NOT_FOUND, "proveedor desconocido");
    }
    let (views, expired) = {
        let mut orders = r.orders.lock().unwrap_or_else(|p| p.into_inner());
        let expired = r.expire(&mut orders);
        if !expired.is_empty() {
            r.save(&orders);
        }
        (orders.iter().map(view).collect::<Vec<_>>(), expired)
    };
    for order in &expired {
        r.run_hook("expire", order);
    }
    Json(views).into_response()
}

async fn one(State(r): State<Arc<Receiver>>, Path((provider, order_id)): Path<(String, String)>) -> Response {
    if provider != r.id {
        return error(StatusCode::NOT_FOUND, "proveedor desconocido");
    }
    let orders = r.orders.lock().unwrap_or_else(|p| p.into_inner());
    match orders.iter().find(|o| o.order.order_id == order_id) {
        Some(o) => Json(view(o)).into_response(),
        None => error(StatusCode::NOT_FOUND, "orden inexistente"),
    }
}

async fn lift(
    State(r): State<Arc<Receiver>>,
    Path((provider, order_id)): Path<(String, String)>,
    Json(body): Json<LiftBody>,
) -> Response {
    if provider != r.id {
        return error(StatusCode::NOT_FOUND, "proveedor desconocido");
    }
    if body.signature.trim().is_empty() {
        return error(StatusCode::BAD_REQUEST, "falta la firma");
    }
    let lifted = {
        let mut orders = r.orders.lock().unwrap_or_else(|p| p.into_inner());
        let now = r.minute();
        let Some(o) = orders.iter_mut().find(|o| o.order.order_id == order_id) else {
            return error(StatusCode::NOT_FOUND, "orden inexistente");
        };
        if o.state != "aplicada" {
            return error(StatusCode::CONFLICT, "la orden no está aplicada");
        }
        o.state = "levantada".into();
        o.ended_min = Some(now);
        o.reason = Some(body.reason.clone());
        let order = o.order.clone();
        r.save(&orders);
        order
    };
    tracing::info!(order = %order_id, "order lifted");
    r.run_hook("lift", &lifted);
    Json(json!({ "orden_id": order_id, "estado": "levantada" })).into_response()
}

pub async fn run(args: ProviderArgs) -> anyhow::Result<()> {
    let kickoff = DateTime::parse_from_rfc3339(&args.kickoff).context("--kickoff must be an RFC 3339 time")?;
    let data = args.data.unwrap_or_else(|| PathBuf::from(format!("var/provider-{}.json", args.id)));
    if let Some(dir) = data.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)?;
    }
    let orders: Vec<Stored> = match std::fs::read(&data) {
        Ok(bytes) => serde_json::from_slice(&bytes).with_context(|| format!("reading {}", data.display()))?,
        Err(_) => Vec::new(),
    };
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .connect_timeout(Duration::from_secs(5))
        .build()?;
    let receiver = Arc::new(Receiver {
        id: args.id.clone(),
        name: args.name.clone().unwrap_or_else(|| args.id.clone()),
        kickoff,
        accepts: args.accepts,
        data,
        hook: args.hook,
        orders: Mutex::new(orders),
        http,
    });
    let app = Router::new()
        .route("/proveedores/{provider}/ordenes", post(receive).get(list))
        .route("/proveedores/{provider}/ordenes/{order_id}", get(one))
        .route("/proveedores/{provider}/ordenes/{order_id}/levantar", post(lift))
        .with_state(receiver.clone());
    let listener =
        tokio::net::TcpListener::bind(args.listen).await.with_context(|| format!("binding {}", args.listen))?;
    tracing::info!(provider = %args.id, "order receiver listening on http://{}", args.listen);
    let Some(edge) = args.gateway else {
        axum::serve(listener, app).await?;
        return Ok(());
    };
    let edge_listener = tokio::net::TcpListener::bind(edge).await.with_context(|| format!("binding {edge}"))?;
    tracing::info!(provider = %args.id, "network edge (HTTP proxy) listening on http://{edge}");
    let edge_app = Router::new().fallback(gateway).with_state(receiver);
    tokio::try_join!(async { axum::serve(listener, app).await }, async { axum::serve(edge_listener, edge_app).await })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use crate::provider::blocks;
    use crate::simulator::OrderBody;

    fn order(kind: &str, target: &str) -> OrderBody {
        OrderBody {
            order_id: "o1".into(),
            case_id: "EXP-1".into(),
            kind: kind.into(),
            target: target.into(),
            expires_min: 120,
            court_id: "jg-1".into(),
            judge_id: "j-1".into(),
            signature: "sig".into(),
        }
    }

    #[test]
    fn domain_orders_cover_subdomains_only() {
        let o = order("dominio", "pelotaya.test");
        assert!(blocks(&o, "pelotaya.test", &[]));
        assert!(blocks(&o, "S1.PelotaYa.test.", &[]));
        assert!(!blocks(&o, "notpelotaya.test", &[]));
        assert!(!blocks(&o, "pelotaya.test.example", &[]));
    }

    #[test]
    fn ip_orders_cover_the_address_however_it_is_reached() {
        let o = order("ip", "127.0.0.2");
        let ip: IpAddr = "127.0.0.2".parse().expect("ip");
        assert!(blocks(&o, "127.0.0.2", &[ip]));
        assert!(blocks(&o, "pirata.test", &[ip]));
        assert!(!blocks(&o, "127.0.0.1", &["127.0.0.1".parse().expect("ip")]));
        assert!(!blocks(&order("otro", "127.0.0.2"), "127.0.0.2", &[ip]));
    }
}
