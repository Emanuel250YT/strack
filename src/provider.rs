//! `strack provider`: a reference receiver an internet provider runs to take Strack's blocking orders,
//! in the wire format the regulation would standardise (the same the challenge simulator speaks). It
//! keeps every order on disk, applies it, reports its status, lifts it on a signed request and lets it
//! expire at `vence_min`. On its own it only records orders; `--hook <command>` runs a command for
//! every apply, lift and expiry (`STRACK_ACTION`, `STRACK_KIND`, `STRACK_TARGET`, `STRACK_ORDER_ID`
//! in its environment) so the provider can push the block to its DNS resolver or firewall.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::Context;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, FixedOffset, Utc};
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
    kickoff: DateTime<FixedOffset>,
    accepts: Vec<String>,
    data: PathBuf,
    hook: Option<String>,
    orders: Mutex<Vec<Stored>>,
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
    let receiver = Arc::new(Receiver {
        id: args.id.clone(),
        kickoff,
        accepts: args.accepts,
        data,
        hook: args.hook,
        orders: Mutex::new(orders),
    });
    let app = Router::new()
        .route("/proveedores/{provider}/ordenes", post(receive).get(list))
        .route("/proveedores/{provider}/ordenes/{order_id}", get(one))
        .route("/proveedores/{provider}/ordenes/{order_id}/levantar", post(lift))
        .with_state(receiver);
    let listener =
        tokio::net::TcpListener::bind(args.listen).await.with_context(|| format!("binding {}", args.listen))?;
    tracing::info!(provider = %args.id, "order receiver listening on http://{}", args.listen);
    axum::serve(listener, app).await?;
    Ok(())
}
