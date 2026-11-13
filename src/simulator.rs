//! HTTP client and wire types for the challenge simulator (also the wire format of providers' order
//! APIs in standalone mode, `standalone.rs`).
//!
//! Field names on the wire are the simulator's (Spanish); serde renames map them to English
//! identifiers. Nothing else in the code base talks to the simulator directly.

use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchInfo {
    pub id: String,
    #[serde(rename = "nombre")]
    pub name: String,
    #[serde(rename = "titular_derechos", default)]
    pub rights_holder: String,
    #[serde(rename = "inicio_iso", default)]
    pub start_iso: String,
    #[serde(rename = "fin_min")]
    pub end_min: f64,
    #[serde(rename = "marcas_de_agua_validas", default)]
    pub valid_watermarks: Vec<ValidWatermark>,
    #[serde(rename = "licenciatarios", default)]
    pub licensees: Vec<Licensee>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidWatermark {
    #[serde(rename = "prefijo")]
    pub prefix: String,
    #[serde(rename = "origen", default)]
    pub origin: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Licensee {
    #[serde(rename = "nombre")]
    pub name: String,
    #[serde(rename = "prefijo_marca")]
    pub watermark_prefix: String,
    #[serde(rename = "dominios_autorizados", default)]
    pub authorized_domains: Vec<String>,
    /// Licensed platform (id in Strack's platform registry) whose session marks are this licensee's
    /// broadcast: a stream carrying one of its marks gets this licensee's watermark.
    #[serde(rename = "plataforma", default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimStatus {
    #[serde(rename = "minuto_actual")]
    pub minute: f64,
    #[serde(rename = "fin_min")]
    pub end_min: f64,
    #[serde(rename = "finalizado", default)]
    pub finished: bool,
    #[serde(rename = "acelerar", default = "default_speedup")]
    pub speedup: f64,
    #[serde(rename = "jueces_de_turno", default)]
    pub judges_on_duty: Vec<String>,
}

fn default_speedup() -> f64 {
    1.0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detection {
    pub id: String,
    #[serde(rename = "minuto")]
    pub minute: f64,
    #[serde(rename = "pagina", default)]
    pub page: String,
    #[serde(default)]
    pub stream_url: String,
    #[serde(rename = "host_stream")]
    pub stream_host: String,
    #[serde(rename = "ip_servidor")]
    pub server_ip: String,
    #[serde(default)]
    pub asn: Option<u64>,
    #[serde(rename = "marca_de_agua_extraida", default)]
    pub watermark: Option<String>,
    #[serde(rename = "captura", default)]
    pub capture: Option<Capture>,
    #[serde(rename = "promocion", default)]
    pub promotion: Vec<Promotion>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capture {
    #[serde(rename = "capturada_min", default)]
    pub captured_min: Option<f64>,
    #[serde(rename = "formato", default)]
    pub format: Option<String>,
    #[serde(rename = "duracion_seg", default)]
    pub duration_sec: Option<f64>,
    #[serde(rename = "contenido_b64", default)]
    pub content_b64: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Promotion {
    #[serde(rename = "red")]
    pub network: String,
    pub url: String,
    #[serde(rename = "minuto", default)]
    pub minute: Option<f64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DetectionFeed {
    #[serde(rename = "minuto_actual")]
    pub minute: f64,
    #[serde(rename = "detecciones", default)]
    pub detections: Vec<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsByIp {
    pub ip: String,
    #[serde(default)]
    pub asn: Option<u64>,
    #[serde(rename = "organizacion", default)]
    pub organization: Option<String>,
    #[serde(rename = "dominios", default)]
    pub domains: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsByDomain {
    #[serde(rename = "dominio")]
    pub domain: String,
    #[serde(default)]
    pub ips: Vec<DnsIp>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsIp {
    pub ip: String,
    #[serde(default)]
    pub asn: Option<u64>,
    #[serde(rename = "organizacion", default)]
    pub organization: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Courts {
    #[serde(rename = "juzgados")]
    pub courts: Vec<Court>,
    #[serde(rename = "turnos")]
    pub shifts: Vec<Shift>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Court {
    pub id: String,
    #[serde(rename = "nombre")]
    pub name: String,
    #[serde(rename = "jurisdiccion", default)]
    pub jurisdiction: String,
    #[serde(rename = "jueces")]
    pub judges: Vec<JudgeRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JudgeRef {
    pub id: String,
    #[serde(rename = "nombre")]
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Shift {
    #[serde(rename = "juez_id")]
    pub judge_id: String,
    #[serde(rename = "desde_min")]
    pub from_min: f64,
    #[serde(rename = "hasta_min")]
    pub until_min: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Provider {
    pub id: String,
    #[serde(rename = "nombre")]
    pub name: String,
    #[serde(rename = "tamano", default)]
    pub size: Option<String>,
    #[serde(rename = "clientes", default)]
    pub customers: u64,
    #[serde(rename = "capacidades", default)]
    pub capabilities: Vec<String>,
}

impl Provider {
    pub fn accepts(&self, kind_wire: &str) -> bool {
        self.capabilities.iter().any(|c| c == kind_wire)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderOrderView {
    #[serde(rename = "orden_id")]
    pub order_id: String,
    #[serde(rename = "estado")]
    pub state: String,
    #[serde(rename = "aplicada_min", default)]
    pub applied_min: Option<f64>,
    #[serde(rename = "finalizada_min", default)]
    pub ended_min: Option<f64>,
    #[serde(rename = "motivo", default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ClaimFeed {
    #[serde(rename = "minuto_actual")]
    pub minute: f64,
    #[serde(rename = "reclamos", default)]
    pub claims: Vec<SimClaim>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimClaim {
    pub id: String,
    #[serde(rename = "minuto")]
    pub minute: f64,
    #[serde(rename = "dominio")]
    pub domain: String,
    #[serde(rename = "proveedor")]
    pub provider_id: String,
    #[serde(rename = "mensaje", default)]
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderBody {
    #[serde(rename = "orden_id")]
    pub order_id: String,
    #[serde(rename = "expediente_id")]
    pub case_id: String,
    #[serde(rename = "tipo")]
    pub kind: String,
    #[serde(rename = "objetivo")]
    pub target: String,
    #[serde(rename = "vence_min")]
    pub expires_min: i64,
    #[serde(rename = "juzgado_id")]
    pub court_id: String,
    #[serde(rename = "juez_id")]
    pub judge_id: String,
    #[serde(rename = "firma")]
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiftBody {
    #[serde(rename = "juez_id")]
    pub judge_id: String,
    #[serde(rename = "firma")]
    pub signature: String,
    #[serde(rename = "motivo")]
    pub reason: String,
}

#[derive(Debug, Clone)]
pub enum SimError {
    /// The simulator answered with an error status and message.
    Http { status: u16, message: String },
    /// The request never got an answer (connection refused, timeout...).
    Transport(String),
    /// The answer could not be decoded.
    Decode(String),
}

impl std::fmt::Display for SimError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SimError::Http { status, message } => write!(f, "HTTP {status}: {message}"),
            SimError::Transport(e) => write!(f, "transport error: {e}"),
            SimError::Decode(e) => write!(f, "decode error: {e}"),
        }
    }
}

impl std::error::Error for SimError {}

#[derive(Clone)]
pub struct SimClient {
    base: String,
    http: reqwest::Client,
}

impl SimClient {
    pub fn new(base: &str) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .connect_timeout(Duration::from_secs(3))
            .user_agent(concat!("strack/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self { base: base.trim_end_matches('/').to_string(), http })
    }

    pub fn base_url(&self) -> &str {
        &self.base
    }

    async fn decode<T: DeserializeOwned>(response: reqwest::Response) -> Result<T, SimError> {
        let status = response.status();
        let body = response.bytes().await.map_err(|e| SimError::Transport(e.to_string()))?;
        if !status.is_success() {
            let message = serde_json::from_slice::<Value>(&body)
                .ok()
                .and_then(|v| v.get("error").and_then(Value::as_str).map(str::to_string))
                .unwrap_or_else(|| String::from_utf8_lossy(&body).into_owned());
            return Err(SimError::Http { status: status.as_u16(), message });
        }
        serde_json::from_slice(&body).map_err(|e| SimError::Decode(e.to_string()))
    }

    async fn get<T: DeserializeOwned>(&self, path: &str, query: &[(&str, String)]) -> Result<T, SimError> {
        let response = self
            .http
            .get(format!("{}{}", self.base, path))
            .query(query)
            .send()
            .await
            .map_err(|e| SimError::Transport(e.to_string()))?;
        Self::decode(response).await
    }

    async fn post<T: DeserializeOwned, B: Serialize>(&self, path: &str, body: &B) -> Result<T, SimError> {
        let response = self
            .http
            .post(format!("{}{}", self.base, path))
            .json(body)
            .send()
            .await
            .map_err(|e| SimError::Transport(e.to_string()))?;
        Self::decode(response).await
    }

    pub async fn status(&self) -> Result<SimStatus, SimError> {
        self.get("/estado", &[]).await
    }

    pub async fn match_info(&self) -> Result<MatchInfo, SimError> {
        self.get("/partido", &[]).await
    }

    pub async fn detections(&self, since: f64) -> Result<DetectionFeed, SimError> {
        self.get("/detecciones", &[("desde", since.to_string())]).await
    }

    /// Passive DNS by IP; `Ok(None)` when the simulator has no records for it.
    pub async fn dns_by_ip(&self, ip: &str) -> Result<Option<DnsByIp>, SimError> {
        match self.get("/dns-pasivo", &[("ip", ip.to_string())]).await {
            Ok(v) => Ok(Some(v)),
            Err(SimError::Http { status: 404, .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Passive DNS by domain; `Ok(None)` when the simulator has no records for it.
    pub async fn dns_by_domain(&self, domain: &str) -> Result<Option<DnsByDomain>, SimError> {
        match self.get("/dns-pasivo", &[("dominio", domain.to_string())]).await {
            Ok(v) => Ok(Some(v)),
            Err(SimError::Http { status: 404, .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub async fn courts(&self) -> Result<Courts, SimError> {
        self.get("/juzgados", &[]).await
    }

    pub async fn providers(&self) -> Result<Vec<Provider>, SimError> {
        self.get("/proveedores", &[]).await
    }

    pub async fn send_order(&self, provider_id: &str, body: &OrderBody) -> Result<Value, SimError> {
        self.post(&format!("/proveedores/{provider_id}/ordenes"), body).await
    }

    pub async fn provider_orders(&self, provider_id: &str) -> Result<Vec<ProviderOrderView>, SimError> {
        self.get(&format!("/proveedores/{provider_id}/ordenes"), &[]).await
    }

    pub async fn lift_order(&self, provider_id: &str, order_id: &str, body: &LiftBody) -> Result<Value, SimError> {
        self.post(&format!("/proveedores/{provider_id}/ordenes/{order_id}/levantar"), body).await
    }

    pub async fn claims(&self, since: f64) -> Result<ClaimFeed, SimError> {
        self.get("/reclamos", &[("desde", since.to_string())]).await
    }
}
