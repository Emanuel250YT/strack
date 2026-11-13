//! Running without the challenge simulator. A match is described in a config file: the match itself
//! (teams, kick-off, valid watermark prefixes, licensees), the courts with their duty shifts, and the
//! internet providers with the address of each one's order API. The clock is the wall clock from
//! kick-off, detections come in through the intake form or API, and orders, their status and lifts
//! go to each provider's own API in the same wire format the simulator uses (`strack provider` is a
//! reference receiver a provider can run).
//!
//! [`MatchSource`] puts both behind one interface, so the engine and the workflow do not change.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, bail};
use chrono::{DateTime, FixedOffset, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::simulator::{
    ClaimFeed, Courts, DetectionFeed, DnsByDomain, DnsByIp, LiftBody, MatchInfo, OrderBody, Provider,
    ProviderOrderView, SimClient, SimError, SimStatus,
};

/// Match minutes after the end during which the match still counts as running (the challenge's
/// grace period; IP blocks expire at the end).
const GRACE_MIN: f64 = 5.0;

/// A provider in the registry and the base address of its order API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderEndpoint {
    #[serde(flatten)]
    pub provider: Provider,
    /// Base address of the provider's order API (`POST {api_url}/proveedores/{id}/ordenes`, ...).
    pub api_url: String,
}

/// One match to follow without a simulator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StandaloneConfig {
    #[serde(rename = "partido")]
    pub match_info: MatchInfo,
    #[serde(rename = "juzgados")]
    pub courts: Courts,
    #[serde(rename = "proveedores")]
    pub providers: Vec<ProviderEndpoint>,
    /// A passive DNS service answering `GET /dns-pasivo?ip=` and `?dominio=` (optional: without it
    /// every IP counts as shared and blocks go by domain).
    #[serde(rename = "dns_pasivo", default)]
    pub passive_dns: Option<String>,
}

impl StandaloneConfig {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let config: StandaloneConfig =
            serde_json::from_str(&text).with_context(|| format!("reading the match config {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> anyhow::Result<()> {
        kickoff(&self.match_info)?;
        if self.match_info.valid_watermarks.is_empty() {
            bail!("the match needs at least one valid watermark prefix");
        }
        if self.providers.is_empty() {
            bail!("the match needs at least one provider");
        }
        for p in &self.providers {
            let ok = reqwest::Url::parse(&p.api_url).is_ok_and(|u| matches!(u.scheme(), "http" | "https"));
            if !ok {
                bail!("provider {} has no valid api_url", p.provider.id);
            }
        }
        if self.courts.shifts.is_empty() {
            bail!("the courts need at least one duty shift");
        }
        Ok(())
    }
}

fn kickoff(info: &MatchInfo) -> anyhow::Result<DateTime<FixedOffset>> {
    DateTime::parse_from_rfc3339(&info.start_iso)
        .with_context(|| format!("inicio_iso must be an RFC 3339 time, got {:?}", info.start_iso))
}

/// A match followed on the wall clock, with orders sent to each provider's API.
pub struct Standalone {
    name: String,
    info: MatchInfo,
    kickoff: DateTime<FixedOffset>,
    courts: Courts,
    providers: Vec<Provider>,
    endpoints: HashMap<String, SimClient>,
    passive_dns: Option<SimClient>,
}

impl Standalone {
    pub fn new(config: StandaloneConfig, source_name: &str) -> anyhow::Result<Self> {
        let kickoff = kickoff(&config.match_info)?;
        let mut endpoints = HashMap::new();
        for p in &config.providers {
            endpoints.insert(p.provider.id.clone(), SimClient::new(&p.api_url)?);
        }
        let passive_dns = config.passive_dns.as_deref().map(SimClient::new).transpose()?;
        Ok(Standalone {
            name: source_name.to_string(),
            info: config.match_info,
            kickoff,
            courts: config.courts,
            providers: config.providers.into_iter().map(|p| p.provider).collect(),
            endpoints,
            passive_dns,
        })
    }

    /// Match minutes since kick-off (negative before it).
    fn minute(&self) -> f64 {
        (Utc::now().signed_duration_since(self.kickoff).num_milliseconds() as f64) / 60_000.0
    }

    fn endpoint(&self, provider_id: &str) -> Result<&SimClient, SimError> {
        self.endpoints
            .get(provider_id)
            .ok_or_else(|| SimError::Http { status: 404, message: format!("unknown provider {provider_id}") })
    }
}

/// Where a match comes from: the challenge simulator, or a config file and the providers' own APIs.
pub enum MatchSource {
    Simulator(SimClient),
    Standalone(Box<Standalone>),
}

impl MatchSource {
    /// What the match follows, for logs and the audit log.
    pub fn base_url(&self) -> &str {
        match self {
            MatchSource::Simulator(sim) => sim.base_url(),
            MatchSource::Standalone(s) => &s.name,
        }
    }

    pub async fn status(&self) -> Result<SimStatus, SimError> {
        match self {
            MatchSource::Simulator(sim) => sim.status().await,
            MatchSource::Standalone(s) => {
                let minute = s.minute();
                let judges_on_duty = s
                    .courts
                    .shifts
                    .iter()
                    .filter(|sh| sh.from_min <= minute && minute < sh.until_min)
                    .map(|sh| sh.judge_id.clone())
                    .collect();
                Ok(SimStatus {
                    minute,
                    end_min: s.info.end_min,
                    finished: minute >= s.info.end_min + GRACE_MIN,
                    speedup: 1.0,
                    judges_on_duty,
                })
            }
        }
    }

    pub async fn match_info(&self) -> Result<MatchInfo, SimError> {
        match self {
            MatchSource::Simulator(sim) => sim.match_info().await,
            MatchSource::Standalone(s) => Ok(s.info.clone()),
        }
    }

    /// The simulator's detection feed; standalone matches get detections through the intake form and
    /// API only.
    pub async fn detections(&self, since: f64) -> Result<DetectionFeed, SimError> {
        match self {
            MatchSource::Simulator(sim) => sim.detections(since).await,
            MatchSource::Standalone(s) => Ok(DetectionFeed { minute: s.minute(), detections: Vec::new() }),
        }
    }

    pub async fn dns_by_ip(&self, ip: &str) -> Result<Option<DnsByIp>, SimError> {
        match self {
            MatchSource::Simulator(sim) => sim.dns_by_ip(ip).await,
            MatchSource::Standalone(s) => match &s.passive_dns {
                Some(dns) => dns.dns_by_ip(ip).await,
                None => Ok(None),
            },
        }
    }

    pub async fn dns_by_domain(&self, domain: &str) -> Result<Option<DnsByDomain>, SimError> {
        match self {
            MatchSource::Simulator(sim) => sim.dns_by_domain(domain).await,
            MatchSource::Standalone(s) => match &s.passive_dns {
                Some(dns) => dns.dns_by_domain(domain).await,
                None => Ok(None),
            },
        }
    }

    pub async fn courts(&self) -> Result<Courts, SimError> {
        match self {
            MatchSource::Simulator(sim) => sim.courts().await,
            MatchSource::Standalone(s) => Ok(s.courts.clone()),
        }
    }

    pub async fn providers(&self) -> Result<Vec<Provider>, SimError> {
        match self {
            MatchSource::Simulator(sim) => sim.providers().await,
            MatchSource::Standalone(s) => Ok(s.providers.clone()),
        }
    }

    pub async fn send_order(&self, provider_id: &str, body: &OrderBody) -> Result<Value, SimError> {
        match self {
            MatchSource::Simulator(sim) => sim.send_order(provider_id, body).await,
            MatchSource::Standalone(s) => s.endpoint(provider_id)?.send_order(provider_id, body).await,
        }
    }

    pub async fn provider_orders(&self, provider_id: &str) -> Result<Vec<ProviderOrderView>, SimError> {
        match self {
            MatchSource::Simulator(sim) => sim.provider_orders(provider_id).await,
            MatchSource::Standalone(s) => s.endpoint(provider_id)?.provider_orders(provider_id).await,
        }
    }

    pub async fn lift_order(&self, provider_id: &str, order_id: &str, body: &LiftBody) -> Result<Value, SimError> {
        match self {
            MatchSource::Simulator(sim) => sim.lift_order(provider_id, order_id, body).await,
            MatchSource::Standalone(s) => s.endpoint(provider_id)?.lift_order(provider_id, order_id, body).await,
        }
    }

    /// The simulator's claims feed; standalone matches have none yet (claims come from the sites).
    pub async fn claims(&self, since: f64) -> Result<ClaimFeed, SimError> {
        match self {
            MatchSource::Simulator(sim) => sim.claims(since).await,
            MatchSource::Standalone(s) => Ok(ClaimFeed { minute: s.minute().max(since), claims: Vec::new() }),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::standalone::{MatchSource, Standalone, StandaloneConfig};

    fn config(kickoff: &str) -> StandaloneConfig {
        serde_json::from_value(serde_json::json!({
            "partido": {"id": "final", "nombre": "Final — A vs. B", "inicio_iso": kickoff, "fin_min": 105.0,
                        "marcas_de_agua_validas": [{"prefijo": "LP26-FIN-OFI", "origen": "titular"}], "licenciatarios": []},
            "juzgados": {"juzgados": [], "turnos": [
                {"juez_id": "j1", "desde_min": -60.0, "hasta_min": 50.0},
                {"juez_id": "j2", "desde_min": 50.0, "hasta_min": 240.0}]},
            "proveedores": [{"id": "isp", "nombre": "ISP", "clientes": 10, "capacidades": ["ip", "dominio"],
                             "api_url": "http://127.0.0.1:9"}]
        }))
        .expect("config")
    }

    #[tokio::test]
    async fn the_clock_runs_from_kick_off() {
        let kickoff = (chrono::Utc::now() - chrono::Duration::minutes(60)).to_rfc3339();
        let cfg = config(&kickoff);
        cfg.validate().expect("valid");
        let source = MatchSource::Standalone(Box::new(Standalone::new(cfg, "final.json").expect("source")));
        let status = source.status().await.expect("status");
        assert!((status.minute - 60.0).abs() < 0.1, "{}", status.minute);
        assert_eq!(status.judges_on_duty, vec!["j2".to_string()]);
        assert!(!status.finished);
        assert!(source.detections(0.0).await.expect("feed").detections.is_empty());
        assert!(source.dns_by_ip("203.0.113.1").await.expect("dns").is_none(), "no passive DNS: unknown IP");
    }

    #[test]
    fn a_config_needs_a_provider_api_and_a_kick_off() {
        let mut bad = config("not a time");
        assert!(bad.validate().is_err());
        bad = config("2026-11-13T21:00:00-03:00");
        bad.providers[0].api_url = "ftp://isp".into();
        assert!(bad.validate().is_err());
    }
}
