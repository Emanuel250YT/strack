//! Case evidence: watermark verification, server identification, collateral risk and capture hashes.

use std::net::IpAddr;

use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::crypto::{hash_value, sha256_hex};
use crate::simulator::{Capture, Detection, DnsByDomain, DnsByIp, MatchInfo, Promotion, Provider};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockKind {
    Ip,
    Domain,
}

impl BlockKind {
    /// Value of `tipo` on the simulator's wire.
    pub fn wire(self) -> &'static str {
        match self {
            BlockKind::Ip => "ip",
            BlockKind::Domain => "dominio",
        }
    }

    pub fn code(self) -> &'static str {
        match self {
            BlockKind::Ip => "ip",
            BlockKind::Domain => "domain",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatermarkVerdict {
    /// Official signal of this match, outside any licensee's authorized domains.
    OfficialSignal,
    /// A licensee's signal re-streamed outside that licensee's authorized domains.
    LicenseeOutsideOwnDomain,
    /// The stream is served from a licensee's authorized domain: lawful rebroadcast.
    AuthorizedDomain,
    /// The watermark belongs to another event.
    OtherEvent,
    /// No watermark could be extracted.
    Missing,
}

impl WatermarkVerdict {
    pub fn blockable(self) -> bool {
        matches!(self, WatermarkVerdict::OfficialSignal | WatermarkVerdict::LicenseeOutsideOwnDomain)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatermarkCheck {
    pub extracted: Option<String>,
    pub matched_prefix: Option<String>,
    pub prefix_origin: Option<String>,
    /// Licensee whose watermark prefix matched, if any.
    pub licensee: Option<String>,
    /// Licensee that owns the stream host as an authorized domain, if any.
    pub authorized_domain_of: Option<String>,
    pub verdict: WatermarkVerdict,
}

/// Public suffixes with two labels that the naive site grouping must not split.
const TWO_LABEL_SUFFIXES: &[&str] = &[
    "com.ar", "gob.ar", "gov.ar", "org.ar", "net.ar", "edu.ar", "int.ar", "mil.ar", "tur.ar", "co.uk", "org.uk",
    "com.br", "com.mx", "com.uy", "com.py", "com.bo", "com.pe", "com.co", "com.ve", "com.ec",
];

/// Registrable domain ("site") of a host: the label before the public suffix plus the suffix.
///
/// A production build would use the Public Suffix List; the simulator only uses `.test` and
/// `.example` names, and the short list above covers the usual Latin American suffixes.
pub fn site_of(host: &str) -> String {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.parse::<IpAddr>().is_ok() {
        return host;
    }
    let labels: Vec<&str> = host.split('.').filter(|l| !l.is_empty()).collect();
    let take = if labels.len() >= 3 && TWO_LABEL_SUFFIXES.contains(&labels[labels.len() - 2..].join(".").as_str()) {
        3
    } else {
        2
    };
    if labels.len() <= take { labels.join(".") } else { labels[labels.len() - take..].join(".") }
}

/// True when `host` is `domain` or one of its subdomains.
pub fn host_in_domain(host: &str, domain: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    host == domain || host.ends_with(&format!(".{domain}"))
}

fn watermark_matches(watermark: &str, prefix: &str) -> bool {
    watermark == prefix || watermark.strip_prefix(prefix).is_some_and(|rest| rest.starts_with('-'))
}

/// Checks the extracted watermark against the match's valid prefixes and licensees.
pub fn check_watermark(extracted: Option<&str>, stream_host: &str, info: &MatchInfo) -> WatermarkCheck {
    let extracted = extracted.map(str::trim).filter(|w| !w.is_empty());
    let authorized_owner =
        info.licensees.iter().find(|l| l.authorized_domains.iter().any(|d| host_in_domain(stream_host, d)));
    let matched = extracted.and_then(|wm| {
        info.valid_watermarks.iter().filter(|v| watermark_matches(wm, &v.prefix)).max_by_key(|v| v.prefix.len())
    });
    let licensee = matched.and_then(|v| info.licensees.iter().find(|l| l.watermark_prefix == v.prefix));
    let verdict = match (extracted, matched) {
        (None, _) => WatermarkVerdict::Missing,
        (Some(_), None) => WatermarkVerdict::OtherEvent,
        (Some(_), Some(_)) if authorized_owner.is_some() => WatermarkVerdict::AuthorizedDomain,
        (Some(_), Some(_)) if licensee.is_some() => WatermarkVerdict::LicenseeOutsideOwnDomain,
        (Some(_), Some(_)) => WatermarkVerdict::OfficialSignal,
    };
    WatermarkCheck {
        extracted: extracted.map(str::to_string),
        matched_prefix: matched.map(|v| v.prefix.clone()),
        prefix_origin: matched.map(|v| v.origin.clone()),
        licensee: licensee.map(|l| l.name.clone()),
        authorized_domain_of: authorized_owner.map(|l| l.name.clone()),
        verdict,
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum CollateralFinding {
    /// The IP also serves domains of other sites.
    ForeignDomains { domains: Vec<String> },
    /// The IP also serves a licensee's authorized domains.
    LicenseeDomains { domains: Vec<String> },
    /// The network operator is a CDN or shared hosting.
    SharedInfrastructure { organization: String },
    /// Passive DNS has no records for the IP, so the collateral risk is unknown.
    NoPassiveDns,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollateralAnalysis {
    pub site: String,
    pub co_hosted: Vec<String>,
    pub findings: Vec<CollateralFinding>,
    pub shared_ip: bool,
    pub recommended: BlockKind,
}

const SHARED_INFRASTRUCTURE_HINTS: &[&str] = &["cdn", "compartid", "shared", "cloud", "anycast"];

fn is_licensee_domain(domain: &str, info: &MatchInfo) -> bool {
    info.licensees.iter().any(|l| l.authorized_domains.iter().any(|a| host_in_domain(domain, a)))
}

/// Collateral rule: block by IP only when everything seen on that IP belongs to the pirate site
/// and the network is not a CDN or shared hosting; otherwise block the stream host by domain.
pub fn analyze_collateral(host: &str, dns_ip: Option<&DnsByIp>, info: &MatchInfo) -> CollateralAnalysis {
    let site = site_of(host);
    let mut findings = Vec::new();
    let co_hosted = dns_ip.map(|d| d.domains.clone()).unwrap_or_default();
    match dns_ip {
        None => findings.push(CollateralFinding::NoPassiveDns),
        Some(dns) => {
            let licensee: Vec<String> = co_hosted.iter().filter(|d| is_licensee_domain(d, info)).cloned().collect();
            let foreign: Vec<String> =
                co_hosted.iter().filter(|d| site_of(d) != site && !licensee.contains(d)).cloned().collect();
            if !foreign.is_empty() {
                findings.push(CollateralFinding::ForeignDomains { domains: foreign });
            }
            if !licensee.is_empty() {
                findings.push(CollateralFinding::LicenseeDomains { domains: licensee });
            }
            if let Some(org) = &dns.organization {
                let lower = org.to_lowercase();
                if SHARED_INFRASTRUCTURE_HINTS.iter().any(|hint| lower.contains(hint)) {
                    findings.push(CollateralFinding::SharedInfrastructure { organization: org.clone() });
                }
            }
        }
    }
    let shared_ip = !findings.is_empty();
    CollateralAnalysis {
        site,
        co_hosted,
        findings,
        shared_ip,
        recommended: if shared_ip { BlockKind::Domain } else { BlockKind::Ip },
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerEvidence {
    pub page: String,
    pub stream_url: String,
    pub host: String,
    pub ip: String,
    pub asn_reported: Option<u64>,
    pub asn_passive_dns: Option<u64>,
    pub organization: Option<String>,
    /// Passive DNS saw the stream host on this IP.
    pub host_seen_on_ip: Option<bool>,
    /// Other IPs where passive DNS saw the stream host.
    pub host_other_ips: Vec<String>,
    pub asn_consistent: Option<bool>,
}

pub fn server_evidence(
    detection: &Detection,
    dns_ip: Option<&DnsByIp>,
    dns_domain: Option<&DnsByDomain>,
) -> ServerEvidence {
    let asn_passive_dns = dns_ip.and_then(|d| d.asn);
    ServerEvidence {
        page: detection.page.clone(),
        stream_url: detection.stream_url.clone(),
        host: detection.stream_host.clone(),
        ip: detection.server_ip.clone(),
        asn_reported: detection.asn,
        asn_passive_dns,
        organization: dns_ip.and_then(|d| d.organization.clone()),
        host_seen_on_ip: dns_domain.map(|d| d.ips.iter().any(|i| i.ip == detection.server_ip)),
        host_other_ips: dns_domain
            .map(|d| d.ips.iter().filter(|i| i.ip != detection.server_ip).map(|i| i.ip.clone()).collect())
            .unwrap_or_default(),
        asn_consistent: match (detection.asn, asn_passive_dns) {
            (Some(a), Some(b)) => Some(a == b),
            _ => None,
        },
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureEvidence {
    pub format: Option<String>,
    pub duration_sec: Option<f64>,
    pub captured_min: Option<f64>,
    pub size_bytes: Option<usize>,
    /// SHA-256 of the decoded capture bytes.
    pub sha256: Option<String>,
    /// For MPEG-TS captures: the first byte is the 0x47 sync byte.
    pub mpegts_sync_byte: Option<bool>,
    pub decode_error: Option<String>,
}

pub fn capture_evidence(capture: Option<&Capture>) -> CaptureEvidence {
    let mut out = CaptureEvidence {
        format: capture.and_then(|c| c.format.clone()),
        duration_sec: capture.and_then(|c| c.duration_sec),
        captured_min: capture.and_then(|c| c.captured_min),
        size_bytes: None,
        sha256: None,
        mpegts_sync_byte: None,
        decode_error: None,
    };
    let Some(content) = capture.and_then(|c| c.content_b64.as_deref()) else {
        out.decode_error = Some("missing_content".into());
        return out;
    };
    match base64::engine::general_purpose::STANDARD.decode(content.trim()) {
        Ok(bytes) => {
            out.size_bytes = Some(bytes.len());
            out.sha256 = Some(sha256_hex(&bytes));
            if out.format.as_deref() == Some("mpegts") {
                out.mpegts_sync_byte = Some(bytes.first() == Some(&0x47));
            }
        }
        Err(e) => out.decode_error = Some(e.to_string()),
    }
    out
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    /// The detection exactly as the feed delivered it (capture included).
    pub detection: Value,
    /// SHA-256 over the canonical JSON of `detection`.
    pub detection_sha256: String,
    pub received_at: String,
    pub received_min: f64,
    pub watermark: WatermarkCheck,
    pub server: ServerEvidence,
    pub collateral: CollateralAnalysis,
    pub capture: CaptureEvidence,
    pub promotion: Vec<Promotion>,
}

impl Evidence {
    pub fn build(
        raw: Value,
        detection: &Detection,
        info: &MatchInfo,
        dns_ip: Option<&DnsByIp>,
        dns_domain: Option<&DnsByDomain>,
        received_at: String,
        received_min: f64,
    ) -> Self {
        Evidence {
            detection_sha256: hash_value(&raw),
            detection: raw,
            received_at,
            received_min,
            watermark: check_watermark(detection.watermark.as_deref(), &detection.stream_host, info),
            server: server_evidence(detection, dns_ip, dns_domain),
            collateral: analyze_collateral(&detection.stream_host, dns_ip, info),
            capture: capture_evidence(detection.capture.as_ref()),
            promotion: detection.promotion.clone(),
        }
    }

    /// Re-derives every hash from the stored raw detection; returns the mismatches found.
    pub fn integrity_problems(&self) -> Vec<String> {
        let mut problems = Vec::new();
        if hash_value(&self.detection) != self.detection_sha256 {
            problems.push("detection_sha256 does not match the stored detection".to_string());
        }
        let capture = self.detection.get("captura").cloned().and_then(|c| serde_json::from_value::<Capture>(c).ok());
        let recomputed = capture_evidence(capture.as_ref());
        if recomputed.sha256 != self.capture.sha256 {
            problems.push("capture sha256 does not match the stored capture content".to_string());
        }
        problems
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanNote {
    AsRecommended,
    /// The provider only blocks by domain, so it gets the stream host instead of the IP.
    DomainFallback,
    /// The provider cannot apply a precise block (domain needed but only IP accepted).
    NotApplicable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderPlan {
    pub provider_id: String,
    pub provider_name: String,
    pub customers: u64,
    pub kind: Option<BlockKind>,
    pub target: Option<String>,
    pub expires_min: Option<i64>,
    pub note: PlanNote,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proposal {
    pub measure: BlockKind,
    pub ip: String,
    pub host: String,
    pub expires_ip_min: i64,
    pub expires_domain_min: i64,
    pub providers: Vec<ProviderPlan>,
}

/// Per-provider plan: the measure where the provider accepts it, the stream host by domain as the
/// fallback for domain-only providers, and nothing where a precise block is not possible.
pub fn plan_measure(
    measure: BlockKind,
    ip: &str,
    host: &str,
    providers: &[Provider],
    expires_ip_min: i64,
    expires_domain_min: i64,
) -> Proposal {
    let plans = providers
        .iter()
        .map(|p| {
            let (kind, note) = match measure {
                BlockKind::Ip if p.accepts(BlockKind::Ip.wire()) => (Some(BlockKind::Ip), PlanNote::AsRecommended),
                BlockKind::Ip if p.accepts(BlockKind::Domain.wire()) => {
                    (Some(BlockKind::Domain), PlanNote::DomainFallback)
                }
                BlockKind::Domain if p.accepts(BlockKind::Domain.wire()) => {
                    (Some(BlockKind::Domain), PlanNote::AsRecommended)
                }
                _ => (None, PlanNote::NotApplicable),
            };
            ProviderPlan {
                provider_id: p.id.clone(),
                provider_name: p.name.clone(),
                customers: p.customers,
                kind,
                target: kind.map(|k| match k {
                    BlockKind::Ip => ip.to_string(),
                    BlockKind::Domain => host.to_string(),
                }),
                expires_min: kind.map(|k| match k {
                    BlockKind::Ip => expires_ip_min,
                    BlockKind::Domain => expires_domain_min,
                }),
                note,
            }
        })
        .collect();
    Proposal {
        measure,
        ip: ip.to_string(),
        host: host.to_string(),
        expires_ip_min,
        expires_domain_min,
        providers: plans,
    }
}

#[cfg(test)]
mod tests {
    use crate::evidence::{
        BlockKind, CollateralFinding, PlanNote, WatermarkVerdict, analyze_collateral, check_watermark, plan_measure,
        site_of,
    };
    use crate::simulator::{DnsByIp, Licensee, MatchInfo, Provider, ValidWatermark};

    fn practice_match() -> MatchInfo {
        MatchInfo {
            id: "practica-01".into(),
            name: "Partido de práctica".into(),
            rights_holder: String::new(),
            start_iso: String::new(),
            end_min: 105.0,
            valid_watermarks: vec![
                ValidWatermark { prefix: "LP26-PRA-OFI".into(), origin: "oficial".into() },
                ValidWatermark { prefix: "LP26-PRA-LIC-NORTE".into(), origin: "licenciatario".into() },
            ],
            licensees: vec![Licensee {
                name: "Canal Norte TV".into(),
                watermark_prefix: "LP26-PRA-LIC-NORTE".into(),
                authorized_domains: vec!["canalnorte.test".into(), "envivo.canalnorte.test".into()],
                platform: None,
            }],
        }
    }

    fn dns(ip: &str, org: &str, domains: &[&str]) -> DnsByIp {
        DnsByIp {
            ip: ip.into(),
            asn: Some(64600),
            organization: Some(org.into()),
            domains: domains.iter().map(|d| d.to_string()).collect(),
        }
    }

    #[test]
    fn official_watermark_on_a_pirate_host_is_blockable() {
        let check = check_watermark(Some("LP26-PRA-OFI-S048211"), "s1.pelotaya.test", &practice_match());
        assert_eq!(check.verdict, WatermarkVerdict::OfficialSignal);
        assert!(check.verdict.blockable());
    }

    #[test]
    fn licensee_on_its_own_domain_is_lawful() {
        let check = check_watermark(Some("LP26-PRA-LIC-NORTE"), "envivo.canalnorte.test", &practice_match());
        assert_eq!(check.verdict, WatermarkVerdict::AuthorizedDomain);
        assert!(!check.verdict.blockable());
    }

    #[test]
    fn licensee_signal_elsewhere_is_blockable() {
        let check = check_watermark(Some("LP26-PRA-LIC-NORTE-X1"), "cdn.robado.test", &practice_match());
        assert_eq!(check.verdict, WatermarkVerdict::LicenseeOutsideOwnDomain);
        assert_eq!(check.licensee.as_deref(), Some("Canal Norte TV"));
    }

    #[test]
    fn other_events_and_missing_watermarks_are_not_blockable() {
        let info = practice_match();
        assert_eq!(
            check_watermark(Some("LP25-F03-OFI-S102934"), "vod.x.test", &info).verdict,
            WatermarkVerdict::OtherEvent
        );
        assert_eq!(check_watermark(Some("LP26-PRA-OFIX"), "vod.x.test", &info).verdict, WatermarkVerdict::OtherEvent);
        assert_eq!(check_watermark(None, "vod.x.test", &info).verdict, WatermarkVerdict::Missing);
        assert_eq!(check_watermark(Some("  "), "vod.x.test", &info).verdict, WatermarkVerdict::Missing);
    }

    #[test]
    fn dedicated_ip_of_the_same_site_is_blocked_by_ip() {
        let d = dns("203.0.113.10", "Bruma Hosting Dedicado", &["s1.pelotaya.test", "s1-respaldo.pelotaya.test"]);
        let analysis = analyze_collateral("s1.pelotaya.test", Some(&d), &practice_match());
        assert!(!analysis.shared_ip);
        assert_eq!(analysis.recommended, BlockKind::Ip);
    }

    #[test]
    fn shared_hosting_is_blocked_by_domain() {
        let d = dns(
            "192.0.2.50",
            "Pampa Web Hosting Compartido",
            &["tv.verpartido-hd.test", "verpartido-hd.test", "panaderia.test"],
        );
        let analysis = analyze_collateral("tv.verpartido-hd.test", Some(&d), &practice_match());
        assert!(analysis.shared_ip);
        assert_eq!(analysis.recommended, BlockKind::Domain);
        assert!(
            analysis.findings.contains(&CollateralFinding::ForeignDomains { domains: vec!["panaderia.test".into()] })
        );
    }

    #[test]
    fn cdn_or_unknown_ip_is_blocked_by_domain() {
        let d = dns("198.51.100.20", "NubeRápida CDN", &["live.golazo-libre.test"]);
        assert_eq!(
            analyze_collateral("live.golazo-libre.test", Some(&d), &practice_match()).recommended,
            BlockKind::Domain
        );
        assert_eq!(
            analyze_collateral("live.golazo-libre.test", None, &practice_match()).recommended,
            BlockKind::Domain
        );
    }

    #[test]
    fn site_grouping_handles_two_label_suffixes() {
        assert_eq!(site_of("s1.pelotaya.test"), "pelotaya.test");
        assert_eq!(site_of("pelotaya.test"), "pelotaya.test");
        assert_eq!(site_of("live.club.com.ar"), "club.com.ar");
        assert_eq!(site_of("203.0.113.10"), "203.0.113.10");
    }

    #[test]
    fn domain_only_providers_get_the_host() {
        let providers = vec![
            Provider {
                id: "a".into(),
                name: "A".into(),
                size: None,
                customers: 10,
                capabilities: vec!["ip".into(), "dominio".into()],
            },
            Provider {
                id: "v".into(),
                name: "V".into(),
                size: None,
                customers: 5,
                capabilities: vec!["dominio".into()],
            },
            Provider { id: "i".into(), name: "I".into(), size: None, customers: 1, capabilities: vec!["ip".into()] },
        ];
        let ip_plan = plan_measure(BlockKind::Ip, "203.0.113.10", "s1.pelotaya.test", &providers, 105, 105);
        assert_eq!(ip_plan.providers[0].kind, Some(BlockKind::Ip));
        assert_eq!(ip_plan.providers[1].kind, Some(BlockKind::Domain));
        assert_eq!(ip_plan.providers[1].note, PlanNote::DomainFallback);
        assert_eq!(ip_plan.providers[1].target.as_deref(), Some("s1.pelotaya.test"));
        let domain_plan = plan_measure(BlockKind::Domain, "192.0.2.50", "tv.verpartido-hd.test", &providers, 105, 105);
        assert_eq!(domain_plan.providers[2].note, PlanNote::NotApplicable);
        assert_eq!(domain_plan.providers[2].kind, None);
    }
}
