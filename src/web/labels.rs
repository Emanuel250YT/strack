//! End-user (Spanish) wording for every state the interface shows.

use crate::evidence::{BlockKind, CollateralFinding, PlanNote, WatermarkVerdict};
use crate::leak::extract::MarkSource;
use crate::leak::trace::{NoticeStatus, StreamState, Trace, TraceEnd, TraceStatus};
use crate::model::{CaseStatus, ClaimStatus, ClaimVerdict, OrderPurpose, OrderStatus};
use crate::workflow::{RegistryStatus, WorkflowError};

#[derive(Debug, Clone, Copy)]
pub struct Label {
    pub text: &'static str,
    pub tone: &'static str,
}

const fn label(text: &'static str, tone: &'static str) -> Label {
    Label { text, tone }
}

pub fn watermark(v: WatermarkVerdict) -> Label {
    match v {
        WatermarkVerdict::OfficialSignal => label("Señal oficial", "tone-ok"),
        WatermarkVerdict::LicenseeOutsideOwnDomain => label("Señal de un licenciatario", "tone-ok"),
        WatermarkVerdict::AuthorizedDomain => label("Licenciatario autorizado", "tone-muted"),
        WatermarkVerdict::OtherEvent => label("Otro evento", "tone-muted"),
        WatermarkVerdict::Missing => label("Sin marca de agua", "tone-muted"),
    }
}

/// What the watermark proves, as a sentence for the case summary.
pub fn watermark_meaning(v: WatermarkVerdict) -> &'static str {
    match v {
        WatermarkVerdict::OfficialSignal => "Es la señal oficial del partido",
        WatermarkVerdict::LicenseeOutsideOwnDomain => {
            "Es la señal de un licenciatario, retransmitida fuera de sus sitios"
        }
        WatermarkVerdict::AuthorizedDomain => "Es un licenciatario autorizado transmitiendo en su propio sitio",
        WatermarkVerdict::OtherEvent => "La marca de agua es de otro evento",
        WatermarkVerdict::Missing => "El stream no tiene marca de agua: no se puede probar que sea este partido",
    }
}

pub fn kind(k: BlockKind) -> &'static str {
    match k {
        BlockKind::Ip => "IP",
        BlockKind::Domain => "Dominio",
    }
}

/// The block kind inside a sentence: `por IP`, `por dominio`.
pub fn kind_phrase(k: BlockKind) -> &'static str {
    match k {
        BlockKind::Ip => "por IP",
        BlockKind::Domain => "por dominio",
    }
}

pub fn case_status(s: CaseStatus) -> Label {
    match s {
        CaseStatus::Dismissed => label("Descartado", "tone-muted"),
        CaseStatus::PendingJudge => label("Pendiente del juez", "tone-warn"),
        CaseStatus::Approved => label("Aprobado", "tone-ok"),
        CaseStatus::Rejected => label("Rechazado", "tone-danger"),
    }
}

pub fn order_status(s: OrderStatus) -> Label {
    match s {
        OrderStatus::AwaitingSignature => label("Espera firma", "tone-warn"),
        OrderStatus::Signed => label("Firmada", "tone-info"),
        OrderStatus::Sending => label("Enviando", "tone-info"),
        OrderStatus::Received => label("Recibida", "tone-info"),
        OrderStatus::Applied => label("Aplicada", "tone-ok"),
        OrderStatus::Failed => label("Falló: se reenvía", "tone-danger"),
        OrderStatus::Rejected => label("Rechazada", "tone-danger"),
        OrderStatus::Expired => label("Vencida", "tone-muted"),
        OrderStatus::Lifted => label("Levantada", "tone-muted"),
        OrderStatus::Abandoned => label("Sin enviar", "tone-muted"),
    }
}

pub fn purpose(p: OrderPurpose) -> &'static str {
    match p {
        OrderPurpose::Original => "Original",
        OrderPurpose::Retry => "Reenvío",
        OrderPurpose::Replacement => "Reemplazo",
    }
}

pub fn claim_status(s: ClaimStatus) -> Label {
    match s {
        ClaimStatus::PendingJudge => label("Pendiente del juez", "tone-warn"),
        ClaimStatus::Resolved => label("Aceptado: bloqueo levantado", "tone-ok"),
        ClaimStatus::Rejected => label("Rechazado", "tone-danger"),
        ClaimStatus::Closed => label("Cerrado", "tone-muted"),
    }
}

pub fn claim_verdict(v: ClaimVerdict) -> Label {
    match v {
        ClaimVerdict::Legitimate => label("Verificado: sitio legítimo detrás de uno de nuestros bloqueos", "tone-ok"),
        ClaimVerdict::PirateSite => label("El reclamante pertenece al mismo sitio pirata", "tone-danger"),
        ClaimVerdict::NoActiveBlock => label("Ningún bloqueo activo lo afecta", "tone-muted"),
    }
}

pub fn registry_status(s: RegistryStatus) -> Label {
    match s {
        RegistryStatus::InProgress => label("En curso", "tone-info"),
        RegistryStatus::Active => label("Activo", "tone-ok"),
        RegistryStatus::Expired => label("Vencido", "tone-muted"),
        RegistryStatus::Lifted => label("Levantado", "tone-warn"),
        RegistryStatus::NotApplied => label("No aplicado", "tone-muted"),
    }
}

pub fn plan_note(n: PlanNote) -> &'static str {
    match n {
        PlanNote::AsRecommended => "Según la recomendación",
        PlanNote::DomainFallback => "Solo acepta dominio: se bloquea el host del stream",
        PlanNote::NotApplicable => "No acepta dominio: sin orden, para no dañar sitios legítimos",
    }
}

pub fn finding(f: &CollateralFinding) -> String {
    match f {
        CollateralFinding::ForeignDomains { domains } => match domains.len() {
            1 => "La IP también aloja 1 sitio de terceros".to_string(),
            n => format!("La IP también aloja {n} sitios de terceros"),
        },
        CollateralFinding::LicenseeDomains { .. } => "La IP aloja dominios de un licenciatario autorizado".to_string(),
        CollateralFinding::SharedInfrastructure { organization } => {
            format!("{organization} es una CDN o un hosting compartido")
        }
        CollateralFinding::NoPassiveDns => {
            "Sin registros de DNS pasivo para la IP: el riesgo es desconocido".to_string()
        }
    }
}

pub fn network(name: &str) -> String {
    match name.to_ascii_lowercase().as_str() {
        "x" => "X".into(),
        "discord" => "Discord".into(),
        "telegram" => "Telegram".into(),
        other => other.to_string(),
    }
}

pub fn error_code(e: WorkflowError) -> &'static str {
    match e {
        WorkflowError::NotFound => "not_found",
        WorkflowError::AlreadyDecided => "already_decided",
        WorkflowError::NotAssigned => "not_assigned",
        WorkflowError::NotOnDuty => "not_on_duty",
        WorkflowError::NoSigningKey => "no_signing_key",
        WorkflowError::MatchOver => "match_over",
        WorkflowError::NothingToDo => "nothing_to_do",
    }
}

/// Message for a `?msg=` / `?error=` code; unknown codes show nothing.
pub fn message(code: &str) -> Option<(&'static str, &'static str)> {
    Some(match code {
        "approved" => ("Orden aprobada y firmada. Se está enviando a cada proveedor.", "ok"),
        "rejected" => ("Pedido rechazado. La decisión quedó registrada con su firma.", "ok"),
        "claim_approved" => ("Reclamo aceptado: se levantan los bloqueos y se envían los reemplazos.", "ok"),
        "claim_rejected" => ("Reclamo rechazado. La decisión quedó registrada con su firma.", "ok"),
        "retries_signed" => ("Reenvíos firmados y en camino.", "ok"),
        "logged_out" => ("Sesión cerrada.", "ok"),
        "reason_required" => ("Indique el motivo del rechazo.", "warn"),
        "csrf" => ("El formulario venció. Vuelva a intentarlo.", "warn"),
        "not_found" => ("No se encontró lo que buscás: puede haber sido borrado.", "danger"),
        "already_decided" => ("Ya fue decidido.", "warn"),
        "not_assigned" => ("No le corresponde: al cambio de turno pasa al juez entrante.", "warn"),
        "not_on_duty" => ("Está fuera de turno: no puede firmar ahora.", "danger"),
        "no_signing_key" => ("Su sesión no tiene la clave de firma. Vuelva a ingresar.", "danger"),
        "match_over" => ("El partido terminó: la orden ya no tendría efecto.", "warn"),
        "nothing_to_do" => ("No hay nada para firmar.", "warn"),
        "trace_started" => ("Rastreo iniciado: se está leyendo el stream.", "ok"),
        "trace_stopping" => ("Deteniendo el rastreo.", "ok"),
        "no_video_in_page" => {
            ("Esa página no tiene un video que podamos leer (ni en reproductores embebidos).", "warn")
        }
        "traces_started_from_page" => ("Encontramos varios videos en la página: cada uno tiene su rastreo.", "ok"),
        "invalid_url" => ("La dirección tiene que ser http:// o https:// y tener un servidor.", "warn"),
        "case_not_found" => ("No existe ese expediente.", "warn"),
        "user_created" => ("Usuario creado. Ya puede ingresar con su contraseña inicial.", "ok"),
        "user_updated" => ("Perfil guardado.", "ok"),
        "password_changed" => ("Contraseña cambiada. Se cerraron las demás sesiones de ese usuario.", "ok"),
        "user_disabled" => ("Usuario deshabilitado: ya no puede ingresar y sus sesiones se cerraron.", "ok"),
        "user_enabled" => ("Usuario habilitado.", "ok"),
        "user_deleted" => ("Usuario eliminado.", "ok"),
        "sessions_closed" => ("Sesiones cerradas.", "ok"),
        "platform_created" => ("Plataforma registrada. Los rastreos nuevos ya aceptan sus marcas.", "ok"),
        "platform_updated" => ("Plataforma guardada.", "ok"),
        "platform_deleted" => ("Plataforma quitada del registro.", "ok"),
        "invalid_username" => {
            ("El usuario va en minúsculas, con números, punto o guion, de 3 a 32 caracteres.", "warn")
        }
        "username_taken" => ("Ese usuario ya existe.", "warn"),
        "name_required" => ("Falta el nombre.", "warn"),
        "password_too_short" => ("La contraseña tiene que tener al menos 10 caracteres.", "warn"),
        "password_mismatch" => ("Las dos contraseñas no coinciden.", "warn"),
        "wrong_password" => ("La contraseña actual no es correcta.", "danger"),
        "judge_required" => ("Elegí el juez al que corresponde la cuenta.", "warn"),
        "judge_taken" => ("Ese juez ya tiene una cuenta.", "warn"),
        "signing_key_required" => ("Falta la clave de firma de demostración del juez.", "warn"),
        "self_action" => ("No podés hacer eso con tu propia cuenta.", "warn"),
        "last_admin" => ("Tiene que quedar al menos una cuenta de administración habilitada.", "warn"),
        "platform_required" => ("Elegí la plataforma a la que pertenece la cuenta.", "warn"),
        "platform_role_fixed" => ("Una cuenta de plataforma queda atada a su plataforma: no cambia de rol.", "warn"),
        "integration_saved" => ("Integración guardada.", "ok"),
        "trace_started_portal" => {
            ("Empezamos a rastrear ese stream. Si lleva la marca de tu plataforma, aparece acá.", "ok")
        }
        "judge_role_fixed" => ("El rol de juez queda atado a su clave de firma: no se puede cambiar.", "warn"),
        "invalid_platform_id" => {
            ("El identificador va en minúsculas, números y guiones, de 2 a 32 caracteres.", "warn")
        }
        "platform_taken" => ("Ya hay una plataforma con ese identificador.", "warn"),
        "token_too_short" => ("El token tiene que tener al menos 16 caracteres, o dejalo vacío.", "warn"),
        "confirm_required" => ("Marcá la confirmación para seguir.", "warn"),
        "password_set" => ("Contraseña guardada. Ya podés ingresar con ella.", "ok"),
        "user_created_link" => {
            ("Usuario creado. Entregale el enlace de un solo uso para que elija su contraseña.", "ok")
        }
        "link_issued" => ("Enlace generado. Entregalo por un canal oficial: no se vuelve a mostrar.", "ok"),
        "access_rejected" => ("Pedido de acceso rechazado.", "ok"),
        "already_requested" => ("Ya hay un pedido pendiente con ese usuario.", "warn"),
        "organism_required" => ("Indicá el organismo.", "warn"),
        "contact_required" => ("Indicá cómo contactarte: por ahí te llega el enlace.", "warn"),
        "too_many_requests" => ("Hay demasiados pedidos pendientes. Probá más tarde.", "warn"),
        "internal" => ("No se pudo guardar el cambio. Revisá los registros del servidor.", "danger"),
        _ => return None,
    })
}

pub fn trace_status(t: &Trace) -> Label {
    match (t.status, t.end) {
        (TraceStatus::Watching, _) if t.stop_requested => label("Deteniéndose", "tone-muted"),
        (TraceStatus::Watching, _) => label("Leyendo el stream", "tone-info"),
        (TraceStatus::Finished, Some(TraceEnd::StreamDown)) => label("Terminado: el stream pirata cayó", "tone-ok"),
        (TraceStatus::Finished, Some(TraceEnd::TimeLimit)) => label("Terminado por tiempo", "tone-muted"),
        (TraceStatus::Finished, Some(TraceEnd::Interrupted)) => label("Interrumpido por un reinicio", "tone-warn"),
        (TraceStatus::Finished, _) => label("Detenido", "tone-muted"),
    }
}

pub fn stream_state(s: StreamState) -> Label {
    match s {
        StreamState::Connecting => label("Conectando", "tone-info"),
        StreamState::Marked => label("En el aire, con marca de sesión", "tone-warn"),
        StreamState::Unmarked => label("En el aire, sin marca legible", "tone-muted"),
        StreamState::Down => label("Caído", "tone-ok"),
    }
}

pub fn notice_status(s: NoticeStatus) -> Label {
    match s {
        NoticeStatus::NotSent => label("Plataforma fuera del registro: sin aviso", "tone-muted"),
        NoticeStatus::Sending => label("Avisando a la plataforma", "tone-info"),
        NoticeStatus::Acknowledged => label("Cuenta suspendida por la plataforma", "tone-ok"),
        NoticeStatus::Rejected => label("La plataforma rechazó el aviso", "tone-danger"),
        NoticeStatus::Failed => label("No se pudo avisar a la plataforma", "tone-danger"),
    }
}

pub fn mark_source(s: MarkSource) -> &'static str {
    match s {
        MarkSource::Watermark => "marca de agua invisible",
        MarkSource::Qr => "código QR visible",
        MarkSource::Metadata => "metadato del cuadro",
    }
}

/// Plain-language reason for a notice error code returned by a platform.
pub fn notice_error(code: &str) -> String {
    match code {
        "invalid_mark" => {
            "La plataforma dice que la marca no es auténtica: puede ser un intento de culpar a otro abonado.".into()
        }
        "unknown_session" => "La plataforma no conoce esa sesión.".into(),
        "unauthorized" => "La plataforma no aceptó la credencial de Strack.".into(),
        "platform not in the registry" => "La plataforma de la marca no está en el registro de Strack.".into(),
        other => format!("Error: {other}"),
    }
}

/// Plain-language name of an audit event (the raw name when there is none).
pub fn audit_event(event: &str) -> String {
    let text = match event {
        "platform_started" => "Plataforma iniciada",
        "platform_stopped" => "Plataforma detenida",
        "match_loaded" => "Partido cargado",
        "login" => "Ingreso",
        "login_failed" => "Ingreso fallido",
        "logout" => "Salida",
        "case_created" => "Expediente abierto",
        "case_dismissed" => "Expediente descartado",
        "detection_attached" => "Detección agregada al expediente",
        "detection_unreadable" => "Detección ilegible",
        "judge_notified" => "Juez notificado",
        "case_approved" => "Bloqueo aprobado",
        "case_rejected" => "Pedido rechazado",
        "case_reassigned" => "Expediente pasado al juez entrante",
        "order_signed" => "Orden firmada",
        "order_sent" => "Orden enviada",
        "order_send_error" => "Error al enviar la orden",
        "order_applied" => "Orden aplicada",
        "order_failed" => "Orden fallida",
        "order_rejected" => "Orden rechazada",
        "order_expired" => "Orden vencida",
        "order_lifted" => "Orden levantada",
        "order_abandoned" => "Orden sin enviar",
        "order_retry_signed" => "Reenvío firmado",
        "retry_awaiting_signature" => "Reenvío esperando firma",
        "retry_skipped" => "Reenvío omitido",
        "lift_signed" => "Levantamiento firmado",
        "claim_received" => "Reclamo recibido",
        "claim_approved" => "Reclamo aceptado",
        "claim_rejected" => "Reclamo rechazado",
        "claim_closed" => "Reclamo cerrado",
        "claim_reassigned" => "Reclamo pasado al juez entrante",
        "trace_started" => "Rastreo iniciado",
        "trace_page_without_video" => "Página sin video para rastrear",
        "trace_stop_requested" => "Rastreo detenido a pedido",
        "trace_finished" => "Rastreo terminado",
        "leak_identified" => "Cuenta de origen identificada",
        "leak_notice_sent" => "Aviso enviado a la plataforma",
        "leak_notice_acknowledged" => "Cuenta suspendida por la plataforma",
        "leak_notice_rejected" => "Aviso rechazado por la plataforma",
        "leak_notice_failed" => "Aviso sin respuesta",
        "leak_platform_unknown" => "Marca de una plataforma no registrada",
        "leak_source_cut" => "Fuente cortada",
        "leak_mark_still_on_air" => "La marca sigue al aire",
        "account_created" => "Usuario creado",
        "account_updated" => "Perfil editado",
        "account_password_changed" => "Contraseña cambiada",
        "account_disabled" => "Usuario deshabilitado",
        "account_enabled" => "Usuario habilitado",
        "account_sessions_closed" => "Sesiones cerradas",
        "account_deleted" => "Usuario eliminado",
        "platform_created" => "Plataforma registrada",
        "platform_updated" => "Plataforma editada",
        "platform_deleted" => "Plataforma quitada",
        "access_requested" => "Pedido de acceso",
        "access_request_approved" => "Pedido de acceso aprobado",
        "access_request_rejected" => "Pedido de acceso rechazado",
        "password_recovery_requested" => "Pedido de recuperación de acceso",
        "password_link_issued" => "Enlace para elegir contraseña generado",
        "password_set_by_link" => "Contraseña elegida con el enlace",
        "platform_integration_updated" => "Integración de plataforma actualizada",
        other => return other.to_string(),
    };
    text.to_string()
}

/// Why a loaded stream could not be taken (`intake::ItemError` codes and lookup failures).
pub fn intake_error(code: &str) -> &'static str {
    match code {
        "invalid_stream_url" => "La dirección del stream no es válida (tiene que empezar con http:// o https://).",
        "invalid_watermark" => "La marca de agua tiene caracteres que no corresponden.",
        "invalid_page" => "La página del reproductor no es una dirección válida.",
        "invalid_ip" => "La IP del servidor no es válida.",
        "repeated" => "Este stream ya estaba en la lista.",
        "too_many" => "Se cargan hasta 200 streams por vez: el resto quedó afuera.",
        "unreadable_json" => "El JSON no se puede leer.",
        "empty" => "No hay nada para cargar.",
        "server_unknown" => "No hay registros del servidor en el DNS pasivo: indicá su IP.",
        "dns_unavailable" => "No se pudo consultar el DNS pasivo. Probá de nuevo en un momento.",
        "match_not_ready" => "El partido todavía no está conectado.",
        _ => "No se pudo cargar.",
    }
}

/// How a detection reached the platform, for people.
pub fn origin(raw: &serde_json::Value) -> Option<String> {
    match raw.get("origen").and_then(serde_json::Value::as_str) {
        Some(crate::intake::ORIGIN_MANUAL) => Some(match raw.get("cargado_por").and_then(serde_json::Value::as_str) {
            Some(user) => format!("cargado por @{user}"),
            None => "cargado a mano".to_string(),
        }),
        Some(crate::intake::ORIGIN_API) => Some("cargado por la API de monitoreo".to_string()),
        _ => None,
    }
}

/// Match time the way football shows it: `27'`.
pub fn minute(m: f64) -> String {
    format!("{}'", m.max(0.0).floor() as i64)
}

/// A length of match time in words: `45 s`, `1 min 30 s`, `25 min`, `1 h 5 min`.
pub fn span(minutes: f64) -> String {
    let secs = (minutes.max(0.0) * 60.0).round() as i64;
    if secs < 60 {
        return format!("{secs} s");
    }
    if secs < 600 {
        return match (secs / 60, secs % 60) {
            (m, 0) => format!("{m} min"),
            (m, s) => format!("{m} min {s} s"),
        };
    }
    match ((secs + 30) / 60 / 60, (secs + 30) / 60 % 60) {
        (0, m) => format!("{m} min"),
        (h, 0) => format!("{h} h"),
        (h, m) => format!("{h} h {m} min"),
    }
}

/// Until when a block holds, from its expiry minute and the minute the match ends.
pub fn until(expires_min: i64, match_end: i64) -> String {
    match expires_min - match_end {
        0 => "hasta el final del partido".to_string(),
        extra if extra > 0 => format!("hasta {} después del final", span(extra as f64)),
        _ => format!("hasta el {}", minute(expires_min as f64)),
    }
}

/// The same, short enough for a table cell: `Final del partido`.
pub fn until_short(expires_min: i64, match_end: i64) -> String {
    match expires_min - match_end {
        0 => "Final del partido".to_string(),
        extra if extra > 0 => format!("{} después del final", span(extra as f64)),
        _ => minute(expires_min as f64),
    }
}

/// A judge's shift in words: `Desde antes del inicio hasta el 50'`.
pub fn shift(from: f64, until: f64, match_end: f64) -> String {
    let start = if from <= 0.0 { "Desde antes del inicio".to_string() } else { format!("Desde el {}", minute(from)) };
    let end = if until >= match_end { "hasta el final".to_string() } else { format!("hasta el {}", minute(until)) };
    format!("{start} {end}")
}

/// Minute the match ends, rounded up the way IP blocks expire (105 before the match is known).
pub fn match_end(store: &crate::model::Store) -> i64 {
    store.match_info.as_ref().map_or(105, |m| m.end_min.ceil() as i64)
}

/// Who did something, for people: `@laura`, the judge's name, `Strack (automático)`.
pub fn actor(store: &crate::model::Store, actor: &str) -> String {
    match actor.split_once(':') {
        Some(("user", name)) => format!("@{name}"),
        Some(("judge", id)) => store.judge_name(id),
        Some(("platform", id)) => format!("Plataforma {id}"),
        Some(("provider", id)) => store.provider(id).map_or_else(|| format!("Proveedor {id}"), |p| p.name.clone()),
        _ => match actor {
            "system" => "Strack (automático)".to_string(),
            "api" => "API de monitoreo".to_string(),
            "public" => "Público".to_string(),
            other => other.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use crate::web::labels::{minute, shift, span, until, until_short};

    #[test]
    fn match_time_reads_like_football() {
        assert_eq!(minute(2.0), "2'");
        assert_eq!(minute(27.9), "27'");
        assert_eq!(minute(-3.0), "0'");
        assert_eq!(span(0.5), "30 s");
        assert_eq!(span(1.5), "1 min 30 s");
        assert_eq!(span(25.3), "25 min");
        assert_eq!(span(65.0), "1 h 5 min");
    }

    #[test]
    fn expiry_and_shifts_in_words() {
        assert_eq!(until(105, 105), "hasta el final del partido");
        assert_eq!(until(135, 105), "hasta 30 min después del final");
        assert_eq!(until_short(105, 105), "Final del partido");
        assert_eq!(shift(-60.0, 50.0, 105.0), "Desde antes del inicio hasta el 50'");
        assert_eq!(shift(50.0, 240.0, 105.0), "Desde el 50' hasta el final");
    }
}
