//! Page shells: the app (sidebar on the grey canvas, the page on a white sheet with its top bar and the
//! live match chip), the public site for visitors (top navigation, no sidebar) and the split sign-in
//! screen used by login, access requests, recovery and one-time links.

use maud::{DOCTYPE, Markup, PreEscaped, html};

use crate::judges::{Role, Session};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Nav {
    Registry,
    Judge,
    Ops,
    Intake,
    Traces,
    Providers,
    Courts,
    Audit,
    Users,
    Platforms,
    Account,
    Portal,
    Guide,
    None,
}

fn current(active: Nav, item: Nav) -> Option<&'static str> {
    (active == item).then_some("page")
}

/// Line icons (24px grid, stroke follows the text colour). Decorative: the label is always visible.
fn icon(paths: &'static str) -> Markup {
    html! {
        svg class="icon" viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor"
            stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false" {
            (PreEscaped(paths))
        }
    }
}

const ICON_REGISTRY: &str = r#"<path d="M9 6h11M9 12h11M9 18h11"/><path d="M4.5 6h.01M4.5 12h.01M4.5 18h.01"/>"#;
const ICON_JUDGE: &str = r#"<path d="M12 4v16M8 20h8M5 7h14"/><path d="M5 7 2.5 13a3 3 0 0 0 5 0Z"/><path d="M19 7l-2.5 6a3 3 0 0 0 5 0Z"/>"#;
const ICON_OPS: &str = r#"<path d="M3 12h4l3-7 4 14 3-7h4"/>"#;
const ICON_TRACE: &str = r#"<circle cx="12" cy="12" r="8.5"/><circle cx="12" cy="12" r="4.5"/><path d="M12 12 18 6"/>"#;
const ICON_INTAKE: &str =
    r#"<path d="M12 15V4M7.5 8.5 12 4l4.5 4.5"/><path d="M4 14v4a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-4"/>"#;
const ICON_PROVIDERS: &str = r#"<path d="M4 7h16v4H4zM4 13h16v4H4z"/><path d="M7.5 9h.01M7.5 15h.01"/>"#;
const ICON_COURTS: &str = r#"<path d="M3 10 12 4l9 6"/><path d="M5 10v8M9 10v8M15 10v8M19 10v8M3 20h18"/>"#;
const ICON_AUDIT: &str = r#"<path d="M7 3h7l5 5v13H7z"/><path d="M14 3v5h5"/><path d="m10 14 2 2 4-4"/>"#;
const ICON_USERS: &str = r#"<circle cx="9" cy="8" r="3.5"/><path d="M2.5 20a6.5 6.5 0 0 1 13 0"/><path d="M16 4.6a3.5 3.5 0 0 1 0 6.8M18 14a6.5 6.5 0 0 1 3.5 6"/>"#;
const ICON_PLATFORMS: &str =
    r#"<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/><path d="m10 8 4 2-4 2z"/>"#;
const ICON_LOGOUT: &str = r#"<path d="M10 4H6a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h4"/><path d="m15 16 4-4-4-4M19 12H9"/>"#;
/// Brand mark: a stream (play symbol) inside a viewfinder, the stream Strack locks onto.
const ICON_MOON: &str = r#"<path d="M20 14.5A8 8 0 1 1 9.5 4a6.5 6.5 0 0 0 10.5 10.5Z"/>"#;
const ICON_SUN: &str = r#"<circle cx="12" cy="12" r="4"/><path d="M12 2.5v2M12 19.5v2M2.5 12h2M19.5 12h2M5.3 5.3l1.4 1.4M17.3 17.3l1.4 1.4M5.3 18.7l1.4-1.4M17.3 6.7l1.4-1.4"/>"#;
const ICON_BRAND: &str = r#"<path d="M4 9V5.5A1.5 1.5 0 0 1 5.5 4H9M15 4h3.5A1.5 1.5 0 0 1 20 5.5V9M20 15v3.5a1.5 1.5 0 0 1-1.5 1.5H15M9 20H5.5A1.5 1.5 0 0 1 4 18.5V15"/><path d="m10 8.5 5.5 3.5-5.5 3.5z"/>"#;

fn nav_item(href: &str, label: &str, paths: &'static str, active: Nav, item: Nav) -> Markup {
    html! {
        li {
            a href=(href) aria-current=[current(active, item)] {
                (icon(paths))
                span { (label) }
            }
        }
    }
}

fn initials(name: &str) -> String {
    name.split_whitespace()
        .filter(|w| w.chars().next().is_some_and(char::is_alphabetic))
        .filter_map(|w| w.chars().next())
        .take(2)
        .collect::<String>()
        .to_uppercase()
}

fn role_label(role: Role) -> &'static str {
    match role {
        Role::Judge => "Juez",
        Role::Operator => "Operaciones",
        Role::Admin => "Administración",
        Role::Platform => "Plataforma",
    }
}

/// Segments of the live match bar in the sidebar card (filled as the match goes on).
const MATCH_SEGMENTS: usize = 24;

fn head(title: &str) -> Markup {
    html! {
        head {
            meta charset="utf-8";
            meta name="viewport" content="width=device-width, initial-scale=1";
            meta name="color-scheme" content="light dark";
            title { (title) " · Strack" }
            link rel="stylesheet" href="/static/app.css";
            script src="/static/app.js" defer {}
        }
    }
}

fn brand() -> Markup {
    html! {
        a class="brand" href="/" {
            span class="brand-mark" { (icon(ICON_BRAND)) }
            span class="brand-word" { "Strack" }
        }
    }
}

/// The live match: teams, clock and state, filled in by `app.js` from `/api/clock`.
fn live_chip() -> Markup {
    html! {
        p class="live-chip" {
            span class="live-dot" data-clock-state { "Partido" }
            span class="live-teams" data-clock-teams {}
            span class="clock" {
                span class="visually-hidden" { "Reloj del partido: " }
                span data-clock-value { "—" }
            }
        }
    }
}

fn env_tag() -> Markup {
    html! { span class="env-tag" title="Los datos son de prueba: no se bloquea nada real." { "Entorno de prueba" } }
}

/// Any page: the app shell for people signed in, the public site for visitors.
pub fn page(title: &str, session: Option<&Session>, active: Nav, body: Markup) -> Markup {
    match session {
        Some(s) => app_page(title, s, active, body),
        None => site_page(title, active, body),
    }
}

fn app_page(title: &str, s: &Session, active: Nav, body: Markup) -> Markup {
    html! {
        (DOCTYPE)
        html lang="es" {
            (head(title))
            body class="app" {
                a class="skip-link" href="#main" { "Saltar al contenido" }
                div class="shell" {
                    aside class="sidebar" {
                        div class="sidebar-head" { (brand()) }
                        nav class="sidenav" aria-label="Principal" {
                            @if s.role == Role::Platform {
                                p class="nav-heading" aria-hidden="true" { "Mi plataforma" }
                                ul class="nav" {
                                    (nav_item("/platform", "Portal", ICON_PLATFORMS, active, Nav::Portal))
                                    (nav_item("/platform/guide", "Guía de integración", ICON_AUDIT, active, Nav::Guide))
                                    (nav_item("/", "Transparencia", ICON_REGISTRY, active, Nav::Registry))
                                }
                            } @else {
                                p class="nav-heading" aria-hidden="true" { "Partido en vivo" }
                                ul class="nav" {
                                    @if s.role == Role::Judge {
                                        (nav_item("/judge", "Panel del juez", ICON_JUDGE, active, Nav::Judge))
                                    }
                                    (nav_item("/ops", "Operaciones", ICON_OPS, active, Nav::Ops))
                                    @if s.role != Role::Judge {
                                        (nav_item("/ops/intake", "Cargar sitios", ICON_INTAKE, active, Nav::Intake))
                                    }
                                    (nav_item("/ops/traces", "Rastreo de origen", ICON_TRACE, active, Nav::Traces))
                                }
                                p class="nav-heading" aria-hidden="true" { "Consulta" }
                                ul class="nav" {
                                    (nav_item("/", "Transparencia", ICON_REGISTRY, active, Nav::Registry))
                                    (nav_item("/ops/providers", "Proveedores", ICON_PROVIDERS, active, Nav::Providers))
                                    (nav_item("/ops/courts", "Juzgados y turnos", ICON_COURTS, active, Nav::Courts))
                                    (nav_item("/ops/audit", "Auditoría", ICON_AUDIT, active, Nav::Audit))
                                }
                                @if s.role == Role::Admin {
                                    p class="nav-heading" aria-hidden="true" { "Administración" }
                                    ul class="nav" {
                                        (nav_item("/admin/users", "Usuarios", ICON_USERS, active, Nav::Users))
                                        (nav_item("/admin/platforms", "Plataformas", ICON_PLATFORMS, active, Nav::Platforms))
                                    }
                                }
                            }
                        }
                        section class="side-match" aria-label="Partido en vivo" {
                            p class="side-match-title" { span data-clock-state { "Partido" } }
                            p class="side-match-teams" data-clock-teams {}
                            div class="segments" data-clock-segments aria-hidden="true" {
                                @for _ in 0..MATCH_SEGMENTS { span {} }
                            }
                            progress class="visually-hidden" data-clock-progress max="105" value="0" aria-label="Avance del partido" {}
                            p class="hint" data-clock-minute { "Esperando el reloj del partido" }
                        }
                        div class="account" {
                            a class="account-link" href="/account" aria-current=[current(active, Nav::Account)] {
                                span class="avatar" aria-hidden="true" { (initials(&s.display_name)) }
                                span class="account-text" {
                                    span class="account-name" { (s.display_name) }
                                    span class="account-role" { (role_label(s.role)) }
                                }
                            }
                            form method="post" action="/logout" {
                                input type="hidden" name="csrf" value=(s.csrf);
                                button class="icon-button" type="submit" title="Salir" {
                                    (icon(ICON_LOGOUT))
                                    span class="visually-hidden" { "Salir (" (s.display_name) ")" }
                                }
                            }
                        }
                    }
                    div class="sheet" {
                        header class="topbar" {
                            p class="topbar-title" { (title) }
                            div class="topbar-side" {
                                (live_chip())
                                (env_tag())
                                button class="icon-button theme-toggle" type="button" data-theme-toggle title="Cambiar entre tema claro y oscuro" {
                                span class="visually-hidden" { "Cambiar entre tema claro y oscuro" }
                                span class="theme-dark" aria-hidden="true" { (icon(ICON_MOON)) }
                                span class="theme-light" aria-hidden="true" { (icon(ICON_SUN)) }
                            }
                            }
                        }
                        main id="main" tabindex="-1" { (body) }
                    }
                }
                div class="visually-hidden" aria-live="polite" data-live {}
            }
        }
    }
}

fn site_page(title: &str, active: Nav, body: Markup) -> Markup {
    html! {
        (DOCTYPE)
        html lang="es" {
            (head(title))
            body class="site" {
                a class="skip-link" href="#main" { "Saltar al contenido" }
                header class="site-header" {
                    div class="site-bar" {
                        (brand())
                        nav class="site-nav" aria-label="Principal" {
                            a href="/" aria-current=[current(active, Nav::Registry)] { "Transparencia" }
                            a href="/access" { "Pedir acceso" }
                            a class="button primary" href="/login" { "Ingresar" }
                            button class="icon-button theme-toggle" type="button" data-theme-toggle title="Cambiar entre tema claro y oscuro" {
                                span class="visually-hidden" { "Cambiar entre tema claro y oscuro" }
                                span class="theme-dark" aria-hidden="true" { (icon(ICON_MOON)) }
                                span class="theme-light" aria-hidden="true" { (icon(ICON_SUN)) }
                            }
                        }
                    }
                }
                div class="site-live" { div class="site-bar" { (live_chip()) (env_tag()) } }
                main id="main" class="site-main" tabindex="-1" { (body) }
                footer class="site-footer" {
                    div class="site-bar" {
                        p { "Strack · órdenes de bloqueo en vivo con firma judicial, evidencia verificable y registro público." }
                    }
                }
                div class="visually-hidden" aria-live="polite" data-live {}
            }
        }
    }
}

/// The sign-in screen: the product on one side, the form on the other. Not a dashboard.
pub fn auth_page(title: &str, body: Markup) -> Markup {
    html! {
        (DOCTYPE)
        html lang="es" {
            (head(title))
            body class="auth" {
                a class="skip-link" href="#main" { "Saltar al contenido" }
                div class="auth-split" {
                    section class="auth-brand" aria-label="Strack" {
                        (brand())
                        div class="auth-pitch" {
                            p class="auth-kicker" { "Órdenes de bloqueo en vivo" }
                            p class="auth-headline" { "Del stream pirata al bloqueo confirmado, en minutos y con firma del juez." }
                            ul class="auth-points" {
                                li { "Evidencia verificable: marca de agua, servidor y huellas de cada captura." }
                                li { "El juez de turno decide desde el celular y la orden llega a todos los proveedores." }
                                li { "Cada paso queda en un registro público y encadenado." }
                            }
                        }
                        div class="auth-bars" aria-hidden="true" { span {} span {} span {} }
                        p class="auth-foot" { (env_tag()) }
                    }
                    main id="main" class="auth-main" tabindex="-1" {
                        div class="auth-card" { (body) }
                        p class="auth-back" { a href="/" { "Ver los bloqueos públicos" } }
                    }
                }
            }
        }
    }
}
