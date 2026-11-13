# CLAUDE.md

Guidance for agents working on **Strack**, the hackathon MVP of a federal platform for live blocking
orders against pirate football streams (Hackathon Argentina Space 2026, track "Datos y Streaming",
challenge `qualydata-org/desafio-futbol`). `AGENTS.md` mirrors this file; keep both identical.

## What the platform must do (challenge rules that shape the code)

- Build a case file per pirate stream with verifiable evidence: watermark matches the match and is not
  a licensee on its own domain; stream server (host, IP, ASN); collateral rule (shared IP → block by
  domain); capture hashes and timestamps.
- The judge on duty logs in, reviews and signs. **The platform signs with a judge's key only after that
  judge logged in and approved.** At a shift change pending work passes to the incoming judge and the
  outgoing judge can no longer sign.
- Send the order to every provider in the type it accepts, follow confirmation, retry failures with a
  **new `orden_id`**, let IP blocks expire at the end of the match, keep an audit log of every step.
- The official evaluator (`evaluacion/verificar.py` in the challenge repo) scores: time to first block
  per phase, client coverage, residual visibility, collateral damage, false positives, IP blocks
  after the match, claims lifted, rejected orders and orders signed off duty. Optimise for those.

## Architecture

Single Rust crate (`edition = 2024`), binary `strack` with subcommands `serve`, `enroll`, `verify`,
`export`, `trace` and `demo platform|pirate` (`src/cli.rs`).

| Module | Responsibility |
|---|---|
| `simulator.rs` | HTTP client and wire types. Simulator field names are Spanish; serde renames map them to English identifiers. Only module that talks to the simulator. |
| `evidence.rs` | Watermark check, collateral analysis, server and capture evidence, per-provider plan. Pure functions with unit tests. |
| `model.rs` | Persisted state: `Store`, `Case`, `OrderRecord`, `Claim`. |
| `workflow.rs` | All state transitions (ingest, approve/reject, sign, retries, provider sync, claims, handover, registry). Pure over `Core`; the only side effect is the audit log. |
| `app.rs` | `App` (settings, accounts, sessions, desk) and one `MatchRun` per `--simulator`: its `SimClient`, `Core`, dispatcher `Notify` and state folder (`match_state_dir`: the first match uses `--state-dir`, match n `match-<n>/`). `App::core()` is the first match, which also holds platform-wide records (sign-ins, admin, leak traces). |
| `engine.rs` | Async loops per match: bootstrap, poller (status, detections, orders, claims) and dispatcher (parallel POSTs). `engine::ingest` is the one path from a detection to a case (feed, intake form, intake API). |
| `standalone.rs` | Matches without the simulator: `StandaloneConfig` (match, courts and shifts, providers with `api_url`, optional passive DNS) and `MatchSource` (`Simulator` or `Standalone`), the one interface the engine uses (`MatchRun.sim`). Standalone: wall clock from kick-off, no detection or claims feed (intake only), orders to each provider's API in the simulator's wire format. Unit-tested. |
| `provider.rs` | `strack provider`: reference order receiver for a provider (orders on disk, status, lift, expiry at `vence_min`, `--hook` per action). `--gateway <addr>` also runs the provider's network edge: an HTTP proxy for its subscribers that enforces the applied orders itself (451 block page with `--name`; a response already streaming is cut as soon as an order covers its host or IP). Unit-tested matching. |
| `intake.rs` | Streams loaded by hand or by monitoring tools: parses text/CSV/JSON into items (unit-tested) and builds the feed-format detection, which records `origen` and `cargado_por`. A stream loaded without a watermark is read first (`web/intake.rs` `read_then_load`, `leak::read`): a session mark of a registered platform that is a licensee's `plataforma` becomes `<prefijo_marca>-S<session>`, the frame becomes the `captura` and `marca_leida` keeps the raw mark; no notice is sent unless "Rastrear" is ticked. The server IP is the host when it is an address, else passive DNS, else the system resolver. |
| `judges.rs` | Accounts, Argon2id passwords, sealed signing keys (Argon2id + ChaCha20-Poly1305), sessions, shifts. |
| `audit.rs` | Append-only, hash-chained JSONL log and its verifier. |
| `crypto.rs` | SHA-256, HMAC (simulator demo signatures), canonical JSON. |
| `export.rs` | Delivery files (`entrega/`) and case-file verification. |
| `admin.rs` | Account and platform-registry management: validation and guards (no self-action, never zero enabled admins, a judge's role is fixed to their sealed key). Unit-tested. |
| `access.rs` | Getting in without an account or a password: access requests (saved in the state dir), recovery requests and one-time password links (hashed, memory only, 30 min, one use). Nothing is mailed: the admin hands the link over. Unit-tested. |
| `web/` | axum + maud server-rendered UI: public registry, login, access and recovery requests and the one-time link page (`recovery.rs`), judge panel, operations board, leak tracing, reference pages (`reference.rs`), stream intake (`intake.rs`), the licensed platforms' portal (`platform.rs`), administration (`admin.rs`), own account (`account.rs`), shared parts (`ui.rs`: page header, figure tiles, dialogs, pager), JSON APIs. |
| `leak/` | Leak tracing (our extra): `source.rs` (frames from MJPEG/JPEG natively or from HLS, DASH, MP4, TS, WebM, RTMP through ffmpeg, network protocols only), `discover.rs` (finds the streams in a pirate page and its iframes), `read.rs` (one-off mark reading for intake: no record, no notice), `marker.rs` (`strack mark` and reading marks from video files), `mark.rs` (`STK2` session mark: platform code, subscriber, 32-bit session, CRC-32; 120 bits), `watermark.rs` (invisible watermark: embed and detector), `raster.rs` + `scene.rs` (synthetic broadcast and optional visible QR), `jpeg.rs` (COM segment), `mjpeg.rs` (multipart writer/reader), `extract.rs` (QR + metadata), `platforms.rs` (registry and notice client), `trace.rs` (trace model and runner). |
| `demo/` | Demo licensed platform and pirate restream servers (`strack demo platform`, `strack demo pirate`); `video.rs` feeds real footage through ffmpeg (`--video`: native size and rate, every frame, on the wall clock, ends with the file unless `--loop`), `encoder.rs` turns a session into live H.264 fMP4 for a `<video>` player. Subscriber accounts live in `accounts.rs` (directory saved to `--data`, browser sessions, one-time links, the demo mailbox that stands in for email), the subscriber side in `site.rs` (sign-up, sign-in, recovery, "Mi cuenta", player) and the staff console in `staff.rs` (subscriber CRUD). Not part of the challenge circuit. |

Locking: each `MatchRun.core` (store + audit + clock), `App.sessions` and `App.desk` (access requests
and password links) are separate `std::sync::Mutex`es. Never hold a guard across `.await` and never hold
two at once (take signing keys from `sessions` first, then lock a core; read leak traces from the first
match before locking a case's match, since it may be the same lock). Find a case's match with
`App::match_of_case`, a claim's with `App::match_of_claim` (claim ids may repeat across matches, so
claim links carry `?partido=`). Leak traces run as their own
tasks and lock `core` briefly per frame; frame decoding and QR detection run in `spawn_blocking`.

## Conventions

- Everything technical in English (code, comments, logs, CLI, commits, docs). Spanish only for
  end-user content: UI copy (`web/labels.rs`, views), the lift reason sent to providers, and
  `entrega/propuesta-normativa.md`.
- Imports use absolute `crate::` paths, never `super::` (the Rust equivalent of the global "no relative
  imports" rule), including inside `#[cfg(test)]` modules.
- Hashes are always computed over `crypto::canonical_json` (keys sorted recursively).
- Order ids: `o{run_id}-{case_tail}-{provider}-{attempt}`; unique per provider and per platform run.
- Roles: `judge` (judge panel), `operator` (operations), `admin` (also `/admin/*`), `platform` (a
  licensed platform's account, bound to `platform_id`; `web::client_scope` keeps it out of `/ops`,
  `/judge`, `/admin`, `/api/cases`, `/api/audit`, so it only reaches `/platform`, `/account` and public
  pages; its role never changes, like a judge's). Admin handlers change a
  copy of the accounts or platforms file, save it, and only then swap it in (`change_accounts`,
  `change_platforms`), so memory and disk never disagree; audit entries never carry passwords,
  keys or tokens.
- UI patterns: page header with the main action on the right, figure tiles before tables (a tile
  that counts a list links to it), a filter toolbar (GET, works without script), create in a
  `<dialog>` whose opener is also a link to a no-script page, destructive actions on the detail page
  behind a required confirmation checkbox. Buttons step 1px on hover and press on click; linked
  tiles lift 2px (motion tokens in `assets/app.css`). No violet anywhere.
- Keep workflow logic out of handlers; handlers check session + CSRF, call `workflow::*`, notify the
  dispatcher, persist and redirect with a `?msg=` / `?error=` code mapped in `labels::message`.
- No secrets in clear in the repo: `config/accounts.json` holds Argon2 hashes and sealed keys only.
  Demo passwords are documented in the README (allowed by the challenge rules).

## UI and accessibility (WCAG 2.2 AA is a requirement)

- Semantic landmarks, skip link, one `h1` per page, tables with `caption` and `th scope`, scrollable
  table wrappers focusable (`tabindex="0"`, `role="region"`, `aria-label`).
- Visual design after the "Nebula" reference the team chose (a Dribbble dashboard): grey canvas
  (`--canvas`) holding the sidebar, each page on a white rounded sheet (`.sheet`) with a sticky top bar,
  white cards with a hairline border whose first `h2` is a header row, black primary buttons, and three
  data colours used only as fills: coral, black (light grey in dark mode) and amber, with hatched
  variants (`--hatch-*`) for bars. Text is always `--ink` or `--muted` (AA on canvas and sheet). System
  sans stack (Inter / Segoe UI), IBM Plex Mono self-hosted for numbers and ids. Light and dark tokens;
  the theme follows the system until the person picks one with the top-bar switch (`data-theme` on
  `<html>`, kept in `localStorage`).
- Brand: `layout::BRAND_MARK` is the Strack mark (two chevrons interlocking into an S, the second
  one turned half a turn, `viewBox 0 0 267 190`) drawn in `currentColor` next to the lowercase
  wordmark "strack" (800 weight); `/favicon.svg` serves it white on a coral tile.
- Type: uppercase only for sidebar section headings and the eyebrow; labels 13px at 500 in
  `--muted`, body 15px, figures (`--t-stat`) 26px.
- Three shells in `web/layout.rs`: `page` gives people signed in the app shell (sidebar sections,
  white active pill, the live match card with a 24-segment bar at its foot, account row; top bar with
  the live chip, the "Entorno de prueba" tag and the theme switch) and visitors the public site (top
  navigation, no sidebar); `auth_page` is the split sign-in screen (dark product panel with hatched
  bars, form card) used by login, access requests, recovery and one-time links. Every clock element
  carries `data-clock-*` and `assets/app.js` fills all of them. Below 1024px the sidebar becomes a top
  bar whose nav scrolls in its own strip; below 900px the sign-in screen stacks.
- Charts: `views::ring` (SVG ring with the total in the middle, legend) and `progress.bar` (hatched
  bars). The CSP forbids inline styles, so sizes go through SVG attributes or `<progress>` values,
  never `style=`.
- Status is always text; colour only reinforces it. Screen-reader-only text inside buttons relies on
  `.button` and `.table-wrap` being positioned, or it escapes scrolling tables and widens the page.
- Visible `:focus-visible`, targets ≥ 40px (WCAG 2.2 AA asks 24), labels on every input, `aria-live` announcements for new
  inbox items, reduced-motion respected, no inline scripts or styles (strict CSP).
- Desktop and phone: check 1366/1920 widths and 360–414px. The case page shows the decision column
  first in reading order and on the right on wide screens.
- Live regions (`data-refresh`) never replace content while focus is inside a form.
- Copy reads like a product, not like the challenge statement: no numbered sections that mirror the
  rules, no simulator, hackathon or "(demo)" wording (the match bar carries an "Entorno de prueba" tag
  instead), no raw ids like `judge:<id>` or `case_id=` (use `labels::actor` and the audit `summary`).
  Match time is football style through `labels::minute` (`27'`), lengths through `labels::span`
  (`25 min`), expiry through `labels::until`/`until_short` ("hasta el final del partido") and shifts
  through `labels::shift`. The case page opens with "Qué se verificó" (one check per finding); hashes
  live in the folded "Detalle técnico" block.

## Verify before finishing

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release
```

End-to-end: run the challenge simulator (`python -X utf8 simulador/servidor.py --acelerar 30`),
`strack serve`, approve as the demo judges, then `python -X utf8 evaluacion/verificar.py` and
`strack verify --audit var/audit.jsonl`. On Windows the simulator needs `-X utf8` (it prints "≈").

UI: with the demo running (`scripts/demo.ps1`) and a headless Chrome on port 9333, `node scripts/ui-audit.mjs`
checks 10 pages at 390 and 1366 px in both themes: no horizontal overflow, no text below AA contrast
(`--selftest` proves the contrast check fires). Screenshots land in `var/ui-audit/shots/`.

Live demo (nothing scripted): `scripts/demo.ps1 -Live [-Video <local file> -Audio <file> -VideoStart <s>]`
runs the standalone match on the wall clock (kick-off `-VideoStart` seconds ago so the clock follows the
recording), the pirate on its own loopback address `127.0.0.2:8200`, the four receivers with Aurora's
network edge on `127.0.0.1:9180`, and a Chrome window (profile `var/demo/viewer`) of an Aurora
subscriber watching the pirate through it. As `fiscalia` load `http://127.0.0.2:8200/`: the case opens
within seconds with the TV Ficticia Play licensee watermark; once a judge approves, the viewer's stream
stops and a reload shows the 451 block page; loading again with "Rastrear" suspends the accounts.

Leak tracing: `strack demo platform`, `strack demo pirate`, `strack serve`, then trace
`http://127.0.0.1:8200/stream.mjpg` from `/ops/traces` (or `strack trace <url>` for a read-only check).
Expect each pirate account identified, acknowledged (`suspended`) and cut, and the audit chain valid.
The same through the client side: create a `platform` account for `tvf`, load
`http://127.0.0.1:8200/stream.mjpg, 127.0.0.1` in Cargar sitios with "Rastrear" ticked, and the portal
lists the accounts as suspended. `strack mark` + `strack trace <file>` check marking offline (outputs
under `var/`; never commit third-party footage).

## Gotchas

- The simulator's `desde` cursor for detections is exact; for claims the platform re-reads a 2-minute
  overlap and deduplicates by id (claims are emitted with a past minute).
- A judge stops signing `--shift-margin-min` (0.1) match minutes before the shift ends so no order
  arrives off duty; pending work goes to the incoming judge.
- Retries of a failed order are signed automatically only by the judge who approved the case, while on
  duty with a live session; otherwise they wait in the on-duty judge's inbox.
- `vence_min` must be an integer greater than the current minute; IP blocks use `ceil(fin_min)`.
- Floats in anything that is hashed (detections, audit data) are rounded to three decimals: longer
  ones do not survive a JSON round trip exactly in `serde_json`, and the stored JSON is re-hashed by
  `strack verify` and the case integrity check (a loaded detection once broke a chain this way).
- Security rules kept in code: the platform portal accepts a new notice `api_url` only when it resolves
  to public IPs (`leak::platforms::public_ip`, tested, IPv4 inside IPv6 included) and marks it
  `api_url_from_platform`; `send_notice` then resolves again, refuses non-public addresses and pins the
  connection to them (`resolve_to_addrs`), and never follows redirects (admin-set addresses may be
  internal); `login_failed` never records a
  username that has no account; a judge reaches an approved case through pending retries only while
  holding the duty.
- The stream reader (traces, Cargar sitios' mark reading, embedded players found by `discover`) only
  opens addresses `source::readable_target` allows: http(s) or rtmp(s), and every resolved address
  public, checked again on every reconnection. `serve --allow-private-streams` (env
  `STRACK_ALLOW_PRIVATE_STREAMS`) lifts the public-address rule for local demos only; `demo.ps1`
  passes it because the demo pirate and platform live on loopback. Read errors go to the log, not to
  the audit trail. The rule also holds while connecting: `source::reader_client` (the shared
  `App.http`, used only by the stream reader) resolves through `PublicOnly`, which drops non-public
  addresses, and follows a redirect only to http(s) on a name or a public address. ffmpeg resolves and
  follows playlists on its own, so production also denies private ranges at the network edge.
- Tracer inputs: `trace::start_from` probes the address (`source::probe`): an HTML page goes through
  `discover` and gets one trace per stream found (`Trace.page_url`); anything else is a stream whose
  format (`Trace.format`) picks the reader. ffmpeg runs with `-re` (stream pace), `-protocol_whitelist`
  (never `file`), `kill_on_drop`, and a 20 s first-frame timeout. A progressive MP4 needs its index
  first (`strack mark` writes `+faststart`) or a server with Range requests: Python's `http.server`
  has none, so a test MP4 served by it reads 0 frames. A VOD stream is read again from the start when
  it ends, until the trace is stopped or hits its 4 h limit.
- Several matches: every match-scoped page takes `?partido=<n>` and marks it with `data-match-key` so
  the bottom bar shows that match's clock; `ui::match_tabs` renders the switcher (nothing for one match).
- The repo lives in a OneDrive folder: state snapshots retry on the next tick if the rename fails.
- Every subcommand is the same `strack.exe`: on Windows a running instance (`serve`, `demo platform`,
  `demo pirate`) locks it and `cargo build --release` fails to link. Stop them, or move the running
  file aside first (`mv target/release/strack.exe target/release/strack-old.exe`: a running image can
  be renamed, not overwritten) and restart them on the new build.
- Live demo: Windows does not resolve `*.localhost` names, so the pirate gets its own loopback
  address (`127.0.0.2`) instead of a name; Chrome skips proxies for loopback unless started with
  `--proxy-bypass-list=<-loopback>`. `Start-Process -ArgumentList` with an array does not quote, so
  values with spaces (provider names, video paths) carry explicit quotes in `demo.ps1`. Never pipe the
  demo script's output: the viewer Chrome inherits the pipe and the command never returns.
- Pirate player with sound: muxing the pirate's reworked frames with the sound of a second HTTP
  session stalled the browser (two clocks; the muxer holds video waiting for audio). The page's
  `/stream.mp4` therefore relays the stolen account's own MP4 session as it arrives (picture and sound
  from the platform's encoder, in sync) and the page script asks again when it ends; `/stream.mjpg`
  stays the reworked copy (resized, logo, banner). The reconnect script builds its address from the
  `<video>` element so `discover` does not take it for another stream.
- H.264 on the GPU: `demo/encoder.rs` uses `h264_nvenc` (low-latency, no B-frames) when
  `STRACK_H264_ENCODER=h264_nvenc`; `demo.ps1` sets it when `nvidia-smi` exists and ffmpeg lists NVENC.
  Consumer NVIDIA cards cap concurrent NVENC sessions, which a demo stays well under.
- If port 8080 is taken on the machine, run the simulator with `--puerto <other>` and point
  `serve --simulator` at it.
- Leak tracing: the invisible watermark is read from frames `PERIOD_SECS / 2` (1 s) apart, so the
  scanner must keep its history across frames (`extract::Scanner` is moved in and out of
  `spawn_blocking`). A cut is confirmed only after the mark has been missing for `CUT_AFTER` (12 s) or
  another session is on the air; keep `CUT_AFTER` well above the gaps between watermark reads.
- `leak::watermark` tests are the contract: at most 2 levels per pixel and PSNR > 40 dB at the peak,
  decoding after the demo pirate's transform (80 % size, JPEG 55, corner logo, banner) at every phase,
  through crops (symmetric and not) and mirroring (`found_through_crop_and_mirror`), and no false
  positive on an unmarked stream. `cargo test --release -- --ignored --nocapture robustness` prints
  the full attack table used in the README.
- The CRC-32 in `mark.rs` is what makes Chase decoding safe (Hamming distance 6 on 88 data bits;
  `up_to_three_flipped_bits_are_always_rejected`). Never shorten it: with a 16-bit CRC, Chase decoding
  produced hybrid marks under collusion. Chase decoding only runs when the accepted platform codes
  are known (`Scanner::new(codes)`).
- Demo platform pages (`demo/site.rs`, `demo/staff.rs`): `platform::page` locks the state for the
  subscriber's name, so build the body inside a block that drops the state guard, then render. A
  stream (`/live/<id>.mp4|.mjpg`) is served only to its owner's browser session, the staff, or the key
  returned by `POST /api/sessions` (the demo pirate signs in with the demo password). Testing forms
  with curl on Windows: curl reads arguments in the ANSI code page, so percent-encode UTF-8 yourself
  (`Fútbol` otherwise arrives as `%FA` and fails validation).
- Live video with sound (`demo/encoder.rs`): the sound is read from the file by ffmpeg and never skips,
  so the picture must never skip either. The encoder must not wait for a paused player (its output
  queues in memory, `MAX_PENDING_BYTES`), and a viewer that lags the broadcast repeats its last picture
  instead of dropping frames; otherwise a 30 s pause left picture and sound 25 s apart.
- Real footage: `real_footage_diagnostics` (ignored) prints per-pair motion and bit errors for a folder
  of 960x540 JPEG frames at 8 fps (`STRACK_FRAMES_DIR`, extract them with ffmpeg). Never commit
  third-party footage or frames; `--video` reads a local file only. Changing chip size, strength, period or payload length
  needs them green. The grass texture in `scene.rs` is static, so it never affects detection.
