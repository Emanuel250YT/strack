// UI audit through the Chrome DevTools Protocol: phone (390 px) and desktop (1366 px) widths, light
// and dark themes, signed out and as the demo accounts. Reports horizontal overflow and text contrast
// below WCAG AA (4.5:1, 3:1 for large text) and saves screenshots to var/ui-audit/shots/.
// Needs a running demo (scripts/demo.ps1) and a headless Chrome with remote debugging on port 9333:
//   chrome --headless=new --remote-debugging-port=9333 --user-data-dir=var/ui-audit/profile about:blank
// Then: node scripts/ui-audit.mjs  (or --selftest, which must report the injected grey text).
import { writeFileSync, mkdirSync } from "node:fs";

const BASE = "http://127.0.0.1:3000";
const OUT = new URL("../var/ui-audit/shots/", import.meta.url);
mkdirSync(OUT, { recursive: true });

const version = await (await fetch("http://127.0.0.1:9333/json/version")).json();
const target = await (await fetch("http://127.0.0.1:9333/json/new?about:blank", { method: "PUT" })).json();
const ws = new WebSocket(target.webSocketDebuggerUrl);
await new Promise((r) => ws.addEventListener("open", r, { once: true }));
let seq = 0;
const pending = new Map();
const waiters = [];
ws.addEventListener("message", (ev) => {
  const msg = JSON.parse(ev.data);
  if (msg.id && pending.has(msg.id)) {
    pending.get(msg.id)(msg);
    pending.delete(msg.id);
  } else if (msg.method) {
    for (const w of waiters.splice(0)) w(msg);
  }
});
const send = (method, params = {}) =>
  new Promise((resolve) => {
    const id = ++seq;
    pending.set(id, resolve);
    ws.send(JSON.stringify({ id, method, params }));
  });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function navigate(url) {
  await send("Page.navigate", { url });
  await sleep(1500);
}
async function evaluate(expression) {
  const r = await send("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true });
  return r.result?.result?.value;
}

await send("Page.enable");
await send("Runtime.enable");

const CHECK = `(() => {
  const parse = (c) => { const m = c && c.match(/rgba?\\(([^)]+)\\)/); if (!m) return null; const p = m[1].split(',').map(Number); return { r: p[0], g: p[1], b: p[2], a: p.length > 3 ? p[3] : 1 }; };
  const lum = ({ r, g, b }) => { const f = (v) => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); }; return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b); };
  const bgOf = (el) => {
    for (let e = el; e; e = e.parentElement) {
      const cs = getComputedStyle(e);
      if (cs.backgroundImage !== 'none') return null;
      const c = parse(cs.backgroundColor);
      if (c && c.a > 0.5) return c;
    }
    return parse(getComputedStyle(document.body).backgroundColor);
  };
  const low = [];
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  while (walker.nextNode()) {
    const t = walker.currentNode;
    if (!t.textContent.trim()) continue;
    const el = t.parentElement;
    if (el.closest('.visually-hidden, [hidden], button[disabled], .button[disabled], option, select')) continue;
    const r = el.getBoundingClientRect();
    if (!r.width || !r.height) continue;
    const cs = getComputedStyle(el);
    if (cs.visibility === 'hidden' || Number(cs.opacity) === 0) continue;
    const fg = parse(cs.color), bg = bgOf(el);
    if (!fg || !bg) continue;
    const a = lum(fg), b = lum(bg);
    const ratio = (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
    const size = parseFloat(cs.fontSize), bold = Number(cs.fontWeight) >= 700;
    const need = size >= 24 || (size >= 18.66 && bold) ? 3 : 4.5;
    if (ratio < need) low.push({ text: t.textContent.trim().slice(0, 40), ratio: Math.round(ratio * 100) / 100, need, cls: String(el.className).slice(0, 40) });
  }
  const vw = document.documentElement.clientWidth;
  const wide = [...document.querySelectorAll('body *')].filter((e) => {
    if (e.closest('.table-wrap, .sidenav, pre')) return false;
    const r = e.getBoundingClientRect();
    return r.width > 0 && r.right > vw + 1;
  }).slice(0, 5).map((e) => e.tagName.toLowerCase() + '.' + String(e.className).split(' ')[0]);
  return { overflowX: document.documentElement.scrollWidth - vw, wide, low: low.slice(0, 8), lowCount: low.length };
})()`;

if (process.argv.includes("--selftest")) {
  await navigate(BASE + "/login");
  const where = await evaluate("(() => { const d = document.createElement('p'); d.textContent = 'texto gris claro de prueba'; d.style.color = '#cccccc'; d.style.background = '#ffffff'; (document.querySelector('main') || document.body).appendChild(d); return location.pathname; })()");
  const r = await evaluate(CHECK);
  console.log("selftest on", where, "low-contrast findings:", JSON.stringify(r.low));
  process.exit(r.lowCount > 0 ? 0 : 1);
}

async function login(user) {
  await navigate(BASE + "/login");
  await evaluate(`(() => { const out = document.querySelector('form[action="/logout"]'); if (out) { out.submit(); } })()`);
  await sleep(800);
  await navigate(BASE + "/login");
  await evaluate(`(() => { const f = document.querySelector('form[action="/login"]'); f.username.value = '${user}'; f.password.value = '${user}-demo-2026'; f.submit(); })()`);
  await sleep(1500);
}

const pages = [
  [null, "/login"],
  [null, "/"],
  [null, "/access"],
  ["fiscalia", "/ops"],
  ["fiscalia", "/ops/cases/EXP-2026-000001"],
  ["fiscalia", "/ops/intake"],
  ["fiscalia", "/ops/traces"],
  ["fiscalia", "/ops/audit"],
  ["laura", "/judge"],
  ["tvf", "/platform"],
];
const results = [];
for (const theme of ["light", "dark"]) {
  await send("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: theme }] });
  for (const width of [390, 1366]) {
    await send("Emulation.setDeviceMetricsOverride", { width, height: width < 600 ? 844 : 900, deviceScaleFactor: 1, mobile: width < 600 });
    let who = undefined;
    for (const [user, path] of pages) {
      if (user !== who) {
        if (user) await login(user);
        else {
          await navigate(BASE + "/login");
          await evaluate(`(() => { const out = document.querySelector('form[action="/logout"]'); if (out) out.submit(); })()`);
          await sleep(800);
        }
        who = user;
      }
      await navigate(BASE + path);
      await evaluate(`localStorage.removeItem('strack-theme'); document.documentElement.removeAttribute('data-theme'); 1`);
      const check = await evaluate(CHECK);
      results.push({ theme, width, page: path, ...check });
      if (width === 390 || path === "/ops" || path === "/login") {
        const shot = await send("Page.captureScreenshot", { format: "png", captureBeyondViewport: false });
        const name = `${theme}-${width}${path.replace(/[\/?=]+/g, "_") || "_root"}.png`;
        writeFileSync(new URL(name, OUT), Buffer.from(shot.result.data, "base64"));
      }
    }
  }
}
for (const r of results) {
  const flag = r.overflowX > 0 || r.lowCount > 0 ? "CHECK" : "ok   ";
  console.log(`${flag} ${r.theme.padEnd(5)} ${String(r.width).padEnd(4)} ${r.page.padEnd(30)} overflowX=${r.overflowX} lowContrast=${r.lowCount}`
    + (r.wide.length ? ` wide=${r.wide.join(",")}` : "") + (r.low.length ? ` low=${JSON.stringify(r.low)}` : ""));
}
ws.close();
process.exit(0);
