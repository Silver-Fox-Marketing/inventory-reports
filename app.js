/* Aged Inventory — dealer picker + report, rendered from encrypted JSON.
 *
 * data/meta.json   {v, salt, iter, built}            (plain: the KDF parameters only)
 * data/index.enc   dealer list + build info           (AES-GCM, key = PBKDF2-SHA256(password, salt))
 * data/<slug>.enc  one dealer's report (aged_data.to_json)
 * Each .enc file is 12-byte IV + ciphertext of gzip(JSON).
 */
"use strict";

const STORE = "agedInventoryKey";
const $ = (sel, el = document) => el.querySelector(sel);
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const money = n => n == null ? "" : "$" + Math.round(n).toLocaleString("en-US");
const fmtDate = iso => { if (!iso) return ""; const [y, m, d] = iso.split("-"); return `${+m}/${+d}/${y}`; };
const BUCKETS = ["Under 60", "60–89", "90–119", "120+"];

let meta, key, index;
const cache = new Map();

/* ---------- crypto ---------- */
const b64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const unb64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));

async function deriveKey(password) {
  const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "PBKDF2", salt: b64(meta.salt), iterations: meta.iter, hash: "SHA-256" },
    base, { name: "AES-GCM", length: 256 }, true, ["decrypt"]);
}

async function fetchJSON(name) {
  const r = await fetch(`data/${name}?v=${encodeURIComponent(meta.built)}`, { cache: "no-cache" });
  if (!r.ok) throw new Error(`${name}: HTTP ${r.status}`);
  const buf = new Uint8Array(await r.arrayBuffer());
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: buf.slice(0, 12) }, key, buf.slice(12));
  const text = await new Response(new Blob([plain]).stream().pipeThrough(new DecompressionStream("gzip"))).text();
  return JSON.parse(text);
}

function remember(k) {
  try { crypto.subtle.exportKey("raw", k).then(raw => localStorage.setItem(STORE, JSON.stringify({ salt: meta.salt, k: unb64(raw) }))); }
  catch (_) { /* private mode: fine, they type it next time */ }
}
function forget() { try { localStorage.removeItem(STORE); } catch (_) { } }
async function rememberedKey() {
  try {
    const s = JSON.parse(localStorage.getItem(STORE) || "null");
    if (!s || s.salt !== meta.salt) return null;  // password rotated: ask again
    return await crypto.subtle.importKey("raw", b64(s.k), { name: "AES-GCM" }, true, ["decrypt"]);
  } catch (_) { return null; }
}

/* ---------- views ---------- */
function show(id) {
  for (const s of ["lock", "picker", "report"]) $("#" + s).hidden = s !== id;
  $("#bar").hidden = id === "lock";
}

function showLock(msg = "") {
  show("lock");
  $("#lockmsg").textContent = msg;
  setTimeout(() => $("#pw").focus(), 0);
}

$("#unlock").addEventListener("submit", async ev => {
  ev.preventDefault();
  const btn = $("#unlock button"), pw = $("#pw").value;
  btn.disabled = true; btn.textContent = "Opening…"; $("#lockmsg").textContent = "";
  try {
    key = await deriveKey(pw);
    index = await fetchJSON("index.enc");
  } catch (e) {
    key = null;
    $("#lockmsg").textContent = e.name === "OperationError" ? "That password didn't work." : `Couldn't load the data (${e.message}).`;
    btn.disabled = false; btn.textContent = "Open";
    return;
  }
  if ($("#remember").checked) remember(key);
  $("#pw").value = ""; btn.disabled = false; btn.textContent = "Open";
  ready();
});

$("#lockbtn").addEventListener("click", () => {
  forget(); key = index = null; cache.clear(); history.replaceState(null, "", location.pathname); showLock();
});

function ready() {
  $("#asof").textContent = `Data from ${fmtDate(index.latestRun)}`;
  renderPicker();
  route();
}

/* picker */
function renderPicker() {
  const q = $("#search").value.trim().toLowerCase();
  const rows = index.dealers.filter(d => !q || d.dealer.toLowerCase().includes(q));
  const groups = new Map();
  for (const d of rows) {
    const L = /[a-z]/i.test(d.dealer[0]) ? d.dealer[0].toUpperCase() : "#";
    if (!groups.has(L)) groups.set(L, []);
    groups.get(L).push(d);
  }
  $("#letters").innerHTML = [...groups.keys()].map(L => `<a href="#letter-${L}" data-letter="${L}">${L}</a>`).join("");
  $("#list").innerHTML = rows.length ? [...groups].map(([L, ds]) => `<h3 id="letter-${L}">${L}</h3>` + ds.map(d => {
    const stale = d.asOf < index.latestRun ? `<span class="pill warn">data from ${fmtDate(d.asOf)}</span>` : "";
    const seen = d.seenN === d.n ? `<span class="pill" title="This dealer publishes no stock dates">minimum ages</span>` : "";
    return `<a class="dealer" href="#${d.slug}"><span class="name">${esc(d.dealer)}${stale}${seen}</span>
      <span class="meta"><b>${d.n90}</b> of ${d.n} at 90+ days</span></a>`;
  }).join("")).join("") : `<p class="empty mut">No dealership matches “${esc(q)}”.</p>`;
}
$("#search").addEventListener("input", renderPicker);
$("#letters").addEventListener("click", ev => {
  const a = ev.target.closest("a[data-letter]");
  if (!a) return;
  ev.preventDefault();  // keep the hash for dealer routes
  document.getElementById("letter-" + a.dataset.letter).scrollIntoView({ behavior: "smooth" });
});

/* routing: #<slug> opens a report, anything else the picker */
window.addEventListener("hashchange", () => key && route());
async function route() {
  const slug = decodeURIComponent(location.hash.slice(1));
  const d = slug && index.dealers.find(x => x.slug === slug);
  if (!d) { show("picker"); document.title = "Aged Inventory"; return; }
  show("report");
  $("#report").innerHTML = `<p class="mut">Loading ${esc(d.dealer)}…</p>`;
  try {
    if (!cache.has(slug)) cache.set(slug, await fetchJSON(slug + ".enc"));
    renderReport(cache.get(slug));
    window.scrollTo(0, 0);
  } catch (e) {
    $("#report").innerHTML = `<p class="err">Couldn't load ${esc(d.dealer)} (${esc(e.message)}).</p><p><a href="#">Back to dealers</a></p>`;
  }
}

/* ---------- report ---------- */
function unitsOf(R) {
  const c = R.unitCols;
  return R.units.map(row => Object.fromEntries(c.map((k, i) => [k, row[i]])));
}
const inStock = u => u.ageSrc === "stock" ? fmtDate(u.inStock) : `seen ${fmtDate(u.firstSeen)}`;
const days = u => u.ageSrc === "stock" ? String(u.age) : `≥${u.age}`;

function tags(m) {
  return (m.nat ? `<b class="tag">US ${m.nat}d</b>` : "") + (m.mo ? `<b class="tag mo">MO ${m.mo}d</b>` : "");
}

function renderReport(R) {
  const U = unitsOf(R);
  R._U = U;
  document.title = `${R.dealer} · Aged Inventory`;
  const n = R.n, pct = n ? Math.round(100 * R.n90 / n) : 0;
  const stale = R.asOf < R.latestRun
    ? `<div class="banner"><b>No fresh data since ${fmtDate(R.asOf)}.</b> The ${fmtDate(R.latestRun)} scrape didn't return this dealer (blocked, failed, or off the schedule), so these numbers are from ${fmtDate(R.asOf)}.</div>` : "";
  const seen = R.seenN
    ? `<div class="banner">${R.seenN === n ? "This dealer's website publishes no stock dates" : `${R.seenN} of ${n} units have no stock date`}, so ${R.seenN === n ? "ages are" : "those are"} counted from the first day we saw each unit (shown as ≥). They are minimums: our history starts ${fmtDate(R.historyFrom)}.</div>` : "";
  const bars = R.buckets.map((c, i) => `<div class="seg s${i}" style="flex:${c || 0.0001}" title="${BUCKETS[i]} days: ${c}">${c ? `<span>${c}</span>` : ""}</div>`).join("");
  const legend = BUCKETS.map((b, i) => `<span><i class="s${i}"></i>${b} days</span>`).join("");
  const mrows = R.models.map((m, i) => `<tr class="mrow ${m.nat || m.mo ? "hl" : ""} ${i >= 12 ? "extra" : ""}">
      <td data-v="${esc(m.name)}"><button type="button" class="mbtn" data-i="${i}" aria-expanded="false"><span class="chev" aria-hidden="true">▸</span>${esc(m.name)}</button> ${tags(m)}</td>
      <td>${m.n}</td><td class="c-avg">${m.avg}</td><td>${m.n90}</td><td class="c-120">${m.n120}</td><td>${m.max}</td></tr>`).join("");
  const restRow = R.models.length > 12 ? `<tr class="mut printonly pin"></tr>` : "";  // filled by restSummary()
  const orows = U.slice(0, 12).map((u, i) => unitRow(u, i, true)).join("");
  const ev = R.events.length ? R.events.map(fmtDate).join(", ") : "none";

  $("#report").innerHTML = `
    <div class="rhead"><a href="#" class="back">← All dealerships</a>
      <h1>${esc(R.dealer)}</h1>
      <div class="mut">New vehicles on the lot as of ${fmtDate(R.asOf)}, from the dealer's own website, read by our inventory scraper.</div>
      <div class="actions"><button type="button" class="ghost" id="csv">Download CSV</button>
        <button type="button" class="ghost" id="print">Print / Save PDF</button></div></div>
    ${stale}${seen}
    <div class="kpis">
      <div class="kpi"><div class="v">${n}</div><div class="l">new units on the lot<br>(+${R.inTransit} in transit or on order)</div></div>
      <div class="kpi red"><div class="v">${R.n90} <small>(${pct}%)</small></div><div class="l">on the lot 90+ days</div></div>
      <div class="kpi"><div class="v">${R.median}</div><div class="l">median days on the lot</div></div>
    </div>
    <h2>How old is the new inventory?</h2>
    <div class="agebar">${bars}</div><div class="legend">${legend}</div>
    <h2>By model <span class="sub">· shaded rows are on the national (US) or Missouri (MO) slowest-seller list, with that list's days of supply</span></h2>
    <div class="hint">Tap a model to list its VINs. Tap a column heading to sort; tap again to reverse.</div>
    <table class="models" id="models"><thead><tr>${sortTh("Model", "text")}${sortTh("Units", "num")}${sortTh("Avg days", "num", "c-avg")}${sortTh("90+", "num")}${sortTh("120+", "num", "c-120")}${sortTh("Oldest", "num")}</tr></thead>
      <tbody>${mrows}${restRow}</tbody></table>
    <h2>Price moves</h2>
    <p><b>${R.cutN} of ${n}</b> new units on the lot now carry a lower advertised price than when we first saw them${R.cutN ? ` (median cut <b>${money(R.cutMed)}</b>)` : ""}.
      Store-wide repricing days since ${fmtDate(R.windowFrom)}: <b>${ev}</b>. ${R.gone} new units have left the website since ${fmtDate(R.windowFrom)} (sold or traded).</p>
    <h2>Oldest units on the lot</h2>
    <div class="wrap"><table class="grid" id="oldest">${unitHead(true)}<tbody>${orows}</tbody></table></div>
    <div class="note">All ${n} units: Download CSV above, or tap a model.</div>
    <footer class="method"><b>How this is built.</b> Age is the report date minus the dealer's published "Date In Stock"; dealers that publish none are aged from the first day we saw each unit (shown as ≥, a minimum).
      Only <i>new</i> units the site lists as on the lot are counted. Prices are advertised website prices; cuts compare with the first time we saw each unit.
      Slow-seller lists: ${esc(index.slowLists.national.source)} (US) and ${esc(index.slowLists.missouri.source)} (MO), ${esc(index.slowLists.national.as_of)}.
      Dealer-tagged "Service Loaner" units are new units used as loaners, still for sale.</footer>`;

  $("#csv").addEventListener("click", () => downloadCSV(R));
  $("#print").addEventListener("click", () => window.print());
  restSummary($("#models"));  // sortable.js
  makeSortable($("#models"), () => { markExtra($("#models")); restSummary($("#models")); });
  makeSortable($("#oldest"), renumber);
  $("#models").addEventListener("click", ev => {
    if (ev.target.closest(".tag, .detail")) return;
    const row = ev.target.closest("tr.mrow");
    if (row) toggleModel(R, row.querySelector(".mbtn"));
  });
}

/* One unit row, shared by the oldest-units grid (withModel) and a model's VIN list. */
function unitHead(withModel) {
  return `<thead><tr><th></th>${sortTh("VIN", "text")}${sortTh("Stock", "text")}${sortTh("Year", "num")}`
    + (withModel ? sortTh("Model", "text") : "")
    + `${sortTh("Trim", "text")}${sortTh("In stock", "date", "r")}${sortTh("Days", "num", "r")}${sortTh("Price", "num", "r")}${sortTh("Cut since first seen", "num", "r")}</tr></thead>`;
}
function unitRow(u, i, withModel) {
  return `<tr><td class="rn">${i + 1}</td><td class="vin" data-v="${esc(u.vin)}">${vinCell(u)}</td><td>${esc(u.stock)}</td><td>${esc(u.year)}</td>`
    + (withModel ? `<td>${esc(u.make)} ${esc(u.model)}</td>` : "")
    + `<td>${esc(u.trim)}</td><td class="r" data-v="${u.ageSrc === "stock" ? u.inStock : u.firstSeen}">${inStock(u)}</td>`
    + `<td class="r ${!withModel && u.age >= 90 ? "aged" : ""}" data-v="${u.age}"><b>${days(u)}</b></td>`
    + `<td class="r" data-v="${u.price ?? ""}">${money(u.price)}</td><td class="r" data-v="${u.cut ?? ""}">${u.cut ? "−" + money(u.cut) : ""}</td></tr>`;
}

function vinCell(u) {
  // Scraped URLs are data: link only plain http(s), never another scheme.
  return /^https?:\/\//i.test(u.url || "") ? `<a href="${esc(u.url)}" target="_blank" rel="noopener noreferrer">${esc(u.vin)}</a>` : esc(u.vin);
}

function toggleModel(R, btn) {
  const row = btn.closest("tr");
  if (btn.getAttribute("aria-expanded") === "true") {
    row.nextElementSibling.remove(); btn.setAttribute("aria-expanded", "false"); return;
  }
  const units = R.models[+btn.dataset.i].units.map(i => R._U[i]);
  const rows = units.map((u, k) => unitRow(u, k, false)).join("");
  const tr = document.createElement("tr");
  tr.className = "detail";
  tr.innerHTML = `<td colspan="6"><div class="dhead"><span>${units.length} units · VIN opens the dealer's listing</span>
      <button type="button" class="copy">Copy VINs</button></div>
      <div class="wrap"><table class="grid">${unitHead(false)}<tbody>${rows}</tbody></table></div></td>`;
  makeSortable($("table", tr), renumber);
  $(".copy", tr).addEventListener("click", ev =>
    copyText(ev.currentTarget, [...tr.querySelectorAll("tbody td.vin")].map(td => td.textContent).join("\n")));
  row.after(tr);
  btn.setAttribute("aria-expanded", "true");
}

function copyText(btn, text) {
  const done = () => { btn.textContent = "Copied"; setTimeout(() => (btn.textContent = "Copy VINs"), 1500); };
  const fallback = () => {
    const t = document.createElement("textarea"); t.value = text; t.setAttribute("readonly", "");
    t.style.position = "fixed"; t.style.opacity = "0"; document.body.appendChild(t); t.select();
    try { document.execCommand("copy"); done(); } finally { t.remove(); }
  };
  (navigator.clipboard ? navigator.clipboard.writeText(text) : Promise.reject()).then(done, fallback);
}

function downloadCSV(R) {
  const head = ["VIN", "Stock", "Year", "Make", "Model", "Trim", "Site status", "Date In Stock", "Days on lot", "Age from",
    "Age band", "On Joe's slow list", "Price", "MSRP", "First seen", "Price when first seen", "Cut since first seen", "Listing"];
  const band = a => a < 60 ? "Under 60" : a < 90 ? "60–89" : a < 120 ? "90–119" : "120+";
  const cell = v => { const s = v == null ? "" : String(v); return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; };
  const lines = [head, ...R._U.map(u => [u.vin, u.stock, u.year, u.make, u.model, u.trim, u.status, u.inStock || "", u.age,
    u.ageSrc === "stock" ? "stock date" : "first seen (minimum)", band(u.age), u.slow, u.price, u.msrp, u.firstSeen,
    u.firstPrice, u.cut, u.url])].map(r => r.map(cell).join(","));
  const blob = new Blob(["﻿" + lines.join("\r\n")], { type: "text/csv;charset=utf-8" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `${R.slug}-aged-inventory-${R.asOf}.csv`;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

/* ---------- boot ---------- */
(async function boot() {
  try {
    meta = await (await fetch("data/meta.json", { cache: "no-cache" })).json();
  } catch (e) {
    showLock("The report data isn't available right now."); return;
  }
  if (!window.crypto?.subtle || !window.DecompressionStream) {
    showLock("This browser is too old to open the reports. Update it, or try Chrome or Safari."); return;
  }
  const k = await rememberedKey();
  if (k) {
    try { key = k; index = await fetchJSON("index.enc"); ready(); return; }
    catch (_) { key = null; forget(); }
  }
  showLock();
})();
