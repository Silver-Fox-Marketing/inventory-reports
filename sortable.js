/* Sortable report tables. Shared by the site (loaded as a file) and the one-off per-dealer HTML
 * (build_aged_report.py inlines this file), so both sort the same way.
 *
 * A <th data-sort="num|text|date"> heading sorts its column: the first tap goes the useful way
 * (numbers high→low, dates oldest first, text A→Z) and a second tap reverses. Cells sort on
 * data-v when present (raw days, prices, ISO dates), else on their text; blank values always
 * sort last. A model row keeps its open VIN list (tr.detail) under it; tr.pin rows stay at the end.
 */
"use strict";

const SORT_FIRST = { num: "descending", date: "ascending", text: "ascending" };

function sortTh(label, type, cls = "") {
  return `<th class="${cls}" data-sort="${type}" aria-sort="none"><button type="button" class="sbtn">${label}<span class="arr" aria-hidden="true"></span></button></th>`;
}

function makeSortable(table, onSorted) {
  table.tHead.addEventListener("click", ev => {
    const th = ev.target.closest("th[data-sort]");
    if (!th) return;
    const type = th.dataset.sort, first = SORT_FIRST[type];
    const dir = th.getAttribute("aria-sort") === first ? (first === "ascending" ? "descending" : "ascending") : first;
    for (const h of th.parentElement.cells) if (h.dataset.sort) h.setAttribute("aria-sort", "none");
    th.setAttribute("aria-sort", dir);
    const body = table.tBodies[0], col = th.cellIndex, sign = dir === "ascending" ? 1 : -1;
    const groups = [], pinned = [];
    for (const r of [...body.rows]) {
      if (r.classList.contains("detail") && groups.length) groups[groups.length - 1].push(r);
      else if (r.classList.contains("pin")) pinned.push(r);
      else groups.push([r]);
    }
    const val = g => { const c = g[0].cells[col]; return (c.dataset.v ?? c.textContent).trim(); };
    groups.sort((a, b) => {
      const x = val(a), y = val(b);
      if (!x || !y) return (!x) - (!y);
      return sign * (type === "num" ? parseFloat(x) - parseFloat(y)
        : x.localeCompare(y, undefined, { numeric: true, sensitivity: "base" }));
    });
    body.append(...groups.flat(), ...pinned);
    if (onSorted) onSorted(body);
  });
}

/* Keep the # column counting 1, 2, 3 down the new order. */
function renumber(body) {
  [...body.rows].forEach((r, i) => { if (r.cells[0].classList.contains("rn")) r.cells[0].textContent = i + 1; });
}

/* The printout shows the first 12 models in the current order, then one "other models" row
 * (tr.printonly.pin) totalling the rest. Cells: name, units, avg, 90+, 120+, oldest. */
function markExtra(table) {
  [...table.tBodies[0].querySelectorAll("tr.mrow")].forEach((r, i) => r.classList.toggle("extra", i >= 12));
}
function restSummary(table) {
  const row = table.querySelector("tr.printonly");
  if (!row) return;
  const rest = [...table.tBodies[0].querySelectorAll("tr.mrow.extra")];
  const sum = i => rest.reduce((a, r) => a + (parseInt(r.cells[i].textContent, 10) || 0), 0);
  row.innerHTML = `<td>${rest.length} other models</td><td>${sum(1)}</td><td class="c-avg"></td><td>${sum(3)}</td><td class="c-120">${sum(4)}</td><td></td>`;
}
