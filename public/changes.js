"use strict";

/* MPatchMonitor — "What changed": every Microsoft revision with a line-by-line diff. */

const CH_CHIPS = [
  { id: "all", label: t("Every revision"), test: () => true },
  { id: "action", label: t("Action required"), test: (c) => Boolean(c.action) },
  { id: "products", label: t("Products added"), test: (c) => c.diff?.products_added?.length },
  { id: "updates", label: t("New updates"), test: (c) => c.diff?.kbs_added?.length },
  { id: "silent", label: t("Changed without a new version"), test: (c) => c.kind === "silent" },
];
const ch = { data: null, chip: "all" };

document.addEventListener("DOMContentLoaded", async () => {
  initTheme();
  try { ch.data = await fetchData(); } catch (err) { return showFatal($("#main"), err); }
  $("#chChips").addEventListener("click", (e) => {
    const b = e.target.closest("button[data-chip]");
    if (!b) return;
    ch.chip = b.dataset.chip;
    renderChanges();
  });
  renderChanges();
  if (location.hash) $(`[id="${CSS.escape(decodeURIComponent(location.hash.slice(1)))}"]`)?.scrollIntoView({ block: "start" });
});

function renderChanges() {
  const revs = ch.data.changes.filter((c) => c.kind === "revised" || c.kind === "silent");
  setHTML($("#chChips"), CH_CHIPS.map((c) =>
    `<button type="button" class="chip" data-chip="${c.id}" aria-pressed="${ch.chip === c.id}">${esc(c.label)} <span>${revs.filter(c.test).length}</span></button>`).join(""));
  const test = CH_CHIPS.find((c) => c.id === ch.chip).test;
  const items = revs.filter(test);
  const detailed = revs.filter((c) => c.diff).length;
  $("#chCount").textContent = t("{n} revisions in the last 60 days, {d} with a detailed comparison. Comparisons exist for revisions published after monitoring started.", { n: revs.length, d: detailed });
  setHTML($("#revisions"), items.map((c) => `<li class="rev-card${c.action ? " needs-action" : ""}" id="${esc(c.cve)}-${esc(c.rev || "")}">
    <div class="rev-head">
      <div>
        <p class="kind">${esc(KINDS[c.kind]?.label || c.kind)}${c.rev ? te(", version {v}", { v: c.kind === "silent" ? t("{v} (unchanged)", { v: c.rev }) : c.diff?.from_rev ? `${c.diff.from_rev} → ${c.rev}` : c.rev }) : ""}</p>
        <h2${MPM_LANG === "it" ? ' lang="en"' : ""}><a href="/cve/${encodeURIComponent(c.cve)}">${esc(c.title)}</a></h2>
        <p class="sub"><span class="id">${esc(c.cve)}</span>${c.priority ? prioBadge(c.priority) : ""}<time datetime="${esc(c.ts)}">${esc(fmtDateTime(c.ts))}</time></p>
      </div>
      ${c.action ? `<p class="action-flag">${c.action === "reinstall" ? te("Microsoft asks to install the update again") : te("Customer action required")}</p>` : ""}
    </div>
    ${c.kind === "silent" ? `<p class="ms-note">${te("Microsoft edited the advisory but kept the same version number, so this change does not appear in its revision history.")}</p>`
      : c.detail ? `<p class="ms-note"><strong>${te("Microsoft's note:")}</strong> <span${MPM_LANG === "it" ? ' lang="en"' : ""}>${esc(c.detail)}</span></p>` : ""}
    ${c.diff ? `<div class="badges">${diffBadges(c.diff)}</div>${renderDiff(c.diff)}` : `<p class="hint">${te("No earlier version on record to compare with.")}</p>`}
  </li>`).join("") || `<li class="empty">${te("No revisions of this type in the last 60 days.")}</li>`);
}
