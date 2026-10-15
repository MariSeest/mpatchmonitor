"use strict";

/* MPatchMonitor — static pages (/feeds, /method): full URLs with copy buttons */

document.addEventListener("DOMContentLoaded", () => {
  initTheme();
  $$("code[data-url]").forEach((el) => {
    const path = el.dataset.url;
    if (!/^\/[A-Za-z0-9/._-]*$/.test(path)) return;
    const url = location.origin + path;
    el.textContent = url;
    const b = document.createElement("button");
    b.type = "button"; b.className = "ghost copy"; b.textContent = t("Copy");
    b.addEventListener("click", () => copyText(url, b));
    el.after(b);
  });
  initEmbed();
});

/* Embed builder (/feeds): preview and HTML snippet for the Patch Tuesday card. */
function initEmbed() {
  const img = $("#embedImg");
  if (!img) return;
  const lang = $("#embedLang"), theme = $("#embedTheme");
  lang.value = MPM_LANG;
  const update = () => {
    const l = lang.value === "it" ? "it" : "en", th = theme.value === "dark" ? "dark" : "light";
    const src = `${location.origin}/embed/patch-tuesday.svg?lang=${l}&theme=${th}`;
    img.src = `/embed/patch-tuesday.svg?lang=${l}&theme=${th}`;
    $("#embedCode").textContent = `<a href="${location.origin}/release?lang=${l}"><img src="${src}" width="400" height="140" alt="${t("Latest Microsoft Patch Tuesday figures by MPatchMonitor")}" loading="lazy"></a>`;
  };
  lang.addEventListener("change", update);
  theme.addEventListener("change", update);
  $("#embedCopy").addEventListener("click", (e) => copyText($("#embedCode").textContent, e.currentTarget));
  update();
}
