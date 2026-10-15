#!/usr/bin/env python3
"""
MPatchMonitor - translations (English source, Italian translation).

Single source of truth: i18n/it.json, a map from an English text segment to its Italian
translation. This tool:

  mark   adds data-i18n / data-i18n-attr keys to the static pages in public/*.html
  build  writes worker/i18n-pages.js (Italian HTML for each marked element, applied by the
         Worker with HTMLRewriter, so Italian pages are complete before any script runs)
         and public/i18n.js (t() for strings rendered by the browser scripts)
  check  fails if a page or a script has a string without a translation, or if the
         generated files are out of date (run by the test suite)

    python tools/i18n.py mark && python tools/i18n.py build
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
import sys
from pathlib import Path

from bs4 import BeautifulSoup, NavigableString, Tag, Comment

ROOT = Path(__file__).resolve().parent.parent
PUBLIC = ROOT / "public"
DICT = ROOT / "i18n" / "it.json"
OUT_WORKER = ROOT / "worker" / "i18n-pages.js"
OUT_CLIENT = PUBLIC / "i18n.js"

INLINE = {"a", "strong", "b", "em", "i", "code", "span", "br", "kbd", "abbr", "small", "sup", "sub", "time",
          "mark", "del", "ins", "s", "input", "wbr", "button"}
NO_TRANSLATE = {"code", "kbd", "pre", "script", "style", "svg", "template"}
ATTRS = ("aria-label", "title", "placeholder", "alt")
LETTERS = re.compile(r"[A-Za-z]")
JS_CALL = re.compile(r"""\b(?:t|te|th)\(\s*("(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*')""")
JS_TERNARY = re.compile(r"""\b(?:t|te|th)\([^"'`\n]*?\?\s*("(?:[^"\\\n]|\\.)*")\s*:\s*("(?:[^"\\\n]|\\.)*")""")
JS_PLURAL = re.compile(r"""\bplural\([^"'`\n]*?,\s*("(?:[^"\\\n]|\\.)*")\s*,\s*("(?:[^"\\\n]|\\.)*")""")
WORKER_CALL = re.compile(r"""\bwt\(\s*("(?:[^"\\\n]|\\.)*")""")


def norm(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()


def key(text: str) -> str:
    return hashlib.sha256(norm(text).encode()).hexdigest()[:10]


def load_dict() -> dict[str, str]:
    return json.loads(DICT.read_text(encoding="utf-8")) if DICT.exists() else {}


# ------------------------------------------------------------------ pages
def soup_of(text: str) -> BeautifulSoup:
    return BeautifulSoup(text, "html.parser")


def inside_no_translate(el: Tag) -> bool:
    chain = [el, *[p for p in el.parents if isinstance(p, Tag)]]
    return any(p.name in NO_TRANSLATE or p.get("translate") == "no" for p in chain)


def is_unit(el: Tag) -> bool:
    if el.name in INLINE - {"a", "span", "strong", "em", "b", "small", "abbr", "time", "button"} or inside_no_translate(el):
        return False
    if el.find_parent(attrs={"data-i18n": True}) is not None:
        return False
    direct = [c for c in el.children if isinstance(c, NavigableString) and not isinstance(c, Comment)]
    if not any(LETTERS.search(str(c)) for c in direct):
        return False
    return all(d.name in INLINE for d in el.descendants if isinstance(d, Tag))


def units(soup: BeautifulSoup) -> list[Tag]:
    body = soup.body or soup
    found = []
    for el in body.find_all(True):
        if is_unit(el) and not any(el in u.descendants for u in found if True):
            found.append(el)
    return found


def attr_units(soup: BeautifulSoup) -> list[tuple[Tag, list[str]]]:
    body = soup.body or soup
    out = []
    for el in [body, *body.find_all(True)]:
        if inside_no_translate(el) and el.name != "svg":
            continue
        names = [a for a in ATTRS if isinstance(el.get(a), str) and LETTERS.search(el.get(a))]
        if names:
            out.append((el, names))
    return out


def strip_marks(text: str) -> str:
    return re.sub(r' data-i18n(?:-attr)?="[^"]*"', "", text)


def unit_key(el: Tag) -> str:
    return key(strip_marks(el.decode_contents()))


def mark_file(path: Path) -> int:
    src = strip_marks(path.read_text(encoding="utf-8"))
    soup = soup_of(src)
    line_start = [0]
    for line in src.splitlines(keepends=True):
        line_start.append(line_start[-1] + len(line))
    inserts: dict[int, list[str]] = {}

    def at(el: Tag) -> int:
        return line_start[el.sourceline - 1] + el.sourcepos + 1 + len(el.name)

    n = 0
    for el in units(soup):
        inserts.setdefault(at(el), []).append(f' data-i18n="{unit_key(el)}"')
        n += 1
    for el, names in attr_units(soup):
        val = ";".join(f"{a}:{key(el[a])}" for a in names)
        inserts.setdefault(at(el), []).append(f' data-i18n-attr="{val}"')
    out = src
    for pos in sorted(inserts, reverse=True):
        out = out[:pos] + "".join(inserts[pos]) + out[pos:]
    path.write_text(out, encoding="utf-8")
    return n


def translate_tree(el: Tag, it: dict[str, str], missing: set[str]) -> Tag:
    el = copy.copy(el)
    for child in el.find_all(True):
        child.attrs.pop("data-i18n-attr", None)
        for a in ATTRS:
            v = child.get(a)
            if isinstance(v, str) and LETTERS.search(v):
                if norm(v) in it:
                    child[a] = it[norm(v)]
                else:
                    missing.add(norm(v))
    for node in list(el.descendants):
        if not isinstance(node, NavigableString) or isinstance(node, Comment):
            continue
        if any(p.name in NO_TRANSLATE or p.get("translate") == "no" for p in node.parents if isinstance(p, Tag)):
            continue
        raw = str(node)
        core = norm(raw)
        if not LETTERS.search(core):
            continue
        if core not in it:
            missing.add(core)
            continue
        lead = " " if raw[:1].isspace() else ""
        trail = " " if raw[-1:].isspace() else ""
        node.replace_with(NavigableString(lead + it[core] + trail))
    return el


def page_tables(it: dict[str, str]) -> tuple[dict, dict, set[str]]:
    html_units, attr_map, missing = {}, {}, set()
    for path in sorted(PUBLIC.glob("*.html")):
        soup = soup_of(path.read_text(encoding="utf-8"))
        for el in soup.find_all(attrs={"data-i18n": True}):
            k = el["data-i18n"]
            if k != unit_key(el):
                missing.add(f"STALE KEY in {path.name}: run 'python tools/i18n.py mark'")
            html_units[k] = norm(translate_tree(el, it, missing).decode_contents())
        body = soup.body or soup
        for node in body.find_all(string=True):
            if isinstance(node, Comment) or not LETTERS.search(str(node)):
                continue
            chain = [p for p in node.parents if isinstance(p, Tag)]
            if any(p.name in NO_TRANSLATE or p.get("translate") == "no" or p.has_attr("data-i18n") for p in chain):
                continue
            missing.add(f"UNMARKED in {path.name}: {norm(str(node))!r} (run 'python tools/i18n.py mark')")
        for el in soup.find_all(attrs={"data-i18n-attr": True}):
            for pair in el["data-i18n-attr"].split(";"):
                name, k = pair.split(":")
                text = norm(el.get(name, ""))
                if k != key(text):
                    missing.add(f"STALE KEY in {path.name}: run 'python tools/i18n.py mark'")
                if text in it:
                    attr_map[k] = it[text]
                else:
                    missing.add(text)
    return html_units, attr_map, missing


# ------------------------------------------------------------------ scripts
def worker_strings() -> set[str]:
    found = set()
    for path in sorted((ROOT / "worker").glob("*.js")):
        if path.name.endswith(".test.js") or path == OUT_WORKER:
            continue
        for m in WORKER_CALL.finditer(path.read_text(encoding="utf-8")):
            found.add(json.loads(m.group(1)))
    return found


def js_strings() -> set[str]:
    found = set()
    for path in sorted(PUBLIC.glob("*.js")):
        if path.name == OUT_CLIENT.name:
            continue
        text = path.read_text(encoding="utf-8")
        for m in JS_TERNARY.finditer(text):
            found.update(json.loads(g) for g in m.groups())
        for m in JS_PLURAL.finditer(text):
            found.update(json.loads(g) for g in m.groups())
        for m in JS_CALL.finditer(text):
            lit = m.group(1)
            if lit.startswith("'"):
                lit = '"' + lit[1:-1].replace('\\"', '"').replace('"', '\\"') + '"'
            found.add(json.loads(lit))
    return found


CLIENT_TEMPLATE = '''"use strict";

/* MPatchMonitor - language of the page and translations for strings rendered by scripts.
 * GENERATED by tools/i18n.py from i18n/it.json: do not edit by hand.
 * The Worker picks the language (?lang=, cookie, browser setting) and sets <html lang>. */

const MPM_LANG = /^it\\b/.test(document.documentElement.lang || "") ? "it" : "en";
const LOCALE = MPM_LANG === "it" ? "it-IT" : "en-GB";
const MPM_IT = __DICT__;

/** Translate a string; {name} placeholders are filled from vars (plain text). */
function t(s, vars) {
  // "context|Text": the context only disambiguates the Italian translation.
  let out = MPM_LANG === "it" && Object.hasOwn(MPM_IT, s) ? MPM_IT[s] : s.slice(s.indexOf("|") + 1);
  if (vars) out = out.replace(/\\{(\\w+)\\}/g, (m, k) => (Object.hasOwn(vars, k) ? String(vars[k]) : m));
  return out;
}
/** Translated and HTML-escaped. */
function te(s, vars) { return esc(t(s, vars)); }
/** Translated, escaped, then {name} replaced with trusted HTML fragments. */
function th(s, html) {
  return esc(t(s)).replace(/\\{(\\w+)\\}/g, (m, k) => (Object.hasOwn(html, k) ? String(html[k]) : m));
}
'''


def build_outputs(it: dict[str, str]) -> tuple[str, str, list[str]]:
    html_units, attr_map, missing = page_tables(it)
    keys = js_strings()
    client_dict = {k: it[k] for k in sorted(keys) if k in it}
    missing |= {k for k in keys if k not in it and LETTERS.search(k)}
    wkeys = worker_strings()
    worker_dict = {k: it[k] for k in sorted(wkeys) if k in it}
    missing |= {k for k in wkeys if k not in it}
    worker = ("/* GENERATED by tools/i18n.py from i18n/it.json: do not edit by hand.\n"
              " * Italian HTML for every element marked data-i18n in public/*.html, and attribute texts. */\n"
              "export default " + json.dumps({"units": dict(sorted(html_units.items())), "attrs": dict(sorted(attr_map.items())),
                                              "strings": worker_dict},
                                             ensure_ascii=False, indent=0) + ";\n")
    client = CLIENT_TEMPLATE.replace("__DICT__", json.dumps(client_dict, ensure_ascii=False, indent=0))
    return worker, client, sorted(missing)


def main(cmd: str) -> int:
    if cmd == "mark":
        for p in sorted(PUBLIC.glob("*.html")):
            print(f"{p.name}: {mark_file(p)} elements")
        return 0
    it = load_dict()
    worker, client, missing = build_outputs(it)
    if cmd == "missing":
        print(json.dumps({m: "" for m in missing}, ensure_ascii=False, indent=1))
        return 0
    if cmd == "build":
        OUT_WORKER.write_text(worker, encoding="utf-8")
        OUT_CLIENT.write_text(client, encoding="utf-8")
        for m in missing:
            print("missing:", m)
        return 1 if missing else 0
    if cmd == "check":
        ok = not missing and OUT_WORKER.exists() and OUT_WORKER.read_text(encoding="utf-8") == worker \
            and OUT_CLIENT.exists() and OUT_CLIENT.read_text(encoding="utf-8") == client
        for m in missing:
            print("missing:", m)
        if not ok and not missing:
            print("generated files are out of date: run 'python tools/i18n.py build'")
        return 0 if ok else 1
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else ""))
