#!/usr/bin/env node
// Security checks for the static HTML pages in this repo. Zero dependencies.
// Usage: node scripts/check-html.mjs [file.html ...]   (default: every tracked *.html)
// Exit 1 and print file:line findings on any failure.
import { readFileSync } from 'node:fs';
import { execSync } from 'node:child_process';

const files = process.argv.slice(2).length
  ? process.argv.slice(2)
  : execSync("git ls-files '*.html'", { encoding: 'utf8' }).split('\n').filter(Boolean);

const SEMVER = String.raw`\d+\.\d+\.\d+(?:[-+][\w.]+)?`;
const PINNED = [
  new RegExp(String.raw`^https://cdnjs\.cloudflare\.com/ajax/libs/[^/]+/${SEMVER}/`),
  new RegExp(String.raw`^https://cdn\.jsdelivr\.net/npm/(?:@[^/@]+/)?[^/@]+@${SEMVER}/`),
  new RegExp(String.raw`^https://unpkg\.com/(?:@[^/@]+/)?[^/@]+@${SEMVER}/`),
];
const pinned = u => PINNED.some(re => re.test(u));
const SRI = /^sha384-[A-Za-z0-9+/]{64}$/;
const SINKS = [
  [/\beval\s*\(/, 'eval()'],
  [/\bnew\s+Function\s*\(/, 'new Function()'],
  [/\bdocument\.write(?:ln)?\s*\(/, 'document.write()'],
  [/\bset(?:Timeout|Interval)\s*\(\s*['"`]/, 'string passed to setTimeout/setInterval'],
];
const HTML_SINK = /\.(?:innerHTML|outerHTML)\s*\+?=|\.insertAdjacentHTML\s*\(/;
const SECRETS = [
  [/AKIA[0-9A-Z]{16}/, 'AWS access key'],
  [/\bghp_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{22,}/, 'GitHub token'],
  [/\bsk-[A-Za-z0-9_-]{20,}/, 'API secret key'],
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----/, 'private key'],
  [/\bapi[_-]?key\s*[:=]\s*["'][A-Za-z0-9_-]{16,}/i, 'hardcoded API key'],
];

const attrs = s => Object.fromEntries([...s.matchAll(/([\w-]+)(?:\s*=\s*"([^"]*)")?/g)].map(m => [m[1].toLowerCase(), m[2] ?? '']));
let failures = 0;

for (const file of files) {
  const src = readFileSync(file, 'utf8');
  const lineOf = idx => src.slice(0, idx).split('\n').length;
  const fail = (idx, msg) => { failures++; console.error(`${file}:${lineOf(idx)}: ${msg}`); };
  const failLine = (line, msg) => { failures++; console.error(`${file}:${line}: ${msg}`); };

  // 1. external scripts
  const importMaps = [], moduleBodies = [];
  for (const m of src.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)) {
    const a = attrs(m[1]);
    if (a.src) {
      if (!pinned(a.src)) fail(m.index, `script src must be an allowlisted CDN pinned to an exact version: ${a.src}`);
      if (!SRI.test(a.integrity ?? '')) fail(m.index, `script needs integrity="sha384-…" (run scripts/sri.sh <url>): ${a.src}`);
      if (a.crossorigin !== 'anonymous') fail(m.index, `script needs crossorigin="anonymous": ${a.src}`);
    }
    if (a.type === 'importmap') importMaps.push({ idx: m.index, body: m[2] });
    if (a.type === 'module' && !a.src) moduleBodies.push(m[2]);
  }

  // 2. import maps: pinned URLs, integrity for every module the page imports
  for (const { idx, body } of importMaps) {
    let map; try { map = JSON.parse(body); } catch { fail(idx, 'importmap is not valid JSON'); continue; }
    const imports = map.imports ?? {}, integrity = map.integrity ?? {};
    for (const [spec, url] of Object.entries(imports)) if (!pinned(url)) fail(idx, `importmap "${spec}" must be an allowlisted CDN pinned to an exact version: ${url}`);
    const resolved = new Set(Object.values(imports).filter(u => !u.endsWith('/')));
    for (const code of moduleBodies) for (const im of code.matchAll(/\bimport\s+(?:[\w*{}\s,$]+?\s+from\s+)?['"]([^'"]+)['"]/g)) {
      const spec = im[1];
      if (imports[spec]) { resolved.add(imports[spec]); continue; }
      const prefix = Object.keys(imports).filter(k => k.endsWith('/') && spec.startsWith(k)).sort((x, y) => y.length - x.length)[0];
      if (prefix) resolved.add(imports[prefix] + spec.slice(prefix.length));
      else if (/^(?:https?:)?\/\//.test(spec)) fail(idx, `module imports a URL directly instead of through the importmap: ${spec}`);
    }
    for (const url of resolved) if (!SRI.test(integrity[url] ?? '')) fail(idx, `importmap "integrity" needs a sha384 entry for ${url}`);
  }

  // 3. stylesheets, 4. transport
  for (const m of src.matchAll(/<link\b([^>]*)>/gi)) {
    const a = attrs(m[1]);
    if (/\bstylesheet\b/i.test(a.rel ?? '') && !a.href.startsWith('https://fonts.googleapis.com/')) fail(m.index, `stylesheet host not allowlisted (inline CSS instead): ${a.href}`);
  }
  for (const m of src.matchAll(/\b(?:src|href)\s*=\s*"\s*http:\/\//gi)) fail(m.index, 'plain http:// resource; use https://');
  for (const m of src.matchAll(/\bhref\s*=\s*"\s*javascript:/gi)) fail(m.index, 'javascript: href');

  // 5. DOM sinks, 6. secrets (per line)
  src.split('\n').forEach((line, i) => {
    for (const [re, what] of SINKS) if (re.test(line)) failLine(i + 1, `forbidden sink: ${what}`);
    if (HTML_SINK.test(line) && !line.includes('/* static */')) failLine(i + 1, 'innerHTML/outerHTML/insertAdjacentHTML without a /* static */ marker (use textContent or a reviewed static template)');
    for (const [re, what] of SECRETS) if (re.test(line)) failLine(i + 1, `possible secret: ${what}`);
  });
}

if (failures) { console.error(`\n${failures} security finding(s).`); process.exit(1); }
console.log(`ok: ${files.length} file(s) passed security checks`);
