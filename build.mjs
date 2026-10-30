#!/usr/bin/env node
// Builds one combined blocklist in AdGuard / uBlock Origin syntax:
//   1. Download every list named in sources.txt into ./temp
//   2. Parse hosts, plain-domain and ||domain^ lists into a set of domains
//   3. Remove every domain covered by the whitelist (domain or any parent domain listed)
//   4. Add every domain from the blacklist
//   5. Write dist/blacklist.txt (and dist/index.html)
// No runtime dependencies: uses Node's built-in fetch, fs, and net modules.

import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import { join, resolve } from 'node:path';

const ROOT = process.cwd();
const TEMP_DIR = join(ROOT, 'temp');
const DIST_DIR = join(ROOT, 'dist');
const TIMEOUT_MS = 60_000;

// Each input is either an http(s) URL or a path relative to the repo root.
const INPUTS = {
  sources: process.env.SOURCES_URL || 'sources.txt',
  whitelist: process.env.WHITELIST_URL || 'whitelist.txt',
  blacklist: process.env.BLACKLIST_URL || 'blacklist.txt',
};
const TITLE = process.env.BLOCKLIST_TITLE || 'Combined Blocklist';

const DOMAIN_RE = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$/;
const ADBLOCK_DOMAIN_RE = /^\|\|([^\s\/^$*|]+)\^$/;          // ||example.com^
const ADBLOCK_EXCEPTION_RE = /^@@\|\|([^\s\/^$*|]+)\^$/;     // @@||example.com^
const ADBLOCK_HOST_PREFIX_RE = /^\|\|([^\s\/^$*|]+)\^/;      // ||example.com^$modifiers

const log = (...args) => console.log(...args);

// ---------- input helpers ----------

async function readInput(spec) {
  if (/^https?:\/\//i.test(spec)) {
    const res = await fetch(spec, {
      redirect: 'follow',
      signal: AbortSignal.timeout(TIMEOUT_MS),
      headers: { 'user-agent': 'blocklist-builder' },
    });
    if (!res.ok) throw new Error(`HTTP ${res.status} for ${spec}`);
    return res.text();
  }
  return readFile(resolve(ROOT, spec), 'utf8');
}

// Drops blank lines and comments. "!" starts a comment; "#" is a comment only when followed by a space,
// so cosmetic rules such as "##.ad" survive.
function cleanLines(text) {
  return text
    .replace(/^﻿/, '')
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('!') && !/^#(\s|$)/.test(l));
}

function normalizeDomain(s) {
  const d = s.toLowerCase().replace(/\.$/, '');
  return DOMAIN_RE.test(d) ? d : null;
}

// Parses one list. Accepts hosts files, plain domain lists, and adblock ||domain^ lists.
// Returns blocked domains, allowed domains (from @@||domain^), and other rules kept verbatim.
function parseList(text) {
  const domains = new Set();
  const exceptions = new Set();
  const passthrough = new Set();
  let ignored = 0;

  for (let line of cleanLines(text)) {
    line = line.replace(/\s+#\s.*$/, '').trim(); // trailing "# comment" in hosts files
    if (!line) continue;

    let m = ADBLOCK_DOMAIN_RE.exec(line);
    if (m) {
      const d = normalizeDomain(m[1]);
      if (d) domains.add(d); else ignored++;
      continue;
    }

    m = ADBLOCK_EXCEPTION_RE.exec(line);
    if (m) {
      const d = normalizeDomain(m[1]);
      if (d) exceptions.add(d); else ignored++;
      continue;
    }

    const parts = line.split(/\s+/);
    if (parts.length >= 2 && isIP(parts[0])) {
      // hosts format: "0.0.0.0 example.com [more hosts...]"
      for (const host of parts.slice(1)) {
        const d = normalizeDomain(host);
        if (d) domains.add(d);
      }
      continue;
    }

    if (parts.length === 1) {
      const d = normalizeDomain(line);
      if (d) {
        domains.add(d);
        continue;
      }
    }

    // Cosmetic rules, rules with $modifiers, regex rules, etc.
    if (/[|^*\/$#@!]/.test(line)) {
      passthrough.add(line);
      continue;
    }

    ignored++;
  }

  return { domains, exceptions, passthrough, ignored };
}

// True if the domain, or any parent domain, is in the allow set.
// Whitelisting example.com also allows sub.example.com.
function isAllowed(domain, allow) {
  let d = domain;
  for (;;) {
    if (allow.has(d)) return true;
    const dot = d.indexOf('.');
    if (dot === -1) return false;
    d = d.slice(dot + 1);
  }
}

function escapeHtml(s) {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
}

// ---------- build ----------

async function main() {
  await rm(TEMP_DIR, { recursive: true, force: true });
  await rm(DIST_DIR, { recursive: true, force: true });
  await mkdir(TEMP_DIR, { recursive: true });
  await mkdir(DIST_DIR, { recursive: true });

  const sourceUrls = [
    ...new Set(cleanLines(await readInput(INPUTS.sources)).map((l) => l.split(/\s+/)[0])),
  ];
  log(`Sources: ${sourceUrls.length}`);

  // 1 + 2. Download each source into ./temp in parallel, then merge in the order listed.
  const results = await Promise.allSettled(
    sourceUrls.map(async (url, i) => {
      const text = await readInput(url);
      await writeFile(join(TEMP_DIR, `${String(i + 1).padStart(2, '0')}.txt`), text);
      return parseList(text);
    }),
  );

  await writeFile(
    join(TEMP_DIR, 'manifest.txt'),
    sourceUrls.map((url, i) => `${String(i + 1).padStart(2, '0')}.txt\t${url}`).join('\n') + '\n',
  );

  const blocked = new Set();
  const passthrough = new Set();
  const failed = [];
  let sourceAllowRules = 0;

  results.forEach((r, i) => {
    const url = sourceUrls[i];
    if (r.status === 'rejected') {
      failed.push(url);
      log(`  FAILED  ${url}\n          ${r.reason?.message ?? r.reason}`);
      return;
    }
    const p = r.value;
    p.domains.forEach((d) => blocked.add(d));
    p.passthrough.forEach((l) => passthrough.add(l));
    sourceAllowRules += p.exceptions.size; // allow rules inside source lists are ignored, counted for the log
    log(`  ok      ${url}  (${p.domains.size} domains, ${p.ignored} ignored)`);
  });

  // 3. Whitelist: remove matching domains (and subdomains) from the combined sources.
  const wl = parseList(await readInput(INPUTS.whitelist));
  const allow = new Set([...wl.domains, ...wl.exceptions]);

  let removedByAllow = 0;
  for (const d of blocked) {
    if (isAllowed(d, allow)) {
      blocked.delete(d);
      removedByAllow++;
    }
  }

  let removedPassthrough = 0;
  for (const line of passthrough) {
    const host = ADBLOCK_HOST_PREFIX_RE.exec(line)?.[1]?.toLowerCase();
    if (host && isAllowed(host, allow)) {
      passthrough.delete(line);
      removedPassthrough++;
    }
  }

  // 4. Blacklist: add every listed domain. Blacklist wins over whitelist when both match.
  const bl = parseList(await readInput(INPUTS.blacklist));
  const conflicts = [];
  for (const d of bl.domains) {
    if (isAllowed(d, allow)) conflicts.push(d);
    blocked.add(d);
  }
  bl.passthrough.forEach((l) => passthrough.add(l));

  // 5. Write output.
  const domainRules = [...blocked].sort().map((d) => `||${d}^`);
  const otherRules = [...passthrough].sort();
  const generated = new Date().toISOString();

  const header = [
    `! Title: ${TITLE}`,
    `! Generated: ${generated}`,
    `! Source lists: ${sourceUrls.length} (failed: ${failed.length})`,
    `! Whitelist entries: ${allow.size}; blacklist entries: ${bl.domains.size}`,
    `! Domain rules: ${domainRules.length}; other rules: ${otherRules.length}`,
    `! Removed by whitelist: ${removedByAllow} domains, ${removedPassthrough} rules`,
    '!',
  ];

  await writeFile(join(DIST_DIR, 'blacklist.txt'), [...header, ...domainRules, ...otherRules].join('\n') + '\n');

  await writeFile(
    join(DIST_DIR, 'index.html'),
    `<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(TITLE)}</title>
<h1>${escapeHtml(TITLE)}</h1>
<p>Updated ${escapeHtml(generated)}</p>
<p><a href="blacklist.txt">blacklist.txt</a>: ${domainRules.length} domain rules, ${otherRules.length} other rules</p>
<p>Failed sources: ${failed.length}</p>
`,
  );

  if (sourceAllowRules) log(`Ignored ${sourceAllowRules} allow rules found inside source lists (use whitelist.txt instead).`);
  if (conflicts.length) {
    log(`Warning: ${conflicts.length} blacklisted domain(s) also match the whitelist; blacklist kept:`);
    conflicts.slice(0, 20).forEach((d) => log(`  - ${d}`));
  }
  log(`Done: ${domainRules.length} domain rules, ${otherRules.length} other rules -> dist/blacklist.txt`);
}

main().catch((err) => {
  console.error(`Build failed: ${err.message}`);
  process.exit(1);
});
