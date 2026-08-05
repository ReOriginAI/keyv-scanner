#!/usr/bin/env bash
set -u

ROOT="${1:-/}"
BAD_VERSION="${BAD_VERSION:-6.0.0}"

if ! command -v node >/dev/null 2>&1; then
  echo "ERROR: node is required (npm projects imply Node.js, but node was not found)." >&2
  exit 3
fi
if [[ ! -d "$ROOT" ]]; then
  echo "ERROR: scan root is not a directory: $ROOT" >&2
  exit 3
fi

TMP_DIR="$(mktemp -d)" || exit 3
trap 'rm -rf "$TMP_DIR"' EXIT INT TERM
FILE_LIST="$TMP_DIR/files.nul"
FIND_ERRORS="$TMP_DIR/find-errors.log"

# Do not descend into virtual kernel filesystems or VCS metadata. We still
# descend into node_modules because keyv can be nested/transitive.
find "$ROOT" \
  \( -type d \( \
       -path /proc -o -path /sys -o -path /dev -o -path /run -o \
       -path '*/.git' -o -path '*/.hg' -o -path '*/.svn' \
     \) -prune \) -o \
  \( -type f \( \
       \( -name package.json \( -path '*/node_modules/keyv/package.json' -o ! -path '*/node_modules/*' \) \) -o \
       \( \( -name package-lock.json -o -name npm-shrinkwrap.json -o \
              -name yarn.lock -o -name pnpm-lock.yaml -o \
              -name bun.lock -o -name bun.lockb \) \
          ! -path '*/node_modules/*' \) \
     \) -print0 \) \
  >"$FILE_LIST" 2>"$FIND_ERRORS"
FIND_STATUS=$?

node - "$BAD_VERSION" "$FILE_LIST" <<'NODE'
'use strict';

const fs = require('fs');
const path = require('path');

const BAD = process.argv[2];
const badParts = parseVersion(BAD);
if (!badParts) {
  console.error(`ERROR: invalid BAD_VERSION: ${BAD}`);
  process.exit(3);
}

const input = fs.readFileSync(process.argv[3]).toString('utf8');
const files = input.split('\0').filter(Boolean);

const confirmed = new Map();
const risky = new Map();
const incomplete = [];
let scanned = 0;

function add(map, file, detail) {
  map.set(`${file}\0${detail}`, { file, detail });
}

function parseVersion(value) {
  const m = String(value).trim().replace(/^v/, '').match(/^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-[0-9A-Za-z.-]+)?$/);
  if (!m) return null;
  return [Number(m[1]), Number(m[2] || 0), Number(m[3] || 0)];
}

function cmp(a, b) {
  for (let i = 0; i < 3; i++) {
    if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
  }
  return 0;
}

function expandXRange(token) {
  const raw = token.replace(/^v/, '');
  const parts = raw.split('.');
  const isX = p => p === undefined || /^(?:x|\*)$/i.test(p);
  if (isX(parts[0])) return { low: [0, 0, 0], high: null };
  const major = Number(parts[0]);
  if (!Number.isInteger(major)) return null;
  if (isX(parts[1])) return { low: [major, 0, 0], high: [major + 1, 0, 0] };
  const minor = Number(parts[1]);
  if (!Number.isInteger(minor)) return null;
  if (isX(parts[2])) return { low: [major, minor, 0], high: [major, minor + 1, 0] };
  const patch = Number(parts[2]);
  if (!Number.isInteger(patch)) return null;
  return { exact: [major, minor, patch] };
}

function comparatorMatches(target, token) {
  token = token.trim();
  if (!token || token === '*') return true;

  const opMatch = token.match(/^(<=|>=|<|>|=|~|\^)?\s*(.+)$/);
  if (!opMatch) return null;
  const op = opMatch[1] || '';
  const raw = opMatch[2].trim();

  if (/^(?:latest|next|beta|alpha|canary)$/i.test(raw)) return null;
  const xr = expandXRange(raw);
  if (!xr) return null;

  if (!op) {
    if (xr.exact) return cmp(target, xr.exact) === 0;
    return cmp(target, xr.low) >= 0 && (!xr.high || cmp(target, xr.high) < 0);
  }

  const v = xr.exact || xr.low;
  if (op === '=') return cmp(target, v) === 0;
  if (op === '<') return cmp(target, v) < 0;
  if (op === '<=') return cmp(target, v) <= 0;
  if (op === '>') return cmp(target, v) > 0;
  if (op === '>=') return cmp(target, v) >= 0;

  if (op === '~') {
    const specified = raw.replace(/^v/, '').split('.').length;
    const high = specified <= 1 ? [v[0] + 1, 0, 0] : [v[0], v[1] + 1, 0];
    return cmp(target, v) >= 0 && cmp(target, high) < 0;
  }

  if (op === '^') {
    let high;
    if (v[0] > 0) high = [v[0] + 1, 0, 0];
    else if (v[1] > 0) high = [0, v[1] + 1, 0];
    else high = [0, 0, v[2] + 1];
    return cmp(target, v) >= 0 && cmp(target, high) < 0;
  }

  return null;
}

function clauseMayMatch(target, clause) {
  clause = clause.trim();
  if (!clause) return true;

  const hyphen = clause.match(/^\s*([^\s]+)\s+-\s+([^\s]+)\s*$/);
  if (hyphen) {
    const lo = parseVersion(hyphen[1]);
    const hi = parseVersion(hyphen[2]);
    return lo && hi ? cmp(target, lo) >= 0 && cmp(target, hi) <= 0 : null;
  }

  const tokens = clause.replace(/,/g, ' ').split(/\s+/).filter(Boolean);
  let unknown = false;
  for (const token of tokens) {
    const result = comparatorMatches(target, token);
    if (result === false) return false;
    if (result === null) unknown = true;
  }
  return unknown ? null : true;
}

function specMaySelectBad(spec) {
  if (typeof spec !== 'string') return { may: false, unknown: false };
  let s = spec.trim();
  s = s.replace(/^workspace:/, '');
  s = s.replace(/^npm:keyv@/, '');

  if (/^(?:file:|link:|git(?:\+|:)|https?:|github:|bitbucket:|gitlab:|\$)/i.test(s)) {
    return { may: true, unknown: true };
  }

  let sawUnknown = false;
  for (const clause of s.split('||')) {
    const result = clauseMayMatch(badParts, clause);
    if (result === true) return { may: true, unknown: false };
    if (result === null) sawUnknown = true;
  }
  return { may: sawUnknown, unknown: sawUnknown };
}

function isKeyvContext(trail, node) {
  if (node && node.name === 'keyv') return true;
  return trail.some(part => {
    const p = String(part);
    return p === 'keyv' || p === 'node_modules/keyv' || p.endsWith('/node_modules/keyv') || /(?:^|\/)keyv@[^/]+$/.test(p);
  });
}

function inspectLockJson(node, trail, file, seen = new Set()) {
  if (!node || typeof node !== 'object' || seen.has(node)) return;
  seen.add(node);

  if (node.version === BAD && isKeyvContext(trail, node)) {
    add(confirmed, file, `resolved keyv@${BAD} in JSON lockfile (${trail.join(' > ') || 'root'})`);
  }

  for (const [key, value] of Object.entries(node)) {
    inspectLockJson(value, trail.concat(key), file, seen);
  }
}

function inspectPackageJson(json, file) {
  if (file.replace(/\\/g, '/').endsWith('/node_modules/keyv/package.json')) {
    if (json && json.name === 'keyv' && json.version === BAD) {
      add(confirmed, file, `installed keyv@${BAD}`);
    }
    return;
  }

  const sections = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'];
  for (const section of sections) {
    const deps = json && json[section];
    if (!deps || typeof deps !== 'object') continue;
    if (Object.prototype.hasOwnProperty.call(deps, 'keyv')) {
      const spec = deps.keyv;
      const result = specMaySelectBad(spec);
      if (result.may) {
        add(risky, file, `${section}.keyv=${JSON.stringify(spec)} ${result.unknown ? '(cannot prove safe)' : `(can select ${BAD})`}`);
      }
    }
  }

  function inspectOverrideObject(obj, trail = []) {
    if (!obj || typeof obj !== 'object') return;
    for (const [key, value] of Object.entries(obj)) {
      if (key === 'keyv' || key.endsWith('>keyv') || key.endsWith('/keyv')) {
        if (typeof value === 'string') {
          const result = specMaySelectBad(value);
          if (result.may) add(risky, file, `${trail.concat(key).join('.')}=${JSON.stringify(value)} can select or reference ${BAD}`);
        } else if (value && typeof value === 'object' && typeof value['.'] === 'string') {
          const result = specMaySelectBad(value['.']);
          if (result.may) add(risky, file, `${trail.concat(key, '.').join('.')}=${JSON.stringify(value['.'])} can select or reference ${BAD}`);
        }
      }
      inspectOverrideObject(value, trail.concat(key));
    }
  }

  inspectOverrideObject(json && json.overrides, ['overrides']);
  inspectOverrideObject(json && json.resolutions, ['resolutions']);
}

function inspectTextLock(buffer, file) {
  const text = buffer.toString('latin1');
  const escaped = BAD.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const direct = new RegExp(`(?:^|[\\s"'/:,(])keyv@(?:npm:)?${escaped}(?=$|[\\s"':,)/])`, 'm');
  if (direct.test(text)) {
    add(confirmed, file, `lockfile contains resolved keyv@${BAD}`);
    return;
  }

  // Yarn v1/Berry: a keyv selector header followed by an exact version field.
  const lines = text.split(/\r?\n/);
  let keyvBlock = false;
  for (const line of lines) {
    if (/^\S/.test(line)) keyvBlock = /keyv@/.test(line);
    if (keyvBlock && new RegExp(`^\\s+version\\s*:?\\s*["']?${escaped}["']?\\s*$`).test(line)) {
      add(confirmed, file, `Yarn lock block resolves keyv@${BAD}`);
      return;
    }
  }
}

for (const file of files) {
  scanned++;
  let buffer;
  try {
    buffer = fs.readFileSync(file);
  } catch (err) {
    incomplete.push(`${file}: ${err.code || err.message}`);
    continue;
  }

  const base = path.basename(file);
  if (base === 'package.json' || base === 'package-lock.json' || base === 'npm-shrinkwrap.json') {
    try {
      const json = JSON.parse(buffer.toString('utf8'));
      if (base === 'package.json') inspectPackageJson(json, file);
      else inspectLockJson(json, [], file);
    } catch (err) {
      incomplete.push(`${file}: invalid/unreadable JSON (${err.message})`);
    }
  } else {
    inspectTextLock(buffer, file);
  }
}

console.log(`Scanned ${scanned} relevant manifest/lockfile(s).`);

if (confirmed.size) {
  console.log(`\nCOMPROMISED keyv@${BAD} FOUND:`);
  for (const { file, detail } of confirmed.values()) console.log(`  ${file}\n    ${detail}`);
}

if (risky.size) {
  console.log(`\nUNSAFE OR UNVERIFIABLE keyv declarations:`);
  for (const { file, detail } of risky.values()) console.log(`  ${file}\n    ${detail}`);
}

if (incomplete.length) {
  console.error(`\nFiles that could not be checked:`);
  for (const item of incomplete) console.error(`  ${item}`);
}

if (!confirmed.size && !risky.size && !incomplete.length) {
  console.log(`No reference to compromised keyv@${BAD} was found.`);
}

if (confirmed.size || risky.size) process.exit(1);
if (incomplete.length) process.exit(2);
process.exit(0);
NODE
SCAN_STATUS=$?

if [[ -s "$FIND_ERRORS" ]]; then
  echo >&2
  echo "Some filesystem paths could not be searched:" >&2
  sed 's/^/  /' "$FIND_ERRORS" >&2
fi

# 1 = compromised/risky; 2 = incomplete scan; 0 = clean and complete.
if [[ $SCAN_STATUS -eq 1 ]]; then
  exit 1
fi
if [[ $SCAN_STATUS -eq 2 || $FIND_STATUS -ne 0 || -s "$FIND_ERRORS" ]]; then
  exit 2
fi
exit 0
