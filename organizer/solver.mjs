/*
 * KCTF:HYDRA — reference solver + full-playthrough test harness
 * ------------------------------------------------------------------
 * NOT deployed (see .vercelignore). This file proves the challenge is
 * winnable: it solves every gate purely from its prompt (black box),
 * pays the required proof-of-work, then plays all 1000 gates over HTTP
 * against a live server and verifies the final flag.
 *
 *   node organizer/solver.mjs             # full 1000-gate HTTP playthrough
 *   node organizer/solver.mjs --inprocess # same, without opening a socket
 *   node organizer/solver.mjs --nofetch   # in-memory solve of all gates
 */
import { createRequire } from 'node:module';
import http from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const gate = require('../api/gate.js');
const { makeRng, buildLayer, nextState, verifyToken, powBits } = gate._internals;
const { b32decode, b58decode, rot13 } = gate._internals.encodings;

const constants = JSON.parse(fs.readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), 'constants.json'), 'utf8'));
const SEED = constants.seed;
const FLAG = constants.flag;
const TOTAL = 1000;

/* ======================= number theory ======================= */

const BI = (v) => BigInt(v);
function eg(a, b) {
  if (b === 0n) return { g: a, x: 1n, y: 0n };
  const r = eg(b, a % b);
  return { g: r.g, x: r.y, y: r.x - (a / b) * r.y };
}
const modinv = (a, m) => ((eg(BigInt(a) % BigInt(m), BigInt(m)).x % BigInt(m)) + BigInt(m)) % BigInt(m);
function powmod(a, e, m) { let r = 1n; a %= m; while (e > 0n) { if (e & 1n) r = (r * a) % m; a = (a * a) % m; e >>= 1n; } return r; }
function md5hex(s) { return crypto.createHash('md5').update(s, 'utf8').digest('hex'); }
function isPrimeW(n) {
  n = BigInt(n);
  if (n < 2n) return false;
  for (const p of [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n]) {
    if (n % p === 0n) return n === p;
  }
  let d = n - 1n, r = 0n;
  while (d % 2n === 0n) { d /= 2n; r++; }
  for (const a of [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n]) {
    let x = powmod(a % n, d, n);
    if (x === 1n || x === n - 1n) continue;
    let ok = false;
    for (let i = 1n; i < r; i++) { x = (x * x) % n; if (x === n - 1n) { ok = true; break; } }
    if (!ok) return false;
  }
  return true;
}
function gcdBig(a, b) { a = BigInt(a); b = BigInt(b); while (b) { const t = a % b; a = b; b = t; } return a; }
function pollard(N) {
  N = BigInt(N);
  if (N % 2n === 0n) return 2n;
  if (isPrimeW(N)) return N;
  for (let c = 1n; ; c += 1n) {
    let x = 2n, y = 2n, d = 1n;
    while (d === 1n) {
      x = (x * x + c) % N;
      y = (y * y + c) % N; y = (y * y + c) % N;
      d = gcdBig(x > y ? x - y : y - x, N);
    }
    if (d !== N) return d;
  }
}
function smallestFactor(N) {
  N = BigInt(N);
  for (let f = 3n; f <= 100000n; f += 2n) if (N % f === 0n) return f;
  const d = pollard(N);
  return d < N / d ? d : N / d;
}
function tonelliShanks(n, p) {
  n = ((n % p) + p) % p;
  if (powmod(n, (p - 1n) / 2n, p) !== 1n) return null;
  if (p % 4n === 3n) return powmod(n, (p + 1n) / 4n, p);
  let s = 0n, q = p - 1n;
  while (q % 2n === 0n) { q /= 2n; s++; }
  let z = 2n;
  while (powmod(z, (p - 1n) / 2n, p) !== p - 1n) z++;
  let m = s, c = powmod(z, q, p), t = powmod(n, q, p), r = powmod(n, (q + 1n) / 2n, p);
  for (let guard = 0; guard < 10000; guard++) {
    if (t === 1n) return r;
    let i = 0n, t2 = t;
    while (t2 !== 1n) { t2 = (t2 * t2) % p; i++; if (i === m) return null; }
    const b = powmod(c, 1n << (m - i - 1n), p);
    m = i; c = (b * b) % p; t = (t * c) % p; r = (r * b) % p;
  }
  return null;
}
function bsgs(g, h, p, maxExp) {
  g = BigInt(g); h = BigInt(h); p = BigInt(p);
  const m = 1n << 12n;
  const table = new Map();
  let e = 1n;
  for (let j = 0n; j < m; j++) { if (!table.has(e)) table.set(e, j); e = (e * g) % p; }
  const factor = powmod(modinv(g, p), m, p);
  let gamma = h;
  const limit = maxExp || p;
  for (let i = 0n; i <= limit / m; i++) {
    const hit = table.get(gamma);
    if (hit !== undefined) {
      const x = i * m + hit;
      if (powmod(g, x, p) === h) return x;
    }
    gamma = (gamma * factor) % p;
  }
  throw new Error('bsgs failed');
}
function crt(pairs) {
  let x = 0n, M = 1n;
  for (const [m, r] of pairs) {
    const mm = BigInt(m), rr = ((BigInt(r) - x) % mm + mm) % mm;
    const inv = modinv(M % mm, mm);
    const t = (rr * inv) % mm;
    x = x + M * t;
    M = M * mm;
  }
  return ((x % M) + M) % M;
}

/* ======================= proof-of-work ======================= */

function solvePow(token, idx, answer, bits) {
  let nonce = 0;
  for (;;) {
    const d = crypto.createHash('sha256').update(`${token}.${idx}.${answer}.${nonce}`, 'utf8').digest();
    let z = 0;
    for (const byte of d) { if (byte === 0) { z += 8; continue; } z += 31 - Math.clz32(byte); break; }
    if (z >= bits) return String(nonce);
    nonce++;
  }
}

/* ======================= classical cipher helpers ======================= */

const ENG = [8.2, 1.5, 2.8, 4.3, 13, 2.2, 2, 6.1, 7, 0.15, 0.77, 4, 2.4, 6.7, 7.5, 1.9, 0.095, 6, 6.3, 9.1, 2.8, 0.98, 2.4, 0.15, 2, 0.074]
  .map((v) => v / 100);
/* dictionary used only to resolve near-miss columns after the frequency
 * attack seeds the key (organizer-side aid; players use any wordlist). */
const DICT = new Set([
  'time', 'year', 'people', 'water', 'light', 'night', 'world', 'heart',
  'stone', 'river', 'storm', 'ember', 'hollow', 'shadow', 'silver', 'quiet',
  'thunder', 'window', 'travel', 'future', 'garden', 'mirror', 'orange',
  'purple', 'forest', 'island', 'circle', 'summer', 'winter', 'spring',
  'autumn', 'castle', 'bridge', 'market', 'temple', 'anchor', 'planet',
  'cosmic', 'nebula', 'pulsar', 'quasar', 'orbit', 'lunar', 'solar',
  'comet', 'meteor', 'grove', 'meadow', 'valley', 'mountain', 'canyon',
  'desert', 'ocean', 'wave', 'tide', 'shore', 'sand', 'cloud', 'rain',
  'snow', 'wind', 'frost', 'flame', 'spark', 'ash', 'smoke', 'dust',
  'seed', 'root', 'leaf', 'branch', 'trunk', 'bark', 'pine', 'oak',
  'maple', 'cedar', 'birch', 'willow', 'fern', 'moss', 'vine', 'thorn',
  'rose', 'lily', 'daisy', 'petal', 'stem', 'bloom', 'bud', 'field',
  'plain', 'plateau', 'ridge', 'slope', 'summit', 'peak', 'cliff',
  'cavern', 'grotto', 'glen', 'dale', 'brook', 'creek', 'stream',
  'lake', 'pond', 'marsh', 'swamp', 'bog', 'delta', 'haven', 'harbor',
  'cove', 'bay', 'gulf', 'reef', 'atoll', 'lagoon', 'strait', 'sound',
  'beacon', 'lantern', 'tower', 'spire', 'dome', 'arch', 'pillar', 'column',
  'vault', 'portal', 'gate', 'wall', 'moat', 'drawbridge', 'turret', 'keep'
]);
function dictScore(text) {
  let n = 0;
  for (const w of text.split(' ')) if (DICT.has(w)) n++;
  return n;
}
function vigDecrypt(ct, key, kl) {
  let out = '', j = 0;
  for (const ch of ct) {
    if (ch >= 'a' && ch <= 'z') {
      const k = key[(j++) % kl];
      out += String.fromCharCode(((ch.charCodeAt(0) - 97 - k + 26) % 26) + 97);
    } else out += ch;
  }
  return out;
}
function chiSquare(text) {
  const counts = new Array(26).fill(0);
  let total = 0;
  for (const ch of text) {
    if (ch >= 'a' && ch <= 'z') { counts[ch.charCodeAt(0) - 97]++; total++; }
  }
  if (!total) return Infinity;
  let score = 0;
  for (let x = 0; x < 26; x++) {
    const e = total * ENG[x];
    score += ((counts[x] - e) * (counts[x] - e)) / e;
  }
  return score / total;
}
function vigSeedKey(ct, kl) {
  const letters = ct.replace(/[^a-z]/g, '');
  const key = [];
  for (let c = 0; c < kl; c++) {
    const counts = new Array(26).fill(0);
    let n = 0;
    for (let i = c; i < letters.length; i += kl) { counts[letters.charCodeAt(i) - 97]++; n++; }
    let bs = 0, bsc = Infinity;
    for (let s = 0; s < 26; s++) {
      let sc = 0;
      for (let x = 0; x < 26; x++) {
        const o = counts[(x + s) % 26];
        const e = n * ENG[x];
        sc += ((o - e) * (o - e)) / e;
      }
      if (sc < bsc) { bsc = sc; bs = s; }
    }
    key.push(bs);
  }
  return key;
}
function solveVigenere(ct) {
  let best = null;
  for (let kl = 5; kl <= 9; kl++) {
    const key = vigSeedKey(ct, kl);
    /* coordinate ascent: fix one column at a time against a wordlist score */
    for (let round = 0; round < 6; round++) {
      let changed = false;
      for (let c = 0; c < kl; c++) {
        const cur = key[c];
        let bs = cur, bsc = dictScore(vigDecrypt(ct, key, kl));
        for (let s = 0; s < 26; s++) {
          if (s === cur) continue;
          key[c] = s;
          const sc = dictScore(vigDecrypt(ct, key, kl));
          if (sc > bsc) { bsc = sc; bs = s; }
        }
        key[c] = bs;
        if (bs !== cur) changed = true;
      }
      if (!changed) break;
    }
    const dec = vigDecrypt(ct, key, kl);
    const score = dictScore(dec);
    if (!best || score > best.score) best = { score, dec, kl };
  }
  return best.dec;
}
function inv2x2(m) {
  /* inverse of a 2x2 integer matrix mod 26 */
  const det = ((m[0][0] * m[1][1] - m[0][1] * m[1][0]) % 26 + 26) % 26;
  const g26 = (a, b) => { while (b) { const t = a % b; a = b; b = t; } return a; };
  if (g26(det, 26) !== 1) throw new Error('singular hill matrix');
  const di = Number(modinv(det, 26n));
  return [
    [(((m[1][1] % 26) * di) % 26 + 26) % 26, (((-m[0][1] % 26) * di) % 26 + 26) % 26],
    [(((-m[1][0] % 26) * di) % 26 + 26) % 26, (((m[0][0] % 26) * di) % 26 + 26) % 26]
  ];
}
function solveHill(ct) {
  const toN = (ch) => ch.charCodeAt(0) - 97;
  /* columns are the known plaintext digraphs "hy" and "dr" */
  const P0 = [[toN('h'), toN('d')], [toN('y'), toN('r')]];
  /* columns are the first two ciphertext digraphs */
  const C0 = [[toN(ct[0]), toN(ct[2])], [toN(ct[1]), toN(ct[3])]];
  const P0i = inv2x2(P0);
  /* K = C0 * P0^{-1} (mod 26) */
  const K = [
    [(C0[0][0] * P0i[0][0] + C0[0][1] * P0i[1][0]) % 26, (C0[0][0] * P0i[0][1] + C0[0][1] * P0i[1][1]) % 26],
    [(C0[1][0] * P0i[0][0] + C0[1][1] * P0i[1][0]) % 26, (C0[1][0] * P0i[0][1] + C0[1][1] * P0i[1][1]) % 26]
  ];
  const Ki = inv2x2(K);
  let out = '';
  for (let i = 0; i < ct.length; i += 2) {
    const c0 = toN(ct[i]), c1 = toN(ct[i + 1]);
    const p0 = (Ki[0][0] * c0 + Ki[0][1] * c1) % 26;
    const p1 = (Ki[1][0] * c0 + Ki[1][1] * c1) % 26;
    out += String.fromCharCode(97 + p0) + String.fromCharCode(97 + p1);
  }
  return out;
}
function rotBlock(arr, start, count, dir) {
  if (count <= 1) return;
  if (dir === 1) { /* left-rotate the block */
    const first = arr[start];
    for (let i = start; i < start + count - 1; i++) arr[i] = arr[i + 1];
    arr[start + count - 1] = first;
  } else {
    const last = arr[start + count - 1];
    for (let i = start + count - 1; i > start; i--) arr[i] = arr[i - 1];
    arr[start] = last;
  }
}
function solveChaocipher(p) {
  const L = p.left.split('');
  const R = p.right.split('');
  let out = '';
  for (const ch of p.ciphertext) {
    /* drive the same stepping from the ciphertext letter's position */
    const i = L.indexOf(ch);
    out += R[i];
    rotBlock(L, 0, 26, 1);                       /* (1) whole left disk left-rotate */
    const rCh = R.splice(i, 1)[0]; R.unshift(rCh); /* (2) R[i] -> front of R       */
    rotBlock(L, 1, 12, 1);                       /* (3) block L[1..12] left-rotate */
    rotBlock(R, 2, 12, 1);                       /* (4) block R[2..13] left-rotate */
  }
  return out;
}
function solvePlayfair(p) {
  const sq = p.square;
  let out = '';
  const ct = p.ciphertext;
  for (let i = 0; i < ct.length; i += 2) {
    const a = ct[i], b = ct[i + 1];
    const ia = sq.indexOf(a), ib = sq.indexOf(b);
    const ra = Math.floor(ia / 5), ca = ia % 5, rb = Math.floor(ib / 5), cb = ib % 5;
    let na, nb;
    if (ra === rb) { na = sq[ra * 5 + ((ca + 4) % 5)]; nb = sq[rb * 5 + ((cb + 4) % 5)]; }
    else if (ca === cb) { na = sq[((ra + 4) % 5) * 5 + ca]; nb = sq[((rb + 4) % 5) * 5 + cb]; }
    else { na = sq[ra * 5 + cb]; nb = sq[rb * 5 + ca]; }
    out += na + nb;
  }
  return out.replace(/x/g, '');
}
function solveColumnar(p) {
  const n = p.ciphertext.length;
  const k = p.order.length;
  const rows = Math.ceil(n / k);
  const empty = k * rows - n;
  const colLen = [];
  for (let j = 0; j < k; j++) colLen.push(j < k - empty ? rows : rows - 1);
  const cols = new Array(k).fill('');
  let pos = 0;
  for (const c of p.order) {
    cols[c] = p.ciphertext.slice(pos, pos + colLen[c]);
    pos += colLen[c];
  }
  let out = '';
  for (let r = 0; r < rows; r++) {
    for (let c = 0; c < k; c++) {
      if (r < colLen[c]) out += cols[c][r];
    }
  }
  return out;
}

/* ======================= black-box solvers ======================= */
/* Every solver works ONLY from the public prompt (plus, for `recall`,
 * the answers the solver itself recorded earlier in the same run). */

/* 2 — repeating-key XOR: crib drag over an unknown keystream length */
const XOR_CRIB = 'theserpentwakes';
function solveXor(p) {
  const ct = Buffer.from(p.data, 'hex');
  const decs = new Set();
  for (let kk = 4; kk <= 10; kk++) {
    const key = [];
    for (let j = 0; j < kk; j++) key.push(ct[j] ^ XOR_CRIB.charCodeAt(j));
    let s = '', all = true;
    for (let i = 0; i < ct.length; i++) {
      const ch = String.fromCharCode(ct[i] ^ key[i % kk]);
      if (!(ch >= 'a' && ch <= 'z')) { all = false; break; }
      s += ch;
    }
    if (all) decs.add(s);
  }
  if (decs.size !== 1) throw new Error('xor ambiguity: ' + decs.size + ' distinct plaintexts');
  return [...decs][0];
}
function solveAffine(p) {
  const toN = (ch) => ch.charCodeAt(0) - 97;
  /* known plaintext "gate": use the pair ('a','t') whose difference 19 is a unit mod 26 */
  const ca = toN(p.data[1]), ct = toN(p.data[2]);
  const diff = ((ct - ca) % 26 + 26) % 26;
  const a = ((diff * Number(modinv(19, 26n))) % 26 + 26) % 26;
  const b = ca; /* plaintext 'a' (0) maps to ca */
  const ia = Number(modinv(a, 26n));
  let out = '';
  for (const ch of p.data) {
    const y = toN(ch);
    out += String.fromCharCode(97 + ((ia * (((y - b) % 26 + 26) % 26)) % 26));
  }
  return out;
}
function solveMultibase(p) {
  const order = p.desc.match(/Applied in order: ([^.]+)\.$/)[1].split(' -> ');
  let cur = p.data;
  for (let i = order.length - 1; i >= 0; i--) {
    const t = order[i];
    if (t === 'base64') cur = Buffer.from(cur, 'base64').toString('ascii');
    else if (t === 'base32') cur = b32decode(cur).toString('ascii');
    else if (t === 'hex') cur = Buffer.from(cur, 'hex').toString('ascii');
    else if (t === 'base58') cur = b58decode(cur).toString('ascii');
    else if (t === 'rot13') cur = rot13(cur);
    else if (t === 'reverse') cur = cur.split('').reverse().join('');
    else throw new Error('unknown transform ' + t);
  }
  return cur;
}

function solve(p, ctx) {
  switch (p.family) {
    case 'multibase': return solveMultibase(p);
    case 'xor': return solveXor(p);
    case 'affine': return solveAffine(p);
    case 'vigenere': return solveVigenere(p.data);
    case 'pin': {
      for (let i = 0; i < 1000000; i++) {
        const pin = String(i).padStart(6, '0');
        if (md5hex(pin) === p.data) return pin;
      }
      throw new Error('pin not found');
    }
    case 'modinv': return modinv(p.data.a, p.data.m).toString();
    case 'modexp': return powmod(BigInt(p.data.a), BigInt(p.data.e), BigInt(p.data.m)).toString();
    case 'semiprime': return smallestFactor(p.data).toString();
    case 'popcount': {
      let n = 0n, t = BigInt(p.data);
      while (t > 0n) { n += t & 1n; t >>= 1n; }
      return n.toString();
    }
    case 'lcg': {
      const M = 4294967296n;
      const xs = p.data.map(BigInt); /* x1..x4 */
      const d1 = ((xs[1] - xs[0]) % M + M) % M; /* odd */
      const d2 = ((xs[2] - xs[1]) % M + M) % M;
      const a = (d2 * modinv(d1, M)) % M;
      const c = ((xs[1] - a * xs[0]) % M + M) % M;
      return ((a * xs[3] + c) % M).toString();
    }
    case 'zwsp': {
      const zchars = p.data.match(/[\u200B\u200C\u200D]/g) || [];
      const bits = [];
      for (const ch of zchars) {
        if (ch === '\u200D') continue;
        bits.push(ch === '\u200C' ? 1 : 0);
      }
      let out = '';
      for (let i = 0; i + 8 <= bits.length; i += 8) {
        let b = 0;
        for (let j = 0; j < 8; j++) b = (b << 1) | bits[i + j];
        out += String.fromCharCode(b);
      }
      return out;
    }
    case 'wsb': {
      const lines = p.data.split('\n');
      const bits = lines.map((l) => (l.length - l.replace(/ +$/, '').length) % 2);
      let out = '';
      for (let i = 0; i + 8 <= bits.length; i += 8) {
        let b = 0;
        for (let j = 0; j < 8; j++) b = (b << 1) | bits[i + j];
        out += String.fromCharCode(b);
      }
      return out;
    }
    case 'custombase': {
      const A = p.desc.match(/alphabet: "([^"]+)"/)[1];
      const bytes = [];
      let acc = 0, nb = 0;
      for (const ch of p.data) {
        const v = A.indexOf(ch);
        if (v < 0) throw new Error('bad char');
        acc = (acc << 5) | v; nb += 5;
        if (nb >= 8) { nb -= 8; bytes.push((acc >>> nb) & 255); }
      }
      return Buffer.from(bytes).toString('ascii');
    }
    case 'ordwalk': {
      const K = Number(p.desc.match(/i\*(\d+)/)[1]);
      let out = '';
      p.data.forEach((v, i) => { out += String.fromCharCode(((v - i * K) % 256 + 256) % 256); });
      return out;
    }
    case 'hill': return solveHill(p.data);
    case 'crt': return crt(p.data.map(([m, r]) => [m, r])).toString();
    case 'dlog': return bsgs(p.data.g, p.data.h, p.data.p, 1n << 18n).toString();
    case 'modsqrt': {
      const p_ = BigInt(p.data.p), z = BigInt(p.data.z);
      const r = tonelliShanks(z, p_);
      if (r === null) throw new Error('no sqrt');
      const small = r < p_ - r ? r : p_ - r;
      return small.toString();
    }
    case 'chaocipher': return solveChaocipher(p.data);
    case 'playfair': return solvePlayfair(p.data);
    case 'columnar': return solveColumnar(p.data);
    case 'recall': {
      const a = p.data.first, b = p.data.second;
      const ansA = ctx.answers[a.gate - 1];
      const ansB = ctx.answers[b.gate - 1];
      if (!ansA || !ansB) throw new Error('recall history missing');
      return ansA[a.pos - 1] + ansB[b.pos - 1];
    }
    default:
      throw new Error('unknown family ' + p.family);
  }
}

/* ======================= harness helpers ======================= */

function attempt(prompt, ctx) {
  const given = String(solve(prompt, ctx)).trim().toLowerCase();
  if (!given) throw new Error('empty solve result');
  return given;
}

/* ======================= in-memory full run ====================== */

function runMemory() {
  const stats = {};
  const answers = [];
  let st = crypto.createHash('sha256').update('hydra-init|' + SEED).digest('hex');
  for (let i = 0; i < TOTAL; i++) {
    const base = Math.max(0, i - 8);
    const layer = buildLayer(SEED, i, st, answers.slice(base), base);
    const got = attempt(layer, { answers });
    stats[layer.family] = (stats[layer.family] || 0) + 1;
    if (got !== layer.answer) {
      console.log('MISMATCH at gate ' + i + ' family=' + layer.family);
      console.log('  expected=' + JSON.stringify(layer.answer).slice(0, 200));
      console.log('  got=' + JSON.stringify(got).slice(0, 200));
      process.exit(1);
    }
    answers.push(layer.answer);
    st = nextState(st, layer.answer);
  }
  console.log('[memory] ' + TOTAL + '/' + TOTAL + ' gates solved.');
  console.log('[family coverage]', JSON.stringify(stats));
}

/* ======================= HTTP full playthrough =================== */

async function runHttp() {
  const server = http.createServer(gate);
  await new Promise((r) => server.listen(8791, r));
  const base = 'http://127.0.0.1:8791/api/gate';
  const req = async (op, body) => {
    const r = await fetch(base + '?op=' + op, {
      method: body ? 'POST' : 'GET',
      headers: { 'content-type': 'application/json' },
      body: body ? JSON.stringify(body) : undefined
    });
    return r.json();
  };

  let r = await req('start', { seed: SEED });
  if (!r.ok) { console.log('start failed', r); process.exit(1); }
  let token = r.token, idx = r.idx;
  const stats = {};
  const answers = [];

  while (true) {
    const prompt = r.prompt;
    const got = attempt(prompt, { answers });
    const nonce = solvePow(token, idx, got, prompt.work);
    stats[prompt.family] = (stats[prompt.family] || 0) + 1;
    r = await req('check', { token, answer: got, pow: nonce });
    if (!r.ok && !r.done) {
      console.log('REJECTED at gate ' + idx + ' (' + prompt.family + ') answer=' + got);
      console.log(JSON.stringify(prompt).slice(0, 400));
      process.exit(1);
    }
    answers.push(got);
    idx = r.idx;
    if (r.done) {
      console.log('[http] done at gate ' + idx + '/' + TOTAL + '. flag=' + r.flag);
      if (r.flag !== FLAG) { console.log('FLAG MISMATCH! expected ' + FLAG); process.exit(1); }
      console.log('[family coverage]', JSON.stringify(stats));
      console.log('[http] FULL PLAYTHROUGH PASSED — flag matches organizer copy.');
      break;
    }
    token = r.token;
  }
  server.close();
}

/* Same full API playthrough without opening a local TCP listener (useful in
 * restricted sandboxes). It invokes the exact Vercel handler with HTTP-shaped
 * request/response objects, so routing, token verification, PoW and JSON
 * responses remain covered end-to-end. */
async function runInProcess() {
  const invoke = async (op, body) => new Promise((resolve) => {
    const res = { headers: {}, setHeader(k, v) { this.headers[k] = v; }, end(s) { resolve(JSON.parse(s)); } };
    gate({ method: body ? 'POST' : 'GET', url: '/api/gate?op=' + op, body: body || undefined }, res);
  });
  let r = await invoke('start', { seed: SEED });
  if (!r.ok) throw new Error('start failed: ' + JSON.stringify(r));
  let token = r.token, idx = r.idx;
  const stats = {};
  const answers = [];
  while (true) {
    const prompt = r.prompt;
    const got = attempt(prompt, { answers });
    const nonce = solvePow(token, idx, got, prompt.work);
    stats[prompt.family] = (stats[prompt.family] || 0) + 1;
    r = await invoke('check', { token, answer: got, pow: nonce });
    if (!r.ok && !r.done) throw new Error('REJECTED at gate ' + idx + ': ' + JSON.stringify(r));
    answers.push(got);
    idx = r.idx;
    if (r.done) {
      if (r.flag !== FLAG) throw new Error('FLAG MISMATCH: ' + r.flag);
      console.log('[handler] done at gate ' + idx + '/' + TOTAL + '. flag=' + r.flag);
      console.log('[family coverage]', JSON.stringify(stats));
      console.log('[handler] FULL PLAYTHROUGH PASSED — flag matches organizer copy.');
      break;
    }
    token = r.token;
  }
}

if (process.argv.includes('--inprocess')) runInProcess().catch((e) => { console.error(e); process.exit(1); });
else if (process.argv.includes('--nofetch')) runMemory();
else runHttp().catch((e) => { console.error(e); process.exit(1); });
