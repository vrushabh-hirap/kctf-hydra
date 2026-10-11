'use strict';
/*
 * KCTF: HYDRA: THOUSANDFOLD — serverless gate engine
 * ------------------------------------------------------------------
 * Never served as a static asset (it lives under /api), so the layer
 * generator, chain math, sealed flag and proof-of-work policy are
 * invisible to players.
 *   ops: ?op=start   POST {seed}         -> issue signed token + gate 1
 *        ?op=check   POST {token,answer,pow} -> verify chain, next gate or flag
 *        ?op=ping    GET                 -> liveness
 *
 * Hardening (v2): gate RNG is keyed by TOKEN_SECRET, every check
 * requires a proof-of-work whose difficulty grows along the chain,
 * 22 puzzle families (most with hidden parameters), recall checkpoints
 * that bind the player's own previous answers, and a multi-block flag
 * keystream. Sessions live 72h. Everything stays deterministic so the
 * organizer harness can prove the run is winnable.
 */

const crypto = require('crypto');
const http = require('http');

/* ============================ CONFIG ============================ */

/* Public entry seed (organizer): sha256(A XOR B XOR C) of the 3 clue values. */
const EXPECTED_SEED = '464761fea19c7539e404bafce5ac0bc9017d525bd31affdb9761eb853fcb17b5';

/* Base64 of (flag_utf8 XOR block-keystream(sha256(FLAG_SECRET+'|hydro|block|'+i))). */
const SEALED_FLAG = 'VUqfE72pKXwFgUd+Tu5Qc7japjsHQVdH4nqklVoaAae3g6BNhRppYRE4RhJ+bFRAHuGSVoQ5It28L7C7ZeWY';

/* Both secrets are required in Vercel. Never ship development fallbacks. */
const FLAG_SECRET = process.env.FLAG_SECRET || '';
const TOKEN_SECRET = process.env.TOKEN_SECRET || '';
const TOTAL = 1000;
const SESSION_TTL = 72 * 60 * 60 * 1000; /* ms */
const HISTORY = 8; /* answers carried in the token for recall checkpoints */
const WORK_BASE = 16; /* proof-of-work bits on gate 1 */
const WORK_STEP = 100; /* +1 bit every WORK_STEP gates */
const WORK_MAX = 20;

/* ========================== CRYPTO UTILS ======================= */

const h256hex = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');
const h256buf = (s) => crypto.createHash('sha256').update(s, 'utf8').digest();

function egcd(a, b) {
  if (b === 0n) return { g: a, x: 1n, y: 0n };
  const r = egcd(b, a % b);
  return { g: r.g, x: r.y, y: r.x - (a / b) * r.y };
}
function gcdInt(a, b) { while (b) { const t = a % b; a = b; b = t; } return a; }
function isPrime(n) {
  if (n < 2n) return false;
  for (const p of [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n]) {
    if (n % p === 0n) return n === p;
  }
  let d = n - 1n, r = 0n;
  while (d % 2n === 0n) { d /= 2n; r += 1n; }
  for (const a of [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n]) {
    let x = 1n, base = a % n, e = d;
    while (e > 0n) { if (e & 1n) x = (x * base) % n; base = (base * base) % n; e >>= 1n; }
    if (x === 1n || x === n - 1n) continue;
    let composite = true;
    for (let i = 1n; i < r; i++) {
      x = (x * x) % n;
      if (x === n - 1n) { composite = false; break; }
    }
    if (composite) return false;
  }
  return true;
}
function powmod(a, e, m) {
  let r = 1n; a %= m;
  while (e > 0n) { if (e & 1n) r = (r * a) % m; a = (a * a) % m; e >>= 1n; }
  return r;
}

/* ============================ PRNG ============================== */
/* Counter-mode sha256, keyed by TOKEN_SECRET. Deterministic and
 * reproducible by the organizer harness, but a leaked handler alone
 * can no longer regenerate the chain: the server secret is required. */

const ALPHA = 'abcdefghijklmnopqrstuvwxyz';
const ALNUM = 'abcdefghijklmnopqrstuvwxyz0123456789';

function makeRng(label) {
  const key = h256buf('hydra-rng-key|' + TOKEN_SECRET + '|' + label);
  let ctr = 0;
  let buf = Buffer.alloc(0);
  let pos = 0;
  function next() {
    if (pos >= buf.length) {
      buf = crypto.createHash('sha256').update(Buffer.concat([key, Buffer.from(':' + (ctr++), 'utf8')])).digest();
      pos = 0;
    }
    return buf[pos++];
  }
  function int(min, max) {
    const range = BigInt(max - min + 1);
    let v = 0n;
    for (let i = 0; i < 8; i++) v = (v << 8n) | BigInt(next());
    return min + Number(v % range);
  }
  function bytes(n) {
    const out = Buffer.alloc(n);
    for (let i = 0; i < n; i++) out[i] = next();
    return out;
  }
  function big(bits) {
    let v = 0n;
    for (let i = 0; i < Math.ceil(bits / 8); i++) v = (v << 8n) | BigInt(next());
    return v % (1n << BigInt(bits));
  }
  function pick(arr) { return arr[int(0, arr.length - 1)]; }
  function token(n, cs) {
    cs = cs || ALNUM;
    let s = '';
    for (let i = 0; i < n; i++) s += cs[int(0, cs.length - 1)];
    return s;
  }
  function shuffle(arr) {
    for (let i = arr.length - 1; i > 0; i--) {
      const j = int(0, i);
      const t = arr[i]; arr[i] = arr[j]; arr[j] = t;
    }
    return arr;
  }
  return { next, int, bytes, big, pick, token, shuffle };
}

/* ========================== ENCODINGS =========================== */

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function b32encode(buf) {
  const chars = [];
  let acc = 0, nb = 0;
  for (const byte of buf) {
    acc = (acc << 8) | byte; nb += 8;
    while (nb >= 5) { nb -= 5; chars.push(B32[(acc >>> nb) & 31]); }
  }
  if (nb > 0) chars.push(B32[(acc << (5 - nb)) & 31]);
  return chars.join('');
}
function b32decode(str, alphabet) {
  const A = alphabet || B32;
  const out = [];
  let acc = 0, nb = 0;
  for (const ch of str) {
    const v = A.indexOf(ch);
    if (v < 0) throw new Error('bad b32 char');
    acc = (acc << 5) | v; nb += 5;
    if (nb >= 8) { nb -= 8; out.push((acc >>> nb) & 255); }
  }
  return Buffer.from(out);
}
function b58encode(buf) {
  let n = 0n;
  for (const b of buf) n = (n << 8n) | BigInt(b);
  let s = '';
  while (n > 0n) { s = B58[Number(n % 58n)] + s; n /= 58n; }
  for (const b of buf) { if (b === 0) s = '1' + s; else break; }
  return s || '1';
}
function b58decode(str) {
  let n = 0n;
  for (const ch of str) {
    const v = B58.indexOf(ch);
    if (v < 0) throw new Error('bad b58 char');
    n = n * 58n + BigInt(v);
  }
  const bytes = [];
  while (n > 0n) { bytes.unshift(Number(n & 255n)); n >>= 8n; }
  for (const ch of str) { if (ch === '1') bytes.unshift(0); else break; }
  return Buffer.from(bytes);
}
function rot13(s) {
  return s.replace(/[a-zA-Z]/g, (c) => {
    const base = c <= 'Z' ? 65 : 97;
    return String.fromCharCode((c.charCodeAt(0) - base + 13) % 26 + base);
  });
}

/* ========================= WORDSTOCK ============================ */
/* Organizer-side wordstock. Letters only, no j/x, so the classical
 * cipher families (Hill, Playfair, Chaocipher, columnar) get clean
 * plaintext and the Vigenere family gets English-looking statistics. */

const WORDS = [
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
  'rose', 'lily', 'daisy', 'petal', 'stem', 'bloom', 'bud', 'garden',
  'field', 'plain', 'plateau', 'ridge', 'slope', 'summit', 'peak', 'cliff',
  'cavern', 'grotto', 'hollow', 'glen', 'dale', 'brook', 'creek', 'stream',
  'lake', 'pond', 'marsh', 'swamp', 'bog', 'delta', 'haven', 'harbor',
  'cove', 'bay', 'gulf', 'reef', 'atoll', 'lagoon', 'strait', 'sound',
  'beacon', 'lantern', 'tower', 'spire', 'dome', 'arch', 'pillar', 'column',
  'vault', 'portal', 'gate', 'wall', 'moat', 'drawbridge', 'turret', 'keep'
];

function phrase(rng, spaced, minLen, maxLen) {
  const target = rng.int(minLen, maxLen);
  let out = '';
  while (out.length < target) {
    const w = rng.pick(WORDS);
    out += (out ? (spaced ? ' ' : '') : '') + w;
  }
  return out;
}

/* ========================= LAYER FAMILIES ======================= */
/* Each returns { family, title, desc, data, answer }.
 * Prompts are self-contained: everything needed to solve is visible.
 * Difficulty = scale (1000 chained gates) + breadth (22 domains)
 * + hidden-parameter cryptanalysis + per-gate proof-of-work. */

const AFFINE_A = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25];
const MB_TRANSFORMS = ['base64', 'base32', 'hex', 'base58', 'rot13', 'reverse'];
const ZW0 = '\u200B', ZW1 = '\u200C', ZWSEP = '\u200D';
const FILLER = [
  'the serpent whispers through the invisible',
  'channels between words carry the payload',
  'silence screams in unicode tones',
  'look beyond what your eyes render',
  'the untyped characters are the message'
];
const ORDWORD = ['serpent', 'circuit', 'oracle', 'ember', 'hollow', 'veil', 'anchor',
  'cipher', 'shroud', 'glyph', 'abyss', 'venom', 'quill', 'thorn', 'lumen', 'runic'];

/* 1 — chained multi-base cascade */
function famMultibase(rng) {
  const L = rng.int(14, 22);
  const token = rng.token(L, ALNUM);
  const pool = MB_TRANSFORMS.slice();
  const chosen = [];
  const n = rng.int(3, 5);
  for (let i = 0; i < n; i++) chosen.push(...pool.splice(rng.int(0, pool.length - 1), 1));
  let cur = token;
  for (const t of chosen) {
    if (t === 'base64') cur = Buffer.from(cur, 'ascii').toString('base64');
    else if (t === 'base32') cur = b32encode(Buffer.from(cur, 'ascii'));
    else if (t === 'hex') cur = Buffer.from(cur, 'ascii').toString('hex');
    else if (t === 'base58') cur = b58encode(Buffer.from(cur, 'ascii'));
    else if (t === 'rot13') cur = rot13(cur);
    else if (t === 'reverse') cur = cur.split('').reverse().join('');
  }
  return {
    family: 'multibase', title: 'MULTIBASE CASCADE',
    desc: 'The key was pushed through ' + n + ' transforms. Applied in order: ' + chosen.join(' -> ') + '.',
    data: cur, answer: token
  };
}

/* 2 — repeating-key XOR (crib drag: unknown keystream length) */
const XOR_CRIB = 'theserpentwakes';
function famXor(rng) {
  for (let guard = 0; guard < 100; guard++) {
    const plain = XOR_CRIB + rng.token(rng.int(13, 25), ALPHA);
    const k = rng.int(4, 10);
    const key = rng.bytes(k);
    const ct = Buffer.alloc(plain.length);
    for (let i = 0; i < plain.length; i++) ct[i] = plain.charCodeAt(i) ^ key[i % k];
    /* every period consistent with the crib must yield the same plaintext */
    const decs = new Set();
    for (let kk = 4; kk <= 10; kk++) {
      const key2 = [];
      for (let j = 0; j < kk; j++) key2.push(ct[j] ^ XOR_CRIB.charCodeAt(j));
      let s = '', all = true;
      for (let i = 0; i < plain.length; i++) {
        const ch = String.fromCharCode(ct[i] ^ key2[i % kk]);
        if (!(ch >= 'a' && ch <= 'z')) { all = false; break; }
        s += ch;
      }
      if (all) decs.add(s);
    }
    if (decs.size === 1 && decs.has(plain)) {
      return {
        family: 'xor', title: 'XOR GATE',
        desc: 'Repeating-key XOR: the ciphertext is a lowercase plaintext XOR a secret keystream that ' +
          'repeats. The plaintext begins with the 15-letter crib "theserpentwakes". The keystream length ' +
          'is an unknown value between 4 and 10. Drag the crib to recover the plaintext.',
        data: ct.toString('hex'), answer: plain
      };
    }
  }
  throw new Error('xor generation failed');
}

/* 3 — affine cipher with known plaintext prefix */
function famAffine(rng) {
  for (let guard = 0; guard < 200; guard++) {
    const tail = rng.token(rng.int(14, 24), ALPHA);
    const plain = 'gate' + tail;
    const a = rng.pick(AFFINE_A), b = rng.int(0, 25);
    let out = '';
    for (const ch of plain) {
      const x = ch.charCodeAt(0) - 97;
      out += String.fromCharCode(97 + ((a * x + b) % 26));
    }
    /* the prefix must pin (a, b): need two known chars whose difference is a unit mod 26 */
    const d1 = ('t'.charCodeAt(0) - 'a'.charCodeAt(0) + 26) % 26;
    if (gcdInt(d1, 26) !== 1) continue;
    return {
      family: 'affine', title: 'AFFINE SEAL',
      desc: 'Affine cipher over lowercase a-z: y = (a*x + b) mod 26. The plaintext begins with "gate". ' +
        'Recover a and b from the known prefix, then invert the map.',
      data: out, answer: plain
    };
  }
  throw new Error('affine generation failed');
}

/* 4 — Vigenere with unknown key over English-like text */
function famVigenere(rng) {
  const text = phrase(rng, true, 240, 300).toLowerCase();
  const KL = rng.int(5, 9);
  const key = rng.token(KL, ALPHA);
  let out = '', j = 0;
  for (const ch of text) {
    if (ch >= 'a' && ch <= 'z') {
      const p = ch.charCodeAt(0) - 97, kk = key.charCodeAt(j % KL) - 97;
      out += String.fromCharCode(97 + ((p + kk) % 26));
      j++;
    } else out += ch;
  }
  return {
    family: 'vigenere', title: 'VIGENERE VIGIL',
    desc: 'Vigenere cipher over lowercase a-z with an unknown key of 5 to 9 lowercase letters. ' +
      'Spaces are preserved and are not enciphered (only letters shift). Recover the key and decrypt.',
    data: out, answer: text
  };
}

/* 5 — hash preimage */
function famPin(rng) {
  const pin = String(rng.int(0, 999999)).padStart(6, '0');
  const h = crypto.createHash('md5').update(pin, 'utf8').digest('hex');
  return {
    family: 'pin', title: 'HASH PREIMAGE',
    desc: 'Find the 6-digit PIN (zero-padded, 000000 to 999999) whose MD5 digest matches the value below.',
    data: h, answer: pin
  };
}

/* 6 — modular inverse */
function famModInv(rng) {
  const m = BigInt(rng.pick([65537, 1000003, 1000000007, 2147483647]));
  let a = BigInt(rng.int(1000003, 2000000000));
  let guard = 0;
  while (egcd(a, m).g !== 1n && guard++ < 1000) a = BigInt(rng.int(1000003, 2000000000));
  const inv = Number((egcd(a, m).x % m + m) % m);
  return {
    family: 'modinv', title: 'MODULAR INVERSE',
    desc: 'Find x such that (a * x) mod m = 1, with a = ' + a + ' and m = ' + m + '. Answer in decimal.',
    data: { a: a.toString(), m: m.toString() },
    answer: String(inv)
  };
}

/* 7 — modular exponentiation */
function famModExp(rng) {
  const m = BigInt(rng.pick([1000000007n, 998244353n, 2147483647n, 1000000009n]));
  const a = BigInt(rng.int(2, 1073741823));
  const e = BigInt(rng.int(60000, 2000000));
  const r = powmod(a, e, m);
  return {
    family: 'modexp', title: 'MODULAR EXPONENTIATION',
    desc: 'Compute a^e mod m with a = ' + a + ', e = ' + e + ', m = ' + m + '. Decimal answer.',
    data: { a: a.toString(), e: e.toString(), m: m.toString() },
    answer: r.toString()
  };
}

/* 8 — semiprime factorization (32-bit primes: needs real factoring) */
function prime32(rng) {
  for (let guard = 0; guard < 4000; guard++) {
    const c = (rng.big(32) | 1n) | (1n << 31n); /* top bit set -> 32-bit range */
    if (isPrime(c)) return c;
  }
  throw new Error('prime32 failed');
}
function famSemiprime(rng) {
  let p = prime32(rng), q = prime32(rng);
  while (p === q) q = prime32(rng);
  const N = p * q;
  const small = p < q ? p : q;
  return {
    family: 'semiprime', title: 'SEMIPRIME SPLIT',
    desc: 'N is the product of two distinct 32-bit primes. Recover the smaller factor. N = ' + N,
    data: N.toString(),
    answer: small.toString()
  };
}

/* 9 — Hamming weight */
function famPopcount(rng) {
  const x = BigInt(rng.int(1, 1000000000)) * 4294967296n + BigInt(rng.int(0, 4294967295));
  let n = 0n, t = x;
  while (t > 0n) { n += t & 1n; t >>= 1n; }
  return {
    family: 'popcount', title: 'BIT POPULATION',
    desc: 'Count the set bits (Hamming weight) of the integer below.',
    data: x.toString(),
    answer: n.toString()
  };
}

/* 10 — LCG prediction with hidden (a, c) */
function famLcg(rng) {
  const M = 4294967296n; /* 2^32 */
  const a = 4n * BigInt(rng.int(16384, 268435456)) + 1n; /* a = 1 mod 4 (full period) */
  const c = 2n * BigInt(rng.int(0, 2147483647)) + 1n; /* odd */
  let x = BigInt(rng.int(0, 2147483647));
  const seq = [];
  for (let i = 0; i < 5; i++) { x = (a * x + c) % M; seq.push(x); }
  const x5 = (a * seq[3] + c) % M;
  return {
    family: 'lcg', title: 'LCG FORESIGHT',
    desc: 'A linear congruential generator modulo 2^32 with a = 1 (mod 4) and an odd additive constant c: ' +
      'x_(n+1) = (a*x_n + c) mod 2^32. The first four outputs x_1..x_4 are listed in order. ' +
      'Recover a and c, then predict x_5.',
    data: seq.slice(0, 4).map(String),
    answer: x5.toString()
  };
}

/* 11 — zero-width steganography */
function famZwsp(rng) {
  const L = rng.int(14, 20);
  const token = rng.token(L, ALNUM);
  const bytes = Buffer.from(token, 'ascii');
  let enc = '';
  for (const b of bytes) {
    for (let i = 7; i >= 0; i--) enc += (b >> i) & 1 ? ZW1 : ZW0;
    enc += ZWSEP;
  }
  const body = rng.pick(FILLER) + ' ' + enc + ' ' + rng.pick(FILLER);
  return {
    family: 'zwsp', title: 'ZERO-WIDTH CEREMONY',
    desc: 'The text below hides a payload in zero-width characters: U+200B = bit 0, U+200C = bit 1, ' +
      'U+200D = byte separator (MSB first). Decode the invisible ink.',
    data: body,
    answer: token
  };
}

/* 12 — trailing-whitespace bits */
function famWsb(rng) {
  const L = rng.int(12, 16);
  const token = rng.token(L, ALNUM);
  const bits = [];
  for (const b of Buffer.from(token, 'ascii')) for (let i = 7; i >= 0; i--) bits.push((b >> i) & 1);
  const lines = bits.map((bit) => {
    const off = rng.int(0, 1) * 2;
    return rng.pick(ORDWORD) + '_' + rng.token(rng.int(3, 8), ALNUM) + ' '.repeat(bit + off);
  });
  return {
    family: 'wsb', title: 'WHITESPACE ORACLE',
    desc: 'One bit per line is encoded in trailing whitespace (space_count mod 2 = bit). Bits are MSB-first, ' +
      '8 per character. Pay attention to what your editor hides.',
    data: lines.join('\n'),
    answer: token
  };
}

/* 13 — custom-base conversion */
function famCustomBase(rng) {
  const alpha = B32.split('');
  rng.shuffle(alpha);
  const A = alpha.join('');
  const L = rng.int(14, 20);
  const token = rng.token(L, ALNUM);
  const chars = [];
  let acc = 0, nb = 0;
  for (const byte of Buffer.from(token, 'ascii')) {
    acc = (acc << 8) | byte; nb += 8;
    while (nb >= 5) { nb -= 5; chars.push(A[(acc >>> nb) & 31]); }
  }
  if (nb > 0) chars.push(A[(acc << (5 - nb)) & 31]);
  return {
    family: 'custombase', title: 'FOREIGN BASE',
    desc: 'Base-32 using a scrambled alphabet: "' + A + '". Decode the payload into ASCII.',
    data: chars.join(''),
    answer: token
  };
}

/* 14 — ordinal shift cipher */
function famOrdwalk(rng) {
  const L = rng.int(14, 20);
  const token = rng.token(L, ALNUM);
  const K = rng.int(17, 200);
  const arr = [...Buffer.from(token, 'ascii')].map((c, i) => (c + i * K) % 256);
  return {
    family: 'ordwalk', title: 'ORDINAL WALK',
    desc: 'Each ASCII byte of the key was shifted by its index: out[i] = (in[i] + i*' + K + ') mod 256. ' +
      'The oracle\'s numbers below must be walked back.',
    data: arr,
    answer: token
  };
}

/* 15 — Hill cipher (2x2 over Z_26, known prefix) */
function famHill(rng) {
  let plain = 'hydr' + phrase(rng, false, 40, 70).toLowerCase();
  if (plain.length % 2 === 1) plain = plain.slice(0, -1);
  let K, det;
  for (let guard = 0; guard < 400; guard++) {
    K = [[rng.int(0, 25), rng.int(0, 25)], [rng.int(0, 25), rng.int(0, 25)]];
    det = ((K[0][0] * K[1][1] - K[0][1] * K[1][0]) % 26 + 26) % 26;
    if (gcdInt(det, 26) === 1) break;
    if (guard === 399) throw new Error('hill matrix failed');
  }
  let out = '';
  for (let i = 0; i < plain.length; i += 2) {
    const p0 = plain.charCodeAt(i) - 97, p1 = plain.charCodeAt(i + 1) - 97;
    const c0 = (((K[0][0] * p0 + K[0][1] * p1) % 26) + 26) % 26;
    const c1 = (((K[1][0] * p0 + K[1][1] * p1) % 26) + 26) % 26;
    out += String.fromCharCode(97 + c0) + String.fromCharCode(97 + c1);
  }
  return {
    family: 'hill', title: 'HILL LOCK',
    desc: 'Hill cipher: a 2x2 matrix over Z_26 acting on digraphs of lowercase a-z ' +
      '(column-major blocks: [c0,c1] = K * [p0,p1]). The plaintext begins with "hydr". ' +
      'Use the known prefix to recover K, then invert K and decrypt every digraph.',
    data: out, answer: plain
  };
}

/* 16 — simultaneous congruences (CRT) */
function famCrt(rng) {
  const mods = [];
  while (mods.length < 4) {
    let m = rng.big(45) | (1n << 44n) | 1n;
    if (gcdInt(Number(m % 2n), 2) !== 1) continue;
    let ok = true;
    for (const q of mods) if (egcd(m, q).g !== 1n) { ok = false; break; }
    if (ok) mods.push(m);
  }
  const M = mods.reduce((acc, m) => acc * m, 1n);
  const x = rng.big(176) % M;
  const pairs = mods.map((m) => [m.toString(), (x % m).toString()]);
  return {
    family: 'crt', title: 'REMAINDER WEAVE',
    desc: 'Solve the simultaneous congruences below (x mod m_i = r_i). ' +
      'Answer with the smallest non-negative solution as a decimal integer.',
    data: pairs, answer: x.toString()
  };
}

/* 17 — discrete logarithm (safe prime, needs baby-step giant-step) */
function famDlog(rng) {
  let q = 0n, p = 0n;
  for (let guard = 0; guard < 4000; guard++) {
    q = rng.big(35) | (1n << 34n) | 1n;
    if (!isPrime(q)) continue;
    p = 2n * q + 1n;
    if (!isPrime(p)) continue;
    break;
  }
  if (p === 0n) throw new Error('dlog prime failed');
  let g = 2n;
  for (; g < 100n; g++) {
    if (powmod(g, 2n, p) !== 1n && powmod(g, q, p) !== 1n) break;
  }
  const a = BigInt(rng.int(1 << 16, 1 << 18));
  const h = powmod(g, a, p);
  return {
    family: 'dlog', title: 'DISCRETE ABYSS',
    desc: 'p is a safe prime (p = 2q + 1, q prime) and g is a generator of the multiplicative group mod p. ' +
      'Given h = g^a mod p, find the exponent a.',
    data: { p: p.toString(), g: g.toString(), h: h.toString() },
    answer: a.toString()
  };
}

/* 18 — modular square root (Tonelli-Shanks) */
function tonelli(n, p) {
  if (powmod(n, (p - 1n) / 2n, p) !== 1n) return null;
  if (p % 4n === 3n) return powmod(n, (p + 1n) / 4n, p);
  let s = 0n, q = p - 1n;
  while (q % 2n === 0n) { q /= 2n; s += 1n; }
  let z = 2n;
  while (powmod(z, (p - 1n) / 2n, p) !== p - 1n) z += 1n;
  let m = s, c = powmod(z, q, p), t = powmod(n, q, p), r = powmod(n, (q + 1n) / 2n, p);
  for (let guard = 0; guard < 1000; guard++) {
    if (t === 1n) return r;
    let i = 0n, t2 = t;
    while (t2 !== 1n) {
      t2 = (t2 * t2) % p; i += 1n;
      if (i === m) return null;
    }
    const b = powmod(c, 1n << (m - i - 1n), p);
    m = i; c = (b * b) % p; t = (t * c) % p; r = (r * b) % p;
  }
  return null;
}
function famModsqrt(rng) {
  let p = 0n;
  for (let guard = 0; guard < 4000; guard++) {
    const c = rng.big(36) | (1n << 35n) | 1n;
    if (!isPrime(c)) continue;
    const s = BigInt(ctz64(c - 1n));
    if (s >= 2n) { p = c; break; }
  }
  if (p === 0n) throw new Error('modsqrt prime failed');
  const y = BigInt(rng.int(2, Number(p - 3n)));
  const z = (y * y) % p;
  const r = tonelli(z, p);
  if (r === null) throw new Error('modsqrt failed');
  const small = r < p - r ? r : p - r;
  return {
    family: 'modsqrt', title: 'ROOT OF QUADRATURE',
    desc: 'p is a prime with p - 1 = 2^s * t, s >= 2, and z is a quadratic residue modulo p. ' +
      'Compute the smaller of the two square roots of z modulo p (the root below p/2), as a decimal integer.',
    data: { p: p.toString(), z: z.toString() },
    answer: small.toString()
  };
}
function ctz64(v) { let n = 0; while ((v & 1n) === 0n) { v >>= 1n; n++; } return n; }

/* 19 — Chaocipher (invertible stepping: whole left rotation + front insert) */
function rotBlock(arr, start, count, dir) {
  if (count <= 1) return;
  if (dir === 1) {
    const first = arr[start];
    for (let i = start; i < start + count - 1; i++) arr[i] = arr[i + 1];
    arr[start + count - 1] = first;
  } else {
    const last = arr[start + count - 1];
    for (let i = start + count - 1; i > start; i--) arr[i] = arr[i - 1];
    arr[start] = last;
  }
}
function famChaocipher(rng) {
  const plain = phrase(rng, false, 50, 70).toLowerCase();
  const L = ALPHA.split('');
  const R = ALPHA.split('');
  rng.shuffle(L);
  rng.shuffle(R);
  const L0 = L.join(''), R0 = R.join('');
  let ct = '';
  for (const ch of plain) {
    const i = R.indexOf(ch);
    ct += L[i];
    rotBlock(L, 0, 26, 1);                    /* (1) whole left disk left-rotate  */
    const rCh = R.splice(i, 1)[0]; R.unshift(rCh); /* (2) R[i] -> front of R       */
    rotBlock(L, 1, 12, 1);                    /* (3) block L[1..12] left-rotate   */
    rotBlock(R, 2, 12, 1);                    /* (4) block R[2..13] left-rotate   */
  }
  return {
    family: 'chaocipher', title: 'CHAOCIPHER MASK',
    desc: 'Chaocipher. Two alphabets of a-z are given: L (left, cipher) and R (right, plain), both ' +
      '0-indexed. Enciphering one plaintext letter p: find i with R[i] = p; the ciphertext letter is ' +
      'L[i]. Then apply, in order: (1) left-rotate the whole left disk by one; (2) move R[i] to the ' +
      'front of R; (3) left-rotate the 12-letter block at L[1..12]; (4) left-rotate the 12-letter block ' +
      'at R[2..13] (L[1] is the second letter). Decrypt by inverting each step.',
    data: { left: L0, right: R0, ciphertext: ct },
    answer: plain
  };
}

/* 20 — Playfair */
const PF_ALPHABET = 'abcdefghiklmnopqrstuvwxyz'; /* i/j merged, x reserved as filler */
function famPlayfair(rng) {
  const square = rng.shuffle(PF_ALPHABET.split('')).join('');
  const plain = phrase(rng, false, 60, 80).toLowerCase().replace(/[jx]/g, '');
  const pairs = [];
  let s = plain;
  while (s.length) {
    const a = s[0];
    if (s.length === 1) { pairs.push([a, 'x']); break; }
    if (s[1] === a) { pairs.push([a, 'x']); s = s.slice(1); }
    else { pairs.push([a, s[1]]); s = s.slice(2); }
  }
  let ct = '';
  for (const [a, b] of pairs) {
    const ia = square.indexOf(a), ib = square.indexOf(b);
    const ra = Math.floor(ia / 5), ca = ia % 5, rb = Math.floor(ib / 5), cb = ib % 5;
    let na, nb;
    if (ra === rb) {
      na = square[ra * 5 + ((ca + 1) % 5)]; nb = square[rb * 5 + ((cb + 1) % 5)];
    } else if (ca === cb) {
      na = square[((ra + 1) % 5) * 5 + ca]; nb = square[((rb + 1) % 5) * 5 + cb];
    } else {
      na = square[ra * 5 + cb]; nb = square[rb * 5 + ca];
    }
    ct += na + nb;
  }
  return {
    family: 'playfair', title: 'PLAYFAIR CLOCK',
    desc: 'Playfair cipher with the 5x5 square below (25 letters, i/j merged). ' +
      'Plaintext is lowercase letters without j or x; duplicate plaintext letters were split by \'x\' ' +
      'and an odd final letter was padded with \'x\'. Digraph rules: same row -> shift right; ' +
      'same column -> shift down; otherwise swap columns keeping rows. Decrypt (shift left / shift up) ' +
      'and drop the x padding.',
    data: { square: square, ciphertext: ct },
    answer: plain
  };
}

/* 21 — columnar transposition */
function famColumnar(rng) {
  const k = rng.int(7, 10);
  const plain = phrase(rng, false, 90, 140).toLowerCase();
  const order = rng.shuffle([...Array(k).keys()]);
  const cols = Array.from({ length: k }, () => '');
  for (let i = 0; i < plain.length; i++) cols[i % k] += plain[i];
  let ct = '';
  for (const c of order) ct += cols[c];
  return {
    family: 'columnar', title: 'COLUMNAR FOLD',
    desc: 'Columnar transposition. The plaintext (letters only) was written row-wise into ' + k +
      ' columns, then read out column by column in the order ' + order.join(',') +
      '. Reconstruct the plaintext.',
    data: { order: order, ciphertext: ct },
    answer: plain
  };
}

/* 22 — recall checkpoints bind the player's own earlier answers */
function famRecall(rng, ctx) {
  const idx = ctx.idx, hist = ctx.history || [], base = ctx.histBase;
  const lo = Math.max(base, 0);
  const span = idx - lo;
  if (span < 2) return null;
  let a = rng.int(lo, idx - 1);
  let b = rng.int(lo, idx - 1);
  let guard = 0;
  while (b === a && guard++ < 50) b = rng.int(lo, idx - 1);
  const ansA = hist[a - base], ansB = hist[b - base];
  if (!ansA || !ansB) return null;
  const pa = rng.int(0, ansA.length - 1);
  const pb = rng.int(0, ansB.length - 1);
  return {
    family: 'recall', title: 'MEMORY RITE',
    desc: 'Your own answers are the key now. Give the ' + (pa + 1) + 'th character of the answer you ' +
      'submitted for gate ' + (a + 1) + ', immediately followed by the ' + (pb + 1) + 'th character of the ' +
      'answer you submitted for gate ' + (b + 1) + ' (no separator).',
    data: { first: { gate: a + 1, pos: pa + 1 }, second: { gate: b + 1, pos: pb + 1 } },
    answer: ansA[pa] + ansB[pb]
  };
}

const FAMILIES = {
  multibase: famMultibase, xor: famXor, affine: famAffine, vigenere: famVigenere,
  pin: famPin, modinv: famModInv, modexp: famModExp, semiprime: famSemiprime,
  popcount: famPopcount, lcg: famLcg, zwsp: famZwsp, wsb: famWsb,
  custombase: famCustomBase, ordwalk: famOrdwalk, hill: famHill, crt: famCrt,
  dlog: famDlog, modsqrt: famModsqrt, chaocipher: famChaocipher, playfair: famPlayfair,
  columnar: famColumnar, recall: famRecall
};
const FAM_NAMES = Object.keys(FAMILIES);

/* build one gate deterministically from (seed, index, chained state, recent answers) */
function buildLayer(seed, idx, stateHex, history, histBase) {
  const rng = makeRng('hydra|' + seed + '|' + idx + '|' + stateHex);
  const base = histBase == null ? Math.max(0, idx - HISTORY) : histBase;
  const hist = history || [];
  const ctx = { seed: seed, idx: idx, history: hist, histBase: base };
  let name = FAM_NAMES[rng.int(0, FAM_NAMES.length - 1)];
  let layer = null;
  if (name === 'recall') layer = famRecall(rng, ctx);
  else layer = FAMILIES[name](rng);
  if (!layer) { /* not enough history yet for recall: fall back, still deterministic */
    const alt = FAM_NAMES.filter((n) => n !== 'recall');
    name = alt[rng.int(0, alt.length - 1)];
    layer = FAMILIES[name](rng);
  }
  return {
    idx: idx,
    family: name,
    title: layer.title,
    desc: layer.desc,
    data: layer.data,
    answer: String(layer.answer).trim().toLowerCase()
  };
}
function publicPrompt(layer) {
  return {
    family: layer.family,
    title: layer.title,
    desc: layer.desc,
    data: layer.data,
    work: powBits(layer.idx)
  };
}

/* ========================== STATE CHAIN ========================= */
/* answer_n binds into the RNG of gate n+1: tamper, skip, reorder all fail. */

function nextState(stateHex, answer) {
  return h256hex(stateHex + '|' + answer);
}

/* ======================= PROOF-OF-WORK ========================= */
/* Every submitted answer must carry a partial sha256 preimage whose
 * difficulty grows with the gate index. This turns answer brute-force
 * (e.g. MD5 over 6 digits, or guesswork) into a CPU cost per attempt. */

function powBits(idx) { return Math.min(WORK_MAX, WORK_BASE + Math.floor(idx / WORK_STEP)); }
function powWork(token, idx, answer, nonce) { return token + '.' + idx + '.' + answer + '.' + nonce; }
function leadingZeroBits(digest) {
  let bits = 0;
  for (const byte of digest) {
    if (byte === 0) { bits += 8; continue; }
    bits += 31 - Math.clz32(byte);
    break;
  }
  return bits;
}
function powOk(token, idx, answer, nonce) {
  const n = typeof nonce === 'string' ? nonce : '';
  if (!/^\d{1,12}$/.test(n)) return false;
  const digest = crypto.createHash('sha256').update(powWork(token, idx, answer, n), 'utf8').digest();
  return leadingZeroBits(digest) >= powBits(idx);
}

/* ======================== SIGNED TOKENS ======================== */

function sign(payload) {
  const p = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  const sig = crypto.createHmac('sha256', TOKEN_SECRET).update(p, 'utf8').digest('base64url');
  return p + '.' + sig;
}
function verifyToken(tok) {
  if (typeof tok !== 'string') return null;
  const parts = tok.split('.');
  if (parts.length !== 2) return null;
  const p = parts[0], sig = parts[1];
  const expect = crypto.createHmac('sha256', TOKEN_SECRET).update(p, 'utf8').digest('base64url');
  const a = Buffer.from(sig, 'utf8'), b = Buffer.from(expect, 'utf8');
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  let payload;
  try { payload = JSON.parse(Buffer.from(p, 'base64url').toString('utf8')); } catch (e) { return null; }
  if (!payload || typeof payload !== 'object') return null;
  if (typeof payload.exp !== 'number' || Date.now() > payload.exp) return null;
  if (typeof payload.s !== 'string' || typeof payload.st !== 'string' || typeof payload.i !== 'number') return null;
  if (payload.h !== undefined) {
    if (!Array.isArray(payload.h) || payload.h.length > HISTORY) return null;
    for (const it of payload.h) if (typeof it !== 'string' || it.length > 400) return null;
  }
  return payload;
}
function makeToken(seed, i, st, hist) {
  return sign({ s: seed, i: i, st: st, h: hist.slice(-HISTORY), exp: Date.now() + SESSION_TTL });
}

/* ========================== FLAG REVEAL ======================== */

function revealFlag() {
  const sb = Buffer.from(SEALED_FLAG, 'base64');
  const out = Buffer.alloc(sb.length);
  for (let b = 0; b * 32 < sb.length; b++) {
    const kb = h256buf(FLAG_SECRET + '|hydro|block|' + b);
    for (let i = 0; i < 32 && b * 32 + i < sb.length; i++) out[b * 32 + i] = sb[b * 32 + i] ^ kb[i];
  }
  const flag = out.toString('utf8');
  if (!/^KCTF\{[\x20-\x7e]+\}$/.test(flag)) throw new Error('flag seal corrupt');
  return flag;
}

/* ============================ HTTP ============================== */

function send(res, code, obj) {
  const body = JSON.stringify(obj);
  res.statusCode = code;
  res.setHeader('content-type', 'application/json; charset=utf-8');
  res.setHeader('cache-control', 'no-store');
  res.end(body);
}
function normAnswer(v) { return String((v == null) ? '' : v).trim().toLowerCase(); }

function getBody(req) {
  return new Promise((resolve, reject) => {
    if (req.body && typeof req.body === 'object') return resolve(req.body);
    if (typeof req.body === 'string') {
      try { return resolve(JSON.parse(req.body || '{}')); } catch (e) { return resolve({}); }
    }
    let raw = '';
    req.on('data', (c) => { raw += c; if (raw.length > 1e6) req.destroy(); });
    req.on('end', () => { try { resolve(JSON.parse(raw || '{}')); } catch (e) { resolve({}); } });
    req.on('error', () => resolve({}));
  });
}

function handler(req, res) {
  const url = new URL(req.url || '/', 'http://hydra.local');
  const op = url.searchParams.get('op') || '';
  const method = (req.method || 'GET').toUpperCase();

  if (method === 'OPTIONS') { res.statusCode = 204; res.end(); return; }

  if (op === 'ping') {
    if (method !== 'GET' && method !== 'HEAD') return send(res, 405, { error: 'GET required' });
    return send(res, 200, { ok: true, service: 'KCTF:HYDRA-THOUSANDFOLD', total: TOTAL, families: FAM_NAMES.length });
  }

  if (op !== 'start' && op !== 'check') return send(res, 404, { error: 'unknown operation' });
  if (FLAG_SECRET.length < 32 || TOKEN_SECRET.length < 32) {
    return send(res, 503, { error: 'challenge secrets are not configured' });
  }

  return getBody(req).then((body) => {
    if (op === 'start') {
      if (method !== 'POST') return send(res, 405, { error: 'POST required' });
      const seed = normAnswer(body && body.seed);
      if (!/^[0-9a-f]{64}$/.test(seed)) return send(res, 400, { error: 'seed must be 64 hex characters' });
      if (seed !== EXPECTED_SEED) return send(res, 403, { error: 'that seed does not hatch' });
      const st = h256hex('hydra-init|' + seed);
      const tok = makeToken(seed, 0, st, []);
      const layer = buildLayer(seed, 0, st, [], 0);
      return send(res, 200, { ok: true, token: tok, idx: 0, total: TOTAL, prompt: publicPrompt(layer) });
    }

    /* op === 'check' */
    if (method !== 'POST') return send(res, 405, { error: 'POST required' });
    const payload = verifyToken(String((body && body.token) || ''));
    if (!payload) return send(res, 401, { error: 'token rejected — restart the gauntlet' });
    const idx = payload.i, st = payload.st;
    if (idx < 0 || idx >= TOTAL) return send(res, 400, { error: 'index out of range' });
    const hist = Array.isArray(payload.h) ? payload.h : [];
    const histBase = idx - hist.length;
    if (histBase < 0) return send(res, 400, { error: 'history window invalid' });
    const layer = buildLayer(payload.s, idx, st, hist, histBase);
    const given = normAnswer(body && body.answer);
    if (!given) return send(res, 400, { error: 'empty answer' });
    if (!powOk(String(body && body.token), idx, given, body && body.pow)) {
      return send(res, 400, { error: 'proof-of-work missing or stale' });
    }
    if (given !== layer.answer) {
      return send(res, 401, { ok: false, error: 'the gate does not yield', idx: idx, total: TOTAL, work: powBits(idx) });
    }
    const nSt = nextState(st, layer.answer);
    const nIdx = idx + 1;
    if (nIdx >= TOTAL) {
      let flag;
      try { flag = revealFlag(); } catch (e) { return send(res, 500, { error: 'flag seal corrupt' }); }
      return send(res, 200, {
        ok: true, done: true, idx: nIdx, total: TOTAL, flag: flag,
        message: 'ALL GATES SLAIN. THE SERPENT FALLS SILENT.'
      });
    }
    /* history is always the trailing window, relative to histBase */
    const nextHist = hist.concat([layer.answer]).slice(-HISTORY);
    const nextBase = nIdx - nextHist.length;
    const tok = makeToken(payload.s, nIdx, nSt, nextHist);
    const next = buildLayer(payload.s, nIdx, nSt, nextHist, nextBase);
    return send(res, 200, { ok: true, idx: nIdx, total: TOTAL, token: tok, prompt: publicPrompt(next) });
  }).catch((e) => send(res, 500, { error: 'internal hydra error' }));
}

module.exports = handler;
module.exports._internals = {
  EXPECTED_SEED, TOTAL, FAM_NAMES, HISTORY,
  powBits, powOk, leadingZeroBits, powWork,
  makeRng, buildLayer, publicPrompt, nextState,
  sign, verifyToken, makeToken, revealFlag,
  tonelli, isPrime, powmod, egcd,
  encodings: { b32encode, b32decode, b58encode, b58decode, rot13 }
};

/* local dev: `node api/gate.js` -> http://localhost:8787/api/gate */
if (require.main === module) {
  const port = Number(process.env.PORT || 8787);
  http.createServer(handler).listen(port, () => {
    console.log('hydra gate listening on http://localhost:' + port + '/api/gate');
  });
}
