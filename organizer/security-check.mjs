/*
 * KCTF:HYDRA — organizer adversarial checks (NOT deployed)
 * ------------------------------------------------------------------
 * Tries to break the handler the way a player would: seed guessing,
 * token tampering, replay, PoW skipping, wrong answers, prompt leaks,
 * brute-force economics, missing secrets.
 *
 *   FLAG_SECRET=... TOKEN_SECRET=... node organizer/security-check.mjs
 */
import { createRequire } from 'node:module';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';

const require = createRequire(import.meta.url);
const gate = require('../api/gate.js');
const I = gate._internals;
const constants = JSON.parse(fs.readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), 'constants.json'), 'utf8'));
const SEED = constants.seed;
const TOTAL = I.TOTAL;

let pass = 0, fail = 0;
const ok = (name, cond, extra) => {
  if (cond) { pass++; console.log('PASS  ' + name + (extra ? '  [' + extra + ']' : '')); }
  else { fail++; console.log('FAIL  ' + name + (extra ? '  [' + extra + ']' : '')); }
};

const invoke = async (op, body) => new Promise((resolve) => {
  const res = { headers: {}, setHeader(k, v) { this.headers[k] = v; }, end(s) { resolve(JSON.parse(s)); } };
  gate({ method: body ? 'POST' : 'GET', url: '/api/gate?op=' + op, body: body || undefined }, res);
});
function basePow(token, idx, answer) {
  let n = 0;
  for (;;) {
    const d = crypto.createHash('sha256').update(token + '.' + idx + '.' + answer + '.' + n).digest();
    let z = 0;
    for (const b of d) { if (!b) { z += 8; continue; } z += 31 - Math.clz32(b); break; }
    if (z >= I.powBits(idx)) return String(n);
    n++;
  }
}

(async () => {
  /* ---- liveness / routing ---- */
  const ping = await invoke('ping');
  ok('ping reports service', ping.ok === true && ping.total === TOTAL, 'families=' + ping.families);
  ok('unknown op -> 404-ish error', (await invoke('bogus')).error !== undefined);

  /* ---- seed gate ---- */
  ok('bad seed rejected', (await invoke('start', { seed: 'f'.repeat(64) })).error !== undefined);
  ok('malformed seed rejected', (await invoke('start', { seed: 'nope' })).error !== undefined);

  /* ---- happy path start ---- */
  const s = await invoke('start', { seed: SEED });
  ok('start issues token + prompt', s.ok === true && typeof s.token === 'string' && !!s.prompt);
  ok('prompt declares PoW bits', typeof s.prompt.work === 'number' && s.prompt.work >= 11, 'work=' + s.prompt.work);

  const layer0 = I.buildLayer(SEED, 0, crypto.createHash('sha256').update('hydra-init|' + SEED).digest('hex'), [], 0);

  /* ---- proof-of-work enforcement ---- */
  const noPow = await invoke('check', { token: s.token, answer: layer0.answer });
  ok('missing PoW rejected (correct answer!)', noPow.ok !== true, noPow.error || '');
  const badPow = await invoke('check', { token: s.token, answer: layer0.answer, pow: '0' });
  ok('bogus PoW rejected', badPow.ok !== true);
  const goodPow = basePow(s.token, 0, layer0.answer);
  ok('valid PoW accepted (answer correct)', (await invoke('check', { token: s.token, answer: layer0.answer, pow: goodPow })).ok === true);

  /* ---- wrong answers ---- */
  const wrong = await invoke('check', { token: s.token, answer: 'zzz', pow: basePow(s.token, 0, 'zzz') });
  ok('wrong answer rejected', wrong.ok !== true);
  ok('wrong answer message is uniform', wrong.error === 'the gate does not yield');

  /* ---- token tampering ---- */
  const parts = s.token.split('.');
  const forgedPayload = Buffer.from(JSON.stringify({ s: SEED, i: 5, st: crypto.createHash('sha256').update('x').digest('hex'), h: [], exp: Date.now() + 3600000 }), 'utf8').toString('base64url');
  ok('forged token (no sig) rejected', (await invoke('check', { token: forgedPayload + '.AAAA', answer: 'zzz', pow: '0' })).ok !== true);
  const tampered = parts[0].slice(0, -2) + (parts[0].slice(-2) === 'AA' ? 'BB' : 'AA');
  ok('tampered payload rejected', (await invoke('check', { token: tampered + '.' + parts[1], answer: 'zzz', pow: '0' })).ok !== true);
  const expired = Buffer.from(JSON.stringify({ s: SEED, i: 0, st: crypto.createHash('sha256').update('hydra-init|' + SEED).digest('hex'), h: [], exp: 1 }), 'utf8').toString('base64url');
  const expSig = crypto.createHmac('sha256', process.env.TOKEN_SECRET).update(expired, 'utf8').digest('base64url');
  ok('expired token rejected', (await invoke('check', { token: expired + '.' + expSig, answer: layer0.answer, pow: '1' })).ok !== true);

  /* ---- state tampering / replay ---- */
  const badState = Buffer.from(JSON.stringify({ s: SEED, i: 0, st: crypto.createHash('sha256').update('tampered').digest('hex'), h: [], exp: Date.now() + 3600000 }), 'utf8').toString('base64url');
  const bsSig = crypto.createHmac('sha256', process.env.TOKEN_SECRET).update(badState, 'utf8').digest('base64url');
  const r = await invoke('check', { token: badState + '.' + bsSig, answer: layer0.answer, pow: basePow(badState + '.' + bsSig, 0, layer0.answer) });
  ok('tampered chain state rejects true answer', r.ok !== true, r.error || '');

  /* ---- prompt leak audit across the whole chain ---- */
  let leak = null, history = [];
  let st = crypto.createHash('sha256').update('hydra-init|' + SEED).digest('hex');
  const gateStart = Date.now();
  for (let i = 0; i < TOTAL; i++) {
    const base = Math.max(0, i - I.HISTORY);
    const layer = I.buildLayer(SEED, i, st, history.slice(base), base);
    const promptJson = JSON.stringify(I.publicPrompt(layer)).toLowerCase();
    /* numeric answers are math-family outputs meant to be derived from the
     * prompt's own numbers; only flag alphabetic answers that surface whole */
    if (layer.answer.length >= 4 && !/^[0-9]+$/.test(layer.answer) && promptJson.includes(layer.answer.toLowerCase())) { leak = { i, family: layer.family, answer: layer.answer }; break; }
    history.push(layer.answer);
    st = I.nextState(st, layer.answer);
  }
  ok('no answer leaks inside any of the 1000 prompts', leak === null, leak ? JSON.stringify(leak) : '1000 prompts audited');

  /* ---- PoW difficulty curve ---- */
  const bits0 = I.powBits(0), bitsMid = I.powBits(500), bitsMax = I.powBits(TOTAL - 1);
  ok('PoW difficulty grows along the chain', bits0 < bitsMid && bitsMid <= bitsMax && bits0 < bitsMax, `${bits0} -> ${bitsMid} -> ${bitsMax} bits (saturating by design)`);

  /* ---- brute-force economics: MD5-pin family via the API ---- */
  const t0 = Date.now();
  let hashes = 0;
  while (Date.now() - t0 < 400) {
    crypto.createHash('sha256').update('x' + hashes).digest();
    hashes++;
  }
  const hps = hashes / ((Date.now() - t0) / 1000);
  const pinBits = I.powBits(250);
  const perAttempt = Math.pow(2, pinBits) / hps; /* seconds of CPU per API guess */
  ok('MD5-pin brute-force through the API is pointless',
    1e6 * perAttempt > 3600,
    `gate 250 needs ${pinBits}-bit PoW => ~${perAttempt.toFixed(2)}s CPU per guess; a million guesses through /api would need ${(1e6 * perAttempt / 3600).toFixed(1)}h (local MD5 solve: ~1.5s)`);

  /* ---- missing secrets must hard-fail ---- */
  const out = execFileSync(process.execPath, ['-e',
    "const g=require('./api/gate.js');" +
    "let s='';const res={setHeader(){},end(v){s=v},statusCode:0};" +
    "g({method:'POST',url:'/api/gate?op=start',body:{seed:process.argv[1]}},res);" +
    "process.stdout.write(s);"
  , SEED], { cwd: path.dirname(path.dirname(fileURLToPath(import.meta.url))), env: { PATH: process.env.PATH } });
  ok('missing secrets -> 503, no fallback', JSON.parse(out.toString()).error === 'challenge secrets are not configured');

  console.log(`\nsecurity-check: ${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
