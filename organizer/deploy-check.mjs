/*
 * KCTF:HYDRA — post-deployment health check (organizer tool, NOT deployed)
 * ------------------------------------------------------------------
 * Verifies a live deployment end-to-end in a few seconds.
 *
 *   node organizer/deploy-check.mjs                        # http://localhost:8787
 *   node organizer/deploy-check.mjs https://kctf-hydra.vercel.app
 *
 * Checks: service/version, seed gate, PoW enforcement, wrong-seed rejection,
 * token tampering, and that secrets are configured (the classic post-deploy
 * miss that makes start/check return 503).
 */
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const constants = JSON.parse(fs.readFileSync(path.join(here, 'constants.json'), 'utf8'));
const SEED = constants.seed;
const base = (process.argv[2] || 'http://localhost:8787').replace(/\/+$/, '') + '/api/gate';

let pass = 0, fail = 0;
const ok = (name, cond, detail) => {
  console.log((cond ? 'PASS  ' : 'FAIL  ') + name + (detail ? '  [' + detail + ']' : ''));
  cond ? pass++ : fail++;
};
const j = async (op, body) => {
  const r = await fetch(base + '?op=' + op, {
    method: body ? 'POST' : 'GET',
    headers: { 'content-type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined
  });
  return { status: r.status, body: await r.json().catch(() => ({})) };
};

const solvePow = (token, idx, answer, bits) => {
  for (let n = 0; ; n++) {
    const d = crypto.createHash('sha256').update(token + '.' + idx + '.' + answer + '.' + n).digest();
    let z = 0;
    for (const b of d) { if (!b) { z += 8; continue; } z += 31 - Math.clz32(b); break; }
    if (z >= bits) return String(n);
  }
};

(async () => {
  console.log('target: ' + base);

  const ping = await j('ping');
  ok('service is live', ping.body.ok === true, ping.body.service + '');
  ok('deployed build is the 22-family engine', ping.body.families === 22, 'families=' + ping.body.families);

  const pong = await j('ping');
  ok('api responds 200', pong.status === 200, 'status=' + pong.status);

  const badSeed = await j('start', { seed: 'f'.repeat(64) });
  if (badSeed.body.error === 'challenge secrets are not configured') {
    ok('secrets configured on this deployment', false,
      'FLAG_SECRET and TOKEN_SECRET env vars are missing or < 32 chars — set them in Vercel and redeploy');
    console.log('\ndeploy-check: ' + pass + ' passed, ' + fail + ' failed');
    process.exit(1);
  }
  ok('secrets configured on this deployment', true);
  ok('wrong seed rejected (403)', badSeed.status === 403, badSeed.body.error + '');

  const allF = 'f'.repeat(64);
  const start = await j('start', { seed: SEED });
  ok('start with the real seed issues a token', start.body.ok === true && typeof start.body.token === 'string',
    'gate 1 family=' + (start.body.prompt && start.body.prompt.family));
  ok('prompt declares its proof-of-work', typeof (start.body.prompt || {}).work === 'number',
    'work=' + ((start.body.prompt || {}).work) + ' bits');

  if (start.body.ok && start.body.token) {
    const noPow = await j('check', { token: start.body.token, answer: 'x' });
    ok('submission without proof-of-work rejected', noPow.status === 400, noPow.body.error + '');
    const wrongAns = await j('check', {
      token: start.body.token,
      answer: 'definitely-not-the-answer',
      pow: solvePow(start.body.token, start.body.idx, 'definitely-not-the-answer', start.body.prompt.work)
    });
    ok('wrong answer (with valid PoW) rejected', wrongAns.status === 401 && wrongAns.body.error === 'the gate does not yield',
      'status=' + wrongAns.status + ' error=' + wrongAns.body.error);
    const parts = String(start.body.token).split('.');
    const forged = parts[0].slice(0, -3) + (parts[0].slice(-3) === 'AAA' ? 'BBB' : 'AAA');
    const tampered = await j('check', { token: forged + '.' + parts[1], answer: 'x', pow: '0' });
    ok('tampered token rejected', tampered.status === 401, tampered.body.error + '');
  }

  console.log('\ndeploy-check: ' + pass + ' passed, ' + fail + ' failed');
  console.log(fail ? 'RESULT: NOT playable yet — fix the FAIL items above.'
    : 'RESULT: deployment is healthy and playable. Run a full 1000-gate proof with:');
  if (!fail) console.log('  HYDRA_BASE="' + base.replace(/\/api\/gate$/, '') + '" node organizer/solver.mjs');
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error('deploy-check error:', e.message); process.exit(1); });
