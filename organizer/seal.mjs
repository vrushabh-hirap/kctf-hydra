/*
 * KCTF:HYDRA — organizer seal tool
 * ------------------------------------------------------------------
 * Re-seals the flag against a FLAG_SECRET of your choice, using the
 * same multi-block keystream scheme as api/gate.js:
 *   block b = sha256(FLAG_SECRET + '|hydro|block|' + b)  (32 bytes)
 *
 *   FLAG_SECRET="$(openssl rand -hex 32)" node organizer/seal.mjs
 *
 * The tool reads organizer/constants.json, prints the new
 * sealedFlagB64, and writes it back to the same file. Copy the value
 * into SEALED_FLAG in api/gate.js before deploying. NEVER deploy with
 * a secret matching the value committed in this repo.
 */
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const dir = path.dirname(fileURLToPath(import.meta.url));
const file = path.join(dir, 'constants.json');
const constants = JSON.parse(fs.readFileSync(file, 'utf8'));

const secret = process.env.FLAG_SECRET || '';
if (secret.length < 32) {
  console.error('FLAG_SECRET (>= 32 chars) is required. Example:');
  console.error('  FLAG_SECRET="$(openssl rand -hex 32)" node organizer/seal.mjs');
  process.exit(1);
}

const flagBuf = Buffer.from(constants.flag, 'utf8');
const out = Buffer.alloc(flagBuf.length);
for (let b = 0; b * 32 < flagBuf.length; b++) {
  const kb = crypto.createHash('sha256').update(secret + '|hydro|block|' + b, 'utf8').digest();
  for (let i = 0; i < 32 && b * 32 + i < flagBuf.length; i++) {
    out[b * 32 + i] = flagBuf[b * 32 + i] ^ kb[i];
  }
}
constants.sealedFlagB64 = out.toString('base64');
fs.writeFileSync(file, JSON.stringify(constants, null, 2) + '\n');

console.log('sealedFlagB64 = ' + constants.sealedFlagB64);
console.log('Write this value into SEALED_FLAG in api/gate.js, then deploy.');
