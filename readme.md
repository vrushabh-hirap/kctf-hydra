# HYDRA: Thousandfold

A single-player, 1,000-gate KCTF challenge combining cryptography, encoding, number theory, bit manipulation, pseudo-random generators, steganography, and classical cipher systems. The player-facing name is **HYDRA: Thousandfold**. The Vercel project/root directory should be named `hydra-thousandfold` when creating a new deployment.

## Deploy to Vercel

1. **Keep this repository private.** `organizer/` contains private answer-generation, the reference solver, the expected flag, and the value needed to configure `FLAG_SECRET`. A private repo is required; a public one hands out the flag.
2. Rotate both secrets before deploying. The values committed here are examples and must never be reused:
   ```sh
   FLAG_SECRET="$(openssl rand -hex 32)" TOKEN_SECRET="$(openssl rand -hex 32)"
   ```
   Re-seal the flag against your new `FLAG_SECRET` and paste the result into `SEALED_FLAG` in `api/gate.js`:
   ```sh
   FLAG_SECRET="<your new secret>" node organizer/seal.mjs
   ```
   `TOKEN_SECRET` must be a different value (>= 32 characters). Add both to Production, Preview, and Development (if using `vercel dev`). Never publish the organizer directory or reveal either secret.
3. Deploy. The static player page is `index.html`; the API is `/api/gate`.
4. Check `/api/gate?op=ping` for service health. A `503` on `start` or `check` means one or both required secrets are missing (there are no fallbacks).

No third-party domains or services are called at runtime. Vercel's Node.js serverless runtime serves the API; the browser page uses same-origin requests.

## How to play

The entry panel gives A as hex and B/C as base64. Decode all three as bytes, XOR them byte-for-byte, and SHA-256 the 32-byte result. Submit the lowercase hex digest to open gate 1. Solve each self-contained prompt and submit its answer; a correct answer advances the signed state token. All 1,000 gates must be completed in order to receive the flag.

There are 22 deterministic puzzle families, and the chain has three layers of friction:

- **Breadth** — cryptanalysis and classical ciphers (repeating-key XOR crib drag, Vigenere with an unknown key, affine with a known prefix, Hill with a known-plaintext attack, Chaocipher stepping, Playfair, columnar transposition), number theory (modular inverse, modular exponentiation, 32-bit semiprime factorization, CRT, discrete logarithm, Tonelli–Shanks square roots), PRNG work (LCG recovery from outputs, hidden multipliers), encodings (multibase cascades, scrambled base-32), steganography (zero-width characters, trailing-whitespace bits), bounded MD5 preimages, popcount, ordinal shifts, and **recall checkpoints** that make you dig up two characters from your own earlier answers.
- **Proof-of-work** — every submission carries a nonce such that `sha256(token · gate · answer · nonce)` starts with the required number of zero bits. The requirement starts at 16 bits and grows one bit every 100 gates (capped at 20). It is published in each prompt as `work`, and the page solves it for you. This makes guessing answers through the API pointless: a 6-digit MD5 preimage via `check` would cost ~55 hours of hashing per million guesses on a single core, versus ~1.5 seconds to solve locally.
- **State binding** — the gate generator is keyed by `TOKEN_SECRET`, each gate's RNG depends on the chained state, and the chained state depends on your answers, so prompts cannot be replayed, reordered, or predicted ahead of time. Sessions live 72 hours (restarting resets progress).

Prompts provide the necessary parameters; nothing needed to solve a gate is hidden outside its prompt. The chain is intentionally long and broad, but remains solvable with scripting and careful prompt parsing.

## Local development and full-playthrough verification

Use Node.js 18 or later. Configure local secrets before running the API:

```sh
FLAG_SECRET="$(node -p 'require("./organizer/constants.json").defaultSecret')" TOKEN_SECRET="$(openssl rand -hex 32)" node api/gate.js
```

In another terminal, run the organizer harness against the local API:

```sh
FLAG_SECRET="$(node -p 'require("./organizer/constants.json").defaultSecret')" TOKEN_SECRET="<same value as above>" node organizer/solver.mjs
```

The harness solves all gates from public prompts, pays the required proof-of-work, makes the full HTTP playthrough, and compares the final flag to the organizer copy. Modes:

```sh
node organizer/solver.mjs             # full 1000-gate HTTP playthrough (opens a socket)
node organizer/solver.mjs --inprocess # same, invoking the Vercel handler directly (no socket)
node organizer/solver.mjs --nofetch   # fast in-memory family/chain check (no HTTP, no PoW)
```

Adversarial self-audit (token tampering, replay, PoW skipping, prompt-leak scan across all 1000 gates, brute-force economics, missing-secret failure):

```sh
FLAG_SECRET=... TOKEN_SECRET=... node organizer/security-check.mjs
```

Post-deployment health check against any live URL (run this the moment a deployment is live — it catches the classic "forgot the env vars" 503):

```sh
node organizer/deploy-check.mjs https://your-project.vercel.app
```

It should print 10/10 PASS and the exact command to run a complete 1000-gate proof against that URL (`HYDRA_BASE=... node organizer/solver.mjs`).

`.vercelignore` excludes `organizer/`, `secret/`, and `assets/` from deployment. `organizer/` contains private answer-generation, the solvers, the expected flag, and the value needed to configure `FLAG_SECRET`. The only flag in the deployed handler is block-sealed with a `FLAG_SECRET`-derived keystream (`sha256(FLAG_SECRET + '|hydro|block|' + i)` per 32-byte block); the separate `TOKEN_SECRET` signs progression tokens and keys the gate generator.

## Challenge reference

- **Name:** HYDRA: Thousandfold
- **Folder/project slug:** `hydra-thousandfold`
- **Flag format:** `KCTF{...}`
- **Gate count:** 1,000
- **Domains:** 22 puzzle families
- **Proof-of-work:** 16 bits at gate 1, +1 bit per 100 gates, capped at 20 bits
- **Session TTL:** 72 hours
