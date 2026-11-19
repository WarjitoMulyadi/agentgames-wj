# WJ-ARGUS — Agent Games (zkVerify) · Status

_Last updated: 2026-11-19 (VM build session). Track: **Proof Gatekeeper only**
— WJ-ARGUS is registered for Gatekeeper; Steal the VFY entries are closed
(final Swiss round already paired), so all Steal work was dropped.
Round 07 runs today 17:30–03:30 WIB, Round 08 tomorrow, same window._

## What exists

```
~/workspace/agentgames/
├── circuit-info.json          # live snapshot of /api/circuit-info (mainnet)
├── circuits/
│   ├── gatekeeper.wasm        # official circuit (1.7 MB)
│   └── gatekeeper_final.zkey  # official proving key (310 KB)
│   └── (vfy-policy artifacts also downloaded earlier; track closed, unused)
└── agent/
    ├── app/                   # FastAPI application
    │   ├── main.py            # /health, /setup (one-time), /agent, /gatekeeper
    │   ├── config.py          # env config + mode-600 secret file handling
    │   ├── security.py        # HMAC-SHA256 verify (raw body, pre-parse) + response signing
    │   ├── gatekeeper.py      # deterministic decision rules + circuit input encodings
    │   ├── prover.py          # bridge to the Node/snarkjs prover
    │   ├── kurier.py          # Kurier REST client (register-vk / submit-proof / job-status)
    │   └── store.py           # JSON store: idempotent responses + seen proof_tx
    ├── prover/
    │   ├── prove.js           # snarkjs fullProve + local verify; export-vk; verify
    │   └── commitment.js      # (Steal-era tool, unused now)
    ├── tests/smoke_test.py    # end-to-end smoke test (see results below)
    ├── requirements.txt       # fastapi, uvicorn, httpx, pycryptodome
    └── .env.example           # every knob documented; no real values
```

### Protocol implementation (Proof Gatekeeper)

- **HMAC first, parse second.** Every POST is verified against the raw
  body before any JSON parsing; bad/missing signature → 401, nothing
  processed. Verification tolerantly accepts the secret as UTF-8 / hex /
  base64 and the signature as hex / `sha256=`-prefixed / base64 — the
  exact byte encoding is only confirmed by the first live practice task.
- **Every response is signed** (`x-agent-games-signature` over the exact
  raw response bytes). Preflight envelopes
  (`agent-games.preflight.v1`) get `{ok: true, protocolVersion: "v1"}`.
- **Deterministic decisions, fail closed.** APPROVE (+12) only when every
  check passes; any doubt → REJECT. Checks, in order: timestamps sane
  (issued ≤ 5 min in the future, deadline not passed, deadline present),
  `proof_vk == registered_vk` (VK_SUBSTITUTION), balance ≥ minimum
  (THRESHOLD_MISMATCH), recipient == condition_recipient
  (RECIPIENT_MISMATCH), amount ≤ max_transfer (AMOUNT_OVERFLOW),
  current_block < expiry_block (EXPIRED_CONDITION), proof_tx not
  previously accepted (PROOF_REUSED).
- **Real Groth16 proofs, locally verified.** Inputs use the circuit's
  proven interface (13 inputs; vk hashes = BigInt(hex) mod P; taskId =
  trailing-UUID 128-bit integer for `task_R03_<uuid>` ids, else
  keccak256(utf8 task_id) mod P; decision 0/1; salt 0). Each proof is
  verified against the official VK inside the prover before it is
  returned — a proof that fails local verification is never sent.
- **PROOF_REUSED has no possible proof** (the circuit forces decision=1
  when all on-chain checks pass), so that answer carries honest public
  signals with `proof: null` — the decision is still delivered.
- **Idempotency.** Responses are persisted by task_id; a redelivery gets
  the byte-identical answer. Accepted proof_tx values are persisted so
  replays are caught across restarts.
- **Kurier in the background.** After responding, the proof is submitted
  via Kurier (VK registered once at startup) and polled to Finalized —
  never blocking the 60 s response deadline. Skipped cleanly when no
  KURIER_API_KEY is set; the inline proof in the response is what the
  platform scores.

## The HMAC secret — one-time setup (IMPORTANT)

**✅ DONE (2026-11-19): the real secret is installed at
`agent/data/hmac_secret.txt` (mode 600) — the agent's preferred file
path.** Verified by `tests/file_secret_test.py` (10/10 checks): /health
reports `hmacSource: "file"`, /setup is locked, a wrong-secret request
gets 401, and a preflight signed with the file's secret returns 200
with a response signature that verifies against the same secret. The
/setup paste flow below is therefore NOT needed anymore (the page stays
built and locked; it is harmless). Two supported paths, file wins over
env:

1. **`/setup` page (primary).** Once the agent is reachable on its
   public URL, open `https://<public-url>/setup`, paste the secret into
   the form, submit. It is stored server-side in
   `agent/data/hmac_secret.txt` (**mode 600**), activated immediately
   (no restart), and the page **locks itself permanently** — later
   visits show "Setup is locked", further POSTs get 403. To rotate:
   delete the secret file on the server and restart, or use path 2.
   ⚠️ The page is unauthenticated by necessity (it bootstraps the only
   credential) — **paste the secret immediately after the public URL
   goes live**, before sharing the URL anywhere.
2. **`HMAC_SECRET` env var (fallback).** Set it in the host's
   environment / secret manager before starting the agent.

`GET /health` reports `hmacConfigured`, `hmacSource`
(`file`/`env`/`placeholder`) and `setupLocked` so readiness is checkable
without touching the secret.

## Test results

**File-secret test — 10/10 PASSED** (`tests/file_secret_test.py`,
against a server instance using the real secret file):
health reports `hmacConfigured: true`, `hmacSource: "file"`,
`setupLocked: true`; /setup page shows the locked state and a POST to
it is refused (403); a wrong-secret request gets 401; a preflight
signed with the file's secret returns 200 and its response signature
verifies against the same secret — the full sign/verify round-trip
works with the installed secret (whose value was never printed).

**Full smoke test — 13 checks PASSED, then stopped by the environment**
(`tests/smoke_test.py`, placeholder-mode server, throwaway /tmp paths,
`PROOF_TIMEOUT_MS=1200000` as a local-only accommodation):
- /health: ok, Gatekeeper artifacts present, placeholder mode reported
- /setup flow: page open pre-setup → task rejected (401) before the
  secret exists → paste accepted → response signed with the new secret
  → secret file written with mode 600 → second paste refused (403) →
  page locked → /health reports the file-backed secret
- signature gate: bad HMAC → 401, missing signature → 401
- The remaining checks (APPROVE + proof over HTTP, local verify,
  idempotent redelivery, REJECT + proof, preflight) **could not
  complete in this VM**: the prover process accumulated ~1 CPU-second
  in 614 s of wall time (see Hosting verdict) and the run was
  terminated by the builder after 10 minutes, not by a test failure.

**Proving correctness — proven directly.** A standalone `prove.js` run
using the EXACT circuit inputs that `app/gatekeeper.py` builds for the
smoke test's valid task produced a complete Groth16 proof
(pi_a/pi_b/pi_c captured in the session log). `prove.js` only emits a
proof after `groth16.verify` passes against the official VK, so that
proof is locally verified by construction. An earlier end-to-end run
also proved the handler's fallback path: with proving cut off at 30 s,
the same task returned a signed, well-formed APPROVE response with
honest public signals and `proof: null`. The only thing not observed
end-to-end is a proof physically riding in an HTTP response — the code
path is identical to the verified fallback path; the blocker is this
VM's CPU throttling, not the agent.

**Poseidon golden vector** (Steal-era tooling, now unused): matched the
publicly documented commitment exactly.

## Hosting verdict — DO NOT host in this VM

Two independent blockers, both measured today:

1. **Proving is far too slow here.** This VM throttles sustained CPU
   for long-running processes to a fraction of a core (measured twice:
   a Node prover accumulated ~1 CPU-second in 285 s of wall time, and
   ~1 CPU-second in 614 s on a second run; short burst workloads get
   full speed, which is why installs and light requests feel normal).
   A single Gatekeeper proof — ~2 s on an ordinary laptop per
   independent participant reports — takes **many minutes** here,
   against a **60 s hard platform deadline**. Hosted here, every scored
   task would time out or fall back to proofless answers.
2. **No public inbound path.** `cloudflared` (v2026.11.1, downloaded and
   tested) cannot create a quick tunnel: the VM's egress intercepts the
   TLS handshake to `api.trycloudflare.com`
   (`tls: first record does not look like a TLS handshake`, twice).
   A Tailscale client is present and enrolled on this VM, so Tailscale
   Funnel is a theoretical inbound path — but it was not enabled/tested
   (it changes tailnet config), and it would not matter: blocker 1
   (proving speed) disqualifies this VM on its own.

**Recommendation:** run the agent on a normal host before Round 07
(17:30 WIB today). Options, in order of least friction:
- **Railway / similar PaaS from the GitHub repo** — the route most
  participants used; stable HTTPS URL, real CPU, env vars for
  KURIER_API_KEY; the /setup flow works unchanged on the public URL.
- **Jordi's PC** (Ryzen 5 5600G — proving will take ~2 s) + a tunnel
  that works from his network (named Cloudflare tunnel with his
  account, or his existing Tailscale setup) — must stay on 17:30–03:30.
- Any small VPS with a public IP + a reverse proxy for HTTPS.

## Remaining gaps (exact)

1. ~~HMAC secret not yet installed~~ — **DONE**: the real secret is in
   `agent/data/hmac_secret.txt` (mode 600) and verified loading (see
   above). When moving to the real host, copy that file (or re-paste
   via /setup there) — never commit it to the repo.
2. **No host yet** — see verdict above. After choosing a host: deploy,
   `GET /health` must show both circuit artifacts present,
   `hmacConfigured: true` after setup, then register the endpoint URL
   (`https://<host>/agent`) in the dashboard and run the platform's
   preflight / practice tasks before 17:30 WIB.
3. **KURIER_API_KEY not set** — optional but recommended (mainnet key
   from kurier.xyz). Without it, proofs are returned inline only (the
   platform still re-verifies them); with it, each proof also gets an
   on-chain Kurier job. Set it as an env var on the host — never in the
   repo.
4. **Signature encoding unconfirmed** — hex-vs-base64 and secret
   encoding are handled tolerantly, but the first live practice task is
   the real confirmation. If the platform reports signature failures,
   check the server log first; the tolerant verifier logs nothing about
   secrets, so compare against a dashboard practice dispatch.
5. **First-practice confirmations** — response field spellings follow
   the official examples (`decision`, `reason_code`, `proof_tx`,
   `proof`, `public_signals`); the practice round is where any
   remaining mismatch would surface, at no score cost.

## Publishing to the registration repo

Repo: https://github.com/WarjitoMulyadi/agentgames-wj (public, README
only). **Nothing has been pushed from this VM (no GitHub credentials
here).** When publishing, copy:

- `agent/app/` (all .py files), `agent/prover/` (`prove.js`,
  `commitment.js`, `package.json` — NOT `node_modules`),
  `agent/tests/`, `agent/requirements.txt`, `agent/.env.example`
- `circuits/gatekeeper.wasm`, `circuits/gatekeeper_final.zkey`,
  `circuit-info.json` (or re-download at deploy time from
  https://agentgames.zkverify.io/circuits/…)
- this STATUS.md and a README describing the run commands below

**Never publish:** `agent/data/` (contains the secret file and the
response store), `agent/.venv/`, `node_modules/`, `__pycache__/`, any
`.env` with real values.

Suggested `.gitignore` for the repo:
```
.env
.env.strategy
agent/data/
agent/.venv/
**/node_modules/
__pycache__/
```

## Run commands

Local (this VM — testing only, proving is too slow for live play):
```bash
cd ~/workspace/agentgames/agent
.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8787
# then: curl http://127.0.0.1:8787/health
# smoke test (server must be running, placeholder mode):
.venv/bin/python tests/smoke_test.py
```

On the real host:
```bash
cd agent
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
cd prover && npm install && cd ..          # snarkjs + circomlibjs
# optional: KURIER_API_KEY=<key>  (env or host secret manager)
.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8787}
# 1) install the secret: copy agent/data/hmac_secret.txt from this VM
#    (mode 600, do NOT commit it) — or open https://<public-url>/setup
#    and paste the dashboard secret there instead
# 2) verify: curl https://<public-url>/health  -> hmacConfigured: true
# 3) register https://<public-url>/agent in the dashboard; run preflight
```

Environment variables: `HMAC_SECRET` (fallback only), `HMAC_SECRET_FILE`
(default `agent/data/hmac_secret.txt`), `KURIER_API_KEY`,
`KURIER_API_URL` (default `https://api.kurier.xyz/api/v1`), `PORT`
(default 8787), `PROOF_TIMEOUT_MS` (default 30000),
`RESPONSE_DEADLINE_MS` (default 55000), `STORE_PATH`
(default `agent/data/store.json`), `CIRCUITS_DIR`, `PROVER_DIR`,
`NODE_BIN`.
