# WJ-ARGUS — Proof Gatekeeper agent (zkVerify Agent Games)

A FastAPI agent for the **Proof Gatekeeper** track of the zkVerify Agent
Games, registered to participant @franggun12. It receives signed task
envelopes, makes a deterministic APPROVE/REJECT decision, and backs every
decision with a Groth16 proof generated locally with the official circuit
(snarkjs), verified locally before it is sent.

Full build/test status and protocol notes: see `STATUS.md`.
Railway deployment steps: see `DEPLOY-NOTES.md`.

## Layout

```
agent/app/         FastAPI application (/health, /setup, /agent, /gatekeeper)
agent/prover/      Node/snarkjs prover (prove.js) — run as a subprocess
agent/tests/       smoke + file-secret tests
circuits/          official Gatekeeper circuit (wasm + proving key)
circuit-info.json  snapshot of the platform's /api/circuit-info
```

The app's default paths assume exactly this layout: circuits are read
from `circuits/` at the repo root, the prover from `agent/prover/`
(see `agent/app/config.py`). No path env vars are needed.

## Quick start (local)

```bash
cd agent
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
cd prover && npm install && cd ..
.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8787}
```

Circuit artifacts (`circuits/gatekeeper.wasm`,
`circuits/gatekeeper_final.zkey`) come from
https://agentgames.zkverify.io/circuits/ — see `circuit-info.json`.

## Secret setup (one-time)

The platform HMAC secret is shown once in the Agent Games dashboard.
**Never commit it.** After deploying, either:

1. open `https://<public-url>/setup` and paste it — stored server-side
   (mode 600), activated immediately, and the page locks itself, or
2. set the `HMAC_SECRET` environment variable on the host.

`GET /health` reports `hmacConfigured` / `hmacSource` / `setupLocked`.
Optional: `KURIER_API_KEY` (Kurier mainnet) enables background on-chain
proof submission. See `agent/.env.example` for all variables.

## Tests

```bash
# full local suite (server running in placeholder mode, throwaway paths)
.venv/bin/python agent/tests/smoke_test.py
# file-secret round-trip (server running with the real secret file)
.venv/bin/python agent/tests/file_secret_test.py
```
