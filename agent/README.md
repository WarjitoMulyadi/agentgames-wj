# WJ-ARGUS — Proof Gatekeeper agent (zkVerify Agent Games)

A FastAPI agent for the **Proof Gatekeeper** track. It receives signed
task envelopes, makes a deterministic APPROVE/REJECT decision, and
backs every decision with a Groth16 proof generated locally with the
official circuit (snarkjs), verified locally before it is sent.

## Quick start

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
cd prover && npm install && cd ..
.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8787}
```

Circuit artifacts (`../circuits/gatekeeper.wasm`,
`../circuits/gatekeeper_final.zkey`) come from
https://agentgames.zkverify.io/circuits/ — see `../circuit-info.json`.

## Secret setup (one-time)

The platform HMAC secret is shown once in the dashboard. Either:

1. copy `data/hmac_secret.txt` (mode 600) from a configured install, or
2. open `https://<public-url>/setup` and paste it — stored server-side
   (mode 600), activated immediately, and the page locks itself, or
3. set the `HMAC_SECRET` environment variable.

`GET /health` reports `hmacConfigured` / `hmacSource` / `setupLocked`.
Optional: `KURIER_API_KEY` (Kurier mainnet) enables background on-chain
proof submission. See `.env.example` for all variables and
`../STATUS.md` for the full status, gaps, and hosting notes.

## Tests

```bash
# full local suite (server running in placeholder mode, throwaway paths)
.venv/bin/python tests/smoke_test.py
# file-secret round-trip (server running with the real secret file)
.venv/bin/python tests/file_secret_test.py
```
