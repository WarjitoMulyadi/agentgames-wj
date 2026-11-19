# WJ-ARGUS — Railway deployment notes

For the browser operator deploying this repo
(https://github.com/WarjitoMulyadi/agentgames-wj) to Railway.
Target: agent live and registered **before Round 07, today 17:30 WIB**.

## Why this layout works with zero path config

`agent/app/config.py` resolves its paths from the repo layout itself:
circuits from `<repo-root>/circuits/`, prover from `agent/prover/`,
secret file + store under `agent/data/` (created at runtime). The repo
root IS the project root, so no `CIRCUITS_DIR` / `PROVER_DIR` /
`STORE_PATH` env vars are needed.

## Deploy config already in the repo (do not re-invent)

- `railway.json` — NIXPACKS builder, explicit build + start commands.
- `nixpacks.toml` — providers python + node; setup pins
  `python311` + `nodejs_20`; install phase pip-installs the root
  `requirements.txt` (mirror of `agent/requirements.txt`) and runs
  `npm --prefix agent/prover ci` (snarkjs deps for the prover).
- `Procfile` — fallback start command, same as railway.json.
- Start command (from repo root):
  `cd agent && uvicorn app.main:app --host 0.0.0.0 --port $PORT`

## Steps

1. **New project from GitHub.** Railway → New Project → Deploy from
   GitHub repo → select `WarjitoMulyadi/agentgames-wj`. If Railway
   asks for a **root directory**, leave it as the repo root (`/`) —
   the config files live there.
2. **Watch the first build.** It must show BOTH the pip install and
   the `npm ci` in `agent/prover` succeeding. If the build fails on a
   missing runtime, check Settings → Build: builder must be Nixpacks
   (the repo's `nixpacks.toml` should be picked up automatically).
3. **Environment variables** (Settings → Variables):
   - `PORT` — provided by Railway automatically. Do NOT set it.
   - `KURIER_API_KEY` — OPTIONAL, skip for now. Without it the agent
     still answers tasks with inline proofs (that is what is scored);
     Kurier only adds a background on-chain submission job. Never put
     the HMAC secret here unless the /setup flow in step 5 fails —
     the fallback variable name is `HMAC_SECRET`.
   - Nothing else is required.
4. **Public URL.** Settings → Networking → Generate Domain. Note the
   `https://<domain>` URL.
5. **Install the HMAC secret IMMEDIATELY** (the /setup page is
   unauthenticated by design — it bootstraps the only credential, so
   do this before sharing the URL anywhere):
   - Open `https://<domain>/setup`, paste the CURRENT dashboard secret
     for WJ-ARGUS (the rotated one shown once in the Edit WJ-ARGUS
     dialog — the pre-rotation value is dead), submit.
   - The page stores it server-side (mode 600) and locks itself
     permanently. A second visit must say setup is locked.
6. **Post-deploy checklist:**
   - [ ] `GET https://<domain>/health` returns ok, lists BOTH
         Gatekeeper circuit artifacts present, and after step 5 shows
         `hmacConfigured: true`, `hmacSource: "file"`,
         `setupLocked: true`.
   - [ ] In the Agent Games dashboard: Edit WJ-ARGUS → set
         **AGENT ENDPOINT** to `https://<domain>/agent` and save
         (saving runs a signed preflight against the URL).
   - [ ] Run **Test preflight** — must pass.
   - [ ] Run at least one **practice task** — must complete; this is
         the first live confirmation of the signature encoding.
   - [ ] Confirm the agent shows HEALTHY in the dashboard.

## Railway caveats (expected behaviour, not bugs)

- **Ephemeral filesystem:** `agent/data/` (secret file + idempotency
  store) does NOT survive a redeploy/restart on Railway. After any
  redeploy, /health will report `hmacConfigured: false` and the
  secret must be re-pasted at `/setup` (it will be open again), and
  the endpoint re-checked in the dashboard. Avoid redeploying during
  the 17:30–03:30 WIB match windows.
- **Do not scale beyond 1 replica** — the store and secret are
  local files.
- **Never** commit `agent/data/`, a real `.env`, or the secret value
  to this repo (`.gitignore` already blocks them).
