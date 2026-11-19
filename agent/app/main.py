"""Agent Games agent (WJ-ARGUS) — FastAPI entrypoint. Proof Gatekeeper only.

Endpoints:
  GET  /health     readiness + circuit/config summary (unsigned)
  GET  /setup      one-time secret bootstrap page (self-locking, see below)
  POST /setup      receives the pasted HMAC secret exactly once
  POST /agent      the registered task endpoint: verifies the HMAC over
                   the raw body, dispatches (preflight / Proof
                   Gatekeeper), returns a signed JSON response.
  POST /gatekeeper same pipeline, Gatekeeper tasks only

Protocol rules enforced here:
  * HMAC-SHA256 verified against the RAW body BEFORE any JSON parsing.
    A bad or missing signature is a 401 and nothing is processed.
  * Every response body is signed: `x-agent-games-signature` over the
    exact raw response bytes.
  * Fail closed: malformed tasks get a deterministic REJECT, never a
    500, never a hang. Work is budgeted well under the platform's
    60-second hard deadline.
  * Kurier proof submission runs in the background after responding.

The /setup bootstrap exists because the platform secret is shown ONCE
in the dashboard and must never travel through chat. Flow: deploy the
agent, open https://<public-url>/setup, paste the secret into the form.
It is stored server-side in a mode-600 file and activated immediately;
the page then locks itself permanently (re-opening requires deleting
the secret file on the server and restarting). The page is necessarily
unauthenticated — it IS the bootstrap for the only credential — so it
must be used immediately after the public URL goes live.

Run:  uvicorn app.main:app --host 0.0.0.0 --port $PORT   (from agent/)
"""

from __future__ import annotations

import asyncio
import json
import logging

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response

from . import config, gatekeeper, kurier, security
from .store import Store

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("agentgames")

app = FastAPI(title="WJ-ARGUS — Agent Games (Proof Gatekeeper)", docs_url=None, redoc_url=None)
store = Store(config.STORE_PATH)


@app.on_event("startup")
async def _startup() -> None:
    if config.HMAC_IS_PLACEHOLDER:
        log.warning(
            "No HMAC secret configured (source=placeholder) — open /setup "
            "on the public URL and paste the dashboard secret, or set "
            "HMAC_SECRET. Real platform traffic cannot be validated yet."
        )
    else:
        log.info("HMAC secret loaded from %s", config.HMAC_SECRET_SOURCE)
    asyncio.create_task(kurier.register_vk_background())


def _signed_response(body: dict, status_code: int = 200) -> Response:
    raw = json.dumps(body, separators=(",", ":")).encode("utf-8")
    return Response(
        content=raw,
        status_code=status_code,
        media_type="application/json",
        headers={config.SIGNATURE_HEADER: security.sign_body(config.HMAC_SECRET, raw)},
    )


# ---------------------------------------------------------------------------
# One-time /setup bootstrap
# ---------------------------------------------------------------------------
_SETUP_PAGE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>WJ-ARGUS — one-time secret setup</title></head>
<body style="font-family: system-ui, sans-serif; max-width: 34rem; margin: 3rem auto; padding: 0 1rem;">
<h1>WJ-ARGUS — one-time secret setup</h1>
<p>Paste the Agent Games HMAC secret from the dashboard (it was shown
once, at registration). It is stored <b>only on this server</b> in a
mode-600 file and activated immediately. This page then locks itself
permanently.</p>
<p><b>Do this now</b> — until the secret is set, this page is open to
anyone who knows the URL.</p>
<form method="post" action="/setup">
  <input type="password" name="secret" autocomplete="off" autofocus
         style="width: 100%; padding: 0.6rem; font-size: 1rem;"
         placeholder="Paste the HMAC secret here">
  <button type="submit" style="margin-top: 1rem; padding: 0.6rem 1.2rem; font-size: 1rem;">
    Save secret &amp; lock setup
  </button>
</form>
</body></html>"""

_SETUP_DONE_PAGE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>WJ-ARGUS — setup</title></head>
<body style="font-family: system-ui, sans-serif; max-width: 34rem; margin: 3rem auto; padding: 0 1rem;">
<h1>Setup is locked</h1>
<p>The HMAC secret is already configured (source: {source}). This page
no longer accepts input. To rotate the secret, delete
<code>data/hmac_secret.txt</code> on the server and restart the agent —
or set the HMAC_SECRET environment variable instead.</p>
</body></html>"""


@app.get("/setup", response_class=HTMLResponse)
async def setup_page() -> HTMLResponse:
    if config.HMAC_IS_PLACEHOLDER:
        return HTMLResponse(_SETUP_PAGE)
    return HTMLResponse(_SETUP_DONE_PAGE.format(source=config.HMAC_SECRET_SOURCE))


@app.post("/setup")
async def setup_submit(request: Request) -> Response:
    if not config.HMAC_IS_PLACEHOLDER:
        return JSONResponse(
            {"ok": False, "error": "setup is locked: a secret is already configured"},
            status_code=403,
        )
    secret = ""
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        try:
            payload = await request.json()
            secret = str(payload.get("secret", ""))
        except Exception:
            secret = ""
    else:
        form = await request.form()
        secret = str(form.get("secret", ""))
    secret = secret.strip()
    if len(secret) < 8 or any(ch.isspace() for ch in secret):
        return JSONResponse(
            {"ok": False, "error": "secret looks empty or malformed — nothing was saved"},
            status_code=400,
        )
    config.install_secret(secret)
    log.info("HMAC secret installed via /setup (stored in mode-600 file, setup now locked)")
    return _signed_response({"ok": True, "setup": "complete", "hmacSource": "file"})


# ---------------------------------------------------------------------------
# Task pipeline
# ---------------------------------------------------------------------------
def _dispatch(body: dict, forced_track: str | None) -> tuple[dict, dict | None]:
    """Route a verified envelope. Returns (response_body, kurier_job)."""
    if body.get("type") == "agent-games.preflight.v1":
        # Preflight handshake: prove the endpoint is alive and signed.
        return {"ok": True, "protocolVersion": "v1"}, None
    if forced_track == "gatekeeper" or body.get("type") == gatekeeper.TASK_TYPE:
        return gatekeeper.handle_task(body, store)
    # Signed but unrecognized envelope: fail closed, signed, no crash.
    return {"ok": False, "error": "unrecognized task envelope"}, None


async def _handle_task_request(request: Request, forced_track: str | None) -> Response:
    raw = await request.body()
    signature = request.headers.get(config.SIGNATURE_HEADER)
    if not security.verify_signature(config.HMAC_SECRET, raw, signature):
        # Fail closed: nothing is parsed, nothing is processed.
        return JSONResponse(
            {"ok": False, "error": "invalid or missing signature"}, status_code=401
        )
    try:
        body = json.loads(raw)
    except json.JSONDecodeError:
        return _signed_response({"ok": False, "error": "body is not valid JSON"}, 400)
    if not isinstance(body, dict):
        return _signed_response({"ok": False, "error": "body is not a JSON object"}, 400)

    response_body, kurier_job = _dispatch(body, forced_track)
    response = _signed_response(response_body)
    if kurier_job is not None:
        asyncio.create_task(
            kurier.submit_proof_background(
                "gatekeeper", kurier_job["proof"], kurier_job["publicSignals"]
            )
        )
    return response


@app.get("/health")
async def health() -> dict:
    hashes = kurier.circuit_vk_hashes()
    return {
        "ok": True,
        "agent": "WJ-ARGUS",
        "protocolVersion": "v1",
        "tracks": ["proof-gatekeeper"],
        "circuits": {
            "gatekeeper": {
                "vkHash": hashes.get("gatekeeper"),
                "wasmPresent": config.GATEKEEPER_WASM.exists(),
                "zkeyPresent": config.GATEKEEPER_ZKEY.exists(),
            }
        },
        "hmacConfigured": not config.HMAC_IS_PLACEHOLDER,
        "hmacSource": config.HMAC_SECRET_SOURCE,
        "setupLocked": not config.HMAC_IS_PLACEHOLDER,
        "kurierConfigured": bool(config.KURIER_API_KEY),
    }


@app.post("/agent")
async def agent_endpoint(request: Request) -> Response:
    return await _handle_task_request(request, forced_track=None)


@app.post("/gatekeeper")
async def gatekeeper_endpoint(request: Request) -> Response:
    return await _handle_task_request(request, forced_track="gatekeeper")
