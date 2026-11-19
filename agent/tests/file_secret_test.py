#!/usr/bin/env python3
"""Round-trip test for the file-based HMAC secret.

Verifies the agent loads its secret from agent/data/hmac_secret.txt:
  * /health reports hmacConfigured=true, hmacSource="file", setupLocked=true
  * /setup is locked (page shows locked state, POST -> 403)
  * a request signed with a WRONG secret -> 401
  * a preflight signed with the file's secret -> 200, and the response
    signature verifies against the same secret (full round-trip)

The secret value is read in-process ONLY to compute signatures; it is
never printed. Run against a server started with the default
HMAC_SECRET_FILE path, e.g. on a second port:
  PORT=8788 STORE_PATH=/tmp/ag-store-real.json \
    .venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8788
  AGENT_BASE=http://127.0.0.1:8788 .venv/bin/python tests/file_secret_test.py
"""

from __future__ import annotations

import hashlib
import hmac as hmac_mod
import json
import os
import sys
import urllib.request
import urllib.error
from pathlib import Path

BASE = os.environ.get("AGENT_BASE", "http://127.0.0.1:8788")
AGENT_DIR = Path(__file__).resolve().parent.parent
SECRET = (AGENT_DIR / "data" / "hmac_secret.txt").read_text().strip()

PASS = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS
    if not cond:
        print(f"FAIL: {name} {detail}", flush=True)
        sys.exit(1)
    PASS += 1
    print(f"  ok: {name}", flush=True)


def sign(secret: str, raw: bytes) -> str:
    return hmac_mod.new(secret.encode(), raw, hashlib.sha256).hexdigest()


def request(method: str, path: str, raw: bytes | None = None, headers: dict | None = None):
    req = urllib.request.Request(BASE + path, data=raw, method=method)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, resp.headers, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read()


def main() -> None:
    print("== health: secret loaded from file ==", flush=True)
    status, _, raw = request("GET", "/health")
    health = json.loads(raw)
    check("health ok", status == 200 and health["ok"] is True)
    check("hmacConfigured true", health["hmacConfigured"] is True)
    check("hmacSource is 'file'", health["hmacSource"] == "file",
          f"(got {health['hmacSource']})")
    check("setupLocked true", health["setupLocked"] is True)

    print("== /setup is locked ==", flush=True)
    status, _, raw = request("GET", "/setup")
    check("setup page shows locked state", status == 200 and b"locked" in raw.lower())
    payload = json.dumps({"secret": "attempted-override-value"}).encode()
    status, _, _ = request("POST", "/setup", payload, {"content-type": "application/json"})
    check("setup POST refused with 403", status == 403, f"(got {status})")

    print("== sign/verify round-trip with the file secret ==", flush=True)
    preflight = {"type": "agent-games.preflight.v1", "agent_id": "file-secret-test",
                 "nonce": "rt1"}
    raw_body = json.dumps(preflight).encode()

    status, _, _ = request("POST", "/agent", raw_body, {
        "content-type": "application/json",
        "x-agent-games-signature": sign("definitely-the-wrong-secret", raw_body),
    })
    check("wrong-secret request rejected with 401", status == 401, f"(got {status})")

    status, headers, raw = request("POST", "/agent", raw_body, {
        "content-type": "application/json",
        "x-agent-games-signature": sign(SECRET, raw_body),
    })
    check("file-secret request accepted (200)", status == 200, f"(got {status})")
    body = json.loads(raw)
    check("preflight answered ok", body.get("ok") is True
          and body.get("protocolVersion") == "v1")
    resp_sig = headers.get("x-agent-games-signature")
    check("response signature verifies against the file secret",
          resp_sig is not None and hmac_mod.compare_digest(resp_sig, sign(SECRET, raw)))

    print(f"\nALL {PASS} FILE-SECRET CHECKS PASSED", flush=True)


if __name__ == "__main__":
    main()
